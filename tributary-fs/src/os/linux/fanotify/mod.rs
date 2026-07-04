//! The fanotify-FILESYSTEM backend: kernel-recursive, privileged, riding the
//! same DriverCore shape the FSEvents loop hardened.
//!
//! Pure machinery — the FID wire decode ([`fid`]) and the admission/intern map
//! ([`map`]) — compiles everywhere tests run (including miri), mirroring the
//! inotify precedent; the FFI Source (the superblock mark, its reader thread,
//! and the seeding walk) is `cfg(all(target_os = "linux", not(miri)))`.
//!
//! A single `FAN_MARK_FILESYSTEM` mark scopes to the whole superblock, so the
//! reader admits by directory-FID membership in a per-root [`FidMap`] before an
//! event ever reaches the seam: an unknown handle is provably outside the root
//! and dropped. Admitted events cross the driver's queue as
//! [`AdmittedEvent`]s inside [`RawLinuxEvent::Fanotify`](super::RawLinuxEvent),
//! carrying paths already resolved against the map and identity already
//! interned — the compile path only lowers each absolute path to its
//! root-relative form.
//!
//! Root UNMOUNT carries NO in-tree fanotify signal — an unmounted
//! `FAN_MARK_FILESYSTEM` superblock stays alive under the mark and the fd simply
//! goes quiet (design §7, container-validated L4.1). Detection is the mount
//! refresh's folded-in root re-stat (`FsOps::refresh_mounts` →
//! `MountRefresh.root`), compared against the barrier identity in
//! `DriverCore::on_mounts_refreshed`: a missing/replaced root lowers the same
//! `DeleteSelf`/`MoveSelf` death lifecycle a macOS `RootChanged` probe uses.
//! (An in-tree delete/replace of the ROOT object itself, by contrast, DOES
//! arrive as `FAN_DELETE_SELF`/`FAN_MOVE_SELF`.)
//!
//! That refresh runs at scope birth and on every loss signal — but a QUIET
//! unmount produces neither, so those triggers alone would never observe it.
//! The composition therefore adds ONE timer: the periodic root-liveness tick
//! (`WatcherOptions::root_liveness_interval`, fanotify-only — see the
//! per-backend death-signal table in the `core` module docs), which re-stats the
//! root on a bounded cadence so a signal-silent unmount is detected within the
//! interval. A loss-triggered refresh still catches it immediately when one
//! occurs; the tick only bounds the otherwise-unobservable quiet case, and
//! `Duration::ZERO` disables it (back to quiet-but-alive until re-access fails).

pub(crate) mod fid;
pub(crate) mod map;

#[cfg(test)]
mod tests;

use std::{num::NonZeroU64, path::PathBuf};

use fid::RenameInfo;
pub(crate) use fid::{FanMask, RawFanotifyEvent};
use map::FidMap;

/// One `FAN_RENAME`'s two admitted halves: each resolved absolute path plus its
/// interned identity. Both halves are always present (the kernel reports the
/// atomic pair in one event), so the lowering emits adjacent
/// `MovedFrom`/`MovedTo` with no pairing window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedRename {
  /// The source's absolute path (old directory + old name).
  pub(crate) old_path: PathBuf,
  /// The destination's absolute path (new directory + new name).
  pub(crate) new_path: PathBuf,
  /// The moved object's interned identity (stable across the rename — the FID
  /// is the object's, not the directory's).
  pub(crate) identity: Option<NonZeroU64>,
}

/// One fanotify event after admission: its mask, the affected object's absolute
/// path (resolved from the directory FID + name against the [`FidMap`]), the
/// object's interned identity, and — for a rename — the atomic pair.
///
/// A single-object dirent event carries `path` + `identity`; a `FAN_RENAME`
/// carries `rename` and leaves the single-object fields empty; a self-event
/// (`DELETE_SELF`/`MOVE_SELF`) whose object is the admitted directory carries
/// that directory's `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedEvent {
  pub(crate) mask: FanMask,
  pub(crate) path: Option<PathBuf>,
  pub(crate) identity: Option<NonZeroU64>,
  pub(crate) rename: Option<AdmittedRename>,
}

/// The result of admitting one decoded event against the map.
pub(crate) enum Admission {
  /// The event addresses the watched root: forward the admitted form.
  Admit(AdmittedEvent),
  /// A directory moved IN from outside the root: forward the admitted form AND
  /// first walk `moved_in` (the moved directory's resolved NEW path) so its
  /// pre-existing descendant directories enter the map. fanotify synthesizes no
  /// per-descendant creates for a rename, so without this walk later events under
  /// those descendants would drop as outside-root forever with no loss signal.
  /// The moved directory itself is already learned (its own FID); only its
  /// subtree needs seeding. The reader — which owns the walk context — runs the
  /// walk and escalates its incompleteness exactly as a reseed's (blind → fatal).
  AdmitAndSeed {
    /// The move event to forward once the subtree is mapped.
    event: AdmittedEvent,
    /// The moved directory's resolved absolute path at its destination — the
    /// walk's starting point.
    moved_in: PathBuf,
    /// The moved directory's own FID — the parent link every descendant the walk
    /// discovers hangs from.
    moved_fid: fid::Fid,
  },
  /// No admitted directory FID matched — the event is provably outside the
  /// root (the superblock firehose), so it is dropped without loss.
  Drop,
}

/// Admits one decoded event against the per-root map: resolves its directory
/// FID(s) to path(s), interns the object identity, and self-maintains the map
/// (learn on a directory create, forget on a directory delete/rename-out).
/// PURE — the reader calls this single-threaded between reads; the FFI side
/// owns nothing but the fd and the seeding walk.
///
/// Membership is the whole filter: a `dir_fid` absent from the map is outside
/// the watched root and dropped. Renames admit if EITHER end is in-root (a
/// move into or out of the tree is still the tree's business); an in-root end
/// resolves fully, an out-of-root end resolves to `None` and the lowering
/// treats the half as a boundary crossing.
pub(crate) fn admit(map: &mut FidMap, event: &RawFanotifyEvent) -> Admission {
  if let Some(rename) = &event.rename {
    return admit_rename(map, event, rename);
  }

  let Some(dir_fid) = &event.dir_fid else {
    // A dirent event with no directory FID is unaddressable; a self-event's
    // own FID also arrives here as `dir_fid`. Either way, without a handle to
    // test membership on, the event cannot be placed under the root.
    return Admission::Drop;
  };
  let Some(dir_path) = map.admit(dir_fid) else {
    return Admission::Drop;
  };

  let mask = event.mask;
  // A self-event (the admitted directory itself deleted or moved) carries no
  // child name and resolves to the directory's own path and identity.
  if (mask.delete_self() || mask.move_self()) && event.name.is_none() {
    let identity = Some(map.intern(dir_fid));
    if mask.delete_self() {
      map.forget(dir_fid);
    }
    return Admission::Admit(AdmittedEvent {
      mask,
      path: Some(dir_path),
      identity,
      rename: None,
    });
  }

  let path = event.name.as_ref().map(|name| join_name(&dir_path, name));
  // Identity is DIRECTORY-only: interning file target FIDs would grow the map's
  // intern table unboundedly under file churn (the O(directories) bound), and
  // file identity is inert under the kernel-recursive Monitor profile anyway
  // (`reconcile_slot` discards it for a non-descending scope — no per-directory
  // child watch to re-arm). A non-directory target attaches `None`.
  let identity = if mask.ondir() {
    event.target_fid.as_ref().map(|fid| map.intern(fid))
  } else {
    None
  };

  // Self-maintenance: a new in-root directory enters the map via its own
  // create's TARGET_FID; a removed one is forgotten so its stale handle stops
  // admitting.
  if mask.ondir()
    && let Some(name) = &event.name
  {
    if mask.created() {
      map.learn(dir_fid, name, event.target_fid.as_ref());
    } else if (mask.removed() || mask.move_self())
      && let Some(child) = &event.target_fid
    {
      map.forget(child);
    }
  }

  Admission::Admit(AdmittedEvent {
    mask,
    path,
    identity,
    rename: None,
  })
}

/// Admits a `FAN_RENAME`: resolves both directory FIDs, self-maintains the map
/// for a moved DIRECTORY, and interns the moved object's identity when it is a
/// directory (a file target attaches none — see [`admit`]).
///
/// The four move flavors — keyed on whether the destination parent is in-root
/// and whether the MOVED OBJECT itself was already a known directory (the
/// membership that says its descendants are already mapped):
///
/// - **in-root rename** (moved dir known, destination in-root): re-parent the one
///   node in place; every descendant follows via the updated parent link — complete
///   by construction, no walk.
/// - **move-in from outside** (moved dir unknown, destination in-root): the moved
///   directory carries pre-existing descendants the seed walk never saw, so after
///   learning the moved dir itself this returns [`Admission::AdmitAndSeed`] — the
///   reader walks the subtree into the map before forwarding, keeping the
///   completeness invariant.
/// - **move-out** (moved dir known, destination outside): forget the moved dir; its
///   descendants' parent links now point at an absent handle, so their walks break
///   and they evict lazily — the map stops admitting the departed subtree naturally.
/// - **move-out of an already-unknown subtree** (moved dir unknown, destination
///   outside): nothing to maintain; only the in-root SOURCE end resolves, and the
///   move admits as a boundary crossing.
fn admit_rename(map: &mut FidMap, event: &RawFanotifyEvent, rename: &RenameInfo) -> Admission {
  let old_dir = map.admit(&rename.old_dir);
  let new_dir = map.admit(&rename.new_dir);
  if old_dir.is_none() && new_dir.is_none() {
    // Both ends outside the root: a rename elsewhere on the superblock.
    return Admission::Drop;
  }

  let old_path = old_dir
    .as_ref()
    .map(|dir| join_name(dir, &rename.old_name))
    .unwrap_or_else(|| PathBuf::from(&os_name(&rename.old_name)));
  let new_path = new_dir
    .as_ref()
    .map(|dir| join_name(dir, &rename.new_name))
    .unwrap_or_else(|| PathBuf::from(&os_name(&rename.new_name)));

  // A directory move maintains admission and, for a DIRECTORY target, its
  // identity. Identity is directory-only (a file move attaches `None`): file
  // identity is inert under the kernel-recursive profile and interning file
  // targets would leak the intern table under churn.
  let moved_fid = event.target_fid.as_ref();
  let identity = if event.mask.ondir() {
    moved_fid.map(|fid| map.intern(fid))
  } else {
    None
  };

  let event = AdmittedEvent {
    mask: event.mask,
    path: None,
    identity: None,
    rename: Some(AdmittedRename {
      old_path,
      new_path: new_path.clone(),
      identity,
    }),
  };

  if event.mask.ondir()
    && let Some(fid) = moved_fid
  {
    if new_dir.is_some() {
      // The moved object was already a known directory IFF it was in-root before
      // the move — the discriminator between the two in-root-destination flavors.
      // Read it BEFORE `learn` overwrites the node.
      let was_in_root = map.contains(fid);
      // In-root destination: re-parent by inserting under the new parent. The
      // moved object keeps its handle (and thus its interned id), so `learn`
      // overwrites its node in place — identity is STABLE across the rename, and
      // its already-mapped descendants follow via the updated parent link. No
      // id-pruning forget: the object did not depart, so pruning then re-minting
      // would fork identity.
      map.learn(&rename.new_dir, &rename.new_name, Some(fid));
      if !was_in_root {
        // Moved IN from outside: its pre-existing descendants were never seeded
        // (no per-descendant creates arrive for a rename). Hand the reader the
        // subtree to walk in before this move is forwarded, so the map is
        // complete by the time any later event under those descendants admits.
        return Admission::AdmitAndSeed {
          event,
          moved_in: new_path,
          moved_fid: fid.clone(),
        };
      }
    } else {
      // Moved OUT of the root: drop admission AND the interned id (departed). A
      // later move back is a fresh move-in — walked in, minting fresh identity —
      // the conservative direction.
      map.forget(fid);
    }
  }

  Admission::Admit(event)
}

/// Joins a raw fanotify child name onto its resolved directory path. A
/// non-UTF-8 or non-component name still produces a path the lowering can
/// escalate to a located rescan (coverage-honest), never a panic.
fn join_name(dir: &std::path::Path, name: &[u8]) -> PathBuf {
  dir.join(os_name(name))
}

/// Interprets a raw fanotify name as an `OsString` path component. On unix the
/// bytes pass through verbatim; elsewhere (test builds) a lossy form keeps the
/// pure paths decodable.
fn os_name(name: &[u8]) -> std::ffi::OsString {
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(name.to_vec())
  }
  #[cfg(not(unix))]
  {
    std::ffi::OsString::from(String::from_utf8_lossy(name).into_owned())
  }
}

/// The composite `fanotify_init` flag set (design §4.1, container-validated):
/// `FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DFID_NAME |
/// FAN_REPORT_TARGET_FID`. `TARGET_FID` without `REPORT_FID` is `EINVAL` — the
/// full composite is mandatory. Restated locally so the pure module carries no
/// libc dependency; the FFI layer cross-asserts it against the composite.
///
/// `FAN_CLASS_NOTIF` is `0x0` (the notification class is the flag word's
/// default), so it contributes no bits and is omitted from the OR.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) const FAN_INIT_FLAGS: u32 = 0x0000_0200 // FAN_REPORT_FID
  | 0x0000_0400 // FAN_REPORT_DIR_FID  (half of DFID_NAME)
  | 0x0000_0800 // FAN_REPORT_NAME     (half of DFID_NAME)
  | 0x0000_1000; // FAN_REPORT_TARGET_FID

/// The mark mask armed on the superblock (design §4.1): every dirent verb plus
/// the self-events and `FAN_ONDIR` so directory events are reported.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) const FAN_MARK_MASK: u64 = fid::FAN_CREATE
  | fid::FAN_DELETE
  | fid::FAN_MODIFY
  | fid::FAN_ATTRIB
  | fid::FAN_RENAME
  | fid::FAN_DELETE_SELF
  | fid::FAN_MOVE_SELF
  | fid::FAN_ONDIR;

/// Encodes `path`'s NFS-style file handle via `name_to_handle_at`, DYNAMICALLY
/// sizing the buffer: `struct file_handle` is a flexible-array type, and a
/// filesystem whose handle exceeds the initial `MAX_HANDLE_SZ` request answers
/// `EOVERFLOW` with the true size written back into `handle_bytes` — so a single
/// fixed buffer would turn an oversized-handle filesystem (which CAN export
/// handles) into a spurious "unsupported". The loop grows to the reported size
/// and retries exactly once; a second `EOVERFLOW` is a lying kernel and fails.
///
/// Returns the FID handle bytes — `handle_type` (native-endian) followed by the
/// opaque bytes — byte-identical to the event-side decode, so a seed FID matches
/// the kernel's event FIDs exactly. `None` when the filesystem cannot encode a
/// handle for this object (a non-exporting fs, a permission/transient failure,
/// or the double-`EOVERFLOW` broken-kernel case). Shared by the seed/reseed walk
/// (which wraps it into a [`fid::Fid`]) and the `Backend::Auto` probe (whose
/// success is this same round-trip succeeding at the true size).
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) fn encode_handle(path: &std::path::Path) -> Option<std::boxed::Box<[u8]>> {
  use std::os::unix::ffi::OsStrExt;

  let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
  let prefix = std::mem::size_of::<libc::file_handle>();
  // Start at MAX_HANDLE_SZ (the common case fits in one try); a larger handle
  // grows the buffer to the kernel-reported size on the single retry below.
  let mut cap = libc::MAX_HANDLE_SZ as usize;
  let mut grown = false;
  loop {
    // The backing buffer is `u64` so the pointer is 8-aligned — a `Vec<u8>` is
    // only 1-aligned, and writing a `file_handle` (align 4) through such a
    // pointer would be undefined behavior.
    let words = prefix.div_ceil(8) + cap.div_ceil(8) + 1;
    let mut storage = vec![0u64; words];
    let mut mount_id: libc::c_int = 0;
    let handle = storage.as_mut_ptr().cast::<libc::file_handle>();
    // SAFETY: storage is 8-aligned and sized for the fixed prefix plus `cap`
    // opaque bytes; this write stays within it.
    unsafe {
      (*handle).handle_bytes = cap as libc::c_uint;
    }
    // SAFETY: handle points at a correctly-sized, aligned file_handle; cpath is
    // NUL-terminated; mount_id is a valid out-param.
    let rc =
      unsafe { libc::name_to_handle_at(libc::AT_FDCWD, cpath.as_ptr(), handle, &mut mount_id, 0) };
    let errno = (rc != 0)
      .then(|| std::io::Error::last_os_error().raw_os_error())
      .flatten();
    match fid::classify_handle_attempt(rc, errno, grown) {
      fid::HandleAttempt::Encoded => {
        // SAFETY: the call succeeded, so the prefix and `handle_bytes` opaque
        // bytes are initialized.
        let (handle_bytes, handle_type) =
          unsafe { ((*handle).handle_bytes as usize, (*handle).handle_type) };
        if handle_bytes > cap {
          // The kernel reported success yet a length past the buffer it filled:
          // structurally impossible, refuse rather than read out of bounds.
          return None;
        }
        // SAFETY: the opaque handle begins right after the prefix and spans
        // handle_bytes (bounded by cap above); reading it as bytes is in-range.
        let opaque = unsafe {
          std::slice::from_raw_parts(storage.as_ptr().cast::<u8>().add(prefix), handle_bytes)
        };
        let mut bytes = Vec::with_capacity(4 + opaque.len());
        bytes.extend_from_slice(&handle_type.to_ne_bytes());
        bytes.extend_from_slice(opaque);
        return Some(bytes.into_boxed_slice());
      }
      fid::HandleAttempt::Grow => {
        // EOVERFLOW wrote the required size back into handle_bytes; retry once
        // at exactly that size.
        // SAFETY: the prefix is initialized on an EOVERFLOW return (the kernel
        // fills handle_bytes with the needed length).
        cap = unsafe { (*handle).handle_bytes as usize };
        grown = true;
      }
      fid::HandleAttempt::Unsupported => return None,
    }
  }
}

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) mod reader;

#[cfg(all(target_os = "linux", not(miri)))]
#[allow(unused_imports)]
pub(crate) use source::{FanotifySpawn, Source, SourceHandle};

#[cfg(all(target_os = "linux", not(miri)))]
mod source;
