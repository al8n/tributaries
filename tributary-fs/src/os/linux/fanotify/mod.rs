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
//! carrying paths already resolved against the map — the compile path only
//! lowers each absolute path to its root-relative form. No node identity rides
//! with them: under the kernel-recursive profile record identity is inert
//! (design §4.9), exactly as the FSEvents lowering attaches none.
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

use std::{collections::BTreeMap, path::PathBuf};

pub(crate) use fid::{FanMask, RawFanotifyEvent};
use fid::{Fid, RenameInfo};
use map::FidMap;

/// One `FAN_RENAME`'s two admitted halves: each resolved absolute path. Both
/// halves are always present (the kernel reports the atomic pair in one event),
/// so the lowering emits adjacent `MovedFrom`/`MovedTo` with no pairing window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedRename {
  /// The source's absolute path (old directory + old name).
  pub(crate) old_path: PathBuf,
  /// The destination's absolute path (new directory + new name).
  pub(crate) new_path: PathBuf,
}

/// One fanotify event after admission: its mask, the affected object's absolute
/// path (resolved from the directory FID + name against the [`FidMap`]), and —
/// for a rename — the atomic pair. No node identity: under the kernel-recursive
/// profile record identity is inert (design §4.9).
///
/// A single-object dirent event carries `path`; a `FAN_RENAME` carries `rename`
/// and leaves the single-object fields empty; a self-event
/// (`DELETE_SELF`/`MOVE_SELF`) whose object is the admitted directory carries
/// that directory's `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedEvent {
  pub(crate) mask: FanMask,
  pub(crate) path: Option<PathBuf>,
  pub(crate) rename: Option<AdmittedRename>,
}

/// A per-read-batch admission memo (design §4.9): caches the ADMITTED
/// `(directory handle → resolved absolute path)` of the events in one
/// [`decode_events`](fid::decode_events) buffer, the storm win when many events
/// address few directories (a rename storm under one parent).
///
/// Soundness rests on the [`FidMap`]'s generation counter. Each cached entry is
/// tagged with the map generation it was resolved against; a lookup is a hit only
/// when the tag still equals the map's current generation. Because EVERY map
/// mutation (`learn`/`forget`/`reseed`/an orphan eviction) bumps that counter,
/// any mutation `admit` performs mid-batch invalidates the whole memo by making
/// every prior tag stale — so the memo can never serve a path the map has since
/// re-parented or pruned. The reader is single-threaded and owns both the map and
/// the memo, so no other writer exists; a fresh `MemoBatch` is used per buffer, so
/// it is also cleared at batch end by construction.
pub(crate) struct MemoBatch {
  /// The admitted `directory handle → (generation, resolved path)` cache. A miss
  /// (an out-of-root directory) is never inserted, so the memo stays bounded by
  /// the distinct in-root directories the batch touched.
  entries: BTreeMap<Box<[u8]>, (u64, PathBuf)>,
  /// How many lookups were served from the cache — an operator-facing counter.
  pub(crate) hits: u64,
  /// How many lookups fell through to a fresh [`FidMap::admit`] (a cold directory
  /// or a stale-generation entry).
  pub(crate) misses: u64,
}

impl MemoBatch {
  /// A fresh, empty memo for one read batch.
  pub(crate) fn new() -> Self {
    Self {
      entries: BTreeMap::new(),
      hits: 0,
      misses: 0,
    }
  }

  /// Resolves a directory FID to its admitted path THROUGH the memo. A cached
  /// entry whose generation still matches the map's is returned directly (a hit);
  /// otherwise the lookup falls to [`FidMap::admit`] (which resolves-or-evicts and
  /// may itself bump the generation), and a resolved path is cached under the
  /// map's post-lookup generation. A miss (`None`) is not cached — the next event
  /// under that handle re-checks membership, honoring a later `learn` of it.
  fn admit(&mut self, map: &mut FidMap, fid: &Fid) -> Option<PathBuf> {
    let generation = map.generation();
    if let Some((tagged, path)) = self.entries.get(fid.handle())
      && *tagged == generation
    {
      self.hits += 1;
      return Some(path.clone());
    }
    self.misses += 1;
    let path = map.admit(fid)?;
    // `admit` may have evicted an orphan on a miss and bumped the generation, but
    // this is the hit branch (a path resolved), which mutates nothing — so the
    // post-call generation still equals the one captured above and correctly tags
    // the entry.
    self
      .entries
      .insert(fid.handle().into(), (map.generation(), path.clone()));
    Some(path)
  }
}

/// The result of admitting one decoded event against the map.
pub(crate) enum Admission {
  /// The event addresses the watched root: forward the admitted form.
  Admit(AdmittedEvent),
  /// A directory moved IN from outside the root: forward the admitted form AND
  /// first walk the moved directory's subtree so its pre-existing descendant
  /// directories enter the map. fanotify synthesizes no per-descendant creates for
  /// a rename, so without this walk later events under those descendants would
  /// drop as outside-root forever with no loss signal. The moved directory itself
  /// is already learned (marked `pending_walk` in the map); only its subtree needs
  /// seeding.
  ///
  /// The request carries the moved directory's FID, NOT a captured path: the
  /// reader resolves the directory's CURRENT path through the map at execution
  /// time, because an in-root rename in the SAME batch may have re-parented it
  /// between this admission and the deferred walk. The reader — which owns the
  /// walk context — runs the walk and escalates its incompleteness exactly as a
  /// reseed's (blind → fatal).
  AdmitAndSeed {
    /// The move event to forward once the subtree is mapped.
    event: AdmittedEvent,
    /// The moved directory's own FID — both the walk-target lookup key (its
    /// current path is resolved through the map) and the parent link every
    /// descendant the walk discovers hangs from.
    moved_fid: fid::Fid,
  },
  /// No admitted directory FID matched — the event is provably outside the
  /// root (the superblock firehose), so it is dropped without loss.
  Drop,
}

/// Admits one decoded event against the per-root map: resolves its directory
/// FID(s) to path(s) — through the batch [`MemoBatch`] — and self-maintains the
/// map (learn on a directory create, forget on a directory delete/rename-out).
/// PURE — the reader calls this single-threaded between reads; the FFI side owns
/// nothing but the fd and the seeding walk. No node identity is produced;
/// admission is membership + path resolution only (design §4.9).
///
/// Membership is the whole filter: a `dir_fid` absent from the map is outside
/// the watched root and dropped. Renames admit if EITHER end is in-root (a
/// move into or out of the tree is still the tree's business); an in-root end
/// resolves fully, an out-of-root end resolves to `None` and the lowering
/// treats the half as a boundary crossing.
pub(crate) fn admit(map: &mut FidMap, event: &RawFanotifyEvent, memo: &mut MemoBatch) -> Admission {
  if let Some(rename) = &event.rename {
    return admit_rename(map, event, rename, memo);
  }

  let Some(dir_fid) = &event.dir_fid else {
    // A dirent event with no directory FID is unaddressable; a self-event's
    // own FID also arrives here as `dir_fid`. Either way, without a handle to
    // test membership on, the event cannot be placed under the root.
    return Admission::Drop;
  };
  let Some(dir_path) = memo.admit(map, dir_fid) else {
    return Admission::Drop;
  };

  let mask = event.mask;
  // A self-event (the admitted directory itself deleted or moved) carries no
  // child name and resolves to the directory's own path.
  if (mask.delete_self() || mask.move_self()) && event.name.is_none() {
    if mask.delete_self() {
      map.forget(dir_fid);
    }
    return Admission::Admit(AdmittedEvent {
      mask,
      path: Some(dir_path),
      rename: None,
    });
  }

  let path = event.name.as_ref().map(|name| join_name(&dir_path, name));

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
    rename: None,
  })
}

/// Admits a `FAN_RENAME`: resolves both directory FIDs and self-maintains the map
/// for a moved DIRECTORY (no identity — see [`admit`]).
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
///   learning the moved dir itself as a `pending_walk` top this returns
///   [`Admission::AdmitAndSeed`] carrying the moved FID — the reader resolves the
///   dir's current path through the map and walks the subtree in before
///   forwarding, keeping the completeness invariant even if a later in-root rename
///   in the same batch re-parents the node first.
/// - **move-out** (moved dir known, destination outside): forget the moved dir; its
///   descendants' parent links now point at an absent handle, so their walks break
///   and they evict lazily — the map stops admitting the departed subtree naturally.
/// - **move-out of an already-unknown subtree** (moved dir unknown, destination
///   outside): nothing to maintain; only the in-root SOURCE end resolves, and the
///   move admits as a boundary crossing.
fn admit_rename(
  map: &mut FidMap,
  event: &RawFanotifyEvent,
  rename: &RenameInfo,
  memo: &mut MemoBatch,
) -> Admission {
  let old_dir = memo.admit(map, &rename.old_dir);
  let new_dir = memo.admit(map, &rename.new_dir);
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

  let moved_fid = event.target_fid.as_ref();

  let event = AdmittedEvent {
    mask: event.mask,
    path: None,
    rename: Some(AdmittedRename { old_path, new_path }),
  };

  if event.mask.ondir()
    && let Some(fid) = moved_fid
  {
    if new_dir.is_some() {
      // The moved object was already a known directory IFF it was in-root before
      // the move — the discriminator between the two in-root-destination flavors.
      // Read it BEFORE `learn` overwrites the node.
      let was_in_root = map.contains(fid);
      if was_in_root {
        // In-root re-parent: `learn` overwrites the node in place, and its
        // already-mapped descendants follow via the updated parent link. No
        // pruning forget (the object did not depart), and no walk (its
        // descendants are already mapped).
        map.learn(&rename.new_dir, &rename.new_name, Some(fid));
      } else {
        // Moved IN from outside: learn the top as a `pending_walk` node (so a
        // `NotFound` at its resolved path during the deferred walk is an
        // incompleteness, not a benign empty walk), then hand the reader its FID
        // to walk the pre-existing descendants in — no per-descendant creates
        // arrive for a rename, so the map is only complete once the walk runs.
        // The walk resolves the CURRENT path through the map, so an in-root rename
        // later in this batch that re-parents the node is followed correctly.
        map.learn_moved_in(&rename.new_dir, &rename.new_name, fid);
        return Admission::AdmitAndSeed {
          event,
          moved_fid: fid.clone(),
        };
      }
    } else {
      // Moved OUT of the root: drop admission (departed). A later move back is a
      // fresh move-in — walked in — the conservative direction.
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

/// Encodes the file handle of the directory `dirfd` ITSELF via
/// `name_to_handle_at(dirfd, "", AT_EMPTY_PATH)` — the fd-relative encoder every
/// caller uses (the pre-live `Backend::Auto` probe on the pinned root, and the
/// live seed/reseed walk on each pinned directory). Because it names no path, no
/// name resolution can redirect it: the handle is taken from exactly the object
/// the caller pinned (opened `O_NOFOLLOW`/`RESOLVE_NO_SYMLINKS` and
/// fstat-verified), so neither a swap of the root path at spawn nor a foreign
/// directory swapped in for a listed name post-live can have its handle seed the
/// admission map (the scope-fence invariant on [`source`]). See
/// [`encode_handle_sized`] for the dynamic `EOVERFLOW`-retry sizing and the
/// returned byte layout.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) fn encode_handle_at(
  dirfd: std::os::fd::BorrowedFd<'_>,
) -> Option<std::boxed::Box<[u8]>> {
  use std::os::fd::AsRawFd;

  // SAFETY: the empty C string literal lives for the call; `dirfd` is a live open
  // directory fd (the caller pins it before this); AT_EMPTY_PATH makes the call
  // operate on `dirfd` directly rather than resolving a name under it.
  unsafe { encode_handle_sized(dirfd.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH) }
}

/// The shared `name_to_handle_at` core, DYNAMICALLY sizing the buffer: `struct
/// file_handle` is a flexible-array type, and a filesystem whose handle exceeds
/// the initial `MAX_HANDLE_SZ` request answers `EOVERFLOW` with the true size
/// written back into `handle_bytes` — so a single fixed buffer would turn an
/// oversized-handle filesystem (which CAN export handles) into a spurious
/// "unsupported". The loop grows to the reported size and retries exactly once;
/// a second `EOVERFLOW` is a lying kernel and fails.
///
/// `dirfd`/`cpath`/`at_flags` are passed straight to `name_to_handle_at`: the
/// path encoder passes `(AT_FDCWD, path, 0)`, the fd encoder passes `(fd, "",
/// AT_EMPTY_PATH)`. Returns the FID handle bytes — `handle_type` (native-endian)
/// followed by the opaque bytes — byte-identical to the event-side decode, so a
/// seed FID matches the kernel's event FIDs exactly. `None` when the filesystem
/// cannot encode a handle for this object (a non-exporting fs, a
/// permission/transient failure, or the double-`EOVERFLOW` broken-kernel case).
///
/// # Safety
///
/// `cpath` must be a valid NUL-terminated pointer that stays live for the call,
/// and `dirfd` must be `AT_FDCWD` or a valid open directory fd matching
/// `at_flags` (an empty path requires `AT_EMPTY_PATH`).
#[cfg(all(target_os = "linux", not(miri)))]
unsafe fn encode_handle_sized(
  dirfd: libc::c_int,
  cpath: *const libc::c_char,
  at_flags: libc::c_int,
) -> Option<std::boxed::Box<[u8]>> {
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
    // a valid NUL-terminated pointer for `at_flags`; mount_id is a valid
    // out-param; dirfd is AT_FDCWD or a live directory fd (caller contract).
    let rc = unsafe { libc::name_to_handle_at(dirfd, cpath, handle, &mut mount_id, at_flags) };
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
