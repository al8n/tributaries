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
//! Root death (unmount / replace) carries NO in-tree fanotify signal — an
//! unmounted `FAN_MARK_FILESYSTEM` superblock stays alive under the mark and the
//! fd simply goes quiet (design §7, container-validated). Detection is instead
//! the mount refresh's folded-in root re-stat (`FsOps::refresh_mounts` →
//! `MountRefresh.root`), compared against the barrier identity in
//! `DriverCore::on_mounts_refreshed`: a missing/replaced root lowers the same
//! `DeleteSelf`/`MoveSelf` death lifecycle a macOS `RootChanged` probe uses. The
//! refresh runs at scope birth and on every loss signal, so **that cadence is
//! the honest detection latency** — no timer, no new effect; an unmount with no
//! following loss is seen at the next loss-armed refresh, and the watcher stays
//! quiet-but-alive until then.

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
  let identity = event.target_fid.as_ref().map(|fid| map.intern(fid));

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
/// for a moved directory (forget the old admission, learn the new one), and
/// interns the moved object's identity from whichever end supplies a target
/// FID.
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

  // A directory move within/into/out of the root maintains admission: the old
  // handle stops admitting, the new one re-enters under the destination
  // directory (when that end is in-root and the object's FID is known).
  let moved_fid = event.target_fid.as_ref();
  let identity = moved_fid.map(|fid| map.intern(fid));
  if event.mask.ondir()
    && let Some(fid) = moved_fid
  {
    map.forget(fid);
    if new_dir.is_some() {
      map.learn(&rename.new_dir, &rename.new_name, Some(fid));
    }
  }

  Admission::Admit(AdmittedEvent {
    mask: event.mask,
    path: None,
    identity: None,
    rename: Some(AdmittedRename {
      old_path,
      new_path,
      identity,
    }),
  })
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

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) mod reader;

#[cfg(all(target_os = "linux", not(miri)))]
#[allow(unused_imports)]
pub(crate) use source::{Source, SourceHandle};

#[cfg(all(target_os = "linux", not(miri)))]
mod source;
