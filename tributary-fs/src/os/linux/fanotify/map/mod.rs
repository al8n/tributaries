//! The per-root FID map: the superblock-firehose filter AND the identity
//! intern table.
//!
//! `FAN_MARK_FILESYSTEM` scopes to the whole superblock, so the stream carries
//! every event on the filesystem — including outside the watched root and via
//! bind mounts elsewhere. Admission is pure directory-FID MEMBERSHIP: a seeded
//! `fid → path` map answers `admit` in O(1) with no syscall; an unknown
//! directory handle is provably outside the root and dropped. New in-root
//! directories enter through their own create events (the child's
//! `FAN_REPORT_TARGET_FID`, learned here); a rescan re-seeds a subtree.
//!
//! The map is ALSO the identity table: `intern` mints exact, sequential ids
//! for handles — never a hash of the handle (a collision would fabricate
//! identity, the class the exact table exists to kill), and the handle already
//! embeds a generation counter, making this stronger identity than
//! `(dev, ino)`. Memory is O(directories under the root) — file identity stays
//! enumerate-sourced, never retained here.
//!
//! The map is single-threaded: the reader owns it and both mutates (learn on
//! create, forget on delete/rename) and reads (admit/intern) it between reads,
//! exactly as the inotify reader owns its `wd` table.
//!
//! Admission NEVER compares fsids. On btrfs the event-fsid is per-superblock
//! while `statfs` on a subvolume reports a per-subvolume id, so an fsid test
//! would wrongly reject in-root subvolume events; handle membership is the only
//! correct filter.

use std::{
  collections::BTreeMap,
  num::NonZeroU64,
  path::{Path, PathBuf},
};

use super::fid::Fid;

/// One directory the seeding walk discovered, ready to enter the map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedEntry {
  /// The directory's FID (from `name_to_handle_at` on the FFI side).
  pub(crate) fid: Fid,
  /// The directory's absolute path.
  pub(crate) path: PathBuf,
}

impl SeedEntry {
  /// Builds a seed entry pairing a directory FID with its path.
  pub(crate) fn new(fid: Fid, path: PathBuf) -> Self {
    Self { fid, path }
  }
}

/// The per-root FID map. Directory membership is the admission filter; the
/// interned ids are the exact object identities.
#[derive(Debug, Default)]
pub(crate) struct FidMap {
  /// The admitted directories: `fid → absolute path`. Membership decides
  /// admission; the path resolves events against the root.
  dirs: BTreeMap<Fid, PathBuf>,
  /// The exact identity intern table: `fid → sequential id`. Spans every
  /// handle ever interned (directories AND file targets), so one object always
  /// maps to one id for the scope's life.
  ids: BTreeMap<Fid, NonZeroU64>,
  /// The next identity to hand out. Sequential and exact — a fresh handle gets
  /// a fresh id, never a hash of its bytes.
  next_id: u64,
}

impl FidMap {
  /// An empty map, ready to be seeded.
  pub(crate) fn new() -> Self {
    Self {
      dirs: BTreeMap::new(),
      ids: BTreeMap::new(),
      next_id: 1,
    }
  }

  /// Seeds the map from a root walk: every entry is an admitted directory.
  /// The walk itself lives in the FFI module (`name_to_handle_at` per dir);
  /// the map only records what it produced.
  pub(crate) fn seed(&mut self, entries: impl IntoIterator<Item = SeedEntry>) {
    for entry in entries {
      self.insert_dir(entry.fid, entry.path);
    }
  }

  /// The admitted directory's path, or `None` when the handle is unknown —
  /// provably outside the watched root, so the caller drops the event. This is
  /// the whole superblock-firehose filter: pure membership, no fsid compare.
  pub(crate) fn admit(&self, fid: &Fid) -> Option<&Path> {
    self.dirs.get(fid).map(PathBuf::as_path)
  }

  /// The exact, stable identity of `fid`, minted sequentially on first sight
  /// and returned unchanged forever after. Never a hash of the handle.
  pub(crate) fn intern(&mut self, fid: &Fid) -> NonZeroU64 {
    if let Some(id) = self.ids.get(fid) {
      return *id;
    }
    let id = NonZeroU64::new(self.next_id).expect("identity counter starts at one");
    self.next_id += 1;
    self.ids.insert(fid.clone(), id);
    id
  }

  /// Records a newly-created in-root directory so its own later events admit.
  /// Called from a `FAN_CREATE` whose subject is a directory (`FAN_ONDIR`)
  /// carrying the child's `TARGET_FID`: the parent must already be admitted
  /// (its path anchors the child's), else the create is outside the root and
  /// ignored. A `child_fid` of `None` (a create with no target FID) cannot
  /// self-maintain and is skipped — the eventual admission comes from a
  /// rescan.
  pub(crate) fn learn(&mut self, dir_fid: &Fid, name: &[u8], child_fid: Option<&Fid>) {
    let Some(child_fid) = child_fid else {
      return;
    };
    let Some(parent) = self.dirs.get(dir_fid) else {
      return;
    };
    let Some(name) = os_name(name) else {
      return;
    };
    let path = parent.join(name);
    self.insert_dir(child_fid.clone(), path);
  }

  /// Drops a directory from admission on its delete or rename-out. Its interned
  /// id is retained (identities are never recycled — a later stale record for
  /// the same handle keeps its old identity rather than colliding with a fresh
  /// object's), so only membership is forgotten.
  pub(crate) fn forget(&mut self, fid: &Fid) {
    self.dirs.remove(fid);
  }

  /// Re-seeds a subtree after a rescan healed it: the affected directories are
  /// re-admitted from a fresh walk. Directories that vanished are NOT pruned
  /// here — a delete/rename event forgets those; this hook only ADDS what a
  /// walk re-observed, so a create the firehose dropped during a loss window is
  /// recovered.
  pub(crate) fn heal(&mut self, entries: impl IntoIterator<Item = SeedEntry>) {
    self.seed(entries);
  }

  /// Whether `fid` is an admitted directory.
  #[cfg(test)]
  pub(crate) fn contains_dir(&self, fid: &Fid) -> bool {
    self.dirs.contains_key(fid)
  }

  /// The number of admitted directories (the map's O(directories) footprint).
  #[cfg(test)]
  pub(crate) fn dir_count(&self) -> usize {
    self.dirs.len()
  }

  fn insert_dir(&mut self, fid: Fid, path: PathBuf) {
    // Interning on insert keeps a directory's admission path and its identity
    // minted together, so an admitted directory always has a stable id.
    self.intern(&fid);
    self.dirs.insert(fid, path);
  }
}

/// Interprets a raw fanotify name as a path component, rejecting the
/// non-components the kernel can report (`.`, `..`, an embedded separator, or a
/// non-UTF-8 name the `Path` join could not address safely).
fn os_name(name: &[u8]) -> Option<&Path> {
  if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
    return None;
  }
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStrExt;
    Some(Path::new(std::ffi::OsStr::from_bytes(name)))
  }
  #[cfg(not(unix))]
  {
    std::str::from_utf8(name).ok().map(Path::new)
  }
}

#[cfg(test)]
mod tests;
