//! The per-root FID map: the superblock-firehose filter AND the identity
//! intern table.
//!
//! `FAN_MARK_FILESYSTEM` scopes to the whole superblock, so the stream carries
//! every event on the filesystem — including outside the watched root and via
//! bind mounts elsewhere. Admission is pure directory MEMBERSHIP: a seeded set
//! of directory handles answers `admit` in O(depth) with no syscall; an unknown
//! directory handle is provably outside the root and dropped. New in-root
//! directories enter through their own create events (the child's
//! `FAN_REPORT_TARGET_FID`, learned here); a loss reseeds the whole map.
//!
//! # Handle-keyed, never fsid-keyed
//!
//! One `FAN_MARK_FILESYSTEM` mark covers exactly one superblock, and a file
//! handle is unique within a superblock — so the map keys on the handle BYTES
//! alone. The fsid buys nothing here (every in-root object shares the mark's
//! superblock) and actively breaks btrfs: the kernel stamps events with the
//! per-superblock fsid, while `statfs` on a subvolume reports a per-subvolume
//! id, so a seeded FID's fsid can differ from the same object's event fsid.
//! Keying on the handle sidesteps that divergence entirely — admission never
//! reads an fsid.
//!
//! # Parent-relative paths, never absolute
//!
//! Each directory stores its own name plus a link to its PARENT's handle, and a
//! path resolves by walking those links up to the root anchor. This mirrors the
//! Monitor's watch tree: a directory rename updates ONE node's `(parent, name)`
//! and every descendant's resolved path follows automatically, with no per-node
//! rewrite. A rename OUT of the root re-parents the moved directory onto an
//! absent (non-admitted) parent — the walk then fails and the whole subtree
//! stops admitting naturally. Eviction is lazy: the rename is O(1), and a
//! descendant whose ancestry no longer reaches the root simply misses admission
//! (its stale node is dropped on that miss).
//!
//! # Identity, never recycled
//!
//! The map is ALSO the identity table: `intern` mints exact, sequential ids for
//! handles — never a hash of the handle (a collision would fabricate identity,
//! the class the exact table exists to kill), and the handle already embeds a
//! generation counter, making this stronger identity than `(dev, ino)`. The
//! intern table SURVIVES a reseed (identities are stable for the scope's life);
//! only the admission structure is rebuilt. Memory is O(directories under the
//! root) — file identity stays enumerate-sourced, never retained here.
//!
//! The map is single-threaded: the reader owns it and both mutates (learn on
//! create, forget on delete/rename, reseed on loss) and reads (admit/intern) it
//! between reads, exactly as the inotify reader owns its `wd` table.

use std::{
  collections::BTreeMap,
  ffi::{OsStr, OsString},
  num::NonZeroU64,
  path::{Path, PathBuf},
};

use super::fid::Fid;

/// A directory handle's bytes, the map's key. A handle is unique within the
/// mark's single superblock, so the bytes alone identify the directory (no fsid
/// — see the module docs on the btrfs divergence).
type HandleKey = Box<[u8]>;

/// One directory the seeding/reseeding walk discovered, ready to enter the map.
/// The walk knows each directory's parent, so the map can store the
/// parent-relative structure directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedEntry {
  /// The directory's FID (from `name_to_handle_at` on the FFI side).
  pub(crate) fid: Fid,
  /// The parent directory's FID, or `None` for the root anchor.
  pub(crate) parent: Option<Fid>,
  /// The directory's own name under its parent; for the root anchor, its
  /// absolute path (the walk's starting point).
  pub(crate) name: OsString,
}

impl SeedEntry {
  /// The root anchor entry: no parent, `name` carrying the absolute root path.
  pub(crate) fn root(fid: Fid, root: &Path) -> Self {
    Self {
      fid,
      parent: None,
      name: root.as_os_str().to_os_string(),
    }
  }

  /// A child directory entry under `parent`, named `name`.
  pub(crate) fn child(fid: Fid, parent: Fid, name: OsString) -> Self {
    Self {
      fid,
      parent: Some(parent),
      name,
    }
  }
}

/// One admitted directory: its parent link and its own name. A path resolves by
/// walking `parent` up to the root anchor (`parent == None`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirNode {
  /// The parent directory's handle key, or `None` for the root anchor.
  parent: Option<HandleKey>,
  /// This directory's name under its parent; for the root anchor, its absolute
  /// path.
  name: OsString,
}

/// The per-root FID map. Directory membership is the admission filter; the
/// interned ids are the exact object identities.
#[derive(Debug, Default)]
pub(crate) struct FidMap {
  /// The admitted directories: `handle → parent-relative node`. Membership
  /// decides admission; the parent chain resolves an event's path against the
  /// root.
  dirs: BTreeMap<HandleKey, DirNode>,
  /// The exact identity intern table: `handle → sequential id`. Spans every
  /// handle ever interned (directories AND file targets), so one object always
  /// maps to one id for the scope's life — and it SURVIVES a reseed.
  ids: BTreeMap<HandleKey, NonZeroU64>,
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

  /// Seeds the map from a root walk: every entry is an admitted directory, and
  /// each carries its parent link so the parent-relative structure is built
  /// directly. The walk itself lives in the FFI module (`name_to_handle_at`
  /// per dir); the map only records what it produced.
  pub(crate) fn seed(&mut self, entries: impl IntoIterator<Item = SeedEntry>) {
    for entry in entries {
      self.insert_dir(entry);
    }
  }

  /// The admitted directory's path, or `None` when the handle is unknown —
  /// provably outside the watched root — OR when the directory's ancestry no
  /// longer reaches the root (a subtree orphaned by a move-out). Either way the
  /// caller drops the event. This is the whole superblock-firehose filter: pure
  /// membership + a parent walk, no fsid compare and no syscall.
  ///
  /// An orphaned directory is EVICTED here: once its walk fails to reach the
  /// root, the stale node is dropped so it never resolves again (lazy eviction
  /// — the O(1) move-out left it for this miss to clean up).
  pub(crate) fn admit(&mut self, fid: &Fid) -> Option<PathBuf> {
    match self.resolve(fid.handle()) {
      Some(path) => Some(path),
      None => {
        self.dirs.remove(fid.handle());
        None
      }
    }
  }

  /// The exact, stable identity of `fid`, minted sequentially on first sight
  /// and returned unchanged forever after. Never a hash of the handle.
  pub(crate) fn intern(&mut self, fid: &Fid) -> NonZeroU64 {
    if let Some(id) = self.ids.get(fid.handle()) {
      return *id;
    }
    let id = NonZeroU64::new(self.next_id).expect("identity counter starts at one");
    self.next_id += 1;
    self.ids.insert(fid.handle().into(), id);
    id
  }

  /// Records a newly-created in-root directory so its own later events admit.
  /// Called from a `FAN_CREATE` whose subject is a directory (`FAN_ONDIR`)
  /// carrying the child's `TARGET_FID`: the parent must already be admitted
  /// (its link anchors the child), else the create is outside the root and
  /// ignored. A `child_fid` of `None` (a create with no target FID) cannot
  /// self-maintain and is skipped — the eventual admission comes from a reseed.
  pub(crate) fn learn(&mut self, dir_fid: &Fid, name: &[u8], child_fid: Option<&Fid>) {
    let Some(child_fid) = child_fid else {
      return;
    };
    if !self.dirs.contains_key(dir_fid.handle()) {
      return;
    }
    let Some(name) = os_name(name) else {
      return;
    };
    self.insert_dir(SeedEntry::child(
      child_fid.clone(),
      dir_fid.clone(),
      name.as_os_str().to_os_string(),
    ));
  }

  /// Drops a directory from admission on its delete or rename-out. Its interned
  /// id is retained (identities are never recycled — a later stale record for
  /// the same handle keeps its old identity rather than colliding with a fresh
  /// object's), so only membership is forgotten. Descendants are NOT touched:
  /// their parent link now points at an absent handle, so their walk fails and
  /// they evict lazily at their next admission miss.
  pub(crate) fn forget(&mut self, fid: &Fid) {
    self.dirs.remove(fid.handle());
  }

  /// Rebuilds the admission structure from a fresh full walk after a loss, then
  /// swaps it in — the simplest correct prune. Directories that vanished during
  /// the loss window are gone (the fresh walk did not observe them); directories
  /// the firehose missed during the window are present (the walk did). The
  /// intern table is untouched, so every identity stays stable across the
  /// reseed. A `FAN_Q_OVERFLOW` (or any lossy decode) funnels here so a covered
  /// overflow can never become permanent blindness.
  pub(crate) fn reseed(&mut self, entries: impl IntoIterator<Item = SeedEntry>) {
    self.dirs.clear();
    self.seed(entries);
  }

  /// Whether `fid` is an admitted directory whose ancestry still reaches the
  /// root.
  #[cfg(test)]
  pub(crate) fn contains_dir(&mut self, fid: &Fid) -> bool {
    self.admit(fid).is_some()
  }

  /// The number of stored directory nodes (the map's O(directories) footprint).
  /// Orphaned-but-not-yet-evicted nodes still count until their admission miss.
  #[cfg(test)]
  pub(crate) fn dir_count(&self) -> usize {
    self.dirs.len()
  }

  /// Resolves a directory handle to its absolute path by walking parent links
  /// up to the root anchor. `None` when the handle is unknown or the chain
  /// breaks before the root (a break marks an orphaned subtree). The depth is
  /// bounded by the tree height; a cycle (structurally impossible from a walk,
  /// but never trusted) is broken by a hop counter capped at the node count.
  fn resolve(&self, handle: &[u8]) -> Option<PathBuf> {
    let mut components: Vec<&OsStr> = Vec::new();
    let mut cursor = handle;
    let mut guard = self.dirs.len() + 1;
    loop {
      let node = self.dirs.get(cursor)?;
      match &node.parent {
        None => {
          // The root anchor: its name is the absolute base path.
          let mut path = PathBuf::from(&node.name);
          for component in components.iter().rev() {
            path.push(component);
          }
          return Some(path);
        }
        Some(parent) => {
          components.push(&node.name);
          cursor = parent;
        }
      }
      guard -= 1;
      if guard == 0 {
        return None;
      }
    }
  }

  fn insert_dir(&mut self, entry: SeedEntry) {
    // Interning on insert keeps a directory's admission and its identity minted
    // together, so an admitted directory always has a stable id.
    self.intern(&entry.fid);
    let parent = entry.parent.map(|fid| fid.handle().into());
    self.dirs.insert(
      entry.fid.handle().into(),
      DirNode {
        parent,
        name: entry.name,
      },
    );
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
