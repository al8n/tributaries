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
//! # Identity: directory-only, O(live directories)
//!
//! The map is ALSO the identity table: `intern` mints exact, sequential ids for
//! handles — never a hash of the handle (a collision would fabricate identity,
//! the class the exact table exists to kill), and the handle already embeds a
//! generation counter, making this stronger identity than `(dev, ino)`.
//!
//! ONLY DIRECTORY handles are interned. Directory handles are already required
//! for admission, so interning them is free; ordinary FILE events attach no
//! identity, because under the kernel-recursive Monitor profile record identity
//! is INERT — the sole consumer, `Monitor::reconcile_slot`, early-returns for a
//! non-descending scope (there are no per-directory child watches to re-arm), and
//! the atomic `FAN_RENAME` pair carries its own old+new addressing rather than
//! leaning on identity. Interning every file target FID would grow this table
//! unboundedly under create/delete churn (OOM), so it is confined to directories.
//!
//! The bound is therefore O(LIVE directories under the root). An id is pruned
//! when its directory is forgotten (delete / rename-out): a departed-and-returned
//! directory mints a FRESH identity, which the Monitor reads as a replacement —
//! the conservative, safe direction (identity inequality drives a re-observe,
//! never a false survivor). Reseed preserves every live directory's id (the
//! admission structure is rebuilt while the intern table is retained), so identity
//! is stable across a covered loss for directories that persisted through it.
//!
//! The map is single-threaded: the reader owns it and both mutates (learn on
//! create, forget on delete/rename, reseed on loss) and reads (admit/intern) it
//! between reads, exactly as the inotify reader owns its `wd` table.
//!
//! # Completeness invariant
//!
//! Admission is membership, so a directory the map does not know drops ITS events
//! as outside-root with no loss signal — a silently-blind subtree. The map is
//! therefore kept COMPLETE by construction: a directory enters it only when its
//! descendants are, at that moment, one of
//!
//! - **empty** — a `FAN_CREATE` of a directory is a `mkdir`, so the learned child
//!   has no pre-existing contents ([`learn`](Self::learn));
//! - **already mapped** — an in-root directory rename re-parents a subtree whose
//!   descendants were seeded/learned before the move, and the parent-relative
//!   representation carries them under the new path with no per-node rewrite; or
//! - **walked** — a directory moved IN from outside the root carries pre-existing
//!   descendants the seed walk never saw (fanotify synthesizes no per-descendant
//!   creates for a rename), so the reader walks the moved subtree and inserts every
//!   descendant directory before forwarding the move (the walk's incompleteness
//!   escalates exactly as a reseed's, blind → fatal).
//!
//! The seed and reseed walks establish the invariant for the whole tree; `learn`
//! and the move-in walk preserve it as directories arrive.

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
  /// The exact identity intern table: `handle → sequential id`, DIRECTORIES only
  /// (file target FIDs are never interned — see the module docs on why file
  /// identity is inert under the kernel-recursive profile). Bounded by the live
  /// directory count: an entry is dropped on `forget` and re-minted fresh should
  /// the directory reappear, and it survives a reseed so a persisting directory
  /// keeps its id across a covered loss.
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

  /// Whether `fid` is a stored directory handle, WITHOUT resolving its path or
  /// evicting an orphan (unlike [`admit`](Self::admit)). This is the move-flavor
  /// discriminator: a directory rename whose moved object is already a known
  /// directory is an in-root re-parent (its descendants are already mapped),
  /// while an unknown moved object arrived from OUTSIDE the root carrying
  /// pre-existing descendants the seed walk never saw — those must be walked in.
  pub(crate) fn contains(&self, fid: &Fid) -> bool {
    self.dirs.contains_key(fid.handle())
  }

  /// The exact, stable identity of a DIRECTORY `fid`, minted sequentially on
  /// first sight and returned unchanged until the directory is forgotten. Never a
  /// hash of the handle. Called only for directory handles (self-events, seeded
  /// and learned directories) — file target FIDs are never interned, keeping the
  /// table O(live directories).
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

  /// Drops a directory from admission AND from the intern table on its delete or
  /// rename-out. Pruning the id bounds the table at O(live directories); the id
  /// is safe to drop because nothing mints it again unless the SAME handle
  /// reappears (the same object — the handle embeds a generation counter), and a
  /// departed-and-returned directory minting a fresh id is the conservative
  /// direction: the Monitor treats identity inequality as a replacement, never a
  /// false survivor. Descendants are NOT touched: their parent link now points at
  /// an absent handle, so their walk fails and they evict lazily at their next
  /// admission miss (and re-mint their own ids only if re-observed).
  pub(crate) fn forget(&mut self, fid: &Fid) {
    self.dirs.remove(fid.handle());
    self.ids.remove(fid.handle());
  }

  /// Rebuilds the admission structure from a fresh full walk after a loss, then
  /// swaps it in — the simplest correct prune. Directories that vanished during
  /// the loss window are gone (the fresh walk did not observe them); directories
  /// the firehose missed during the window are present (the walk did).
  ///
  /// A directory that PERSISTED through the loss keeps its interned id (it is
  /// re-inserted by the fresh seed, and `intern` returns the existing id for a
  /// known handle) — identity stays stable across a covered loss. A directory that
  /// VANISHED during the loss has its id pruned here: the loss ate its delete
  /// event, so `forget` never ran, and leaving its id would leak the table past
  /// O(live directories). The prune keeps live ids and drops only departed ones,
  /// so a reappearance still mints a fresh identity (the conservative direction).
  /// A `FAN_Q_OVERFLOW` (or any lossy decode) funnels here so a covered overflow
  /// can never become permanent blindness.
  pub(crate) fn reseed(&mut self, entries: impl IntoIterator<Item = SeedEntry>) {
    self.dirs.clear();
    self.seed(entries);
    // Drop ids for directories the fresh walk did not re-observe (vanished across
    // the loss). Live directories were just re-seeded, so they survive the retain
    // with their ids intact.
    let dirs = &self.dirs;
    self.ids.retain(|handle, _| dirs.contains_key(handle));
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

  /// The number of interned identities — the intern table's footprint. Bounded by
  /// the live directory count (file target FIDs are never interned, and a
  /// forgotten directory's id is pruned), so churn of files leaves it unchanged.
  #[cfg(test)]
  pub(crate) fn interned_count(&self) -> usize {
    self.ids.len()
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
