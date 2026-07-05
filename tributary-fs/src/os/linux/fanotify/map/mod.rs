//! The per-root FID map: the superblock-firehose filter — admission only.
//!
//! `FAN_MARK_FILESYSTEM` scopes to the whole superblock, so the stream carries
//! every event on the filesystem — including outside the watched root and via
//! bind mounts elsewhere. Admission is pure directory MEMBERSHIP: a seeded set
//! of directory handles answers `admit` in O(depth) with no syscall; an unknown
//! directory handle is provably outside the root and dropped. New in-root
//! directories enter through their own create events (the child's
//! `FAN_REPORT_TARGET_FID`, learned here); a loss reseeds the whole map.
//!
//! # Admission is the map's only job; identity is deliberately absent
//!
//! The map records directory membership and resolves paths — nothing else.
//! There is no identity intern table (design §4.9): under the kernel-recursive
//! Monitor profile record identity is INERT — the sole consumer,
//! `Monitor::reconcile_slot`, early-returns for a non-descending scope (there
//! are no per-directory child watches to re-arm), and the atomic `FAN_RENAME`
//! pair carries its own old+new addressing rather than leaning on a node
//! identity. Interning would only have added a directory→id table that grows
//! with the tree (and unboundedly under file churn if files were interned) for
//! a value nothing reads, so fanotify records attach NO node identity — exactly
//! as the FSEvents kernel-recursive lowering attaches none. File identity, where
//! a descending profile needs it, stays enumerate-sourced on inotify.
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
//! Each directory stores its own name, a link to its PARENT's handle, AND the
//! set of its immediate children (the dual link). A path resolves by walking the
//! parent links up to the root anchor. This mirrors the Monitor's watch tree: a
//! directory rename updates ONE node's `(parent, name)` and every descendant's
//! resolved path follows automatically, with no per-node rewrite. A departure
//! (delete / rename-out) walks the `children` adjacency to prune the WHOLE
//! subtree in O(subtree) — so a populated move-out drops every descendant at
//! once, rather than leaking them until each lingering node happens to miss
//! admission. The lazy `admit`-miss eviction remains as a belt for any residual
//! orphan a parent-chain break still leaves.
//!
//! The bound is O(LIVE directories under the root): a departed directory (and
//! every descendant, via the `children` adjacency) is dropped on `forget`, and
//! files never enter the map at all.
//!
//! # Generation counter for the reader's batch memo
//!
//! Every mutation (`seed`, `learn`, `forget`, `reseed`, an orphan eviction)
//! bumps a monotone [`generation`](Self::generation). The single-threaded reader
//! caches admitted `(dir-handle → path)` resolutions WITHIN one read batch (the
//! rename-storm win: many events under few directories), tagging each cached
//! entry with the generation it was resolved at. Because ANY mutation bumps the
//! counter, a cached entry whose generation no longer matches the map's is a
//! miss and is re-resolved — so the memo survives the mutations `admit` itself
//! performs mid-batch without ever serving a stale path. The counter lives here
//! (not the memo) so invalidation is a single comparison with no scattered
//! cache-clearing; the memo itself lives in the reader.
//!
//! The map is single-threaded: the reader owns it and both mutates (learn on
//! create, forget on delete/rename, reseed on loss) and reads (admit) it between
//! reads, exactly as the inotify reader owns its `wd` table.
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
  collections::{BTreeMap, BTreeSet},
  ffi::{OsStr, OsString},
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

/// One admitted directory: its parent link, its own name, and its immediate
/// children. A path resolves by walking `parent` up to the root anchor
/// (`parent == None`); the `children` set is the dual link the Monitor's watch
/// tree keeps, so a departure can prune the WHOLE subtree in O(subtree) rather
/// than leaking descendant ids until each hits a lazy admission miss.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirNode {
  /// The parent directory's handle key, or `None` for the root anchor.
  parent: Option<HandleKey>,
  /// This directory's name under its parent; for the root anchor, its absolute
  /// path.
  name: OsString,
  /// The handle keys of this directory's immediate child directories. Maintained
  /// as the exact inverse of every child's `parent` link (insert/learn adds,
  /// forget/re-parent moves) so `forget` can walk and prune a departed subtree in
  /// one O(subtree) pass — the eager departure the lazy per-miss eviction alone
  /// cannot deliver.
  children: BTreeSet<HandleKey>,
  /// Whether this directory was learned via a move-IN and its descendant walk
  /// has not yet completed. A move-in learns the top node before the reader runs
  /// the subtree walk; the walk resolves the node's CURRENT path through the map
  /// at execution time (an intervening in-root rename may have re-parented it),
  /// and clears this flag on completion. While set, a `NotFound` at the resolved
  /// path is an incompleteness (blind → fatal), NOT a benign empty walk: the node
  /// still being in-map proves no rename-out was processed (the single-threaded
  /// reader would have forgotten it first), so a missing directory is a genuine
  /// coverage hole rather than a moved-away race.
  pending_walk: bool,
}

/// A snapshot of the map's live footprint for the operator-facing stats
/// accessor: the number of admitted directories and the current mutation
/// generation (the batch memo's invalidation token).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MapStats {
  pub(crate) directories: usize,
  pub(crate) memo_generation: u64,
}

/// The per-root FID map: directory membership is the whole admission filter.
#[derive(Debug, Default)]
pub(crate) struct FidMap {
  /// The admitted directories: `handle → parent-relative node`. Membership
  /// decides admission; the parent chain resolves an event's path against the
  /// root.
  dirs: BTreeMap<HandleKey, DirNode>,
  /// A monotone counter bumped on every mutation, so the reader's per-batch
  /// admission memo can tag each cached path with the map state it was resolved
  /// against and treat a generation mismatch as a miss (see the module docs).
  generation: u64,
  /// The ceiling on directory nodes (design §4.9): `None` is uncapped. A live
  /// `learn` growing the map past it is a terminal condition the reader signals
  /// fatal — a capped map that silently stopped learning is the silent-loss
  /// shape. The seed/reseed walks enforce the same cap up front (an over-cap tree
  /// is fanotify-unviable), so this only guards live growth.
  max_directories: Option<usize>,
}

impl FidMap {
  /// An empty, uncapped map, ready to be seeded.
  pub(crate) fn new() -> Self {
    Self {
      dirs: BTreeMap::new(),
      generation: 0,
      max_directories: None,
    }
  }

  /// An empty map with the directory cap the options requested (design §4.9;
  /// `None` = uncapped).
  pub(crate) fn with_capacity(max_directories: Option<usize>) -> Self {
    Self {
      max_directories,
      ..Self::new()
    }
  }

  /// The current mutation generation — the token the reader's batch memo tags its
  /// cached resolutions with. Bumped by every mutation, so a memo entry whose
  /// generation differs from this is stale and must be re-resolved.
  pub(crate) fn generation(&self) -> u64 {
    self.generation
  }

  /// Bumps the generation, invalidating every batch-memo entry tagged against a
  /// prior state. Called by each mutation.
  fn bump(&mut self) {
    self.generation = self.generation.wrapping_add(1);
  }

  /// Whether the map holds MORE directory nodes than the cap allows (never true
  /// when uncapped). The reader polls this after a live `learn` and signals fatal
  /// when it trips: a capped map that keeps eventing while silently refusing to
  /// learn new directories would drop their events as outside-root forever.
  pub(crate) fn over_capacity(&self) -> bool {
    self
      .max_directories
      .is_some_and(|cap| self.dirs.len() > cap)
  }

  /// The number of MORE directory nodes the cap still admits: `cap - len`,
  /// saturating at zero so an already-over-cap map reports no room. `None` when
  /// uncapped (no ceiling to subtract against). The reader threads this into a
  /// move-in subtree walk as the walk's own directory budget, so an additive walk
  /// fences on the room ACTUALLY LEFT rather than the full cap — a near-cap map
  /// then never allocates a whole extra cap of descendants before the fatal.
  pub(crate) fn remaining_capacity(&self) -> Option<usize> {
    self
      .max_directories
      .map(|cap| cap.saturating_sub(self.dirs.len()))
  }

  /// A snapshot of the map's live footprint, for the operator-facing stats
  /// accessor.
  pub(crate) fn stats(&self) -> MapStats {
    MapStats {
      directories: self.dirs.len(),
      memo_generation: self.generation,
    }
  }

  /// Seeds the map from a root walk: every entry is an admitted directory, and
  /// each carries its parent link so the parent-relative structure is built
  /// directly. The walk itself lives in the FFI module (`name_to_handle_at`
  /// per dir); the map only records what it produced.
  pub(crate) fn seed(&mut self, entries: impl IntoIterator<Item = SeedEntry>) {
    for entry in entries {
      self.insert_dir(entry, false);
    }
    // The walk is the sole cap fence: it stops (anchor included) at the ceiling,
    // so the vec `seed` receives already fits the cap — this map should never
    // exceed it after a fresh seed. Pin that here so a future walk change that
    // let an over-cap vec through would trip in tests rather than silently build
    // a map the live `over_capacity` fatal must then catch. (`reseed` clears
    // first, so it too seeds a fresh map against the full cap.)
    debug_assert!(
      !self.over_capacity(),
      "a seed vec must already fit the directory cap: the walk fences it"
    );
  }

  /// The admitted directory's path, or `None` when the handle is unknown —
  /// provably outside the watched root — OR when the directory's ancestry no
  /// longer reaches the root (a subtree orphaned by a move-out). Either way the
  /// caller drops the event. This is the whole superblock-firehose filter: pure
  /// membership + a parent walk, no fsid compare and no syscall.
  ///
  /// An orphaned directory is EVICTED here: once its walk fails to reach the
  /// root, its stale node AND any still-attached descendants are pruned so
  /// nothing resolves again. This is a belt — `forget` already prunes a departed
  /// subtree eagerly via the adjacency — for any residual orphan a break in the
  /// parent chain still leaves behind.
  pub(crate) fn admit(&mut self, fid: &Fid) -> Option<PathBuf> {
    match self.resolve(fid.handle()) {
      Some(path) => Some(path),
      None => {
        self.evict_orphan(fid.handle());
        None
      }
    }
  }

  /// Evicts an orphan (a node whose parent chain no longer reaches the root) and
  /// its still-attached descendants, unlinking it from its parent (a no-op when
  /// the parent is already gone). A node ABSENT from the map — the hot
  /// firehose-drop path, an unknown handle provably outside the root — is left
  /// untouched after the single membership check, so the drop stays cheap (and the
  /// generation does not bump). Belt for the lazy path: `forget` prunes eagerly,
  /// so this only fires on a residual orphan.
  fn evict_orphan(&mut self, handle: &[u8]) {
    let key: HandleKey = handle.into();
    let Some(node) = self.dirs.get(&key) else {
      return;
    };
    if let Some(parent) = node.parent.clone()
      && let Some(parent_node) = self.dirs.get_mut(&parent)
    {
      parent_node.children.remove(&key);
    }
    self.prune_subtree(key);
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

  /// Whether `fid` is the map's ROOT ANCHOR — the one node whose parent link is
  /// `None` (every other node names a parent). This is the root-FID knowledge the
  /// admission classifier consults to route a self-event on the watched root to the
  /// death lifecycle: the anchor holds the root's own handle (encoded from the spawn
  /// pin and pinned across reseeds by the anchor-match gate), so a `DELETE_SELF`/
  /// `MOVE_SELF` whose self-FID answers `true` here is the root's own death — even
  /// in the FID-only shape the periodic liveness tick would otherwise be the sole
  /// detector of. Handle-keyed like the whole map, so the kernel's per-superblock
  /// event fsid never enters the decision (the btrfs divergence).
  pub(crate) fn is_root(&self, fid: &Fid) -> bool {
    self
      .dirs
      .get(fid.handle())
      .is_some_and(|node| node.parent.is_none())
  }

  /// Records a newly-created in-root directory so its own later events admit.
  /// Called from a `FAN_CREATE` whose subject is a directory (`FAN_ONDIR`)
  /// carrying the child's `TARGET_FID`: the parent must already be admitted
  /// (its link anchors the child), else the create is outside the root and
  /// ignored. A `child_fid` of `None` (a create with no target FID) cannot
  /// self-maintain and is skipped — the eventual admission comes from a reseed.
  pub(crate) fn learn(&mut self, dir_fid: &Fid, name: &[u8], child_fid: Option<&Fid>) {
    self.learn_inner(dir_fid, name, child_fid, false);
  }

  /// Learns a directory MOVED IN from outside the root (or re-parented onto a new
  /// in-root parent) as a move-in top, marking it `pending_walk` so the reader's
  /// subtree walk knows a `NotFound` at its resolved path is an incompleteness,
  /// not a benign empty walk. Same admission rule as [`learn`]: the destination
  /// parent must already be in-root, else the move is outside the root and
  /// ignored. Used only when the moved object was NOT already a known directory
  /// (an in-root re-parent of an already-mapped dir uses [`learn`] — its
  /// descendants are already mapped, so no walk and no pending flag).
  pub(crate) fn learn_moved_in(&mut self, dir_fid: &Fid, name: &[u8], child_fid: &Fid) {
    self.learn_inner(dir_fid, name, Some(child_fid), true);
  }

  fn learn_inner(
    &mut self,
    dir_fid: &Fid,
    name: &[u8],
    child_fid: Option<&Fid>,
    pending_walk: bool,
  ) {
    let Some(child_fid) = child_fid else {
      return;
    };
    if !self.dirs.contains_key(dir_fid.handle()) {
      return;
    }
    let Some(name) = os_name(name) else {
      return;
    };
    self.insert_dir(
      SeedEntry::child(
        child_fid.clone(),
        dir_fid.clone(),
        name.as_os_str().to_os_string(),
      ),
      pending_walk,
    );
  }

  /// Resolves a move-in top's CURRENT path through the map (its parent chain,
  /// which an intervening in-root rename may have re-parented since the move was
  /// admitted) for the reader's deferred subtree walk. The returned flag is the
  /// node's `pending_walk` state: `true` means the walk still owes descendants
  /// (a `NotFound` there is an incompleteness), `false` means an intervening
  /// event already cleared it (a queued re-run is a no-op the reader can skip).
  /// `None` when the node is gone (forgotten/orphaned before the walk ran — the
  /// reader cancels the walk).
  pub(crate) fn pending_walk_target(&self, fid: &Fid) -> Option<(PathBuf, bool)> {
    let pending = self.dirs.get(fid.handle())?.pending_walk;
    let path = self.resolve(fid.handle())?;
    Some((path, pending))
  }

  /// Clears a move-in top's `pending_walk` flag once its subtree walk completes,
  /// so a later `NotFound` at its path is again a benign vanished-race (the walk
  /// no longer owes descendants). A no-op if the node is gone.
  pub(crate) fn clear_pending_walk(&mut self, fid: &Fid) {
    if let Some(node) = self.dirs.get_mut(fid.handle()) {
      node.pending_walk = false;
    }
  }

  /// Drops a directory AND its whole subtree from admission on its delete or
  /// rename-out, walking the `children` adjacency so every departed descendant is
  /// pruned in the SAME O(subtree) step — not left to leak until each hits a lazy
  /// admission miss. This bounds the map at O(live directories). The forgotten
  /// node is also unlinked from its parent's `children`, keeping the adjacency the
  /// exact inverse of the parent links.
  pub(crate) fn forget(&mut self, fid: &Fid) {
    let key: HandleKey = fid.handle().into();
    if let Some(node) = self.dirs.get(&key)
      && let Some(parent) = node.parent.clone()
      && let Some(parent_node) = self.dirs.get_mut(&parent)
    {
      parent_node.children.remove(&key);
    }
    self.prune_subtree(key);
  }

  /// Removes `root` and every directory reachable through the `children`
  /// adjacency. Iterative (an explicit stack, no recursion-depth bound on a deep
  /// subtree) and bounded by the subtree's node count. The starting node is
  /// assumed already unlinked from its parent by the caller. Bumps the generation
  /// only when a node was actually removed, so a no-op prune (an unknown handle)
  /// leaves the batch memo valid.
  fn prune_subtree(&mut self, root: HandleKey) {
    let mut stack = vec![root];
    let mut removed = false;
    while let Some(key) = stack.pop() {
      if let Some(node) = self.dirs.remove(&key) {
        removed = true;
        stack.extend(node.children);
      }
    }
    if removed {
      self.bump();
    }
  }

  /// Rebuilds the admission structure from a fresh full walk after a loss, then
  /// swaps it in — the simplest correct prune. Directories that vanished during
  /// the loss window are gone (the fresh walk did not observe them); directories
  /// the firehose missed during the window are present (the walk did). A
  /// `FAN_Q_OVERFLOW` (or any lossy decode) funnels here so a covered overflow can
  /// never become permanent blindness.
  ///
  /// The `children` adjacency is rebuilt from the fresh walk: `dirs.clear()` drops
  /// every stale node, and the walk emits parents before children (DFS), so each
  /// `insert_dir` links the child under an already-present parent — the adjacency
  /// is consistent by construction after the swap. The clear-then-rebuild bumps
  /// the generation, so any batch-memo entry from before the reseed misses.
  pub(crate) fn reseed(&mut self, entries: impl IntoIterator<Item = SeedEntry>) {
    self.dirs.clear();
    self.bump();
    self.seed(entries);
  }

  /// Whether `fid` is an admitted directory whose ancestry still reaches the
  /// root.
  #[cfg(test)]
  pub(crate) fn contains_dir(&mut self, fid: &Fid) -> bool {
    self.admit(fid).is_some()
  }

  /// The admitted directory's path WITHOUT the orphan-eviction side effect of
  /// [`admit`](Self::admit) — a read-only resolution for the admission-classifier
  /// oracle, which must decide a FID's admittance against a fixed pre-classify map
  /// state. `Some` exactly when [`admit`](Self::admit) would resolve it (the handle
  /// is stored and its ancestry reaches the root).
  #[cfg(test)]
  pub(crate) fn resolve_path(&self, fid: &Fid) -> Option<PathBuf> {
    self.resolve(fid.handle())
  }

  /// The number of stored directory nodes (the map's O(directories) footprint).
  /// Orphaned-but-not-yet-evicted nodes still count until their admission miss.
  #[cfg(test)]
  pub(crate) fn dir_count(&self) -> usize {
    self.dirs.len()
  }

  /// Asserts the `children` adjacency is the exact inverse of the parent links
  /// (mirroring the Monitor's `assert_invariants`): every node listed in a
  /// parent's `children` exists and names that parent, and every node's parent
  /// (when present) lists it back. A drift here is a maintenance-site bug — a
  /// missing dual link would leave a departed subtree un-pruned.
  #[cfg(test)]
  pub(crate) fn assert_adjacency(&self) {
    for (key, node) in &self.dirs {
      for child in &node.children {
        let child_node = self
          .dirs
          .get(child)
          .expect("a child in an adjacency set must exist as a node");
        assert_eq!(
          child_node.parent.as_deref(),
          Some(&key[..]),
          "a node in a parent's children set must name that parent"
        );
      }
      if let Some(parent) = &node.parent {
        let parent_node = self
          .dirs
          .get(parent)
          .expect("a node's parent must exist as a node");
        assert!(
          parent_node.children.contains(key),
          "a node's parent must list it as a child"
        );
      }
    }
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

  /// Inserts (or re-parents in place) one directory node, maintaining the parent
  /// `children` adjacency both ways. `pending_walk` marks a move-in top whose
  /// descendant walk has not yet run. A key already present is a RE-PARENT (an
  /// in-root rename overwriting the node): its existing `children` are preserved
  /// (they move with it via the parent link, not by rewrite) and it is unlinked
  /// from its old parent before being linked under the new one.
  ///
  /// A re-parent PRESERVES an existing `pending_walk` (the requested flag is OR-ed
  /// with it): an in-root rename of a move-in top that has NOT yet been walked
  /// (`learn`, requesting `false`) must not discharge the outstanding obligation —
  /// the deferred walk still owes the descendants, now at the re-parented path.
  /// Clearing it here would drop the walk and re-open the burst hole (a moved-in
  /// populated dir renamed again in-root before its walk runs, then left blind).
  ///
  /// The parent link only lands in the parent's `children` if the parent is
  /// already present — every producer honors this: a walk emits parents before
  /// children (DFS), and `learn`/`learn_moved_in` insert a single child under an
  /// already-admitted parent. The [`assert_adjacency`](Self::assert_adjacency)
  /// checker pins the resulting invariant in tests.
  fn insert_dir(&mut self, entry: SeedEntry, pending_walk: bool) {
    self.bump();
    let key: HandleKey = entry.fid.handle().into();
    let parent = entry.parent.map(|fid| fid.handle().into());

    // A re-parent overwrites an existing node: unlink it from its old parent,
    // carry its existing children across, and OR-in its outstanding pending_walk
    // so an in-root rename never discharges a not-yet-run move-in walk.
    let existing = self.dirs.get(&key).map(|node| {
      (
        node.parent.clone(),
        node.children.clone(),
        node.pending_walk,
      )
    });
    if let Some((old_parent, _, _)) = &existing
      && *old_parent != parent
      && let Some(old_parent) = old_parent
      && let Some(old) = self.dirs.get_mut(old_parent)
    {
      old.children.remove(&key);
    }

    if let Some(parent) = &parent
      && let Some(parent_node) = self.dirs.get_mut(parent)
    {
      parent_node.children.insert(key.clone());
    }
    let (children, pending_walk) = match existing {
      Some((_, children, was_pending)) => (children, pending_walk || was_pending),
      None => (BTreeSet::new(), pending_walk),
    };
    self.dirs.insert(
      key,
      DirNode {
        parent,
        name: entry.name,
        children,
        pending_walk,
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
