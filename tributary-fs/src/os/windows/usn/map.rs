//! The per-root directory-FRN map: the subtree-scoped resolver that turns a
//! record's `(parent FRN, name)` into a root-relative location — the fanotify
//! `FidMap` discipline on `Copy` 128-bit keys.
//!
//! The completeness invariant is the whole design: a directory is in the map
//! IFF it is currently an in-root directory on the root's volume-side
//! subtree. Membership is decided by the map alone, never by opening the
//! subject (journal records for already-deleted objects are tombstones —
//! open-by-id fails exactly when the answer matters most), so mutations are
//! applied in strict journal order by the one consumer that owns the map. A
//! parent FRN the map does not know is OUTSIDE the root — dropped by
//! admission, not an error.
//!
//! Pure data only — no FFI — so the twins pin the resolver on every host,
//! including under miri, before the journal source exists.

use std::collections::{BTreeMap, BTreeSet};

/// One mapped directory: its parent link and its name in that parent.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FrnNode {
  parent: u128,
  name: String,
}

/// What a live `learn` decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LearnOutcome {
  /// The directory joined the map.
  Learned,
  /// The parent is not mapped: the directory is outside the root (or the
  /// map is blind to it — the caller's loss machinery decides which).
  OutsideRoot,
  /// Admitting it would exceed the configured directory cap: the map can no
  /// longer be complete, so the source must die rather than go blind.
  OverCapacity,
}

/// The subtree-scoped directory-FRN map.
#[derive(Debug)]
pub(crate) struct FrnMap {
  root: u128,
  nodes: BTreeMap<u128, FrnNode>,
  children: BTreeMap<u128, BTreeSet<u128>>,
  /// Monotone mutation counter — the batch memo's invalidation token.
  generation: u64,
  max_directories: Option<usize>,
}

impl FrnMap {
  /// An empty map anchored at `root` (the pinned root handle's FRN).
  pub(crate) fn new(root: u128, max_directories: Option<usize>) -> Self {
    Self {
      root,
      nodes: BTreeMap::new(),
      children: BTreeMap::new(),
      generation: 0,
      max_directories,
    }
  }

  /// The map's mutation generation.
  pub(crate) fn generation(&self) -> u64 {
    self.generation
  }

  /// How many directories are mapped (the root anchor is implicit).
  pub(crate) fn directories(&self) -> usize {
    self.nodes.len()
  }

  /// Whether `frn` is the root anchor itself.
  pub(crate) fn is_root(&self, frn: u128) -> bool {
    frn == self.root
  }

  /// Whether `frn` is mapped (the root anchor included).
  pub(crate) fn contains(&self, frn: u128) -> bool {
    self.is_root(frn) || self.nodes.contains_key(&frn)
  }

  /// Installs the seed walk's entries. The walk feeds parents before
  /// children (a directory's parent is always walked first), so every entry
  /// admits; an entry whose parent is missing is a walk-order bug and is
  /// dropped rather than poisoning the map.
  pub(crate) fn seed(&mut self, entries: impl IntoIterator<Item = (u128, u128, String)>) {
    for (frn, parent, name) in entries {
      let _ = self.learn(frn, parent, name);
    }
  }

  /// Resolves a mapped directory to its root-relative components (empty =
  /// the root itself), or `None` when it is not mapped.
  pub(crate) fn resolve_dir(&self, frn: u128) -> Option<Vec<String>> {
    if self.is_root(frn) {
      return Some(Vec::new());
    }
    let mut components = Vec::new();
    let mut cursor = frn;
    // The parent chain is acyclic by construction (a reparent onto a
    // descendant is refused), so the walk terminates at the root or falls
    // off the map.
    loop {
      let node = self.nodes.get(&cursor)?;
      components.push(node.name.clone());
      if node.parent == self.root {
        components.reverse();
        return Some(components);
      }
      cursor = node.parent;
    }
  }

  /// Resolves a record's `(parent, name)` to the SUBJECT's root-relative
  /// components, or `None` when the parent is outside the root.
  pub(crate) fn resolve_child(&self, parent: u128, name: &str) -> Option<Vec<String>> {
    let mut components = self.resolve_dir(parent)?;
    components.push(name.to_owned());
    Some(components)
  }

  /// Admits a directory under a mapped parent.
  pub(crate) fn learn(&mut self, frn: u128, parent: u128, name: String) -> LearnOutcome {
    if !self.contains(parent) {
      return LearnOutcome::OutsideRoot;
    }
    if self
      .max_directories
      .is_some_and(|cap| self.nodes.len() >= cap && !self.nodes.contains_key(&frn))
    {
      return LearnOutcome::OverCapacity;
    }
    // Re-learning (a create replaying over an existing entry) re-parents.
    if let Some(existing) = self.nodes.get(&frn) {
      let old_parent = existing.parent;
      if let Some(siblings) = self.children.get_mut(&old_parent) {
        siblings.remove(&frn);
      }
    }
    self.nodes.insert(frn, FrnNode { parent, name });
    self.children.entry(parent).or_default().insert(frn);
    self.generation += 1;
    LearnOutcome::Learned
  }

  /// Forgets a directory AND everything mapped below it (a delete or an
  /// out-of-root move takes the whole subtree with it).
  pub(crate) fn forget(&mut self, frn: u128) {
    if !self.nodes.contains_key(&frn) {
      return;
    }
    let mut stack = vec![frn];
    while let Some(cursor) = stack.pop() {
      if let Some(children) = self.children.remove(&cursor) {
        stack.extend(children);
      }
      if let Some(node) = self.nodes.remove(&cursor)
        && let Some(siblings) = self.children.get_mut(&node.parent)
      {
        siblings.remove(&cursor);
      }
    }
    self.generation += 1;
  }

  /// Re-parents a mapped directory (an in-root → in-root rename). The
  /// subtree follows for free — descendants resolve through the parent
  /// chain. A reparent onto the directory's own subtree would knot the
  /// chain into a cycle; the journal never reports one (the filesystem
  /// refuses it), so it is refused here too and the caller escalates.
  pub(crate) fn reparent(&mut self, frn: u128, new_parent: u128, new_name: String) -> bool {
    if !self.nodes.contains_key(&frn) || !self.contains(new_parent) {
      return false;
    }
    // Walk the NEW parent's chain: hitting `frn` means the destination is
    // inside the moved subtree.
    let mut cursor = new_parent;
    while cursor != self.root {
      if cursor == frn {
        return false;
      }
      match self.nodes.get(&cursor) {
        Some(node) => cursor = node.parent,
        None => return false,
      }
    }
    let Some(node) = self.nodes.get_mut(&frn) else {
      return false;
    };
    let old_parent = node.parent;
    node.parent = new_parent;
    node.name = new_name;
    if let Some(siblings) = self.children.get_mut(&old_parent) {
      siblings.remove(&frn);
    }
    self.children.entry(new_parent).or_default().insert(frn);
    self.generation += 1;
    true
  }

  /// Drops every entry and re-anchors — the reseed's swap point. The caller
  /// walks the tree and feeds [`seed`](Self::seed) again.
  pub(crate) fn clear(&mut self) {
    self.nodes.clear();
    self.children.clear();
    self.generation += 1;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const ROOT: u128 = 1;

  fn seeded() -> FrnMap {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([
      (10, ROOT, "a".into()),
      (20, 10, "b".into()),
      (30, 20, "c".into()),
    ]);
    map
  }

  #[test]
  fn resolution_walks_the_parent_chain() {
    let map = seeded();
    assert_eq!(map.resolve_dir(ROOT), Some(vec![]));
    assert_eq!(map.resolve_dir(10), Some(vec!["a".into()]));
    assert_eq!(
      map.resolve_dir(30),
      Some(vec!["a".into(), "b".into(), "c".into()])
    );
    assert_eq!(
      map.resolve_child(20, "file.txt"),
      Some(vec!["a".into(), "b".into(), "file.txt".into()])
    );
    assert_eq!(map.resolve_dir(99), None, "unmapped is outside");
    assert_eq!(map.resolve_child(99, "x"), None);
  }

  #[test]
  fn learn_requires_a_mapped_parent() {
    let mut map = seeded();
    assert_eq!(
      map.learn(40, 99, "orphan".into()),
      LearnOutcome::OutsideRoot
    );
    assert_eq!(map.learn(40, 30, "d".into()), LearnOutcome::Learned);
    assert_eq!(
      map.resolve_dir(40).unwrap(),
      vec!["a", "b", "c", "d"]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>()
    );
  }

  #[test]
  fn the_cap_refuses_growth_not_replacement() {
    let mut map = FrnMap::new(ROOT, Some(2));
    assert_eq!(map.learn(10, ROOT, "a".into()), LearnOutcome::Learned);
    assert_eq!(map.learn(20, ROOT, "b".into()), LearnOutcome::Learned);
    assert_eq!(map.learn(30, ROOT, "c".into()), LearnOutcome::OverCapacity);
    // Re-learning a mapped entry is a mutation, not growth.
    assert_eq!(map.learn(20, 10, "b2".into()), LearnOutcome::Learned);
    assert_eq!(map.directories(), 2);
  }

  #[test]
  fn forget_takes_the_subtree() {
    let mut map = seeded();
    let before = map.generation();
    map.forget(20);
    assert!(map.generation() > before);
    assert!(map.contains(10));
    assert!(!map.contains(20));
    assert!(!map.contains(30), "the descendant fell with its parent");
    map.forget(99); // unmapped: a no-op
  }

  #[test]
  fn reparent_moves_the_subtree_and_refuses_cycles() {
    let mut map = seeded();
    // A reparent of a onto its own grandchild c is refused — the chain
    // would knot into a cycle.
    assert!(!map.reparent(10, 30, "knot".into()));
    // Move c from under b to under a, renamed.
    assert!(map.reparent(30, 10, "c2".into()));
    assert_eq!(
      map.resolve_dir(30).unwrap(),
      vec!["a".to_owned(), "c2".to_owned()]
    );
    // With c now OUTSIDE b's subtree, b may legally move under it.
    assert!(map.reparent(20, 30, "b2".into()));
    assert_eq!(
      map.resolve_dir(20).unwrap(),
      vec!["a".to_owned(), "c2".to_owned(), "b2".to_owned()]
    );
    // Unmapped participants are refused.
    assert!(!map.reparent(99, 10, "x".into()));
    assert!(!map.reparent(30, 99, "x".into()));
  }

  #[test]
  fn clear_reanchors() {
    let mut map = seeded();
    map.clear();
    assert_eq!(map.directories(), 0);
    assert!(map.contains(ROOT), "the anchor survives");
    assert_eq!(map.learn(10, ROOT, "fresh".into()), LearnOutcome::Learned);
  }
}
