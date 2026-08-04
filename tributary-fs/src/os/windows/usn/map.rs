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
  /// The link CONTRADICTS the map's standing topology: the proposed parent is
  /// the directory itself, or sits inside its own subtree, so applying it
  /// would knot the parent chain into a cycle.
  ///
  /// The filesystem never permits such a link, so the record proving it is
  /// never a report of the live tree — it is HISTORY read out of order. A
  /// resume cursor below the live edge replays records the seed walk has
  /// already superseded: `create A under P`, replayed against a map where P
  /// has since moved under A, is exactly the shape. Silently applying it
  /// produced `A → P → A` and the next resolution walked it forever, taking
  /// the pump and shutdown with it.
  ///
  /// It is NOT the cap's death sentence: the map is stale, not overfull, and
  /// the cure is the reseed spine — an ordered loss, a fresh walk, a cursor
  /// re-anchored at the live edge.
  Inconsistent,
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
  ///
  /// Every mutator refuses a link that would knot the chain, so the walk is
  /// acyclic by construction — and it is bounded here ANYWAY. A resolver is
  /// called from the pump's hot path and from teardown; a hypothesis about the
  /// mutators being total is not something a non-terminating loop should rest
  /// on, because the failure mode is not a wrong answer but a wedged pump and
  /// a shutdown that never returns. The bound is the mapped-directory count:
  /// any acyclic chain reaches the root within it, so a walk that exceeds it
  /// has provably re-entered a node and answers `None` — the same "outside the
  /// root" degrade an unmapped parent already produces, which the callers
  /// route into admission drops and the reseed spine.
  pub(crate) fn resolve_dir(&self, frn: u128) -> Option<Vec<String>> {
    if self.is_root(frn) {
      return Some(Vec::new());
    }
    let mut components = Vec::new();
    let mut cursor = frn;
    for _ in 0..=self.nodes.len() {
      let node = self.nodes.get(&cursor)?;
      components.push(node.name.clone());
      if node.parent == self.root {
        components.reverse();
        return Some(components);
      }
      cursor = node.parent;
    }
    None
  }

  /// Whether relinking something under `frn` would put `frn`'s new home
  /// INSIDE its own subtree — the containment refusal both mutators share.
  ///
  /// Answers `true` for the two cases a caller must refuse identically: the
  /// chain above `new_parent` really does pass through `frn`, or the chain
  /// cannot be proven to reach the root at all (a missing link, or a length
  /// past the mapped-directory count, which only a pre-existing knot can
  /// produce). "Cannot prove it is safe" and "proved it is unsafe" earn the
  /// same answer, because the caller's alternative is to write a link it
  /// cannot resolve back.
  ///
  /// Walking UPWARD from `new_parent` — rather than downward from `frn`
  /// through `children` — keeps the test bounded by the same node count
  /// [`resolve_dir`](Self::resolve_dir) uses, and needs no allocation.
  fn descends_from(&self, new_parent: u128, frn: u128) -> bool {
    let mut cursor = new_parent;
    for _ in 0..=self.nodes.len() {
      if cursor == frn {
        return true;
      }
      if cursor == self.root {
        return false;
      }
      match self.nodes.get(&cursor) {
        Some(node) => cursor = node.parent,
        None => return true,
      }
    }
    true
  }

  /// Whether relinking `frn` under `new_parent` would knot the parent chain —
  /// the standing map's containment verdict, asked WITHOUT mutating anything.
  ///
  /// The same predicate [`learn`](Self::learn) and [`reparent`](Self::reparent)
  /// refuse on, exposed because a caller that must DISCARD a subtree before
  /// re-learning it has to ask first. `forget` turns the subtree's top into a
  /// leaf, and a leaf's proposed parent can never be inside it, so a
  /// contradiction that was provable one statement earlier becomes unprovable —
  /// and the cycle the refusal exists to catch applies silently instead.
  ///
  /// An UNMAPPED `frn` answers `false`: nothing hangs below it here, so nothing
  /// can be knotted by giving it a parent (that is the fresh-directory case
  /// `learn` admits).
  pub(crate) fn knots(&self, frn: u128, new_parent: u128) -> bool {
    self.nodes.contains_key(&frn) && self.descends_from(new_parent, frn)
  }

  /// Resolves a record's `(parent, name)` to the SUBJECT's root-relative
  /// components, or `None` when the parent is outside the root.
  pub(crate) fn resolve_child(&self, parent: u128, name: &str) -> Option<Vec<String>> {
    let mut components = self.resolve_dir(parent)?;
    components.push(name.to_owned());
    Some(components)
  }

  /// Admits a directory under a mapped parent.
  ///
  /// Learning is the map's ONLY growth path and also its replay path, so it
  /// carries the same containment refusal [`reparent`](Self::reparent) does: a
  /// re-learn is a re-parent, and a re-parent onto the moved subtree's own
  /// interior is the cycle.
  pub(crate) fn learn(&mut self, frn: u128, parent: u128, name: String) -> LearnOutcome {
    if !self.contains(parent) {
      return LearnOutcome::OutsideRoot;
    }
    // Only an entry that ALREADY has a chain can be knotted by relinking it; a
    // fresh directory is a leaf, and a leaf's new parent cannot be inside it.
    if self.nodes.contains_key(&frn) && self.descends_from(parent, frn) {
      return LearnOutcome::Inconsistent;
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
    // The NEW parent's chain reaching `frn` means the destination is inside
    // the moved subtree.
    if self.descends_from(new_parent, frn) {
      return false;
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

  /// The replay cycle, exactly as the journal produces it.
  ///
  /// A resume cursor below the live edge replays history against a map the
  /// seed walk built from the CURRENT tree: `A` has since moved to the root
  /// and `P` beneath `A`, and the replayed `create A under P` proposes the
  /// link `A → P` while `P → A` already stands. Applying it closed the parent
  /// chain into `A → P → A`, and the next resolution walked it forever — the
  /// pump and shutdown hung with no `Fatal`, `Overflow` or `Rescan` emitted.
  #[test]
  fn a_replayed_create_that_would_knot_the_chain_is_refused() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "A".into()), (20, 10, "P".into())]);

    assert_eq!(
      map.learn(10, 20, "A".into()),
      LearnOutcome::Inconsistent,
      "a re-parent onto the entry's own descendant is refused"
    );
    // The refusal LEAVES THE MAP ALONE: the standing topology still resolves.
    assert_eq!(map.resolve_dir(10), Some(vec!["A".to_owned()]));
    assert_eq!(
      map.resolve_dir(20),
      Some(vec!["A".to_owned(), "P".to_owned()])
    );

    // Self-parenting is the degenerate case of the same knot.
    assert_eq!(map.learn(10, 10, "A".into()), LearnOutcome::Inconsistent);

    // A re-parent that does NOT knot still applies: the refusal is about
    // containment, not about re-learning.
    map.seed([(30, ROOT, "sibling".into())]);
    assert_eq!(map.learn(20, 30, "P2".into()), LearnOutcome::Learned);
    assert_eq!(
      map.resolve_dir(20),
      Some(vec!["sibling".to_owned(), "P2".to_owned()])
    );
  }

  /// A fresh directory is a leaf, so nothing can be inside it: learning one
  /// under any mapped parent is never a knot, and the cheap containment test
  /// must not start refusing ordinary growth.
  #[test]
  fn learning_a_new_directory_is_never_a_knot() {
    let mut map = seeded();
    assert_eq!(map.learn(40, 30, "d".into()), LearnOutcome::Learned);
    assert_eq!(map.learn(50, ROOT, "e".into()), LearnOutcome::Learned);
    assert_eq!(map.learn(60, 40, "f".into()), LearnOutcome::Learned);
  }

  /// The cap and the knot are DIFFERENT refusals, because they earn different
  /// answers upstream: an overfull map kills the source, a contradicted one
  /// reseeds it.
  #[test]
  fn the_knot_refusal_is_not_the_cap_refusal() {
    let mut map = FrnMap::new(ROOT, Some(2));
    assert_eq!(map.learn(10, ROOT, "A".into()), LearnOutcome::Learned);
    assert_eq!(map.learn(20, 10, "P".into()), LearnOutcome::Learned);
    assert_eq!(map.learn(30, ROOT, "c".into()), LearnOutcome::OverCapacity);
    assert_eq!(map.learn(10, 20, "A".into()), LearnOutcome::Inconsistent);
  }

  /// Resolution terminates even against a chain no mutator would have
  /// written. The invariant is enforced, but the resolver is on the pump's hot
  /// path and on the teardown path, so it answers `None` rather than spinning:
  /// a wrong answer is recoverable, a hung shutdown is not.
  #[test]
  fn resolution_is_bounded_even_on_a_knotted_chain() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "A".into()), (20, 10, "P".into())]);
    // Reach past the refusals and knot the chain by hand — the state the
    // silent relearn used to produce.
    map.nodes.insert(
      10,
      FrnNode {
        parent: 20,
        name: "A".into(),
      },
    );
    assert_eq!(map.resolve_dir(10), None);
    assert_eq!(map.resolve_dir(20), None);
    assert_eq!(map.resolve_child(10, "x"), None);
    // And the mutators refuse to deepen it rather than reasoning from it.
    assert!(!map.reparent(20, 10, "P".into()));
  }

  /// The containment verdict is answerable WITHOUT mutating, and answers the
  /// same way the mutators do — which is the whole point of exposing it: a
  /// caller that is about to discard a subtree can ask while the evidence still
  /// stands. After the discard the same question answers `false`, because the
  /// entry it was about is gone.
  #[test]
  fn the_knot_is_answerable_before_the_subtree_is_discarded() {
    let mut map = seeded();
    assert!(map.knots(10, 30), "a is above c: relinking a under c knots");
    assert!(map.knots(10, 10), "self-parenting is the degenerate knot");
    assert!(!map.knots(30, 10), "c under a is an ordinary move");
    assert!(
      !map.knots(99, 10),
      "an unmapped subject has nothing below it"
    );
    // The mutators agree with it, and the generation is untouched by asking.
    let before = map.generation();
    assert_eq!(map.learn(10, 30, "knot".into()), LearnOutcome::Inconsistent);
    assert!(!map.reparent(10, 30, "knot".into()));
    assert_eq!(map.generation(), before, "asking mutates nothing");
    // And the evidence really does evaporate with the subtree.
    map.forget(10);
    assert!(
      !map.knots(10, 30),
      "the discard erased the standing chain the refusal was reading"
    );
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
