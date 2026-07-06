use std::{
  collections::{BTreeSet, HashMap, HashSet},
  path::{Path, PathBuf},
};

use proptest::prelude::*;
use tributary_proto::Interest;

use super::{Subscription, Subsumer, UnwatchOutcome, WatchOutcome};

/// A monotonic minter of `u32` fs-root test handles — stands in for the real
/// `tributary-fs` handle the driver obtains by arming a kernel watch.
#[derive(Default)]
struct Handles {
  next: u32,
}

impl Handles {
  fn mint(&mut self) -> u32 {
    self.next += 1;
    self.next
  }
}

/// A test-side driver mirroring what S2 will do: plan the watch, mint a fresh
/// handle for a new/widened root (reuse the existing one when covered), then
/// commit. Returns the committed root handle plus the engine-minted subscription.
fn watch(
  s: &mut Subsumer<u32>,
  handles: &mut Handles,
  path: &str,
  interest: Interest,
) -> (u32, Subscription) {
  let outcome = s.plan_watch(Path::new(path), interest);
  let (fs_root, sub) = match &outcome {
    WatchOutcome::Covered { fs_root, sub } => (*fs_root, *sub),
    WatchOutcome::Widen { sub, .. } | WatchOutcome::Disjoint { sub, .. } => (handles.mint(), *sub),
  };
  s.commit_watch(&outcome, fs_root);
  (fs_root, sub)
}

/// The canonical paths of every live root, as a set.
fn root_paths(s: &Subsumer<u32>) -> BTreeSet<PathBuf> {
  s.roots().map(|(p, _)| p.to_path_buf()).collect()
}

#[test]
fn disjoint_paths_stay_separate() {
  let mut s = Subsumer::<u32>::new();
  let mut h = Handles::default();

  let (ra, sa) = watch(&mut s, &mut h, "/a", Interest::all());
  let (rb, sb) = watch(&mut s, &mut h, "/b", Interest::all());

  assert_ne!(ra, rb, "unrelated paths get distinct roots");
  assert_ne!(sa, sb, "each watch mints a distinct subscription");
  assert_eq!(
    root_paths(&s),
    BTreeSet::from([PathBuf::from("/a"), PathBuf::from("/b")]),
  );
  assert_eq!(s.entry(ra).unwrap().subscribers, vec![sa]);
  assert_eq!(s.entry(rb).unwrap().subscribers, vec![sb]);
  // The side table records each subscription's registration path.
  assert_eq!(s.subscription_path(sa), Some(Path::new("/a")));
  assert_eq!(s.subscription_path(sb), Some(Path::new("/b")));
}

#[test]
fn descendant_is_covered() {
  let mut s = Subsumer::<u32>::new();
  let mut h = Handles::default();

  let (ra, sa) = watch(&mut s, &mut h, "/a", Interest::all());

  // `/a/b` is already covered by `/a`: no new root, no new kernel watch.
  let outcome = s.plan_watch(Path::new("/a/b"), Interest::all());
  let sb = match &outcome {
    WatchOutcome::Covered { fs_root, sub } => {
      assert_eq!(*fs_root, ra, "covered by the /a root");
      *sub
    }
    other => panic!("expected Covered by /a, got {other:?}"),
  };
  s.commit_watch(&outcome, ra);

  assert_eq!(root_paths(&s), BTreeSet::from([PathBuf::from("/a")]));
  assert_eq!(s.entry(ra).unwrap().subscribers, vec![sa, sb]);
}

#[test]
fn ancestor_widens_and_repoints() {
  let mut s = Subsumer::<u32>::new();
  let mut h = Handles::default();

  let (narrow, s_narrow) = watch(&mut s, &mut h, "/a/b", Interest::all());

  // Watching the strict ancestor `/a` subsumes `/a/b`.
  let outcome = s.plan_watch(Path::new("/a"), Interest::all());
  let s_wide = match &outcome {
    WatchOutcome::Widen {
      new_root_path,
      repointed,
      unwatch,
      sub,
      ..
    } => {
      assert_eq!(new_root_path, Path::new("/a"));
      assert_eq!(
        repointed,
        &vec![s_narrow],
        "the /a/b subscriber is re-pointed"
      );
      assert_eq!(unwatch, &vec![narrow], "the old /a/b root is released");
      *sub
    }
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide);

  assert_ne!(wide, narrow);
  assert_eq!(root_paths(&s), BTreeSet::from([PathBuf::from("/a")]));
  // The old narrow root is gone; both subs now ride the wider root.
  assert!(s.entry(narrow).is_none());
  assert_eq!(s.entry(wide).unwrap().subscribers, vec![s_narrow, s_wide]);
  assert_eq!(s.entry(wide).unwrap().path, PathBuf::from("/a"));
}

#[test]
fn unwatch_last_subscriber_empties_root() {
  let mut s = Subsumer::<u32>::new();
  let mut h = Handles::default();

  let (ra, sa) = watch(&mut s, &mut h, "/a", Interest::all());
  let (_covered_root, sb) = watch(&mut s, &mut h, "/a/b", Interest::all());

  // Dropping the covered subscriber leaves the root alive (still one subscriber).
  assert!(matches!(s.plan_unwatch(sb), Some(UnwatchOutcome::Dropped)));
  assert_eq!(s.entry(ra).unwrap().subscribers, vec![sa]);

  // Dropping the last subscriber empties (and removes) the root.
  assert!(matches!(
    s.plan_unwatch(sa),
    Some(UnwatchOutcome::RootEmptied { fs_root }) if fs_root == ra,
  ));
  assert!(s.entry(ra).is_none());
  assert!(root_paths(&s).is_empty());

  // Unknown / already-dropped subscriptions report nothing.
  assert!(s.plan_unwatch(sa).is_none());
}

// ---------------------------------------------------------------------------
// Property tests: invariants over any random watch/unwatch sequence.
// ---------------------------------------------------------------------------

/// Whether `ancestor` is an ancestor of (or equal to) `descendant` in the
/// component-wise canonical-path space (the same relation iradix keys on).
fn is_ancestor_or_equal(ancestor: &Path, descendant: &Path) -> bool {
  descendant.starts_with(ancestor)
}

/// One scripted operation against the engine. `Unwatch(idx)` drops the live
/// subscription at `idx % live_count` (a stable index into the live set), so the
/// script exercises both draining and re-pointing without knowing minted ids.
#[derive(Debug, Clone)]
enum Op {
  Watch(PathBuf),
  Unwatch(usize),
}

/// A pool of short, overlapping absolute paths drawn from a tiny component
/// alphabet, so watches genuinely nest and subsume rather than staying disjoint.
fn path_strategy() -> impl Strategy<Value = PathBuf> {
  proptest::collection::vec(prop_oneof!["a", "b", "c"], 1..=4)
    .prop_map(|parts| PathBuf::from(format!("/{}", parts.join("/"))))
}

fn op_strategy() -> impl Strategy<Value = Op> {
  prop_oneof![
    path_strategy().prop_map(Op::Watch),
    any::<usize>().prop_map(Op::Unwatch),
  ]
}

/// Replays `ops` against a fresh engine, returning it and the live
/// `Subscription -> canonical path` model the script implies. Both sides agree on
/// liveness: the model records exactly the subscription each `watch` minted and
/// removes exactly the one each `unwatch` dropped.
fn run(ops: &[Op]) -> (Subsumer<u32>, HashMap<Subscription, PathBuf>) {
  let mut s = Subsumer::<u32>::new();
  let mut h = Handles::default();
  // Insertion-ordered so an `Unwatch(idx)` selection is deterministic.
  let mut live: Vec<(Subscription, PathBuf)> = Vec::new();

  for op in ops {
    match op {
      Op::Watch(path) => {
        let (_root, sub) = watch(&mut s, &mut h, &path.to_string_lossy(), Interest::all());
        live.push((sub, path.clone()));
      }
      Op::Unwatch(idx) => {
        if live.is_empty() {
          continue;
        }
        let (sub, _) = live.remove(idx % live.len());
        assert!(
          s.plan_unwatch(sub).is_some(),
          "a live subscription must be dropped",
        );
      }
    }
  }
  (s, live.into_iter().collect())
}

proptest! {
  // No on-disk regression file: it would resolve the current directory (a `getcwd`
  // syscall) at setup, which trips Miri's isolation on an otherwise sans-I/O suite.
  #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

  /// (a) The live roots are pairwise disjoint (no root is an ancestor of another).
  #[test]
  fn roots_are_pairwise_disjoint(ops in proptest::collection::vec(op_strategy(), 0..40)) {
    let (s, _live) = run(&ops);
    let roots: Vec<PathBuf> = s.roots().map(|(p, _)| p.to_path_buf()).collect();
    for (i, a) in roots.iter().enumerate() {
      for (j, b) in roots.iter().enumerate() {
        if i != j {
          prop_assert!(
            !is_ancestor_or_equal(a, b),
            "roots {a:?} and {b:?} overlap",
          );
        }
      }
    }
  }

  /// (b) Every live subscription is covered by exactly one root that is an
  /// ancestor-or-equal of its path. The path is read from the engine's own side
  /// table (via `subscription_path`), so this also checks the side table stays
  /// consistent with the script across widening re-points.
  #[test]
  fn every_sub_covered_by_exactly_one_root(ops in proptest::collection::vec(op_strategy(), 0..40)) {
    let (s, live) = run(&ops);
    let roots: Vec<PathBuf> = s.roots().map(|(p, _)| p.to_path_buf()).collect();
    for (sub, expected_path) in &live {
      let recorded = s
        .subscription_path(*sub)
        .expect("a live subscription has a recorded path");
      prop_assert_eq!(recorded, expected_path.as_path(), "side-table path drifted");
      let covering = roots.iter().filter(|r| is_ancestor_or_equal(r, recorded)).count();
      prop_assert_eq!(
        covering, 1,
        "sub {} at {:?} is covered by {} roots, want exactly 1",
        sub, recorded, covering,
      );
    }
  }

  /// (c) No live root has an empty subscriber set, and every indexed root has an
  /// entry (the index and the entries map stay in lockstep).
  #[test]
  fn no_zero_subscriber_root(ops in proptest::collection::vec(op_strategy(), 0..40)) {
    let (s, _live) = run(&ops);
    for (_path, handle) in s.roots() {
      let entry = s.entry(handle).expect("indexed root has an entry");
      prop_assert!(!entry.subscribers.is_empty(), "root {handle} has no subscribers");
    }
  }

  /// The whole live subscription set is exactly what the script implies — nothing
  /// is dropped or duplicated across widening re-points.
  #[test]
  fn live_sub_set_matches_model(ops in proptest::collection::vec(op_strategy(), 0..40)) {
    let (s, live) = run(&ops);
    let engine_subs: HashSet<Subscription> = s
      .roots()
      .flat_map(|(_p, h)| s.entry(h).unwrap().subscribers.clone())
      .collect();
    let model_subs: HashSet<Subscription> = live.keys().copied().collect();
    prop_assert_eq!(engine_subs, model_subs);
  }
}
