use std::{
  cell::RefCell,
  collections::{HashMap, VecDeque},
  io,
  path::{Path, PathBuf},
};

use tributary_proto::{Epoch, Interest};

use super::{
  Event, RootArmer, Subscription, Subsumer, WatchError, apply_watch, epoch::EpochLedger,
};

/// One recorded call against the fake armer, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
  Arm(PathBuf),
  Disarm(u32),
}

/// A fake [`RootArmer`] over `u32` handles: it records every arm/disarm in order
/// (so a test can assert the widen sequence) and can be told to fail the *next*
/// arm (so a test can drive the arm-failure unwind) — without any real filesystem
/// or the un-constructible `RootHandle`.
struct FakeArmer {
  inner: RefCell<FakeInner>,
}

struct FakeInner {
  next_handle: u32,
  calls: Vec<Call>,
  /// Fail the next `arm` when set, consuming the flag.
  fail_next_arm: bool,
}

impl FakeArmer {
  fn new() -> Self {
    Self {
      inner: RefCell::new(FakeInner {
        next_handle: 0,
        calls: Vec::new(),
        fail_next_arm: false,
      }),
    }
  }

  /// Arm the next call fails.
  fn fail_next_arm(&self) {
    self.inner.borrow_mut().fail_next_arm = true;
  }

  fn calls(&self) -> Vec<Call> {
    self.inner.borrow().calls.clone()
  }

  fn arm_count(&self) -> usize {
    self
      .inner
      .borrow()
      .calls
      .iter()
      .filter(|c| matches!(c, Call::Arm(_)))
      .count()
  }
}

impl RootArmer for FakeArmer {
  type Handle = u32;

  async fn arm(&self, path: &Path, _interest: Interest) -> Result<u32, WatchError> {
    let mut inner = self.inner.borrow_mut();
    inner.calls.push(Call::Arm(path.to_path_buf()));
    if inner.fail_next_arm {
      inner.fail_next_arm = false;
      return Err(WatchError::Canonicalize {
        path: path.to_path_buf(),
        source: io::Error::other("injected arm failure"),
      });
    }
    inner.next_handle += 1;
    Ok(inner.next_handle)
  }

  async fn disarm(&self, handle: u32) -> Result<(), super::UnwatchError> {
    self.inner.borrow_mut().calls.push(Call::Disarm(handle));
    Ok(())
  }
}

/// The driver-side state `apply_watch` threads through, bundled for the tests.
struct Harness {
  subsumer: Subsumer<u32>,
  epochs: EpochLedger,
  queue: VecDeque<Event>,
  armer: FakeArmer,
}

impl Harness {
  fn new() -> Self {
    Self {
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      queue: VecDeque::new(),
      armer: FakeArmer::new(),
    }
  }

  async fn watch(&mut self, path: &str, interest: Interest) -> Result<Subscription, WatchError> {
    apply_watch(
      &mut self.subsumer,
      &mut self.epochs,
      &mut self.queue,
      &self.armer,
      Path::new(path),
      interest,
    )
    .await
  }
}

#[tokio::test]
async fn overlapping_watch_issues_one_arm() {
  let mut h = Harness::new();

  // /a arms one kernel watch.
  h.watch("/a", Interest::all()).await.expect("watch /a");
  // /a/b is covered by /a — no second arm, and never an `Overlaps`.
  let covered = h.watch("/a/b", Interest::all()).await;
  assert!(
    covered.is_ok(),
    "an overlapping watch never surfaces Overlaps"
  );

  assert_eq!(
    h.armer.arm_count(),
    1,
    "two overlapping subscriptions collapse to exactly one arm"
  );
  assert_eq!(
    h.armer.calls(),
    vec![Call::Arm(PathBuf::from("/a"))],
    "only the covering root /a is armed"
  );
}

#[tokio::test]
async fn widen_arms_new_before_disarming_old() {
  let mut h = Harness::new();

  // Arm the narrow root /a/b first (handle 1).
  h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  // Now watch its ancestor /a — a widen: it subsumes /a/b.
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a widens");

  // The wider root /a must be armed BEFORE the subsumed /a/b (handle 1) is
  // disarmed, so coverage never gaps (design §4).
  assert_eq!(
    h.armer.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a")),
      Call::Disarm(1),
    ],
    "arm-new precedes disarm-old on a widen"
  );
}

#[tokio::test]
async fn arm_failure_abandons_plan_no_pending_leak() {
  let mut h = Harness::new();

  h.armer.fail_next_arm();
  let result = h.watch("/a", Interest::all()).await;

  assert!(result.is_err(), "a failed arm surfaces the error");
  assert_eq!(
    h.subsumer.pending_len(),
    0,
    "a failed arm abandons the plan — no pending reservation leaks"
  );
  // The engine committed nothing: a subsequent watch of the same path is a fresh
  // Disjoint arm, not a phantom Covered against a leaked entry.
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a after the earlier failure");
  assert_eq!(
    h.armer.arm_count(),
    2,
    "the retried watch arms again (the failed plan left no live root)"
  );
}

#[tokio::test]
async fn widen_emits_dominating_rescan_per_repointed_sub() {
  let mut h = Harness::new();

  // Two narrow roots, each its own subscription and kernel watch.
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c");

  // Pretend each subscription has already seen some events (advance its high-water
  // through the real ledger: from base START, an fs epoch e stamps to e, so this
  // lands sb's high-water at 4 and sc's at 2).
  h.epochs.stamp(sb, Epoch::new(4));
  h.epochs.stamp(sc, Epoch::new(2));

  // Widen over both with /a.
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a widens");

  // One synthetic Rescan per re-pointed subscription, each dominating that
  // subscription's prior stream and naming the widened root to re-enumerate.
  let rescans: Vec<_> = h.queue.iter().collect();
  assert_eq!(rescans.len(), 2, "one Rescan per re-pointed subscription");
  for ev in &rescans {
    assert!(ev.is_rescan(), "the synthetic event is a Rescan");
    assert_eq!(ev.path(), Path::new("/a"), "it names the widened root");
  }

  let by_sub: HashMap<Subscription, Epoch> = rescans
    .iter()
    .map(|ev| (ev.subscription(), ev.epoch()))
    .collect();
  assert_eq!(
    by_sub.get(&sb).copied(),
    Some(Epoch::new(5)),
    "sb's Rescan strictly dominates its high-water of 4"
  );
  assert_eq!(
    by_sub.get(&sc).copied(),
    Some(Epoch::new(3)),
    "sc's Rescan strictly dominates its high-water of 2"
  );
}

#[tokio::test]
async fn heterogeneous_interest_widen_unions_coverage() {
  let mut h = Harness::new();

  // Two subsumed roots with DISJOINT interests, plus a newcomer with a third.
  let created_only = Interest::new().maybe_created(true);
  let removed_only = Interest::new().maybe_removed(true);
  let modified_only = Interest::new().maybe_modified(true);

  h.watch("/a/b", created_only).await.expect("watch /a/b");
  h.watch("/a/c", removed_only).await.expect("watch /a/c");

  // Widen over both with a newcomer wanting only modifications.
  h.watch("/a", modified_only).await.expect("watch /a widens");

  // The single surviving root is /a; its armed interest must be the UNION of every
  // subsumed interest and the newcomer's — never narrower than any subscriber
  // relied on.
  let roots: Vec<_> = h
    .subsumer
    .roots()
    .map(|(p, handle)| (p.to_path_buf(), handle))
    .collect();
  assert_eq!(
    roots.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(),
    vec![PathBuf::from("/a")],
    "the widen collapses to the single root /a"
  );
  let armed = h
    .subsumer
    .entry(roots[0].1)
    .expect("the widened root entry")
    .interest;
  assert!(armed.created(), "union keeps /a/b's Created");
  assert!(armed.removed(), "union keeps /a/c's Removed");
  assert!(armed.modified(), "union keeps the newcomer's Modified");
}
