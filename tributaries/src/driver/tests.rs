use std::{
  cell::RefCell,
  collections::{HashMap, VecDeque},
  io,
  path::{Path, PathBuf},
};

use tributary_proto::{Epoch, Interest};

use tributary_fs::WatchRootError;

use super::{
  Event, Filter, RootArmer, Subscription, Subsumer, WatchError, WidenJournal, apply_watch,
  epoch::EpochLedger, resume_pending_widen,
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
///
/// **It enforces the lower watcher's disjoint-root contract** ([`tributary_fs::Watcher`]):
/// arming a path that overlaps a currently-armed fake root (is an ancestor-or-descendant
/// of it) returns [`WatchRootError::Overlaps`], exactly as production does. This is what
/// makes the widen-ordering tests validate a *real-executable* sequence — a naive
/// arm-before-unwatch (arming the wider root while a subsumed one is still live) would be
/// rejected here just as it is by the real kernel watcher, so a test cannot pass against
/// an ordering production could never run.
struct FakeArmer {
  inner: RefCell<FakeInner>,
}

struct FakeInner {
  next_handle: u32,
  calls: Vec<Call>,
  /// The arm-path of every currently-live (armed, not yet disarmed) fake root, keyed by
  /// handle. A fresh `arm` is rejected with `Overlaps` if its path overlaps any of these
  /// — the disjoint-root contract the real [`tributary_fs::Watcher`] enforces (design §4).
  live: HashMap<u32, PathBuf>,
  /// How many of the next `arm` calls to fail, decremented on each failed arm. Set to 1
  /// to fail just the next arm, or to N to drive a rollback re-arm failure after the
  /// wider arm already failed (the degenerate double-failure path).
  fail_arms: u32,
  /// Each armed handle's fs-authoritative canonical path (what `root_path` reports).
  /// By default the path passed to `arm`; a `retarget` entry overrides it to model
  /// the canonicalization TOCTOU (fs reports a different path than the umbrella
  /// planned).
  root_paths: HashMap<u32, PathBuf>,
  /// Planned path → the divergent fs path `arm` should record for it (a component
  /// swapped between the umbrella's canonicalization and fs's).
  retarget: HashMap<PathBuf, PathBuf>,
  /// The interest each `arm` was called with, in call order — so a test can assert
  /// every umbrella arm is `Interest::all` (design §4).
  armed_interests: Vec<Interest>,
}

impl FakeArmer {
  fn new() -> Self {
    Self {
      inner: RefCell::new(FakeInner {
        next_handle: 0,
        calls: Vec::new(),
        live: HashMap::new(),
        fail_arms: 0,
        root_paths: HashMap::new(),
        retarget: HashMap::new(),
        armed_interests: Vec::new(),
      }),
    }
  }

  /// The next `arm` call fails.
  fn fail_next_arm(&self) {
    self.inner.borrow_mut().fail_arms = 1;
  }

  /// The next `n` `arm` calls fail — to drive a rollback re-arm failure (the degenerate
  /// double-failure path) after the wider arm already failed.
  fn fail_arms(&self, n: u32) {
    self.inner.borrow_mut().fail_arms = n;
  }

  /// Model the canonicalization TOCTOU: an `arm(planned)` records `fs` as the handle's
  /// fs-canonical path, so `root_path` reports `fs` — diverging from what was planned.
  fn retarget(&self, planned: &str, fs: &str) {
    self
      .inner
      .borrow_mut()
      .retarget
      .insert(PathBuf::from(planned), PathBuf::from(fs));
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

  /// The interest of every `arm` call, in order.
  fn armed_interests(&self) -> Vec<Interest> {
    self.inner.borrow().armed_interests.clone()
  }
}

impl RootArmer for FakeArmer {
  type Handle = u32;

  async fn arm(&self, path: &Path, interest: Interest) -> Result<u32, WatchError> {
    let mut inner = self.inner.borrow_mut();
    inner.calls.push(Call::Arm(path.to_path_buf()));
    inner.armed_interests.push(interest);
    if inner.fail_arms > 0 {
      inner.fail_arms -= 1;
      return Err(WatchError::Canonicalize {
        path: path.to_path_buf(),
        source: io::Error::other("injected arm failure"),
      });
    }
    // The disjoint-root contract (design §4): reject a path overlapping any live root —
    // ancestor-or-descendant — with `Overlaps`, exactly as `tributary_fs::Watcher` does.
    // This is what forces the widen to unwatch the subsumed roots BEFORE arming the
    // wider one; an arm-before-unwatch would land here and be rejected, just like in
    // production. (Rejection creates no handle and touches no live-set — nothing armed.)
    if let Some(existing) = inner
      .live
      .values()
      .find(|live| path.starts_with(live) || live.starts_with(path))
      .cloned()
    {
      return Err(WatchError::Fs(WatchRootError::Overlaps {
        path: path.to_path_buf(),
        existing,
      }));
    }
    inner.next_handle += 1;
    let handle = inner.next_handle;
    // fs's canonical path for this handle: the retarget override, else the armed path.
    let fs_path = inner
      .retarget
      .get(path)
      .cloned()
      .unwrap_or_else(|| path.to_path_buf());
    inner.root_paths.insert(handle, fs_path);
    // Track the arm-path (not the retargeted fs path) for overlap: production checks the
    // overlap in the coordinate the umbrella plans against, and the `retarget` models a
    // separate fs-side divergence caught by the `fs_path_preserves_plan` guard, not here.
    inner.live.insert(handle, path.to_path_buf());
    Ok(handle)
  }

  fn root_path(&self, handle: u32) -> Option<PathBuf> {
    self.inner.borrow().root_paths.get(&handle).cloned()
  }

  async fn disarm(&self, handle: u32) -> Result<(), super::UnwatchError> {
    let mut inner = self.inner.borrow_mut();
    inner.calls.push(Call::Disarm(handle));
    inner.root_paths.remove(&handle);
    inner.live.remove(&handle);
    Ok(())
  }
}

/// The driver-side state `apply_watch` threads through, bundled for the tests.
struct Harness {
  subsumer: Subsumer<u32>,
  epochs: EpochLedger,
  /// Mirrors the driver's per-subscription filter map, so the rollback's degenerate
  /// loss path (which reclaims a lost subscriber's filter) is exercised as it runs in
  /// `Tributaries::watch`. A watch that succeeds records `Filter::all` here, mirroring
  /// `Tributaries::watch` inserting the caller's filter on success.
  filters: HashMap<Subscription, Filter>,
  queue: VecDeque<Event>,
  /// Mirrors the driver's in-flight-widen journal (design §4, cancellation safety), so a
  /// test can simulate a dropped `watch()` future (journal set + subsumed disarmed) and
  /// then drive `resume_pending_widen`.
  pending_widen: Option<WidenJournal<u32>>,
  armer: FakeArmer,
}

impl Harness {
  fn new() -> Self {
    Self {
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
      queue: VecDeque::new(),
      pending_widen: None,
      armer: FakeArmer::new(),
    }
  }

  async fn watch(&mut self, path: &str, interest: Interest) -> Result<Subscription, WatchError> {
    let sub = apply_watch(
      &mut self.subsumer,
      &mut self.epochs,
      &mut self.filters,
      &mut self.queue,
      &mut self.pending_widen,
      &self.armer,
      Path::new(path),
      interest,
    )
    .await?;
    // Mirror `Tributaries::watch`: on success record the subscription's filter (the
    // per-sub state the degenerate rollback path must reclaim if this sub is later lost).
    self.filters.insert(sub, Filter::all());
    Ok(sub)
  }

  /// Repairs a journaled-but-incomplete widen, mirroring `Tributaries::resume_pending_widen`
  /// (design §4). A test simulating a dropped `watch()` future calls this after
  /// [`journal_and_disarm_widen`](Self::journal_and_disarm_widen).
  async fn resume(&mut self) {
    resume_pending_widen(
      &mut self.subsumer,
      &mut self.epochs,
      &mut self.filters,
      &mut self.queue,
      &mut self.pending_widen,
      &self.armer,
    )
    .await;
  }

  /// Drives a widen of `path` to exactly the mid-transaction state a dropped `watch()`
  /// future would leave: journal the plan, then disarm the subsumed kernel roots — but
  /// **stop before arming the wider root** (as a `select!`/timeout cancel between the
  /// disarm and the commit would). The subsumer's index is untouched (no commit ran), so
  /// its subsumed `RootEntry`s and the newcomer's pending reservation stay live, exactly
  /// as they would after a real drop. Returns the plan's subsumed handles.
  async fn journal_and_disarm_widen(&mut self, path: &str) -> Vec<u32> {
    let outcome = self.subsumer.plan_watch(Path::new(path), Interest::all());
    let super::WatchOutcome::Widen { unwatch, .. } = &outcome else {
      panic!("expected a Widen plan for {path}");
    };
    let unwatch = unwatch.clone();
    // Journal BEFORE the disarms (design §4), exactly as `apply_watch` does.
    self.pending_widen = Some(WidenJournal {
      outcome: outcome.clone(),
    });
    for &old in &unwatch {
      let _ = self.armer.disarm(old).await;
    }
    // Deliberately no arm/commit: the future is "dropped" here.
    unwatch
  }

  /// Mirrors `Tributaries::unwatch`'s state cleanup at the harness level (no real
  /// watcher): plan the unwatch, reclaim the subscription's epoch-ledger state on
  /// EVERY successful outcome, and disarm on a root-emptied outcome. Returns whether
  /// the subscription was live.
  async fn unwatch(&mut self, sub: Subscription) -> bool {
    match self.subsumer.plan_unwatch(sub) {
      None => false,
      Some(super::UnwatchOutcome::Dropped) => {
        self.filters.remove(&sub);
        self.epochs.remove(sub);
        true
      }
      Some(super::UnwatchOutcome::RootEmptied { fs_root }) => {
        self.filters.remove(&sub);
        self.epochs.remove(sub);
        let _ = self.armer.disarm(fs_root).await;
        true
      }
    }
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

/// The widen ordering (design §4), forced by the lower watcher's disjoint-root
/// contract: [`tributary_fs::Watcher::watch`] rejects a root overlapping a live one
/// (`Overlaps`), so the wider root **cannot** be armed while a subsumed one is live —
/// the widen must **disarm the subsumed roots BEFORE arming the wider root**. The brief
/// coverage gap this opens is closed by the dominating `Rescan` each re-pointed
/// subscription receives (loss-is-a-Rescan). This asserts that real-executable order
/// against the overlap-rejecting fake — the pre-fix arm-before-unwatch would have been
/// rejected by the fake (as by the kernel) and never reached here.
#[tokio::test]
async fn widen_disarms_subsumed_before_arming_the_wider_root() {
  let mut h = Harness::new();

  // Arm the narrow root /a/b first (handle 1).
  let s_narrow = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  // Now watch its ancestor /a — a widen: it subsumes /a/b. This SUCCEEDS only because
  // the widen disarms /a/b before arming /a; arming /a while /a/b is live would be
  // rejected `Overlaps` by the fake, exactly as the real watcher would reject it.
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a widens (subsumed /a/b disarmed first, so the wider arm is legal)");

  // The subsumed /a/b (handle 1) is disarmed FIRST, then the wider /a is armed — the
  // reverse of a naive arm-before-unwatch (which the disjoint-root contract forbids).
  assert_eq!(
    h.armer.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Disarm(1),
      Call::Arm(PathBuf::from("/a")),
    ],
    "disarm-subsumed precedes arm-wider on a widen (the only real-executable order)"
  );

  // The single surviving root is the wider /a (the subsumed /a/b handle is gone).
  let roots: Vec<PathBuf> = h.subsumer.roots().map(|(p, _)| p.to_path_buf()).collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a")],
    "the widen collapses to /a"
  );

  // The re-pointed /a/b subscriber gets a dominating Rescan closing the unwatch→arm gap,
  // naming the widened root to re-enumerate.
  let rescans: Vec<_> = h.queue.iter().collect();
  assert_eq!(rescans.len(), 1, "one dominating Rescan per re-pointed sub");
  assert!(rescans[0].is_rescan(), "the re-point signal is a Rescan");
  assert_eq!(
    rescans[0].subscription(),
    s_narrow,
    "it is delivered to the re-pointed subscriber"
  );
  assert_eq!(
    rescans[0].path(),
    Path::new("/a"),
    "the Rescan names the widened root the consumer must re-enumerate"
  );
}

/// The widen rollback (design §4/§8): when the wider arm FAILS after the subsumed roots
/// were disarmed, each subsumed root is re-armed (fresh handle) and its subscribers are
/// re-pointed with a dominating Rescan, restoring the pre-widen state; the newcomer's
/// `watch` returns the arm error and leaks no pending reservation or per-sub state.
#[tokio::test]
async fn widen_arm_failure_rolls_back_subsumed_roots() {
  let mut h = Harness::new();

  // Two narrow roots (handles 1 and 2), each its own subscription.
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c");
  // Give each some history so its rollback Rescan is a strict, checkable dominance.
  h.epochs.stamp(sb, Epoch::new(4));
  h.epochs.stamp(sc, Epoch::new(2));

  // Fail the WIDER arm: the widen disarms /a/b and /a/c, then the arm of /a fails.
  h.armer.fail_next_arm();
  let result = h.watch("/a", Interest::all()).await;
  assert!(result.is_err(), "the failed wider arm surfaces the error");

  // Rollback restored BOTH subsumed roots: /a/b and /a/c are re-armed (fresh handles 4
  // and 5) after being disarmed. The call trace: arm 1,2 (setup), then disarm 1,2 +
  // arm /a (fails, no handle) + re-arm /a/b, /a/c.
  assert_eq!(
    h.armer.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Arm(PathBuf::from("/a")), // the failed wider arm (mints no handle)
      Call::Arm(PathBuf::from("/a/b")), // rollback re-arm
      Call::Arm(PathBuf::from("/a/c")), // rollback re-arm
    ],
    "the wider arm fails after the subsumed roots are disarmed; both are re-armed"
  );

  // The two subsumed roots are live again (re-keyed onto their fresh handles), and the
  // failed wider root /a is NOT present.
  let roots: Vec<PathBuf> = h.subsumer.roots().map(|(p, _)| p.to_path_buf()).collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a/b"), PathBuf::from("/a/c")],
    "the pre-widen roots are restored; the failed wider root never committed"
  );
  // Both original subscriptions are still live and ride their restored roots.
  assert_eq!(h.subsumer.subscription_path(sb), Some(Path::new("/a/b")));
  assert_eq!(h.subsumer.subscription_path(sc), Some(Path::new("/a/c")));

  // Each restored subscriber got a dominating Rescan (the re-arm restarted fs epochs at
  // 0, and the disarm→re-arm window may have missed events — no silent loss).
  let by_sub: HashMap<Subscription, Epoch> = h
    .queue
    .iter()
    .map(|ev| {
      assert!(ev.is_rescan(), "every rollback signal is a Rescan");
      (ev.subscription(), ev.epoch())
    })
    .collect();
  assert_eq!(
    by_sub.len(),
    2,
    "one dominating Rescan per restored subscriber"
  );
  assert_eq!(
    by_sub.get(&sb).copied(),
    Some(Epoch::new(5)),
    "sb's rollback Rescan strictly dominates its high-water of 4"
  );
  assert_eq!(
    by_sub.get(&sc).copied(),
    Some(Epoch::new(3)),
    "sc's rollback Rescan strictly dominates its high-water of 2"
  );

  // No pending reservation leaked, and the newcomer established no subscription: a
  // subsequent watch of /a/b is Covered by the restored root (one arm, no new one).
  assert_eq!(
    h.subsumer.pending_len(),
    0,
    "the aborted widen leaks no pending reservation"
  );
}

/// The widen rollback's **degenerate** double-failure (design §4/§8): when a rollback
/// re-arm ALSO fails, that root cannot be restored — its subscribers are signalled a
/// loss Rescan (never silently dropped) and the dead root is torn out of the subsumer
/// with its subscribers' per-subscription state (filter + epoch) reclaimed, so nothing
/// dangles on a never-armed handle.
#[tokio::test]
async fn widen_rollback_double_failure_signals_loss_and_reclaims() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  h.epochs.stamp(sb, Epoch::new(7));
  assert!(
    h.filters.contains_key(&sb),
    "sb's filter is recorded before the loss"
  );

  // Fail the next TWO arms: the wider /a arm (→ rollback), then the rollback re-arm of
  // /a/b (→ degenerate: /a/b cannot be restored).
  h.armer.fail_arms(2);
  let result = h.watch("/a", Interest::all()).await;
  assert!(result.is_err(), "the failed wider arm surfaces the error");

  // Trace: setup arm /a/b, then disarm /a/b + the (failed) wider arm /a + the (failed)
  // rollback re-arm /a/b.
  assert_eq!(
    h.armer.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Disarm(1),
      Call::Arm(PathBuf::from("/a")),   // failed wider arm
      Call::Arm(PathBuf::from("/a/b")), // failed rollback re-arm
    ],
    "the wider arm fails, the rollback re-arm of the sole subsumed root also fails"
  );

  // The root could not be restored, so no live root remains — /a/b was torn out.
  assert_eq!(
    h.subsumer.roots().count(),
    0,
    "the unrestorable root is torn out (not left dangling on a never-armed handle)"
  );
  // sb's side-table record, filter, and epoch state are all reclaimed.
  assert_eq!(
    h.subsumer.subscription_path(sb),
    None,
    "the lost subscriber's side-table record is gone"
  );
  assert!(
    !h.filters.contains_key(&sb),
    "the lost subscriber's filter is reclaimed"
  );
  assert_eq!(
    h.epochs.tracked_len(),
    (0, 0),
    "the lost subscriber's epoch state is reclaimed"
  );

  // But the loss was NOT silent: sb received a dominating Rescan naming its root.
  let rescans: Vec<_> = h.queue.iter().collect();
  assert_eq!(
    rescans.len(),
    1,
    "the lost subscriber is signalled exactly one loss Rescan"
  );
  assert!(rescans[0].is_rescan(), "the loss signal is a Rescan");
  assert_eq!(
    rescans[0].subscription(),
    sb,
    "delivered to the lost subscriber"
  );
  assert_eq!(
    rescans[0].path(),
    Path::new("/a/b"),
    "the loss Rescan names the root whose coverage was lost"
  );
  assert_eq!(
    rescans[0].epoch(),
    Epoch::new(8),
    "the loss Rescan strictly dominates sb's high-water of 7"
  );

  // No pending reservation leaked.
  assert_eq!(h.subsumer.pending_len(), 0, "no pending reservation leaks");
}

/// The cancellation-safety journal (design §4, Finding 1): a `watch()` future dropped
/// after the widen disarmed the subsumed roots but before it armed the wider one leaves
/// subscribers on disarmed roots with no async cleanup — so the journal is set and the
/// NEXT public entry point's `resume_pending_widen` must bring state back to a consistent
/// pre-widen coverage: each disarmed subsumed root re-armed (fresh handle) and re-pointed
/// with a dominating Rescan, no subscriber left uncovered, the newcomer's pending
/// reservation discarded, and the journal cleared.
#[tokio::test]
async fn dropped_widen_after_disarm_is_repaired_on_next_call() {
  let mut h = Harness::new();

  // Two narrow roots (handles 1 and 2), each its own subscription and some history.
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c");
  h.epochs.stamp(sb, Epoch::new(4));
  h.epochs.stamp(sc, Epoch::new(2));

  // Simulate a `watch("/a")` future dropped mid-widen: journal set + /a/b, /a/c disarmed,
  // but the wider /a never armed and the plan never committed.
  let subsumed = h.journal_and_disarm_widen("/a").await;
  assert_eq!(subsumed.len(), 2, "the widen subsumed both narrow roots");
  assert!(h.pending_widen.is_some(), "the widen is journaled");
  // The subsumed kernel roots are disarmed — subscribers momentarily uncovered.
  for &old in &subsumed {
    assert!(
      h.armer.root_path(old).is_none(),
      "subsumed root {old} was disarmed by the dropped widen"
    );
  }
  // Give the newcomer's dropped plan a visible pending reservation to prove resume clears
  // it: exactly one plan is still pending (the /a widen the dropped future minted).
  assert_eq!(
    h.subsumer.pending_len(),
    1,
    "the dropped widen's newcomer plan is still pending"
  );

  // The next public entry point resumes the journal.
  h.resume().await;

  // Both subsumed roots are live again (re-armed onto fresh handles 4 and 5) and still
  // serve their subscriptions — nothing uncovered.
  let roots: Vec<PathBuf> = h.subsumer.roots().map(|(p, _)| p.to_path_buf()).collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a/b"), PathBuf::from("/a/c")],
    "the pre-widen roots are restored (re-armed); the dropped widen left no wider root"
  );
  assert_eq!(h.subsumer.subscription_path(sb), Some(Path::new("/a/b")));
  assert_eq!(h.subsumer.subscription_path(sc), Some(Path::new("/a/c")));
  // Both subscriptions are covered by a live root (fs knows their fresh handles).
  let live_handles: Vec<u32> = h.subsumer.roots().map(|(_, handle)| handle).collect();
  for handle in live_handles {
    assert!(
      h.armer.root_path(handle).is_some(),
      "the restored root's fresh handle is live-armed"
    );
  }

  // Each restored subscriber got a dominating Rescan (the re-arm restarted fs epochs at 0,
  // and the disarm→re-arm window may have dropped events — no silent loss).
  let by_sub: HashMap<Subscription, Epoch> = h
    .queue
    .iter()
    .map(|ev| {
      assert!(ev.is_rescan(), "every repair signal is a Rescan");
      (ev.subscription(), ev.epoch())
    })
    .collect();
  assert_eq!(
    by_sub.len(),
    2,
    "one dominating Rescan per restored subscriber"
  );
  assert_eq!(
    by_sub.get(&sb).copied(),
    Some(Epoch::new(5)),
    "sb's repair Rescan strictly dominates its high-water of 4"
  );
  assert_eq!(
    by_sub.get(&sc).copied(),
    Some(Epoch::new(3)),
    "sc's repair Rescan strictly dominates its high-water of 2"
  );

  // The journal is cleared and the newcomer's pending reservation was discarded (the
  // dropped future handed out no subscription).
  assert!(
    h.pending_widen.is_none(),
    "the journal is cleared after resume"
  );
  assert_eq!(
    h.subsumer.pending_len(),
    0,
    "resume discarded the dropped widen's pending reservation"
  );

  // Resume is a no-op the second time (idempotent): no extra arms, no extra Rescans.
  let arms_before = h.armer.arm_count();
  let queued_before = h.queue.len();
  h.resume().await;
  assert_eq!(
    h.armer.arm_count(),
    arms_before,
    "a second resume arms nothing"
  );
  assert_eq!(
    h.queue.len(),
    queued_before,
    "a second resume queues nothing"
  );
}

/// `resume_pending_widen` is a no-op when nothing is journaled (design §4, idempotency):
/// the common case — every entry point calls it, but almost no call has a pending widen.
#[tokio::test]
async fn resume_is_idempotent_when_nothing_pending() {
  let mut h = Harness::new();

  // A couple of live subscriptions and no in-flight widen.
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/x/y", Interest::all()).await.expect("watch /x/y");
  assert!(h.pending_widen.is_none(), "no widen is journaled");

  let calls_before = h.armer.calls();
  let queued_before = h.queue.len();
  let roots_before: Vec<PathBuf> = h.subsumer.roots().map(|(p, _)| p.to_path_buf()).collect();

  // Resume with nothing pending — must change nothing.
  h.resume().await;

  assert!(h.pending_widen.is_none(), "still nothing journaled");
  assert_eq!(h.armer.calls(), calls_before, "resume issued no fs calls");
  assert_eq!(h.queue.len(), queued_before, "resume queued nothing");
  let roots_after: Vec<PathBuf> = h.subsumer.roots().map(|(p, _)| p.to_path_buf()).collect();
  assert_eq!(roots_after, roots_before, "the live roots are unchanged");
  // The subscriptions are untouched and still live.
  assert_eq!(h.subsumer.subscription_path(sb), Some(Path::new("/a/b")));
  assert_eq!(h.subsumer.subscription_path(sc), Some(Path::new("/x/y")));
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

/// Every kernel arm — Disjoint AND Widen — uses `Interest::all` regardless of the
/// subscription's requested interest (design §4): the root never narrows what it
/// collects, so a covered/subsumed subscription can ask for any kind without the
/// shared watch under-serving it. The requested interest becomes a per-subscription
/// fan-out gate, recorded in the side table (asserted below), not a demand on the arm.
#[tokio::test]
async fn every_arm_uses_interest_all_and_records_the_sub_interest() {
  let mut h = Harness::new();

  // Two subsumed roots with DISJOINT interests, plus a newcomer with a third.
  let created_only = Interest::new().with_created();
  let removed_only = Interest::new().with_removed();
  let modified_only = Interest::new().with_modified();

  let sb = h.watch("/a/b", created_only).await.expect("watch /a/b");
  let sc = h.watch("/a/c", removed_only).await.expect("watch /a/c");

  // Widen over both with a newcomer wanting only modifications.
  let sa = h.watch("/a", modified_only).await.expect("watch /a widens");

  // The single surviving root is /a.
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

  // Every arm the driver issued used Interest::all — never the caller's narrow mask.
  for interest in h.armer.armed_interests() {
    assert_eq!(
      interest,
      Interest::all(),
      "every umbrella arm (disjoint + widen) is Interest::all"
    );
  }

  // Each subscription keeps its OWN interest in the side table as its fan-out gate;
  // the widen re-point preserves each subsumed sub's interest.
  assert_eq!(h.subsumer.subscription_interest(sb), Some(created_only));
  assert_eq!(h.subsumer.subscription_interest(sc), Some(removed_only));
  assert_eq!(h.subsumer.subscription_interest(sa), Some(modified_only));
}

/// A `Covered` subscription may ask for a kind its covering root's original watcher
/// never requested, and it is still served — because the root is armed `Interest::all`
/// (design §4), so nothing is under-served with no compensating `Rescan`. The
/// requested interest is recorded as this subscription's fan-out gate. (The regression:
/// the pre-fix Covered branch adopted the subscriber without ensuring the root's armed
/// interest covered it, so a removed-asking covered sub under a created-only root
/// silently lost removals below.)
#[tokio::test]
async fn covered_sub_with_wider_interest_still_delivered() {
  let mut h = Harness::new();

  // Arm /a asking only for creations…
  let created_only = Interest::new().with_created();
  h.watch("/a", created_only).await.expect("watch /a");

  // …then a covered /a/b asking only for removals.
  let removed_only = Interest::new().with_removed();
  let sb = h
    .watch("/a/b", removed_only)
    .await
    .expect("watch /a/b covered");

  // Exactly one arm (the second is Covered), and it was Interest::all — so the root
  // DOES carry removals for /a/b, even though /a asked only for creations.
  assert_eq!(
    h.armer.arm_count(),
    1,
    "the covered watch issues no second arm"
  );
  assert_eq!(
    h.armer.armed_interests(),
    vec![Interest::all()],
    "the one arm is Interest::all, so the root carries every kind"
  );

  // /a/b's own gate is its requested removed-only interest; a removal under /a/b passes
  // it. The interest_admits gate lives in fan_out_raw over a real fs event, so here we
  // assert the recorded gate directly (the fan-out projection is covered in route/epoch
  // tests): the root is all() and the sub's gate admits removals.
  assert_eq!(
    h.subsumer.subscription_interest(sb),
    Some(removed_only),
    "the covered sub's own removed-only interest is its fan-out gate"
  );
  use super::interest_admits;
  assert!(
    interest_admits(removed_only, &tributary_fs::EventKind::Removed),
    "a removal under /a/b is admitted by the covered sub's gate — not silently lost"
  );
  assert!(
    !interest_admits(created_only, &tributary_fs::EventKind::Removed),
    "…and the gate is genuinely narrowing (a created-only gate would drop it)"
  );
}

/// Two subscriptions at the SAME path with HETEROGENEOUS interest each keep their own
/// gate (design §4/§5): the root is armed all() once, and both interests coexist in the
/// side table.
#[tokio::test]
async fn equal_path_heterogeneous_interest() {
  let mut h = Harness::new();
  let created_only = Interest::new().with_created();
  let removed_only = Interest::new().with_removed();

  let s1 = h.watch("/a", created_only).await.expect("watch /a created");
  // A second watch at the exact same path is Covered by the first (get_ancestor is
  // ancestor-OR-equal), sharing the one root; it keeps its own removed-only gate.
  let s2 = h.watch("/a", removed_only).await.expect("watch /a removed");

  assert_eq!(h.armer.arm_count(), 1, "equal paths share one kernel watch");
  assert_eq!(h.subsumer.subscription_interest(s1), Some(created_only));
  assert_eq!(h.subsumer.subscription_interest(s2), Some(removed_only));
}

/// The canonicalization TOCTOU (design §4): when fs's reported root path diverges from
/// the umbrella's planned one but stays disjoint, the subsumer is keyed on FS's path —
/// so later fs-canonical events (which start with fs's path, not the planned one) route
/// to the creating subscription instead of being silently dropped by a `starts_with`
/// miss.
#[tokio::test]
async fn canonical_key_uses_fs_root_path_not_the_planned_one() {
  let mut h = Harness::new();

  // The umbrella plans /a/link, but fs canonicalizes a symlinked component to /a/real.
  h.armer.retarget("/a/link", "/a/real");
  let sub = h
    .watch("/a/link", Interest::all())
    .await
    .expect("watch /a/link");

  // The committed root + side-table path are fs's /a/real — the coordinate events use.
  let roots: Vec<PathBuf> = h.subsumer.roots().map(|(p, _)| p.to_path_buf()).collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a/real")],
    "the root is keyed on fs's canonical path, not the planned /a/link"
  );
  assert_eq!(
    h.subsumer.subscription_path(sub),
    Some(Path::new("/a/real")),
    "the subscription's coverage path is in fs's coordinate"
  );
  // A fs-canonical event under /a/real is covered by the subscription's /a/real path;
  // under the pre-fix /a/link key it would fail starts_with and be silently dropped.
  assert!(
    Path::new("/a/real/child").starts_with(h.subsumer.subscription_path(sub).unwrap()),
    "an fs-canonical event routes to the creating subscription (no silent drop)"
  );
}

/// The TOCTOU abort path (design §4): when fs's reported path diverges in a way that
/// changes subsumption — here it lands UNDER an existing root, so it should have been
/// Covered, not a fresh arm — the driver disarms the just-armed root and aborts
/// cleanly, leaving no mis-keyed or overlapping entry (and no pending leak).
#[tokio::test]
async fn canonical_race_that_changes_subsumption_aborts_cleanly() {
  let mut h = Harness::new();
  h.watch("/a", Interest::all()).await.expect("watch /a");

  // A disjoint plan for /b, but fs reports it canonicalizes to /a/inside — now covered
  // by the existing /a root. Committing it as a fresh disjoint root would break
  // disjointness, so the driver must abort.
  h.armer.retarget("/b", "/a/inside");
  let result = h.watch("/b", Interest::all()).await;
  assert!(
    result.is_err(),
    "a subsumption-changing canonical race aborts"
  );

  // The just-armed root was disarmed (arm then disarm of handle 2), and no phantom
  // entry lingers: the only live root is still /a.
  let roots: Vec<PathBuf> = h.subsumer.roots().map(|(p, _)| p.to_path_buf()).collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a")],
    "no mis-keyed entry lingers"
  );
  assert_eq!(
    h.subsumer.pending_len(),
    0,
    "the aborted plan leaks no pending reservation"
  );
  assert!(
    matches!(h.armer.calls().last(), Some(Call::Disarm(_))),
    "the just-armed root was disarmed on abort"
  );
}

/// The `EpochLedger` is reclaimed on EVERY successful unwatch (design; Finding 4): a
/// watch → stamp/repoint → unwatch churn must not grow the ledger's base/high_water
/// maps unbounded. Both the plain-Dropped and last-subscriber-RootEmptied outcomes
/// must call `remove`.
#[tokio::test]
async fn unwatch_reclaims_epoch_ledger_across_churn() {
  let mut h = Harness::new();

  // Churn many cycles; each watch stamps (populating high_water) and some widen
  // (populating base via repoint), then unwatch — which must reclaim both.
  for _ in 0..50 {
    let a = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
    h.epochs.stamp(a, Epoch::new(7)); // populate high_water for a
    // Widen over /a/b with /a → repoints `a` (populates base for a) and adds `wide`.
    let wide = h
      .watch("/a", Interest::all())
      .await
      .expect("watch /a widens");
    // Drain both subscriptions.
    assert!(h.unwatch(a).await, "a was live");
    assert!(h.unwatch(wide).await, "wide was live");
  }

  // After the churn the ledger holds NO per-subscription state — both maps reclaimed.
  assert_eq!(
    h.epochs.tracked_len(),
    (0, 0),
    "unwatch reclaims epoch base + high_water on every outcome (no unbounded leak)"
  );
  // And the subsumer has no live roots either.
  assert_eq!(
    h.subsumer.roots().count(),
    0,
    "all roots released after the churn"
  );
}
