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
        fail_next_arm: false,
        root_paths: HashMap::new(),
        retarget: HashMap::new(),
        armed_interests: Vec::new(),
      }),
    }
  }

  /// Arm the next call fails.
  fn fail_next_arm(&self) {
    self.inner.borrow_mut().fail_next_arm = true;
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
    if inner.fail_next_arm {
      inner.fail_next_arm = false;
      return Err(WatchError::Canonicalize {
        path: path.to_path_buf(),
        source: io::Error::other("injected arm failure"),
      });
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
    Ok(handle)
  }

  fn root_path(&self, handle: u32) -> Option<PathBuf> {
    self.inner.borrow().root_paths.get(&handle).cloned()
  }

  async fn disarm(&self, handle: u32) -> Result<(), super::UnwatchError> {
    let mut inner = self.inner.borrow_mut();
    inner.calls.push(Call::Disarm(handle));
    inner.root_paths.remove(&handle);
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

  /// Mirrors `Tributaries::unwatch`'s state cleanup at the harness level (no real
  /// watcher): plan the unwatch, reclaim the subscription's epoch-ledger state on
  /// EVERY successful outcome, and disarm on a root-emptied outcome. Returns whether
  /// the subscription was live.
  async fn unwatch(&mut self, sub: Subscription) -> bool {
    match self.subsumer.plan_unwatch(sub) {
      None => false,
      Some(super::UnwatchOutcome::Dropped) => {
        self.epochs.remove(sub);
        true
      }
      Some(super::UnwatchOutcome::RootEmptied { fs_root }) => {
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
