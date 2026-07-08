use std::{
  collections::{BTreeMap, HashMap, VecDeque},
  ffi::OsString,
  io,
  marker::PhantomData,
  num::NonZeroU64,
  path::{Path, PathBuf},
  time::Duration,
};

use agnostic_lite::tokio::TokioRuntime;
use tributary_fs::{ChangeId, Epoch, EventKind, Interest, Location, WatchRootError};

use super::{Owner, epoch::EpochLedger, interest_admits};
use crate::{
  coalesce::Coalescer,
  error::{UnwatchError, WatchError},
  event::Event,
  filter::Filter,
  source::{Armed, Source, SourceEvent},
  subscription::Subscription,
  subsume::Subsumer,
};

/// A path's `OsString` components — the key form the fs subsumer uses.
fn key(path: &str) -> Vec<OsString> {
  components(Path::new(path))
}

/// A path's `OsString` components.
fn components(path: &Path) -> Vec<OsString> {
  path
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

/// One recorded call against the fake source, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
  Arm(PathBuf),
  Disarm(u32),
}

/// A fake [`Source`] over `u32` handles: it records every arm/disarm in order (so a test
/// can assert the widen sequence), can be told to fail the *next* arm (so a test can drive
/// the arm-failure path), and models the source's canonical-key adoption (a `retarget`
/// diverges the reported canonical key from the requested one — the design §4 TOCTOU).
///
/// **It enforces the source's disjoint-root contract** (mirroring [`tributary_fs::Watcher`]):
/// arming a key overlapping a currently-armed fake root returns
/// [`WatchRootError::Overlaps`], so the widen-ordering tests validate a *real-executable*
/// sequence — a naive arm-before-unwatch would be rejected here just as the kernel watcher
/// rejects it.
struct FakeSource {
  next_handle: u32,
  calls: Vec<Call>,
  /// Each currently-live handle's arm-path — the overlap check keys on this.
  live: HashMap<u32, PathBuf>,
  /// Each live handle's fs-authoritative canonical key ([`Source::root_key`] reports it,
  /// and [`Source::arm`] returns it). `None` once the root is disarmed or killed.
  canonical: HashMap<u32, Vec<OsString>>,
  /// How many of the next `arm` calls to fail, decremented on each failed arm.
  fail_arms: u32,
  /// Planned path → the divergent canonical path `arm` should report for it (the §4
  /// canonicalization TOCTOU: the source commits a different coordinate than planned).
  retarget: HashMap<PathBuf, PathBuf>,
}

impl FakeSource {
  fn new() -> Self {
    Self {
      next_handle: 0,
      calls: Vec::new(),
      live: HashMap::new(),
      canonical: HashMap::new(),
      fail_arms: 0,
      retarget: HashMap::new(),
    }
  }

  /// The next `arm` call fails.
  fn fail_next_arm(&mut self) {
    self.fail_arms = 1;
  }

  /// The next `n` `arm` calls fail (each decrements the counter) — drives the failed-widen
  /// restore where the wider arm AND some re-arms fail.
  fn fail_next_arms(&mut self, n: u32) {
    self.fail_arms = n;
  }

  /// Model the canonicalization TOCTOU: an `arm(planned)` reports `fs` as the handle's
  /// canonical key, diverging from what was planned.
  fn retarget(&mut self, planned: &str, fs: &str) {
    self
      .retarget
      .insert(PathBuf::from(planned), PathBuf::from(fs));
  }

  /// Model the root dying out of band (deleted / torn down): its handle stops naming a
  /// live root, so [`Source::root_key`] answers `None` — without recording a `Disarm`
  /// (the umbrella never released it; the source did).
  fn kill_root(&mut self, handle: u32) {
    self.canonical.remove(&handle);
    self.live.remove(&handle);
  }

  fn calls(&self) -> Vec<Call> {
    self.calls.clone()
  }

  fn arm_count(&self) -> usize {
    self
      .calls
      .iter()
      .filter(|c| matches!(c, Call::Arm(_)))
      .count()
  }
}

impl Source<OsString> for FakeSource {
  type Handle = u32;

  async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
    let path: PathBuf = key.iter().collect();
    self.calls.push(Call::Arm(path.clone()));
    if self.fail_arms > 0 {
      self.fail_arms -= 1;
      return Err(WatchError::Canonicalize {
        path,
        source: io::Error::other("injected arm failure"),
      });
    }
    // The disjoint-root contract (design §4): reject a key overlapping any live root,
    // exactly as `tributary_fs::Watcher` does — this forces disarm-before-arm on a widen.
    if let Some(existing) = self
      .live
      .values()
      .find(|live| path.starts_with(live) || live.starts_with(&path))
      .cloned()
    {
      return Err(WatchError::Fs(WatchRootError::Overlaps { path, existing }));
    }
    self.next_handle += 1;
    let handle = self.next_handle;
    // The canonical key: the retarget override, else the requested key. Overlap tracks the
    // arm-path (the coordinate planned against); the retarget models a separate fs-side
    // divergence the `fs_path_preserves_plan` guard catches, not this overlap check.
    let canonical_path = self
      .retarget
      .get(&path)
      .cloned()
      .unwrap_or_else(|| path.clone());
    let canonical_key = components(&canonical_path);
    self.canonical.insert(handle, canonical_key.clone());
    self.live.insert(handle, path);
    Ok(Armed::new(handle, canonical_key))
  }

  async fn disarm(&mut self, handle: u32) {
    self.calls.push(Call::Disarm(handle));
    self.canonical.remove(&handle);
    self.live.remove(&handle);
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    None
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.canonical.get(&handle).cloned()
  }
}

/// Builds a `Rescan` [`SourceEvent`] for `handle` at `path` — the terminal / overflow
/// coverage-loss signal `retire_if_dead` classifies via [`Source::root_key`].
fn rescan_event(handle: u32, path: &str) -> SourceEvent<OsString, u32> {
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Rescan,
    None,
    Location::new(),
    Epoch::new(0),
    ChangeId::new(NonZeroU64::MIN),
  )
}

/// A synthetic `Modified` [`Event`] for `sub` at `path`, pre-stamped umbrella epoch
/// `epoch` — the ready-to-deliver event the backpressure tests feed straight into
/// [`Owner::try_emit`], the funnel that fills the bounded channel and sheds on overflow.
fn modified_event(sub: Subscription, path: &str, epoch: u64) -> Event<OsString, ()> {
  Event::synthetic(
    sub,
    key(path),
    Location::new(),
    EventKind::Modified,
    Epoch::new(epoch),
  )
}

/// A raw `Modified` [`SourceEvent`] for `handle` at `path` — the cancel-safety test's queued
/// changes, distinguished by key.
fn source_modified(handle: u32, path: &str, epoch: u64) -> SourceEvent<OsString, u32> {
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Modified,
    None,
    Location::new(),
    Epoch::new(epoch),
    ChangeId::new(NonZeroU64::MIN),
  )
}

/// Drives the owner's reconcile primitives over a [`FakeSource`], with the owner's event
/// stream drained on demand — the sans-I/O reconcile logic exercised without a real
/// filesystem, runtime timers, or the select loop.
struct Harness {
  owner: Owner<OsString, (), TokioRuntime, FakeSource>,
  events: async_channel::Receiver<Event<OsString, ()>>,
  /// Kept alive so the owner's command receiver never observes a closed channel (the loop
  /// is not run here; reconcile is driven directly).
  _commands: async_channel::Sender<super::Command<OsString, ()>>,
}

impl Harness {
  fn new() -> Self {
    Self::with_coalescer(None)
  }

  fn with_coalescer(coalescer: Option<Coalescer<OsString, ()>>) -> Self {
    Self::build(coalescer, None)
  }

  /// A harness whose owner→consumer event channel is **bounded** at `capacity` — for the
  /// backpressure tests, where a stalled consumer fills the channel and the owner sheds the
  /// affected subscription to a parked dominating `Rescan` (design backpressure doc).
  fn bounded(capacity: usize) -> Self {
    Self::build(None, Some(capacity))
  }

  fn build(coalescer: Option<Coalescer<OsString, ()>>, capacity: Option<usize>) -> Self {
    let (event_tx, event_rx) = match capacity {
      Some(cap) => async_channel::bounded(cap),
      None => async_channel::unbounded(),
    };
    let (command_tx, command_rx) = async_channel::unbounded();
    let owner = Owner {
      source: FakeSource::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
      needs_rescan: BTreeMap::new(),
      coalescer,
      commands: command_rx,
      events: event_tx,
      _rt: PhantomData::<TokioRuntime>,
    };
    Self {
      owner,
      events: event_rx,
      _commands: command_tx,
    }
  }

  async fn watch(&mut self, path: &str, interest: Interest) -> Result<Subscription, WatchError> {
    self
      .owner
      .reconcile_watch(&key(path), (), interest, Filter::all())
      .await
  }

  async fn unwatch(&mut self, sub: Subscription) -> Result<(), UnwatchError> {
    self.owner.reconcile_unwatch(sub).await
  }

  /// Every event the owner has pushed to its stream so far (Rescans, coalescer output).
  fn drain(&self) -> Vec<Event<OsString, ()>> {
    let mut out = Vec::new();
    while let Ok(event) = self.events.try_recv() {
      out.push(event);
    }
    out
  }
}

#[tokio::test]
async fn overlapping_watch_issues_one_arm() {
  let mut h = Harness::new();

  h.watch("/a", Interest::all()).await.expect("watch /a");
  let covered = h.watch("/a/b", Interest::all()).await;
  assert!(
    covered.is_ok(),
    "an overlapping watch never surfaces Overlaps"
  );

  assert_eq!(
    h.owner.source.arm_count(),
    1,
    "two overlapping subscriptions collapse to exactly one arm"
  );
  assert_eq!(
    h.owner.source.calls(),
    vec![Call::Arm(PathBuf::from("/a"))],
    "only the covering root /a is armed"
  );
}

/// The widen ordering (design §4), forced by the source's disjoint-root contract: the
/// wider root cannot be armed while a subsumed one is live, so the widen must **disarm the
/// subsumed roots BEFORE arming the wider root**. The brief coverage gap is closed by the
/// dominating `Rescan` each re-pointed subscription receives.
#[tokio::test]
async fn widen_disarms_subsumed_before_arming_the_wider_root() {
  let mut h = Harness::new();

  let s_narrow = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a widens (subsumed /a/b disarmed first, so the wider arm is legal)");

  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Disarm(1),
      Call::Arm(PathBuf::from("/a")),
    ],
    "disarm-subsumed precedes arm-wider on a widen (the only real-executable order)"
  );

  let roots: Vec<PathBuf> = h
    .owner
    .subsumer
    .roots()
    .map(|(k, _)| PathBuf::from_iter(k))
    .collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a")],
    "the widen collapses to /a"
  );

  let rescans = h.drain();
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

#[tokio::test]
async fn arm_failure_abandons_plan_no_pending_leak() {
  let mut h = Harness::new();

  h.owner.source.fail_next_arm();
  let result = h.watch("/a", Interest::all()).await;

  assert!(result.is_err(), "a failed arm surfaces the error");
  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "a failed arm abandons the plan — no pending reservation leaks"
  );
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a after the earlier failure");
  assert_eq!(
    h.owner.source.arm_count(),
    2,
    "the retried watch arms again (the failed plan left no live root)"
  );
}

#[tokio::test]
async fn widen_emits_dominating_rescan_per_repointed_sub() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c");
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  h.watch("/a", Interest::all())
    .await
    .expect("watch /a widens");

  let rescans = h.drain();
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

/// The widen arm failure RESTORE (design driver-golden doc, invariant I3): when the wider
/// arm FAILS after the subsumed roots were disarmed, the owner
/// must **not** leave those live subscriptions bound to disarmed handles (recorded-live yet
/// never delivering again). It re-arms each disarmed root through the choke point and mints
/// a dominating Rescan per subscriber — the subs are live-and-covered again, never
/// published-watched-but-disarmed. Regression: the old code signalled one Rescan and left
/// the roots disarmed, so future changes were silently lost.
#[tokio::test]
async fn widen_arm_failure_restores_disarmed_roots() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c");
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // Only the wider arm fails; the two restore re-arms succeed.
  h.owner.source.fail_next_arm();
  let result = h.watch("/a", Interest::all()).await;
  assert!(result.is_err(), "the failed wider arm surfaces the error");

  // Disarm-subsumed, wider arm fails, THEN both subsumed roots are re-armed (the restore).
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Arm(PathBuf::from("/a")),
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
    ],
    "the failed widen re-arms the disarmed subsumed roots (restore, not strand)"
  );

  // No pending reservation leaked (the newcomer's plan was aborted).
  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "the aborted widen leaks no pending reservation"
  );

  // Both subsumed subscriptions are live-and-covered again on FRESH, live handles.
  let view = h.owner.subsumer.view();
  assert!(
    view.is_watched(&key("/a/b")) && view.is_watched(&key("/a/c")),
    "the restored subscriptions read watched again"
  );
  let roots: Vec<(PathBuf, u32)> = h
    .owner
    .subsumer
    .roots()
    .map(|(k, handle)| (PathBuf::from_iter(k), handle))
    .collect();
  assert_eq!(
    roots.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(),
    vec![PathBuf::from("/a/b"), PathBuf::from("/a/c")],
    "the two subsumed roots are back (re-armed), not collapsed and not gone"
  );
  for (path, handle) in &roots {
    assert!(
      h.owner.source.root_key(*handle).is_some(),
      "the re-armed root {path:?} is on a LIVE handle — never published-watched-but-disarmed"
    );
  }

  // Each restored subscriber got a dominating Rescan (re-enumerate onto the re-armed root).
  let by_sub: HashMap<Subscription, Epoch> = h
    .drain()
    .iter()
    .map(|ev| {
      assert!(ev.is_rescan(), "every restore signal is a Rescan");
      (ev.subscription(), ev.epoch())
    })
    .collect();
  assert_eq!(
    by_sub.get(&sb).copied(),
    Some(Epoch::new(5)),
    "sb's restore Rescan strictly dominates its high-water of 4"
  );
  assert_eq!(
    by_sub.get(&sc).copied(),
    Some(Epoch::new(3)),
    "sc's restore Rescan strictly dominates its high-water of 2"
  );
}

/// The failed-widen restore when a subsumed root is genuinely DEAD (design driver-golden
/// doc, invariant I3/I4): the wider arm fails AND one disarmed root
/// cannot be re-armed. That root is RETIRED — a dominating terminal Rescan, its per-sub
/// state freed, and it leaves the view — while the re-armable one is restored. Never a
/// sub left recorded-live-but-disarmed.
#[tokio::test]
async fn widen_arm_failure_retires_root_that_cannot_rearm() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c");
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // Fail the wider arm AND the first restore re-arm (/a/b): so /a/b cannot be re-armed
  // (retired) while /a/c re-arms (restored). Restore iterates in root-key order (/a/b, /a/c).
  h.owner.source.fail_next_arms(2);
  let result = h.watch("/a", Interest::all()).await;
  assert!(result.is_err(), "the failed wider arm surfaces the error");

  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "the aborted widen leaks no pending reservation"
  );

  let view = h.owner.subsumer.view();
  // /a/c re-armed and covered; /a/b retired (removed from the view — no longer watched).
  assert!(
    view.is_watched(&key("/a/c")),
    "the re-armable subsumed root is restored and watched"
  );
  assert!(
    !view.is_watched(&key("/a/b")),
    "the dead subsumed root is RETIRED — not left published-watched-but-disarmed"
  );
  let roots: Vec<PathBuf> = h
    .owner
    .subsumer
    .roots()
    .map(|(k, _)| PathBuf::from_iter(k))
    .collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a/c")],
    "only the re-armed root remains; the un-re-armable one is gone"
  );
  // The retired /a/b subscriber's per-sub state is freed (I4); the restored /a/c's is kept.
  assert!(
    !h.owner.filters.contains_key(&sb),
    "the retired root's subscriber filter is freed (I4)"
  );
  assert!(
    h.owner.filters.contains_key(&sc),
    "the restored subscriber's filter is kept"
  );

  // BOTH subscribers got a dominating Rescan (sb: terminal/retire; sc: restore re-point).
  let by_sub: HashMap<Subscription, Epoch> = h
    .drain()
    .iter()
    .map(|ev| {
      assert!(ev.is_rescan(), "every loss/restore signal is a Rescan");
      (ev.subscription(), ev.epoch())
    })
    .collect();
  assert_eq!(
    by_sub.get(&sb).copied(),
    Some(Epoch::new(5)),
    "the retired sb's terminal Rescan strictly dominates its high-water of 4"
  );
  assert_eq!(
    by_sub.get(&sc).copied(),
    Some(Epoch::new(3)),
    "the restored sc's Rescan strictly dominates its high-water of 2"
  );
}

/// A `Covered` subscription may ask for a kind its covering root's original watcher never
/// requested, and is still served — every root is armed the source's widest interest
/// (design §4), so nothing is under-served. The requested interest is recorded as this
/// subscription's fan-out gate.
#[tokio::test]
async fn covered_sub_with_wider_interest_still_delivered() {
  let mut h = Harness::new();

  let created_only = Interest::new().with_created();
  h.watch("/a", created_only).await.expect("watch /a");

  let removed_only = Interest::new().with_removed();
  let sb = h
    .watch("/a/b", removed_only)
    .await
    .expect("watch /a/b covered");

  assert_eq!(
    h.owner.source.arm_count(),
    1,
    "the covered watch issues no second arm"
  );
  assert_eq!(
    h.owner.subsumer.subscription_interest(sb),
    Some(removed_only),
    "the covered sub's own removed-only interest is its fan-out gate"
  );
  assert!(
    interest_admits(removed_only, &EventKind::Removed),
    "a removal under /a/b is admitted by the covered sub's gate — not silently lost"
  );
  assert!(
    !interest_admits(created_only, &EventKind::Removed),
    "…and the gate is genuinely narrowing (a created-only gate would drop it)"
  );
}

/// Two subscriptions at the SAME path with heterogeneous interest each keep their own gate
/// (design §4/§5): one root, both interests coexist in the side table.
#[tokio::test]
async fn equal_path_heterogeneous_interest() {
  let mut h = Harness::new();
  let created_only = Interest::new().with_created();
  let removed_only = Interest::new().with_removed();

  let s1 = h.watch("/a", created_only).await.expect("watch /a created");
  let s2 = h.watch("/a", removed_only).await.expect("watch /a removed");

  assert_eq!(
    h.owner.source.arm_count(),
    1,
    "equal paths share one kernel watch"
  );
  assert_eq!(
    h.owner.subsumer.subscription_interest(s1),
    Some(created_only)
  );
  assert_eq!(
    h.owner.subsumer.subscription_interest(s2),
    Some(removed_only)
  );
}

/// The canonical-key adoption (design §4, invariant I2): the subsumer is keyed on the
/// source's reported canonical key, not the planned one — so later canonical events route
/// to the creating subscription instead of missing a `starts_with` on the planned key.
#[tokio::test]
async fn canonical_key_uses_source_key_not_the_planned_one() {
  let mut h = Harness::new();

  h.owner.source.retarget("/a/link", "/a/real");
  let sub = h
    .watch("/a/link", Interest::all())
    .await
    .expect("watch /a/link");

  let roots: Vec<PathBuf> = h
    .owner
    .subsumer
    .roots()
    .map(|(k, _)| PathBuf::from_iter(k))
    .collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a/real")],
    "the root is keyed on the source's canonical key, not the planned /a/link"
  );
  assert_eq!(
    h.owner.subsumer.subscription_key(sub),
    Some(key("/a/real").as_slice()),
    "the subscription's coverage key is in the source's coordinate"
  );
  assert!(
    key("/a/real/child").starts_with(h.owner.subsumer.subscription_key(sub).unwrap()),
    "a canonical event routes to the creating subscription (no silent drop)"
  );
}

/// The canonical-race abort (design §4, invariant I2): when the source's reported key
/// diverges in a way that changes subsumption (here it lands UNDER an existing root), the
/// owner disarms the just-armed root and aborts cleanly — no mis-keyed entry, no leak.
#[tokio::test]
async fn canonical_race_that_changes_subsumption_aborts_cleanly() {
  let mut h = Harness::new();
  h.watch("/a", Interest::all()).await.expect("watch /a");

  h.owner.source.retarget("/b", "/a/inside");
  let result = h.watch("/b", Interest::all()).await;
  assert!(
    result.is_err(),
    "a subsumption-changing canonical race aborts"
  );

  let roots: Vec<PathBuf> = h
    .owner
    .subsumer
    .roots()
    .map(|(k, _)| PathBuf::from_iter(k))
    .collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a")],
    "no mis-keyed entry lingers"
  );
  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "the aborted plan leaks no pending reservation"
  );
  assert!(
    matches!(h.owner.source.calls().last(), Some(Call::Disarm(_))),
    "the just-armed root was disarmed on abort"
  );
}

/// The `EpochLedger` is reclaimed on EVERY successful unwatch (invariant I4): a watch →
/// stamp/repoint → unwatch churn must not grow the ledger's maps unbounded.
#[tokio::test]
async fn unwatch_reclaims_epoch_ledger_across_churn() {
  let mut h = Harness::new();

  for _ in 0..50 {
    let a = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
    h.owner.epochs.stamp(a, Epoch::new(7));
    let wide = h
      .watch("/a", Interest::all())
      .await
      .expect("watch /a widens");
    let _ = h.drain(); // discard the repoint Rescans
    assert!(h.unwatch(a).await.is_ok(), "a was live");
    assert!(h.unwatch(wide).await.is_ok(), "wide was live");
  }

  assert_eq!(
    h.owner.epochs.tracked_len(),
    (0, 0),
    "unwatch reclaims epoch base + high_water on every outcome (no unbounded leak)"
  );
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "all roots released after the churn"
  );
}

/// The source liveness hook (design §4, Step 4 / invariant I4): `retire_if_dead` retires a
/// root exactly when the source has forgotten it ([`Source::root_key`] is `None` — a
/// terminal coverage loss), and keeps a still-live root (an overflow re-enumeration).
/// Retirement frees the root's index + filter + epoch state through the one retire point.
#[tokio::test]
async fn terminal_rescan_retires_root_overflow_keeps_it() {
  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  h.owner.epochs.stamp(sub, Epoch::new(3));

  // Handle 1 is live: an overflow Rescan (root_key is Some) must NOT retire it.
  h.owner.retire_if_dead(&rescan_event(1, "/a"));
  assert_eq!(
    h.owner.subsumer.roots().count(),
    1,
    "an overflow Rescan on a still-live root keeps it"
  );
  assert!(
    h.owner.filters.contains_key(&sub),
    "the live root's subscriber state is untouched"
  );

  // The root dies out of band (root_key now None): the terminal Rescan retires it.
  h.owner.source.kill_root(1);
  h.owner.retire_if_dead(&rescan_event(1, "/a"));
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "a terminal Rescan retires the dead root (I4)"
  );
  assert!(
    !h.owner.filters.contains_key(&sub),
    "retirement frees the filter (I4)"
  );
  assert_eq!(
    h.owner.epochs.tracked_len(),
    (0, 0),
    "retirement frees the epoch state (I4)"
  );
}

/// The one residual "dropped wait" case (design driver-golden doc, invariant I1): a
/// `watch` whose caller vanished after the reconcile committed (its reply `oneshot` is
/// closed) is treated as an immediate unwatch — the orphaned subscription is reconciled
/// away, releasing its root and per-sub state, so nothing leaks.
#[tokio::test]
async fn caller_vanished_after_commit_is_reconciled_away() {
  let mut h = Harness::new();

  let (reply, response) = futures_channel::oneshot::channel();
  drop(response); // the caller's wait vanished before the reconcile ran

  h.owner
    .on_watch(key("/a"), (), Interest::all(), Filter::all(), reply)
    .await;

  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "the orphaned subscription was retired"
  );
  assert!(h.owner.filters.is_empty(), "its filter state was reclaimed");
  assert_eq!(
    h.owner.source.arm_count(),
    1,
    "the watch armed once (it committed) before being reconciled away"
  );
  assert!(
    matches!(h.owner.source.calls().last(), Some(Call::Disarm(_))),
    "the committed root was disarmed by the immediate unwatch"
  );
}

/// Backpressure (design backpressure doc, checklist #1/#4/#5): a **stalled consumer** fills
/// the bounded event channel, so the owner sheds the affected subscription to a parked
/// dominating `Rescan` instead of blocking or growing memory without bound. The owner never
/// blocks (every `try_emit` returns synchronously); repeated overflow is idempotent (one
/// parked slot, monotone epoch); and on resume the consumer receives exactly one `Rescan`
/// whose epoch strictly dominates every event delivered before it — no silent loss.
#[tokio::test]
async fn stalled_consumer_parks_dominating_rescan_and_resumes() {
  let mut h = Harness::bounded(2);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  // Drive the subscription's epoch high-water up, as genuine deliveries would.
  for raw in 0..3 {
    h.owner.epochs.stamp(sub, Epoch::new(raw));
  }

  // The consumer is stalled (not draining): the two-slot channel fills in-order.
  h.owner.try_emit(modified_event(sub, "/a/f0", 0));
  h.owner.try_emit(modified_event(sub, "/a/f1", 1));
  // The next delivery finds the channel full → shed to a parked dominating Rescan. The call
  // returns synchronously (the owner never awaits the channel — no block, no unbounded
  // growth).
  h.owner.try_emit(modified_event(sub, "/a/f2", 2));
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|(_, e)| *e),
    Some(Epoch::new(3)),
    "overflow parked a Rescan minted one past the high-water (strictly dominating)"
  );

  // Further overflow while parked is SUPPRESSED and idempotent: no second Rescan is minted,
  // the parked epoch is unchanged, and the channel is not probed again.
  h.owner.try_emit(modified_event(sub, "/a/f3", 3));
  assert_eq!(
    h.owner.needs_rescan.len(),
    1,
    "repeated overflow collapses to one parked Rescan"
  );
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|(_, e)| *e),
    Some(Epoch::new(3)),
    "the parked epoch is idempotent under repeated overflow"
  );

  // Resume: the consumer drains the two buffered (pre-overflow) deliveries.
  let buffered = h.drain();
  assert_eq!(
    buffered.len(),
    2,
    "the pre-overflow events buffered in-order, not lost"
  );
  assert!(
    buffered.iter().all(|e| !e.is_rescan()),
    "the buffered events are the ordinary deliveries"
  );

  // On the next loop tick the owner retries the parked Rescan; now there is room.
  h.owner.flush_pending_rescans();
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the parked Rescan was delivered on resume"
  );
  let resumed = h.drain();
  assert_eq!(
    resumed.len(),
    1,
    "exactly the dominating Rescan is delivered on resume"
  );
  let rescan = &resumed[0];
  assert!(rescan.is_rescan(), "the shed signal is a Rescan");
  assert_eq!(rescan.subscription(), sub, "…for the affected subscription");
  assert_eq!(
    rescan.path(),
    Path::new("/a"),
    "…naming its covered key to re-enumerate"
  );
  let max_delivered = buffered
    .iter()
    .map(Event::epoch)
    .max()
    .expect("two buffered events");
  assert!(
    rescan.epoch() > max_delivered,
    "the shed Rescan strictly dominates every event delivered before it (no silent loss)"
  );
}

/// Fairness (design backpressure doc): a parked overflow `Rescan` for one subscription
/// never blocks delivery to ANOTHER. With a full channel, subscription A overflows and
/// parks; once a slot drains, an event for subscription B flows through immediately, while a
/// further A delivery is suppressed (dominated by A's still-parked Rescan) rather than
/// jumping ahead of it.
#[tokio::test]
async fn parked_rescan_does_not_block_other_subscriptions() {
  let mut h = Harness::bounded(1);
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a");
  let sb = h.watch("/b", Interest::all()).await.expect("watch /b");

  // Fill the single slot with an A delivery, then overflow A → park A's Rescan. B untouched.
  h.owner.try_emit(modified_event(sa, "/a/f0", 0));
  h.owner.try_emit(modified_event(sa, "/a/f1", 1));
  assert!(
    h.owner.needs_rescan.contains_key(&sa),
    "A overflowed and parked a Rescan"
  );
  assert!(
    !h.owner.needs_rescan.contains_key(&sb),
    "B is unaffected by A's overflow"
  );

  // The consumer makes progress: drain the one buffered A delivery.
  assert_eq!(h.drain().len(), 1, "the pre-overflow A delivery drains");

  // Now a B delivery flows even though A remains parked (fairness), while a further A
  // delivery is suppressed by A's parked Rescan (never delivered ahead of it).
  h.owner.try_emit(modified_event(sb, "/b/f0", 0));
  h.owner.try_emit(modified_event(sa, "/a/f2", 2));
  let after = h.drain();
  assert_eq!(after.len(), 1, "only B's delivery flows; A's is suppressed");
  assert_eq!(
    after[0].subscription(),
    sb,
    "the delivered event belongs to the unparked B"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sa),
    "A stays parked until its Rescan is flushed"
  );
}

/// Root death with no silent loss on a full channel (design backpressure doc): a watched root
/// **dies while the event channel is full**. The run loop fans out the terminal coverage-loss
/// `Rescan` and THEN retires the dead root, on the same source event. With the channel full
/// the terminal Rescan is *parked*, and retirement must **keep** it (unlike a
/// consumer-initiated unwatch, which drops it) so the resuming consumer still learns the root
/// is gone. Regression test for the co-retire bug where `retire_if_dead` dropped the owed
/// Rescan in the very tick it was parked, leaving the consumer permanently stale.
#[tokio::test]
async fn root_death_while_channel_full_keeps_owed_rescan() {
  let mut h = Harness::bounded(2);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  // Drive the subscription's epoch high-water up, as genuine deliveries would.
  for raw in 0..3 {
    h.owner.epochs.stamp(sub, Epoch::new(raw));
  }

  // The consumer is stalled (not draining): the two-slot channel fills in-order.
  h.owner.try_emit(modified_event(sub, "/a/f0", 0));
  h.owner.try_emit(modified_event(sub, "/a/f1", 1));

  // The root dies out of band. Reproduce the run loop's same-event ordering: fan out the
  // terminal Rescan first, then retire. The fan-out finds the channel full, so the terminal
  // coverage-loss Rescan is shed to a parked dominating Rescan.
  h.owner.source.kill_root(1);
  h.owner.fan_out_and_push(&rescan_event(1, "/a"));
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|(_, e)| *e),
    Some(Epoch::new(3)),
    "the terminal Rescan parked (channel full), minted one past the high-water"
  );

  // Retiring the dead root frees its filter + epoch but must KEEP the parked terminal Rescan
  // — dropping it here is the silent-loss regression this test guards.
  h.owner.retire_if_dead(&rescan_event(1, "/a"));
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "the dead root is retired"
  );
  assert!(
    !h.owner.filters.contains_key(&sub),
    "retirement frees the dead root's filter (I4)"
  );
  assert_eq!(
    h.owner.epochs.tracked_len(),
    (0, 0),
    "retirement frees the dead root's epoch state (I4)"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "retirement KEEPS the owed terminal Rescan (no silent loss on root death)"
  );

  // Resume: the consumer drains the two buffered pre-death deliveries.
  let buffered = h.drain();
  assert_eq!(
    buffered.len(),
    2,
    "the pre-death events buffered in-order, not lost"
  );

  // The next loop tick retries the parked Rescan; now there is room, so it is delivered.
  h.owner.flush_pending_rescans();
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the parked terminal Rescan self-drained on resume"
  );
  let resumed = h.drain();
  assert_eq!(
    resumed.len(),
    1,
    "exactly the terminal Rescan is delivered on resume — the consumer is not left stale"
  );
  let rescan = &resumed[0];
  assert!(rescan.is_rescan(), "the coverage-loss signal is a Rescan");
  assert_eq!(
    rescan.subscription(),
    sub,
    "…for the subscription whose root died"
  );
  assert_eq!(
    rescan.path(),
    Path::new("/a"),
    "…naming its covered key, which the consumer re-enumerates to discover the root is gone"
  );
  let max_delivered = buffered
    .iter()
    .map(Event::epoch)
    .max()
    .expect("two buffered events");
  assert!(
    rescan.epoch() > max_delivered,
    "the terminal Rescan strictly dominates every event delivered before it (no silent loss)"
  );
}

/// Source-drain no-silent-loss (design backpressure doc, checklist #1):
/// a per-subscription overflow `Rescan` is **parked while the event channel is full**, then
/// the source drains (`next` → `None`) at teardown. The owner must deliver that owed Rescan
/// **before** the stream ends, retrying across the full channel until the resuming consumer
/// frees a slot — never dropping it. Regression: the old teardown flushed only the coalescer
/// tail, dropping the parked Rescan, so a consumer that resumed after source-drain reached
/// stream-end permanently stale. Exercises the exact drain the source-`None` break runs.
#[tokio::test]
async fn source_drain_delivers_owed_parked_rescan_no_silent_loss() {
  let mut h = Harness::bounded(1);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  for raw in 0..2 {
    h.owner.epochs.stamp(sub, Epoch::new(raw));
  }

  // Fill the one slot, then overflow → park a dominating Rescan (the channel stays full).
  h.owner.try_emit(modified_event(sub, "/a/f0", 0));
  h.owner.try_emit(modified_event(sub, "/a/f1", 1));
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|(_, e)| *e),
    Some(Epoch::new(2)),
    "overflow parked a dominating Rescan while the channel is full"
  );

  // The source drains at teardown. `drain_owed_before_shutdown` retries the owed Rescan across
  // the full channel while the consumer resumes, delivering it before stream end. Run the
  // drain concurrently with the resuming consumer so the retry-under-full path is exercised.
  let events = h.events.clone();
  let owner = &mut h.owner;
  let consumer = async {
    let buffered = events
      .recv()
      .await
      .expect("the buffered pre-overflow event drains first");
    let owed = events
      .recv()
      .await
      .expect("then the owed Rescan is delivered (not dropped)");
    (buffered, owed)
  };
  // Bounded, so a regression (the owed Rescan never delivered) fails cleanly, not hangs.
  let (_, (buffered, owed)) = tokio::time::timeout(Duration::from_secs(10), async {
    tokio::join!(owner.drain_owed_before_shutdown(), consumer)
  })
  .await
  .expect("source-drain teardown delivered the owed Rescan before the deadline (no silent loss)");

  assert!(
    !buffered.is_rescan(),
    "the first delivered event is the buffered ordinary one, in order"
  );
  assert!(owed.is_rescan(), "the owed shed signal is a Rescan");
  assert_eq!(owed.subscription(), sub, "…for the overflowed subscription");
  assert_eq!(
    owed.path(),
    Path::new("/a"),
    "…naming its covered key to re-enumerate"
  );
  assert!(
    owed.epoch() > buffered.epoch(),
    "the owed Rescan strictly dominates every event delivered before it (no silent loss)"
  );
  assert!(
    owner.needs_rescan.is_empty(),
    "source-drain teardown delivered the owed Rescan — nothing left parked"
  );
}

/// Source cancel-safety is load-bearing (design source doc hard contract):
/// the owner drives `source.next()` as one `select!` arm, so a competing command/timer branch
/// **drops the in-flight `next()` future**. A contract-conforming source that dequeues on the
/// poll that returns `Ready` loses nothing across arbitrarily many such cancellations; a source
/// that dequeues on poll START silently loses the in-flight event (the owner parks no Rescan —
/// it never saw it). This reproduces the owner's cancel-then-retry pattern with both a
/// conforming and a violating source, proving the documented contract is what keeps the owner's
/// inline `next()` lossless.
#[tokio::test]
async fn source_next_cancellation_is_lossless_only_when_cancel_safe() {
  use futures_util::FutureExt;

  /// Cancel-SAFE: yields (returns `Pending`) BEFORE consuming, so a poll cancelled here
  /// consumed nothing — the dequeue happens only on the poll that returns `Ready`.
  struct CancelSafe {
    queue: VecDeque<SourceEvent<OsString, u32>>,
    consumed: u32,
  }
  impl Source<OsString> for CancelSafe {
    type Handle = u32;
    async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
      Ok(Armed::new(1, key.to_vec()))
    }
    async fn disarm(&mut self, _handle: u32) {}
    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      tokio::task::yield_now().await; // Pending once BEFORE the dequeue → cancel-safe
      self.consumed += 1;
      self.queue.pop_front()
    }
    fn root_key(&self, _handle: u32) -> Option<Vec<OsString>> {
      Some(key("/w"))
    }
  }

  /// Cancel-UNSAFE: dequeues on poll START and holds the event in the future's local across
  /// the yield — so a cancellation drops the popped event (silent loss, no Rescan owed).
  struct CancelUnsafe {
    queue: VecDeque<SourceEvent<OsString, u32>>,
    lost: u32,
  }
  impl Source<OsString> for CancelUnsafe {
    type Handle = u32;
    async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
      Ok(Armed::new(1, key.to_vec()))
    }
    async fn disarm(&mut self, _handle: u32) {}
    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      let popped = self.queue.pop_front(); // dequeue on poll START (the bug)
      if popped.is_some() {
        self.lost += 1; // provisionally lost until it survives to be returned
      }
      tokio::task::yield_now().await; // a cancellation here drops `popped` → truly lost
      if popped.is_some() {
        self.lost -= 1; // survived to return → not lost
      }
      popped
    }
    fn root_key(&self, _handle: u32) -> Option<Vec<OsString>> {
      Some(key("/w"))
    }
  }

  const N: u64 = 6;
  const CANCELS: u32 = 2;

  /// Reproduces the owner's `select!` arm: `next()` is polled FIRST (as in the loop), yields
  /// `Pending`, then the ready "interrupt" (a stand-in for a command/timer branch) wins → the
  /// in-flight `next()` is dropped. `CANCELS` cancellations, then one `next()` runs to
  /// completion — repeated until the source drains. Returns the delivered events and the
  /// cancellation count.
  async fn drive<S>(source: &mut S) -> (Vec<SourceEvent<OsString, u32>>, u32)
  where
    S: Source<OsString, Handle = u32>,
  {
    let mut delivered = Vec::new();
    let mut cancels = 0u32;
    loop {
      for _ in 0..CANCELS {
        futures_util::select_biased! {
          ev = source.next().fuse() => if let Some(event) = ev { delivered.push(event); },
          _  = std::future::ready(()).fuse() => cancels += 1,
        }
      }
      match source.next().await {
        Some(event) => delivered.push(event),
        None => break,
      }
    }
    (delivered, cancels)
  }

  let queued = || -> VecDeque<_> {
    (0..N)
      .map(|i| source_modified(1, &format!("/w/f{i}"), i))
      .collect()
  };
  let expected: Vec<Vec<OsString>> = (0..N).map(|i| key(&format!("/w/f{i}"))).collect();

  // A cancel-safe source loses NOTHING despite repeated cancellation.
  let mut safe = CancelSafe {
    queue: queued(),
    consumed: 0,
  };
  let (delivered, cancels) = drive(&mut safe).await;
  assert!(
    cancels > 0,
    "the select actually cancelled in-flight next() futures"
  );
  assert_eq!(
    delivered
      .iter()
      .map(|e| e.key().to_vec())
      .collect::<Vec<_>>(),
    expected,
    "a cancel-safe source delivers every event, in order — no loss across cancellation"
  );

  // A cancel-UNSAFE source (dequeue on poll start) silently loses the cancelled-in-flight
  // events — proving the documented cancel-safety contract is load-bearing, not incidental.
  let mut bad = CancelUnsafe {
    queue: queued(),
    lost: 0,
  };
  let (delivered_bad, _) = drive(&mut bad).await;
  assert!(
    delivered_bad.len() < usize::try_from(N).unwrap(),
    "a cancel-unsafe source loses events to cancellation (delivered {} of {N})",
    delivered_bad.len()
  );
  assert!(
    bad.lost > 0,
    "the cancel-unsafe source dropped popped-but-unreturned events (silent loss, no Rescan)"
  );
}
