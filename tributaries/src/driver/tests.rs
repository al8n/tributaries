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
  options::{DebounceConfig, TributariesOptions},
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
/// the arm-failure path), can be told to return the *next* arm **dead-on-arrival** (a
/// reported-armed handle the source has already forgotten — [`Source::root_key`] is `None` —
/// so a test can drive the driver's I2 arm-choke-point liveness check), and models the
/// source's canonical-key adoption (a `retarget` diverges the reported canonical key from the
/// requested one — the design §4 TOCTOU).
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
  /// How many of the next `arm` calls to return **dead-on-arrival**: the arm reports success
  /// (a handle + canonical key) but the root is NOT recorded live, so [`Source::root_key`]
  /// answers `None` for its handle — modelling a root torn down between the arm request and its
  /// completion. The driver's arm-choke-point liveness check (invariant I2) must reject it.
  dead_on_arrival_arms: u32,
  /// Planned path → the divergent canonical path `arm` should report for it (the §4
  /// canonicalization TOCTOU: the source commits a different coordinate than planned).
  retarget: HashMap<PathBuf, PathBuf>,
  /// Models [`Source::canonicalize_key`]: a caller key → its canonicalization result —
  /// `Some(canonical)` re-keys it (a symlink/`..` resolving to a different coordinate), `None`
  /// rejects it (the fs source's non-existent-path case). A key ABSENT here canonicalizes to
  /// itself (identity — the already-canonical common case).
  canonicalize: HashMap<Vec<OsString>, Option<Vec<OsString>>>,
  /// Forces the next SUCCESSFUL `arm` to return this handle value instead of a freshly-minted one —
  /// modelling a source that REUSES a still-recorded handle value, a **generation-unique**
  /// [`Source::Handle`] contract VIOLATION, so a test can drive the failed-widen restore's rebind
  /// debug_assert tripwire. One-shot: consumed by the next arm that gets past the fail/overlap
  /// checks.
  reuse_next_handle: Option<u32>,
}

impl FakeSource {
  fn new() -> Self {
    Self {
      next_handle: 0,
      calls: Vec::new(),
      live: HashMap::new(),
      canonical: HashMap::new(),
      fail_arms: 0,
      dead_on_arrival_arms: 0,
      retarget: HashMap::new(),
      canonicalize: HashMap::new(),
      reuse_next_handle: None,
    }
  }

  /// Model [`Source::canonicalize_key`] re-keying `from` onto the canonical coordinate `to`
  /// (a symlink / `..` path resolving elsewhere).
  fn canonicalizes_to(&mut self, from: &str, to: &str) {
    self.canonicalize.insert(key(from), Some(key(to)));
  }

  /// Model [`Source::canonicalize_key`] REJECTING `k` (the fs source's non-existent-path case):
  /// the driver must fail the watch rather than commit an eventless key.
  fn cannot_canonicalize(&mut self, k: &str) {
    self.canonicalize.insert(key(k), None);
  }

  /// Force the next successful `arm` to return `handle` (a REUSED handle value) — drives the
  /// failed-widen restore's rebind debug_assert tripwire for a contract-violating source.
  fn reuse_next_arm_handle(&mut self, handle: u32) {
    self.reuse_next_handle = Some(handle);
  }

  /// The next `arm` call fails.
  fn fail_next_arm(&mut self) {
    self.fail_arms = 1;
  }

  /// The next `arm` call returns **dead-on-arrival**: a reported-armed handle the source has
  /// already forgotten ([`Source::root_key`] answers `None` for it), driving the driver's I2
  /// liveness check at the arm choke point.
  fn dead_on_arrival_next_arm(&mut self) {
    self.dead_on_arrival_arms = 1;
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

  fn canonicalize_key(&self, k: &[OsString]) -> Result<Vec<OsString>, WatchError> {
    match self.canonicalize.get(k) {
      // Re-key onto the modelled canonical coordinate.
      Some(Some(canonical)) => Ok(canonical.clone()),
      // A key the source cannot canonicalize (non-existent path): reject, don't commit-eventless.
      Some(None) => Err(WatchError::Canonicalize {
        path: k.iter().collect(),
        source: io::Error::other("injected non-canonicalizable key"),
      }),
      // Absent → already canonical (identity), the common case.
      None => Ok(k.to_vec()),
    }
  }

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
    // Mint a fresh monotonic handle, UNLESS a test forced this arm to reuse a specific value (a
    // `Source::Handle` generation-unique contract violation) to drive the restore's debug_assert.
    let handle = match self.reuse_next_handle.take() {
      Some(forced) => forced,
      None => {
        self.next_handle += 1;
        self.next_handle
      }
    };
    // The canonical key: the retarget override, else the requested key. Overlap tracks the
    // arm-path (the coordinate planned against); the retarget models a separate fs-side
    // divergence the `fs_path_preserves_plan` guard catches, not this overlap check.
    let canonical_path = self
      .retarget
      .get(&path)
      .cloned()
      .unwrap_or_else(|| path.clone());
    let canonical_key = components(&canonical_path);
    // A dead-on-arrival arm reports success but the root was torn down before it completed: do
    // NOT record it live/canonical, so [`Source::root_key`] answers `None` and the driver's I2
    // liveness check at the arm choke point must reject it (best-effort disarming the stray
    // handle). Models the fs source's `root_path == None` after a nominally-successful watch.
    if self.dead_on_arrival_arms > 0 {
      self.dead_on_arrival_arms -= 1;
      return Ok(Armed::new(handle, canonical_key));
    }
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

/// Builds a `Rescan` [`SourceEvent`] for `handle` at `path` with raw fs `epoch` — the terminal /
/// overflow coverage-loss signal `retire_if_dead` classifies via [`Source::root_key`]. The epoch is
/// the source's raw stamp (rebased at fan-out); it is irrelevant on the retire path (which mints its
/// own `shed_rescan`) and load-bearing only when the fanned `Rescan` overflows and parks at its own
/// stamped epoch (Codex R5).
fn rescan_event(handle: u32, path: &str, epoch: u64) -> SourceEvent<OsString, u32> {
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Rescan,
    None,
    Location::new(),
    Epoch::new(epoch),
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

/// A raw `Removed` [`SourceEvent`] for `handle` at `path` — the user-visible NON-`Rescan`
/// terminal event the fs layer can surface for a watched-root deletion before its terminal
/// `Rescan`, which `retire_if_dead` must also retire a dead root on (Codex R11 F1).
fn source_removed(handle: u32, path: &str, epoch: u64) -> SourceEvent<OsString, u32> {
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Removed,
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
      commands_weak: command_tx.downgrade(),
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

/// Codex R7 F2 regression (design §3, a handle is a per-watcher capability): every
/// [`Subscription`] is branded with its owning watcher's `InstanceId`, so a handle minted by one
/// watcher can never `unwatch` another's subscription — even when their `ScopeId`s collide (each
/// owner mints scope ids independently from 1). The brand is checked BEFORE any state is mutated.
///
/// Fail-on-old: without the instance brand the two watchers' first subscriptions are equal bare
/// `ScopeId(1)`s, so `b.unwatch(a_sub)` matches B's own live subscription by scope id and wrongly
/// retires it.
#[tokio::test]
async fn a_foreign_subscription_cannot_unwatch_a_local_one_with_a_colliding_scope_id() {
  let mut a = Harness::new();
  let mut b = Harness::new();

  // Each owner mints scope ids from 1, so these two handles share the SAME `ScopeId` but carry
  // DIFFERENT per-watcher instance brands.
  let a_sub = a.watch("/x", Interest::all()).await.expect("watch on A");
  let b_sub = b.watch("/x", Interest::all()).await.expect("watch on B");
  assert_eq!(
    a_sub.id(),
    b_sub.id(),
    "the two owners minted a colliding ScopeId"
  );
  assert_ne!(
    a_sub, b_sub,
    "…but the per-watcher instance brand makes them distinct handles"
  );

  // B rejects A's foreign handle BEFORE touching any state, even though its ScopeId collides with
  // B's live subscription.
  let err = b
    .unwatch(a_sub)
    .await
    .expect_err("a foreign subscription is rejected");
  assert!(
    err.is_unknown_subscription(),
    "a foreign handle is Unknown, not applied to B's colliding subscription"
  );

  // B's own subscription stayed live throughout: still watched, and still unwatchable itself.
  assert!(
    b.owner.subsumer.view().is_watched(&key("/x")),
    "B's subscription stays live after rejecting the foreign unwatch"
  );
  b.unwatch(b_sub)
    .await
    .expect("B's own subscription is still live and unwatchable");
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

/// Codex R13 (the STRUCTURAL close of the handle-liveness class at the ARM choke point): a fresh
/// `Disjoint` `watch` whose arm is **dead-on-arrival** — the source reports it armed but has
/// already forgotten the root ([`Source::root_key`] is `None`) — must FAIL the watch, not commit a
/// root no live source watch backs. The driver's I2 liveness validation at the single arm-and-key
/// choke point rejects it: it best-effort disarms the stray handle and surfaces
/// [`WatchError::DeadOnArrival`], leaving NO root recorded, NO `is_watched` published, and NO
/// subscription returned.
///
/// Fail-on-old: without the choke-point liveness check the dead handle is committed as a root —
/// `watch` returns `Ok`, `is_watched` is true, a root is recorded, and a subscription leaks — so
/// every assertion below flips.
#[tokio::test]
async fn disjoint_dead_on_arrival_arm_fails_no_root_committed() {
  let mut h = Harness::new();

  h.owner.source.dead_on_arrival_next_arm();
  let result = h.watch("/a", Interest::all()).await;

  let err = result.expect_err("a dead-on-arrival fresh arm fails the watch");
  assert!(
    err.is_dead_on_arrival(),
    "the failure is the dead-on-arrival arm error, got {err:?}"
  );
  // The arm happened once (minting handle 1); the choke point found it dead and best-effort
  // disarmed it — the stray handle is released, never committed.
  assert_eq!(
    h.owner.source.calls(),
    vec![Call::Arm(PathBuf::from("/a")), Call::Disarm(1)],
    "the dead-on-arrival handle is best-effort disarmed, not committed"
  );
  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "the failed arm abandons the plan — no pending reservation leaks"
  );
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/a")),
    "NO root is committed for a dead-on-arrival arm (fail-on-old: is_watched true)"
  );
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "no root is recorded (fail-on-old: the dead handle is committed as a root)"
  );
  // The view is clean, so a retry arms afresh — the dead-on-arrival left no live root behind.
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a after the dead-on-arrival failure");
  assert_eq!(
    h.owner.source.arm_count(),
    2,
    "the retried watch arms again (the dead-on-arrival plan left no live root)"
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

  // BOTH subscribers got a dominating Rescan (sb: terminal/retire; sc: restore re-point). The
  // retired sb's terminal Rescan is durably PARKED by the shared retire primitive (before its
  // subsumer state was freed), so flush it into the stream before draining.
  h.owner.flush_pending_rescans();
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

/// Codex R15-F2 regression (the failed-widen restore under the **generation-unique**
/// [`Source::Handle`] contract): a source that re-mints a **still-recorded** sibling's handle value
/// for a re-arm violates the contract, and the rebind choke point's `debug_assert` must catch it
/// LOUDLY rather than silently corrupt the reverse index. Here the widen of `/a` fails and the
/// restore of `/a/b` (old handle 1) re-arms while the source REUSES handle `2` — still recorded as
/// the not-yet-restored sibling `/a/c`. `rebind_root(1, 2)` would overwrite `by_handle[2]` and
/// strand `/a/c`, so the debug_assert trips first.
///
/// The earlier R14-F2 defensive recovery (disarm the aliased handle + retire `old`) was RETIRED
/// (Codex R15): it was incomplete, and when the alias was an unrelated *live* root its `disarm`
/// released that root's real source watch while its record + coverage stayed live — silently missing
/// future changes (R15-F2). The strengthened contract makes the alias impossible for a conforming
/// source (a re-arm mints a fresh generation while `old` and its siblings are still recorded), so
/// the debug_assert is the debug/test-only tripwire for a violating one. Hence `#[should_panic]` —
/// and `ignore`d in release builds, where `debug_assert!` is compiled out and nothing panics.
#[tokio::test]
#[should_panic(expected = "already recorded for a different root")]
#[cfg_attr(
  not(debug_assertions),
  ignore = "the debug_assert tripwire is compiled out in release builds"
)]
async fn failed_widen_restore_reusing_a_recorded_sibling_handle_trips_the_tripwire() {
  let mut h = Harness::new();

  let _sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let _sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2

  // The wider /a arm fails, AND the first restore re-arm (/a/b) REUSES handle 2 — still recorded as
  // the not-yet-restored sibling /a/c. That is a generation-unique `Source::Handle` VIOLATION, so
  // the rebind choke point's debug_assert panics on it rather than corrupt `by_handle` (R15-F2).
  h.owner.source.fail_next_arm();
  h.owner.source.reuse_next_arm_handle(2);
  // Panics inside the restore, before the watch returns — the source violated the handle contract.
  let _ = h.watch("/a", Interest::all()).await;
}

/// Codex R13 (the ARM-choke-point liveness close, widen path): a `Widen` whose **wider** arm is
/// dead-on-arrival — the source reports it armed but has already forgotten the wider root
/// ([`Source::root_key`] is `None`) — must run the same restore the injected arm-failure does, not
/// strand the subsumed roots it disarmed. The choke point rejects the dead wider handle
/// (best-effort disarming it) and surfaces [`WatchError::DeadOnArrival`]; the widen's failure path
/// then re-arms the disarmed subsumed roots (restore) and aborts the newcomer's plan. No subsumed
/// subscription is left recorded-live-but-disarmed.
///
/// Fail-on-old: without the choke-point check the dead wider handle is committed as the widened
/// root — the subsumed roots collapse onto a handle NO live watch backs and their subscribers
/// silently stop seeing events.
#[tokio::test]
async fn widen_dead_on_arrival_wider_arm_restores_disarmed_roots() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c");
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // The wider /a arm is dead-on-arrival; the two restore re-arms succeed (live).
  h.owner.source.dead_on_arrival_next_arm();
  let result = h.watch("/a", Interest::all()).await;
  let err = result.expect_err("the dead-on-arrival wider arm fails the widen");
  assert!(
    err.is_dead_on_arrival(),
    "the widen fails with the dead-on-arrival arm error, got {err:?}"
  );

  // Disarm-subsumed, the wider arm reports armed-then-dead so the choke point disarms its stray
  // handle (3), THEN both subsumed roots are re-armed (the restore) — never stranded.
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Arm(PathBuf::from("/a")),
      Call::Disarm(3),
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
    ],
    "the dead-on-arrival wider handle is disarmed, then the subsumed roots restored (not stranded)"
  );

  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "the aborted widen leaks no pending reservation"
  );

  // Both subsumed subscriptions are live-and-covered again on FRESH, live handles — the dead wider
  // root was never committed.
  let view = h.owner.subsumer.view();
  assert!(
    view.is_watched(&key("/a/b")) && view.is_watched(&key("/a/c")),
    "the restored subscriptions read watched again"
  );
  assert!(
    !view.is_watched(&key("/a")),
    "the dead-on-arrival wider root was NEVER committed (fail-on-old: /a is watched)"
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
    "the two subsumed roots are back (re-armed), not collapsed onto the dead wider handle"
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

/// Codex R14 F1 regression (design §4, invariant I2 — the Covered-path canonicalization close):
/// a NON-canonical watch key that resolves **under an already-watched canonical root** must be
/// canonicalized BEFORE classification, so the `Covered` subscription is committed on the
/// **canonical** coordinate its events arrive under — not the raw key. The driver canonicalizes
/// every key at the single choke point ([`Source::canonicalize_key`]) ahead of `plan_watch`, so
/// the covered newcomer is keyed on `/root/b` (the resolved coordinate) and a real canonical event
/// under `/root/b` reaches it.
///
/// Fail-on-old: with the raw-key Covered commit the newcomer is keyed on the non-canonical
/// `/root/link`; a canonical `/root/b/file` event fails its ancestor match, so it is delivered
/// NOTHING (no `Rescan` — the root is alive; only THIS subscription's key never matches). The
/// committed-key and delivery assertions then FAIL.
#[tokio::test]
async fn noncanonical_covered_watch_is_canonicalized_then_receives_events() {
  let mut h = Harness::new();

  // An already-watched canonical root (handle 1).
  let s_root = h
    .watch("/root", Interest::all())
    .await
    .expect("watch /root");

  // A non-canonical key under it (a symlinked child) resolving to the canonical `/root/b`.
  h.owner.source.canonicalizes_to("/root/link", "/root/b");
  let s_link = h
    .watch("/root/link", Interest::all())
    .await
    .expect("the covered non-canonical watch is accepted (canonicalized, not rejected)");

  // No fresh arm — it is Covered by /root — but it is committed on the CANONICAL coordinate.
  assert_eq!(
    h.owner.source.arm_count(),
    1,
    "the covered watch arms nothing (subsumed under /root)"
  );
  assert_eq!(
    h.owner.subsumer.subscription_key(s_link),
    Some(key("/root/b").as_slice()),
    "the covered subscription is keyed on the source's canonical coordinate, not the raw \
     /root/link (fail-on-old: committed verbatim as /root/link)"
  );

  // A real canonical event under /root/b reaches the covered subscription — the whole point.
  h.owner
    .fan_out_and_push(&source_modified(1, "/root/b/file", 0));
  let delivered = h.drain();
  assert!(
    delivered
      .iter()
      .any(|ev| ev.subscription() == s_link && !ev.is_rescan()),
    "a canonical event under /root/b reaches the covered subscription (fail-on-old: keyed on \
     /root/link, the canonical event fails its ancestor match → silently misses)"
  );
  assert!(
    delivered
      .iter()
      .any(|ev| ev.subscription() == s_root && !ev.is_rescan()),
    "…and its covering root's own subscription still receives it too"
  );
}

/// Codex R14 F1 regression (the reject arm): a watch key the source CANNOT canonicalize (the fs
/// source's non-existent-path case) is rejected with [`WatchError::Canonicalize`] at the choke
/// point — never silently committed as an eventless key. Nothing is recorded and no plan leaks.
#[tokio::test]
async fn watch_whose_key_cannot_be_canonicalized_is_rejected() {
  let mut h = Harness::new();

  h.owner.source.cannot_canonicalize("/ghost");
  let err = h
    .watch("/ghost", Interest::all())
    .await
    .expect_err("a non-canonicalizable key is rejected, not committed");
  assert!(
    err.is_canonicalize(),
    "the rejection is a Canonicalize error, got {err:?}"
  );

  assert_eq!(
    h.owner.source.arm_count(),
    0,
    "a rejected watch arms nothing"
  );
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "no root is recorded for a rejected watch"
  );
  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "the rejected watch leaks no pending reservation (canonicalize fails before plan_watch)"
  );
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/ghost")),
    "the rejected key is never published watched"
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
  h.owner.retire_if_dead(&rescan_event(1, "/a", 0));
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
  h.owner.retire_if_dead(&rescan_event(1, "/a", 0));
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

/// Codex R11 F1 regression (design §4, invariant I4): a watched root can surface its own
/// deletion as a user-visible NON-`Rescan` terminal event (a `Removed`) that the lower fs layer
/// FOLLOWS with a terminal `Rescan`. If `retire_if_dead` retired the dead root only on the
/// `Rescan` (the old `!raw.is_rescan()` gate), a caller that observes the `Removed` and
/// re-`watch`es the same path BEFORE the queued terminal `Rescan` is processed would be
/// classified `Covered` by the STILL-RECORDED dead root — handed a subscription backed by NO live
/// source watch, which the later `Rescan` then retires: writes under the recreated root are
/// silently missed.
///
/// A dead root (`Source::root_key` is `None`) is retired on ANY terminal event: the `Removed`
/// force-removes it from the coverage index BEFORE control returns, so the re-`watch` is
/// `Disjoint` → a FRESH source arm. The `Removed` is NOT separately fanned out (Codex R12 F2) — the
/// coverage loss is owed as the dominating terminal `Rescan` the retire parks, which re-enumerates
/// the subtree; a redundant ordinary `Removed` would be buffered-then-dropped under debounce.
///
/// Fail-on-old: with the `!raw.is_rescan()` gate the `Removed` returns `false` without retiring,
/// the re-watch is `Covered` (no fresh arm) against the dead handle, and `arm_count` stays 1 → the
/// `== 2` assertion FAILS.
#[tokio::test]
async fn dead_root_removed_before_terminal_rescan_retires_so_rewatch_rearms() {
  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  h.owner.epochs.stamp(sub, Epoch::new(3));
  assert_eq!(
    h.owner.source.arm_count(),
    1,
    "the initial watch armed once"
  );

  // The root dies out of band; the fs layer surfaces the deletion as a user-visible `Removed`
  // (root_key now `None`) BEFORE the terminal `Rescan`.
  h.owner.source.kill_root(1);
  let retired = h.owner.retire_if_dead(&source_removed(1, "/a", 0));
  assert!(
    retired,
    "a dead root retires on the non-`Rescan` terminal event too (run loop skips its own fan-out)"
  );

  // The `Removed` is NOT fanned out as an ordinary event (Codex R12 F2): the coverage loss is owed
  // as the dominating terminal `Rescan` the retire parks, so nothing is delivered inline.
  assert!(
    h.drain().is_empty(),
    "no ordinary terminal event is fanned out — the parked Rescan carries the coverage loss"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the retired subscription is owed a dominating terminal Rescan (no silent loss)"
  );

  // The dead root is retired NOW (on the `Removed`, before the terminal `Rescan`), so it has left
  // the coverage index and can no longer cover a watch.
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "the dead root is retired on the `Removed`, not left recorded until the `Rescan`"
  );

  // The caller re-watches the recreated path BEFORE the queued terminal `Rescan` is processed.
  // With the dead root gone it is `Disjoint` → a FRESH source arm, not `Covered` by the dead handle.
  let resub = h.watch("/a", Interest::all()).await.expect("re-watch /a");
  assert_ne!(resub, sub, "the re-watch mints a fresh subscription");
  assert_eq!(
    h.owner.source.arm_count(),
    2,
    "the re-watch triggers a FRESH arm — NOT `Covered` by the dead root (fail-on-old: stays 1)"
  );

  // The re-watch rides the live re-armed handle (2), so a change under the recreated root is
  // delivered — not silently missed as it would be if the sub were `Covered` by the dead handle.
  h.owner.fan_out_and_push(&source_modified(2, "/a/f", 0));
  let delivered = h.drain();
  assert_eq!(
    delivered.len(),
    1,
    "a change under the recreated root is delivered to the re-watch (not silently missed)"
  );
  assert_eq!(
    delivered[0].subscription(),
    resub,
    "…to the fresh subscription riding the live re-armed handle"
  );
}

/// Codex R12 F1 regression (the STRUCTURAL close of the dead-root-coverage class): the owner loop
/// is command-biased, so a `watch` queued while a dead root's terminal event is still pending runs
/// FIRST — before `retire_if_dead` consumes that event and force-removes the root. Here the source
/// has forgotten the covering root ([`Source::root_key`] is `None`) but its terminal event has NOT
/// yet reached `retire_if_dead`, so the root is still recorded in the coverage index. A re-`watch`
/// of a path that dead root would cover must NOT be classified `Covered` against the
/// source-forgotten handle: `reconcile_watch` validates the covering root's liveness, retires the
/// dead root (owing its subscriber a dominating terminal `Rescan`), re-plans, and arms a FRESH live
/// root — so an event under that recreated root is delivered, not silently missed. Unlike the R11
/// path (which retires eagerly on the `Removed`), this closes the window regardless of
/// terminal-event timing: the validation happens at the `watch`, not on the pending terminal event.
///
/// Fail-on-old: without the `Covered` liveness validation the re-watch binds `Covered` to the dead
/// handle, arms nothing (arm_count stays 1) and leaves the dead root recorded, so the event under
/// the fresh handle routes to no live root → the arm-count, surviving-root, and delivery assertions
/// FAIL.
#[tokio::test]
async fn covered_rewatch_validates_liveness_retires_dead_root_and_rearms() {
  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  h.owner.epochs.stamp(sub, Epoch::new(3));
  assert_eq!(
    h.owner.source.arm_count(),
    1,
    "the initial watch armed once"
  );

  // The covering root dies out of band (`root_key` → None) but its terminal event has NOT yet been
  // processed by `retire_if_dead`: the command-biased loop runs the queued re-`watch` first, with
  // the dead root still recorded in the coverage index.
  h.owner.source.kill_root(1);
  assert_eq!(
    h.owner.subsumer.roots().count(),
    1,
    "the dead root is still RECORDED (its terminal event has not yet retired it)"
  );

  // A re-`watch` of a path the dead root WOULD cover. The structural fix validates the covering
  // root's liveness, finds it dead, retires it, re-plans → `Disjoint` → a FRESH arm.
  let resub = h
    .watch("/a/b", Interest::all())
    .await
    .expect("re-watch /a/b");
  assert_ne!(resub, sub, "the re-watch mints a fresh subscription");
  assert_eq!(
    h.owner.source.arm_count(),
    2,
    "the re-watch validates liveness, retires the dead root, and arms a FRESH live root \
     (fail-on-old: binds `Covered` to the dead handle → stays 1)"
  );

  // The dead /a root left the coverage index; only the fresh /a/b root remains — not two roots,
  // and not the dead one still recorded.
  let roots: Vec<Vec<OsString>> = h.owner.subsumer.roots().map(|(k, _)| k.to_vec()).collect();
  assert_eq!(
    roots,
    vec![key("/a/b")],
    "the dead /a root is retired and replaced by the fresh /a/b root (fail-on-old: /a survives)"
  );

  // The old subscriber's per-sub state is freed, and it is owed a dominating terminal Rescan — the
  // retire-and-replan loses no coverage.
  assert!(
    !h.owner.filters.contains_key(&sub),
    "the dead root's subscriber state is freed on retirement (I4)"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "…and it is owed a dominating terminal Rescan (no silent loss)"
  );

  // An event under the FRESH live root (handle 2) reaches the re-watch — the whole point: the
  // newcomer rides a live source watch, not the dead handle.
  h.owner.fan_out_and_push(&source_modified(2, "/a/b/f", 0));
  let delivered = h.drain();
  assert_eq!(
    delivered.len(),
    1,
    "a change under the recreated root reaches the re-watch (fail-on-old: bound to the dead handle → 0)"
  );
  assert_eq!(
    delivered[0].subscription(),
    resub,
    "…to the fresh subscription riding the live re-armed handle"
  );
}

/// Codex R12 F2 regression (design §6 / backpressure doc, no silent loss): a dead root's terminal
/// coverage loss must reach the consumer as the durable, strictly-dominating terminal `Rescan` the
/// retire primitive parks — NOT as an ordinary `Removed` fanned through the debounce coalescer. The
/// earlier (R11) path fanned the non-`Rescan` terminal event through `fan_out_and_push`; with
/// debounce that admits it to the coalescer, where — depending on the settle window — it is either
/// buffered-then-dropped by the retire's `drop_subscription` (silently losing the promised event)
/// or surfaces as a redundant second terminal event dominated by the parked Rescan. Either way it is
/// redundant with the dominating terminal Rescan that re-enumerates the subtree, so the fix stops
/// fanning it out.
///
/// The settle window is zero, so a lifecycle event fanned through the coalescer drains at once — the
/// visible face of the buffer-through fan-out the fix removes (a longer window would instead
/// buffer-then-drop it, an equally-wrong silent loss that is simply not observable in the end
/// state).
///
/// Fail-on-old: with `fan_out_and_push(raw)` still routing the `Removed` through the coalescer, the
/// consumer receives that redundant `Removed` in addition to the terminal Rescan → the "nothing
/// reaches the consumer through the coalescer" assertion FAILS.
#[tokio::test]
async fn dead_root_terminal_removed_under_debounce_signals_via_parked_rescan_only() {
  // Debounce ENABLED with an immediate-settle window, so a lifecycle event fanned through the
  // coalescer drains at once rather than buffering — making the buffer-through fan-out observable.
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_millis(0))
    .with_max_hold(Duration::from_millis(0));
  let mut h = Harness::with_coalescer(Some(Coalescer::new(cfg)));
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  h.owner.epochs.stamp(sub, Epoch::new(3));

  // The root dies out of band; the fs surfaces the deletion as a NON-`Rescan` terminal `Removed`.
  h.owner.source.kill_root(1);
  let retired = h.owner.retire_if_dead(&source_removed(1, "/a", 0));
  assert!(retired, "the dead root retires on the terminal `Removed`");

  // No ordinary terminal event reaches the consumer through the coalescer (fail-on-old: the fanned
  // `Removed` drains here under the immediate-settle window).
  assert!(
    h.drain().is_empty(),
    "the dead-root terminal event is NOT fanned through the coalescer (fail-on-old: a redundant \
     `Removed` drains)"
  );
  // Nothing dangles buffered in the coalescer for the retired subscription.
  assert!(
    h.owner
      .coalescer
      .as_ref()
      .and_then(Coalescer::next_deadline)
      .is_none(),
    "no coalescer entry dangles for the retired subscription"
  );
  // The coverage loss is owed as the durable dominating terminal Rescan.
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the coverage loss is owed as a parked dominating terminal Rescan"
  );

  // It self-drains on the next flush — the consumer learns the root is gone via exactly one Rescan.
  h.owner.flush_pending_rescans();
  let delivered = h.drain();
  assert_eq!(
    delivered.len(),
    1,
    "exactly the terminal Rescan reaches the consumer"
  );
  assert!(
    delivered[0].is_rescan(),
    "…and it is the coverage-loss Rescan"
  );
  assert_eq!(
    delivered[0].subscription(),
    sub,
    "…for the subscription whose root died"
  );
  assert_eq!(
    delivered[0].path(),
    Path::new("/a"),
    "…naming its covered key, which the consumer re-enumerates to discover the root is gone"
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

/// The post-commit orphan window (design driver-golden doc, invariant I1, Codex R10): a `watch`
/// whose caller's wait is dropped **after** the owner committed and **successfully sent** the reply,
/// but **before** the wait observed it, must not strand the committed subscription. The reply carries
/// a RAII `WatchGrant`, not a bare `Subscription`; dropping the reply `Receiver` (the vanished wait)
/// drops the grant, whose `Drop` enqueues a `DropOrphan` the owner reconciles away — releasing the
/// root, filter, and epoch state exactly like an unwatch (the same purge the churn test checks).
///
/// This is the residual hole a bare-`Subscription` reply left open: a successful `send` only proves
/// the receiver existed at that instant, never that it polls the value. Distinct from
/// `caller_vanished_after_commit_is_reconciled_away`, which drops the receiver **before** the send
/// (the pre-existing immediate-reconcile edge); here the send succeeds and the grant's `Drop` is the
/// only thing that can detect the drop.
///
/// Fail-on-old: with the bare reply (no grant `Drop`), dropping the receiver drops only the
/// subscription value — nothing is enqueued and the committed subscription stays live — so the
/// `try_recv().expect(..)` (no `DropOrphan` present) and every purge assertion FAIL.
#[tokio::test]
async fn watch_wait_dropped_after_commit_reconciles_the_orphan_away() {
  let mut h = Harness::new();

  // Drive the owner to COMMIT the watch and SUCCESSFULLY send the reply: `response` is held here,
  // so the grant lands in the `oneshot` slot — exactly the post-send, pre-poll window.
  let (reply, response) = futures_channel::oneshot::channel();
  h.owner
    .on_watch(key("/a"), (), Interest::all(), Filter::all(), reply)
    .await;
  assert_eq!(
    h.owner.source.arm_count(),
    1,
    "the watch armed once — it committed before the wait was dropped"
  );
  assert!(
    h.owner.subsumer.view().is_watched(&key("/a")),
    "the committed subscription reads watched while the grant is still in flight"
  );

  // The caller's wait vanishes in the post-send-pre-poll window: dropping the receiver drops the
  // grant sitting in the slot, whose `Drop` enqueues a reply-less `DropOrphan`.
  drop(response);

  // Process that `DropOrphan` exactly as the run loop would. `try_recv` (not `recv().await`) so the
  // fail-on-old path — where no command was enqueued — asserts cleanly instead of hanging.
  let cmd = h
    .owner
    .commands
    .try_recv()
    .expect("the dropped grant enqueued a DropOrphan cleanup command");
  match cmd {
    super::Command::DropOrphan(sub) => {
      let _ = h.owner.reconcile_unwatch(sub).await;
    }
    _ => panic!("the dropped grant must enqueue exactly a DropOrphan"),
  }

  // The orphan is fully purged — subsumer record, filter, and epoch state all released.
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/a")),
    "the orphaned subscription is no longer watched (reconciled away)"
  );
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "its subsumer root/record is released"
  );
  assert!(h.owner.filters.is_empty(), "its filter entry is purged");
  assert_eq!(
    h.owner.epochs.tracked_len(),
    (0, 0),
    "its epoch state is purged"
  );
  assert!(
    matches!(h.owner.source.calls().last(), Some(Call::Disarm(_))),
    "the committed root was disarmed by the DropOrphan reconcile"
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
    h.owner.needs_rescan.get(&sub).map(|p| p.epoch),
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
    h.owner.needs_rescan.get(&sub).map(|p| p.epoch),
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
  // coverage-loss Rescan overflows and parks. It is an already-minted `Rescan`, so it parks at its
  // OWN dominating epoch — its umbrella stamp `base + raw` = 0 + 3, past the high-water of 2 — not a
  // fresh `shed_rescan` (Codex R5); for a source-overflow Rescan on a live root that is the same
  // strictly-dominating value.
  h.owner.source.kill_root(1);
  h.owner.fan_out_and_push(&rescan_event(1, "/a", 3));
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|p| p.epoch),
    Some(Epoch::new(3)),
    "the overflowed terminal Rescan parked at its own dominating epoch (base + raw = 3)"
  );

  // Retiring the dead root frees its filter + epoch but must KEEP the parked terminal Rescan
  // — dropping it here is the silent-loss regression this test guards.
  h.owner.retire_if_dead(&rescan_event(1, "/a", 0));
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

/// Codex R5 regression (design backpressure doc §8, epoch calibration / no silent loss): a **widen
/// while the event channel is FULL** so the synthetic re-point `Rescan` overflows into
/// `needs_rescan`. It must park at its OWN epoch — the `repoint` base its new root's genuine events
/// are calibrated to tie — NOT a fresh `shed_rescan` (one past the high-water). Parking at
/// `shed_rescan` (high-water + 1) leaves the parked `Rescan` one *above* the new root's
/// raw-epoch-0 event, so a dominance-applying consumer drops that post-widen event as "dominated"
/// even though it happened AFTER the re-enumeration → silent loss under backpressure.
///
/// Fail-on-old: with the old unconditional `park_rescan`, the parked/delivered `Rescan` is epoch 6
/// (high-water 4 → repoint 5 → shed 6), one above the new root's raw-0 stamp (5) → both the
/// `needs_rescan == 5` and the `raw-0 not below the Rescan` assertions FAIL.
#[tokio::test]
async fn widen_repoint_rescan_parks_at_own_epoch_not_shed_when_channel_full() {
  let mut h = Harness::bounded(2);
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // root 1
  // Drive sb's high-water to 4, as genuine deliveries would.
  for raw in 0..5 {
    h.owner.epochs.stamp(sb, Epoch::new(raw));
  }

  // FILL both slots so the widen's re-point Rescan must overflow-park. `try_emit` never re-stamps a
  // pre-stamped delivery, so these fillers leave sb's high-water at 4.
  h.owner.try_emit(modified_event(sb, "/a/b/f0", 0));
  h.owner.try_emit(modified_event(sb, "/a/b/f1", 1));
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the fillers took both slots without overflowing yet"
  );

  // Widen /a/b → /a: sb is re-pointed. `repoint` rebases sb's epoch_base to high-water.next() = 5
  // and mints the re-point Rescan at 5; sb's new root (handle 2) will stamp its raw-0/raw-1 events
  // 5 + 0 and 5 + 1. The `push_all` of that Rescan finds the channel full → it overflows.
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a widens");

  // R5: the overflowed re-point Rescan parks at its OWN epoch (the repoint base 5), NOT a fresh
  // shed_rescan (high-water.next() = 6). Parking at 6 would sort the new root's raw-0 event (5)
  // below it and drop it as dominated.
  assert_eq!(
    h.owner.needs_rescan.get(&sb).map(|p| p.epoch),
    Some(Epoch::new(5)),
    "the re-point Rescan parked at the repoint base (5), not shed_rescan (6)"
  );

  // Resume: drain the two fillers, then flush the parked re-point Rescan.
  assert_eq!(h.drain().len(), 2, "the two pre-widen fillers drained");
  h.owner.flush_pending_rescans();
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the parked re-point Rescan was delivered on resume"
  );
  let rescan = h
    .drain()
    .into_iter()
    .find(|e| e.subscription() == sb && e.is_rescan())
    .expect("the re-point Rescan was delivered");
  assert_eq!(rescan.path(), Path::new("/a"), "it names the widened root");
  let rescan_epoch = rescan.epoch();
  assert_eq!(
    rescan_epoch,
    Epoch::new(5),
    "the delivered re-point Rescan carries the repoint base (5), not shed_rescan (6)"
  );

  // sb's new root (handle 2) now delivers genuine events; they stamp base + raw = 5 + 0, 5 + 1.
  // Drain after each so the two co-subscribers (sb and the new /a watch) never overflow the
  // two-slot channel.
  h.owner.fan_out_and_push(&source_modified(2, "/a/b/g0", 0));
  let raw0 = h
    .drain()
    .into_iter()
    .find(|e| e.subscription() == sb)
    .expect("sb's new-root raw-0 event was delivered, not suppressed");
  h.owner.fan_out_and_push(&source_modified(2, "/a/b/g1", 1));
  let raw1 = h
    .drain()
    .into_iter()
    .find(|e| e.subscription() == sb)
    .expect("sb's new-root raw-1 event was delivered");

  // The R5 payoff: the new root's raw-0 (epoch 5) is NOT below the delivered Rescan (epoch 5) — it
  // ties, so a dominance-applying consumer keeps it. With the old shed_rescan (Rescan at 6), raw-0
  // (5) sorts BELOW it → dropped as dominated → silent loss of a post-widen change.
  assert_eq!(raw0.epoch(), Epoch::new(5), "raw-0 stamps the repoint base");
  assert_eq!(raw1.epoch(), Epoch::new(6), "raw-1 stamps base + 1");
  assert!(
    raw0.epoch() >= rescan_epoch,
    "the new root's raw-0 genuine event is not dominated by the re-point Rescan (no silent loss)"
  );
  assert!(
    raw1.epoch() >= rescan_epoch,
    "…and raw-1 is not dominated either"
  );
}

/// Codex R5 sibling (the coalescer-buffered-delta variant of the re-point-epoch hole): when a
/// re-pointed subscription has **buffered pre-widen deltas** in the coalescer and the channel is
/// FULL, `Coalescer::admit(rescan)` flushes those deltas AHEAD of the re-point `Rescan` in
/// `push_all`; the first flushed ordinary delta hits `Full` and parks via `park_rescan` at a fresh
/// `shed_rescan` (one above the repoint base), suppressing the Rescan behind it and dropping the new
/// root's raw-0 as dominated — the same silent loss the direct-overflow fix closed, via the buffer.
/// The fix drops a re-pointed sub's coalescer buffer BEFORE its re-point Rescan (the Rescan
/// dominates those deltas), so nothing flushes ahead and the Rescan parks at its own repoint base.
///
/// Fail-on-old: with the `drop_subscription` before the widen re-point push removed, the buffered
/// delta flushes ahead, parks at `shed_rescan` (high-water 5 → 6), and the parked epoch is 6, not 5.
#[tokio::test]
async fn widen_drops_buffered_coalescer_delta_so_repoint_rescan_parks_at_own_epoch() {
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(7200));
  let mut h = Harness::build(Some(Coalescer::new(cfg)), Some(2));
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // root 1
  for raw in 0..5 {
    h.owner.epochs.stamp(sb, Epoch::new(raw)); // high-water 4
  }

  // A pre-widen delta BUFFERS in the coalescer (long quiet window → admit runs but nothing drains).
  // It is pre-stamped, so it does not move sb's high-water off 4.
  h.owner
    .push_all(vec![modified_event(sb, "/a/b/buffered", 3)]);
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the buffered delta is held in the coalescer, not overflowed"
  );

  // Fill both channel slots so the widen's re-point Rescan push must overflow-park.
  h.owner.try_emit(modified_event(sb, "/a/b/f0", 0));
  h.owner.try_emit(modified_event(sb, "/a/b/f1", 1));

  // Widen /a/b → /a: `repoint` rebases sb's base to high-water.next() = 5 and mints the re-point
  // Rescan at 5. The fix drops sb's coalescer buffer before pushing that Rescan, so the buffered
  // delta cannot flush ahead of it and park at a fresh `shed_rescan` (6).
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a widens");

  assert_eq!(
    h.owner.needs_rescan.get(&sb).map(|p| p.epoch),
    Some(Epoch::new(5)),
    "the buffered delta was dropped, so the re-point Rescan parked at the repoint base (5), \
     not a fresh shed_rescan (6) minted by a buffered delta flushing ahead of it"
  );
}

/// Codex R8 regression (design backpressure doc, no silent loss): while a subscription is PARKED
/// (its overflow `Rescan` sits in `needs_rescan`), a later SOURCE `Rescan` for a DIFFERENT key
/// under the same root must NOT be discarded — it is an independent coverage-loss signal. The old
/// `try_emit` early-returned for every event of a parked sub, so the second Rescan's subtree was
/// never re-enumerated. The fix merges it into the parked debt, widening the key to the common
/// ancestor that covers BOTH losses.
///
/// Fail-on-old: with the unconditional early return (no merge), the parked key stays `/a/x` and the
/// eventually-delivered Rescan never covers `/a/y` → the common-ancestor assertion FAILS.
#[tokio::test]
async fn a_source_rescan_while_parked_merges_coverage_instead_of_being_dropped() {
  let mut h = Harness::bounded(2);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a"); // root handle 1
  for raw in 0..3 {
    h.owner.epochs.stamp(sub, Epoch::new(raw)); // high-water 2
  }

  // FILL both channel slots so the first source Rescan must overflow-park.
  h.owner.try_emit(modified_event(sub, "/a/f0", 0));
  h.owner.try_emit(modified_event(sub, "/a/f1", 1));

  // A source Rescan for /a/x overflows → parks at its own located key.
  h.owner.fan_out_and_push(&rescan_event(1, "/a/x", 5));
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|p| p.key.clone()),
    Some(key("/a/x")),
    "the first source Rescan parked at its own key /a/x"
  );

  // A SECOND source Rescan for a DIFFERENT key /a/y arrives while parked. It must be MERGED, not
  // discarded: the parked key widens to the common ancestor /a, re-enumerating a superset that
  // covers BOTH /a/x and /a/y.
  h.owner.fan_out_and_push(&rescan_event(1, "/a/y", 6));
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|p| p.key.clone()),
    Some(key("/a")),
    "the second source Rescan merged into the parked debt, widening the key to the common \
     ancestor /a that covers both losses (not dropped, not left at /a/x)"
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
    h.owner.needs_rescan.get(&sub).map(|p| p.epoch),
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
    fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
      Ok(key.to_vec())
    }
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
    fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
      Ok(key.to_vec())
    }
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

/// R2-F1 regression (design backpressure doc, no silent loss): a failed widen whose subsumed
/// root cannot re-arm retires it — and when the event channel is **full** (a stalled consumer)
/// the retire must still owe that root's subscriber its dominating terminal `Rescan`. The shared
/// retire primitive **parks** it into `needs_rescan` (root key + a dominating epoch, captured
/// while live) BEFORE `force_remove_root`, so a full channel cannot drop it. Regression: the old
/// code force-removed the root first and only then pushed the Rescan, so on a full channel
/// `park_rescan`'s `subscription_key` lookup found nothing and the owed terminal Rescan was
/// silently dropped. Fail-on-old: with park-before-retire reverted, the `needs_rescan`/resume
/// assertions FAIL.
#[tokio::test]
async fn failed_widen_retire_parks_owed_terminal_rescan_when_channel_full() {
  let mut h = Harness::bounded(1);
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // root 1
  let _sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // root 2
  // Drive sb's high-water up so its terminal Rescan has a prior stream to dominate.
  for raw in 0..3 {
    h.owner.epochs.stamp(sb, Epoch::new(raw)); // sb high-water 2
  }
  // FILL the one slot so the retire's terminal Rescan for sb must overflow-park, never deliver
  // inline. The raw funnel does not overflow yet (the slot holds exactly this one delivery).
  h.owner.try_emit(modified_event(sb, "/a/b/f0", 0));
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the pre-widen delivery filled the slot without overflowing yet"
  );

  // Fail the wider arm AND the first restore re-arm (/a/b): restore iterates root-key order
  // (/a/b, /a/c), so /a/b cannot re-arm (retired) while /a/c re-arms (restored).
  h.owner.source.fail_next_arms(2);
  let result = h.watch("/a", Interest::all()).await;
  assert!(result.is_err(), "the failed wider arm surfaces the error");

  assert!(
    !h.owner.subsumer.view().is_watched(&key("/a/b")),
    "the un-re-armable subsumed root is retired"
  );
  // The core of the regression: despite the full channel, the retired root's owed terminal
  // Rescan is durably PARKED (parked before the subsumer state was freed), not dropped.
  assert!(
    h.owner.needs_rescan.contains_key(&sb),
    "the retired root's owed terminal Rescan is parked despite the full channel (not dropped)"
  );

  // Resume: drain the buffered pre-widen delivery, then flush the parked Rescans (bounded 1, so
  // flush + drain twice to release every parked entry).
  let buffered = h.drain();
  assert!(
    buffered
      .iter()
      .any(|e| e.subscription() == sb && !e.is_rescan()),
    "the pre-widen sb delivery drained in order"
  );
  let mut resumed = Vec::new();
  for _ in 0..2 {
    h.owner.flush_pending_rescans();
    resumed.extend(h.drain());
  }
  let sb_rescan = resumed
    .iter()
    .find(|e| e.subscription() == sb && e.is_rescan())
    .expect("sb receives its owed terminal dominating Rescan after resume (no silent loss)");
  assert_eq!(
    sb_rescan.path(),
    Path::new("/a/b"),
    "the terminal Rescan names the retired root the consumer re-enumerates"
  );
  let sb_max = buffered
    .iter()
    .filter(|e| e.subscription() == sb)
    .map(Event::epoch)
    .max()
    .expect("sb had a buffered delivery");
  assert!(
    sb_rescan.epoch() > sb_max,
    "sb's terminal Rescan strictly dominates every event delivered to it before it"
  );
}

/// R2-F2 regression (design backpressure doc, checklist #5): with debounce enabled a
/// subscription is **parked** (overflow) AND still holds **buffered tail deltas** whose epoch
/// sits at or above its parked `Rescan`'s (the coalescer admits before `try_emit` suppresses).
/// When the source drains, the owner must NOT deliver those tail deltas ahead of the owed
/// `Rescan` — doing so would let a high-water consumer ignore the `Rescan` and leave the overflow
/// loss unrecovered. The drain **purges** a parked sub's tail (its Rescan re-enumerates +
/// dominates them) and delivers the Rescan first. Regression: the old drain flushed the coalescer
/// tail with a bare `try_send` BEFORE the Rescans, so a tail delta with epoch >= the Rescan was
/// delivered before it. Fail-on-old: with bare-`try_send` tail-first restored, FAILS.
#[tokio::test]
async fn source_drain_orders_parked_rescan_before_its_buffered_tail() {
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(7200));
  let mut h = Harness::build(Some(Coalescer::new(cfg)), Some(1));
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  for raw in 0..2 {
    h.owner.epochs.stamp(sub, Epoch::new(raw)); // high-water 1
  }

  // Fill the one slot and overflow → park a dominating Rescan (epoch 2). The raw funnel bypasses
  // the coalescer, so its buffer is untouched by these two.
  h.owner.try_emit(modified_event(sub, "/a/f0", 0));
  h.owner.try_emit(modified_event(sub, "/a/f1", 1));
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|p| p.epoch),
    Some(Epoch::new(2)),
    "overflow parked a dominating Rescan while the channel is full"
  );

  // After parking, more deltas arrive and BUFFER in the coalescer (admit runs unconditionally;
  // not yet due, so nothing drains). Their epoch (9) is far above the parked Rescan's (2) —
  // exactly the tail-vs-Rescan ordering hazard.
  h.owner.push_all(vec![modified_event(sub, "/a/g0", 9)]);

  // The source drains at teardown; run the drain concurrently with a resuming consumer that
  // collects every event for the sub up to and including its Rescan.
  let events = h.events.clone();
  let owner = &mut h.owner;
  let consumer = async {
    let mut seen: Vec<Event<OsString, ()>> = Vec::new();
    while let Ok(event) = events.recv().await {
      if event.subscription() == sub {
        let is_rescan = event.is_rescan();
        seen.push(event);
        if is_rescan {
          break;
        }
      }
    }
    seen
  };
  let (_, seen) = tokio::time::timeout(Duration::from_secs(10), async {
    tokio::join!(owner.drain_owed_before_shutdown(), consumer)
  })
  .await
  .expect("the source-drain teardown delivered the owed Rescan before the deadline");

  let rescan_pos = seen
    .iter()
    .position(|e| e.is_rescan())
    .expect("the owed Rescan was delivered");
  let rescan_epoch = seen[rescan_pos].epoch();
  assert_eq!(rescan_epoch, Epoch::new(2), "the owed dominating Rescan");
  for earlier in &seen[..rescan_pos] {
    assert!(
      earlier.epoch() < rescan_epoch,
      "no delta with epoch >= the Rescan's is delivered before it (dominance preserved)"
    );
  }
  assert!(
    !seen.iter().any(|e| e.key() == key("/a/g0").as_slice()),
    "the parked sub's buffered tail delta was purged (dominated by its Rescan), not delivered"
  );
  assert!(
    owner.needs_rescan.is_empty(),
    "the owed Rescan was delivered — nothing left parked"
  );
}

/// R2-F3 regression (design backpressure doc, invariant II): after the source drains, the owner
/// owes every parked `Rescan` and retries across a full channel — but that retry must keep
/// servicing the command mailbox, or a `Close` behind a full channel (a held-but-not-draining
/// receiver keeps it both full and un-closed) queues forever and `close()` hangs. The drain
/// `select!`s its retry timer against `commands.recv`, so a mid-drain `Close` is surfaced (to be
/// acked) within a bounded deadline. Fail-on-old: with the command-unresponsive (blind-sleep)
/// drain loop, this times out.
#[tokio::test]
async fn source_drain_retry_stays_responsive_to_close() {
  let mut h = Harness::bounded(1);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  for raw in 0..2 {
    h.owner.epochs.stamp(sub, Epoch::new(raw));
  }
  // Fill the one slot and overflow → park a dominating Rescan; the channel stays FULL and its
  // receiver is HELD but never drained, so neither the slot-freed nor the all-receivers-dropped
  // exit can ever fire on its own.
  h.owner.try_emit(modified_event(sub, "/a/f0", 0));
  h.owner.try_emit(modified_event(sub, "/a/f1", 1));
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "overflow parked a Rescan; the channel is full"
  );
  let _held = h.events.clone(); // a receiver that never drains (keeps the channel full + open)

  // Another handle calls close(): the Close command queues on the (unbounded) mailbox.
  let (reply, response) = futures_channel::oneshot::channel();
  h._commands
    .try_send(super::Command::Close { reply })
    .expect("enqueue the Close command");

  // The source-drain retry must service that Close rather than spin behind the full channel.
  let returned = tokio::time::timeout(
    Duration::from_secs(10),
    h.owner.drain_owed_before_shutdown(),
  )
  .await
  .expect(
    "the source-drain retry stayed responsive to Close (did not hang behind the full channel)",
  );
  let close_reply = returned.expect("the mid-drain Close is surfaced to the caller to be acked");

  // Ack it exactly as `run` does; the close() caller then completes.
  close_reply.send(Ok(())).expect("ack the Close");
  assert!(
    matches!(response.await, Ok(Ok(()))),
    "close() completes once the drain surfaced and acked its Close"
  );
}

/// A [`Source`] whose `next()` **parks** until the test drops its `drain` sender, then yields
/// `None` — so a test can watch a key and take a `WatchView` clone, and only THEN drive the
/// owner's source-drain teardown deterministically (no race between the watch command and the
/// source draining). `arm` succeeds and records the root so `root_key` reports it live.
struct DrainableSource {
  next_handle: u32,
  live: HashMap<u32, Vec<OsString>>,
  drain: async_channel::Receiver<std::convert::Infallible>,
}

impl Source<OsString> for DrainableSource {
  type Handle = u32;

  fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
    Ok(key.to_vec())
  }

  async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
    self.next_handle += 1;
    let handle = self.next_handle;
    self.live.insert(handle, key.to_vec());
    Ok(Armed::new(handle, key.to_vec()))
  }

  async fn disarm(&mut self, handle: u32) {
    self.live.remove(&handle);
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    // Park until the test drops the drain sender; a closed channel (Err) means "drain now".
    match self.drain.recv().await {
      Ok(never) => match never {},
      Err(_) => None,
    }
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.live.get(&handle).cloned()
  }
}

/// R3-F1 regression (design §5, no stale read plane on teardown): the owner publishes an EMPTY
/// read plane at teardown, so a `WatchView` clone taken while watching stops advertising the (now
/// dead) coverage once the source drains and the stream ends. Exercises the real `run()`
/// source-drain teardown through the public [`Tributaries::with_source`](super::Tributaries).
///
/// Regression: the old teardown dropped the owner without republishing, so a retained view kept
/// reading `is_watched=true` / `covering=Some` for a subscription whose owner task + source are
/// gone — a dedup caller (the indexer) would then skip re-installing it and silently miss changes
/// after rebuilding a fresh watcher. Fail-on-old: without the empty publish, `is_watched` stays
/// true after stream-end → FAILS.
#[tokio::test]
async fn teardown_publishes_empty_read_plane_so_view_stops_advertising_dead_subs() {
  let (drain_tx, drain_rx) = async_channel::bounded::<std::convert::Infallible>(1);
  let source = DrainableSource {
    next_handle: 0,
    live: HashMap::new(),
    drain: drain_rx,
  };
  let mut w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());

  // A view clone taken WHILE watching — the pre-taken handle the regression is about.
  let view = w.view();
  let watched = key("/a");
  let _sub = w
    .watch(watched.clone(), (), Interest::all(), Filter::all())
    .await
    .expect("watch /a");
  assert!(view.is_watched(&watched), "the live watch is advertised");
  assert!(
    view.covering(&watched).is_some(),
    "…and attribution resolves it while live"
  );

  // Drain the source: dropping the sender makes `next()` yield None → the source-drain teardown.
  drop(drain_tx);

  // Once the stream ends (next() → None), the owner has torn down and published the empty plane.
  let ended = tokio::time::timeout(Duration::from_secs(10), w.next()).await;
  assert!(
    matches!(ended, Ok(None)),
    "the event stream ends after the source drains + teardown"
  );

  // The pre-taken view now reports nothing watched — the empty read plane published on teardown.
  assert!(
    !view.is_watched(&watched),
    "the retained view stops advertising the dead subscription after teardown (empty read plane)"
  );
  assert!(
    view.covering(&watched).is_none(),
    "…and attribution resolves to nothing (the owner + source are gone)"
  );
}

/// A `u64`-valued [`Owner`] over a [`FakeSource`], with its drainable event stream — the
/// value-baking regression rig. `V = u64` (not [`Harness`]'s `()`) so attribution values are
/// distinguishable; the tests drive the owner's reconcile/emit primitives directly, then assert
/// the baked [`Event::value`] on drained events.
struct OwnerU64 {
  owner: Owner<OsString, u64, TokioRuntime, FakeSource>,
  events: async_channel::Receiver<Event<OsString, u64>>,
  /// Kept alive so the owner's command receiver never observes a closed channel.
  _commands: async_channel::Sender<super::Command<OsString, u64>>,
}

impl OwnerU64 {
  /// Builds the rig with a bounded event channel of `capacity` and an optional coalescer.
  fn new(capacity: usize, coalescer: Option<Coalescer<OsString, u64>>) -> Self {
    let (event_tx, event_rx) = async_channel::bounded(capacity);
    let (command_tx, command_rx) = async_channel::unbounded();
    let owner = Owner {
      source: FakeSource::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
      needs_rescan: BTreeMap::new(),
      coalescer,
      commands_weak: command_tx.downgrade(),
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

  /// Drains every event currently queued on the owner's stream.
  fn drain(&self) -> Vec<Event<OsString, u64>> {
    let mut out = Vec::new();
    while let Ok(event) = self.events.try_recv() {
      out.push(event);
    }
    out
  }
}

/// Value baking, ordinary path (design §3): every delivered delta carries its owning
/// subscription's value, baked at emit time. Fail-on-old: with `Event::value` left `None`, the
/// `Some(42)` assertion FAILS.
#[tokio::test]
async fn delivered_delta_carries_owning_subscription_value() {
  let mut rig = OwnerU64::new(8, None);
  let sub = rig
    .owner
    .reconcile_watch(&key("/a"), 42, Interest::all(), Filter::all())
    .await
    .expect("watch /a");

  // A raw change under /a fans out to the covering sub; the delivery is baked with the sub's value.
  rig.owner.fan_out_and_push(&source_modified(1, "/a/f", 0));

  let drained = rig.drain();
  assert_eq!(drained.len(), 1, "one delivery for the single covering sub");
  assert_eq!(
    drained[0].subscription(),
    sub,
    "…retagged with its subscription"
  );
  assert_eq!(
    drained[0].value().copied(),
    Some(42),
    "a normal delivered delta carries its owning subscription's value (baked at emit time)"
  );
}

/// R4 regression (design §3, event attribution survives teardown): a source-drain leaves a queued
/// coalescer **tail delta** (from one live sub) AND an **owed parked Rescan** (from another sub
/// whose root died). The owner tears down — publishing the EMPTY read plane (R3-F1) — and only
/// THEN does the consumer drain those queued events. Each must be attributable via its baked
/// [`Event::value`], NOT via the emptied [`WatchView`] (whose `resolve` now answers `None`).
///
/// The terminal (retire) Rescan is the sharp case: its owning sub's subsumer state is force-removed
/// at retire, so the value CANNOT be re-resolved at flush time — it is captured at park time while
/// the sub is live. Fail-on-old: with `Event::value` left `None`, the `Some(7)`/`Some(9)`
/// assertions FAIL, and `resolve` returns `None` post-teardown, so the old resolve-based
/// attribution recovers nothing.
#[tokio::test]
async fn baked_value_attributes_queued_events_after_teardown_empties_view() {
  // Windows long enough that the tail delta never settles on its own — it survives as a coalescer
  // tail the teardown drain flushes.
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(7200));
  let mut rig = OwnerU64::new(8, Some(Coalescer::new(cfg)));

  let a = rig
    .owner
    .reconcile_watch(&key("/a"), 7, Interest::all(), Filter::all())
    .await
    .expect("watch /a"); // root handle 1
  let b = rig
    .owner
    .reconcile_watch(&key("/b"), 9, Interest::all(), Filter::all())
    .await
    .expect("watch /b"); // root handle 2

  // A view clone taken WHILE both are live — the handle the R3-F1/R4 story is about.
  let view = rig.owner.subsumer.view();
  assert_eq!(
    view.resolve(&key("/b")).map(|s| *s.get()),
    Some(9),
    "the live view attributes /b while its sub is live"
  );

  // subB buffers a coalescer tail delta (baked value 9 at fan-out; not due under the long window).
  rig.owner.fan_out_and_push(&source_modified(2, "/b/g0", 5));

  // subA's root dies: the terminal Rescan is parked with subA's value CAPTURED AT PARK TIME, then
  // its subsumer state is force-removed — after which the value can no longer be resolved.
  rig.owner.retire_root_with_terminal_rescan(1);
  assert!(
    rig.owner.needs_rescan.contains_key(&a),
    "subA owes a parked terminal Rescan"
  );
  assert_eq!(
    rig.owner.subsumer.subscription_value(a),
    None,
    "subA's subsumer state is gone post-retire — its value HAD to be captured at park time"
  );

  // Teardown drain: deliver the owed Rescan and the coalescer tail into the channel.
  rig.owner.drain_owed_once();
  assert_eq!(
    view.resolve(&key("/b")).map(|s| *s.get()),
    Some(9),
    "subB still resolves through the live view just before the empty publish"
  );

  // Publish the EMPTY read plane exactly as `run()` does at teardown (R3-F1): the view now reports
  // nothing watched, so `resolve` can no longer attribute the still-queued events.
  rig.owner.subsumer.publish_empty();
  assert!(
    view.resolve(&key("/b")).is_none(),
    "teardown emptied the view — resolve now attributes NOTHING for the queued tail delta"
  );
  assert!(
    view.resolve(&key("/a")).is_none(),
    "…and nothing for the retired root"
  );

  // The consumer drains AFTER teardown and attributes each event via its BAKED value.
  let drained = rig.drain();

  let rescan = drained
    .iter()
    .find(|e| e.subscription() == a && e.is_rescan())
    .expect("subA's owed terminal Rescan was delivered");
  assert_eq!(
    rescan.value().copied(),
    Some(7),
    "the owed terminal Rescan carries subA's value baked at park time — attribution survives \
     teardown (the emptied view resolves to None)"
  );

  let tail = drained
    .iter()
    .find(|e| e.subscription() == b && !e.is_rescan())
    .expect("subB's coalescer tail delta was delivered");
  assert_eq!(
    tail.value().copied(),
    Some(9),
    "the coalesced tail delta preserved subB's baked value through buffering"
  );

  assert!(
    drained.iter().all(|e| e.value().is_some()),
    "every delivered event carries a baked owning-subscription value (none slips through as None)"
  );
}

/// Codex R9-F1 (the full per-subscription-purge class): a **consumer unwatch** must purge the
/// debounce coalescer along with every other per-sub structure, so a delta buffered before the
/// unwatch can never drain to the retired subscription. The coalescer's drain path
/// (`drain_coalescer_due` / the teardown flush → `try_emit`) has no live-subscription check, so an
/// entry left buffered is delivered for a subscription whose `unwatch` already resolved.
///
/// Fail-on-old: without `coalescer.drop_subscription(sub)` on unwatch, the buffered delta survives
/// the unwatch and the flush emits it → the drain is non-empty.
#[tokio::test]
async fn consumer_unwatch_purges_buffered_coalescer_delta() {
  // A long quiet window so `push_all`'s immediate drain buffers the delta rather than emitting it.
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(7200));
  let mut h = Harness::with_coalescer(Some(Coalescer::new(cfg)));
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");

  // A pre-unwatch delta buffers in the coalescer (long window → admit runs, nothing drains).
  h.owner.push_all(vec![modified_event(sub, "/a/f", 0)]);
  assert!(
    h.drain().is_empty(),
    "the delta is held under the long quiet window, not yet emitted"
  );

  // The consumer unwatches: every per-sub structure — including the coalescer buffer — is purged.
  h.unwatch(sub).await.expect("sub was live");

  // Both the settle-timer edge and the teardown flush drain the coalescer through `try_emit`;
  // neither may surface anything for the retired subscription.
  h.owner.drain_coalescer_due();
  h.owner.drain_owed_once();
  assert!(
    h.drain().is_empty(),
    "no buffered coalescer event drains for a subscription whose unwatch already resolved"
  );
}

/// Codex R9-F2 (the panic-stranding class): a panic in a caller-provided callback the owner runs
/// synchronously (here the admission [`Filter`] predicate at fan-out) unwinds the owner before the
/// normal teardown path empties the read plane. The `impl Drop for Owner` guard publishes an empty
/// plane on **any** owner drop — normal exit OR a panic — so a retained [`WatchView`] never keeps
/// advertising a subscription whose owner task has died (the R3 stale-read-plane mode). The single
/// Drop guard covers the whole class at once: any unwind through the owner future runs it.
///
/// Fail-on-old: with `impl Drop for Owner` removed, dropping the panicked owner leaves the last
/// committed (non-empty) plane published, so the view still reports the sub watched → the final
/// assertion FAILS.
#[tokio::test]
async fn owner_drop_publishes_empty_read_plane_on_a_panicking_caller_callback() {
  let mut h = Harness::new();
  // A filter whose predicate panics when fan-out consults it — the exact caller callback the owner
  // invokes synchronously inside the run loop.
  let sub = h
    .owner
    .reconcile_watch(
      &key("/a"),
      (),
      Interest::all(),
      Filter::new(|_| -> bool { panic!("caller filter predicate panics inside fan-out") }),
    )
    .await
    .expect("watch /a"); // root handle 1

  // A view clone taken while the sub is live — the retained handle the guarantee is about.
  let view = h.owner.subsumer.view();
  assert!(
    view.is_watched(&key("/a")),
    "the live watch is advertised while the sub is live"
  );

  // Drive an event through fan-out so the filter panics and the owner primitive unwinds. Catch it
  // so the test survives to observe the plane, exactly as a runtime drops a panicked task's future.
  let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    h.owner.fan_out_and_push(&source_modified(1, "/a/f", 0));
  }));
  assert!(
    panicked.is_err(),
    "the caller filter panicked, unwinding the owner"
  );
  assert!(
    view.is_watched(&key("/a")),
    "the caught panic left the owner alive — the plane is unchanged until the owner drops"
  );
  let _ = sub;

  // Dropping the owner (as a runtime drops a panicked task's future) runs the Drop guard, which
  // publishes the empty read plane so the retained view stops advertising the now-dead subscription.
  drop(h);
  assert!(
    !view.is_watched(&key("/a")),
    "the Owner Drop guard emptied the read plane on unwind — no stale coverage for a dead owner"
  );
  assert!(
    view.covering(&key("/a")).is_none(),
    "…and attribution resolves to nothing after the guard empties the plane"
  );
}
