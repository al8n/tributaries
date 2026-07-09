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
  /// An in-place bidirectional coverage-reconcile request: the root handle and the retained cover
  /// (the survivor antichain) the driver forwarded (design M2-B / M2-B v2).
  SetCover(u32, Vec<Vec<OsString>>),
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
  /// Each live handle's modelled ACTUAL kernel coverage as a retained antichain (M2-B v2, Codex
  /// R36): the fake applies every [`set_cover`](Source::set_cover) IMMEDIATELY (unlike `FsSource`,
  /// which queues) so a test can assert the source's true coverage after a shrink-then-grow. A
  /// handle ABSENT here is at FULL coverage (its whole armed root — the fresh-arm default and the
  /// cancel-equivalent); a `Some(cover)` covers exactly the union of the retained prefixes'
  /// subtrees. Queried by [`actual_covers`](Self::actual_covers).
  actual_cover: HashMap<u32, Vec<Vec<OsString>>>,
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
      actual_cover: HashMap::new(),
    }
  }

  /// Whether the fake's modelled ACTUAL kernel coverage for `handle` includes `key` (M2-B v2): a
  /// handle at FULL coverage (no recorded `set_cover`) covers everything under its armed root; a
  /// narrowed handle covers exactly the union of its retained prefixes' subtrees. The regression
  /// probe: after a shrink that pruned a subtree then a grow re-issue, the previously-pruned key is
  /// covered again.
  fn actual_covers(&self, handle: u32, key: &[OsString]) -> bool {
    match self.actual_cover.get(&handle) {
      Some(cover) => cover
        .iter()
        .any(|prefix| key.starts_with(prefix.as_slice())),
      None => self
        .canonical
        .get(&handle)
        .is_some_and(|root| key.starts_with(root.as_slice())),
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

  fn disarm(&mut self, handle: u32) {
    // Synchronous release request (contract clauses 1 & 3): record it and mark the handle released
    // IMMEDIATELY — drop it from `canonical`/`live`, so `root_key` answers `None` at once and a
    // subsequent arm never sees it. Immediate application trivially satisfies the
    // release-before-subsequent-arm ordering.
    self.calls.push(Call::Disarm(handle));
    self.canonical.remove(&handle);
    self.live.remove(&handle);
  }

  fn set_cover(&mut self, handle: u32, retained: &[Vec<OsString>]) {
    // Synchronous, fire-and-forget in-place bidirectional coverage-reconcile REQUEST (design M2-B /
    // M2-B v2): record the root handle and the retained cover the driver forwarded, so a test can
    // assert exactly which covers fired and in what order. The fake keeps the root live — set_cover
    // reconciles coverage BELOW a root, never releases it — so `root_key` still answers, unlike
    // `disarm`. Unlike `FsSource` (which QUEUES and drains opportunistically), the fake APPLIES the
    // reconcile immediately, so `actual_covers` reflects the source's true coverage right away: a
    // cover including the root's own key is FULL coverage (drop the narrowing entry), else it narrows
    // to exactly the retained antichain — this is what lets a test observe a pruned key regain
    // coverage after the grow re-issue (Codex R36).
    self.calls.push(Call::SetCover(handle, retained.to_vec()));
    let root_is_covered = self.canonical.get(&handle).is_some_and(|root| {
      retained
        .iter()
        .any(|prefix| prefix.as_slice() == root.as_slice())
    });
    if root_is_covered {
      self.actual_cover.remove(&handle);
    } else {
      self.actual_cover.insert(handle, retained.to_vec());
    }
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
  /// The dedicated close signal's sender (Codex R27): kept alive so the owner's close receiver
  /// never observes a closed channel, and used by the close-under-teardown tests to inject a close
  /// exactly as `Tributaries::close` does — `try_send(reply)` on this channel, never a command.
  closes: async_channel::Sender<super::CloseReply>,
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
    let (close_tx, close_rx) = async_channel::bounded(1);
    let (cleanup_tx, cleanup_rx) = async_channel::unbounded();
    let owner = Owner {
      source: FakeSource::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
      needs_rescan: BTreeMap::new(),
      unclaimed: std::collections::HashSet::new(),
      coalescer,
      cleanup_tx,
      cleanup_rx,
      commands: command_rx,
      closes: close_rx,
      events: event_tx,
      #[cfg(debug_assertions)]
      observed_handles: std::collections::HashSet::new(),
      _rt: PhantomData::<TokioRuntime>,
    };
    Self {
      owner,
      events: event_rx,
      _commands: command_tx,
      closes: close_tx,
    }
  }

  async fn watch(&mut self, path: &str, interest: Interest) -> Result<Subscription, WatchError> {
    self
      .owner
      .reconcile_watch(&key(path), (), interest, Filter::all())
      .await
  }

  fn unwatch(&mut self, sub: Subscription) -> Result<(), UnwatchError> {
    self.owner.release_subscription(sub)
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
  // Only /a is ARMED. The covered /a/b commit re-issues a (cancel-equivalent) shrink to keep any
  // queued snapshot fresh (Codex R35), never a second arm — so filter to the arms.
  let arms: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::Arm(_)))
    .collect();
  assert_eq!(
    arms,
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

/// M2-B shrink-in-place call-site (design §5): unwatching the widening subscription of a root that
/// widened over NESTED survivors leaves the armed root over-broad, so `release_subscription` forwards
/// EXACTLY ONE `source.set_cover` with the survivor antichain — and NO `disarm` (the root survives; shrink
/// reclaims coverage BELOW it, never releases it).
#[tokio::test]
async fn over_broad_unwatch_set_covers_root_in_place() {
  let mut h = Harness::new();

  // Nested survivors under a to-be-wide root: /a/b and its covered child /a/b/c.
  let _s_b = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let _s_bc = h
    .watch("/a/b/c", Interest::all())
    .await
    .expect("watch /a/b/c covered");
  let s_a = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a widens");
  let wide = h
    .owner
    .subsumer
    .roots()
    .find(|(k, _)| *k == key("/a").as_slice())
    .map(|(_, handle)| handle)
    .expect("the wide /a root is live");

  // Baseline: the widen disarmed the subsumed /a/b root and armed /a — no shrink of the WIDE root
  // yet. (The covered /a/b/c commit re-issued a shrink for the NARROW /a/b root, handle 1, not this
  // wide one — Codex R35 freshness re-issue.)
  assert!(
    !h.owner
      .source
      .calls()
      .iter()
      .any(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide)),
    "no shrink of the wide root before the over-broadening unwatch"
  );

  h.unwatch(s_a).expect("unwatch the widening /a");

  let shrinks: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide))
    .collect();
  assert_eq!(
    shrinks,
    vec![Call::SetCover(wide, vec![key("/a/b")])],
    "exactly one shrink of the wide root to the nested-survivor antichain /a/b (not the raw \
     {{/a/b, /a/b/c}})"
  );
  // The over-broad root is reclaimed in place, never released: no disarm of the wide handle.
  assert!(
    !h.owner
      .source
      .calls()
      .iter()
      .any(|c| matches!(c, Call::Disarm(handle) if *handle == wide)),
    "an over-broad drop shrinks the surviving root, never disarms it"
  );
}

/// No shrink when the drop does NOT leave the root over-broad (design §5): unwatching a NARROWER
/// covered subscription leaves the root still pinned by its own equal-key subscriber, so
/// `release_subscription` forwards no shrink.
#[tokio::test]
async fn narrow_unwatch_does_not_set_cover() {
  let mut h = Harness::new();

  let _s_a = h.watch("/a", Interest::all()).await.expect("watch /a");
  let s_b = h
    .watch("/a/b", Interest::all())
    .await
    .expect("watch /a/b covered");

  // The covered /a/b commit re-issues a cancel-equivalent shrink for the still-pinned root (Codex
  // R35); snapshot the shrink calls so far, so we can assert the UNWATCH below adds none of its own.
  let shrinks_before: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(..)))
    .collect();

  // Drop the narrower /a/b: the root /a is still watched by its own /a subscriber — not over-broad.
  h.unwatch(s_b).expect("unwatch /a/b");

  let shrinks_after: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(..)))
    .collect();
  assert_eq!(
    shrinks_before, shrinks_after,
    "a narrower drop widens no gap — the root stays pinned by its own /a subscriber, so the unwatch \
     fires no shrink"
  );
}

/// The orphan (`DropOrphan`) release path also shrinks (design M2-B): a committed-but-unclaimed wide
/// watch whose caller wait was dropped funnels through the SAME `release_subscription` a caller unwatch
/// does, so an over-broad drop on THAT path forwards the shrink too. The synchronous fire-and-forget
/// shape is exactly what makes one call uniform across every release path (caller unwatch, orphan,
/// teardown) with no async-seam split.
#[tokio::test]
async fn over_broad_droporphan_also_set_covers() {
  let mut h = Harness::new();

  let _s_b = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let s_a = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a widens");
  let wide = h
    .owner
    .subsumer
    .roots()
    .find(|(k, _)| *k == key("/a").as_slice())
    .map(|(_, handle)| handle)
    .expect("the wide /a root is live");

  // Retire the wide /a subscription through the ORPHAN path, not a caller unwatch.
  h.owner.apply_cleanup(super::Cleanup::DropOrphan(s_a));

  let shrinks: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(..)))
    .collect();
  assert_eq!(
    shrinks,
    vec![Call::SetCover(wide, vec![key("/a/b")])],
    "the orphan release shrinks the over-broad root too (uniform sync call-site)"
  );
}

/// R35 freshness re-issue: a queued shrink's retained cover is RE-ISSUED on every Covered commit, so a
/// pending snapshot can never go stale under a still-live root. Wide /a over survivor /a/b: unwatching
/// the widening /a shrinks to {/a/b}; a later `watch /a/c` (Covered, no arm) re-issues the FRESH
/// {/a/b, /a/c} cover — never leaving the stale {/a/b} that a later arm would apply, pruning /a/c's
/// coverage while the subsumer advertises it live (the R35 silent loss); and a final `watch /a`
/// (Covered, key == root) re-issues the cancel-equivalent {/a}, retaining the whole root so nothing is
/// reclaimed. Each is a distinct forwarded `source.set_cover` — the source's LATEST-WINS discipline makes
/// the last one per handle the one actually applied.
///
/// Fail-on-old: without the Covered-commit re-issue, only the first shrink ({/a/b}) is ever sent; the
/// covered /a/c never refreshes it, so the queued {/a/b} applies and silently drops /a/c.
#[tokio::test]
async fn covered_commit_reissues_fresh_retained_cover() {
  let mut h = Harness::new();

  // Wide /a over a disjoint survivor /a/b (a widen, so /a/b is NOT a covered commit — no re-issue
  // until the covered watches below).
  let _s_b = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let s_a = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a widens");
  let wide = h
    .owner
    .subsumer
    .roots()
    .find(|(k, _)| *k == key("/a").as_slice())
    .map(|(_, handle)| handle)
    .expect("the wide /a root is live");

  // Nothing shrunk the wide root yet (the widen re-issues nothing).
  assert!(
    !h.owner
      .source
      .calls()
      .iter()
      .any(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide)),
    "no shrink of the wide root before any over-broadening drop or covered commit"
  );

  // (1) Unwatch the widening /a → over-broad → shrink to the {/a/b} survivor cover.
  h.unwatch(s_a).expect("unwatch the widening /a");
  // (2) watch /a/c, Covered under the still-live wide /a (arms nothing) → re-issue the FRESH
  //     {/a/b, /a/c} cover so the queued shrink never trails behind as the stale {/a/b}.
  let _s_c = h
    .watch("/a/c", Interest::all())
    .await
    .expect("watch /a/c covered");
  // (3) watch /a again, Covered with key == root → cancel-equivalent re-issue {/a} (retain the root).
  let _s_a2 = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a again covered");

  let shrinks: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide))
    .collect();
  assert_eq!(
    shrinks,
    vec![
      Call::SetCover(wide, vec![key("/a/b")]),
      Call::SetCover(wide, vec![key("/a/b"), key("/a/c")]),
      Call::SetCover(wide, vec![key("/a")]),
    ],
    "each Covered commit re-issues the CURRENT retained cover: the {{/a/b}} survivor drop, then the \
     FRESH {{/a/b, /a/c}} (never the stale {{/a/b}}), then the cancel-equivalent {{/a}} once /a \
     re-pins the root — so a queued shrink can never apply a stale snapshot (Codex R35)"
  );
  // The re-issue that matters most: the covered /a/c commit forwarded a cover that INCLUDES /a/c —
  // the fresh membership, never trailing behind as the stale {/a/b} that would drop /a/c silently.
  assert!(
    shrinks
      .iter()
      .any(|c| matches!(c, Call::SetCover(_, cover) if cover.contains(&key("/a/c")))),
    "the covered /a/c commit re-issued a cover that includes /a/c (freshness, not the stale snapshot)"
  );
}

/// M2-B v2 Covered-OUTSIDE bridge + grow, end to end at the driver (Codex R36): after an applied
/// set_cover NARROWED a wide root's ACTUAL coverage below a key, a later watch of that pruned key is
/// `Covered` (arms nothing) yet the source no longer backs it — silent loss unless bridged. The driver
/// must, as one composition: (i) PARK a dominating Rescan for the newcomer's OWN key (bridging the
/// commit→grow gap — suppressed while the grant is unclaimed, delivered once claimed); (ii) re-issue a
/// `set_cover` whose FRESH cover INCLUDES the newcomer (the grow trigger); and (iii) the source's ACTUAL
/// coverage then includes the newcomer again while the retained survivor never lost coverage.
///
/// Fail-on-old: a prune-only shrink cannot restore coverage, so the newcomer would commit over a hole
/// with no Rescan behind it — the exact R36 silent loss this closes.
#[tokio::test]
async fn covered_outside_narrowed_root_parks_bridge_and_grows_coverage() {
  let mut h = Harness::new();

  // Wide /a over a disjoint survivor /a/b, then drop the widening /a → over-broad → set_cover narrows
  // the wide root's ACTUAL coverage to {/a/b}; /a/c is now strictly outside it (pruned at the source).
  let _s_b = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let s_a = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a widens");
  let wide = h
    .owner
    .subsumer
    .roots()
    .find(|(k, _)| *k == key("/a").as_slice())
    .map(|(_, handle)| handle)
    .expect("the wide /a root is live");
  h.unwatch(s_a).expect("unwatch the widening /a");

  // Precondition — the source's actual coverage was narrowed: /a/b stays covered, /a/c does NOT.
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/b")),
    "the retained /a/b survivor stays covered after the shrink"
  );
  assert!(
    !h.owner.source.actual_covers(wide, &key("/a/c")),
    "the pruned /a/c is NOT covered before the newcomer (the narrowed source state)"
  );

  let set_covers_before = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide))
    .count();

  // Watch /a/c: Covered under the still-armed wide /a, but OUTSIDE the narrowed cover {/a/b}.
  let s_c = h
    .watch("/a/c", Interest::all())
    .await
    .expect("watch /a/c covered-outside");

  // (i) A dominating bridging Rescan is PARKED for the newcomer, naming its OWN key /a/c.
  let parked = h
    .owner
    .needs_rescan
    .get(&s_c)
    .expect("a bridging Rescan is parked for the covered-outside newcomer");
  assert_eq!(
    parked.key,
    key("/a/c"),
    "the bridge Rescan re-enumerates the newcomer's own key"
  );
  // ...suppressed while the grant is unclaimed, then delivered once claimed. Clear any pre-existing
  // stream events first (the widen re-pointed /a/b's Rescan) so the probe sees only the bridge.
  let _ = h.drain();
  h.owner.unclaimed.insert(s_c);
  h.owner.flush_pending_rescans();
  assert!(
    h.drain().is_empty(),
    "the parked bridge Rescan is suppressed while the newcomer's grant is unclaimed"
  );
  h.owner.unclaimed.remove(&s_c); // the caller claims the grant
  h.owner.flush_pending_rescans();
  let delivered = h.drain();
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == s_c && e.is_rescan() && e.key() == key("/a/c").as_slice()),
    "the bridge Rescan delivers to the newcomer once its grant is claimed"
  );

  // (ii) The Covered-outside commit re-issued a set_cover whose FRESH cover INCLUDES the newcomer.
  let set_covers_after: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide))
    .collect();
  assert!(
    set_covers_after.len() > set_covers_before,
    "the covered-outside commit re-issued a set_cover (the grow trigger)"
  );
  assert!(
    set_covers_after
      .iter()
      .any(|c| matches!(c, Call::SetCover(_, cover) if cover.contains(&key("/a/c")))),
    "the re-issued cover INCLUDES the newcomer /a/c — the grow, never the stale {{/a/b}}"
  );

  // (iii) The source's ACTUAL coverage grew back to include /a/c, and /a/b never lost coverage.
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/c")),
    "the source grew its actual coverage back to include the newcomer /a/c (Codex R36)"
  );
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/b")),
    "the retained /a/b never lost coverage across the grow (no gap, no re-crawl)"
  );
}

/// Codex R38 regression — the recorded retained cover is PESSIMISTIC on a broaden: a Covered-outside
/// grow only ENQUEUES the set_cover (for the fs source, a reply-less try_send applied later), so the
/// record must NOT broaden at issuance. Two back-to-back Covered-outside watches after a narrow:
/// the SECOND lands in the first's enqueue→apply window and must STILL classify outside the old
/// narrow record — parking its own bridging Rescan — or writes under its still-pruned subtree would
/// be silently missed. Fail-on-old: recording the broadened cover at the first grow made the second
/// newcomer read inside-cover, skipping its bridge.
#[tokio::test]
async fn second_covered_outside_during_a_pending_broaden_still_bridges() {
  let mut h = Harness::new();

  // Narrow the wide /a root to {/a/b} (the over-broad release records the NARROW cover).
  let _s_b = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let s_a = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a widens");
  h.unwatch(s_a).expect("unwatch the widening /a");

  // FIRST Covered-outside newcomer: bridges + enqueues the grow (the record must stay {/a/b}).
  let s_c = h
    .watch("/a/c", Interest::all())
    .await
    .expect("watch /a/c covered-outside");
  assert!(
    h.owner.needs_rescan.contains_key(&s_c),
    "the first covered-outside newcomer parks its bridge"
  );

  // SECOND Covered-outside newcomer, conceptually inside the first grow's enqueue→apply window:
  // the pessimistic record means it MUST also classify outside and park its own bridge.
  let s_d = h
    .watch("/a/d", Interest::all())
    .await
    .expect("watch /a/d covered-outside");
  assert!(
    h.owner.needs_rescan.contains_key(&s_d),
    "the SECOND covered-outside newcomer ALSO parks a bridge — the record never broadened at \
     issuance (Codex R38)"
  );
  // And its own grow re-issue carries a cover including /a/d (latest-wins at the source).
  assert!(
    h.owner
      .source
      .calls()
      .iter()
      .any(|c| matches!(c, Call::SetCover(_, cover) if cover.contains(&key("/a/d")))),
    "the second newcomer re-triggered the grow with a cover including its key"
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
/// for a re-arm violates the contract, and the arm choke point's observed-handle `debug_assert`
/// (Codex R17) must catch it LOUDLY rather than let `rebind_root` silently corrupt the reverse
/// index. Here the widen of `/a` fails and the restore of `/a/b` (old handle 1) re-arms while the
/// source REUSES handle `2` — already observed when the sibling `/a/c` was armed. The re-arm trips
/// the observed-handle assert first (`rebind_root(1, 2)` would otherwise overwrite `by_handle[2]`
/// and strand `/a/c`).
///
/// The earlier R14-F2 defensive recovery (disarm the aliased handle + retire `old`) was RETIRED
/// (Codex R15): it was incomplete, and when the alias was an unrelated *live* root its `disarm`
/// released that root's real source watch while its record + coverage stayed live — silently missing
/// future changes (R15-F2). The strengthened contract makes the alias impossible for a conforming
/// source (a re-arm mints a fresh generation while `old` and its siblings are still recorded), so
/// the debug_assert is the debug/test-only tripwire for a violating one. Hence `#[should_panic]` —
/// and `ignore`d in release builds, where `debug_assert!` is compiled out and nothing panics.
#[tokio::test]
#[should_panic(expected = "already observed by this owner")]
#[cfg_attr(
  not(debug_assertions),
  ignore = "the debug_assert tripwire is compiled out in release builds"
)]
async fn failed_widen_restore_reusing_a_recorded_sibling_handle_trips_the_tripwire() {
  let mut h = Harness::new();

  let _sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let _sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2

  // The wider /a arm fails, AND the first restore re-arm (/a/b) REUSES handle 2 — already observed
  // when the sibling /a/c was armed. That is a generation-unique `Source::Handle` VIOLATION, so the
  // arm choke point's observed-handle debug_assert panics at re-arm time, before the rebind (R17).
  h.owner.source.fail_next_arm();
  h.owner.source.reuse_next_arm_handle(2);
  // Panics inside the restore, before the watch returns — the source violated the handle contract.
  let _ = h.watch("/a", Interest::all()).await;
}

/// Codex R16 regression (generation-unique contract, the SAME-key case the original R15 rebind
/// tripwire wrongly exempted with `|| new_handle == old`): the failed-widen restore re-arm must
/// mint a FRESH handle even for the same key — reusing `old` is a `Source::Handle` violation,
/// because a stale pre-disarm event still carrying `old` would then route through the re-armed root
/// and be stamped in the new generation past the restore Rescan (a handle-ABA sibling). The
/// exhaustive observed-handle tripwire (Codex R17) has NO same-key exemption: `old` was observed
/// when `/a/b` was first armed, so re-arming with it trips the arm choke point's assert.
///
/// Fail-on-old: the retired R15 rebind assert's `|| new_handle == old` exemption masked this
/// same-`old` reuse (no panic). The observed-handle set — which records `old` at its first arm and
/// never prunes — has no such exemption, so a same-`old` re-arm still trips.
#[tokio::test]
#[should_panic(expected = "already observed by this owner")]
#[cfg_attr(
  not(debug_assertions),
  ignore = "the debug_assert tripwire is compiled out in release builds"
)]
async fn failed_widen_restore_reusing_old_handle_trips_the_tripwire() {
  let mut h = Harness::new();

  let _sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let _sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2

  // The wider /a arm fails; the first restore re-arm (/a/b) REUSES handle 1 — /a/b's OWN old handle
  // (same-key reuse), observed when /a/b was first armed. Generation-unique forbids reissuing `old`,
  // so the arm choke point's observed-handle debug_assert panics at re-arm time (R16/R17) rather
  // than let a stale `old` event route through the re-armed root.
  h.owner.source.fail_next_arm();
  h.owner.source.reuse_next_arm_handle(1);
  let _ = h.watch("/a", Interest::all()).await;
}

/// Codex R17 regression (the exhaustive observed-handle tripwire — the POST-RETIREMENT reuse the
/// per-site live-index checks MISSED): a handle removed from the live index by an `unwatch` (or a
/// terminal retirement) that a later arm REUSES is still a generation-unique `Source::Handle`
/// violation — a stale event still carrying it would route through the re-armed root in its new
/// generation. The retired per-site checks only asserted `entry(handle).is_none()` against the
/// CURRENT index, so a reused post-retirement handle (absent from the index) passed them silently;
/// the owner-level observed-handle set catches it, because the handle was observed at its first arm
/// and the set is never pruned.
///
/// Fail-on-old: after the `unwatch`, handle 1 is gone from `by_handle` (`plan_unwatch` removes it on
/// `RootEmptied`), so the reused-handle re-watch takes the `Disjoint` commit path whose retired
/// live-index-only assert `entry(1).is_none()` would PASS — no panic, and `/b` would silently bind
/// to the retired handle 1. The observed-handle assert trips instead, at the arm choke point.
#[tokio::test]
#[should_panic(expected = "already observed by this owner")]
#[cfg_attr(
  not(debug_assertions),
  ignore = "the debug_assert tripwire is compiled out in release builds"
)]
async fn rearm_reusing_a_retired_handle_trips_the_tripwire() {
  let mut h = Harness::new();

  // Watch /a (handle 1), then unwatch it: the root is emptied, so `plan_unwatch` disarms handle 1
  // AND removes it from the live index (`by_handle`). Handle 1 is now retired — gone from every live
  // structure, but permanently recorded in the owner's observed-handle set.
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  h.unwatch(sa).expect("unwatch /a");

  // Re-watch a disjoint key and force the source to REUSE the retired handle 1 — a generation-unique
  // `Source::Handle` violation. The retired live-index check would pass (handle 1 is absent from the
  // index after the unwatch), but the arm choke point's observed-handle debug_assert panics (R17).
  h.owner.source.reuse_next_arm_handle(1);
  let _ = h.watch("/b", Interest::all()).await;
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
    assert!(h.unwatch(a).is_ok(), "a was live");
    assert!(h.unwatch(wide).is_ok(), "wide was live");
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

/// The one residual "dropped wait" case (design driver-golden doc, invariant I1): a `watch` whose
/// caller vanished before the owner could hand back the grant (its reply `oneshot` is closed at send
/// time) is orphaned — its owner-local state (subsumer record, filter, epoch) is purged and, being
/// the root's last subscriber, its kernel watch is released through the **synchronous**
/// [`Source::disarm`] request. The release awaits nothing, so a `Close` queued behind this `Watch` is
/// never blocked on source I/O (invariant II — Close-responsive by construction).
///
/// Non-vacuous: asserts the orphan's owner-local state is fully purged, its last-subscriber `Disarm`
/// op is recorded at cleanup, and the released handle is logically dead immediately
/// (`root_key` → None). Fail-on-old (the pre-golden awaited disarm could block the owner): here the
/// synchronous `release_subscription` records the release at once and never yields.
#[tokio::test]
async fn caller_vanished_after_commit_releases_the_orphan_synchronously() {
  let mut h = Harness::new();

  let (reply, response) = futures_channel::oneshot::channel();
  drop(response); // the caller's wait vanished before the reconcile ran

  h.owner
    .on_watch(key("/a"), (), Interest::all(), Filter::all(), reply)
    .await;

  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "the orphaned subscription's owner-local state was purged"
  );
  assert!(h.owner.filters.is_empty(), "its filter state was reclaimed");
  assert_eq!(
    h.owner.source.arm_count(),
    1,
    "the watch armed once (it committed) before being orphaned"
  );
  // The last-subscriber disarm ran SYNCHRONOUSLY at cleanup: a `Disarm(1)` is recorded and the handle
  // is logically dead immediately (`root_key` → None) — no deferral, no await, nothing to block a
  // `Close` queued behind this `Watch`.
  assert!(
    h.owner.source.calls().contains(&Call::Disarm(1)),
    "the committed root's last-subscriber disarm was requested synchronously at cleanup"
  );
  assert_eq!(
    h.owner.source.root_key(1),
    None,
    "the released handle is logically dead immediately"
  );
}

/// The post-commit orphan window (design driver-golden doc, invariant I1, Codex R10): a `watch`
/// whose caller's wait is dropped **after** the owner committed and **successfully sent** the reply,
/// but **before** the wait observed it, must not strand the committed subscription. The reply carries
/// a RAII `WatchGrant`, not a bare `Subscription`; dropping the reply `Receiver` (the vanished wait)
/// drops the grant, whose `Drop` enqueues a `DropOrphan` the owner reconciles away — purging the
/// filter and epoch state and releasing the root's kernel watch through the **synchronous**
/// [`Source::disarm`] request (never an awaited teardown that could block a `Close` behind it).
///
/// This is the residual hole a bare-`Subscription` reply left open: a successful `send` only proves
/// the receiver existed at that instant, never that it polls the value. Distinct from
/// `caller_vanished_after_commit_releases_the_orphan_synchronously`, which drops the receiver
/// **before** the send (the immediate-reconcile edge); here the send succeeds and the grant's `Drop`
/// is the only thing that can detect the drop.
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
  // grant sitting in the slot, whose `Drop` enqueues a reply-less `Cleanup::DropOrphan` on the
  // dedicated cleanup channel.
  drop(response);

  // Process that `Cleanup::DropOrphan` exactly as the run loop would. `try_recv` (not `recv().await`)
  // so the fail-on-old path — where no cleanup was enqueued — asserts cleanly instead of hanging.
  let cleanup = h
    .owner
    .cleanup_rx
    .try_recv()
    .expect("the dropped grant enqueued a DropOrphan cleanup notice");
  assert!(
    matches!(cleanup, super::Cleanup::DropOrphan(_)),
    "the dropped grant must enqueue exactly a Cleanup::DropOrphan"
  );
  // Apply it exactly as the run loop's cleanup drain does: release the orphan through the unified
  // `release_subscription` — purge owner-local state and request the emptied root's synchronous
  // `source.disarm`.
  h.owner.apply_cleanup(cleanup);

  // The orphan's owner-local state is fully purged — subsumer record, filter, and epoch all released.
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
  // The kernel disarm ran SYNCHRONOUSLY as part of the DropOrphan dispatch: a `Disarm(1)` is recorded
  // and the released handle is logically dead immediately (`root_key` → None) — no deferral, so a
  // `Close` behind this `DropOrphan` is never blocked on source I/O.
  assert!(
    h.owner.source.calls().contains(&Call::Disarm(1)),
    "the committed root's last-subscriber disarm was requested synchronously at cleanup"
  );
  assert_eq!(
    h.owner.source.root_key(1),
    None,
    "the released handle is logically dead immediately"
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
    fn disarm(&mut self, _handle: u32) {}
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
    fn disarm(&mut self, _handle: u32) {}
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
/// owes every parked `Rescan` and retries across a full channel — but that retry must stay
/// responsive to shutdown, or a close behind a full channel (a held-but-not-draining receiver keeps
/// it both full and un-closed) waits forever and `close()` hangs. The drain checks the dedicated
/// close signal at the top priority (a non-blocking `try_recv` each iteration AND the first arm of
/// its retry `select!`), so a mid-drain close is surfaced (to be acked) within a bounded deadline.
/// Fail-on-old: with the close-unresponsive (blind-sleep) drain loop, this times out.
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

  // Another handle calls close(): the reply rides the dedicated close signal, not the mailbox.
  let (reply, response) = futures_channel::oneshot::channel();
  h.closes
    .try_send(reply)
    .expect("send the close on the dedicated signal");

  // The source-drain retry must service that close rather than spin behind the full channel.
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

/// R28-F2 regression (design backpressure doc, no silent loss): a close that INTERRUPTS the
/// source-drain teardown must not skip the final best-effort owed flush. The drain returns the
/// reply at its top-priority close check WITHOUT running an owed pass — but a resuming consumer may
/// have freed a channel slot in the window just before the close arrived, so the now-sendable
/// CLAIMED parked Rescan must still get its last offer. `run`'s tail runs ONE more non-blocking
/// [`drain_owed_once`](super::Owner::drain_owed_once) when the drain returns `Some(reply)` (mirroring
/// the non-drain close path); this test exercises that exact tail sequence (drain → `Some(reply)` →
/// final pass → ack).
///
/// Fail-on-old: without the tail's final pass the owed Rescan is never delivered — the drain returned
/// before any pass and the freed slot goes unused — so a consumer that resumes reaches stream-end
/// permanently stale.
#[tokio::test]
async fn source_drain_close_interrupt_still_runs_a_final_owed_pass() {
  let mut h = Harness::bounded(1);
  // A CLAIMED sub (reconcile_watch commits directly — never recorded `unclaimed`), so its parked
  // debt is genuinely owed and offered by `flush_pending_rescans`, never suppressed.
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  for raw in 0..2 {
    h.owner.epochs.stamp(sub, Epoch::new(raw)); // high-water 1
  }

  // Fill the one slot (a buffered ordinary event) and overflow → park a dominating Rescan (epoch 2).
  h.owner.try_emit(modified_event(sub, "/a/f0", 0));
  h.owner.try_emit(modified_event(sub, "/a/f1", 1));
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|p| p.epoch),
    Some(Epoch::new(2)),
    "overflow parked a dominating Rescan while the channel is full"
  );

  // A resuming consumer FREES one slot (drains the buffered ordinary event) — the channel now has
  // room for the owed Rescan.
  let buffered = h
    .events
    .try_recv()
    .expect("the buffered ordinary event drains, freeing a slot");
  assert!(!buffered.is_rescan(), "the freed event is the ordinary one");

  // …then a close is queued on the dedicated signal, all BEFORE the drain runs. The drain observes
  // the already-queued close at its top-priority `try_recv` and returns it WITHOUT running an owed
  // pass — so the freed slot is left unused and the owed Rescan stays parked.
  let (reply, response) = futures_channel::oneshot::channel();
  h.closes
    .try_send(reply)
    .expect("send the close on the dedicated signal");
  let interrupted = h.owner.drain_owed_before_shutdown().await;
  let close_reply = interrupted.expect("the queued close interrupted the drain and is surfaced");
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the interrupted drain returned before delivering the owed Rescan (the freed slot is unused)"
  );

  // `run`'s tail: because the drain returned `Some(reply)`, run ONE final best-effort owed pass
  // before publish_empty + ack. The slot is now free, so this delivers the owed Rescan.
  h.owner.drain_owed_once();
  // Ack exactly as `run` does; the close() caller then completes.
  close_reply.send(Ok(())).expect("ack the close");
  assert!(
    matches!(response.await, Ok(Ok(()))),
    "close() completes once the drain surfaced and acked its close"
  );

  // The final pass delivered the now-sendable owed Rescan — nothing left parked, and it dominates
  // the earlier ordinary event.
  let owed = h
    .events
    .try_recv()
    .expect("the final owed pass delivered the parked Rescan onto the freed slot");
  assert!(owed.is_rescan(), "the delivered owed signal is a Rescan");
  assert_eq!(owed.subscription(), sub, "…for the overflowed subscription");
  assert_eq!(
    owed.path(),
    Path::new("/a"),
    "…naming its covered key to re-enumerate"
  );
  assert!(
    owed.epoch() > buffered.epoch(),
    "the owed Rescan strictly dominates the ordinary event delivered before it (no silent loss)"
  );
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the final pass delivered the owed Rescan — nothing left parked"
  );
}

/// Codex R30-F1 regression — the close-time grant-resolution drain is bounded by the grants IN FLIGHT,
/// never by the unbounded PUBLIC backlog. A close that interrupts the source drain runs the tail's
/// [`drain_pending_cleanup`](super::Owner::drain_pending_cleanup) — a full drain of the dedicated
/// cleanup channel — BEFORE its final owed pass, so a subscription the caller claimed (its
/// [`Cleanup::Claim`](super::Cleanup::Claim) queued) has its [`unclaimed`](super::Owner::unclaimed)
/// suppression lifted and its genuinely-owed parked Rescan delivered, even with a deep public
/// `Watch`/`Unwatch` backlog sitting UNWALKED in the mailbox (the O(public backlog) close-ack the old
/// close-time mailbox scan caused). This test drives that exact sequence (drain → `Some(reply)` →
/// cleanup drain → final pass → ack) with ~2000 prefilled public commands.
///
/// Fail-on-old: the retired mailbox scan walked `commands.len()` (the whole 2000-deep public backlog)
/// to find the claim — O(public backlog); the cleanup drain finds it in the dedicated channel (O(grants
/// in flight)) and leaves the 2000 public commands untouched (asserted below).
#[tokio::test]
async fn close_tail_drains_cleanup_not_public_backlog() {
  let mut h = Harness::new(); // unbounded event channel — has capacity for the owed Rescan
  // An UNCLAIMED sub (its grant still in flight) with parked overflow debt: `flush_pending_rescans`
  // SUPPRESSES it while unclaimed, so a plain final pass would withhold it.
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  h.owner.unclaimed.insert(sub);
  for raw in 0..2 {
    h.owner.epochs.stamp(sub, Epoch::new(raw));
  }
  h.owner.park_rescan(sub);
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the unclaimed sub's overflow Rescan is parked (suppressed while unclaimed)"
  );

  // Prefill ~2000 PUBLIC Watch commands (reply receivers dropped): the deep mailbox backlog the old
  // linearize walked O(n) to find a claim. The cleanup drain must NOT walk them.
  const BACKLOG: usize = 2000;
  for i in 0..BACKLOG {
    let (reply, resp) = futures_channel::oneshot::channel();
    drop(resp);
    h._commands
      .try_send(super::Command::Watch {
        key: key(&format!("/flood{i}")),
        value: (),
        interest: Interest::all(),
        filter: Filter::all(),
        reply,
      })
      .expect("prefill a public backlog command");
  }
  // The caller CLAIMS the grant — its `Cleanup::Claim` rides the dedicated cleanup channel (as a
  // defused grant's `try_send` would), NOT the public mailbox.
  h.owner
    .cleanup_tx
    .try_send(super::Cleanup::Claim(sub))
    .expect("enqueue the claim on the dedicated cleanup channel");

  // A close is queued on the dedicated signal BEFORE the drain runs, so the drain returns it at its
  // top-priority `try_recv` WITHOUT running any pass or draining any cleanup.
  let (reply, response) = futures_channel::oneshot::channel();
  h.closes
    .try_send(reply)
    .expect("send the close on the dedicated signal");
  let interrupted =
    tokio::time::timeout(Duration::from_secs(5), h.owner.drain_owed_before_shutdown())
      .await
      .expect("the drain returns promptly (close queued first), not O(public backlog)");
  let close_reply = interrupted.expect("the queued close interrupted the drain and is surfaced");
  assert!(
    h.owner.unclaimed.contains(&sub) && h.owner.needs_rescan.contains_key(&sub),
    "the drain returned before draining the queued Cleanup::Claim — the debt is still suppressed"
  );
  assert!(
    h.drain().is_empty(),
    "…and nothing was delivered yet (a bare final pass here would suppress the unclaimed debt)"
  );

  // `run`'s tail on a drain-interrupt: FIRST the full cleanup drain (bounded by grants in flight —
  // one Claim here — NOT the 2000-command backlog), lifting the sub's suppression, THEN one final
  // owed pass.
  h.owner.drain_pending_cleanup();
  assert!(
    !h.owner.unclaimed.contains(&sub),
    "the cleanup drain processed the Claim — suppression lifted"
  );
  h.owner.drain_owed_once();

  // The final pass delivered the now-owed Rescan BEFORE the ack is sent (mirroring `run`'s tail order:
  // drain_pending_cleanup → drain_owed_once → publish_empty → reply.send). Assert it is observable now.
  let delivered = h.drain();
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == sub && e.is_rescan()),
    "the claimed sub's parked Rescan is delivered by the final pass, before the ack (Codex R30-F1)"
  );
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the owed debt is resolved, not stranded by stale suppression state"
  );
  // The 2000 public commands are UNTOUCHED — the cleanup drain is O(grants in flight), not O(public
  // backlog); they drop unread at teardown (senders see Closed). This is the F1 property.
  assert_eq!(
    h.owner.commands.len(),
    BACKLOG,
    "the public backlog is never walked by the cleanup drain (Codex R30-F1)"
  );

  // Ack exactly as `run` does; the close() caller then completes.
  close_reply.send(Ok(())).expect("ack the close");
  assert!(
    matches!(response.await, Ok(Ok(()))),
    "close() completes once the interrupted drain acked its close"
  );
}

/// Close-responsive source drain (design source doc, invariant II): during source-drain teardown a
/// queued [`Cleanup::DropOrphan`](super::Cleanup::DropOrphan) is released through the synchronous
/// [`release_subscription`](super::Owner::release_subscription) — it purges the orphan's owner-local
/// state and requests the emptied root's `source.disarm`, awaiting nothing — so it never wedges the
/// owner, and the close (on its dedicated signal) is surfaced promptly with no scheduling discipline
/// to get wrong. The purge is keyed on the orphan alone, so a live sub's owed Rescan survives it.
///
/// Non-vacuous: with a `Cleanup::DropOrphan` queued on the cleanup channel and a SEPARATE live
/// subscription keeping a Rescan parked behind a full, held-open channel (so the drain loop keeps
/// spinning and draining cleanup), it asserts the drain surfaces the close within the deadline, the
/// orphan is reconciled away (its last-subscriber root released synchronously — a `Disarm` op
/// recorded), and the live sub's owed Rescan survives untouched.
#[tokio::test]
async fn source_drain_dropped_orphan_is_purged_without_blocking_close_on_disarm() {
  let mut h = Harness::bounded(1);

  // A LIVE subscription whose parked overflow Rescan keeps the drain loop spinning (its channel is
  // filled + held open below), plus an ORPHAN on a disjoint root — the `DropOrphan` target and its
  // own root's last subscriber, so releasing it requests that root's `disarm`.
  let live = h.watch("/a", Interest::all()).await.expect("watch /a");
  let orphan = h.watch("/b", Interest::all()).await.expect("watch /b");
  // Monotonic mint: /a = handle 1, /b = handle 2.

  for raw in 0..2 {
    h.owner.epochs.stamp(live, Epoch::new(raw));
  }
  // Fill the one slot and overflow → park the LIVE sub's dominating Rescan; the held receiver keeps
  // the channel full + open, so neither the slot-freed nor the all-receivers-dropped exit can fire.
  h.owner.try_emit(modified_event(live, "/a/f0", 0));
  h.owner.try_emit(modified_event(live, "/a/f1", 1));
  assert!(
    h.owner.needs_rescan.contains_key(&live),
    "overflow parked the live sub's Rescan; the channel is full"
  );
  let _held = h.events.clone(); // a receiver that never drains (keeps the channel full + open)

  // Queue Cleanup::DropOrphan(orphan) on the dedicated cleanup channel. The close is NOT sent yet:
  // under R27 a close already pending on the dedicated signal would (correctly) preempt everything, so
  // to exercise the drain SERVICING the DropOrphan we let it arrive only after the drain's first pass.
  // Run the drain concurrently with a sender that yields once (so the drain runs its first
  // top-of-iteration cleanup drain — servicing the queued DropOrphan via the synchronous release —
  // before the close lands), then interrupts it via the dedicated close arm.
  h.owner
    .cleanup_tx
    .try_send(super::Cleanup::DropOrphan(orphan))
    .expect("enqueue the DropOrphan cleanup notice");
  let (reply, response) = futures_channel::oneshot::channel();
  let closes = h.closes.clone();
  let (returned, ()) = tokio::time::timeout(Duration::from_secs(5), async {
    tokio::join!(h.owner.drain_owed_before_shutdown(), async move {
      tokio::task::yield_now().await;
      closes
        .try_send(reply)
        .expect("send the close on the dedicated signal");
    })
  })
  .await
  .expect("the drain serviced the queued DropOrphan and then surfaced the close");
  let close_reply = returned.expect("the mid-drain close is surfaced to the caller to be acked");

  // Ack it exactly as `run` does; the close() caller then completes.
  close_reply.send(Ok(())).expect("ack the close");
  assert!(
    matches!(response.await, Ok(Ok(()))),
    "close() completes once the drain surfaced and acked its close"
  );

  // The orphan's last-subscriber root was released SYNCHRONOUSLY — a `Disarm(2)` recorded at cleanup
  // — while the live sub's owed Rescan (a DIFFERENT sub's `needs_rescan` entry) survived untouched.
  assert!(
    h.owner.source.calls().contains(&Call::Disarm(2)),
    "the teardown released the orphan's last-subscriber root via the synchronous disarm request"
  );
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/b")),
    "the orphan is reconciled away (its per-sub state purged)"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&live),
    "the live sub's owed parked Rescan survived the orphan purge"
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

  fn disarm(&mut self, handle: u32) {
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
  /// Kept alive so the owner's close receiver never observes a closed channel (these rigs drive
  /// primitives directly and never inject a close).
  _closes: async_channel::Sender<super::CloseReply>,
}

impl OwnerU64 {
  /// Builds the rig with a bounded event channel of `capacity` and an optional coalescer.
  fn new(capacity: usize, coalescer: Option<Coalescer<OsString, u64>>) -> Self {
    let (event_tx, event_rx) = async_channel::bounded(capacity);
    let (command_tx, command_rx) = async_channel::unbounded();
    let (close_tx, close_rx) = async_channel::bounded(1);
    let (cleanup_tx, cleanup_rx) = async_channel::unbounded();
    let owner = Owner {
      source: FakeSource::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
      needs_rescan: BTreeMap::new(),
      unclaimed: std::collections::HashSet::new(),
      coalescer,
      cleanup_tx,
      cleanup_rx,
      commands: command_rx,
      closes: close_rx,
      events: event_tx,
      #[cfg(debug_assertions)]
      observed_handles: std::collections::HashSet::new(),
      _rt: PhantomData::<TokioRuntime>,
    };
    Self {
      owner,
      events: event_rx,
      _commands: command_tx,
      _closes: close_tx,
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
  h.unwatch(sub).expect("sub was live");

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

/// R20-F2 regression (design source doc, invariant I4 / no false debt):
/// [`release_subscription`](super::Owner::release_subscription) must clear a subscription's
/// owner-local per-sub state — above all its parked overflow [`Rescan`](tributary_fs::EventKind::Rescan)
/// — EVEN WHEN the subscription is already absent from the subsumer (terminal-retired). A committed-but-unclaimed
/// watch can be terminal-retired (its terminal Rescan parked, the sub force-removed from the
/// subsumer) while its [`WatchGrant`](super::WatchGrant) still sits in the reply slot; the later
/// [`Cleanup::DropOrphan`](super::Cleanup::DropOrphan) then finds `plan_unwatch` reporting `Unknown`. The fix
/// runs the local purge (keyed on the sub alone) BEFORE that early return, so no parked Rescan is
/// left behind as FALSE debt — a Rescan deliverable for a subscription the caller never received, or
/// endlessly retried on a full channel at source-drain — while a live sibling's parked Rescan stays
/// untouched.
///
/// Fail-on-old: with the early `Unknown` return placed BEFORE the local cleanup, the orphan's parked
/// Rescan lingers in `needs_rescan` and the first assertion fails.
#[tokio::test]
async fn drop_orphan_after_terminal_retire_clears_the_orphans_parked_rescan_no_false_debt() {
  let mut h = Harness::bounded(1);

  // A LIVE sibling on one disjoint root and the ORPHAN on another. Monotonic mint: /a = handle 1
  // (sibling), /b = handle 2 (orphan).
  let sibling = h.watch("/a", Interest::all()).await.expect("watch /a");
  let orphan = h.watch("/b", Interest::all()).await.expect("watch /b");

  // Give the LIVE sibling a parked overflow Rescan: fill the one channel slot, then overflow it — so
  // the test can assert the orphan purge leaves a DIFFERENT sub's owed Rescan untouched.
  for raw in 0..2 {
    h.owner.epochs.stamp(sibling, Epoch::new(raw));
  }
  h.owner.try_emit(modified_event(sibling, "/a/f0", 0));
  h.owner.try_emit(modified_event(sibling, "/a/f1", 1));
  assert!(
    h.owner.needs_rescan.contains_key(&sibling),
    "the sibling's overflow parked a dominating Rescan"
  );

  // Terminal-retire the ORPHAN's root (handle 2): parks the orphan's terminal Rescan into
  // needs_rescan AND force-removes the sub from the subsumer — the committed-but-unclaimed-then-
  // terminal-retired state R20-F2 is about (plan_unwatch can no longer find it).
  h.owner.retire_root_with_terminal_rescan(2);
  assert!(
    h.owner.needs_rescan.contains_key(&orphan),
    "terminal retirement parked the orphan's owed terminal Rescan"
  );
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/b")),
    "the orphan's root is retired from the subsumer"
  );

  // The orphan's WatchGrant now fires: DropOrphan → release_subscription. The subsumer no longer
  // records the orphan, so plan_unwatch reports Unknown — but the owner-local cleanup MUST still have
  // run (and no last-subscriber disarm is issued, since the root is already terminal-retired).
  let outcome = h.owner.release_subscription(orphan);
  assert!(
    outcome.is_err_and(|err| err.is_unknown_subscription()),
    "a terminal-retired sub is Unknown to the subsumer"
  );

  // R20-F2: the orphan's parked Rescan is GONE (no false debt) …
  assert!(
    !h.owner.needs_rescan.contains_key(&orphan),
    "the orphan's parked Rescan was cleared despite the subsumer reporting Unknown (no false debt)"
  );
  // … while the LIVE sibling's parked Rescan (a DIFFERENT sub) is left untouched.
  assert!(
    h.owner.needs_rescan.contains_key(&sibling),
    "the live sibling's owed parked Rescan survived the orphan purge untouched"
  );
}

/// The umbrella NEVER surfaces `Overlaps` (design source doc; `error::WatchError`): a re-`watch` of a
/// just-orphaned key succeeds even though the orphan's release was requested a moment earlier. A
/// [`Cleanup::DropOrphan`](super::Cleanup::DropOrphan)'s
/// [`release_subscription`](super::Owner::release_subscription) removes the emptied root from the
/// subsumer AND issues the synchronous `source.disarm`, so the re-`watch` is classified `Disjoint`
/// (the subsumer no longer records it) and the source has already applied the release before the
/// fresh arm (disarm contract clause 2) — no flush machinery, no
/// [`Overlaps`](tributary_fs::WatchRootError::Overlaps). The re-`watch` arms a FRESH
/// generation-unique handle; the released OLD handle is logically dead and cannot touch it.
///
/// Non-vacuous: the recorded op sequence is exactly `Arm(/a)`, `Disarm(1)`, `Arm(/a)` — the release
/// is recorded BEFORE the re-watch's arm (release-before-subsequent-arm ordering) with only ONE arm
/// for the re-watch (no `Overlaps` retry) — and the OLD handle's `root_key` is `None` while the
/// re-watch is live and covered on a fresh root.
#[tokio::test]
async fn rewatch_of_a_just_orphaned_key_succeeds_no_overlaps() {
  let mut h = Harness::new();

  // Watch /a → its root's only subscriber (handle 1), armed at the source.
  let orphan = h.watch("/a", Interest::all()).await.expect("watch /a");

  // The NORMAL-loop DropOrphan handling: release the orphan's owner-local state (removing /a from the
  // subsumer) AND request its emptied root's synchronous disarm — the FakeSource applies the release
  // immediately, so handle 1 is logically dead at once.
  h.owner
    .release_subscription(orphan)
    .expect("the orphan (its root's last subscriber) is released");
  assert_eq!(
    h.owner.source.root_key(1),
    None,
    "the orphaned root is logically dead immediately (its disarm was a synchronous request)"
  );

  // Re-watch /a: `Disjoint` (the subsumer no longer records it) → arm a FRESH root. The prior release
  // was already applied, so the source never reports `Overlaps` and no retry is needed.
  let rewatched = h
    .watch("/a", Interest::all())
    .await
    .expect("the re-watch never surfaces Overlaps (the prior release was already applied)");
  assert_ne!(
    orphan, rewatched,
    "the re-watch minted a fresh subscription"
  );

  // The op sequence proves the ordering: the orphan's `Disarm(1)` is recorded BEFORE the re-watch's
  // single `Arm(/a)` — release-before-subsequent-arm, and no `Overlaps` retry (exactly two arms).
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a")),
      Call::Disarm(1),
      Call::Arm(PathBuf::from("/a")),
    ],
    "release recorded before the re-watch's (single) arm — no Overlaps"
  );
  assert_eq!(
    h.owner.source.root_key(1),
    None,
    "the OLD handle stays released — it cannot touch the new root"
  );
  assert!(
    h.owner.subsumer.view().is_watched(&key("/a")),
    "the re-watch is live and covered on a fresh root"
  );
}

/// Golden widen ordering (design source doc, disarm contract clause 2): a widen releases its subsumed
/// narrow roots via the **synchronous** [`Source::disarm`] request and then arms the wider root, so
/// the recorded op sequence shows every `Disarm(narrow…)` BEFORE the `Arm(wider)`, and by the time the
/// wider root is armed those releases are already applied — a conforming source can never report
/// `Overlaps`. Beyond the plain ordering check, this asserts the released narrow handles are logically
/// dead (`root_key` → None) once the wider root is live.
#[tokio::test]
async fn widen_records_releases_before_wider_arm_and_applies_them() {
  let mut h = Harness::new();

  // Two disjoint narrow roots: /a/b (handle 1) and /a/c (handle 2).
  h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  h.watch("/a/c", Interest::all()).await.expect("watch /a/c");

  // Widen to /a: releases the two narrow roots, then arms the wider /a (handle 3).
  h.watch("/a", Interest::all())
    .await
    .expect("watch /a widens over the narrow roots");

  // The op sequence: both narrow arms, then BOTH releases, then the single wider arm — every `Disarm`
  // recorded before `Arm(/a)` (release-before-subsequent-arm ordering, and no `Overlaps` retry).
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Arm(PathBuf::from("/a")),
    ],
    "the narrow roots are released before the wider root is armed"
  );
  // The releases are APPLIED: the narrow handles are logically dead, and the wider root (handle 3) is
  // live and covers both old narrow keys.
  assert_eq!(h.owner.source.root_key(1), None, "narrow /a/b released");
  assert_eq!(h.owner.source.root_key(2), None, "narrow /a/c released");
  assert_eq!(
    h.owner.source.root_key(3),
    Some(key("/a")),
    "the wider root is armed and live"
  );
  assert!(
    h.owner.subsumer.view().is_watched(&key("/a/b")),
    "the widened root covers the old narrow keys"
  );
}

/// Immediate logical death (design source doc, disarm contract clause 3): after the owner releases a
/// subscription (an unwatch/orphan cleanup), the source's `root_key` answers `None` for the freed
/// handle AT ONCE — even for an FsSource-shaped source whose transport teardown is still pending.
/// Modelled by a double whose `disarm` queues the transport release (applied only at the next `arm`,
/// like the real `Watcher`'s bounded command channel) yet marks the handle logically dead immediately.
#[tokio::test]
async fn release_marks_handle_logically_dead_immediately_even_with_transport_pending() {
  /// An FsSource-shaped double: `disarm` queues the transport teardown (drained at the next `arm`)
  /// but marks the handle logically dead at once via `pending_set`.
  struct PendingReleaseSource {
    next_handle: u32,
    /// Handles whose transport watch is still installed (the "kernel" side); a `disarm` does NOT
    /// remove from here — only the next `arm`'s drain does.
    transport_live: std::collections::HashSet<u32>,
    /// The requested-but-not-yet-applied releases, plus their mirror for O(1) `root_key`.
    pending: VecDeque<u32>,
    pending_set: std::collections::HashSet<u32>,
    keys: HashMap<u32, Vec<OsString>>,
  }

  impl Source<OsString> for PendingReleaseSource {
    type Handle = u32;

    fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
      Ok(key.to_vec())
    }

    async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
      // Apply every deferred transport teardown FIRST (mirroring `FsSource::arm`).
      while let Some(released) = self.pending.pop_front() {
        self.transport_live.remove(&released);
        self.pending_set.remove(&released);
        self.keys.remove(&released);
      }
      self.next_handle += 1;
      let handle = self.next_handle;
      self.transport_live.insert(handle);
      self.keys.insert(handle, key.to_vec());
      Ok(Armed::new(handle, key.to_vec()))
    }

    fn disarm(&mut self, handle: u32) {
      // Synchronous request: queue the transport teardown (deferred to the next arm) and mark the
      // handle logically dead immediately.
      if self.pending_set.insert(handle) {
        self.pending.push_back(handle);
      }
    }

    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      None
    }

    fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
      // Logically dead immediately, even though `transport_live` still holds it.
      if self.pending_set.contains(&handle) {
        return None;
      }
      self.keys.get(&handle).cloned()
    }
  }

  let (event_tx, _event_rx) = async_channel::unbounded::<Event<OsString, ()>>();
  let (command_tx, command_rx) = async_channel::unbounded::<super::Command<OsString, ()>>();
  let (_close_tx, close_rx) = async_channel::bounded::<super::CloseReply>(1);
  let (cleanup_tx, cleanup_rx) = async_channel::unbounded::<super::Cleanup>();
  let mut owner = Owner {
    source: PendingReleaseSource {
      next_handle: 0,
      transport_live: std::collections::HashSet::new(),
      pending: VecDeque::new(),
      pending_set: std::collections::HashSet::new(),
      keys: HashMap::new(),
    },
    subsumer: Subsumer::new(),
    epochs: EpochLedger::new(),
    filters: HashMap::new(),
    needs_rescan: BTreeMap::new(),
    unclaimed: std::collections::HashSet::new(),
    coalescer: None,
    cleanup_tx,
    cleanup_rx,
    commands: command_rx,
    closes: close_rx,
    events: event_tx,
    #[cfg(debug_assertions)]
    observed_handles: std::collections::HashSet::new(),
    _rt: PhantomData::<TokioRuntime>,
  };
  let _commands = command_tx; // keep the command channel open (the dropped-handles teardown signal)

  // Watch /a → handle 1, its transport watch installed and live.
  let sub = owner
    .reconcile_watch(&key("/a"), (), Interest::all(), Filter::all())
    .await
    .expect("watch /a");
  assert_eq!(
    owner.source.root_key(1),
    Some(key("/a")),
    "the armed root is live before release"
  );

  // Release it (the caller unwatch path): the last-subscriber disarm is a synchronous REQUEST — its
  // transport teardown is still queued (applied only at the next arm) …
  owner
    .release_subscription(sub)
    .expect("the subscription is released");

  // … yet the handle is logically dead IMMEDIATELY (contract clause 3) …
  assert_eq!(
    owner.source.root_key(1),
    None,
    "root_key answers None the instant the release is requested"
  );
  // … while its transport watch is genuinely still installed (release pending, applied at next arm).
  assert!(
    owner.source.transport_live.contains(&1),
    "the transport teardown is still pending — an FsSource-shaped deferred release"
  );
}

/// Codex R24-F1 regression, NORMAL loop (design driver-golden doc, invariant I1 / no false debt):
/// the run loop's top-of-iteration parked-Rescan flush is now **unconditional**, and which parked
/// debt it OFFERS is decided by owner STATE — [`flush_pending_rescans`](super::Owner::flush_pending_rescans)
/// suppresses any entry whose sub is still `unclaimed` (its [`WatchGrant`](super::WatchGrant) in
/// flight). So an orphaned (committed-but-unclaimed, then dropped) subscription's parked terminal
/// [`Rescan`](tributary_fs::EventKind::Rescan) is NEVER delivered, no matter how its
/// [`Cleanup::DropOrphan`](super::Cleanup::DropOrphan) interleaves with the flush — closing the TOCTOU the
/// mailbox-idle gate left open (a `DropOrphan` could enqueue after the emptiness probe but before the
/// flush's `try_send`).
///
/// Exercises the REAL spawned [`run`](super::run) loop over a source that arms the watched root live,
/// then on a trigger delivers a terminal event for that root AFTER killing it — and, in the same
/// synchronous terminal-retire step (its `root_key` probe), drops the held reply receiver so the
/// grant's `Drop` enqueues the `DropOrphan`. The committed grant was recorded `unclaimed` by
/// `on_watch`, so its parked terminal Rescan is suppressed by state and the `DropOrphan` then purges
/// it. The event channel has CAPACITY (unbounded), so a non-suppressing flush *would* deliver.
///
/// Fail-on-old: temporarily revert the `unclaimed` suppression in `flush_pending_rescans` (offer every
/// entry) and the parked Rescan is delivered — the drained stream is non-empty and the assertion flips.
#[tokio::test]
async fn unclaimed_orphans_parked_rescan_is_suppressed_by_state_in_the_run_loop() {
  /// The Watch's reply receiver: the owner sends the committed [`WatchGrant`](super::WatchGrant) into
  /// it; the source holds it and drops it during the terminal-retire, so the grant's `Drop` enqueues
  /// the `DropOrphan`.
  type ReplyRx = futures_channel::oneshot::Receiver<Result<super::WatchGrant, WatchError>>;

  /// A source that arms `/a` live, then — on the trigger carrying the Watch's reply receiver —
  /// delivers a terminal `Rescan` for it after killing the root. When `retire_if_dead` probes
  /// `root_key` for the now-dead handle, it drops the held reply receiver, so the grant's `Drop`
  /// enqueues the `DropOrphan` synchronously between the retire's park and the next loop-top flush
  /// (the exact R23-F1 interleaving). After the one terminal event `next` parks, so the loop stays
  /// alive to answer `Close`.
  struct TerminalRetireSource {
    next_handle: u32,
    live: HashMap<u32, Vec<OsString>>,
    trigger: async_channel::Receiver<ReplyRx>,
    held_reply: std::sync::Mutex<Option<ReplyRx>>,
    delivered_terminal: bool,
  }

  impl Source<OsString> for TerminalRetireSource {
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

    fn disarm(&mut self, handle: u32) {
      self.live.remove(&handle);
    }

    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      if self.delivered_terminal {
        // The one terminal event is delivered; park so the loop survives to answer `Close`.
        std::future::pending::<Option<SourceEvent<OsString, u32>>>().await
      } else {
        let reply_rx = match self.trigger.recv().await {
          Ok(rx) => rx,
          Err(_) => return None,
        };
        *self.held_reply.lock().unwrap() = Some(reply_rx);
        // Kill the watched root so the terminal-retire's `root_key` probe reports it dead …
        self.live.clear();
        self.delivered_terminal = true;
        // … and deliver its terminal Rescan, which drives the retire-and-park.
        Some(rescan_event(1, "/a", 0))
      }
    }

    fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
      match self.live.get(&handle) {
        Some(k) => Some(k.clone()),
        None => {
          // The dead-root terminal-retire probe: drop the held reply receiver NOW so the grant's
          // `Drop` enqueues the `DropOrphan`. With state suppression the exact interleaving no longer
          // matters (the sub is `unclaimed`, so its parked Rescan is suppressed regardless) — but this
          // still drives the committed-but-unclaimed → terminal-retire → drop path end to end.
          // Idempotent: a later dead probe finds `None`.
          drop(self.held_reply.lock().unwrap().take());
          None
        }
      }
    }
  }

  let (event_tx, event_rx) = async_channel::unbounded::<Event<OsString, ()>>();
  let (command_tx, command_rx) = async_channel::unbounded::<super::Command<OsString, ()>>();
  let (close_tx, close_rx) = async_channel::bounded::<super::CloseReply>(1);
  let (cleanup_tx, cleanup_rx) = async_channel::unbounded::<super::Cleanup>();
  let (trigger_tx, trigger_rx) = async_channel::unbounded::<ReplyRx>();
  let owner = Owner {
    source: TerminalRetireSource {
      next_handle: 0,
      live: HashMap::new(),
      trigger: trigger_rx,
      held_reply: std::sync::Mutex::new(None),
      delivered_terminal: false,
    },
    subsumer: Subsumer::new(),
    epochs: EpochLedger::new(),
    filters: HashMap::new(),
    needs_rescan: BTreeMap::new(),
    unclaimed: std::collections::HashSet::new(),
    coalescer: None,
    cleanup_tx,
    cleanup_rx,
    commands: command_rx,
    closes: close_rx,
    events: event_tx,
    #[cfg(debug_assertions)]
    observed_handles: std::collections::HashSet::new(),
    _rt: PhantomData::<TokioRuntime>,
  };
  let run = tokio::spawn(super::run(owner));

  // A hand-built Watch whose reply receiver is HELD UNPOLLED — the grant lands in the reply slot
  // (committed-but-unclaimed). The receiver is handed to the source (via the trigger) so it can drop
  // it during the terminal-retire.
  let (reply, reply_rx) = futures_channel::oneshot::channel();
  command_tx
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      interest: Interest::all(),
      filter: Filter::all(),
      reply,
    })
    .expect("enqueue the Watch");
  // Hand the reply receiver to the source and trigger the terminal event: the loop commits the watch
  // (recording the grant `unclaimed`), then delivers the terminal event — retire-and-park AND, in the
  // same synchronous step, enqueue the DropOrphan. The parked Rescan is suppressed by state until the
  // DropOrphan purges it.
  trigger_tx
    .try_send(reply_rx)
    .expect("hand the reply receiver to the source");

  // Give the loop a beat to run those iterations to quiescence.
  tokio::time::sleep(Duration::from_millis(250)).await;

  // `close()` still completes (the loop is Close-responsive by construction) — the reply rides the
  // dedicated close signal, not the command mailbox.
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  close_tx
    .try_send(close_reply)
    .expect("send the close on the dedicated signal");
  let acked = tokio::time::timeout(Duration::from_secs(5), close_response)
    .await
    .expect("close() completes within the deadline")
    .expect("the close reply channel stays open");
  assert!(matches!(acked, Ok(())), "close() succeeds");

  // The event stream carries NO event for the orphaned subscription: its parked terminal Rescan was
  // suppressed by the `unclaimed` state and then purged by the DropOrphan. Fail-on-old: revert the
  // suppression and the flush delivers it, so the drain is non-empty.
  let mut delivered = Vec::new();
  while let Ok(event) = event_rx.try_recv() {
    delivered.push(event);
  }
  assert!(
    delivered.is_empty(),
    "the orphan's parked terminal Rescan was suppressed by state — no event for a subscription the \
     caller never obtained (got {} event(s))",
    delivered.len()
  );

  tokio::time::timeout(Duration::from_secs(5), run)
    .await
    .expect("the run task joins after Close")
    .expect("the run task did not panic");
}

/// Codex R31 regression — a grant left UNPOLLED in the watch reply slot across a source-drain
/// teardown is POISONED: it fired neither `Claim` nor `DropOrphan`, so the teardown's cleanup-channel
/// linearization could not see it, its suppressed parked debt died with the owner, and the stream has
/// already ended. A post-teardown [`defuse`](super::WatchGrant::defuse) must therefore return `Err`
/// (the public `watch` surfaces `Closed`) — never an `Ok` subscription for a stream that ended
/// without its owed Rescan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unpolled_grant_across_source_drain_teardown_is_poisoned() {
  let (drain_tx, drain_rx) = async_channel::bounded::<std::convert::Infallible>(1);
  let source = DrainableSource {
    next_handle: 0,
    live: HashMap::new(),
    drain: drain_rx,
  };
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());

  // A hand-built Watch whose reply receiver is HELD UNPOLLED: the owner commits the sub and sends
  // the grant into the slot, where it sits (unclaimed, no Cleanup fired).
  let (reply, response) = futures_channel::oneshot::channel();
  w.commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      interest: Interest::all(),
      filter: Filter::all(),
      reply,
    })
    .expect("enqueue the Watch");
  tokio::time::sleep(Duration::from_millis(100)).await; // let the owner commit + send the grant

  // The source drains (next → None): the owner runs its source-drain teardown — the unpolled
  // grant's sub is unclaimed, no Cleanup is queued, so the drain exits and the owner drops.
  drop(drain_tx);
  tokio::time::sleep(Duration::from_millis(200)).await; // let the teardown complete

  // NOW the caller polls the reply: the grant arrives, but its claim's try_send finds the cleanup
  // receiver gone — the grant is poisoned, exactly what the public watch maps to `Closed`.
  let grant = tokio::time::timeout(Duration::from_secs(5), response)
    .await
    .expect("the reply was sent before teardown")
    .expect("the grant sits in the slot")
    .expect("the watch committed successfully");
  assert!(
    grant.defuse().is_err(),
    "a grant polled after the owner tore down is POISONED — watch() surfaces Closed, never a dead Ok"
  );
}

/// Codex R32 regression — the source-drain exit is ATOMIC with respect to grant claims: the drain
/// CLOSES the cleanup channel before accepting its all-unclaimed exit, so a grant defused in the
/// window after the final emptiness observation but BEFORE the owner drops (the receiver was still
/// alive — the R32 race) fails its claim try_send and is POISONED. Fail-on-old: without the in-exit
/// cut, the post-drain defuse lands on the still-open channel and returns a live-looking Ok that no
/// later drain will ever service.
#[tokio::test]
async fn claim_after_the_source_drain_cut_is_poisoned_even_before_owner_drop() {
  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  h.owner.unclaimed.insert(sub);
  // The unpolled grant sits in a caller's reply slot, wired to the SAME cleanup channel.
  let grant = super::WatchGrant::new(sub, h.owner.cleanup_tx.clone());
  // Its root terminal-retires: the owed terminal Rescan parks, suppressed (unclaimed).
  h.owner.retire_root_with_terminal_rescan(1);

  // Source drain runs to its all-unclaimed exit — which now CUTS (closes the cleanup channel),
  // drains pre-cut claims, and runs a final owed pass before returning.
  let returned = tokio::time::timeout(Duration::from_secs(5), h.owner.drain_owed_before_shutdown())
    .await
    .expect("the drain exits promptly");
  assert!(returned.is_none(), "no close interrupted the drain");

  // The OWNER STILL EXISTS (pre-drop window) — yet the claim must already be poisoned.
  assert!(
    grant.defuse().is_err(),
    "a claim after the source-drain cut is poisoned even while the owner is still alive (Codex R32)"
  );
  assert!(
    h.drain().iter().all(|e| e.subscription() != sub),
    "the suppressed debt was never delivered for the never-claimed subscription"
  );
}

/// Codex R24 — SOURCE-DRAIN teardown under the STATE model (owed = CLAIMED): an UNCLAIMED
/// terminal-retired sub's parked terminal Rescan is suppressed by the owner's `unclaimed` state —
/// never delivered even with event-channel CAPACITY — while a claimed live sub's owed Rescan still
/// delivers, and [`drain_owed_before_shutdown`](super::Owner::drain_owed_before_shutdown) then
/// EXITS instead of spinning on the unclaimed leftover: with NO grant-resolution
/// [`Cleanup`](super::Cleanup) ever arriving, STATE alone withholds the debt AND lets the drain exit —
/// the debt is owed to nobody (the R24 close of the R23 TOCTOU).
#[tokio::test]
async fn source_drain_suppresses_unclaimed_orphan_debt_and_exits_without_spinning() {
  let mut h = Harness::new(); // unbounded event channel — has capacity
  let live = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let orphan = h.watch("/b", Interest::all()).await.expect("watch /b"); // handle 2
  // Model the orphan's grant as still in flight (committed, successfully sent, unclaimed).
  h.owner.unclaimed.insert(orphan);

  // The LIVE (claimed) sub owes a parked dominating Rescan (its overflow debt) …
  for raw in 0..2 {
    h.owner.epochs.stamp(live, Epoch::new(raw));
  }
  h.owner.park_rescan(live);
  // … and the ORPHAN is terminal-retired (parked terminal Rescan + force-removed from the subsumer)
  // while its grant is still unclaimed.
  h.owner.retire_root_with_terminal_rescan(2);
  assert!(
    h.owner.needs_rescan.contains_key(&live) && h.owner.needs_rescan.contains_key(&orphan),
    "both the live sub's overflow Rescan and the orphan's terminal Rescan are parked"
  );

  // NO Cleanup is enqueued: the orphan stays unclaimed with its parked terminal Rescan for the whole
  // drain, so the exit MUST come from STATE (owed-to-nobody), not from the debt being purged away.

  // The drain delivers the claimed sub's owed Rescan, suppresses the unclaimed one, and exits
  // promptly (everything still owed belongs to unclaimed subs — owed to nobody): no spin on an
  // abandoned grant.
  let returned = tokio::time::timeout(Duration::from_secs(5), h.owner.drain_owed_before_shutdown())
    .await
    .expect("the drain exits promptly instead of spinning on unclaimed-only debt");
  assert!(returned.is_none(), "no Close interrupted the drain");

  let delivered = h.drain();
  assert!(
    !delivered.iter().any(|e| e.subscription() == orphan),
    "the unclaimed orphan's parked terminal Rescan is suppressed by state — never delivered"
  );
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == live && e.is_rescan()),
    "the claimed live sub's owed Rescan IS delivered (no-silent-loss for claimed subs)"
  );
  assert!(
    h.owner
      .needs_rescan
      .keys()
      .all(|s| h.owner.unclaimed.contains(s)),
    "only unclaimed (owed-to-nobody) debt remains at exit"
  );
}

/// Codex R24 — the POST-Close best-effort tail under the STATE model: the tail is a plain
/// [`drain_owed_once`](super::Owner::drain_owed_once) (the R23 pre-drain helper is gone — state
/// suppression made it unnecessary). A residual [`Cleanup::DropOrphan`](super::Cleanup::DropOrphan)
/// left UNDRAINED on the cleanup channel (this test runs only `drain_owed_once`, not the cleanup
/// drain) may go entirely unprocessed, yet the unclaimed orphan's parked terminal Rescan is
/// still withheld — suppressed by the owner's `unclaimed` state, not by command timing — while the
/// claimed live sub's owed Rescan is delivered by the same pass. The event channel has CAPACITY, so
/// the flush *would* deliver the orphan's Rescan were it not state-gated.
#[tokio::test]
async fn final_drain_suppresses_unclaimed_orphan_debt_after_close() {
  let mut h = Harness::new(); // unbounded event channel — has capacity
  let live = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let orphan = h.watch("/b", Interest::all()).await.expect("watch /b"); // handle 2
  // Model the orphan's grant as still in flight (committed, successfully sent, unclaimed).
  h.owner.unclaimed.insert(orphan);

  for raw in 0..2 {
    h.owner.epochs.stamp(live, Epoch::new(raw));
  }
  h.owner.park_rescan(live);
  h.owner.retire_root_with_terminal_rescan(2);
  assert!(
    h.owner.needs_rescan.contains_key(&live) && h.owner.needs_rescan.contains_key(&orphan),
    "both the live sub's overflow Rescan and the orphan's terminal Rescan are parked"
  );

  // Model the post-Close tail: a residual Cleanup::DropOrphan sits UNDRAINED on the cleanup channel
  // (this test deliberately runs ONLY drain_owed_once, which never touches the cleanup channel), so it
  // goes unprocessed — the suppression must hold from STATE regardless.
  h.owner
    .cleanup_tx
    .try_send(super::Cleanup::DropOrphan(orphan))
    .expect("enqueue the residual DropOrphan cleanup notice");
  h.owner.drain_owed_once();

  let delivered = h.drain();
  assert!(
    !delivered.iter().any(|e| e.subscription() == orphan),
    "the unclaimed orphan's parked Rescan is suppressed by state in the final pass (Codex R24)"
  );
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == live && e.is_rescan()),
    "the claimed live sub's owed Rescan IS delivered by the best-effort pass"
  );
}

/// Codex R24 — claim-then-deliver: suppression must never become LOSS for a subscription the caller
/// actually obtained. An unclaimed sub's parked terminal Rescan is withheld (retained, not offered);
/// once its [`Cleanup::Claim`](super::Cleanup::Claim) is applied — the caller defused the grant
/// and now holds the sub — the very next flush delivers the parked Rescan: the debt was deferred,
/// never dropped.
#[tokio::test]
async fn claimed_grant_lifts_suppression_and_its_parked_rescan_is_delivered() {
  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  h.owner.unclaimed.insert(sub);

  // Terminal-retire the unclaimed sub's root: its owed terminal Rescan parks, suppressed.
  h.owner.retire_root_with_terminal_rescan(1);
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the terminal Rescan is parked"
  );
  h.owner.flush_pending_rescans();
  assert!(
    h.drain().is_empty(),
    "unclaimed: the parked Rescan is suppressed, not offered"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "…and retained (deferred), not dropped"
  );

  // The caller claims: apply the Cleanup::Claim exactly as the run loop's cleanup drain does.
  h.owner.apply_cleanup(super::Cleanup::Claim(sub));
  h.owner.flush_pending_rescans();
  let delivered = h.drain();
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == sub && e.is_rescan()),
    "claimed: the parked terminal Rescan is delivered — suppression never became loss"
  );
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the owed debt is resolved once claimed"
  );
}

/// Codex R24-F2 regression — sustained control-plane load must not starve a CLAIMED sub's parked
/// Rescan: the flush is UNCONDITIONAL again (the R23 mailbox-idle gate is reverted), so a live
/// parked Rescan is delivered within a bounded window even while a flood keeps the command mailbox
/// continuously non-empty. Fail-on-old: with the R23 `commands.is_empty()` gate, the flood keeps the
/// gate shut and the parked re-point Rescan is withheld past the deadline.
///
/// Setup: a bounded(1) event channel; widening two claimed narrow watches to `/a` mints TWO
/// re-point Rescans — the first fills the only slot, the second overflows and PARKS. A spawned
/// flood then try_sends bursts of `Watch` commands (reply receivers dropped, so each send-fails and
/// is released synchronously) keeping the mailbox busy, while the consumer drains: BOTH re-point
/// Rescans must arrive within the deadline (the parked one flushed between commands).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parked_rescan_delivers_under_sustained_command_load() {
  let (_drain_tx, drain_rx) = async_channel::bounded::<std::convert::Infallible>(1);
  let source = DrainableSource {
    next_handle: 0,
    live: HashMap::new(),
    drain: drain_rx,
  };
  let mut w: super::Tributaries<OsString, (), TokioRuntime, u32> = super::Tributaries::with_source(
    source,
    TributariesOptions::new().with_event_capacity(std::num::NonZeroUsize::new(1).expect("nonzero")),
  );

  // Two claimed narrow watches, then the widen: two re-point Rescans — one fills bounded(1), the
  // other parks as overflow debt for a CLAIMED subscription.
  let narrow_b = w
    .watch(key("/a/b"), (), Interest::all(), Filter::all())
    .await
    .expect("watch /a/b");
  let narrow_c = w
    .watch(key("/a/c"), (), Interest::all(), Filter::all())
    .await
    .expect("watch /a/c");
  let _wide = w
    .watch(key("/a"), (), Interest::all(), Filter::all())
    .await
    .expect("widen to /a");

  // The flood: bursts of Watch commands whose reply receivers are dropped (each send-fails at the
  // owner and is released synchronously) — pure control-plane load keeping the mailbox non-empty.
  let flood_commands = w.commands.clone();
  let flood = tokio::spawn(async move {
    loop {
      for _ in 0..8 {
        let (reply, response) = futures_channel::oneshot::channel();
        drop(response);
        if flood_commands
          .try_send(super::Command::Watch {
            key: key("/flood"),
            value: (),
            interest: Interest::all(),
            filter: Filter::all(),
            reply,
          })
          .is_err()
        {
          return;
        }
      }
      tokio::task::yield_now().await;
    }
  });

  // Under sustained load, BOTH re-point Rescans arrive within the deadline: the queued one first,
  // then the PARKED one — flushed by the unconditional per-tick flush despite the busy mailbox.
  let mut seen = std::collections::HashSet::new();
  for _ in 0..2 {
    let event = tokio::time::timeout(Duration::from_secs(5), w.next())
      .await
      .expect("a re-point Rescan is delivered within the deadline despite sustained command load")
      .expect("the stream is open");
    assert!(event.is_rescan(), "the widen minted re-point Rescans");
    seen.insert(event.subscription());
  }
  assert!(
    seen.contains(&narrow_b) && seen.contains(&narrow_c),
    "both re-pointed subscriptions received their Rescan — the parked one was never starved"
  );
  flood.abort();
}

/// Spawns a control-plane flood: bursts of `Watch` commands whose reply receivers are dropped (each
/// send-fails at the owner and is released synchronously) — keeping the command mailbox continuously
/// non-empty, so the command-biased select's other arms can win only through the fairness valve.
fn spawn_command_flood(
  commands: async_channel::Sender<super::Command<OsString, ()>>,
) -> tokio::task::JoinHandle<()> {
  tokio::spawn(async move {
    loop {
      for _ in 0..8 {
        let (reply, response) = futures_channel::oneshot::channel();
        drop(response);
        if commands
          .try_send(super::Command::Watch {
            key: key("/flood"),
            value: (),
            interest: Interest::all(),
            filter: Filter::all(),
            reply,
          })
          .is_err()
        {
          return;
        }
      }
      tokio::task::yield_now().await;
    }
  })
}

/// A source whose `next` yields one pre-queued event per trigger message, then parks — the
/// command-flood fairness rig (Codex R25-F2): with the command arm continuously ready, only the run
/// loop's fairness valve can pump these events. `next` is cancellation-safe: the trigger message
/// and the event are consumed on the same poll that returns `Ready`.
struct TriggeredSource {
  next_handle: u32,
  live: HashMap<u32, Vec<OsString>>,
  events: std::collections::VecDeque<SourceEvent<OsString, u32>>,
  trigger: async_channel::Receiver<()>,
}

impl Source<OsString> for TriggeredSource {
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

  fn disarm(&mut self, handle: u32) {
    self.live.remove(&handle);
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    match self.trigger.recv().await {
      Ok(()) => self.events.pop_front(),
      Err(_) => None,
    }
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.live.get(&handle).cloned()
  }
}

/// Codex R25-F1 regression — a `Cleanup::Claim` already QUEUED when the source drains must be drained
/// before the drain's all-unclaimed exit: the caller defused the grant (it holds the sub), so the
/// parked terminal Rescan is genuinely owed and must be delivered before the stream ends. The exit
/// predicate reads post-claim state (the cleanup channel is drained and must be observed empty), or
/// suppression becomes permanent loss. Fail-on-old: the pre-R25 exit takes the all-unclaimed arm
/// before the queued claim is drained — nothing is delivered and the assertion flips.
#[tokio::test]
async fn queued_claim_grant_is_serviced_before_the_source_drain_exit() {
  let mut h = Harness::new(); // unbounded event channel — has capacity
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  h.owner.unclaimed.insert(sub);
  // Terminal-retire the unclaimed sub's root: its owed terminal Rescan parks, suppressed.
  h.owner.retire_root_with_terminal_rescan(1);
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the terminal Rescan is parked"
  );
  // The caller defuses as the source drains: its Cleanup::Claim is already queued when the drain runs.
  h.owner
    .cleanup_tx
    .try_send(super::Cleanup::Claim(sub))
    .expect("enqueue the Claim on the cleanup channel");

  let returned = tokio::time::timeout(Duration::from_secs(5), h.owner.drain_owed_before_shutdown())
    .await
    .expect("the drain exits promptly after delivering the claimed debt");
  assert!(returned.is_none(), "no Close interrupted the drain");

  let delivered = h.drain();
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == sub && e.is_rescan()),
    "the claimed sub's parked Rescan is delivered before the source-drain exit (Codex R25-F1)"
  );
  assert!(
    h.owner.needs_rescan.is_empty(),
    "the owed debt is resolved, not stranded"
  );
}

/// Codex R25-F2 regression — a RAW source event is delivered within a bounded window under a
/// sustained command flood: the command-biased select would starve `next()` forever, so the
/// fairness valve (after `COMMAND_FAIRNESS_BUDGET` consecutive command wins, one non-blocking
/// source poll + a due-coalescer drain) is what pumps it. Fail-on-old: without the valve the
/// command arm wins every iteration and the event never surfaces — the recv times out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_source_event_delivers_under_sustained_command_load() {
  let (trigger_tx, trigger_rx) = async_channel::unbounded::<()>();
  let source = TriggeredSource {
    next_handle: 0,
    live: HashMap::new(),
    events: std::collections::VecDeque::from([SourceEvent::new(
      1,
      key("/a/f"),
      EventKind::Created,
      None,
      Location::new(),
      Epoch::new(0),
      ChangeId::new(NonZeroU64::MIN),
    )]),
    trigger: trigger_rx,
  };
  let mut w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());
  let sub = w
    .watch(key("/a"), (), Interest::all(), Filter::all())
    .await
    .expect("watch /a"); // handle 1

  let flood = spawn_command_flood(w.commands.clone());
  trigger_tx.try_send(()).expect("release the queued event");

  let event = tokio::time::timeout(Duration::from_secs(5), w.next())
    .await
    .expect("the raw source event is delivered despite the sustained command flood (the valve)")
    .expect("the stream is open");
  assert_eq!(event.subscription(), sub, "routed to the covering sub");
  flood.abort();
}

/// Codex R26 regression — the source-drain teardown makes OWED progress under a sustained command
/// flood: its per-iteration command servicing is BOUNDED (COMMAND_FAIRNESS_BUDGET), so a
/// continuously non-empty mailbox cannot starve `drain_owed_once` — an already-CLAIMED parked
/// Rescan is delivered within a bounded window even though the flood keeps the drain from exiting
/// (the exit's empty-mailbox linearization defers, delivery does not).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_drain_delivers_claimed_debt_under_sustained_command_flood() {
  let mut h = Harness::new(); // unbounded event channel — has capacity
  let live = h.watch("/a", Interest::all()).await.expect("watch /a"); // claimed (Harness::watch)
  for raw in 0..2 {
    h.owner.epochs.stamp(live, Epoch::new(raw));
  }
  h.owner.park_rescan(live);

  let flood = spawn_command_flood(h._commands.clone());
  // Under the flood the drain never observes an empty mailbox, so it keeps servicing (and never
  // exits within the window) — but the bounded pre-drain guarantees the owed pass runs every
  // iteration, so the claimed Rescan is delivered long before the timeout lapses.
  let _ = tokio::time::timeout(Duration::from_secs(2), h.owner.drain_owed_before_shutdown()).await;
  flood.abort();
  assert!(
    h.drain()
      .iter()
      .any(|e| e.subscription() == live && e.is_rescan()),
    "the claimed sub's parked Rescan is delivered despite the sustained command flood (Codex R26)"
  );
}

/// Codex R25-F2 regression — DUE debounced output drains within a bounded window under a sustained
/// command flood: the settle-timer arm can never win against a continuously-ready command arm, so
/// the valve's due-coalescer drain is what honors the coalescer's hold bounds. Fail-on-old: without
/// the valve neither the timer nor the source arm ever fires and the buffered event never drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn due_debounced_event_drains_under_sustained_command_load() {
  let (trigger_tx, trigger_rx) = async_channel::unbounded::<()>();
  let source = TriggeredSource {
    next_handle: 0,
    live: HashMap::new(),
    events: std::collections::VecDeque::from([SourceEvent::new(
      1,
      key("/a/f"),
      EventKind::Modified,
      None,
      Location::new(),
      Epoch::new(0),
      ChangeId::new(NonZeroU64::MIN),
    )]),
    trigger: trigger_rx,
  };
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_millis(20))
    .with_max_hold(Duration::from_millis(100));
  let mut w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new().debounce(cfg));
  let sub = w
    .watch(key("/a"), (), Interest::all(), Filter::all())
    .await
    .expect("watch /a"); // handle 1

  let flood = spawn_command_flood(w.commands.clone());
  trigger_tx.try_send(()).expect("release the queued event");

  let event = tokio::time::timeout(Duration::from_secs(5), w.next())
    .await
    .expect("the due debounced event drains despite the flood (the valve's due-coalescer drain)")
    .expect("the stream is open");
  assert_eq!(event.subscription(), sub, "routed to the covering sub");
  flood.abort();
}

/// Codex R27 (M2-A) regression — `close()` is never starved behind an unbounded command backlog:
/// the reply rides a **dedicated** high-priority signal, checked at the TOP priority in the real
/// [`run`](super::run) loop (a non-blocking `try_recv` each iteration AND the first `select!` arm),
/// so a requested shutdown completes within a bounded window no matter how deep the command mailbox
/// is. Exercises the REAL spawned run loop over a source that parks (never drains, so the loop stays
/// alive purely to answer the close), with the unbounded mailbox both PREFILLED with 500 fail-fast
/// `Watch` commands AND kept continuously non-empty by a spawned flood.
///
/// Fail-on-old: with `Close` on the FIFO command mailbox behind the 500-deep backlog + the ongoing
/// flood, the owner would have to chew through the whole backlog (arm/orphan/disarm each) before it
/// ever dequeued the `Close`, so `close()` waits it out and probabilistically times out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_is_not_starved_by_a_prefilled_command_backlog_and_flood() {
  let (_drain_tx, drain_rx) = async_channel::bounded::<std::convert::Infallible>(1);
  let source = DrainableSource {
    next_handle: 0,
    live: HashMap::new(),
    drain: drain_rx, // held open (`_drain_tx` kept alive) so `next()` parks forever
  };
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());

  // A live claimed subscription, so the owner is genuinely running with real state (the finding's
  // "owner/source kept alive while shutdown is requested").
  w.watch(key("/a"), (), Interest::all(), Filter::all())
    .await
    .expect("watch /a");

  // Prefill the UNBOUNDED command mailbox with MANY fail-fast Watch commands: each reply receiver is
  // dropped, so the owner's send-back fails and it releases the orphan synchronously (arm→disarm) —
  // real per-command work the old FIFO `Close` would have queued behind.
  for _ in 0..500 {
    let (reply, response) = futures_channel::oneshot::channel();
    drop(response);
    w.commands
      .try_send(super::Command::Watch {
        key: key("/backlog"),
        value: (),
        interest: Interest::all(),
        filter: Filter::all(),
        reply,
      })
      .expect("prefill the command backlog");
  }
  // …and a sustained flood keeping the mailbox continuously non-empty against the real run loop.
  let flood = spawn_command_flood(w.commands.clone());

  // close() rides the dedicated close signal, so it completes within a bounded window DESPITE the
  // 500-deep backlog + ongoing flood on the command mailbox (Codex R27).
  let closed = tokio::time::timeout(Duration::from_secs(5), w.close())
    .await
    .expect("close() completes within the deadline despite the command backlog + flood");
  assert!(matches!(closed, Ok(())), "close() succeeds");
  flood.abort();
}

/// Codex R27 (M2-A) regression, SOURCE-DRAIN teardown under a flood — a close DURING the owed-Rescan
/// drain is surfaced within a bounded window even while a sustained command flood keeps the mailbox
/// continuously non-empty. [`drain_owed_before_shutdown`](super::Owner::drain_owed_before_shutdown)
/// checks the dedicated close signal FIRST (a non-blocking `try_recv` before its bounded command
/// pre-drain AND the first arm of its retry `select!`), so the close outranks the flood the bounded
/// pre-drain services. A claimed sub's parked overflow Rescan behind a full, held-open channel keeps
/// the drain spinning (so the close-check is genuinely exercised mid-drain).
///
/// Fail-on-old (Close on the FIFO mailbox): behind the flood the drain's command servicing would
/// dequeue flood commands ahead of the `Close`, so the close waits out the never-emptying backlog and
/// times out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_drain_close_is_surfaced_under_sustained_command_flood() {
  let mut h = Harness::bounded(1);
  let live = h.watch("/a", Interest::all()).await.expect("watch /a"); // claimed
  for raw in 0..2 {
    h.owner.epochs.stamp(live, Epoch::new(raw));
  }
  // Fill the one slot and overflow → park the CLAIMED sub's dominating Rescan; the held receiver
  // keeps the channel full + open, so the drain keeps spinning (neither exit fires on its own).
  h.owner.try_emit(modified_event(live, "/a/f0", 0));
  h.owner.try_emit(modified_event(live, "/a/f1", 1));
  assert!(
    h.owner.needs_rescan.contains_key(&live),
    "overflow parked the claimed sub's Rescan; the channel is full"
  );
  let _held = h.events.clone(); // a receiver that never drains (keeps the channel full + open)

  // A sustained command flood keeping the mailbox continuously non-empty during the drain.
  let flood = spawn_command_flood(h._commands.clone());

  // A close rides the dedicated signal.
  let (reply, response) = futures_channel::oneshot::channel();
  h.closes
    .try_send(reply)
    .expect("send the close on the dedicated signal");

  // The source-drain teardown surfaces the close within the deadline despite the flood (Codex R27).
  let returned = tokio::time::timeout(Duration::from_secs(5), h.owner.drain_owed_before_shutdown())
    .await
    .expect("the source-drain teardown surfaced the close despite the sustained command flood");
  let close_reply = returned.expect("the mid-drain close is surfaced to the caller to be acked");
  // Ack it exactly as `run` does; the close() caller then completes.
  close_reply.send(Ok(())).expect("ack the close");
  assert!(
    matches!(response.await, Ok(Ok(()))),
    "close() completes once the drain surfaced and acked its close, under the flood"
  );
  flood.abort();
}
