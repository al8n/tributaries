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
use tributary_proto::{ChangeId, Epoch, Location};

use super::{Owner, epoch::EpochLedger};
use crate::{
  coalesce::Coalescer,
  error::{FaultKind, SourceFault, UnwatchError, WatchError},
  event::{Event, EventKind},
  filter::Filter,
  interest::Interest,
  options::{Debounce, DebounceConfig, TributariesOptions, WatchOptions},
  source::{Armed, Source, SourceEvent, SyncToken},
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

/// The directory the fake's SECOND classification ground names — one concrete rendering of
/// the cookie directory `FsSource::is_sync_artifact` matches through
/// `tributary_fs::is_sync_cookie_dir_name`, uid suffix and all.
///
/// No pre-existing key anywhere in this file carries a component of this name (the only
/// dotted leaves in it are `.cookie`, under ordinary parents), so admitting the ground
/// reclassifies nothing the cells sharing [`FakeSource`] already rest on.
const COOKIE_DIR: &str = ".tributaries-sync-cookies-501";

/// One recorded call against the fake source, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
  Arm(PathBuf),
  Disarm(u32),
  /// An in-place root RETARGET (the gapless widen): the preserved handle and the
  /// wider key it now covers. Distinguishable from the release-and-rearm dance
  /// (a `Disarm` followed by an `Arm`) precisely because it is neither.
  Replace(u32, PathBuf),
  /// An in-place coverage PRUNE request: the root handle and the retained cover (the survivor
  /// antichain) the driver forwarded (the set-cover design v3, the shrink-in-place seam).
  SetCover(u32, Vec<Vec<OsString>>),
  /// An AWAITED in-place coverage GROW: the root handle and the fresh cover (including the newcomer)
  /// the driver awaited (the set-cover design v3). Applied-before-return, mirroring the fs source's acked
  /// `Watcher::set_cover`.
  Grow(u32, Vec<Vec<OsString>>),
}

/// One step of a scripted [`FakeSource::begin_sync`] poll: consumed one-per-poll of the
/// scripted future so a cell can force finding 1's inter-arm race deterministically under
/// manual noop-waker polling.
enum ScriptStep {
  /// The poll returns `Pending` — the write is still in flight.
  Pending,
  /// The poll SIDE-EFFECT-DELIVERS the cookie key (models the fs worker's `reply.send(Ok)`
  /// landing) yet STILL returns `Pending`: the delivered-but-unread cookie is now physical,
  /// but this `select` pass will move on to poll a later arm — the exact "the fs sent Ok
  /// between select arm 1 and arm 3 of one pass" interleave.
  PendingThenComplete,
  /// The poll resolves `Ready` with the cookie key — the ordinary completion, so a cell can
  /// pin the write-first bias winning a tie against a simultaneously-ready cancellation.
  Ready,
}

/// The hand-rolled future a scripted [`FakeSource::begin_sync`] awaits: each poll consumes one
/// [`ScriptStep`], so polling the enclosing `on_sync` future advances the write one arm-race pass
/// at a time. Borrows the source's script and its delivery sink (disjoint fields) for the life of
/// the `begin_sync` call.
struct ScriptedBegin<'a> {
  script: &'a mut VecDeque<ScriptStep>,
  delivered: &'a mut Vec<Vec<OsString>>,
  cookie_key: Vec<OsString>,
}

impl std::future::Future for ScriptedBegin<'_> {
  type Output = Vec<OsString>;

  fn poll(
    self: std::pin::Pin<&mut Self>,
    _cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Vec<OsString>> {
    // All fields are `Unpin`, so the pin projects trivially.
    let this = self.get_mut();
    match this.script.pop_front() {
      Some(ScriptStep::Ready) => std::task::Poll::Ready(this.cookie_key.clone()),
      Some(ScriptStep::PendingThenComplete) => {
        // The write's `reply.send(Ok)` succeeds as a side effect, yet the arm still parks:
        // the physical cookie exists but this pass will poll a later, ready arm.
        this.delivered.push(this.cookie_key.clone());
        std::task::Poll::Pending
      }
      Some(ScriptStep::Pending) | None => std::task::Poll::Pending,
    }
  }
}

/// A fake [`Source`] over `u32` handles: it records every arm/disarm in order (so a test
/// can assert the widen sequence), can be told to fail the *next* arm (so a test can drive
/// the arm-failure path), can be told to return the *next* arm **dead-on-arrival** (a
/// reported-armed handle the source has already forgotten — [`Source::root_key`] is `None` —
/// so a test can drive the driver's I2 arm-choke-point liveness check), and models the
/// source's canonical-key adoption (a `retarget` diverges the reported canonical key from the
/// requested one — the design §4 TOCTOU).
///
/// **It enforces the source's disjoint-root contract** (mirroring the `tributary-fs` watcher):
/// arming a key overlapping a currently-armed fake root returns a
/// [`FaultKind::Conflict`] fault, so the widen-ordering tests validate a *real-executable*
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
  /// Whether this source supports the gapless in-place widen ([`Source::replace`]).
  /// OFF by default, so every existing cell keeps exercising the release-and-rearm
  /// path; the adoption cells turn it on.
  supports_replace: bool,
  /// Whether this source offers the sync barrier ([`Source::begin_sync`]). OFF by default (the trait
  /// default is `Unsupported`), so the cells that push a [`super::PendingSync`] directly are
  /// unaffected; a cell driving the real `on_sync`/end-to-end install path turns it on, and
  /// `begin_sync` then returns a deterministic `<dir>/cookie-<seq>` key the test can deliver.
  supports_sync: bool,
  /// When set, `grow` never resolves — a coverage widening against a hung mount,
  /// the state the close race exists for.
  grow_pending: bool,
  /// Cookie writes this source actually performed, so a cell can prove a REFUSED
  /// barrier left no marker behind.
  begun_syncs: usize,
  /// Cookie keys handed to `end_sync` — the reap ledger (F5).
  ended_syncs: Vec<Vec<OsString>>,
  /// Tokens handed to `cancel_sync` — the abandon-arm ledger. Records the
  /// token an `on_sync` abandon (a caller timeout or a close) hands the source
  /// so a cell can prove a delivered-but-unread cookie is freed by TOKEN, not
  /// by the path the owner never learned.
  cancelled_syncs: Vec<SyncToken>,
  /// The token the most recent `begin_sync` was minted with — the same token an
  /// abandon then cancels, recorded so a cell can assert the cancel names EXACTLY
  /// the sync that began (the nonce is owner-random and unreconstructable).
  begun_token: Option<SyncToken>,
  /// A hand-driven `begin_sync` poll schedule (empty = the ordinary immediate
  /// `Ok(cookie_key)`). Each step drives ONE poll of the scripted future so a
  /// cell can force finding 1's inter-arm race under manual noop-waker polling.
  sync_script: VecDeque<ScriptStep>,
  /// Cookie keys the scripted `begin_sync` SIDE-EFFECT-DELIVERED (a
  /// [`ScriptStep::PendingThenComplete`] poll): the fs worker's `reply.send(Ok)`
  /// landing modeled as a physical delivery that the `select` pass never reads.
  fs_delivered: Vec<Vec<OsString>>,
  /// How many of the next `arm` calls to fail, decremented on each failed arm.
  fail_arms: u32,
  /// How many of the next `grow` calls to fail with [`WatchError::CoverageIncomplete`],
  /// decremented on each failed grow — drives the grow-before-commit failure path (ratified R1:
  /// the watch fails, the record does not broaden). A failed grow applies NO coverage change
  /// (the conservative model: the missing subtree stays missing, survivors keep theirs).
  fail_grows: u32,
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
  /// Each live handle's modelled ACTUAL kernel coverage as a retained antichain (set-cover): the fake applies every [`set_cover`](Source::set_cover) IMMEDIATELY (unlike `FsSource`,
  /// which queues) so a test can assert the source's true coverage after a shrink-then-grow. A
  /// handle ABSENT here is at FULL coverage (its whole armed root — the fresh-arm default and the
  /// cancel-equivalent); a `Some(cover)` covers exactly the union of the retained prefixes'
  /// subtrees. Queried by [`actual_covers`](Self::actual_covers).
  actual_cover: HashMap<u32, Vec<Vec<OsString>>>,
  /// The handle's raw event stream, drained by [`next`](Source::next). A successful
  /// [`replace`](Source::replace) ENQUEUES one epoch-bumped full-root `Rescan` here, mirroring the
  /// real `FsSource::replace` commit — the fidelity that surfaces a stale transient-root `Rescan`
  /// left on the preserved handle by a diverging-then-rolled-back widen.
  pending_events: VecDeque<SourceEvent<OsString, u32>>,
  /// The next raw epoch a `replace`-emitted `Rescan` carries — bumped per replace so each commit's
  /// full-root Rescan is "epoch-bumped" like the real source's.
  next_replace_epoch: u64,
}

impl FakeSource {
  fn new() -> Self {
    Self {
      next_handle: 0,
      calls: Vec::new(),
      live: HashMap::new(),
      canonical: HashMap::new(),
      supports_replace: false,
      supports_sync: false,
      grow_pending: false,
      begun_syncs: 0,
      ended_syncs: Vec::new(),
      cancelled_syncs: Vec::new(),
      begun_token: None,
      sync_script: VecDeque::new(),
      fs_delivered: Vec::new(),
      fail_arms: 0,
      fail_grows: 0,
      dead_on_arrival_arms: 0,
      retarget: HashMap::new(),
      canonicalize: HashMap::new(),
      reuse_next_handle: None,
      actual_cover: HashMap::new(),
      pending_events: VecDeque::new(),
      next_replace_epoch: 1,
    }
  }

  /// Whether the fake's modelled ACTUAL kernel coverage for `handle` includes `key`: a
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

  /// Reconcile the modelled ACTUAL coverage to exactly `retained` — the shared application both
  /// [`set_cover`](Source::set_cover) (prune) and [`grow`](Source::grow) perform. A cover including
  /// the root's own key is FULL coverage (drop the narrowing entry); else it narrows to exactly the
  /// retained antichain. Both a prune and a grow reconcile to `retained` (the driver only ever sends
  /// a narrower cover to `set_cover` and a wider one to `grow`), so the model application is identical
  /// — the tests distinguish them by the recorded [`Call`].
  fn apply_cover(&mut self, handle: u32, retained: &[Vec<OsString>]) {
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

  /// The next `grow` call fails with [`WatchError::CoverageIncomplete`], applying no coverage
  /// change — drives the grow-before-commit failure path (R1).
  fn fail_next_grow(&mut self) {
    self.fail_grows = 1;
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
      Some(None) => Err(WatchError::canonicalize(
        k.iter().collect::<PathBuf>().display().to_string(),
        SourceFault::new(FaultKind::NotFound)
          .with_source(io::Error::other("injected non-canonicalizable key")),
      )),
      // Absent → already canonical (identity), the common case.
      None => Ok(k.to_vec()),
    }
  }

  async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
    let path: PathBuf = key.iter().collect();
    self.calls.push(Call::Arm(path.clone()));
    if self.fail_arms > 0 {
      self.fail_arms -= 1;
      return Err(WatchError::source(
        SourceFault::new(FaultKind::Other).with_source(io::Error::other("injected arm failure")),
      ));
    }
    // The disjoint-root contract (design §4): reject a key overlapping any live root,
    // exactly as the `tributary-fs` watcher does — this forces disarm-before-arm on a widen.
    if let Some(existing) = self
      .live
      .values()
      .find(|live| path.starts_with(live) || live.starts_with(&path))
      .cloned()
    {
      return Err(WatchError::source(
        SourceFault::new(FaultKind::Conflict).with_source(io::Error::other(format!(
          "fake root {} overlaps the already-armed {}",
          path.display(),
          existing.display()
        ))),
      ));
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

  fn is_sync_artifact(&self, key: &[OsString]) -> bool {
    // The fake's reserved namespace carries BOTH of the grounds `FsSource::is_sync_artifact`
    // does, because an endpoint classifier proven against one of them has been proven
    // against neither: the grounds read different components of the key, so a suppression
    // that discards a whole change can survive under the leaf ground while the parent
    // ground never exercises it.
    //
    // GROUND 1 — the LEAF is a name this fake mints (`cookie-…`, standing in for the
    // binding's cookie grammar), or the leaf IS the cookie directory.
    //
    // GROUND 2 — the leaf's IMMEDIATE parent is exactly the cookie directory, whatever the
    // leaf: the shape the real source uses for cookies whose names it cannot predict. Like
    // the real one, neither ground reads any deeper component.
    let Some(leaf) = key.last().and_then(|leaf| leaf.to_str()) else {
      return false;
    };
    if leaf.starts_with("cookie-") || leaf == COOKIE_DIR {
      return true;
    }
    key
      .len()
      .checked_sub(2)
      .and_then(|parent| key[parent].to_str())
      .is_some_and(|parent| parent == COOKIE_DIR)
  }

  fn end_sync(&mut self, _handle: u32, cookie_key: &[OsString]) {
    self.ended_syncs.push(cookie_key.to_vec());
    // The reserved leaf a source-misbehaviour cell writes: the reap is recorded and then
    // unwinds carrying a payload whose own disposal unwinds too.
    if cookie_key.last().and_then(|leaf| leaf.to_str()) == Some("cookie-boom") {
      BOOM_COOKIES_REAPED.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
      std::panic::panic_any(PanicsOnDrop);
    }
  }

  fn cancel_sync(&mut self, _handle: u32, token: SyncToken) {
    // The abandon-arm ledger: an `on_sync` timeout or close hands the token here, and only
    // this call can free a cookie whose delivered-but-unread write the owner never got a path
    // for. Overrides the seam's defaulted no-op.
    self.cancelled_syncs.push(token);
  }

  async fn begin_sync(
    &mut self,
    _handle: u32,
    dir_key: &[OsString],
    token: SyncToken,
  ) -> Result<Vec<OsString>, crate::error::SyncError> {
    if !self.supports_sync {
      return Err(crate::error::SyncError::Unsupported);
    }
    self.begun_syncs += 1;
    // The token the abandon arm will later cancel — recorded so a cell can prove the cancel
    // names EXACTLY the sync that began (the nonce is owner-random, so the token cannot be
    // reconstructed from outside).
    self.begun_token = Some(token);
    // A deterministic cookie key under the sub's directory: `<dir>/cookie-<seq>`. The seq makes it
    // predictable so a test can deliver the matching artifact event; `is_sync_artifact` (a `cookie-`
    // leaf) both suppresses that event and resolves the barrier on it.
    let mut cookie_key = dir_key.to_vec();
    cookie_key.push(OsString::from(format!("cookie-{}", token.seq())));
    // With no script this is the ordinary immediate completion. A script drives the poll
    // schedule by hand so a cell can force finding 1's inter-arm race: a poll that
    // side-effect-delivers the cookie yet returns `Pending`, letting a later ready arm win the
    // same `select` pass.
    if self.sync_script.is_empty() {
      return Ok(cookie_key);
    }
    let delivered = ScriptedBegin {
      script: &mut self.sync_script,
      delivered: &mut self.fs_delivered,
      cookie_key,
    }
    .await;
    Ok(delivered)
  }

  async fn replace(
    &mut self,
    handle: u32,
    new_key: &[OsString],
  ) -> Result<Armed<OsString, u32>, WatchError> {
    if !self.supports_replace {
      return Err(WatchError::source(SourceFault::new(FaultKind::Unsupported)));
    }
    let path: PathBuf = new_key.iter().collect();
    self.calls.push(Call::Replace(handle, path.clone()));
    // The canonical key honors the retarget override (mirroring `arm`), so a
    // test can model an fs-side canonicalization race the `fs_path_preserves_plan`
    // guard must catch — the divergent-widen rollback path.
    let canonical_path = self
      .retarget
      .get(&path)
      .cloned()
      .unwrap_or_else(|| path.clone());
    let canonical: Vec<OsString> = components(&canonical_path);
    // Make-before-break, modeled: the SAME handle now covers the (canonical)
    // key, and the old coverage is never dropped in between.
    self.live.insert(handle, canonical_path);
    self.canonical.insert(handle, canonical.clone());
    // Model the real `FsSource::replace`: a successful make-before-break commit delivers ONE
    // epoch-bumped full-root `Rescan` on the PRESERVED handle, keyed at the committed canonical root.
    // A diverging widen enqueues `Rescan(divergent)`, then its rollback enqueues `Rescan(restored)`,
    // both riding this one preserved handle — the fidelity that surfaces the stale transient-root
    // Rescan the umbrella must clamp.
    let epoch = self.next_replace_epoch;
    self.next_replace_epoch += 1;
    self.pending_events.push_back(SourceEvent::new(
      handle,
      canonical.clone(),
      EventKind::Rescan,
      Location::new(),
      Epoch::new(epoch),
      Some(ChangeId::new(NonZeroU64::MIN)),
    ));
    Ok(Armed::new(handle, canonical))
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
    // Synchronous, fire-and-forget in-place coverage PRUNE request (the set-cover design v3): record the root
    // handle and the retained cover the driver forwarded, so a test can assert exactly which prunes
    // fired and in what order. The fake keeps the root live — a prune reconciles coverage BELOW a
    // root, never releases it — so `root_key` still answers, unlike `disarm`. Unlike `FsSource` (which
    // QUEUES and drains opportunistically), the fake APPLIES immediately, so `actual_covers` reflects
    // the source's true coverage right away.
    self.calls.push(Call::SetCover(handle, retained.to_vec()));
    self.apply_cover(handle, retained);
  }

  async fn grow(&mut self, handle: u32, retained: &[Vec<OsString>]) -> Result<(), WatchError> {
    // The AWAITED, applied-before-`Ok` GROW (the set-cover design v3): record the fresh cover
    // (including the newcomer) and apply it to the modelled ACTUAL coverage IMMEDIATELY — so
    // `actual_covers` reflects the newcomer the instant this returns `Ok`, mirroring the fs source's
    // fenced `Watcher::set_cover` ack. This is what lets a test observe a pruned key regain coverage
    // the moment the covered-outside watch returns, with no bridging Rescan. An injected failure
    // (`fail_next_grow`) records the ATTEMPT but applies nothing — coverage may not include the
    // retained keys (the conservative model) — and reports the fs binding's degraded-fence error,
    // driving the grow-before-commit abort (R1).
    self.calls.push(Call::Grow(handle, retained.to_vec()));
    if self.grow_pending {
      core::future::pending::<()>().await;
    }
    if self.fail_grows > 0 {
      self.fail_grows -= 1;
      return Err(WatchError::CoverageIncomplete);
    }
    self.apply_cover(handle, retained);
    Ok(())
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    // Drain the handle's raw event stream (a `replace`-emitted full-root `Rescan`), or `None` once
    // empty — the source-drained signal every existing cell already relied on.
    self.pending_events.pop_front()
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.canonical.get(&handle).cloned()
  }
}

/// Builds a `Rescan` [`SourceEvent`] for `handle` at `path` with raw fs `epoch` — the terminal /
/// overflow coverage-loss signal `retire_if_dead` classifies via [`Source::root_key`]. The epoch is
/// the source's raw stamp (rebased at fan-out); it is irrelevant on the retire path (which mints its
/// own `shed_rescan`) and load-bearing only when the fanned `Rescan` overflows and parks at its own
/// stamped epoch.
fn rescan_event(handle: u32, path: &str, epoch: u64) -> SourceEvent<OsString, u32> {
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Rescan,
    Location::new(),
    Epoch::new(epoch),
    Some(ChangeId::new(NonZeroU64::MIN)),
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
/// A legal [`panic_any`](std::panic::panic_any) payload whose own disposal unwinds — the only
/// shape that makes a containment boundary's `Err` dangerous, and so the instrument every
/// payload-disposal cell reaches for.
struct PanicsOnDrop;

impl Drop for PanicsOnDrop {
  fn drop(&mut self) {
    std::panic::panic_any(ForgottenPayload);
  }
}

/// The payload [`PanicsOnDrop`]'s own disposal unwinds with.
///
/// A ZST, and that is the point. This is the payload a total disposal must
/// [forget](core::mem::forget) — the operation that cuts the recursion runs no destructor — so by
/// contract it is unreachable for the rest of the process. A zero-sized box allocates nothing, so
/// the cells assert that containment while retaining nothing for a whole-process leak check to
/// report. A `panic!("…")` message makes it a `Box<&'static str>` instead: 16 bytes per disposal
/// that LeakSanitizer reports, in a suite where every OTHER retained allocation is a real defect.
struct ForgottenPayload;

/// How many `cookie-boom` cookies [`FakeSource::end_sync`] has been handed.
///
/// A process-wide counter because the ledger it would otherwise use lives inside the source,
/// inside the owner being DROPPED — the very destructor under test. Only the owner-teardown
/// reap cell writes the `cookie-boom` leaf, so no other cell can move it.
static BOOM_COOKIES_REAPED: core::sync::atomic::AtomicUsize =
  core::sync::atomic::AtomicUsize::new(0);

fn source_modified(handle: u32, path: &str, epoch: u64) -> SourceEvent<OsString, u32> {
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Modified,
    Location::new(),
    Epoch::new(epoch),
    Some(ChangeId::new(NonZeroU64::MIN)),
  )
}

/// A raw `Removed` [`SourceEvent`] for `handle` at `path` — the user-visible NON-`Rescan`
/// terminal event the fs layer can surface for a watched-root deletion before its terminal
/// `Rescan`, which `retire_if_dead` must also retire a dead root on.
fn source_removed(handle: u32, path: &str, epoch: u64) -> SourceEvent<OsString, u32> {
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Removed,
    Location::new(),
    Epoch::new(epoch),
    Some(ChangeId::new(NonZeroU64::MIN)),
  )
}

/// A raw `Created` [`SourceEvent`] for `handle` at `path`.
fn source_created(handle: u32, path: &str, epoch: u64) -> SourceEvent<OsString, u32> {
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Created,
    Location::new(),
    Epoch::new(epoch),
    Some(ChangeId::new(NonZeroU64::MIN)),
  )
}

/// A raw whole-`Moved` [`SourceEvent`] on `handle` from `from` to `to` — fan-out
/// projects it per subscriber coverage (design §5), so one raw move drives both the
/// whole-move interest gate and the single-endpoint projections.
fn source_moved(handle: u32, from: &str, to: &str, epoch: u64) -> SourceEvent<OsString, u32> {
  SourceEvent::new(
    handle,
    key(to),
    EventKind::Moved { from: key(from) },
    Location::new(),
    Epoch::new(epoch),
    Some(ChangeId::new(NonZeroU64::MIN)),
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
  /// Kept alive so the owner's sync-admission receiver never observes a closed channel (the loop
  /// is not run here; the sync primitives are driven directly).
  _sync_commands: async_channel::Sender<super::SyncRequest>,
  /// The dedicated close signal's sender: kept alive so the owner's close receiver
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
    let (sync_command_tx, sync_command_rx) = async_channel::unbounded::<super::SyncRequest>();
    let (close_tx, close_rx) = async_channel::bounded(1);
    let (cleanup_tx, cleanup_rx) = async_channel::unbounded();
    let owner = Owner {
      source: FakeSource::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
      filter_payload_forgotten: false,
      needs_rescan: BTreeMap::new(),
      suppressed_rescan: BTreeMap::new(),
      unclaimed: std::collections::HashSet::new(),
      flush_cursor: None,
      #[cfg(test)]
      last_flush_visited: 0,
      #[cfg(test)]
      test_pre_cut_claims: Vec::new(),
      debounce: None,
      coalescer,
      pending_syncs: Vec::new(),
      sync_seq: 0,
      sync_nonce_seed: std::collections::hash_map::RandomState::new(),
      loss_serial: HashMap::new(),
      loss_gen: std::sync::Arc::new(core::sync::atomic::AtomicU64::new(0)),
      cleanup_tx,
      cleanup_rx,
      commands: command_rx,
      sync_commands: sync_command_rx,
      closes: close_rx,
      events: event_tx,
      #[cfg(debug_assertions)]
      observed_handles: super::ObservedHandles::new(),
      _rt: PhantomData::<TokioRuntime>,
    };
    Self {
      owner,
      events: event_rx,
      _commands: command_tx,
      _sync_commands: sync_command_tx,
      closes: close_tx,
    }
  }

  async fn watch(&mut self, path: &str, interest: Interest) -> Result<Subscription, WatchError> {
    self
      .watch_with(path, WatchOptions::new().with_interest(interest))
      .await
  }

  /// [`watch`](Self::watch) with the full per-watch options — for the tests exercising
  /// a custom filter or a per-subscription debounce posture.
  async fn watch_with(
    &mut self,
    path: &str,
    options: WatchOptions<OsString>,
  ) -> Result<Subscription, WatchError> {
    self
      .owner
      .reconcile_watch(&key(path), (), options)
      .await
      .map_err(|stop| match stop {
        super::ReconcileStop::Failed(err) => err,
        // These harness owners are driven directly — nothing ever sends on their close signal — so
        // the in-place widen's close race cannot fire here.
        super::ReconcileStop::CloseRequested(_) => {
          unreachable!("no close is sent to a directly-driven harness owner")
        }
      })
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
  // Only /a is ARMED. The covered /a/b lands INSIDE the covering root's full coverage (never
  // narrowed), so it grows nothing and arms nothing — so filter to the arms.
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

/// Regression (design §3, a handle is a per-watcher capability): every
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
async fn widen_prefers_the_gapless_in_place_replace_when_the_source_offers_it() {
  let mut h = Harness::new();
  h.owner.source.supports_replace = true;

  let s_narrow = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let s_wide = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a widens");

  // NO disarm, NO second arm: the root was retargeted in place, so its coverage
  // was never dropped — the gap the release-and-rearm dance opens does not exist.
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Replace(1, PathBuf::from("/a")),
    ],
    "a widen the source can do in place must never release-and-rearm"
  );

  // The root is now keyed at the WIDER path — under the SAME (preserved) handle.
  let roots: Vec<(PathBuf, u32)> = h
    .owner
    .subsumer
    .roots()
    .map(|(k, handle)| (PathBuf::from_iter(k), handle))
    .collect();
  assert_eq!(
    roots,
    vec![(PathBuf::from("/a"), 1)],
    "one root, widened, on the preserved handle"
  );

  // The re-pointed subscriber is still rebased with its dominating Rescan: its
  // root changed, so its view must re-base even though no coverage was lost.
  let rescans: Vec<Subscription> = h
    .drain()
    .into_iter()
    .filter(|e| e.kind().is_rescan())
    .map(|e| e.subscription())
    .collect();
  assert!(
    rescans.contains(&s_narrow),
    "the re-pointed subscription is rebased onto the wider root: {rescans:?}"
  );
  let _ = s_wide;
}

/// A source that cannot widen in place (the default) keeps the old dance — the
/// adoption is a pure optimization, never a behavior change.
#[tokio::test]
async fn widen_falls_back_to_release_and_rearm_without_replace_support() {
  let mut h = Harness::new();
  // `supports_replace` is off by default.
  let _narrow = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  h.watch("/a", Interest::all()).await.expect("watch /a");

  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Disarm(1),
      Call::Arm(PathBuf::from("/a")),
    ],
    "without in-place support the widen still releases and re-arms"
  );
}

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
    Path::new("/a/b"),
    "the Rescan names the SUBSCRIPTION's own subtree to re-enumerate, not the wider root \
     it now rides — the coverage gap the widen opened is exactly what this sub owns"
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

/// The STRUCTURAL close of the handle-liveness class at the ARM choke point: a fresh
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
    // Each re-pointed subscription is told to re-enumerate ITS OWN subtree, not the
    // wider root it now rides: the disarm/re-arm gap made exactly its own coverage
    // uncertain, and /a is not its to walk.
    let own = if ev.subscription() == sb {
      "/a/b"
    } else {
      "/a/c"
    };
    assert_eq!(
      ev.path(),
      Path::new(own),
      "the re-point Rescan is scoped to the subscription, not to the widened root"
    );
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

/// set-cover shrink-in-place call-site (design §5): unwatching the widening subscription of a root that
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

  // Baseline: the widen disarmed the subsumed /a/b root and armed /a — no prune of the WIDE root
  // yet. (The covered /a/b/c landed INSIDE the /a/b root's full coverage, so it grew and pruned
  // nothing — v3 issues a cover call only when a newcomer falls OUTSIDE a narrowed cover.)
  assert!(
    !h.owner
      .source
      .calls()
      .iter()
      .any(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide)),
    "no prune of the wide root before the over-broadening unwatch"
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

  // The covered /a/b landed INSIDE the /a root's full coverage (never narrowed), so it issued no
  // cover call; snapshot the prune calls so far, so we can assert the UNWATCH below adds none of its
  // own.
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

/// The orphan (`DropOrphan`) release path also shrinks (the set-cover design): a committed-but-unclaimed wide
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

/// set-cover : covered-outside commits GROW (never prune), and the cancel-equivalent grows back to FULL.
/// Wide /a over survivor /a/b: unwatching the widening /a PRUNES to {/a/b}; a later `watch /a/c`
/// (Covered-outside, arms nothing) GROWS to the FRESH {/a/b, /a/c}; and a final `watch /a` (Covered,
/// key == root, also outside the narrowed cover) grows back to FULL coverage — the cancel-equivalent —
/// and clears the record to None (a subscriber now pins the root at its own key). One prune then two
/// grows, each carrying the CURRENT fresh cover; and — every grow being AWAITED — the record stays
/// EXACT at every step (None → {/a/b} → {/a/b, /a/c} → None).
#[tokio::test]
async fn covered_outside_grows_then_repins_to_full() {
  let mut h = Harness::new();

  // Wide /a over a disjoint survivor /a/b (a widen, so /a/b is NOT a covered commit — no cover call
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

  // No cover call on the wide root yet (the widen issues none).
  assert!(
    !h.owner
      .source
      .calls()
      .iter()
      .any(|c| matches!(c, Call::SetCover(handle, _) | Call::Grow(handle, _) if *handle == wide)),
    "no cover call on the wide root before any over-broadening drop or covered-outside commit"
  );

  // (1) Unwatch the widening /a → over-broad → PRUNE to {/a/b}, record Some({/a/b}).
  h.unwatch(s_a).expect("unwatch the widening /a");
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b")]),
    "the prune narrowed the record to {{/a/b}}"
  );
  // (2) watch /a/c, Covered-OUTSIDE {/a/b} → GROW to the fresh {/a/b, /a/c}, record Some({/a/b, /a/c}).
  let _s_c = h
    .watch("/a/c", Interest::all())
    .await
    .expect("watch /a/c covered-outside");
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the grow broadened the record EXACTLY to {{/a/b, /a/c}} (broaden-on-return)"
  );
  // (3) watch /a again, Covered with key == root (also outside the narrowed cover) → GROW to FULL
  //     coverage (the cancel-equivalent), record None (/a now pins the root at its own key).
  let _s_a2 = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a again covered");
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    None,
    "re-pinning the root at its own key grows back to FULL and clears the record"
  );

  // The prune is a Call::SetCover; both broadens are Call::Grow carrying the CURRENT fresh cover.
  let covers: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(handle, _) | Call::Grow(handle, _) if *handle == wide))
    .collect();
  assert_eq!(
    covers,
    vec![
      Call::SetCover(wide, vec![key("/a/b")]),
      Call::Grow(wide, vec![key("/a/b"), key("/a/c")]),
      Call::Grow(wide, vec![key("/a")]),
    ],
    "one PRUNE then two GROWs, each carrying the fresh cover: the {{/a/b}} survivor drop, then the \
     grow to {{/a/b, /a/c}}, then the cancel-equivalent grow to FULL {{/a}}"
  );
  // The full-coverage repin restored actual coverage everywhere under /a.
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/c")),
    "the grow covered /a/c"
  );
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/z")),
    "the cancel-equivalent grew back to FULL coverage under /a"
  );
}

/// set-cover Covered-OUTSIDE grow, end to end at the driver: after a PRUNE narrowed a
/// wide root's ACTUAL coverage below a key, a later watch of that pruned key is `Covered` (arms
/// nothing) yet the source no longer backs it. The driver AWAITS a `Source::grow` to a fresh cover
/// that INCLUDES the newcomer, applied BEFORE the watch returns, so: (i) NO bridging Rescan is parked
/// (coverage is live on return — a new watch is "changes from now on"); (ii) the commit issued a
/// Call::Grow with the fresh cover; (iii) the source's ACTUAL coverage includes the newcomer at
/// return while the survivor never lost coverage; and the record broadens EXACTLY to the grown cover.
///
/// Fail-on-old: a deferred fire-and-forget re-issue behind an already-flushed bridge could drop the
/// write between commit and apply — the exact commit-to-apply silent loss the awaited grow closes.
#[tokio::test]
async fn covered_outside_narrowed_root_grows_before_returning() {
  let mut h = Harness::new();

  // Wide /a over a disjoint survivor /a/b, then drop the widening /a → over-broad → PRUNE narrows the
  // wide root's ACTUAL coverage to {/a/b}; /a/c is now strictly outside it (pruned at the source).
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

  // Precondition — the source's actual coverage was narrowed: /a/b covered, /a/c NOT; record {/a/b}.
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/b")),
    "the retained /a/b survivor stays covered after the prune"
  );
  assert!(
    !h.owner.source.actual_covers(wide, &key("/a/c")),
    "the pruned /a/c is NOT covered before the newcomer (the narrowed source state)"
  );
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b")]),
    "the record narrowed to {{/a/b}} on the prune issue"
  );

  let grows_before = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::Grow(handle, _) if *handle == wide))
    .count();

  // Watch /a/c: Covered under the still-armed wide /a, but OUTSIDE the narrowed cover {/a/b}.
  let s_c = h
    .watch("/a/c", Interest::all())
    .await
    .expect("watch /a/c covered-outside");

  // (i) NO bridging Rescan is parked — the grow was applied before the watch returned, so nothing is
  // owed under the newcomer's key (v3: coverage is live on return, so no bridge).
  assert!(
    !h.owner.needs_rescan.contains_key(&s_c),
    "no bridge Rescan is parked for the covered-outside newcomer — coverage is live on return (v3)"
  );

  // (ii) The commit AWAITED a Call::Grow whose FRESH cover INCLUDES the newcomer.
  let grows_after: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::Grow(handle, _) if *handle == wide))
    .collect();
  assert!(
    grows_after.len() > grows_before,
    "the covered-outside commit issued a Call::Grow (the grow trigger)"
  );
  assert_eq!(
    grows_after,
    vec![Call::Grow(wide, vec![key("/a/b"), key("/a/c")])],
    "the grow carried the fresh survivor+newcomer cover {{/a/b, /a/c}}"
  );

  // (iii) The source's ACTUAL coverage now includes /a/c (grown before return), /a/b never lost it,
  // and the record broadened EXACTLY to the grown cover.
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/c")),
    "the source grew its actual coverage to include /a/c before the watch returned"
  );
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/b")),
    "the retained /a/b never lost coverage across the grow (no gap, no re-crawl)"
  );
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the record broadened EXACTLY on grow-return, matching the source's live coverage"
  );
}

/// set-cover : a second Covered newcomer landing INSIDE the record broadened by an earlier grow does NOT
/// re-grow and owes NO bridge. Because the first grow is AWAITED and applied before its
/// watch returned, the record broadened EXACTLY to the source's live coverage — so a newcomer now
/// under that coverage classifies INSIDE and the source already backs it. (Contrast the v2 pessimism:
/// there the grow was a fire-and-forget re-issue with an enqueue→apply window, so the record could not
/// broaden at issuance and a second newcomer had to park its own bridge; v3 has no such window.)
#[tokio::test]
async fn second_covered_inside_the_grown_cover_does_not_regrow() {
  let mut h = Harness::new();

  // Narrow the wide /a root to {/a/b}, then GROW it back to {/a/b, /a/c} via a covered-outside /a/c.
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
  let _s_c = h
    .watch("/a/c", Interest::all())
    .await
    .expect("watch /a/c covered-outside grows");
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the first grow broadened the record EXACTLY to {{/a/b, /a/c}}"
  );
  let grows_before = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::Grow(handle, _) if *handle == wide))
    .count();

  // A SECOND Covered newcomer INSIDE the grown cover: /a/c/x is under the retained prefix /a/c.
  let s_cx = h
    .watch("/a/c/x", Interest::all())
    .await
    .expect("watch /a/c/x covered-INSIDE");

  // It classifies INSIDE the record, so the source already backs it: NO new grow, NO bridge parked.
  assert!(
    !h.owner.needs_rescan.contains_key(&s_cx),
    "an inside-cover newcomer parks no bridge — coverage already backs it"
  );
  let grows_after = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::Grow(handle, _) if *handle == wide))
    .count();
  assert_eq!(
    grows_after, grows_before,
    "an inside-cover newcomer issues NO grow (the exact broadened record classifies it INSIDE)"
  );
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the record is unchanged by an inside-cover newcomer"
  );
}

/// set-cover F2, end to end at the driver: a non-root unwatch that shrinks an
/// already-narrowed cover RE-PRUNES. After a grow broadened the wide /a root's cover to {/a/b, /a/c},
/// unwatching the non-root /a/c survivor leaves the cover reclaimable to {/a/b}, so
/// `release_subscription` issues a sync `set_cover` PRUNE with the shrunken antichain and narrows the
/// record. Fail-on-old: the old detect_shrink only fired for a departing key EQUAL to the root key, so
/// a non-root departure left the grown /a/c coverage pinned forever (a budget leak).
#[tokio::test]
async fn grow_then_unwatch_non_root_reprunes() {
  let mut h = Harness::new();

  // Narrow /a to {/a/b}, then grow to {/a/b, /a/c} via a covered-outside /a/c.
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
  let s_c = h
    .watch("/a/c", Interest::all())
    .await
    .expect("watch /a/c covered-outside grows");
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the grow broadened the record to {{/a/b, /a/c}}"
  );
  let prunes_before = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide))
    .count();

  // Unwatch the NON-ROOT /a/c survivor: the cover can shrink further, to {/a/b} (F2).
  h.unwatch(s_c).expect("unwatch the non-root /a/c");

  let prunes_after: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide))
    .collect();
  assert_eq!(
    prunes_after.len(),
    prunes_before + 1,
    "the non-root unwatch issued exactly one re-prune of the wide root"
  );
  assert_eq!(
    prunes_after.last(),
    Some(&Call::SetCover(wide, vec![key("/a/b")])),
    "the re-prune carries the shrunken {{/a/b}} antichain"
  );
  // The record narrowed back to {/a/b}, and the source reclaimed /a/c's coverage in place.
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b")]),
    "the record narrowed on the F2 re-prune issue"
  );
  assert!(
    !h.owner.source.actual_covers(wide, &key("/a/c")),
    "the /a/c coverage was reclaimed by the re-prune"
  );
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/b")),
    "the retained /a/b survivor keeps coverage"
  );
  assert!(
    !h.owner
      .source
      .calls()
      .iter()
      .any(|c| matches!(c, Call::Disarm(handle) if *handle == wide)),
    "the re-prune reclaims in place, never disarms the surviving root"
  );
}

/// A live-root source `Rescan` degrades the root's NARROWED retained-cover record to the
/// empty cover: the loss signal means the recorded claim may span a hole, so a newcomer
/// that would have classified Covered-INSIDE (committing with NO grow — silently unwatched
/// over the hole) instead classifies Covered-OUTSIDE and drives a coverage-re-proving grow.
/// Fail-on-old: without the degrade, the post-`Rescan` newcomer under the retained cover
/// commits with zero `Grow` calls and its subtree stays dead until an unrelated reconcile.
#[tokio::test]
async fn source_rescan_degrades_the_retained_cover_so_newcomers_regrow() {
  let mut h = Harness::new();

  // Narrow the wide /a root to {/a/b}: widen /a over /a/b, then drop the widening /a (PRUNE).
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
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b")]),
    "the prune narrowed the record to {{/a/b}}"
  );
  let _ = h.drain();

  // Baseline: a newcomer INSIDE the retained cover commits with no grow.
  let _s_inside = h
    .watch("/a/b/deep", Interest::all())
    .await
    .expect("a covered-inside newcomer commits");
  assert!(
    !h.owner
      .source
      .calls()
      .iter()
      .any(|c| matches!(c, Call::Grow(handle, _) if *handle == wide)),
    "inside the retained cover no grow is needed"
  );

  // The source signals coverage loss on the LIVE root (an overflow / failed re-arm
  // Rescan): mirror the loop's live-root sequence — retire (no-op, the root is live),
  // degrade, fan out.
  let loss = rescan_event(wide, "/a/b", 1);
  h.owner.consume_source_event(&loss);
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![]),
    "the narrowed record degraded to the empty cover — it claims nothing below the root"
  );
  let _ = h.drain();

  // A newcomer that WOULD have been covered-inside now re-proves coverage via grow, and
  // the record broadens exactly to the grown cover.
  let _s2 = h
    .watch("/a/b/deeper", Interest::all())
    .await
    .expect("the post-loss newcomer commits through a re-proving grow");
  let grows: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::Grow(handle, _) if *handle == wide))
    .collect();
  assert_eq!(
    grows.len(),
    1,
    "the post-loss newcomer drove exactly one grow"
  );
  let Call::Grow(_, grown) = &grows[0] else {
    unreachable!("filtered to grows");
  };
  assert!(
    grown
      .iter()
      .any(|k| key("/a/b/deeper").starts_with(k.as_slice())),
    "the grown antichain covers the newcomer, got {grown:?}"
  );
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/b/deeper")),
    "the newcomer's subtree is genuinely covered after the grow"
  );
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(grown.clone()),
    "the record broadened exactly to the grown cover"
  );
}

/// An unwatch after the degrade must NOT resurrect the coverage claim: the shrink detector
/// re-prunes only when the survivor antichain is CONTAINED by the recorded cover, and after
/// a degrade to the empty cover no survivor is — the survivors' keys are membership, not
/// proof of coverage, and the fire-and-forget prune never establishes any. Fail-on-old:
/// containment unchecked, the sibling unwatch "shrank" the empty record to the survivor
/// antichain and recorded it as authoritative, so the follow-up newcomer classified
/// Covered-INSIDE, skipped the grow, and committed over the unproven region.
#[tokio::test]
async fn post_degrade_unwatch_keeps_the_record_degraded_until_a_grow_re_proves() {
  let mut h = Harness::new();

  // A wide /a root narrowed to {/a/b}, then grown to {/a/b, /a/c} via a covered-outside watch.
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
  let s_c = h
    .watch("/a/c", Interest::all())
    .await
    .expect("watch /a/c grows the cover");
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the grown record names both survivors"
  );
  let _ = h.drain();

  // The source signals coverage loss; the claim degrades to the empty cover.
  let loss = rescan_event(wide, "/a", 1);
  h.owner.consume_source_event(&loss);
  assert_eq!(h.owner.subsumer.retained_cover_of(wide), Some(vec![]));
  let calls_before = h.owner.source.calls().len();

  // A sibling unwatch must neither re-prune nor resurrect the claim.
  h.unwatch(s_c).expect("unwatch the /a/c sibling");
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![]),
    "the record stays degraded across the unwatch — survivors are not proof of coverage"
  );
  assert!(
    !h.owner.source.calls()[calls_before..]
      .iter()
      .any(|c| matches!(c, Call::SetCover(handle, _) if *handle == wide)),
    "no reclaim prune is issued against a degraded record"
  );

  // The next newcomer under the surviving cover still re-proves coverage via grow.
  let _s2 = h
    .watch("/a/b/x", Interest::all())
    .await
    .expect("the post-unwatch newcomer commits through a re-proving grow");
  let grows: Vec<Call> = h.owner.source.calls()[calls_before..]
    .iter()
    .filter(|c| matches!(c, Call::Grow(handle, _) if *handle == wide))
    .cloned()
    .collect();
  assert_eq!(grows.len(), 1, "the newcomer drove the re-proving grow");
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/b/x")),
    "the newcomer's subtree is genuinely covered after the grow"
  );
}

/// Grow-before-commit (ratified R1): a Covered-outside newcomer whose awaited [`Source::grow`]
/// FAILS fails the `watch()` with the retryable `CoverageIncomplete` — never a committed
/// subscription whose subtree has no kernel backing and no retry owner. The record is NOT broadened
/// (record-exact), nothing leaks (the not-yet-committed plan unwinds through the same `abort_watch`
/// the dead-covering-root re-plan uses), and a subsequent identical `watch()` re-issues the grow
/// and succeeds (self-healing). Fail-on-old: the pre-R1 order committed BEFORE the grow, so a
/// failed grow returned `Ok` over a coverage hole with the record broadened to coverage that does
/// not exist — and the SECOND newcomer then classified inside-cover and silently received nothing.
#[tokio::test]
async fn covered_outside_grow_failure_fails_the_watch_and_broadens_nothing() {
  let mut h = Harness::new();

  // Narrow the wide /a root to {/a/b}: widen /a over /a/b, then drop the widening /a (PRUNE).
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
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b")]),
    "the prune narrowed the record to {{/a/b}}"
  );
  // Clear the setup's widen Rescan so the post-failure stream assert below is exact.
  let _ = h.drain();
  let filters_before = h.owner.filters.len();

  // The next grow fails: the covered-outside watch of /a/c must FAIL, not commit (R1).
  h.owner.source.fail_next_grow();
  let err = h
    .watch("/a/c", Interest::all())
    .await
    .expect_err("a failed covered-outside grow fails the watch (grow-before-commit)");
  assert!(
    err.is_coverage_incomplete(),
    "the failure is the retryable CoverageIncomplete, got {err:?}"
  );

  // The grow was ATTEMPTED, carrying the fresh survivors+newcomer cover computed BEFORE commit
  // (the explicit-newcomer parameter)...
  let grows: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::Grow(handle, _) if *handle == wide))
    .collect();
  assert_eq!(
    grows,
    vec![Call::Grow(wide, vec![key("/a/b"), key("/a/c")])],
    "the failed grow carried the fresh {{/a/b, /a/c}} cover"
  );
  // ...but the record did NOT broaden — record-exact, so the next newcomer under the pruned
  // region still classifies outside-cover...
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b")]),
    "no broaden on a failed grow — the record still names the source's true coverage"
  );
  // ...the source's actual coverage is unchanged (the fake applies nothing on a failed grow)...
  assert!(
    !h.owner.source.actual_covers(wide, &key("/a/c")),
    "the newcomer's subtree is NOT covered after the failed grow"
  );
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/b")),
    "survivor coverage is untouched by the failed grow (never moves)"
  );
  // ...and nothing leaked: no pending reservation, no published subscription, no per-sub state,
  // no parked debt, nothing delivered.
  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "the aborted plan leaks no pending reservation"
  );
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/a/c")),
    "the failed watch is never published as watched"
  );
  assert_eq!(
    h.owner.filters.len(),
    filters_before,
    "no filter was registered for the never-committed subscription"
  );
  assert!(
    h.owner.needs_rescan.is_empty() && h.owner.suppressed_rescan.is_empty(),
    "no parked Rescan debt for a never-committed subscription"
  );
  assert!(
    h.drain().is_empty(),
    "the failed watch delivered nothing (existing subscribers are covered by the source's own \
     in-band Rescan, per the grow error contract — not by the umbrella)"
  );

  // Self-heal: an identical retry re-issues the grow (the record still classifies /a/c
  // outside-cover) and commits with the broadened record.
  let _s_c = h
    .watch("/a/c", Interest::all())
    .await
    .expect("the identical retry succeeds");
  let grows_after: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .filter(|c| matches!(c, Call::Grow(handle, _) if *handle == wide))
    .collect();
  assert_eq!(
    grows_after,
    vec![
      Call::Grow(wide, vec![key("/a/b"), key("/a/c")]),
      Call::Grow(wide, vec![key("/a/b"), key("/a/c")]),
    ],
    "the retry re-issued the SAME grow — the unbroadened record classified it outside-cover again"
  );
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the successful retry broadened the record exactly on grow-Ok"
  );
  assert!(
    h.owner.source.actual_covers(wide, &key("/a/c")),
    "the retry's grow applied — the newcomer's subtree is live"
  );
  assert!(
    h.owner.subsumer.view().is_watched(&key("/a/c")),
    "the retry committed and published"
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

/// Regression (the failed-widen restore under the **generation-unique**
/// [`Source::Handle`] contract): a source that re-mints a **still-recorded** sibling's handle value
/// for a re-arm violates the contract, and the arm choke point's observed-handle `debug_assert`
/// must catch it LOUDLY rather than let `rebind_root` silently corrupt the reverse
/// index. Here the widen of `/a` fails and the restore of `/a/b` (old handle 1) re-arms while the
/// source REUSES handle `2` — already observed when the sibling `/a/c` was armed. The re-arm trips
/// the observed-handle assert first (`rebind_root(1, 2)` would otherwise overwrite `by_handle[2]`
/// and strand `/a/c`).
///
/// The earlier defensive recovery (disarm the aliased handle + retire `old`) was
/// RETIRED: it was incomplete, and when the alias was an unrelated *live* root its `disarm`
/// released that root's real source watch while its record + coverage stayed live — silently missing
/// future changes. The strengthened contract makes the alias impossible for a conforming
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
  // arm choke point's observed-handle debug_assert panics at re-arm time, before the rebind.
  h.owner.source.fail_next_arm();
  h.owner.source.reuse_next_arm_handle(2);
  // Panics inside the restore, before the watch returns — the source violated the handle contract.
  let _ = h.watch("/a", Interest::all()).await;
}

/// Regression (generation-unique contract, the SAME-key case the original rebind
/// tripwire wrongly exempted with `|| new_handle == old`): the failed-widen restore re-arm must
/// mint a FRESH handle even for the same key — reusing `old` is a `Source::Handle` violation,
/// because a stale pre-disarm event still carrying `old` would then route through the re-armed root
/// and be stamped in the new generation past the restore Rescan (a handle-ABA sibling). The
/// exhaustive observed-handle tripwire has NO same-key exemption: `old` was observed
/// when `/a/b` was first armed, so re-arming with it trips the arm choke point's assert.
///
/// Fail-on-old: the retired rebind assert's `|| new_handle == old` exemption masked this
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
  // so the arm choke point's observed-handle debug_assert panics at re-arm time () rather
  // than let a stale `old` event route through the re-armed root.
  h.owner.source.fail_next_arm();
  h.owner.source.reuse_next_arm_handle(1);
  let _ = h.watch("/a", Interest::all()).await;
}

/// Regression (the observed-handle tripwire — the POST-RETIREMENT reuse the
/// per-site live-index checks MISSED): a handle removed from the live index by an `unwatch` (or a
/// terminal retirement) that a later arm REUSES is still a generation-unique `Source::Handle`
/// violation — a stale event still carrying it would route through the re-armed root in its new
/// generation. The retired per-site checks only asserted `entry(handle).is_none()` against the
/// CURRENT index, so a reused post-retirement handle (absent from the index) passed them silently;
/// the owner-level observed-handle window catches it, because the handle was observed at its first
/// arm and observations leave the window only by eviction — never by retirement.
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
  // structure, but still recorded in the owner's observed-handle window.
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  h.unwatch(sa).expect("unwatch /a");

  // Re-watch a disjoint key and force the source to REUSE the retired handle 1 — a generation-unique
  // `Source::Handle` violation. The retired live-index check would pass (handle 1 is absent from the
  // index after the unwatch), but the arm choke point's observed-handle debug_assert panics.
  h.owner.source.reuse_next_arm_handle(1);
  let _ = h.watch("/b", Interest::all()).await;
}

/// Regression (the LIVE-alias guarantee must not ride on the bounded window): the window evicts by
/// ARM HISTORY, not by live-root population, so a root held live across more than
/// [`super::OBSERVED_HANDLE_HISTORY`] intervening arms ages out of it while it is still recorded.
/// A later arm reusing THAT handle is the violation this tripwire most exists to catch — the live
/// alias `commit_watch` would let overwrite the reverse handle mapping, stranding `/live` and
/// misrouting its events into the new root. Peak live roots here is TWO; only the arm count is
/// large, so nothing about this owner's resource use excuses the miss.
///
/// Fail-on-old: with the window as the tripwire's only input, the churn has evicted handle 1, so
/// `observe` reports it unseen, the assert passes, and the reuse commits silently — no panic, and
/// `#[should_panic]` fails the cell.
#[tokio::test]
#[should_panic(expected = "already observed by this owner")]
#[cfg_attr(
  not(debug_assertions),
  ignore = "the debug_assert tripwire is compiled out in release builds"
)]
#[cfg(debug_assertions)]
async fn rearm_reusing_a_live_handle_aged_out_of_the_window_trips_the_tripwire() {
  let mut h = Harness::new();

  // Handle 1, and it stays live for the whole cell — never unwatched, never retired.
  let _live = h
    .watch("/live", Interest::all())
    .await
    .expect("watch the root that stays live");

  // Churn disjoint roots past the window's capacity. Each cycle arms a fresh handle and retires it
  // again, so live roots never exceed two — but the arm history alone evicts handle 1.
  for i in 0..=super::OBSERVED_HANDLE_HISTORY {
    let sub = h
      .watch(&format!("/churn{i}"), Interest::all())
      .await
      .expect("watch a disjoint root");
    h.unwatch(sub).expect("unwatch it again");
  }

  // A disjoint newcomer whose arm REUSES the still-live handle 1 — a generation-unique
  // `Source::Handle` violation. The subsumer still records `/live` under handle 1, so the arm choke
  // point's live-index check trips regardless of what the window has evicted.
  h.owner.source.reuse_next_arm_handle(1);
  let _ = h.watch("/newcomer", Interest::all()).await;
}

/// The observed-handle tripwire is a bounded WINDOW, not a lifetime ledger: ordinary
/// watch/unwatch churn of disjoint roots must leave the debug build's history bounded by
/// [`super::OBSERVED_HANDLE_HISTORY`], not by the number of arms the owner has ever performed.
/// A debug or staging soak run to expose production leaks must not carry a historical-growth
/// source of its own.
///
/// The second half is what keeps the bound from being free: the window still holds its capacity
/// after the churn, so the most recent arms — where a handle-recycling source shows up — are all
/// still covered.
#[tokio::test]
#[cfg_attr(
  not(debug_assertions),
  ignore = "the observed-handle window is compiled out in release builds"
)]
#[cfg(debug_assertions)]
async fn observed_handle_history_is_bounded_by_its_window_not_by_lifetime_arms() {
  let mut h = Harness::new();

  // Churn disjoint roots: each watch arms a fresh handle, each unwatch empties its root and
  // retires it. Every live root and delivery obligation is reclaimed correctly throughout — the
  // only thing that could grow is the history itself.
  let churn = super::OBSERVED_HANDLE_HISTORY + 64;
  for i in 0..churn {
    let sub = h
      .watch(&format!("/r{i}"), Interest::all())
      .await
      .expect("watch a disjoint root");
    h.unwatch(sub).expect("unwatch it again");
  }
  assert_eq!(
    h.owner.source.arm_count(),
    churn,
    "every cycle armed a fresh handle, so the history saw every one of them"
  );
  assert_eq!(
    h.owner.observed_handles.len(),
    super::OBSERVED_HANDLE_HISTORY,
    "the history is capped at its window — never the {churn} arms this owner performed"
  );
}

/// The ARM-choke-point liveness close, widen path: a `Widen` whose **wider** arm is
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

  let created_only = Interest::none().with_created();
  h.watch("/a", created_only).await.expect("watch /a");

  let removed_only = Interest::none().with_removed();
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
    removed_only.admits(&EventKind::<OsString>::Removed),
    "a removal under /a/b is admitted by the covered sub's gate — not silently lost"
  );
  assert!(
    !created_only.admits(&EventKind::<OsString>::Removed),
    "…and the gate is genuinely narrowing (a created-only gate would drop it)"
  );
}

/// the public command mailbox is BOUNDED — a submission past
/// `command_capacity` awaits ADMISSION while the owner is parked inside a
/// caller-bounded reconcile, so poll-then-cancel callers can never grow the queue (a
/// cancel before admission leaves nothing queued). Race-free negative window: the
/// gated arm parks the owner, capacity 1 is filled by the second watch, and this test
/// controls both the gate and the only submitters.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_admission_backpressures_when_the_mailbox_is_full() {
  struct GatedArmSource {
    inner: FakeSource,
    /// Each `arm` awaits one token before delegating — the owner parks mid-reconcile
    /// until the test feeds it.
    gate: async_channel::Receiver<()>,
  }

  impl Source<OsString> for GatedArmSource {
    type Handle = u32;

    fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
      self.inner.canonicalize_key(key)
    }

    async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
      let _ = self.gate.recv().await;
      self.inner.arm(key).await
    }

    fn disarm(&mut self, handle: u32) {
      self.inner.disarm(handle);
    }

    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      // Keep the source alive: the FakeSource's instant `None` would drain the owner
      // before the watches under test even arrive.
      core::future::pending().await
    }

    fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
      self.inner.root_key(handle)
    }
  }

  let (gate_tx, gate_rx) = async_channel::unbounded::<()>();
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> = super::Tributaries::with_source(
    GatedArmSource {
      inner: FakeSource::new(),
      gate: gate_rx,
    },
    TributariesOptions::new().with_command_capacity(std::num::NonZeroUsize::new(1).unwrap()),
  );

  // Watch 1 is consumed by the owner, which parks inside the gated arm. Watch 2 then
  // fills the capacity-1 mailbox. Watch 3's submission must AWAIT admission.
  let w1 = {
    let w = w.clone();
    tokio::spawn(async move { w.watch(key("/one"), (), WatchOptions::new()).await })
  };
  let w2 = {
    let w = w.clone();
    tokio::spawn(async move { w.watch(key("/two"), (), WatchOptions::new()).await })
  };
  // Deterministic fill order: give the owner and the two submitters time to reach
  // their steady state (owner parked in arm; mailbox holding exactly one command).
  tokio::time::sleep(std::time::Duration::from_millis(200)).await;
  let w3 = {
    let w = w.clone();
    tokio::spawn(async move { w.watch(key("/three"), (), WatchOptions::new()).await })
  };
  tokio::time::sleep(std::time::Duration::from_millis(300)).await;
  assert!(
    !w3.is_finished(),
    "the third watch awaits mailbox ADMISSION while the owner is parked and the \
     capacity-1 mailbox is full — it must not resolve, and nothing queues"
  );

  // Open the gate for all three arms: every submission admits, reconciles, resolves.
  for _ in 0..3 {
    gate_tx.send(()).await.expect("feed the arm gate");
  }
  for handle in [w1, w2, w3] {
    tokio::time::timeout(std::time::Duration::from_secs(20), handle)
      .await
      .expect("watch resolves once the owner unparks")
      .expect("task")
      .expect("watch succeeds");
  }
}

/// `parts()`: the caller owns the spawn — the same construction as `with_source`
/// minus the detach. Spawning the returned driver future manually drives the full
/// watch → unwatch → close lifecycle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parts_future_drives_the_watcher_when_caller_spawned() {
  struct AliveSource(FakeSource);
  impl Source<OsString> for AliveSource {
    type Handle = u32;
    fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
      self.0.canonicalize_key(key)
    }
    async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
      self.0.arm(key).await
    }
    fn disarm(&mut self, handle: u32) {
      self.0.disarm(handle);
    }
    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      // Keep the source alive (FakeSource's instant `None` would drain the owner).
      core::future::pending().await
    }
    fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
      self.0.root_key(handle)
    }
  }

  let (w, driver): (super::Tributaries<OsString, (), TokioRuntime, u32>, _) =
    super::Tributaries::parts(AliveSource(FakeSource::new()), TributariesOptions::new());
  let driver = tokio::spawn(driver);

  let sub = w
    .watch(key("/a"), (), WatchOptions::new())
    .await
    .expect("watch through the caller-spawned driver");
  assert!(w.view().is_watched(&key("/a")), "the read plane published");
  w.unwatch(sub).await.expect("unwatch");
  w.close()
    .await
    .expect("close resolves — the caller-spawned driver serviced it");
  tokio::time::timeout(Duration::from_secs(5), driver)
    .await
    .expect("the driver future completes after close")
    .expect("driver task");
}

/// `parts()` caveat two, pinned: DROPPING the un-spawned driver future is hard
/// teardown — the owner's drop publishes an empty read plane and closes every channel,
/// so calls surface Closed/Stopped rather than hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_parts_future_is_hard_teardown() {
  let (mut w, driver): (super::Tributaries<OsString, (), TokioRuntime, u32>, _) =
    super::Tributaries::parts(FakeSource::new(), TributariesOptions::new());
  drop(driver);

  let err = w
    .watch(key("/a"), (), WatchOptions::new())
    .await
    .expect_err("watch against a dropped driver surfaces Closed");
  assert!(matches!(err, WatchError::Closed), "got {err:?}");
  assert!(
    !w.view().is_watched(&key("/a")),
    "the read plane is empty-and-honest after the hard teardown"
  );
  assert!(w.next().await.is_none(), "the event stream is ended");
}

/// dropping the `parts()` driver MID-ARM cancels the in-flight reconcile at
/// its await point — and the SOURCE drops with the owner, which is the contract's
/// reclamation boundary: a conforming source's `Drop` tears down whatever external
/// effect the cancelled arm had initiated (`grow` shares the same await surface). The
/// instrumented source proves both halves: the arm was genuinely in flight when the
/// driver dropped, and the source's Drop ran promptly to reclaim.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_parts_future_mid_arm_drops_the_source_for_reclamation() {
  struct InstrumentedSource {
    inner: FakeSource,
    /// Closed when an arm is entered — the test's proof the reconcile was in flight.
    arm_entered: Option<futures_channel::oneshot::Sender<()>>,
    /// Never yields: holds the owner at the arm await point.
    gate: async_channel::Receiver<()>,
    /// Set by Drop — the reclamation boundary observed.
    dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
  }
  impl Drop for InstrumentedSource {
    fn drop(&mut self) {
      // A real transport would tear down its external watches here (the contract's
      // cancellation clause); the flag stands in for that teardown.
      self
        .dropped
        .store(true, std::sync::atomic::Ordering::Release);
    }
  }
  impl Source<OsString> for InstrumentedSource {
    type Handle = u32;
    fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
      self.inner.canonicalize_key(key)
    }
    async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
      if let Some(entered) = self.arm_entered.take() {
        let _ = entered.send(());
      }
      // Park forever: the cancellation arrives as this future being dropped.
      let _ = self.gate.recv().await;
      self.inner.arm(key).await
    }
    fn disarm(&mut self, handle: u32) {
      self.inner.disarm(handle);
    }
    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      core::future::pending().await
    }
    fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
      self.inner.root_key(handle)
    }
  }

  let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let (entered_tx, entered_rx) = futures_channel::oneshot::channel();
  let (_gate_tx, gate_rx) = async_channel::unbounded::<()>();
  let (w, driver): (super::Tributaries<OsString, (), TokioRuntime, u32>, _) =
    super::Tributaries::parts(
      InstrumentedSource {
        inner: FakeSource::new(),
        arm_entered: Some(entered_tx),
        gate: gate_rx,
        dropped: std::sync::Arc::clone(&dropped),
      },
      TributariesOptions::new(),
    );
  let driver = tokio::spawn(driver);

  // Submit a watch and wait until the owner is provably INSIDE the gated arm.
  let watching = {
    let w = w.clone();
    tokio::spawn(async move { w.watch(key("/a"), (), WatchOptions::new()).await })
  };
  entered_rx
    .await
    .expect("the arm was entered — reconcile in flight");

  // Cancel the driver mid-arm.
  driver.abort();
  let _ = driver.await;

  // The source dropped WITH the owner — the reclamation boundary fired...
  assert!(
    dropped.load(std::sync::atomic::Ordering::Acquire),
    "the source's Drop ran when the mid-arm driver was cancelled"
  );
  // ...and the caller's in-flight watch surfaces Closed rather than hanging.
  let err = tokio::time::timeout(Duration::from_secs(5), watching)
    .await
    .expect("the watch settles")
    .expect("task")
    .expect_err("a cancelled owner surfaces Closed to the in-flight watch");
  assert!(matches!(err, WatchError::Closed), "got {err:?}");
}

/// The mid-arm twin for `grow`: dropping the `parts()` driver MID-GROW cancels the in-flight
/// covered-outside reconcile at its await point — which, grow-before-commit (R1), is now
/// PRE-commit, so the unwind strands nothing: no subscription was committed, no grant minted to
/// orphan, and the pending plan drops with the owner. The SOURCE drops with the owner too — the
/// contract's reclamation boundary for whatever external re-arm the cancelled grow had initiated
/// — and the caller's in-flight watch surfaces Closed rather than hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_parts_future_mid_grow_drops_the_source_for_reclamation() {
  struct GrowGatedSource {
    inner: FakeSource,
    /// Closed when a grow is entered — the test's proof the covered-outside reconcile was
    /// parked at the PRE-commit grow await when the driver dropped.
    grow_entered: Option<futures_channel::oneshot::Sender<()>>,
    /// Never yields: holds the owner at the grow await point.
    gate: async_channel::Receiver<()>,
    /// Set by Drop — the reclamation boundary observed.
    dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
  }
  impl Drop for GrowGatedSource {
    fn drop(&mut self) {
      self
        .dropped
        .store(true, std::sync::atomic::Ordering::Release);
    }
  }
  impl Source<OsString> for GrowGatedSource {
    type Handle = u32;
    fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
      self.inner.canonicalize_key(key)
    }
    async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
      self.inner.arm(key).await
    }
    fn disarm(&mut self, handle: u32) {
      self.inner.disarm(handle);
    }
    fn set_cover(&mut self, handle: u32, retained: &[Vec<OsString>]) {
      self.inner.set_cover(handle, retained);
    }
    async fn grow(&mut self, handle: u32, retained: &[Vec<OsString>]) -> Result<(), WatchError> {
      if let Some(entered) = self.grow_entered.take() {
        let _ = entered.send(());
      }
      // Park forever: the cancellation arrives as this future being dropped.
      let _ = self.gate.recv().await;
      self.inner.grow(handle, retained).await
    }
    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      core::future::pending().await
    }
    fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
      self.inner.root_key(handle)
    }
  }

  let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let (entered_tx, entered_rx) = futures_channel::oneshot::channel();
  let (_gate_tx, gate_rx) = async_channel::unbounded::<()>();
  let (w, driver): (super::Tributaries<OsString, (), TokioRuntime, u32>, _) =
    super::Tributaries::parts(
      GrowGatedSource {
        inner: FakeSource::new(),
        grow_entered: Some(entered_tx),
        gate: gate_rx,
        dropped: std::sync::Arc::clone(&dropped),
      },
      TributariesOptions::new(),
    );
  let driver = tokio::spawn(driver);

  // Build the covered-outside state through the real loop: /a/b, widen /a, unwatch the widening
  // sub — the wide root's cover narrows to {/a/b} (prune + record), and no grow has run yet.
  // (The widen's dominating Rescan sits harmlessly in the event channel; nothing here drains it.)
  let _s_b = w
    .watch(key("/a/b"), (), WatchOptions::new())
    .await
    .expect("watch /a/b");
  let s_a = w
    .watch(key("/a"), (), WatchOptions::new())
    .await
    .expect("watch /a widens");
  w.unwatch(s_a).await.expect("unwatch the widening /a");

  // Watch /a/c: Covered-outside → the owner parks INSIDE the gated grow, before any commit.
  let watching = {
    let w = w.clone();
    tokio::spawn(async move { w.watch(key("/a/c"), (), WatchOptions::new()).await })
  };
  entered_rx
    .await
    .expect("the grow was entered — the covered-outside reconcile is parked pre-commit");

  // Cancel the driver mid-grow.
  driver.abort();
  let _ = driver.await;

  // The source dropped WITH the owner — the reclamation boundary fired...
  assert!(
    dropped.load(std::sync::atomic::Ordering::Acquire),
    "the source's Drop ran when the mid-grow driver was cancelled"
  );
  // ...and the caller's in-flight watch surfaces Closed rather than hanging (nothing was
  // committed, so there is no grant and no subscription to strand).
  let err = tokio::time::timeout(Duration::from_secs(5), watching)
    .await
    .expect("the watch settles")
    .expect("task")
    .expect_err("a cancelled owner surfaces Closed to the in-flight watch");
  assert!(matches!(err, WatchError::Closed), "got {err:?}");
  assert!(
    !w.view().is_watched(&key("/a/c")),
    "the cancelled covered-outside watch was never published"
  );
}

/// `parts_local()`: the `!Send` construction path end-to-end — a genuinely thread-local
/// source (`Rc` state, implementing [`LocalSource`](crate::source::LocalSource) directly,
/// so no [`Source`] impl could be written for it) drives the full watch → raw event →
/// attributed delivery → close lifecycle, with the driver future polled on the thread
/// that owns the source (a tokio `LocalSet` — the "poll it where the source lives"
/// caveat) while the handle plane is used exactly as under `parts()`.
#[tokio::test]
async fn parts_local_drives_a_thread_local_source_end_to_end() {
  use std::{
    cell::{Cell, RefCell},
    rc::Rc,
  };

  use crate::source::LocalSource;

  /// A thread-local source: handle minting and the live-root map ride `Rc`s, so `Self`
  /// is `!Send` and every `async fn` future (capturing `&mut Self`) is too.
  struct RcSource {
    next_handle: Rc<Cell<u32>>,
    live: Rc<RefCell<HashMap<u32, Vec<OsString>>>>,
    /// Raw changes the test feeds in; `recv` is cancel-safe, satisfying the `next`
    /// contract, and parks while the test holds the sender (the driver exits via
    /// `close`, not stream end).
    events: async_channel::Receiver<SourceEvent<OsString, u32>>,
  }

  impl LocalSource<OsString> for RcSource {
    type Handle = u32;

    fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
      Ok(key.to_vec())
    }

    async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
      let handle = self.next_handle.get() + 1;
      self.next_handle.set(handle);
      self.live.borrow_mut().insert(handle, key.to_vec());
      Ok(Armed::new(handle, key.to_vec()))
    }

    fn disarm(&mut self, handle: u32) {
      self.live.borrow_mut().remove(&handle);
    }

    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      self.events.recv().await.ok()
    }

    fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
      self.live.borrow().get(&handle).cloned()
    }
  }

  let (event_tx, event_rx) = async_channel::unbounded();
  let source = RcSource {
    next_handle: Rc::new(Cell::new(0)),
    live: Rc::new(RefCell::new(HashMap::new())),
    events: event_rx,
  };
  let (mut w, driver): (super::Tributaries<OsString, (), TokioRuntime, u32>, _) =
    super::Tributaries::parts_local(source, TributariesOptions::new());

  let local = tokio::task::LocalSet::new();
  local
    .run_until(async move {
      let driver = tokio::task::spawn_local(driver);

      let sub = w
        .watch(key("/a"), (), WatchOptions::new())
        .await
        .expect("watch through the locally-polled driver");
      assert!(w.view().is_watched(&key("/a")), "the read plane published");

      // Feed a raw change under the armed root (the fixture mints handle 1 first).
      event_tx
        .send(source_modified(1, "/a/file.txt", 1))
        .await
        .expect("feed the thread-local source");
      let event = tokio::time::timeout(Duration::from_secs(10), w.next())
        .await
        .expect("delivery is prompt")
        .expect("the change is delivered");
      assert_eq!(
        event.subscription(),
        sub,
        "attributed to the covering subscription"
      );
      assert!(event.kind().is_modified(), "the kind survives the fan-out");

      w.close().await.expect("close resolves on the local driver");
      tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("the driver future completes after close")
        .expect("driver task");
    })
    .await;
}

/// the coalescer's buffered-entry cap engages the EXISTING loss-accounting
/// path — a high-cardinality burst past the cap sheds the subscription to a dominating
/// parked Rescan (`park_rescan`: shed epoch + `needs_rescan` merge + coalescer purge),
/// so debounce keeps the crate's bounded-memory guarantee with no silent loss.
#[tokio::test]
async fn coalescer_overflow_sheds_to_a_dominating_parked_rescan() {
  // Never-settling windows: nothing drains on its own, so the buffer would grow one
  // entry per distinct key without the cap.
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(7200))
    .with_max_buffered(2);
  let mut h = Harness::with_coalescer(Some(Coalescer::new(Some(cfg))));
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  h.owner.epochs.stamp(sub, Epoch::new(3));

  // Two distinct keys fill the cap; the third OVERFLOWS: the coalescer sheds the
  // subscription instead of growing.
  h.owner.fan_out_and_push(&source_modified(1, "/a/k0", 4));
  h.owner.fan_out_and_push(&source_modified(1, "/a/k1", 5));
  assert!(
    h.owner.needs_rescan.is_empty(),
    "under the cap nothing is shed"
  );
  h.owner.fan_out_and_push(&source_modified(1, "/a/k2", 6));

  // The shed landed in the parked-Rescan debt (dominating epoch) and the purge freed
  // the subscription's buffered entries — bounded memory, accounted loss.
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the overflowed subscription is owed a dominating parked Rescan"
  );
  let parked_epoch = h.owner.needs_rescan.get(&sub).expect("parked").epoch;
  assert!(
    parked_epoch >= Epoch::new(6),
    "the shed Rescan dominates the purged buffered epochs (got {parked_epoch:?})"
  );

  // The flush delivers the dominating Rescan to the consumer — the loss is announced.
  h.owner.flush_pending_rescans();
  let delivered = h.drain();
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == sub && e.kind().is_rescan()),
    "the parked Rescan flushes to the consumer"
  );
}

/// Per-subscription debounce (design §6): two subscriptions over ONE root,
/// one inheriting the watcher-global settle policy, one watched with `Debounce::Off` —
/// one raw burst delivers every event to the raw subscription undelayed while the
/// settled sibling holds a single collapsed entry.
#[tokio::test]
async fn per_sub_off_delivers_raw_while_inherit_sibling_settles() {
  // Never-settling global windows: the settled side deterministically holds, no timers.
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(7200));
  let mut h = Harness::with_coalescer(Some(Coalescer::new(Some(cfg))));
  let settled = h.watch("/a", Interest::all()).await.expect("watch /a");
  let raw = h
    .watch_with("/a", WatchOptions::new().with_debounce(Debounce::Off))
    .await
    .expect("watch /a raw");

  // One three-write burst to a single path fans out to BOTH covering subscriptions.
  for epoch in 1..=3 {
    h.owner.fan_out_and_push(&source_modified(1, "/a/f", epoch));
  }

  let delivered = h.drain();
  let raw_events: Vec<_> = delivered
    .iter()
    .filter(|e| e.subscription() == raw)
    .collect();
  assert_eq!(
    raw_events.len(),
    3,
    "the Off subscription sees every raw event, undelayed and uncollapsed"
  );
  assert!(
    raw_events.windows(2).all(|w| w[0].epoch() < w[1].epoch()),
    "…in admission (= epoch) order"
  );
  assert!(
    !delivered.iter().any(|e| e.subscription() == settled),
    "the inheriting sibling's burst is still settling — nothing delivered yet"
  );

  // The settled sibling holds exactly its ONE collapsed entry: the teardown flush
  // releases a single event carrying the newest stamp.
  h.owner.drain_owed_once();
  let tail = h.drain();
  assert_eq!(
    tail.len(),
    1,
    "the settled sibling collapsed the burst to one"
  );
  assert_eq!(tail[0].subscription(), settled);
  assert_eq!(
    tail[0].epoch(),
    Epoch::new(3),
    "the newest observation's stamp"
  );
}

/// The lazy-instantiation matrix, `Off` half: `Debounce::Off` when the watcher-global
/// debounce is off too is a NO-OP — events already pass through untouched, so no
/// coalescer is instantiated (the zero-cost claim).
#[tokio::test]
async fn off_with_global_none_never_instantiates_the_coalescer() {
  let mut h = Harness::new();
  let sub = h
    .watch_with("/a", WatchOptions::new().with_debounce(Debounce::Off))
    .await
    .expect("watch /a");
  assert!(
    h.owner.coalescer.is_none(),
    "Off atop a disabled global debounce instantiates nothing"
  );

  h.owner.fan_out_and_push(&source_modified(1, "/a/f", 0));
  let delivered = h.drain();
  assert_eq!(delivered.len(), 1, "events pass straight through");
  assert_eq!(delivered[0].subscription(), sub);
}

/// The lazy-instantiation matrix, `Custom` half: a `Debounce::Custom` commit when the
/// watcher-global debounce is off instantiates the coalescer lazily with NO default —
/// the override settles while an inheriting sibling keeps passing through raw.
#[tokio::test]
async fn custom_with_global_none_lazily_instantiates_the_coalescer() {
  let mut h = Harness::new();
  assert!(h.owner.coalescer.is_none(), "nothing opted in yet");

  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(7200));
  let custom = h
    .watch_with(
      "/a",
      WatchOptions::new().with_debounce(Debounce::Custom(cfg)),
    )
    .await
    .expect("watch /a"); // root 1
  assert!(
    h.owner.coalescer.is_some(),
    "the first Custom commit lazily instantiated the coalescer"
  );
  let inherit = h.watch("/b", Interest::all()).await.expect("watch /b"); // root 2

  h.owner.fan_out_and_push(&source_modified(1, "/a/f", 0)); // custom → settles
  h.owner.fan_out_and_push(&source_modified(2, "/b/g", 0)); // inherit-of-nothing → raw

  let delivered = h.drain();
  assert_eq!(
    delivered.len(),
    1,
    "only the inheriting sibling's event passes through"
  );
  assert_eq!(delivered[0].subscription(), inherit);
  assert!(
    delivered[0].kind().is_modified(),
    "…as the raw delivery itself, not a Rescan"
  );
  let _ = custom;
  assert!(
    h.owner
      .coalescer
      .as_ref()
      .and_then(Coalescer::next_deadline)
      .is_some(),
    "the Custom subscription's delta is held settling"
  );
}

/// The forget-vs-drop regression at the driver seam (design §6, the subtle
/// cleanup split): a WIDEN re-points a live subscription — its buffered pre-widen deltas
/// are dropped, but its `Debounce::Custom` policy survives, so post-widen events on the
/// wider root still settle. An overflow park likewise keeps the policy; only release
/// (unwatch) and terminal retirement forget it.
#[tokio::test]
async fn widen_repoint_keeps_the_custom_policy_release_forgets_it() {
  let mut h = Harness::new();
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(7200));
  let sb = h
    .watch_with(
      "/a/b",
      WatchOptions::new().with_debounce(Debounce::Custom(cfg)),
    )
    .await
    .expect("watch /a/b"); // root 1, lazily instantiates the coalescer

  // A pre-widen delta buffers under the Custom policy.
  h.owner.fan_out_and_push(&source_modified(1, "/a/b/f", 0));
  assert!(h.drain().is_empty(), "the pre-widen delta is settling");

  // Widen to /a: sb re-points onto the wider root — the coalescer purge is
  // drop_subscription (buffers only), NOT forget (policy retained).
  let sa = h.watch("/a", Interest::all()).await.expect("widen to /a"); // root 2
  let delivered = h.drain();
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == sb && e.is_rescan()),
    "the re-pointed subscription received its dominating widen Rescan"
  );
  assert!(
    !delivered
      .iter()
      .any(|e| e.subscription() == sb && !e.is_rescan()),
    "the purged pre-widen delta never delivers (dominated by the Rescan)"
  );
  let coalescer = h.owner.coalescer.as_ref().expect("coalescer live");
  assert!(
    coalescer.has_policy(sb),
    "the widen re-point KEPT the Custom policy — the subscription is still live"
  );

  // THE regression assert: a post-widen event on the WIDER root fans out to BOTH
  // subscribers — the widener (inheriting the disabled default: raw pass-through) and
  // the re-pointed sb, whose retained Custom policy must still settle its copy.
  h.owner.fan_out_and_push(&source_modified(2, "/a/b/g", 0));
  let delivered = h.drain();
  assert!(
    !delivered.iter().any(|e| e.subscription() == sb),
    "sb's post-widen delta is buffered under the retained Custom policy, not raw"
  );
  assert!(
    delivered.iter().any(|e| e.subscription() == sa),
    "…while the inheriting widener's copy passes through raw (per-sub isolation)"
  );

  // The overflow park keeps it too…
  h.owner.park_rescan(sb);
  let coalescer = h.owner.coalescer.as_ref().expect("coalescer live");
  assert!(
    coalescer.has_policy(sb),
    "an overflow park purges buffers but keeps the policy"
  );

  // …while release (unwatch) FORGETS it with the subscription.
  h.unwatch(sb).expect("unwatch");
  let coalescer = h.owner.coalescer.as_ref().expect("coalescer live");
  assert!(
    !coalescer.has_policy(sb),
    "release_subscription forgets the retired subscription's policy"
  );
}

/// Terminal retirement (root death) FORGETS the dead subscription's policy — the other
/// half of the forget split, so a retired subscription leaks no policy entry.
#[tokio::test]
async fn terminal_retirement_forgets_the_policy() {
  let mut h = Harness::new();
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(7200));
  let sub = h
    .watch_with(
      "/a",
      WatchOptions::new().with_debounce(Debounce::Custom(cfg)),
    )
    .await
    .expect("watch /a"); // root 1
  assert!(
    h.owner
      .coalescer
      .as_ref()
      .expect("coalescer")
      .has_policy(sub),
    "the Custom policy is registered at commit"
  );

  h.owner.source.kill_root(1);
  h.owner.retire_root_with_terminal_rescan(1);
  assert!(
    !h.owner
      .coalescer
      .as_ref()
      .expect("coalescer")
      .has_policy(sub),
    "terminal retirement forgets the dead subscription's policy"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "…while its owed terminal Rescan is still parked (unaffected by the forget)"
  );
}

/// a retire-and-rewatch cycle against a FULL channel is structurally
/// bounded — terminal parked Rescans retained past their subscriptions' retirement
/// count as RETIRED debt, and watch admission is refused at the cap
/// ([`WatchError::RescanBacklog`]), breaking the only loop that grows it. Draining the
/// owed Rescans (the flush frees entries) restores admission. Capacity-1 channel, the
/// exact repro shape.
#[tokio::test]
async fn retire_rewatch_cycle_is_bounded_by_the_retired_debt_gate() {
  let mut h = Harness::bounded(1);

  // Fill the single event slot so every terminal Rescan parks instead of delivering.
  let plug = h.watch("/plug", Interest::all()).await.expect("watch plug");
  h.owner.epochs.stamp(plug, Epoch::new(1));
  h.owner.source.kill_root(1);
  h.owner.retire_root_with_terminal_rescan(1);
  h.owner.flush_pending_rescans(); // occupies the one slot with plug's terminal Rescan

  // Cycle: watch a fresh key, kill its root, retire — each round force-removes the sub
  // while RETAINING its parked terminal entry (the retired debt the gate counts).
  let mut cycles = 0usize;
  loop {
    match h.watch(&format!("/cycle{cycles}"), Interest::all()).await {
      Ok(_) => {
        // FakeSource handles are monotone: this watch armed handle cycles+2 (plug took 1).
        let handle = u32::try_from(cycles).expect("small") + 2;
        h.owner.source.kill_root(handle);
        h.owner.retire_root_with_terminal_rescan(handle);
        cycles += 1;
        assert!(
          cycles
            <= super::Owner::<OsString, (), TokioRuntime, FakeSource>::RETIRED_RESCAN_DEBT_LIMIT
              + 1,
          "the gate must refuse before the debt exceeds its cap"
        );
      }
      Err(WatchError::RescanBacklog) => break,
      Err(other) => panic!("unexpected watch error: {other:?}"),
    }
  }
  let retired = h
    .owner
    .needs_rescan
    .keys()
    .filter(|&&sub| h.owner.subsumer.subscription_key(sub).is_none())
    .count();
  assert!(
    retired <= super::Owner::<OsString, (), TokioRuntime, FakeSource>::RETIRED_RESCAN_DEBT_LIMIT,
    "retired debt is capped (got {retired})"
  );

  // Drain the owed Rescans: each flush frees entries, restoring admission.
  loop {
    h.owner.flush_pending_rescans();
    if h.drain().is_empty() {
      break;
    }
  }
  h.watch("/after-drain", Interest::all())
    .await
    .expect("admission restored once the retired debt drained");
}

/// a BATCH conversion — one root death retiring an entire covered cohort at
/// once — legitimately stands ABOVE the retired-debt threshold (bounded by the caller's
/// own peak concurrent subscriptions, state it was already paying for), and the gate
/// then refuses the replenishing watch, so the live-plus-retired total can never grow
/// past peak-live-plus-threshold. Draining restores admission.
#[tokio::test]
async fn batch_retirement_stands_above_the_threshold_but_cannot_replenish() {
  const COHORT: usize = 1200; // deliberately above RETIRED_RESCAN_DEBT_LIMIT (1024)
  let mut h = Harness::bounded(1);

  // A covered cohort: the first watch arms the root, the rest subsume onto it — all
  // admitted while retired debt is zero (the batch-conversion bypass shape).
  for _ in 0..COHORT {
    h.watch("/batch", Interest::all())
      .await
      .expect("cohort watch admitted under a zero retired count");
  }

  // One root death converts the whole cohort 1:1 into retired parked debt.
  h.owner.source.kill_root(1);
  h.owner.retire_root_with_terminal_rescan(1);
  let retired = h
    .owner
    .needs_rescan
    .keys()
    .filter(|&&sub| h.owner.subsumer.subscription_key(sub).is_none())
    .count();
  assert_eq!(
    retired, COHORT,
    "the batch stands above the threshold — bounded by the caller's own peak cohort"
  );

  // Replenishment is refused: the gate sees the retired debt at/above the threshold.
  let refused = h.watch("/fresh", Interest::all()).await;
  assert!(
    matches!(refused, Err(WatchError::RescanBacklog)),
    "admission refused while retired debt sits at/above the threshold (got {refused:?})"
  );

  // Drain the owed terminal Rescans (capacity-1: one flush offer per drained slot —
  // also exercising the cursor-resumed pass); admission then returns.
  loop {
    h.owner.flush_pending_rescans();
    if h.drain().is_empty() {
      break;
    }
  }
  h.watch("/fresh", Interest::all())
    .await
    .expect("admission restored once the retired debt drained");
}

/// each flush pass visits a ROOM-PROPORTIONAL number of candidates — never
/// the whole parked map. Capacity-1 drain over a 64-entry retired cohort: every pass
/// visits at most two keys (the one delivered offer plus the probe that found the
/// channel full or the map empty), pinned by the test-only visited counter.
#[tokio::test]
async fn flush_pass_work_is_room_proportional_not_map_proportional() {
  const COHORT: usize = 64;
  let mut h = Harness::bounded(1);
  for _ in 0..COHORT {
    h.watch("/cohort", Interest::all())
      .await
      .expect("cohort watch");
  }
  h.owner.source.kill_root(1);
  h.owner.retire_root_with_terminal_rescan(1);

  // Drain slot-by-slot: each pass must do O(room) work, not O(map).
  let mut delivered = 0usize;
  while delivered < COHORT {
    h.owner.flush_pending_rescans();
    assert!(
      h.owner.last_flush_visited <= 2,
      "a capacity-1 pass visits at most the delivered offer plus one probe \
       (visited {} with {} entries left)",
      h.owner.last_flush_visited,
      COHORT - delivered
    );
    let batch = h.drain();
    if batch.is_empty() {
      break;
    }
    delivered += batch.len();
  }
  assert_eq!(delivered, COHORT, "every owed terminal Rescan drained");
  assert!(h.owner.needs_rescan.is_empty(), "no residue");
}

/// an ALL-UNCLAIMED retired cohort costs the flush NOTHING — the debt lives
/// in the suppressed partition, the offerable map stays empty (so the 25 ms retry timer
/// never arms for it), and every flush pass visits zero candidates instead of probing
/// the whole cohort each tick. Claiming one grant moves exactly its entry into the
/// offerable map and it delivers.
#[tokio::test]
async fn unclaimed_retired_cohort_costs_the_flush_nothing() {
  const COHORT: usize = 64;
  let mut h = Harness::new();
  let mut subs = Vec::new();
  for _ in 0..COHORT {
    let sub = h.watch("/cohort", Interest::all()).await.expect("watch");
    h.owner.unclaimed.insert(sub); // model every grant as still in flight
    subs.push(sub);
  }
  h.owner.source.kill_root(1);
  h.owner.retire_root_with_terminal_rescan(1);

  assert!(
    h.owner.needs_rescan.is_empty(),
    "no offerable debt — the retry timer has nothing to arm for"
  );
  assert_eq!(
    h.owner.suppressed_rescan.len(),
    COHORT,
    "the whole cohort's terminal debt is suppressed apart"
  );
  h.owner.flush_pending_rescans();
  assert_eq!(
    h.owner.last_flush_visited, 0,
    "a flush pass over an all-unclaimed cohort visits ZERO candidates"
  );
  assert!(h.drain().is_empty(), "nothing delivered while unclaimed");

  // One claim lifts exactly one entry into the offerable map; it delivers.
  let claimed = subs[COHORT / 2];
  h.owner.apply_cleanup(super::Cleanup::Claim(claimed));
  assert_eq!(h.owner.needs_rescan.len(), 1, "the claim moved its entry");
  h.owner.flush_pending_rescans();
  let delivered = h.drain();
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == claimed && e.is_rescan()),
    "the claimed sub's terminal Rescan is delivered — suppression never became loss"
  );
  assert_eq!(
    h.owner.suppressed_rescan.len(),
    COHORT - 1,
    "the other suppressed entries remain, still costing nothing"
  );
}

/// a `Cleanup::Claim` that RACES the source-drain's atomic cut —
/// injected via the test-only window hook BETWEEN the emptiness observation and the
/// close, so the CUT BLOCK's own drain finds it — re-arms OFFERABLE debt that a full
/// event channel cannot take in the final best-effort pass. The drain must NOT return
/// then (the claimer holds a live Ok subscription; returning strands its terminal
/// Rescan forever): it takes the post-cut `continue`, the closed cleanup channel's
/// select arm disables on its first error instead of spinning, and the retry loop
/// delivers once the consumer drains the plug. Fail-on-old: the old cut block
/// returned unconditionally — the racer's Rescan was stranded and this test's second
/// recv would time out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raced_pre_cut_claim_is_delivered_not_stranded() {
  let mut h = Harness::bounded(1);
  // Plug the single event slot with an unrelated claimed sub's owed Rescan.
  let plug = h.watch("/plug", Interest::all()).await.expect("watch plug");
  h.owner.epochs.stamp(plug, Epoch::new(1));
  h.owner.source.kill_root(1);
  h.owner.retire_root_with_terminal_rescan(1);
  h.owner.flush_pending_rescans(); // the slot now holds plug's terminal Rescan

  // The racing sub: unclaimed grant, terminal-retired — its debt sits SUPPRESSED, so
  // the drain's emptiness predicate holds (offerable empty, cleanup empty)…
  let racer = h
    .watch("/racer", Interest::all())
    .await
    .expect("watch racer");
  h.owner.unclaimed.insert(racer);
  h.owner.source.kill_root(2);
  h.owner.retire_root_with_terminal_rescan(2);
  assert!(h.owner.needs_rescan.is_empty() && h.owner.suppressed_rescan.contains_key(&racer));

  // …and the claim lands IN THE WINDOW: the test injection point sends it
  // onto the still-open cleanup channel exactly between the drain's emptiness
  // observation and the atomic cut — so the CUT BLOCK ITSELF drains it, re-arms
  // offerable debt against the FULL channel, and must take the post-cut `continue`
  // rather than returning. (A claim merely pre-queued before the drain is drained at
  // the loop top and never reaches the cut — the path this regression exists to pin.)
  h.owner
    .test_pre_cut_claims
    .push(super::Cleanup::Claim(racer));

  let events = h.events.clone();
  let drain = tokio::spawn(async move {
    // Drive the drain to completion on its own task; it must not return while the
    // racer's offerable debt is undeliverable.
    h.owner.drain_owed_before_shutdown().await;
    h
  });
  tokio::time::sleep(Duration::from_millis(300)).await;
  assert!(
    !drain.is_finished(),
    "the drain stays in the retry loop while the raced claim's Rescan cannot be \
     delivered — returning here would strand a live Ok subscription"
  );

  // The consumer drains the plug; the retry tick then delivers the racer's Rescan and
  // the drain exits.
  let first = tokio::time::timeout(Duration::from_secs(5), events.recv())
    .await
    .expect("recv settles")
    .expect("plug Rescan");
  assert_eq!(first.subscription(), plug);
  let second = tokio::time::timeout(Duration::from_secs(10), events.recv())
    .await
    .expect("recv settles")
    .expect("racer Rescan");
  assert!(
    second.subscription() == racer && second.is_rescan(),
    "the raced claim's terminal Rescan IS delivered"
  );
  let h = tokio::time::timeout(Duration::from_secs(5), drain)
    .await
    .expect("the drain returns once the raced debt delivered")
    .expect("drain task");
  assert!(h.owner.needs_rescan.is_empty(), "nothing stranded");
}

/// [`Interest::admits`] gates a whole [`EventKind::Moved`] delivery under the `moved()`
/// interest bit (design §5) — directly constructible now that the umbrella owns the
/// source-neutral vocabulary with the move endpoint in-kind (the fs `MovedEvent`
/// payload had no public constructor, so this arm was previously untestable).
#[test]
fn interest_gates_a_whole_moved_by_the_moved_bit() {
  let moved = EventKind::Moved {
    from: key("/a/src/f"),
  };
  assert!(
    Interest::none().with_moved().admits(&moved),
    "a moved-interested gate admits the whole Moved"
  );
  assert!(
    Interest::all().admits(&moved),
    "the widest gate admits it too"
  );
  assert!(
    !Interest::none()
      .with_created()
      .with_removed()
      .admits(&moved),
    "a gate without the moved bit rejects the whole Moved — it is gated by moved(), \
     not by its endpoints' created/removed projections"
  );
}

/// End-to-end interest regression through the driver's fan-out (design §5): the gate
/// applies to the PROJECTED kind, so a created-only subscription receives a plain
/// `Created` AND a move-IN projection (a raw `Moved` whose destination alone it
/// covers, projected to `Created` before the gate) — but neither a `Modified` nor a
/// whole `Moved` (both endpoints covered, gated by the absent `moved` bit and never
/// smuggled through its endpoint projections).
#[tokio::test]
async fn created_only_subscription_receives_created_and_move_in_only() {
  let mut h = Harness::new();
  let sub = h
    .watch("/a", Interest::none().with_created())
    .await
    .expect("watch /a");

  h.owner.fan_out_and_push(&source_created(1, "/a/f", 0));
  h.owner.fan_out_and_push(&source_modified(1, "/a/f", 1));
  // Both endpoints under /a → projected to the whole Moved, rejected by the absent
  // moved bit.
  h.owner
    .fan_out_and_push(&source_moved(1, "/a/src", "/a/dst", 2));
  // Source OUTSIDE /a → projected to the move-in: a synthesized Created, admitted.
  h.owner
    .fan_out_and_push(&source_moved(1, "/outside/g", "/a/arrived", 3));

  let delivered = h.drain();
  assert_eq!(
    delivered.len(),
    2,
    "exactly the plain Created and the move-in projection are delivered, got {delivered:?}"
  );
  assert!(delivered.iter().all(|ev| ev.subscription() == sub));
  assert!(
    delivered[0].kind().is_created() && delivered[0].key() == key("/a/f").as_slice(),
    "the plain Created is admitted by the created bit"
  );
  assert!(
    delivered[1].kind().is_created() && delivered[1].key() == key("/a/arrived").as_slice(),
    "the move-in projection is a plain Created at the destination — admitted by the \
     created bit, not the moved bit"
  );
  assert!(
    delivered[1].move_from().is_none(),
    "the projection carries no move source — it is not a whole Moved"
  );
}

/// Two subscriptions at the SAME path with heterogeneous interest each keep their own gate
/// (design §4/§5): one root, both interests coexist in the side table.
#[tokio::test]
async fn equal_path_heterogeneous_interest() {
  let mut h = Harness::new();
  let created_only = Interest::none().with_created();
  let removed_only = Interest::none().with_removed();

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
  let err = h
    .watch("/b", Interest::all())
    .await
    .expect_err("a subsumption-changing canonical race aborts");
  assert!(
    err.is_canonical_race(),
    "the abort is the retryable canonical-race error, got {err:?}"
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

/// Regression (design §4, invariant I2 — the Covered-path canonicalization close):
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

/// Regression (the reject arm): a watch key the source CANNOT canonicalize (the fs
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

/// Regression (design §4, invariant I4): a watched root can surface its own
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
/// `Disjoint` → a FRESH source arm. The `Removed` is NOT separately fanned out — the
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

  // The `Removed` is NOT fanned out as an ordinary event: the coverage loss is owed
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

/// Regression (the STRUCTURAL close of the dead-root-coverage class): the owner loop
/// is command-biased, so a `watch` queued while a dead root's terminal event is still pending runs
/// FIRST — before `retire_if_dead` consumes that event and force-removes the root. Here the source
/// has forgotten the covering root ([`Source::root_key`] is `None`) but its terminal event has NOT
/// yet reached `retire_if_dead`, so the root is still recorded in the coverage index. A re-`watch`
/// of a path that dead root would cover must NOT be classified `Covered` against the
/// source-forgotten handle: `reconcile_watch` validates the covering root's liveness, retires the
/// dead root (owing its subscriber a dominating terminal `Rescan`), re-plans, and arms a FRESH live
/// root — so an event under that recreated root is delivered, not silently missed. Unlike the terminal-retirement
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

/// Regression (design §6 / backpressure doc, no silent loss): a dead root's terminal
/// coverage loss must reach the consumer as the durable, strictly-dominating terminal `Rescan` the
/// retire primitive parks — NOT as an ordinary `Removed` fanned through the debounce coalescer. The
/// earlier path fanned the non-`Rescan` terminal event through `fan_out_and_push`; with
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
  let mut h = Harness::with_coalescer(Some(Coalescer::new(Some(cfg))));
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
    .on_watch(key("/a"), (), WatchOptions::new(), reply)
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

/// The post-commit orphan window (design driver-golden doc, invariant I1): a `watch`
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
    .on_watch(key("/a"), (), WatchOptions::new(), reply)
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

  // Further overflow while parked is SUPPRESSED and collapses to the SAME parked slot — but
  // its epoch advances to keep strictly dominating the newly-dropped event. It must: f3 was
  // stamped at the high-water the first shed already reached, so a parked Rescan left at that
  // epoch merely TIES it, and a tie is not dominated — a conforming consumer would keep f3's
  // position and never re-read what f3 described.
  h.owner.try_emit(modified_event(sub, "/a/f3", 3));
  assert_eq!(
    h.owner.needs_rescan.len(),
    1,
    "repeated overflow collapses to one parked Rescan"
  );
  assert_eq!(
    h.owner.needs_rescan.get(&sub).map(|p| p.epoch),
    Some(Epoch::new(4)),
    "the parked epoch advances past the event this suppression just dropped"
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
  // fresh `shed_rescan`; for a source-overflow Rescan on a live root that is the same
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

/// Regression (design backpressure doc §8, epoch calibration / no silent loss): a **widen
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

  // the overflowed re-point Rescan parks at its OWN epoch (the repoint base 5), NOT a fresh
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
  assert_eq!(
    rescan.path(),
    Path::new("/a/b"),
    "it names the re-pointed subscription's own key, not the widened root"
  );
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

  // The park-unchanged payoff: the new root's raw-0 (epoch 5) is NOT below the delivered Rescan (epoch 5) — it
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

/// Sibling (the coalescer-buffered-delta variant of the re-point-epoch hole): when a
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
  let mut h = Harness::build(Some(Coalescer::new(Some(cfg))), Some(2));
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

/// Regression (design backpressure doc, no silent loss): while a subscription is PARKED
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

/// Regression (design backpressure doc, no silent loss): a failed widen whose subsumed
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

/// Regression (design backpressure doc, checklist #5): with debounce enabled a
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
  let mut h = Harness::build(Some(Coalescer::new(Some(cfg))), Some(1));
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

/// Regression (design backpressure doc, invariant II): after the source drains, the owner
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

/// Regression (design backpressure doc, no silent loss): a close that INTERRUPTS the
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

/// Regression — the close-time grant-resolution drain is bounded by the grants IN FLIGHT,
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
    h.owner.suppressed_rescan.contains_key(&sub),
    "the unclaimed sub's overflow Rescan is parked into the suppressed partition"
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
        options: WatchOptions::new(),
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
    h.owner.unclaimed.contains(&sub) && h.owner.suppressed_rescan.contains_key(&sub),
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
    "the claimed sub's parked Rescan is delivered by the final pass, before the ack"
  );
  assert!(
    h.owner.needs_rescan.is_empty() && h.owner.suppressed_rescan.is_empty(),
    "the owed debt is resolved, not stranded by stale suppression state"
  );
  // The 2000 public commands are UNTOUCHED — the cleanup drain is O(grants in flight), not O(public
  // backlog); they drop unread at teardown (senders see Closed). This is the F1 property.
  assert_eq!(
    h.owner.commands.len(),
    BACKLOG,
    "the public backlog is never walked by the cleanup drain"
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
  // a close already pending on the dedicated signal would (correctly) preempt everything, so
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

/// Regression (design §5, no stale read plane on teardown): the owner publishes an EMPTY
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
    .watch(watched.clone(), (), WatchOptions::new())
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
  /// Kept alive so the owner's sync-admission receiver never observes a closed channel.
  _sync_commands: async_channel::Sender<super::SyncRequest>,
  /// Kept alive so the owner's close receiver never observes a closed channel (these rigs drive
  /// primitives directly and never inject a close).
  _closes: async_channel::Sender<super::CloseReply>,
}

impl OwnerU64 {
  /// Builds the rig with a bounded event channel of `capacity` and an optional coalescer.
  fn new(capacity: usize, coalescer: Option<Coalescer<OsString, u64>>) -> Self {
    let (event_tx, event_rx) = async_channel::bounded(capacity);
    let (command_tx, command_rx) = async_channel::unbounded();
    let (sync_command_tx, sync_command_rx) = async_channel::unbounded::<super::SyncRequest>();
    let (close_tx, close_rx) = async_channel::bounded(1);
    let (cleanup_tx, cleanup_rx) = async_channel::unbounded();
    let owner = Owner {
      source: FakeSource::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
      filter_payload_forgotten: false,
      needs_rescan: BTreeMap::new(),
      suppressed_rescan: BTreeMap::new(),
      unclaimed: std::collections::HashSet::new(),
      flush_cursor: None,
      #[cfg(test)]
      last_flush_visited: 0,
      #[cfg(test)]
      test_pre_cut_claims: Vec::new(),
      debounce: None,
      coalescer,
      pending_syncs: Vec::new(),
      sync_seq: 0,
      sync_nonce_seed: std::collections::hash_map::RandomState::new(),
      loss_serial: HashMap::new(),
      loss_gen: std::sync::Arc::new(core::sync::atomic::AtomicU64::new(0)),
      cleanup_tx,
      cleanup_rx,
      commands: command_rx,
      sync_commands: sync_command_rx,
      closes: close_rx,
      events: event_tx,
      #[cfg(debug_assertions)]
      observed_handles: super::ObservedHandles::new(),
      _rt: PhantomData::<TokioRuntime>,
    };
    Self {
      owner,
      events: event_rx,
      _commands: command_tx,
      _sync_commands: sync_command_tx,
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
    .reconcile_watch(&key("/a"), 42, WatchOptions::new())
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

/// Regression (design §3, event attribution survives teardown): a source-drain leaves a queued
/// coalescer **tail delta** (from one live sub) AND an **owed parked Rescan** (from another sub
/// whose root died). The owner tears down — publishing the EMPTY read plane — and only
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
  let mut rig = OwnerU64::new(8, Some(Coalescer::new(Some(cfg))));

  let a = rig
    .owner
    .reconcile_watch(&key("/a"), 7, WatchOptions::new())
    .await
    .expect("watch /a"); // root handle 1
  let b = rig
    .owner
    .reconcile_watch(&key("/b"), 9, WatchOptions::new())
    .await
    .expect("watch /b"); // root handle 2

  // A view clone taken WHILE both are live — the handle the story is about.
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

  // Publish the EMPTY read plane exactly as `run()` does at teardown: the view now reports
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

/// The full per-subscription-purge class: a **consumer unwatch** must purge the
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
  let mut h = Harness::with_coalescer(Some(Coalescer::new(Some(cfg))));
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

/// The panic-stranding class: a panic in a caller-provided callback the owner runs
/// synchronously (here the admission [`Filter`] predicate at fan-out) unwinds the owner before the
/// normal teardown path empties the read plane. The `impl Drop for Owner` guard publishes an empty
/// plane on **any** owner drop — normal exit OR a panic — so a retained [`WatchView`] never keeps
/// advertising a subscription whose owner task has died (the stale-read-plane mode). The single
/// Drop guard covers the whole class at once: any unwind through the owner future runs it.
///
/// Fail-on-old: with `impl Drop for Owner` removed, dropping the owner leaves the last committed
/// (non-empty) plane published, so the view still reports the sub watched → the final assertion
/// FAILS.
///
/// The panicking filter here is also the containment witness: the fan-out RETURNS (it no longer
/// unwinds the owner), so every other subscription and the control plane survive one tenant's
/// broken predicate. The `ownership` module carries the full quarantine: containment
/// (`a_panicking_filter_cannot_take_the_owner_or_a_healthy_lane_with_it`), its per-subscription
/// blast radius (`quarantining_one_subscription_leaves_a_sibling_sharing_its_filter_intact`), and
/// its ordering against the Rescan it owes
/// (`a_filter_panic_under_debounce_releases_no_delta_after_its_rescan`).
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
      WatchOptions::new().with_filter(Filter::new(|_| -> bool {
        panic!("caller filter predicate panics inside fan-out")
      })),
    )
    .await
    .expect("watch /a"); // root handle 1

  // A view clone taken while the sub is live — the retained handle the guarantee is about.
  let view = h.owner.subsumer.view();
  assert!(
    view.is_watched(&key("/a")),
    "the live watch is advertised while the sub is live"
  );

  // Drive an event through fan-out so the filter panics. The unwind is CONTAINED at the predicate,
  // so this returns normally and the owner is still serving.
  h.owner.fan_out_and_push(&source_modified(1, "/a/f", 0));
  assert!(
    view.is_watched(&key("/a")),
    "the contained panic left the owner alive — the plane is unchanged until the owner drops"
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

/// The owner's teardown guard reaps every cookie still pending, each inside its own
/// containment, so ONE misbehaving [`Source::end_sync`] cannot leave the rest of the marker
/// files on disk. That containment hands back a PAYLOAD, and disposing of a payload runs the
/// misbehaving source's own destructor — so dropping it here reintroduces exactly the escape
/// the containment was built to close, one line further out and in the worst frame in the
/// crate: this destructor also runs while the owner task is UNWINDING (a panicking caller
/// callback is precisely how it is reached), where a second unwind is not a contained failure
/// but an immediate process abort.
///
/// FAIL-ON-REVERT: contain with a bare `catch_unwind` and let its `Err` fall out of scope, and
/// the first payload's destructor unwinds out of the teardown loop — the two cookies behind it
/// are never reaped, and the unwind leaves through `drop(h)`.
#[tokio::test]
async fn owner_teardown_reaps_every_cookie_although_a_payload_panics_as_it_is_disposed_of() {
  const COOKIES: usize = 3;

  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  let entered = BOOM_COOKIES_REAPED.load(core::sync::atomic::Ordering::SeqCst);
  let mut replies = Vec::new();
  for _ in 0..COOKIES {
    let (reply_tx, reply_rx) = futures_channel::oneshot::channel();
    replies.push(reply_rx);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key("/a/cookie-boom"),
      sub,
      root: handle,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: reply_tx,
    });
  }

  // The teardown guard: it publishes the empty plane, then reaps.
  drop(h);

  assert_eq!(
    BOOM_COOKIES_REAPED.load(core::sync::atomic::Ordering::SeqCst) - entered,
    COOKIES,
    "a payload that panics as it is disposed of skipped the cookies queued behind it — each \
     one is a marker file left on the caller's filesystem"
  );
}

/// Regression (design source doc, invariant I4 / no false debt):
/// [`release_subscription`](super::Owner::release_subscription) must clear a subscription's
/// owner-local per-sub state — above all its parked overflow [`Rescan`](EventKind::Rescan)
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
  // terminal-retired state this pins (plan_unwatch can no longer find it).
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

  // the orphan's parked Rescan is GONE (no false debt) …
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
/// overlap rejection. The re-`watch` arms a FRESH
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
  let (_sync_command_tx, sync_command_rx) = async_channel::unbounded::<super::SyncRequest>();
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
    filter_payload_forgotten: false,
    needs_rescan: BTreeMap::new(),
    suppressed_rescan: BTreeMap::new(),
    unclaimed: std::collections::HashSet::new(),
    flush_cursor: None,
    #[cfg(test)]
    last_flush_visited: 0,
    #[cfg(test)]
    test_pre_cut_claims: Vec::new(),
    debounce: None,
    coalescer: None,
    pending_syncs: Vec::new(),
    sync_seq: 0,
    sync_nonce_seed: std::collections::hash_map::RandomState::new(),
    loss_serial: HashMap::new(),
    loss_gen: std::sync::Arc::new(core::sync::atomic::AtomicU64::new(0)),
    cleanup_tx,
    cleanup_rx,
    commands: command_rx,
    sync_commands: sync_command_rx,
    closes: close_rx,
    events: event_tx,
    #[cfg(debug_assertions)]
    observed_handles: super::ObservedHandles::new(),
    _rt: PhantomData::<TokioRuntime>,
  };
  let _commands = command_tx; // keep the command channel open (the dropped-handles teardown signal)

  // Watch /a → handle 1, its transport watch installed and live.
  let sub = owner
    .reconcile_watch(&key("/a"), (), WatchOptions::new())
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

/// Regression, NORMAL loop (design driver-golden doc, invariant I1 / no false debt):
/// the run loop's top-of-iteration parked-Rescan flush is now **unconditional**, and which parked
/// debt it OFFERS is decided by owner STATE — [`flush_pending_rescans`](super::Owner::flush_pending_rescans)
/// suppresses any entry whose sub is still `unclaimed` (its [`WatchGrant`](super::WatchGrant) in
/// flight). So an orphaned (committed-but-unclaimed, then dropped) subscription's parked terminal
/// [`Rescan`](EventKind::Rescan) is NEVER delivered, no matter how its
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
  /// (the exact interleaving this pins). After the one terminal event `next` parks, so the loop stays
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
  let (_sync_command_tx, sync_command_rx) = async_channel::unbounded::<super::SyncRequest>();
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
    filter_payload_forgotten: false,
    needs_rescan: BTreeMap::new(),
    suppressed_rescan: BTreeMap::new(),
    unclaimed: std::collections::HashSet::new(),
    flush_cursor: None,
    #[cfg(test)]
    last_flush_visited: 0,
    #[cfg(test)]
    test_pre_cut_claims: Vec::new(),
    debounce: None,
    coalescer: None,
    pending_syncs: Vec::new(),
    sync_seq: 0,
    sync_nonce_seed: std::collections::hash_map::RandomState::new(),
    loss_serial: HashMap::new(),
    loss_gen: std::sync::Arc::new(core::sync::atomic::AtomicU64::new(0)),
    cleanup_tx,
    cleanup_rx,
    commands: command_rx,
    sync_commands: sync_command_rx,
    closes: close_rx,
    events: event_tx,
    #[cfg(debug_assertions)]
    observed_handles: super::ObservedHandles::new(),
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
      options: WatchOptions::new(),
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

/// Regression — a grant left UNPOLLED in the watch reply slot across a source-drain
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
      options: WatchOptions::new(),
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

/// Regression — the source-drain exit is ATOMIC with respect to grant claims: the drain
/// CLOSES the cleanup channel before accepting its all-unclaimed exit, so a grant defused in the
/// window after the final emptiness observation but BEFORE the owner drops (the receiver was still
/// alive — the claim-vs-cut race) fails its claim try_send and is POISONED. Fail-on-old: without the in-exit
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
    "a claim after the source-drain cut is poisoned even while the owner is still alive"
  );
  assert!(
    h.drain().iter().all(|e| e.subscription() != sub),
    "the suppressed debt was never delivered for the never-claimed subscription"
  );
}

/// SOURCE-DRAIN teardown under the STATE model (owed = CLAIMED): an UNCLAIMED
/// terminal-retired sub's parked terminal Rescan is suppressed by the owner's `unclaimed` state —
/// never delivered even with event-channel CAPACITY — while a claimed live sub's owed Rescan still
/// delivers, and [`drain_owed_before_shutdown`](super::Owner::drain_owed_before_shutdown) then
/// EXITS instead of spinning on the unclaimed leftover: with NO grant-resolution
/// [`Cleanup`](super::Cleanup) ever arriving, STATE alone withholds the debt AND lets the drain exit —
/// the debt is owed to nobody (the close of the mailbox-idle TOCTOU).
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
    h.owner.needs_rescan.contains_key(&live) && h.owner.suppressed_rescan.contains_key(&orphan),
    "both parked: the live sub's overflow Rescan offerable, the unclaimed orphan's terminal \
     Rescan in the suppressed partition"
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
    h.owner.needs_rescan.is_empty() && h.owner.suppressed_rescan.contains_key(&orphan),
    "only suppressed (owed-to-nobody) debt remains at exit — the offerable map drained"
  );
}

/// the POST-Close best-effort tail under the STATE model: the tail is a plain
/// [`drain_owed_once`](super::Owner::drain_owed_once) (the retired pre-drain helper is gone — state
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
    h.owner.needs_rescan.contains_key(&live) && h.owner.suppressed_rescan.contains_key(&orphan),
    "both parked: the live sub's overflow Rescan offerable, the unclaimed orphan's terminal \
     Rescan in the suppressed partition"
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
    "the unclaimed orphan's parked Rescan is suppressed by state in the final pass"
  );
  assert!(
    delivered
      .iter()
      .any(|e| e.subscription() == live && e.is_rescan()),
    "the claimed live sub's owed Rescan IS delivered by the best-effort pass"
  );
}

/// claim-then-deliver: suppression must never become LOSS for a subscription the caller
/// actually obtained. An unclaimed sub's parked terminal Rescan is withheld (retained, not offered);
/// once its [`Cleanup::Claim`](super::Cleanup::Claim) is applied — the caller defused the grant
/// and now holds the sub — the very next flush delivers the parked Rescan: the debt was deferred,
/// never dropped.
#[tokio::test]
async fn claimed_grant_lifts_suppression_and_its_parked_rescan_is_delivered() {
  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  h.owner.unclaimed.insert(sub);

  // Terminal-retire the unclaimed sub's root: its owed terminal Rescan parks into the
  // SUPPRESSED partition — the flush never even visits it.
  h.owner.retire_root_with_terminal_rescan(1);
  assert!(
    h.owner.suppressed_rescan.contains_key(&sub),
    "the terminal Rescan is parked, suppressed"
  );
  h.owner.flush_pending_rescans();
  assert!(
    h.drain().is_empty(),
    "unclaimed: the parked Rescan is suppressed, not offered"
  );
  assert_eq!(
    h.owner.last_flush_visited, 0,
    "…at zero flush cost — suppressed debt lives outside the offerable map"
  );
  assert!(
    h.owner.suppressed_rescan.contains_key(&sub),
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
    h.owner.needs_rescan.is_empty() && h.owner.suppressed_rescan.is_empty(),
    "the owed debt is resolved once claimed"
  );
}

/// Regression — sustained control-plane load must not starve a CLAIMED sub's parked
/// Rescan: the flush is UNCONDITIONAL again (the retired mailbox-idle gate is reverted), so a live
/// parked Rescan is delivered within a bounded window even while a flood keeps the command mailbox
/// continuously non-empty. Fail-on-old: with the retired `commands.is_empty()` gate, the flood keeps the
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
    .watch(key("/a/b"), (), WatchOptions::new())
    .await
    .expect("watch /a/b");
  let narrow_c = w
    .watch(key("/a/c"), (), WatchOptions::new())
    .await
    .expect("watch /a/c");
  let _wide = w
    .watch(key("/a"), (), WatchOptions::new())
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
            options: WatchOptions::new(),
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
            options: WatchOptions::new(),
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
/// command-flood fairness rig: with the command arm continuously ready, only the run
/// loop's fairness valve can pump these events. `next` is cancellation-safe: the trigger message
/// and the event are consumed on the same poll that returns `Ready`.
struct TriggeredSource {
  next_handle: u32,
  live: HashMap<u32, Vec<OsString>>,
  events: std::collections::VecDeque<SourceEvent<OsString, u32>>,
  trigger: async_channel::Receiver<()>,
  grows: std::sync::Arc<std::sync::atomic::AtomicU32>,
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

  async fn grow(&mut self, _handle: u32, _retained: &[Vec<OsString>]) -> Result<(), WatchError> {
    self.grows.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(())
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

/// Regression — a `Cleanup::Claim` already QUEUED when the source drains must be drained
/// before the drain's all-unclaimed exit: the caller defused the grant (it holds the sub), so the
/// parked terminal Rescan is genuinely owed and must be delivered before the stream ends. The exit
/// predicate reads post-claim state (the cleanup channel is drained and must be observed empty), or
/// suppression becomes permanent loss. Fail-on-old: the old exit takes the all-unclaimed arm
/// before the queued claim is drained — nothing is delivered and the assertion flips.
#[tokio::test]
async fn queued_claim_grant_is_serviced_before_the_source_drain_exit() {
  let mut h = Harness::new(); // unbounded event channel — has capacity
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  h.owner.unclaimed.insert(sub);
  // Terminal-retire the unclaimed sub's root: its owed terminal Rescan parks into the
  // suppressed partition.
  h.owner.retire_root_with_terminal_rescan(1);
  assert!(
    h.owner.suppressed_rescan.contains_key(&sub),
    "the terminal Rescan is parked, suppressed"
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
    "the claimed sub's parked Rescan is delivered before the source-drain exit"
  );
  assert!(
    h.owner.needs_rescan.is_empty() && h.owner.suppressed_rescan.is_empty(),
    "the owed debt is resolved, not stranded"
  );
}

/// Regression — a RAW source event is delivered within a bounded window under a
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
      Location::new(),
      Epoch::new(0),
      Some(ChangeId::new(NonZeroU64::MIN)),
    )]),
    trigger: trigger_rx,
    grows: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
  };
  let mut w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());
  let sub = w
    .watch(key("/a"), (), WatchOptions::new())
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

/// Regression — a live-root coverage-loss `Rescan` pumped through the COMMAND-FAIRNESS
/// VALVE (not the select arm) still degrades the retained-cover record: both source
/// paths run the one `consume_source_event` funnel (retire → degrade → fan out).
/// Fail-on-old: the valve's forced poll went retire → fan-out directly, so under a
/// sustained command flood the `Rescan` delivered while the stale narrowed claim
/// survived — and the next covered newcomer skipped its coverage-re-proving grow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valve_pumped_rescan_still_degrades_the_retained_cover() {
  let (trigger_tx, trigger_rx) = async_channel::unbounded::<()>();
  let grows = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
  let source = TriggeredSource {
    next_handle: 0,
    live: HashMap::new(),
    // The queued live-root coverage-loss signal: handle 2 is the wide /a root the widen
    // below arms second.
    events: std::collections::VecDeque::from([SourceEvent::new(
      2,
      key("/a"),
      EventKind::Rescan,
      Location::new(),
      Epoch::new(1),
      None,
    )]),
    trigger: trigger_rx,
    grows: grows.clone(),
  };
  let mut w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());

  // Narrow the wide /a root to {/a/b}: widen /a over /a/b (handle 2), then prune the widener.
  let s_b = w
    .watch(key("/a/b"), (), WatchOptions::new())
    .await
    .expect("watch /a/b");
  let s_a = w
    .watch(key("/a"), (), WatchOptions::new())
    .await
    .expect("watch /a widens");
  w.unwatch(s_a).await.expect("unwatch the widening /a");
  // Consume the widen re-point Rescan so the valve-pumped loss signal is the next delivery.
  let repoint = tokio::time::timeout(Duration::from_secs(5), w.next())
    .await
    .expect("the re-point Rescan arrives")
    .expect("stream open");
  assert!(repoint.is_rescan() && repoint.subscription() == s_b);

  // Under a sustained command flood only the fairness valve pumps the source: the queued
  // loss Rescan must arrive AND degrade the record on that same valve path.
  let flood = spawn_command_flood(w.commands.clone());
  trigger_tx.try_send(()).expect("release the queued Rescan");
  let event = tokio::time::timeout(Duration::from_secs(5), w.next())
    .await
    .expect("the loss Rescan is delivered through the valve despite the flood")
    .expect("stream open");
  assert!(
    event.is_rescan() && event.subscription() == s_b,
    "the coverage-loss Rescan fanned to the covering sub"
  );
  flood.abort();

  // The record degraded on the valve path iff this covered newcomer re-proves via grow.
  assert_eq!(grows.load(std::sync::atomic::Ordering::SeqCst), 0);
  let _s2 = w
    .watch(key("/a/b/x"), (), WatchOptions::new())
    .await
    .expect("the post-loss newcomer commits through a re-proving grow");
  assert_eq!(
    grows.load(std::sync::atomic::Ordering::SeqCst),
    1,
    "the newcomer classified covered-OUTSIDE against the degraded record and grew"
  );
}

/// Regression — the source-drain teardown makes OWED progress under a sustained command
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
    "the claimed sub's parked Rescan is delivered despite the sustained command flood"
  );
}

/// Regression — DUE debounced output drains within a bounded window under a sustained
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
      Location::new(),
      Epoch::new(0),
      Some(ChangeId::new(NonZeroU64::MIN)),
    )]),
    trigger: trigger_rx,
    grows: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
  };
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_millis(20))
    .with_max_hold(Duration::from_millis(100));
  let mut w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new().debounce(cfg));
  let sub = w
    .watch(key("/a"), (), WatchOptions::new())
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

/// Regression — `close()` is never starved behind an unbounded command backlog:
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
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> = super::Tributaries::with_source(
    source,
    // The mailbox is BOUNDED; size it to this test's full 500-deep
    // prefill so the close-vs-deepest-possible-backlog shape is preserved.
    TributariesOptions::new().with_command_capacity(std::num::NonZeroUsize::new(500).unwrap()),
  );

  // A live claimed subscription, so the owner is genuinely running with real state (the finding's
  // "owner/source kept alive while shutdown is requested").
  w.watch(key("/a"), (), WatchOptions::new())
    .await
    .expect("watch /a");

  // Prefill the command mailbox to its FULL configured depth with fail-fast Watch commands: each
  // reply receiver is dropped, so the owner's send-back fails and it releases the orphan
  // synchronously (arm→disarm) — real per-command work the old FIFO `Close` would have queued
  // behind.
  for _ in 0..500 {
    let (reply, response) = futures_channel::oneshot::channel();
    drop(response);
    w.commands
      .try_send(super::Command::Watch {
        key: key("/backlog"),
        value: (),
        options: WatchOptions::new(),
        reply,
      })
      .expect("prefill the command backlog");
  }
  // …and a sustained flood keeping the mailbox continuously non-empty against the real run loop.
  let flood = spawn_command_flood(w.commands.clone());

  // close() rides the dedicated close signal, so it completes within a bounded window DESPITE the
  // 500-deep backlog + ongoing flood on the command mailbox.
  let closed = tokio::time::timeout(Duration::from_secs(5), w.close())
    .await
    .expect("close() completes within the deadline despite the command backlog + flood");
  assert!(matches!(closed, Ok(())), "close() succeeds");
  flood.abort();
}

/// Regression, SOURCE-DRAIN teardown under a flood — a close DURING the owed-Rescan
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

  // The source-drain teardown surfaces the close within the deadline despite the flood.
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

/// F2 + F3 — a `Rescan` at or above a pending cookie's key resolves that
/// barrier `Dominated`, and it does so only AFTER the `Rescan` itself is
/// published to the stream (structurally: `consume_source_event` fans out
/// before it dominates). The postcondition proves both: the caller's reply is
/// `Dominated` AND the covering `Rescan` is drainable, never a reply that
/// outran its cover.
#[tokio::test]
async fn a_rescan_dominates_a_pending_sync_and_the_rescan_is_published() {
  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-1"),
    sub,
    root: handle,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: reply_tx,
  });

  h.owner.consume_source_event(&rescan_event(handle, "/a", 5));

  let events = h.drain();
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "the covering Rescan is on the stream: {events:?}"
  );
  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "the barrier resolved Dominated, not Delivered"
  );
}

/// F3 — a cookie that is delivered while its subscription already carries a
/// parked `Rescan` (an earlier loss) resolves `Dominated`, not `Delivered`:
/// the caller must re-enumerate, so reporting a clean delivery would risk
/// stale state.
#[tokio::test]
async fn a_cookie_delivered_over_existing_rescan_debt_resolves_dominated() {
  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  // A bounded, stalled channel so a fanned Rescan sheds to `needs_rescan`.
  let mut h = Harness::bounded(1);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  // Fill the channel, then a Rescan sheds the sub to a parked (needs_rescan) Rescan.
  h.owner.try_emit(modified_event(sub, "/a/x", 1));
  h.owner.consume_source_event(&rescan_event(handle, "/a", 2));
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the sub carries parked Rescan debt"
  );

  // Now the cookie arrives. Delivery cannot be clean while a Rescan is owed.
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-1"),
    sub,
    root: handle,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: reply_tx,
  });
  h.owner
    .consume_source_event(&source_created(handle, "/a/cookie-1", 3));
  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "a cookie delivered over Rescan debt is Dominated"
  );
}

/// R13 — the interest/filter lens at the umbrella boundary (the end-to-end
/// companion to the proto fail-on-old cells): a `Modified`-only subscription
/// cannot be discharged by a structural `Removed` it never sees — only by the
/// covering `Rescan` the Monitor now stands over an erased coverage deficit.
/// The `Removed` for a dark child is FILTERED (never delivered) and does NOT
/// dominate the pending sync; the covering `Rescan` IS delivered (Rescans
/// bypass interest AND filter) and resolves the barrier `Dominated`. This
/// proves the "reached the sub" half of the R13 fix: the covering `Rescan` the
/// proto layer emits when a filter-subject record empties a hole DOES reach a
/// filtered subscriber and dominate its sync, where the structural record —
/// which two prior Monitor-level reviews assumed "converged the consumer" —
/// provably could not.
#[tokio::test]
async fn a_covering_rescan_dominates_a_modified_only_sync_a_removed_cannot() {
  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::new();
  // The umbrella's `Interest::new()` is deliver-everything (== all); a
  // Modified-only subscription starts from `none` and opts in Modified alone.
  let sub = h
    .watch("/a", Interest::none().with_modified())
    .await
    .expect("watch /a modified-only");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-1"),
    sub,
    root: handle,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: reply_tx,
  });

  // A structural Removed for the dark child: FILTERED (a Modified-only sub
  // never sees it) and it does NOT dominate the sync — a structural record a
  // filtered sub cannot see must not discharge the barrier.
  h.owner
    .consume_source_event(&source_removed(handle, "/a/child", 5));
  assert!(
    h.drain().iter().all(|e| !e.kind().is_removed()),
    "the Removed is filtered from the Modified-only sub"
  );
  assert!(
    (&mut reply_rx).now_or_never().is_none(),
    "a Removed the sub never sees does not resolve the barrier"
  );

  // The covering Rescan the Monitor now stands over the erased hole: delivered
  // (it bypasses the filter) and dominating.
  h.owner.consume_source_event(&rescan_event(handle, "/a", 6));
  assert!(
    h.drain().iter().any(|e| e.kind().is_rescan()),
    "the covering Rescan reaches the Modified-only sub"
  );
  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "the barrier resolved Dominated via the covering Rescan, not a false Delivered"
  );
}

/// F5 — a CALLER unwatch of a subscription with a pending sync fails the
/// barrier `Retired` AND reaps its cookie file (the root is still live, so the
/// marker is real and must not leak).
#[tokio::test]
async fn an_unwatched_subscription_reaps_its_pending_cookie() {
  use futures_util::FutureExt;

  use crate::error::SyncError;

  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-1"),
    sub,
    root: handle,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: reply_tx,
  });

  h.owner.release_subscription(sub).expect("unwatch");

  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Err(SyncError::Retired)))
    ),
    "the caller-unwatched barrier fails Retired"
  );
  assert_eq!(
    h.owner.source.ended_syncs,
    vec![key("/a/cookie-1")],
    "the cookie is reaped, not leaked"
  );
}

/// F6 — an in-place widen whose retarget canonicalizes to a key that does NOT
/// contain the subsumed root ROLLS THE HANDLE BACK to its original coverage
/// (never disarms it while old subscribers are committed) and refuses the
/// newcomer with a canonicalization race.
#[tokio::test]
async fn a_diverging_in_place_widen_rolls_back_and_keeps_old_coverage() {
  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::new();
  h.owner.source.supports_replace = true;

  let s_narrow = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let handle = h
    .owner
    .subsumer
    .subscription_root(s_narrow)
    .expect("live root");

  // A pending sync on the sole root's subscriber, installed BEFORE the widen. The exact rollback
  // retargets the preserved stream away and back with NO Rescan, silently missing any change in that
  // window — so the barrier must resolve `Dominated` (re-enumerate), never strand to timeout.
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/b/cookie-1"),
    sub: s_narrow,
    root: handle,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: reply_tx,
  });

  // The widen of /a canonicalizes to /z — which does NOT contain /a/b, so it
  // would strand s_narrow. The rollback must restore /a/b on the same handle.
  h.owner
    .source
    .retarget
    .insert(PathBuf::from("/a"), PathBuf::from("/z"));

  let err = h
    .watch("/a", Interest::all())
    .await
    .expect_err("the diverging widen is refused");
  assert!(matches!(err, WatchError::CanonicalRace), "{err:?}");

  // The preserved handle was NEVER disarmed — no Disarm in the ledger.
  assert!(
    !h.owner
      .source
      .calls()
      .iter()
      .any(|c| matches!(c, Call::Disarm(_))),
    "the preserved handle must not be disarmed while old subscribers remain: {:?}",
    h.owner.source.calls()
  );
  // s_narrow still has its coverage: the root is keyed back at /a/b.
  let roots: Vec<PathBuf> = h
    .owner
    .subsumer
    .roots()
    .map(|(k, _)| PathBuf::from_iter(k))
    .collect();
  assert_eq!(
    roots,
    vec![PathBuf::from("/a/b")],
    "the sole root is rolled back to its original coverage"
  );
  assert!(
    h.owner.subsumer.subscription_root(s_narrow).is_some(),
    "the old subscription is still live on the restored root"
  );

  // The rollback rebinds the sole live root's stream: its subscriber's pending sync resolves
  // `Dominated` (re-enumeration meets the barrier), its cookie is reaped, and it owes a dominating
  // `Rescan` that publishes and clears once the consumer drains.
  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "the sole root's pending sync resolves Dominated after the exact rollback"
  );
  assert_eq!(
    h.owner.source.ended_syncs,
    vec![key("/a/b/cookie-1")],
    "the dominated barrier's cookie is reaped"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&s_narrow),
    "s_narrow owes a dominating Rescan for the silently-missed retarget window"
  );
  h.owner.flush_pending_rescans();
  let events = h.drain();
  assert!(
    events
      .iter()
      .any(|e| e.subscription() == s_narrow && e.kind().is_rescan()),
    "s_narrow receives the dominating Rescan: {events:?}"
  );
}

/// R2-d — a delta shed to a parked Rescan for a pre-cookie change, then
/// PUBLISHED (cleared from needs_rescan) before the cookie, still resolves the
/// barrier `Dominated`: the sticky loss serial advanced during the window, so
/// even with no debt left parked at resolution the caller is told to
/// re-enumerate rather than trust a false `Delivered`.
#[tokio::test]
async fn a_loss_published_before_the_cookie_still_resolves_dominated() {
  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::bounded(4);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  // Install the barrier FIRST (snapshots the loss serial at 0).
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-1"),
    sub,
    root: handle,
    loss_serial_at_install: h.owner.loss_serial.get(&sub).copied().unwrap_or(0),
    dominated_at_install: false,
    reply: reply_tx,
  });

  // A loss during the window: fill the channel, shed a delta to a parked
  // Rescan, then drain the channel so the parked Rescan PUBLISHES and clears.
  for i in 0..4 {
    h.owner.try_emit(modified_event(sub, "/a/fill", i));
  }
  h.owner.try_emit(modified_event(sub, "/a/lost", 9)); // sheds -> parked
  assert!(h.owner.needs_rescan.contains_key(&sub));
  let _ = h.drain(); // free the channel
  h.owner.flush_pending_rescans(); // publish the parked Rescan -> clears needs_rescan
  assert!(
    !h.owner.needs_rescan.contains_key(&sub),
    "the parked Rescan was published and cleared"
  );

  // The cookie arrives with NO debt parked — but the serial advanced, so
  // Dominated, not a false Delivered.
  h.owner
    .consume_source_event(&source_created(handle, "/a/cookie-1", 20));
  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "a loss published before the cookie must still yield Dominated"
  );
}

/// R2-a — a widen's re-pointed subscription with a pending sync resolves
/// `Dominated` at commit time (its stream re-based onto the wider root), never
/// waiting for a cookie on the old handle.
#[tokio::test]
async fn a_widen_resolves_the_repointed_subscriptions_pending_sync() {
  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::new();
  let s_narrow = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let handle = h.owner.subsumer.subscription_root(s_narrow).expect("live");

  // A pending sync on the narrow sub.
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/b/cookie-1"),
    sub: s_narrow,
    root: handle,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: reply_tx,
  });

  // Widen /a/b -> /a: s_narrow is re-pointed onto the wider root.
  let _wide = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a widens");

  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "the re-pointed subscription's barrier resolves Dominated at the widen"
  );
}

/// F1 — a barrier installed over debt that ALREADY stood at install (a change lost BEFORE the
/// barrier) resolves `Dominated`, even after that parked Rescan publishes-and-clears before the
/// cookie: at resolution the loss serial is unchanged AND `needs_rescan` is empty, so ONLY the
/// install-time `dominated_at_install` snapshot separates it from a genuinely clean sync. A pre-call
/// loss is exactly what the barrier must not hide behind a false `Delivered`.
///
/// Fail-on-old (no `dominated_at_install`): the published-and-cleared debt leaves a clean flush and
/// an unchanged serial, so the barrier reports `Delivered` — the bug.
#[tokio::test]
async fn a_barrier_installed_over_existing_debt_resolves_dominated() {
  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  // Pre-install debt: the sub already owes a parked Rescan (a change lost before ANY barrier).
  h.owner.park_rescan(sub);
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the sub owes a parked Rescan before the barrier is installed"
  );

  // Install the barrier through the REAL `on_sync` path, so it snapshots `dominated_at_install` from
  // the standing debt (the loss serial is snapshot too, but will not advance during the window). The
  // caller's generation snapshot is taken here, AFTER the park, so only the standing debt can force
  // the domination — the property this cell pins.
  let loss_gen_at_call = h.owner.loss_gen.load(core::sync::atomic::Ordering::SeqCst);
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.on_sync(sub, loss_gen_at_call, reply_tx).await;
  assert!(
    !h.owner.source.ended_syncs.contains(&key("/a/cookie-1")),
    "the cookie is still pending — not yet reaped"
  );

  // The pre-install Rescan publishes and clears BEFORE the cookie: no debt parked and the serial
  // unchanged at resolution, so only the install-time snapshot can still force Dominated.
  h.owner.flush_pending_rescans();
  assert!(
    !h.owner.needs_rescan.contains_key(&sub),
    "the pre-install Rescan published and cleared"
  );

  // The cookie arrives clean-looking — but the pre-call loss the install captured wins.
  h.owner
    .consume_source_event(&source_created(handle, "/a/cookie-1", 20));
  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "a barrier installed over pre-existing debt resolves Dominated, not a false Delivered"
  );
  assert_eq!(
    h.owner.source.ended_syncs,
    vec![key("/a/cookie-1")],
    "the resolved barrier's cookie is reaped"
  );
}

/// A cookie write that completes for a caller who has ALREADY gone is reaped inline, never parked and
/// never orphaned. This is the `on_sync` race's write-first outcome: the fs backend buffered its
/// successful `Ok(path)` just as the caller's deadline fired, so its own send-failure self-reap will
/// not run — reaping here is the only thing that frees the file.
///
/// Fail-on-old (drop the caller-gone check in `admit_begun_cookie`): the completed cookie is parked as
/// a `PendingSync` no one waits on and its file is never `end_sync`ed here — both assertions fail.
#[tokio::test]
async fn a_completed_cookie_for_a_gone_caller_is_reaped_not_installed() {
  use crate::{error::SyncError, source::SyncOutcome};

  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  let (reply_tx, reply_rx) = futures_channel::oneshot::channel::<Result<SyncOutcome, SyncError>>();
  drop(reply_rx);
  let loss_gen_at_call = h.owner.loss_gen.load(core::sync::atomic::Ordering::SeqCst);
  h.owner
    .admit_begun_cookie(key("/a/cookie-1"), sub, handle, loss_gen_at_call, reply_tx);

  assert!(
    h.owner.pending_syncs.is_empty(),
    "a completed cookie for a gone caller parks no barrier"
  );
  assert_eq!(
    h.owner.source.ended_syncs,
    vec![key("/a/cookie-1")],
    "the completed cookie is reaped inline, never orphaned"
  );
}

/// The companion: a completed cookie for a caller still waiting IS parked (and not reaped), so the
/// caller-gone reap above is genuinely gated on the cancellation, not unconditional.
#[tokio::test]
async fn a_completed_cookie_for_a_live_caller_is_parked_not_reaped() {
  use crate::{error::SyncError, source::SyncOutcome};

  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  let (reply_tx, _reply_rx) = futures_channel::oneshot::channel::<Result<SyncOutcome, SyncError>>();
  let loss_gen_at_call = h.owner.loss_gen.load(core::sync::atomic::Ordering::SeqCst);
  h.owner
    .admit_begun_cookie(key("/a/cookie-1"), sub, handle, loss_gen_at_call, reply_tx);

  assert_eq!(
    h.owner.pending_syncs.len(),
    1,
    "a live caller's barrier is parked to await its cookie"
  );
  assert!(
    h.owner.source.ended_syncs.is_empty(),
    "and its cookie is not reaped while the caller still waits"
  );
}

/// A covering `Rescan` DELIVERED (never parked) between the caller's `sync()` call and the barrier's
/// install dominates it too. An already-installed barrier riding that same `Rescan` resolves
/// `Dominated` (the `dominate_*` family does it directly); a barrier whose caller had merely CALLED
/// must not resolve `Delivered` for the change that `Rescan` replaced, or the outcome would depend on
/// how the owner's loop happened to interleave the request with the event.
///
/// The delivered path leaves NO trace the install-time probes can read — nothing parks, so the debt
/// maps stay empty and the per-subscription `loss_serial` never moves. Only the shared generation,
/// advanced at the domination choke point, still carries it.
#[tokio::test]
async fn a_delivered_rescan_between_the_call_and_the_install_resolves_dominated() {
  use core::sync::atomic::Ordering;

  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  // The caller snapshots the shared generation, exactly as `Tributaries::sync` does before enqueueing.
  let loss_gen_at_call = h.owner.loss_gen.load(Ordering::SeqCst);

  // A source `Rescan` is consumed and DELIVERED while the request still sits in the mailbox.
  h.owner
    .consume_source_event(&rescan_event(handle, "/a", 10));
  assert!(
    !h.owner.needs_rescan.contains_key(&sub) && !h.owner.suppressed_rescan.contains_key(&sub),
    "the Rescan was delivered, not parked — no standing debt for the install to snapshot"
  );
  assert_eq!(
    h.owner.loss_serial.get(&sub).copied().unwrap_or(0),
    0,
    "a delivered Rescan never moves the per-subscription serial — the long-window probe is blind too"
  );

  // Install with the caller's stale snapshot, then deliver the cookie over the pristine-looking state.
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.on_sync(sub, loss_gen_at_call, reply_tx).await;
  h.owner
    .consume_source_event(&source_created(handle, "/a/cookie-1", 20));
  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "a Rescan delivered between the caller's sync() call and the install resolves Dominated"
  );
  assert_eq!(
    h.owner.source.ended_syncs,
    vec![key("/a/cookie-1")],
    "the dominated barrier's cookie is reaped"
  );
}

/// The CALL-to-INSTALL window: a loss the owner processes AFTER the caller's `sync()` enqueued its
/// request but BEFORE the owner dispatches it resolves the barrier `Dominated`.
///
/// This is the window neither install-time probe can see, and it is why the barrier's loss window is
/// anchored at the caller's call (the shared `loss_gen` snapshot [`super::Tributaries::sync`] takes
/// before it sends) rather than at the install. The loss here parks, publishes and clears entirely
/// inside the window, so by the time `on_sync` runs, `needs_rescan`/`suppressed_rescan` are empty
/// again (no standing debt to snapshot) AND the per-subscription loss serial has already advanced
/// (so the install-to-resolve `lost_during_window` comparison sees no change). Yet the lost change
/// is PRE-CALL — its kernel event predates the caller's `sync()` — so it must never be reported as a
/// clean `Delivered`.
///
/// Fail-on-old (no `loss_gen` term in `dominated_at_install`): both install-time probes read a
/// pristine state and the cookie's flush is clean, so the barrier reports `Delivered` — the bug.
#[tokio::test]
async fn a_loss_between_the_call_and_the_install_resolves_dominated() {
  use core::sync::atomic::Ordering;

  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  // The caller snapshots the shared loss generation exactly as `Tributaries::sync` does — BEFORE the
  // request is enqueued — and the owner has not dispatched it yet.
  let loss_gen_at_call = h.owner.loss_gen.load(Ordering::SeqCst);

  // The owner now processes a PRE-CALL loss while the request sits in the mailbox: the sub sheds to
  // a parked Rescan, which then publishes and clears. Both install-time probes are now blind to it.
  h.owner.park_rescan(sub);
  h.owner.flush_pending_rescans();
  assert!(
    !h.owner.needs_rescan.contains_key(&sub) && !h.owner.suppressed_rescan.contains_key(&sub),
    "the loss published and cleared before the barrier is installed — no standing debt to snapshot"
  );
  assert_ne!(
    h.owner.loss_serial.get(&sub).copied().unwrap_or(0),
    0,
    "the loss serial ALREADY advanced, so the install-to-resolve comparison cannot see this loss"
  );

  // Install with the caller's STALE snapshot — exactly what the queued `SyncRequest` carries.
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.on_sync(sub, loss_gen_at_call, reply_tx).await;

  // The cookie arrives over a state that looks pristine. Only the call-time generation still knows.
  h.owner
    .consume_source_event(&source_created(handle, "/a/cookie-1", 20));
  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "a loss processed between the caller's sync() call and the barrier's install resolves \
     Dominated, never a false Delivered"
  );
}

/// A parked Rescan PUBLISHED in the call-to-install window resolves the barrier `Dominated`, not a
/// false `Delivered`. The caller snapshots the shared generation AFTER a pre-call loss parked (so the
/// park's bump is already folded into the snapshot); the owner then publishes-and-clears that parked
/// Rescan while the request sits in the mailbox. Publishing a parked re-enumeration is a DELIVERED
/// covering Rescan, so it must dominate a barrier whose `sync()` preceded it — the publish half of the
/// same invariant `note_domination` enforces at the delivered-Rescan choke point.
///
/// Fail-on-old (the publish did not advance the generation): by install the debt map is empty, the
/// per-sub loss serial was snapshotted after the park's bump (so it never appears to move), and the
/// generation still equals the caller's snapshot — every probe reads a pristine state and the cookie's
/// flush is clean, so the barrier reports `Delivered` for a pre-call re-enumeration the caller must
/// still process.
#[tokio::test]
async fn a_parked_rescan_published_in_the_call_window_resolves_dominated() {
  use core::sync::atomic::Ordering;

  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  // A pre-call loss parks debt for the sub — its kernel event predates the caller's `sync()`.
  h.owner.park_rescan(sub);
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "the pre-call loss parked debt"
  );

  // The caller snapshots the shared generation AFTER the park — so the park's bump is already folded
  // in, exactly as `Tributaries::sync` sees it for a loss that happened before the call.
  let loss_gen_at_call = h.owner.loss_gen.load(Ordering::SeqCst);

  // The owner publishes-and-clears the parked Rescan while the request still sits in the mailbox (the
  // call-to-install window). Without the publish-half domination this advances NEITHER the generation
  // the caller snapshotted NOR the per-sub serial (snapshotted after the park's bump), so both
  // install-time probes go blind.
  h.owner.flush_pending_rescans();
  assert!(
    !h.owner.needs_rescan.contains_key(&sub),
    "the parked Rescan published and cleared before the barrier installs"
  );

  // Install with the caller's stale snapshot, then deliver the cookie over the now-pristine state.
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.on_sync(sub, loss_gen_at_call, reply_tx).await;
  h.owner
    .consume_source_event(&source_created(handle, "/a/cookie-1", 20));

  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "a parked Rescan published in the call-to-install window resolves Dominated, not a false Delivered"
  );
}

/// An installed barrier is dominated by a DESCENDANT Rescan. A barrier for `/r` (cookie `/r/.cookie`)
/// that receives a Rescan at `/r/x` (a descendant coverage loss) must resolve `Dominated`: a raw
/// source Rescan fans out to every subscriber of its root, so the `/r` subscriber owes a
/// re-enumeration the Rescan stands in for — regardless of where its cookie sits.
///
/// Fail-on-old (domination keyed on cookie-path ancestry, `cookie_key.starts_with(event.key())`):
/// `/r/.cookie` does not start with `/r/x`, so the barrier is not dominated and falsely resolves
/// `Delivered` (here the reply is simply left unresolved).
#[tokio::test]
async fn an_installed_barrier_is_dominated_by_a_descendant_rescan() {
  use futures_util::FutureExt;

  use crate::source::SyncOutcome;

  let mut h = Harness::new();
  let sub = h.watch("/r", Interest::all()).await.expect("watch /r");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/r/.cookie"),
    sub,
    root: handle,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: reply_tx,
  });

  // A DESCENDANT loss: a Rescan at /r/x re-enumerates a subtree the /r subscriber owns, but its
  // cookie /r/.cookie does not start with /r/x — the old cookie-prefix rule missed exactly this.
  h.owner
    .consume_source_event(&rescan_event(handle, "/r/x", 5));

  assert!(
    matches!(
      (&mut reply_rx).now_or_never(),
      Some(Ok(Ok(SyncOutcome::Dominated)))
    ),
    "a descendant-loss Rescan dominates the /r barrier by subscription, not by cookie ancestry"
  );
}

/// A stale transient-root Rescan left on the preserved handle by a diverging-then-rolled-back in-place
/// widen is CLAMPED to the live root, so it never widens a parked debt to a common ancestor. The
/// diverging `replace(/a → /z)` and the rollback `replace(→ /a/b)` each commit a full-root Rescan on
/// the one preserved handle (the fake now models the real `FsSource`); the stale `Rescan(/z)` rides a
/// handle whose CURRENT root is the rolled-back `/a/b`, disjoint from `/z`.
///
/// Fail-on-old (no clamp): pumping the stale `Rescan(/z)` merges its `/z` key into the rollback's
/// parked `/a/b` debt at their common ancestor (the root `/`), over-owing a re-enumeration of the
/// whole tree. With the clamp the stale key is rewritten to the live root, so the debt stays `/a/b`.
#[tokio::test]
async fn a_transient_root_rescan_after_a_widen_rollback_is_clamped_to_the_live_root() {
  let mut h = Harness::new();
  h.owner.source.supports_replace = true;

  let s_narrow = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let handle = h
    .owner
    .subsumer
    .subscription_root(s_narrow)
    .expect("live root");

  // The widen of /a canonicalizes to the DIVERGENT /z (which does not contain /a/b), so the widen
  // rolls back to /a/b on the preserved handle. Each `replace` enqueues one full-root Rescan on the
  // handle's stream: Rescan(/z) from the divergent retarget, then Rescan(/a/b) from the rollback.
  h.owner
    .source
    .retarget
    .insert(PathBuf::from("/a"), PathBuf::from("/z"));
  let err = h
    .watch("/a", Interest::all())
    .await
    .expect_err("the diverging widen is refused");
  assert!(matches!(err, WatchError::CanonicalRace), "{err:?}");

  // The rollback already parked s_narrow's dominating Rescan at its exact /a/b coverage, and the
  // preserved handle's CURRENT root_key is the rolled-back /a/b.
  assert_eq!(
    h.owner.needs_rescan.get(&s_narrow).map(|p| p.key.clone()),
    Some(key("/a/b")),
    "the rollback owes s_narrow a Rescan at its exact /a/b coverage"
  );
  assert_eq!(h.owner.source.root_key(handle), Some(key("/a/b")));

  // Pump the replace-emitted stream: the stale transient-root Rescan(/z) then the rollback's
  // Rescan(/a/b), both riding the live handle.
  let mut pumped = Vec::new();
  while let Some(ev) = h.owner.source.next().await {
    pumped.push(ev);
  }
  assert_eq!(
    pumped.len(),
    2,
    "each replace enqueued one full-root Rescan: {pumped:?}"
  );
  for ev in &pumped {
    h.owner.consume_source_event(ev);
  }

  // The owed re-enumeration for s_narrow stays at /a/b: the clamp rewrote the stale disjoint /z to
  // the live root, so merging it never widened the debt to a common ancestor (`/`).
  assert_eq!(
    h.owner.needs_rescan.get(&s_narrow).map(|p| p.key.clone()),
    Some(key("/a/b")),
    "the stale /z Rescan was clamped to the live root; the debt never widened to a common ancestor"
  );
}

/// `on_sync` skips an already-canceled reply. If the caller's `sync()` deadline fires during
/// admission — dropping the response receiver — the owner must not mint a token, await `begin_sync`,
/// or park a PendingSync for a reply nobody will read.
#[tokio::test]
async fn on_sync_skips_an_already_canceled_barrier() {
  use crate::{error::SyncError, source::SyncOutcome};

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");

  // The caller already timed out during admission: its response receiver is dropped, so the reply
  // sender reports canceled before the owner does any cookie work.
  let (reply_tx, reply_rx) = futures_channel::oneshot::channel::<Result<SyncOutcome, SyncError>>();
  drop(reply_rx);
  assert!(
    reply_tx.is_canceled(),
    "the reply is canceled before on_sync runs"
  );

  h.owner.on_sync(sub, 0, reply_tx).await;

  assert!(
    h.owner.pending_syncs.is_empty(),
    "no PendingSync is parked for an already-canceled reply"
  );
  // `on_sync` increments `sync_seq` before minting the token / calling `begin_sync`, so an unmoved
  // seq proves the skip precedes any cookie work.
  assert_eq!(
    h.owner.sync_seq, 0,
    "no token was minted — the skip precedes begin_sync"
  );
  assert!(
    h.owner.source.ended_syncs.is_empty(),
    "no cookie was written, so none is reaped"
  );
}

/// Finding 1, the inter-arm race forced deterministically: the fs write COMPLETES (delivers its
/// cookie) between the `select_biased!` pass that polls `begin_sync` and that same pass's
/// cancellation arm. A scripted `begin_sync` future side-effect-delivers the cookie key yet still
/// returns `Pending`, so the now-ready cancellation wins the SAME pass — the exact "the fs sent Ok
/// between select arm 1 and arm 3 of one pass" interleave. The owner never learned the cookie's
/// path (only a completed `begin_sync` returns it), so the ONLY thing that can free the physical
/// cookie is `cancel_sync(token)` on the abandon arm.
///
/// Fail-on-old (drop the `cancel_sync` on the cancellation arm): `cancelled_syncs` is empty and the
/// delivered cookie is orphaned — the leak the whole token-cancel handshake exists to close.
#[tokio::test]
async fn a_write_completing_between_its_poll_and_the_cancel_poll_is_cancelled_by_token() {
  use core::sync::atomic::Ordering;
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  h.owner.source.sync_script =
    VecDeque::from([ScriptStep::Pending, ScriptStep::PendingThenComplete]);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");

  let loss_gen = h.owner.loss_gen.load(Ordering::SeqCst);
  let (reply_tx, reply_rx) = futures_channel::oneshot::channel();
  let mut cx = Context::from_waker(Waker::noop());
  let mut fut = Box::pin(h.owner.on_sync(sub, loss_gen, reply_tx));

  // Pass #1: `begin_sync`'s first scripted step is `Pending`, and the caller is still waiting
  // (its receiver is alive) so the cancellation arm is pending too — the whole pass parks. This
  // models R7-1's healthy ordering: nothing is ready, so nothing is dropped.
  assert!(
    fut.as_mut().poll(&mut cx).is_pending(),
    "the write is in flight and the caller still waits — the pass parks"
  );

  // The caller's deadline fires: its response receiver drops. On the NEXT pass the write's
  // scripted step delivers the cookie (side effect) yet returns `Pending`, and the now-ready
  // cancellation wins the SAME pass; the write future — holding a ready, unread delivery — is
  // dropped with the `select`.
  drop(reply_rx);
  let admit = fut.as_mut().poll(&mut cx);
  assert!(
    matches!(admit, Poll::Ready(super::SyncAdmit::Done)),
    "the cancellation arm resolves the abandoned barrier in the same pass"
  );
  drop(fut);

  let token = h
    .owner
    .source
    .begun_token
    .expect("begin_sync minted the token");
  assert_eq!(
    h.owner.source.fs_delivered,
    vec![key("/a/cookie-1")],
    "the write DID complete and deliver its cookie between the two arm polls"
  );
  assert!(
    h.owner.source.ended_syncs.is_empty(),
    "no path-precise reap was possible — the owner never learned the cookie key"
  );
  assert_eq!(
    h.owner.source.cancelled_syncs,
    vec![token],
    "the token cancel is the ONLY thing that frees the delivered-but-unread cookie"
  );
  assert!(
    h.owner.pending_syncs.is_empty(),
    "the abandoned barrier parked nothing (leak oracle)"
  );
}

/// The close-arm companion to the inter-arm race: same scripted delivery, but a CLOSE arrives
/// while the write is in flight instead of the caller timing out. On the pass where the write
/// side-effect-delivers its cookie, the close arm — ranked ABOVE cancellation — wins, threading its
/// reply back for teardown AND token-cancelling the delivered-but-unread cookie.
///
/// Fail-on-old (drop the `cancel_sync` on the close arm): `cancelled_syncs` is empty and the
/// delivered cookie is orphaned across the close.
#[tokio::test]
async fn a_write_completing_between_its_poll_and_the_cancel_poll_is_cancelled_by_token_close_arm() {
  use core::sync::atomic::Ordering;
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  h.owner.source.sync_script =
    VecDeque::from([ScriptStep::Pending, ScriptStep::PendingThenComplete]);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");

  let loss_gen = h.owner.loss_gen.load(Ordering::SeqCst);
  // The caller stays alive (its receiver is held), so only the close can win the race.
  let (reply_tx, _reply_rx) = futures_channel::oneshot::channel();
  let mut cx = Context::from_waker(Waker::noop());
  let mut fut = Box::pin(h.owner.on_sync(sub, loss_gen, reply_tx));

  assert!(
    fut.as_mut().poll(&mut cx).is_pending(),
    "the write is in flight and no close is queued — the pass parks"
  );

  // A close is requested on the dedicated signal while the write is in flight. On the next pass
  // the write delivers its cookie (side effect) yet returns `Pending`, and the close arm wins the
  // SAME pass.
  let (close_reply, _close_resp) =
    futures_channel::oneshot::channel::<Result<(), super::CloseError>>();
  h.closes
    .try_send(close_reply)
    .expect("queue the close on the dedicated signal");

  let admit = fut.as_mut().poll(&mut cx);
  assert!(
    matches!(admit, Poll::Ready(super::SyncAdmit::CloseRequested(_))),
    "the close arm consumes its reply and abandons the in-flight write"
  );
  drop(fut);

  let token = h
    .owner
    .source
    .begun_token
    .expect("begin_sync minted the token");
  assert_eq!(
    h.owner.source.fs_delivered,
    vec![key("/a/cookie-1")],
    "the write delivered its cookie between the two arm polls"
  );
  assert!(
    h.owner.source.ended_syncs.is_empty(),
    "the owner never learned the cookie key — no path-precise reap"
  );
  assert_eq!(
    h.owner.source.cancelled_syncs,
    vec![token],
    "the close abandon token-cancels the delivered-but-unread cookie"
  );
  assert!(
    h.owner.pending_syncs.is_empty(),
    "the abandoned barrier parked nothing (leak oracle)"
  );
}

/// The guard that keeps the token cancel from firing spuriously: when the write is READY on the
/// pass (not merely side-effect-delivering), the write-first bias makes it win the tie over a
/// simultaneously-ready cancellation — R7-1's ordering — and a completed cookie for a gone caller
/// is reaped by PATH (`end_sync`), never token-cancelled. This proves the cancel is confined to the
/// abandon arms, not the admit path.
#[tokio::test]
async fn a_ready_write_still_wins_the_tie_and_is_not_token_cancelled() {
  use core::sync::atomic::Ordering;
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  h.owner.source.sync_script = VecDeque::from([ScriptStep::Pending, ScriptStep::Ready]);
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");

  let loss_gen = h.owner.loss_gen.load(Ordering::SeqCst);
  let (reply_tx, reply_rx) = futures_channel::oneshot::channel();
  let mut cx = Context::from_waker(Waker::noop());
  let mut fut = Box::pin(h.owner.on_sync(sub, loss_gen, reply_tx));

  assert!(
    fut.as_mut().poll(&mut cx).is_pending(),
    "the write is in flight; the caller still waits — the pass parks"
  );

  // The caller's deadline fires — but on the next pass the write is READY, and the write-first
  // bias makes it win the tie over the simultaneously-ready cancellation. A completed cookie for a
  // gone caller is reaped by PATH, never token-cancelled.
  drop(reply_rx);
  let admit = fut.as_mut().poll(&mut cx);
  assert!(
    matches!(admit, Poll::Ready(super::SyncAdmit::Done)),
    "the ready write wins the tie and admits"
  );
  drop(fut);

  assert_eq!(
    h.owner.source.ended_syncs,
    vec![key("/a/cookie-1")],
    "the completed cookie is reaped by PATH — the R7-1 write-first outcome"
  );
  assert!(
    h.owner.source.cancelled_syncs.is_empty(),
    "a completed write is NOT token-cancelled — the cancel fires only on abandon"
  );
  assert!(
    h.owner.source.fs_delivered.is_empty(),
    "the Ready step resolves the write; it does not side-effect-deliver"
  );
  assert!(
    h.owner.pending_syncs.is_empty(),
    "the gone caller's cookie is reaped inline, not parked (leak oracle)"
  );
}

/// A source for the END-TO-END sync tests: arms roots live, offers the barrier
/// ([`Source::begin_sync`]) returning a deterministic `<dir>/cookie-<seq>` key, and — when `observe`
/// is set — queues that cookie's own artifact event so the driver's funnel matches and resolves the
/// barrier `Delivered`. With `observe` cleared the cookie is never reported, so the barrier can only
/// resolve via the caller's `R::timeout`. `next` parks when its queue is empty, keeping the run loop
/// alive to answer `close`/further requests.
struct SyncSource {
  next_handle: u32,
  live: HashMap<u32, Vec<OsString>>,
  pending: VecDeque<SourceEvent<OsString, u32>>,
  observe: bool,
}

impl Source<OsString> for SyncSource {
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

  fn is_sync_artifact(&self, key: &[OsString]) -> bool {
    key
      .last()
      .and_then(|leaf| leaf.to_str())
      .is_some_and(|leaf| leaf.starts_with("cookie-"))
  }

  async fn begin_sync(
    &mut self,
    handle: u32,
    dir_key: &[OsString],
    token: SyncToken,
  ) -> Result<Vec<OsString>, crate::error::SyncError> {
    let mut cookie_key = dir_key.to_vec();
    cookie_key.push(OsString::from(format!("cookie-{}", token.seq())));
    if self.observe {
      // Report the cookie's own create so the funnel matches it and resolves the barrier.
      self.pending.push_back(SourceEvent::new(
        handle,
        cookie_key.clone(),
        EventKind::Created,
        Location::new(),
        Epoch::new(1),
        Some(ChangeId::new(NonZeroU64::MIN)),
      ));
    }
    Ok(cookie_key)
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    if let Some(event) = self.pending.pop_front() {
      Some(event)
    } else {
      // Park so the run loop survives to answer `close` and later requests.
      std::future::pending::<Option<SourceEvent<OsString, u32>>>().await
    }
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.live.get(&handle).cloned()
  }
}

/// F4 — a sync admitted through the DEDICATED mailbox (no longer the key/value-bearing command
/// mailbox) still runs end to end: [`Tributaries::sync`](super::Tributaries::sync) sends a
/// `SyncRequest`, the run loop's sync arm dispatches `on_sync`, the cookie's own event arrives, and
/// the barrier resolves `Delivered` on a clean flush — proving the rewired admission+observation path.
#[tokio::test]
async fn a_sync_admitted_through_the_dedicated_mailbox_still_resolves() {
  use crate::source::SyncOutcome;

  let source = SyncSource {
    next_handle: 0,
    live: HashMap::new(),
    pending: VecDeque::new(),
    observe: true,
  };
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());
  let sub = w
    .watch(key("/a"), (), WatchOptions::new())
    .await
    .expect("watch /a");

  let outcome = tokio::time::timeout(Duration::from_secs(5), w.sync(sub, Duration::from_secs(5)))
    .await
    .expect("the sync resolves within the test deadline")
    .expect("the sync succeeds");
  assert!(
    matches!(outcome, SyncOutcome::Delivered),
    "a clean end-to-end sync via the dedicated mailbox resolves Delivered: {outcome:?}"
  );
}

/// F4 — the caller's deadline bounds the barrier: a sync whose cookie is never observed resolves
/// `Err(Timeout)` (the `R::timeout` wrapping admission-plus-observation fires), never a hang.
#[tokio::test]
async fn a_sync_times_out_when_never_observed() {
  use crate::error::SyncError;

  let source = SyncSource {
    next_handle: 0,
    live: HashMap::new(),
    pending: VecDeque::new(),
    observe: false,
  };
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());
  let sub = w
    .watch(key("/a"), (), WatchOptions::new())
    .await
    .expect("watch /a");

  let result = tokio::time::timeout(
    Duration::from_secs(5),
    w.sync(sub, Duration::from_millis(100)),
  )
  .await
  .expect("the outer test deadline is not hit — the inner sync timeout fires first");
  assert!(
    matches!(result, Err(SyncError::Timeout)),
    "a barrier whose cookie is never observed times out: {result:?}"
  );
}

/// A SATURATING control-plane flood: it keeps the command mailbox continuously non-empty by
/// REFILLING the slot the owner just drained, and stops only once the channel closes.
///
/// Each command is an `Unwatch` of an ALREADY-RETIRED subscription: the owner answers it
/// `UnknownSubscription` without arming, disarming, or minting any state, so the flood is pure
/// control-plane pressure that allocates nothing however long it runs. (The shared
/// [`spawn_command_flood`] gives up on the first full mailbox, so it cannot hold a *prefilled* one
/// saturated — which is precisely the condition under test here.)
fn spawn_saturating_command_flood(
  commands: async_channel::Sender<super::Command<OsString, ()>>,
  retired: Subscription,
) -> tokio::task::JoinHandle<()> {
  tokio::spawn(async move {
    loop {
      let (reply, response) = futures_channel::oneshot::channel();
      drop(response);
      match commands.try_send(super::Command::Unwatch {
        sub: retired,
        reply,
      }) {
        Ok(()) => {}
        // A FULL mailbox is the goal, not a stop condition: yield, then refill the slot the owner
        // took, so the biased select never observes the mailbox empty.
        Err(async_channel::TrySendError::Full(_)) => tokio::task::yield_now().await,
        // The owner is gone.
        Err(async_channel::TrySendError::Closed(_)) => return,
      }
    }
  })
}

/// Ordinary command traffic must not starve the sync mailbox. The run loop's `select!` is biased and
/// polls `commands.recv()` ahead of the sync arm, so a CONTINUOUSLY-ready command mailbox means the
/// sync arm never wins: an admitted `SyncRequest` would sit until its caller's deadline expired even
/// though the owner is perfectly healthy. (The command-fairness valve does not help — it forces one
/// SOURCE service, then returns to the same ordering.) The loop-top take-at-most-one sync drain gives
/// the two control mailboxes 1:1 service, so the barrier resolves under any flood.
///
/// Run against the REAL `run` loop: the mailbox is prefilled to its full configured depth AND held
/// saturated by a refilling flood for the whole barrier.
///
/// Fail-on-old (no loop-top sync drain): the sync arm never wins against the saturated mailbox, so
/// the barrier starves and the caller's `R::timeout` fires — `Err(Timeout)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_flood_does_not_starve_the_sync_mailbox() {
  use crate::source::SyncOutcome;

  let source = SyncSource {
    next_handle: 0,
    live: HashMap::new(),
    pending: VecDeque::new(),
    observe: true,
  };
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> = super::Tributaries::with_source(
    source,
    // A deep BOUNDED mailbox, so the prefill below is a genuinely deep backlog the flood can hold
    // saturated — the shape a starved sync arm would never get out from under.
    TributariesOptions::new().with_command_capacity(std::num::NonZeroUsize::new(500).unwrap()),
  );
  let sub = w
    .watch(key("/a"), (), WatchOptions::new())
    .await
    .expect("watch /a");

  // A retired subscription for the flood to re-unwatch: answered `UnknownSubscription`, so every
  // flood command is pure control-plane pressure that mints no state.
  let retired = w
    .watch(key("/doomed"), (), WatchOptions::new())
    .await
    .expect("watch /doomed");
  w.unwatch(retired).await.expect("retire /doomed");

  // Saturate the mailbox to its full depth BEFORE the sync is issued, then keep it saturated: the
  // command arm is ready at every single poll of the biased select from here on.
  for _ in 0..500 {
    let (reply, response) = futures_channel::oneshot::channel();
    drop(response);
    w.commands
      .try_send(super::Command::Unwatch {
        sub: retired,
        reply,
      })
      .expect("prefill the command backlog");
  }
  let flood = spawn_saturating_command_flood(w.commands.clone(), retired);

  // The barrier is served by the loop-top fair drain, never by the starved sync arm.
  let outcome = tokio::time::timeout(Duration::from_secs(10), w.sync(sub, Duration::from_secs(5)))
    .await
    .expect("the outer test deadline is not hit — the sync resolves or its own timeout fires");
  flood.abort();
  let outcome = outcome.expect("the sync resolves rather than starving behind the command flood");
  assert!(
    matches!(outcome, SyncOutcome::Delivered),
    "the barrier resolves cleanly under the flood — no loss occurred, so the deliberately GLOBAL \
     loss generation must not fire spuriously on unrelated control-plane traffic: {outcome:?}"
  );
}

/// A source for the HELD-write tests: it arms roots live and offers the barrier
/// ([`Source::begin_sync`]), but `begin_sync` first parks on a gate the test holds shut — modelling a
/// hung backend write (a stuck FUSE/NFS mount) that never returns. `next` parks when idle, keeping the
/// run loop alive so the race's cancellation and close arms can free the owner.
struct HeldBeginSyncSource {
  next_handle: u32,
  live: HashMap<u32, Vec<OsString>>,
  /// `begin_sync` awaits one token here before returning the cookie. The tests never send (and keep
  /// the paired sender alive so the channel stays open rather than erroring), so the write stays held
  /// for the whole test — the only thing that frees the owner is the race, never the write completing.
  begin_gate: async_channel::Receiver<()>,
}

impl Source<OsString> for HeldBeginSyncSource {
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

  fn is_sync_artifact(&self, key: &[OsString]) -> bool {
    key
      .last()
      .and_then(|leaf| leaf.to_str())
      .is_some_and(|leaf| leaf.starts_with("cookie-"))
  }

  async fn begin_sync(
    &mut self,
    _handle: u32,
    dir_key: &[OsString],
    token: SyncToken,
  ) -> Result<Vec<OsString>, crate::error::SyncError> {
    // Park on the test's gate: the write is held until the test releases it (it never does), so the
    // owner would wedge here forever under an inline `begin_sync().await`.
    let _ = self.begin_gate.recv().await;
    let mut cookie_key = dir_key.to_vec();
    cookie_key.push(OsString::from(format!("cookie-{}", token.seq())));
    Ok(cookie_key)
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    // Park so the run loop survives to service the race and later commands.
    std::future::pending::<Option<SourceEvent<OsString, u32>>>().await
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.live.get(&handle).cloned()
  }
}

/// A held backend write must not wedge the owner. When the caller's `sync()` deadline fires and drops
/// its response, the race's cancellation arm frees the owner within the caller's own timeout, so the
/// owner resumes servicing its mailbox — a follow-up command resolves promptly.
///
/// Fail-on-old (the inline `begin_sync().await`): after the caller is gone the owner stays parked in
/// the held write forever, so the follow-up watch never resolves and this test hangs to its bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timed_out_sync_frees_the_owner_when_the_caller_drops() {
  use crate::error::SyncError;

  // The gate the test holds shut: `begin_sync` parks on it forever, modelling a hung backend write.
  let (_begin_tx, begin_rx) = async_channel::unbounded::<()>();
  let source = HeldBeginSyncSource {
    next_handle: 0,
    live: HashMap::new(),
    begin_gate: begin_rx,
  };
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());
  let sub = w
    .watch(key("/a"), (), WatchOptions::new())
    .await
    .expect("watch /a");

  // The owner dispatches this sync and parks in the held write's race. The caller's deadline fires,
  // dropping the response — which (only with the race) fires the owner's cancellation arm and frees
  // it. A generous outer bound proves the INNER sync timeout is what returns, not a hang.
  let result = tokio::time::timeout(
    Duration::from_secs(10),
    w.sync(sub, Duration::from_millis(300)),
  )
  .await
  .expect("the outer bound is not hit — the inner sync timeout returns");
  assert!(
    matches!(result, Err(SyncError::Timeout)),
    "the held sync times out: {result:?}"
  );

  // The owner must not be wedged in the abandoned write: a subsequent command is serviced promptly.
  // Under the old inline await this watch never resolves (the owner is still parked in the held
  // `begin_sync`), so the bound below fires and the test fails.
  tokio::time::timeout(
    Duration::from_secs(5),
    w.watch(key("/b"), (), WatchOptions::new()),
  )
  .await
  .expect(
    "the owner services a command after the timed-out sync — it is not wedged in the held write",
  )
  .expect("the follow-up watch succeeds");
  assert!(
    w.view().is_watched(&key("/b")),
    "the follow-up watch committed — the owner resumed servicing the mailbox after freeing itself"
  );
}

/// A close during a held write tears down at once — it does not wait the write out. The close arm in
/// `on_sync`'s race outranks the parked `begin_sync`, so a `close` on the dedicated signal wins and
/// rides back to drive teardown, and the abandoned sync's caller then sees the owner gone.
///
/// This is the close-race form's guarantee: with a cancellation-only race, this close would instead
/// block behind the held write until the sync's own (long-lived) caller went away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_during_a_held_sync_tears_down_promptly() {
  use crate::error::SyncError;

  let (_begin_tx, begin_rx) = async_channel::unbounded::<()>();
  let source = HeldBeginSyncSource {
    next_handle: 0,
    live: HashMap::new(),
    begin_gate: begin_rx,
  };
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());
  let sub = w
    .watch(key("/a"), (), WatchOptions::new())
    .await
    .expect("watch /a");

  // A sync with a LONG deadline on a background task, so it never self-cancels: the owner parks in the
  // held write, and the ONLY thing that can free it is the close under test.
  let syncer = {
    let w = w.clone();
    tokio::spawn(async move { w.sync(sub, Duration::from_secs(30)).await })
  };
  // Let the owner dispatch the sync and park in the held `begin_sync` before the close arrives.
  tokio::time::sleep(Duration::from_millis(200)).await;

  // Close must resolve WITHOUT the gate ever opening: the close arm outranks the parked write.
  tokio::time::timeout(Duration::from_secs(5), w.close())
    .await
    .expect("close tears down promptly while the write is held — it does not wait the write out")
    .expect("close acknowledges");

  // The abandoned held sync resolves once the owner tore down: on_sync returned its close verdict
  // without ever sending on the sync's reply, so the dropped reply surfaces `Closed` to the caller.
  let sync_result = tokio::time::timeout(Duration::from_secs(5), syncer)
    .await
    .expect("the held sync resolves once the owner tore down")
    .expect("sync task");
  assert!(
    matches!(sync_result, Err(SyncError::Closed)),
    "the abandoned held sync resolves Closed after the close-driven teardown: {sync_result:?}"
  );
}

/// A source for the HELD-RETARGET tests: it arms roots live and offers the in-place widen
/// ([`Source::replace`]), but `replace` first parks on a gate the test holds shut — modelling a hung
/// backend retarget (a stuck FUSE/NFS mount) that never returns. `next` parks when idle, keeping the
/// run loop alive so the race's close arm can free the owner.
struct HeldReplaceSource {
  next_handle: u32,
  live: HashMap<u32, Vec<OsString>>,
  /// `replace` awaits one token here before returning. The tests never send (and keep the paired
  /// sender alive so the channel stays open rather than erroring), so the retarget stays held for the
  /// whole test — the only thing that frees the owner is the race, never the retarget completing.
  replace_gate: async_channel::Receiver<()>,
  /// When `Some`, the FIRST `replace` skips the gate and commits at this key instead. Pointed
  /// somewhere that contains NO subsumed root, it is the canonicalization race that drives the owner
  /// into the widen's ROLLBACK retarget — so the SECOND `replace`, the rollback, is the held one.
  first_replace_diverges_to: Option<Vec<OsString>>,
  /// `replace` calls so far, so the divergent form above can hold the rollback rather than the widen.
  replace_calls: u32,
}

impl Source<OsString> for HeldReplaceSource {
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

  async fn replace(
    &mut self,
    handle: u32,
    new_key: &[OsString],
  ) -> Result<Armed<OsString, u32>, WatchError> {
    self.replace_calls += 1;
    // The divergent form: commit the widen's retarget at a key the plan does not preserve, so the
    // owner rolls back — and the rollback below is what parks on the gate.
    if self.replace_calls == 1
      && let Some(divergent) = self.first_replace_diverges_to.clone()
    {
      self.live.insert(handle, divergent.clone());
      return Ok(Armed::new(handle, divergent));
    }
    // Park on the test's gate: the retarget is held until the test releases it (it never does), so
    // the owner would wedge here forever under an inline `replace().await`.
    let _ = self.replace_gate.recv().await;
    self.live.insert(handle, new_key.to_vec());
    Ok(Armed::new(handle, new_key.to_vec()))
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    // Park so the run loop survives to service the race and later commands.
    std::future::pending::<Option<SourceEvent<OsString, u32>>>().await
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.live.get(&handle).cloned()
  }
}

/// Drives a widen that takes the IN-PLACE [`Source::replace`] path against a source whose retarget is
/// held forever, then closes: shared by the two held-retarget tests, which differ only in WHICH of the
/// widen's two `replace` awaits is the held one. Asserts the finding's acceptance both ways — `close()`
/// resolves without the gate ever opening, and the abandoned widen's `watch()` sees `Closed`.
async fn assert_a_held_retarget_does_not_wedge_close(
  first_replace_diverges_to: Option<Vec<OsString>>,
) {
  // The gate the test holds shut: `replace` parks on it forever, modelling a hung backend retarget.
  let (_replace_tx, replace_rx) = async_channel::unbounded::<()>();
  let source = HeldReplaceSource {
    next_handle: 0,
    live: HashMap::new(),
    replace_gate: replace_rx,
    first_replace_diverges_to,
    replace_calls: 0,
  };
  let w: super::Tributaries<OsString, (), TokioRuntime, u32> =
    super::Tributaries::with_source(source, TributariesOptions::new());
  // The SOLE root the widen below subsumes — which is what sends it down the in-place retarget path
  // (`unwatch.as_slice()` matching `[only]`) rather than release-and-rearm.
  w.watch(key("/a/b"), (), WatchOptions::new())
    .await
    .expect("watch /a/b");

  // The widen on a background task, so it never goes away on its own: the owner parks in the held
  // retarget, and the ONLY thing that can free it is the close under test. (A `watch` caller has no
  // deadline to self-cancel on — and could not interrupt the owner if it did, which is exactly why
  // the race is close-only.)
  let widener = {
    let w = w.clone();
    tokio::spawn(async move { w.watch(key("/a"), (), WatchOptions::new()).await })
  };
  // Let the owner dispatch the widen and park in the held `replace` before the close arrives.
  tokio::time::sleep(Duration::from_millis(200)).await;

  // Close must resolve WITHOUT the gate ever opening: the close arm outranks the parked retarget.
  tokio::time::timeout(Duration::from_secs(5), w.close())
    .await
    .expect("close tears down promptly while the retarget is held — it does not wait it out")
    .expect("close acknowledges");

  // The abandoned widen resolves once the owner tore down: the reconcile returned its close verdict
  // without ever sending on the watch's reply, so the dropped reply surfaces `Closed` to the caller.
  let watch_result = tokio::time::timeout(Duration::from_secs(5), widener)
    .await
    .expect("the held widen resolves once the owner tore down")
    .expect("widen task");
  assert!(
    matches!(watch_result, Err(WatchError::Closed)),
    "the abandoned held widen resolves Closed after the close-driven teardown: {watch_result:?}"
  );
}

/// A held in-place widen RETARGET must not wedge the owner. The owner parks in the held `replace`
/// mid-reconcile; the close on the dedicated signal wins that race, rides back through
/// `dispatch_command` as the same `Flow::Break` the run loop's own close arm produces, and tears down
/// — so `close()`'s bounded-latency contract holds even against a mount that never answers.
///
/// Fail-on-old (the inline `self.source.replace(only, key).await`): the owner stays parked in the held
/// retarget forever, so the run loop never polls `closes` again and `close()` hangs to its bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hung_in_place_replace_does_not_wedge_close() {
  assert_a_held_retarget_does_not_wedge_close(None).await;
}

/// The widen's ROLLBACK retarget is raced too. Here the first `replace` COMMITS at `/z` — a key
/// containing none of the subsumed roots, so `fs_path_preserves_plan` rejects it and the owner rolls
/// the retarget back — and it is that rollback which hangs. Both of the widen's `replace` awaits are
/// therefore proven close-interruptible, not just the first.
///
/// Fail-on-old (the inline rollback `self.source.replace(handle, &only_key).await`): same wedge, one
/// await later — `close()` hangs to its bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hung_in_place_replace_rollback_does_not_wedge_close() {
  assert_a_held_retarget_does_not_wedge_close(Some(key("/z"))).await;
}

/// A raw `Modified` [`SourceEvent`] carrying a real root-relative `location` — the
/// coordinate fan-out must rebase per subscriber. `location` is given as `/`-joined
/// segments **relative to the armed root**, exactly as a source reports it.
fn source_modified_at(
  handle: u32,
  path: &str,
  location: &str,
  epoch: u64,
) -> SourceEvent<OsString, u32> {
  let segments = location
    .split('/')
    .filter(|s| !s.is_empty())
    .map(tributary_proto::Segment::new);
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Modified,
    Location::from_segments(segments),
    Epoch::new(epoch),
    Some(ChangeId::new(NonZeroU64::MIN)),
  )
}

/// A raw `Rescan` [`SourceEvent`] carrying a real root-relative `location`, given as
/// `/`-joined segments relative to the armed root it was captured against — the located
/// coverage-loss signal a source emits for a subtree below its root.
fn rescan_event_at(
  handle: u32,
  path: &str,
  location: &str,
  epoch: u64,
) -> SourceEvent<OsString, u32> {
  let segments = location
    .split('/')
    .filter(|s| !s.is_empty())
    .map(tributary_proto::Segment::new);
  SourceEvent::new(
    handle,
    key(path),
    EventKind::Rescan,
    Location::from_segments(segments),
    Epoch::new(epoch),
    Some(ChangeId::new(NonZeroU64::MIN)),
  )
}

/// A raw whole-`Moved` [`SourceEvent`] carrying BOTH endpoints' real root-relative
/// locations, each given as `/`-joined segments relative to the one armed root the move was
/// captured against — the pair a source reports for a rename inside its root.
fn source_moved_at(
  handle: u32,
  from: &str,
  from_location: &str,
  to: &str,
  to_location: &str,
  epoch: u64,
) -> SourceEvent<OsString, u32> {
  let segments = |location: &str| {
    Location::from_segments(
      location
        .split('/')
        .filter(|s| !s.is_empty())
        .map(tributary_proto::Segment::new)
        .collect::<Vec<_>>(),
    )
  };
  SourceEvent::new(
    handle,
    key(to),
    EventKind::Moved { from: key(from) },
    segments(to_location),
    Epoch::new(epoch),
    Some(ChangeId::new(NonZeroU64::MIN)),
  )
  .with_move_from_location(segments(from_location))
}

/// A rescan is a LOCATED statement — "coverage became uncertain at and below this key" —
/// and routing it by geometry rather than by shared physical root is what keeps a
/// per-subscription consumer inside its own boundary. These cells pin the three cases and
/// the loss the disjoint one used to cause.
mod rescan_geometry {
  use super::*;

  /// A rescan disjoint from a subscription is not delivered to it, while a sibling on the
  /// same physical root that the loss DOES touch still receives it.
  ///
  /// Fail-on-old (fan-out pushed every rescan to every subscriber of the root): the
  /// disjoint `/a/b/deep` receives `Rescan(/a/x)` — a path outside its watch, naming a
  /// subtree it owns none of.
  #[tokio::test]
  async fn a_disjoint_located_rescan_is_not_delivered() {
    let mut h = Harness::new();
    let wide = h.watch("/a", Interest::all()).await.expect("watch /a");
    let deep = h
      .watch("/a/b/deep", Interest::all())
      .await
      .expect("watch /a/b/deep");

    h.owner.consume_source_event(&rescan_event(1, "/a/x", 1));

    let delivered = h.drain();
    assert_eq!(
      delivered.len(),
      1,
      "only the subscription the loss touches is served: {delivered:?}"
    );
    assert_eq!(delivered[0].subscription(), wide);
    assert_eq!(
      delivered[0].path(),
      Path::new("/a/x"),
      "the covering subscription keeps the located key"
    );
    assert!(
      !delivered.iter().any(|e| e.subscription() == deep),
      "the disjoint sibling receives no instruction to inspect /a/x"
    );
  }

  /// A rescan that CONTAINS a subscription still reaches it — a whole-root loss loses
  /// nobody — but the instruction is clamped to that subscription's own key.
  ///
  /// Fail-on-old: the narrow subscriber is told to re-enumerate `/a`, which is neither its
  /// data nor its business.
  #[tokio::test]
  async fn a_containing_rescan_is_clamped_to_the_subscription() {
    let mut h = Harness::new();
    let wide = h.watch("/a", Interest::all()).await.expect("watch /a");
    let deep = h
      .watch("/a/b/deep", Interest::all())
      .await
      .expect("watch /a/b/deep");

    h.owner.consume_source_event(&rescan_event(1, "/a", 1));

    let delivered = h.drain();
    let path_of = |who: Subscription| {
      delivered
        .iter()
        .find(|e| e.subscription() == who)
        .map(Event::path)
    };
    assert_eq!(delivered.len(), 2, "a root-wide loss reaches both");
    assert_eq!(path_of(wide), Some(PathBuf::from("/a")));
    assert_eq!(
      path_of(deep),
      Some(PathBuf::from("/a/b/deep")),
      "the contained subscription re-enumerates ITS OWN subtree"
    );
  }

  /// A pending sync on a subscription the located loss does not touch must NOT resolve
  /// `Dominated`: domination stands in for a re-enumeration, and this subscriber is being
  /// handed none.
  ///
  /// Fail-on-old (domination keyed on physical-root equality): the disjoint sibling's
  /// barrier resolves `Dominated` for a recovery event it never receives.
  #[tokio::test]
  async fn a_disjoint_rescan_does_not_dominate_an_unaffected_barrier() {
    use futures_util::FutureExt;

    let mut h = Harness::new();
    let touched = h.watch("/a/x", Interest::all()).await.expect("watch /a/x");
    let untouched = h.watch("/a/y", Interest::all()).await.expect("watch /a/y");
    // Both ride one root: /a/x arms it, /a/y widens to /a and re-points /a/x onto it.
    h.watch("/a", Interest::all()).await.expect("watch /a");
    let root = h
      .owner
      .subsumer
      .subscription_root(touched)
      .expect("a live subscription rides a root");
    assert_eq!(
      h.owner.subsumer.subscription_root(untouched),
      Some(root),
      "the two subscriptions share one physical root"
    );
    h.drain();

    let (tx_touched, mut rx_touched) = futures_channel::oneshot::channel();
    let (tx_untouched, mut rx_untouched) = futures_channel::oneshot::channel();
    h.owner.pending_syncs.push(crate::driver::PendingSync {
      cookie_key: key("/a/x/.cookie"),
      sub: touched,
      root,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: tx_touched,
    });
    h.owner.pending_syncs.push(crate::driver::PendingSync {
      cookie_key: key("/a/y/.cookie"),
      sub: untouched,
      root,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: tx_untouched,
    });

    h.owner.consume_source_event(&rescan_event(root, "/a/x", 1));

    assert!(
      matches!(
        (&mut rx_touched).now_or_never(),
        Some(Ok(Ok(crate::source::SyncOutcome::Dominated)))
      ),
      "the barrier of the subscription the loss touched is dominated by it"
    );
    assert!(
      (&mut rx_untouched).now_or_never().is_none(),
      "the disjoint sibling's barrier is untouched — no re-enumeration was handed to it"
    );
    assert_eq!(
      h.owner.pending_syncs.len(),
      1,
      "only the affected barrier was consumed"
    );
  }
}

/// Suppressing an event behind standing rescan debt is sound only while that debt
/// actually covers it — spatially AND temporally. A parked debt is not always the whole
/// subscription, and its epoch was minted before the event it is now being asked to
/// stand in for, so both halves must be re-established at the moment of suppression.
mod parked_debt {
  use super::*;

  /// The trace: a located `Rescan(/a/x)` parks on a full channel, then an ordinary change
  /// in the DISJOINT sibling subtree `/a/y` is suppressed behind it. The parked debt must
  /// widen to cover `/a/y/file` and advance past its stamp.
  ///
  /// Fail-on-old (`note_loss` alone): the retained `Rescan(/a/x)` neither reaches
  /// `/a/y/file` nor postdates it, so the change disappears with no event and no covering
  /// recovery instruction — a reconstructing consumer stays permanently stale.
  #[tokio::test]
  async fn a_later_sibling_loss_widens_the_parked_located_rescan() {
    let mut h = Harness::bounded(1);
    let sub = h.watch("/a", Interest::all()).await.expect("watch /a");

    // Fill the one slot, then park the located rescan behind it.
    h.owner.fan_out_and_push(&source_modified(1, "/a/plug", 0));
    h.owner.fan_out_and_push(&rescan_event(1, "/a/x", 1));
    assert_eq!(
      h.owner.needs_rescan.get(&sub).map(|p| p.key.clone()),
      Some(key("/a/x")),
      "the located rescan parked unchanged at its own key"
    );

    // The stamp the next raw-0 delivery will receive (the high-water clamp), captured
    // before it is suppressed so the temporal half can be asserted exactly.
    let suppressed_stamp = h.owner.epochs.stamp(sub, Epoch::new(0));
    h.owner
      .fan_out_and_push(&source_modified(1, "/a/y/file", 0));

    let parked = h
      .owner
      .needs_rescan
      .get(&sub)
      .expect("debt is still parked");
    assert_eq!(
      parked.key,
      key("/a"),
      "the debt widened to the common ancestor covering BOTH losses"
    );
    assert!(
      parked.epoch > suppressed_stamp,
      "the debt's epoch strictly dominates the event it suppressed \
       ({:?} vs {suppressed_stamp:?})",
      parked.epoch
    );

    // And the delivered recovery instruction actually reaches the lost change.
    assert_eq!(h.drain().len(), 1, "the plug drains");
    h.owner.flush_pending_rescans();
    let recovery = h.drain();
    assert_eq!(recovery.len(), 1);
    assert!(recovery[0].is_rescan());
    assert!(
      recovery[0].reaches(&key("/a/y/file")),
      "the delivered Rescan covers the suppressed change: {:?}",
      recovery[0].path()
    );
    assert!(recovery[0].epoch() > suppressed_stamp, "…and postdates it");
  }

  /// A whole move has two affected endpoints, and a suppression must widen the debt to
  /// cover BOTH — the destination alone is not the change.
  ///
  /// Fail-on-old: the move's source endpoint `/a/src/f` is covered by neither the parked
  /// key nor the widened one.
  #[tokio::test]
  async fn a_suppressed_move_widens_the_debt_over_both_endpoints() {
    let mut h = Harness::bounded(1);
    let sub = h.watch("/a", Interest::all()).await.expect("watch /a");

    h.owner.fan_out_and_push(&source_modified(1, "/a/plug", 0));
    h.owner.fan_out_and_push(&rescan_event(1, "/a/dst/deep", 1));
    assert_eq!(
      h.owner.needs_rescan.get(&sub).map(|p| p.key.clone()),
      Some(key("/a/dst/deep"))
    );

    h.owner
      .fan_out_and_push(&source_moved(1, "/a/src/f", "/a/dst/f", 0));

    let parked_key = h
      .owner
      .needs_rescan
      .get(&sub)
      .expect("debt is still parked")
      .key
      .clone();
    assert_eq!(h.drain().len(), 1);
    h.owner.flush_pending_rescans();
    let recovery = h.drain();
    assert!(
      recovery[0].reaches(&key("/a/src/f")) && recovery[0].reaches(&key("/a/dst/f")),
      "the widened debt covers both endpoints of the lost move: {:?} (parked {:?})",
      recovery[0].path(),
      parked_key
    );
  }

  /// The same repair applies to an UNCLAIMED subscription, whose debt lives in the
  /// separate `suppressed_rescan` partition — the suppression path must not repair only
  /// one of the two maps.
  ///
  /// Fail-on-old: an unclaimed subscription's debt keeps its narrow key and stale epoch,
  /// so its grant's first delivery after the claim is a Rescan that covers nothing lost.
  #[tokio::test]
  async fn an_unclaimed_subscriptions_parked_debt_widens_too() {
    let mut h = Harness::bounded(1);
    let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
    h.owner.unclaimed.insert(sub);

    h.owner.fan_out_and_push(&source_modified(1, "/a/plug", 0));
    h.owner.fan_out_and_push(&rescan_event(1, "/a/x", 1));
    assert_eq!(
      h.owner.suppressed_rescan.get(&sub).map(|p| p.key.clone()),
      Some(key("/a/x")),
      "an unclaimed sub's debt parks in the suppressed partition"
    );

    let suppressed_stamp = h.owner.epochs.stamp(sub, Epoch::new(0));
    h.owner
      .fan_out_and_push(&source_modified(1, "/a/y/file", 0));

    let parked = h
      .owner
      .suppressed_rescan
      .get(&sub)
      .expect("the unclaimed debt is still parked");
    assert_eq!(parked.key, key("/a"), "it widened to cover the later loss");
    assert!(
      parked.epoch > suppressed_stamp,
      "and advanced past the event it suppressed"
    );
  }
}

/// The public `Location` must be relative to the key the caller watched, not to the
/// mutable physical root underneath it — otherwise an unrelated `watch` silently
/// re-coordinates a stable subscription and its filter starts rejecting.
mod location_coordinate {
  use super::*;

  /// The same logical change, before and after an unrelated caller widens the shared
  /// physical root, reports the SAME location to the unchanged subscription.
  ///
  /// Fail-on-old (the raw physical-root location was copied verbatim): the location grows
  /// from `[x]` to `[b, x]` when somebody else watches the ancestor.
  #[tokio::test]
  async fn a_widen_does_not_move_an_unrelated_subscriptions_coordinate() {
    let mut h = Harness::new();
    let narrow = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
    h.drain();

    // Armed root == /a/b, so the source reports the change at location [x].
    h.owner
      .fan_out_and_push(&source_modified_at(1, "/a/b/x", "x", 0));
    let before = h.drain();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].location().len(), 1, "one level below /a/b");

    // An unrelated caller watches /a: the shared physical root widens to /a and /a/b is
    // re-pointed onto it. /a/b's own key is untouched.
    h.watch("/a", Interest::all()).await.expect("watch /a");
    let root = h
      .owner
      .subsumer
      .subscription_root(narrow)
      .expect("the re-pointed subscription is live");
    h.drain();

    // The SAME logical change now arrives on the wider root, so its raw location is [b, x].
    h.owner
      .fan_out_and_push(&source_modified_at(root, "/a/b/x", "b/x", 1));
    let after = h.drain();
    let narrow_after = after
      .iter()
      .find(|e| e.subscription() == narrow)
      .expect("the narrow subscription still receives the change");
    assert_eq!(
      narrow_after.location(),
      before[0].location(),
      "the subscription's coordinate is invariant under an unrelated widen"
    );
    let wide_after = after
      .iter()
      .find(|e| e.subscription() != narrow)
      .expect("the widening subscription receives it too");
    assert_eq!(
      wide_after.location().len(),
      2,
      "the /a subscription's own coordinate is two levels deep — each sees its own"
    );
  }

  /// The rebased coordinate is what the FILTER sees, so a one-level depth filter written
  /// against the subscription's own key keeps admitting across the widen.
  ///
  /// Fail-on-old: after the widen the filter reads depth 2 and silently rejects every
  /// future change, with no coverage-loss signal to explain the gap.
  #[tokio::test]
  async fn a_depth_filter_survives_an_unrelated_widen() {
    let mut h = Harness::new();
    let narrow = h
      .watch_with(
        "/a/b",
        WatchOptions::new().with_filter(Filter::new(|input: &crate::FilterInput<'_, OsString>| {
          input.location().len() == 1
        })),
      )
      .await
      .expect("watch /a/b with a one-level filter");
    h.drain();

    h.owner
      .fan_out_and_push(&source_modified_at(1, "/a/b/x", "x", 0));
    assert_eq!(h.drain().len(), 1, "the filter admits before the widen");

    h.watch("/a", Interest::all()).await.expect("watch /a");
    let root = h
      .owner
      .subsumer
      .subscription_root(narrow)
      .expect("the re-pointed subscription is live");
    h.drain();

    h.owner
      .fan_out_and_push(&source_modified_at(root, "/a/b/x", "b/x", 1));
    let after = h.drain();
    assert!(
      after.iter().any(|e| e.subscription() == narrow),
      "the one-level filter still admits the same logical change after the widen: {after:?}"
    );
  }

  /// An in-place widen preserves the source handle — and therefore the queue behind it —
  /// so a change captured BEFORE the widen is drained after it, still carrying the
  /// coordinate of the narrower root it was captured against. Rebasing it by the depth of
  /// the root that is armed *now* over-strips it by the widen distance, re-coordinating
  /// exactly the subscription whose key never moved.
  ///
  /// FAIL-ON-REVERT: rebase on `root_view`'s current root depth instead of the event's own
  /// `captured_root_depth`, and the queued change reaches `/a/b` root-anchored — an empty
  /// location for a change one level below it, and a one-level filter that stops admitting.
  #[tokio::test]
  async fn a_change_queued_across_an_in_place_widen_keeps_its_capture_coordinate() {
    let mut h = Harness::new();
    // The gapless widen: the root is retargeted in place, so handle 1 survives it.
    h.owner.source.supports_replace = true;
    let narrow = h
      .watch_with(
        "/a/b",
        WatchOptions::new().with_filter(Filter::new(|input: &crate::FilterInput<'_, OsString>| {
          input.location().len() == 1
        })),
      )
      .await
      .expect("watch /a/b with a one-level filter");
    h.drain();

    // Armed root == /a/b: the source reports this change at location [x].
    h.owner
      .fan_out_and_push(&source_modified_at(1, "/a/b/x", "x", 0));
    let before = h.drain();
    assert_eq!(before.len(), 1, "the filter admits before the widen");

    // An unrelated caller widens the shared root to /a, in place.
    h.watch("/a", Interest::all()).await.expect("watch /a");
    assert_eq!(
      h.owner.subsumer.subscription_root(narrow),
      Some(1),
      "staging: the widen was in place, so the handle — and its queue — survived"
    );
    h.drain();

    // A change the source captured BEFORE the widen, drained only now: same handle, and
    // its location is still measured against /a/b.
    h.owner
      .fan_out_and_push(&source_modified_at(1, "/a/b/x", "x", 1));
    let after = h.drain();
    let queued = after
      .iter()
      .find(|e| e.subscription() == narrow)
      .expect("the one-level filter still admits the queued pre-widen change");
    assert_eq!(
      queued.location(),
      before[0].location(),
      "a change queued across the widen keeps the coordinate it was captured in"
    );
    assert_eq!(
      queued.location().len(),
      1,
      "one level below /a/b, as captured"
    );
  }

  /// The widener receives that same queued pre-widen change — and its own coordinate for
  /// it is unstatable: the leading segments are not in the delivery, and the key is in the
  /// source's component space rather than in canonical location segments. So the delivery
  /// is anchored at the subscription root, leaving its absolute key authoritative, instead
  /// of reporting `/a` + `[x]` for a change that is really at `/a/b/x`.
  ///
  /// FAIL-ON-REVERT: `saturating_sub` in `fan_out` instead of the `checked_sub` split, and
  /// `/a` is handed the location `[x]` — a name-bearing path (`/a/x`) that never changed.
  #[tokio::test]
  async fn the_widener_is_anchored_for_a_change_it_cannot_coordinate() {
    let mut h = Harness::new();
    h.owner.source.supports_replace = true;
    let narrow = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
    let wide = h.watch("/a", Interest::all()).await.expect("watch /a");
    h.drain();

    h.owner
      .fan_out_and_push(&source_modified_at(1, "/a/b/x", "x", 1));
    let after = h.drain();
    let at_widener = after
      .iter()
      .find(|e| e.subscription() == wide)
      .expect("the widener covers the change and receives it");
    assert!(
      at_widener.location().is_empty(),
      "the unstatable coordinate degrades to root-anchored, not to a wrong name: {:?}",
      at_widener.location()
    );
    assert_eq!(
      at_widener.path(),
      Path::new("/a/b/x"),
      "and the absolute key still says exactly what changed"
    );
    let at_narrow = after
      .iter()
      .find(|e| e.subscription() == narrow)
      .expect("the subscription at the capture root receives it too");
    assert_eq!(
      at_narrow.location().len(),
      1,
      "the subscription the change was captured under keeps its exact coordinate"
    );
  }

  /// The one transformation that rewrites a key — the clamp of a stale transient-root
  /// `Rescan` onto the live root — must restate the coordinate with it. The stale event's
  /// location was measured against the transient root, so carrying it onto the clamped key
  /// leaves a pair that describes no root: the anchor is inferred from
  /// `key.len() - location.len()`, and a deep location under a shallow live root underflows
  /// it to zero.
  ///
  /// FAIL-ON-REVERT: re-key the clamp by hand (`SourceEvent::new(handle, root_key, kind,
  /// event.location().clone(), ..)`) instead of `rekeyed_at_root`, and the subscription at
  /// `/a` is told to re-enumerate `/a` at `[d2, d3]` — a subtree of its own watch the loss
  /// never touched, whose real state it would then keep while believing it re-scanned.
  #[tokio::test]
  async fn a_clamped_transient_root_rescan_is_anchored_at_the_live_root() {
    let mut h = Harness::new();
    let at_root = h.watch("/a", Interest::all()).await.expect("watch /a");
    h.drain();

    // The stale artifact of a diverging-then-rolled-back in-place widen: a located `Rescan`
    // deep under the transient root `/z`, riding a handle whose CURRENT root is `/a`.
    h.owner
      .consume_source_event(&rescan_event_at(1, "/z/d1/d2/d3", "d1/d2/d3", 1));

    let delivered = h.drain();
    let clamped = delivered
      .iter()
      .find(|e| e.subscription() == at_root)
      .expect("the live root's subscriber receives the clamped re-enumeration");
    assert!(clamped.kind().is_rescan());
    assert_eq!(
      clamped.path(),
      Path::new("/a"),
      "the clamp names the live root, never the transient one"
    );
    assert!(
      clamped.location().is_empty(),
      "the clamped key IS the subscription's root, so the coordinate is the empty one — \
       not a leftover measured against /z: {:?}",
      clamped.location()
    );
  }

  /// A move has TWO endpoints and the raw event's location describes only the destination.
  /// The source-only projection re-keys the delivery onto the move's SOURCE, so it must
  /// carry the source's coordinate with it: a subscriber covering only the source is the
  /// one that needs to learn the file left its tree, and its filter reads the location.
  ///
  /// FAIL-ON-REVERT: root-anchor the projection (`location: Location::new()` in
  /// `Event::source_move_out`), and a location-aware filter is handed the WATCHED ROOT's
  /// coordinate for a change one level below it — so the one-level filter here rejects the
  /// removal outright, and even an admitting subscriber is told the change is at its root.
  #[tokio::test]
  async fn a_source_only_move_projection_carries_the_source_endpoints_coordinate() {
    let mut h = Harness::new();
    // The armed root is /a; /a/src is merely covered by it, so both endpoints of the move
    // below are measured against /a.
    let wide = h.watch("/a", Interest::all()).await.expect("watch /a");
    let source_only = h
      .watch_with(
        "/a/src",
        WatchOptions::new().with_filter(Filter::new(|input: &crate::FilterInput<'_, OsString>| {
          input.location().len() == 1
        })),
      )
      .await
      .expect("watch /a/src with a one-level filter");
    h.drain();

    // /a/src/f → /a/dst/f: the destination is outside /a/src, so that subscriber gets the
    // source-only projection (a synthesized Removed at the source endpoint).
    h.owner.fan_out_and_push(&source_moved_at(
      1, "/a/src/f", "src/f", "/a/dst/f", "dst/f", 1,
    ));
    let delivered = h.drain();

    let projected = delivered
      .iter()
      .find(|e| e.subscription() == source_only)
      .expect("the one-level filter admits the removal — it is one level below /a/src");
    assert!(projected.kind().is_removed());
    assert_eq!(
      projected.path(),
      Path::new("/a/src/f"),
      "the projection is keyed on the source endpoint"
    );
    assert_eq!(
      projected.location(),
      &Location::from_segments([tributary_proto::Segment::new("f")]),
      "and located there too, rebased into /a/src's own coordinate"
    );

    // The both-endpoints subscriber is unaffected: it receives the whole move, located at
    // the destination as before.
    let whole = delivered
      .iter()
      .find(|e| e.subscription() == wide)
      .expect("the covering subscription receives the whole move");
    assert_eq!(whole.move_from(), Some(key("/a/src/f").as_slice()));
    assert_eq!(
      whole.location(),
      &Location::from_segments(
        ["dst", "f"]
          .into_iter()
          .map(tributary_proto::Segment::new)
          .collect::<Vec<_>>()
      ),
      "a whole move stays located at its destination"
    );
  }
}

/// A [`Source`] mints its own sync-barrier artifacts inside the tree it watches, and no
/// consumer may ever be told about one. A rename, though, has TWO endpoints and can put an
/// artifact at one of them and an ordinary user object at the other — so the reservation is
/// a property of an ENDPOINT, and testing it against the event's key alone answers the
/// wrong question.
///
/// # The loss these cells stand over
///
/// `consume_source_event` used to test `is_sync_artifact(event.key())` and `return` on a
/// match. `SourceEvent::key` is a move's DESTINATION, so a user file renamed INTO the
/// reserved namespace matched — and the whole change was discarded before it ever reached
/// the fan-out. The subscriber watching the source endpoint was told nothing: no `Moved`,
/// no projected `Removed`, and no [`Rescan`](crate::EventKind::Rescan), because nothing
/// classified this as a coverage loss. Its picture of that name stayed stale for the life
/// of the watch, under a barrier that certifies delivery.
///
/// # Why every row runs twice
///
/// `FakeSource::is_sync_artifact` carries both of the grounds the real
/// `FsSource::is_sync_artifact` does — a leaf grammar and the leaf's immediate parent
/// directory — and they read different components of the key. A single-key suppression can
/// therefore survive under one ground while never being exercised by the other, which is
/// how this class of defect stays alive. Each row below is pinned against BOTH.
///
/// # The matrix
///
/// | source endpoint | destination endpoint | what a covering subscriber receives |
/// |---|---|---|
/// | artifact | artifact | nothing at all |
/// | user     | artifact | `Removed`, keyed and located at the SOURCE |
/// | artifact | user     | `Created`, keyed and located at the DESTINATION |
/// | user     | user     | the whole `Moved`, unchanged |
mod reserved_namespace {
  use futures_util::FutureExt;

  use super::*;
  use crate::source::SyncOutcome;

  /// A root-relative [`Location`] from `/`-joined segments — the coordinate form every
  /// assertion here compares against, built exactly as the source-event helpers build the
  /// coordinates they feed in.
  fn located(location: &str) -> Location {
    Location::from_segments(
      location
        .split('/')
        .filter(|s| !s.is_empty())
        .map(tributary_proto::Segment::new)
        .collect::<Vec<_>>(),
    )
  }

  /// GROUND 2's reserved path and its root-relative location under `/a`: a leaf no grammar
  /// could predict, classified only by the cookie DIRECTORY holding it.
  fn inside_the_cookie_directory(leaf: &str) -> (String, String) {
    (
      format!("/a/{COOKIE_DIR}/{leaf}"),
      format!("{COOKIE_DIR}/{leaf}"),
    )
  }

  // ---------------------------------------------------------------------------
  // Row: user → artifact. A `Removed` at the SOURCE endpoint.
  // ---------------------------------------------------------------------------

  /// The rename the whole-event discard swallowed. Two geometries are watched at once:
  /// `wide` covers BOTH endpoints (so an unmasked destination hands it the whole `Moved`,
  /// artifact path and all), and `source_only` covers ONLY the source — the subscription
  /// that used to receive nothing whatsoever.
  ///
  /// The location assertions are the point of using the two-location move helper: the
  /// move-out projection is re-keyed onto the source endpoint, so it must carry the
  /// SOURCE's coordinate, rebased into each subscriber's own.
  async fn assert_a_move_into_the_reserved_namespace_delivers_its_source_endpoint(
    artifact: &str,
    artifact_location: &str,
  ) {
    let mut h = Harness::new();
    let wide = h.watch("/a", Interest::all()).await.expect("watch /a");
    let source_only = h
      .watch("/a/important", Interest::all())
      .await
      .expect("watch /a/important");
    h.drain();

    h.owner.consume_source_event(&source_moved_at(
      1,
      "/a/important/file",
      "important/file",
      artifact,
      artifact_location,
      1,
    ));

    let delivered = h.drain();
    assert_eq!(
      delivered.len(),
      2,
      "both covering subscriptions learn the file left: {delivered:?}"
    );
    for (sub, coordinate) in [(wide, "important/file"), (source_only, "file")] {
      let projected = delivered
        .iter()
        .find(|e| e.subscription() == sub)
        .expect("a subscriber covering the source endpoint is served");
      assert!(
        projected.kind().is_removed(),
        "the covered endpoint is the source, so the move projects to a Removed: {projected:?}"
      );
      assert_eq!(
        projected.path(),
        Path::new("/a/important/file"),
        "keyed on the source endpoint, never on the reserved destination"
      );
      assert_eq!(
        projected.location(),
        &located(coordinate),
        "and located there too, rebased into this subscriber's own coordinate"
      );
      assert_eq!(
        projected.move_from(),
        None,
        "a Removed names no other endpoint, so the artifact path cannot leak through it"
      );
    }
  }

  /// FAIL-ON-REVERT: restore the whole-event discard (`if !event.kind().is_rescan() &&
  /// self.source.is_sync_artifact(event.key()) { .. return; }` at the head of
  /// `consume_source_event`) and NOTHING is delivered — the silent loss this class is.
  /// Dropping only the destination mask (`covers_to` back to a bare
  /// `to.starts_with(canonical)` in `route::project`) fails it the other way: `wide` gets a
  /// whole `Moved` naming the reserved destination.
  #[tokio::test]
  async fn a_move_into_the_reserved_namespace_delivers_its_source_endpoint_by_leaf_grammar() {
    assert_a_move_into_the_reserved_namespace_delivers_its_source_endpoint(
      "/a/cookie-7",
      "cookie-7",
    )
    .await;
  }

  /// The same row on the OTHER ground: the destination is reserved by the directory holding
  /// it, not by any name this crate could predict.
  ///
  /// FAIL-ON-REVERT: as above; additionally, drop the parent-directory ground from
  /// `FakeSource::is_sync_artifact` and this cell stops testing anything — the move becomes
  /// an ordinary one and the `Removed` assertion fails against a whole `Moved`.
  #[tokio::test]
  async fn a_move_into_the_reserved_namespace_delivers_its_source_endpoint_by_parent_directory() {
    let (artifact, location) = inside_the_cookie_directory("anything");
    assert_a_move_into_the_reserved_namespace_delivers_its_source_endpoint(&artifact, &location)
      .await;
  }

  // ---------------------------------------------------------------------------
  // Row: artifact → user. A `Created` at the DESTINATION endpoint.
  // ---------------------------------------------------------------------------

  /// The mirror: an artifact renamed OUT to an ordinary name. A subscriber covering the
  /// destination must learn an object ARRIVED in its tree — and must not learn that what
  /// arrived was the source's own barrier marker, so the projection names no `from`.
  async fn assert_a_move_out_of_the_reserved_namespace_delivers_its_destination_endpoint(
    artifact: &str,
    artifact_location: &str,
  ) {
    let mut h = Harness::new();
    let wide = h.watch("/a", Interest::all()).await.expect("watch /a");
    let dest_only = h
      .watch("/a/adopted", Interest::all())
      .await
      .expect("watch /a/adopted");
    h.drain();

    h.owner.consume_source_event(&source_moved_at(
      1,
      artifact,
      artifact_location,
      "/a/adopted/file",
      "adopted/file",
      1,
    ));

    let delivered = h.drain();
    assert_eq!(
      delivered.len(),
      2,
      "both covering subscriptions learn the object arrived: {delivered:?}"
    );
    for (sub, coordinate) in [(wide, "adopted/file"), (dest_only, "file")] {
      let projected = delivered
        .iter()
        .find(|e| e.subscription() == sub)
        .expect("a subscriber covering the destination endpoint is served");
      assert!(
        projected.kind().is_created(),
        "the covered endpoint is the destination, so the move projects to a Created: \
         {projected:?}"
      );
      assert_eq!(
        projected.path(),
        Path::new("/a/adopted/file"),
        "keyed on the destination endpoint: {projected:?}"
      );
      assert_eq!(
        projected.location(),
        &located(coordinate),
        "located at the destination, rebased into this subscriber's own coordinate"
      );
      assert_eq!(
        projected.move_from(),
        None,
        "a Created names no source, so the artifact it was cannot leak through it"
      );
    }
  }

  /// FAIL-ON-REVERT: drop the source mask (`covers_from` back to a bare
  /// `from.starts_with(canonical)` in `route::project`) and `wide` receives a whole `Moved`
  /// whose `from` is the artifact's own path.
  #[tokio::test]
  async fn a_move_out_of_the_reserved_namespace_delivers_its_destination_endpoint_by_leaf_grammar()
  {
    assert_a_move_out_of_the_reserved_namespace_delivers_its_destination_endpoint(
      "/a/cookie-7",
      "cookie-7",
    )
    .await;
  }

  /// The same row on the parent-directory ground.
  #[tokio::test]
  async fn a_move_out_of_the_reserved_namespace_delivers_its_destination_endpoint_by_parent_directory()
   {
    let (artifact, location) = inside_the_cookie_directory("anything");
    assert_a_move_out_of_the_reserved_namespace_delivers_its_destination_endpoint(
      &artifact, &location,
    )
    .await;
  }

  // ---------------------------------------------------------------------------
  // Row: artifact → artifact. Nothing at all.
  // ---------------------------------------------------------------------------

  /// A rename BETWEEN two reserved names is reserved at every endpoint it has, so it is
  /// settled without routing: never fanned out, never coalesced, never delivered.
  async fn assert_a_move_within_the_reserved_namespace_reaches_nobody(
    from: &str,
    from_location: &str,
    to: &str,
    to_location: &str,
  ) {
    let mut h = Harness::new();
    let _wide = h.watch("/a", Interest::all()).await.expect("watch /a");
    h.drain();

    h.owner
      .consume_source_event(&source_moved_at(1, from, from_location, to, to_location, 1));

    let delivered = h.drain();
    assert!(
      delivered.is_empty(),
      "a change reserved at every endpoint it has reaches no consumer: {delivered:?}"
    );
  }

  /// FAIL-ON-REVERT: narrow `ReservedEndpoints::is_total` to `matches!(self,
  /// Self::Destination | Self::All)`'s complement — or, minimally, drop `Self::All` from
  /// `masks_source` — and the whole-move suppression degrades to a `Removed` naming one
  /// artifact path.
  #[tokio::test]
  async fn a_move_within_the_reserved_namespace_reaches_nobody_by_leaf_grammar() {
    assert_a_move_within_the_reserved_namespace_reaches_nobody(
      "/a/cookie-7",
      "cookie-7",
      "/a/cookie-8",
      "cookie-8",
    )
    .await;
  }

  /// The same row on the parent-directory ground: two unpredictable leaves inside the one
  /// cookie directory.
  #[tokio::test]
  async fn a_move_within_the_reserved_namespace_reaches_nobody_by_parent_directory() {
    let (from, from_location) = inside_the_cookie_directory("one");
    let (to, to_location) = inside_the_cookie_directory("two");
    assert_a_move_within_the_reserved_namespace_reaches_nobody(
      &from,
      &from_location,
      &to,
      &to_location,
    )
    .await;
  }

  // ---------------------------------------------------------------------------
  // Row: user → user. The move, unchanged — the over-suppression guard.
  // ---------------------------------------------------------------------------

  /// Suppression removes a change from every stream, so a ground that over-reaches is the
  /// same silent loss with the endpoints swapped. Each of these destinations sits one step
  /// outside its ground — a leaf the grammar does not mint, and a leaf whose cookie
  /// directory is its GRANDparent rather than its parent (neither ground reads deeper than
  /// the immediate parent) — and the move must survive whole.
  async fn assert_a_move_near_but_outside_the_reserved_namespace_is_not_masked(
    to: &str,
    to_location: &str,
  ) {
    let mut h = Harness::new();
    let wide = h.watch("/a", Interest::all()).await.expect("watch /a");
    h.drain();

    h.owner.consume_source_event(&source_moved_at(
      1,
      "/a/important/file",
      "important/file",
      to,
      to_location,
      1,
    ));

    let delivered = h.drain();
    assert_eq!(
      delivered.len(),
      1,
      "one covering subscriber, one whole move: {delivered:?}"
    );
    let whole = &delivered[0];
    assert_eq!(whole.subscription(), wide);
    assert_eq!(
      whole.move_from(),
      Some(key("/a/important/file").as_slice()),
      "an unreserved move keeps BOTH endpoints"
    );
    assert_eq!(whole.path(), Path::new(to));
    assert_eq!(
      whole.location(),
      &located(to_location),
      "a whole move stays located at its destination"
    );
  }

  /// FAIL-ON-REVERT: widen the fake's leaf ground to a bare `starts_with("cookie")` and the
  /// destination becomes reserved — the delivery degrades to a source-only `Removed`.
  #[tokio::test]
  async fn a_move_to_a_leaf_the_grammar_does_not_mint_is_not_masked() {
    assert_a_move_near_but_outside_the_reserved_namespace_is_not_masked(
      "/a/cookies-7",
      "cookies-7",
    )
    .await;
  }

  /// FAIL-ON-REVERT: let the parent ground scan every component instead of only `key[len -
  /// 2]` and this deeper descendant is reserved — a user file erased from every stream.
  #[tokio::test]
  async fn a_move_below_the_cookie_directorys_own_children_is_not_masked() {
    let (to, to_location) = inside_the_cookie_directory("sub/leaf");
    assert_a_move_near_but_outside_the_reserved_namespace_is_not_masked(&to, &to_location).await;
  }

  // ---------------------------------------------------------------------------
  // Single-endpoint kinds keep today's single-key answer.
  // ---------------------------------------------------------------------------

  /// A change with ONE endpoint has one verdict, and a reserved key makes it total: the
  /// cookie's own create (and its unlink) reaches nobody. Endpoint-awareness must not have
  /// loosened this — it is the suppression the namespace exists for.
  async fn assert_a_single_endpoint_change_at_a_reserved_key_reaches_nobody(artifact: &str) {
    let mut h = Harness::new();
    let _wide = h.watch("/a", Interest::all()).await.expect("watch /a");
    h.drain();

    h.owner
      .consume_source_event(&source_created(1, artifact, 1));

    let delivered = h.drain();
    assert!(
      delivered.is_empty(),
      "the artifact's own single-endpoint change is covered by nobody: {delivered:?}"
    );
  }

  /// FAIL-ON-REVERT: drop the mask from `route::project`'s single-endpoint arm (`return
  /// to.starts_with(canonical).then(|| event.deliver(sub))`) and the cookie's create is
  /// delivered to every covering subscriber.
  #[tokio::test]
  async fn a_single_endpoint_change_at_a_reserved_key_reaches_nobody_by_leaf_grammar() {
    assert_a_single_endpoint_change_at_a_reserved_key_reaches_nobody("/a/cookie-7").await;
  }

  /// The same, on the parent-directory ground.
  #[tokio::test]
  async fn a_single_endpoint_change_at_a_reserved_key_reaches_nobody_by_parent_directory() {
    let (artifact, _location) = inside_the_cookie_directory("anything");
    assert_a_single_endpoint_change_at_a_reserved_key_reaches_nobody(&artifact).await;
  }

  // ---------------------------------------------------------------------------
  // A `Rescan` is never classified, so it is never suppressed.
  // ---------------------------------------------------------------------------

  /// A [`Rescan`](crate::EventKind::Rescan) names no object — it is the statement that
  /// coverage below a key became uncertain — so it has no endpoint to reserve. Classifying
  /// one would hide a coverage loss behind the very namespace whose events it may have
  /// eaten, and the loss would be unrecoverable: nothing else is owed for it.
  async fn assert_a_rescan_inside_the_reserved_namespace_is_still_delivered(
    at: &str,
    location: &str,
  ) {
    let mut h = Harness::new();
    let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
    h.drain();

    h.owner
      .consume_source_event(&rescan_event_at(1, at, location, 1));

    let delivered = h.drain();
    let projected = delivered
      .iter()
      .find(|e| e.subscription() == sub)
      .expect("a coverage-loss signal is never suppressed, wherever it is located");
    assert!(
      projected.kind().is_rescan(),
      "a Rescan is delivered as itself, never reshaped by the namespace: {projected:?}"
    );
    assert_eq!(
      projected.path(),
      Path::new(at),
      "the re-enumeration keeps the located key the loss names"
    );
  }

  /// FAIL-ON-REVERT: drop the `is_rescan` early return from `Owner::reserved_endpoints` and
  /// this `Rescan` classifies `All`, so `fan_out_and_push` settles it without routing —
  /// coverage loss, silently swallowed.
  #[tokio::test]
  async fn a_rescan_at_a_reserved_key_is_still_delivered_by_leaf_grammar() {
    assert_a_rescan_inside_the_reserved_namespace_is_still_delivered("/a/cookie-7", "cookie-7")
      .await;
  }

  /// The same, on the parent-directory ground.
  #[tokio::test]
  async fn a_rescan_at_a_reserved_key_is_still_delivered_by_parent_directory() {
    let (at, location) = inside_the_cookie_directory("anything");
    assert_a_rescan_inside_the_reserved_namespace_is_still_delivered(&at, &location).await;
  }

  // ---------------------------------------------------------------------------
  // A barrier still resolves on a cookie that arrives by RENAME.
  // ---------------------------------------------------------------------------

  /// A cookie is an observation however it arrives, and a rename is one of the ways it can.
  /// The pre-fix code resolved the barrier on exactly this event and then discarded the
  /// whole change; the fix keeps the resolution AND delivers the user endpoint, so this
  /// cell asserts both halves — a resolution that came at the price of the `Removed` would
  /// be the same loss with a certificate on top.
  async fn assert_a_cookie_arriving_by_rename_resolves_its_barrier(
    cookie: &str,
    cookie_location: &str,
  ) {
    let mut h = Harness::new();
    let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
    let handle = h.owner.subsumer.subscription_root(sub).expect("live root");
    h.drain();

    let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
    h.owner.pending_syncs.push(crate::driver::PendingSync {
      cookie_key: key(cookie),
      sub,
      root: handle,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: reply_tx,
    });

    h.owner.consume_source_event(&source_moved_at(
      1,
      "/a/important/file",
      "important/file",
      cookie,
      cookie_location,
      1,
    ));

    let delivered = h.drain();
    let projected = delivered
      .iter()
      .find(|e| e.subscription() == sub)
      .expect("the user endpoint is delivered, barrier or no barrier");
    assert!(
      projected.kind().is_removed(),
      "the user endpoint arrives as the source-only projection, not as a whole move naming \
       the cookie: {projected:?}"
    );
    assert_eq!(projected.path(), Path::new("/a/important/file"));
    assert_eq!(projected.location(), &located("important/file"));
    assert!(
      matches!(
        (&mut reply_rx).now_or_never(),
        Some(Ok(Ok(SyncOutcome::Delivered)))
      ),
      "a cookie that arrived by rename resolves its barrier Delivered"
    );
  }

  /// FAIL-ON-REVERT: gate the resolution back on `reserved.is_total()` instead of
  /// `reserved.any()` in `consume_source_event` and the barrier never resolves — the reply
  /// stays pending and the caller waits out its whole timeout.
  #[tokio::test]
  async fn a_cookie_arriving_by_rename_resolves_its_barrier_by_leaf_grammar() {
    assert_a_cookie_arriving_by_rename_resolves_its_barrier("/a/cookie-7", "cookie-7").await;
  }

  /// The same, on the parent-directory ground — the shape a second consumer of the lower
  /// crate actually produces, since its cookie names follow no grammar this crate knows.
  #[tokio::test]
  async fn a_cookie_arriving_by_rename_resolves_its_barrier_by_parent_directory() {
    let (cookie, location) = inside_the_cookie_directory("anything");
    assert_a_cookie_arriving_by_rename_resolves_its_barrier(&cookie, &location).await;
  }

  // ---------------------------------------------------------------------------
  // The resolution is strictly AFTER the change's own publication.
  // ---------------------------------------------------------------------------

  /// `consume_source_event` resolves a barrier only once `fan_out_and_push` has published
  /// this change or durably parked it. A barrier resolved first would let a caller waking
  /// on another thread drain past a delivery the resolution implies it will find — the
  /// prohibited half-barrier.
  ///
  /// The order is made OBSERVABLE by making this change's own publication the thing that
  /// creates the debt: the one-slot channel is already full, so the projected `Removed`
  /// sheds the subscription to a parked `Rescan` and advances its loss serial. The
  /// resolution reads both. Resolving BEFORE the fan-out would find an empty debt map and
  /// an unmoved serial, and would answer `Delivered`; resolving after finds the debt this
  /// very change created, and answers `Dominated`.
  ///
  /// FAIL-ON-REVERT: hoist the `resolve_matching_pending_sync` call above
  /// `self.fan_out_and_push(event)` and the outcome flips to `Delivered` — a clean-delivery
  /// certificate handed out over a subscription that owes a re-enumeration.
  #[tokio::test]
  async fn a_barrier_resolves_only_after_its_own_change_is_durably_parked() {
    let mut h = Harness::bounded(1);
    let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
    let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

    // Fill the one slot, so THIS change's own publication is what sheds.
    h.owner.try_emit(modified_event(sub, "/a/x", 1));

    let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
    h.owner.pending_syncs.push(crate::driver::PendingSync {
      cookie_key: key("/a/cookie-7"),
      sub,
      root: handle,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: reply_tx,
    });

    h.owner.consume_source_event(&source_moved_at(
      1,
      "/a/important/file",
      "important/file",
      "/a/cookie-7",
      "cookie-7",
      2,
    ));

    assert!(
      h.owner.needs_rescan.contains_key(&sub),
      "the user endpoint could not be published, so it parked as durable Rescan debt"
    );
    assert!(
      matches!(
        (&mut reply_rx).now_or_never(),
        Some(Ok(Ok(SyncOutcome::Dominated)))
      ),
      "the resolution read the debt this change's own publication created, so it ran after it"
    );
  }

  // ---------------------------------------------------------------------------
  // A consumed record always ticks the settle clock — suppressing a change is not
  // a reason to stop paying the debounce its bound.
  // ---------------------------------------------------------------------------

  /// A debounce policy whose windows are short enough to expire on a paused clock but long
  /// enough that nothing settles by accident while a cell is setting up.
  fn settle_in_20ms_hold_100ms() -> DebounceConfig {
    DebounceConfig::new()
      .with_quiet_window(Duration::from_millis(20))
      .with_max_hold(Duration::from_millis(100))
  }

  /// A user change buffered under debounce must be released once its hold expires, even
  /// though every record the source hands over in the meantime is a **totally reserved** one
  /// that is suppressed before it is routed anywhere.
  ///
  /// `fan_out_and_push` returns on `is_total()` **above** [`push_all`](super::Owner::push_all),
  /// which owns the only normal-path `drain_ready` — so the suppressed record used to consume the
  /// loop's iteration and pay the debounce nothing. `consume_source_event` now drains the due
  /// output itself, on every path out of the funnel.
  ///
  /// The clock is paused, so "its hold expired" is a fact of the test rather than a race: the
  /// entry is due before the reserved record is fed, and the reserved record is the only thing
  /// that runs afterwards.
  ///
  /// FAIL-ON-REVERT: drop the `self.drain_coalescer_due()` between `fan_out_and_push` and the
  /// barrier arms in `consume_source_event` and nothing is delivered — the buffered change is
  /// still sitting in the coalescer, past its bound, exactly as the finding describes.
  #[tokio::test(start_paused = true)]
  async fn a_totally_reserved_record_still_releases_the_due_change_it_holds_up() {
    let mut h = Harness::with_coalescer(Some(Coalescer::new(Some(settle_in_20ms_hold_100ms()))));
    let sub = h.watch("/a", Interest::all()).await.expect("watch /a");

    // The user's change buffers under debounce — nothing is owed to the consumer yet.
    h.owner.consume_source_event(&source_created(1, "/a/f", 1));
    assert!(
      h.drain().is_empty(),
      "the user change is still settling, so nothing is delivered on admission"
    );

    // Its hold expires while the source has nothing but another `Watcher`'s cookies to hand over.
    tokio::time::advance(Duration::from_millis(150)).await;
    let (reserved, _) = inside_the_cookie_directory("anything");
    h.owner
      .consume_source_event(&source_created(1, &reserved, 2));

    let delivered = h.drain();
    assert_eq!(
      delivered.len(),
      1,
      "consuming the reserved record released the due change, and released only it: {delivered:?}"
    );
    assert_eq!(delivered[0].subscription(), sub);
    assert_eq!(
      delivered[0].path(),
      Path::new("/a/f"),
      "…the user's change, never the cookie that unblocked it"
    );
  }

  /// The drain is not an admission: a flood of totally reserved records is still delivered to
  /// nobody AND still buffered nowhere. The suppression `fan_out_and_push` performs is untouched —
  /// what changed is only that consuming one of these records now pays the settle clock.
  ///
  /// Proven on both halves: the consumer stream stays empty across a clock advance past the whole
  /// hold, and a `flush_all` — which force-emits *everything* the coalescer holds regardless of
  /// deadline — comes back empty, so no reserved record was buffered to be released later either.
  ///
  /// FAIL-ON-REVERT: route the `is_total()` arm of `fan_out_and_push` through `fan_out_raw` +
  /// `push_all` — "draining" by ADMITTING the reserved change rather than suppressing it — and the
  /// cookies surface on the consumer's stream. The post-advance half is what fails first (under a
  /// 20ms quiet window nothing is due at admission, so the admitted cookies come out on the drain
  /// after it); `flush_all` catches whatever a longer window would still be holding.
  #[tokio::test(start_paused = true)]
  async fn a_reserved_flood_is_neither_delivered_nor_coalesced() {
    let mut h = Harness::with_coalescer(Some(Coalescer::new(Some(settle_in_20ms_hold_100ms()))));
    h.watch("/a", Interest::all()).await.expect("watch /a");

    // Both classification grounds, and a distinct leaf per record so nothing could collapse.
    for seq in 0..16u64 {
      let by_grammar = format!("/a/cookie-{seq}");
      let (by_parent, _) = inside_the_cookie_directory(&format!("leaf-{seq}"));
      h.owner
        .consume_source_event(&source_created(1, &by_grammar, seq * 2));
      h.owner
        .consume_source_event(&source_created(1, &by_parent, seq * 2 + 1));
    }

    assert!(
      h.drain().is_empty(),
      "no reserved record reaches the consumer"
    );
    tokio::time::advance(Duration::from_millis(150)).await;
    h.owner.drain_coalescer_due();
    assert!(
      h.drain().is_empty(),
      "…and none is released by a later drain either"
    );

    let mut held = Vec::new();
    h.owner
      .coalescer
      .as_mut()
      .expect("debounce is enabled")
      .flush_all(&mut held);
    assert!(
      held.is_empty(),
      "no reserved record was ever admitted to the coalescer: {held:?}"
    );
  }

  /// The same sweep on the funnel's OTHER early return: a record whose root the source has
  /// already forgotten is consumed by `retire_if_dead` and never fanned out. Retirement is
  /// idempotent, so a repeat terminal event on an already-retired handle does no work at all —
  /// it is a consumed record that pays an unrelated subscription's settle clock nothing.
  ///
  /// The buffered change belongs to a **different, live** root, so the retirement neither
  /// drops nor forgets it — the only thing that can release it is the drain.
  ///
  /// FAIL-ON-REVERT: drop the `self.drain_coalescer_due()` on the `retire_if_dead` arm of
  /// `consume_source_event` and the live root's due change is not delivered.
  #[tokio::test(start_paused = true)]
  async fn a_dead_root_record_still_releases_another_roots_due_change() {
    let mut h = Harness::with_coalescer(Some(Coalescer::new(Some(settle_in_20ms_hold_100ms()))));
    let live = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
    h.watch("/b", Interest::all()).await.expect("watch /b"); // handle 2
    h.drain();

    h.owner.consume_source_event(&source_created(1, "/a/f", 1));
    assert!(h.drain().is_empty(), "the live root's change is settling");

    tokio::time::advance(Duration::from_millis(150)).await;
    // The OTHER root dies out of band and its terminal event arrives.
    h.owner.source.kill_root(2);
    h.owner.consume_source_event(&source_removed(2, "/b", 2));

    let delivered = h.drain();
    assert_eq!(
      delivered.len(),
      1,
      "the dead-root record released the live root's due change: {delivered:?}"
    );
    assert_eq!(delivered[0].subscription(), live);
    assert_eq!(delivered[0].path(), Path::new("/a/f"));
  }

  /// The flood, end to end, against the REAL run loop — the shape the finding names.
  ///
  /// The run loop's `select!` is biased with `source.next()` **above** the settle timer, and this
  /// source is ready on every poll, so the timer arm is never even reached; the source arm also
  /// zeroes `command_streak`, so the command-fairness valve's due-drain never fires either. The
  /// only thing left that can honor the debounce's bound is the funnel's own drain.
  ///
  /// Every flood record is reserved by its PARENT DIRECTORY alone — the classification ground that
  /// makes this reachable from outside the process: a second `Watcher` over the same tree writes
  /// cookies whose leaf names follow no grammar this crate knows, so its ordinary sync loop is the
  /// flood.
  ///
  /// FAIL-ON-REVERT: drop the `self.drain_coalescer_due()` between `fan_out_and_push` and the
  /// barrier arms in `consume_source_event` and `w.next()` waits out its whole timeout
  /// (`Elapsed(())`) — the user's change is held for as long as the other watcher keeps syncing.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_sustained_reserved_flood_cannot_starve_a_due_change_in_the_run_loop() {
    let (trigger_tx, trigger_rx) = async_channel::unbounded::<()>();
    let stop = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    // Stops the flood on the way out — on the assertion's success AND on its panic. A task that
    // never yields cannot be shut down, so the runtime's own drop would hang behind it.
    let _stop_on_exit = StopFloodOnDrop(stop.clone());
    let source = ArtifactFloodSource {
      next_handle: 0,
      live: HashMap::new(),
      user_event: Some(source_created(1, "/a/f", 1)),
      trigger: trigger_rx,
      minted: 0,
      stop: stop.clone(),
    };
    let mut w: super::super::Tributaries<OsString, (), TokioRuntime, u32> =
      super::super::Tributaries::with_source(
        source,
        TributariesOptions::new().debounce(settle_in_20ms_hold_100ms()),
      );
    let sub = w
      .watch(key("/a"), (), WatchOptions::new())
      .await
      .expect("watch /a"); // handle 1

    // Release the user's change; from here the source hands over nothing but cookies, forever.
    trigger_tx.try_send(()).expect("release the user change");

    let event = tokio::time::timeout(Duration::from_secs(5), w.next())
      .await
      .expect("the debounced user change drains despite the sustained reserved flood")
      .expect("the stream is open");
    assert_eq!(event.subscription(), sub, "routed to the covering sub");
    assert_eq!(
      event.path(),
      Path::new("/a/f"),
      "…and it is the user's change, not a cookie"
    );
  }

  /// Sets [`ArtifactFloodSource`]'s stop flag as the test frame unwinds or returns.
  struct StopFloodOnDrop(std::sync::Arc<core::sync::atomic::AtomicBool>);

  impl Drop for StopFloodOnDrop {
    fn drop(&mut self) {
      self.0.store(true, core::sync::atomic::Ordering::SeqCst);
    }
  }

  /// A source that hands over one user change and then floods with records another `Watcher`'s
  /// sync loop produces: leaves inside the cookie directory, classified reserved by their parent
  /// alone. Once the flood starts `next` **never awaits**, so the biased `select!` takes the source
  /// arm on every poll — the starvation shape, reproduced exactly.
  struct ArtifactFloodSource {
    next_handle: u32,
    live: HashMap<u32, Vec<OsString>>,
    /// Held back until the test releases it, so it cannot be consumed before its subscriber
    /// exists.
    user_event: Option<SourceEvent<OsString, u32>>,
    trigger: async_channel::Receiver<()>,
    /// A fresh reserved leaf per record: nothing can collapse, so a regression that admitted
    /// these to the coalescer could not hide behind a merge.
    minted: u64,
    stop: std::sync::Arc<core::sync::atomic::AtomicBool>,
  }

  impl Source<OsString> for ArtifactFloodSource {
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

    /// The PARENT-DIRECTORY ground only — the one a cookie whose name this crate cannot predict
    /// is classified by, and the one this branch newly reaches.
    fn is_sync_artifact(&self, key: &[OsString]) -> bool {
      key
        .len()
        .checked_sub(2)
        .and_then(|parent| key[parent].to_str())
        .is_some_and(|parent| parent == COOKIE_DIR)
    }

    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      if self.user_event.is_some() {
        // Cancellation-safe: the trigger message and the event are taken on the same poll that
        // returns `Ready`, so a losing `select!` arm dropping this future loses neither.
        self.trigger.recv().await.ok()?;
        return self.user_event.take();
      }
      if self.stop.load(core::sync::atomic::Ordering::SeqCst) {
        return None;
      }
      self.minted += 1;
      Some(SourceEvent::new(
        1,
        key(&format!("/a/{COOKIE_DIR}/{}", self.minted)),
        EventKind::Created,
        Location::new(),
        Epoch::new(self.minted),
        Some(ChangeId::new(NonZeroU64::MIN)),
      ))
    }

    fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
      self.live.get(&handle).cloned()
    }
  }
}

/// The owner is both the semantic core AND the host for arbitrary caller code —
/// a `Source` method, a subscription's `Filter` predicate — and it retains
/// admitted control requests past a bounded ingress. Every cell here pins one of
/// those seams against the failure state that exploits it.
mod ownership {
  use super::*;
  use crate::driver::{MAX_PENDING_SYNCS, ReconcileStop};

  /// The run loop selects a command and then awaits the whole reconcile
  /// INSIDE that branch, so while `Source::arm` is pending the loop never returns
  /// to its `select!` — the dedicated close lane exists but nothing polls it.
  /// Close then stays pending for as long as the mount does, with the read plane
  /// and every source resource still live.
  ///
  /// FAIL-ON-REVERT: drop the close arm from `Owner::arm`'s `select_biased!` (back
  /// to `self.source.arm(key).await?`) and `close()` never resolves — the timeout
  /// below fires, which is exactly the reproduction #49 filed.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_permanently_pending_arm_cannot_wedge_close() {
    struct WedgedArmSource {
      inner: FakeSource,
      entered: std::sync::Arc<core::sync::atomic::AtomicBool>,
    }

    impl Source<OsString> for WedgedArmSource {
      type Handle = u32;

      fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
        self.inner.canonicalize_key(key)
      }

      async fn arm(&mut self, _key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
        self
          .entered
          .store(true, core::sync::atomic::Ordering::SeqCst);
        core::future::pending().await
      }

      fn disarm(&mut self, handle: u32) {
        self.inner.disarm(handle);
      }

      async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
        core::future::pending().await
      }

      fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
        self.inner.root_key(handle)
      }
    }

    let entered = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let w: crate::Tributaries<OsString, (), TokioRuntime, u32> = crate::Tributaries::with_source(
      WedgedArmSource {
        inner: FakeSource::new(),
        entered: std::sync::Arc::clone(&entered),
      },
      TributariesOptions::new(),
    );

    let watching = {
      let w = w.clone();
      tokio::spawn(async move { w.watch(key("/a"), (), WatchOptions::new()).await })
    };
    // Settle on the owner being parked INSIDE the arm — the only state in which
    // this proves anything.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !entered.load(core::sync::atomic::Ordering::SeqCst)
      && std::time::Instant::now() < deadline
    {
      tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
      entered.load(core::sync::atomic::Ordering::SeqCst),
      "staging: the owner is parked inside Source::arm"
    );

    let closed = tokio::time::timeout(std::time::Duration::from_secs(10), w.close())
      .await
      .expect("close resolves against a source that never returns from arm");
    assert!(
      closed.is_ok(),
      "the close lane is honoured while an arm is wedged: {closed:?}"
    );
    // The abandoned reconcile's caller sees the watcher closed rather than hanging.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), watching).await;
  }

  /// The `grow` half of the same seam. `grow` is awaited on the Covered-outside
  /// path with exactly the same run-loop shape, and the stock binding's `grow`
  /// waits on the lower cover-settle fence — so a hung mount parks the owner
  /// there just as it does in `arm`.
  ///
  /// FAIL-ON-REVERT: call `self.source.grow(..).await` directly instead of the
  /// close-raced `Owner::grow` and this cell hangs — the queued close is never
  /// observed and the assertion below is never reached.
  #[tokio::test]
  async fn a_queued_close_abandons_a_pending_grow() {
    let mut h = Harness::new();
    h.owner.source.grow_pending = true;
    // A close is already queued on the dedicated signal, exactly as
    // `Tributaries::close` leaves it.
    let (reply, _on_close) = futures_channel::oneshot::channel();
    h.closes.try_send(reply).expect("the close signal accepts");

    let stop = h
      .owner
      .grow(1, &[key("/a")])
      .await
      .expect_err("a queued close abandons the pending grow");
    assert!(
      matches!(stop, ReconcileStop::CloseRequested(_)),
      "the close wins the race and rides back to teardown: {stop:?}"
    );
  }

  /// A per-subscription `Filter` predicate is arbitrary caller code run
  /// inline in the ONE owner task. An unwind through it used to take the owner
  /// with it — the shared event stream closes, every unrelated subscription
  /// stops, and later `watch` calls answer `Closed` — so one tenant's broken
  /// predicate denied service to every other.
  ///
  /// FAIL-ON-REVERT: call `filter.admits(..)` directly in `fan_out_raw`'s gate and
  /// this cell unwinds at the fan-out below, never reaching an assertion.
  #[test]
  fn a_panicking_filter_cannot_take_the_owner_or_a_healthy_lane_with_it() {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .expect("the runtime builds");
    runtime.block_on(async {
      let mut h = Harness::new();
      // A healthy subscription and a poisoned one, both covered by one root.
      let healthy = h
        .owner
        .reconcile_watch(&key("/a"), (), WatchOptions::new())
        .await
        .expect("watch /a");
      let poisoned = h
        .owner
        .reconcile_watch(
          &key("/a/b"),
          (),
          WatchOptions::new().with_filter(Filter::new(|_| -> bool {
            panic!("a tenant's filter predicate panics inside fan-out")
          })),
        )
        .await
        .expect("watch /a/b");

      // One event covered by both. Reaching the line after this at all is the
      // containment: the owner did not unwind.
      h.owner.fan_out_and_push(&source_modified(1, "/a/b/f", 0));

      let delivered: Vec<_> = core::iter::from_fn(|| h.events.try_recv().ok()).collect();
      assert!(
        delivered
          .iter()
          .any(|event| event.subscription() == healthy && !event.kind().is_rescan()),
        "the healthy lane received its delivery — one tenant's filter cannot deny it service"
      );

      // The poisoned subscription's gate is retired (never entered again) and it is
      // owed a dominating Rescan, so its consumer learns in-band that its view
      // diverged rather than silently receiving a changed admission policy.
      assert!(
        h.owner
          .needs_rescan
          .contains_key(&poisoned)
          .then_some(true)
          .or_else(|| h
            .owner
            .suppressed_rescan
            .contains_key(&poisoned)
            .then_some(true))
          .unwrap_or(
            delivered
              .iter()
              .any(|event| { event.subscription() == poisoned && event.kind().is_rescan() })
          ),
        "the quarantined subscription is owed (or was delivered) a dominating Rescan"
      );

      // And the owner is still serving: a further watch reconciles normally.
      h.owner
        .reconcile_watch(&key("/c"), (), WatchOptions::new())
        .await
        .expect("the owner still serves after containing the panic");
    });
  }

  /// The caught PAYLOAD is caller data too. `catch_unwind` hands back the value the panic
  /// carried, and disposing of that box runs the value's own `Drop` — arbitrary caller code,
  /// since a `panic_any` payload is any `Send + 'static` value the caller chose. Dropped in
  /// the owner's own frame, one whose destructor panics starts a SECOND unwind that the
  /// containment has already stopped guarding: the owner dies, the shared stream closes and
  /// every unrelated subscription goes with it — precisely the blast radius the
  /// per-subscription quarantine exists to prevent, reintroduced one line past the boundary.
  ///
  /// FAIL-ON-REVERT: dispose of the payload by binding it in `unwrap_or_else(|_| ..)` instead
  /// of handing it to the contained `dispose_panic_payload`, and the fan-out below unwinds
  /// through the owner, never reaching an assertion.
  #[test]
  fn a_panic_payload_whose_drop_panics_cannot_take_the_owner_with_it() {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .expect("the runtime builds");
    runtime.block_on(async {
      let mut h = Harness::new();
      let healthy = h
        .owner
        .reconcile_watch(&key("/a"), (), WatchOptions::new())
        .await
        .expect("watch /a");
      let poisoned = h
        .owner
        .reconcile_watch(
          &key("/a/b"),
          (),
          WatchOptions::new().with_filter(Filter::new(|_| -> bool {
            std::panic::panic_any(PanicsOnDrop)
          })),
        )
        .await
        .expect("watch /a/b");
      h.drain();

      // One event covered by both. Reaching the line after this at all is the containment of
      // BOTH unwinds — the predicate's and its payload's disposal.
      h.owner.fan_out_and_push(&source_modified(1, "/a/b/f", 0));

      let delivered = h.drain();
      assert!(
        delivered
          .iter()
          .any(|event| event.subscription() == healthy && !event.kind().is_rescan()),
        "the healthy lane received its delivery — a payload's destructor cannot deny it \
         service either: {delivered:?}"
      );
      assert!(
        h.owner
          .filters
          .get(&poisoned)
          .is_some_and(|gate| gate.quarantined),
        "the payload's own unwind did not cost the quarantine that the predicate's earned"
      );
      assert!(
        h.owner.needs_rescan.contains_key(&poisoned)
          || h.owner.suppressed_rescan.contains_key(&poisoned)
          || delivered
            .iter()
            .any(|event| event.subscription() == poisoned && event.kind().is_rescan()),
        "the quarantined subscription is still owed (or was delivered) a dominating Rescan"
      );

      // And the owner is still serving.
      h.owner
        .reconcile_watch(&key("/c"), (), WatchOptions::new())
        .await
        .expect("the owner still serves after containing the payload's unwind too");
    });
  }

  /// Forgetting a payload is the last containment left when a payload's own destructor
  /// panics, and it leaks that payload — an allocation of the caller's choosing, unreachable
  /// for the rest of the process. Bounding that leak per SUBSCRIPTION bounds it in the shape
  /// of the wrong resource: a subscription is a caller-churnable object, so
  /// watch → panic once → release → repeat retains another arbitrary allocation every cycle,
  /// with nothing between the caller and OOM.
  ///
  /// The bound therefore latches the OWNER's whole filter plane: one forgotten payload per
  /// watcher, ever. A predicate is never entered again — which is what makes the bound hold
  /// no matter how the caller churns — and a watch that ASKS for a filter is refused with a
  /// typed terminal rather than silently created with a gate that will never run. Watches
  /// that filter nothing lose nothing and stay admitted.
  ///
  /// FAIL-ON-REVERT: drop the owner latch (keep only the per-subscription quarantine) and the
  /// predicate is entered once per cycle — eight forgotten payloads for eight cycles, and no
  /// refusal at all.
  #[test]
  fn subscription_churn_cannot_accumulate_forgotten_filter_payloads() {
    const CYCLES: usize = 8;

    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .expect("the runtime builds");
    runtime.block_on(async {
      let mut h = Harness::new();
      // Every entry into a panicking predicate is at most one forgotten payload, and no
      // entry is none — so counting entries counts the leak.
      let entries = std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
      let mut admitted = 0usize;
      let mut refused = 0usize;

      for cycle in 0..CYCLES {
        let hits = std::sync::Arc::clone(&entries);
        let outcome = h
          .watch_with(
            "/a/b",
            WatchOptions::new().with_filter(Filter::new(move |_| -> bool {
              hits.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
              std::panic::panic_any(PanicsOnDrop)
            })),
          )
          .await;
        let Ok(sub) = outcome else {
          let err = outcome.expect_err("refused");
          assert!(
            err.is_filter_retired(),
            "cycle {cycle} was refused for the wrong reason: {err:?}"
          );
          refused += 1;
          continue;
        };
        admitted += 1;
        let root = h
          .owner
          .subsumer
          .subscription_root(sub)
          .expect("the fresh subscription has a root");
        // One covered change: the predicate unwinds, its payload cannot be disposed of,
        // and the owner has to forget it.
        h.owner
          .fan_out_and_push(&source_modified(root, "/a/b/f", cycle as u64));
        h.drain();
        h.unwatch(sub).expect("the subscription is released");
      }

      assert_eq!(
        entries.load(core::sync::atomic::Ordering::SeqCst),
        1,
        "the panicking predicate was entered more than once across {CYCLES} churn cycles — \
         each entry is another payload the owner has to forget"
      );
      assert_eq!(admitted, 1, "only the first filtered watch was admitted");
      assert_eq!(
        refused,
        CYCLES - 1,
        "every later filtered watch was refused with the typed terminal"
      );

      // The refusal is scoped to watches that actually ask for filtering: an unfiltered one
      // can lose nothing to a retired filter plane, so it is still served.
      h.watch_with("/c", WatchOptions::new())
        .await
        .expect("an unfiltered watch is unaffected by the retired filter plane");
    });
  }

  /// The refusal at `watch` cannot be the bound on its own: a `Filter` slot is
  /// hot-swappable, so a caller can be admitted with the admit-all default and install a
  /// panicking predicate afterwards, through a handle it kept. The bound is the GATE's —
  /// once the owner has forgotten a payload it enters no predicate at all — and the refusal
  /// is only what keeps a caller from being silently unfiltered.
  ///
  /// FAIL-ON-REVERT: remove the latch check from the fan-out gate (leave only the refusal at
  /// admission) and the swapped-in predicate runs, forgetting a second payload — through a
  /// subscription no refusal could ever have caught.
  #[test]
  fn a_retired_filter_plane_enters_no_predicate_swapped_in_afterwards() {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .expect("the runtime builds");
    runtime.block_on(async {
      let mut h = Harness::new();

      // Trip the latch once, exactly as a tenant's filter would.
      let tripped = h
        .watch_with(
          "/a",
          WatchOptions::new().with_filter(Filter::new(|_| -> bool {
            std::panic::panic_any(PanicsOnDrop)
          })),
        )
        .await
        .expect("watch /a");
      let tripped_root = h
        .owner
        .subsumer
        .subscription_root(tripped)
        .expect("/a is live");
      h.owner
        .fan_out_and_push(&source_modified(tripped_root, "/a/f", 0));
      h.drain();
      assert!(
        h.owner.filter_payload_forgotten,
        "staging: the owner had to forget the payload"
      );

      // And now the churn the refusal cannot see: each cycle is admitted while its filter is
      // still the admit-all default, then has caller code swapped into that slot through the
      // handle the caller kept. If the gate ever entered one, every cycle would forget
      // another payload.
      let entries = std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
      let mut last = None;
      for cycle in 0..4u64 {
        let slot: Filter<OsString> = Filter::all();
        let sub = h
          .watch_with("/b", WatchOptions::new().with_filter(slot.clone()))
          .await
          .expect("an admit-all watch is still admitted");
        let root = h.owner.subsumer.subscription_root(sub).expect("/b is live");
        h.drain();
        let hits = std::sync::Arc::clone(&entries);
        slot.swap(move |_| -> bool {
          hits.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
          std::panic::panic_any(PanicsOnDrop)
        });
        h.owner
          .fan_out_and_push(&source_modified(root, "/b/f", cycle + 1));
        last = Some((sub, root, h.drain()));
        if cycle + 1 < 4 {
          h.unwatch(sub).expect("the subscription is released");
        }
      }
      let (sub, root, delivered) = last.expect("the loop ran");

      assert_eq!(
        entries.load(core::sync::atomic::Ordering::SeqCst),
        0,
        "the retired plane entered a predicate swapped in behind the refusal — one more \
         forgotten payload per cycle, and the cycle is free"
      );
      assert!(
        h.owner
          .filters
          .get(&sub)
          .is_some_and(|gate| gate.quarantined),
        "the subscription whose gate the latch retired is marked, exactly as one whose own \
         predicate unwound"
      );
      assert!(
        h.owner.needs_rescan.contains_key(&sub)
          || h.owner.suppressed_rescan.contains_key(&sub)
          || delivered
            .iter()
            .any(|event| event.subscription() == sub && event.kind().is_rescan()),
        "and it is owed a dominating Rescan, so its consumer learns in-band that its \
         admission gate is gone"
      );

      // Fail-open survives the latch exactly as it survives a predicate's own unwind: once
      // the owed Rescan is published, later changes are DELIVERED — over-delivery, never a
      // silent drop of what the swapped-in predicate would have rejected — and still without
      // entering it.
      h.owner.flush_pending_rescans();
      h.drain();
      h.owner.fan_out_and_push(&source_modified(root, "/b/g", 2));
      let after = h.drain();
      assert!(
        after
          .iter()
          .any(|event| event.subscription() == sub && !event.kind().is_rescan()),
        "a retired plane over-delivers rather than dropping silently: {after:?}"
      );
      assert_eq!(
        entries.load(core::sync::atomic::Ordering::SeqCst),
        0,
        "and it still entered no predicate"
      );
    });
  }

  /// A `Filter` is a handle onto a SHARED predicate slot, and callers clone one across
  /// subscriptions deliberately. Retiring a panicking predicate by writing admit-all into
  /// that slot therefore retires it for every subscription registered from the same
  /// filter value — while only the one that unwound is recorded as having lost coverage.
  /// A tenant's filtering boundary would silently disappear because a DIFFERENT tenant's
  /// predicate panicked, with no Rescan and no loss marker to say so.
  ///
  /// FAIL-ON-REVERT: quarantine by `filter.swap(|_| true)` instead of the
  /// per-subscription mark, and the sibling stops running its predicate (the call count
  /// freezes) and starts admitting what it was configured to reject.
  #[test]
  fn quarantining_one_subscription_leaves_a_sibling_sharing_its_filter_intact() {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .expect("the runtime builds");
    runtime.block_on(async {
      let mut h = Harness::new();
      // ONE filter value, cloned across two disjoint subscriptions — the ordinary way a
      // caller applies one policy to several watches. It panics on `boom`, rejects
      // `hidden`, and admits everything else; the counter proves whether it ran at all.
      let calls = std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
      let shared = Filter::new({
        let calls = std::sync::Arc::clone(&calls);
        move |input: &crate::FilterInput<'_, OsString>| {
          calls.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
          match input.key().last().and_then(|c| c.to_str()) {
            Some("boom") => panic!("a tenant's filter predicate panics inside fan-out"),
            Some("hidden") => false,
            _ => true,
          }
        }
      });
      let poisoned = h
        .watch_with("/a/x", WatchOptions::new().with_filter(shared.clone()))
        .await
        .expect("watch /a/x");
      let sibling = h
        .watch_with("/a/y", WatchOptions::new().with_filter(shared.clone()))
        .await
        .expect("watch /a/y");
      h.drain();
      // The two are disjoint, so each rides its own root.
      let poisoned_root = h
        .owner
        .subsumer
        .subscription_root(poisoned)
        .expect("/a/x is live");
      let sibling_root = h
        .owner
        .subsumer
        .subscription_root(sibling)
        .expect("/a/y is live");

      // A change only /a/x covers: its predicate unwinds, and /a/x is quarantined.
      h.owner
        .fan_out_and_push(&source_modified(poisoned_root, "/a/x/boom", 0));
      assert_eq!(
        calls.load(core::sync::atomic::Ordering::SeqCst),
        1,
        "staging: exactly the poisoned subscription's invocation ran"
      );
      assert!(
        h.owner.needs_rescan.contains_key(&poisoned)
          || h.owner.suppressed_rescan.contains_key(&poisoned),
        "the quarantined subscription is owed a dominating Rescan"
      );

      // The poisoned subscription's own gate is retired: caller code is never entered
      // for it again, whatever arrives.
      h.owner
        .fan_out_and_push(&source_modified(poisoned_root, "/a/x/other", 1));
      assert_eq!(
        calls.load(core::sync::atomic::Ordering::SeqCst),
        1,
        "the quarantined subscription never re-enters the predicate that unwound"
      );

      // The sibling registered from a CLONE of the same filter is untouched: it still
      // runs the predicate, and still rejects what that predicate rejects.
      h.owner
        .fan_out_and_push(&source_modified(sibling_root, "/a/y/hidden", 2));
      assert_eq!(
        calls.load(core::sync::atomic::Ordering::SeqCst),
        2,
        "the sibling's own gate still runs — the quarantine did not reach through the \
         shared slot"
      );
      assert!(
        !h.drain()
          .iter()
          .any(|event| event.subscription() == sibling),
        "the sibling still rejects what its filter rejects — no filtering boundary was \
         silently dropped"
      );
      assert!(
        !h.owner.needs_rescan.contains_key(&sibling)
          && !h.owner.suppressed_rescan.contains_key(&sibling),
        "and it was never put under loss for somebody else's panic"
      );

      // Fail-open survives for the quarantined subscription itself: its debt is what it
      // is owed, and once that Rescan is published its later changes are DELIVERED —
      // over-delivery, never a silent drop of what its broken predicate would have
      // rejected.
      h.owner.flush_pending_rescans();
      h.drain();
      h.owner
        .fan_out_and_push(&source_modified(poisoned_root, "/a/x/hidden", 3));
      assert!(
        h.drain()
          .iter()
          .any(|event| event.subscription() == poisoned && !event.kind().is_rescan()),
        "a quarantined subscription admits what its retired predicate would have rejected"
      );
    });
  }

  /// The quarantine mints a `Rescan` that strictly dominates everything stamped before
  /// it — including the delivery the panic itself fail-opened, which was stamped moments
  /// earlier in the same fan-out. Under debounce, letting that delivery (or any entry
  /// already buffered for the subscription) sit in the coalescer puts it behind a settle
  /// window that outlives the Rescan's publication, so the timer releases a lower-epoch
  /// delta AFTER the signal claiming to dominate it: a high-water consumer discards a
  /// legitimate delivery, a naive one re-diverges past the enumeration.
  ///
  /// FAIL-ON-REVERT: drop the coalescer purge and push the fanned deliveries through
  /// `push_all`, and the settle timer releases both epoch-0 deltas after the epoch-2
  /// Rescan has already been delivered.
  #[test]
  fn a_filter_panic_under_debounce_releases_no_delta_after_its_rescan() {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .expect("the runtime builds");
    runtime.block_on(async {
      // Long enough that admission genuinely buffers across the panic, short enough to
      // elapse inside this cell.
      let cfg = DebounceConfig::new()
        .with_quiet_window(Duration::from_millis(100))
        .with_max_hold(Duration::from_millis(1000));
      let mut h = Harness::with_coalescer(Some(Coalescer::new(Some(cfg))));
      let sub = h
        .watch_with(
          "/a",
          WatchOptions::new().with_filter(Filter::new(
            |input: &crate::FilterInput<'_, OsString>| {
              if input.key().last().and_then(|c| c.to_str()) == Some("boom") {
                panic!("a tenant's filter predicate panics inside fan-out");
              }
              true
            },
          )),
        )
        .await
        .expect("watch /a");
      h.drain();

      // An admitted delta buffers behind the settle window.
      h.owner.fan_out_and_push(&source_modified(1, "/a/early", 0));
      assert!(
        h.owner
          .coalescer
          .as_ref()
          .is_some_and(|c| c.next_deadline().is_some()),
        "staging: the admitted delta is buffered, not delivered"
      );
      assert!(
        h.drain().is_empty(),
        "staging: nothing escapes the settle window yet"
      );

      // The predicate unwinds on the next delta: it fails OPEN and the subscription is
      // quarantined and owed a dominating Rescan.
      h.owner.fan_out_and_push(&source_modified(1, "/a/boom", 0));
      let debt = h
        .owner
        .needs_rescan
        .get(&sub)
        .expect("the quarantined subscription is owed a dominating Rescan")
        .epoch;

      // Nothing of this subscription is left behind its own debt: the older buffered
      // entry was dropped, and the fail-opened delivery took the standing-debt gate
      // rather than the coalescer.
      assert!(
        h.owner
          .coalescer
          .as_ref()
          .is_some_and(|c| c.next_deadline().is_none()),
        "the quarantined subscription holds nothing buffered behind its own Rescan"
      );

      // Publish the Rescan, then let the settle window elapse and drain what it holds.
      h.owner.flush_pending_rescans();
      let published = h.drain();
      assert!(
        published
          .iter()
          .any(|e| e.subscription() == sub && e.kind().is_rescan() && e.epoch() == debt),
        "the dominating Rescan reaches the consumer: {published:?}"
      );

      tokio::time::sleep(Duration::from_millis(250)).await;
      h.owner.drain_coalescer_due();
      let tail = h.drain();
      assert!(
        tail
          .iter()
          .all(|e| e.subscription() != sub || e.epoch() >= debt),
        "no delivery the Rescan dominates may follow it: {tail:?}"
      );
      assert!(
        tail.is_empty(),
        "and there is nothing left to release at all: {tail:?}"
      );
    });
  }

  /// The bounded sync mailbox limits requests waiting to be RECEIVED. Once
  /// the owner drains one it retains the barrier — and a real cookie FILE — until
  /// the cookie is observed, dominated, cancelled or retired, and the caller picks
  /// its own timeout. Admissions can therefore outrun observations without bound.
  ///
  /// FAIL-ON-REVERT: remove the `pending_syncs.len() >= MAX_PENDING_SYNCS` arm from
  /// `on_sync` and every admission parks — the pending population grows with total
  /// admitted calls and nothing is refused.
  #[tokio::test]
  async fn sync_admission_stops_at_the_in_flight_bound() {
    let mut h = Harness::new();
    h.owner.source.supports_sync = true;
    let sub = h
      .owner
      .reconcile_watch(&key("/a"), (), WatchOptions::new())
      .await
      .expect("watch /a");

    // Every caller keeps waiting: the cookie is never observed, so no barrier
    // resolves and nothing is ever reclaimed.
    let mut refused = 0usize;
    // Every receiver is RETAINED: cancellation reclaim cannot help a caller that
    // is genuinely still waiting, which is the whole point of the bound.
    let mut waiters = Vec::new();
    for _ in 0..(MAX_PENDING_SYNCS * 2) {
      let (reply, mut on_reply) = futures_channel::oneshot::channel();
      h.owner.on_sync(sub, 0, reply).await;
      match futures_util::poll!(&mut on_reply) {
        core::task::Poll::Ready(Ok(Err(crate::error::SyncError::Busy))) => refused += 1,
        core::task::Poll::Ready(other) => panic!("unexpected sync resolution: {other:?}"),
        // Admitted and parked on a cookie that is never observed.
        core::task::Poll::Pending => waiters.push(on_reply),
      }
    }
    assert!(refused > 0, "admission stops at the in-flight bound");
    assert!(
      waiters.len() <= MAX_PENDING_SYNCS,
      "at most the bound of callers are ever admitted: {}",
      waiters.len()
    );
    assert!(
      h.owner.pending_syncs.len() <= MAX_PENDING_SYNCS,
      "the owner retains at most the bound, not one per admitted call: {}",
      h.owner.pending_syncs.len()
    );
    assert!(
      h.owner.source.begun_syncs <= MAX_PENDING_SYNCS,
      "a refused barrier is refused BEFORE its cookie is written, so it leaves no \
       marker on the filesystem: {} writes",
      h.owner.source.begun_syncs
    );
  }

  /// Upper `close()` used to acknowledge and only then DROP the source,
  /// which starts the lower teardown but can neither await nor report it — so a
  /// caller that terminates its runtime on that acknowledgement abandons native
  /// threads and marker files, and the lower `NotQuiesced` evidence is hidden.
  ///
  /// FAIL-ON-REVERT: send `Ok(())` on the close reply instead of the source's
  /// verdict and this cell sees a successful close over a source that reported it
  /// was not quiescent.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn close_forwards_the_sources_quiescence_verdict() {
    struct NotQuiescentSource {
      inner: FakeSource,
      joined: std::sync::Arc<core::sync::atomic::AtomicUsize>,
    }

    impl Source<OsString> for NotQuiescentSource {
      type Handle = u32;

      fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
        self.inner.canonicalize_key(key)
      }

      async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
        self.inner.arm(key).await
      }

      fn disarm(&mut self, handle: u32) {
        self.inner.disarm(handle);
      }

      async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
        core::future::pending().await
      }

      fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
        self.inner.root_key(handle)
      }

      async fn join_close(&mut self) -> Result<(), crate::error::SourceCloseError> {
        self
          .joined
          .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Err(crate::error::SourceCloseError::NotQuiesced { pending: 3 })
      }
    }

    let joined = std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let w: crate::Tributaries<OsString, (), TokioRuntime, u32> = crate::Tributaries::with_source(
      NotQuiescentSource {
        inner: FakeSource::new(),
        joined: std::sync::Arc::clone(&joined),
      },
      TributariesOptions::new(),
    );
    w.watch(key("/a"), (), WatchOptions::new())
      .await
      .expect("watch /a");

    let closed = tokio::time::timeout(std::time::Duration::from_secs(10), w.close())
      .await
      .expect("close resolves");
    assert_eq!(
      joined.load(core::sync::atomic::Ordering::SeqCst),
      1,
      "the owner awaited the source's join before acknowledging"
    );
    match closed {
      Err(crate::error::CloseError::Source(err)) => assert!(
        err.is_not_quiesced(),
        "the source's own verdict is forwarded verbatim: {err:?}"
      ),
      other => panic!("close reported {other:?} over a source that proved nothing"),
    }
  }
}
