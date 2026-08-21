use std::{
  collections::{HashMap, VecDeque},
  ffi::OsString,
  io,
  marker::PhantomData,
  num::NonZeroU64,
  path::{Path, PathBuf},
  time::Duration,
};

use agnostic_lite::tokio::TokioRuntime;
use tributary_proto::{ChangeId, Epoch, Location};

use super::{Filters, Owner, ParkedRescans, epoch::EpochLedger};
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

/// One call against the fake on its **SEAM ledger** — a second, independent ordered ledger
/// alongside [`Call`], and unlike [`Call`] a TOTAL one: every method of the [`Source`] trait is
/// recorded here, the synchronous read probes and the lifecycle seam included, so a cell asserting
/// "not one `Source` call happened in this window" is making a claim about the whole trait rather than
/// about a curated subset of it.
///
/// It is deliberately NOT folded into [`Call`]. Dozens of existing cells assert [`Call`] as an exact
/// sequence, and many of them drive a teardown or a cookie reap, so adding
/// [`BeginClose`](Self::BeginClose) or [`EndSync`](Self::EndSync) there would rewrite every one of
/// those ledgers without changing a single behaviour they pin. This ledger is read only by the cells
/// that care about the seam, which assert it in full — establishing traffic included — so nothing can
/// be hidden by a window boundary; where a cell only needs the teardown, it splits the sequence at
/// [`BeginClose`](Self::BeginClose) and asserts BOTH halves.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceCall {
  CanonicalizeKey(Vec<OsString>),
  Arm(PathBuf),
  Disarm(u32),
  Grow(u32),
  SetCover(u32),
  Next,
  Replace(u32),
  BeginSync(u32),
  EndSync(Vec<OsString>),
  CancelSync(u32),
  IsSyncArtifact(Vec<OsString>),
  RootKey(u32),
  /// The teardown seam's SYNCHRONOUS initiation. Its position in this ledger is the whole point: it
  /// must precede every fire-and-forget request a teardown issues, and it must appear exactly once.
  BeginClose,
  /// The teardown seam's bounded wait, which stays LAST.
  JoinClose,
}

/// A CLONEABLE handle on a [`FakeSource`]'s [`SourceCall`] ledger.
///
/// Shared rather than owned because every teardown cell must read the ledger AFTER the owner — and
/// with it the source — has been moved into [`run`] and dropped: the seam is the last thing that
/// happens, so a ledger reachable only through `h.owner.source` could never testify about it. A
/// `Mutex` (not a `RefCell`) so the source stays `Sync` alongside `Send`, and an `AtomicUsize` for the
/// lifetime `begin_close` count, which is kept apart from the call list because "exactly once" is a
/// claim about the owner's whole life.
#[derive(Clone)]
struct SeamLedger {
  calls: std::sync::Arc<std::sync::Mutex<Vec<SourceCall>>>,
  begin_closes: std::sync::Arc<core::sync::atomic::AtomicUsize>,
}

impl SeamLedger {
  fn new() -> Self {
    Self {
      calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
      begin_closes: std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0)),
    }
  }

  fn note(&self, call: SourceCall) {
    self.calls.lock().expect("seam ledger").push(call);
  }

  /// Every `Source` call this source has received, in order — the whole life of the source, no
  /// window: a teardown claim is about where the seam sits among ALL of them.
  fn calls(&self) -> Vec<SourceCall> {
    self.calls.lock().expect("seam ledger").clone()
  }

  /// How many [`Source::begin_close`] calls the source received, ever.
  fn begin_closes(&self) -> usize {
    self.begin_closes.load(core::sync::atomic::Ordering::SeqCst)
  }
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
  /// Arm-path → how many more arms of THAT path refuse with [`FaultKind::Capacity`] — the
  /// source's retryable resource-budget refusal (the fs binding's watch-instance limit, and its
  /// teardown-backlog bound), decremented per refusal. Keyed by path rather than counted globally
  /// because the failed-widen restore's retry is per-root: a flat counter cannot express "refuse
  /// each root's FIRST re-arm and admit its second", which is what proves the retry runs for every
  /// root rather than only the one that happens to be reached first. Checked BEFORE
  /// [`fail_arms`](Self::fail_arms), so a cell can drive a capacity-refused wider arm whose
  /// restore re-arms then fail FATALLY.
  capacity_refusals: HashMap<PathBuf, u32>,
  /// Arm-paths whose `arm` NEVER resolves — a re-arm against a hung mount, the state the close race
  /// exists for. The ORDERING probe a call count alone cannot make: a source call the restore must
  /// not issue past a terminal outcome is one it CANNOT issue, because such a call has no close
  /// signal left able to preempt it and never comes back. The request is recorded on the ledger
  /// BEFORE it parks, so a violation shows up as both an extra call and a reconcile that never
  /// completes — a count says "fewer", this says "none, and here is why it must be none".
  wedge_arms: std::collections::HashSet<PathBuf>,
  /// Arm-path → how many more arms of THAT path are served normally before every later one parks
  /// FOREVER: the COUNTED [`wedge_arms`](Self::wedge_arms), for the mount that hangs partway through
  /// a restore. A cell driving one reconcile by hand cannot install a wedge between two polls — the
  /// reconcile future holds the owner borrowed for its whole life — so the mid-flight wedge has to be
  /// scripted up front and armed by the call count instead. Decremented per served arm, counting from
  /// wherever the cell installs it.
  wedge_arms_after: HashMap<PathBuf, u32>,
  /// Arm-paths whose `arm` PANICS rather than returning — a caller-provided extension point that
  /// unwinds through the whole [`run`](super::run) future instead of answering it. The request is
  /// recorded on the ledger BEFORE the unwind, so a cell can still say which call the owner was
  /// inside when its task died. The counterpart to [`wedge_arms`](Self::wedge_arms): a wedged arm and
  /// a panicking one are the two ways a `run` future terminates WITHOUT reaching its teardown tail
  /// (dropped, and panicked), which is exactly the pair of paths the owner's destructor covers alone.
  panic_arms: std::collections::HashSet<PathBuf>,
  /// Every `arm` of these paths parks FOREVER holding a [`PanicsWhenCancelled`] guard, so the arm
  /// future the owner's close race CANCELS unwinds out of its own destructor — with WHICH payload
  /// the injecting cell chooses, exactly as for a panicking call. The counterpart to
  /// [`panic_arms`](Self::panic_arms), which unwinds out of the CALL: a `Source` call and the
  /// cancellation of a `Source`-returned future are two different pieces of implementor code, and a
  /// boundary proven against one has been proven against neither.
  boom_on_cancel_arms: HashMap<PathBuf, Boom>,
  /// `replace` parks FOREVER holding a [`PanicsWhenCancelled`] guard — the retarget future the
  /// in-place widen's close race cancels.
  boom_on_cancel_replace: Option<Boom>,
  /// `grow` parks FOREVER holding a [`PanicsWhenCancelled`] guard — the coverage-widening future the
  /// covered-outside watch's close race cancels.
  boom_on_cancel_grow: Option<Boom>,
  /// `begin_sync` parks FOREVER holding a [`PanicsWhenCancelled`] guard — the cookie write
  /// [`Owner::on_sync`]'s close race cancels.
  boom_on_cancel_begin_sync: Option<Boom>,
  /// Cleanup obligations the cancelled FUTURES above still owe, booked by each
  /// [`PanicsWhenCancelled`] guard and discharged by none of them.
  ///
  /// Deliberately not part of the fake's modelled source state, and not consulted by
  /// [`join_close`](Source::join_close): the whole shape being modelled is a future that owns
  /// cleanup the `Source` cannot be asked about, so the wait answers `Ok(())` while this stays
  /// non-zero. Shared through [`future_owed`](Self::future_owed) so a cell can still read it after
  /// the source is gone.
  future_owed: std::sync::Arc<core::sync::atomic::AtomicUsize>,
  /// The payload [`Source::begin_close`] PANICS with after recording itself, or [`None`] for the
  /// initiation that behaves — the teardown seam's own extension point misbehaving, as opposed to a
  /// reap behind it. Recorded first, and the lifetime counter bumped first, so a cell can still say
  /// the seam was entered exactly once across an initiation that unwound.
  panic_begin_close: Option<Boom>,
  /// Root handles whose [`Source::disarm`] PANICS, and with WHICH payload. The release is recorded
  /// and APPLIED before the unwind — the fake's modelled coverage is left exactly as a successful
  /// disarm leaves it — so a cell's claim is about where the unwind travels and not about a source
  /// left half-torn-down.
  panic_disarms: HashMap<u32, Boom>,
  /// Every [`Source::disarm`] PANICS with this payload, whatever the handle — the injector for
  /// CHURN, where the point is that the callback is entered at most once however many roots the
  /// caller arms and releases, so naming the handles in advance would presuppose the answer.
  panic_every_disarm: Option<Boom>,
  /// Root handles whose [`Source::set_cover`] PANICS, and with WHICH payload. The prune is recorded
  /// and APPLIED before the unwind, so the fake models the sub-case the driver's recorded cover has
  /// to be safe against: a source that really did prune its kernel coverage and only then blew up in
  /// its own bookkeeping. A record left at the previous, BROADER value there is the one direction
  /// that commits a newcomer with no kernel backing.
  panic_set_covers: HashMap<u32, Boom>,
  /// Whether [`Source::join_close`] unwinds at the CALL, before any future exists at all — the
  /// shape only a hand-written `join_close` can take, and the one a boundary around the `.await`
  /// alone would not cover.
  panic_join_close_call: bool,
  /// Whether the future [`Source::join_close`] returns unwinds at its first POLL. A different piece
  /// of implementor code at a different instant from the call above, which is why the two are
  /// injected — and contained — separately.
  panic_join_close_poll: bool,
  /// Whether the future [`Source::join_close`] returns unwinds in its own `Drop` — the THIRD piece
  /// of implementor code the bounded wait runs, and the only one that runs behind the verdict.
  ///
  /// The future still resolves `Ok(())` first, because that pairing is the whole hazard: the wait
  /// has an honest clean verdict in hand and source-owned cleanup then fails, so a boundary that
  /// merely contains the disposal leaves `close()` reporting a shutdown nobody observed.
  panic_join_close_drop: bool,
  /// The payload [`Source::cancel_sync`] PANICS with after recording itself, or [`None`] for the
  /// reclamation that behaves — the by-name reclamation of an abandoned in-flight write
  /// misbehaving, which on the close-win arm runs while the owner holds a CONSUMED [`CloseReply`].
  /// Recorded and applied first, so the ledger still attributes the unwind to a reclamation the
  /// source did perform.
  panic_cancel_sync: Option<Boom>,
  /// How many of the next `replace` calls refuse with [`FaultKind::Capacity`] — the in-place
  /// retarget's admission refusal (`ReplaceRootError::CleanupBacklog`), which the widen must
  /// triage BEFORE it disarms anything.
  refuse_replaces: u32,
  /// `replace` calls served so far, counted only for
  /// [`close_signal_after_replace`](Self::close_signal_after_replace) below.
  replace_calls: u32,
  /// A clone of the owner's close SENDER, CLOSED from inside the `replace` whose ordinal this names —
  /// every [`Tributaries`](super::Tributaries) handle going away while THAT retarget is in flight —
  /// after which the call PARKS FOREVER and never answers.
  ///
  /// It exists because a cell cannot retire the handles mid-retarget from outside: the reconcile future
  /// holds the owner borrowed for its whole life, so nothing else runs between the two polls that
  /// bracket the event (the same reason [`wedge_arms_after`](Self::wedge_arms_after) is counted rather
  /// than installed between polls). Scripting it by call count reaches either of the widen's two
  /// retargets — the initial one at ordinal 1, and the divergence ROLLBACK at ordinal 2.
  ///
  /// The park is the load-bearing half. Closing the signal and RETURNING would let the race resolve on
  /// its own ready result, so `HandlesGone` would only ever be read off a signal that was already
  /// closed before the retarget was issued — and the hazard is the opposite case: a `replace` the owner
  /// POLLED and then dropped, which [`Source::replace`] does not abort, so the binding may still commit
  /// the retarget this reconcile is abandoning. Parking leaves exactly that future in flight when the
  /// close arm reads the signal gone on the next poll.
  close_signal_during_replace: Option<(u32, async_channel::Sender<super::CloseReply>)>,
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
  /// The TOTAL ordered [`SourceCall`] ledger, behind a [`SeamLedger`] handle so a cell can still read
  /// it once the owner has been dropped (see [`SourceCall`] for why it is separate from
  /// [`calls`](Self::calls), and [`SeamLedger`] for why it is shared). Interior mutability because
  /// three `Source` methods — `canonicalize_key`, `is_sync_artifact`, `root_key` — take `&self`, and
  /// leaving them out is exactly the curation this ledger exists to avoid.
  seam: SeamLedger,
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
      capacity_refusals: HashMap::new(),
      wedge_arms: std::collections::HashSet::new(),
      wedge_arms_after: HashMap::new(),
      panic_arms: std::collections::HashSet::new(),
      boom_on_cancel_arms: HashMap::new(),
      boom_on_cancel_replace: None,
      boom_on_cancel_grow: None,
      boom_on_cancel_begin_sync: None,
      future_owed: std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0)),
      panic_begin_close: None,
      panic_disarms: HashMap::new(),
      panic_every_disarm: None,
      panic_set_covers: HashMap::new(),
      panic_join_close_call: false,
      panic_join_close_poll: false,
      panic_join_close_drop: false,
      panic_cancel_sync: None,
      refuse_replaces: 0,
      replace_calls: 0,
      close_signal_during_replace: None,
      fail_grows: 0,
      dead_on_arrival_arms: 0,
      retarget: HashMap::new(),
      canonicalize: HashMap::new(),
      reuse_next_handle: None,
      actual_cover: HashMap::new(),
      pending_events: VecDeque::new(),
      next_replace_epoch: 1,
      seam: SeamLedger::new(),
    }
  }

  /// Records one call on the TOTAL [`SourceCall`] ledger. Every `Source` method the fake implements
  /// funnels through here, so the ledger cannot silently lose a method as the trait grows.
  fn note(&self, call: SourceCall) {
    self.seam.note(call);
  }

  /// A handle on this source's seam ledger that OUTLIVES it — taken before the owner is moved into
  /// [`run`], read after the run future has completed and dropped both.
  fn seam(&self) -> SeamLedger {
    self.seam.clone()
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

  /// The next `n` arms of `path` refuse with [`FaultKind::Capacity`] — a resource budget
  /// exhausted, the request declined without touching anything, retryable the moment it frees
  /// (`EMFILE`/the inotify instance limit; the watcher's teardown backlog). Per-path so a cell can
  /// script "refuse this root's first re-arm, admit its second" independently for each root.
  fn refuse_capacity(&mut self, path: &str, n: u32) {
    self.capacity_refusals.insert(PathBuf::from(path), n);
  }

  /// The next `n` `replace` calls refuse with [`FaultKind::Capacity`] — the in-place retarget
  /// declined at admission, with the old root's coverage untouched.
  fn refuse_next_replaces(&mut self, n: u32) {
    self.refuse_replaces = n;
  }

  /// Every `arm` of `path` from now on parks FOREVER — the hung-mount arm. Set on the roots a
  /// terminal restore outcome must never touch, so issuing one is not a countable slip but a
  /// reconcile that cannot return.
  fn wedge_arm(&mut self, path: &str) {
    self.wedge_arms.insert(PathBuf::from(path));
  }

  /// The next `served` arms of `path` behave normally; every arm after them parks FOREVER. The
  /// counted [`wedge_arm`](Self::wedge_arm), for a wedge that must appear PARTWAY through one
  /// hand-polled reconcile — which cannot be installed between polls, the reconcile future holding
  /// the owner borrowed throughout. Counting starts here, so an already-established root's own arm is
  /// not among the `served`.
  fn wedge_arms_after(&mut self, path: &str, served: u32) {
    self.wedge_arms_after.insert(PathBuf::from(path), served);
  }

  /// Every `arm` of `path` from now on PANICS — the misbehaving extension point whose unwind leaves
  /// the [`run`](super::run) future through its `poll`, so the owner is dropped by a task destruction
  /// rather than by its own teardown tail.
  fn panic_arm(&mut self, path: &str) {
    self.panic_arms.insert(PathBuf::from(path));
  }

  /// Every `arm` of `path` from now on parks FOREVER, and unwinds with `boom` when the arm future
  /// is CANCELLED — the wedged mount whose abandoned request takes its caller's destructor with it.
  /// The payload is the cell's choice for the reason every panicking CALL's is: the two shapes
  /// drive different code once the plane can be quarantined (see [`Boom`]).
  fn boom_on_cancel_arm(&mut self, path: &str, boom: Boom) {
    self.boom_on_cancel_arms.insert(PathBuf::from(path), boom);
  }

  /// `replace` parks FOREVER and unwinds with `boom` when the retarget future is CANCELLED.
  fn boom_on_cancel_replace(&mut self, boom: Boom) {
    self.boom_on_cancel_replace = Some(boom);
  }

  /// `grow` parks FOREVER and unwinds with `boom` when the coverage-widening future is CANCELLED.
  fn boom_on_cancel_grow(&mut self, boom: Boom) {
    self.boom_on_cancel_grow = Some(boom);
  }

  /// `begin_sync` parks FOREVER and unwinds with `boom` when the cookie write is CANCELLED.
  fn boom_on_cancel_begin_sync(&mut self, boom: Boom) {
    self.boom_on_cancel_begin_sync = Some(boom);
  }

  /// The obligation counter every [`PanicsWhenCancelled`] guard books against, for a cell that
  /// wants to read it after the source itself is gone.
  fn future_owed(&self) -> std::sync::Arc<core::sync::atomic::AtomicUsize> {
    std::sync::Arc::clone(&self.future_owed)
  }

  /// [`Source::begin_close`] PANICS with `boom` from now on — the teardown seam's initiation as a
  /// misbehaving extension point, which is the ONE `Source` call that stands ahead of every reap,
  /// the bounded wait and the acknowledgement in [`run`](super::run)'s tail.
  fn panic_begin_close(&mut self, boom: Boom) {
    self.panic_begin_close = Some(boom);
  }

  /// [`Source::disarm`] of `handle` PANICS with `boom` from now on — the fire-and-forget release
  /// the teardown tail's queued grant cleanup issues, misbehaving after it has already been applied.
  fn panic_disarm(&mut self, handle: u32, boom: Boom) {
    self.panic_disarms.insert(handle, boom);
  }

  /// EVERY [`Source::disarm`] PANICS with `boom` from now on, whatever the handle — the injector a
  /// churn cell needs, where the claim is about how many times the callback is entered across roots
  /// the cell has not armed yet.
  fn panic_every_disarm(&mut self, boom: Boom) {
    self.panic_every_disarm = Some(boom);
  }

  /// [`Source::set_cover`] of `handle` PANICS with `boom` from now on — the fire-and-forget
  /// coverage PRUNE the teardown tail's queued grant cleanup issues, misbehaving after it has
  /// already been applied.
  fn panic_set_cover(&mut self, handle: u32, boom: Boom) {
    self.panic_set_covers.insert(handle, boom);
  }

  /// [`Source::join_close`] PANICS at the CALL from now on — the bounded quiescence wait's
  /// extension point unwinding before it has produced a future to await.
  fn panic_join_close_call(&mut self) {
    self.panic_join_close_call = true;
  }

  /// The future [`Source::join_close`] returns PANICS at its first POLL from now on — the same
  /// extension point misbehaving at the other of its two instants.
  fn panic_join_close_poll(&mut self) {
    self.panic_join_close_poll = true;
  }

  /// The future [`Source::join_close`] returns resolves `Ok(())` and then PANICS in its own `Drop`
  /// from now on — the wait's third piece of implementor code, running behind the verdict the first
  /// two produced.
  fn panic_join_close_drop(&mut self) {
    self.panic_join_close_drop = true;
  }

  /// [`Source::cancel_sync`] PANICS with `boom` from now on — the by-name reclamation of an
  /// abandoned in-flight [`Source::begin_sync`], misbehaving on the one arm that issues it while
  /// holding a consumed [`CloseReply`].
  fn panic_cancel_sync(&mut self, boom: Boom) {
    self.panic_cancel_sync = Some(boom);
  }

  /// CLOSE `closes` from inside the `during`-th `replace` (1-based) and then PARK that call forever —
  /// every handle retired while that retarget is in flight. See
  /// [`close_signal_during_replace`](Self::close_signal_during_replace) for why the fake has to be the
  /// one to do it, and why it must park rather than return.
  fn close_signal_during_replace(
    &mut self,
    during: u32,
    closes: async_channel::Sender<super::CloseReply>,
  ) {
    self.close_signal_during_replace = Some((during, closes));
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

  /// How many roots this source still has ARMED — its own view, not the driver's. A release the
  /// owner never issued leaves one here, which is what a quarantined plane costs in watch budget.
  fn live_root_count(&self) -> usize {
    self.live.len()
  }
}

impl Source<OsString> for FakeSource {
  type Handle = u32;

  fn canonicalize_key(&self, k: &[OsString]) -> Result<Vec<OsString>, WatchError> {
    self.note(SourceCall::CanonicalizeKey(k.to_vec()));
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
    self.note(SourceCall::Arm(path.clone()));
    // The hung mount, checked first because it composes with nothing: this arm never returns, so
    // whatever the other injectors would have said is unreachable. The ledger already records the
    // request, so a cell can still attribute the wedge to the exact call that must not have happened.
    if self.wedge_arms.contains(&path) {
      core::future::pending::<()>().await;
    }
    // The panicking extension point, checked beside the wedge because it composes with nothing
    // either: this arm never answers, it unwinds. The ledger already holds the request.
    if self.panic_arms.contains(&path) {
      panic!("injected arm panic for {}", path.display());
    }
    // The wedge whose CANCELLATION unwinds: the guard is held across the park, so the owner's close
    // race destroying this future runs it. Checked beside the two above because it composes with
    // nothing either — this arm never answers, and the ledger already holds the request.
    if let Some(shape) = self.boom_on_cancel_arms.get(&path).copied() {
      // Booked BEFORE the park, so the obligation is the future's own from the instant the race
      // can cancel it. The release below is what a future allowed to run to completion reaches;
      // a cancelled one never does, and its destructor unwinds instead of discharging.
      let mut boom = PanicsWhenCancelled::book(&self.future_owed, shape);
      core::future::pending::<()>().await;
      boom.release();
    }
    // Its counted form: the mount that hangs only from this path's Nth arm onwards, so a cell can
    // wedge a RETRIED re-arm while the reconcile future still holds the owner borrowed.
    if let Some(served) = self.wedge_arms_after.get_mut(&path) {
      if *served == 0 {
        core::future::pending::<()>().await;
      }
      *served -= 1;
    }
    // The retryable refusal, checked FIRST so it composes with the fatal injector below: a
    // resource budget is exhausted and nothing was touched, so the caller may ask again.
    if let Some(remaining) = self.capacity_refusals.get_mut(&path)
      && *remaining > 0
    {
      *remaining -= 1;
      return Err(WatchError::source(
        SourceFault::new(FaultKind::Capacity)
          .with_source(io::Error::other("injected capacity refusal")),
      ));
    }
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
    self.note(SourceCall::IsSyncArtifact(key.to_vec()));
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
    // the real one, neither ground reads any deeper component, and — also like the real one —
    // the parent ground is decided FIRST, from the components, so "whatever the leaf" keeps
    // covering a leaf that is not UTF-8 at all.
    if key
      .len()
      .checked_sub(2)
      .and_then(|parent| key[parent].to_str())
      .is_some_and(|parent| parent == COOKIE_DIR)
    {
      return true;
    }
    key
      .last()
      .and_then(|leaf| leaf.to_str())
      .is_some_and(|leaf| leaf.starts_with("cookie-") || leaf == COOKIE_DIR)
  }

  fn end_sync(&mut self, _handle: u32, cookie_key: &[OsString]) {
    self.note(SourceCall::EndSync(cookie_key.to_vec()));
    self.ended_syncs.push(cookie_key.to_vec());
    // The reserved leaves a source-misbehaviour cell writes: the reap is recorded and then unwinds.
    // A leaf per REAPING SITE — the owner's destructor and `run`'s tail contain their reaps for
    // different reasons and are asserted apart — so neither cell can move the other's ledger, and
    // the leaf also picks the PAYLOAD, since the three shapes drive different code (see [`Boom`]).
    match cookie_key.last().and_then(|leaf| leaf.to_str()) {
      // The owner destructor's reap loop, with a payload whose own disposal unwinds: the reap is
      // entered, the payload is FORGOTTEN, and the plane quarantines behind it. What the cell
      // asserting where that loop stops injects.
      Some("cookie-boom") => {
        BOOM_COOKIES_REAPED.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Boom::Hostile.raise();
      }
      // The same loop with an ORDINARY payload, which records `unwound` and leaves the plane open —
      // the shape that keeps the loop's PER-CALL containment observable, since a boundary around
      // the whole loop would catch the identical panic and still skip every cookie behind it.
      Some("cookie-drop-boom") => Boom::Ordinary.raise(),
      // The same loop with a payload that strands a real allocation, for the two cells that price
      // what the loop can be made to forget rather than counting where it stops. A leaf per cell,
      // because the book they strand into is read per tag and a shared leaf would put both cells'
      // allocations under one reading — see [`Boom::Costly`].
      Some("cookie-costly-boom") => Boom::Costly(DESTRUCTOR_REAP_STRANDED).raise(),
      Some("cookie-total-boom") => Boom::Costly(BOUND_TOTAL_STRANDED).raise(),
      // The OPTIONAL reaps, whose cells assert that the work queued behind them still happens. A
      // payload the disposal had to FORGET would quarantine the plane, and everything behind the
      // panic would then be skipped rather than run — a different claim, and the one
      // `a_quarantined_source_plane_still_tears_down_and_answers_close` makes.
      Some("cookie-tail-boom" | "cookie-cleanup-boom" | "cookie-widen-boom") => {
        Boom::Ordinary.raise()
      }
      // The reap that ARMS the quarantine, for the cells whose subject is the bound itself.
      Some("cookie-quarantine-boom") => Boom::Hostile.raise(),
      // The reap that arms it from INSIDE a reconcile — a failed widen's restore, dominating the
      // barriers of the root it has just re-bound. A leaf of its own rather than the churn cell's,
      // because the two cells read the same latch over different populations and a shared leaf
      // would let either one arm the other's quarantine.
      Some("cookie-restore-boom") => Boom::Hostile.raise(),
      // The reap that arms it from inside a reconcile's RE-PLAN — a dead covering root retired
      // before the plan is taken again, dominating the barriers it owed on the way out. Its own
      // leaf for the same reason the restore's is: the cell reading it counts acquisitions behind a
      // latch it has to be the only thing to arm.
      Some("cookie-covered-boom") => Boom::Hostile.raise(),
      _ => {}
    }
  }

  fn cancel_sync(&mut self, handle: u32, token: SyncToken) {
    self.note(SourceCall::CancelSync(handle));
    // The abandon-arm ledger: an `on_sync` timeout or close hands the token here, and only
    // this call can free a cookie whose delivered-but-unread write the owner never got a path
    // for. Overrides the seam's defaulted no-op.
    self.cancelled_syncs.push(token);
    // Recorded AND applied before the unwind, exactly as `disarm` is: the reclamation happened and
    // then the source blew up in its own bookkeeping, so a cell's claim stays about how far the
    // unwind travels. The PAYLOAD is the injecting cell's choice — see [`Boom`], and the shape it
    // picks decides whether the plane quarantines behind the unwind.
    if let Some(boom) = self.panic_cancel_sync {
      boom.raise();
    }
  }

  async fn begin_sync(
    &mut self,
    handle: u32,
    dir_key: &[OsString],
    token: SyncToken,
  ) -> Result<Vec<OsString>, crate::error::SyncError> {
    self.note(SourceCall::BeginSync(handle));
    if !self.supports_sync {
      return Err(crate::error::SyncError::Unsupported);
    }
    self.begun_syncs += 1;
    // The token the abandon arm will later cancel — recorded so a cell can prove the cancel
    // names EXACTLY the sync that began (the nonce is owner-random, so the token cannot be
    // reconstructed from outside).
    self.begun_token = Some(token);
    // The write that parks and unwinds on CANCELLATION, for the reason `arm`'s counterpart gives.
    // Placed AFTER the token is recorded, so the close arm's by-name reclamation still names exactly
    // the sync that began.
    if let Some(shape) = self.boom_on_cancel_begin_sync {
      // The obligation booked and released as at `arm`'s counterpart.
      let mut boom = PanicsWhenCancelled::book(&self.future_owed, shape);
      core::future::pending::<()>().await;
      boom.release();
    }
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
    self.note(SourceCall::Replace(handle));
    self.replace_calls += 1;
    // Every handle retired while THIS retarget is in flight: close the signal, then never answer. The
    // race's close arm reads the signal gone on its next poll and drops this polled-but-unfinished
    // `replace` — the abandoned-retarget state the handles-gone reading has to be terminal for.
    if self
      .close_signal_during_replace
      .as_ref()
      .is_some_and(|(during, _)| *during == self.replace_calls)
      && let Some((_, closes)) = self.close_signal_during_replace.take()
    {
      closes.close();
      core::future::pending::<()>().await;
    }
    // The retarget that parks and unwinds on CANCELLATION, for the reason `arm`'s counterpart gives.
    if let Some(shape) = self.boom_on_cancel_replace {
      // The obligation booked and released as at `arm`'s counterpart.
      let mut boom = PanicsWhenCancelled::book(&self.future_owed, shape);
      core::future::pending::<()>().await;
      boom.release();
    }
    // An admission REFUSAL: the request was made and declined, so the call is on the ledger, and
    // `replace` is atomic on failure — the old root's coverage is exactly as it was.
    if self.refuse_replaces > 0 {
      self.refuse_replaces -= 1;
      return Err(WatchError::source(
        SourceFault::new(FaultKind::Capacity)
          .with_source(io::Error::other("injected replace capacity refusal")),
      ));
    }
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
    self.note(SourceCall::Disarm(handle));
    self.canonical.remove(&handle);
    self.live.remove(&handle);
    // The reserved handles a source-misbehaviour cell arms: the release is recorded AND applied, and
    // only then does the call unwind — so the fake models a source that did the work and then blew
    // up in its own bookkeeping, keeping the cell's claim about the unwind's reach. The PAYLOAD is
    // the injecting cell's choice — see [`Boom`]. The blanket injector is consulted second so a
    // per-handle one can still say something sharper about one root.
    if let Some(boom) = self
      .panic_disarms
      .get(&handle)
      .copied()
      .or(self.panic_every_disarm)
    {
      boom.raise();
    }
  }

  fn set_cover(&mut self, handle: u32, retained: &[Vec<OsString>]) {
    // Synchronous, fire-and-forget in-place coverage PRUNE request (the set-cover design v3): record the root
    // handle and the retained cover the driver forwarded, so a test can assert exactly which prunes
    // fired and in what order. The fake keeps the root live — a prune reconciles coverage BELOW a
    // root, never releases it — so `root_key` still answers, unlike `disarm`. Unlike `FsSource` (which
    // QUEUES and drains opportunistically), the fake APPLIES immediately, so `actual_covers` reflects
    // the source's true coverage right away.
    self.calls.push(Call::SetCover(handle, retained.to_vec()));
    self.note(SourceCall::SetCover(handle));
    self.apply_cover(handle, retained);
    // Recorded AND applied before the unwind, exactly as `panic_disarms` is: the fake models a
    // source that pruned and then blew up, which is the sub-case a record left at its previous
    // broader value would be unsafe for. The PAYLOAD is the injecting cell's choice — see [`Boom`].
    if let Some(boom) = self.panic_set_covers.get(&handle).copied() {
      boom.raise();
    }
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
    self.note(SourceCall::Grow(handle));
    if self.grow_pending {
      core::future::pending::<()>().await;
    }
    // The grow that parks and unwinds on CANCELLATION, for the reason `arm`'s counterpart gives.
    if let Some(shape) = self.boom_on_cancel_grow {
      // The obligation booked and released as at `arm`'s counterpart.
      let mut boom = PanicsWhenCancelled::book(&self.future_owed, shape);
      core::future::pending::<()>().await;
      boom.release();
    }
    if self.fail_grows > 0 {
      self.fail_grows -= 1;
      return Err(WatchError::CoverageIncomplete);
    }
    self.apply_cover(handle, retained);
    Ok(())
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    self.note(SourceCall::Next);
    // Drain the handle's raw event stream (a `replace`-emitted full-root `Rescan`), or `None` once
    // empty — the source-drained signal every existing cell already relied on.
    self.pending_events.pop_front()
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.note(SourceCall::RootKey(handle));
    self.canonical.get(&handle).cloned()
  }

  fn begin_close(&mut self) {
    // Counted TWO ways, because the two answer different questions: the ordered seam ledger says WHERE
    // this landed relative to every fire-and-forget request a teardown issues, and the counter says it
    // landed exactly once — which a sequence containing one `BeginClose` also says, so the counter is
    // the redundancy that survives a cell asserting only a prefix.
    self
      .seam
      .begin_closes
      .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    self.note(SourceCall::BeginClose);
    // Counted and recorded BEFORE the unwind, so a cell can assert that an initiation which panicked
    // still latched exactly one entry — the property the owner's `source_closing` latch owes, since
    // it is set ahead of this call and the destructor's own entry reads it afterwards. The PAYLOAD
    // is the injecting cell's choice — see [`Boom`].
    if let Some(boom) = self.panic_begin_close {
      boom.raise();
    }
  }

  fn join_close(
    &mut self,
  ) -> impl core::future::Future<Output = Result<(), crate::error::SourceCloseError>> + Send {
    // Noted at the CALL rather than inside the future, so the request is on the ledger even when
    // the call is the thing that unwinds. The one caller awaits it immediately, so the ledger's
    // order is what it always was.
    self.note(SourceCall::JoinClose);
    if self.panic_join_close_call {
      std::panic::panic_any(PanicsOnDrop);
    }
    FakeJoinClose {
      poll_panics: self.panic_join_close_poll,
      drop_panics: self.panic_join_close_drop,
    }
  }
}

/// The future [`FakeSource::join_close`] hands back.
///
/// Hand-written rather than an `async` block because the wait's third piece of implementor code is
/// this future's own `Drop`, and a compiler-generated future has no destructor a cell can make
/// misbehave. The wait's FIRST piece is not here at all: an unwind at the CALL happens inside
/// [`join_close`](Source::join_close) itself, ahead of this type's construction, which is exactly
/// what makes the three separable.
struct FakeJoinClose {
  /// PANIC at the first poll, before any verdict exists.
  poll_panics: bool,
  /// PANIC in `Drop`, AFTER the poll has already handed back a clean `Ok(())`.
  drop_panics: bool,
}

impl core::future::Future for FakeJoinClose {
  type Output = Result<(), crate::error::SourceCloseError>;

  fn poll(
    self: core::pin::Pin<&mut Self>,
    _: &mut core::task::Context<'_>,
  ) -> core::task::Poll<Self::Output> {
    if self.poll_panics {
      std::panic::panic_any(PanicsOnDrop);
    }
    core::task::Poll::Ready(Ok(()))
  }
}

impl Drop for FakeJoinClose {
  fn drop(&mut self) {
    // The payload is hostile ([`PanicsOnDrop`]) for the reason every other injector's is: a
    // boundary that catches this has to dispose of the payload too, and disposal runs the payload's
    // own destructor.
    if self.drop_panics {
      std::panic::panic_any(PanicsOnDrop);
    }
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
/// A guard the fake holds ACROSS a park, so cancelling the future it is parked in runs its
/// destructor.
///
/// The instrument for the one piece of implementor code no `Source`-call injector can reach: what
/// runs when the owner wins a race against a `Source`-returned future and DESTROYS it. An `async fn`
/// future keeps whatever its body parked with, so a guard placed before the park is exactly the
/// caller `Drop` a cancellation is obliged to run — and the [`Source`] contract no more requires it
/// to be panic-free than it requires a [`Filter`] predicate to be.
///
/// The payload is the injecting cell's choice ([`Boom`]) for the reason every other misbehaviour
/// injector's is: a boundary that catches this must dispose of the payload inside a boundary too,
/// and what THAT disposal does decides whether the owner's optional source plane quarantines behind
/// the cancellation. A cell asserting that the requests queued behind a cancelled future still
/// reach the source and a cell asserting the bound on the leak are asking for opposite things.
///
/// It also OWNS a cleanup obligation, and that is the half the verdict turns on. The counter it
/// books against is the FUTURE's, not the source's: nothing a [`Source::join_close`] can be asked
/// reflects it, so the fake's wait answers `Ok(())` truthfully however this guard ends. The only
/// discharge is [`release`](Self::release), which the future's body reaches when it is allowed to
/// run to completion — a cancelled one never is, and the destructor below unwinds AHEAD of the
/// discharge rather than performing it. So a cell holding the counter after `close()` is reading
/// whether a native resource stayed live behind the acknowledgement.
struct PanicsWhenCancelled {
  /// Obligations outstanding, shared with the cell through
  /// [`FakeSource::future_owed`](FakeSource::future_owed). Booked at construction.
  owed: std::sync::Arc<core::sync::atomic::AtomicUsize>,
  /// Whether [`release`](Self::release) already discharged this one.
  released: bool,
  /// Which payload the cancellation unwinds with — the injecting cell's choice.
  boom: Boom,
}

impl PanicsWhenCancelled {
  /// Books one obligation the future now owns and only this guard can discharge.
  fn book(owed: &std::sync::Arc<core::sync::atomic::AtomicUsize>, boom: Boom) -> Self {
    owed.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    Self {
      owed: std::sync::Arc::clone(owed),
      released: false,
      boom,
    }
  }

  /// The discharge a future that RAN TO COMPLETION makes. Unreachable for a cancelled one, which is
  /// the whole point: its destructor is then the only release left, and that destructor unwinds.
  fn release(&mut self) {
    self.owed.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    self.released = true;
  }
}

impl Drop for PanicsWhenCancelled {
  fn drop(&mut self) {
    if self.released {
      return;
    }
    // Unwinds with the obligation still outstanding: a `Drop` that panics before releasing what it
    // held is exactly the shape the [`Source`] cannot answer for afterwards.
    self.boom.raise();
  }
}

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

/// Which payload an injected [`Source`] panic carries — the choice that decides what the
/// containment's DISPOSAL of it does, and so whether the owner's source plane quarantines.
///
/// A knob rather than one hostile shape everywhere, because the two shapes now drive different
/// code. Before the plane could be quarantined, hostility was free: a forgotten payload cost memory
/// and nothing else, so every injector reached for it and every cell got the payload-disposal claim
/// thrown in. It is not free any more —
/// [`forgotten`](super::SourceDisposals::forgotten) turns the OPTIONAL callbacks off for the rest
/// of the owner's life — so a cell asserting that the work queued BEHIND a panic still happens and
/// a cell asserting that the leak is BOUNDED are now asking for opposite things, and each has to
/// say which.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Boom {
  /// An ordinary `&'static str` payload: its disposal drops it and returns, so the call is recorded
  /// as unwound and the plane stays open. What a cell asserting "everything behind this call still
  /// runs" injects.
  Ordinary,
  /// A [`PanicsOnDrop`] payload: its own destructor unwinds, so the disposal has to FORGET it and
  /// the plane quarantines. What a cell asserting the bound on that leak injects. Costs no retained
  /// allocation — see [`ForgottenPayload`].
  Hostile,
  /// A [`PanicsOnDropCostly`] payload: hostile, and its destructor MINTS a heap allocation and
  /// books it against the tag on the way past. What a cell asserting the SIZE of the bound injects,
  /// because "one arbitrary allocation per call, forever" is the defect the bound exists for and
  /// [`Hostile`](Self::Hostile), which mints nothing, leaves nothing to read.
  ///
  /// The payload the disposal then forgets is itself zero-sized, deliberately, and the minted block
  /// stays reachable from the book: the WITNESS is the count, not the block's unreachability.
  /// [`StrandedAllocation`] carries the whole reason for that shape.
  ///
  /// The `&'static str` is the reading's OWNER — the cell whose assertion counts these — because
  /// the book is process-wide and the suite runs its cells in parallel. A plain length would make
  /// every costly cell's delta a race against every other one; counting only its own tag makes each
  /// reading exact whatever else is running. Every tag must therefore be used by exactly one cell.
  Costly(&'static str),
}

impl Boom {
  /// Raises this shape's panic. Never returns.
  fn raise(self) -> ! {
    match self {
      Self::Ordinary => panic!("an injected `Source` panic with an ordinary payload"),
      Self::Hostile => std::panic::panic_any(PanicsOnDrop),
      Self::Costly(site) => std::panic::panic_any(PanicsOnDropCostly(site)),
    }
  }
}

/// [`PanicsOnDrop`]'s expensive twin: its own disposal unwinds with a payload whose MINTING
/// allocates and books, so every trip through this destructor is one countable unit of what a
/// forced [`forget`](core::mem::forget) costs.
///
/// The plain twin proves the containment is TOTAL; this one prices it. A source that can be made to
/// panic with this on every watch/unwatch cycle would cost a real process one arbitrary allocation
/// per cycle, forever, which is the unbounded leak [`forgotten`](super::SourceDisposals::forgotten)
/// exists to cap at one.
///
/// The mint is the only thing that costs. The payload the disposal is then forced to forget owns no
/// heap data of its own, and the block minted for it stays reachable from the book rather than
/// being carried off — so a reading is the book's COUNT, and never the allocator's. See
/// [`StrandedAllocation`], where that trade is the whole reason for the shape.
///
/// Carries the tag of the cell that will count it — see [`Boom::Costly`] for why the book is read
/// per tag rather than by length.
struct PanicsOnDropCostly(&'static str);

impl Drop for PanicsOnDropCostly {
  fn drop(&mut self) {
    std::panic::panic_any(StrandedAllocation::mint(self.0));
  }
}

/// The payload [`PanicsOnDropCostly`]'s disposal has to FORGET, and the mark that one allocation
/// was minted for the forget that swallowed it.
///
/// # Why the payload owns nothing and the allocation lives in a book
///
/// The suite runs under LeakSanitizer, which reports every block no live pointer reaches, and a
/// forgotten payload is unreachable by construction — so whatever this type owned directly WOULD be
/// reported. That leg cannot be told to expect it from here either: LSan is Linux-only, so no
/// reading taken where this fixture is written can check the expectation, and the frames CI reports
/// come back unsymbolized, so a suppression would have no dependable name to key on. The only shape
/// that is right by construction is therefore one that retains nothing at all — so this is a ZST,
/// boxing it allocates no block, and the `forget` that cuts the recursion strands not one byte a
/// sanitizer can see. It is the same idiom [`ForgottenPayload`] already runs on, and for the same
/// reason.
///
/// The cost is therefore priced in the book instead. [`mint`](Self::mint) makes a real allocation,
/// attributable one-for-one to this forget because nothing else calls it, and files it under the
/// cell's tag where a static owns it for the rest of the process — counted rather than reported.
/// That count is the WITNESS, and it had to be a count either way: a cell cannot ask the allocator
/// how many payloads were forgotten, and the payload is beyond reach the instant it is, so the
/// reading has to be taken on the way in.
///
/// What is given up is only the LITERAL loss. Everything a cell exercises is unchanged — a
/// destructor that unwinds, a payload whose own destructor makes dropping it impossible, a disposal
/// driven to `forget` — and the allocation is still made, still attributable to that forget, and
/// still counted. It is simply owned by the book rather than by nobody.
struct StrandedAllocation;

impl StrandedAllocation {
  /// Mints one against `site`'s reading and books it, returning the payload the destructor unwinds
  /// with.
  ///
  /// The allocation goes to the book and nowhere else; the payload handed back is zero-sized — see
  /// the type's own note for why that split is load-bearing.
  fn mint(site: &'static str) -> Self {
    STRANDED
      .lock()
      .expect("the stranded-allocation book")
      .push(StrandedRecord {
        site,
        _held: std::sync::Arc::new(vec![0_u8; 1024]),
      });
    Self
  }

  /// How many allocations have been stranded against `site` process-wide. Counted per tag rather
  /// than as a length so several costly cells can run in parallel without moving each other's
  /// reading; each tag belongs to exactly one cell, which is what makes a raw count sound where
  /// [`BOOM_COOKIES_REAPED`] needs the same discipline.
  fn stranded(site: &'static str) -> usize {
    STRANDED
      .lock()
      .expect("the stranded-allocation book")
      .iter()
      .filter(|booked| booked.site == site)
      .count()
  }
}

/// One entry in the book: which reading the strand belongs to, and the block it keeps reachable.
struct StrandedRecord {
  /// The tag [`StrandedAllocation::stranded`] counts by — see [`Boom::Costly`].
  site: &'static str,
  /// The allocation itself. The book is its only owner, which is exactly what keeps a whole-process
  /// leak check quiet about a block minted for a payload nothing can reach.
  _held: std::sync::Arc<Vec<u8>>,
}

/// Every allocation minted for a forgotten [`StrandedAllocation`], kept reachable and tagged with
/// the reading it belongs to — see that type's note for why the cost is booked here rather than
/// carried off by the payload, and why the book is a static.
static STRANDED: std::sync::Mutex<Vec<StrandedRecord>> = std::sync::Mutex::new(Vec::new());

/// How many `cookie-boom` cookies [`FakeSource::end_sync`] has been handed.
///
/// A process-wide counter because the ledger it would otherwise use lives inside the source,
/// inside the owner being DROPPED — the very destructor under test. Only the owner-teardown
/// reap cell writes the `cookie-boom` leaf, so no other cell can move it.
static BOOM_COOKIES_REAPED: core::sync::atomic::AtomicUsize =
  core::sync::atomic::AtomicUsize::new(0);

/// The stranded-allocation tag the `cookie-costly-boom` leaf mints against, read by
/// [`the_destructors_reap_strands_one_allocation_however_many_cookies_are_pending`] alone — see
/// [`Boom::Costly`] for why the book is counted per tag.
const DESTRUCTOR_REAP_STRANDED: &str = "destructor-reap";

/// The tag the `cookie-total-boom` leaf mints against, read by
/// [`the_forgotten_payload_total_is_a_constant_of_the_code_not_of_what_the_caller_drove`] alone.
/// Its churn and its seam entry mint against it too, which is what makes that cell's reading a
/// TOTAL across every site it drove rather than a count of any one of them.
const BOUND_TOTAL_STRANDED: &str = "bound-total";

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
    Self::build(coalescer, None, None)
  }

  /// A harness whose owner→consumer event channel is **bounded** at `capacity` — for the
  /// backpressure tests, where a stalled consumer fills the channel and the owner sheds the
  /// affected subscription to a parked dominating `Rescan` (design backpressure doc).
  fn bounded(capacity: usize) -> Self {
    Self::build(None, Some(capacity), None)
  }

  /// A harness whose event channel is bounded at `capacity` AND whose command mailbox is bounded
  /// at `commands` — the real watcher's shape, where
  /// [`command_capacity`](TributariesOptions::command_capacity) is what bounds a queued backlog.
  /// The other constructors leave the mailbox unbounded because they drive the owner directly and
  /// never queue one.
  fn bounded_mailbox(capacity: usize, commands: usize) -> Self {
    Self::build(None, Some(capacity), Some(commands))
  }

  fn build(
    coalescer: Option<Coalescer<OsString, ()>>,
    capacity: Option<usize>,
    command_capacity: Option<usize>,
  ) -> Self {
    let (event_tx, event_rx) = match capacity {
      Some(cap) => async_channel::bounded(cap),
      None => async_channel::unbounded(),
    };
    let (command_tx, command_rx) = match command_capacity {
      Some(cap) => async_channel::bounded(cap),
      None => async_channel::unbounded(),
    };
    let (sync_command_tx, sync_command_rx) = async_channel::unbounded::<super::SyncRequest>();
    let (close_tx, close_rx) = async_channel::bounded(1);
    let (cleanup_tx, cleanup_rx) = async_channel::unbounded();
    let owner = Owner {
      source: FakeSource::new(),
      source_closing: false,
      source_disposals: super::SourceDisposals::default(),
      deferred: crate::subsume::Salvage::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: Filters::new(),
      filter_payload_forgotten: false,
      needs_rescan: ParkedRescans::new(),
      suppressed_rescan: ParkedRescans::new(),
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
      .reconcile_watch(&key(path), &(), options)
      .await
      .map_err(|stop| match stop {
        super::ReconcileStop::Failed(err) => err,
        // These harness owners are driven directly — nothing ever sends on their close signal — so
        // the in-place widen's close race cannot fire here.
        super::ReconcileStop::CloseRequested(_) => {
          unreachable!("no close is sent to a directly-driven harness owner")
        }
        // A cell MAY close the signal (the last handle dropping) and then drive a reconcile through
        // this helper, so this one is reachable: report exactly what a real `watch()` caller reads
        // off the reply the owner drops for it. Cells asserting on the teardown outcome ITSELF call
        // `reconcile_watch` directly, where the [`super::ReconcileStop`] is not yet flattened.
        super::ReconcileStop::HandlesGone => WatchError::Closed,
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

/// The failed-widen restore must not read a **capacity refusal** as death. A widen releases its
/// subsumed roots BEFORE arming the wider one, so any resource bound hit inside that window — the
/// fs binding's watch-instance limit needs no wedged mount at all — arrives at the restore's
/// re-arms, where "the root is genuinely dead" retired *healthy established* roots that a caller
/// did nothing wrong to lose. A refusal means *ask again shortly*, so the restore asks again,
/// paced, inside its budget.
///
/// Both roots' first re-arm is refused and their second admitted, so the retry is proven for each
/// root rather than only the first one reached. The clock is paused: the pacing is a fact of the
/// cell, not a race.
///
/// FAIL-ON-REVERT: restore `Err(ReconcileStop::Failed(_)) => retire_root_with_terminal_rescan(old)`
/// as the sole failure arm (retire on EVERY kind) and each root is retired on its first refusal —
/// the call ledger loses its second attempt per root, both keys leave the view, and the terminal
/// `Rescan`s this cell asserts are absent are parked instead.
#[tokio::test(start_paused = true)]
async fn a_capacity_refused_widen_restore_retries_rather_than_retiring_healthy_roots() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // The budget is exhausted for the wider arm and for each root's FIRST re-arm, then frees —
  // exactly the shape of an instance-limit blip that the widen's own releases are already curing.
  h.owner.source.refuse_capacity("/a", 1);
  h.owner.source.refuse_capacity("/a/b", 1);
  h.owner.source.refuse_capacity("/a/c", 1);

  let started = tokio::time::Instant::now();
  let result = h.watch("/a", Interest::all()).await;
  let elapsed = started.elapsed();
  assert!(
    result.is_err(),
    "the refused wider arm still fails the newcomer's watch"
  );

  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Arm(PathBuf::from("/a")),
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Arm(PathBuf::from("/a/c")),
    ],
    "every refused re-arm is OFFERED AGAIN, per root, instead of being read as a dead root"
  );
  assert!(
    elapsed >= 2 * super::RESTORE_RETRY_PACE,
    "the two retries WAITED between attempts — paced, never a hot spin against a busy source: \
     {elapsed:?}"
  );

  // Both subsumed subscriptions are live-and-covered again, on fresh live handles.
  let view = h.owner.subsumer.view();
  assert!(
    view.is_watched(&key("/a/b")) && view.is_watched(&key("/a/c")),
    "neither healthy root was retired for a refusal that cleared"
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
    "both roots are back, re-armed"
  );
  for (path, handle) in &roots {
    assert!(
      h.owner.source.root_key(*handle).is_some(),
      "the retried root {path:?} is on a LIVE handle"
    );
  }
  assert!(
    h.owner.filters.contains_key(&sb) && h.owner.filters.contains_key(&sc),
    "no per-subscription state was freed: nothing retired"
  );
  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "the aborted widen leaks no pending reservation"
  );

  // No TERMINAL Rescan is owed to anyone. `retire_root_with_terminal_rescan` parks its terminal
  // Rescan straight into `needs_rescan`/`suppressed_rescan` before freeing state, and this
  // harness's event channel is unbounded (so no ordinary emit can park) — an empty pair is
  // therefore exactly "no root was retired".
  assert!(
    h.owner.needs_rescan.is_empty() && h.owner.suppressed_rescan.is_empty(),
    "no terminal coverage-loss Rescan was parked for either root"
  );
  // What the subscribers DO get is the ordinary restore re-point Rescan, as on any failed widen.
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

/// The other half of the split, and the one that keeps it from trading one defect for another: a
/// re-arm that fails for a reason no wait can cure is still retired on its FIRST refusal, exactly
/// as before the retry existed. The verdict is taken from the RE-ARM's own kind, so a widen whose
/// wider arm was refused on capacity buys its subsumed roots nothing when their own re-arms are
/// fatal.
///
/// FAIL-ON-REVERT: widen the retry from `is_capacity_refusal(&err)` to every `Failed` (v1's
/// define-the-transient-set-by-complement) and these fatal re-arms are re-offered until the budget
/// expires — the call ledger grows a pace's worth of attempts per root and the cell spends
/// `RESTORE_RETRY_BUDGET` reaching the same retirement.
#[tokio::test]
async fn a_fatal_re_arm_is_retired_on_its_first_refusal_however_the_wider_arm_failed() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c");
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // The wider arm is refused on the RETRYABLE kind; both re-arms then fail fatally, and keep
  // failing — so a retry that fired here would spend the whole budget before retiring anyway.
  h.owner.source.refuse_capacity("/a", 1);
  h.owner.source.fail_next_arms(u32::MAX);

  let started = std::time::Instant::now();
  let result = h.watch("/a", Interest::all()).await;
  let elapsed = started.elapsed();
  assert!(result.is_err(), "the failed widen surfaces the error");

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
    "exactly ONE re-arm attempt per root: a fatal refusal is never re-offered"
  );
  assert!(
    elapsed < super::RESTORE_RETRY_BUDGET / 2,
    "…and no budget is spent waiting on it: {elapsed:?}"
  );

  // Both roots retired, exactly as they always were: out of the view, per-sub state freed, and a
  // durable dominating terminal Rescan parked for each subscriber before that state went away.
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b")) && !view.is_watched(&key("/a/c")),
    "a genuinely dead root still leaves the view"
  );
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "neither root survives a fatal re-arm"
  );
  assert!(
    !h.owner.filters.contains_key(&sb) && !h.owner.filters.contains_key(&sc),
    "each retired root's subscriber state is freed (I4)"
  );

  h.owner.flush_pending_rescans();
  let by_sub: HashMap<Subscription, Epoch> = h
    .drain()
    .iter()
    .map(|ev| {
      assert!(ev.is_rescan(), "every retirement signal is a Rescan");
      (ev.subscription(), ev.epoch())
    })
    .collect();
  assert_eq!(
    by_sub.get(&sb).copied(),
    Some(Epoch::new(5)),
    "sb's terminal Rescan strictly dominates its high-water of 4"
  );
  assert_eq!(
    by_sub.get(&sc).copied(),
    Some(Epoch::new(3)),
    "sc's terminal Rescan strictly dominates its high-water of 2"
  );
}

/// The in-place retarget's triage: a widen subsuming exactly ONE root asks the source to retarget
/// it, and a refusal there is answered where it lands — BEFORE the first disarm. `replace` is
/// atomic on failure and nothing has been released yet, so failing the watch is refusal-before-
/// mutation: no teardown, no coverage gap, no `Rescan` owed to anyone, and the caller retries when
/// it likes. Falling through instead would release this healthy root and then ask the very budget
/// that just refused for a fresh stream.
///
/// FAIL-ON-REVERT: restore `ReplaceStep::Replaced(Err(_)) => None` as the only replace-error arm
/// (triaging nothing) and the widen falls into release-and-rearm — `Disarm(1)` and a wider
/// `Arm(/a)` appear on the ledger, the sole root's coverage is dropped mid-flight, and the watch
/// no longer fails at all.
#[tokio::test]
async fn a_retarget_refused_on_capacity_fails_the_widen_before_anything_is_disarmed() {
  let mut h = Harness::new();
  h.owner.source.supports_replace = true;

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.source.refuse_next_replaces(1);

  let err = h
    .watch("/a", Interest::all())
    .await
    .expect_err("a refused retarget fails the watch outright");
  assert_eq!(
    err.fault().map(SourceFault::kind),
    Some(FaultKind::Capacity),
    "the caller is told it was a retryable budget refusal: {err:?}"
  );

  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Replace(1, PathBuf::from("/a")),
    ],
    "NOTHING was disarmed: no release, no wider arm, no rollback — the refusal is answered first"
  );
  assert!(
    h.owner.subsumer.view().is_watched(&key("/a/b")),
    "the sole subsumed root keeps reading watched"
  );
  assert!(
    h.owner.source.root_key(1).is_some(),
    "…and its source watch never stopped — the handle is untouched"
  );
  let roots: Vec<(PathBuf, u32)> = h
    .owner
    .subsumer
    .roots()
    .map(|(k, handle)| (PathBuf::from_iter(k), handle))
    .collect();
  assert_eq!(
    roots,
    vec![(PathBuf::from("/a/b"), 1)],
    "the root is still recorded at its own key, on its ORIGINAL handle"
  );
  assert!(
    h.owner.filters.contains_key(&sb),
    "the subscriber's state is untouched"
  );
  assert_eq!(
    h.owner.subsumer.pending_len(),
    0,
    "the abandoned widen leaks no pending reservation"
  );
  assert!(
    h.drain().is_empty() && h.owner.needs_rescan.is_empty() && h.owner.suppressed_rescan.is_empty(),
    "nothing was lost, so nothing is owed: not one Rescan, delivered or parked"
  );
}

/// A close the widen's own arm ALREADY CONSUMED is TERMINAL for the unwind, not merely a posture to
/// run it under. The wider arm can lose to the close race, and that caller's reply is then held in
/// hand — the close signal is bounded at one slot and drains as it is consumed, so nothing is left
/// to preempt a re-arm started in that state and every attempt would be added straight onto that
/// caller's `close()` latency, whose bound is the contract every other owner await is raced to keep.
///
/// So the roots are retired synchronously and the reply handed straight back: NO re-arm is issued at
/// all. The refusal staged here never clears, so a restore that ran would burn its whole budget; the
/// cell proves the negative by the exact call ledger (not one re-arm after the disarms), by the
/// elapsed time, and by acking the returned reply — `close()` is answered rather than left waiting.
///
/// FAIL-ON-REVERT: run the restore in a "no retry" posture instead (a zero budget: one attempt per
/// root, then retire) and the ledger grows a re-arm per root — a source call issued after the reply
/// was consumed, with nothing left able to interrupt it. Revert further, to a bounded budget at this
/// call site, and each root is re-offered for the full `RESTORE_RETRY_BUDGET` while the close reply
/// sits unsent, so the elapsed assertion fails too.
#[tokio::test]
async fn a_widen_holding_a_consumed_close_reply_retires_without_retrying() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // Every re-arm the restore could issue is refused on the RETRYABLE kind, and it never clears: the
  // only thing that can keep the restore from running is the close reply the widen is holding.
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  h.owner.source.refuse_capacity("/a/c", u32::MAX);

  // A close is already queued on the dedicated signal, exactly as `Tributaries::close` leaves it.
  let (reply, response) = futures_channel::oneshot::channel();
  h.closes.try_send(reply).expect("the close signal accepts");

  let started = std::time::Instant::now();
  let stop = h
    .owner
    .reconcile_watch(
      &key("/a"),
      &(),
      WatchOptions::new().with_interest(Interest::all()),
    )
    .await
    .expect_err("the consumed close abandons the widen");
  let elapsed = started.elapsed();

  let super::ReconcileStop::CloseRequested(close_reply) = stop else {
    panic!("the consumed close reply rides back out of the reconcile: {stop:?}");
  };
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      // The ledger ENDS at the disarms. No `Arm(/a)`: the queued close wins the choke point's
      // biased race before the wider arm is ever issued. And no re-arm either: the consumed reply is
      // terminal, so both roots are retired synchronously.
    ],
    "a held close reply means NO further source call — not one re-arm on `close()`'s clock"
  );
  assert!(
    elapsed < super::RESTORE_RETRY_BUDGET / 2,
    "the reconcile returns promptly rather than waiting out a retry budget: {elapsed:?}"
  );

  // `close()` completes: ack the reply exactly as the run loop's teardown does, and the caller
  // that was waiting on it is answered.
  close_reply.send(Ok(())).expect("the close reply is live");
  assert!(
    matches!(response.await, Ok(Ok(()))),
    "the close() caller is answered, never left pending behind the widen"
  );

  // Both roots retired, so nothing is left recorded-live-but-disarmed (I3) for the teardown to
  // find — the same close-path behaviour as before the retry existed.
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b")) && !view.is_watched(&key("/a/c")),
    "no subscription is left published-watched on a released handle"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sb) && h.owner.needs_rescan.contains_key(&sc),
    "each retirement still parked its durable dominating terminal Rescan"
  );
}

/// Every handle dropping must END the restore, not be waited out by it. When the last handle goes,
/// the close signal closes with the command mailbox, so nothing will ever answer a close race —
/// and the run loop is where that closed mailbox is READ and teardown begins. A restore that keeps
/// arming never returns there: it spins its whole budget against a source refusing for its own
/// reasons while the watcher is already, unrecoverably, on its way out.
///
/// The signal is already closed when this restore begins, so its per-root probe reports the terminal
/// condition before the FIRST re-arm and every root is retired without one. The refusal staged here
/// never clears, so nothing else could have ended the restore; the cell proves the negative by the
/// exact call ledger (not one re-arm) and by the elapsed time.
///
/// The WIDER arm is absent from that ledger too, and for the sibling reason: `Owner::arm` reads the
/// closed signal as terminal, so the widen never issues it either. The ledger therefore ends at the
/// two disarms.
///
/// FAIL-ON-REVERT: drop the per-root probe (leave handles-gone to be discovered at a pace) and the
/// ledger grows a re-arm for every root. Fold the terminal into an ordinary per-root failure on top
/// of that — the outer loop carrying on — and the later roots are armed too. Fold it into "the pace
/// elapsed" instead and the pace resolves INSTANTLY on the closed channel every time, so the restore
/// hot-spins the full `RESTORE_RETRY_BUDGET` and the elapsed assertion fails as well. Answer the
/// closed signal in `Owner::arm` with an un-raced re-issue again and the wider `Arm(/a)` returns to
/// the ledger.
#[tokio::test]
async fn every_handle_gone_ends_the_restore_retry_instead_of_spinning_out_its_budget() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // A refusal that never clears: only a terminal outcome can end the restore.
  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  h.owner.source.refuse_capacity("/a/c", u32::MAX);
  // The last handle drops: `Tributaries`' close signal closes in lockstep with the command
  // mailbox the run loop takes its teardown signal from.
  h.closes.close();

  let started = std::time::Instant::now();
  let result = h.watch("/a", Interest::all()).await;
  let elapsed = started.elapsed();
  assert!(result.is_err(), "the refused widen still fails the watch");

  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      // The wider arm does not reach the source at all: the widen's own `Owner::arm` reads the
      // closed signal as terminal before issuing it. The ledger ends at the disarms, with no wider
      // arm and no re-arm for either root.
      Call::Disarm(2),
    ],
    "the closed signal is terminal BEFORE the first re-arm, and terminal for every root still to \
     come"
  );
  assert!(
    elapsed < super::RESTORE_RETRY_BUDGET / 2,
    "the reconcile returns to the loop — where the closed mailbox drives teardown — instead of \
     spinning: {elapsed:?}"
  );

  // Terminal for the roots too: neither is left recorded-live-but-disarmed for the teardown.
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b")) && !view.is_watched(&key("/a/c")),
    "no subscription is left published-watched on a released handle"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sb) && h.owner.needs_rescan.contains_key(&sc),
    "each retirement still parked its durable dominating terminal Rescan"
  );
}

/// ORDERING, not effect. A consumed close reply must be checked BEFORE the re-arm, and the two are
/// not the same claim: a check that runs after it still issues the call, and that call is the
/// hazard. Nothing can preempt it — the reply came off a one-slot signal that is empty again — so a
/// source hung on a dead mount holds the [`run`] loop with the reply undelivered, exactly the wedge
/// every owner await is raced to avoid.
///
/// So this cell does not count attempts, it makes them fatal: every subsumed root's arm is WEDGED,
/// and the reconcile is deadlined. Issue one re-arm and it never returns. THREE roots, because the
/// claim is about all the remaining ones, not just the next.
///
/// FAIL-ON-REVERT: check the held reply anywhere after `self.arm` — a "no retry" posture threaded
/// INTO the restore, per-root or otherwise — and the first re-arm parks forever: the timeout below
/// fires, and the ledger shows the `Arm` that must not have been issued.
#[tokio::test(start_paused = true)]
async fn a_consumed_close_reply_ends_the_unwind_before_one_more_source_call() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  let sd = h.watch("/a/d", Interest::all()).await.expect("watch /a/d"); // handle 3
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));
  h.owner.epochs.stamp(sd, Epoch::new(6));

  // Each subsumed root's re-arm would hang forever — the mount the close race exists for. Set AFTER
  // the watches above, which needed those same arms to succeed.
  h.owner.source.wedge_arm("/a/b");
  h.owner.source.wedge_arm("/a/c");
  h.owner.source.wedge_arm("/a/d");

  // A close is already queued on the dedicated signal, exactly as `Tributaries::close` leaves it, so
  // the wider arm's biased race consumes it and the reconcile carries the reply into its unwind.
  let (reply, response) = futures_channel::oneshot::channel();
  h.closes.try_send(reply).expect("the close signal accepts");

  let stop = tokio::time::timeout(
    Duration::from_secs(30),
    h.owner.reconcile_watch(
      &key("/a"),
      &(),
      WatchOptions::new().with_interest(Interest::all()),
    ),
  )
  .await
  .expect(
    "the unwind returns without issuing a re-arm; a re-arm here would park on the wedged mount \
     forever, with the consumed reply undelivered and no close left to interrupt it",
  )
  .expect_err("the consumed close abandons the widen");

  let super::ReconcileStop::CloseRequested(close_reply) = stop else {
    panic!("the consumed close reply rides back out of the reconcile: {stop:?}");
  };
  // The zero-ARM ledger: three establishing arms, three disarms, and no arm after them. Scoped to what
  // [`Call`] records (arm/disarm/replace/cover) — the TOTAL "no `Source` call of any kind in this
  // window" claim is the seam cells' ([`SourceCall`]), because the retirement this exit runs reaches
  // `Source::end_sync` for a root with a pending barrier and no arm/disarm ledger can see that.
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Arm(PathBuf::from("/a/d")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Disarm(3),
    ],
    "not one source call after the reply was consumed — zero re-arms, for every remaining root"
  );
  assert_eq!(
    h.owner
      .source
      .calls()
      .iter()
      .skip(6)
      .filter(|call| matches!(call, Call::Arm(_)))
      .count(),
    0,
    "stated as the ledger claim it is: zero arms once the reply is held"
  );

  // The reply is the one that came in, and it is live: ack it as the run loop's teardown does.
  close_reply.send(Ok(())).expect("the close reply is live");
  assert!(
    matches!(response.await, Ok(Ok(()))),
    "the close() caller is answered, never left pending behind a wedged re-arm"
  );

  // All three roots retired, so nothing is left recorded-live-but-disarmed (I3) for the teardown.
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b"))
      && !view.is_watched(&key("/a/c"))
      && !view.is_watched(&key("/a/d")),
    "no subscription is left published-watched on a released handle"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sb)
      && h.owner.needs_rescan.contains_key(&sc)
      && h.owner.needs_rescan.contains_key(&sd),
    "each retirement still parked its durable dominating terminal Rescan"
  );
}

/// FIRST CLOSE WINS, across a widen unwind. `Tributaries::close` AWAITS its send on the one-slot
/// signal, so a second caller's reply lands the instant the first is consumed — mid-unwind. If the
/// unwind then issues a re-arm, that re-arm's own close race can consume the SECOND reply and hand it
/// back as the reconcile's verdict, where it is preferred over the error carrying the first: the
/// first caller's `close()` is left waiting on a reply that was silently dropped, while a caller who
/// arrived later is answered.
///
/// Staged with both callers real: `response` waits on the first, `late` on the second. The
/// assertion is about WHICH reply comes back — acking the returned one must satisfy the first caller
/// and only the first. The subsumed roots' arms are WEDGED, which is what makes the second reply
/// reachable at all under a reverted ordering: a re-arm issued while holding the first reply parks,
/// the queued sender lands its reply into the slot that re-arm just left empty, and the re-arm's own
/// close race consumes it.
///
/// FAIL-ON-REVERT: let the unwind re-arm while holding the first reply (thread it in as a posture
/// rather than treating it as terminal) and that re-arm parks on the wedge, takes the SECOND reply,
/// and returns it — the caller prefers it over the error carrying the first, so `response` resolves
/// `Err` (the first reply was dropped) and the `late` assertion inverts.
#[tokio::test(start_paused = true)]
async fn a_second_close_during_a_widen_unwind_never_displaces_the_first_reply() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2

  // A re-arm issued past the held reply would park here — the hung mount that gives the second close
  // its window, and that nothing is left to interrupt.
  h.owner.source.wedge_arm("/a/b");
  h.owner.source.wedge_arm("/a/c");

  // Caller ONE closes: its reply takes the signal's only slot.
  let (first, response) = futures_channel::oneshot::channel();
  h.closes.try_send(first).expect("the close signal accepts");
  // Caller TWO closes while the first is still queued: `Tributaries::close` awaits the send, so this
  // parks on the full slot and lands the moment the first reply is consumed.
  let (second, late) = futures_channel::oneshot::channel();
  let queueing = {
    let closes = h.closes.clone();
    tokio::spawn(async move { closes.send(second).await })
  };

  let stop = tokio::time::timeout(
    Duration::from_secs(30),
    h.owner.reconcile_watch(
      &key("/a"),
      &(),
      WatchOptions::new().with_interest(Interest::all()),
    ),
  )
  .await
  .expect("the unwind returns rather than parking on a wedged re-arm")
  .expect_err("the consumed close abandons the widen");
  let super::ReconcileStop::CloseRequested(close_reply) = stop else {
    panic!("a close reply rides back out of the reconcile: {stop:?}");
  };
  queueing
    .await
    .expect("the second closer task completes")
    .expect("…and its reply lands on the slot the first one freed");

  // The returned reply is the FIRST caller's: acking it answers that caller, and only that caller.
  close_reply
    .send(Ok(()))
    .expect("the returned reply is live");
  assert!(
    matches!(response.await, Ok(Ok(()))),
    "the FIRST close() to be consumed is the one satisfied — first close wins"
  );
  // The second reply was neither consumed nor dropped by the unwind: it is still on the signal, for
  // the teardown the returned reply drives to find.
  assert_eq!(
    h.owner.closes.len(),
    1,
    "the later close is left queued, not consumed in place of the first"
  );
  // And the unwind still did its own job: both roots retired with their durable dominating terminal
  // Rescans, so nothing is left recorded-live-but-disarmed (I3) for that teardown.
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b")) && !view.is_watched(&key("/a/c")),
    "no subscription is left published-watched on a released handle"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sb) && h.owner.needs_rescan.contains_key(&sc),
    "each retirement still parked its durable dominating terminal Rescan"
  );
  drop(view);
  // Dropping the owner is that teardown's last step. The queued reply's sender goes with the
  // receiver, which is what `Tributaries::close` maps to `CloseError::Stopped` — the documented
  // answer for "another racing close already won and tore the owner down".
  drop(h);
  assert!(
    late.await.is_err(),
    "the later caller learns the watcher stopped, rather than being answered ahead of the first"
  );
}

/// The pace's half of the same ordering claim: every handle going away is
/// discovered while root ONE paces, and the outer multi-root loop must not carry on to root two. It
/// used to — the condition was returned as an ordinary per-root failure, so the loop retired that
/// root and armed the next, with nothing left able to interrupt an arm against a stalled source.
///
/// Driven by hand-polling so the close is neither timing- nor task-ordering-dependent: poll once to
/// park inside the pace (the ledger's state is asserted there), close the signal, poll again. The
/// later roots' arms are WEDGED, so a loop that carries on cannot complete — the second poll would
/// return `Pending` rather than the verdict.
///
/// FAIL-ON-REVERT: return handles-gone as a per-root failure again (clear the budget and retire just
/// this root) and the second poll parks on `/a/c`'s wedged arm — `Pending`, with the `Arm(/a/c)` that
/// must not exist on the ledger.
#[tokio::test]
async fn handles_gone_at_a_pace_ends_the_restore_before_the_next_root_is_armed() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  let sd = h.watch("/a/d", Interest::all()).await.expect("watch /a/d"); // handle 3
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));
  h.owner.epochs.stamp(sd, Epoch::new(6));

  // The wider arm and root ONE's re-arm are refused on the retryable kind, and never clear: root one
  // reaches the pace, which is where the handles go away.
  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  // The roots AFTER it must never be armed at all, so arming one hangs instead of merely counting.
  h.owner.source.wedge_arm("/a/c");
  h.owner.source.wedge_arm("/a/d");

  let mut cx = Context::from_waker(Waker::noop());
  let widen = key("/a");
  let mut reconcile = Box::pin(h.owner.reconcile_watch(
    &widen,
    &(),
    WatchOptions::new().with_interest(Interest::all()),
  ));

  // Pass #1: the widen disarms all three roots, the wider arm is refused, and root one's re-arm is
  // refused too — so the restore parks in its pace, with the close signal still open and empty. It
  // cannot have parked anywhere later: every arm past root one's is wedged, and this pass ends.
  assert!(
    reconcile.as_mut().poll(&mut cx).is_pending(),
    "staging: the restore is parked in root one's retry pace"
  );

  // The last handle drops: the close signal closes in lockstep with the command mailbox the run loop
  // takes its teardown signal from. The pace's close arm reads it on the next poll.
  h.closes.close();

  let stop = match reconcile.as_mut().poll(&mut cx) {
    Poll::Ready(Err(stop)) => stop,
    Poll::Ready(Ok(sub)) => panic!("the refused widen cannot commit: {sub:?}"),
    Poll::Pending => panic!(
      "the restore armed a later root past the terminal condition and parked on its wedged mount — \
       nothing is left to interrupt it, and teardown never starts"
    ),
  };
  drop(reconcile);
  assert!(
    matches!(&stop, super::ReconcileStop::HandlesGone),
    "every handle gone is an ABANDON — no reply is invented for a caller that no longer exists — and \
     a no-ack TEARDOWN, never the ordinary failed watch the run loop keeps running past ({stop:?})"
  );
  // The zero-ARM ledger, read once the future is gone: root one's re-arm is the LAST arm. The close
  // landed between the two polls, so this also fixes when the later roots were not armed — never,
  // before or after it. Scoped to what [`Call`] records; the total claim over every `Source` method is
  // the seam cells' ([`SourceCall`]).
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Arm(PathBuf::from("/a/d")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Disarm(3),
      Call::Arm(PathBuf::from("/a")),
      Call::Arm(PathBuf::from("/a/b")),
    ],
    "zero arms once the handles are gone — the outer loop does not carry on to /a/c or /a/d"
  );

  // Terminal for the roots too: all three retired, so the teardown finds none recorded-live-but-
  // disarmed (I3), and each subscriber is owed its durable dominating terminal Rescan.
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b"))
      && !view.is_watched(&key("/a/c"))
      && !view.is_watched(&key("/a/d")),
    "no subscription is left published-watched on a released handle"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sb)
      && h.owner.needs_rescan.contains_key(&sc)
      && h.owner.needs_rescan.contains_key(&sd),
    "each retirement still parked its durable dominating terminal Rescan"
  );
}

/// The other condition a pace can report, and the one the per-root probe cannot cover for it: a close
/// REPLY consumed at root one's pace. From that instant the reconcile is holding a reply on a signal
/// that is now empty and still open — so the probe reads `Empty` and waves the next root's re-arm
/// through, and that re-arm has nothing left to preempt it and can consume a later caller's reply
/// over the held one. Which makes the pace's own reading terminal in its own right: it ends the
/// restore where it is taken.
///
/// Hand-polled for the same determinism as the handles-gone cell, and the roots after the first are
/// WEDGED so a loop that carries on cannot complete.
///
/// FAIL-ON-REVERT: turn the pace's consumed close back into a per-root verdict the outer loop carries
/// on from — the per-root probe does NOT save it, because a consumed reply leaves the signal empty
/// rather than closed — and the second poll parks on `/a/c`'s wedged arm, with the `Arm(/a/c)` that
/// must not exist on the ledger.
#[tokio::test]
async fn a_close_consumed_at_a_pace_ends_the_restore_before_the_next_root_is_armed() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // The wider arm and root ONE's re-arm are refused on the retryable kind and never clear, so root
  // one reaches the pace — where the close lands.
  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  // Root two must never be armed, so arming it hangs rather than merely showing up on the ledger.
  h.owner.source.wedge_arm("/a/c");

  let mut cx = Context::from_waker(Waker::noop());
  let widen = key("/a");
  let mut reconcile = Box::pin(h.owner.reconcile_watch(
    &widen,
    &(),
    WatchOptions::new().with_interest(Interest::all()),
  ));
  assert!(
    reconcile.as_mut().poll(&mut cx).is_pending(),
    "staging: the restore is parked in root one's retry pace"
  );

  // A close arrives mid-pace, exactly as `Tributaries::close` leaves one on the dedicated signal.
  let (reply, response) = futures_channel::oneshot::channel();
  h.closes.try_send(reply).expect("the close signal accepts");

  let stop = match reconcile.as_mut().poll(&mut cx) {
    Poll::Ready(Err(stop)) => stop,
    Poll::Ready(Ok(sub)) => panic!("the refused widen cannot commit: {sub:?}"),
    Poll::Pending => panic!(
      "the restore armed root two while holding the consumed reply and parked on its wedged mount — \
       the signal it would need to be rescued by is the one it just emptied"
    ),
  };
  drop(reconcile);
  let super::ReconcileStop::CloseRequested(close_reply) = stop else {
    panic!("the reply consumed at the pace rides back out of the reconcile: {stop:?}");
  };
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Arm(PathBuf::from("/a")),
      Call::Arm(PathBuf::from("/a/b")),
    ],
    "zero arms once the pace consumed a reply — root two is retired, not re-armed"
  );

  // The consumed reply is answered rather than dropped: `close()` completes.
  close_reply
    .send(Ok(()))
    .expect("the returned reply is live");
  assert!(
    matches!(response.await, Ok(Ok(()))),
    "the close() caller is answered, never left pending behind a widen's unwind"
  );
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b")) && !view.is_watched(&key("/a/c")),
    "no subscription is left published-watched on a released handle"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sb) && h.owner.needs_rescan.contains_key(&sc),
    "each retirement still parked its durable dominating terminal Rescan"
  );
}

/// The budget's expiry is a fallback to the OLD behaviour, never something softer: a capacity
/// refusal that outlives `RESTORE_RETRY_BUDGET` retires the root with its durable dominating
/// terminal `Rescan`, exactly as a fatal one does. The retry buys a bounded wait; it never
/// converts an unclearing refusal into a root that reads watched forever and delivers nothing.
///
/// One subsumed root, so the whole shared budget is spent on it. The clock is paused, so the
/// budget elapses as a fact of the cell rather than in real seconds.
///
/// FAIL-ON-REVERT: drop the deadline (retry while the refusal is `Capacity`, unconditionally) and
/// this cell never terminates — the refusal never clears. Revert the retry entirely and the
/// re-arm is attempted once, so the `>= 2` attempt assertion fails.
#[tokio::test(start_paused = true)]
async fn a_capacity_refusal_outliving_the_retry_budget_retires_the_root_as_it_always_did() {
  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  h.owner.epochs.stamp(sb, Epoch::new(4));

  // Neither the wider arm nor the re-arm will ever be admitted.
  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);

  let started = tokio::time::Instant::now();
  let result = h.watch("/a", Interest::all()).await;
  let elapsed = started.elapsed();
  assert!(result.is_err(), "the refused widen fails the watch");

  // The budget was spent — and only the budget.
  assert!(
    elapsed >= super::RESTORE_RETRY_BUDGET,
    "the retry ran until its deadline: {elapsed:?}"
  );
  let attempts = h
    .owner
    .source
    .calls()
    .iter()
    .filter(|call| **call == Call::Arm(PathBuf::from("/a/b")))
    .count()
    - 1; // the initial watch's own arm
  assert!(
    attempts >= 2,
    "the re-arm was retried, not concluded dead on its first refusal: {attempts}"
  );
  let ceiling = super::RESTORE_RETRY_BUDGET.div_duration_f64(super::RESTORE_RETRY_PACE) as usize;
  assert!(
    attempts <= ceiling + 2,
    "…and the retry is bounded by the budget, not by the source's patience: {attempts}"
  );

  // Then it retired exactly as a fatal refusal always did.
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/a/b")),
    "an unclearing refusal still ends in retirement — never a root that reads watched forever"
  );
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "the root left the view"
  );
  assert!(
    !h.owner.filters.contains_key(&sb),
    "the retired root's subscriber state is freed (I4)"
  );
  h.owner.flush_pending_rescans();
  let delivered = h.drain();
  assert_eq!(
    delivered.len(),
    1,
    "exactly one signal is owed: {delivered:?}"
  );
  assert!(delivered[0].is_rescan(), "…a Rescan");
  assert_eq!(delivered[0].subscription(), sb);
  assert_eq!(
    delivered[0].epoch(),
    Epoch::new(5),
    "the terminal Rescan strictly dominates sb's high-water of 4"
  );
}

/// WINDOW ONE of the restore's arm race: the last close sender disappears AFTER the per-root probe
/// read the signal empty. The probe is a snapshot — checking it earlier or more often cannot change
/// that — so what makes the ordering sound is that the ATTEMPT re-reads the signal in the same race
/// as the arm ([`Owner::rearm_racing_close`]), with the close arm polled first: a closure landing in
/// this window costs ZERO source calls.
///
/// Staged exactly as that sentence reads, against the attempt the restore's loop actually runs: the
/// real [`Owner::probe_close_signal`] answers `None` on an open, empty signal, the signal then closes,
/// and the real [`Owner::rearm_disarmed_root`] is asked for its first attempt. It is driven directly
/// rather than through a widen because the window has no suspension point end-to-end — nothing awaits
/// between the probe and the arm's own close poll, so no outer harness can place a closure there;
/// only the attempt can be handed the state the closure leaves behind.
///
/// The negative is asserted by LIVENESS, not by counting: the re-arm is WEDGED, so an attempt that
/// issues it cannot come back at all, and the deadline below fires. (A closed signal is precisely
/// the state in which nothing is left able to interrupt such an arm.)
///
/// FAIL-ON-REVERT: drop the close arm from [`Owner::rearm_racing_close`] and await `Source::arm`
/// bare — the signal is already closed, so nothing else re-reads it — and that arm parks on the
/// wedge forever: the timeout fires and the ledger shows the `Arm` that must not have been issued.
#[tokio::test(start_paused = true)]
async fn a_signal_that_closes_after_the_probe_ends_the_attempt_before_the_source_is_touched() {
  let mut h = Harness::new();

  // The re-arm this attempt would issue never returns — the hung mount an arm issued past a gone
  // signal hands itself, with nothing left able to interrupt it.
  h.owner.source.wedge_arm("/a/b");

  // The TOCTOU read, taken by the restore's own probe: the signal is open and empty, so the probe
  // waves the re-arm through…
  assert!(
    h.owner.probe_close_signal().is_none(),
    "staging: the probe reads the open, empty signal as non-terminal"
  );
  // …and only THEN does the last handle drop, closing the signal in lockstep with the command
  // mailbox the run loop takes its teardown signal from. Every check the probe could have made is
  // already behind us.
  h.closes.close();

  // A full budget, on the owner's own (paused) clock: the attempt is terminal before the deadline is
  // ever consulted, so nothing here rests on how much of it is left.
  let retry_until = tokio::time::Instant::now().into_std() + super::RESTORE_RETRY_BUDGET;
  let step = tokio::time::timeout(
    Duration::from_secs(30),
    h.owner.rearm_disarmed_root(&key("/a/b"), retry_until),
  )
  .await
  .expect(
    "the attempt reports the closed signal instead of arming; an arm issued here would park on the \
     wedged mount forever, with nothing left able to interrupt it",
  );

  assert!(
    matches!(
      step,
      super::RearmStep::Terminal(super::RestoreTerminal::HandlesGone)
    ),
    "every handle gone is TERMINAL for the whole restore, read off the attempt's own race"
  );
  // The zero-ARM ledger: not one arm, disarm, replace or cover request reached the source. (Nothing
  // else could have either — there is no barrier and no orphan here — but that is this cell's setup
  // rather than something [`Call`] testifies to; see the seam cells for the total claim.)
  assert!(
    h.owner.source.calls().is_empty(),
    "the closed signal is read BEFORE `Source::arm` is issued: {:?}",
    h.owner.source.calls()
  );
}

/// WINDOW TWO: the closure arrives after a retry's pace resolved on its TIMER rather than on its own
/// close arm — so the reading that let the retry proceed is behind us, and the next attempt is the
/// only thing left able to notice. Which it is, because [`Owner::rearm_disarmed_root`] has exactly one
/// arm site: EVERY attempt is raced, the first and each post-pace retry alike.
///
/// Hand-polled so the pace's timer win and the closure are ordered facts, not timing luck: poll to
/// park in root one's pace, let the pace elapse, poll again — which resolves the pace on the timer
/// (the signal is still open and empty) and issues the retried attempt — then close the signal and
/// poll once more.
///
/// The negative is asserted by LIVENESS: the retried arm and every later root's arm are WEDGED, so a
/// second arm cannot return a verdict at all and the final poll stays `Pending`. The wedge is
/// scripted by call count because it has to appear PARTWAY through this one reconcile, which holds
/// the owner borrowed for its whole life.
///
/// FAIL-ON-REVERT: race only the FIRST attempt and await the post-pace retries' `Source::arm` bare
/// and that retry parks on the wedge: the last poll parks, and the ledger carries the extra
/// `Arm(/a/b)` that must not exist.
#[tokio::test]
async fn a_closure_after_the_pace_timer_wins_ends_the_retried_attempt_without_re_issuing_it() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // The wider arm is refused on the retryable kind and never clears, so the widen unwinds into the
  // restore. Root one's FIRST re-arm is refused the same way, which is what sends it to a pace.
  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", 1);
  // From root one's SECOND re-arm on, its mount hangs: the refused first attempt is served, and the
  // POST-PACE retry — the attempt this cell is about — parks forever.
  h.owner.source.wedge_arms_after("/a/b", 1);
  // Root two must never be armed again either, so a loop that carries on cannot complete.
  h.owner.source.wedge_arm("/a/c");

  let mut cx = Context::from_waker(Waker::noop());
  let widen = key("/a");
  let mut reconcile = Box::pin(h.owner.reconcile_watch(
    &widen,
    &(),
    WatchOptions::new().with_interest(Interest::all()),
  ));

  // Pass #1: both roots are released, the wider arm is refused, and root one's first re-arm is
  // refused too — so the restore parks in its pace, with the signal still open and empty.
  assert!(
    reconcile.as_mut().poll(&mut cx).is_pending(),
    "staging: the restore is parked in root one's retry pace"
  );

  // Let the pace elapse, so the next poll resolves it on the TIMER rather than on its close arm.
  tokio::time::sleep(2 * super::RESTORE_RETRY_PACE).await;

  // Pass #2: the pace's close arm reads the open, empty signal and the timer wins, so the retried
  // attempt is issued — and parks on the mount that has just gone hung.
  assert!(
    reconcile.as_mut().poll(&mut cx).is_pending(),
    "staging: the pace elapsed and the retried re-arm is in flight"
  );

  // NOW the last handle drops — after the retry timer won, with the retried arm already pending.
  h.closes.close();

  let stop = match reconcile.as_mut().poll(&mut cx) {
    Poll::Ready(Err(stop)) => stop,
    Poll::Ready(Ok(sub)) => panic!("the refused widen cannot commit: {sub:?}"),
    Poll::Pending => panic!(
      "the retried attempt was not raced: its closed signal was answered by an arm onto the \
       wedged mount, and nothing is left able to interrupt it"
    ),
  };
  drop(reconcile);
  assert!(
    matches!(&stop, super::ReconcileStop::HandlesGone),
    "every handle gone is an ABANDON — no reply is invented for a caller that no longer exists — and \
     a no-ack TEARDOWN, never the ordinary failed watch the run loop keeps running past ({stop:?})"
  );
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Arm(PathBuf::from("/a")),
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/b")),
      // The retried attempt is the LAST call: nothing arms past its closed signal, and no /a/c.
    ],
    "the retried attempt reports the closed signal instead of re-issuing, and the outer loop does \
     not carry on to /a/c"
  );

  // Terminal for the roots too: both retired, so the teardown finds none recorded-live-but-disarmed
  // (I3), and each subscriber is owed its durable dominating terminal Rescan.
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b")) && !view.is_watched(&key("/a/c")),
    "no subscription is left published-watched on a released handle"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sb) && h.owner.needs_rescan.contains_key(&sc),
    "each retirement still parked its durable dominating terminal Rescan"
  );
}

/// WINDOW THREE, and the core case: the closure arrives while the raced re-arm is already PENDING.
/// An arm issued past that reading has NOTHING left able to interrupt it: a source stalled on a dead
/// mount pins the owner and its native resources for good, while the roots the widen already
/// released stay merely recorded-and-disarmed.
///
/// So the restore races the arm itself and maps the gone signal straight to a terminal, dropping the
/// pending arm. Hand-polled so the closure lands inside that pending arm as a fact of the cell: poll
/// to park in root one's re-arm, close the signal, poll again.
///
/// The negative is asserted by LIVENESS, not by counting: the re-arm is WEDGED, so an arm issued
/// past the closure cannot come back and the second poll stays `Pending` — an out-of-order check
/// cannot merely add a call here, the reconcile cannot return.
///
/// FAIL-ON-REVERT: drop the close arm from [`Owner::rearm_racing_close`] and await
/// `Source::arm` bare — or answer its gone signal by issuing the arm anyway — and the second poll
/// parks on `Arm(/a/b)`, with that arm on the ledger and the reconcile never returning to the loop.
#[tokio::test]
async fn a_closure_while_the_raced_re_arm_is_pending_ends_the_restore_rather_than_re_issuing_it() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // The wider arm is refused on the retryable kind, so the widen unwinds into the restore…
  h.owner.source.refuse_capacity("/a", u32::MAX);
  // …where every re-arm hangs: root one's is what the closure lands inside, and root two's is what a
  // loop carrying on past the terminal would park on. Set AFTER the watches above, which needed those
  // same arms to succeed.
  h.owner.source.wedge_arm("/a/b");
  h.owner.source.wedge_arm("/a/c");

  let mut cx = Context::from_waker(Waker::noop());
  let widen = key("/a");
  let mut reconcile = Box::pin(h.owner.reconcile_watch(
    &widen,
    &(),
    WatchOptions::new().with_interest(Interest::all()),
  ));

  // Pass #1: both roots released, the wider arm refused, and root one's re-arm issued and parked. The
  // close signal was open and empty at the race's first poll — the arm is legitimately in flight.
  assert!(
    reconcile.as_mut().poll(&mut cx).is_pending(),
    "staging: root one's raced re-arm is pending on its wedged mount"
  );

  // The last handle drops WHILE that arm is pending: the close arm of the race that issued it is
  // what reads the signal next.
  h.closes.close();

  let stop = match reconcile.as_mut().poll(&mut cx) {
    Poll::Ready(Err(stop)) => stop,
    Poll::Ready(Ok(sub)) => panic!("the refused widen cannot commit: {sub:?}"),
    Poll::Pending => panic!(
      "the pending re-arm's closed signal was answered by a second arm: it parked on the \
       wedged mount, the reconcile never returns to the loop, and teardown never starts"
    ),
  };
  drop(reconcile);
  assert!(
    matches!(&stop, super::ReconcileStop::HandlesGone),
    "every handle gone is an ABANDON — no reply is invented for a caller that no longer exists — and \
     a no-ack TEARDOWN, never the ordinary failed watch the run loop keeps running past ({stop:?})"
  );
  // The ledger fixes both halves: root one's re-arm was issued exactly ONCE — the pending future is
  // dropped, never re-issued — and root two's was never issued at all.
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Arm(PathBuf::from("/a")),
      Call::Arm(PathBuf::from("/a/b")),
    ],
    "one re-arm, raced and abandoned — not a second one issued past the closure, and nothing for \
     /a/c"
  );

  // Terminal for the roots too: both retired, so the teardown finds none recorded-live-but-disarmed
  // (I3), and each subscriber is owed its durable dominating terminal Rescan.
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b")) && !view.is_watched(&key("/a/c")),
    "no subscription is left published-watched on a released handle"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sb) && h.owner.needs_rescan.contains_key(&sc),
    "each retirement still parked its durable dominating terminal Rescan"
  );
}

/// The OUTCOME rather than the ordering, and the layer above all three windows above. Those make the
/// cancellation correct; this is about what the cancellation is then REPORTED as. Reported as an
/// ordinary failed watch, [`Owner::on_watch`] answers the caller and
/// [`Owner::dispatch_command`] returns [`super::Flow::Continue`] — so the [`run`] loop keeps running
/// with a cancelled [`Source::arm`] behind it, and its own dropped-handles arm cannot stop that: that
/// arm fires only once the mailbox is closed AND DRAINED, so every command still buffered in it is
/// dispatched first, each free to call the source again before the source is dropped — the one
/// boundary at which the contract's cancellation clause reclaims what the abandoned arm may have
/// started.
///
/// So the gone signal is a no-ack TEARDOWN ([`super::Teardown::HandlesGone`]), and this cell reads it
/// exactly where the loop decides: the [`super::Flow`] `dispatch_command` returns. `Break` with NO
/// `closing` — the signal that closed is the one every `close()` caller rides, so there is nothing to
/// acknowledge and nothing may be invented — and no source-drain debt (nothing drained).
///
/// Hand-polled so the closure is an ordered fact rather than timing luck: poll to park in root one's
/// retry pace, close the signal, poll again. Root two's re-arm is WEDGED, so the negative holds by
/// LIVENESS as well as by the ledger — a restore that carried on could not return a `Flow` at all,
/// and a mis-ordered check cannot merely add a call.
///
/// FAIL-ON-REVERT: map the terminal back to `WatchError::Closed` (`Failed`, an ordinary failed watch)
/// and this returns `Flow::Continue` — the loop keeps going past the cancelled arm. Invent an
/// acknowledgement for it (`closing: Some(_)`) and the same match fails: no reply exists to answer.
#[tokio::test]
async fn handles_gone_during_a_restore_breaks_the_owner_loop_with_no_acknowledgement() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // The wider arm and root ONE's re-arm are refused on the retryable kind and never clear, so the
  // restore reaches root one's pace — where the handles go away.
  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  // Root two must never be armed, so a restore that carries on cannot come back at all.
  h.owner.source.wedge_arm("/a/c");

  // The widen, dispatched the way the run loop dispatches one: through `dispatch_command`, whose
  // `Flow` IS the loop's decision to keep going or stop.
  let (reply, response) = futures_channel::oneshot::channel();
  let mut cx = Context::from_waker(Waker::noop());
  let mut dispatch = Box::pin(h.owner.dispatch_command(Ok(super::Command::Watch {
    key: key("/a"),
    value: (),
    options: WatchOptions::new().with_interest(Interest::all()),
    reply,
  })));

  // Pass #1: the widen releases both roots, the wider arm is refused, and root one's re-arm is
  // refused too — so the restore parks in its pace, with the close signal still open and empty.
  assert!(
    dispatch.as_mut().poll(&mut cx).is_pending(),
    "staging: the restore is parked in root one's retry pace"
  );

  // The last handle drops: the close signal closes in lockstep with the command mailbox.
  h.closes.close();

  let flow = match dispatch.as_mut().poll(&mut cx) {
    Poll::Ready(flow) => flow,
    Poll::Pending => panic!(
      "the restore armed root two past the terminal condition and parked on its wedged mount — \
       nothing is left to interrupt it, and the loop never gets its verdict"
    ),
  };
  drop(dispatch);
  match flow {
    super::Flow::Break {
      closing: None,
      drain_owed: false,
    } => {}
    super::Flow::Break {
      closing: Some(_), ..
    } => panic!(
      "an acknowledgement was invented: the signal that closed is the one a `close()` caller would \
       have ridden, so no reply can exist to answer"
    ),
    super::Flow::Break {
      drain_owed: true, ..
    } => panic!("a consumer-side teardown owes no source-drain pass"),
    super::Flow::Continue => panic!(
      "the loop was told to keep running past a cancelled arm: whatever is still buffered in the \
       closed mailbox gets dispatched, and may call the source again before it is dropped"
    ),
  }

  // The zero-ARM ledger, read once the future is gone: root one's re-arm is the LAST arm, so no arm ran
  // between the cancelled one and this verdict. Scoped to what [`Call`] records; that no `Source` call
  // of ANY kind runs between the cancelled arm and the teardown seam is the seam cells' claim
  // ([`SourceCall`]), which the retirement's cookie reap would otherwise slip past this ledger.
  assert_eq!(
    h.owner.source.calls(),
    vec![
      Call::Arm(PathBuf::from("/a/b")),
      Call::Arm(PathBuf::from("/a/c")),
      Call::Disarm(1),
      Call::Disarm(2),
      Call::Arm(PathBuf::from("/a")),
      Call::Arm(PathBuf::from("/a/b")),
    ],
    "zero source calls once the handles are gone"
  );
  // Nothing is invented for the `watch()` caller either: its reply is DROPPED, which is what
  // `watch()` reads as `Closed` — and no such caller can even be left, since a pending `watch()`
  // borrows the handle whose loss this outcome IS.
  assert!(
    response.await.is_err(),
    "the abandoned watch's reply is dropped, never answered over a teardown"
  );

  // Terminal for the roots too: both retired, so the teardown finds none recorded-live-but-disarmed
  // (I3), and each subscriber is owed its durable dominating terminal Rescan.
  let view = h.owner.subsumer.view();
  assert!(
    !view.is_watched(&key("/a/b")) && !view.is_watched(&key("/a/c")),
    "no subscription is left published-watched on a released handle"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sb) && h.owner.needs_rescan.contains_key(&sc),
    "each retirement still parked its durable dominating terminal Rescan"
  );
}

/// The buffered command specifically, driven through the REAL [`run`] loop — the one place the
/// difference between `Flow::Continue` and `Flow::Break` is observable as behaviour rather than as a
/// value. A `Watch` admitted while handles still existed sits in the mailbox behind the widen;
/// `async_channel` hands a closed-but-nonempty mailbox its buffered items before it ever reports the
/// channel gone, so a loop that merely kept going would dispatch that `Watch` and arm the source with
/// the restore's cancelled arm still unreclaimed — for a caller who is provably gone (a pending
/// `watch()` borrows the handle it sent on).
///
/// The negative is asserted by LIVENESS: the buffered watch's own arm is WEDGED, so dispatching it
/// cannot merely add a ledger entry — the loop can never return, and teardown never runs. This cell
/// therefore fails by hanging on the poll, which no later refactor can explain away as a counting
/// artifact.
///
/// Hand-polled so both facts are ordered: poll to park in the restore's pace with the second command
/// already queued, then drop every handle (close signal closed, mailbox closed WITH the command still
/// in it) and poll again.
///
/// FAIL-ON-REVERT: report the gone signal as an ordinary failed watch and the second poll parks
/// forever on `Arm(/z)` — the command that must never reach the source.
#[tokio::test]
async fn a_command_buffered_when_the_handles_dropped_never_reaches_the_source() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  h.owner.epochs.stamp(sb, Epoch::new(4));

  // The wider arm and the re-arm are refused on the retryable kind and never clear, so the widen
  // unwinds into a restore that reaches its pace — where the handles go away.
  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  // The BUFFERED command's own arm hangs, so a loop that dispatches it cannot come back.
  h.owner.source.wedge_arm("/z");

  let Harness {
    owner,
    events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  // Two commands, the widen FIRST: the loop dispatches it and must never reach the second, which was
  // admitted (and buffered) while handles still existed.
  let (widen_reply, widen_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: widen_reply,
    })
    .expect("enqueue the widen");
  let (buffered_reply, buffered_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/z"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: buffered_reply,
    })
    .expect("enqueue the command behind it");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));

  // Pass #1: the loop selects the widen — the command arm outranks the source arm, which matters
  // here because [`FakeSource::next`] answers `None` at once and would otherwise break the loop to a
  // source drain — and it releases `/a/b`, is refused the wider arm, and parks in the restore's pace,
  // with the `/z` watch still in the mailbox.
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked in the restore's retry pace"
  );

  // Every handle drops: the close signal closes, and the command mailbox closes WITH THE `/z` WATCH
  // STILL IN IT — the state in which a continuing loop reaches that command rather than the
  // dropped-handles `Err` this teardown otherwise shares.
  closes.close();
  drop(commands);

  match run.as_mut().poll(&mut cx) {
    Poll::Ready(()) => {}
    Poll::Pending => panic!(
      "the loop kept running past the cancelled re-arm and dispatched the buffered `/z` watch: its \
       arm has nothing left able to interrupt it, so the owner is pinned and teardown never runs"
    ),
  }

  // Never dispatched, so never answered: the caller — already gone, every handle is — reads the
  // dropped reply as `Closed`, exactly as it reads the abandoned widen's.
  assert!(
    buffered_response.await.is_err(),
    "the buffered watch is answered by nobody, because it was served by nobody"
  );
  assert!(
    widen_response.await.is_err(),
    "the abandoned widen's reply is dropped rather than answered over a teardown"
  );

  // The teardown the break reached still paid what the retirement owed: the subsumed root's durable
  // dominating terminal `Rescan` is on the stream before the owner is gone.
  let mut delivered = Vec::new();
  while let Ok(event) = events.try_recv() {
    delivered.push(event);
  }
  assert_eq!(
    delivered.len(),
    1,
    "exactly one signal is owed: {delivered:?}"
  );
  assert!(delivered[0].is_rescan(), "…a Rescan");
  assert_eq!(delivered[0].subscription(), sb);
  assert_eq!(
    delivered[0].epoch(),
    Epoch::new(5),
    "the terminal Rescan strictly dominates sb's high-water of 4"
  );
}

/// The seam ordering itself, for the exact case the code's own documentation got wrong:
/// **a retired root carrying a pending sync**. The failed-widen unwind was documented as
/// owner-local — "no [`Source`] call is issued for any root between the reconcile's cancelled source
/// future and the source's own teardown seam" — and the call graph says otherwise:
///
/// ```text
/// begin_close_then_retire_disarmed_roots
///   → retire_root_with_terminal_rescan → rescan_live_root
///     → dominate_syncs_of_root → reap_cookie → Source::end_sync
/// ```
///
/// So a terminal outcome retired a root whose barrier was still pending, that retirement reaped its
/// cookie, and the reap reached the source with an abandoned [`Source::arm`] still unreclaimed — the
/// one call whose cancellation nothing short of the source's own teardown can reclaim. Two more of
/// the same shape follow it in [`run`]'s tail (`reap_all_pending_syncs`, and grant cleanup's
/// [`disarm`](Source::disarm)/[`set_cover`](Source::set_cover) — the next cell).
///
/// The fix is not to make that chain source-free — it is the shared no-silent-loss primitive and it
/// is not going to become owner-local — but to move the SEAM ahead of it. So the claim this cell
/// pins is an ORDER, and it reads it off the TOTAL [`SourceCall`] ledger: every `Source` method the
/// fake implements, the read probes included, in sequence, for the source's whole life. `BeginClose`
/// sits between the cancelled re-arm and the cookie reap, and `JoinClose` — the bounded wait — still
/// comes last.
///
/// Driven through the REAL [`run`] loop rather than `dispatch_command`, because the tail is half of
/// the window and only the loop reaches it. Hand-polled so the closure is an ordered fact rather than
/// timing luck: poll to park in root one's retry pace, drop every handle, poll again. Root two's
/// re-arm is WEDGED, so a restore that carried on could not return at all.
///
/// FAIL-ON-REVERT: put the seam back at the end of the tail (`owner.source.begin_close()` after
/// `swap_in_empty`, with the terminal unwind entering nothing) and the ledger reads
/// `… Arm(/a/b), EndSync(…), BeginClose, JoinClose` — the reap ahead of the seam, which is the
/// defect itself.
#[tokio::test]
async fn a_retired_root_with_a_pending_sync_reaps_its_cookie_only_past_the_seam() {
  use crate::source::SyncOutcome;
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // The barrier that makes the retirement reach the source: a cookie riding root ONE, whose caller is
  // still waiting (the receiver is HELD, so the loop-top `prune_abandoned_syncs` leaves it alone —
  // an abandoned barrier would reap early and the window would never be tested).
  let root_b = h
    .owner
    .subsumer
    .subscription_root(sb)
    .expect("live root for /a/b");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/b/cookie-1"),
    sub: sb,
    root: root_b,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The wider arm and root ONE's re-arm are refused on the retryable kind and never clear, so the
  // restore reaches root one's pace — where the handles go away.
  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  // Root two must never be armed, so a restore that carries on cannot come back.
  h.owner.source.wedge_arm("/a/c");
  // Taken BEFORE the owner is moved into `run`: the seam is the last thing that happens, so the
  // ledger has to outlive the source it records.
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (widen_reply, widen_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: widen_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));

  // Pass #1: the loop selects the widen (the command arm outranks the source arm, which matters here
  // because [`FakeSource::next`] answers `None` at once and would otherwise break the loop to a source
  // drain), releases both roots, is refused the wider arm, and parks in the restore's pace.
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked in the restore's retry pace"
  );

  // Every handle drops: the close signal closes in lockstep with the command mailbox.
  closes.close();
  drop(commands);

  match run.as_mut().poll(&mut cx) {
    Poll::Ready(()) => {}
    Poll::Pending => panic!(
      "the restore armed root two past the terminal condition and parked on its wedged mount — \
       nothing is left to interrupt it, and teardown never runs"
    ),
  }

  // THE ORDER. Total, in sequence, for the whole life of the source:
  //
  //   the two establishing watches (canonicalize, arm, the choke point's liveness probe each),
  //   the widen's canonicalize, its two releases, its refused wider arm, root one's refused re-arm,
  //   → THE SEAM ←
  //   the retired root's cookie reap, then the bounded quiescence wait.
  //
  // Root two contributes no reap (no barrier rode it) and no re-arm (the terminal preceded it).
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/a/c")),
      SourceCall::Arm(PathBuf::from("/a/c")),
      SourceCall::RootKey(2),
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Disarm(1),
      SourceCall::Disarm(2),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/b/cookie-1")),
      SourceCall::JoinClose,
    ],
    "the retirement's cookie reap must land PAST the seam, not between the cancelled re-arm and it"
  );
  // The redundancy that survives a future cell asserting only a prefix.
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once, however many callers could have entered it"
  );

  // Nothing about the unwind's own obligations is traded away for the ordering: the barrier resolves
  // `Dominated` (its cookie can no longer prove anything, and the terminal `Rescan` dominates it), and
  // the abandoned watch's reply is dropped rather than answered over a teardown.
  assert!(
    matches!(
      sync_response.await.expect("the barrier is answered"),
      Ok(SyncOutcome::Dominated)
    ),
    "a barrier on a retired root is met by re-enumeration"
  );
  assert!(
    widen_response.await.is_err(),
    "the abandoned widen's reply is dropped, never answered over a teardown"
  );

  // And each subscriber still got its durable dominating terminal `Rescan` before the stream ended.
  let mut delivered = Vec::new();
  while let Ok(event) = events.try_recv() {
    delivered.push(event);
  }
  assert_eq!(delivered.len(), 2, "one per subsumed root: {delivered:?}");
  assert!(
    delivered.iter().all(super::Event::is_rescan),
    "both are Rescans: {delivered:?}"
  );
}

/// The seam ordering for the OTHER two reachabilities in the same window, both in [`run`]'s teardown
/// tail rather than in the reconcile: the remaining cookies reaped at teardown
/// (`reap_all_pending_syncs` → [`Source::end_sync`]) and QUEUED GRANT CLEANUP, whose orphan release
/// reaches [`Source::disarm`] when it empties a root and [`Source::set_cover`] when it merely narrows
/// one. Traced:
///
/// ```text
/// drain_pending_cleanup → apply_cleanup → release_subscription → Source::disarm / Source::set_cover
///                                                             → retire_syncs_of_subscription
///                                                               → reap_cookie → Source::end_sync
/// ```
///
/// Both ran before the old end-of-tail seam, so a terminal reconcile's cancelled [`Source::arm`] was
/// followed by a release and a prune with nothing yet told to wind down. Moving the seam to the TOP of
/// the tail is what puts them past it, and this cell reads that off the same total ledger.
///
/// Two orphans, because the release has two source-touching outcomes and one cell should pin both: the
/// sole subscriber of `/x` (its departure EMPTIES the root → `Disarm`) and the root-key subscriber of
/// `/y`, which keeps a narrower sibling (its departure leaves the root OVER-BROAD → `SetCover`).
/// Neither root is part of the widen, so the widen's unwind cannot be what releases them.
///
/// FAIL-ON-REVERT: leave the seam at the end of the tail and the ledger reads
/// `… Arm(/a/b), EndSync(…), Disarm(3), SetCover(4), BeginClose, JoinClose` — all three source calls
/// ahead of the seam.
#[tokio::test]
async fn queued_orphan_cleanup_touches_the_source_only_past_the_seam() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  // The widen's two roots.
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));
  // An unrelated root with ONE subscriber: releasing it empties the root.
  let sx = h.watch("/x", Interest::all()).await.expect("watch /x"); // handle 3
  // An unrelated root whose ROOT-KEY subscriber departs while a narrower one stays: the root survives
  // over-broad, so the release prunes coverage in place instead of releasing it.
  let sy = h.watch("/y", Interest::all()).await.expect("watch /y"); // handle 4
  h.watch("/y/n", Interest::all())
    .await
    .expect("watch /y/n under it");

  // A barrier still riding `/x`'s root, whose caller is HELD so the loop-top prune leaves it alone:
  // this is the cookie the teardown's own reap has to handle, and it must handle it past the seam.
  let root_x = h
    .owner
    .subsumer
    .subscription_root(sx)
    .expect("live root for /x");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/x/cookie-7"),
    sub: sx,
    root: root_x,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // A sender on the grant-resolution channel that OUTLIVES the destructuring, so both orphans can be
  // queued MID-UNWIND — after the loop's last top-of-iteration `drain_pending_cleanup` and before the
  // terminal. Queued any earlier they are drained by that loop-top pass, long before the widen is even
  // selected, and the window this cell exists for is never entered.
  let grants = h.owner.cleanup_tx.clone();

  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  h.owner.source.wedge_arm("/a/c");
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (widen_reply, widen_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: widen_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));

  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked in the restore's retry pace"
  );

  // Both grants resolve as ORPHANS while the unwind is parked: the loop is inside the reconcile, so
  // nothing drains them until the teardown tail — which is exactly where the release must land past the
  // seam. (`async_channel` keeps messages queued before a `close` receivable, so the tail's atomic claim
  // cut does not discard these.)
  grants
    .try_send(super::Cleanup::DropOrphan(sx))
    .expect("queue the emptying orphan");
  grants
    .try_send(super::Cleanup::DropOrphan(sy))
    .expect("queue the narrowing orphan");

  closes.close();
  drop(commands);

  match run.as_mut().poll(&mut cx) {
    Poll::Ready(()) => {}
    Poll::Pending => panic!(
      "the restore armed root two past the terminal condition and parked on its wedged mount"
    ),
  }

  let calls = seam.calls();
  let seam_at = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .expect("the seam was entered");
  // The whole point, stated as an exact sequence rather than a count: everything the teardown asks of
  // the source comes AFTER the seam entry, in the tail's own order — the remaining cookie first
  // (`reap_all_pending_syncs`), then the two orphan releases in the order they were queued, then the
  // bounded wait.
  assert_eq!(
    &calls[seam_at..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/x/cookie-7")),
      SourceCall::Disarm(3),
      SourceCall::SetCover(4),
      SourceCall::JoinClose,
    ],
    "every teardown request must land past the seam, in the tail's order"
  );
  // And the other half of the claim: nothing of that kind happened BEFORE it. The prefix is the
  // establishing traffic and the widen's own unwind, and not one `EndSync`, `Disarm(3)` or `SetCover`
  // appears in it.
  assert_eq!(
    &calls[..seam_at],
    &[
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/a/c")),
      SourceCall::Arm(PathBuf::from("/a/c")),
      SourceCall::RootKey(2),
      SourceCall::CanonicalizeKey(key("/x")),
      SourceCall::Arm(PathBuf::from("/x")),
      SourceCall::RootKey(3),
      SourceCall::CanonicalizeKey(key("/y")),
      SourceCall::Arm(PathBuf::from("/y")),
      SourceCall::RootKey(4),
      SourceCall::CanonicalizeKey(key("/y/n")),
      SourceCall::RootKey(4),
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Disarm(1),
      SourceCall::Disarm(2),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::Arm(PathBuf::from("/a/b")),
    ],
    "nothing was asked of the source between the cancelled re-arm and the seam"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once, however many callers could have entered it"
  );

  // The orphan releases still did their owner-local work, and the held barrier still resolved: the
  // reordering buys the invariant without dropping an obligation. `/x`'s barrier is answered
  // `Closed` — its caller's reply is dropped by the teardown reap, which is what a dropped sender
  // reads as.
  assert!(
    sync_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
  assert!(
    widen_response.await.is_err(),
    "the abandoned widen's reply is dropped rather than answered over a teardown"
  );
}

/// [`Source::begin_close`] is contracted as a once-per-source initiation, and moving it EARLIER
/// created a second caller: the terminal reconcile enters it, and [`run`]'s tail enters it too. This
/// cell is the double-entry check, over every teardown shape the loop has — the two that pass through a
/// reconcile terminal (where BOTH callers exist) and the three that do not (where only the tail's entry
/// can produce it at all).
///
/// Both halves matter and they fail differently. A missing latch double-enters the seam on the widen
/// paths; a latch that swallows the tail's entry leaves an ORDINARY close never telling its source to
/// wind down at all — the regression a cell that only looked at the widen would miss.
///
/// FAIL-ON-REVERT: drop the `source_closing` latch (call `self.source.begin_close()` directly) and the
/// two widen shapes report 2. Delete the tail's `owner.begin_source_close()` and the three plain shapes
/// report 0.
#[tokio::test]
async fn the_teardown_seam_is_entered_exactly_once_on_every_terminal_path() {
  use std::task::{Context, Poll, Waker};

  // SHAPE 1 — a mid-reconcile terminal with every handle gone: the unwind enters the seam, and the
  // tail then runs over an owner that has already entered it.
  {
    let mut h = Harness::new();
    let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
    h.owner.epochs.stamp(sb, Epoch::new(4));
    h.owner.source.refuse_capacity("/a", u32::MAX);
    h.owner.source.refuse_capacity("/a/b", u32::MAX);
    let seam = h.owner.source.seam();
    let Harness {
      owner,
      events: _events,
      _commands: commands,
      _sync_commands,
      closes,
    } = h;
    let (reply, _response) = futures_channel::oneshot::channel();
    commands
      .try_send(super::Command::Watch {
        key: key("/a"),
        value: (),
        options: WatchOptions::new().with_interest(Interest::all()),
        reply,
      })
      .expect("enqueue the widen");
    let mut cx = Context::from_waker(Waker::noop());
    let mut run = Box::pin(super::run(owner));
    assert!(run.as_mut().poll(&mut cx).is_pending(), "staging: the pace");
    closes.close();
    drop(commands);
    assert!(
      matches!(run.as_mut().poll(&mut cx), Poll::Ready(())),
      "the handles-gone terminal breaks the loop"
    );
    assert_eq!(
      seam.begin_closes(),
      1,
      "handles gone mid-restore: the unwind's entry and the tail's must collapse to one"
    );
  }

  // SHAPE 2 — a mid-reconcile terminal with a CONSUMED close reply: same two callers, plus an
  // acknowledgement that must still carry the source's quiescence verdict.
  {
    let mut h = Harness::new();
    let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
    h.owner.epochs.stamp(sb, Epoch::new(4));
    h.owner.source.refuse_capacity("/a", u32::MAX);
    h.owner.source.refuse_capacity("/a/b", u32::MAX);
    let seam = h.owner.source.seam();
    let Harness {
      owner,
      events: _events,
      _commands: commands,
      _sync_commands,
      closes,
    } = h;
    let (reply, _response) = futures_channel::oneshot::channel();
    commands
      .try_send(super::Command::Watch {
        key: key("/a"),
        value: (),
        options: WatchOptions::new().with_interest(Interest::all()),
        reply,
      })
      .expect("enqueue the widen");
    let mut cx = Context::from_waker(Waker::noop());
    let mut run = Box::pin(super::run(owner));
    assert!(run.as_mut().poll(&mut cx).is_pending(), "staging: the pace");
    let (close_reply, close_response) = futures_channel::oneshot::channel();
    closes.try_send(close_reply).expect("request the close");
    assert!(
      matches!(run.as_mut().poll(&mut cx), Poll::Ready(())),
      "the consumed reply breaks the loop"
    );
    assert_eq!(
      seam.begin_closes(),
      1,
      "a close consumed mid-restore: the unwind's entry and the tail's must collapse to one"
    );
    assert!(
      matches!(close_response.await, Ok(Ok(()))),
      "the threaded reply still carries the source's quiescence verdict"
    );
  }

  // SHAPE 3 — an ordinary close command, no widen anywhere: the tail is the ONLY caller, so this is
  // where a latch that suppressed it would show up.
  {
    let mut h = Harness::new();
    let _sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
    let seam = h.owner.source.seam();
    let Harness {
      owner,
      events: _events,
      _commands: commands,
      _sync_commands,
      closes,
    } = h;
    let (close_reply, close_response) = futures_channel::oneshot::channel();
    closes.try_send(close_reply).expect("request the close");
    super::run(owner).await;
    drop(commands);
    assert_eq!(
      seam.begin_closes(),
      1,
      "an ordinary close must still tell its source to wind down"
    );
    assert!(
      matches!(close_response.await, Ok(Ok(()))),
      "and still carry the verdict back"
    );
  }

  // SHAPE 4 — every handle dropped with no close request and no widen: the mailbox's own `Err` arm.
  {
    let mut h = Harness::new();
    let _sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
    let seam = h.owner.source.seam();
    let Harness {
      owner,
      events: _events,
      _commands: commands,
      _sync_commands,
      closes,
    } = h;
    closes.close();
    drop(commands);
    super::run(owner).await;
    assert_eq!(
      seam.begin_closes(),
      1,
      "dropped handles must still tell the source to wind down"
    );
  }

  // SHAPE 5 — a SOURCE DRAIN with a consumer still attached: the one teardown that runs the owed-Rescan
  // drain first, so the seam is entered ahead of a pass that itself drains grant cleanup.
  {
    let mut h = Harness::new();
    let _sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
    let seam = h.owner.source.seam();
    let Harness {
      owner,
      events,
      _commands: commands,
      _sync_commands,
      closes,
    } = h;
    // The fake's `next` answers `None` as soon as its scripted stream is empty, which IS the drain.
    super::run(owner).await;
    assert_eq!(
      seam.begin_closes(),
      1,
      "a source drain must still tell the source to wind down, exactly once"
    );
    // What this shape pins is the COUNT above plus the seam's two ends: nothing is owed here, so the
    // drain issues no request of its own and there is no ordering left to observe — the drain path's
    // ordering is the tail's first statement, and the previous cell is what reads it. The bounded wait
    // still comes last, which is the half a reordering of the tail would break here too.
    let calls = seam.calls();
    assert_eq!(
      calls.last(),
      Some(&SourceCall::JoinClose),
      "the bounded wait is still last: {calls:?}"
    );
    assert!(
      calls
        .iter()
        .filter(|call| **call == SourceCall::BeginClose)
        .count()
        == 1,
      "and the seam appears once in the sequence too: {calls:?}"
    );
    drop((commands, closes, events));
  }
}

/// The INITIAL retarget: an in-place widen that reads EVERY HANDLE GONE off its
/// retarget race is a TERMINAL outcome, not an ordinary failed watch. It breaks the [`run`] loop, and
/// the teardown seam is then the next `Source` interaction there is.
///
/// It used to `return Err(WatchError::Closed.into())` — a [`ReconcileStop::Failed`], so `on_watch`
/// answered the caller and `dispatch_command` returned [`Flow::Continue`] and the loop ran ON: pruning
/// abandoned barriers (→ [`Source::end_sync`]) and dispatching whatever was still BUFFERED behind the
/// widen in the closed mailbox (→ [`Source::arm`]), every one of them AHEAD of the seam and every one
/// of them while the abandoned retarget may still commit. [`Source::replace`] is not cancel-abortive:
/// dropping the future abandons only the notification, never the swap.
///
/// The handles are retired WHILE THE RETARGET IS IN FLIGHT — the fake closes the close signal from
/// inside `replace` and then never answers — because that is the case with an unreclaimable effect in
/// it: the race's close arm reads the signal gone on the next poll and drops a `replace` the owner had
/// already polled. A signal closed BEFORE the race began reaches the same arm having never issued the
/// retarget at all, and the arm cannot tell the two apart, so pinning the one with the live effect
/// pins both.
///
/// The buffered second watch is the LIVENESS half, per the seam cells above: its `arm` is WEDGED, so a
/// loop that kept going cannot merely add a ledger entry — it parks forever on a mount that never
/// answers, with nothing left able to preempt it, and the teardown never runs at all.
///
/// FAIL-ON-REVERT: put `return Err(WatchError::Closed.into())` back in the retarget's `HandlesGone`
/// arm and the second poll is `Pending` — the loop dispatched the wedged watch and the run future
/// never completes.
#[tokio::test]
async fn an_in_place_retarget_losing_every_handle_breaks_the_loop_at_the_seam() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  h.owner.source.supports_replace = true;

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  h.owner.epochs.stamp(sb, Epoch::new(4));

  // A barrier riding root one whose caller is still WAITING (the receiver is held, so the loop-top
  // `prune_abandoned_syncs` leaves it alone). It is the teardown's own reap, and where it lands
  // relative to the seam is half of what this cell reads.
  let root_b = h
    .owner
    .subsumer
    .subscription_root(sb)
    .expect("live root for /a/b");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/b/cookie-1"),
    sub: sb,
    root: root_b,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The watch buffered BEHIND the widen: a loop that keeps going dispatches it, and its arm never
  // answers. Nothing preempts it — the close signal is already gone — so a mis-ordering is a run
  // future that cannot complete, not one extra ledger entry.
  h.owner.source.wedge_arm("/w");
  // Every handle retired while the widen's retarget is in flight.
  h.owner
    .source
    .close_signal_during_replace(1, h.closes.clone());
  // Taken BEFORE the owner is moved into `run`: the seam is the last thing that happens.
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (widen_reply, widen_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: widen_reply,
    })
    .expect("enqueue the widen");
  let (wedged_reply, wedged_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/w"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: wedged_reply,
    })
    .expect("enqueue the watch buffered behind it");
  // The public senders drop in lockstep with the close signal the fake is about to close; both
  // commands are already queued, and `async_channel` keeps a queued message receivable.
  drop(commands);

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));

  // Pass #1: the loop selects the widen (the command arm outranks the source arm, which matters
  // because [`FakeSource::next`] answers `None` at once and would otherwise break the loop to a source
  // drain), plans the in-place retarget, and parks inside `replace` — which closed the close signal on
  // its way in.
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked in the in-place retarget"
  );
  assert!(
    closes.is_closed(),
    "staging: the retarget retired every handle while it was in flight"
  );

  match run.as_mut().poll(&mut cx) {
    Poll::Ready(()) => {}
    Poll::Pending => panic!(
      "the handles-gone retarget failed the watch instead of breaking the loop, so the loop went on \
       to dispatch the watch buffered behind it and parked on its wedged mount — nothing is left to \
       interrupt it, and teardown never runs"
    ),
  }

  // THE ORDER. Total, in sequence, for the whole life of the source:
  //
  //   the establishing watch (canonicalize, arm, the choke point's liveness probe),
  //   the widen's canonicalize, the sole subsumed root's pre-retarget key probe, the abandoned
  //   retarget,
  //   → THE SEAM ←
  //   the teardown's cookie reap, then the bounded quiescence wait.
  //
  // The wedged watch contributes NOTHING: the break came before it was ever dispatched.
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::RootKey(1),
      SourceCall::Replace(1),
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/b/cookie-1")),
      SourceCall::JoinClose,
    ],
    "the abandoned retarget must be followed by the seam, not by another Source call"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once, however many callers could have entered it"
  );

  // The abandoned widen's caller is answered by a DROPPED reply, not by an error over a teardown —
  // and the watch behind it never reached the source at all.
  assert!(
    widen_response.await.is_err(),
    "the abandoned widen's reply is dropped rather than answered over a teardown"
  );
  assert!(
    wedged_response.await.is_err(),
    "the watch buffered behind it was never dispatched"
  );
  assert!(
    sync_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// The ROLLBACK retarget — the same terminal claim for the widen's SECOND `replace`, proven
/// separately because it is a separate arm on a separate race, and neither arm inherits the other's
/// treatment.
///
/// The first retarget COMMITS at a divergent `/z`, which contains none of the subsumed roots, so
/// `fs_path_preserves_plan` rejects it and the owner rolls the retarget back to `/a/b`. It is that
/// ROLLBACK which loses every handle mid-flight, and it leaves the preserved handle at the divergent
/// WIDER key with the rollback abandoned — so a `Failed` verdict would let the loop go on planning
/// against a coverage picture that is already wrong and may change again underneath it.
///
/// FAIL-ON-REVERT: put `return Err(WatchError::Closed.into())` back in the ROLLBACK's `HandlesGone`
/// arm and the second poll is `Pending` — the loop dispatched the wedged watch buffered behind the
/// widen and parked on a mount that never answers.
#[tokio::test]
async fn an_in_place_rollback_losing_every_handle_breaks_the_loop_at_the_seam() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  h.owner.source.supports_replace = true;

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  h.owner.epochs.stamp(sb, Epoch::new(4));

  let root_b = h
    .owner
    .subsumer
    .subscription_root(sb)
    .expect("live root for /a/b");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/b/cookie-1"),
    sub: sb,
    root: root_b,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The widen of `/a` commits at `/z` — a key containing no subsumed root — so the owner rolls back.
  h.owner.source.retarget("/a", "/z");
  // …and it is the ROLLBACK (ordinal two) that loses every handle while in flight.
  h.owner
    .source
    .close_signal_during_replace(2, h.closes.clone());
  h.owner.source.wedge_arm("/w");
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (widen_reply, widen_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: widen_reply,
    })
    .expect("enqueue the widen");
  let (wedged_reply, wedged_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/w"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: wedged_reply,
    })
    .expect("enqueue the watch buffered behind it");
  drop(commands);

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));

  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked in the divergence rollback"
  );
  assert!(
    closes.is_closed(),
    "staging: the rollback retired every handle while it was in flight"
  );

  match run.as_mut().poll(&mut cx) {
    Poll::Ready(()) => {}
    Poll::Pending => panic!(
      "the handles-gone ROLLBACK failed the watch instead of breaking the loop, so the loop went on \
       to dispatch the watch buffered behind it and parked on its wedged mount"
    ),
  }

  // Two retargets ahead of the seam — the divergent commit and the abandoned rollback — and not one
  // Source call between the abandoned one and `BeginClose`.
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::RootKey(1),
      SourceCall::Replace(1),
      SourceCall::Replace(1),
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/b/cookie-1")),
      SourceCall::JoinClose,
    ],
    "the abandoned rollback must be followed by the seam, not by another Source call"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once, however many callers could have entered it"
  );

  assert!(
    widen_response.await.is_err(),
    "the abandoned widen's reply is dropped rather than answered over a teardown"
  );
  assert!(
    wedged_response.await.is_err(),
    "the watch buffered behind it was never dispatched"
  );
  assert!(
    sync_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// The DROPPED driver future: a caller that drops the [`run`] future never reaches
/// its teardown tail, and the tail is where the seam is entered. Yet the owner's destructor still calls
/// the source — [`Source::end_sync`], once per cookie still pending — so leaving the seam to the tail
/// left this path issuing `Source` calls with ZERO `begin_close` behind them, against a contract that
/// specifies exactly one. `Source::Drop` cannot cover it: the owner's fields drop only AFTER the
/// destructor body, so it is strictly behind every callback in it.
///
/// The future is dropped while parked in a WEDGED [`Source::arm`], which is the state that makes the
/// ordering matter rather than merely the count: the cancelled arm is the one call nothing short of the
/// source's own teardown can reclaim, so a reap issued ahead of the seam here is exactly the pre-seam
/// re-entry the moved seam exists to forbid.
///
/// The ledger ends at the reap: a synchronous destructor cannot await, so there is no `JoinClose` on
/// this path at all — which [`Source::begin_close`] documents as the abnormal-teardown shape.
///
/// FAIL-ON-REVERT: delete the destructor's seam entry and the ledger reads `… Arm(/x), EndSync(…)` —
/// a `Source` call past a cancelled arm with the source never told to wind down, and
/// `begin_closes()` reads 0 against a once-per-source contract.
#[tokio::test]
async fn dropping_the_driver_future_enters_the_seam_before_its_cookie_reap() {
  use std::task::{Context, Waker};

  let mut h = Harness::new();
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1

  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-3"),
    sub: sa,
    root: root_a,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The mount the future is dropped on: this arm never answers, so the future is dropped with a
  // `Source::arm` genuinely in flight.
  h.owner.source.wedge_arm("/x");
  let seam = h.owner.source.seam();
  // Read AFTER the owner is gone: the destructor's own read-plane guarantee is asserted alongside the
  // seam, because the ordering between them is the one this cell must not silently swap.
  let view = h.owner.subsumer.view();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes: _closes,
  } = h;

  let (reply, response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/x"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply,
    })
    .expect("enqueue the watch that parks");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked in the wedged arm"
  );

  // The caller drops the driver future — a cancelled task, not a teardown. The owner is dropped with
  // it, and its destructor is the only thing that still runs.
  drop(run);

  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/x")),
      SourceCall::Arm(PathBuf::from("/x")),
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/cookie-3")),
    ],
    "the destructor's cookie reap must land PAST the seam, and the seam is the only thing between it \
     and the cancelled arm"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "a dropped driver future still tells its source to wind down — exactly once"
  );

  // The read plane is still emptied FIRST, which the ledger cannot say: the seam entry was inserted
  // below that publish precisely so a panicking `begin_close` cannot leave stale coverage advertised.
  assert!(
    !view.is_watched(&key("/a")),
    "the destructor emptied the read plane — no stale coverage for a dropped owner"
  );
  assert!(
    response.await.is_err(),
    "the parked watch's reply is dropped rather than answered"
  );
  assert!(
    sync_response.await.is_err(),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// The PANIC UNWIND — the destructor's other caller-less termination, and the one
/// where getting it wrong costs more than an ordering. `Owner::drop` runs here with a panic already in
/// flight, so a second unwind out of it is not a contained failure but an immediate process ABORT: the
/// seam entry is therefore contained on its own, exactly as each cookie reap is, and it sits BELOW the
/// read-plane publish so one misbehaving `begin_close` cannot leave a retained [`WatchView`]
/// advertising a dead owner's coverage.
///
/// The panic comes out of [`Source::arm`] — a public extension point the owner runs on its own thread
/// with nothing to race against — and unwinds through the whole run future. The future is owned by the
/// closure under [`std::panic::catch_unwind`], so the owner is dropped BY that unwind rather than
/// after it.
///
/// FAIL-ON-REVERT: delete the destructor's seam entry and the ledger reads `… Arm(/x), EndSync(…)`
/// with `begin_closes()` at 0 — a `Source` call on an unwinding owner's way out with the source never
/// told to wind down.
#[tokio::test]
async fn a_panic_unwinding_through_the_driver_future_enters_the_seam_before_its_cookie_reap() {
  use std::task::{Context, Waker};

  let mut h = Harness::new();
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1

  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-4"),
    sub: sa,
    root: root_a,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The arm that PANICS rather than answering — the unwind this destructor's containment exists for.
  h.owner.source.panic_arm("/x");
  let seam = h.owner.source.seam();
  let view = h.owner.subsumer.view();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes: _closes,
  } = h;

  let (reply, response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/x"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply,
    })
    .expect("enqueue the watch that panics");

  // The run future lives INSIDE the caught frame, so the unwind out of its `poll` is what drops the
  // owner — the destructor runs mid-panic, which is the case that must not double-unwind.
  let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
    let mut cx = Context::from_waker(Waker::noop());
    let mut run = Box::pin(super::run(owner));
    let _ = run.as_mut().poll(&mut cx);
  }));
  assert!(
    unwound.is_err(),
    "staging: the source's panic unwound out of the run future"
  );

  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/x")),
      SourceCall::Arm(PathBuf::from("/x")),
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/cookie-4")),
    ],
    "the unwinding owner's cookie reap must land PAST the seam"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "a panic unwinding through the owner still tells its source to wind down — exactly once"
  );
  // Unchanged by the insertion, and the reason it goes below the publish rather than above it.
  assert!(
    !view.is_watched(&key("/a")),
    "the destructor still emptied the read plane on the panic path"
  );
  assert!(
    response.await.is_err(),
    "the panicked watch's reply is gone"
  );
  assert!(
    sync_response.await.is_err(),
    "the reaped barrier's caller sees the dropped reply as Closed"
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
  let mut h = Harness::build(Some(Coalescer::new(Some(cfg))), Some(2), None);
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
  let mut h = Harness::build(Some(Coalescer::new(Some(cfg))), Some(1), None);
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
  // before the empty publish + ack. The slot is now free, so this delivers the owed Rescan.
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
  // drain_pending_cleanup → drain_owed_once → swap_in_empty → reply.send). Assert it is observable now.
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
      source_closing: false,
      source_disposals: super::SourceDisposals::default(),
      deferred: crate::subsume::Salvage::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: Filters::new(),
      filter_payload_forgotten: false,
      needs_rescan: ParkedRescans::new(),
      suppressed_rescan: ParkedRescans::new(),
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
    .reconcile_watch(&key("/a"), &42, WatchOptions::new())
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
    .reconcile_watch(&key("/a"), &7, WatchOptions::new())
    .await
    .expect("watch /a"); // root handle 1
  let b = rig
    .owner
    .reconcile_watch(&key("/b"), &9, WatchOptions::new())
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
  drop(rig.owner.subsumer.swap_in_empty());
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
      &(),
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

/// The owner's teardown guard contains EACH reap on its own and stops the loop at the first
/// payload it had to FORGET — the two halves of what that loop owes, asserted as one ordered
/// ledger because the same cookie sequence is what distinguishes them.
///
/// The containment hands back a PAYLOAD, and disposing of a payload runs the misbehaving source's
/// own destructor — so dropping it here reintroduces exactly the escape the containment was built
/// to close, one line further out and in the worst frame in the crate: this destructor also runs
/// while the owner task is UNWINDING (a panicking caller callback is precisely how it is reached),
/// where a second unwind is not a contained failure but an immediate process abort.
///
/// Four cookies, and the leaf of each picks what its reap does:
///
/// - an ORDINARY panic first ([`Boom::Ordinary`]). Its disposal drops the payload and returns, so
///   the plane stays open and the cookie BEHIND it is still reaped. That is the PLACEMENT claim: a
///   containment around the whole loop would catch the identical panic and still leave every marker
///   file behind it on the caller's filesystem.
/// - a clean cookie, reaped, which is what makes the placement claim readable.
/// - a HOSTILE panic ([`Boom::Hostile`]) whose own destructor unwinds. Its disposal has to
///   [forget](tributary_proto::unwind::PayloadDisposal::Forgotten) the payload, and the reap is
///   still ENTERED and still returns — the disposal is total even in a destructor frame.
/// - a fourth cookie, which is SKIPPED. That is the BOUND: this loop is the one contained source
///   entry that repeats within a single owner's destruction, so it is issued through
///   [`offer_source`](super::offer_source) and the forgotten payload shuts it. The marker file
///   stays for the source's own `Drop`, which runs immediately after this body.
///
/// FAIL-ON-REVERT, two ways. Contain with a bare `catch_unwind` and let its `Err` fall out of
/// scope, and the first payload's destructor unwinds out of the teardown loop — the cookies behind
/// it are never reaped, and the unwind leaves through `drop(h)`. Route the loop through
/// [`call_source`](super::call_source) instead, and the fourth cookie is reaped as well: the ledger
/// grows an entry and the loop is once more unbounded in what it can be made to forget.
#[tokio::test]
async fn owner_teardown_contains_each_reap_apart_and_stops_at_a_payload_it_had_to_forget() {
  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  let seam = h.owner.source.seam();
  let entered = BOOM_COOKIES_REAPED.load(core::sync::atomic::Ordering::SeqCst);
  let mut replies = Vec::new();
  for leaf in [
    "/a/cookie-drop-boom",
    "/a/cookie-behind-the-ordinary-panic",
    "/a/cookie-boom",
    "/a/cookie-behind-the-forgotten-payload",
  ] {
    let (reply_tx, reply_rx) = futures_channel::oneshot::channel();
    replies.push(reply_rx);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key(leaf),
      sub,
      root: handle,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: reply_tx,
    });
  }
  let before = seam.calls().len();

  // The teardown guard: it publishes the empty plane, enters the seam, then reaps.
  drop(h);

  assert_eq!(
    &seam.calls()[before..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/cookie-drop-boom")),
      SourceCall::EndSync(key("/a/cookie-behind-the-ordinary-panic")),
      SourceCall::EndSync(key("/a/cookie-boom")),
    ],
    "each reap is contained APART — the cookie behind the ordinary panic is still reaped — and the \
     loop stops at the payload it had to forget, leaving the one behind it for the source's own \
     `Drop`"
  );
  assert_eq!(
    BOOM_COOKIES_REAPED.load(core::sync::atomic::Ordering::SeqCst) - entered,
    1,
    "the hostile reap is ENTERED, and entered exactly once: the loop's containment disposed of a \
     payload whose own destructor unwinds without leaving this destructor"
  );

  for reply in replies {
    assert!(
      reply.await.is_err(),
      "a barrier still pending at teardown reads as Closed, reaped or skipped"
    );
  }
}

/// The SAME reap on the other teardown path: [`run`]'s tail reaps every still-pending cookie under a
/// containment of its own, so one panicking [`Source::end_sync`] can neither leave the cookies queued
/// behind it on the caller's filesystem nor carry off the acknowledgement they stand in front of.
///
/// The tail's reap is the destructor's reap reached from the other direction, and it is the more
/// expensive one to lose. The destructor has nothing behind it but its own field drops; the tail
/// still owes the bounded [`join_close`](Source::join_close) and the acknowledgement carrying its
/// verdict, and the destructor that runs next can make NEITHER — it cannot await, and it is not
/// given the reply. So an unwind out of the first reap leaves `run` itself and the caller's
/// `close()` reads the dropped sender as the OWNER-side
/// [`Stopped`](crate::error::CloseError::Stopped) over a source teardown nobody waited for.
/// [`Source`] is a public extension point exactly like the caller's `C`/`V`, so this is the
/// downgrade the sibling teardown cells close, reached through the source rather than through a
/// caller value.
///
/// What the reply CARRIES is the second half, and it is not `Ok(())`: a contained `Source` call that
/// unwound is folded into the verdict ([`fold_into`](super::SourceDisposals::fold_into)), so the
/// caller is told the SOURCE-side `Stopped`. The reap lost source-owned cleanup — a marker file
/// still on the caller's filesystem — that `join_close`'s honest `Ok(())` says nothing about, and
/// the two readings are distinguishable here precisely because one arrives as a reply and the other
/// as a dropped sender.
///
/// Three cookies with the panicking one FIRST, because the claim is about the boundary's PLACEMENT:
/// containment around the whole loop would catch the same panic and still skip the two behind it.
///
/// The payload is ORDINARY ([`Boom::Ordinary`]), and the choice is load-bearing rather than
/// incidental: a payload the disposal had to FORGET quarantines this owner's whole optional source
/// plane ([`forgotten`](super::SourceDisposals::forgotten)), and the two cookies this cell is about
/// would then be SKIPPED rather than reaped — the right behaviour, and a different claim, made by
/// [`a_quarantined_source_plane_still_tears_down_and_answers_close`]. Placement and bound cannot be
/// asserted by one cell because the bound is what makes placement unobservable.
///
/// FAIL-ON-REVERT: drop the containment from [`reap_cookie`](Owner::reap_cookie) — the funnel
/// [`reap_all_pending_syncs`](Owner::reap_all_pending_syncs) reaps through — and the first reap's
/// unwind carries off the `mem::take`n vector: the two cookies behind it are reaped by neither the
/// tail NOR the destructor, since the take already emptied `pending_syncs`, while the ledger ends
/// without `JoinClose` and `close()` answers off a dropped sender. Keep the containment but discard
/// its outcome instead of recording it, and every ledger claim still holds while the caller is told
/// the shutdown was clean over a reap the owner watched fail.
#[tokio::test]
async fn the_tails_cookie_reap_survives_a_panicking_end_sync_and_still_carries_the_verdict() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");

  let mut sync_responses = Vec::new();
  for leaf in ["/a/cookie-tail-boom", "/a/cookie-2", "/a/cookie-3"] {
    let (sync_reply, sync_response) = futures_channel::oneshot::channel();
    sync_responses.push(sync_response);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key(leaf),
      sub: sa,
      root: root_a,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: sync_reply,
    });
  }

  // Read AFTER the owner has been moved into `run` and dropped: the reaps and the bounded wait are
  // the last things that happen, so a ledger reachable through `h.owner` could not testify.
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands,
    _sync_commands,
    closes,
  } = h;

  // Injected exactly as `Tributaries::close` does, before the first poll, so the loop's dedicated
  // close arm wins its first iteration and the tail is all this cell drives.
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  // Contained HERE too, so an escape is observed by this cell rather than by the harness: the
  // assertions below are what must fail, and they can only run if the poll returns. Through
  // [`contain`](tributary_proto::unwind::contain) rather than a bare `catch_unwind` so the payload a
  // REVERTED reap hands back is retired inside a boundary of its own — the shapes are injectable
  // ([`Boom`]) and this wrapper must not depend on which one a cell picked.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a panicking `Source::end_sync` must not leave the tail — the reap is contained in the funnel \
     the tail reaps through, not allowed out through the owner's spawner"
  );
  // THE VERDICT, and two claims in one reading. The reply is still ANSWERED — a reap that unwound
  // out of the tail would have dropped that sender, which reads as the OWNER-side
  // `CloseError::Stopped` and is not what this matches. And what it carries is the SOURCE-side
  // `Stopped`, because the reap's own unwind is folded in: `join_close` answered `Ok(())` honestly
  // about everything it can SEE, while the marker file the reap failed to unlink is not something
  // it can see at all.
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must be ANSWERED, and must carry the SOURCE-side verdict a reap that unwound makes \
     honest — not the `Ok(())` the source's own wait produced, and not the owner-side Stopped a \
     dropped sender reads as"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the tail never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/cookie-tail-boom")),
      SourceCall::EndSync(key("/a/cookie-2")),
      SourceCall::EndSync(key("/a/cookie-3")),
      SourceCall::JoinClose,
    ],
    "every cookie queued behind the panicking reap is still reaped, and the bounded wait is still \
     made ahead of the acknowledgement: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once however the reaps behind it behave"
  );

  for sync_response in sync_responses {
    assert!(
      sync_response.await.is_err(),
      "a barrier still pending at teardown reads as Closed"
    );
  }
}

/// The teardown seam's own initiation as the misbehaving extension point, entered from [`run`]'s
/// TAIL: [`begin_source_close`](Owner::begin_source_close) contains the source call it makes, so a
/// panicking [`Source::begin_close`] cannot carry off every reap, the bounded wait and the
/// acknowledgement behind it. The mid-reconcile entry is the sibling cell; this one is the entry
/// with the whole tail behind it.
///
/// This is the ONE `Source` call the tail makes before its reaps. `Owner::drop` enters the same
/// funnel — for the abnormal terminations, where a second unwind is an immediate process abort —
/// and the mitigation that gives the tail is real but partial: the
/// `source_closing` latch is set BEFORE the source is called, so an escaping panic still leaves the
/// destructor able to reap and empty the read plane, and its own contained entry is a no-op rather
/// than a second `begin_close`. What the destructor cannot do is the rest: it cannot await
/// [`join_close`](Source::join_close) and it is not given the close reply, so an uncontained
/// initiation costs exactly the source's quiescence VERDICT and the caller's acknowledgement —
/// `close()` reads the dropped sender as [`Stopped`](crate::error::CloseError::Stopped) over a
/// teardown nobody waited for.
///
/// What the acknowledgement then CARRIES is the source-side [`Stopped`](SourceCloseError::Stopped),
/// not `Ok(())`: the initiation is a contained `Source` call like any other, so an unwind out of it
/// is folded into the verdict ([`fold_into`](super::SourceDisposals::fold_into)). An initiation that
/// blew up proved nothing about the shutdown it was starting, and the fake's `join_close` cannot
/// know that — it answers for what it can see. The reading is still distinguishable from the
/// uncontained failure above, and that is the whole reason both are asserted: one arrives as a
/// REPLY, the other as a dropped sender.
///
/// Two cookies are left pending so the reaps are observable as well as the verdict: they are what
/// stands between the panicking initiation and the wait, and a boundary placed anywhere later than
/// this call would lose them.
///
/// The payload is ORDINARY ([`Boom::Ordinary`]) so those two reaps stay observable: a payload the
/// disposal had to FORGET quarantines the optional source plane
/// ([`forgotten`](super::SourceDisposals::forgotten)), and the reaps behind the initiation would
/// then be skipped by design rather than run —
/// [`a_quarantined_source_plane_still_tears_down_and_answers_close`] is where that is the claim.
///
/// FAIL-ON-REVERT: drop the containment from inside
/// [`begin_source_close`](Owner::begin_source_close) and the panic leaves `run`'s poll — the cell's
/// own boundary reports `Err`, the ledger ends at the destructor's reaps with no `JoinClose`, and
/// `close()` answers off a dropped sender. `begin_closes()` reads 1 either way, which is the point:
/// the latch was never the part that was missing. Keep the containment but discard its outcome, and
/// every ledger claim still holds while the caller is told the source shut down cleanly over an
/// initiation that never completed.
#[tokio::test]
async fn the_tails_seam_entry_survives_a_panicking_begin_close_and_still_reaps_and_answers() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");

  let mut sync_responses = Vec::new();
  for leaf in ["/a/cookie-2", "/a/cookie-3"] {
    let (sync_reply, sync_response) = futures_channel::oneshot::channel();
    sync_responses.push(sync_response);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key(leaf),
      sub: sa,
      root: root_a,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: sync_reply,
    });
  }

  h.owner.source.panic_begin_close(Boom::Ordinary);

  // Read AFTER the owner has been moved into `run` and dropped: the seam is the last thing that
  // happens, so a ledger reachable through `h.owner` could not testify.
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands,
    _sync_commands,
    closes,
  } = h;

  // Injected exactly as `Tributaries::close` does, before the first poll, so the loop's dedicated
  // close arm wins its first iteration and the tail is all this cell drives.
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  // Contained HERE too, so an escape is observed by this cell rather than by the harness — and
  // through [`contain`](tributary_proto::unwind::contain) rather than a bare `catch_unwind` so the
  // payload a REVERTED tail hands back is retired inside a boundary of its own. A bare
  // `catch_unwind` would leave it in scope, and a cell injecting a hostile shape ([`Boom`]) would
  // then abort the test binary instead of reporting which claim broke.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a panicking `Source::begin_close` must not leave the tail — the seam entry is contained in the \
     funnel the tail enters, not allowed out through the owner's spawner"
  );
  // THE VERDICT, because it is what the destructor behind an escaping panic could never supply —
  // and it is the SOURCE-side reading, since an initiation that unwound proved nothing about the
  // shutdown it was starting. The owner-side `Stopped` a dropped sender reads as is what this
  // distinguishes it from.
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must be ANSWERED, and must carry the SOURCE-side verdict an initiation that unwound \
     makes honest — not the `Ok(())` the source's own wait produced, and not the owner-side Stopped \
     a dropped sender reads as"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the tail never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/cookie-2")),
      SourceCall::EndSync(key("/a/cookie-3")),
      SourceCall::JoinClose,
    ],
    "every cookie behind the panicking initiation is still reaped, and the bounded wait is still \
     made ahead of the acknowledgement: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the latch is set BEFORE the source is called, so an initiation that unwound still counts as \
     the one entry and the destructor's own contained entry behind it is a no-op"
  );

  for sync_response in sync_responses {
    assert!(
      sync_response.await.is_err(),
      "a barrier still pending at teardown reads as Closed"
    );
  }
}

/// The SAME initiation misbehaving at the OTHER kind of entry: a **mid-reconcile terminal mint**,
/// which enters the seam before it retires anything and is nowhere near [`run`]'s tail. A failed
/// widen whose restore reads a close reply retires every root still awaiting restoration, and
/// [`begin_close_then_retire_disarmed_roots`](Owner::begin_close_then_retire_disarmed_roots) enters
/// the seam as its first statement to keep that retirement's own `Source` calls on the far side of
/// the initiation.
///
/// A boundary written at the TAIL's call site covers none of this. The unwind here leaves the
/// reconcile, `dispatch_command` and the [`run`] loop itself, so the tail is never reached at all:
/// no cookie reap, no bounded [`join_close`](Source::join_close), and no acknowledgement — the
/// caller's `close()` reads the dropped sender as [`Stopped`](crate::error::CloseError::Stopped)
/// over a teardown nobody waited for. Nor can [`Owner::drop`] repair it: the latch this entry
/// already set makes the destructor's own entry a no-op, and the destructor can make neither the
/// wait nor the acknowledgement regardless. That is why the containment lives inside
/// [`begin_source_close`](Owner::begin_source_close) rather than at the entries — the funnel
/// performs the act, so an entry cannot forget the boundary.
///
/// A cookie rides the retired root, so the reaps are observable as well as the verdict: they are
/// what stands between the panicking initiation and the wait on THIS path, exactly as the two
/// pending cookies do on the tail's. Its payload is ORDINARY ([`Boom::Ordinary`]) for the reason the
/// tail's sibling gives: a payload the disposal had to FORGET quarantines the optional plane
/// ([`forgotten`](super::SourceDisposals::forgotten)) and the reap behind the initiation is then
/// skipped by design, which is a different cell's claim.
///
/// The close arrives as a REPLY on the dedicated signal rather than as a closed channel, because the
/// acknowledgement is half the claim: a handles-gone terminal has nobody to answer, so it could
/// witness the reaps and the wait but never the verdict reaching a caller. What that reply carries
/// is the SOURCE-side [`Stopped`](SourceCloseError::Stopped) — the initiation's own unwind, folded
/// in — which is a fact reaching a caller rather than a teardown nobody heard about.
///
/// FAIL-ON-REVERT: drop the containment from
/// [`begin_source_close`](Owner::begin_source_close) and the panic leaves `run`'s poll — the cell's
/// own boundary reports `Err`, the ledger ends at the destructor's reap with no `JoinClose`, and
/// `close()` answers off a dropped sender. Put a boundary back at `run`'s tail INSTEAD and nothing
/// changes: this entry is not the tail's.
#[tokio::test]
async fn a_mid_reconcile_seam_entry_survives_a_panicking_begin_close_and_still_reaps_and_answers() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // The barrier that makes the retirement reach the source behind the panicking initiation. Its
  // receiver is HELD, so the loop-top `prune_abandoned_syncs` leaves it alone.
  let root_b = h
    .owner
    .subsumer
    .subscription_root(sb)
    .expect("live root for /a/b");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/b/cookie-1"),
    sub: sb,
    root: root_b,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The wider arm and root ONE's re-arm are refused on the retryable kind and never clear, so the
  // restore parks in root one's pace — where the close reply lands.
  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  // Root two must never be armed, so a restore that carried on past the terminal cannot come back.
  h.owner.source.wedge_arm("/a/c");
  h.owner.source.panic_begin_close(Boom::Ordinary);

  // Taken BEFORE the owner is moved into `run`: the wait is the last thing that happens, so the
  // ledger has to outlive the source it records.
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (widen_reply, widen_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: widen_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));

  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked in the restore's retry pace"
  );

  // Injected exactly as `Tributaries::close` does — a REPLY, so the teardown owes an
  // acknowledgement. The pace's close arm is polled first, so this ends the restore on its next
  // pass, with the reply consumed and in hand.
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  // Contained HERE too, so an escape is observed by this cell rather than by the harness — and
  // through [`contain`](tributary_proto::unwind::contain) rather than a bare `catch_unwind` so the
  // payload a REVERTED funnel hands back is retired inside a boundary of its own, whichever shape
  // ([`Boom`]) the injecting cell picked.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a panicking `Source::begin_close` must not leave a MID-RECONCILE terminal — the seam entry is \
     contained in the funnel every entry goes through, not only at the tail's"
  );
  // THE VERDICT, and on this path it is what an uncontained initiation costs outright: the tail
  // that makes it is behind the unwind, not in front of it. What it carries is the SOURCE-side
  // reading — an initiation that unwound proved nothing about the shutdown it was starting — which
  // is exactly the fact an uncontained one could report to nobody at all.
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must be ANSWERED, and must carry the SOURCE-side verdict an initiation that unwound \
     makes honest — not the `Ok(())` the source's own wait produced, and not the owner-side Stopped \
     a dropped sender reads as"
  );

  // THE ORDER, total and in sequence for the whole life of the source: the initiation still lands
  // ahead of the retirement's cookie reap although it unwound, and the bounded wait is still last.
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/a/c")),
      SourceCall::Arm(PathBuf::from("/a/c")),
      SourceCall::RootKey(2),
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Disarm(1),
      SourceCall::Disarm(2),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/b/cookie-1")),
      SourceCall::JoinClose,
    ],
    "the retirement's reap and the bounded wait behind a panicking initiation must both still happen"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the latch is set BEFORE the source is called, so an initiation that unwound still counts as \
     the one entry and the tail's own entry behind it is a no-op"
  );

  assert!(
    matches!(
      sync_response.await,
      Ok(Ok(crate::source::SyncOutcome::Dominated))
    ),
    "the retired root's barrier is still answered Dominated by the terminal Rescan that dominates it"
  );
  assert!(
    widen_response.await.is_err(),
    "the abandoned widen's reply is dropped rather than answered over a teardown"
  );
}

/// [`reap_cookie`](Owner::reap_cookie) as the misbehaving extension point on a caller the tail never
/// reaches: a failed widen's TERMINAL RETIREMENT, which arrives through
/// [`dominate_syncs_of_root`](Owner::dominate_syncs_of_root) while the reconcile is already
/// unwinding.
///
/// This is the reachability the boundary's altitude decides. Five prunes reap through that one
/// funnel, and a boundary written at any one of them leaves the other four uncontained — this one
/// included, although it is the [`Source`] call the moved seam exists to order and therefore the one
/// path where an unwind costs the most: it escapes the reconcile, `dispatch_command` and the [`run`]
/// loop, so the tail's remaining reaps, the bounded [`join_close`](Source::join_close) and the
/// acknowledgement carrying its verdict are all skipped, and the last two are unreachable from
/// [`Owner::drop`].
///
/// Two cookies on the retired root with the panicking one FIRST, because the claim is about the
/// boundary's PLACEMENT as much as its existence: a boundary around the prune's loop would catch the
/// identical panic and still leave the second marker file on the caller's filesystem. Its payload is
/// ORDINARY ([`Boom::Ordinary`]) so the second reap stays observable — a forgotten one quarantines
/// the optional plane ([`forgotten`](super::SourceDisposals::forgotten)) and skips it by design,
/// which is [`a_quarantined_source_plane_still_tears_down_and_answers_close`]'s claim rather than
/// this one's.
///
/// The close arrives as a REPLY rather than as a closed signal, so the acknowledgement is
/// observable: a handles-gone terminal has nobody to answer.
///
/// FAIL-ON-REVERT: drop the containment from [`reap_cookie`](Owner::reap_cookie) and the cell's own
/// boundary reports `Err` — the second cookie is reaped by nothing, the ledger ends without
/// `JoinClose`, and `close()` answers off a dropped sender. Keep that containment but bypass the
/// funnel HERE with a bare `self.source.end_sync(…)` and the same thing happens, which is what
/// attributes the claim to this caller rather than to the funnel serving all of them.
#[tokio::test]
async fn a_failed_widens_terminal_retirement_survives_a_panicking_cookie_reap_and_still_answers() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  h.owner.epochs.stamp(sb, Epoch::new(4));
  h.owner.epochs.stamp(sc, Epoch::new(2));

  // Both barriers ride the root the restore retires, the panicking cookie first. Their receivers are
  // HELD, so the loop-top `prune_abandoned_syncs` leaves them alone.
  let root_b = h
    .owner
    .subsumer
    .subscription_root(sb)
    .expect("live root for /a/b");
  let mut sync_responses = Vec::new();
  for leaf in ["/a/b/cookie-widen-boom", "/a/b/cookie-2"] {
    let (sync_reply, sync_response) = futures_channel::oneshot::channel();
    sync_responses.push(sync_response);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key(leaf),
      sub: sb,
      root: root_b,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: sync_reply,
    });
  }

  h.owner.source.refuse_capacity("/a", u32::MAX);
  h.owner.source.refuse_capacity("/a/b", u32::MAX);
  h.owner.source.wedge_arm("/a/c");

  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (widen_reply, widen_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: widen_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));

  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked in the restore's retry pace"
  );

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  // Contained HERE too, through [`contain`](tributary_proto::unwind::contain) so a REVERTED
  // funnel's payload is retired inside a boundary of its own, whichever shape ([`Boom`]) it is.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a panicking `Source::end_sync` must not leave a terminal retirement — the reap is contained in \
     the funnel every prune reaps through, not only at the prunes the tail reaches"
  );
  // THE VERDICT: still ANSWERED — an escaping unwind would have dropped that sender — and carrying
  // the SOURCE-side reading the reap's own unwind is folded into, since a marker file the reap
  // failed to unlink is not something `join_close` can see.
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must be ANSWERED, and must carry the SOURCE-side verdict a reap that unwound makes \
     honest — not the `Ok(())` the source's own wait produced, and not the owner-side Stopped a \
     dropped sender reads as"
  );

  // THE ORDER, total and in sequence: the seam, then BOTH of the retired root's cookies, then the
  // bounded wait. Root two contributes no reap (no barrier rode it) and no re-arm (the terminal
  // preceded it).
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/a/c")),
      SourceCall::Arm(PathBuf::from("/a/c")),
      SourceCall::RootKey(2),
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Disarm(1),
      SourceCall::Disarm(2),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/b/cookie-widen-boom")),
      SourceCall::EndSync(key("/a/b/cookie-2")),
      SourceCall::JoinClose,
    ],
    "the cookie queued behind the panicking reap is still reaped, and the bounded wait is still \
     made ahead of the acknowledgement"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once however the reaps behind it behave"
  );

  for sync_response in sync_responses {
    assert!(
      matches!(
        sync_response.await,
        Ok(Ok(crate::source::SyncOutcome::Dominated))
      ),
      "every barrier of the retired root is still answered Dominated"
    );
  }
  assert!(
    widen_response.await.is_err(),
    "the abandoned widen's reply is dropped rather than answered over a teardown"
  );
}

/// [`Source::cancel_sync`] as the misbehaving extension point on [`on_sync`](Owner::on_sync)'s
/// CLOSE-WIN arm — the by-name reclamation of the in-flight cookie write a close just abandoned,
/// issued while the owner holds the CONSUMED [`CloseReply`].
///
/// Holding the reply is what makes this arm different from the sibling abandon: an unwind out of the
/// reclamation drops that sender on its way out, so `close()` answers
/// [`Stopped`](crate::error::CloseError::Stopped) before anything downstream can decide otherwise —
/// and it escapes `run` ahead of every cookie reap, the bounded [`join_close`](Source::join_close)
/// and the acknowledgement, none of which [`Owner::drop`] can supply. So the boundary lives in
/// [`abandon_sync`](Owner::abandon_sync), the funnel both arms reclaim through, rather than at the
/// terminal arm alone: the live arm wants the same bound for the ordinary reason (one misbehaving
/// source must not take the whole owner and every unrelated subscription with it).
///
/// The arm is also a TERMINAL MINT, so it enters the seam before the reclamation — which is what
/// makes [`source_closing`](Owner::source_closing) a truthful reading of "the owner is on its
/// terminal path" at every mint rather than at all but this one. The ledger reads that back:
/// `BeginClose` ahead of the `CancelSync`, and [`Source::begin_close`] documents `cancel_sync` as one
/// of the four fire-and-forget requests that may still arrive after it.
///
/// A cookie is left pending so the tail's reap is observable behind the panicking reclamation, and
/// the payload is ORDINARY ([`Boom::Ordinary`]) so it stays that way: one the disposal had to
/// FORGET quarantines the optional plane ([`forgotten`](super::SourceDisposals::forgotten)), and
/// that reap would then be skipped by design — the claim
/// [`a_quarantined_source_plane_still_tears_down_and_answers_close`] makes instead.
///
/// FAIL-ON-REVERT: drop the containment from [`abandon_sync`](Owner::abandon_sync) and the cell's
/// own boundary reports `Err` — the pending cookie is reaped by the destructor alone, the ledger
/// ends without `JoinClose`, and `close()` answers off the reply this arm dropped mid-unwind. Move
/// the seam entry back below the reclamation and the ledger's first two teardown entries swap,
/// which is the ordering half. Keep the containment but discard its outcome and every ledger claim
/// still holds while the caller is told the source shut down cleanly over a write it never
/// reclaimed.
#[tokio::test]
async fn on_syncs_close_win_survives_a_panicking_cancel_sync_and_still_reaps_and_answers() {
  use core::sync::atomic::Ordering;
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  // The write parks on every pass, so only the close can end the race.
  h.owner.source.sync_script = VecDeque::from([ScriptStep::Pending, ScriptStep::Pending]);
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1

  // The reap that must still happen behind the panicking reclamation. Its receiver is HELD, so the
  // loop-top prune leaves it alone.
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");
  let (parked_reply, parked_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-2"),
    sub: sa,
    root: root_a,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: parked_reply,
  });

  h.owner.source.panic_cancel_sync(Boom::Ordinary);
  let loss_gen = h.owner.loss_gen.load(Ordering::SeqCst);
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands,
    _sync_commands: sync_commands,
    closes,
  } = h;

  // The barrier whose write the close abandons. Its caller stays alive (the receiver is held), so
  // the cancellation arm cannot win the race instead.
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  sync_commands
    .try_send(super::SyncRequest {
      sub: sa,
      loss_gen_at_call: loss_gen,
      reply: sync_reply,
    })
    .expect("enqueue the sync request");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));

  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the loop dispatched the sync and its write is in flight"
  );

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  // Contained HERE too, through [`contain`](tributary_proto::unwind::contain) so a REVERTED
  // funnel's payload is retired inside a boundary of its own, whichever shape ([`Boom`]) it is.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a panicking `Source::cancel_sync` must not leave the close-win arm — the reclamation is \
     contained in the funnel both abandon arms go through"
  );
  // THE VERDICT, and here it is the reply this very arm was holding: an unwind out of the
  // reclamation drops it, and `close()` then reads the OWNER-side `Stopped` off a dead sender.
  // What arrives instead is a REPLY carrying the SOURCE-side reading, because the reclamation's own
  // unwind is folded in: an in-flight write the source was never able to reclaim is cleanup
  // `join_close` cannot answer for.
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must be ANSWERED on the reply this arm was holding, and must carry the SOURCE-side \
     verdict a reclamation that unwound makes honest — not the `Ok(())` the source's own wait \
     produced, and not the owner-side Stopped a dropped sender reads as"
  );

  // THE ORDER: the seam ahead of the reclamation (the terminal mint enters it), the reclamation
  // although it unwound, then the tail's reap and the bounded wait behind it.
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::RootKey(1),
      SourceCall::BeginSync(1),
      SourceCall::BeginClose,
      SourceCall::CancelSync(1),
      SourceCall::EndSync(key("/a/cookie-2")),
      SourceCall::JoinClose,
    ],
    "the cookie behind the panicking reclamation is still reaped, and the bounded wait is still \
     made ahead of the acknowledgement"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the terminal mint enters the seam and the tail's own entry behind it is a no-op"
  );

  assert!(
    sync_response.await.is_err(),
    "the abandoned barrier's reply is dropped, which its caller reads as Closed"
  );
  assert!(
    parked_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// A CANCELLED [`Source`] future as the misbehaving extension point, on [`Owner::arm`]'s close-win
/// arm.
///
/// A different piece of implementor code from every `Source`-call cell beside this one. What the
/// close race destroys is a value of the implementor's own opaque type — an `async fn` future
/// holding whatever its body parked with — and the [`Source`] contract requires its destructor to be
/// panic-free no more than it requires a [`Filter`] predicate to be. `select_biased!` destroys the
/// futures it owns BEFORE it runs the winning arm's handler, so an unwind out of one leaves `run`
/// carrying off a [`CloseReply`] that was already in hand, ahead of the reap, the bounded
/// [`join_close`](Source::join_close) and the acknowledgement — the last two unreachable from
/// [`Owner::drop`]. So the future is held in a slot the race only borrows and destroyed through
/// [`retire_raced_source_future`](super::retire_raced_source_future) once the winner is known.
///
/// Containing that unwind is half of what is owed, and this cell pins the other half: what the
/// CALLER is told. The cancelled future owns cleanup that is invisible to the [`Source`] — the guard
/// books its obligation inside the future's own body — so the fake's
/// [`join_close`](Source::join_close) resolves a truthful `Ok(())` while the resource stays live,
/// and only the fact the owner RECORDED at the disposal can make the acknowledgement honest. That is
/// the difference between a boundary and an account: the source cannot be asked about an obligation
/// it was never told of.
///
/// Hand-polled so the close lands INSIDE the pending arm as a fact of the cell: poll to park in the
/// arm, request the close, poll again.
///
/// A cookie is left pending on an unrelated root so the tail's reap is observable behind the
/// cancellation — and it is NOT reaped. The payload this destructor unwinds with is one the
/// disposal has to [forget](tributary_proto::unwind::PayloadDisposal::Forgotten), which quarantines
/// the plane's optional callbacks ([`forgotten`](super::SourceDisposals::forgotten)) before the tail
/// reaches its reaps. That is the bound's stated price arriving through a CANCELLED FUTURE rather
/// than through a call, and it is what
/// [`a_forgotten_payload_from_a_cancelled_future_shuts_the_optional_plane`] makes its subject; the
/// four sibling cancellation cells read it the same way. What the quarantine does not reach is
/// everything else asserted here: the seam entry, the bounded wait and the acknowledgement are
/// mandatory.
///
/// FAIL-ON-REVERT, three ways. Stop RECORDING the disposal (drop the `note_unwound` from the
/// funnel's terminal arm, or make the fold a no-op) and everything else in this cell still passes
/// while `close()` answers `Ok(())` over an obligation the assertion below shows is still
/// outstanding — which is precisely the defect's shape. Narrow the record to one bit — contain the
/// disposal and read only `is_err`, instead of routing it through
/// [`call_source`](super::call_source) — and the forgotten payload is recorded as an ordinary
/// unwind: the plane stays open, the ledger regains its `EndSync`, and nothing bounds the payloads
/// the rest of the teardown's optional requests can strand. Hand the funnel a `false` instead —
/// destroying the cancelled arm bare, which is what leaving it inside the `select` amounts to — and
/// the cell's own boundary reports `Err`: the ledger ends without `JoinClose`, and `close()`
/// answers off the reply this arm was holding.
#[tokio::test]
async fn arms_close_win_survives_a_cancelled_arm_whose_destructor_panics() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  let sx = h.watch("/x", Interest::all()).await.expect("watch /x"); // handle 1
  let root_x = h
    .owner
    .subsumer
    .subscription_root(sx)
    .expect("live root for /x");

  // The reap that must still happen behind the cancellation. Its receiver is HELD, so the loop-top
  // prune leaves it alone.
  let (parked_reply, parked_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/x/cookie-2"),
    sub: sx,
    root: root_x,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: parked_reply,
  });

  // The disjoint watch whose arm parks forever and unwinds when the close race cancels it.
  h.owner.source.boom_on_cancel_arm("/z", Boom::Hostile);
  let seam = h.owner.source.seam();
  // The cleanup that arm's future OWNS. Held here so it outlives the source, and read after the
  // acknowledgement: the guard books it before parking and its destructor unwinds ahead of the
  // discharge, so what survives the close is a native resource nothing in the `Source` names.
  let owed = h.owner.source.future_owed();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (watch_reply, watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/z"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the watch whose arm hangs");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the loop dispatched the watch and its arm is parked"
  );

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  // Contained HERE too, through [`contain`](tributary_proto::unwind::contain) so a REVERTED site's
  // hostile payload is retired before the failing assertion below unwinds past it — a bare
  // `catch_unwind` leaves it in scope and the revert aborts the binary instead of reporting which
  // claim broke.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a cancelled `Source::arm` whose destructor unwinds must not leave the close-win arm"
  );
  // THE VERDICT, and two claims in one reading. The reply is still ANSWERED — an unwind out of the
  // cancellation would have dropped it, and a dropped sender reads as the OWNER-side
  // `CloseError::Stopped`. And what it carries is the SOURCE-side reading rather than the `Ok(())`
  // the fake's `join_close` produced, which is honest about everything the source can SEE: the
  // obligation the cancelled arm was holding is the future's own, and nothing in the `Source`
  // reflects it, so forwarding that `Ok(())` would report a clean shutdown over a native resource
  // the owner watched stay live.
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must carry the SOURCE-side verdict the watched cleanup failure makes honest — not the \
     `Ok(())` the source's own wait produced, and not the owner-side Stopped a dropped reply reads as"
  );
  assert_eq!(
    owed.load(core::sync::atomic::Ordering::SeqCst),
    1,
    "and the obligation really is still outstanding behind that acknowledgement — no `Source` call \
     could have told the owner so, which is why the verdict cannot be left to one"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the seam was never entered: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[SourceCall::BeginClose, SourceCall::JoinClose],
    "the cookie behind the cancellation is SKIPPED — the destructor's payload had to be forgotten, \
     which shuts the optional plane — while the MANDATORY seam entry and bounded wait are made \
     exactly as they would be over an open one: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once however the cancellation behaves"
  );
  assert!(
    watch_response.await.is_err(),
    "the abandoned watch's reply is dropped, which its caller reads as Closed"
  );
  assert!(
    parked_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// The same cancelled-future extension point on [`Owner::grow`]'s close-win arm — the AWAITED
/// coverage widening a covered-outside watch issues against an already-live root.
///
/// Its own site rather than `arm`'s: the seam entry here is guarded by a NARROWER predicate (only the
/// consumed reply is terminal; the handles-gone arm is a `Failed` the loop goes on from), so a
/// containment written to that predicate has to be proven against this arm specifically.
///
/// The verdict is asserted here for the same reason as at `arm`'s site, and asserting it at more
/// than one site is what makes the record a property of the MECHANISM rather than of whichever
/// race was patched: the fold reads one latch, and every terminal disposal writes it.
///
/// The pending cookie behind the cancellation is SKIPPED, for the reason
/// [`arms_close_win_survives_a_cancelled_arm_whose_destructor_panics`] states in full: this
/// destructor's payload has to be forgotten, which quarantines the optional plane the reap is
/// issued on.
///
/// FAIL-ON-REVERT, three ways. Stop recording the disposal (or make the fold a no-op) and `close()`
/// answers `Ok(())` over cleanup the owner watched fail, with every other claim here still passing.
/// Narrow the record to one bit — read the disposal's containment as `is_err` rather than routing it
/// through [`call_source`](super::call_source) — and the plane stays open behind a payload that was
/// forgotten anyway: the ledger regains its `EndSync`. Hand the funnel a `false` instead and the
/// cell's own boundary reports `Err` — the ledger ends without `JoinClose`, and `close()` answers off
/// the consumed reply.
#[tokio::test]
async fn grows_close_win_survives_a_cancelled_grow_whose_destructor_panics() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  let sx = h.watch("/x", Interest::all()).await.expect("watch /x"); // handle 1
  let root_x = h
    .owner
    .subsumer
    .subscription_root(sx)
    .expect("live root for /x");
  let (parked_reply, parked_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/x/cookie-2"),
    sub: sx,
    root: root_x,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: parked_reply,
  });

  // A wide `/a` root whose RETAINED cover was pruned back to `{/a/b}` — the state in which a watch of
  // `/a/c` is covered-outside and so must GROW rather than arm.
  let _sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sa = h
    .watch("/a", Interest::all())
    .await
    .expect("watch /a widens");
  h.unwatch(sa).expect("unwatch the widening /a");

  h.owner.source.boom_on_cancel_grow(Boom::Hostile);
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (watch_reply, watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a/c"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the covered-outside watch");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the loop dispatched the covered-outside watch and its grow is parked"
  );

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a cancelled `Source::grow` whose destructor unwinds must not leave the close-win arm"
  );
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must carry the SOURCE-side verdict a cancelled grow's failed cleanup makes honest — the \
     reply is still ANSWERED (an unwind would have dropped it, reading as the owner-side Stopped), \
     and the `Ok(())` the source's own wait produced does not survive a disposal the owner watched fail"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the seam was never entered: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[SourceCall::BeginClose, SourceCall::JoinClose],
    "the cookie behind the cancellation is SKIPPED — the destructor's payload had to be forgotten, \
     which shuts the optional plane — while the MANDATORY seam entry and bounded wait are made \
     exactly as they would be over an open one: {calls:?}"
  );
  assert_eq!(seam.begin_closes(), 1, "the seam is entered exactly once");
  assert!(
    watch_response.await.is_err(),
    "the abandoned watch's reply is dropped, which its caller reads as Closed"
  );
  assert!(
    parked_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// The same cancelled-future extension point on
/// [`replace_racing_close`](Owner::replace_racing_close)'s close-win arm — the in-place retarget a
/// widen issues when the source offers the gapless path.
///
/// Its own site because the abandoned RETARGET is the one cancellation the owner already reasons
/// about as not cancel-abortive: the binding may still commit the swap this reconcile is walking
/// away from, so the terminal reading has to reach the seam even when the implementor's own
/// destructor is what runs on the way there. It is also the site where a future owning cleanup the
/// source cannot name is least surprising — the parked retarget holds a reservation against a swap
/// the source has not been told is abandoned — so the obligation is read here as well as at `arm`.
///
/// The pending cookie behind the cancellation is SKIPPED, for the reason
/// [`arms_close_win_survives_a_cancelled_arm_whose_destructor_panics`] states in full: this
/// destructor's payload has to be forgotten, which quarantines the optional plane the reap is
/// issued on.
///
/// FAIL-ON-REVERT, three ways. Stop recording the disposal (or make the fold a no-op) and `close()`
/// answers `Ok(())` while the obligation asserted below is still outstanding, with every other
/// claim here still passing. Narrow the record to one bit — read the disposal's containment as
/// `is_err` rather than routing it through [`call_source`](super::call_source) — and the plane stays
/// open behind a payload that was forgotten anyway: the ledger regains its `EndSync`. Hand the
/// funnel a `false` instead and the cell's own boundary reports `Err` — the ledger ends without
/// `JoinClose`, and `close()` answers off the consumed reply.
#[tokio::test]
async fn replaces_close_win_survives_a_cancelled_retarget_whose_destructor_panics() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  h.owner.source.supports_replace = true;
  let sx = h.watch("/x", Interest::all()).await.expect("watch /x"); // handle 1
  let root_x = h
    .owner
    .subsumer
    .subscription_root(sx)
    .expect("live root for /x");
  let (parked_reply, parked_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/x/cookie-2"),
    sub: sx,
    root: root_x,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: parked_reply,
  });

  let _sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  h.owner.source.boom_on_cancel_replace(Boom::Hostile);
  let seam = h.owner.source.seam();
  // The cleanup the retarget future OWNS, held so it outlives the source. Invisible to the
  // `Source`: the fake's bounded wait answers `Ok(())` with this still non-zero.
  let owed = h.owner.source.future_owed();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (watch_reply, watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the loop dispatched the widen and its in-place retarget is parked"
  );

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a cancelled `Source::replace` whose destructor unwinds must not leave the close-win arm"
  );
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must carry the SOURCE-side verdict a cancelled retarget's failed cleanup makes honest — \
     the reply is still ANSWERED (an unwind would have dropped it, reading as the owner-side \
     Stopped), and the `Ok(())` the source's own wait produced does not survive it"
  );
  assert_eq!(
    owed.load(core::sync::atomic::Ordering::SeqCst),
    1,
    "and the retarget's own obligation is still outstanding behind that acknowledgement — the \
     `join_close` that answered `Ok(())` was never in a position to know about it"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the seam was never entered: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[SourceCall::BeginClose, SourceCall::JoinClose],
    "the cookie behind the cancellation is SKIPPED — the destructor's payload had to be forgotten, \
     which shuts the optional plane — while the MANDATORY seam entry and bounded wait are made \
     exactly as they would be over an open one: {calls:?}"
  );
  assert_eq!(seam.begin_closes(), 1, "the seam is entered exactly once");
  assert!(
    watch_response.await.is_err(),
    "the abandoned widen's reply is dropped, which its caller reads as Closed"
  );
  assert!(
    parked_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// The same cancelled-future extension point on
/// [`rearm_racing_close`](Owner::rearm_racing_close)'s close arm — a failed widen's RESTORE re-arm,
/// the one race this crate added rather than inherited.
///
/// Its own site because it is the only one where BOTH close readings are terminal, so the
/// containment covers the whole arm rather than the consumed-reply half of it. It is also the site
/// furthest from the tail: the restore is already unwinding a widen when the cancellation happens,
/// and everything after it — the roots' retirement, their durable dominating `Rescan`s, the reap —
/// stands behind the panic.
///
/// The pending cookie behind the cancellation is SKIPPED, for the reason
/// [`arms_close_win_survives_a_cancelled_arm_whose_destructor_panics`] states in full: this
/// destructor's payload has to be forgotten, which quarantines the optional plane the reap is
/// issued on. The roots' RETIREMENT is not on that plane and is asserted to happen regardless — the
/// quarantine gates what the owner asks the source for, not what the owner does to its own state.
///
/// FAIL-ON-REVERT, three ways. Stop recording the disposal (or make the fold a no-op) and `close()`
/// answers `Ok(())` over cleanup the owner watched fail, with every other claim here still passing.
/// Narrow the record to one bit — read the disposal's containment as `is_err` rather than routing it
/// through [`call_source`](super::call_source) — and the plane stays open behind a payload that was
/// forgotten anyway: the reap the ledger must not contain reappears. Hand the funnel a `false`
/// instead and the cell's own boundary reports `Err` — the roots are never retired, the ledger ends
/// without `JoinClose`, and `close()` answers off the consumed reply.
#[tokio::test]
async fn a_restores_raced_rearm_survives_a_cancellation_whose_destructor_panics() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  let sx = h.watch("/x", Interest::all()).await.expect("watch /x"); // handle 1
  let root_x = h
    .owner
    .subsumer
    .subscription_root(sx)
    .expect("live root for /x");
  let (parked_reply, parked_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/x/cookie-2"),
    sub: sx,
    root: root_x,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: parked_reply,
  });

  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c");

  // The wider arm is refused on the retryable kind, so the widen unwinds into the restore…
  h.owner.source.refuse_capacity("/a", u32::MAX);
  // …where root one's re-arm parks forever and unwinds when the close race cancels it.
  h.owner.source.boom_on_cancel_arm("/a/b", Boom::Hostile);
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands: commands,
    _sync_commands,
    closes,
  } = h;

  let (watch_reply, watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the refused widen is in its restore, parked in root one's raced re-arm"
  );

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a cancelled restore re-arm whose destructor unwinds must not leave the race"
  );
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must carry the SOURCE-side verdict a cancelled re-arm's failed cleanup makes honest — \
     the reply is still ANSWERED (an unwind would have dropped it, reading as the owner-side \
     Stopped), and the `Ok(())` the source's own wait produced does not survive it"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the seam was never entered: {calls:?}"));
  assert_eq!(
    calls.last(),
    Some(&SourceCall::JoinClose),
    "the bounded wait is still made ahead of the acknowledgement: {calls:?}"
  );
  assert!(
    !calls[split..].contains(&SourceCall::EndSync(key("/x/cookie-2"))),
    "the cookie behind the cancellation is SKIPPED — the destructor's payload had to be forgotten, \
     which shuts the optional plane the reap is issued on: {calls:?}"
  );
  assert_eq!(seam.begin_closes(), 1, "the seam is entered exactly once");
  assert!(
    watch_response.await.is_err(),
    "the abandoned widen's reply is dropped, which its caller reads as Closed"
  );
  assert!(
    parked_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
  let _ = (sb, sc);
}

/// The same cancelled-future extension point on [`on_sync`](Owner::on_sync)'s close-win arm — the
/// in-flight COOKIE WRITE a close abandons.
///
/// Its own site, and the one whose live sibling is deliberately left uncontained: this race also
/// loses to the caller's own `sync()` timeout, and THAT reading is not terminal — the loop keeps
/// serving every other subscription, nothing is owed an acknowledgement, and the cancellation sits
/// beside an uncontained await on the very same future. Only the consumed reply has work behind it
/// nothing downstream can redo.
///
/// It also draws the line the verdict turns on more sharply than any other site, and the
/// quarantine sharpens it further. The by-name `cancel_sync` this arm would issue covers what the
/// source KNOWS about — the cookie the token names — and it is on the OPTIONAL plane, so this
/// destructor's forgotten payload shuts it along with the reap behind it: the ledger below is the
/// two of them missing. The obligation the write's own future was holding was never on any plane at
/// all. Nothing named it to the source, so `join_close` answers `Ok(())` truthfully, and the only
/// thing that can make the acknowledgement honest is the fact the owner recorded when the disposal
/// unwound. A by-name reclamation being available for one obligation is exactly what makes it
/// tempting to assume the source can answer for the other — and here it is not even issued.
///
/// That the reclamation LANDS when the plane is open is asserted one cell away, by
/// [`on_syncs_close_win_survives_a_panicking_cancel_sync_and_still_reaps_and_answers`], whose
/// injected payload is ordinary for exactly that reason. Skipping it is the bound's price, stated
/// in full at [`arms_close_win_survives_a_cancelled_arm_whose_destructor_panics`]: the cookie the
/// token names is one the source still holds and unlinks at its own `Drop`, while the payload the
/// disposal forgot is unreachable to everything forever.
///
/// FAIL-ON-REVERT, three ways. Stop recording the disposal (or make the fold a no-op) and `close()`
/// answers `Ok(())` while the obligation asserted below is still outstanding, with every other claim
/// here still passing. Narrow the record to one bit — read the disposal's containment as `is_err`
/// rather than routing it through [`call_source`](super::call_source) — and the plane stays open
/// behind a payload that was forgotten anyway: the ledger regains both the `CancelSync` and the
/// `EndSync`. Hand the funnel a `false` instead and the cell's own boundary reports `Err`: the
/// ledger ends without `JoinClose`, and `close()` answers off the consumed reply.
#[tokio::test]
async fn on_syncs_close_win_survives_a_cancelled_write_whose_destructor_panics() {
  use core::sync::atomic::Ordering;
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  h.owner.source.boom_on_cancel_begin_sync(Boom::Hostile);
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1

  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");
  let (parked_reply, parked_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-2"),
    sub: sa,
    root: root_a,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: parked_reply,
  });

  let loss_gen = h.owner.loss_gen.load(Ordering::SeqCst);
  let seam = h.owner.source.seam();
  // The cleanup the write future OWNS, as distinct from the cookie the token names: the source is
  // told about the second and never about the first.
  let owed = h.owner.source.future_owed();

  let Harness {
    owner,
    events: _events,
    _commands,
    _sync_commands: sync_commands,
    closes,
  } = h;

  // The barrier whose write the close abandons. Its caller stays alive (the receiver is held), so
  // the cancellation arm cannot win the race instead.
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  sync_commands
    .try_send(super::SyncRequest {
      sub: sa,
      loss_gen_at_call: loss_gen,
      reply: sync_reply,
    })
    .expect("enqueue the sync request");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the loop dispatched the sync and its write is in flight"
  );

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a cancelled `Source::begin_sync` whose destructor unwinds must not leave the close-win arm"
  );
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must carry the SOURCE-side verdict a cancelled write's failed cleanup makes honest — \
     the reply is still ANSWERED (an unwind would have dropped it, reading as the owner-side \
     Stopped), and the `Ok(())` the source's own wait produced does not survive it"
  );
  assert_eq!(
    owed.load(core::sync::atomic::Ordering::SeqCst),
    1,
    "and the write's own obligation is still outstanding behind that acknowledgement — nothing the \
     source knows about could have reported what the cancelled future itself was holding, and no \
     `join_close` could have been asked"
  );

  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::RootKey(1),
      SourceCall::BeginSync(1),
      SourceCall::BeginClose,
      SourceCall::JoinClose,
    ],
    "the two reclamations standing behind the cancellation — the abandoned write's by-name \
     `cancel_sync` and the pending cookie's reap — are both SKIPPED, because the destructor's \
     payload had to be forgotten and both are issued on the optional plane; the mandatory seam \
     entry and bounded wait are made exactly as they would be over an open one"
  );
  assert_eq!(seam.begin_closes(), 1, "the seam is entered exactly once");
  assert!(
    sync_response.await.is_err(),
    "the abandoned barrier's reply is dropped, which its caller reads as Closed"
  );
  assert!(
    parked_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// The tail's QUEUED GRANT CLEANUP as the third way a `Source` call reaches the terminal path: the
/// close-time [`drain_pending_cleanup`](Owner::drain_pending_cleanup) applies each queued
/// [`Cleanup`], and a [`Cleanup::DropOrphan`] whose release empties a root issues that root's
/// fire-and-forget [`Source::disarm`]. Contained per call, so one panicking release cannot carry off
/// the cleanups queued behind it, the bounded [`join_close`](Source::join_close), or the
/// acknowledgement carrying its verdict.
///
/// Two orphans on two disjoint roots, the panicking one FIRST, because the claim is about the
/// boundary's PLACEMENT: a boundary around the drain loop would catch the same panic and still
/// abandon the second orphan's root — armed, in a source that has already been told to stop, with
/// nothing left to release it. Its payload is ORDINARY ([`Boom::Ordinary`]) so that second release
/// stays observable: a payload the disposal had to FORGET quarantines the optional plane
/// ([`forgotten`](super::SourceDisposals::forgotten)) and the second root is then left armed on
/// purpose — the bounded-leak trade, asserted by
/// [`a_forgotten_source_payload_bounds_the_leak_to_one_allocation_however_hard_a_caller_churns`].
///
/// The engine is consistent by the time this call is made — `plan_unwatch` has committed the removal
/// and its salvage is placed — so resuming past the panic leaves nothing half-applied. The fake
/// applies the release before it unwinds for the same reason: what is under test is how far the
/// unwind travels, not a source left half-torn-down.
///
/// FAIL-ON-REVERT: call `self.source.disarm(fs_root)` bare again and the first orphan's unwind
/// leaves `run` — the second root is never disarmed, the ledger ends without `JoinClose`, and
/// `close()` answers off a dropped sender. Move the boundary out to wrap `apply_cleanup` inside the
/// drain loop instead and the second orphan survives but the claim is weaker than the code; move it
/// around the drain and the second orphan is lost again. Keep the boundary but discard its outcome
/// and every ledger claim still holds while the caller is told the source shut down cleanly over a
/// kernel watch it never released.
#[tokio::test]
async fn the_tails_grant_cleanup_survives_a_panicking_disarm_and_still_releases_the_rest() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let sb = h.watch("/b", Interest::all()).await.expect("watch /b"); // handle 2
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");
  let root_b = h
    .owner
    .subsumer
    .subscription_root(sb)
    .expect("live root for /b");
  assert_ne!(root_a, root_b, "the two watches must sit on disjoint roots");

  h.owner.source.panic_disarm(root_a, Boom::Ordinary);

  // Queued exactly as a dropped `WatchGrant` queues them, and left for the TAIL to apply: the close
  // below is injected before the first poll, and the loop's close check sits above its
  // top-of-iteration cleanup drain, so the first thing to see these is `run`'s teardown.
  h.owner
    .cleanup_tx
    .try_send(super::Cleanup::DropOrphan(sa))
    .expect("queue the panicking orphan");
  h.owner
    .cleanup_tx
    .try_send(super::Cleanup::DropOrphan(sb))
    .expect("queue the orphan behind it");

  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands,
    _sync_commands,
    closes,
  } = h;

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  // Through [`contain`](tributary_proto::unwind::contain) for the reason the sibling seam cell gives:
  // retiring a reverted release's payload inside a boundary is what makes the revert report a failed
  // assertion instead of a second unwind out of the assertion's own frame.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a panicking `Source::disarm` must not leave the tail's grant-cleanup drain"
  );
  // THE VERDICT: still ANSWERED — an escaping unwind would have dropped that sender — and carrying
  // the SOURCE-side reading the release's own unwind is folded into. A kernel watch the source
  // failed to release is not something its `join_close` can see, so the honest `Ok(())` it produced
  // is not the whole truth about what stayed live.
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must be ANSWERED, and must carry the SOURCE-side verdict a release that unwound makes \
     honest — not the `Ok(())` the source's own wait produced, and not the owner-side Stopped a \
     dropped sender reads as"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the tail never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::Disarm(root_a),
      SourceCall::Disarm(root_b),
      SourceCall::JoinClose,
    ],
    "the orphan queued behind the panicking release is still released, and the bounded wait is \
     still made ahead of the acknowledgement: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once however the releases behind it behave"
  );
}

/// The grant-cleanup COOKIE REAP contained per cookie, so one panicking [`Source::end_sync`] can
/// neither strand the marker files queued behind it nor abandon the rest of the release that issued
/// it — the emptied root's [`Source::disarm`] included.
///
/// Driven on the LIVE path deliberately, and that is a claim about reachability worth stating
/// plainly: [`run`]'s tail cannot reach this reap with anything to do. The tail's
/// [`reap_all_pending_syncs`](Owner::reap_all_pending_syncs) runs BEFORE its grant-cleanup drain and
/// `mem::take`s the whole pending map, so by the time a queued [`Cleanup::DropOrphan`] reaches
/// [`retire_syncs_of_subscription`](Owner::retire_syncs_of_subscription) there is no cookie left for
/// it to find — and neither the source-drain drain nor the mid-reconcile terminal re-admits one. The
/// boundary here is therefore owed to the paths that DO reach it with cookies pending: a caller
/// `unwatch`, an orphaned `watch` grant, and the run loop's own top-of-iteration cleanup drain, where
/// an escaping panic takes the whole owner down and every unrelated subscription with it — the same
/// blast radius the filter gate and the owner's destructor are already contained against.
///
/// Two cookies with the panicking one FIRST, so the boundary's placement is what is under test:
/// containment around the reap loop would catch the same panic and still leave the second marker
/// file on the caller's filesystem, and containment around the whole release would additionally skip
/// the `Disarm` the ledger ends with.
///
/// FAIL-ON-REVERT: drop the containment from [`reap_cookie`](Owner::reap_cookie), or bypass that
/// funnel at THIS prune with a bare `self.source.end_sync(…)`, and the cell's own boundary reports
/// `Err` — the second cookie is never reaped and the emptied root is never disarmed. The second form
/// is what attributes the claim to this caller rather than to the funnel serving all of them.
#[tokio::test]
async fn a_grant_cleanups_cookie_reap_survives_a_panicking_end_sync_and_still_disarms() {
  let mut h = Harness::new();
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");

  let mut sync_responses = Vec::new();
  for leaf in ["/a/cookie-cleanup-boom", "/a/cookie-2"] {
    let (sync_reply, sync_response) = futures_channel::oneshot::channel();
    sync_responses.push(sync_response);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key(leaf),
      sub: sa,
      root: root_a,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: sync_reply,
    });
  }

  let seam = h.owner.source.seam();
  let before = seam.calls().len();

  // Exactly what the tail's drain and the loop's own do with a dropped grant's cleanup. Through
  // [`contain`](tributary_proto::unwind::contain) so a reverted reap's payload is retired here
  // rather than dropped by the failing assertion's own unwind, which a hostile shape ([`Boom`])
  // would turn into an abort.
  let applied = tributary_proto::unwind::contain(|| {
    h.owner.apply_cleanup(super::Cleanup::DropOrphan(sa));
  });
  assert!(
    applied.is_ok(),
    "a panicking `Source::end_sync` must not leave the release that issued it"
  );

  let calls = seam.calls();
  assert_eq!(
    &calls[before..],
    &[
      SourceCall::EndSync(key("/a/cookie-cleanup-boom")),
      SourceCall::EndSync(key("/a/cookie-2")),
      SourceCall::Disarm(root_a),
    ],
    "the cookie behind the panicking reap is still reaped, and the release still reaches the \
     emptied root's disarm: {calls:?}"
  );

  for sync_response in sync_responses {
    assert!(
      matches!(
        sync_response.await,
        Ok(Err(crate::error::SyncError::Retired))
      ),
      "every barrier of the released subscription is still failed typed"
    );
  }

  // The owner is still serving: the containment bounded the unwind, it did not end the watcher.
  let sc = h.watch("/c", Interest::all()).await.expect("watch /c");
  assert!(
    h.owner.subsumer.subscription_root(sc).is_some(),
    "the contained panic left the owner alive and still able to commit a watch"
  );
}

/// The coverage PRUNE as the misbehaving extension point, on the path that makes the boundary owed:
/// [`run`]'s tail drains its queued grant cleanup, a [`Cleanup::DropOrphan`] lands in
/// [`release_subscription`](Owner::release_subscription), and the departing root-key subscriber
/// leaves the shared root over-broad — so [`Source::set_cover`] is issued with the rest of the
/// teardown still ahead of it.
///
/// [`Source::set_cover`] is a public extension point exactly like `disarm` and `end_sync`, and an
/// unwind out of it here leaves `run` itself: the cleanups queued BEHIND it, the bounded
/// [`join_close`](Source::join_close) and the acknowledgement carrying its verdict all go with it,
/// and the destructor that runs next can make neither of the last two — it cannot await, and it is
/// not given the reply. `close()` would read the dropped sender as
/// [`Stopped`](crate::error::CloseError::Stopped) over a source teardown nobody waited for.
///
/// A SECOND cleanup is queued behind the panicking one, because the claim is about the boundary's
/// PLACEMENT: a boundary around the drain loop would catch the identical panic and still abandon
/// the release queued behind it. The payload is ORDINARY ([`Boom::Ordinary`]) so that second
/// release stays observable — a payload the disposal had to FORGET quarantines the optional plane
/// ([`forgotten`](super::SourceDisposals::forgotten)) and skips it deliberately, which is
/// [`a_quarantined_source_plane_still_tears_down_and_answers_close`]'s subject rather than this
/// cell's.
///
/// FAIL-ON-REVERT: call `self.source.set_cover(handle, &retained)` bare again and the panic leaves
/// `run`'s poll — the cell's own boundary reports `Err`, the ledger ends at `SetCover` with neither
/// the `Disarm` behind it nor `JoinClose`, and `close()` is answered by a dropped sender. Keep the
/// boundary but discard its outcome and every ledger claim still holds while the caller is told the
/// source shut down cleanly over a prune it never completed.
#[tokio::test]
async fn the_tails_coverage_prune_survives_a_panicking_set_cover_and_still_waits_and_answers() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  // `/y` is the ROOT; `/y/n` rides it Covered. Dropping the root-key subscriber leaves the root
  // armed for `/y/n` alone and its kernel coverage reclaimable — the `shrink: Some(..)` arm.
  let sy = h.watch("/y", Interest::all()).await.expect("watch /y"); // handle 1
  h.watch("/y/n", Interest::all()).await.expect("watch /y/n");
  // A second, disjoint root whose own orphan is queued BEHIND the panicking one.
  let sz = h.watch("/z", Interest::all()).await.expect("watch /z"); // handle 2
  let root_y = h
    .owner
    .subsumer
    .subscription_root(sy)
    .expect("live root for /y");

  // A cookie still pending, so the tail's own reap is observable as well as the wait: the reaps run
  // ahead of the cleanup drain, and all of it must still happen.
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/y/cookie-prune"),
    sub: sy,
    root: root_y,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  h.owner.source.panic_set_cover(root_y, Boom::Ordinary);
  let seam = h.owner.source.seam();
  let grants = h.owner.cleanup_tx.clone();

  let Harness {
    owner,
    events: _events,
    _commands,
    _sync_commands,
    closes,
  } = h;

  // Queued BEFORE the first poll, which is exactly where the tail drains them from: the loop's
  // top-of-iteration close check runs ahead of its cleanup drain, so a close already in the signal
  // breaks to teardown with both cleanups still queued.
  grants
    .try_send(super::Cleanup::DropOrphan(sy))
    .expect("queue the narrowing orphan");
  grants
    .try_send(super::Cleanup::DropOrphan(sz))
    .expect("queue the emptying orphan behind it");

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  // Contained HERE too, through [`contain`](tributary_proto::unwind::contain) rather than a bare
  // `catch_unwind` so the payload a REVERTED prune hands back is retired inside a boundary of its
  // own — a bare one leaves it in scope, and a hostile shape ([`Boom`]) would then abort the test
  // binary instead of reporting which claim broke.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a panicking `Source::set_cover` must not leave the tail — the prune is contained at the one \
     call the release primitive makes, not allowed out through the owner's spawner"
  );
  // THE VERDICT, because it is what a prune that unwound out of the tail would have carried off —
  // and it carries the SOURCE-side reading, since a prune that blew up mid-flight leaves kernel
  // coverage its own `join_close` cannot describe.
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must be ANSWERED, and must carry the SOURCE-side verdict a prune that unwound makes \
     honest — not the `Ok(())` the source's own wait produced, and not the owner-side Stopped a \
     dropped sender reads as"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the tail never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/y/cookie-prune")),
      SourceCall::SetCover(root_y),
      SourceCall::Disarm(2),
      SourceCall::JoinClose,
    ],
    "the cleanup queued behind the panicking prune is still applied, and the bounded wait is still \
     made ahead of the acknowledgement: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once however the prune behind it behaves"
  );
  assert!(
    sync_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// The one contained `Source` call whose boundary CHANGES recorded state, and what it records.
///
/// Resuming past a panicking [`Source::set_cover`] means the driver's retained-cover record is
/// written by a line the source never completed. Three readings are available and only one is safe.
/// Recording the requested `retained` leaves the record narrow-and-pessimistic — legal, and exactly
/// what a conforming no-op `set_cover` produces — but it is a claim about a prune that may have gone
/// FURTHER than `retained` before it unwound. Skipping the record entirely leaves the previous,
/// BROADER value standing, which is the one direction that commits a later newcomer over kernel
/// coverage that is not there. So the error arm records the EMPTY cover: the same claim
/// [`degrade_retained_cover`](crate::subsume::Subsumer::degrade_retained_cover) stands for a
/// live-root loss signal, under which every later newcomer under the root re-proves coverage
/// through an awaited [`Source::grow`] before it commits.
///
/// Driven on the LIVE path, because the record has a consumer only there: on the terminal path
/// nothing left reads it. The consumer is what this asserts — a newcomer at `/y/n/deep`, which sits
/// INSIDE the requested cover `[/y/n]` and outside the empty one.
///
/// FAIL-ON-REVERT (three mutations, one cell): record `Some(retained)` on the error arm and
/// `/y/n/deep` classifies inside the cover, so no `Grow` is issued. Contain the pair instead — skip
/// the record when the prune unwinds — and the record stays `None` (full coverage), so no newcomer
/// is ever outside-cover and no `Grow` is issued either. Drop the containment altogether and the
/// panic leaves `apply_cleanup`, so the cell's own boundary reports `Err`.
#[tokio::test]
async fn a_panicking_set_cover_records_the_empty_cover_so_a_later_newcomer_re_proves_coverage() {
  let mut h = Harness::new();
  let sy = h.watch("/y", Interest::all()).await.expect("watch /y"); // handle 1
  h.watch("/y/n", Interest::all()).await.expect("watch /y/n");
  let root_y = h
    .owner
    .subsumer
    .subscription_root(sy)
    .expect("live root for /y");

  assert_eq!(
    h.owner
      .subsumer
      .entry(root_y)
      .expect("live root record")
      .retained_cover,
    None,
    "staging: the root has never been narrowed, so the record is full coverage"
  );

  h.owner.source.panic_set_cover(root_y, Boom::Ordinary);
  // Exactly what the tail's drain and the loop's own do with a dropped grant's cleanup. Through
  // [`contain`](tributary_proto::unwind::contain) so a reverted site's payload is retired here
  // rather than dropped by the failing assertion's own unwind, which a hostile shape ([`Boom`])
  // would turn into an abort.
  let applied = tributary_proto::unwind::contain(|| {
    h.owner.apply_cleanup(super::Cleanup::DropOrphan(sy));
  });
  assert!(
    applied.is_ok(),
    "a panicking `Source::set_cover` must not leave the release that issued it"
  );

  assert_eq!(
    h.owner
      .subsumer
      .entry(root_y)
      .expect("the root survives for /y/n")
      .retained_cover,
    Some(Vec::new()),
    "a prune that unwound records the EMPTY cover — not the cover it may not have applied, and not \
     the previous broader one"
  );

  // The consumer of that record, and the whole point of choosing the empty cover: a newcomer that
  // would have been INSIDE the requested cover `[/y/n]` is outside the empty one, so it re-proves
  // coverage through an awaited grow before its commit.
  let before = h.owner.source.calls().len();
  h.watch("/y/n/deep", Interest::all())
    .await
    .expect("watch /y/n/deep");
  let grows: Vec<Call> = h
    .owner
    .source
    .calls()
    .into_iter()
    .skip(before)
    .filter(|call| matches!(call, Call::Grow(..)))
    .collect();
  assert_eq!(
    grows,
    // The fresh cover is the survivors-plus-newcomer ANTICHAIN, so the newcomer collapses into the
    // prefix that already covers it — the grow re-asserts `[/y/n]` rather than widening it. Which is
    // the point: the newcomer sits INSIDE the cover the panicking prune requested, so recording that
    // cover would have classified it covered and issued nothing at all.
    vec![Call::Grow(root_y, vec![key("/y/n")])],
    "the newcomer under a root whose prune unwound is classified outside-cover and grows before it \
     commits"
  );
}
/// The BOUND on what a containment costs, driven the way a caller can actually reach it: repeated
/// live RELEASES against a source whose [`Source::disarm`] panics with a payload the disposal has to
/// FORGET.
///
/// Every cell above this one asserts that a contained unwind goes no further than it should. None
/// of them can see what it COSTS, because their payloads mint and book nothing on the way past
/// ([`ForgottenPayload`]) — there is no reading to take. The cost is the whole defect here:
/// [`Forgotten`](tributary_proto::unwind::PayloadDisposal::Forgotten) leaks one payload, a payload
/// is implementor data of any size, and the release primitive this drives sits on a LIVE path a
/// caller reaches at will. Unbounded, that is one arbitrary allocation per release until the
/// process is out of memory — and it is exactly the obligation that type's own documentation leaves
/// to callers foreign code can drive to it repeatedly.
///
/// # Why every root is armed BEFORE the first release
///
/// Because that is now the only order a caller can drive, and the order the bound is stated
/// against. The quarantine refuses new ACQUISITION as well as declining reclamation
/// ([`forgotten`](super::SourceDisposals::forgotten)), so a watch-release-watch-release loop would
/// stop at the first refusal and the cell would be counting one release rather than `CYCLES` of
/// them. Arming the whole population first is what a caller with `CYCLES` established
/// subscriptions has, and releasing them one at a time is the churn the latch has to bound: the
/// fence caps how much state can EXIST when the quarantine arms, and this bit caps what releasing
/// all of it costs.
///
/// So the payload here MINTS a heap allocation and books it on the way past ([`Boom::Costly`]), and
/// the cell asserts both halves of the bound:
///
/// - **entries.** [`Source::disarm`] is entered exactly ONCE across every release, not once per
///   release. That is the mechanism — [`forgotten`](super::SourceDisposals::forgotten) quarantines
///   the optional plane at the first forgotten payload and [`offer_source`](super::offer_source)
///   enters no callback again — and counting entries is what distinguishes it from a source that
///   merely stopped panicking.
/// - **allocations.** Exactly one is stranded, however many releases run. Each skipped release
///   still DESTROYS the request it declined, inside the boundary, but a `disarm` closure captures
///   only a `Copy` [`Source::Handle`], so no skip here can forget anything — which is the
///   per-site half of the bound
///   [`forgotten`](super::SourceDisposals::forgotten) derives.
///
/// The price is asserted with it, because a bound whose cost is not stated is not a trade: the roots
/// of every release after the first are left ARMED in the source, which is watch budget the owner
/// declines to reclaim. That is the deliberate direction — a kernel watch is something the source
/// still knows about and releases at its own `Drop`, while a forgotten payload is unreachable to
/// everything forever. And the closing watch pins the OTHER half of the trade: it is refused, not
/// served, because a plane that reclaims nothing must not keep arming roots.
///
/// FAIL-ON-REVERT: route the release through [`call_source`](super::call_source) instead of
/// [`offer_source`](super::offer_source), or clear the latch, and `disarm` is entered on every
/// release with an allocation stranded per entry — `CYCLES` of each. Record only
/// [`unwound`](super::SourceDisposals::unwound) and drop the `forgotten` bit and the same thing
/// happens, which is what makes the two bits separate rather than one. Drop the acquisition fence
/// and the closing watch commits a fresh root instead of being refused.
#[tokio::test]
async fn a_forgotten_source_payload_bounds_the_leak_to_one_allocation_however_hard_a_caller_churns()
{
  /// Enough releases that a per-call leak is unmistakable against a per-plane one, and few enough
  /// that the assertion names a number rather than a rate.
  const CYCLES: usize = 8;
  /// This cell's tag in the stranded-allocation book — see [`Boom::Costly`].
  const CHURN: &str = "churn";

  let mut h = Harness::new();
  // EVERY disarm rather than named handles: the claim is about how many releases enter the
  // callback at all, and naming the handles would presuppose which ones the owner still enters.
  h.owner.source.panic_every_disarm(Boom::Costly(CHURN));

  let seam = h.owner.source.seam();
  let stranded_before = StrandedAllocation::stranded(CHURN);
  let entered_before = disarms(&seam);

  // The whole population, armed while the plane is still open — see the note above.
  let mut churned = Vec::new();
  for cycle in 0..CYCLES {
    let path = format!("/churn-{cycle}");
    churned.push(
      h.watch(&path, Interest::all())
        .await
        .expect("watch the churned root"),
    );
  }

  for (cycle, sub) in churned.into_iter().enumerate() {
    // Exactly what a dropped `WatchGrant` queues and what the loop's own top-of-iteration drain
    // applies — the LIVE release primitive, which is the one a caller can drive as often as it
    // likes. Contained here so a REVERTED boundary reports a failed assertion instead of taking the
    // cell down with it.
    let applied = tributary_proto::unwind::contain(|| {
      h.owner.apply_cleanup(super::Cleanup::DropOrphan(sub));
    });
    assert!(
      applied.is_ok(),
      "release {cycle}: a panicking `Source::disarm` must not leave the release that issued it"
    );
  }

  assert_eq!(
    disarms(&seam) - entered_before,
    1,
    "the source plane quarantines on the FIRST forgotten payload, so the release callback is \
     entered once for the whole watcher — not once per release"
  );
  assert_eq!(
    StrandedAllocation::stranded(CHURN) - stranded_before,
    1,
    "exactly one arbitrary allocation is stranded however many releases the caller drives — the \
     bound is one forgotten payload for the whole churnable plane"
  );

  // THE PRICE, asserted rather than implied: the roots of every release after the first are still
  // armed in the source, because the owner declined to ask for their release. That is the trade —
  // watch budget the source still knows about and frees at its own `Drop`, against memory nothing
  // can ever reach again.
  assert_eq!(
    h.owner.source.live_root_count(),
    CYCLES - 1,
    "the quarantined plane leaves every root after the first armed — the reclamation the bound costs"
  );

  // And the other half of the same trade: a plane that will never reclaim must not keep ACQUIRING,
  // so a fresh watch is refused with a variant that says the condition never clears. An ordinary
  // error return, which is what keeps the refusal from being a wedge.
  let refused = h.watch("/served", Interest::all()).await;
  assert!(
    matches!(refused, Err(WatchError::SourceRetired)),
    "a quarantined source plane refuses a NEW watch rather than arming a root nothing will ever \
     release: {refused:?}"
  );
}

/// The bound applied where a caller cannot reach at all: a TERMINAL DISPOSAL whose payload has to be
/// forgotten shuts the optional plane, and the release queued behind it is never issued.
///
/// # Why the disposal is a different claim from the call
///
/// Every quarantine cell above this one arms the latch through a `Source` CALL. What a close race
/// destroys is not a call: it is a value of the implementor's own opaque type, cancelled by the
/// owner, whose destructor is arbitrary caller code and whose caught payload is caller data. Both
/// facts about that disposal matter, and they are not the same fact — one unwound, and the payload
/// it carried had itself to be
/// [forgotten](tributary_proto::unwind::PayloadDisposal::Forgotten). Reading only the first is the
/// escape this cell exists to close: the disposal is contained, the record is written, the fold
/// makes the verdict honest, and the plane stays wide open behind a payload that has already been
/// leaked — so the very next fire-and-forget request the teardown makes can leak another.
///
/// # Why it is asserted as an A/B rather than as one reading
///
/// Because a single hostile leg cannot tell "the plane quarantined" apart from "this release was
/// never going to be issued on a terminal path anyway". The two legs are the SAME staging with the
/// same close, differing only in the payload the cancelled arm's destructor unwinds with
/// ([`Boom`]), and the release behind it is the only thing that moves:
///
/// - [`Boom::Ordinary`] — the disposal drops its payload and returns. Nothing was leaked, the plane
///   stays open, and the queued [`Cleanup::DropOrphan`](super::Cleanup::DropOrphan)'s
///   [`Source::disarm`] IS issued at the teardown's drain.
/// - [`Boom::Hostile`] — the disposal has to forget its payload. The plane quarantines and that same
///   release is NOT issued: one kernel watch the owner declines to ask about, against a payload
///   nothing can ever reach again.
///
/// Everything the caller cannot do without is asserted in BOTH legs, inside the helper, because a
/// bound that also cost the teardown its verdict would be no trade: the run future resolves, the
/// acknowledgement is sent rather than dropped, and it carries the source-side
/// [`Stopped`](SourceCloseError::Stopped) either way — an unwound disposal is folded in whichever
/// shape its payload took.
///
/// The release is queued only once the arm has PARKED, so the loop's top-of-iteration drain cannot
/// have applied it: the first thing to see it is the teardown, standing behind the disposal.
///
/// FAIL-ON-REVERT: read the disposal's containment as one bit — `contain(...).is_err()` with only
/// [`note_unwound`](super::SourceDisposals::note_unwound) behind it, instead of routing it through
/// [`call_source`](super::call_source) — and the hostile leg's `Disarm` reappears: the two legs
/// become indistinguishable, which is exactly what the collapsed bit does to the bound.
#[tokio::test]
async fn a_forgotten_payload_from_a_cancelled_future_shuts_the_optional_plane() {
  use std::task::{Context, Poll, Waker};

  /// One close-win cancellation on [`Owner::arm`] whose destructor unwinds with `boom`, with a
  /// queued orphan release standing behind it. Hands back the root that release names and the seam
  /// ledger from the seam entry onward.
  async fn drive(boom: Boom) -> (u32, Vec<SourceCall>) {
    let mut h = Harness::new();
    let sx = h.watch("/x", Interest::all()).await.expect("watch /x"); // handle 1
    let root_x = h
      .owner
      .subsumer
      .subscription_root(sx)
      .expect("live root for /x");
    // The disjoint watch whose arm parks forever and unwinds when the close race cancels it.
    h.owner.source.boom_on_cancel_arm("/z", boom);
    let seam = h.owner.source.seam();
    // Cloned before the owner is moved into `run`, so the release can be queued at the one instant
    // that makes the claim readable — see below.
    let cleanups = h.owner.cleanup_tx.clone();

    let Harness {
      owner,
      events: _events,
      _commands: commands,
      _sync_commands,
      closes,
    } = h;

    let (watch_reply, watch_response) = futures_channel::oneshot::channel();
    commands
      .try_send(super::Command::Watch {
        key: key("/z"),
        value: (),
        options: WatchOptions::new().with_interest(Interest::all()),
        reply: watch_reply,
      })
      .expect("enqueue the watch whose arm hangs");

    let mut cx = Context::from_waker(Waker::noop());
    let mut run = Box::pin(super::run(owner));
    assert!(
      run.as_mut().poll(&mut cx).is_pending(),
      "staging: the loop dispatched the watch and its arm is parked"
    );

    // Queued only NOW, with the arm already parked: the loop's top-of-iteration drain has already
    // run and cannot have applied it, so the first thing to see this release is the teardown —
    // behind the disposal, which is where the question is.
    cleanups
      .try_send(super::Cleanup::DropOrphan(sx))
      .expect("queue the release the teardown must decide about");

    let (close_reply, close_response) = futures_channel::oneshot::channel();
    closes.try_send(close_reply).expect("request the close");

    // Contained HERE too, through [`contain`](tributary_proto::unwind::contain), so a REVERTED
    // boundary's payload is retired inside a boundary of its own rather than by a failing
    // assertion's unwind — which in this frame would be an abort rather than a report.
    let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

    assert!(
      matches!(drove, Ok(Poll::Ready(()))),
      "a cancelled arm's unwinding destructor must not leave the close-win arm, whichever payload \
       it carries"
    );
    assert!(
      matches!(
        close_response.await,
        Ok(Err(crate::error::CloseError::Source(
          crate::error::SourceCloseError::Stopped
        )))
      ),
      "close() must be ANSWERED and carry the SOURCE-side verdict the watched cleanup failure makes \
       honest — the fold reads that the disposal unwound, not what its payload cost"
    );
    assert!(
      watch_response.await.is_err(),
      "the abandoned watch's reply is dropped, which its caller reads as Closed"
    );

    let calls = seam.calls();
    let split = calls
      .iter()
      .position(|call| *call == SourceCall::BeginClose)
      .unwrap_or_else(|| panic!("the seam was never entered: {calls:?}"));
    (root_x, calls[split..].to_vec())
  }

  let (open_root, open) = drive(Boom::Ordinary).await;
  assert!(
    open.contains(&SourceCall::Disarm(open_root)),
    "the CONTROL leg: a disposal that merely unwound leaks nothing, so the plane stays open and the \
     release queued behind the cancellation is issued: {open:?}"
  );
  assert!(
    open.contains(&SourceCall::JoinClose),
    "…and the teardown is otherwise the ordinary one: {open:?}"
  );

  let (shut_root, shut) = drive(Boom::Hostile).await;
  assert!(
    !shut.contains(&SourceCall::Disarm(shut_root)),
    "THE CLAIM: the same disposal, with a payload it had to FORGET, quarantines the plane — the \
     release standing behind the cancellation is never issued, which is the bound reaching a site \
     no caller can drive: {shut:?}"
  );
  assert!(
    shut.contains(&SourceCall::JoinClose),
    "and only the OPTIONAL half is shut: the mandatory bounded wait is still made over a \
     quarantined plane: {shut:?}"
  );
}

/// What the destructor's reap loop can be made to leak, priced: a source that forgets a payload at
/// every [`Source::end_sync`] strands exactly ONE allocation however many cookies are pending.
///
/// # Why reachability was not a bound here, although this loop runs once per owner
///
/// Every other act the teardown cannot skip is straight-line code — the seam entry, the bounded
/// wait's call, its poll, each terminal mint's disposal — so "reached at most once per owner" caps
/// what each can forget at one. This one is a LOOP. It runs once per pending cookie, up to
/// [`MAX_PENDING_SYNCS`](super::MAX_PENDING_SYNCS) of them, inside a single destruction, so the same
/// sentence caps nothing: a hostile source gets one arbitrary allocation per cookie out of one
/// owner's death, with the latch already set and nothing consulting it.
///
/// The payload here therefore MINTS a heap allocation and books it on the way past
/// ([`Boom::Costly`]), for the reason
/// [`a_forgotten_source_payload_bounds_the_leak_to_one_allocation_however_hard_a_caller_churns`]'s
/// does: the unbooked payload every other containment cell uses proves the disposal is total but
/// leaves nothing a cell could count, and what is under test here is the SIZE of the leak rather
/// than the reach of the unwind.
///
/// `COOKIES` is far above one and far below the ceiling, so a per-cookie leak reads as `COOKIES`
/// rather than as a rate — and the entries are counted beside the allocations, because a source that
/// simply stopped panicking would strand one too.
///
/// The price is the other half and is asserted with it: every cookie behind the first is a marker
/// file the owner declines to ask about, left for the source's own `Drop` — which runs immediately
/// after this body, still holding every one of them. Nothing waits on the requests that were not
/// issued: the pending entries are destroyed either way, so every parked barrier still reads Closed.
///
/// FAIL-ON-REVERT: route the loop through [`call_source`](super::call_source) and every cookie is
/// entered with an allocation stranded per entry — `COOKIES` of each, out of one owner's
/// destruction, which is the escape the gate closes.
#[tokio::test]
async fn the_destructors_reap_strands_one_allocation_however_many_cookies_are_pending() {
  /// Enough pending cookies that a per-cookie leak is unmistakable against a per-plane one, and far
  /// enough below [`MAX_PENDING_SYNCS`](super::MAX_PENDING_SYNCS) that the number is this cell's
  /// choice rather than the ceiling's.
  const COOKIES: usize = 32;

  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
  let handle = h.owner.subsumer.subscription_root(sub).expect("live root");

  let seam = h.owner.source.seam();
  let stranded_before = StrandedAllocation::stranded(DESTRUCTOR_REAP_STRANDED);
  let mut replies = Vec::new();
  for _ in 0..COOKIES {
    let (reply_tx, reply_rx) = futures_channel::oneshot::channel();
    replies.push(reply_rx);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key("/a/cookie-costly-boom"),
      sub,
      root: handle,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: reply_tx,
    });
  }
  let before = seam.calls().len();

  // The teardown guard: it publishes the empty plane, enters the seam, then reaps.
  drop(h);

  let reaps = seam.calls()[before..]
    .iter()
    .filter(|call| matches!(call, SourceCall::EndSync(_)))
    .count();
  assert_eq!(
    reaps, 1,
    "the loop quarantines on the FIRST forgotten payload, so the reap is entered once for the whole \
     destruction — not once per cookie"
  );
  assert_eq!(
    StrandedAllocation::stranded(DESTRUCTOR_REAP_STRANDED) - stranded_before,
    1,
    "exactly one arbitrary allocation is stranded however many cookies were pending — the loop is \
     bounded by the latch, which is the only thing that can bound a loop"
  );

  for reply in replies {
    assert!(
      reply.await.is_err(),
      "a barrier still pending at teardown reads as Closed, reaped or skipped — nothing waits on a \
       request the quarantine declined to issue"
    );
  }
}

/// The whole bound as an ARITHMETIC claim: what one owner can be made to forget is a constant of the
/// code, and no amount of caller work moves it.
///
/// # The property, stated as the thing that would break
///
/// A finite bound per site is not what a panic-driven OOM needs refuting. What it needs is that
/// nothing a CALLER does raises the total — because a caller can watch, unwatch, cover, sync and
/// cancel for as long as it likes, and a source that forgets a payload at each of those turns an
/// arbitrary workload into an arbitrary leak. So this cell drives both kinds of site at once against
/// a source that strands a real allocation at every one of them, and asserts a number that is a sum
/// of ONES rather than a function of `CYCLES` or `COOKIES`:
///
/// - **1** for the whole CHURNABLE plane, however many releases run, because
///   [`forgotten`](super::SourceDisposals::forgotten) closes it after the first;
/// - **1** at [`Source::begin_close`], a MANDATORY site the quarantine deliberately does not reach —
///   [`call_source`](super::call_source) runs whatever the latch says — and which the
///   `source_closing` latch admits exactly once however many teardown entrants arrive;
/// - **0** from the destructor's reap loop, which is on the churnable plane and already shut by the
///   time the cookies reach it. Its skipped reaps still DESTROY the entries they declined, inside
///   the boundary, and that disposal can forget a payload of its own — but only a caller `C`
///   destructor could raise one there, and this cell's keys are ordinary [`OsString`]s.
///
/// Two, therefore, out of a caller that drove `CYCLES` releases and left `COOKIES` barriers pending
/// against a source that was hostile at every turn. The two units are asserted apart — the entry
/// counts say which site each came from — because a single total of two could otherwise be read as
/// one unit counted twice.
///
/// Every root is armed before the first release, for the reason
/// [`a_forgotten_source_payload_bounds_the_leak_to_one_allocation_however_hard_a_caller_churns`]
/// gives: the quarantine refuses new acquisition, so the population a caller can churn is the one
/// that existed when the latch was set. That fence is what makes `COOKIES` a ceiling this cell may
/// name rather than a rate — without it the barriers behind a quarantine are unlimited.
///
/// The individual units have their own cells
/// ([`a_forgotten_source_payload_bounds_the_leak_to_one_allocation_however_hard_a_caller_churns`],
/// [`the_destructors_reap_strands_one_allocation_however_many_cookies_are_pending`],
/// [`a_forgotten_payload_from_a_cancelled_future_shuts_the_optional_plane`]). What only this one says
/// is that they ADD to a constant rather than multiply by anything the caller supplied.
///
/// FAIL-ON-REVERT: route either optional site through [`call_source`](super::call_source) and the
/// total becomes `CYCLES + 1` or `COOKIES + 1` — a number the caller chose, which is precisely what
/// the bound denies. Gate `begin_close` through [`offer_source`](super::offer_source) instead and the
/// total falls to one while the teardown loses the seam entry it owes the source exactly once, which
/// is the trade the mandatory half refuses.
#[tokio::test]
async fn the_forgotten_payload_total_is_a_constant_of_the_code_not_of_what_the_caller_drove() {
  /// Releases the caller drives, and cookies it leaves pending. Both are chosen well above one so
  /// that a per-call leak names them and a bounded one does not.
  const CYCLES: usize = 8;
  const COOKIES: usize = 32;

  let mut h = Harness::new();
  // Every release, and the seam entry: one CHURNABLE site and one MANDATORY one, hostile at every
  // entry, so the total below is the bound rather than a count of how often the source misbehaved.
  h.owner
    .source
    .panic_every_disarm(Boom::Costly(BOUND_TOTAL_STRANDED));
  h.owner
    .source
    .panic_begin_close(Boom::Costly(BOUND_TOTAL_STRANDED));

  let seam = h.owner.source.seam();
  let stranded_before = StrandedAllocation::stranded(BOUND_TOTAL_STRANDED);
  let disarms_before = disarms(&seam);

  // The whole population first, while the plane is still open — the churned roots and the one the
  // cookies below ride. See the note above for why the arms cannot be interleaved with the
  // releases any more.
  let mut churned = Vec::new();
  for cycle in 0..CYCLES {
    let path = format!("/churn-{cycle}");
    churned.push(
      h.watch(&path, Interest::all())
        .await
        .expect("watch the churned root"),
    );
  }
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a");
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");

  for (cycle, sub) in churned.into_iter().enumerate() {
    // The LIVE release primitive a dropped `WatchGrant` queues. Contained here so a REVERTED
    // boundary reports a failed assertion rather than taking the cell down with it.
    let applied = tributary_proto::unwind::contain(|| {
      h.owner.apply_cleanup(super::Cleanup::DropOrphan(sub));
    });
    assert!(
      applied.is_ok(),
      "release {cycle}: a panicking `Source::disarm` must not leave the release that issued it"
    );
  }

  let mut replies = Vec::new();
  for _ in 0..COOKIES {
    let (reply_tx, reply_rx) = futures_channel::oneshot::channel();
    replies.push(reply_rx);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key("/a/cookie-total-boom"),
      sub: sa,
      root: root_a,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: reply_tx,
    });
  }
  let before = seam.calls().len();

  drop(h);

  assert_eq!(
    disarms(&seam) - disarms_before,
    1,
    "the churnable plane is entered once for the whole watcher, not once per cycle"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam entry is MANDATORY — it is made over a plane the churn already quarantined — and it \
     is made exactly once"
  );
  assert_eq!(
    seam.calls()[before..]
      .iter()
      .filter(|call| matches!(call, SourceCall::EndSync(_)))
      .count(),
    0,
    "and the destructor's reap loop, which is on the churnable plane, is entered not at all: the \
     cookies were queued behind a quarantine the caller's own churn had already armed"
  );
  assert_eq!(
    StrandedAllocation::stranded(BOUND_TOTAL_STRANDED) - stranded_before,
    2,
    "TWO allocations for the whole owner — one for the churnable plane and one for the mandatory \
     seam entry — out of a caller that drove {CYCLES} releases and left {COOKIES} barriers pending \
     against a source hostile at every turn. Not {CYCLES}, not {COOKIES}, and not a sum of them: \
     the bound is a constant of the code"
  );

  for reply in replies {
    assert!(
      reply.await.is_err(),
      "a barrier still pending at teardown reads as Closed, reaped or skipped"
    );
  }
}

/// A QUARANTINED plane on the teardown path: it still tears down, still makes the bounded wait, and
/// still answers `close()` — degraded, never wedged.
///
/// The sibling cells all inject an ORDINARY payload precisely so the work queued behind a panicking
/// call stays observable. This is the other side of that choice, and it has to be asserted rather
/// than reasoned about, because the quarantine's whole mechanism is *stop entering the source* and
/// the failure mode nearest to it is *stop making progress*. What must survive is everything the
/// caller cannot do without:
///
/// - the run future RESOLVES. No wedge, no park on a plane that will never answer.
/// - the bounded [`join_close`](Source::join_close) is still made. It is MANDATORY
///   ([`call_source`](super::call_source)), so the quarantine cannot reach it — a plane that skipped
///   the wait would answer `close()` with no verdict at all.
/// - the acknowledgement is still SENT, carrying the source-side
///   [`Stopped`](SourceCloseError::Stopped). Distinguishable from a dropped sender, which reads as
///   the owner-side [`Stopped`](crate::error::CloseError::Stopped).
///
/// And the cost is on the ledger where it can be read: the two cookies queued BEHIND the forgotten
/// payload are not reaped, because [`reap_cookie`](Owner::reap_cookie) is optional and the plane is
/// shut. Two marker files stay on the caller's filesystem for the source to find at its own `Drop` —
/// the deliberate price of refusing an unbounded heap leak to a source that panicked and then
/// panicked again disposing of the payload it panicked with.
///
/// FAIL-ON-REVERT: gate the bounded wait on the quarantine too — make `join_close` go through
/// [`offer_source`](super::offer_source) — and the ledger ends without `JoinClose` while `close()`
/// answers off a verdict nobody produced. Make the quarantine skip the acknowledgement and the
/// caller waits forever on a watcher that has already gone.
#[tokio::test]
async fn a_quarantined_source_plane_still_tears_down_and_answers_close() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");

  // The hostile cookie FIRST, so the two behind it are what the quarantine costs. Its payload's own
  // destructor unwinds, which is what forces the disposal to forget it and arms the latch.
  let mut sync_responses = Vec::new();
  for leaf in ["/a/cookie-quarantine-boom", "/a/cookie-2", "/a/cookie-3"] {
    let (sync_reply, sync_response) = futures_channel::oneshot::channel();
    sync_responses.push(sync_response);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key(leaf),
      sub: sa,
      root: root_a,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: sync_reply,
    });
  }

  // Read AFTER the owner has been moved into `run` and dropped: the reaps and the bounded wait are
  // the last things that happen, so a ledger reachable through `h.owner` could not testify.
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands,
    _sync_commands,
    closes,
  } = h;

  // Injected exactly as `Tributaries::close` does, before the first poll, so the loop's dedicated
  // close arm wins its first iteration and the tail is all this cell drives.
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  // Contained HERE too, through [`contain`](tributary_proto::unwind::contain) so the hostile
  // payload a REVERTED boundary hands back is retired inside a boundary of its own rather than by
  // the failing assertion's unwind, which it would turn into an abort.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a quarantined source plane must still RESOLVE its teardown — the latch stops the owner asking \
     the source for things, not the owner finishing"
  );
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "close() must still be ANSWERED over a quarantined plane, carrying the SOURCE-side verdict the \
     forgotten payload's own unwind makes honest — never a hang, and never a dropped sender"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the tail never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/cookie-quarantine-boom")),
      SourceCall::JoinClose,
    ],
    "the reaps behind the forgotten payload are SKIPPED — the bound's stated price — while the \
     mandatory bounded wait is still made ahead of the acknowledgement: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once however the plane behind it behaves"
  );

  for sync_response in sync_responses {
    assert!(
      sync_response.await.is_err(),
      "a barrier still pending at teardown reads as Closed, reaped or not"
    );
  }
}

/// The quarantine is one plane, not one callback: armed on a LIVE path through [`Source::disarm`],
/// it also stops [`Owner::drop`]'s cookie reap — and the owner still tears down completely.
///
/// The two calls sit one function apart and look identical — both synchronous, both
/// fire-and-forget, both under the same containment — and they are reached by entirely different
/// routes, which is what makes the cross-callback claim worth pinning rather than assuming. `disarm`
/// is reachable from a LIVE path as often as a caller cares to churn. The destructor's reap is
/// reachable only once per owner and is the LAST reap there will ever be: the tail's own
/// [`reap_all_pending_syncs`](Owner::reap_all_pending_syncs) has taken the map before it runs, so a
/// cookie that reaches here is one nothing else can still discharge. It is gated all the same,
/// because it is a LOOP — up to [`MAX_PENDING_SYNCS`](super::MAX_PENDING_SYNCS) reaps inside one
/// destruction — and "runs once per owner" says nothing about how many payloads a loop can be made
/// to forget.
///
/// No panic is injected into the reaps at all, deliberately: what is under test is whether the
/// callback is ENTERED, and a reap that also unwinds would let a passing cell be read as a claim
/// about containment instead. The quarantine is armed entirely by the staging above, through a
/// different callback, which is the whole point.
///
/// What is NOT skipped is asserted with it, because a bound that also wedged the teardown would be
/// no trade at all: the seam is still entered ahead of the reaps, every pending barrier still reads
/// Closed, and the read plane is still emptied for a retained [`WatchView`]. The gate declines to
/// ASK the source for things; it never declines to finish.
///
/// FAIL-ON-REVERT: route the destructor's loop through [`call_source`](super::call_source) and the
/// three cookies are reaped over a plane the caller already drove to its bound — the loop is once
/// more able to forget a payload per cookie, up to `MAX_PENDING_SYNCS` of them in a single
/// destructor. Route the release through `call_source` instead and the staging's second orphan
/// re-enters `disarm`, which is the same bound going away one function earlier.
#[tokio::test]
async fn a_quarantine_armed_on_a_live_path_also_stops_the_destructors_cookie_reap() {
  let mut h = Harness::new();

  // Every root this cell needs is armed FIRST, while the plane is still open: the quarantine
  // refuses new acquisition as well as declining reclamation
  // ([`forgotten`](super::SourceDisposals::forgotten)), so a watch issued after the staging below
  // would be refused rather than armed. The subject here is what the latch does to the CALLBACKS,
  // and the population it acts on is whatever existed when it was set.
  let doomed = h
    .watch("/gone-1", Interest::all())
    .await
    .expect("watch /gone-1");
  let quarantined = h
    .watch("/gone-2", Interest::all())
    .await
    .expect("watch /gone-2");
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a");
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");

  // STAGING, in two halves. First: arm the quarantine on a LIVE path, through the release primitive
  // a caller drives. Contained here so a reverted boundary fails an assertion rather than the cell.
  let root_doomed = h
    .owner
    .subsumer
    .subscription_root(doomed)
    .expect("live root for /gone-1");
  h.owner.source.panic_disarm(root_doomed, Boom::Hostile);
  let seam = h.owner.source.seam();
  let armed_at = disarms(&seam);
  let applied = tributary_proto::unwind::contain(|| {
    h.owner.apply_cleanup(super::Cleanup::DropOrphan(doomed));
  });
  assert!(
    applied.is_ok(),
    "staging: a panicking `Source::disarm` must not leave the release that issued it"
  );
  assert_eq!(
    disarms(&seam) - armed_at,
    1,
    "staging: the release that ARMS the quarantine is itself entered — the latch is set by its \
     disposal, not ahead of it"
  );

  // Second: a disjoint root released with the plane already shut, which must enter no callback at
  // all. This is the OPTIONAL half of the split, and it is what gives the mandatory half below
  // something to contrast with.
  h.owner
    .apply_cleanup(super::Cleanup::DropOrphan(quarantined));
  assert_eq!(
    disarms(&seam) - armed_at,
    1,
    "a quarantined plane issues NO further release — the optional callback is not entered, which is \
     the whole bound"
  );

  // THE CLAIM: three cookies still pending when the owner is destroyed, on the root armed above.
  // None of their leaves is a panicking one — whether the callback is ENTERED is the question, and
  // an unwinding reap would blur it into a containment claim.
  let mut replies = Vec::new();
  for leaf in ["/a/cookie-1", "/a/cookie-2", "/a/cookie-3"] {
    let (reply_tx, reply_rx) = futures_channel::oneshot::channel();
    replies.push(reply_rx);
    h.owner.pending_syncs.push(super::PendingSync {
      cookie_key: key(leaf),
      sub: sa,
      root: root_a,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: reply_tx,
    });
  }
  // A view taken while the sub is live, so the destructor's read-plane guarantee can be read after
  // the owner is gone: the gate must not cost the teardown any of the work it is FOR.
  let view = h.owner.subsumer.view();
  let before = seam.calls().len();

  // The teardown guard: it enters the seam, then reaps. Only the first is mandatory, so only the
  // first ignores the latch the staging above set.
  drop(h);

  assert_eq!(
    &seam.calls()[before..],
    &[SourceCall::BeginClose],
    "the seam entry is MANDATORY and still made, while the reap behind it is OPTIONAL and is not: \
     a quarantine armed through `disarm` on a live path reaches `end_sync` in the destructor, which \
     is one plane rather than one callback"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once however the plane behind it behaves"
  );
  assert!(
    !view.is_watched(&key("/a")),
    "and the teardown still FINISHED: the read plane is emptied for a retained view exactly as it \
     is over an open plane — the gate declines to ask the source for things, never to complete"
  );
  for reply in replies {
    assert!(
      reply.await.is_err(),
      "a barrier still pending at teardown reads as Closed, reaped or skipped — nothing waits on a \
       request the quarantine declined to issue"
    );
  }
}

/// The OTHER half of the quarantine, and the half that makes the first one a bound: a quarantined
/// plane refuses new caller-initiated ACQUISITION, so the resource set it retains cannot grow past
/// what existed when the latch was set.
///
/// # Why declining to reclaim was not, on its own, a bound
///
/// A plane that stops issuing [`Source::disarm`] and [`Source::end_sync`] but keeps serving
/// `watch` and `sync` has not capped anything — it has changed which resource leaks. Every cycle of
/// watch-and-unwatch arms a kernel watch nothing releases; every sequential barrier writes a marker
/// file nothing unlinks. Neither is bounded by anything in this crate:
/// [`MAX_PENDING_SYNCS`](super::MAX_PENDING_SYNCS) caps how many barriers are OUTSTANDING at once,
/// which a caller that lets each one resolve before asking for the next never approaches, and there
/// is no cap at all on roots. "The source still knows about it and will free it at its own `Drop`"
/// is not an answer, because the caller decides when the owner is dropped and may never do it.
///
/// So the latch refuses both acquisitions, each with a variant of its own that says the condition
/// never clears ([`WatchError::SourceRetired`], [`SyncError::SourceRetired`]) — and this cell drives
/// `CYCLES` of both against a plane that quarantined with a known population, then reads that
/// population back.
///
/// # What is asserted, and why each reading is the one that would move
///
/// - **the refusals** are ordinary error returns, per cycle. A refusal that hung, or that dropped
///   the reply, would be a wedge dressed as a bound.
/// - **arms** and **live roots** are unchanged across every cycle. Counting arms catches a watch
///   that was admitted and then failed for some unrelated reason; counting live roots catches the
///   whole trade — the roots released during the cycles are NOT reclaimed either, so the set does
///   not shrink and must not grow.
/// - **cookies ever written** (`begun_syncs`, not the pending count) is the reading the in-flight
///   cap cannot make. A caller that drops each barrier before asking for the next keeps
///   `pending_syncs` at zero forever while writing one file per request, so the pending map is
///   exactly the wrong population to measure here.
/// - **releases still work, and delivery still works.** The fence refuses GROWTH; a watcher that
///   also stopped retiring subscriptions or stopped fanning events out would have been retired, not
///   quarantined.
///
/// The releases are driven from a pool armed BEFORE the quarantine, because that is the only churn
/// a caller has left: the acquisition half of a watch/unwatch cycle is what this fence refuses, so
/// the population a caller can churn is fixed at the moment the latch is set — which is the property
/// under test, stated as the staging.
///
/// FAIL-ON-REVERT: delete either gate. Without the watch gate the arm count and the live-root count
/// both climb by `CYCLES`; without the sync gate `begun_syncs` climbs by `CYCLES`, one marker file
/// per cycle, with nothing left that ever unlinks one.
#[tokio::test]
async fn a_quarantined_plane_refuses_new_acquisition_so_its_retained_set_cannot_grow() {
  use futures_util::FutureExt;

  /// Enough cycles that growth of one resource per cycle is unmistakable against none.
  const CYCLES: usize = 32;

  let mut h = Harness::new();
  // Without this the barrier would be refused `Unsupported` and the sync half of the cell would
  // pass over a source that could never have written a cookie in the first place.
  h.owner.source.supports_sync = true;

  // The population established while the plane is still OPEN: the root the quarantine is armed
  // through, the survivor every refused barrier is asked against, and the pool the cycles release.
  let doomed = h
    .watch("/gone", Interest::all())
    .await
    .expect("watch /gone");
  let served = h
    .watch("/served", Interest::all())
    .await
    .expect("watch /served");
  let root_served = h
    .owner
    .subsumer
    .subscription_root(served)
    .expect("live root for /served");
  let mut pool = Vec::new();
  for cycle in 0..CYCLES {
    let path = format!("/pool-{cycle}");
    pool.push(
      h.watch(&path, Interest::all())
        .await
        .expect("watch the pooled root"),
    );
  }

  // ARM the quarantine through the live release primitive, with a payload the disposal has to
  // forget. Contained so a reverted boundary fails an assertion rather than the cell.
  let root_doomed = h
    .owner
    .subsumer
    .subscription_root(doomed)
    .expect("live root for /gone");
  h.owner.source.panic_disarm(root_doomed, Boom::Hostile);
  let seam = h.owner.source.seam();
  let armed = tributary_proto::unwind::contain(|| {
    h.owner.apply_cleanup(super::Cleanup::DropOrphan(doomed));
  });
  assert!(
    armed.is_ok(),
    "staging: a panicking `Source::disarm` must not leave the release that issued it"
  );
  assert_eq!(
    seam.begin_closes(),
    0,
    "staging: the quarantine is armed on a LIVE path — nothing here is a teardown"
  );

  // THE SNAPSHOT: what the source holds at the instant the latch is set. Everything below is read
  // against these three numbers.
  let roots_at_quarantine = h.owner.source.live_root_count();
  let arms_at_quarantine = h.owner.source.arm_count();
  let cookies_at_quarantine = h.owner.source.begun_syncs;

  for (cycle, pooled) in pool.into_iter().enumerate() {
    let path = format!("/post-{cycle}");
    let watched = h.watch(&path, Interest::all()).await;
    assert!(
      matches!(watched, Err(WatchError::SourceRetired)),
      "cycle {cycle}: a quarantined plane refuses a NEW watch rather than arming a root nothing \
       will ever release: {watched:?}"
    );

    let (reply_tx, reply_rx) = futures_channel::oneshot::channel();
    h.owner.on_sync(served, 0, reply_tx).await;
    // Read WITHOUT awaiting, deliberately: a refusal is answered on the spot, so a reply that is
    // not ready ALREADY means the barrier was admitted and parked behind a cookie. Awaiting it
    // would hang on that cookie instead of reporting it.
    let answered = reply_rx.now_or_never();
    assert!(
      matches!(
        answered,
        Some(Ok(Err(crate::error::SyncError::SourceRetired)))
      ),
      "cycle {cycle}: a quarantined plane refuses a NEW barrier rather than writing a cookie \
       nothing will ever reap — and ANSWERS the caller on the spot rather than parking it or \
       dropping its reply: {answered:?}"
    );
    assert!(
      h.owner.pending_syncs.is_empty(),
      "cycle {cycle}: a refused barrier leaves no pending entry — it is refused ahead of the write, \
       so no marker exists to be reaped"
    );

    // The release half still works: a caller can always shed state. What it cannot do is take more
    // on, which is why the retained set below does not move in either direction.
    h.owner.apply_cleanup(super::Cleanup::DropOrphan(pooled));
    assert_eq!(
      h.owner.source.live_root_count(),
      roots_at_quarantine,
      "cycle {cycle}: the retained root set moved — a quarantined plane neither reclaims what it \
       holds nor acquires anything new"
    );
  }

  assert_eq!(
    h.owner.source.arm_count(),
    arms_at_quarantine,
    "not one arm was issued across {CYCLES} refused watches"
  );
  assert_eq!(
    h.owner.source.begun_syncs, cookies_at_quarantine,
    "not one cookie was written across {CYCLES} refused barriers — the reading the in-flight cap \
     cannot make, since sequential barriers never approach it"
  );
  assert_eq!(
    h.owner.source.live_root_count(),
    roots_at_quarantine,
    "the retained set is exactly what existed when the quarantine armed, which is what makes it a \
     bound rather than a change of leak"
  );

  // And the watcher is still a watcher: what it already had is still served.
  h.owner
    .fan_out_and_push(&source_modified(root_served, "/served/f", 0));
  let delivered = h.drain();
  assert!(
    delivered.iter().any(|event| event.subscription() == served),
    "a quarantined plane still DELIVERS to the subscriptions it already had — the fence refuses \
     growth, it does not retire the watcher: {delivered:?}"
  );
}

/// The one acquisition the fence deliberately does NOT stand in front of, and the reason it does
/// not: a failed widen's [`restore_disarmed_roots`](Owner::restore_disarmed_roots), whose per-root
/// domination reaps a cookie through [`offer_source`](super::offer_source). A reap handed a payload
/// the disposal must FORGET sets [`forgotten`](super::SourceDisposals::forgotten) partway through
/// the restore's loop, with released roots still awaiting their re-arm — and the loop does not
/// re-read the latch, so it arms them exactly as it armed the roots ahead of the reap.
///
/// Being outside the fence is structural here rather than a check this loop skips: the re-arm is
/// issued by [`rearm_racing_close`](Owner::rearm_racing_close), which calls [`Source::arm`]
/// directly, while the fenced [`arm`](Owner::arm) is the caller-acquisition primitive.
/// [`a_quarantine_armed_mid_widen_refuses_the_wider_arm_and_the_restore_puts_every_root_back`] is
/// the same staging one step earlier, where the acquisition IS a caller's and IS refused — the two
/// together are what say the fence separates the caller's growth from the reconcile's own repair.
///
/// [`a_quarantined_plane_refuses_new_acquisition_so_its_retained_set_cannot_grow`] arms the same
/// latch OUTSIDE any reconcile, which is why it cannot see this: there, every acquisition after the
/// latch is a caller's and every one of them is refused. Here the latch arms while the owner is
/// mid-reconcile and the acquisitions behind it are the reconcile's own.
///
/// # Why the restore keeps re-arming, and what the latch bounds instead
///
/// Reading the latch as a hard instant-snapshot — retire the released roots this restore has not
/// reached rather than re-arm them — would reintroduce the exact defect the release-and-rearm
/// restore exists to prevent, under a new trigger: a widen's failure would take down HEALTHY
/// established roots on a condition that says nothing about them, here one hostile `end_sync`
/// against one unrelated subscription's barrier. A failed widen must not cost coverage for the
/// roots that were fine.
///
/// So the restore continues, and what the latch guarantees is a POPULATION bound rather than an
/// instant snapshot: the restore re-arms only roots this same reconcile released, at most one per
/// released entry, so what a quarantined owner retains never passes the pre-widen root population.
/// The excursion is also unrepeatable. A widen is initiated by a caller `watch`, every one of them
/// reaches it through [`reconcile_watch`](Owner::reconcile_watch)'s entry gate, and the owner runs
/// one reconcile at a time — so once the latch is set no second widen can ever begin. The
/// load-bearing property is therefore untouched: nothing a caller does raises the bound.
///
/// # What is asserted, and why each reading is the one that would move
///
/// - **the latch armed, and armed MID-restore.** The ledger puts the hostile reap BETWEEN the first
///   restored root's re-arm and the two behind it. A cell that armed the latch before the widen
///   would be the churn cell again, measuring a population no restore was holding.
/// - **the roots behind the reap are still re-armed**, one [`Source::arm`] per released entry and in
///   order. That is the behaviour being kept, and the ordered ledger is the only reading that pins
///   both halves of it — that they happen, and that they happen after the latch.
/// - **every pre-widen subscription still names a LIVE root.** Counting arms alone would survive a
///   restore that re-armed and then retired; this is the reading that says coverage was kept.
/// - **the live root count is EXACTLY the pre-widen population** — not larger, since the restore
///   re-arms nothing the widen did not release, and not smaller, since no healthy root was retired
///   for a condition unrelated to it. Both directions are the claim, so it is an equality.
/// - **a fresh caller watch is refused.** What the fence makes true is that this excursion is one
///   in-flight widen's tail rather than a channel a caller can drive again.
///
/// FAIL-ON-REVERT: give the restore the literal instant-snapshot reading — re-check the latch after
/// the domination and retire the released roots it has not reached instead of re-arming them. The
/// two roots behind the hostile reap then never arm again: the ordered ledger loses their re-arms,
/// their subscriptions stop naming a live root, and the live root count falls to one.
#[tokio::test]
async fn a_quarantine_armed_mid_restore_still_re_arms_within_the_pre_widen_population() {
  use futures_util::FutureExt;

  let mut h = Harness::new();

  // The pre-widen population: three disjoint roots one `watch` of `/a` subsumes and releases
  // together, so the restore has roots BEHIND the one whose domination arms the latch.
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  let sd = h.watch("/a/d", Interest::all()).await.expect("watch /a/d"); // handle 3
  let roots_before_widen = h.owner.source.live_root_count();
  let arms_before_widen = h.owner.source.arm_count();
  assert_eq!(
    (roots_before_widen, arms_before_widen),
    (3, 3),
    "staging: three disjoint roots, one arm each"
  );

  // The barrier whose domination arms the latch. It rides the FIRST root the restore reaches, so
  // two released roots are still behind it when the reap unwinds; its receiver is HELD, so nothing
  // prunes it out from under the restore.
  let root_b = h
    .owner
    .subsumer
    .subscription_root(sb)
    .expect("live root for /a/b");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/b/cookie-restore-boom"),
    sub: sb,
    root: root_b,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The wider arm fails AFTER the three roots are released, which is the only way into the restore.
  h.owner.source.fail_next_arm();
  // The seam reads the whole ledger, staging included, so the assertion below is total rather than
  // a suffix — nothing can be inserted ahead of the widen without being seen.
  let seam = h.owner.source.seam();
  let widened = h.watch("/a", Interest::all()).await;
  assert!(
    widened.is_err(),
    "staging: the widen must FAIL past its disarms — a committed widen never restores: {widened:?}"
  );

  assert!(
    h.owner.source_disposals.quarantined(),
    "staging: the restore's own domination reap forgot its payload, so the plane is quarantined — \
     and it was armed from inside a reconcile that went on running"
  );

  // THE ORDER, total and in sequence. The hostile reap sits between the first restored root's
  // re-arm and the two behind it: the latch was already set when `/a/c` and `/a/d` were armed.
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/a/c")),
      SourceCall::Arm(PathBuf::from("/a/c")),
      SourceCall::RootKey(2),
      SourceCall::CanonicalizeKey(key("/a/d")),
      SourceCall::Arm(PathBuf::from("/a/d")),
      SourceCall::RootKey(3),
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Disarm(1),
      SourceCall::Disarm(2),
      SourceCall::Disarm(3),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(4),
      SourceCall::EndSync(key("/a/b/cookie-restore-boom")),
      SourceCall::Arm(PathBuf::from("/a/c")),
      SourceCall::RootKey(5),
      SourceCall::Arm(PathBuf::from("/a/d")),
      SourceCall::RootKey(6),
    ],
    "the restore re-arms every root the widen released, in order, and keeps doing so after its own \
     domination reap has quarantined the plane"
  );

  // Coverage was KEPT, which is the half an arm count cannot state: each pre-widen subscription
  // still names a root the source itself holds live.
  for (sub, path) in [(sb, "/a/b"), (sc, "/a/c"), (sd, "/a/d")] {
    let root = h
      .owner
      .subsumer
      .subscription_root(sub)
      .unwrap_or_else(|| panic!("{path} is still recorded on a root after the restore"));
    assert!(
      h.owner.source.root_key(root).is_some(),
      "{path} names a root the SOURCE still holds — a restore that retired it on the quarantine \
       would have cost coverage for a root nothing was wrong with"
    );
  }

  assert_eq!(
    h.owner.source.arm_count(),
    arms_before_widen + 1 + roots_before_widen,
    "the wider arm that failed, then exactly ONE re-arm per released root — which is what caps the \
     excursion at the pre-widen population rather than at anything a caller chose"
  );
  assert_eq!(
    h.owner.source.live_root_count(),
    roots_before_widen,
    "what the quarantined owner retains is EXACTLY the pre-widen root population: the restore adds \
     nothing the widen did not release, and retires nothing the widen would have kept"
  );

  // Read WITHOUT awaiting: the domination answers on the spot, so a reply that is not ready already
  // means the barrier is parked behind a cookie no quarantined plane will ever reap.
  let answered = sync_response.now_or_never();
  assert!(
    matches!(
      answered,
      Some(Ok(Ok(crate::source::SyncOutcome::Dominated)))
    ),
    "the barrier the hostile reap belonged to is still answered Dominated — the containment decides \
     how far the unwind travels, never what the caller is told: {answered:?}"
  );

  // And the excursion is over with the reconcile: the next acquisition is a CALLER's, and the fence
  // is what makes this a one-time tail rather than a channel that can be driven again.
  let after = h.watch("/e", Interest::all()).await;
  assert!(
    matches!(after, Err(WatchError::SourceRetired)),
    "a widen cannot even BEGIN past the latch, so no second restore can ever straddle it: {after:?}"
  );
  assert_eq!(
    h.owner.source.live_root_count(),
    roots_before_widen,
    "and the refused watch armed nothing"
  );
}

/// The bypass an ENTRY gate cannot close, driven end to end: a reconcile that passed the gate arms
/// the quarantine ITSELF and then reaches an acquisition, with nothing between the two that re-reads
/// the latch.
///
/// The [`Covered`](super::WatchOutcome::Covered) re-plan is the loop that does it. A newcomer under
/// a covering root the source has already forgotten is not committed against that dead handle: the
/// root is retired first ([`retire_root_with_terminal_rescan`](Owner::retire_root_with_terminal_rescan)),
/// which dominates every barrier it owed, and each domination reaps a cookie through
/// [`offer_source`](super::offer_source). A reap whose payload the disposal must FORGET sets
/// [`forgotten`](super::SourceDisposals::forgotten) right there — and the loop then re-plans and
/// carries on, because retiring the dead root is what it came to do and a plan re-taken after it is
/// the whole point of the loop.
///
/// The re-plan classifies [`Disjoint`](super::WatchOutcome::Disjoint) and asks for a FRESH root. On
/// a gate-only fence that arm was issued: the watch succeeded past the owner's own source
/// retirement, and because the eventual `unwatch` skips its [`Source::disarm`] on the same
/// quarantined plane, the root it armed was held until the owner was dropped. That is the retained
/// set growing after the latch — precisely what the fence exists to forbid, reached by a caller who
/// only had to `watch` a path under a dead root.
///
/// # Why re-reading the gate here would have been the wrong fix
///
/// It closes this loop and leaves the next one to remember. This is the SECOND place a reconcile has
/// been found arming the latch behind a gate it already passed —
/// [`a_quarantine_armed_mid_restore_still_re_arms_within_the_pre_widen_population`] is the first —
/// so the refusal moved to the two primitives that ACQUIRE, [`arm`](Owner::arm) and
/// [`grow`](Owner::grow). Every caller-initiated acquisition passes through one of them, so no loop
/// written later can acquire by forgetting a check, and the entry gate is kept for what it is good
/// at: refusing earlier, cheaper, and before anything is planned.
///
/// # What is asserted, and why each reading is the one that would move
///
/// - **the latch armed, and armed by the RE-PLAN's own reap.** Without that the cell is testing the
///   entry gate again, which was never in doubt.
/// - **not one [`Source::arm`]**, read as an ordered ledger rather than a count, so the reading also
///   says nothing was armed and then released to make the count come out.
/// - **the watch is refused [`SourceRetired`](WatchError::SourceRetired)** — the same variant the
///   entry gate reports, so a caller cannot tell which half of the fence answered it.
/// - **the dead root still left the index**, and its subscriber is still owed its dominating
///   terminal `Rescan`. The refusal must cost the retirement nothing: a fence that also abandoned
///   the dead-root cleanup would trade one defect for another.
/// - **the barrier is still answered `Dominated`.** The containment decides how far an unwind
///   travels, never what a caller is told.
///
/// FAIL-ON-REVERT: delete the refusal at the top of [`arm`](Owner::arm). The re-planned `Disjoint`
/// arm is issued and succeeds, so the ledger gains `Arm("/a/b")` + its liveness `RootKey`, the arm
/// count climbs by one, the source holds a live root it will never be asked to release, and the
/// watch returns `Ok` instead of `SourceRetired`.
#[tokio::test]
async fn a_quarantine_armed_by_a_dead_covering_roots_reap_refuses_the_replanned_arm() {
  use futures_util::FutureExt;

  let mut h = Harness::new();
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let root = h
    .owner
    .subsumer
    .subscription_root(sub)
    .expect("live root for /a");

  // The barrier whose domination arms the latch. Its receiver is HELD, so nothing prunes it out
  // from under the retirement the re-plan is about to perform.
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-covered-boom"),
    sub,
    root,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The covering root dies out of band — `root_key` answers `None` — with its terminal event NOT
  // yet consumed, so it is still RECORDED. That is the state the command-biased loop leaves a
  // queued `watch` to find, and the only state the `Covered` re-plan is reached from.
  h.owner.source.kill_root(root);
  assert!(
    !h.owner.source_disposals.quarantined(),
    "staging: the plane is still OPEN when the watch is issued — the latch is armed by the \
     reconcile itself, not before it"
  );
  let seam = h.owner.source.seam();
  let arms_before = h.owner.source.arm_count();

  // A watch of a path the dead root would cover: `Covered` against a dead handle → retire → reap →
  // LATCH → re-plan → `Disjoint` → an arm that must now be refused.
  let refused = h.watch("/a/b", Interest::all()).await;

  assert!(
    h.owner.source_disposals.quarantined(),
    "staging: the re-plan's own domination reap forgot its payload, so the latch armed INSIDE a \
     reconcile that had already passed the entry gate"
  );
  assert!(
    matches!(refused, Err(WatchError::SourceRetired)),
    "an acquisition behind a latch this very reconcile armed is refused with the same variant the \
     entry gate reports: {refused:?}"
  );

  // THE ORDER, total and in sequence — the seam reads the whole ledger, staging included, so this
  // is not a suffix that something could be inserted ahead of. The liveness probe finds the
  // covering root dead, the retirement reaps its cookie — and NOTHING follows: no arm was issued
  // for the re-planned `Disjoint` newcomer.
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::RootKey(root),
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::RootKey(root),
      SourceCall::EndSync(key("/a/cookie-covered-boom")),
    ],
    "the reconcile retires the dead root and stops there — the fence at the acquisition primitive \
     is what the re-plan cannot walk past"
  );
  assert_eq!(
    h.owner.source.arm_count(),
    arms_before,
    "not one arm was issued behind the latch this reconcile armed"
  );

  // The refusal cost the retirement nothing: the dead root left the index, its subscriber's state
  // was freed, and the dominating terminal `Rescan` it is owed is durably parked.
  assert_eq!(
    h.owner.subsumer.roots().count(),
    0,
    "the dead root is still retired — the fence refuses the ACQUISITION, never the cleanup"
  );
  assert!(
    h.owner.needs_rescan.contains_key(&sub),
    "…and its subscriber is still owed the dominating terminal Rescan (no silent loss)"
  );

  // Read WITHOUT awaiting: the domination answers on the spot, so a reply that is not ready already
  // means the barrier is parked behind a cookie no quarantined plane will ever reap.
  let answered = sync_response.now_or_never();
  assert!(
    matches!(
      answered,
      Some(Ok(Ok(crate::source::SyncOutcome::Dominated)))
    ),
    "the barrier the hostile reap belonged to is still answered Dominated: {answered:?}"
  );
}

/// The same fence one step further in, where refusing has to UNDO rather than merely decline: a
/// latch armed behind the entry gate refuses the WIDER arm, so the widen fails after it has already
/// released its subsumed roots — and [`restore_disarmed_roots`](Owner::restore_disarmed_roots) puts
/// every one of them back.
///
/// # Why the reconcile body is entered directly
///
/// Because [`reconcile_watch`](Owner::reconcile_watch)'s entry gate is exactly what a real caller
/// passes on its way in, and the state under test is what that body is left in when the latch arms
/// BEHIND it. Driving `watch` with the latch already set would test the entry gate — which is not in
/// question — and no in-crate act arms the latch between a widen's disarms and its arm: the
/// `Covered` re-plan (the vehicle
/// [`a_quarantine_armed_by_a_dead_covering_roots_reap_refuses_the_replanned_arm`] uses) cannot
/// produce a [`Widen`](super::WatchOutcome::Widen), since a dead covering root is an ANCESTOR of the
/// newcomer and the index is pairwise disjoint, so no other root can lie under it. So the latch is
/// armed the way a caller genuinely arms it — a live release whose [`Source::disarm`] panics with a
/// payload the disposal must forget — and the reconcile body is then entered as the gate leaves it.
///
/// # What is asserted, and why each reading is the one that would move
///
/// - **the wider arm is NEVER issued**, read off the ordered ledger. This is the acquisition; a
///   count alone would not say the disarms happened first.
/// - **every released root is re-armed**, one per released entry and in order. The restore reaches
///   [`Source::arm`] through [`rearm_racing_close`](Owner::rearm_racing_close) rather than the
///   fenced [`arm`](Owner::arm), which is what keeps the refusal from costing coverage.
/// - **every pre-widen subscription still names a LIVE root**, and the live root count is exactly
///   what it was. Not larger, since nothing new was acquired; not smaller, since nothing healthy
///   was retired.
/// - **nothing was committed**: the caller's admission gate is still in the reconcile's slot, so no
///   subscription was installed against a plan that failed.
///
/// FAIL-ON-REVERT: delete the refusal at the top of [`arm`](Owner::arm). The wider arm is issued and
/// SUCCEEDS, so `Arm("/a")` appears on the ledger, the widen COMMITS — three roots collapse to one,
/// the three re-arms never happen, the gate is taken out of its slot — and the reconcile returns
/// `Ok` on a plane that will never release the root it just took.
#[tokio::test]
async fn a_quarantine_armed_mid_widen_refuses_the_wider_arm_and_the_restore_puts_every_root_back() {
  let mut h = Harness::new();

  // The pre-widen population: three disjoint roots one `watch` of `/a` subsumes and releases
  // together, so the refusal lands with released roots owed a restore.
  let sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b"); // handle 1
  let sc = h.watch("/a/c", Interest::all()).await.expect("watch /a/c"); // handle 2
  let sd = h.watch("/a/d", Interest::all()).await.expect("watch /a/d"); // handle 3

  // ARM the latch the way a caller can: a live release whose `disarm` unwinds with a payload the
  // disposal has to forget. Contained so a reverted boundary fails an assertion, not the cell.
  let doomed = h
    .watch("/gone", Interest::all())
    .await
    .expect("watch /gone"); // handle 4
  let root_doomed = h
    .owner
    .subsumer
    .subscription_root(doomed)
    .expect("live root for /gone");
  h.owner.source.panic_disarm(root_doomed, Boom::Hostile);
  let armed = tributary_proto::unwind::contain(|| {
    h.owner.apply_cleanup(super::Cleanup::DropOrphan(doomed));
  });
  assert!(
    armed.is_ok(),
    "staging: a panicking `Source::disarm` must not leave the release that issued it"
  );
  assert!(
    h.owner.source_disposals.quarantined(),
    "staging: the plane is quarantined before the reconcile body is entered"
  );

  let seam = h.owner.source.seam();
  let roots_at_quarantine = h.owner.source.live_root_count();
  let arms_at_quarantine = h.owner.source.arm_count();

  // The reconcile body the entry gate admits, entered with the latch set — see this cell's note.
  let mut gate = Some(Filter::all());
  let widened = h
    .owner
    .reconcile_canonical_watch(
      &key("/a"),
      &(),
      Interest::all(),
      &mut gate,
      Debounce::Inherit,
    )
    .await;

  assert!(
    matches!(
      widened,
      Err(super::ReconcileStop::Failed(WatchError::SourceRetired))
    ),
    "the wider arm is refused, so the widen fails as an ordinary failed arm does — the shape every \
     caller already unwinds through: {widened:?}"
  );
  assert!(
    gate.is_some(),
    "nothing committed, so the caller's admission gate is still in the reconcile's slot"
  );

  // THE ORDER, total and in sequence — the seam reads the whole ledger, staging included, so the
  // wider arm's absence is a statement about every call the owner made rather than about a window.
  // The three disarms the widen owes, then NO `Arm("/a")`, then one re-arm per released root.
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/a/c")),
      SourceCall::Arm(PathBuf::from("/a/c")),
      SourceCall::RootKey(2),
      SourceCall::CanonicalizeKey(key("/a/d")),
      SourceCall::Arm(PathBuf::from("/a/d")),
      SourceCall::RootKey(3),
      SourceCall::CanonicalizeKey(key("/gone")),
      SourceCall::Arm(PathBuf::from("/gone")),
      SourceCall::RootKey(4),
      SourceCall::Disarm(4),
      SourceCall::Disarm(1),
      SourceCall::Disarm(2),
      SourceCall::Disarm(3),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(5),
      SourceCall::Arm(PathBuf::from("/a/c")),
      SourceCall::RootKey(6),
      SourceCall::Arm(PathBuf::from("/a/d")),
      SourceCall::RootKey(7),
    ],
    "the widen releases, is refused its acquisition, and restores exactly what it released — never \
     the wider root"
  );

  // Coverage was KEPT, which is the half an arm count cannot state: each pre-widen subscription
  // still names a root the source itself holds live.
  for (sub, path) in [(sb, "/a/b"), (sc, "/a/c"), (sd, "/a/d")] {
    let root = h
      .owner
      .subsumer
      .subscription_root(sub)
      .unwrap_or_else(|| panic!("{path} is still recorded on a root after the restore"));
    assert!(
      h.owner.source.root_key(root).is_some(),
      "{path} names a root the SOURCE still holds — a refusal that cost coverage would be a wedge \
       in place of a bound"
    );
  }
  assert_eq!(
    h.owner.source.arm_count(),
    arms_at_quarantine + 3,
    "exactly one re-arm per released root, and not one acquisition — the wider arm never happened"
  );
  assert_eq!(
    h.owner.source.live_root_count(),
    roots_at_quarantine,
    "the retained set is exactly what it was when the latch armed: nothing acquired, nothing \
     healthy retired"
  );
}

/// The fence's other primitive, on the one path that acquires WITHOUT minting a handle: a `Covered`
/// newcomer under a root an earlier prune narrowed below its key must be grown back before it is
/// committed, and a latch armed behind the entry gate refuses that [`grow`](Owner::grow).
///
/// # Why a grow is an acquisition at all
///
/// It mints no handle, so the retained ROOT count does not move — which is exactly why it had to be
/// argued rather than assumed. What it takes is kernel coverage the owner previously gave back, and
/// the only thing that ever narrows a root again is [`Source::set_cover`], an OPTIONAL callback a
/// quarantined plane never issues. So a grow admitted behind the latch broadens a root permanently,
/// and the subscription committed behind it is one whose release cannot even ask for the prune back.
///
/// [`Source::replace`] is the deliberate contrast and the reason this one is fenced while that one
/// is not: a retarget preserves the handle, so the [`Source::disarm`] already owed for that root
/// still discharges everything it holds and the live root count is unchanged across it.
///
/// The reconcile body is entered directly for the reason given on
/// [`a_quarantine_armed_mid_widen_refuses_the_wider_arm_and_the_restore_puts_every_root_back`]: the
/// entry gate is what a caller passes, and the state under test is the body behind it.
///
/// # What is asserted, and why each reading is the one that would move
///
/// - **no [`Source::grow`] is issued**, read off the ordered ledger.
/// - **the retained-cover record did not broaden**, and the source's actual coverage still excludes
///   the newcomer's subtree. A refused grow that recorded coverage anyway would leave the NEXT
///   newcomer classifying inside a cover that does not exist — the silent-loss direction R1 exists
///   to forbid.
/// - **nothing was committed**: the newcomer is not watched and the caller's gate is still in its
///   slot.
///
/// FAIL-ON-REVERT: delete the refusal at the top of [`grow`](Owner::grow). `Grow(wide, {/a/b,
/// /a/c})` appears on the ledger, the record broadens to include `/a/c`, and the reconcile commits a
/// subscription over coverage the owner can no longer ever reclaim.
#[tokio::test]
async fn a_quarantine_armed_mid_reconcile_refuses_a_covered_newcomers_grow() {
  let mut h = Harness::new();

  // Narrow the wide `/a` root to {/a/b}: widen `/a` over `/a/b`, then drop the widening `/a`
  // (PRUNE). Done while the plane is still OPEN, because the prune itself is an optional callback a
  // quarantined plane would decline.
  let _sb = h.watch("/a/b", Interest::all()).await.expect("watch /a/b");
  let sa = h
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
  h.unwatch(sa).expect("unwatch the widening /a");
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b")]),
    "staging: the prune narrowed the record to {{/a/b}}"
  );

  // ARM the latch the way a caller can — see the widen cell's note.
  let doomed = h
    .watch("/gone", Interest::all())
    .await
    .expect("watch /gone");
  let root_doomed = h
    .owner
    .subsumer
    .subscription_root(doomed)
    .expect("live root for /gone");
  h.owner.source.panic_disarm(root_doomed, Boom::Hostile);
  let armed = tributary_proto::unwind::contain(|| {
    h.owner.apply_cleanup(super::Cleanup::DropOrphan(doomed));
  });
  assert!(
    armed.is_ok(),
    "staging: a panicking `Source::disarm` must not leave the release that issued it"
  );
  assert!(
    h.owner.source_disposals.quarantined(),
    "staging: the plane is quarantined before the reconcile body is entered"
  );

  let seam = h.owner.source.seam();
  let filters_before = h.owner.filters.len();

  // A `Covered`-OUTSIDE newcomer: `/a/c` lies under the wide root but outside its narrowed cover,
  // so committing it requires a grow first (grow-before-commit, R1).
  let mut gate = Some(Filter::all());
  let covered = h
    .owner
    .reconcile_canonical_watch(
      &key("/a/c"),
      &(),
      Interest::all(),
      &mut gate,
      Debounce::Inherit,
    )
    .await;

  assert!(
    matches!(
      covered,
      Err(super::ReconcileStop::Failed(WatchError::SourceRetired))
    ),
    "a grow behind the latch is refused, and the newcomer fails rather than committing over \
     coverage nothing will ever prune back: {covered:?}"
  );
  // THE ORDER, total and in sequence. The reconcile's LAST call is the `Covered` re-plan's liveness
  // probe on the wide root — the refusal stands between that probe and the grow, so no `Grow` was
  // ever issued.
  assert_eq!(
    seam.calls(),
    vec![
      SourceCall::CanonicalizeKey(key("/a/b")),
      SourceCall::Arm(PathBuf::from("/a/b")),
      SourceCall::RootKey(1),
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::RootKey(1),
      SourceCall::Disarm(1),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::RootKey(wide),
      SourceCall::SetCover(wide),
      SourceCall::CanonicalizeKey(key("/gone")),
      SourceCall::Arm(PathBuf::from("/gone")),
      SourceCall::RootKey(3),
      SourceCall::Disarm(3),
      SourceCall::RootKey(wide),
    ],
    "the newcomer's covering root is validated live and then nothing: the refusal stands ahead of \
     the grow, so the source is never asked to broaden anything"
  );

  // The record did NOT broaden, and the source's actual coverage is unchanged — so the next
  // newcomer under the pruned region still classifies outside-cover rather than inside a cover that
  // does not exist.
  assert_eq!(
    h.owner.subsumer.retained_cover_of(wide),
    Some(vec![key("/a/b")]),
    "a refused grow broadens nothing — the record still names the source's true coverage"
  );
  assert!(
    !h.owner.source.actual_covers(wide, &key("/a/c")),
    "the newcomer's subtree is NOT covered, which is what makes committing it a silent hole"
  );

  // And nothing was committed: no subscription, and the caller's gate never left its slot.
  assert!(
    gate.is_some(),
    "nothing committed, so the caller's admission gate is still in the reconcile's slot"
  );
  assert_eq!(
    h.owner.filters.len(),
    filters_before,
    "no subscription was installed behind the refused grow"
  );
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/a/c")),
    "…and the newcomer's key is not published as watched"
  );
}

/// The quarantined SKIP path destroys what it was handed, and it does so inside the boundary: a
/// pending cookie whose caller component destructor unwinds cannot escape a teardown that declined
/// to reap it.
///
/// # Why the skip path is where this bites
///
/// Every request on this plane arrives as a closure that has already CAPTURED what it was going to
/// hand the source. Declining to CALL it is not declining to DESTROY it, and
/// [`Owner::drop`]'s reap is the one offering site whose closure owns anything with a destructor at
/// all — a whole [`PendingSync`](super::PendingSync), the caller's own cookie key with it. The
/// other four capture a `Copy` [`Source::Handle`], a [`SyncToken`] of four integers, or a borrow.
///
/// Dropped bare on the way out of [`offer_source`](super::offer_source), that caller destructor
/// unwinds in the worst frame in the crate. This destructor also runs while the owner task is
/// UNWINDING — a panicking caller callback is precisely how it is reached — and a second unwind
/// there is not a contained failure but an immediate process ABORT, ahead of every remaining cookie
/// and with nothing reported about any of it. The whole point of the quarantine is that a
/// doubly-broken implementor costs memory rather than the process; a skip path that aborted would
/// have been the one way back in.
///
/// # What is asserted
///
/// The destructor really RUNS (the counter moves), which is what separates "contained" from
/// "silently skipped"; the teardown then completes in full — the MANDATORY seam entry is still
/// made, the read plane is still emptied for a retained [`WatchView`], and every parked barrier
/// still reads Closed. No reap appears behind the seam, because the plane is shut: that is the
/// declining half, and the destruction happening anyway is the half this cell is about.
///
/// The teardown reached here is [`Owner::drop`]'s, which is the ONLY path a still-pending cookie can
/// take to a skipped offer — [`run`]'s tail takes the map first
/// ([`reap_all_pending_syncs`](Owner::reap_all_pending_syncs)) and hands the key to the salvage
/// route rather than to the closure. That destructor is not given the close reply and cannot await,
/// so there is no `close()` verdict on this path to read; what testifies instead is the ledger and
/// the counter, and both are asserted.
///
/// FAIL-ON-REVERT: drop the disposal from [`offer_source`](super::offer_source)'s skip path — let
/// the closure fall out of scope — and the marked destructor unwinds out of `Owner::drop`, which
/// the cell's own boundary around the teardown then reports as a teardown that did not return.
#[tokio::test]
async fn a_quarantined_skip_contains_the_component_destructor_of_the_cookie_it_declined() {
  let mut rig = OwnerOverHostileKeys::new();

  // Two roots armed while the plane is open: the one the quarantine is armed through, and the one
  // the cookies ride.
  let doomed = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/gone", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /gone");
  let bearer = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /a");
  let root = rig
    .owner
    .subsumer
    .subscription_root(bearer)
    .expect("live root for /a");
  let ledger = rig.owner.source.ledger();

  // ARM the quarantine through a release whose payload the disposal has to forget.
  rig.owner.source.panic_every_disarm(Boom::Hostile);
  let armed = tributary_proto::unwind::contain(|| {
    rig.owner.apply_cleanup(super::Cleanup::DropOrphan(doomed));
  });
  assert!(
    armed.is_ok(),
    "staging: a panicking `Source::disarm` must not leave the release that issued it"
  );

  // Three cookies the destructor will decline to reap. The MARKED one carries a caller component
  // whose destructor unwinds; the other two are inert, so the ledger below reads as a claim about
  // entries rather than about which key happened to blow up.
  let mut replies = Vec::new();
  for (leaf, hostile) in [
    ("/a/cookie-1", false),
    ("/a/cookie-hostile", true),
    ("/a/cookie-3", false),
  ] {
    let (reply, response) = futures_channel::oneshot::channel();
    replies.push(response);
    rig.owner.pending_syncs.push(super::PendingSync {
      cookie_key: HostileComponent::key(leaf, hostile),
      sub: bearer,
      root,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply,
    });
  }

  // A view taken while the sub is live, so the destructor's read-plane guarantee can be read after
  // the owner is gone.
  let view = rig.owner.subsumer.view();
  let before = ledger.lock().expect("hostile ledger").len();
  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  // Armed LAST, so nothing the staging above destroyed can spend the one-shot.
  HOSTILE_COMPONENT_ARMED.set(true);

  // Contained HERE too, through [`contain`](tributary_proto::unwind::contain), so a REVERTED
  // funnel's escaping unwind is reported as a failed claim rather than taking the cell down before
  // a single assertion is read — and so its payload is retired inside a boundary rather than by the
  // failing assertion's own unwind.
  let torn = tributary_proto::unwind::contain(move || drop(rig));

  assert!(
    torn.is_ok(),
    "the teardown must RETURN: a declined request's destruction is the funnel's to contain, and an \
     unwind that leaves `Owner::drop` is the abort this whole plane exists to refuse"
  );
  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "the declined cookie was still DESTROYED — its caller component destructor ran, and unwound — \
     which is the half a skip path cannot decline"
  );
  assert_eq!(
    &ledger.lock().expect("hostile ledger")[before..],
    &[HostileCall::BeginClose],
    "the MANDATORY seam entry is still made and no reap is issued behind it: the plane declines to \
     ask, and the destruction it cannot decline is contained rather than escaping"
  );
  assert!(
    !view.is_watched(&HostileComponent::key("/a", false)),
    "and the teardown still FINISHED behind the contained unwind: the read plane is emptied for a \
     retained view exactly as it is over an open one"
  );
  for reply in replies {
    assert!(
      reply.await.is_err(),
      "a barrier still pending at teardown reads as Closed — reaped, skipped, or destroyed through \
       an unwind"
    );
  }
}

/// The PRICE of that containment, which is the term the bound gained: a payload a skipped offer's
/// disposal has to FORGET is leaked and counted exactly as a panicking call's is — one arbitrary
/// allocation, out of a request the source never even received.
///
/// # Why the unit has to be priced rather than reasoned about
///
/// [`a_quarantined_skip_contains_the_component_destructor_of_the_cookie_it_declined`] proves the
/// disposal is TOTAL, and it can prove nothing about cost: its payload is a bare
/// [`ForgottenPayload`], which mints nothing and so leaves nothing to measure. Containment is not
/// free here. The disposal runs through [`call_source`](super::call_source), so a caller destructor
/// that unwinds with a payload whose OWN destructor unwinds leaves that payload
/// [forgotten](tributary_proto::unwind::PayloadDisposal::Forgotten) — implementor-or-caller data of
/// any size, unreachable for the rest of the process — and the site that can produce one is a LOOP.
///
/// That is the term [`forgotten`](super::SourceDisposals::forgotten) now carries alongside its ten
/// fixed units, and it is why the bound is no longer a single small constant. This cell pins the
/// UNIT — one strand per declined request whose caller destructor is doubly hostile — while
/// [`a_quarantined_plane_refuses_new_acquisition_so_its_retained_set_cannot_grow`] pins the other
/// half of the arithmetic: the fence is what stops a caller replenishing the population the loop
/// runs over, so the term is `MAX_PENDING_SYNCS` rather than a function of how long the caller ran.
///
/// One marked cookie rather than all three, because the marking is one-shot
/// ([`HOSTILE_COMPONENT_ARMED`]) and must stay that way: a second unwind inside the same declined
/// entry's drop glue would abort the process rather than be contained, which is a property of drop
/// glue and not of this boundary. The unit is per REQUEST; the loop's ceiling is arithmetic.
///
/// FAIL-ON-REVERT: drop the disposal from [`offer_source`](super::offer_source)'s skip path and the
/// TEARDOWN no longer returns — the marked destructor's unwind leaves `Owner::drop` and is caught by
/// this cell's own boundary instead of the funnel's. That is the discriminating reading, and it is
/// asserted first, deliberately: the strand still books under the revert, because the cell's own
/// containment disposes of the payload the owner's should have. The count is the PRICE this cell
/// exists to state; the contained teardown is the CLAIM that makes the price a bound.
#[tokio::test]
async fn a_skipped_offer_that_forgets_a_payload_strands_exactly_one_allocation() {
  let mut rig = OwnerOverHostileKeys::new();

  let doomed = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/gone", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /gone");
  let bearer = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /a");
  let root = rig
    .owner
    .subsumer
    .subscription_root(bearer)
    .expect("live root for /a");

  rig.owner.source.panic_every_disarm(Boom::Hostile);
  let armed = tributary_proto::unwind::contain(|| {
    rig.owner.apply_cleanup(super::Cleanup::DropOrphan(doomed));
  });
  assert!(
    armed.is_ok(),
    "staging: a panicking `Source::disarm` must not leave the release that issued it"
  );

  let mut replies = Vec::new();
  for (leaf, hostile) in [
    ("/a/cookie-1", false),
    ("/a/cookie-costly", true),
    ("/a/cookie-3", false),
  ] {
    let (reply, response) = futures_channel::oneshot::channel();
    replies.push(response);
    rig.owner.pending_syncs.push(super::PendingSync {
      cookie_key: HostileComponent::key(leaf, hostile),
      sub: bearer,
      root,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply,
    });
  }

  let stranded_before = StrandedAllocation::stranded(SKIPPED_OFFER_STRANDED);
  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  // The marked destructor unwinds with a payload that MINTS a heap allocation and books it on the
  // way past, so the forget has a witness — see [`StrandedAllocation`]. Set together with the
  // arming, and cleared by the one-shot with it.
  HOSTILE_COMPONENT_COSTLY.set(Some(SKIPPED_OFFER_STRANDED));
  HOSTILE_COMPONENT_ARMED.set(true);

  // Contained for the reason its sibling's teardown is, and it is also the DISCRIMINATING reading
  // here — see the note above.
  let torn = tributary_proto::unwind::contain(move || drop(rig));

  assert!(
    torn.is_ok(),
    "the teardown must RETURN: the declined request's disposal belongs inside the funnel's \
     boundary, which is what makes the strand below a bounded cost rather than an escaped unwind"
  );
  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the declined cookie's marked component really did unwind"
  );
  assert_eq!(
    StrandedAllocation::stranded(SKIPPED_OFFER_STRANDED) - stranded_before,
    1,
    "exactly one arbitrary allocation is stranded by a declined request whose disposal had to \
     forget its payload — the unit the bound multiplies by the reap loop's ceiling, and the reason \
     that ceiling has to be a constant of the code"
  );
  for reply in replies {
    assert!(
      reply.await.is_err(),
      "a barrier still pending at teardown reads as Closed however its entry was destroyed"
    );
  }
}

/// The stranded-allocation tag the skipped-offer disposal mints against, read by
/// [`a_skipped_offer_that_forgets_a_payload_strands_exactly_one_allocation`] alone — see
/// [`Boom::Costly`] for why the book is counted per tag, and why every tag belongs to one cell.
const SKIPPED_OFFER_STRANDED: &str = "skipped-offer";

/// How many [`Source::disarm`] calls a ledger has recorded — the entry count the quarantine cells
/// bound, read as a delta so a cell's staging cannot be mistaken for its claim.
fn disarms(seam: &SeamLedger) -> usize {
  seam
    .calls()
    .iter()
    .filter(|call| matches!(call, SourceCall::Disarm(_)))
    .count()
}

/// Whether [`PlaneValue`]'s destructor unwinds, and how many times it has.
///
/// Process-wide, like [`BOOM_COOKIES_REAPED`] and for the same reason: the value these govern is
/// released from inside the owner being DROPPED — the very destructor under test — so a ledger
/// reachable through the owner could not testify about it. Only
/// [`owner_teardown_enters_the_seam_although_releasing_the_displaced_plane_unwinds`] constructs a
/// [`PlaneValue`] at all, so nothing else can move either counter.
static PLANE_VALUE_DROP_UNWINDS: core::sync::atomic::AtomicBool =
  core::sync::atomic::AtomicBool::new(false);
static PLANE_VALUE_UNWOUND: core::sync::atomic::AtomicUsize =
  core::sync::atomic::AtomicUsize::new(0);

/// A caller value (`V`) whose destructor UNWINDS once [`PLANE_VALUE_DROP_UNWINDS`] is set.
///
/// The `V` half of the caller-panic class an owner teardown must survive: `C`/`V` are caller types
/// stored in the published read-plane snapshot, and a caller `Drop` is as arbitrary as a caller
/// `Filter` predicate — the contract cannot require panic-freedom of either.
///
/// ARMED rather than unconditional because the staging itself moves the value: dropping a
/// subscription copies-on-write the radix node that holds its value and disposes of the copy, so a
/// destructor that unwound on every drop would unwind in a frame the cell is only passing through.
/// A ZST, so a panicking release retains no allocation of its own for a whole-process leak check to
/// report — see [`ForgottenPayload`].
#[derive(Clone)]
struct PlaneValue;

impl Drop for PlaneValue {
  fn drop(&mut self) {
    if PLANE_VALUE_DROP_UNWINDS.load(core::sync::atomic::Ordering::SeqCst) {
      PLANE_VALUE_UNWOUND.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
      std::panic::panic_any(ForgottenPayload);
    }
  }
}

/// An [`Owner`] over a [`FakeSource`] whose CALLER VALUE the cell chooses — the rig for every
/// teardown cell that needs the read plane to own a caller `V` with a destructor of its own
/// ([`PlaneValue`], which unwinds; [`WitnessValue`], which reports). Mirrors [`OwnerU64`]; the value
/// type is the only difference that matters.
struct OwnerOverValue<V> {
  owner: Owner<OsString, V, TokioRuntime, FakeSource>,
  /// Kept alive so the owner's event sender never observes a closed channel.
  _events: async_channel::Receiver<Event<OsString, V>>,
  /// Kept alive so the owner's command receiver never observes a closed channel.
  _commands: async_channel::Sender<super::Command<OsString, V>>,
  /// Kept alive so the owner's sync-admission receiver never observes a closed channel.
  _sync_commands: async_channel::Sender<super::SyncRequest>,
  /// Kept alive so the owner's close receiver never observes a closed channel. The teardown cells
  /// that drive [`run`](super::run) rather than the destructor send their close request on it.
  _closes: async_channel::Sender<super::CloseReply>,
}

impl<V: Clone> OwnerOverValue<V> {
  fn new() -> Self {
    let (event_tx, event_rx) = async_channel::unbounded();
    let (command_tx, command_rx) = async_channel::unbounded();
    let (sync_command_tx, sync_command_rx) = async_channel::unbounded::<super::SyncRequest>();
    let (close_tx, close_rx) = async_channel::bounded(1);
    let (cleanup_tx, cleanup_rx) = async_channel::unbounded();
    let owner = Owner {
      source: FakeSource::new(),
      source_closing: false,
      source_disposals: super::SourceDisposals::default(),
      deferred: crate::subsume::Salvage::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: Filters::new(),
      filter_payload_forgotten: false,
      needs_rescan: ParkedRescans::new(),
      suppressed_rescan: ParkedRescans::new(),
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
    Self {
      owner,
      _events: event_rx,
      _commands: command_tx,
      _sync_commands: sync_command_tx,
      _closes: close_tx,
    }
  }
}

/// Emptying the read plane is TWO operations, and the owner's destructor may only run the
/// infallible one ahead of the teardown seam. Installing the empty snapshot runs no caller code.
/// RELEASING the snapshot it displaces runs caller destructors: that snapshot owns radix nodes
/// holding `C` keys and `V` values, and it is their LAST owner whenever an authoritative mutation
/// removed them and no publish followed — the state a caller callback that unwound out of a
/// subsumer mutator between its commit and its `publish` leaves standing.
///
/// Fused as a store, that release sits AHEAD of the seam entry and the cookie reaps with nothing
/// guarding it, so one caller `Drop` skips both: zero `begin_close` against a once-per-source
/// contract, and every marker file left on the caller's filesystem. On the termination this
/// destructor exists for — an owner already unwinding — it is worse than skipped work, because a
/// second unwind out of a destructor running during an unwind ABORTS the process.
///
/// The release is therefore held back and contained, below every obligation the destructor has.
/// This cell drives the SURVIVABILITY half of that: the displaced publication is the last owner of
/// a `V` whose destructor unwinds, and the teardown must still enter the seam exactly once, still
/// reap its cookie, and let nothing escape. Where the release sits among those is what
/// [`owner_teardown_releases_the_displaced_plane_below_every_cookie_it_owes`] reads, because ONE
/// contained unwind cannot distinguish it — the containment absorbs a single panic wherever it
/// stands.
///
/// The state is ASSEMBLED, not provoked. Reaching it through a real mutator needs a caller `C`
/// whose `Clone` unwinds (or a handle whose `Hash` does) landing between `cover_remove`'s commit and
/// `plan_unwatch`'s publish — a call count internal to the mutator, and a cell keyed on it would
/// pin that count rather than this destructor. The cell takes the publication out, drops the
/// subscription, and puts the publication back, which is that state exactly.
///
/// The teardown runs under [`catch_unwind`](std::panic::catch_unwind) on a path that is NOT itself
/// unwinding, deliberately: it makes "nothing escapes this destructor" an assertion rather than a
/// process abort, and it keeps the reverted form a FAILING cell instead of a dead harness. The
/// containment is what makes the unwinding termination safe, and escape-freedom is the property
/// that decides it either way.
///
/// The drop-path ledger carries no `JoinClose`: a synchronous destructor cannot await the bounded
/// wait, which is the abnormal-teardown shape [`Source::begin_close`] documents.
///
/// FAIL-ON-REVERT: release the displaced publication at the swap (the fused `store` this replaced)
/// and the caller destructor unwinds out of the destructor's first statement — `teardown` is `Err`,
/// the ledger has no `BeginClose` and no `EndSync` at all, and the cookie survives its owner.
#[tokio::test]
async fn owner_teardown_enters_the_seam_although_releasing_the_displaced_plane_unwinds() {
  let mut rig = OwnerOverValue::<PlaneValue>::new();

  // The subscription whose caller value the published snapshot ends up alone in owning.
  let sub = rig
    .owner
    .reconcile_watch(&key("/a"), &PlaneValue, WatchOptions::new())
    .await
    .expect("watch /a"); // root handle 1
  let root = rig
    .owner
    .subsumer
    .subscription_root(sub)
    .expect("live root for /a");

  // A cookie still pending at teardown: the reap is the work standing BEHIND the release, and the
  // ledger is how the cell reads whether it was attempted.
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  rig.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-plane"),
    sub,
    root,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // STAGING — the authoritative trees move PAST the published snapshot: take the publication out
  // of the slot, drop the subscription (which removes its value from the authoritative coverage
  // plane, and would have released it through the publish that follows), then put the publication
  // back. The slot now holds a snapshot that is the last owner of a departed caller value.
  let published = rig.owner.subsumer.swap_in_empty();
  rig
    .owner
    .subsumer
    .test_plan_unwatch(sub)
    .expect("the live subscription departs the authoritative plane");
  rig.owner.subsumer.test_reinstall_publication(published);

  // Read AFTER the owner is gone: the destructor's own read-plane guarantee is asserted alongside
  // the seam, because the release must not be allowed to cost it.
  let seam = rig.owner.source.seam();
  let view = rig.owner.subsumer.view();
  assert!(
    view.is_watched(&key("/a")),
    "staging: the slot still advertises the departed subscription — the stale publication is the \
     one thing left holding its value"
  );

  // Only now does the value's destructor unwind, so the staging above ran over silent drops.
  let unwound_before = PLANE_VALUE_UNWOUND.load(core::sync::atomic::Ordering::SeqCst);
  PLANE_VALUE_DROP_UNWINDS.store(true, core::sync::atomic::Ordering::SeqCst);
  let teardown = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(rig)));
  PLANE_VALUE_DROP_UNWINDS.store(false, core::sync::atomic::Ordering::SeqCst);

  assert_eq!(
    PLANE_VALUE_UNWOUND.load(core::sync::atomic::Ordering::SeqCst) - unwound_before,
    1,
    "staging: the teardown really did release the displaced publication as the last owner of the \
     departed value, and that release really did unwind"
  );
  // THE LEDGER, split at the seam. Below it: the teardown's own calls, and only those — the reap an
  // unwinding release must not have cost, and no `JoinClose`, which a synchronous destructor cannot
  // await.
  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| {
      panic!(
        "a caller destructor unwinding out of the read plane's release left the source never told \
         to wind down: {calls:?}"
      )
    });
  assert_eq!(
    &calls[..split],
    &[
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::Arm(PathBuf::from("/a")),
      SourceCall::RootKey(1),
    ],
    "the establishing watch is all that precedes the seam: {calls:?}"
  );
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/cookie-plane")),
    ],
    "a caller destructor unwinding out of the read plane's release must leave the seam entered and \
     the cookie reaped: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once over the source's whole life"
  );
  assert!(
    teardown.is_ok(),
    "nothing may escape this destructor: it runs on the owner's panic path too, where a second \
     unwind is an immediate process abort rather than a contained failure"
  );

  // Unchanged by the split: the SWAP is what empties the plane, and it ran before anything could
  // unwind.
  assert!(
    !view.is_watched(&key("/a")),
    "the destructor still emptied the read plane, although releasing what it displaced unwound"
  );
  assert!(
    sync_response.await.is_err(),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// What a [`WitnessValue`] saw at the instant the teardown released it.
#[derive(Debug)]
struct ReleaseObservation {
  /// Every [`Source`] call the teardown had made by then, in order.
  calls: Vec<SourceCall>,
  /// The close acknowledgement, if it had ALREADY been delivered by then. [`None`] means it had
  /// not — or that the path has no reply to deliver at all, which is the synchronous destructor.
  ack: Option<Result<(), crate::error::CloseError>>,
}

thread_local! {
  /// The ledger a released [`WitnessValue`] reads, and the arming switch for the whole witness.
  ///
  /// Thread-local rather than owner-reachable because the release happens INSIDE the teardown under
  /// test — the owner's own destructor, or [`run`](super::run)'s tail past its last await — so a
  /// witness held by the owner could not testify about it. Thread-local rather than process-wide
  /// (which is what [`PLANE_VALUE_UNWOUND`] must be, being read across a `catch_unwind`) because
  /// libtest gives each cell its own thread and both teardowns run on the cell's own: no parallel
  /// cell can perturb these, and none needs to.
  static RELEASE_WITNESS: core::cell::RefCell<Option<SeamLedger>> =
    const { core::cell::RefCell::new(None) };
  /// The close acknowledgement's receiver, parked where the released value's destructor can ask it
  /// whether the reply has landed YET. Left empty by the destructor path, which has no reply.
  static ACK_PROBE: core::cell::RefCell<
    Option<futures_channel::oneshot::Receiver<Result<(), crate::error::CloseError>>>,
  > = const { core::cell::RefCell::new(None) };
  /// What the FIRST released witness saw. The first release is the earliest instant a caller
  /// destructor could unwind, so it is the strictest reading of what the teardown still owed.
  static RELEASE_OBSERVATION: core::cell::RefCell<Option<ReleaseObservation>> =
    const { core::cell::RefCell::new(None) };
  /// How many witnesses the teardown released, so a cell can pin that ONE displaced snapshot really
  /// does hold SEVERAL departed caller values — the premise the ordering rests on.
  static RELEASED_WITNESSES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// A caller value (`V`) whose destructor REPORTS instead of unwinding: at the instant the teardown
/// releases it, it reads the source's [`SeamLedger`] and probes the close acknowledgement, and
/// files both in [`RELEASE_OBSERVATION`].
///
/// The ordering half of the class [`PlaneValue`] covers the survivability half of. Containment
/// answers "does ONE unwinding caller destructor escape", and no more: `catch_unwind` regains
/// control only once the unwind reaches it, while drop glue leaving a panicking `C`/`V` destructor
/// carries on destroying the remaining radix nodes of the same publication — so a SECOND caller
/// destructor that panics there is a panic during cleanup, which ABORTS the process. An aborted
/// process asserts nothing, so the ordering is read where it IS decidable: from a value that
/// testifies out of its own `Drop` about the work already behind it.
///
/// ARMED by [`RELEASE_WITNESS`] holding a ledger, exactly as [`PlaneValue`] is armed and for the
/// same reason: the staging itself moves the value — registering and retiring a subscription
/// copies-on-write the radix node that holds it and disposes of the copy — so an unarmed witness
/// stays silent through frames the cell is only passing through.
#[derive(Clone)]
struct WitnessValue;

impl Drop for WitnessValue {
  fn drop(&mut self) {
    let Some(calls) = RELEASE_WITNESS.with_borrow(|ledger| ledger.as_ref().map(SeamLedger::calls))
    else {
      return;
    };
    RELEASED_WITNESSES.set(RELEASED_WITNESSES.get() + 1);
    let ack =
      ACK_PROBE.with_borrow_mut(|probe| probe.as_mut().and_then(|rx| rx.try_recv().ok()?));
    RELEASE_OBSERVATION.with_borrow_mut(|slot| {
      if slot.is_none() {
        *slot = Some(ReleaseObservation { calls, ack });
      }
    });
  }
}

/// Stages the one state the read plane's release is ABOUT — a published snapshot that is the last
/// owner of DEPARTED caller values — over two disjoint roots, and hands back the pending cookie's
/// caller-side reply.
///
/// TWO, not one, because the ordering argument rests on there being more than one: a single
/// interrupted mutator can leave several removed entries alive in the publication alone, so the
/// release can run several caller destructors, and containment only ever catches the first.
///
/// The state is ASSEMBLED, not provoked, for the reason spelled out on
/// [`owner_teardown_enters_the_seam_although_releasing_the_displaced_plane_unwinds`]: reaching it
/// through a real mutator would key the cell on a call count internal to that mutator. Take the
/// publication out of the slot, retire both subscriptions from the authoritative plane (whose own
/// publish then lands on the emptied slot), and put the stale publication back.
async fn stage_departed_plane_values(
  rig: &mut OwnerOverValue<WitnessValue>,
) -> futures_channel::oneshot::Receiver<Result<super::SyncOutcome, crate::error::SyncError>> {
  let a = rig
    .owner
    .reconcile_watch(&key("/a"), &WitnessValue, WatchOptions::new())
    .await
    .expect("watch /a"); // root handle 1
  let b = rig
    .owner
    .reconcile_watch(&key("/b"), &WitnessValue, WatchOptions::new())
    .await
    .expect("watch /b"); // root handle 2
  let root = rig
    .owner
    .subsumer
    .subscription_root(a)
    .expect("live root for /a");

  // A cookie still pending at teardown: its reap is the work standing behind the release on BOTH
  // paths, and the seam ledger is how the witness reads whether it had already happened.
  let (reply, response) = futures_channel::oneshot::channel();
  rig.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-order"),
    sub: a,
    root,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply,
  });

  let published = rig.owner.subsumer.swap_in_empty();
  rig
    .owner
    .subsumer
    .test_plan_unwatch(a)
    .expect("the live subscription on /a departs the authoritative plane");
  rig
    .owner
    .subsumer
    .test_plan_unwatch(b)
    .expect("the live subscription on /b departs the authoritative plane");
  rig.owner.subsumer.test_reinstall_publication(published);

  let view = rig.owner.subsumer.view();
  assert!(
    view.is_watched(&key("/a")) && view.is_watched(&key("/b")),
    "staging: the slot still advertises both departed subscriptions — the stale publication is the \
     one thing left holding their values"
  );
  response
}

/// The teardown seam's ledger as the establishing two watches leave it, which every release
/// observation below opens with.
fn establishing_calls() -> Vec<SourceCall> {
  vec![
    SourceCall::CanonicalizeKey(key("/a")),
    SourceCall::Arm(PathBuf::from("/a")),
    SourceCall::RootKey(1),
    SourceCall::CanonicalizeKey(key("/b")),
    SourceCall::Arm(PathBuf::from("/b")),
    SourceCall::RootKey(2),
  ]
}

/// The owner's destructor must release the displaced read plane BELOW every obligation it has — the
/// teardown seam AND every pending cookie's reap — not merely below the seam.
///
/// Containing that release makes ONE unwinding caller destructor survivable, and no more: a second
/// one panicking as drop glue works through the same publication is a panic during cleanup, which
/// aborts the process before the containment can regain control. ONE displaced snapshot is enough
/// to reach that — the interrupted-mutator state the release exists for can strand several removed
/// entries at once, which is why the staging retires two subscriptions rather than one.
///
/// So the release is ordered LAST instead, and an abort out of it then costs nothing that was owed:
/// the seam is entered and every marker file reaped before the first caller destructor runs at all.
/// What follows is only the owner's own field drops, and `subsumer`, `filters` and `source` all
/// hold caller-defined state that can abort this destructor the same way regardless.
///
/// FAIL-ON-REVERT: put the release back above the reap loop and the witness reports a ledger with
/// no `EndSync` in it; fuse it into the swap as a `store` would and the ledger has no `BeginClose`
/// either.
#[tokio::test]
async fn owner_teardown_releases_the_displaced_plane_below_every_cookie_it_owes() {
  let mut rig = OwnerOverValue::<WitnessValue>::new();
  let sync_response = stage_departed_plane_values(&mut rig).await;
  let view = rig.owner.subsumer.view();
  let seam = rig.owner.source.seam();

  // Only now does the witness report, so the staging above ran over silent drops.
  RELEASE_WITNESS.with_borrow_mut(|slot| *slot = Some(seam.clone()));
  drop(rig);
  RELEASE_WITNESS.with_borrow_mut(|slot| *slot = None);

  assert_eq!(
    RELEASED_WITNESSES.get(),
    2,
    "staging: ONE displaced publication was the last owner of BOTH departed values — which is why \
     containing the release cannot be the whole answer"
  );
  let observed = RELEASE_OBSERVATION
    .take()
    .expect("the destructor released the displaced publication");
  let mut owed = establishing_calls();
  owed.push(SourceCall::BeginClose);
  owed.push(SourceCall::EndSync(key("/a/cookie-order")));
  assert_eq!(
    observed.calls, owed,
    "the first caller destructor the release runs must find the seam entered and every cookie \
     already reaped — everything this destructor owes: {observed:?}"
  );
  assert!(
    observed.ack.is_none(),
    "a synchronous destructor has no close acknowledgement to give: {observed:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once over the source's whole life"
  );

  // Unchanged by the ordering: the SWAP is what empties the plane, and it is still this
  // destructor's first statement.
  assert!(
    !view.is_watched(&key("/a")) && !view.is_watched(&key("/b")),
    "the destructor still emptied the read plane before anything else it does"
  );
  assert!(
    sync_response.await.is_err(),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// [`run`](super::run)'s normal tail must release the displaced read plane BELOW the bounded
/// quiescence wait and BELOW the acknowledgement that carries its verdict.
///
/// Both are work nothing else can do: the destructor that runs next cannot await
/// [`Source::join_close`], and it is not given the reply. Containment cannot protect them, for the
/// reason the destructor cell above states — it catches the first panic, and a second caller
/// destructor unwinding out of the same publication aborts the process. Ordering the release last
/// is what makes that abort cost nothing: a `close()` answered by a dropped sender over a source
/// teardown nobody waited for is no longer standing behind it.
///
/// The SWAP stays where it is, above the wait, and this cell pins that half too: the plane must be
/// empty before `close()` resolves, or a caller whose `close()` returned can still hold a
/// [`WatchView`](crate::WatchView) advertising coverage whose owner and source are gone.
///
/// FAIL-ON-REVERT: move the release back above `join_close().await` and the witness reports a
/// ledger with no `JoinClose` in it; leave it between the wait and the reply and the witness finds
/// no acknowledgement delivered.
#[tokio::test]
async fn the_run_tail_releases_the_displaced_plane_below_the_wait_and_the_acknowledgement() {
  let mut rig = OwnerOverValue::<WitnessValue>::new();
  let sync_response = stage_departed_plane_values(&mut rig).await;
  let view = rig.owner.subsumer.view();
  let seam = rig.owner.source.seam();

  let OwnerOverValue {
    owner,
    _events,
    _commands,
    _sync_commands,
    _closes: closes,
  } = rig;
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  RELEASE_WITNESS.with_borrow_mut(|slot| *slot = Some(seam.clone()));
  ACK_PROBE.with_borrow_mut(|slot| *slot = Some(close_response));
  super::run(owner).await;
  RELEASE_WITNESS.with_borrow_mut(|slot| *slot = None);
  let _ = ACK_PROBE.take();

  assert_eq!(
    RELEASED_WITNESSES.get(),
    2,
    "staging: ONE displaced publication was the last owner of BOTH departed values"
  );
  let observed = RELEASE_OBSERVATION
    .take()
    .expect("the tail released the displaced publication");
  let mut owed = establishing_calls();
  owed.push(SourceCall::BeginClose);
  owed.push(SourceCall::EndSync(key("/a/cookie-order")));
  owed.push(SourceCall::JoinClose);
  assert_eq!(
    observed.calls, owed,
    "the first caller destructor the release runs must find the bounded wait already made: \
     {observed:?}"
  );
  assert!(
    matches!(observed.ack, Some(Ok(()))),
    "and the close already acknowledged, carrying the source's quiescence verdict: {observed:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once over the source's whole life"
  );

  // The half the ordering may NOT buy: the plane is emptied by the SWAP, which stays above the
  // wait, so it is already empty at the instant `close()` resolves.
  assert!(
    !view.is_watched(&key("/a")) && !view.is_watched(&key("/b")),
    "the tail still emptied the read plane before the close was answered"
  );
  assert!(
    sync_response.await.is_err(),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// The bounded quiescence wait's own extension point unwinding at the CALL — before it has produced
/// a future to await at all, which only a hand-written [`Source::join_close`] can do and which is
/// exactly the shape a boundary placed around the `.await` would miss.
///
/// [`join_close`](Source::join_close) is the only AWAITED `Source` call on the terminal path, and
/// [`contain`](tributary_proto::unwind::contain) is synchronous — so the wait's boundary is three
/// separate boundaries (the call, each poll, and the disposal of the future), and this cell drives
/// the first. An unwind here leaves `run` with the acknowledgement itself still owed: the caller's
/// `close()` then reads a dropped sender, and — the worse half — the tail's final ordered release of
/// the displaced read plane is left to the unwinding frame's drop glue, where a panicking caller
/// `Drop` is a second unwind and an immediate process ABORT.
///
/// What the caller learns is the ruling this pins: [`CloseError::Source`] carrying
/// [`SourceCloseError::Stopped`], whose own documentation already reads *the source's own machinery
/// stopped before it could confirm the shutdown, so nothing was proven about what it still held*.
/// Not the owner-side [`CloseError::Stopped`], which names three owner-side causes and would report
/// an owner fault for a source one — and which is also what a dropped sender reads as, so a cell
/// that accepted it could not tell the fix from its absence.
///
/// FAIL-ON-REVERT: `owner.source.join_close().await` bare again and the panic leaves `run`'s poll —
/// the cell's own boundary reports `Err`, and `close()` resolves `Stopped` off the dropped sender
/// rather than carrying a source-side verdict.
#[tokio::test]
async fn the_tails_bounded_wait_survives_a_join_close_that_unwinds_at_the_call() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");

  // A cookie still pending, so the reaps that stand AHEAD of the wait are observable too: the claim
  // is that the tail runs to its end, not merely that it does not unwind.
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-wait"),
    sub: sa,
    root: root_a,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  h.owner.source.panic_join_close_call();
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands,
    _sync_commands,
    closes,
  } = h;

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  // Contained HERE too, through [`contain`](tributary_proto::unwind::contain) rather than a bare
  // `catch_unwind` so the hostile payload a REVERTED wait hands back is retired before the failing
  // assertion below unwinds past it.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a `Source::join_close` that unwinds at the CALL must not leave the tail — the whole wait is \
     contained, the call included"
  );
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "the caller is told the SOURCE stopped before confirming its shutdown — a source-side fact, not \
     the owner-side Stopped a dropped sender would have produced"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the tail never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/cookie-wait")),
      SourceCall::JoinClose,
    ],
    "the wait was asked for and the reaps ahead of it still happened: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once however the wait behind it behaves"
  );
  assert!(
    sync_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// The SAME extension point unwinding at its first POLL — a different piece of implementor code at a
/// different instant from the call above — and the half of the ruling that removes a process ABORT.
///
/// While the wait was uncontained, a panicking `join_close` made `displaced` a live local of an
/// unwinding frame: the tail's final, ORDERED, contained release never ran, and the frame's own drop
/// glue released the displaced publication with no boundary at all. That publication can be the last
/// owner of SEVERAL departed caller values (the staging retires two for exactly that reason), and a
/// caller `Drop` unwinding inside an unwind is an immediate process abort — the hazard putting the
/// release last was meant to have removed, reintroduced whole by the one call above it.
///
/// So this reads the ordering from a value that TESTIFIES out of its own `Drop`
/// ([`WitnessValue`]) rather than from a panic: on the panicking-verdict path the release must still
/// run, and must still find the wait made and the acknowledgement — carrying the source-side verdict
/// — already delivered.
///
/// FAIL-ON-REVERT: await `self.source.join_close()` bare inside the funnel and the tail unwinds out
/// of the poll — this cell's own boundary reports `Err`, and the witness finds NO acknowledgement,
/// because the frame carried it off. Contain the poll but move the release above the wait and the
/// witness reports a ledger with no `JoinClose` in it instead.
#[tokio::test]
async fn the_run_tail_still_releases_the_displaced_plane_when_the_bounded_wait_unwinds() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverValue::<WitnessValue>::new();
  let sync_response = stage_departed_plane_values(&mut rig).await;
  let seam = rig.owner.source.seam();
  rig.owner.source.panic_join_close_poll();

  let OwnerOverValue {
    owner,
    _events,
    _commands,
    _sync_commands,
    _closes: closes,
  } = rig;
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  RELEASE_WITNESS.with_borrow_mut(|slot| *slot = Some(seam.clone()));
  ACK_PROBE.with_borrow_mut(|slot| *slot = Some(close_response));
  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  // Driven through [`contain`](tributary_proto::unwind::contain) rather than awaited bare, and here
  // that is not a nicety: a REVERTED wait hands back the hostile [`PanicsOnDrop`] payload, and a
  // payload libtest disposes of for itself unwinds a second time inside the runner — which does not
  // report a failing claim, it wedges the run. Retired here, the revert reports which assertion
  // broke.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));
  RELEASE_WITNESS.with_borrow_mut(|slot| *slot = None);
  let _ = ACK_PROBE.take();

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a `Source::join_close` that unwinds at its first POLL must not leave the tail"
  );
  assert_eq!(
    RELEASED_WITNESSES.get(),
    2,
    "staging: ONE displaced publication was the last owner of BOTH departed values — which is why \
     an unwinding tail releasing it with no boundary is an abort rather than a contained failure"
  );
  let observed = RELEASE_OBSERVATION
    .take()
    .expect("the tail still released the displaced publication");
  let mut owed = establishing_calls();
  owed.push(SourceCall::BeginClose);
  owed.push(SourceCall::EndSync(key("/a/cookie-order")));
  owed.push(SourceCall::JoinClose);
  assert_eq!(
    observed.calls, owed,
    "the ordered release still runs on the panicking-verdict path, and still below the wait: \
     {observed:?}"
  );
  assert!(
    matches!(
      observed.ack,
      Some(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "and below an acknowledgement that carries the SOURCE-side verdict a contained unwind maps to: \
     {observed:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once over the source's whole life"
  );
  assert!(
    sync_response.await.is_err(),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// The SAME extension point at its THIRD instant — the future resolves `Ok(())` and then unwinds in
/// its own `Drop` — and the one phase a total containment does not by itself account for.
///
/// The call and each poll PRODUCE the verdict, so an unwind in either IS the verdict and nothing is
/// left to lose. The disposal is different in kind: it runs BEHIND a verdict already in hand, and a
/// boundary around it bounds the unwind without touching what the wait is about to return. So the
/// containment could be total — nothing escaping, payload included — and the verdict still ignore
/// one of the three phases it contained: `close()` answered a CLEAN shutdown while source-owned
/// cleanup, the very work that `Drop` was doing, had failed with the source's own resources
/// possibly still live. Bounding an unwind is not accounting for one; the account is what the
/// caller is told.
///
/// The disposal's outcome therefore OVERRIDES the verdict, and that is the reporting half rather
/// than a silencing one — the hook reported the panic when it was raised, and forwarding the stale
/// `Ok(())` is what would have silenced it. The reaps and the acknowledgement are asserted beside
/// it because the honest verdict must not be bought by unwinding out of the tail to deliver it.
///
/// FAIL-ON-REVERT: make the override a no-op (`fold_into` returning `reading.0` unconditionally)
/// and the wait hands back the `Ok(())` the poll produced — `close()` resolves `Ok(())`, this
/// cell's verdict assertion fails, and every OTHER claim in it still passes, which is exactly the
/// shape of the defect: a shutdown reported successful over cleanup that was watched to fail. Drop
/// the fold outright (`retire_raced_source_future(..); reading`) and it does not even build — the
/// wait's own return type is the `Result` only the fold produces, so the omission is a type error
/// rather than a silent regression. Destroy the future UNCONTAINED instead (pass `false`) and the
/// unwind leaves `run`'s poll: the first assertion below reports it, and the acknowledgement goes
/// with the frame.
#[tokio::test]
async fn the_tails_bounded_wait_reports_a_join_close_that_unwinds_in_its_own_drop() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  let sa = h.watch("/a", Interest::all()).await.expect("watch /a"); // handle 1
  let root_a = h
    .owner
    .subsumer
    .subscription_root(sa)
    .expect("live root for /a");

  // A cookie still pending, so the reaps that stand AHEAD of the wait are observable too: the claim
  // is that the tail runs to its end AND reports honestly, not that it trades one for the other.
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  h.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/a/cookie-disposal"),
    sub: sa,
    root: root_a,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  h.owner.source.panic_join_close_drop();
  let seam = h.owner.source.seam();

  let Harness {
    owner,
    events: _events,
    _commands,
    _sync_commands,
    closes,
  } = h;

  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  // Contained HERE too, through [`contain`](tributary_proto::unwind::contain) rather than a bare
  // `catch_unwind`: a boundary that catches the hostile payload must retire it, and a payload
  // libtest disposes of for itself unwinds a second time inside the runner — which does not report
  // a failing claim, it wedges the run.
  let drove = tributary_proto::unwind::contain(|| run.as_mut().poll(&mut cx));

  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "a `join_close` future that unwinds in its own `Drop` must not leave the tail — the disposal is \
     contained like the other two phases"
  );
  assert!(
    matches!(
      close_response.await,
      Ok(Err(crate::error::CloseError::Source(
        crate::error::SourceCloseError::Stopped
      )))
    ),
    "and the caller is told the SOURCE stopped before confirming its shutdown — NOT the `Ok(())` \
     the poll produced, which the contained disposal has since falsified"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the tail never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/a/cookie-disposal")),
      SourceCall::JoinClose,
    ],
    "the wait was asked for and the reaps ahead of it still happened: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once however the wait's future behaves on its way out"
  );
  assert!(
    sync_response.await.is_err(),
    "a barrier still pending at teardown reads as Closed"
  );
}

/// A `Disjoint` watch whose close signal CLOSES mid-arm is TERMINAL, and arms nothing.
///
/// This is the behaviour change the ruling is about. The branch used to answer a closed signal by
/// re-issuing [`Source::arm`] UN-RACED and adopting whatever came back — so a `Disjoint` watch
/// against a source that admits it returned `Ok(sub)`, committing a subscription for a watcher whose
/// every handle was already gone, over an arm nothing could preempt and against a stream the
/// cancelled first arm may have left the source holding. It now returns
/// [`ReconcileStop::HandlesGone`]: the seam is entered at the mint, no `Source::arm` is issued, and
/// the [`run`] loop breaks with no acknowledgement to give.
///
/// The premise the re-issue rested on — *the reconcile still owes its caller a verdict* — is what
/// this cell also settles. [`Tributaries::watch`](crate::Tributaries::watch) holds a `&self` borrow
/// on the handle across its whole reply wait, and the close signal's sender is a field of that same
/// handle, so a waiting `watch()` future keeps the signal open: this reading proves none is waiting.
/// The verdict was owed to nobody.
///
/// The negative is asserted by LIVENESS as well as by the ledger: the arm is WEDGED, so a re-issue
/// could not return at all and the hand-poll below would report `Pending` rather than a verdict —
/// an out-of-order check cannot merely add a call here.
///
/// FAIL-ON-REVERT: answer the closed signal with `self.source.arm(key).await` again and the single
/// poll parks on the wedge, with the `Arm` that must not have been issued on the ledger.
#[tokio::test]
async fn a_disjoint_watch_whose_signal_closes_mid_arm_is_terminal_and_arms_nothing() {
  use std::task::{Context, Poll, Waker};

  let mut h = Harness::new();
  // The arm an un-raced re-issue would hand itself: it never returns, and with the signal already
  // closed nothing is left able to interrupt it.
  h.owner.source.wedge_arm("/a");
  // The last handle drops: the close signal closes in lockstep with the command mailbox the run
  // loop takes its teardown signal from.
  h.closes.close();

  let seam = h.owner.source.seam();
  let before = seam.calls().len();

  let mut cx = Context::from_waker(Waker::noop());
  let newcomer = key("/a");
  let mut reconcile = Box::pin(h.owner.reconcile_watch(&newcomer, &(), WatchOptions::new()));
  let settled = match reconcile.as_mut().poll(&mut cx) {
    Poll::Ready(settled) => settled,
    Poll::Pending => {
      panic!("the closed signal was answered by an arm nothing can preempt: it parked on the wedge")
    }
  };
  drop(reconcile);

  assert!(
    matches!(settled, Err(super::ReconcileStop::HandlesGone)),
    "a `Disjoint` arm whose signal closed is a no-ack TEARDOWN, not a committed subscription and \
     not an ordinary failed watch"
  );
  assert_eq!(
    &seam.calls()[before..],
    // The seam entry is the ONLY thing the source hears: the key is canonicalized at the choke
    // point as always, the close arm then reads the signal gone, and no `Arm` is ever issued.
    &[
      SourceCall::CanonicalizeKey(key("/a")),
      SourceCall::BeginClose
    ],
    "the closed signal is answered by the seam, not by an arm"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered at the mint, ahead of everything the abandoned reconcile does on its way \
     out"
  );
  assert!(
    h.owner.source_closing,
    "…and `source_closing` reads terminal, so the abandoned reconcile's caller-owned removals are \
     held for the tail rather than released here"
  );
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/a")),
    "nothing is committed: the plan unwound through `abort_watch`"
  );

  // What the caller-visible verdict flattens to, for the caller that by this reading cannot exist:
  // the same `Closed` a dropped reply reads as, which is why the `watch()` contract is unchanged.
  let flattened = h.watch("/b", Interest::all()).await;
  assert!(
    matches!(flattened, Err(WatchError::Closed)),
    "flattened for a `watch()` caller it is `Closed`, exactly as a dropped reply reads: {flattened:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "a second terminal reconcile re-enters the seam not at all — the latch holds across both"
  );
}

/// The sibling reading on the other awaited coverage call: a `Covered`-outside watch whose close
/// signal CLOSES mid-[`grow`](Source::grow) is terminal too.
///
/// It used to fail the watch `WatchError::Closed` and let the [`run`] loop carry on — dispatching
/// whatever the closed mailbox still held buffered and calling the source again, all behind a
/// cancelled `Source::grow` and with no teardown seam in between. That is precisely the window
/// [`Teardown`] says must be empty, and the argument that it was empty had to be re-made per method.
/// Now the one signal reads the same way at every race: `ReconcileStop::HandlesGone`, the seam
/// entered at the mint, and the loop broken before one more command is dispatched.
///
/// The severity is genuinely lower than the arm's — a cancelled `grow` mints nothing and leaves a
/// handle the owner can still name and release — which is why the doc clause that USED to justify
/// it (*the close this lost to tears the source down immediately*) mattered: it was false on both
/// arms, and nothing else stood in its place.
///
/// FAIL-ON-REVERT: return `Err(WatchError::Closed.into())` from the closed-channel arm again and the
/// reconcile reports `Failed(Closed)` — an ordinary failed watch the loop goes on from — with the
/// seam not entered at all.
#[tokio::test]
async fn a_covered_outside_watch_whose_signal_closes_mid_grow_is_terminal_and_grows_nothing() {
  let mut h = Harness::new();
  let sy = h.watch("/y", Interest::all()).await.expect("watch /y"); // handle 1
  h.watch("/y/n", Interest::all()).await.expect("watch /y/n");
  let root_y = h
    .owner
    .subsumer
    .subscription_root(sy)
    .expect("live root for /y");
  // The root-key subscriber departs, so the root is pruned down to `[/y/n]` and its record narrows:
  // a newcomer outside that antichain is what owes an awaited grow.
  h.unwatch(sy).expect("unwatch the root-key subscriber");
  assert_eq!(
    h.owner
      .subsumer
      .entry(root_y)
      .expect("the root survives for /y/n")
      .retained_cover,
    Some(vec![key("/y/n")]),
    "staging: the root is narrowed, so `/y/other` will classify outside-cover"
  );

  // The last handle drops while the newcomer's grow is what the reconcile owes.
  h.closes.close();
  let seam = h.owner.source.seam();
  let before = seam.calls().len();

  let settled = h
    .owner
    .reconcile_watch(&key("/y/other"), &(), WatchOptions::new())
    .await;

  assert!(
    matches!(settled, Err(super::ReconcileStop::HandlesGone)),
    "a `Covered`-outside grow whose signal closed is a no-ack TEARDOWN, not a failed watch the loop \
     goes on from"
  );
  assert_eq!(
    &seam.calls()[before..],
    &[
      SourceCall::CanonicalizeKey(key("/y/other")),
      SourceCall::RootKey(root_y),
      SourceCall::BeginClose,
    ],
    "the covering root is validated live as always, and then the closed signal is answered by the \
     seam rather than by a grow"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered at the mint, ahead of everything the abandoned reconcile does on its way \
     out"
  );
  assert!(
    h.owner.source_closing,
    "…and `source_closing` reads terminal for the abandoned reconcile's caller-owned removals"
  );
  assert!(
    !h.owner.subsumer.view().is_watched(&key("/y/other")),
    "nothing is committed: the plan unwound through `abort_watch`"
  );
  assert_eq!(
    h.owner
      .subsumer
      .entry(root_y)
      .expect("the root survives")
      .retained_cover,
    Some(vec![key("/y/n")]),
    "and the retained-cover record is not broadened by a grow that never landed"
  );
}

thread_local! {
  /// Arms [`HostileValue`]'s destructor, and DISARMS ITSELF the moment one unwinds.
  ///
  /// Exactly one unwind, because one is the whole budget.
  /// [`contain`](tributary_proto::unwind::contain) regains control only once the unwind reaches it,
  /// while the drop glue leaving a panicking caller destructor carries on destroying the rest of the
  /// bundle — so a SECOND panicking destructor there is a panic during cleanup, which aborts the
  /// process outright. An aborted process asserts nothing and takes the whole harness with it, so
  /// the survivability question a cell can actually decide is the one-unwind one. The ordering
  /// question is decided without any panic at all, by [`WitnessValue`].
  ///
  /// Thread-local, unlike [`PLANE_VALUE_DROP_UNWINDS`], because SEVERAL cells arm this one and
  /// libtest runs them in parallel: a process-wide switch would let one cell's arming spend the
  /// other's single unwind, which is a flake rather than a defect. Each cell owns its thread, the
  /// values are released by a `run` future this thread polls by hand, and `catch_unwind` never
  /// leaves the thread it was entered on — so the switch is reachable everywhere the cell needs it.
  static HOSTILE_VALUE_ARMED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
  /// How many [`HostileValue`] destructors have unwound on this cell's own thread.
  static HOSTILE_VALUE_UNWOUND: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// A caller value (`V`) whose destructor unwinds — but only for the instances a cell MARKED, and
/// only while [`HOSTILE_VALUE_ARMED`] stands.
///
/// Per-instance rather than per-type, unlike [`PlaneValue`], because this cell needs a populated
/// read plane it is NOT testing: the establishing subscriptions' values ride the published snapshots
/// the terminal unwind displaces, and a type that unwound for all of them would spend the single
/// unwind budget above on a value the cell is only passing through.
#[derive(Clone)]
struct HostileValue {
  unwinds: bool,
}

impl HostileValue {
  /// The value a cell hands to the request whose abandonment it is testing.
  fn hostile() -> Self {
    Self { unwinds: true }
  }

  /// The value a cell hands to an establishing subscription it is only passing through.
  fn inert() -> Self {
    Self { unwinds: false }
  }
}

impl Drop for HostileValue {
  fn drop(&mut self) {
    if self.unwinds && HOSTILE_VALUE_ARMED.replace(false) {
      HOSTILE_VALUE_UNWOUND.set(HOSTILE_VALUE_UNWOUND.get() + 1);
      std::panic::panic_any(ForgottenPayload);
    }
  }
}

/// A caller destructor unwinding out of a TERMINAL reconcile's own removals must not be able to
/// answer `close()` for the source.
///
/// The terminal reconcile holds a CONSUMED [`CloseReply`] and hands it back for the run tail to
/// answer with [`Source::join_close`]'s verdict. Everything it does on the way out — abandoning the
/// not-yet-committed plan, retiring the roots the widen disarmed — removes caller `C`/`V` from the
/// engine, and a mutator that DESTROYED those removals ran the caller's destructors right there, in
/// front of the bounded wait and the acknowledgement. One unwinding `Drop` then took the reply with
/// it: the caller's `close()` read a dropped sender as [`Stopped`](crate::error::CloseError::Stopped)
/// over a source teardown nobody waited for, and the source's own quiescence evidence — the
/// strongest lifecycle fact the lower layer produces — was never asked for.
///
/// Containment cannot be the answer at those sites for the reason the sibling cells state: it
/// catches the first panic, and the tail is what owes the wait. So the mutators hand their removals
/// back instead ([`Salvage`](crate::subsume::Salvage)) and the driver's ONE disposal route
/// ([`Owner::retire_salvage`]) holds them, on the terminal path only, until the release the tail
/// already makes last.
///
/// The shape is the widen whose arm and re-arm are both refused on capacity, so the reconcile is
/// pacing inside its restore when the close lands — a genuinely terminal reconcile, not an assembled
/// state — and the cookie riding a DISJOINT root is the reap the tail still owes when the release
/// runs.
///
/// This cell strands no allocation: both hostile instances sit directly in the bundle's `Vec`s, so
/// every frame between the unwinding destructor and the containment is drop glue, which drops its
/// remaining fields and elements while unwinding. That is what separates it from
/// [`owner_teardown_enters_the_seam_although_releasing_the_displaced_plane_unwinds`], whose value
/// sits inside an `Arc<Published>`: `Arc`'s deallocation is a statement AFTER the value's
/// `drop_in_place`, so an unwind out of that one skips it.
///
/// FAIL-ON-REVERT: make [`Owner::retire_salvage`] release unconditionally (delete the
/// `source_closing` branch, which IS the deferral) and the plan abort destroys the caller value
/// inside the reconcile. The unwind leaves `run` itself, so the tail never happens: `close()` reads
/// the dropped sender as `Stopped`, the drive assertion sees the escape, and the ledger has neither
/// the cookie reap nor `JoinClose` in it.
#[tokio::test]
async fn a_terminal_reconciles_caller_destructor_cannot_answer_close_for_the_source() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverValue::<HostileValue>::new();

  // The root the widen subsumes, and a DISJOINT root to hang the still-pending cookie on — so the
  // reap the release must stand behind is the TAIL's `reap_all_pending_syncs`, not the retirement's
  // own domination of the widened root's barriers.
  let subsumed = rig
    .owner
    .reconcile_watch(&key("/a/b"), &HostileValue::inert(), WatchOptions::new())
    .await
    .expect("watch /a/b"); // root handle 1
  let bystander = rig
    .owner
    .reconcile_watch(&key("/x"), &HostileValue::inert(), WatchOptions::new())
    .await
    .expect("watch /x"); // root handle 2
  rig.owner.epochs.stamp(subsumed, Epoch::new(4));
  let bystander_root = rig
    .owner
    .subsumer
    .subscription_root(bystander)
    .expect("live root for /x");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  rig.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/x/cookie-terminal"),
    sub: bystander,
    root: bystander_root,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The widen's arm AND every re-arm of the root it disarmed are refused on CAPACITY, so the
  // reconcile reaches its restore and paces there — the window a close can land in.
  rig.owner.source.refuse_capacity("/a", u32::MAX);
  rig.owner.source.refuse_capacity("/a/b", u32::MAX);
  let seam = rig.owner.source.seam();

  let OwnerOverValue {
    owner,
    _events,
    _commands: commands,
    _sync_commands,
    _closes: closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/a"),
      // THE value under test: the request's own, which the abandoned plan stashes a clone of and
      // the abandoned request still owns.
      value: HostileValue::hostile(),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(run.as_mut().poll(&mut cx).is_pending(), "staging: the pace");
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  // Only now does the marked value's destructor unwind, so the staging above ran over silent drops.
  let unwound_before = HOSTILE_VALUE_UNWOUND.get();
  HOSTILE_VALUE_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_VALUE_ARMED.set(false);

  assert_eq!(
    HOSTILE_VALUE_UNWOUND.get() - unwound_before,
    1,
    "staging: the terminal reconcile really did give up a caller value whose destructor unwinds"
  );
  // THE VERDICT, read first because it is the whole claim: `Stopped` is what a dropped sender reads
  // as, and a mid-reconcile release that unwound dropped exactly that sender.
  assert!(
    matches!(close_response.await, Ok(Ok(()))),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by a caller \
     destructor unwinding out of the reconcile that consumed the reply"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "the run loop must reach its own end: an unwinding caller destructor is contained where the \
     tail places it, not allowed out through the owner's spawner"
  );

  // And the work that verdict is supposed to cover: the ledger from the seam onward is the
  // teardown's own, with the tail's cookie reap and the bounded wait both already made.
  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the terminal reconcile never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/x/cookie-terminal")),
      SourceCall::JoinClose,
    ],
    "every cookie reaped and the bounded wait made, all ahead of the release that unwound: \
     {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "the seam is entered exactly once over the source's whole life"
  );
  assert!(
    sync_response.await.is_err(),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// The seam is entered wherever a reconcile MINTS a terminal outcome, not only where the widen's
/// unwind retires roots — because the latch is what tells [`Owner::retire_salvage`] the owner is on
/// its terminal path.
///
/// [`Owner::arm`]'s consumed-close arm is the one the widen's retirement does NOT stand in front of:
/// a plain [`Disjoint`](crate::subsume::WatchOutcome::Disjoint) watch whose arm loses the race has
/// no disarmed roots to retire, so nothing else on that path would have set the latch. Its plan
/// abort then destroys the caller's not-yet-committed reservation while a CONSUMED [`CloseReply`]
/// sits in the returned stop — one unwinding caller destructor and `close()` reads a dropped sender
/// as [`Stopped`](crate::error::CloseError::Stopped), with the source never asked to quiesce.
///
/// Entering the seam at the mint costs the source nothing observable: no `Source` call stands
/// between it and the tail's own (idempotent) entry, so the order the source sees is exactly the
/// order it saw before. What it buys is that "terminal" is one bit rather than a property of each
/// unwinding arm's control flow.
///
/// FAIL-ON-REVERT: delete the `begin_source_close()` from [`Owner::arm`]'s `Some(close_reply)` arm
/// and the latch is unset when the plan is aborted: the reservation's caller destructor runs inside
/// the reconcile, the unwind leaves `run`, and `close()` reports `Stopped`.
#[tokio::test]
async fn a_disjoint_arm_losing_the_close_race_enters_the_seam_before_it_abandons_the_plan() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverValue::<HostileValue>::new();

  // A bystander root carrying the cookie, so the tail owes a reap the release must stand behind.
  let bystander = rig
    .owner
    .reconcile_watch(&key("/x"), &HostileValue::inert(), WatchOptions::new())
    .await
    .expect("watch /x"); // root handle 1
  let bystander_root = rig
    .owner
    .subsumer
    .subscription_root(bystander)
    .expect("live root for /x");
  let (sync_reply, sync_response) = futures_channel::oneshot::channel();
  rig.owner.pending_syncs.push(super::PendingSync {
    cookie_key: key("/x/cookie-disjoint"),
    sub: bystander,
    root: bystander_root,
    loss_serial_at_install: 0,
    dominated_at_install: false,
    reply: sync_reply,
  });

  // The newcomer is DISJOINT, so its reconcile arms once and retires nothing: the close race inside
  // that arm is the only thing that can make it terminal.
  rig.owner.source.wedge_arm("/d");
  let seam = rig.owner.source.seam();

  let OwnerOverValue {
    owner,
    _events,
    _commands: commands,
    _sync_commands,
    _closes: closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: key("/d"),
      value: HostileValue::hostile(),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the disjoint watch");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the disjoint arm"
  );
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_VALUE_UNWOUND.get();
  HOSTILE_VALUE_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_VALUE_ARMED.set(false);

  assert_eq!(
    HOSTILE_VALUE_UNWOUND.get() - unwound_before,
    1,
    "staging: the abandoned plan really did give up a caller value whose destructor unwinds"
  );
  assert!(
    matches!(close_response.await, Ok(Ok(()))),
    "close() must still carry the SOURCE's quiescence verdict"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = seam.calls();
  let split = calls
    .iter()
    .position(|call| *call == SourceCall::BeginClose)
    .unwrap_or_else(|| panic!("the arm that consumed the close never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      SourceCall::BeginClose,
      SourceCall::EndSync(key("/x/cookie-disjoint")),
      SourceCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert_eq!(
    seam.begin_closes(),
    1,
    "entering the seam at the mint must not make it a SECOND entry: the tail's is then the no-op"
  );
  assert!(
    sync_response.await.is_err(),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

thread_local! {
  /// Whether a MARKED [`HostileComponent`]'s destructor unwinds, on this cell's own thread.
  ///
  /// One-shot: the first marked destructor to run clears it, so a cell spends exactly one unwind and
  /// the drop glue that carries on behind it cannot raise the SECOND panic that would abort the
  /// process outright.
  static HOSTILE_COMPONENT_ARMED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
  /// How many [`HostileComponent`] destructors have unwound on this cell's own thread.
  static HOSTILE_COMPONENT_UNWOUND: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
  /// Which stranded-allocation reading a MARKED destructor's payload belongs to, when the cell is
  /// pricing the leak rather than proving containment.
  ///
  /// [`None`] — the default every other cell keeps — raises the bare [`ForgottenPayload`], which
  /// mints nothing and so leaves nothing to read. A tag makes the unwind carry [`Boom::Costly`]'s
  /// payload instead, which mints and books an allocation on its way past, so the forget has a
  /// witness. Set alongside [`HOSTILE_COMPONENT_ARMED`] and spent with it, so a cell prices exactly
  /// one unwind.
  static HOSTILE_COMPONENT_COSTLY: core::cell::Cell<Option<&'static str>> =
    const { core::cell::Cell::new(None) };
}

/// A caller KEY COMPONENT (`C`) whose destructor unwinds — the `C` half of [`HostileValue`], and the
/// half the [`Salvage`](crate::subsume::Salvage) funnel's two structural blind spots are about.
///
/// `unwinds` is deliberately OUTSIDE the equality: [`Ord`]/[`Eq`]/[`Hash`] read `name` alone, so a
/// marked component and an inert one with the same name are THE SAME KEY to the radix, the side
/// table and the coverage plane. That is what lets a cell register several subscriptions at one key
/// and mark only the DUPLICATES — the registrations whose keys a grouping keyed by an owned `Vec<C>`
/// discards — so a fired destructor names exactly one site instead of the first `C` the teardown
/// happens to touch.
#[derive(Clone, Debug)]
struct HostileComponent {
  name: &'static str,
  unwinds: bool,
}

impl HostileComponent {
  /// The components of `path` — every one of them marked iff `unwinds`.
  fn key(path: &'static str, unwinds: bool) -> Vec<Self> {
    path
      .split('/')
      .filter(|part| !part.is_empty())
      .map(|name| Self { name, unwinds })
      .collect()
  }

  /// A key's component names — what the ledger records, so no ledger entry owns a component whose
  /// destructor could fire while the cell is reading it.
  fn names(key: &[Self]) -> Vec<&'static str> {
    key.iter().map(|component| component.name).collect()
  }
}

impl PartialEq for HostileComponent {
  fn eq(&self, other: &Self) -> bool {
    self.name == other.name
  }
}

impl Eq for HostileComponent {}

impl PartialOrd for HostileComponent {
  fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for HostileComponent {
  fn cmp(&self, other: &Self) -> core::cmp::Ordering {
    self.name.cmp(other.name)
  }
}

impl core::hash::Hash for HostileComponent {
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.name.hash(state);
  }
}

impl Drop for HostileComponent {
  fn drop(&mut self) {
    if self.unwinds && HOSTILE_COMPONENT_ARMED.replace(false) {
      HOSTILE_COMPONENT_UNWOUND.set(HOSTILE_COMPONENT_UNWOUND.get() + 1);
      // The payload is the cell's choice for the reason every injected `Source` panic's is: a
      // containment that catches this disposes of the payload too, and only a payload that BOOKS
      // something on its way past can price what forgetting it costs — see
      // [`HOSTILE_COMPONENT_COSTLY`].
      match HOSTILE_COMPONENT_COSTLY.replace(None) {
        Some(site) => Boom::Costly(site).raise(),
        None => std::panic::panic_any(ForgottenPayload),
      }
    }
  }
}

/// The caller data a [`Filter`] predicate captures, whose destructor unwinds — the FILTER half of
/// [`HostileComponent`], and the only way to reach a caller destructor that no key component can
/// stand in for.
///
/// A `Filter` boxes caller code, and caller code owns whatever the caller likes: retiring a
/// subscription therefore runs a caller destructor that is neither a `C` nor a `V`, at a site the
/// key-shaped fixtures cannot mark. It shares [`HostileComponent`]'s one-shot arming so a cell
/// spends exactly one unwind however the destructor is reached.
struct HostileFilterState;

impl Drop for HostileFilterState {
  fn drop(&mut self) {
    if HOSTILE_COMPONENT_ARMED.replace(false) {
      HOSTILE_COMPONENT_UNWOUND.set(HOSTILE_COMPONENT_UNWOUND.get() + 1);
      std::panic::panic_any(ForgottenPayload);
    }
  }
}

/// A [`Filter`] whose predicate captures a [`HostileFilterState`], so DROPPING the filter unwinds.
/// The predicate itself is inert and admits everything — a cell that never routes an event never
/// enters it, and the measurement is about the gate's disposal, not its verdict.
fn hostile_filter() -> Filter<HostileComponent> {
  let state = HostileFilterState;
  Filter::new(move |_| {
    let _ = &state;
    true
  })
}

/// One [`Source`] call [`HostileKeySource`] received. Records component NAMES rather than
/// components, so the ledger a cell reads after the unwind owns no destructor of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
enum HostileCall {
  Arm(Vec<&'static str>),
  Disarm(u32),
  EndSync(Vec<&'static str>),
  BeginClose,
  JoinClose,
}

/// A minimal [`Source`] over [`HostileComponent`] keys: enough to arm, disarm, wedge one arm on a
/// hung mount, reap a cookie and answer the close — the surface the two hostile-`C` cells drive.
///
/// It never DROPS a stored key: a released handle moves to `released` and keeps its entry, so the
/// only marked destructors that can run are the engine's own, which is the whole measurement.
struct HostileKeySource {
  next_handle: u32,
  live: HashMap<u32, Vec<HostileComponent>>,
  released: std::collections::HashSet<u32>,
  /// Keys whose `arm` NEVER resolves — the hung mount the close race exists for.
  wedged: Vec<Vec<HostileComponent>>,
  /// What every [`Source::disarm`] unwinds with from now on, for the cells that need this rig's
  /// plane QUARANTINED before they stage anything.
  panic_every_disarm: Option<Boom>,
  calls: std::sync::Arc<std::sync::Mutex<Vec<HostileCall>>>,
}

impl HostileKeySource {
  fn new() -> Self {
    Self {
      next_handle: 0,
      live: HashMap::new(),
      released: std::collections::HashSet::new(),
      wedged: Vec::new(),
      panic_every_disarm: None,
      calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
    }
  }

  fn note(&self, call: HostileCall) {
    self.calls.lock().expect("hostile ledger").push(call);
  }

  fn ledger(&self) -> std::sync::Arc<std::sync::Mutex<Vec<HostileCall>>> {
    self.calls.clone()
  }

  fn wedge_arm(&mut self, path: &'static str) {
    self.wedged.push(HostileComponent::key(path, false));
  }

  /// EVERY [`Source::disarm`] PANICS with `boom` from now on — [`FakeSource`]'s injector of the
  /// same name, on the rig whose keys are the caller destructors. What a cell arming this plane's
  /// quarantine before its own staging uses.
  fn panic_every_disarm(&mut self, boom: Boom) {
    self.panic_every_disarm = Some(boom);
  }
}

impl Source<HostileComponent> for HostileKeySource {
  type Handle = u32;

  fn canonicalize_key(
    &self,
    key: &[HostileComponent],
  ) -> Result<Vec<HostileComponent>, WatchError> {
    Ok(key.to_vec())
  }

  async fn arm(
    &mut self,
    key: &[HostileComponent],
  ) -> Result<Armed<HostileComponent, u32>, WatchError> {
    self.note(HostileCall::Arm(HostileComponent::names(key)));
    if self.wedged.iter().any(|wedge| wedge.as_slice() == key) {
      core::future::pending::<()>().await;
    }
    self.next_handle += 1;
    let handle = self.next_handle;
    self.live.insert(handle, key.to_vec());
    Ok(Armed::new(handle, key.to_vec()))
  }

  fn disarm(&mut self, handle: u32) {
    self.note(HostileCall::Disarm(handle));
    self.released.insert(handle);
    // Recorded AND applied before the unwind, as [`FakeSource`]'s is: the release happened and then
    // the source blew up in its own bookkeeping, so a cell's claim stays about how far the unwind
    // travels rather than about what was reclaimed.
    if let Some(boom) = self.panic_every_disarm {
      boom.raise();
    }
  }

  async fn next(&mut self) -> Option<SourceEvent<HostileComponent, u32>> {
    core::future::pending().await
  }

  fn end_sync(&mut self, _handle: u32, cookie_key: &[HostileComponent]) {
    self.note(HostileCall::EndSync(HostileComponent::names(cookie_key)));
  }

  fn begin_close(&mut self) {
    self.note(HostileCall::BeginClose);
  }

  async fn join_close(&mut self) -> Result<(), crate::error::SourceCloseError> {
    self.note(HostileCall::JoinClose);
    Ok(())
  }

  fn root_key(&self, handle: u32) -> Option<Vec<HostileComponent>> {
    if self.released.contains(&handle) {
      return None;
    }
    self.live.get(&handle).cloned()
  }
}

/// An [`Owner`] over [`HostileKeySource`], plus the channel ends a driven [`run`](super::run) needs
/// kept open. The [`OwnerOverValue`] of the `C` half.
struct OwnerOverHostileKeys {
  owner: Owner<HostileComponent, (), TokioRuntime, HostileKeySource>,
  _events: async_channel::Receiver<Event<HostileComponent, ()>>,
  /// A clone of the owner's event SENDER, so a cell can fill a bounded stream — see
  /// [`fill_stream`](Self::fill_stream).
  events: async_channel::Sender<Event<HostileComponent, ()>>,
  commands: async_channel::Sender<super::Command<HostileComponent, ()>>,
  _sync_commands: async_channel::Sender<super::SyncRequest>,
  closes: async_channel::Sender<super::CloseReply>,
}

impl OwnerOverHostileKeys {
  fn new() -> Self {
    Self::bounded(usize::MAX)
  }

  /// The rig over an event stream of `capacity` — `usize::MAX` for the unbounded default.
  fn bounded(capacity: usize) -> Self {
    let (event_tx, event_rx) = if capacity == usize::MAX {
      async_channel::unbounded()
    } else {
      async_channel::bounded(capacity)
    };
    let (command_tx, command_rx) = async_channel::unbounded();
    let (sync_command_tx, sync_command_rx) = async_channel::unbounded::<super::SyncRequest>();
    let (close_tx, close_rx) = async_channel::bounded(1);
    let (cleanup_tx, cleanup_rx) = async_channel::unbounded();
    let owner = Owner {
      source: HostileKeySource::new(),
      source_closing: false,
      source_disposals: super::SourceDisposals::default(),
      deferred: crate::subsume::Salvage::new(),
      subsumer: Subsumer::new(),
      epochs: EpochLedger::new(),
      filters: Filters::new(),
      filter_payload_forgotten: false,
      needs_rescan: ParkedRescans::new(),
      suppressed_rescan: ParkedRescans::new(),
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
      events: event_tx.clone(),
      #[cfg(debug_assertions)]
      observed_handles: super::ObservedHandles::new(),
      _rt: PhantomData::<TokioRuntime>,
    };
    Self {
      owner,
      _events: event_rx,
      events: event_tx,
      commands: command_tx,
      _sync_commands: sync_command_tx,
      closes: close_tx,
    }
  }

  /// Fills the event stream with one placeholder, so a consumer that has stopped draining is
  /// modeled: [`flush_pending_rescans`](Owner::flush_pending_rescans) skips a full channel outright,
  /// which leaves parked debt parked instead of delivered.
  fn fill_stream(&self, sub: Subscription) {
    self
      .events
      .try_send(Event::rescan(
        sub,
        HostileComponent::key("/filler", false),
        Epoch::new(0),
      ))
      .expect("fill the event stream");
  }

  /// Hangs a still-pending barrier off `sub`'s root, so the teardown tail owes a cookie reap the
  /// deferred release must stand behind.
  fn park_cookie(
    &mut self,
    sub: Subscription,
    cookie: &'static str,
  ) -> futures_channel::oneshot::Receiver<Result<super::SyncOutcome, crate::error::SyncError>> {
    let root = self
      .owner
      .subsumer
      .subscription_root(sub)
      .expect("live root for the bystander");
    let (reply, response) = futures_channel::oneshot::channel();
    self.owner.pending_syncs.push(super::PendingSync {
      cookie_key: HostileComponent::key(cookie, false),
      sub,
      root,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply,
    });
    response
  }
}

/// The terminal `Disjoint` close race must place EVERY caller key it owns, not only the ones a
/// mutator handed back.
///
/// `#[must_use]` on [`Salvage`](crate::subsume::Salvage) enumerates CALL SITES, so it reaches only
/// what a mutator RETURNS. A terminal reconcile also owns caller keys no mutator ever saw: the plan
/// it is abandoning carried a copy of the key, and the reconcile itself owns the canonicalized key
/// the source built out of the caller's own components and it borrows for its whole body. Both were
/// destroyed by the frame exit, in front of the tail's bounded [`join_close`](Source::join_close)
/// and the acknowledgement carrying its verdict — the same unwind the funnel exists to prevent,
/// arriving through a hole the funnel's own compiler check cannot see.
///
/// The plan's copy is gone outright (the outcome carries no key at all: every variant's root key was
/// a duplicate of the subscription's own with no production reader), and the canonicalized key is
/// placed through the one disposal route once the borrow ends.
///
/// FAIL-ON-REVERT, either half: put `root_key: key.to_vec()` back on
/// [`Disjoint`](crate::subsume::WatchOutcome::Disjoint), or delete the `keep_key(canonical_key)`
/// from [`Owner::reconcile_watch`], and the marked destructor fires inside the reconcile instead:
/// the unwind leaves `run`, `close()` reads the dropped sender as
/// [`Stopped`](crate::error::CloseError::Stopped), and the ledger has neither the cookie reap nor
/// `JoinClose` behind the seam.
#[tokio::test]
async fn a_terminal_disjoint_close_race_places_every_caller_key_it_owns() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverHostileKeys::new();

  // A bystander root carrying the cookie, so the tail owes a reap the release must stand behind.
  let bystander = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  let cookie = rig.park_cookie(bystander, "/x/cookie-disjoint");

  // The newcomer is DISJOINT and its arm hangs, so the close race inside that arm is the only thing
  // that can make this reconcile terminal — and a disjoint watch retires no root, so the ONLY caller
  // keys in play are the request's own, its canonicalization, and the reservation's copy.
  rig.owner.source.wedge_arm("/d");
  let ledger = rig.owner.source.ledger();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      // THE key under test: MARKED, so every copy of it the abandoned reconcile owns names this
      // cell when its destructor unwinds.
      key: HostileComponent::key("/d", true),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the disjoint watch");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the disjoint arm"
  );
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  // Only now can a marked destructor unwind, so the staging above ran over silent drops.
  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the terminal reconcile really did give up a caller key whose destructor unwinds"
  );
  // THE VERDICT, read first because it is the whole claim. `now_or_never` rather than `await`
  // because a REVERT leaves the panicking poll's generator poisoned and undropped, so it still owns
  // the reply sender: awaiting one would hang the cell instead of reporting what broke, and a
  // regression cell has to say. By the time `run` resolves the acknowledgement is already sent, so
  // the one-poll read is exactly the passing case.
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by a caller \
     key destructor unwinding out of the reconcile that consumed the reply"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the arm that consumed the close never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-disjoint"]),
      HostileCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// A converted mutator's INTERIOR is the funnel's other blind spot: `#[must_use]` says what a call
/// site may do with a return, and nothing at all about what the mutator destroys on its way to
/// producing one.
///
/// Several subscriptions may share one key. The dead-root retirement groups the departing
/// subscribers by cover key, and a grouping keyed by an OWNED `Vec<C>` keeps the first and destroys
/// every later duplicate the moment its entry is found occupied — inside
/// [`force_remove_root`](Subsumer::force_remove_root), which the terminal failed-widen unwind calls
/// with [`source_closing`](Owner::source_closing) already latched. One duplicate's caller destructor
/// then unwound in front of the remaining reaps, the bounded wait and the acknowledgement, with the
/// whole bundle the mutator was still assembling lost with it.
///
/// So every removed record is retained BEFORE the grouping runs, and the grouping borrows those
/// retained keys instead of owning one.
///
/// The marking is what makes the reading precise: [`HostileComponent`]'s equality ignores the mark,
/// so the three subscriptions here are at one key while only the two DUPLICATES are marked. The
/// first registration's key is the one the grouping keeps, so a fired destructor can only be a
/// discarded duplicate — never the retirement's own root key, and never a component the teardown
/// merely passed through.
///
/// FAIL-ON-REVERT: group by `entry(sub_record.key)` again (owning the key, retaining only the
/// representative) and the duplicate's destructor fires inside the mutator: the unwind leaves `run`,
/// `close()` reports `Stopped`, and the ledger has neither the cookie reap nor `JoinClose` in it.
#[tokio::test]
async fn a_terminal_retirement_places_the_duplicate_keys_it_removes() {
  use std::task::{Context, Poll, Waker};

  // A stream the cell FILLS below, so the retirement's owed terminal `Rescan`s stay parked instead
  // of being delivered. That is not incidental staging: delivering one CLONES the parked key onto
  // the event and then destroys the parked entry, so a marked component would unwind inside
  // `flush_pending_rescans` — the same class as the defect under test, in the driver's parked-debt
  // plane rather than in a converted mutator, and it would answer this cell's question with the
  // wrong site. Full, the flush is skipped and the only marked destructors left are the mutator's.
  let mut rig = OwnerOverHostileKeys::bounded(1);

  // THREE subscriptions at ONE key. The first is inert — its key is the one a grouping keyed by an
  // owned `Vec<C>` keeps — and the two that follow are the MARKED duplicates such a grouping
  // discards. They are `Covered` by the first's root, so all three ride handle 1 with their own
  // equal keys recorded side by side.
  let first = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a/b", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /a/b");
  let second = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a/b", true),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("re-watch /a/b");
  let third = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a/b", true),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("re-watch /a/b once more");
  let subsumed = rig
    .owner
    .subsumer
    .subscription_root(first)
    .expect("live root for /a/b");
  assert_eq!(
    rig.owner.subsumer.subscribers(subsumed),
    vec![first, second, third],
    "staging: one root, three subscribers, and the marked duplicates behind the inert first"
  );
  rig.fill_stream(first);

  // A bystander root carrying the cookie, so the tail owes a reap the release must stand behind —
  // and a DISJOINT one, so the reap is the tail's own rather than the retirement's domination.
  let bystander = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  let cookie = rig.park_cookie(bystander, "/x/cookie-widen");

  // The widen releases the subsumed root and then hangs on the wider arm: the close lands there, so
  // the reconcile is terminal with a root already disarmed — the unwind that retires it.
  rig.owner.source.wedge_arm("/a");
  let ledger = rig.owner.source.ledger();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      // Inert: the widening request's own key is not what this cell is measuring.
      key: HostileComponent::key("/a", false),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the wider arm, the subsumed root already released"
  );
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the terminal retirement really did give up a duplicate key whose destructor unwinds"
  );
  // `now_or_never` for the reason the sibling cell states: a revert must report, never hang.
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by a \
     duplicate key destroyed inside the mutator"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the terminal widen never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-widen"]),
      HostileCall::JoinClose,
    ],
    "every cookie reaped and the bounded wait made, all ahead of the release that unwound: \
     {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// The teardown tail's own DELIVERY destroys caller state, and it stands ahead of the bounded wait.
///
/// [`Owner::flush_pending_rescans`] is not a [`Subsumer`] mutator, so `#[must_use]` on
/// [`Salvage`](crate::subsume::Salvage) cannot see it at all: it clones the parked key onto the
/// event it mints and then CLEARS the parked entry, whose key and baked value are the caller's own.
/// The tail runs it (`drain_owed_once`) between the cookie reaps and
/// [`join_close`](Source::join_close), so a caller component destructor unwinding there takes the
/// source's verdict and the acknowledgement with it.
///
/// This is the site the sibling retirement cell had to stage AROUND — it fills the event stream so
/// this flush is skipped — which is what makes it measured rather than inferred.
///
/// The staging is exact in three ways. The debt is planted at a key of its OWN, not at the
/// subscription's, because a marked key that is also a radix key is destroyed earlier by the
/// persistent tree's own node collapse (see [`Salvage`](crate::subsume::Salvage)'s stated
/// mid-mutator limit) and would name that instead. The stream is FULL across the first poll, so the
/// flush at the top of each loop iteration delivers nothing on a live pass. And it is drained
/// before the terminal poll, so the tail's flush is the one pass with room to deliver.
///
/// FAIL-ON-REVERT: put `self.needs_rescan.remove(&sub);` back in place of the placement on either
/// the `Ok` or the `Closed` arm, and the parked entry's destructor fires inside the flush: the
/// unwind leaves `run`, `close()` reads the dropped sender as
/// [`Stopped`](crate::error::CloseError::Stopped), and the ledger has the reap but no `JoinClose`.
#[tokio::test]
async fn a_terminal_tail_flush_places_the_parked_entry_it_delivers() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverHostileKeys::bounded(1);

  // The debt's owner, at an INERT key — the radix stores this one, and this cell is not about it.
  let owed = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  // THE key under test: parked debt at a key of its own, MARKED, living nowhere but this entry.
  rig
    .owner
    .needs_rescan
    .merge_max::<u32>(
      owed,
      HostileComponent::key("/x/lost", true),
      Epoch::new(1),
      Some(()),
    )
    .release();
  // A cookie on the same root, so the tail owes a reap the flush must stand behind.
  let cookie = rig.park_cookie(owed, "/x/cookie-flush");
  // FULL across the first poll: the top-of-iteration flush skips a full channel outright, so the
  // planted debt survives every live pass.
  rig.fill_stream(owed);

  // The newcomer is DISJOINT and its arm hangs, so the close race inside that arm is the only thing
  // that makes this reconcile terminal — and a disjoint watch retires no root, so no retirement
  // competes with the flush for the one unwind this cell spends.
  rig.owner.source.wedge_arm("/d");
  let ledger = rig.owner.source.ledger();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: HostileComponent::key("/d", false),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the disjoint watch");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the disjoint arm"
  );
  assert!(
    _events.try_recv().is_ok(),
    "staging: drain the filler so the TAIL's flush is the first pass with room to deliver"
  );
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the teardown really did give up a caller key whose destructor unwinds"
  );
  // `now_or_never` rather than `await`: a REVERT leaves the panicking poll's generator poisoned and
  // undropped, so it still owns the reply sender and an await would hang instead of reporting.
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by the \
     parked entry the tail's own flush cleared"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );
  assert!(
    !_events.is_empty(),
    "staging: the flush really delivered the owed Rescan — an undelivered one clears no entry and \
     measures nothing"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the terminal disjoint arm never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-flush"]),
      HostileCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// A merge that WIDENS a parked key destroys the components it truncates off, and a merge that
/// re-bakes a value destroys the one it displaces — both by plain in-place mutation, which no
/// `#[must_use]` can see.
///
/// The terminal retirement parks a `Rescan` for every subscriber of the dying root. A subscriber
/// that ALREADY carries parked debt takes the occupied arm, where the parked key is truncated down
/// to the two keys' common prefix — and the truncated tail is caller components. The retirement
/// runs from the failed widen's unwind with
/// [`source_closing`](Owner::source_closing) already latched, so this is in front of the tail's
/// reaps, its bounded wait and its acknowledgement.
///
/// The standing debt is parked here through the ordinary door (a merge onto an empty plane) at a
/// key one component DEEPER than the subscription's own — the shape a source-emitted `Rescan`
/// parked at its own located key produces — so the retirement's merge really has a tail to shed,
/// and only that tail is marked.
///
/// FAIL-ON-REVERT: make `widen_to_cover` truncate again (`parked.truncate(common)`) instead of
/// splitting the tail off into the bundle, and the truncated component's destructor fires inside
/// the merge: the unwind leaves `run`, `close()` reports `Stopped`, and the ledger has no
/// `JoinClose`.
#[tokio::test]
async fn a_terminal_merge_places_the_key_tail_it_widens_away() {
  use std::task::{Context, Poll, Waker};

  // A stream the cell FILLS below, so the tail's flush is skipped outright and the only merge in
  // play is the retirement's own.
  let mut rig = OwnerOverHostileKeys::bounded(1);

  // Inert key: this cell measures the TRUNCATED TAIL, not the subscription's own components.
  let doomed = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a/b", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /a/b");

  // Standing debt at `/a/b/deep`, one component below the subscription's key and MARKED — so the
  // retirement's merge against `/a/b` sheds exactly `deep` and nothing else.
  let mut deep = HostileComponent::key("/a/b", false);
  deep.extend(HostileComponent::key("/deep", true));
  rig
    .owner
    .needs_rescan
    .merge_max::<u32>(doomed, deep, Epoch::new(1), Some(()))
    .release();
  rig.fill_stream(doomed);

  let bystander = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  let cookie = rig.park_cookie(bystander, "/x/cookie-merge");

  rig.owner.source.wedge_arm("/a");
  let ledger = rig.owner.source.ledger();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: HostileComponent::key("/a", false),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the wider arm, the subsumed root already released"
  );
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the widening merge really did shed a component whose destructor unwinds"
  );
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by a key \
     tail truncated away inside the merge"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the terminal widen never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-merge"]),
      HostileCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// A subscription's ADMISSION GATE is caller code, and the tail's queued grant cleanup retires it.
///
/// [`Owner::retire_sub_state`] reclaims the per-subscription [`Filter`], and a `Filter` boxes a
/// caller predicate that may own anything at all — so the reclaim runs a caller destructor that no
/// key component stands in for. Both retire paths reach it on the terminal side of the seam; this
/// cell takes the failed widen's, where the retirement runs with
/// [`source_closing`](Owner::source_closing) latched and every reap, the bounded wait and the
/// acknowledgement still owed.
///
/// The key is INERT throughout, so the only destructor that can unwind is the gate's.
///
/// FAIL-ON-REVERT: put `self.filters.remove(&sub);` back in place of the placement, and the
/// predicate's captured state is destroyed inside the retirement: the unwind leaves `run`,
/// `close()` reports `Stopped`, and the ledger has no `JoinClose`.
#[tokio::test]
async fn a_terminal_retirement_places_the_admission_gate_it_reclaims() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverHostileKeys::new();

  // The gate under test rides the subscription the terminal widen retires. The driver takes sole
  // ownership of the filter at commit, so retiring the entry is what drops the predicate.
  rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a/b", false),
      &(),
      WatchOptions::new().with_filter(hostile_filter()),
    )
    .await
    .expect("watch /a/b");

  let bystander = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  let cookie = rig.park_cookie(bystander, "/x/cookie-gate");

  rig.owner.source.wedge_arm("/a");
  let ledger = rig.owner.source.ledger();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: HostileComponent::key("/a", false),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the widen");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the wider arm, the subsumed root already released"
  );
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the terminal retirement really did give up a gate whose predicate state unwinds"
  );
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by a caller \
     filter destroyed inside the retirement"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the terminal widen never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-gate"]),
      HostileCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// The gate a terminal reconcile NEVER INSTALLED is caller code too, and the frame that owned it
/// is the one being abandoned.
///
/// [`reconcile_canonical_watch`](Owner::reconcile_canonical_watch) is handed the caller's
/// [`Filter`] and consumes it only where it COMMITS. Every other way out is a
/// [`ReconcileStop`](super::ReconcileStop) that says nothing about the gate — so while the
/// reconcile OWNED it, a terminal exit destroyed an uninstalled `Filter`, whose boxed predicate
/// holds whatever the caller likes. That destructor ran as the inner future completed: before the
/// outer frame resumed, before the bounded [`join_close`](Source::join_close), and before the
/// acknowledgement carrying its verdict.
///
/// It is the canonicalized key's sibling and takes the key's shape: the gate lives in a slot the
/// CALLER's frame owns, a commit takes it out, and the borrow ends when the reconcile returns.
///
/// The key is INERT throughout — this is the wedged-arm close race the key cell drives, with the
/// marking moved onto the gate — so the only destructor that can unwind is the one belonging to a
/// gate that was never installed.
///
/// FAIL-ON-REVERT: take `filter: Filter<C>` by value again and install it directly, and the
/// predicate's captured state is destroyed inside the abandoned reconcile: the unwind leaves `run`,
/// `close()` reports `Stopped`, and the ledger has no `JoinClose`.
#[tokio::test]
async fn a_terminal_reconcile_places_the_gate_it_never_installed() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverHostileKeys::new();

  // A bystander root carrying the cookie, so the tail owes a reap the release must stand behind.
  let bystander = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  let cookie = rig.park_cookie(bystander, "/x/cookie-uninstalled");

  // The newcomer is DISJOINT and its arm hangs, so the close race inside that arm is the only thing
  // that can make this reconcile terminal — and it goes terminal BEFORE any commit, which is the
  // one state in which the gate is still the reconcile's to lose.
  rig.owner.source.wedge_arm("/d");
  let ledger = rig.owner.source.ledger();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      // INERT key, so no copy of it can stand in for the gate when a destructor fires.
      key: HostileComponent::key("/d", false),
      value: (),
      options: WatchOptions::new()
        .with_interest(Interest::all())
        .with_filter(hostile_filter()),
      reply: watch_reply,
    })
    .expect("enqueue the disjoint watch");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the disjoint arm, nothing committed"
  );
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the abandoned reconcile really did give up a gate whose predicate state unwinds"
  );
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by an \
     uninstalled gate destroyed inside the reconcile that consumed the reply"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the arm that consumed the close never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-uninstalled"]),
      HostileCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// The tail's queued GRANT CLEANUP purges parked debt, and that debt is the caller's.
///
/// A committed-but-unclaimed [`WatchGrant`] whose caller never polls the reply enqueues a
/// [`Cleanup::DropOrphan`], which the teardown tail drains
/// ([`drain_pending_cleanup`](Owner::drain_pending_cleanup)) into
/// [`release_subscription`](Owner::release_subscription). That release purges the sub's parked
/// overflow `Rescan` — an entry owning a caller key and the caller value baked onto it — between
/// the tail's cookie reaps and its bounded [`join_close`](Source::join_close).
///
/// The orphan is enqueued only AFTER the loop has parked inside a wedged arm, because the loop
/// drains this channel at the top of every iteration: queued earlier it would be released on a LIVE
/// path, where the release is correct and measures nothing.
///
/// FAIL-ON-REVERT: put `self.needs_rescan.remove(&sub);` / `self.suppressed_rescan.remove(&sub);`
/// back in place of the placements, and the parked entry's destructor fires inside the release:
/// the unwind leaves `run`, `close()` reports `Stopped`, and the ledger has no `JoinClose`.
#[tokio::test]
async fn a_terminal_grant_cleanup_places_the_parked_debt_it_purges() {
  use std::task::{Context, Poll, Waker};

  // FILLED below, so the flush at the top of each loop iteration is skipped and the planted debt
  // survives to the tail's cleanup drain instead of being delivered on a live pass.
  let mut rig = OwnerOverHostileKeys::bounded(1);

  // Inert key: the debt's own parked key is what this cell marks, not the subscription's.
  let orphan = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/p", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /p");
  rig
    .owner
    .needs_rescan
    .merge_max::<u32>(
      orphan,
      HostileComponent::key("/p", true),
      Epoch::new(1),
      Some(()),
    )
    .release();
  rig.fill_stream(orphan);

  let bystander = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  let cookie = rig.park_cookie(bystander, "/x/cookie-orphan");

  // The newcomer is DISJOINT and its arm hangs, so the close race inside that arm is what makes the
  // reconcile terminal — and a disjoint watch retires no root, so the ONLY thing that can purge the
  // planted debt is the tail's own cleanup drain.
  rig.owner.source.wedge_arm("/d");
  let ledger = rig.owner.source.ledger();
  let cleanup_tx = rig.owner.cleanup_tx.clone();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: HostileComponent::key("/d", false),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the disjoint watch");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the disjoint arm"
  );
  // The grant's caller dropped its wait: exactly one `Cleanup::DropOrphan` fires per grant, and the
  // loop is parked, so the tail is the first thing that can drain it.
  drop(super::WatchGrant::new(orphan, cleanup_tx));
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the tail's cleanup drain really did purge a parked key whose destructor unwinds"
  );
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by parked \
     debt purged inside the release"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the terminal disjoint arm never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-orphan"]),
      // The release emptied the orphan's root, so its synchronous fire-and-forget disarm rides here
      // too — on the far side of the seam, where a best-effort request belongs.
      HostileCall::Disarm(1),
      HostileCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// A settle window nothing in a cell can outlive, so an admitted delta is still BUFFERED when the
/// teardown reaches it.
fn parked_debounce() -> DebounceConfig {
  DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3600))
    .with_max_hold(Duration::from_secs(3600))
}

/// The teardown flush EMPTIES two indexes, and their keys are the caller's — a `clear()` and a
/// discarded destructuring binding, neither of which returns anything for `#[must_use]` to guard.
///
/// [`Coalescer::flush_all`] force-emits the coalesced tail so a source drain loses nothing, and
/// the events themselves are DELIVERED. What used to die where it stood is the bookkeeping around
/// them: the deadline index was `clear()`ed, and consuming the buffer discarded each map-owned key
/// under a `_path` binding. Both are deep copies of the caller's own components, and the tail runs
/// this ([`drain_owed_once`](Owner::drain_owed_once)) between the cookie reaps and the bounded
/// [`join_close`](Source::join_close).
///
/// The delta belongs to the BYSTANDER, which nothing in this cell releases — so no purge can reach
/// its entries first and the tail's flush is the only thing that empties them.
///
/// FAIL-ON-REVERT, either half: put `self.deadlines.clear()` back, or drop each buffer key under a
/// `_path` binding again, and the marked component is destroyed inside the flush: the unwind leaves
/// `run`, `close()` reports `Stopped`, and the ledger has no `JoinClose`.
#[tokio::test]
async fn a_terminal_coalescer_flush_places_the_index_keys_it_empties() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverHostileKeys::new();

  let bystander = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  let cookie = rig.park_cookie(bystander, "/x/cookie-flush");

  rig.owner.coalescer = Some(Coalescer::new(Some(parked_debounce())));
  // MARKED: the admitted event's key is deep-copied into the buffer's own key and into the deadline
  // index's, and those two copies are what the flush gives up. The event carries a third and is
  // delivered whole, so a fired destructor can only belong to an index copy or to the release.
  rig.owner.push_all(std::vec![Event::synthetic(
    bystander,
    HostileComponent::key("/x/f", true),
    Location::new(),
    EventKind::Modified,
    Epoch::new(1),
  )]);
  assert!(
    rig
      .owner
      .coalescer
      .as_ref()
      .is_some_and(|coalescer| coalescer.next_deadline().is_some()),
    "staging: the delta is still buffered, so the tail's flush is what empties both indexes"
  );

  rig.owner.source.wedge_arm("/d");
  let ledger = rig.owner.source.ledger();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: HostileComponent::key("/d", false),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the disjoint watch");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the disjoint arm"
  );
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the tail's flush really did give up an index key whose destructor unwinds"
  );
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by an index \
     key destroyed inside the teardown flush"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the terminal disjoint arm never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-flush"]),
      HostileCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// `BTreeMap::remove` hands back the VALUE and destroys the KEY, and the key is the caller's.
///
/// This is the sub-class a search for unsalvaged removals misses, because such a search reads what a
/// removal RETURNS. The coalescer's purge salvaged the scan's copy of the key, the deadline
/// index's copy, and the buffered event — and let `self.buffer.remove(&key)` destroy the copy the
/// MAP owned, inside the call, unmentioned. Neither `#[must_use]` nor a private-map wrapper can see
/// it: the removal does return something and the site does use it. `remove_entry` is the whole fix,
/// and finding the site is the whole work.
///
/// It is terminal-reachable through the tail's own cleanup drain: `drain_pending_cleanup` →
/// [`release_subscription`](Owner::release_subscription) →
/// [`Coalescer::forget_subscription`] → [`Coalescer::drop_subscription`], with
/// [`source_closing`](Owner::source_closing) latched and the bounded
/// [`join_close`](Source::join_close) and the acknowledgement both still owed.
///
/// FAIL-ON-REVERT: put `self.buffer.remove(&key)` back in place of `remove_entry`, and the
/// map-owned key's destructor fires inside the purge — ahead of every other copy, which the loop
/// salvages only afterwards: the unwind leaves `run`, `close()` reports `Stopped`, and the ledger
/// has no `JoinClose`.
#[tokio::test]
async fn a_terminal_purge_places_the_map_owned_key_its_removal_destroyed() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverHostileKeys::new();

  // Watched FIRST, so its root is handle 1 — the disarm the release requests below.
  let orphan = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/p", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /p");
  let bystander = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  let cookie = rig.park_cookie(bystander, "/x/cookie-purge");

  rig.owner.coalescer = Some(Coalescer::new(Some(parked_debounce())));
  // MARKED, and buffered for the ORPHAN — the subscription the tail's cleanup drain releases, so
  // the purge reaches this entry before the tail's own flush could.
  rig.owner.push_all(std::vec![Event::synthetic(
    orphan,
    HostileComponent::key("/p/f", true),
    Location::new(),
    EventKind::Modified,
    Epoch::new(1),
  )]);
  assert!(
    rig
      .owner
      .coalescer
      .as_ref()
      .is_some_and(|coalescer| coalescer.next_deadline().is_some()),
    "staging: the delta is buffered under a map-owned key the purge must hand back"
  );

  rig.owner.source.wedge_arm("/d");
  let ledger = rig.owner.source.ledger();
  let cleanup_tx = rig.owner.cleanup_tx.clone();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: HostileComponent::key("/d", false),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the disjoint watch");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the disjoint arm"
  );
  // The grant's caller dropped its wait: exactly one `Cleanup::DropOrphan` fires per grant, and the
  // loop is parked, so the tail is the first thing that can drain it.
  drop(super::WatchGrant::new(orphan, cleanup_tx));
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the tail's purge really did give up a buffered key whose destructor unwinds"
  );
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by the \
     map-owned key a removal destroyed"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the terminal disjoint arm never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-purge"]),
      // The release emptied the orphan's root, so its synchronous fire-and-forget disarm rides here
      // too — on the far side of the seam, where a best-effort request belongs.
      HostileCall::Disarm(1),
      HostileCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// The set-cover RE-RECORD supersedes a cover by plain field assignment, and the tail reaches it.
///
/// [`Subsumer::set_retained_cover`] replaces a root's recorded coverage. The record it replaces is
/// an `Option<Vec<Vec<C>>>` of caller components, and a plain assignment destroys it where it
/// stands — the shape no `#[must_use]` can see, because nothing is returned at all.
///
/// It is terminal-reachable through the tail's own cleanup drain: `drain_pending_cleanup` →
/// `release_subscription` → `plan_unwatch` → `Dropped { shrink: Some(..) }` → this re-record, with
/// [`source_closing`](Owner::source_closing) latched and the bounded
/// [`join_close`](Source::join_close) and the acknowledgement both still owed.
///
/// Reaching it with a NON-EMPTY previous record takes two shrinks: the root-key subscriber departs
/// first (recording `{/a/b, /a/c}` over a full-coverage `None`), and only the SECOND departure —
/// the orphan the tail releases — replaces a record that actually owns caller components. The
/// record is then re-recorded with `/a/c` MARKED, which decides nothing (the mark is outside the
/// component's equality) and leaves the marked components living in the RECORD alone, so a fired
/// destructor can only be the superseded record's.
///
/// FAIL-ON-REVERT: assign the field again (`record.retained_cover = cover;`) in place of the
/// `mem::replace` whose result is placed, and the superseded cover's destructor fires inside the
/// mutator: the unwind leaves `run`, `close()` reports `Stopped`, and the ledger has no
/// `JoinClose`.
#[tokio::test]
async fn a_terminal_cover_re_record_places_the_cover_it_supersedes() {
  use std::task::{Context, Poll, Waker};

  let mut rig = OwnerOverHostileKeys::new();

  // One root at /a with three subscribers: the root-key one, an inert survivor, and the MARKED
  // departure whose components the second re-record supersedes.
  let wide = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /a");
  rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a/b", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /a/b");
  let departing = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/a/c", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /a/c");
  let root = rig
    .owner
    .subsumer
    .subscription_root(wide)
    .expect("live root for /a");

  // First shrink, on a LIVE path: the root-key subscriber departs, leaving the root over-broad, so
  // the cover is recorded for the first time — over a `None`, which supersedes nothing.
  rig
    .owner
    .release_subscription(wide)
    .expect("release the root-key subscriber");
  assert_eq!(
    rig.owner.subsumer.retained_cover_of(root),
    Some(vec![
      HostileComponent::key("/a/b", false),
      HostileComponent::key("/a/c", false)
    ]),
    "staging: the record now OWNS caller components, so the next re-record has one to supersede"
  );
  // Re-record the SAME cover with the departing prefix MARKED. The mark is outside the component's
  // equality, so this narrows nothing and changes no decision — it only puts the marked components
  // where this cell needs them: in the RECORD, and nowhere else. A key that is also a radix key
  // would be destroyed earlier by the tree's own node collapse (see
  // [`Salvage`](crate::subsume::Salvage)'s stated mid-mutator limit) and would name that instead.
  rig
    .owner
    .subsumer
    .set_retained_cover(
      root,
      Some(vec![
        HostileComponent::key("/a/b", false),
        HostileComponent::key("/a/c", true),
      ]),
    )
    .release();

  let bystander = rig
    .owner
    .reconcile_watch(
      &HostileComponent::key("/x", false),
      &(),
      WatchOptions::new(),
    )
    .await
    .expect("watch /x");
  let cookie = rig.park_cookie(bystander, "/x/cookie-cover");

  rig.owner.source.wedge_arm("/d");
  let ledger = rig.owner.source.ledger();
  let cleanup_tx = rig.owner.cleanup_tx.clone();

  let OwnerOverHostileKeys {
    owner,
    _events,
    events: _events_tx,
    commands,
    _sync_commands,
    closes,
  } = rig;
  let (watch_reply, _watch_response) = futures_channel::oneshot::channel();
  commands
    .try_send(super::Command::Watch {
      key: HostileComponent::key("/d", false),
      value: (),
      options: WatchOptions::new().with_interest(Interest::all()),
      reply: watch_reply,
    })
    .expect("enqueue the disjoint watch");

  let mut cx = Context::from_waker(Waker::noop());
  let mut run = Box::pin(super::run(owner));
  assert!(
    run.as_mut().poll(&mut cx).is_pending(),
    "staging: the run loop is parked inside the disjoint arm"
  );
  drop(super::WatchGrant::new(departing, cleanup_tx));
  let (close_reply, close_response) = futures_channel::oneshot::channel();
  closes.try_send(close_reply).expect("request the close");

  let unwound_before = HOSTILE_COMPONENT_UNWOUND.get();
  HOSTILE_COMPONENT_ARMED.set(true);
  let drove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.as_mut().poll(&mut cx)));
  HOSTILE_COMPONENT_ARMED.set(false);

  assert_eq!(
    HOSTILE_COMPONENT_UNWOUND.get() - unwound_before,
    1,
    "staging: the tail's second shrink really did supersede a cover whose destructor unwinds"
  );
  assert!(
    matches!(
      futures_util::FutureExt::now_or_never(close_response),
      Some(Ok(Ok(())))
    ),
    "close() must still carry the SOURCE's quiescence verdict, not a Stopped invented by a cover \
     superseded inside the re-record"
  );
  assert!(
    matches!(drove, Ok(Poll::Ready(()))),
    "nothing may escape the run loop"
  );

  let calls = ledger.lock().expect("hostile ledger").clone();
  let split = calls
    .iter()
    .position(|call| *call == HostileCall::BeginClose)
    .unwrap_or_else(|| panic!("the terminal disjoint arm never entered the seam: {calls:?}"));
  assert_eq!(
    &calls[split..],
    &[
      HostileCall::BeginClose,
      HostileCall::EndSync(std::vec!["x", "cookie-cover"]),
      HostileCall::JoinClose,
    ],
    "the reap and the bounded wait both stand ahead of the release that unwound: {calls:?}"
  );
  assert!(
    matches!(futures_util::FutureExt::now_or_never(cookie), Some(Err(_))),
    "the reaped barrier's caller sees the dropped reply as Closed"
  );
}

/// The deferral must be ENGAGED ONLY on the terminal path.
///
/// [`Owner::retire_salvage`] holds a mutator's caller-owned removals when
/// [`source_closing`](Owner::source_closing) stands and releases them at the call site otherwise,
/// and only the second half bounds the bundle: the latch is set once, by the decision to tear this
/// owner down, so what accumulates is one teardown's worth of removals and the owner is gone
/// immediately after. Engage it on a live path instead and every committed watch, every departure
/// and every dead-root retirement retains its caller `C`/`V` for as long as the watcher runs — an
/// unbounded leak in the shape of ordinary traffic, and one no other cell would notice, since
/// nothing observable changes until memory runs out.
///
/// So both halves are read here, over the same mutator, with only the latch between them: the LIVE
/// side proves the bundle stays empty through a commit, a departure and a retirement; the TERMINAL
/// side proves that emptiness is the latch working rather than the bundle being unreachable.
///
/// FAIL-ON-REVERT: make [`Owner::retire_salvage`] defer unconditionally (drop the `source_closing`
/// test) and the first live assertion fails. Make it release unconditionally and the terminal
/// assertion fails.
#[tokio::test]
async fn the_deferral_is_engaged_on_the_terminal_path_alone() {
  let mut h = Harness::new();

  // LIVE — a commit.
  let a = h.watch("/a", Interest::all()).await.expect("watch /a");
  let b = h.watch("/b", Interest::all()).await.expect("watch /b");
  assert!(
    h.owner.deferred.is_empty(),
    "a committed watch deferred something: its republish displaced a publication, and on a live \
     path that publication is the caller's to have back at once"
  );

  // LIVE — a departure, which removes the subscription record, its cover value and (its root now
  // being empty) the root record too.
  h.unwatch(a).expect("unwatch /a");
  assert!(
    h.owner.deferred.is_empty(),
    "a departure deferred something"
  );

  // LIVE — a dead-root retirement, the heaviest live mutator there is: it force-removes the root,
  // every subscriber's record and every cover value in one pass.
  let root_b = h
    .owner
    .subsumer
    .subscription_root(b)
    .expect("live root for /b");
  h.owner.retire_root_with_terminal_rescan(root_b);
  assert!(
    h.owner.deferred.is_empty(),
    "a dead-root retirement deferred something on a LIVE path — the bundle would then grow with \
     ordinary traffic, forever"
  );

  // TERMINAL — the same mutator, with only the latch changed.
  let c = h.watch("/c", Interest::all()).await.expect("watch /c");
  let root_c = h
    .owner
    .subsumer
    .subscription_root(c)
    .expect("live root for /c");
  h.owner.begin_source_close();
  h.owner.retire_root_with_terminal_rescan(root_c);
  assert!(
    !h.owner.deferred.is_empty(),
    "past the seam the same retirement must HOLD its removals — otherwise the live emptiness above \
     says nothing about the deferral and everything about it being dead code"
  );
}

/// Queues one public `Watch` on the command mailbox exactly as [`Tributaries::watch`] does, with
/// its reply slot already abandoned — the caller in this shape only asks whether the send was
/// ADMITTED. Returns the mailbox's own verdict.
fn queue_public_watch(
  commands: &async_channel::Sender<super::Command<OsString, ()>>,
) -> Result<(), async_channel::TrySendError<super::Command<OsString, ()>>> {
  let (reply, response) = futures_channel::oneshot::channel();
  drop(response);
  commands.try_send(super::Command::Watch {
    key: key("/refused"),
    value: (),
    options: WatchOptions::new(),
    reply,
  })
}

/// A refused request is HELD, so the teardown that refuses one must bound how many it can be
/// handed.
///
/// The source-drain retry keeps servicing the public mailbox for as long as the owed delivery
/// takes, and [`handle_teardown_command`](Owner::handle_teardown_command) PLACES every refused
/// request's key, value and admission gate rather than destroying them. Holding is right; holding
/// an unbounded number of them is not. The mailbox bounds what sits there at one instant and
/// nothing more: a live handle refills it as fast as the drain empties it, and behind a full event
/// channel the drain runs until the consumer resumes — so acceptance turns a bounded backlog into
/// unbounded retention, with the owner's memory as the only stop. Nothing has to unwind for that to
/// bite; it is a defect about RETAINING, not about ordering a destruction that happens anyway.
///
/// So this reads a COUNT rather than an emptiness. The mailbox is filled to capacity before the
/// drain starts, and a handle then pushes far more at it than the mailbox could ever hold — one
/// push per drain poll, for the whole life of the drain. What the teardown retains must still be
/// exactly one mailbox's worth.
///
/// FAIL-ON-REVERT: drop the `self.commands.close()` at the top of
/// [`drain_owed_before_shutdown`](Owner::drain_owed_before_shutdown) and put its public-command
/// `select!` arm back, and every post-cut push is admitted and retained: the count climbs with the
/// flood instead of standing at the mailbox's capacity.
#[tokio::test]
async fn a_source_drain_teardown_bounds_what_its_refusals_retain() {
  use std::task::{Context, Waker};

  /// The mailbox's whole capacity — the bound the retention may not exceed.
  const MAILBOX: usize = 4;
  /// Post-teardown pushes, far past anything the mailbox could hold at once.
  const FLOOD: usize = 200;

  let mut h = Harness::bounded_mailbox(1, MAILBOX);
  // A CLAIMED sub whose dominating Rescan is parked behind a FULL, held-open event channel: the
  // drain can neither deliver it nor exit, which is exactly the long window a live handle refills.
  let live = h.watch("/a", Interest::all()).await.expect("watch /a");
  for raw in 0..2 {
    h.owner.epochs.stamp(live, Epoch::new(raw));
  }
  h.owner.try_emit(modified_event(live, "/a/f0", 0));
  h.owner.try_emit(modified_event(live, "/a/f1", 1));
  assert!(
    h.owner.needs_rescan.contains_key(&live),
    "staging: the claimed sub's Rescan is parked behind a full channel, so the drain must retry"
  );
  let _held = h.events.clone(); // a receiver that never drains: full AND open for the whole cell

  // The pre-cut backlog: one mailbox's worth, and provably no more.
  for _ in 0..MAILBOX {
    queue_public_watch(&h._commands).expect("prefill the mailbox to capacity");
  }
  assert!(
    queue_public_watch(&h._commands).is_err(),
    "staging: the mailbox is full, so what the drain can INHERIT is capped by its capacity"
  );

  // The tail enters the seam before it runs this drain, and that latch is what makes
  // `retire_salvage` HOLD rather than release at the call site — so without it the refusals below
  // are disposed of live and the count would read zero for the wrong reason.
  h.owner.begin_source_close();

  let commands = h._commands.clone();
  let mut cx = Context::from_waker(Waker::noop());
  let mut drain = Box::pin(h.owner.drain_owed_before_shutdown());
  let mut admitted_after_the_cut = 0usize;
  for _ in 0..FLOOD {
    if queue_public_watch(&commands).is_ok() {
      admitted_after_the_cut += 1;
    }
    assert!(
      drain.as_mut().poll(&mut cx).is_pending(),
      "the drain stays in its retry loop — the owed Rescan is undeliverable and the consumer lives"
    );
  }
  drop(drain);

  assert_eq!(
    admitted_after_the_cut, 0,
    "a push after the cut must fail in the CALLER's frame, where the request it hands back is the \
     caller's own to destroy, instead of reaching the owner to be held"
  );
  assert_eq!(
    h.owner.deferred.filters_len(),
    MAILBOX,
    "the teardown holds exactly the pre-cut backlog: {FLOOD} further pushes retained nothing"
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
    source_closing: false,
    source_disposals: super::SourceDisposals::default(),
    deferred: crate::subsume::Salvage::new(),
    subsumer: Subsumer::new(),
    epochs: EpochLedger::new(),
    filters: Filters::new(),
    filter_payload_forgotten: false,
    needs_rescan: ParkedRescans::new(),
    suppressed_rescan: ParkedRescans::new(),
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
    .reconcile_watch(&key("/a"), &(), WatchOptions::new())
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
    source_closing: false,
    source_disposals: super::SourceDisposals::default(),
    deferred: crate::subsume::Salvage::new(),
    subsumer: Subsumer::new(),
    epochs: EpochLedger::new(),
    filters: Filters::new(),
    filter_payload_forgotten: false,
    needs_rescan: ParkedRescans::new(),
    suppressed_rescan: ParkedRescans::new(),
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
/// flood: a handle pushing `Watch` at the owner for the whole teardown cannot starve
/// `drain_owed_once`, and an already-CLAIMED parked Rescan is delivered within a bounded window.
///
/// The drain CUTS the public mailbox before its first pass, so the flood's sends fail in the
/// flooding task's own frame and never reach the owner at all; what the drain inherits is the
/// backlog queued at the cut, drained once. Servicing the mailbox is therefore bounded by
/// construction rather than by a fairness budget, and the owed pass runs on every iteration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_drain_delivers_claimed_debt_under_sustained_command_flood() {
  let mut h = Harness::new(); // unbounded event channel — has capacity
  let live = h.watch("/a", Interest::all()).await.expect("watch /a"); // claimed (Harness::watch)
  for raw in 0..2 {
    h.owner.epochs.stamp(live, Epoch::new(raw));
  }
  h.owner.park_rescan(live);

  let flood = spawn_command_flood(h._commands.clone());
  // The flood races the drain's cut: whatever it queued before it is serviced once, and every push
  // after it fails outside the owner. Either way the owed pass runs on every iteration, so the
  // claimed Rescan is delivered long before the timeout lapses.
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
/// drain is surfaced within a bounded window even after a sustained command flood has piled a deep
/// backlog into the mailbox. [`drain_owed_before_shutdown`](super::Owner::drain_owed_before_shutdown)
/// checks the dedicated close signal FIRST — a non-blocking `try_recv` ahead of the pre-cut backlog
/// drain, AND the first arm of its retry `select!` — so the close outranks every queued request. A
/// claimed sub's parked overflow Rescan behind a full, held-open channel keeps the drain spinning
/// (so the close-check is genuinely exercised mid-drain).
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

  // A sustained command flood, filling the mailbox ahead of the drain and pushing at it after.
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

/// The FIRST sync an owner admits mints `seq = 1`. [`Owner::sync_seq`] starts at 0 and
/// `on_sync` PRE-increments it before minting the token, so 0 is a value no cookie name has
/// ever carried — which is what entitles the fs binding's classifier to refuse a `seq` of 0
/// as a user file rather than suppressing it.
///
/// The seq is taken from the token the real admission path handed to `begin_sync`, not
/// asserted as a constant: if a later release switches the counter to a post-increment (or
/// seeds it elsewhere), the first cookie of every owner starts carrying a `seq` the
/// classifier refuses — a genuine cookie republished on every consumer stream as a user
/// create — and that change fails HERE, at the minter, instead of leaking in production.
/// `source::fs::tests::the_classifier_accepts_the_name_the_first_sync_of_an_owner_mints`
/// pins the accepting side of the same seam.
///
/// FAIL-ON-REVERT: take the counter's OLD value (`let seq = self.sync_seq; self.sync_seq +=
/// 1;` and mint from `seq`) and the first token carries 0.
#[tokio::test]
async fn the_first_sync_an_owner_admits_mints_seq_one() {
  use core::sync::atomic::Ordering;

  let mut h = Harness::new();
  h.owner.source.supports_sync = true;
  let sub = h.watch("/a", Interest::all()).await.expect("watch /a");

  // The caller's receiver stays alive: an already-canceled reply is skipped before any token
  // is minted, which would leave `begun_token` empty and make this cell vacuous.
  let loss_gen = h.owner.loss_gen.load(Ordering::SeqCst);
  let (reply_tx, _reply_rx) = futures_channel::oneshot::channel();
  h.owner.on_sync(sub, loss_gen, reply_tx).await;

  let token = h
    .owner
    .source
    .begun_token
    .expect("the first admitted sync minted a token");
  assert_eq!(
    token.seq(),
    1,
    "the first cookie of an owner carries seq 1 — the counter is pre-incremented, so no sync \
     ever renders 0"
  );
  assert_ne!(
    token.instance(),
    0,
    "the instance brand is a NonZeroU64, so no cookie name carries instance 0 either"
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
  // …and on a cookie observed as a move's SOURCE endpoint.
  // ---------------------------------------------------------------------------

  /// A cookie renamed OUT of the reserved namespace is observed at the move's **source**
  /// endpoint, which [`SourceEvent::key`](crate::SourceEvent::key) — the destination — does
  /// not name. The owner saw the ordered post-cookie proof either way: the queue reached the
  /// cookie, which is the whole content of the barrier. Matching the pending key against the
  /// destination alone therefore left this barrier parked on an event that can never arrive,
  /// until its caller's own timeout fired over a source that had done nothing wrong.
  ///
  /// Both halves are asserted, as in the destination row: the barrier resolves AND the user
  /// endpoint — here the move's destination, an ordinary name the artifact was adopted into
  /// — is still delivered as its own projection.
  async fn assert_a_cookie_leaving_the_reserved_namespace_resolves_its_barrier(
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

    // The artifact leaves the namespace: source = the cookie, destination = a user name.
    h.owner.consume_source_event(&source_moved_at(
      1,
      cookie,
      cookie_location,
      "/a/adopted",
      "adopted",
      1,
    ));

    let delivered = h.drain();
    let projected = delivered
      .iter()
      .find(|e| e.subscription() == sub)
      .expect("the user endpoint is delivered, barrier or no barrier");
    assert!(
      projected.kind().is_created(),
      "the covered endpoint is the destination, so the move projects to a Created: \
       {projected:?}"
    );
    assert_eq!(
      projected.path(),
      Path::new("/a/adopted"),
      "keyed on the user endpoint, never on the reserved source"
    );
    assert_eq!(
      projected.move_from(),
      None,
      "a Created names no other endpoint, so the cookie path cannot leak through it"
    );
    assert!(
      matches!(
        (&mut reply_rx).now_or_never(),
        Some(Ok(Ok(SyncOutcome::Delivered)))
      ),
      "the cookie was observed as the move's SOURCE endpoint, which resolves the barrier"
    );
  }

  /// FAIL-ON-REVERT: match the pending key against `event.key()` alone in
  /// `resolve_matching_pending_sync` (dropping the `masks_source` arm) and the reply stays
  /// pending — `now_or_never()` answers `None` — while the caller waits out its deadline.
  #[tokio::test]
  async fn a_cookie_leaving_the_reserved_namespace_resolves_its_barrier_by_leaf_grammar() {
    assert_a_cookie_leaving_the_reserved_namespace_resolves_its_barrier("/a/cookie-7", "cookie-7")
      .await;
  }

  /// The same, on the parent-directory ground.
  #[tokio::test]
  async fn a_cookie_leaving_the_reserved_namespace_resolves_its_barrier_by_parent_directory() {
    let (cookie, location) = inside_the_cookie_directory("anything");
    assert_a_cookie_leaving_the_reserved_namespace_resolves_its_barrier(&cookie, &location).await;
  }

  /// A rename BETWEEN two reserved names classifies `All` — nothing about it may reach any
  /// subscriber — and the pending cookie can sit at EITHER end of it. This cell pins the end
  /// a destination-only match misses: the barrier's cookie is the move's **source**, renamed
  /// away to another reserved name.
  ///
  /// The suppression is asserted alongside the resolution: a both-reserved change reaching a
  /// subscriber would be the namespace leak the masking exists to prevent, and a barrier
  /// certificate is no licence for it.
  ///
  /// FAIL-ON-REVERT: as above — restore the `event.key()`-only match and the reply stays
  /// pending, because the key names the reserved DESTINATION and the cookie is at the source.
  #[tokio::test]
  async fn a_cookie_renamed_between_two_reserved_names_resolves_at_its_source_endpoint() {
    let mut h = Harness::new();
    let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
    let handle = h.owner.subsumer.subscription_root(sub).expect("live root");
    h.drain();

    let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
    h.owner.pending_syncs.push(crate::driver::PendingSync {
      cookie_key: key("/a/cookie-7"),
      sub,
      root: handle,
      loss_serial_at_install: 0,
      dominated_at_install: false,
      reply: reply_tx,
    });

    // Both endpoints are reserved, and the pending cookie is the SOURCE one. The destination
    // uses the parent-directory ground, so the two ends are reserved on DIFFERENT grounds and
    // neither verdict could have been inferred from the other.
    let (destination, destination_location) = inside_the_cookie_directory("renamed");
    h.owner.consume_source_event(&source_moved_at(
      1,
      "/a/cookie-7",
      "cookie-7",
      &destination,
      &destination_location,
      1,
    ));

    assert!(
      h.drain().is_empty(),
      "a change reserved at every endpoint reaches nobody, barrier or no barrier"
    );
    assert!(
      matches!(
        (&mut reply_rx).now_or_never(),
        Some(Ok(Ok(SyncOutcome::Delivered)))
      ),
      "the cookie was observed at the move's source endpoint, which resolves the barrier"
    );
  }

  /// ONE move can name TWO pending cookies. Barriers coexist routinely — a `RootHandle` is
  /// `Copy` and one subscription may hold several — so two completed sync writes `K1` and `K2`
  /// can both be outstanding when a single `All` move relates them (`K1` renamed onto `K2`).
  /// That observation is ordered after BOTH writes and therefore proves both: each caller's
  /// cookie is on disk and the queue has reached past it.
  ///
  /// Resolving only the first is a silent stall, not a slower answer. Overwriting `K2` need
  /// not produce any further record of it — the move IS its last event — so the unresolved
  /// caller waits out its own deadline over a source that did exactly what it was asked.
  ///
  /// The third, unrelated barrier is here for the removal mechanics rather than the
  /// arithmetic, and its POSITION is the point: it sits in the MIDDLE, so the vector's tail is
  /// a MATCH. `swap_remove` moves the tail into the vacated slot, so resolving the source
  /// barrier at index 0 relocates the DESTINATION barrier down into index 0 — and a scan that
  /// advanced its cursor past a removal would step over exactly that relocated match and leave
  /// its caller waiting forever. Had the unrelated entry been last instead, the skipped element
  /// would have been the one nothing is waiting on, the destination barrier would still resolve
  /// from its original slot, and every assertion below would stay green under the mutation the
  /// stationary cursor exists to prevent.
  ///
  /// FAIL-ON-REVERT — two distinct mutations, and this cell must catch BOTH:
  /// * put back the single `position()` + `swap_remove()` in `resolve_matching_pending_sync`
  ///   (resolve the first match and return) and the DESTINATION barrier never completes —
  ///   `now_or_never()` answers `None` — while its entry stays in `pending_syncs` with nothing
  ///   left to match it;
  /// * advance the cursor on a removal (`i += 1` after the `swap_remove`, instead of leaving it
  ///   stationary) and that same destination barrier is skipped — `swap_remove` had just moved
  ///   it down into the slot the cursor abandoned — so it is never reaped, never answered, and
  ///   is still sitting in `pending_syncs` at the end.
  #[tokio::test]
  async fn one_move_naming_two_pending_cookies_resolves_both_barriers() {
    let mut h = Harness::new();
    let sub = h.watch("/a", Interest::all()).await.expect("watch /a");
    let handle = h.owner.subsumer.subscription_root(sub).expect("live root");
    h.drain();

    // The move's two endpoints, reserved on DIFFERENT grounds (leaf grammar / cookie
    // directory), so neither barrier's match could have been inferred from the other's.
    let (destination, destination_location) = inside_the_cookie_directory("renamed");

    let mut install = |cookie: &str| {
      let (reply_tx, reply_rx) = futures_channel::oneshot::channel();
      h.owner.pending_syncs.push(crate::driver::PendingSync {
        cookie_key: key(cookie),
        sub,
        root: handle,
        loss_serial_at_install: 0,
        dominated_at_install: false,
        reply: reply_tx,
      });
      reply_rx
    };
    // Order matters: a MATCH is at the tail, with the unrelated entry between the two matches.
    // The first `swap_remove` therefore relocates the destination barrier into the cursor's own
    // slot, which is the only arrangement under which a cursor that advanced on a removal skips
    // an entry anyone is waiting on.
    let mut at_source = install("/a/cookie-7");
    // Not named by this move at all: it must still be waiting afterwards.
    let mut unrelated = install("/a/cookie-99");
    let mut at_destination = install(&destination);

    h.owner.consume_source_event(&source_moved_at(
      1,
      "/a/cookie-7",
      "cookie-7",
      &destination,
      &destination_location,
      1,
    ));

    assert!(
      h.drain().is_empty(),
      "a change reserved at every endpoint reaches nobody, barriers or no barriers"
    );
    assert!(
      matches!(
        (&mut at_source).now_or_never(),
        Some(Ok(Ok(SyncOutcome::Delivered)))
      ),
      "the barrier whose cookie is the move's source resolves"
    );
    assert!(
      matches!(
        (&mut at_destination).now_or_never(),
        Some(Ok(Ok(SyncOutcome::Delivered)))
      ),
      "and so does the barrier whose cookie is the move's destination — one observation \
       proves both writes, so it must answer both callers, and this is the entry `swap_remove` \
       relocated into the slot the cursor deliberately does not advance past"
    );
    assert!(
      (&mut unrelated).now_or_never().is_none(),
      "the barrier this move never named is left waiting for its own cookie"
    );

    // Each resolved entry kept the full per-entry sequence, reap included: its marker is
    // released, and it is gone from the pending set rather than left for `Owner::drop`.
    assert_eq!(
      h.owner.source.ended_syncs,
      vec![key("/a/cookie-7"), key(&destination)],
      "both cookies are reaped, each before its own outcome is sent"
    );
    assert_eq!(
      h.owner
        .pending_syncs
        .iter()
        .map(|pending| pending.cookie_key.clone())
        .collect::<Vec<_>>(),
      vec![key("/a/cookie-99")],
      "exactly the unmatched barrier survives the scan"
    );
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
      .flush_all::<u32>(&mut held)
      .release();
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

  /// The same flood against a **current-thread** executor — the mode where "the loop keeps
  /// spinning" stops being a latency question and becomes a liveness one.
  ///
  /// A [`Source`] may legally return `Some` on every poll, the biased `select!` puts that arm
  /// above the timer, and consuming a record awaits nothing — a wholly reserved one does not
  /// even reach the channel. So the owner task can complete iteration after iteration without
  /// one await that returns `Pending`. On tokio's `new_current_thread` (and single-threaded
  /// smol, both supported) that task then owns the thread outright: the subscriber draining
  /// the stream, the `close()` caller and every unrelated task stop being polled for as long
  /// as the source stays ready — which, for another process syncing against the same tree, is
  /// indefinitely.
  ///
  /// The multi-threaded flood cell above cannot see this: a second worker keeps the consumer
  /// running whatever the owner does. That runtime flavour was in fact chosen to get around
  /// this very behaviour while the cell was being written, so the workaround was the defect.
  ///
  /// Both halves are proven ON that executor, and the user record is released MID-flood (the
  /// source mints it between cookies, never ahead of them), so the delivery is evidence that
  /// source servicing kept reaching a consumer while the flood ran:
  ///   1. `w.next()` hands over the user's change;
  ///   2. `w.close()` — which rides its own channel, but only reaches it if the CALLER is
  ///      polled — completes.
  ///
  /// # Why the worker thread
  ///
  /// A livelocked owner cannot be shut down and `block_on` never returns, so an in-runtime
  /// timeout is worthless: its own task is not polled either, and a failing run would HANG
  /// rather than fail. So the runtime is built on a worker thread and this thread waits on a
  /// channel with a deadline. On expiry it sets the flood's stop flag — the source then drains
  /// (`next` answers `None`) and the worker unwinds to completion — and fails loudly with the
  /// livelock named. A cell that can only hang is a cell that proves nothing under mutation.
  ///
  /// FAIL-ON-REVERT: drop the `SOURCE_FAIRNESS_BUDGET` yield at the foot of `run`'s loop and
  /// this cell fails on the deadline — "the current-thread runtime never reported: the owner
  /// task monopolized the executor" — instead of on an assertion, which is exactly what the
  /// livelock is.
  #[test]
  fn a_current_thread_executor_survives_an_endlessly_ready_source() {
    let stop = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    // Belt and braces with the explicit store below: the flood must stop on EVERY way out of
    // this frame, or a leaked worker thread spins for the rest of the test binary's life.
    let _stop_on_exit = StopFloodOnDrop(stop.clone());
    let (release_tx, release_rx) = async_channel::unbounded::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();

    let worker_stop = stop.clone();
    let worker = std::thread::spawn(move || {
      let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the current-thread runtime builds");
      runtime.block_on(async move {
        let source = EndlessReservedFloodSource {
          next_handle: 0,
          live: HashMap::new(),
          release: release_rx,
          minted: 0,
          stop: worker_stop,
        };
        let mut w: super::super::Tributaries<OsString, (), TokioRuntime, u32> =
          super::super::Tributaries::with_source(source, TributariesOptions::new());
        let sub = w
          .watch(key("/a"), (), WatchOptions::new())
          .await
          .expect("watch /a"); // handle 1

        // From here the source is ready on every poll, forever. Release one user record
        // into the middle of that stream.
        release_tx.try_send(()).expect("release the user change");

        let event = w
          .next()
          .await
          .expect("the stream is open while the flood runs");
        assert_eq!(event.subscription(), sub, "routed to the covering sub");
        assert_eq!(
          event.path(),
          Path::new("/a/f"),
          "…and it is the user's change, not a cookie"
        );

        w.close().await.expect("close is acknowledged");
        // Only reached when both halves completed; a panic above disconnects the channel
        // instead, which this thread's waiter reports as a failure rather than a livelock.
        let _ = done_tx.send(());
      });
    });

    let verdict = done_rx.recv_timeout(Duration::from_secs(20));
    // Whatever happened, let the worker finish: a still-spinning source keeps the thread hot.
    stop.store(true, core::sync::atomic::Ordering::SeqCst);
    match verdict {
      Ok(()) => worker.join().expect("the worker thread completed cleanly"),
      // The worker panicked (an assertion failed): surface its own message.
      Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
        let panic = worker
          .join()
          .expect_err("a disconnect means the worker unwound");
        std::panic::resume_unwind(panic);
      }
      Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
        let _ = worker.join();
        panic!(
          "the current-thread runtime never reported: the owner task monopolized the \
           executor under an endlessly ready source, so neither the consumer nor the \
           close caller was ever polled"
        );
      }
    }
  }

  /// A source with an unbounded supply of reserved records and no `Pending` in it: past the
  /// first arm, every poll returns `Some` immediately. One user record can be spliced into the
  /// middle of that stream by the test, so a delivery proves servicing continued DURING the
  /// flood rather than merely before it.
  ///
  /// Distinct from [`ArtifactFloodSource`] on purpose: that one holds its user record back
  /// behind an awaited trigger and emits it FIRST, which is what its own cell needs.
  struct EndlessReservedFloodSource {
    next_handle: u32,
    live: HashMap<u32, Vec<OsString>>,
    /// Probed non-blockingly on each poll: a token here mints the user record in place of
    /// that poll's cookie, so it arrives BETWEEN flood records.
    release: async_channel::Receiver<()>,
    minted: u64,
    stop: std::sync::Arc<core::sync::atomic::AtomicBool>,
  }

  impl Source<OsString> for EndlessReservedFloodSource {
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

    /// The parent-directory ground — a cookie whose leaf name follows no grammar this crate
    /// knows, which is the shape another `Watcher` over the same tree actually produces.
    fn is_sync_artifact(&self, key: &[OsString]) -> bool {
      key
        .len()
        .checked_sub(2)
        .and_then(|parent| key[parent].to_str())
        .is_some_and(|parent| parent == COOKIE_DIR)
    }

    async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
      // Nothing is minted before a root is armed: a record naming a handle this source has
      // not issued reads as a DEAD-root record and takes the retirement path, not the flood
      // path. The `watch` command that arms is what wakes this select, so parking here costs
      // no wakeup of its own.
      if self.live.is_empty() {
        core::future::pending::<()>().await;
      }
      // The escape hatch the waiting thread uses to end a livelocked run: draining the source
      // is the one thing that stops the flood without the owner having to be polled by anyone.
      if self.stop.load(core::sync::atomic::Ordering::SeqCst) {
        return None;
      }
      self.minted += 1;
      // Cancellation-safe: the token and the record it mints are taken on the same poll that
      // returns `Ready`, so a losing `select!` arm dropping this future loses neither.
      let key = match self.release.try_recv() {
        Ok(()) => key("/a/f"),
        Err(_) => key(&format!("/a/{COOKIE_DIR}/{}", self.minted)),
      };
      Some(SourceEvent::new(
        1,
        key,
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
        .reconcile_watch(&key("/a"), &(), WatchOptions::new())
        .await
        .expect("watch /a");
      let poisoned = h
        .owner
        .reconcile_watch(
          &key("/a/b"),
          &(),
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
        .reconcile_watch(&key("/c"), &(), WatchOptions::new())
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
        .reconcile_watch(&key("/a"), &(), WatchOptions::new())
        .await
        .expect("watch /a");
      let poisoned = h
        .owner
        .reconcile_watch(
          &key("/a/b"),
          &(),
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
        .reconcile_watch(&key("/c"), &(), WatchOptions::new())
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
      .reconcile_watch(&key("/a"), &(), WatchOptions::new())
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
