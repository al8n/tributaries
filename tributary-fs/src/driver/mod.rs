//! The async driver task: a thin executor around [`DriverCore`].
//!
//! Every decision lives in the sans-I/O core; this loop only moves bytes —
//! it selects over the command channel, the core's one timer, the blocking
//! pool's results, and every root's OS batches, executes the core's
//! [`Effect`]s (stream spawn/teardown and probes on the blocking pool, event
//! delivery by `try_send`), and feeds each outcome straight back in.
//!
//! # The one-sample rule
//!
//! Every fact this executor reports about a filesystem OBJECT — kind, device,
//! inode, mount frame — comes from ONE sample of that object: a single `statx`
//! (or `symlink_metadata`) of one path, or one `fstat` of one pinned fd. Never
//! two path syscalls whose results are then paired, because a rename or bind
//! toggling between them would pair one object's identity with another's frame,
//! and the identity checks downstream (a per-directory arm confirms only
//! `(dev, ino)`) would then admit a foreign object. The Linux enumerate, the
//! root-liveness refresh, and the spawn barriers all obey it — see
//! [`stat_sample`], [`root_liveness_and_frame`], and the pinned-fd reads in
//! `os::linux`.
//!
//! The Linux backends REQUIRE `statx` (Linux 4.11+): the spawn barrier probes it
//! once up front and refuses a kernel below the floor (see `os::linux`), so this
//! executor's live-path sample ([`stat_sample`]) is always a `statx` and never
//! needs a sub-`statx` fallback. A `statx` mask miss (no `STATX_MNT_ID` below 5.8)
//! still drops just the mount frame (absent, never mixed in from a second lookup)
//! and the core fences that object on the device belt — so the rule holds either
//! way: one object, one sample.

use std::{
  collections::{BTreeMap, BTreeSet, HashMap},
  num::NonZeroUsize,
  path::{Path, PathBuf},
  sync::{
    Arc, Mutex, MutexGuard, PoisonError,
    atomic::{AtomicBool, AtomicU64, Ordering},
  },
  time::Duration,
};

use agnostic_lite::{RuntimeLite, time::Instant as _};
use futures_util::{FutureExt, StreamExt, stream::SelectAll};
use tributary_proto::{
  Change, Instant, Interest, IoClass, ReqId, ScopeId, Segment, WatchError, WatchId,
};

use crate::{
  core::{
    CoverNoop, CoverReconcile, CoverSettle, Delivery, DriverCore, Effect, ExpectedObject, FenceId,
    MountRefresh, ProbeId, ProbeOutcome, RawDirEntry, RawEnumerate, RootLiveness,
  },
  error::WatchRootError,
  os::{
    Backend, BackendKind, EventReceiver, RootIdentity, RootMeta, ScopePort, Source, SourceConfig,
    SourceError, SourceHandle, SourceMessage, linux::WatchOutcome,
  },
  watcher::{CoverOutcome, SkipReason},
};

#[cfg(all(test, feature = "tokio"))]
pub(crate) mod testing;
#[cfg(all(test, feature = "tokio"))]
mod tests;

/// The driver-side knobs a watcher hands its task.
#[derive(Debug, Clone)]
pub(crate) struct DriverConfig {
  /// The OS event-coalescing latency.
  pub(crate) latency: Duration,
  /// The requested rename-pairing window; the effective window never falls
  /// below what the latency makes physically necessary.
  pub(crate) move_window: Duration,
  /// Per-root capacity of the callback→driver channel, in batches.
  pub(crate) os_batch_capacity: NonZeroUsize,
  /// Load-shedding exclusion directories applied to every root.
  pub(crate) exclusions: Vec<PathBuf>,
  /// The backend lowering profile every root registers with — the PROVISIONAL
  /// Monitor profile (the platform's descending default on Linux). Under
  /// [`Backend::Auto`] the spawn barrier probes and the core adopts the
  /// resolved backend's profile at [`on_stream_spawned`]; a forced backend
  /// makes this the final profile.
  ///
  /// [`on_stream_spawned`]: DriverCore::on_stream_spawned
  pub(crate) profile: BackendKind,
  /// The per-root backend SELECTION the spawn barrier honors: [`Backend::Auto`]
  /// probes and falls back, the explicit variants pin the choice (a forced
  /// [`Backend::Fanotify`] surfaces a typed error instead of falling back).
  /// Ignored on macOS. The Monitor profile above is provisional until this
  /// resolves.
  pub(crate) backend: Backend,
  /// The periodic root-liveness deadline for signal-silent-on-unmount backends
  /// (fanotify): the driver re-stats such a root on this cadence so a quiet
  /// unmount — which emits no kernel signal and no loss — is still detected.
  /// [`Duration::ZERO`] disables the tick.
  pub(crate) root_liveness_interval: Duration,
  /// The fanotify admission-map directory cap (design §4.9); `None` = uncapped.
  /// Threaded into each fanotify spawn's `SourceConfig`; ignored by inotify and
  /// macOS.
  pub(crate) max_map_directories: Option<usize>,
  /// First-retry delay for a failed cookie unlink; the backoff doubles per
  /// attempt up to [`cookie_retry_cap`](Self::cookie_retry_cap).
  pub(crate) cookie_retry_base: Duration,
  /// The cookie-unlink backoff ceiling.
  pub(crate) cookie_retry_cap: Duration,
  /// Max unlink attempts per arming; then an UNMARKED record PARKS
  /// (`RemoveFailed`, unscheduled) until an explicit re-arm (a fresh reap/cancel,
  /// a retire sweep, or the close sweep). A record still carrying a reap mark is
  /// serviced into one fresh arming at that exhaustion instead (see
  /// [`CookieRegistry::schedule_retry`]). Never a spin — the fresh arming
  /// consumes the mark.
  pub(crate) cookie_retry_budget: u8,
  /// Per-scope unremoved-cookie cap: at or above it, a new `SyncRoot` command
  /// is refused [`CleanupBacklog`](crate::error::SyncRootError::CleanupBacklog)
  /// — the per-scope memory bound on the ledger.
  pub(crate) cookie_backlog_cap: usize,
  /// GLOBAL unremoved-cookie cap across every scope, live or retired: at or
  /// above it a new `SyncRoot` is refused `CleanupBacklog` whatever scope owns
  /// the residue. The per-scope cap resets for each fresh scope, so without this
  /// a sync→failing-cleanup→unwatch→rewatch churn would grow `owned` without
  /// bound across RETIRED scopes; this ceiling makes total ledger memory bounded
  /// regardless of churn, and self-heals as the cleanup retries drain.
  pub(crate) cookie_global_cap: usize,
}

impl DriverConfig {
  /// First-retry delay for a failed cookie unlink (§1.9 default).
  pub(crate) const DEFAULT_COOKIE_RETRY_BASE: Duration = Duration::from_millis(100);
  /// Cookie-unlink backoff ceiling (§1.9 default).
  pub(crate) const DEFAULT_COOKIE_RETRY_CAP: Duration = Duration::from_secs(5);
  /// Cookie-unlink attempt budget per arming (§1.9 default).
  pub(crate) const DEFAULT_COOKIE_RETRY_BUDGET: u8 = 8;
  /// Per-scope unremoved-cookie cap (§1.9 default).
  pub(crate) const DEFAULT_COOKIE_BACKLOG_CAP: usize = 8;
  /// Global unremoved-cookie cap across all scopes — several scopes' worth of
  /// per-scope headroom, so ordinary multi-root use never trips it while a
  /// permafailing-unlink churn stays bounded.
  pub(crate) const DEFAULT_COOKIE_GLOBAL_CAP: usize = 128;

  /// The platform's native backend profile — PROVISIONAL under
  /// `Backend::Auto` (the resolved `RootMeta.backend` supersedes it at
  /// spawn); on Windows the provisional and resolved profiles are both
  /// kernel-recursive, so the reconcile is always profile-stable there.
  pub(crate) fn platform_profile() -> BackendKind {
    if cfg!(target_os = "linux") {
      BackendKind::Inotify
    } else if cfg!(target_os = "windows") {
      BackendKind::Rdcw
    } else {
      BackendKind::FsEvents
    }
  }
}

impl DriverConfig {
  /// The rename window actually armed — the same total derivation the public
  /// options expose (see [`WatcherOptions::effective_move_window`]).
  ///
  /// [`WatcherOptions::effective_move_window`]: crate::WatcherOptions::effective_move_window
  pub(crate) fn effective_move_window(&self) -> Duration {
    crate::options::derive_move_window(self.move_window, self.latency)
  }
}

/// The reply channel of one `Command::Watch`, carrying a [`WatchGrant`] on
/// success.
pub(crate) type WatchReply = futures_channel::oneshot::Sender<Result<WatchGrant, WatchRootError>>;

/// The dispatch plumbing of one sync-cookie write parked on its scope's
/// coverage-settle fence: where the cookie is to be written, and the reply that
/// carries its path back to the caller at write-complete.
///
/// ROUTING ONLY — this map answers "which caller does this fence belong to",
/// nothing else. The parked write's TRUTH is its ledger obligation
/// ([`Phase::Parked`]), born at admission: which syncs are parked, which scope
/// each belongs to, its name, and whether a cancel has marked it are all read
/// from the ledger, so no gauge, cancel, or sweep depends on this local. The
/// driver is the only mutator of both sides and moves them in lockstep — an
/// entry here exists exactly while its obligation is `Parked`.
struct ParkedCookie {
  dir: PathBuf,
  reply: futures_channel::oneshot::Sender<Result<PathBuf, crate::error::SyncRootError>>,
}

/// The immutable identity of ONE cookie-record incarnation, minted under the
/// ledger lock when the record is born (the sync's admission). A path can be
/// REUSED across incarnations (a direct fs-API caller reusing a cookie name
/// recreates the same path after the old file is unlinked); the id cannot. Every
/// internal completion carries the id of the record it was spawned for, and every
/// record mutation it performs is conditioned on the id still matching — the
/// record-level mirror of the per-scope root generation (R6-5): stale actors
/// become no-ops instead of acting on the wrong incarnation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct CookieId(u64);

/// A test-only tally of every obligation BIRTH and every typed terminal, kept
/// under the ledger mutex so it cannot race the transitions it counts. It exists
/// to assert the census equation — `births = ConfirmedGone + NeverCreated +
/// AbnormalResidual + live` — which is the structural proof that no obligation
/// ever leaves the ledger untyped: the equation can only hold if every removal
/// went through [`LedgerInner::retire`] naming its evidence.
#[cfg(all(test, feature = "tokio"))]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct Census {
  births: u64,
  confirmed_gone: u64,
  never_created: u64,
  abnormal_residual: u64,
}

#[cfg(all(test, feature = "tokio"))]
impl Census {
  fn count(&mut self, reaped: Reaped) {
    let counter = match reaped {
      Reaped::ConfirmedGone => &mut self.confirmed_gone,
      Reaped::NeverCreated => &mut self.never_created,
      Reaped::AbnormalResidual => &mut self.abnormal_residual,
    };
    *counter += 1;
  }

  /// Every birth is accounted for exactly once: as one of the three typed
  /// terminals, or as a record still live in the ledger.
  fn balances(&self, live: usize) -> bool {
    self.births == self.confirmed_gone + self.never_created + self.abnormal_residual + live as u64
  }
}

/// Everything the pool and the driver must observe atomically about cookies:
/// one mutex, so a claim, a reap-request mark, and a record transition can never
/// interleave (see [`CookieGuard::claim`] and [`CookieIngress::mark`]). Shared
/// with the watcher handle as the cleanup ingress ([`cookie_ingress`]), so a
/// public reap or cancel is a transition on this same state. Replaces the bare
/// `HashMap<PathBuf, ScopeId>` the ledger was before the lifecycle state machine.
struct LedgerInner {
  /// Every cookie obligation the driver has admitted and not yet retired, keyed
  /// by its immutable incarnation id. The ONE insert site is the sync's ADMISSION
  /// ([`CookieRegistry::admit_parked`]), always with a freshly minted, unique
  /// id, so an insert can never displace an existing obligation: a same-path
  /// successor gets its own key and both records coexist until each earns its own
  /// terminal. The value carries the landing path and the lifecycle phase.
  ///
  /// Because birth is admission — not the later dispatch — this map is the WHOLE
  /// gauge: `len()` is the global cap's Φ in one term, with a parked sync and a
  /// dispatched write each counted exactly once, from one store, with nothing to
  /// dedup against a second one.
  ///
  /// Shared with the blocking pool: a dispatched write publishes the path it
  /// ACTUALLY landed at (see [`CookieGuard::claim`]), because only the write
  /// knows it — a cookie for a covered FILE subscription lands in the file's
  /// PARENT. Publishing under the lock the sweeps and cancels take is what makes
  /// the unorderable operations safe: no interleaving can leave a created file
  /// that nobody owns.
  obligations: HashMap<CookieId, Obligation>,
  /// Landing path -> incarnation id: the index a public path-addressed removal
  /// resolves through, filled when the write learns where its cookie landed (only
  /// the write does — a covered FILE subscription lands in the PARENT).
  /// Newest-claim-wins on a hostile same-path reuse: a claim overwrites the
  /// entry, never the displaced record, which keeps its own key and reaches its
  /// terminal through the id-addressed sweeps. Removed with its record, only
  /// while it still points BACK to that id (a successor's entry is never
  /// clobbered).
  by_path: HashMap<PathBuf, CookieId>,
  /// Rendered cookie file NAME -> incarnation id, for cancel-by-name lookup. The
  /// name (not the path) is what the canceller knows: the umbrella lost the path
  /// (only the write learns where the cookie landed) but can re-render the name
  /// from the token it minted. Inserted at BIRTH, so a cancel-by-name always has
  /// a target whatever the obligation's phase — including a write still in the
  /// pool, which is what lets the reap mark ride the record instead of a
  /// free-standing tombstone. One entry per record; removed with the record while
  /// it still points back to that id (newest-birth-wins on a hostile name reuse).
  by_name: HashMap<String, CookieId>,
  /// The id mint (§1.1). Bumped under this mutex ONCE per admitted sync, at
  /// ADMISSION ([`CookieRegistry::admit_parked`]) — the ONE site that inserts a
  /// record, so mint and birth are one step and an id can never be minted for a
  /// record that is never born. The id then rides the guard the dispatch hands
  /// its write, through the [`CookieGuard::claim`] that adopts it and any
  /// `self_reap`, so one sync carries one id across its whole lifecycle. `u64`
  /// monotone, driver-lifetime only (no persistence, no wraparound concern), so
  /// no two incarnations ever share an id.
  next_cookie_id: u64,
  /// The LRU clock for recovery re-arm ordering (R11-1). Bumped under this
  /// mutex at every transition INTO `RemoveFailed`, stamping the failing
  /// record's `last_failure_seq` — so a record that keeps failing keeps moving
  /// to the BACK of the recovery selection order (`rearm_parked_batch`).
  failure_clock: u64,
  #[cfg(all(test, feature = "tokio"))]
  census: Census,
}

impl LedgerInner {
  fn new() -> Self {
    Self {
      obligations: HashMap::new(),
      by_path: HashMap::new(),
      by_name: HashMap::new(),
      next_cookie_id: 0,
      failure_clock: 0,
      #[cfg(all(test, feature = "tokio"))]
      census: Census::default(),
    }
  }

  /// Removes incarnation `id` and its two index entries — the ONLY way a record
  /// leaves the ledger. Because the record is keyed by its id, the removal is
  /// structural: a confirm for incarnation N can never delete a successor M that
  /// reclaimed the same path (M has a different key). Returns the removed record
  /// (`None` if it was already retired — a racing confirm, or the abnormal-path
  /// take).
  ///
  /// Each index entry is dropped only while it still points BACK to this id: the
  /// umbrella mints per-sync-unique names (owner-global seq + nonce), so this is
  /// always true for it, but a direct fs-API caller that reused one name across
  /// two live incarnations must not have the survivor's index clobbered by the
  /// other's retire.
  fn retire(&mut self, id: CookieId, reaped: Reaped) -> Option<Obligation> {
    let ob = self.obligations.remove(&id)?;
    #[cfg(all(test, feature = "tokio"))]
    self.census.count(reaped);
    #[cfg(not(all(test, feature = "tokio")))]
    let _ = reaped;
    if let Some(path) = ob.path.as_ref()
      && self.by_path.get(path) == Some(&id)
    {
      self.by_path.remove(path);
    }
    if self.by_name.get(&ob.name) == Some(&id) {
      self.by_name.remove(&ob.name);
    }
    Some(ob)
  }

  /// A transient unlink failure landed for incarnation `id`: bump the record's
  /// attempt count, PARK it as `RemoveFailed` (no deadline — only the driver
  /// owns the clock, so only the driver schedules), and refresh its LRU re-arm
  /// key. Returns the new attempt count, or `None` if the record has since been
  /// retired (the abnormal-path take), so this failure is stale and touches
  /// nothing — not even the clock: only a real failure of a live incarnation
  /// advances the LRU order.
  ///
  /// Called by the job that performed the failing unlink, under this mutex,
  /// BEFORE it reports the verdict: physical truth is written by the job that
  /// learned it, so a lost completion message can cost promptness (the record
  /// parks awaiting a re-arm) but never ownership truth (a `Removing` record
  /// nothing re-arms). Reads the count as it stands — never assuming `Removing`
  /// — the tolerance rule that makes every rare interleaving converge.
  fn record_remove_failed(&mut self, id: CookieId) -> Option<u8> {
    if !self.obligations.contains_key(&id) {
      return None;
    }
    // Stamp the LRU clock under this same lock the failure transition rides, so
    // a stale failure can never refresh a successor's key.
    self.failure_clock += 1;
    let seq = self.failure_clock;
    let ob = self
      .obligations
      .get_mut(&id)
      .expect("the record was present under this held lock");
    let attempts = match ob.phase {
      Phase::Removing { attempts } | Phase::RemoveFailed { attempts, .. } => attempts,
      Phase::Parked { .. } | Phase::InPool | Phase::Owned => 0,
    }
    .saturating_add(1);
    ob.phase = Phase::RemoveFailed {
      attempts,
      retry_at: None,
    };
    ob.last_failure_seq = seq;
    Some(attempts)
  }
}

/// The typed terminal of a cookie obligation — the reason a [`retire`] removes a
/// record, stated at every removal site so a removal can never be an untyped
/// inference.
///
/// [`retire`]: LedgerInner::retire
#[derive(Clone, Copy, Debug)]
enum Reaped {
  /// The unlink returned `Ok` or already-gone — the file is confirmed removed.
  ConfirmedGone,
  /// Nothing physical was ever created for this incarnation: a write that
  /// failed before it landed a file.
  NeverCreated,
  /// The abnormal-path [`Drop`] backstop swept the record best-effort, outside
  /// any orderly close grace.
  AbnormalResidual,
}

/// One cookie obligation's ledger record: the scope it belongs to, its rendered
/// name (kept so retiring the record can also drop its `by_name` index without
/// recomputation), its immutable incarnation identity, the path it landed at, the
/// reap mark, its LRU re-arm key, and its lifecycle phase.
struct Obligation {
  scope: ScopeId,
  name: String,
  /// Immutable incarnation identity — also this record's ledger key. Never
  /// changes for the life of the record; a same-path successor gets a fresh one.
  id: CookieId,
  /// The path the write landed the cookie at, learned only once the write
  /// reports it. `None` while the sync is parked on its fence or its write is
  /// still in the pool; `Some(P)` from the claim (or the refused claim's
  /// self-reap) onward — the sweeps and the abnormal-path backstop unlink
  /// through it, and `by_path` maps it back to this id. A pathless record is
  /// exactly one for which no file can exist yet, so every sweep leaves it to
  /// its own write (or, parked, to its pre-physical terminal) rather than
  /// unlinking.
  path: Option<PathBuf>,
  /// This obligation must not survive: set by a cancel that names it, whatever
  /// its phase. It rides the record rather than a free-standing tombstone set,
  /// so it cannot be set for an obligation that does not exist, cannot be left
  /// behind by any other refusal, and dies with the record it marks — the
  /// boundedness rule holds by construction instead of by a sweep protocol.
  /// [`CookieGuard::claim`] reads its OWN record's mark inside the same critical
  /// section as the shutdown/retiring/generation refusals, so a cancel either
  /// finds the cookie owned (and reaps it through the phase machine) or refuses
  /// the claim before ownership ever lands — no third interleaving.
  reap_requested: bool,
  /// The R11-1 LRU re-arm key — the `failure_clock` value stamped at the
  /// record's most recent transition into `RemoveFailed` (0 = never failed;
  /// unreachable for a parked record, which required ≥ 1 failure). Refreshed
  /// on EVERY failure, so a permafailing record that was just re-armed and
  /// failed again moves BEHIND every record that failed before it: recovery
  /// selection (`rearm_parked_batch`) becomes least-recently-failed-first,
  /// which is what makes it starvation-free.
  last_failure_seq: u64,
  phase: Phase,
}

/// The per-record lifecycle phase. `attempts` counts unlink attempts MADE for
/// the current arming; it rides the record (not a driver-local map) so the close
/// drain and the live loop share one truth.
///
/// Every phase is an honest obligation: each is counted by the global gauge and
/// by the close reply, so no phase transition can make a physical cookie — or a
/// write that may be about to create one — vanish from the accounting.
enum Phase {
  /// Admitted and parked on its coverage-settle fence: no write has been
  /// dispatched, so this obligation is PRE-PHYSICAL — no file can exist for it
  /// and its `path` is `None`, which is why no sweep can ever try to unlink it.
  /// It is nonetheless a full obligation: the global cap counts it, the close
  /// reply counts it, and a cancel naming it has a record to mark — the reason
  /// the cancel of a not-yet-dispatched sync needs no free-standing lookaside.
  /// Its `fence` is the settle it waits on; `parked_cookies` routes that fence
  /// back to the caller's reply.
  Parked { fence: FenceId },
  /// A write job for this obligation is in the pool: no file exists yet, or one
  /// may at any instant. Its scope's single-flight write gate is exactly "this
  /// scope has an obligation in this phase".
  InPool,
  /// The write claimed: the file at `path` (which is `Some` from the claim on)
  /// is owned. No removal in flight or requested-and-armed.
  Owned,
  /// Exactly one unlink job is in the pool FOR THIS OBLIGATION (single-flight):
  /// the record leaves this phase only once that job's syscall has returned.
  Removing { attempts: u8 },
  /// The last unlink failed. `Some(retry_at)` = SCHEDULED (the driver, which
  /// owns the clock, stamped the deadline); `None` = PARKED — budget exhausted
  /// for an UNMARKED record (one still carrying a reap mark is serviced into one
  /// fresh arming at that exhaustion instead of parking, see
  /// [`CookieRegistry::schedule_retry`]), or the failure has not been scheduled
  /// yet — awaiting an explicit re-arm (a fresh reap/cancel request, a retire
  /// sweep, the close sweep, or the recovery re-arm batch). Never CPU-spinning.
  /// The deadline rides the record it belongs to, so no schedule can outlive,
  /// mismatch, or clobber its incarnation.
  RemoveFailed {
    attempts: u8,
    retry_at: Option<Instant>,
  },
}

type CookieLedger = Arc<Mutex<LedgerInner>>;

/// Mints the cookie-cleanup ingress: ONE ledger, shared between the watcher
/// HANDLE and its driver task, plus the **capacity-1** coalescing wake the handle
/// rings after marking an obligation. The two halves are created together — at
/// the watcher's spawn, alongside the command channel — because the handle side
/// must address the very records the driver admits.
///
/// This pair REPLACES the dedicated cleanup queue the public reap and cancel used
/// to feed. That queue had to be unbounded (a bounded one once refused a removal
/// and orphaned the file it named), while every dedup and ownership resolution
/// happened only after dequeue — so nothing bounded the QUEUE, and a flood of
/// duplicate or unknown requests allocated one caller-sized message apiece. The
/// tension is not resolved by sizing a channel; it is dissolved by moving the
/// request onto the obligation it names. Because a record now exists from
/// admission to its typed terminal ([`CookieRegistry::admit_parked`]), a cleanup
/// request has somewhere to LIVE: it is one bool on already-counted state, so
/// there is no queue to bound and no admission to refuse.
pub(crate) fn cookie_ingress() -> (CookieIngress, CookieWake) {
  let ledger: CookieLedger = Arc::new(Mutex::new(LedgerInner::new()));
  // Capacity 1, and the token is a bare `()`: it carries no request — it only says
  // "some bit changed, sweep". A second wake against a full channel is therefore
  // not a dropped request but a COALESCED one: the pending token's sweep has not
  // run yet, so it will see every bit set before it takes the lock (§3.4).
  let (wake_tx, wake_rx) = async_channel::bounded(1);
  (
    CookieIngress {
      ledger: Arc::clone(&ledger),
      wake: wake_tx,
    },
    CookieWake {
      ledger,
      wake: wake_rx,
    },
  )
}

/// The HANDLE side of the cookie-cleanup ingress: the shared ledger, and the wake.
///
/// Every public cleanup request — [`request_remove_cookie`] and
/// [`request_cancel_sync`] — is exactly this: resolve the caller's address to an
/// obligation through a projection, set that obligation's reap mark, ring the
/// wake. It creates nothing, decides nothing, dispatches nothing, and retains
/// nothing; the driver owns every reaction, on records it already owns.
///
/// [`request_remove_cookie`]: crate::Watcher::request_remove_cookie
/// [`request_cancel_sync`]: crate::Watcher::request_cancel_sync
///
/// # A hostile flood retains NOTHING — structurally, not by draining
///
/// Per call: one mutex critical section (an O(1) projection lookup and, at most,
/// one bool store on a PRE-EXISTING record) and one `try_send` into a capacity-1
/// channel. No queue exists to grow, no entry is created, and an unaddressable
/// target touches nothing at all — it does not even wake. The retained-memory
/// delta of `loop { request_remove_cookie(random) }` is therefore ZERO, and the
/// whole ingress-reachable state is `obligations` (≤ the global cap, enforced at
/// admission, where a refusal creates nothing) plus one wake slot. Crucially this
/// holds even when the driver is NEVER SCHEDULED — a current-thread runtime whose
/// caller never yields — because the bound is a property of the SHAPE, not of a
/// drain keeping up with a producer.
///
/// # A genuine request can never be refused — by TYPE
///
/// A genuine request names an obligation this watcher admitted, and both public
/// addresses become valid strictly before a caller can legitimately hold them:
/// `by_path` is filled by the claim, whose mutex section precedes the `sync_root`
/// reply that is the ONLY place a caller learns the path (claim-before-reply);
/// `by_name` is filled at admission, before `sync_root` can even be answered. The
/// ingress locks the same mutex those writes took, so it observes them.
///
/// There is then no refusal edge on the genuine path: a mutex lock cannot fail
/// (poisoning is absorbed — [`lock_ledger`]), a bool store cannot fail, and the
/// wake is not load-bearing for admission (only for promptness — see
/// [`CookieWake`]). There is NO CAPACITY ANYWHERE on the genuine path: the
/// obligation IS the storage, so "never refuse a genuine unlink" and "bound the
/// ingress" stop competing. The old lane could guarantee only one of them —
/// unbounded bought admission at the cost of the bound; bounded would have traded
/// it back.
///
/// # The door's trade-off, stated
///
/// An UNADDRESSABLE target — a path or name matching no live obligation — is
/// dropped right here rather than queued to be discovered a no-op later. This is
/// exact rather than heuristic, because the ledger is birth-to-terminal complete:
/// an unknown address provably names no obligation of this watcher. The one
/// caller-visible nuance: a caller that PREDICTS a cookie path before its
/// `sync_root` reply arrives (possible only by re-deriving `dir.join(name)`
/// out-of-contract) is dropped at the door where it would once have been queued
/// and then found to be a no-op — the same net effect, now by construction.
///
/// The rule this generalizes to, for any lane added later: **every queue's
/// occupancy must derive from a counted obligation or a driver-minted grant;
/// anything else needs a door.**
///
/// Cloneable: it is a handle over shared state, and every clone addresses the one
/// ledger. Nothing about the mechanism is per-holder.
#[derive(Clone)]
pub(crate) struct CookieIngress {
  ledger: CookieLedger,
  /// The capacity-1 wake. `Sender`, so the driver's `recv` observes the close
  /// when the watcher drops — the same shape the command channel uses.
  wake: async_channel::Sender<()>,
}

/// The DRIVER side of the cookie-cleanup ingress: the same ledger its registry is
/// built around, and the wake it parks on.
///
/// # No request can be lost
///
/// The ingress orders **set the bit (under the mutex) → `try_send`**; the driver
/// orders **`recv` → lock and sweep**. Given a bit set at instant *t*:
///
/// - the `try_send` SUCCEEDS ⇒ a token exists ⇒ some later `recv` consumes it, and
///   the sweep that follows acquires the lock after our release ⇒ it sees our bit;
/// - the `try_send` finds the channel FULL ⇒ a token was already enqueued and not
///   yet consumed at *t* ⇒ the `recv` that consumes it happens no earlier than
///   *t*, so the sweep following it locks after our release ⇒ it sees our bit.
///   This is why a full wake is coalescing rather than lossy;
/// - the channel is CLOSED ⇒ the driver is gone ⇒ its terminal sweep (the orderly
///   close's, or the registry's `Drop` backstop) already owns every record
///   regardless of any bit.
///
/// A bit a sweep SEES but cannot act on immediately — a `Removing`/scheduled
/// record it can only coalesce onto — is not lost either: it rides the record,
/// and the arming that owns the record services it (retire, or a consume into one
/// fresh arming at budget exhaustion — see [`CookieRegistry::schedule_retry`]).
/// A seen bit is therefore a serviced bit, not merely a seen one.
///
/// The retire and close sweeps remain the promptness backstop for every residual
/// scheduling gap, exactly as before.
pub(crate) struct CookieWake {
  ledger: CookieLedger,
  wake: async_channel::Receiver<()>,
}

impl CookieIngress {
  /// Marks the obligation `resolve` names — the whole ingress. The lookup and the
  /// store are ONE critical section, so no claim can interleave between them: a
  /// cancel either finds the record already claimed (and the wake sweep reaps the
  /// cookie through the phase machine) or marks it in time for
  /// [`CookieGuard::claim`] to read the mark and refuse. There is no third
  /// interleaving, and no second decision point that could disagree with the
  /// driver — because this makes no decision at all.
  ///
  /// The mark is idempotent and monotone within a request cycle: set here, cleared
  /// only by the driver, in the same critical section in which it ACTS on it.
  fn mark(&self, resolve: impl FnOnce(&LedgerInner) -> Option<CookieId>) {
    {
      let mut inner = lock_ledger(&self.ledger);
      let Some(id) = resolve(&inner) else {
        // Unaddressable: not an obligation of this watcher. Nothing to store it
        // on, and nothing to tell the driver about — drop it at the door.
        return;
      };
      let Some(ob) = inner.obligations.get_mut(&id) else {
        return;
      };
      ob.reap_requested = true;
    }
    // Ring the wake with the lock RELEASED: the critical section above must stay
    // pure memory (no allocation, no I/O, no waker work), and the release is what
    // the no-lost-request argument orders the send against (see [`CookieWake`]).
    // A full channel means a wake is already pending, which is precisely the wake
    // that will observe the bit just set — so ignoring the result is correct, not
    // lossy. A closed channel means the driver is gone and its terminal sweep owns
    // every record.
    let _ = self.wake.try_send(());
  }

  /// Reaps the cookie at `path` — the public completed-cookie request, resolved
  /// through the projection the claim filled.
  pub(crate) fn request_remove(&self, path: &Path) {
    self.mark(|inner| inner.by_path.get(path).copied());
  }

  /// Cancels the sync whose rendered cookie file is `name` — the public
  /// cancel-by-name request. `by_name` is populated at ADMISSION, so this always
  /// has a target whatever the obligation's phase: a sync still parked on its
  /// fence, a write still in the pool, or a cookie already owned.
  pub(crate) fn request_cancel(&self, name: &str) {
    self.mark(|inner| inner.by_name.get(name).copied());
  }

  /// The live obligation count as the HANDLE sees it — the flood cell's oracle: it
  /// reads the very ledger a public request transitions, so "the flood retained
  /// nothing" is asserted on the structure itself rather than inferred from
  /// process memory.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn ledger_len(&self) -> usize {
    lock_ledger(&self.ledger).obligations.len()
  }

  /// How many wake tokens are outstanding — never more than 1 by construction.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn wake_len(&self) -> usize {
    self.wake.len()
  }
}

/// A detached-blocking-job spawner, captured from the driver's runtime so the
/// registry's [`Drop`] can dispatch its best-effort abnormal-path unlinks
/// off-reactor without an `R` type parameter in scope. `Send + Sync` (the
/// captured closure is zero-capture, so it is both) keeps [`CookieRegistry`]
/// itself `Sync`, so `&cookies` can be read inside the `Send` close-drain future
/// where the LIVE ledger is the drain's quiescence condition (§5.2).
type DetachedSpawner = Box<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>;

/// Locks the ledger, ignoring poisoning: every critical section is a small,
/// invariant-preserving mutation that cannot leave the maps half-written, and
/// the terminal sweep runs from a [`Drop`] — where unwrapping a poisoned lock
/// would abort the process mid-unwind instead of reaping the cookies.
fn lock_ledger(ledger: &CookieLedger) -> MutexGuard<'_, LedgerInner> {
  ledger.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `backoff(k) = min(base · 2^(k-1), cap)` — the cookie-unlink retry delay for
/// the `k`-th attempt of the current arming (`k` ≥ 1). Saturating so a large
/// attempt count can never overflow the shift.
fn cookie_backoff(base: Duration, cap: Duration, attempt: u8) -> Duration {
  let shift = attempt.saturating_sub(1).min(31);
  base.saturating_mul(1u32 << shift).min(cap)
}

/// The ownership half one dispatched cookie write carries into the blocking
/// pool: the ledger holding the record born for it, and the two flags that can
/// refuse the handover.
struct CookieGuard {
  /// This write's incarnation id (§1.1), minted at DISPATCH under the ledger lock
  /// together with the record it keys — the SINGLE birth site — and carried from
  /// here: the [`claim`](Self::claim) and any `self_reap` transition THAT record.
  /// One physical write, one id, one record, for the whole lifecycle: the global
  /// cap has nothing to dedup, and a reused name cannot mask a distinct write
  /// (R12-F3).
  id: CookieId,
  ledger: CookieLedger,
  /// The registry is gone (driver returned, panicked, or was cancelled).
  shutdown: Arc<AtomicBool>,
  /// This write's scope is retiring (its stream is being torn down).
  retiring: Arc<AtomicBool>,
  /// The scope's live root generation, shared with the registry. A replace
  /// commit bumps it under the SURVIVING scope, so a write dispatched under the
  /// pre-replace root carries a now-stale [`dispatched_generation`].
  ///
  /// [`dispatched_generation`]: Self::dispatched_generation
  generation: Arc<AtomicU64>,
  /// The generation current when this write was dispatched. A claim finding the
  /// live generation moved past this one is refused: the root the cookie was to
  /// be reported on is gone, and its create event could never reach the current
  /// stream.
  dispatched_generation: u64,
}

impl CookieGuard {
  /// Hands a just-created cookie to the registry, which then owns it. `None`
  /// means the handover was REFUSED — a cancel named this obligation, the
  /// registry is gone, the scope is retiring, or the scope's root generation has
  /// moved past the one this write was dispatched under — so a sweep has already
  /// passed this path by, or the root the cookie belongs to is gone; either way
  /// the caller must unlink the file itself.
  ///
  /// The refusal check and the transition are ONE critical section against the
  /// sweeps, and every sweep raises its flag BEFORE taking the ledger. So a
  /// claim that lands after a sweep took the map necessarily observes the raised
  /// flag and refuses (the write reaps itself), and one that lands before it is
  /// in the map that sweep takes. There is no third interleaving: a created file
  /// is always owned by exactly one of the two. The generation is one more
  /// refusal reason inside this SAME section, never a new race: a replace commit
  /// bumps it, so a write whose captured generation is stale reaps itself
  /// exactly as a retired one does. The record's own REAP MARK is one more, read
  /// in this same section: a cancel that named this obligation while its write
  /// was still in the pool forces the claim to refuse and self-reap, closing the
  /// "delivered-but-unread cookie orphaned by a raced cancel" window. The mark
  /// rides the record it refuses: usually the self-reap that follows retires the
  /// record and the mark dies with it, but if that unlink fails the record
  /// survives carrying the mark, which the failing arming's budget-exhaustion
  /// completion then services (see [`CookieRegistry::schedule_retry`]).
  ///
  /// An ABSENT record means the abnormal-path [`Drop`] already took the ledger;
  /// its flag is raised before that take, so this refuses on either observation
  /// and the write reaps its own file.
  fn claim(&self, path: &Path) -> Option<CookieId> {
    let mut inner = lock_ledger(&self.ledger);
    let ob = inner.obligations.get_mut(&self.id)?;
    if ob.reap_requested
      || self.shutdown.load(Ordering::SeqCst)
      || self.retiring.load(Ordering::SeqCst)
      || self.generation.load(Ordering::SeqCst) != self.dispatched_generation
    {
      return None;
    }
    // Transition THIS write's own record — born at its dispatch under this same
    // lock — rather than inserting one: there is no insert-by-path anywhere, so
    // a claim can never displace another obligation. A same-path successor and
    // predecessor coexist under distinct keys, each retired by its own syscall
    // verdict. The claim publishes the path only the write knows (a covered FILE
    // subscription's cookie lands in the PARENT), which is what the sweeps and a
    // public path-addressed removal then resolve through.
    //
    // `by_path` MAY overwrite an entry left by an older incarnation at this path
    // (a hostile same-path reuse — direct-fs-API name reuse only; umbrella names
    // are per-sync-unique). Newest-claim-wins: the displaced id's record is left
    // untouched (we cannot know which file-at-P history is live), and it reaches
    // its terminal through the id-addressed sweeps, which unlink P on its behalf
    // and earn its confirm.
    let landed = path.to_path_buf();
    ob.path = Some(landed.clone());
    ob.phase = Phase::Owned;
    inner.by_path.insert(landed, self.id);
    Some(self.id)
  }
}

/// Owns every cookie this driver has written and not yet removed. Ownership is
/// the registry's, never the reply oneshot's: a caller that abandons its sync
/// cannot strand a file, and neither can a scope that dies under an in-flight
/// write.
///
/// Every physical unlink that ends a cookie's life is a TRACKED, counted job:
/// its ledger record is dropped only once the unlink CONFIRMS (success, or a
/// file already gone), so a transient failure retains the record for a later
/// sweep rather than silently orphaning the file. The reaps that end a cookie
/// — a completed-cookie reap and a scope's stream teardown
/// ([`retire_scope`](Self::retire_scope)), and the orderly close's
/// [`sweep_owned`](Self::sweep_owned) — each raise their flag before taking the
/// paths, so a write still in the blocking pool can never slip a file past the
/// sweep that was supposed to reap it. This type's [`Drop`] is the
/// ABNORMAL-path backstop only (a panic or a task cancellation, where no close
/// grace exists): it dispatches its remaining unlinks DETACHED so it can never
/// block the very unwind it runs under.
struct CookieRegistry<F: FsOps> {
  ops: F,
  /// Raised before the registry stops accepting handovers — at the orderly
  /// close's sweep and, as the abnormal-path backstop, in [`Drop`]. A write in
  /// the pool re-checks it while claiming its file, so a write can never outlive
  /// the registry that dispatched it.
  shutdown: Arc<AtomicBool>,
  ledger: CookieLedger,
  /// Per-scope retirement flags, cloned into each dispatched write. Raised
  /// BEFORE a retiring scope's cookies are unlinked, so a write that lands
  /// afterwards reaps itself instead of surviving. The entry is dropped with the
  /// scope (the write holds its own clone), so this never accrues dead scopes.
  retiring: HashMap<ScopeId, Arc<AtomicBool>>,
  /// Each live scope's canonical root — the FLOOR its cookies may never be
  /// written above (see [`cookie_dir`]). Dropped with the scope, like the flags.
  roots: HashMap<ScopeId, PathBuf>,
  /// Each live scope's root GENERATION, cloned into each dispatched write and
  /// bumped at every replace commit's lane swap (see
  /// [`advance_generation_locked`](Self::advance_generation_locked)), under the
  /// ledger lock so the bump is atomic with a claim. A write claims only while
  /// the generation still matches the one it captured, so a barrier dispatched
  /// under a superseded root reaps itself rather than landing a cookie the
  /// current stream could never observe. Dropped with the scope, like the flags
  /// and the root.
  generations: HashMap<ScopeId, Arc<AtomicU64>>,
  /// Spawns a detached blocking job. Captured from the driver's runtime at
  /// construction so [`Drop`] — which has no `R` in scope — can dispatch its
  /// best-effort abnormal-path unlinks OFF-reactor. Unlinking synchronously in
  /// Drop would, on a hung mount, wedge the very unwind (a panic or a task
  /// cancellation) the Drop is running under; a detached job cannot.
  spawn_detached: DetachedSpawner,
}

impl<F: FsOps> CookieRegistry<F> {
  /// Takes the ledger rather than minting one: it is created at the watcher's
  /// spawn ([`cookie_ingress`]) and shared with the handle, whose public cleanup
  /// requests are transitions on the records this registry admits.
  fn new<R>(ops: F, ledger: CookieLedger) -> Self
  where
    R: RuntimeLite,
  {
    Self {
      ops,
      shutdown: Arc::new(AtomicBool::new(false)),
      ledger,
      retiring: HashMap::new(),
      roots: HashMap::new(),
      generations: HashMap::new(),
      spawn_detached: Box::new(|job| R::spawn_blocking_detach(job)),
    }
  }

  /// `scope`'s stream is live under `root` — recorded on the SAME transitions
  /// the scope registry learns them on (birth, and a replace's commit, which
  /// overwrites the root under a surviving scope). Birth establishes generation
  /// 0; a replace's commit RE-records the root here but no longer bumps the
  /// generation — the bump moved to the lane swap itself
  /// ([`advance_generation_locked`](Self::advance_generation_locked), taken
  /// under the ledger lock), so it is atomic with a concurrent claim and lands
  /// at the swap's linearization point rather than in this post-commit call.
  fn scope_live(&mut self, scope: ScopeId, root: PathBuf) {
    self.roots.insert(scope, root);
    self
      .generations
      .entry(scope)
      .or_insert_with(|| Arc::new(AtomicU64::new(0)));
  }

  /// Bumps `scope`'s root generation under the LEDGER LOCK — the same lock
  /// [`CookieGuard::claim`] takes to read it — so a bump and a claim cannot
  /// interleave: a claim either completes before the bump (sees the OLD
  /// generation, and the stream that generation names is still the current one)
  /// or after it (sees the new generation and refuses). Called at the replace
  /// commit's lane swap, so the generation transition IS the swap's
  /// linearization point: a write dispatched under the retiring root can never
  /// claim once the new stream is live, and one that already claimed belongs to
  /// the still-current old stream. A scope with no generation entry has no
  /// dispatched writes to revoke, so a missing entry is a no-op.
  fn advance_generation_locked(&self, scope: ScopeId) {
    let _ledger = lock_ledger(&self.ledger);
    if let Some(generation) = self.generations.get(&scope) {
      generation.fetch_add(1, Ordering::SeqCst);
    }
  }

  /// The root a cookie for `scope` must stay inside. `None` for a scope with no
  /// live stream — nothing to write a barrier on.
  fn root_of(&self, scope: ScopeId) -> Option<&Path> {
    self.roots.get(&scope).map(PathBuf::as_path)
  }

  /// BIRTHS one cookie obligation, PARKED on the settle fence its sync was
  /// admitted under, and returns its incarnation id. The id, the record, and its
  /// `by_name` entry are all created HERE — the SINGLE birth site, and the single
  /// id mint — under the ledger lock, so:
  ///
  /// - every admitted sync is a COUNTED obligation from the instant its caller
  ///   can address it, so the global cap sees a parked sync and a dispatched
  ///   write alike, in one term, with no second gauge to keep in step;
  /// - a cancel-by-name always has a target, whatever the phase — which is why
  ///   the reap mark can ride the record instead of a free-standing tombstone,
  ///   and why cancelling a sync whose write has not been dispatched needs no
  ///   lookaside scan of the driver's parked-routing local;
  /// - an insert can never displace a live obligation, since the id is minted
  ///   with it and is unique by construction.
  ///
  /// Called only AFTER every admission refusal has passed: a refused sync must
  /// create nothing at all.
  fn admit_parked(&mut self, scope: ScopeId, name: String, fence: FenceId) -> CookieId {
    let mut inner = lock_ledger(&self.ledger);
    inner.next_cookie_id += 1;
    let id = CookieId(inner.next_cookie_id);
    inner.obligations.insert(
      id,
      Obligation {
        scope,
        name: name.clone(),
        id,
        path: None,
        reap_requested: false,
        last_failure_seq: 0,
        phase: Phase::Parked { fence },
      },
    );
    // Newest-birth-wins on a hostile same-name reuse: the displaced record
    // keeps its own key and its own terminal — only cancel-by-name's lookup is
    // imprecise, and only for a direct-API caller reusing one name.
    inner.by_name.insert(name, id);
    #[cfg(all(test, feature = "tokio"))]
    {
      inner.census.births += 1;
    }
    id
  }

  /// The parked obligation on `fence` — its id, scope, and rendered name. The
  /// LEDGER is what knows a sync is parked; `parked_cookies` only routes the
  /// fence to its caller's reply, so this reads the truth rather than the local.
  /// O(ledger), which the global cap bounds.
  fn parked_on(&self, fence: FenceId) -> Option<(CookieId, ScopeId, String)> {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .find(|ob| matches!(ob.phase, Phase::Parked { fence: on } if on == fence))
      .map(|ob| (ob.id, ob.scope, ob.name.clone()))
  }

  /// The DISPATCH decision for the obligation parked on a settled fence: either
  /// the write goes to the pool under the returned handle (`Parked → InPool`), or
  /// the obligation reaches its terminal here, having created nothing.
  ///
  /// `None` means DO NOT WRITE — a cancel marked this obligation before its write
  /// was ever dispatched, so it is retired `NeverCreated` right here (nothing
  /// physical can exist for a parked record) and the caller must answer the
  /// barrier `Retired` and abandon the fence. Folding the mark into the dispatch
  /// is what makes "cancel a sync that has not been written yet" one transition of
  /// the machine rather than a lookaside protocol.
  ///
  /// `Some(guard)` transitions the record `InPool` and hands the write its
  /// ownership handle, minting the scope's retirement flag on demand. The flags
  /// are taken here, at dispatch, so they cover the whole in-flight window:
  /// everything that retires the cookie between here and the write's landing is
  /// visible to the write itself.
  fn dispatch_guard(&mut self, scope: ScopeId, id: CookieId) -> Option<CookieGuard> {
    let generation = Arc::clone(
      self
        .generations
        .entry(scope)
        .or_insert_with(|| Arc::new(AtomicU64::new(0))),
    );
    let dispatched_generation = generation.load(Ordering::SeqCst);
    let retiring = Arc::clone(self.retiring.entry(scope).or_default());
    {
      let mut inner = lock_ledger(&self.ledger);
      let ob = inner.obligations.get_mut(&id)?;
      if ob.reap_requested {
        inner.retire(id, Reaped::NeverCreated);
        return None;
      }
      ob.phase = Phase::InPool;
    }
    Some(CookieGuard {
      id,
      ledger: Arc::clone(&self.ledger),
      shutdown: Arc::clone(&self.shutdown),
      retiring,
      generation,
      dispatched_generation,
    })
  }

  /// The count of outstanding cookie obligations: one ledger snapshot, ONE term.
  /// Every lifecycle stage from the sync's admission to its typed terminal is ONE
  /// record in this map — a sync parked on its fence, an in-pool write, an owned
  /// cookie, an unlink in flight, a failed unlink — so there is nothing to dedup
  /// and no second gauge that could drift out of step with it.
  ///
  /// Serves BOTH the close reply (a `NotQuiesced` count) AND `SyncRoot`
  /// admission (the whole-lifecycle global cap Φ, §4.1). ONE method, so the two
  /// callers can never diverge (divergence is exactly how the earlier close bug
  /// happened); do not fork it.
  ///
  /// A false `Ok(0)` is foreclosed structurally: the record is born before any
  /// caller can address the obligation — and long before a file can exist — and
  /// is removed only by a typed [`retire`], which every path takes only once it
  /// holds evidence: a syscall verdict, or the fact that nothing was ever
  /// created. There is no window in which an obligation exists and this count
  /// omits it.
  ///
  /// [`retire`]: LedgerInner::retire
  fn unremoved(&self) -> usize {
    lock_ledger(&self.ledger).obligations.len()
  }

  /// How many cookies `scope` still owns — the backlog cap's probe. O(ledger),
  /// which the cap keeps bounded (`cookie_backlog_cap × live scopes`).
  fn unremoved_for(&self, scope: ScopeId) -> usize {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter(|ob| ob.scope == scope)
      .count()
  }

  /// Whether `scope` has a sync anywhere in the write pipeline — parked on its
  /// settle fence, or dispatched into the pool. This is the single-flight write
  /// gate: ONE phase probe over the one ledger, rather than two structures (a
  /// gauge and a parked local) to keep in step with each other.
  ///
  /// The gate opens the moment that sync leaves `Parked`/`InPool` — at its CLAIM,
  /// or at the typed terminal of a write that created nothing — rather than at the
  /// tail of its `CookieWriteDone`. A scope can therefore transiently hold one
  /// write JOB plus one COMPLETING TAIL (a claimed write whose completion message
  /// is still in flight), which is the bound that matters: at most one
  /// `write_cookie` syscall per scope is ever outstanding, so a caller that times
  /// out and retries still cannot pile blocking writes against a hung mount.
  fn has_pending_write(&self, scope: ScopeId) -> bool {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .any(|ob| ob.scope == scope && matches!(ob.phase, Phase::Parked { .. } | Phase::InPool))
  }

  /// Re-arms PARKED removal records at a cap refusal — refusing-scope-FIRST,
  /// then least-recently-FAILED-first across every other scope — so a caller
  /// being refused always makes progress on its own backlog, and a recovered
  /// mount's records can never be starved by a permafailing one (R11-1):
  /// `last_failure_seq` is refreshed on every failure, so records that keep
  /// failing keep moving to the BACK of the selection order, and a record that
  /// has not failed since the fs recovered ratchets monotonically to the front.
  ///
  /// The backlog-recovery driver: a parked record on a RETIRED scope has no live
  /// scope to sweep it and no timer to retry it, so without this a
  /// since-recovered filesystem would never drain those records and the global
  /// cap could lock out every future sync permanently. Bounded: ≤ `limit`
  /// re-arms for the refusing scope PLUS ≤ `limit` across the rest, per refusal
  /// (the two budgets are separate, so a scope whose own cap-sized backlog
  /// re-parks between refusals can never consume the whole batch and starve the
  /// rotation). Single-flight and the scheduled/`Removing` filters coalesce
  /// everything already owned by a timer or an in-flight job. Returns how many
  /// were re-armed. No fs I/O, no allocation growth beyond the snapshot; runs
  /// only on the refusal path.
  fn rearm_parked_batch<R>(
    &self,
    op_tx: &async_channel::Sender<OpResult<F::Handle>>,
    refusing: ScopeId,
    limit: usize,
  ) -> usize
  where
    R: RuntimeLite,
  {
    // ONE lock: snapshot every PARKED record — `RemoveFailed` carrying no
    // deadline of its own. The deadline rides the record, so "scheduled" is one
    // field of the record being tested, not a cross-structure conjunction.
    let parked: Vec<(CookieId, ScopeId, u64)> = {
      let inner = lock_ledger(&self.ledger);
      inner
        .obligations
        .values()
        .filter(|ob| matches!(ob.phase, Phase::RemoveFailed { retry_at: None, .. }))
        .map(|ob| (ob.id, ob.scope, ob.last_failure_seq))
        .collect()
    };
    let (mut mine, mut others): (Vec<_>, Vec<_>) = parked
      .into_iter()
      .partition(|(_, scope, _)| *scope == refusing);
    mine.truncate(limit); // order immaterial: ≤ cap + 1 records
    others.sort_by_key(|(_, _, seq)| *seq); // LRU: least-recently-failed first
    others.truncate(limit);
    let rearmed = mine.len() + others.len();
    for (id, _, _) in mine.into_iter().chain(others) {
      self.request_removal::<R>(op_tx, RemovalRequest::Targeted(id));
    }
    rearmed
  }

  /// Spawns the ONE blocking unlink of `path` for incarnation `id` (the record
  /// was already transitioned to `Removing` under the ledger lock by the
  /// decision that called this, which read `id` from the record inside that
  /// same section). The job writes the PHYSICAL VERDICT itself, under the ledger
  /// mutex, before reporting anything: a confirmed removal (`Ok` / already gone)
  /// retires incarnation `id` — a racing successor keeps its own key and is left
  /// intact — and a transient failure parks the record as `RemoveFailed` so the
  /// file is never orphaned. The `CookieRemoveDone` that follows carries the id
  /// and drives SCHEDULING only: the driver owns the clock, so it alone stamps
  /// the retry deadline. Truth therefore rides the job that learned it, and a
  /// lost completion costs promptness (a parked record awaits a re-arm), never
  /// ownership.
  ///
  /// ACCEPTED PHYSICAL RESIDUAL: the dispatched job targets `path` by NAME at
  /// the fs level. If a successor recreates the file before this job's syscall
  /// runs, the job unlinks the successor's FILE; the retire touches only
  /// incarnation `id`, so the successor RECORD survives, its next unlink confirms
  /// already-gone, and close accounting never lies. This needs same-path reuse —
  /// direct-API name reuse only (umbrella names are per-sync-unique ⇒
  /// per-sync-unique paths) — and is unfixable without handle-anchored unlink
  /// semantics the platform APIs do not offer.
  fn spawn_unlink<R>(
    &self,
    op_tx: &async_channel::Sender<OpResult<F::Handle>>,
    path: PathBuf,
    id: CookieId,
  ) where
    R: RuntimeLite,
  {
    let ops = self.ops.clone();
    let ledger = Arc::clone(&self.ledger);
    let tx = op_tx.clone();
    R::spawn_blocking_detach(move || {
      let confirmed = ops.remove_cookie(&path).is_ok();
      {
        let mut inner = lock_ledger(&ledger);
        if confirmed {
          // Retire incarnation `id`: keyed by the id, this can never remove a
          // successor that reclaimed the same path between the unlink syscall and
          // this lock.
          inner.retire(id, Reaped::ConfirmedGone);
        } else {
          // The syscall has already returned, so leaving `Removing` here cannot
          // overlap a second unlink for this record: the file is retained as
          // failed, PARKED until the driver schedules its retry.
          inner.record_remove_failed(id);
        }
      }
      let _ = tx.try_send(OpResult::CookieRemoveDone { id, confirmed });
    });
  }

  /// The under-the-lock removal decision: returns `Some((path, id))` iff the
  /// caller must now spawn an unlink, having transitioned that record to
  /// `Removing` here. Single-flight-per-record follows because only a state that
  /// is not already `Removing` can dispatch, and the transition happens before
  /// the job exists. The wake sweep calls this inside its OWN critical
  /// section (so one whole pass is one lock acquisition); every other
  /// producer routes through [`request_removal`](Self::request_removal).
  ///
  /// EVERY request is id-addressed: no path-addressed removal decision exists in
  /// the driver at all, because the one PUBLIC path-addressed request resolves
  /// `by_path` at the door — under this same mutex, in the same critical section
  /// that marks the record it found ([`CookieIngress::request_remove`]). So a
  /// record displaced from `by_path` by a same-path successor stays reachable, and
  /// a retired one is a no-op: a stale actor never touches a successor
  /// incarnation.
  fn removal_decision_locked(
    inner: &mut LedgerInner,
    req: &RemovalRequest,
  ) -> Option<(PathBuf, CookieId)> {
    // A record that is missing — already retired — is idempotently nothing.
    let id = match req {
      RemovalRequest::Targeted(id) | RemovalRequest::RetryDue(id) => *id,
    };
    let ob = inner.obligations.get_mut(&id)?;
    // A record with no path has no file to unlink: its sync is still parked (no
    // write has been dispatched, so nothing physical can exist), or its write is
    // in the pool and only that write can learn where its cookie landed. This one
    // line is what makes every sweep, retry and public removal structurally
    // incapable of unlinking for a pre-physical record: a parked record is left to
    // its pre-physical terminal, and an in-pool one reaps itself against the flags.
    let path = ob.path.clone()?;
    let attempts = match (&ob.phase, req) {
      // Owned: a marked record or a targeted sweep dispatches a fresh removal;
      // a retry for a not-yet-failed record is a no-op.
      (Phase::Owned, RemovalRequest::Targeted(_)) => Some(0),
      (Phase::Owned, RemovalRequest::RetryDue(_)) => None,
      // RemoveFailed, SCHEDULED (its own retry owns it): coalesce for a marked
      // record or a targeted sweep; the due retry itself dispatches.
      (
        Phase::RemoveFailed {
          retry_at: Some(_), ..
        },
        RemovalRequest::Targeted(_),
      ) => None,
      // RemoveFailed, PARKED: a marked record or a targeted sweep RE-ARMS with a
      // fresh budget.
      (Phase::RemoveFailed { retry_at: None, .. }, RemovalRequest::Targeted(_)) => Some(0),
      // The retry dispatcher fired for a due record: dispatch it preserving the
      // attempt count toward the budget.
      (Phase::RemoveFailed { attempts, .. }, RemovalRequest::RetryDue(_)) => Some(*attempts),
      // A `Removing` record (an unlink already owns this record's fate) → coalesce.
      (Phase::Removing { .. }, _) => None,
      // A parked sync and an in-pool write are pre-physical, so neither is
      // addressable for removal: see `path` above.
      (Phase::Parked { .. } | Phase::InPool, _) => None,
    };
    let attempts = attempts?;
    // Any deadline this record carried is superseded by the dispatch: it lives
    // inside the phase, so the transition retires it with no second structure to
    // keep in step and no chance of a schedule outliving its arming.
    ob.phase = Phase::Removing { attempts };
    Some((path, id))
  }

  /// The ONE unlink dispatch point routed to by `retire_scope`, `sweep_owned`,
  /// the recovery re-arm, and the retry dispatcher (the wake sweep uses the
  /// `_locked` core directly, so one pass is one lock acquisition). Decides under
  /// the ledger lock, spawns after unlock.
  fn request_removal<R>(
    &self,
    op_tx: &async_channel::Sender<OpResult<F::Handle>>,
    req: RemovalRequest,
  ) where
    R: RuntimeLite,
  {
    let decision = {
      let mut inner = lock_ledger(&self.ledger);
      Self::removal_decision_locked(&mut inner, &req)
    };
    if let Some((path, id)) = decision {
      self.spawn_unlink::<R>(op_tx, path, id);
    }
  }

  /// The PHYSICAL half of the wake sweep: ONE O(ledger) pass that routes every
  /// MARKED obligation through the same phase machine every other producer routes
  /// through, deciding under the lock and spawning after it is released — the
  /// invariable rule, since an unlink on a hung mount under this mutex would
  /// serialize every other critical section behind it, the caller-facing ingress
  /// included.
  ///
  /// The mark is cleared EXACTLY when the sweep acts on it — i.e. iff the decision
  /// transitioned the record to `Removing` and this call will spawn its unlink.
  /// That equivalence is what each surviving mark then means:
  ///
  /// - `Parked` — pre-physical, so nothing is dispatched (no path, no file). Its
  ///   terminal is the caller-answering one [`retire_parked_cookies`] runs.
  /// - `InPool` — only the write knows where its cookie will land, so nothing is
  ///   dispatched. The mark is what its claim reads, refuses on, and self-reaps
  ///   against; it dies with the record.
  /// - `Removing` / SCHEDULED `RemoveFailed` — an unlink or a deadline already
  ///   owns this record's fate, so the request COALESCES onto it. The mark stays,
  ///   and the arming that owns the record services it: on retire the mark dies
  ///   with the record, and on budget exhaustion the failing completion consumes
  ///   the mark into one fresh arming ([`CookieRegistry::schedule_retry`]) — not
  ///   dependent on a subsequent wake.
  /// - PARKED `RemoveFailed` — budget-spent and unscheduled: the request re-arms it
  ///   with a fresh budget, which is the demand edge that makes a fresh reap or
  ///   cancel accelerate a stalled backlog.
  fn sweep_reap_marks<R>(&self, op_tx: &async_channel::Sender<OpResult<F::Handle>>)
  where
    R: RuntimeLite,
  {
    let dispatch: Vec<(PathBuf, CookieId)> = {
      let mut inner = lock_ledger(&self.ledger);
      let marked: Vec<CookieId> = inner
        .obligations
        .values()
        .filter(|ob| ob.reap_requested)
        .map(|ob| ob.id)
        .collect();
      marked
        .into_iter()
        .filter_map(|id| {
          let decided = Self::removal_decision_locked(&mut inner, &RemovalRequest::Targeted(id))?;
          if let Some(ob) = inner.obligations.get_mut(&id) {
            ob.reap_requested = false;
          }
          Some(decided)
        })
        .collect()
    };
    for (path, id) in dispatch {
      self.spawn_unlink::<R>(op_tx, path, id);
    }
  }

  /// The earliest scheduled cookie-unlink retry, or `None` if every failed record
  /// is parked — the driver's deadline arm. O(ledger), which the global cap
  /// bounds.
  fn min_retry_at(&self) -> Option<Instant> {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter_map(|ob| match ob.phase {
        Phase::RemoveFailed { retry_at, .. } => retry_at,
        Phase::Parked { .. } | Phase::InPool | Phase::Owned | Phase::Removing { .. } => None,
      })
      .min()
  }

  /// Pulls every scheduled retry no later than `floor` — the close sweep's
  /// flat-base rule, so a record sitting on a far exponential deadline is still
  /// retried inside the grace instead of making close report a spurious
  /// `NotQuiesced`.
  fn pull_retries_forward(&self, floor: Instant) {
    let mut inner = lock_ledger(&self.ledger);
    for ob in inner.obligations.values_mut() {
      if let Phase::RemoveFailed {
        retry_at: Some(at), ..
      } = &mut ob.phase
        && *at > floor
      {
        *at = floor;
      }
    }
  }

  /// Schedules incarnation `id`'s retry after a failed unlink — the driver is the
  /// only writer of deadlines, because it is the only holder of the clock. A
  /// record PARKED within its budget takes `now + backoff(attempts)`. Past the
  /// budget an UNMARKED record stays parked (no schedule, zero CPU) awaiting an
  /// explicit re-arm; a record that still carries a STANDING reap mark is
  /// serviced here instead — the mark is consumed into exactly one fresh arming,
  /// scheduled due-now, because the wake that carried it may already have been
  /// spent by a coalescing sweep while an earlier arming owned the record. Any
  /// other phase — retired by a racing confirm, or already re-armed into
  /// `Removing` by a sweep — is a stale report and touches nothing. `flat` uses
  /// the flat base delay during the close drain (the ~1 s grace bounds attempts
  /// there).
  fn schedule_retry(&self, config: &DriverConfig, id: CookieId, now: Instant, flat: bool) {
    let mut inner = lock_ledger(&self.ledger);
    let Some(ob) = inner.obligations.get_mut(&id) else {
      return;
    };
    let Phase::RemoveFailed {
      attempts,
      retry_at: retry_at @ None,
    } = &mut ob.phase
    else {
      return;
    };
    if *attempts > config.cookie_retry_budget {
      // Budget exhausted: the record would park. A standing reap mark is serviced
      // in this same critical section — consumed into exactly one fresh arming
      // (attempts 0, `Targeted` re-arm semantics), scheduled due-now for the
      // existing retry machinery to dispatch. Set-then-consume can never lose a
      // request; consume-then-park can never spin. An unmarked record parks.
      if ob.reap_requested {
        ob.reap_requested = false;
        ob.phase = Phase::RemoveFailed {
          attempts: 0,
          retry_at: Some(now),
        };
      }
      return;
    }
    let delay = if flat {
      config.cookie_retry_base
    } else {
      cookie_backoff(config.cookie_retry_base, config.cookie_retry_cap, *attempts)
    };
    *retry_at = Some(now + delay);
  }

  /// Retires `scope`: raise its flag FIRST — a write still in the pool then
  /// finds its claim refused and reaps itself, rather than landing a file into a
  /// scope nothing will sweep again — then route every cookie the scope still
  /// owns through the phase machine (§2.7): `Owned` and PARKED `RemoveFailed`
  /// dispatch with a fresh budget, a scheduled `RemoveFailed` keeps its retry, a
  /// `Removing` coalesces, and an `InPool` record is left to the flag it just
  /// raised (only its own write knows where its file landed). The records are
  /// KEPT until each unlink confirms, so a transient failure cannot orphan the
  /// file.
  ///
  /// A sync still PARKED on its fence is pre-physical, so there is nothing here to
  /// unlink and nothing to revoke by flag: dropping `roots` above is what retires
  /// it. Its fence was resolved `Degraded` by the same teardown, so the next
  /// settle observation finds the scope gone, retires the record `NeverCreated`
  /// and answers its barrier `Retired` — the ONE site that resolves a parked sync,
  /// caller reply and ledger record in the same step.
  fn retire_scope<R>(&mut self, scope: ScopeId, op_tx: &async_channel::Sender<OpResult<F::Handle>>)
  where
    R: RuntimeLite,
  {
    if let Some(flag) = self.retiring.remove(&scope) {
      flag.store(true, Ordering::SeqCst);
    }
    self.roots.remove(&scope);
    // The generation is per-scope and dies with it — a retired scope's writes
    // are already revoked by the flag above, so the generation has no work left.
    self.generations.remove(&scope);
    // Snapshot each of the scope's incarnation ids under the lock, then dispatch
    // each as a `Targeted(id)`, which addresses the incarnation directly.
    let reap: Vec<CookieId> = lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter(|ob| ob.scope == scope)
      .map(|ob| ob.id)
      .collect();
    for id in reap {
      self.request_removal::<R>(op_tx, RemovalRequest::Targeted(id));
    }
    // A record whose unlink PERMANENTLY fails (a genuinely undeletable file —
    // rare: we created it, so we hold its directory) parks here after its budget
    // with no live scope left to re-arm it, lingering in the ledger until the
    // driver closes or the fs recovers. That is the honest floor for "never
    // orphan a file we cannot confirm gone" (the alternative is to FORGET it,
    // i.e. leak the disk file). The dead-scope tail no longer grows without bound
    // under watch/unwatch churn: the GLOBAL cookie cap (checked at `SyncRoot`
    // admission) ceilings the whole ledger across live AND retired scopes.
  }

  /// Raises the shutdown flag WITHOUT sweeping — the orderly close's first step,
  /// so a write landing during the close drain finds its claim refused and reaps
  /// itself (inside its own tracked job) rather than landing a cookie owned but
  /// unswept behind the sweep below.
  fn begin_shutdown(&self) {
    self.shutdown.store(true, Ordering::SeqCst);
  }

  /// Routes every cookie the registry still owns through the phase machine — the
  /// orderly close's sweep, run BEFORE the registry is dropped so the close grace
  /// COVERS the unlinks: a hung mount then makes close report `NotQuiesced`
  /// honestly rather than wedging, and each record is dropped as its unlink
  /// confirms. Run after [`begin_shutdown`](Self::begin_shutdown), so nothing new
  /// can land unswept behind it. Per-phase rules as
  /// [`retire_scope`](Self::retire_scope) (§2.8).
  ///
  /// PARKED syncs are not this sweep's to resolve — they are pre-physical, and
  /// their callers' replies live in the driver's routing local; close retires them
  /// through [`retire_parked_cookies`] alongside this call.
  fn sweep_owned<R>(&self, op_tx: &async_channel::Sender<OpResult<F::Handle>>)
  where
    R: RuntimeLite,
  {
    // Snapshot each incarnation id, then dispatch each `Targeted(id)`,
    // addressing the incarnation directly.
    let owned: Vec<CookieId> = lock_ledger(&self.ledger)
      .obligations
      .keys()
      .copied()
      .collect();
    for id in owned {
      self.request_removal::<R>(op_tx, RemovalRequest::Targeted(id));
    }
  }

  /// How many cookies the registry currently owns — the leak oracle: a failed
  /// write, an abandoned reply, a retired scope, and a completed-cookie reap must
  /// all leave it exactly as they found it.
  #[cfg(all(test, feature = "tokio"))]
  fn len(&self) -> usize {
    lock_ledger(&self.ledger).obligations.len()
  }

  /// How many obligations carry a reap mark — a test hook proving the
  /// boundedness rule (a mark exists only on a live obligation, and never
  /// survives it).
  #[cfg(all(test, feature = "tokio"))]
  fn reap_marks(&self) -> usize {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter(|ob| ob.reap_requested)
      .count()
  }

  /// How many of `scope`'s records are PARKED — `RemoveFailed` carrying no
  /// deadline (the same predicate `rearm_parked_batch` selects on). The
  /// recovery-fairness suites' oracle for which scope's backlog a cap refusal
  /// re-armed vs. left parked.
  #[cfg(all(test, feature = "tokio"))]
  fn parked_for(&self, scope: ScopeId) -> usize {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter(|ob| {
        ob.scope == scope && matches!(ob.phase, Phase::RemoveFailed { retry_at: None, .. })
      })
      .count()
  }

  /// The birth/terminal census paired with the live record count — the census
  /// equation's oracle.
  #[cfg(all(test, feature = "tokio"))]
  fn census(&self) -> (Census, usize) {
    let inner = lock_ledger(&self.ledger);
    (inner.census, inner.obligations.len())
  }
}

/// Which producer is asking [`CookieRegistry::removal_decision_locked`] to
/// remove a cookie — the two callers with different addressing/re-arm
/// semantics. Both address ONE incarnation by id: with the cleanup queue gone,
/// the public path-addressed request resolves its path to an id at the door, so
/// no path-addressed removal decision survives here.
#[derive(Clone)]
enum RemovalRequest {
  /// A targeted request — a marked record on the wake sweep, a retire sweep, the
  /// close sweep, a recovery re-arm: addresses one incarnation by id, and a no-op
  /// if that incarnation has been retired (a sweep never touches a successor
  /// incarnation it did not select — it may belong to a different, live scope).
  /// `Owned` dispatches; a PARKED `RemoveFailed` re-arms with a fresh budget; a
  /// scheduled `RemoveFailed` or a `Removing` coalesces; a sync still parked and a
  /// write still in the pool are pre-physical, so neither is addressable for
  /// removal — the pool write reaps itself against the flags and the mark.
  Targeted(CookieId),
  /// The retry dispatcher, firing a due deadline: dispatches only a
  /// `RemoveFailed` record, PRESERVING its attempt count toward the budget; a
  /// retired incarnation or any other phase is a no-op.
  RetryDue(CookieId),
}

impl<F: FsOps> Drop for CookieRegistry<F> {
  fn drop(&mut self) {
    // The ABNORMAL-path backstop — a panic or a task cancellation, where no
    // orderly close ran its tracked sweep. On the NORMAL path the close already
    // swept every owned cookie as a grace-covered job, so this finds the ledger
    // empty (or only records whose unlink transiently failed) and merely raises
    // the flag one more, idempotent, time.
    //
    // The flag is raised BEFORE the map is taken, and a write claims its file
    // under the same lock: a claim that beat the take is in the map this sweep
    // unlinks; one that lost it sees the flag and reaps itself. Neither order
    // leaks. The unlinks are DETACHED, never synchronous: a synchronous unlink
    // on a hung mount would wedge the very unwind this Drop runs under. A
    // detached job may not run on a cancelled runtime — the accepted best-effort
    // for the abnormal path, which by construction cannot block.
    self.shutdown.store(true, Ordering::SeqCst);
    // Retire every remaining record under ONE lock (removing its two index
    // entries with it), each counted as the abnormal residual it is. Keep the
    // landing path of each record that has NO unlink already in flight, for a
    // detached best-effort unlink.
    //
    // A record with NO path is pre-physical, so it has no file to reap: a sync
    // still PARKED on its fence had no write dispatched at all (its caller's reply
    // drops with the driver's locals, and its record is counted here as the
    // abnormal residual it is), while a write still IN THE POOL knows where its
    // file landed and nobody else does — the flag raised above is what makes it
    // refuse its claim and reap the file itself, the same protocol that covers a
    // write racing an orderly close.
    //
    // A `Removing` record already has a job — the orderly-close drain's (which
    // may be hung past the grace), or one spawned just before an abnormal cancel
    // — and a second unlink for the same path is exactly the duplicate the
    // single-flight choke point forbids. A `Removing` record whose job never
    // lands on a cancelled runtime is the accepted abnormal-path residual, no
    // worse than any other detached job there.
    //
    // ACCEPTED RESIDUAL (orderly close): a `Removing` record whose unlink hangs
    // PAST the ~1 s grace and only THEN fails is skipped here and gets no retry —
    // its file persists. This is bounded and honestly reported: close already
    // returned `NotQuiesced` counting that cookie (`unremoved` tallies every
    // record), and the residue is an inert, reserved-namespace
    // (`is_sync_artifact`) file that never surfaces as a user event. Removing it
    // after the fact would require a cleanup owner that outlives the driver task
    // and awaits the hung unlink — disproportionate machinery for an inert file
    // left by a pathological mount during shutdown. On a healthy fs the drain
    // confirms every unlink within the grace and this branch reaps nothing.
    let reap: Vec<PathBuf> = {
      let mut inner = lock_ledger(&self.ledger);
      let ids: Vec<CookieId> = inner.obligations.keys().copied().collect();
      ids
        .into_iter()
        .filter_map(|id| inner.retire(id, Reaped::AbnormalResidual))
        .filter(|ob| !matches!(ob.phase, Phase::Removing { .. }))
        .filter_map(|ob| ob.path)
        .collect()
    };
    if reap.is_empty() {
      return;
    }
    let ops = self.ops.clone();
    (self.spawn_detached)(Box::new(move || {
      for path in reap {
        let _ = ops.remove_cookie(&path);
      }
    }));
  }
}

/// One in-flight root replacement: the reservation the commit releases and
/// the caller's reply. A descending replace parks its spawned-but-uncommitted
/// replacement in `arming` while the new root's pre-arm runs on the blocking
/// pool ([`FsOps::preflight_arm`]); a kernel-recursive replace commits
/// straight off its spawn and never populates it.
struct ReplaceState<H> {
  reservation: crate::watcher::ReservationGuard,
  reply: futures_channel::oneshot::Sender<Result<(), crate::error::ReplaceRootError>>,
  arming: Option<SpawnedSource<H>>,
}

/// One watch awaiting its spawn result: the reply channel plus the root the
/// watcher reserved, so the final-root revalidation can exclude this watch's
/// own reservation from the conflict check.
struct PendingWatch {
  requested: PathBuf,
  reply: WatchReply,
}

/// A registration grant held between a descending spawn's success and its
/// ROOT watch-result: the stream is live but covers nothing until the root's
/// kernel watch arms, and the public contract dates delivery from the grant.
struct DeferredGrant {
  pending: PendingWatch,
  /// The final canonical root (what the grant hands the caller).
  root: PathBuf,
}

/// Commits one successful registration: hands the caller the armed-to-unwind
/// grant. `false` means the watch() future was already gone — the caller
/// unwinds the scope.
fn commit_grant(
  pending: PendingWatch,
  scope: ScopeId,
  root: PathBuf,
  unwind_tx: &async_channel::Sender<ScopeId>,
) -> bool {
  let grant = WatchGrant::new(scope, root, unwind_tx.clone());
  match pending.reply.send(Ok(grant)) {
    Ok(()) => true,
    Err(payload) => {
      // The receiver is already gone; unwind synchronously rather than
      // through the grant's Drop.
      if let Ok(grant) = payload {
        grant.defuse();
      }
      false
    }
  }
}

/// Lowers a failed ROOT arm to the registration vocabulary: the caller asked
/// to watch a directory that was validated at spawn, so an arm failure is a
/// race (the object vanished) or an environment limit.
fn arm_grant_error(err: WatchError, requested: PathBuf, root: PathBuf) -> WatchRootError {
  match err {
    WatchError::NotFound | WatchError::Gone => WatchRootError::NotFound { path: requested },
    err => WatchRootError::Source(SourceError::RootUnavailable {
      root,
      source: std::io::Error::other(format!(
        "the root watch could not be armed ({})",
        err.as_str()
      )),
    }),
  }
}

/// The successful payload of a watch reply: ownership of the just-spawned
/// stream, armed to unwind.
///
/// A oneshot send succeeding only proves the receiver was alive — not that
/// the `watch()` future will ever poll the value out. Until
/// [`defuse`](Self::defuse) — called only after the watcher has inserted the
/// registry entry — dropping the grant (a cancelled future, a dropped
/// receiver) asks the driver to unwatch the scope, so no live stream is ever
/// left without an owner. This is the commit half of a two-phase handoff;
/// the unwind funnels into the driver's normal unwatch path (teardown,
/// `on_scope_dead`, registry reconciliation).
pub(crate) struct WatchGrant {
  scope: ScopeId,
  root: PathBuf,
  unwind: async_channel::Sender<ScopeId>,
  armed: bool,
}

impl WatchGrant {
  /// Mints an armed grant. The driver is the only production caller; tests
  /// mint grants to pin the unwind contract.
  pub(crate) const fn new(
    scope: ScopeId,
    root: PathBuf,
    unwind: async_channel::Sender<ScopeId>,
  ) -> Self {
    Self {
      scope,
      root,
      unwind,
      armed: true,
    }
  }

  /// The granted scope.
  pub(crate) const fn scope(&self) -> ScopeId {
    self.scope
  }

  /// Commits the grant: the caller now owns the stream through its registry,
  /// and dropping the grant no longer unwinds it.
  pub(crate) fn defuse(mut self) {
    self.armed = false;
  }
}

impl Drop for WatchGrant {
  fn drop(&mut self) {
    if self.armed {
      // Unbounded and driver-held: this send only fails when the driver is
      // gone, whose own exit path already reclaimed every stream.
      let _ = self.unwind.try_send(self.scope);
    }
  }
}

impl core::fmt::Debug for WatchGrant {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("WatchGrant")
      .field("scope", &self.scope)
      .field("root", &self.root)
      .field("armed", &self.armed)
      .finish_non_exhaustive()
  }
}

/// One command from the watcher facade to its driver task.
pub(crate) enum Command {
  /// Watch a new root; resolves once the native stream is live.
  Watch {
    /// The root to watch.
    root: PathBuf,
    /// The delivery interest for the new scope.
    interest: Interest,
    /// Resolved once the stream is live, with the scope handle and the
    /// canonical root path event paths will arrive under.
    reply: WatchReply,
  },
  /// Stop watching a root; the awaited form resolves once its stream is torn down.
  Unwatch {
    /// The scope to stop.
    scope: ScopeId,
    /// `Some` for the awaited [`Watcher::unwatch`](crate::Watcher::unwatch) (resolved with
    /// whether the scope existed); `None` for the non-blocking, reply-less
    /// [`Watcher::request_unwatch`](crate::Watcher::request_unwatch) — the SAME teardown and
    /// registry reclamation, simply unacknowledged. The driver applies both
    /// identically and skips the ack when there is no reply.
    reply: Option<futures_channel::oneshot::Sender<bool>>,
  },
  /// Reconcile a live scope's per-directory coverage to the `retained` cover IN PLACE,
  /// BIDIRECTIONALLY — prune every descended watch strictly outside the cover AND re-arm
  /// any retained subtree an earlier, narrower cover pruned — keeping every already-covered
  /// retained subtree and its connecting ancestors armed (no re-arm, so no gap). The core
  /// answers every refusal as a typed no-op (unknown scope, not publicly live,
  /// kernel-recursive profile, refused cover), acknowledged immediately; a reconcile that
  /// RAN parks its acknowledgement under a settlement fence, resolved only once the scope's
  /// re-arm work has quiesced — the effect-completion fence, so the ack means "the retained
  /// cover is live", never "the effects were queued".
  SetCover {
    /// The scope to reconcile.
    scope: ScopeId,
    /// The canonical absolute paths whose coverage MUST be retained (the survivor
    /// antichain). Every watch neither under one of these nor an ancestor of one is
    /// pruned; every retained prefix not currently covered is re-armed.
    retained: Vec<PathBuf>,
    /// `Some` for the awaited [`Watcher::set_cover`](crate::Watcher::set_cover) — resolved
    /// with the reconcile's [`CoverOutcome`]: immediately for a no-op, at the settlement
    /// fence otherwise; `None` for the non-blocking, reply-less
    /// [`Watcher::request_set_cover`](crate::Watcher::request_set_cover) — the PROMPT path
    /// that applies a queued reconcile without waiting for a later arm. The driver applies
    /// both identically; a reply-less reconcile opens no fence, though its window still
    /// feeds the settlement bookkeeping (loss memory, floor rewind).
    reply: Option<futures_channel::oneshot::Sender<CoverOutcome>>,
  },
  /// Replace a live root's coverage with `root` (make-before-break): the
  /// new stream goes live before the old one is retired, the `RootHandle`,
  /// scope, and epoch stream survive, and the commit's epoch-bumped
  /// full-root `Rescan` instructs the consumer to re-read the widened
  /// world. The reservation travels WITH the command: the driver releases
  /// it at commit or failure, so cancelling the caller's future abandons
  /// only the notification, never the reservation or the swap.
  Replace {
    /// The live scope whose root is being replaced.
    scope: ScopeId,
    /// The canonicalized replacement root.
    root: PathBuf,
    /// The reservation covering `root` (exempting `scope`).
    reservation: crate::watcher::ReservationGuard,
    /// Resolved at commit, or with the typed failure.
    reply: futures_channel::oneshot::Sender<Result<(), crate::error::ReplaceRootError>>,
  },
  /// Place a sync cookie under `dir` for `scope`, resolving with the path it
  /// landed at. The write PARKS on the scope's coverage-settle fence: under a
  /// descending backend a pre-sync write inside a subtree whose per-directory
  /// watch is mid-re-arm was never kernel-reported, and no queue ordering
  /// covers it — settling first means every re-arm terminal is armed-live or
  /// dropped-with-a-standing-`Rescan`. A kernel-recursive scope is trivially
  /// settled, so the write dispatches at once. A `Degraded` settle still
  /// writes: the covering `Rescan` the loss already emitted rides the queue
  /// ahead of the cookie, so the barrier is met by domination.
  SyncRoot {
    /// The root the cookie must be reported on.
    scope: ScopeId,
    /// The directory to place it in (validated inside the root by the watcher).
    dir: PathBuf,
    /// The minted cookie name (the caller owns the reserved namespace).
    name: String,
    /// Resolved with the cookie's path at WRITE-complete — never at observe
    /// (the observation arrives on the caller's own event stream).
    reply: futures_channel::oneshot::Sender<Result<PathBuf, crate::error::SyncRootError>>,
  },
  /// Orderly shutdown; resolves when every stream is torn down.
  Close {
    /// Resolved with the number of teardowns still wedged past the close
    /// grace — 0 means native-stream quiescence was proven.
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only snapshot of per-scope bookkeeping the suites assert is
  /// reclaimed on teardown (the live delivery-lane count), so a leak of that
  /// state under watch/unwatch churn is provable rather than inferred.
  #[cfg(all(test, feature = "tokio"))]
  DebugLaneCount {
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only count of the awaited-unwatch waiters parked for `scope`, so a
  /// suite can prove an issue-and-cancel storm leaves the waiter vector
  /// bounded rather than growing without limit.
  #[cfg(all(test, feature = "tokio"))]
  DebugUnwatchWaiters {
    scope: ScopeId,
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only count of the cookies the driver still OWNS, so a suite can
  /// prove that a failed write, an abandoned reply, a retired scope, and a
  /// completed-cookie reap each leave the registry exactly as they found it — a
  /// leak (or unbounded growth under repeated failure) is then provable rather
  /// than inferred from the unlinks.
  #[cfg(all(test, feature = "tokio"))]
  DebugCookieCount {
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only count of the obligations carrying a reap mark, so a suite can
  /// prove a mark never survives the obligation it names (the boundedness rule).
  #[cfg(all(test, feature = "tokio"))]
  DebugCookieReapMarks {
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only count of `scope`'s PARKED removal records (`RemoveFailed`
  /// carrying no deadline), so the recovery-fairness suites can assert which
  /// scope's backlog a cap refusal re-armed and which stayed parked.
  #[cfg(all(test, feature = "tokio"))]
  DebugCookieParkedFor {
    scope: ScopeId,
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only read of the birth/terminal census plus the live record count, so
  /// a suite can assert the census equation over a whole scenario: every
  /// obligation ever born is either still live or accounted for by exactly one
  /// typed terminal.
  #[cfg(all(test, feature = "tokio"))]
  DebugCookieCensus {
    reply: futures_channel::oneshot::Sender<(Census, usize)>,
  },
}

/// Lowers a refused cover reconcile to the public outcome — answered at
/// command time, the never-fenced half of the set-cover ack.
const fn noop_outcome(reason: CoverNoop) -> CoverOutcome {
  match reason {
    CoverNoop::KernelRecursive => CoverOutcome::Recursive,
    CoverNoop::UnknownScope => CoverOutcome::Skipped(SkipReason::UnknownRoot),
    CoverNoop::NotLive => CoverOutcome::Skipped(SkipReason::NotLive),
    CoverNoop::RefusedCover => CoverOutcome::Skipped(SkipReason::RefusedCover),
  }
}

/// Lowers a settled fence's verdict to the public outcome. This is the ONLY
/// constructor of an [`Applied`](CoverOutcome::Applied) /
/// [`Degraded`](CoverOutcome::Degraded) for a parked reply — reached solely
/// through [`resolve_cover_settlements`] — which is what makes a queue-time
/// acknowledgement unrepresentable: nothing else can answer a fenced reply.
const fn settle_outcome(settle: CoverSettle) -> CoverOutcome {
  match settle {
    CoverSettle::Applied => CoverOutcome::Applied,
    CoverSettle::Degraded => CoverOutcome::Degraded,
  }
}

/// Retires every PARKED obligation `doomed` selects, BEFORE any write is
/// dispatched for it — the ONE pre-physical terminal, shared by the cancel
/// sweep, the replace-commit's uncovered-parked revoke, and the close sweep.
///
/// Each selected obligation earns `NeverCreated`: a parked record is
/// pre-physical by construction (no write was dispatched, so no file can exist),
/// which is exactly the evidence that terminal names. Its caller is answered
/// `Retired` through the fence's routing entry, and its settle fence is abandoned
/// in the core — the same prune the cancelled-ack path runs, and equally
/// untouching of the scope's loss memory and settle floor.
///
/// The ledger is walked ONCE, and `doomed` sees each parked obligation together
/// with its routing entry, so a selection can read the record's truth (scope,
/// mark) and the plumbing (the target dir) in one place. Record, reply and fence
/// move together here, so the routing local and the ledger can never disagree
/// about which syncs are parked.
fn retire_parked_cookies<F: FsOps>(
  core: &mut DriverCore,
  parked_cookies: &mut BTreeMap<FenceId, ParkedCookie>,
  cookies: &CookieRegistry<F>,
  doomed: &dyn Fn(&Obligation, &ParkedCookie) -> bool,
) {
  // Decide AND retire under the one ledger lock; the replies and the core's fence
  // bookkeeping are touched only after it is released. No FS I/O is reachable
  // from here at all — a parked obligation has no file — but the lock still holds
  // nothing but memory, as every ledger critical section must.
  let abandoned: std::collections::BTreeSet<FenceId> = {
    let mut inner = lock_ledger(&cookies.ledger);
    let selected: Vec<(FenceId, CookieId)> = inner
      .obligations
      .values()
      .filter_map(|ob| match ob.phase {
        Phase::Parked { fence } => parked_cookies
          .get(&fence)
          .filter(|parked| doomed(ob, parked))
          .map(|_| (fence, ob.id)),
        Phase::InPool | Phase::Owned | Phase::Removing { .. } | Phase::RemoveFailed { .. } => None,
      })
      .collect();
    for (_, id) in &selected {
      inner.retire(*id, Reaped::NeverCreated);
    }
    selected.into_iter().map(|(fence, _)| fence).collect()
  };
  for fence in &abandoned {
    if let Some(parked) = parked_cookies.remove(fence) {
      // The umbrella's canceller has usually dropped this receiver already (so the
      // send is a no-op there), but a direct-API caller learns its parked sync was
      // retired rather than reading a bare `Closed`.
      let _ = parked.reply.send(Err(crate::error::SyncRootError::Retired));
    }
  }
  core.abandon_cover_fences(&abandoned);
}

/// Resolves every parked set-cover acknowledgement whose fence has settled —
/// the loop-top (and close-drain) choke point. It first prunes CANCELLED
/// callers (the reply receiver is gone) on BOTH sides of the seam: the parked
/// sender here, and the fence's pending tuple in the core
/// ([`DriverCore::abandon_cover_fences`]) — the scope's loss memory and
/// settle-floor bookkeeping stay untouched, so the settle observation's cover
/// repair is unaffected. Pruning only the sender would let an issue-and-cancel
/// storm against a stalled scope grow the core's pending list without bound
/// (the bounded mailbox limits instantaneous traffic, never the total). The
/// prune is O(parked) per pass, and it means a reported settlement may
/// legitimately find no sender (a caller dropped at close).
#[allow(clippy::too_many_arguments)]
fn resolve_cover_settlements<R, F>(
  core: &mut DriverCore,
  ops: &F,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  cover_replies: &mut BTreeMap<FenceId, futures_channel::oneshot::Sender<CoverOutcome>>,
  parked_cookies: &mut BTreeMap<FenceId, ParkedCookie>,
  cookies: &mut CookieRegistry<F>,
  live: &dyn Fn(ScopeId) -> bool,
) where
  R: RuntimeLite,
  F: FsOps,
{
  let mut abandoned = std::collections::BTreeSet::new();
  cover_replies.retain(|fence, reply| {
    let alive = !reply.is_canceled();
    if !alive {
      abandoned.insert(*fence);
    }
    alive
  });
  core.abandon_cover_fences(&abandoned);
  // A cancelled sync (the caller dropped its future) abandons its fence the same
  // way — and, since the cookie is simply never written, its obligation reaches
  // the pre-physical terminal with it rather than lingering in the ledger for a
  // write that will never be dispatched.
  retire_parked_cookies(core, parked_cookies, cookies, &|_, parked| {
    parked.reply.is_canceled()
  });
  for (fence, settle) in core.poll_cover_settlements() {
    // A missing sender is a caller dropped at close; settlement already
    // updated the core's bookkeeping either way.
    if let Some(reply) = cover_replies.remove(&fence) {
      let _ = reply.send(settle_outcome(settle));
      continue;
    }
    // The settle-fenced cookie write. BOTH verdicts write: a `Degraded`
    // settle means a WINDOW loss already stood a covering `Rescan` that
    // rides the queue ahead of this cookie, and any LEVEL-PERSISTENT
    // deficit (an arm-refused slot, an exhausted-read interior — darkness
    // that outlives its edge `Rescan`) is re-signaled below before the
    // write dispatches — so a covering `Rescan` rides the queue ahead of
    // this cookie in EVERY case, and the barrier is met by domination
    // rather than by delivery. Only a scope that DIED loses its write (its
    // fences degrade at teardown, and there is no stream left to report the
    // cookie on).
    if let Some(cookie) = parked_cookies.remove(&fence) {
      let _ = settle;
      // The obligation this fence carries: born at its sync's admission, so it is
      // always here — the routing entry above and the record move in lockstep,
      // which is why nothing below has to tolerate a missing record. Should that
      // lockstep ever be broken by a later change, the caller is still ANSWERED
      // rather than left to read a bare `Closed` off a dropped reply: no routing
      // entry may be discarded without resolving the barrier it carries.
      let Some((id, scope, name)) = cookies.parked_on(fence) else {
        let _ = cookie.reply.send(Err(crate::error::SyncRootError::Retired));
        continue;
      };
      // The root the cookie must stay inside — and, being recorded on the same
      // transitions the stream is, a second proof the scope is live.
      let Some(root) = cookies
        .root_of(scope)
        .filter(|_| live(scope))
        .map(Path::to_path_buf)
      else {
        // The scope died under the parked sync. Nothing physical was ever created
        // for it — no write was dispatched — so the obligation earns the
        // pre-physical terminal here, in the same step that answers its barrier.
        // The fence needs no abandoning: it already settled to reach this line.
        lock_ledger(&cookies.ledger).retire(id, Reaped::NeverCreated);
        let _ = cookie.reply.send(Err(crate::error::SyncRootError::Retired));
        continue;
      };
      // F2: a standing terminal deficit means this scope has dark coverage
      // no past `Rescan` covers going forward. Re-signal it NOW — the fresh
      // epoch-bumped `Rescan`s enter the effect queue ahead of anything the
      // cookie write can cause (its own record arrives only via a later
      // batch input), and the loop-top `execute_effects` flushes them to the
      // consumer before that record can be routed.
      let _ = core.resignal_coverage_deficits(scope);
      // The dispatched write is a TRACKED, single-flighted job: from here its
      // obligation is an `InPool` record rather than a `Parked` one — still the
      // scope's single-flight gate (a second sync is refused while it stands),
      // still one unit of the global cap, and now an outstanding obligation that
      // holds close in `NotQuiesced` rather than letting it wedge on a hung mount.
      // The guard is taken HERE FIRST, at dispatch, so the flags it carries cover
      // the whole in-flight window: a teardown, a cancel, or a driver exit between
      // this line and the write's landing is visible to the write itself.
      //
      // A cancel that named this sync while it was parked refuses the dispatch
      // instead: the obligation is retired pre-physically and no write is ever
      // made, which is the same refusal the claim would make on the same mark, one
      // phase earlier and without creating the file first.
      let Some(guard) = cookies.dispatch_guard(scope, id) else {
        let _ = cookie.reply.send(Err(crate::error::SyncRootError::Retired));
        continue;
      };
      let ops = ops.clone();
      let tx = op_tx.clone();
      R::spawn_blocking_detach(move || {
        let ParkedCookie { dir, reply } = cookie;
        match ops.write_cookie(&root, &dir, &name) {
          Ok(path) => {
            // Hand the file to the registry — the path the write ACTUALLY
            // landed at, which only the write knows (a covered FILE
            // subscription's cookie lands in the parent).
            match guard.claim(&path) {
              None => {
                // A refused claim means a cancel named this obligation, the
                // registry is gone, the scope is retiring, or the generation
                // moved: its cookie must not survive, so the write self-reaps
                // (never discarding ownership before the unlink confirms —
                // finding 2's fix).
                self_reap(&ops, &guard, path, None);
                let _ = reply.send(Err(crate::error::SyncRootError::Retired));
              }
              Some(id) => {
                if let Err(Ok(path)) = reply.send(Ok(path)) {
                  // A caller that abandoned the sync (timed out, dropped the
                  // future) has dropped this reply receiver and will never ask
                  // for this cookie's removal. The write completing late must
                  // not outlive the barrier that asked for it: reap the file,
                  // but keep ownership (of incarnation `id`) until the unlink
                  // confirms.
                  self_reap(&ops, &guard, path, Some(id));
                }
              }
            }
          }
          Err(source) => {
            // Nothing was created, so this incarnation reaches its terminal
            // having produced no file: retire it as never-created, IN THE JOB
            // that learned the fact. This is what keeps repeated failed syncs on
            // a long-lived scope from growing the ledger — and, because the
            // record leaves only once nothing physical can exist, it can never
            // uncount a live obligation.
            lock_ledger(&guard.ledger).retire(guard.id, Reaped::NeverCreated);
            let _ = reply.send(Err(crate::error::SyncRootError::Write {
              path: dir.join(&name),
              source,
            }));
          }
        }
        // Done, whatever the verdict. Every physical fact this write learned is
        // already written to its record, under the ledger lock, by the code that
        // learned it; this message only tells the driver — the sole owner of the
        // clock — to schedule a retry if the record parked failed.
        let _ = tx.try_send(OpResult::CookieWriteDone { id: guard.id });
      });
    }
  }
}

/// The write job's self-reap: unlink a cookie its own write must not leave
/// behind, NEVER discarding ownership before the unlink CONFIRMS, and NEVER
/// acting on a record that is not the one this write was born for. Every verdict
/// is written to that record here, in the job, under the ledger lock; the
/// `CookieWriteDone` that follows carries only the id, and the driver — the sole
/// owner of the clock — schedules the retry of a record left `RemoveFailed`.
///
/// `claimed = None` — the claim was REFUSED. The record is still `InPool`: it is
/// RE-ASSERTED here (its path published, so every sweep can find the file, and
/// its phase moved to `Removing`) BEFORE the unlink, and that ordering is what
/// keeps the accounting honest — the obligation is never momentarily invisible
/// while its file is on disk, and a `Drop` landing mid-unlink skips it as it
/// skips any `Removing` record. The re-assert deliberately ignores the
/// shutdown/retiring flags that caused the refusal: it is what keeps a failing
/// unlink from orphaning the file.
///
/// `claimed = Some(id)` — the reply send FAILED, so OUR claim left record `id`
/// `Owned`, and a racing token-cancel may already have moved it to `Removing`
/// and dispatched its own unlink (the caller-gone event that fails `reply.send`
/// is the same event that makes the umbrella send `Cancel`); we first CLAIM the
/// removal under the lock, addressing our own id, so the two claimants cannot
/// overlap and we can never act on a SUCCESSOR that reclaimed the path.
///
/// An ABSENT record (only the abnormal-path `Drop`'s take) leaves the refusal
/// case a bare best-effort unlink of the file this write itself created, and the
/// reply-fail case yielding: the record's fate is no longer ours to write.
fn self_reap<F: FsOps>(ops: &F, guard: &CookieGuard, path: PathBuf, claimed: Option<CookieId>) {
  // The incarnation whose fate this reap writes. Both cases name this write's own
  // record — a claim returns the guard's id — but the reply-fail case addresses
  // the id the claim ACTUALLY returned, so a stale claimant can never transition
  // a record that is not the one it claimed.
  let id = claimed.unwrap_or(guard.id);
  // Decide under the lock; every unlink runs after it is released. No FS I/O may
  // happen under the ledger mutex: on a hung mount it would serialize every other
  // pool job behind this one.
  let tracked = {
    let mut inner = lock_ledger(&guard.ledger);
    match inner.obligations.get_mut(&id) {
      // Refusal case: the record never left `InPool` — only this write can learn
      // where its cookie landed, so no other actor could have moved it. Re-assert
      // it, publishing the path so every sweep and the backstop can find the file.
      // `by_path` follows the same newest-claim-wins rule a claim does.
      Some(ob) if matches!(ob.phase, Phase::InPool) => {
        ob.path = Some(path.clone());
        ob.phase = Phase::Removing { attempts: 0 };
        inner.by_path.insert(path.clone(), id);
        true
      }
      // Reply-fail case: take the removal, or yield to whoever beat us.
      Some(ob) if matches!(ob.phase, Phase::Owned) => {
        ob.phase = Phase::Removing { attempts: 0 };
        true
      }
      // Removing/RemoveFailed: a cancel-dispatched unlink already owns this
      // record's fate — unlinking from here would race a file that is no longer
      // ours to remove.
      Some(_) => return,
      // The abnormal-path take already retired the record (it raises its flag
      // first, which is why we were refused).
      None => {
        // A reply-failed claim yields: a racing confirm may already have removed
        // our file, and a successor could own the path now.
        if claimed.is_some() {
          return;
        }
        false
      }
    }
  };
  if !tracked {
    // A refused claim still unlinks the file it created — best-effort, and no
    // record's fate rides on it (the take already retired the record).
    let _ = ops.remove_cookie(&path);
    return;
  }
  if ops.remove_cookie(&path).is_ok() {
    lock_ledger(&guard.ledger).retire(id, Reaped::ConfirmedGone);
  } else {
    // Retain as failed: the file is still on disk and this record still owns it.
    lock_ledger(&guard.ledger).record_remove_failed(id);
  }
}

/// Revokes every barrier still PARKED for `scope` whose directory the just-
/// committed replacement root no longer covers. A replace overwrites the root
/// under a surviving scope; a parked write whose directory now sits outside that
/// coverage would place a cookie the current stream could never observe, so its
/// obligation is retired `NeverCreated` (no write was dispatched, so nothing
/// physical was ever created) and its caller answered `Retired`, rather than left
/// to strand. A parked write STILL inside the (widened) root is kept: it
/// dispatches normally under the bumped generation. The DISPATCHED counterpart —
/// a write already in the pool — is revoked instead by the generation the same
/// commit bumped, checked when it claims.
fn revoke_uncovered_parked_cookies<F: FsOps>(
  core: &mut DriverCore,
  parked_cookies: &mut BTreeMap<FenceId, ParkedCookie>,
  cookies: &CookieRegistry<F>,
  scope: ScopeId,
  new_root: &Path,
) {
  retire_parked_cookies(core, parked_cookies, cookies, &|ob, parked| {
    ob.scope == scope && !cookie_dir_within_root(new_root, &parked.dir)
  });
}

/// Drops CANCELLED awaited-unwatch waiters (the caller dropped its future, so
/// the reply receiver is gone) from every scope's parked vector, removing
/// now-empty scope entries — the loop-top (and close-drain) choke point,
/// analogous to [`resolve_cover_settlements`]'s cancel prune. A `RootHandle`
/// is `Copy`, so a caller can issue-and-cancel `unwatch` repeatedly against a
/// scope whose teardown or replacement is stalled; without this prune each
/// canceled sender would accrue until quiescence (the bounded command mailbox
/// caps instantaneous traffic, never the total). A surviving (still-awaited)
/// waiter keeps its verdict and resolves at quiescence. O(parked) per pass.
fn prune_canceled_unwatch_waiters(
  unwatch_replies: &mut BTreeMap<ScopeId, Vec<(futures_channel::oneshot::Sender<bool>, bool)>>,
) {
  unwatch_replies.retain(|_, waiters| {
    waiters.retain(|(reply, _)| !reply.is_canceled());
    !waiters.is_empty()
  });
}

/// A spawned native source, as the blocking pool hands it back.
pub(crate) struct SpawnedSource<H> {
  /// The live stream handle.
  pub(crate) handle: H,
  /// The stream's single ordered message queue.
  pub(crate) receiver: EventReceiver,
  /// What the spawn learned about the root.
  pub(crate) meta: RootMeta,
}

/// The watcher-side registry of live scopes, written EXCLUSIVELY by the
/// driver task: it records a scope live (before the watch reply is sent) and
/// dead (at every teardown), in program order on one task — so an
/// insert-after-remove interleaving between the two transitions cannot exist.
/// The watcher only reads.
pub(crate) trait ScopeRegistry: Send + Sync + 'static {
  /// `scope`'s stream is live; its event paths arrive under `root`, whose
  /// object identity and ancestor identities the registry retains for the
  /// disjointness checks of later watches. `backend` is the primitive the
  /// spawn barrier selected — the capability report a later `backend_of` query
  /// reads back.
  fn scope_live(
    &self,
    scope: ScopeId,
    root: &Path,
    identity: RootIdentity,
    ancestors: &[RootIdentity],
    backend: BackendKind,
    stats: Option<crate::os::BackendStatsHandle>,
  );

  /// `scope` ended (unwatch, root death, stream fatal, close); its entry is
  /// reclaimed.
  fn scope_dead(&self, scope: ScopeId);

  /// The live or reserved root that overlaps `final_root`, ignoring the one
  /// reservation at `reserved` (the checking watch's own). The backend
  /// re-canonicalizes during spawn, so disjointness must hold for the FINAL
  /// root — the reservation only ever vouched for the form the watcher knew —
  /// and the driver, as the registry's single writer, checks it immediately
  /// before the scope goes live.
  ///
  /// Overlap is decided by byte containment AND by object identity — equality
  /// with a live root, the new root's ancestor chain containing a live root
  /// (new-inside-existing), or a live root's ancestor chain containing the new
  /// identity (existing-inside-new) — so spelling aliases on case- or
  /// normalization-insensitive volumes cannot admit two watches over one
  /// subtree.
  fn final_root_conflict(
    &self,
    final_root: &Path,
    identity: RootIdentity,
    ancestors: &[RootIdentity],
    reserved: Option<&Path>,
    exempt: Option<ScopeId>,
  ) -> Option<PathBuf>;
}

/// One arm or disarm collected from a single effect-drain cycle. The driver
/// groups these per scope and dispatches each scope's run as ONE batch — one
/// control message, one potential reader wake for N arms — while keeping each
/// arm's individual reply (an [`Arm`](Self::Arm) still yields one
/// [`WatchInstalled`](OpResult::WatchInstalled)). Emission order is preserved
/// inside the batch so a disarm and a later re-arm of the same slot apply in
/// the order the core produced them.
pub(crate) enum ControlRequest {
  /// Install a per-directory watch for `watch` (arming `parent`'s child
  /// `name`, addressed by absolute `path`). `expected` is the `(dev, ino)` the
  /// opened object must still have before the watch installs (the enumerate→arm
  /// rename guard); `None` leaves the arm unverified.
  Arm {
    watch: WatchId,
    parent: WatchId,
    name: Segment,
    path: Arc<PathBuf>,
    expected: Option<ExpectedObject>,
  },
  /// Remove `watch`'s per-directory watch (fire-and-forget; no reply).
  Disarm { watch: WatchId },
}

/// The blocking-pool side of the platform: spawn, teardown, and stat. A
/// test implementation runs the whole driver loop against a fake filesystem.
pub(crate) trait FsOps: Clone + Send + Sync + 'static {
  /// The live-stream handle type.
  type Handle: SourceControl;

  /// Starts the native source (blocking).
  fn spawn_source(&self, config: SourceConfig) -> Result<SpawnedSource<Self::Handle>, SourceError>;

  /// `lstat`s one path (blocking).
  fn probe(&self, path: &Path) -> ProbeOutcome;

  /// Creates the sync cookie `name` for `dir`, inside `root` (blocking),
  /// returning the path it landed at. The cookie's whole purpose is the kernel
  /// event its creation mints: it rides the root's ordered queue behind every
  /// change the backend reported before it, so observing it proves those changes
  /// have already exited the pipeline. A read-only tree fails here with
  /// `PermissionDenied` — the honest refusal.
  ///
  /// `dir` is the SUBSCRIPTION's key, which a covered FILE subscription makes a
  /// file: the cookie then lands in the containing directory instead, and never
  /// above `root` (see [`cookie_dir`]). So the RETURNED path is the only
  /// authority on where the cookie went — `dir.join(name)` is not, and nothing
  /// may record ownership of a cookie by predicting its path.
  fn write_cookie(&self, root: &Path, dir: &Path, name: &str) -> Result<PathBuf, std::io::Error>;

  /// Unlinks a sync cookie (blocking). Idempotent: a cookie already gone (a
  /// crash leftover reaped by someone else, a racing sync) maps to `Ok(())`.
  /// Every OTHER failure is RETURNED so the caller can retain the cookie's
  /// ledger record and let a later sweep retry the unlink, rather than silently
  /// orphaning the file. The unlink's own event is suppressed by the reserved
  /// namespace, never by any pending-cookie bookkeeping.
  fn remove_cookie(&self, path: &Path) -> Result<(), std::io::Error>;

  /// Re-reads the live mount table strictly under `root` AND re-stats the root
  /// itself (blocking): the mount prefixes, whether the read was authoritative,
  /// and the root's liveness. The root re-stat rides the mount refresh so a
  /// kernel-recursive backend's root death (unmount/replace — no in-tree signal)
  /// is caught at the refresh cadence without any new timer or effect.
  fn refresh_mounts(&self, root: &Path) -> MountRefresh;

  /// Attaches the arm/disarm port of `scope`'s freshly spawned source under
  /// its transport `generation` (the delivery lane), so the descending
  /// executors can route to its reader AND recognize a control batch left
  /// over from a prior transport. A no-op for executors (fakes) that answer
  /// arms themselves.
  fn attach_scope(&self, scope: ScopeId, port: ScopePort, generation: u64) {
    let _ = (scope, port, generation);
  }

  /// Detaches `scope`'s port (and any transient state keyed under it) at
  /// stream teardown.
  fn detach_scope(&self, scope: ScopeId) {
    let _ = scope;
  }

  /// Installs a per-directory kernel watch for `watch` at `path` (blocking).
  /// Reached only under a descending profile. `expected` is the object the arm
  /// must confirm the open lands on (the enumerate→arm rename guard).
  fn add_watch(
    &self,
    scope: ScopeId,
    watch: WatchId,
    parent: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome;

  /// Removes a per-directory kernel watch (blocking, fire-and-forget).
  fn remove_watch(&self, scope: ScopeId, watch: WatchId);

  /// Executes one scope's batch of arms/disarms (blocking) and returns each
  /// arm's outcome, in order. The default runs them one-by-one through
  /// [`add_watch`](Self::add_watch)/[`remove_watch`](Self::remove_watch) — the
  /// right shape for a fake with no transport; the real inotify source
  /// overrides it to ship the whole batch as ONE control message so N arms cost
  /// at most one reader wake. `generation` is the transport generation the
  /// batch was emitted for; the real source refuses a batch whose generation
  /// no longer matches the attached port (a leftover of a replaced
  /// transport). The default ignores it — a fake answers arms itself and has
  /// no transport to leak.
  fn batch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> Vec<(WatchId, WatchOutcome)> {
    let _ = generation;
    let mut outcomes = Vec::new();
    for request in requests {
      match request {
        ControlRequest::Arm {
          watch,
          parent,
          name,
          path,
          expected,
        } => outcomes.push((
          watch,
          self.add_watch(scope, watch, parent, &path, &name, expected),
        )),
        ControlRequest::Disarm { watch } => self.remove_watch(scope, watch),
      }
    }
    outcomes
  }

  /// Arms `watch` at `path` on an EXPLICIT port — the not-yet-attached
  /// replacement transport of an in-flight descending replace (blocking).
  /// The scope's port table still routes to the OLD stream at this point, so
  /// the pre-arm cannot go through [`batch_control`](Self::batch_control);
  /// commit-or-unwind is decided by the returned outcome. The default routes
  /// through [`add_watch`](Self::add_watch) — the right shape for executors
  /// (fakes) that answer arms themselves and carry `Inert` ports.
  fn preflight_arm(
    &self,
    port: &ScopePort,
    scope: ScopeId,
    watch: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    let _ = port;
    self.add_watch(scope, watch, watch, path, name, expected)
  }

  /// Reads one directory — entries with their stat facts (blocking). Reached
  /// only under a descending profile; `watch` addresses the directory object
  /// for executors that resolve anchors rather than paths.
  fn enumerate(&self, watch: WatchId, path: &Path) -> RawEnumerate;
}

/// The control surface of a live stream handle.
pub(crate) trait SourceControl: Send + 'static {
  /// Quiesces and destroys the stream (blocking, bounded).
  fn shutdown(self);

  /// The clonable arm/disarm port of this source, `Inert` when the backend
  /// carries no arm traffic (kernel-recursive sources, fakes).
  fn scope_port(&self) -> ScopePort {
    ScopePort::Inert
  }

  /// The source's live stats handle, `Some` only for a fanotify source (every
  /// other backend has no pollable internals — design §4.9). The driver threads
  /// it into the registry so [`Watcher::backend_stats`](crate::Watcher::backend_stats)
  /// can snapshot it per root.
  fn backend_stats(&self) -> Option<crate::os::BackendStatsHandle> {
    None
  }

  /// Where a successor stream could resume this one's journal from, when the
  /// backend keeps one and its ids are still valid. A root replacement takes
  /// this from the RETIRING stream and hands it to the replacement's spawn,
  /// so the swap window is replayed from the journal rather than left to the
  /// commit `Rescan` alone. `None` — the default, and every backend without a
  /// journal — simply means live-only: the `Rescan` still covers the window.
  fn resume_token(&self) -> Option<crate::os::ResumeToken> {
    None
  }
}

impl SourceControl for SourceHandle {
  fn shutdown(self) {
    SourceHandle::shutdown(self);
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn scope_port(&self) -> ScopePort {
    SourceHandle::scope_port(self)
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn backend_stats(&self) -> Option<crate::os::BackendStatsHandle> {
    SourceHandle::backend_stats(self)
  }

  // Every source but the Linux ones mints a resume point (inotify and
  // fanotify have no journal to resume from, so they keep the `None`
  // default). FSEvents is the one backend that actually replays from it.
  #[cfg(not(all(target_os = "linux", not(miri))))]
  fn resume_token(&self) -> Option<crate::os::ResumeToken> {
    SourceHandle::resume_token(self)
  }
}

/// Maps an enumerate open failure to the Monitor's `IoClass` vocabulary.
fn io_class(err: &std::io::Error) -> IoClass {
  match err.kind() {
    std::io::ErrorKind::NotFound => IoClass::NotFound,
    std::io::ErrorKind::PermissionDenied => IoClass::Permission,
    _ => IoClass::Io,
  }
}

/// The proto file kind of a stat file type (symlinks are never followed). Feeds
/// the metadata-based enumerate/liveness sample; the Linux path derives the kind
/// from its one sample's raw mode instead ([`kind_of_mode`], via [`stat_sample`]).
#[cfg(not(all(target_os = "linux", not(miri))))]
fn kind_of(kind: &std::fs::FileType) -> tributary_proto::FileKind {
  if kind.is_dir() {
    tributary_proto::FileKind::Dir
  } else if kind.is_symlink() {
    tributary_proto::FileKind::Symlink
  } else if kind.is_file() {
    tributary_proto::FileKind::File
  } else {
    tributary_proto::FileKind::Other
  }
}

// The metadata-based `(dev, ino)` extractors feed the non-Linux enumerate and
// liveness samples; the Linux path reads both from its one `statx` result, so it
// never calls these.
#[cfg(all(unix, not(all(target_os = "linux", not(miri)))))]
fn dev_of(meta: &std::fs::Metadata) -> u64 {
  use std::os::unix::fs::MetadataExt;
  meta.dev()
}

#[cfg(all(not(unix), not(all(target_os = "linux", not(miri)))))]
fn dev_of(_meta: &std::fs::Metadata) -> u64 {
  0
}

#[cfg(all(unix, not(all(target_os = "linux", not(miri)))))]
fn ino_of(meta: &std::fs::Metadata) -> u64 {
  use std::os::unix::fs::MetadataExt;
  meta.ino()
}

#[cfg(all(not(unix), not(all(target_os = "linux", not(miri)))))]
fn ino_of(_meta: &std::fs::Metadata) -> u64 {
  0
}

/// Every fact one caller reads about a filesystem object, from ONE sample of that
/// object (symlink not followed): its kind, device, inode, and mount frame. The
/// four are always one object's — the one-sample rule (see the driver module doc)
/// made concrete, so a rename/bind slipping between two syscalls can never pair
/// one object's identity with another's frame.
#[cfg(all(target_os = "linux", not(miri)))]
#[derive(Debug)]
struct StatSample {
  kind: tributary_proto::FileKind,
  dev: u64,
  ino: u64,
  /// The mount frame, `Some` only when the sample reported the mount id, `None`
  /// on a `statx` mask miss (`STATX_MNT_ID` is 5.8; below it the bit stays unset)
  /// — the core then fences on the device belt.
  frame: Option<u64>,
}

/// ONE sample of the object at `path` (symlink not followed): the sole path-syscall
/// behind every fact a caller reads about that object.
///
/// `statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS | STATX_MNT_ID)` —
/// kind, device, inode, AND mount frame all from THAT one result. The Linux backends
/// require `statx` (Linux 4.11+, gated once at spawn — see `os::linux`), so there is
/// no sub-`statx` fallback: the sample is always this single syscall. A mask miss
/// (`STATX_MNT_ID` is 5.8) declines only the frame (`None`), and the core then fences
/// that object on the device belt.
///
/// The path is resolved the same way `symlink_metadata` was, so an anchor
/// (`/proc/self/fd/N`) enumerate reads every fact THROUGH the pinned fd too. Any
/// errno propagates unchanged (notably `NOENT`), keeping the callers'
/// `Missing`/raced-away meanings.
#[cfg(all(target_os = "linux", not(miri)))]
fn stat_sample(path: &Path) -> Result<StatSample, rustix::io::Errno> {
  use rustix::fs::{AtFlags, StatxFlags, makedev, statx};
  let stx = statx(
    rustix::fs::CWD,
    path,
    AtFlags::SYMLINK_NOFOLLOW,
    StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID),
  )?;
  Ok(StatSample {
    kind: kind_of_mode(u32::from(stx.stx_mode)),
    dev: makedev(stx.stx_dev_major, stx.stx_dev_minor),
    ino: stx.stx_ino,
    frame: (stx.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(stx.stx_mnt_id),
  })
}

/// The proto file kind of a raw `st_mode`/`stx_mode` (symlinks are never followed).
#[cfg(all(target_os = "linux", not(miri)))]
fn kind_of_mode(mode: u32) -> tributary_proto::FileKind {
  use rustix::fs::FileType;
  match FileType::from_raw_mode(mode) {
    FileType::Directory => tributary_proto::FileKind::Dir,
    FileType::Symlink => tributary_proto::FileKind::Symlink,
    FileType::RegularFile => tributary_proto::FileKind::File,
    _ => tributary_proto::FileKind::Other,
  }
}

/// The root's liveness verdict AND its current mount frame from ONE
/// [`stat_sample`] — so the refresh pairs the identity it decides
/// alive-vs-replaced on with the frame it adopts from the SAME object, never two
/// separate path lookups a replace/remount could split. The single sample yields
/// `(dev, ino)` for the liveness identity and `stx_mnt_id` for the frame in one
/// atomic read: were these two reads (an `lstat` then a `statx`), a swap between
/// them would let the OLD identity's "alive-and-matching" verdict adopt a DIFFERENT
/// object's mount frame, over-/under-fencing genuine children until the next refresh
/// healed it.
///
/// A mask miss yields the identity from the SAME result with a `None` frame, so a
/// transient miss never mispairs, it just declines the frame (the core keeps its
/// captured one). The sample maps to the [`RootLiveness`] taxonomy exactly as the
/// prior `symlink_metadata` did: `ENOENT` is `Missing` (DeleteSelf), any other error
/// is `Unreadable` (MoveSelf), success is `Present`.
#[cfg(all(target_os = "linux", not(miri)))]
fn root_liveness_and_frame(root: &Path) -> (RootLiveness, Option<u64>) {
  match stat_sample(root) {
    Ok(sample) => (
      RootLiveness::Present(RootIdentity::new(sample.dev, sample.ino.into())),
      sample.frame,
    ),
    Err(rustix::io::Errno::NOENT) => (RootLiveness::Missing, None),
    Err(_) => (RootLiveness::Unreadable, None),
  }
}

/// The non-Linux / miri sample: `symlink_metadata` for the liveness verdict, no
/// mount frame (no mount-id notion off Linux — the macOS refresh executor inherits
/// this, and its core descent fences on device alone). Kept a single stat so the
/// identity is still one object's, matching the Linux helper's atomicity.
#[cfg(all(
  not(all(target_os = "linux", not(miri))),
  not(all(target_os = "windows", not(miri)))
))]
fn root_liveness_and_frame(root: &Path) -> (RootLiveness, Option<u64>) {
  let liveness = match std::fs::symlink_metadata(root) {
    Ok(meta) => RootLiveness::Present(RootIdentity::new(dev_of(&meta), ino_of(&meta).into())),
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => RootLiveness::Missing,
    Err(_) => RootLiveness::Unreadable,
  };
  (liveness, None)
}

/// The Windows sample: the identity must be the SAME `(volume serial,
/// 128-bit file id)` the spawn barrier minted into `RootMeta` — a stat-based
/// `(0, 0)` here would make the birth refresh classify every healthy root
/// as replaced. Read through the same pinned-handle helper the barrier
/// uses; the open itself is the liveness verdict.
#[cfg(all(target_os = "windows", not(miri)))]
fn root_liveness_and_frame(root: &Path) -> (RootLiveness, Option<u64>) {
  let liveness = match crate::os::windows::ffi::open_directory(root) {
    Ok(handle) => {
      use std::os::windows::io::AsHandle;
      match crate::os::windows::ffi::identity_of(handle.as_handle()) {
        Ok(identity) => {
          RootLiveness::Present(RootIdentity::new(identity.volume_serial, identity.file_id))
        }
        Err(_) => RootLiveness::Unreadable,
      }
    }
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => RootLiveness::Missing,
    Err(_) => RootLiveness::Unreadable,
  };
  (liveness, None)
}

/// The real platform: `Source::spawn` + `lstat`.
#[derive(Debug, Clone, Default)]
pub(crate) struct RealFs {
  /// Per-scope arm/disarm ports of live descending sources, attached at
  /// spawn success and detached at stream teardown. Kernel-recursive scopes
  /// attach `Inert` and never route arm traffic. Each port carries the
  /// TRANSPORT GENERATION it was attached under (the scope's delivery lane):
  /// a control batch is dispatched with the generation current at emission,
  /// and a batch whose generation no longer matches the attached port is
  /// stale — a leftover of the pre-replace transport — and must not arm the
  /// replacement's fd nor publish an anchor into the swapped scope.
  #[cfg(all(target_os = "linux", not(miri)))]
  ports: std::sync::Arc<std::sync::RwLock<BTreeMap<ScopeId, (u64, ScopePort)>>>,
  /// Transient `O_PATH` anchors returned by arms (keyed by the globally
  /// unique watch, valued with the owning scope for teardown reclamation),
  /// held only until the watch's cold enumerate consumes them
  /// (anchor-relative readdir), so fd usage stays O(in-flight operations) —
  /// never O(tree).
  #[cfg(all(target_os = "linux", not(miri)))]
  anchors: std::sync::Arc<std::sync::Mutex<BTreeMap<WatchId, (ScopeId, std::os::fd::OwnedFd)>>>,
}

impl RealFs {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// The transport generation currently attached for `scope`, or a sentinel
  /// (`u64::MAX`) when no descending port is attached — a value no real lane
  /// generation reaches, so a control op resolving it fails the front-check
  /// and refuses rather than arming a nonexistent transport.
  #[cfg(all(target_os = "linux", not(miri)))]
  fn current_generation(&self, scope: ScopeId) -> u64 {
    self
      .ports
      .read()
      .unwrap()
      .get(&scope)
      .map(|(generation, _)| *generation)
      .unwrap_or(u64::MAX)
  }

  /// Builds one arm request, resolving the parent's still-held transient anchor
  /// so the open is object-correct even across a parent rename. A consumed (or
  /// never-held) anchor falls back to the absolute path with ENOENT honesty —
  /// the Monitor's NotFound path re-arms. The root is its own parent, and
  /// `openat(anchor, name)` cannot re-open the anchor itself, so the root
  /// always arms by absolute path.
  ///
  /// The path fallback is exactly why `expected` matters: an absolute-path open
  /// can land on a DIFFERENT object if a rename slipped in after the enumerate,
  /// so the reader confirms the opened fd's `(dev, ino)` against `expected`
  /// before installing the watch (the anchor-chain open is already object-pinned
  /// through `/proc/self/fd`, but the fallback is not — and it is the common case
  /// once the cold enumerate has consumed the parent anchor).
  #[cfg(all(target_os = "linux", not(miri)))]
  fn build_arm_request(
    &self,
    watch: WatchId,
    parent: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> crate::os::linux::AnchorRequest {
    let expected = expected.map(|e| crate::os::linux::ExpectedObject {
      dev: e.dev,
      ino: e.ino,
    });
    let parent_anchor = if parent == watch {
      None
    } else {
      self
        .anchors
        .lock()
        .unwrap()
        .get(&parent)
        .and_then(|(_, fd)| fd.try_clone().ok())
    };
    match parent_anchor {
      Some(fd) => crate::os::linux::AnchorRequest {
        watch,
        parent: Some(fd),
        name: std::ffi::OsString::from(name.as_str()),
        expected,
      },
      None => crate::os::linux::AnchorRequest {
        watch,
        parent: None,
        name: path.as_os_str().to_os_string(),
        expected,
      },
    }
  }
}

/// The directory a sync cookie for `dir` actually lands in: `dir` itself when it
/// IS one, its containing directory otherwise — never above `root`.
///
/// The cookie key a sync carries is the subscription's own, and a FILE
/// subscription is validly covered (it commits under an armed ancestor) — so
/// `dir` can name a file, and creating `file/.tributaries-sync-…` inside it would
/// fail ENOTDIR instead of establishing a barrier. The cookie goes BESIDE such a
/// subscription instead, and the caller learns the real location from the
/// returned path.
///
/// `root` is the FLOOR, and it is load-bearing rather than defensive. The
/// watcher proved `dir` is INSIDE the root, so the parent of a `dir` strictly
/// under the root is inside it too — but the parent of the ROOT is not, and a
/// root that has just died (deleted, or replaced by a file) is exactly a `dir`
/// that fails the directory test. Without the floor, a sync racing a root death
/// would place a cookie in the root's PARENT: outside the watched tree, where no
/// event can be reported and nothing else would have any business writing. With
/// it, such a write answers the typed failure instead — the honest outcome for a
/// barrier on a root that is gone.
///
/// One sample, symlink NOT followed: a symlinked directory is not a directory
/// here, and deliberately so — a cookie written through it would be created
/// under the link's TARGET and its event reported outside this root, never
/// meeting the barrier.
fn cookie_dir<'a>(root: &Path, dir: &'a Path) -> &'a Path {
  match std::fs::symlink_metadata(dir) {
    Ok(meta) if meta.is_dir() => dir,
    _ => match dir.parent() {
      Some(parent) if parent.starts_with(root) => parent,
      // No containing directory inside the root: `dir` IS the root (or has no
      // parent at all). Keep `dir` — the create then fails honestly.
      _ => dir,
    },
  }
}

/// Whether a minted cookie NAME is exactly one normal filename component — no
/// separators, no `.`/`..`, not absolute, not empty. The umbrella mints
/// `.tributaries-sync-…`, always normal; anything else is a contract violation
/// that must be refused BEFORE it reaches a path join, where an absolute or
/// `..` name would escape the directory the barrier was validated for.
pub(crate) fn is_normal_cookie_name(name: &str) -> bool {
  let mut components = Path::new(name).components();
  matches!(
    (components.next(), components.next()),
    (Some(std::path::Component::Normal(_)), None)
  )
}

/// `path` with its `.`/`..` components folded lexically (no filesystem access),
/// or `None` if a `..` would climb above the path's anchor. Purely lexical, so
/// it is safe to run inline on the owner's thread — the containment decision it
/// feeds never touches a possibly-hung mount.
fn lexically_normalized(path: &Path) -> Option<PathBuf> {
  let mut out = PathBuf::new();
  for component in path.components() {
    match component {
      std::path::Component::ParentDir => {
        if !out.pop() {
          return None;
        }
      }
      std::path::Component::CurDir => {}
      other => out.push(other.as_os_str()),
    }
  }
  Some(out)
}

/// Whether a cookie directory lies within `root` once `.`/`..` are folded
/// lexically. This REPLACES a plain `starts_with`, which accepts `/r/../outside`
/// (component-wise, `/r/../outside` does start with `/r`) and would place a
/// barrier outside the watched tree. `root` is canonical (no `.`/`..`), so a
/// lexical prefix test on the folded `dir` is exact.
pub(crate) fn cookie_dir_within_root(root: &Path, dir: &Path) -> bool {
  lexically_normalized(dir).is_some_and(|dir| dir.starts_with(root))
}

impl FsOps for RealFs {
  type Handle = SourceHandle;

  fn spawn_source(&self, config: SourceConfig) -> Result<SpawnedSource<Self::Handle>, SourceError> {
    if !config.backend.native_to_host() {
      return Err(SourceError::ForeignBackend {
        requested: config.backend,
      });
    }
    // The spawn itself mints the RootMeta — canonical root, device, and the
    // mount seed are all finalized BEFORE the stream starts delivering, so
    // the metadata is a safe authority for every event on the queue; deriving
    // any of it here, after start, could postdate events already enqueued.
    let (handle, receiver, meta) = Source::spawn(config)?;
    Ok(SpawnedSource {
      handle,
      receiver,
      meta,
    })
  }

  fn probe(&self, path: &Path) -> ProbeOutcome {
    match std::fs::symlink_metadata(path) {
      Ok(meta) => {
        let file_type = meta.file_type();
        let kind = if file_type.is_dir() {
          tributary_proto::FileKind::Dir
        } else if file_type.is_file() {
          tributary_proto::FileKind::File
        } else if file_type.is_symlink() {
          tributary_proto::FileKind::Symlink
        } else {
          tributary_proto::FileKind::Other
        };
        let (file_id, dev) = inode_of(&meta);
        ProbeOutcome::Present { kind, file_id, dev }
      }
      Err(err) if err.kind() == std::io::ErrorKind::NotFound => ProbeOutcome::Missing,
      Err(_) => ProbeOutcome::Failed,
    }
  }

  fn write_cookie(&self, root: &Path, dir: &Path, name: &str) -> Result<PathBuf, std::io::Error> {
    // Resolve the cookie DIRECTORY, then CANONICALIZE it: `canonicalize` follows
    // every symlink in the path, so an ALREADY-EXISTING intermediate symlink
    // (`<root>/link/sub` where `link` targets outside) is resolved to where the
    // cookie would truly land — the lexical containment check upstream never sees
    // that, because component-wise the spelling still sits under the root.
    // Canonicalizing the root too makes the beneath test compare two paths from
    // the SAME resolver (identical prefix form on every platform). Both blocking
    // calls run on the driver's blocking pool, never the owner loop, so a hung
    // mount cannot wedge it. `canonicalize` requires the target to exist; a cookie
    // directory that is gone is already a typed write failure, so the valid case
    // is unchanged.
    let canonical_dir = std::fs::canonicalize(cookie_dir(root, dir))?;
    let canonical_root = std::fs::canonicalize(root)?;
    if !canonical_dir.starts_with(&canonical_root) {
      // The real directory escapes the watched root — its cookie's create event
      // could never reach this root's stream. Refuse before creating anything.
      return Err(std::io::Error::other(
        "the cookie directory resolves outside the watched root",
      ));
    }
    let path = canonical_dir.join(name);
    // create_new: a cookie name is minted unique (instance + pid + seq), so an
    // existing file at that path is a foreign artifact or a name collision —
    // never something to silently overwrite.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // O_NOFOLLOW on the FINAL component: a symlink swapped in where the cookie is
    // to land is refused (ELOOP) rather than followed to a target that could sit
    // outside the root, where its create event would never meet the barrier.
    // create_new (O_EXCL) already refuses an existing final symlink; O_NOFOLLOW
    // makes that refusal explicit and errno-honest.
    //
    // Canonicalizing the directory closes the PRE-EXISTING intermediate-symlink
    // escape (every intermediate link is resolved before the beneath check), and
    // O_NOFOLLOW + create_new guard the final component. RESIDUAL — a symlink
    // swapped INTO an intermediate directory AFTER `canonicalize` but BEFORE this
    // open (a genuine sub-microsecond TOCTOU) is still followable, because a
    // path-based open is not beneath-anchored. Closing that last window needs a
    // beneath-anchored traversal (Linux `openat2(RESOLVE_BENEATH |
    // RESOLVE_NO_SYMLINKS)`, or per-component `openat` with `O_NOFOLLOW` from a
    // pinned root-directory fd), which this crate does not yet thread a per-scope
    // root fd for. Only that post-canonicalize swap remains.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
      use std::os::unix::fs::OpenOptionsExt;
      options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(&path)?;
    Ok(path)
  }

  fn remove_cookie(&self, path: &Path) -> Result<(), std::io::Error> {
    match std::fs::remove_file(path) {
      // Idempotent by contract: an already-gone cookie is success.
      Ok(()) => Ok(()),
      Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
      // A transient failure (a hung mount, a flipped permission) is reported,
      // not swallowed, so the record survives for a later sweep to retry.
      Err(err) => Err(err),
    }
  }

  fn refresh_mounts(&self, root: &Path) -> MountRefresh {
    let (mounts, authoritative) = match crate::os::mounts_under(root) {
      Some(mounts) => (mounts, true),
      None => (Vec::new(), false),
    };
    // ONE sample proves liveness AND reads the mount frame: `root_liveness_and_frame`
    // is a single `statx` (symlink not followed, so a root retargeted to a symlink is
    // a replacement, not a follow), yielding the `(dev, ino)` the death gate decides
    // alive-vs-replaced on AND the frame the core adopts — from the SAME object. A
    // same-object re-mount keeps `(dev, ino)` (the death gate passes) but moves the
    // root to a new mount; adopting the frame from the identical sample keeps the
    // enumerate descent fence relative to that new mount without ever pairing the
    // identity verdict with a different object's frame (a replace/remount between two
    // separate lookups would). A `Missing` root is DeleteSelf, any other stat failure
    // is Unreadable (MoveSelf) — the exact `RootChanged`-probe mapping; the mount id
    // is inotify's best-effort belt (`None` below 5.8), taken from the same result's
    // mask.
    let (root_liveness, root_mnt_id) = root_liveness_and_frame(root);
    MountRefresh {
      mounts,
      authoritative,
      root: root_liveness,
      root_mnt_id,
    }
  }
  #[cfg(all(target_os = "linux", not(miri)))]
  fn attach_scope(&self, scope: ScopeId, port: ScopePort, generation: u64) {
    self
      .ports
      .write()
      .unwrap()
      .insert(scope, (generation, port));
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn detach_scope(&self, scope: ScopeId) {
    // Purge the port AND this scope's anchors under the anchors lock held
    // across both: a concurrent `batch_control` publishes an anchor only
    // while holding this same lock and only after re-confirming the port's
    // generation, so it cannot slip a fresh anchor in AFTER this purge (it
    // would find the generation already gone). Lock order everywhere is
    // anchors-then-ports.
    let mut anchors = self.anchors.lock().unwrap();
    self.ports.write().unwrap().remove(&scope);
    anchors.retain(|_, (anchor_scope, _)| *anchor_scope != scope);
  }

  // Arm/disarm route through the live source's control path (the reader owns
  // the fd and the wd table). A scope with no attached port — a
  // kernel-recursive source, or an arm racing its own stream teardown —
  // answers the honest typed refusal, never a silent success.
  #[cfg(all(target_os = "linux", not(miri)))]
  fn add_watch(
    &self,
    scope: ScopeId,
    watch: WatchId,
    parent: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    // A direct single arm runs against the CURRENT transport (the caller is
    // synchronous, not a leftover batch), so it adopts the attached
    // generation rather than one captured earlier.
    let generation = self.current_generation(scope);
    self
      .batch_control(
        scope,
        generation,
        vec![ControlRequest::Arm {
          watch,
          parent,
          name: name.clone(),
          path: Arc::new(path.to_path_buf()),
          expected,
        }],
      )
      .into_iter()
      .next()
      .map(|(_, outcome)| outcome)
      .unwrap_or(WatchOutcome::Failed(WatchError::Gone))
  }

  #[cfg(not(all(target_os = "linux", not(miri))))]
  fn add_watch(
    &self,
    _scope: ScopeId,
    _watch: WatchId,
    _parent: WatchId,
    _path: &Path,
    _name: &Segment,
    _expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    WatchOutcome::Failed(WatchError::Io)
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn remove_watch(&self, scope: ScopeId, watch: WatchId) {
    let generation = self.current_generation(scope);
    self.batch_control(scope, generation, vec![ControlRequest::Disarm { watch }]);
  }

  #[cfg(not(all(target_os = "linux", not(miri))))]
  fn remove_watch(&self, _scope: ScopeId, _watch: WatchId) {}

  // The batched arm path IS the real inotify arm path: even a single arm goes
  // through it, so anchor bookkeeping and the control envelope live in exactly
  // one place. The whole batch becomes ONE `Control::Batch` message, so a drain
  // cycle that produces N arms wakes the reader at most once.
  #[cfg(all(target_os = "linux", not(miri)))]
  fn batch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> Vec<(WatchId, WatchOutcome)> {
    use crate::os::linux::ControlOp;

    // GENERATION FRONT-CHECK: a batch whose generation no longer matches the
    // attached port is a leftover of a transport a replace has since
    // retired. Its arms must NOT install on the replacement's fd (they name
    // old-world paths), and its disarms are moot (their kernel watches died
    // with the old fd). The one live case that also lands here is a
    // kernel-recursive or teardown-racing scope with no descending port —
    // both refuse identically.
    let port = match self.ports.read().unwrap().get(&scope) {
      Some((attached, ScopePort::Inotify(port))) if *attached == generation => port.clone(),
      _ => {
        return requests
          .iter()
          .filter_map(|request| match request {
            ControlRequest::Arm { watch, .. } => {
              Some((*watch, WatchOutcome::Failed(WatchError::Gone)))
            }
            ControlRequest::Disarm { .. } => None,
          })
          .collect();
      }
    };

    // Build the control ops in emission order, remembering each arm's watch so
    // the reader's index-aligned replies map back to their outcomes. Disarms
    // drop the watch's transient anchor here (the reader issues the kernel
    // removal).
    let mut ops = Vec::with_capacity(requests.len());
    let mut arm_watches = Vec::new();
    for request in requests {
      match request {
        ControlRequest::Arm {
          watch,
          parent,
          name,
          path,
          expected,
        } => {
          ops.push(ControlOp::Arm(
            self.build_arm_request(watch, parent, &path, &name, expected),
          ));
          arm_watches.push(watch);
        }
        ControlRequest::Disarm { watch } => {
          self.anchors.lock().unwrap().remove(&watch);
          ops.push(ControlOp::Disarm(watch));
        }
      }
    }

    let replies = port.batch(ops);
    // Publish each arm's transient anchor (held until its cold enumerate
    // consumes it) under the anchors lock, re-confirming the generation still
    // matches WHILE holding it. A replace committing during `port.batch`
    // above swaps the port under a NEW generation; without this re-check a
    // late insert would resurrect an anchor `detach_scope` just purged. The
    // lock is held across the ports read so the check and the insert are
    // atomic against `detach_scope` (which purges under the same lock).
    let mut outcomes = Vec::with_capacity(arm_watches.len());
    let mut anchors = self.anchors.lock().unwrap();
    let still_current = self
      .ports
      .read()
      .unwrap()
      .get(&scope)
      .is_some_and(|(attached, _)| *attached == generation);
    for (watch, reply) in arm_watches.into_iter().zip(replies) {
      if let Some(anchor) = reply.anchor
        && still_current
      {
        anchors.insert(watch, (scope, anchor));
      }
      outcomes.push((watch, reply.outcome));
    }
    outcomes
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn preflight_arm(
    &self,
    port: &ScopePort,
    _scope: ScopeId,
    watch: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    use crate::os::linux::ControlOp;

    let ScopePort::Inotify(port) = port else {
      return WatchOutcome::Failed(WatchError::Gone);
    };
    let ops = vec![ControlOp::Arm(
      self.build_arm_request(watch, watch, path, name, expected),
    )];
    let Some(reply) = port.batch(ops).pop() else {
      return WatchOutcome::Failed(WatchError::Gone);
    };
    // The anchor is deliberately DROPPED, not stored: the commit's
    // detach_scope purges this scope's anchors wholesale, and a refused
    // commit would leave a stale anchor pointing into a torn-down transport.
    // The post-commit root enumerate falls back to path-based listing — a
    // new root renamed inside that window reads as the root dying right
    // after the swap, healed loudly by the refresh-cadence liveness check.
    reply.outcome
  }

  fn enumerate(&self, watch: WatchId, path: &Path) -> RawEnumerate {
    // Consume the watch's transient anchor when one is still held: the
    // listing then reads THROUGH the armed object (/proc re-opens an O_PATH
    // fd), immune to a rename between the arm and this read. The anchor
    // closes on scope exit either way — fd usage stays O(in-flight).
    #[cfg(all(target_os = "linux", not(miri)))]
    {
      use std::os::fd::AsRawFd;
      let anchor = self.anchors.lock().unwrap().remove(&watch);
      if let Some((_, anchor)) = anchor {
        let via = PathBuf::from(format!("/proc/self/fd/{}", anchor.as_raw_fd()));
        let listed = list_dir(&via);
        drop(anchor);
        return listed;
      }
    }
    let _ = watch;
    list_dir(path)
  }
}

/// All of one directory entry's stat facts — kind, device, inode, mount frame —
/// from a SINGLE path sample, symlink not followed. `None` is a raced-away entry
/// (the listing no longer reflects that name).
///
/// On Linux this is ONE [`stat_sample`]: every fact comes from that one result,
/// so a rename/bind toggling between two syscalls can never pair one object's
/// `(kind, dev, ino)` with another object's mount frame — the arm downstream
/// verifies `(dev, ino)` only, so a raced foreign bind that split the sample
/// could otherwise be classified descendable and armed. A `statx` mask miss (no
/// `STATX_MNT_ID` below 5.8) drops just the frame (`None`) and descent runs on the
/// device belt. Off Linux, one `symlink_metadata` (no mount-id notion; the core
/// fences on device alone) — still a single object's facts.
#[cfg(all(target_os = "linux", not(miri)))]
fn dir_entry_stat(entry_path: &Path) -> Option<(tributary_proto::FileKind, u64, u64, Option<u64>)> {
  let sample = stat_sample(entry_path).ok()?;
  Some((sample.kind, sample.dev, sample.ino, sample.frame))
}

#[cfg(not(all(target_os = "linux", not(miri))))]
fn dir_entry_stat(entry_path: &Path) -> Option<(tributary_proto::FileKind, u64, u64, Option<u64>)> {
  let meta = std::fs::symlink_metadata(entry_path).ok()?;
  Some((
    kind_of(&meta.file_type()),
    dev_of(&meta),
    ino_of(&meta),
    None,
  ))
}

/// One blocking readdir + a single per-entry stat sample, lowered to raw stat
/// facts (see [`dir_entry_stat`] for the one-sample discipline).
fn list_dir(path: &Path) -> RawEnumerate {
  let dir = match std::fs::read_dir(path) {
    Ok(dir) => dir,
    Err(err) => return RawEnumerate::Failed(io_class(&err)),
  };
  let mut entries = Vec::new();
  let mut complete = true;
  for entry in dir {
    let Ok(entry) = entry else {
      // The read was cut short mid-directory; what was seen still
      // reconciles, and the incomplete flag drives the Monitor's retry.
      complete = false;
      break;
    };
    let entry_path = entry.path();
    let Some((kind, dev, ino, mnt_id)) = dir_entry_stat(&entry_path) else {
      // A raced-away entry: the listing no longer reflects one name.
      complete = false;
      continue;
    };
    entries.push(RawDirEntry {
      name: entry.file_name().as_encoded_bytes().to_vec(),
      kind,
      dev,
      ino,
      mnt_id,
    });
  }
  RawEnumerate::Listed { entries, complete }
}

fn inode_of(meta: &std::fs::Metadata) -> (Option<std::num::NonZeroU64>, u64) {
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    (std::num::NonZeroU64::new(meta.ino()), meta.dev())
  }
  #[cfg(not(unix))]
  {
    let _ = meta;
    (None, 0)
  }
}

/// One blocking operation's result, shipped back to the select loop.
enum OpResult<H> {
  Spawned {
    scope: ScopeId,
    result: Result<SpawnedSource<H>, SourceError>,
  },
  Probed {
    probe: ProbeId,
    outcome: ProbeOutcome,
  },
  MountsRefreshed {
    scope: ScopeId,
    refresh: MountRefresh,
  },
  TornDown {
    scope: ScopeId,
  },
  WatchInstalled {
    watch: WatchId,
    outcome: WatchOutcome,
  },
  /// A descending replace's pre-arm resolved: the new root's kernel watch on
  /// the REPLACEMENT transport installed (or refused) while the old stream
  /// still owns the scope. Routed to the replace commit, never to the core's
  /// ordinary watch-result path.
  RebindArmed {
    scope: ScopeId,
    outcome: WatchOutcome,
  },
  Enumerated {
    req: ReqId,
    raw: RawEnumerate,
  },
  /// A dispatched physical cookie WRITE finished — success, refusal, or error.
  /// Sent exactly once per dispatched write, carrying only the incarnation it was
  /// dispatched for: every physical fact is already on that record, written by the
  /// job under the ledger lock. The driver's one job here is SCHEDULING — if the
  /// write's self-reap left the record parked as failed, stamp its retry deadline
  /// (the driver owns the clock).
  CookieWriteDone {
    id: CookieId,
  },
  /// A dispatched physical cookie UNLINK finished for incarnation `id`, which the
  /// job has already resolved on the record: `confirmed` = Ok / already gone (the
  /// record and its indexes are retired); `!confirmed` = transient failure (the
  /// record is parked `RemoveFailed`). As above, the driver only schedules — and a
  /// report whose incarnation has since been retired or re-armed touches nothing.
  CookieRemoveDone {
    id: CookieId,
    confirmed: bool,
  },
}

/// The earlier of two optional deadlines (the core's timer and the earliest due
/// cookie retry), in proto-`Instant` space.
fn min_instant(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
  match (a, b) {
    (Some(a), Some(b)) => Some(a.min(b)),
    (a, b) => a.or(b),
  }
}

/// Dispatches every cookie-unlink retry whose deadline is at or before `now`
/// (T8): one O(ledger) scan under the lock, then each due incarnation routed
/// through the phase machine, which preserves the record's attempt count toward
/// the budget and drops the deadline with the transition out of `RemoveFailed`.
/// A record retired between the scan and its dispatch is a no-op — the deadline
/// rides the record, so it can never fire against another incarnation.
fn dispatch_due_cookie_retries<R, F>(
  cookies: &CookieRegistry<F>,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  now: Instant,
) where
  R: RuntimeLite,
  F: FsOps,
{
  let due: Vec<CookieId> = {
    let inner = lock_ledger(&cookies.ledger);
    inner
      .obligations
      .values()
      .filter(|ob| matches!(ob.phase, Phase::RemoveFailed { retry_at: Some(at), .. } if at <= now))
      .map(|ob| ob.id)
      .collect()
  };
  for id in due {
    cookies.request_removal::<R>(op_tx, RemovalRequest::RetryDue(id));
  }
}

/// The driver's WHOLE reaction to the public cleanup ingress: one pass over the
/// reap marks, servicing every request that has landed since the last pass.
///
/// The wake that triggers this carries no request — it only says "some bit
/// changed" — so the sweep re-reads the marks rather than a queue, and requests
/// against one record naturally coalesce into one action. It costs one O(ledger)
/// pass, which the global cap bounds, and it is self-limiting (each action clears
/// the mark that caused it), so the biased select's arm order stays a valid
/// starvation fence.
///
/// Both halves take the marks as their whole selection, so neither needs to be
/// told which request arrived:
///
/// - the PHYSICAL half dispatches an unlink for every marked record that has a
///   file and no removal already in flight;
/// - the PRE-PHYSICAL half retires every marked record still PARKED on its settle
///   fence, answering its barrier `Retired` and abandoning the fence — so a sync
///   cancelled before its write was ever dispatched creates no file at all, which
///   is the same refusal its claim would have made, one phase earlier.
fn sweep_reap_requests<R, F>(
  cookies: &CookieRegistry<F>,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  parked_cookies: &mut BTreeMap<FenceId, ParkedCookie>,
  core: &mut DriverCore,
) where
  R: RuntimeLite,
  F: FsOps,
{
  cookies.sweep_reap_marks::<R>(op_tx);
  retire_parked_cookies(core, parked_cookies, cookies, &|ob, _| ob.reap_requested);
}

/// Handles a `CookieRemoveDone` (§2.3), identical in the live arm and the close
/// drain. The unlink's verdict already landed on the record, in the job that
/// performed it, so this only SCHEDULES: a transient failure left the record
/// parked `RemoveFailed`, and the driver — the sole owner of the clock — stamps
/// its backed-off retry deadline, or leaves it parked past the budget (no
/// schedule, zero CPU). A confirm has nothing left to do. `flat` uses the flat
/// base delay during the close drain (the 1 s grace bounds attempts there).
fn on_cookie_remove_done<F: FsOps>(
  cookies: &CookieRegistry<F>,
  config: &DriverConfig,
  id: CookieId,
  confirmed: bool,
  now: Instant,
  flat: bool,
) {
  if confirmed {
    return;
  }
  cookies.schedule_retry(config, id, now, flat);
}

/// Runs one watcher's driver loop until `commands` closes or a `Close`
/// command arrives. Consumes the command receiver and the event sender; the
/// sender dropping is the consumer's end-of-stream.
///
/// `cleanup` is this driver's half of the cookie-cleanup ingress
/// ([`cookie_ingress`]): the ledger it shares with the watcher handle, and the
/// coalescing wake the handle rings after marking one of this driver's own
/// obligations. There is no cleanup QUEUE — a public reap or cancel is a
/// transition on an already-counted record, so it can neither be refused nor
/// accrue, whatever the command traffic or the runtime's scheduling.
pub(crate) async fn run<R, F>(
  config: DriverConfig,
  ops: F,
  commands: async_channel::Receiver<Command>,
  cleanup: CookieWake,
  events: async_channel::Sender<(ScopeId, Arc<PathBuf>, Change)>,
  registry: impl ScopeRegistry,
) where
  R: RuntimeLite,
  F: FsOps,
{
  let CookieWake {
    ledger,
    wake: reap_wake,
  } = cleanup;
  let mut core = DriverCore::new(
    config.effective_move_window(),
    config.root_liveness_interval,
  );
  let origin = R::now();
  let now = move || Instant::from_origin(R::now().duration_since(origin));
  // Unbounded so the blocking pool reports results with a plain `try_send`
  // (`send_blocking` does not exist on wasm builds, where async-channel has no
  // blocking API); the op volume is already bounded by outstanding operations
  // — one spawn/teardown per root plus one probe per parked batch item.
  let (op_tx, op_rx) = async_channel::unbounded::<OpResult<F::Handle>>();
  // One lane per source: its single ordered queue, chased by a `None` end
  // marker — the receiver-disconnect fact itself, which a dropped sender
  // would otherwise erase silently.
  let mut os: SelectAll<
    futures_util::stream::BoxStream<'static, (ScopeId, u64, Option<SourceMessage>)>,
  > = SelectAll::new();
  // The guard keeps the SelectAll from ever emptying: an empty SelectAll
  // reports termination, which would spin the loop's stream arm.
  os.push(futures_util::stream::pending().boxed());
  let mut handles: BTreeMap<ScopeId, F::Handle> = BTreeMap::new();
  // Each spawned stream is one delivery LANE, tagged by a per-driver
  // generation: a scope's current lane is the one whose messages reach the
  // core. Today exactly one lane exists per scope for its whole life;
  // replace_root retires a lane and installs a successor under the SAME
  // scope, and a retired lane's stragglers are dropped here (dominated by
  // the replace commit's covering Rescan) — its end marker is not a death.
  let mut lanes: BTreeMap<ScopeId, u64> = BTreeMap::new();
  let mut next_lane: u64 = 0;
  // Blocking-pool work that owns — or is about to own — a native stream:
  // spawns dispatched but not yet returned, teardowns dispatched but not yet
  // confirmed. Close quiesces BOTH alongside the live handles: a spawn still
  // in flight can otherwise start a native source after the close reply, and
  // an unconfirmed teardown is a stream still winding down. Teardowns COUNT
  // rather than flag: a replace can have the retired lane's teardown in
  // flight while the scope is live on its successor, so one scope may owe
  // several confirmations.
  let mut pending_spawns: BTreeSet<ScopeId> = BTreeSet::new();
  let mut pending_teardowns: BTreeMap<ScopeId, usize> = BTreeMap::new();
  // In-flight root replacements, keyed by the (live) scope being widened:
  // the reservation parks here until the commit or failure releases it, and
  // the OpResult::Spawned router below diverts a replace-spawn's result away
  // from the birth path.
  let mut replace_states: BTreeMap<ScopeId, ReplaceState<F::Handle>> = BTreeMap::new();
  // Each live scope's committed backend — the commit-time profile gate: a
  // replacement whose spawn resolved to a different LOWERING PROFILE
  // (descending↔KR) is refused as BackendDiverged, because a live scope
  // never swaps lowering profiles.
  let mut scope_backends: BTreeMap<ScopeId, BackendKind> = BTreeMap::new();
  let mut watch_replies: BTreeMap<ScopeId, PendingWatch> = BTreeMap::new();
  // Descending-profile grants held between spawn success and the ROOT's
  // watch-result: the spawned source starts with no watches, so "live" — the
  // moment the public contract starts promising delivery — is the root arm,
  // not the fd. A grant here resolves at `WatchInstalled`, at stream
  // teardown (the scope died first), or by dropping at close (`Closed`).
  let mut deferred_grants: BTreeMap<ScopeId, DeferredGrant> = BTreeMap::new();
  // Awaited unwatch replies parked until the scope is fully quiescent, each
  // paired with the verdict to send then: `true` for a live scope this
  // unwatch tears down, `false` (UnknownRoot) for a scope whose root already
  // died while a replacement was still resolving — the reply still waits for
  // that replacement's teardown, but reports the scope gone. A `RootHandle`
  // is `Copy`, so ONE scope can accrue several awaited unwatches (a second
  // arriving before the first quiesces); every waiter is kept and resolved
  // together — dropping one would surface to its caller as `Closed`, which
  // the watcher reads as driver death and would wrongly clear the registry.
  let mut unwatch_replies: BTreeMap<ScopeId, Vec<(futures_channel::oneshot::Sender<bool>, bool)>> =
    BTreeMap::new();
  // Awaited set-cover acknowledgements parked under their settlement fences
  // (see `Command::SetCover`): resolved by `resolve_cover_settlements` at the
  // loop top once the scope's re-arm work quiesces, dropped at close (the
  // caller sees `Closed` through the dropped-reply mapping).
  let mut cover_replies: BTreeMap<FenceId, futures_channel::oneshot::Sender<CoverOutcome>> =
    BTreeMap::new();
  // Sync-cookie writes parked under the SAME settlement fences (see
  // `Command::SyncRoot`): the write dispatches to the blocking pool once the
  // scope's re-arm work quiesces, whatever the settle's verdict.
  let mut parked_cookies: BTreeMap<FenceId, ParkedCookie> = BTreeMap::new();
  // The OWNER of every cookie this driver writes, from its sync's ADMISSION —
  // before any file can exist — until that obligation earns a typed terminal, its
  // scope's stream tears down, or this local drops. Every gauge the cookie
  // lifecycle needs is a probe of this one ledger: the single-flight write gate,
  // the per-scope backlog, the global cap, the retry schedule, and the close
  // count. Ownership never rides the reply oneshot, so a caller that abandons its
  // sync cannot strand a file and no source-side removal queue is needed; the
  // orderly close sweeps owned cookies as tracked jobs, and the registry's `Drop`
  // reaps any remainder best-effort so a panicking or CANCELLED driver task still
  // cleans up.
  //
  // The ledger is the SHARED half of the cleanup ingress rather than this task's
  // private state: the watcher handle marks the records this registry admits, so
  // both are views on one store under one mutex — the same sharing shape the root
  // set has. It outlives this task inside the handle's `Arc`, which is inert: with
  // the driver gone, a mark lands on an empty ledger (the terminal sweep already
  // retired everything) and the wake `try_send` finds a closed channel.
  let mut cookies = CookieRegistry::new::<R>(ops.clone(), ledger);
  // Uncommitted watch grants unwind through here (see `WatchGrant`); the
  // driver keeps a sender so grants can always be minted, which is fine —
  // exit is driven by the COMMAND channel, and this receiver merely pends.
  let (unwind_tx, unwind_rx) = async_channel::unbounded::<ScopeId>();

  let close_reply = loop {
    execute_effects::<R, F>(
      &mut core,
      &ops,
      &config,
      &op_tx,
      &mut handles,
      &mut pending_spawns,
      &mut pending_teardowns,
      &mut scope_backends,
      &mut lanes,
      &events,
      &mut unwatch_replies,
      &mut deferred_grants,
      &mut cookies,
      &registry,
      &now,
    );

    // Service any cookie-unlink retries now due, opportunistically at the loop
    // top so a busy loop that never parks still drives them promptly (T8) — the
    // belt-and-suspenders the timer arm below shares.
    dispatch_due_cookie_retries::<R, F>(&cookies, &op_tx, now());

    // Fairness for the cleanup ingress: the select below is command-biased (it
    // polls `commands` before the wake), so a caller that keeps the bounded
    // command mailbox continuously ready would otherwise STARVE cleanup and leave
    // cookies lingering owned. Consuming a PENDING wake here, every iteration,
    // guarantees cleanup makes steady progress whatever the command load, while
    // preserving the command/close priority the biased select gives. Cheap by
    // construction: no wake pending means no request has landed since the last
    // sweep, so this is one non-blocking probe.
    if reap_wake.try_recv().is_ok() {
      sweep_reap_requests::<R, F>(&cookies, &op_tx, &mut parked_cookies, &mut core);
    }

    // Set-cover settlements resolve at this one choke point — after the
    // previous arm's results fed the core and their effects drained, BEFORE
    // any new command is processed — so a lossy settle's `applied_cover`
    // rewind always lands before the next reconcile computes its broadening
    // delta, and a teardown-folded `Degraded` is delivered promptly.
    resolve_cover_settlements::<R, F>(
      &mut core,
      &ops,
      &op_tx,
      &mut cover_replies,
      &mut parked_cookies,
      &mut cookies,
      &|scope| handles.contains_key(&scope),
    );
    // Reclaim canceled awaited-unwatch waiters at the same choke point, so an
    // issue-and-cancel storm against a stalled scope cannot grow its waiter
    // vector without bound.
    prune_canceled_unwatch_waiters(&mut unwatch_replies);

    // The one deadline arm serves BOTH the core's timer and the earliest due
    // cookie-unlink retry: an IDLE driver with one `RemoveFailed` cookie would
    // otherwise park forever and never retry (finding 3). Both live in proto-
    // `Instant` space; take their min, then convert once for `sleep_until`.
    let deadline = min_instant(core.poll_timeout(), cookies.min_retry_at())
      .map(|d| origin + d.elapsed_since_origin());
    let timer = async {
      match deadline {
        Some(at) => {
          R::sleep_until(at).await;
        }
        None => futures_util::future::pending::<()>().await,
      }
    }
    .fuse();
    futures_util::pin_mut!(timer);

    // Arm order is the starvation fence: INTERNAL, self-limiting inputs drain
    // before externally replenishable ones. Op results and grant unwinds are
    // completions of work this loop itself dispatched (bounded by what is
    // outstanding), and the core deadline only fires at instants the core armed
    // and re-arms strictly later — none can stay ready forever, so polling them
    // first cannot starve the later arms. The COMMAND channel can: a saturated,
    // continuously-refilled mailbox keeps a command-first order permanently
    // ready, so arm/enumerate completions are never consumed, scopes never
    // settle, and every reconciled SetCover appends fence + reply state without
    // bound. Commands still outrank the source-event stream (the one order that
    // is load-bearing the other way): events are budget-backpressured but
    // effectively endless, and Close arrives on the command channel.
    futures_util::select_biased! {
      res = op_rx.recv().fuse() => {
        match res.expect("the driver holds a sender") {
          OpResult::Spawned { scope, result } => {
            pending_spawns.remove(&scope);
            if replace_states.contains_key(&scope) {
              let spawned = match result {
                Ok(spawned) => spawned,
                Err(err) => {
                  let replace = replace_states.remove(&scope).expect("just checked");
                  drop(replace.reservation);
                  let _ = replace
                    .reply
                    .send(Err(crate::error::ReplaceRootError::Source(err)));
                  // A failed replacement spawn is the one resolution that
                  // enqueues NO teardown (there is nothing to retire), so a
                  // concurrent unwatch waiting on this scope would never be
                  // re-checked by a TornDown — resolve it here if the failed
                  // spawn was the last obligation. Every other resolution
                  // ends in a counted teardown whose TornDown re-checks.
                  if scope_quiesced(
                    scope,
                    &handles,
                    &pending_spawns,
                    &pending_teardowns,
                    &replace_states,
                  ) {
                    resolve_unwatch_waiters(&mut unwatch_replies, scope);
                  }
                  continue;
                }
              };
              // Death wins, and a live scope never swaps lowering profiles —
              // both refusals land BEFORE any commit or pre-arm.
              let backend = spawned.meta.backend;
              let old_kr = scope_backends
                .get(&scope)
                .is_some_and(BackendKind::is_kernel_recursive);
              let refusal = if !handles.contains_key(&scope) {
                Some(crate::error::ReplaceRootError::Retired)
              } else if old_kr != backend.is_kernel_recursive() {
                Some(crate::error::ReplaceRootError::BackendDiverged)
              } else {
                None
              };
              if let Some(err) = refusal {
                let replace = replace_states.remove(&scope).expect("just checked");
                retire_refused::<R, F>(&op_tx, &mut pending_teardowns, scope, spawned);
                drop(replace.reservation);
                let _ = replace.reply.send(Err(err));
                continue;
              }
              if backend.is_kernel_recursive() {
                let replace = replace_states.remove(&scope).expect("just checked");
                let widened = spawned.meta.root.clone();
                let outcome = commit_replace::<R, F>(
                  &mut core,
                  &ops,
                  &op_tx,
                  &mut handles,
                  &mut lanes,
                  &mut next_lane,
                  &mut pending_teardowns,
                  &mut os,
                  &registry,
                  &cookies,
                  scope,
                  spawned,
                  replace.reservation.path(),
                  None,
                  &now,
                );
                if let Ok(backend) = &outcome {
                  scope_backends.insert(scope, *backend);
                  // Any barrier still parked under coverage the new root has
                  // moved out from under is revoked BEFORE the commit records the
                  // new root; the generation that revokes writes already in the
                  // pool under the old root was bumped inside `commit_replace`, at
                  // the lane swap. This only RE-records the cookie floor for the
                  // widened root.
                  revoke_uncovered_parked_cookies(&mut core, &mut parked_cookies, &cookies, scope, &widened);
                  cookies.scope_live(scope, widened);
                }
                // The reservation releases HERE — commit or failure alike —
                // after the registry overwrite (commit) has already made the
                // new coverage visible, so the path is covered continuously.
                drop(replace.reservation);
                let _ = replace.reply.send(outcome.map(|_| ()));
                continue;
              }
              // Descending: arm the new root on the NEW transport first; the
              // commit (or unwind) rides the outcome. The scope's port table
              // still routes to the OLD stream, so the arm goes through the
              // explicit-port seam.
              let Some(watch) = core.root_watch(scope) else {
                // The handle map says live but the core disagrees — refuse
                // without committing anything.
                let replace = replace_states.remove(&scope).expect("just checked");
                retire_refused::<R, F>(&op_tx, &mut pending_teardowns, scope, spawned);
                drop(replace.reservation);
                let _ = replace
                  .reply
                  .send(Err(crate::error::ReplaceRootError::Retired));
                continue;
              };
              let port = spawned.handle.scope_port();
              let path = spawned.meta.root.clone();
              // The same object confirmation the birth root arm carries: the
              // spawn barrier read the identity; the arm confirms the opened
              // object still is it.
              let name = Segment::new(
                path
                  .file_name()
                  .and_then(|name| name.to_str())
                  .unwrap_or("/"),
              );
              let expected = u64::try_from(spawned.meta.identity.ino())
                .ok()
                .and_then(core::num::NonZeroU64::new)
                .map(|ino| ExpectedObject {
                  dev: spawned.meta.identity.dev(),
                  ino,
                });
              replace_states
                .get_mut(&scope)
                .expect("just checked")
                .arming = Some(spawned);
              let ops_for_arm = ops.clone();
              let tx = op_tx.clone();
              R::spawn_blocking_detach(move || {
                let outcome =
                  ops_for_arm.preflight_arm(&port, scope, watch, &path, &name, expected);
                let _ = tx.try_send(OpResult::RebindArmed { scope, outcome });
              });
              continue;
            }
            match result {
            Ok(spawned) => {
              let canonical_root = spawned.meta.root.clone();
              let identity = spawned.meta.identity;
              let ancestors = spawned.meta.ancestors.clone();
              let backend = spawned.meta.backend;
              let pending = watch_replies.remove(&scope);
              // FINAL-ROOT REVALIDATION: the backend re-canonicalizes during
              // spawn, so the root the stream actually watches can differ
              // from the path the watcher reserved (a symlink retargeted, a
              // directory replaced mid-flight). The reservation vouched only
              // for the form it held; this check — on the registry's single
              // writer, immediately before the scope would go live — is the
              // authority on the final root's disjointness, and it compares
              // object identities so a spelling alias cannot slip past it.
              if let Some(existing) = registry.final_root_conflict(
                &canonical_root,
                identity,
                &ancestors,
                pending.as_ref().map(|p| p.requested.as_path()),
                None,
              ) {
                // Never goes live: tear the fresh stream down inside the
                // pending accounting and end the scope like a failed spawn.
                *pending_teardowns.entry(scope).or_insert(0) += 1;
                let tx = op_tx.clone();
                let handle = spawned.handle;
                R::spawn_blocking_detach(move || {
                  handle.shutdown();
                  let _ = tx.try_send(OpResult::TornDown { scope });
                });
                core.on_spawn_rejected(scope);
                if let Some(pending) = pending {
                  let _ = pending.reply.send(Err(WatchRootError::Overlaps {
                    path: canonical_root,
                    existing,
                  }));
                }
              } else {
                core.on_stream_spawned(scope, Ok(spawned.meta));
                // Mint the transport generation (the delivery lane) FIRST so
                // the port attaches under it: the descending root's first
                // AddWatch is dispatched carrying this same generation.
                let lane = next_lane;
                next_lane += 1;
                lanes.insert(scope, lane);
                // The arm/disarm port attaches before any effect of this
                // spawn can execute, so a descending root's first AddWatch
                // always finds its scope routed under the current generation.
                ops.attach_scope(scope, spawned.handle.scope_port(), lane);
                // The live stats handle (fanotify only) is captured before the
                // handle is stored, so the registry can hand a `backend_stats`
                // query the same counters the reader writes.
                let stats = spawned.handle.backend_stats();
                handles.insert(scope, spawned.handle);
                os.push(
                  spawned
                    .receiver
                    .map(move |msg| (scope, lane, Some(msg)))
                    .chain(futures_util::stream::once(async move {
                      (scope, lane, None)
                    }))
                    .boxed(),
                );
                // The registry learns the scope is live BEFORE the grant can
                // reach the watcher: both registry transitions then execute on
                // this task in program order, so a death signal processed
                // later can never be overtaken by this insert — the
                // insert-after-remove race has no actors left to run it. A
                // scope dying before the caller polls its grant simply yields
                // a dead-on-arrival handle.
                registry.scope_live(scope, &canonical_root, identity, &ancestors, backend, stats);
                scope_backends.insert(scope, backend);
                // The cookie floor travels with the stream: a sync for this
                // scope may write inside this root, never above it.
                cookies.scope_live(scope, canonical_root.clone());
                match backend {
                  // Descending: the stream is live but covers NOTHING until
                  // the root's kernel watch arms; the grant defers to the
                  // root's watch-result so the public "from resolve, every
                  // change is delivered" bracket holds.
                  BackendKind::Inotify => {
                    if let Some(pending) = pending {
                      deferred_grants.insert(scope, DeferredGrant {
                        pending,
                        root: canonical_root,
                      });
                    } else {
                      // The watch() future was already cancelled: immediate
                      // unwatch, exactly like a refused inline grant.
                      core.on_unwatch(scope);
                    }
                  }
                  // Kernel-recursive: the live stream IS the coverage, so the
                  // grant commits inline. fanotify's superblock mark and the
                  // Windows primitives' subtree streams cover the whole root
                  // exactly like FSEvents.
                  BackendKind::FsEvents
                  | BackendKind::Fanotify
                  | BackendKind::Rdcw
                  | BackendKind::UsnJournal => {
                    let owned = match pending {
                      Some(pending) => {
                        commit_grant(pending, scope, canonical_root, &unwind_tx)
                      }
                      None => false,
                    };
                    if !owned {
                      // The watch() future was cancelled before the reply
                      // could hand ownership over: tear the just-spawned
                      // stream down as an immediate unwatch. (Cancellation
                      // AFTER a successful send is the grant's unwind.)
                      core.on_unwatch(scope);
                    }
                  }
                }
              }
            }
            Err(err) => {
              core.on_stream_spawned(scope, Err(clone_error(&err)));
              if let Some(pending) = watch_replies.remove(&scope) {
                // A spawn-side kind rejection keeps the public contract's
                // vocabulary: the caller asked to watch a directory and the
                // final root is not one.
                let reply = match err {
                  SourceError::NotADirectory { root } => {
                    WatchRootError::NotADirectory { path: root }
                  }
                  err => WatchRootError::Source(err),
                };
                let _ = pending.reply.send(Err(reply));
              }
            }
          }},
          OpResult::Probed { probe, outcome } => core.on_probe_result(probe, outcome, now()),
          OpResult::MountsRefreshed { scope, refresh } => {
            core.on_mounts_refreshed(scope, refresh, now())
          }
          OpResult::WatchInstalled { watch, outcome } => {
          // A deferred registration grant riding on this arm resolves FIRST,
          // so a failed root arm answers the caller before the core's
          // teardown effects run (which would otherwise answer it again). A
          // deferred scope has no children yet (nothing enumerates before
          // the root is live), so any arm landing on it IS the root's.
          let deferred_scope = core
            .scope_of_watch(watch)
            .filter(|scope| deferred_grants.contains_key(scope));
          if let Some(scope) = deferred_scope {
            let DeferredGrant { pending, root } =
              deferred_grants.remove(&scope).expect("scope found above");
            match outcome {
              WatchOutcome::Installed(_) | WatchOutcome::Aliased(_) => {
                if !commit_grant(pending, scope, root, &unwind_tx) {
                  core.on_unwatch(scope);
                }
              }
              WatchOutcome::Failed(err) => {
                let _ = pending.reply.send(Err(arm_grant_error(err, pending.requested, root)));
              }
            }
          }
          core.on_watch_installed(watch, outcome);
        }
        OpResult::RebindArmed { scope, outcome } => {
          let Some(mut replace) = replace_states.remove(&scope) else {
            // Swept by close (its stream already retired) or never ours.
            continue;
          };
          let Some(spawned) = replace.arming.take() else {
            drop(replace.reservation);
            continue;
          };
          let widened = spawned.meta.root.clone();
          let outcome = if !handles.contains_key(&scope) {
            // Death wins: the scope ended while the pre-arm was in flight.
            retire_refused::<R, F>(&op_tx, &mut pending_teardowns, scope, spawned);
            Err(crate::error::ReplaceRootError::Retired)
          } else if let WatchOutcome::Failed(err) = outcome {
            // The new transport could not cover the new root: unwind, the
            // old coverage untouched.
            let root = spawned.meta.root.clone();
            retire_refused::<R, F>(&op_tx, &mut pending_teardowns, scope, spawned);
            Err(crate::error::ReplaceRootError::Source(
              SourceError::RootUnavailable {
                root,
                source: arm_failure(err),
              },
            ))
          } else {
            commit_replace::<R, F>(
              &mut core,
              &ops,
              &op_tx,
              &mut handles,
              &mut lanes,
              &mut next_lane,
              &mut pending_teardowns,
              &mut os,
              &registry,
              &cookies,
              scope,
              spawned,
              replace.reservation.path(),
              Some(outcome),
              &now,
            )
          };
          if let Ok(backend) = &outcome {
            scope_backends.insert(scope, *backend);
            // The cookie floor follows the committed root (see the kernel-
            // recursive commit above); the generation that revokes in-flight
            // writes under the old root was already bumped inside `commit_replace`
            // at the lane swap. Parked barriers the new root no longer covers are
            // revoked first.
            revoke_uncovered_parked_cookies(&mut core, &mut parked_cookies, &cookies, scope, &widened);
            cookies.scope_live(scope, widened);
          }
          drop(replace.reservation);
          let _ = replace.reply.send(outcome.map(|_| ()));
        }
        OpResult::Enumerated { req, raw } => {
          core.on_enumerated(req, raw);
        }
        OpResult::TornDown { scope } => {
            if let Some(owed) = pending_teardowns.get_mut(&scope) {
              *owed -= 1;
              if *owed == 0 {
                pending_teardowns.remove(&scope);
              }
            }
            // The unwatch fence is per-scope QUIESCENCE across EVERY native
            // obligation — a straggler teardown, a replacement still
            // spawning or pre-arming, or a committed handle — not merely the
            // one stream this TornDown retired.
            if scope_quiesced(
              scope,
              &handles,
              &pending_spawns,
              &pending_teardowns,
              &replace_states,
            ) {
              resolve_unwatch_waiters(&mut unwatch_replies, scope);
            }
          }
        OpResult::CookieWriteDone { id } => {
          // The write already wrote its own verdict to its record: nothing to
          // reopen (the gate is the phase) and nothing to sweep (a reap mark dies
          // with the record it marks). If a self-reap's unlink FAILED, the record
          // is parked `RemoveFailed` — schedule its retry.
          cookies.schedule_retry(&config, id, now(), false);
        }
        OpResult::CookieRemoveDone { id, confirmed } => {
          on_cookie_remove_done(&cookies, &config, id, confirmed, now(), false);
        }
        }
      },
      unwound = unwind_rx.recv().fuse() => {
        // An uncommitted grant dropped (a watch() future cancelled after its
        // reply was sent but before it was polled): unwind through the
        // normal unwatch path so the stream, the registry, and the core all
        // reconcile.
        if let Ok(scope) = unwound {
          core.on_unwatch(scope);
        }
      },
      _ = timer => {
        core.on_timeout(now());
        // The one wake also services due cookie retries (T8); firing both is
        // harmless — `on_timeout` before its deadline just re-arms, and a retry
        // pass with nothing due is a no-op.
        dispatch_due_cookie_retries::<R, F>(&cookies, &op_tx, now());
      },
      cmd = commands.recv().fuse() => match cmd {
        Ok(Command::Watch { root, interest, reply }) => {
          let requested = root.clone();
          let scope = core.on_watch(root, interest, config.profile);
          watch_replies.insert(scope, PendingWatch { requested, reply });
        }
        Ok(Command::Replace {
          scope,
          root,
          reservation,
          reply,
        }) => {
          if !handles.contains_key(&scope) {
            let _ = reply.send(Err(crate::error::ReplaceRootError::UnknownRoot));
          } else {
            match replace_states.entry(scope) {
              std::collections::btree_map::Entry::Occupied(_) => {
                let _ = reply.send(Err(crate::error::ReplaceRootError::ReplaceInFlight));
              }
              std::collections::btree_map::Entry::Vacant(slot) => {
                // Dispatch the replacement spawn through the SAME blocking-pool
                // accounting a birth spawn uses; the Spawned router diverts the
                // result to the commit tail by the replace_states key.
                pending_spawns.insert(scope);
                let mut source_config = SourceConfig::new(vec![root]);
                // The swap window rides the journal, not just the covering
                // Rescan: the RETIRING stream's resume point is taken here —
                // the one moment it is provably still live (the branch above
                // proved the handle) — and handed to the replacement's spawn,
                // which replays from it. Taking it EARLY only widens the
                // replay (an earlier id replays more), and duplicates are
                // always legal; a backend with no journal, a wrapped id
                // space, or a foreign device simply mints/honors nothing and
                // the `Rescan` covers the window as before.
                source_config.since = handles.get(&scope).and_then(SourceControl::resume_token);
                source_config.exclusions = config.exclusions.clone();
                source_config.latency = config.latency;
                source_config.channel_capacity = config.os_batch_capacity;
                source_config.backend = config.backend;
                source_config.max_map_directories = config.max_map_directories;
                let ops_for_spawn = ops.clone();
                let tx = op_tx.clone();
                R::spawn_blocking_detach(move || {
                  let result = ops_for_spawn.spawn_source(source_config);
                  let _ = tx.try_send(OpResult::Spawned { scope, result });
                });
                slot.insert(ReplaceState {
                  reservation,
                  reply,
                  arming: None,
                });
              }
            }
          }
        }
        Ok(Command::Unwatch { scope, reply }) => {
          if handles.contains_key(&scope) || watch_replies.contains_key(&scope) {
            // A live scope: the awaited form records its waiter (answered at
            // quiescence with `true`); the reply-less `request_unwatch` tears
            // down identically but registers none. Waiters ACCUMULATE — a
            // duplicate unwatch of the same handle joins the queue, never
            // evicts an earlier waiter.
            if let Some(reply) = reply {
              unwatch_replies
                .entry(scope)
                .or_default()
                .push((reply, true));
            }
            core.on_unwatch(scope);
          } else if pending_spawns.contains(&scope)
            || pending_teardowns.contains_key(&scope)
            || replace_states.contains_key(&scope)
          {
            // The live handle already died (root death / fatal) but the scope
            // is NOT yet quiescent — a replacement is still spawning or
            // pre-arming, or a teardown is still draining. The death path
            // already tore the original stream down and a replacement resolves
            // to `Retired` and is torn down; there is nothing more to trigger.
            // Park the reply for quiescence rather than reporting the scope
            // gone while a native stream is still coming up, and answer
            // UnknownRoot (`false`) — the root died. Waiters accumulate here
            // too (a duplicate must not evict an earlier one).
            if let Some(reply) = reply {
              unwatch_replies
                .entry(scope)
                .or_default()
                .push((reply, false));
            }
          } else if let Some(reply) = reply {
            // Genuinely unknown: never watched, or already fully quiesced.
            let _ = reply.send(false);
          }
        }
        Ok(Command::SetCover { scope, retained, reply }) => {
          // In-place bidirectional coverage reconcile. The core is the authority on whether
          // a reconcile ran: every refusal — unknown scope, not yet publicly live,
          // kernel-recursive profile, refused cover — comes back as a typed `Noop` and is
          // acknowledged IMMEDIATELY, never fenced. A reconcile that RAN parks its reply
          // under a fence opened right here, before any other core input, so the fence
          // inherits exactly this reconcile's window (a born-lossy coalesced grow
          // included); the loop-top `resolve_cover_settlements` answers it once the
          // scope's re-arm work quiesces. A reply-less reconcile (`request_set_cover`)
          // opens no fence — its window still feeds the settlement bookkeeping,
          // unacknowledged.
          match core.on_set_cover(scope, &retained) {
            CoverReconcile::Reconciling => {
              if let Some(reply) = reply {
                let fence = core.open_cover_fence(scope);
                cover_replies.insert(fence, reply);
              }
            }
            CoverReconcile::Noop(reason) => {
              if let Some(reply) = reply {
                let _ = reply.send(noop_outcome(reason));
              }
            }
          }
        }
        Ok(Command::SyncRoot {
          scope,
          dir,
          name,
          reply,
        }) => {
          // The scope's canonical root, only for a live scope — the FLOOR the
          // cookie directory must stay within and a proof the scope exists.
          let live_root = handles
            .contains_key(&scope)
            .then(|| cookies.root_of(scope).map(Path::to_path_buf))
            .flatten();
          match live_root {
            None => {
              let _ = reply.send(Err(crate::error::SyncRootError::UnknownRoot));
            }
            Some(root) => {
              // The cookie NAME is one normal component (the umbrella mints
              // `.tributaries-sync-…`); a separator, `..`, or absolute name is a
              // contract violation refused before it can escape on a join. The
              // DIRECTORY must lie within the root once `.`/`..` are folded — the
              // containment a plain `starts_with` misses for `<root>/../out`.
              if !is_normal_cookie_name(&name) {
                let _ = reply.send(Err(crate::error::SyncRootError::BadCookieName { name }));
              } else if !cookie_dir_within_root(&root, &dir) {
                let _ = reply.send(Err(crate::error::SyncRootError::DirOutsideRoot { dir, root }));
              } else if cookies.has_pending_write(scope) {
                // Single-flight per scope: refuse a second sync while one for
                // this scope is anywhere in the pipeline — still PARKED on its
                // settle fence, or its write DISPATCHED (an `InPool` obligation).
                // At most one physical write per scope can then be outstanding, so
                // a caller that times out and retries cannot pile unbounded
                // blocking writes against a hung mount. ONE O(cap) probe over the
                // one ledger, because both stages are one record there.
                let _ = reply.send(Err(crate::error::SyncRootError::WriteInFlight));
              } else if cookies.unremoved_for(scope) >= config.cookie_backlog_cap
                || cookies.unremoved() >= config.cookie_global_cap
              {
                // The memory bound (§4.3), per-scope AND WHOLE-LIFECYCLE global:
                // too many unremoved cookies for this scope, OR too many total
                // admitted-but-unconfirmed cookie obligations watcher-wide. The
                // global gauge Φ = `unremoved()` is ONE term over ONE store: every
                // lifecycle stage from admission on is exactly one ledger record —
                // a sync parked on its fence, a write in the pool, an owned cookie,
                // an unconfirmed removal — so there is nothing to dedup and no
                // second gauge that could drift. Admission increments Φ by exactly
                // one only under Φ < cap, and no other event increases it, so
                // Φ ≤ cap at every point (§4.3): the ledger is bounded by a FLAT
                // cap, blocking cookie-write jobs in flight ≤ Φ ≤ cap (the
                // pool-exhaustion attack is capped watcher-wide), and a
                // sync→fail→unwatch→rewatch churn cannot grow the ledger past it.
                // Refuse retryably — the cleanup owner keeps retrying, and on a
                // recovered fs the backlog drains and syncs resume with no operator
                // action.
                //
                // Kick recovery before refusing: re-arm a bounded batch of PARKED
                // (budget-spent, unscheduled) records. A parked record on a
                // RETIRED scope has no live scope to sweep it and no timer to
                // retry it, so without this a since-recovered fs would never drain
                // the backlog and the cap could refuse every future sync forever.
                // The re-armed records confirm on a recovered fs (freeing the cap
                // for a later sync) or re-park on a still-failing one — bounded work.
                cookies.rearm_parked_batch::<R>(&op_tx, scope, config.cookie_backlog_cap);
                let _ = reply.send(Err(crate::error::SyncRootError::CleanupBacklog));
              } else {
                // ADMITTED — and admission is BIRTH. Every refusal above has
                // passed, so this sync becomes an obligation right here, before its
                // caller can hold any address for it: from this line the global cap
                // counts it, the single-flight gate stands on it, a cancel naming
                // it has a record to mark, and the close reply cannot miss it. A
                // REFUSED admission creates nothing at all — the reason a hostile
                // flood of refused syncs cannot mint state.
                //
                // The write parks on a settle fence opened right here — the same
                // fence a reconcile's ack rides, so it inherits this moment's
                // window. A kernel-recursive scope has no re-arm work, so the
                // fence settles at the very next loop-top poll and the write
                // dispatches immediately; a descending scope waits for its
                // in-flight re-arms to quiesce, which is precisely the ordering
                // the barrier needs.
                let fence = core.open_cover_fence(scope);
                cookies.admit_parked(scope, name, fence);
                // The routing half: which caller this fence answers, and where its
                // cookie is to be written. Inserted in the same step as the record
                // it belongs to, and removed in the same step it leaves `Parked` —
                // the lockstep that keeps this local from ever being a second
                // opinion about which syncs are parked.
                parked_cookies.insert(fence, ParkedCookie { dir, reply });
              }
            }
          }
        }
        Ok(Command::Close { reply }) => break Some(reply),
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugLaneCount { reply }) => {
          let _ = reply.send(lanes.len());
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugCookieCount { reply }) => {
          let _ = reply.send(cookies.len());
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugUnwatchWaiters { scope, reply }) => {
          let _ = reply.send(unwatch_replies.get(&scope).map_or(0, Vec::len));
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugCookieReapMarks { reply }) => {
          let _ = reply.send(cookies.reap_marks());
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugCookieParkedFor { scope, reply }) => {
          let _ = reply.send(cookies.parked_for(scope));
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugCookieCensus { reply }) => {
          let _ = reply.send(cookies.census());
        }
        // The watcher facade dropped: same orderly teardown, nobody to tell.
        Err(_) => break None,
      },
      // The cookie-cleanup wake, ranked below `commands` so it can never starve a
      // Close, and above the source stream. It cannot drop a request whatever the
      // command load: the request is already ON its record before this fires, and
      // this only says one has landed. A closed wake leaves this inert: the
      // watcher drops the wake and the command sender together, so `commands`
      // (higher-priority) fires its `break None` first — this arm is never
      // selected on the way out, and the terminal sweep below owns every record
      // regardless of any mark.
      wake = reap_wake.recv().fuse() => {
        if wake.is_ok() {
          sweep_reap_requests::<R, F>(&cookies, &op_tx, &mut parked_cookies, &mut core);
        }
      },
      msg = os.next() => {
        if let Some((scope, lane, msg)) = msg {
          // A retired lane's stragglers are dropped whole: the replace
          // commit's covering Rescan dominates them, and the retired end
          // marker is a teardown artifact, never a death. (Today every
          // scope has exactly one lane for its whole life, so this gate
          // never fires — pinned by the existing suites.)
          if lanes.get(&scope) != Some(&lane) {
            continue;
          }
          match msg {
            // The payload travels whole: its budget slot is released by the
            // core exactly when the batch settles or is discarded, so parked
            // events stay inside the transport budget.
            Some(SourceMessage::Batch(payload)) => core.on_batch(scope, payload, now()),
            // The queue is the source's ONE ordered lane, so everything the
            // signal postdates was already handled above it — no drain, no
            // barrier, nothing to reason about. Dropping the ack BEFORE
            // acting re-arms the dedup: a loss racing it either rides a
            // fresh message or is covered by the rescan this becomes.
            Some(SourceMessage::Overflow(ack)) => {
              drop(ack);
              core.on_root_overflow(scope, now());
            }
            Some(SourceMessage::Fatal(_)) => core.on_source_fatal(scope, now()),
            // The receiver disconnected while the stream should still be
            // live: the source died without managing to say so (its sender
            // dropped) — a dead stream, not a teardown of ours (that path
            // removes the handle before the disconnect can arrive). The end
            // marker fires only after the queue yielded everything it held.
            None => {
              if handles.contains_key(&scope) {
                core.on_source_fatal(scope, now());
              }
            }
          }
        }
      },
    }
  };

  // Orderly shutdown: quiesce every stream — the live handles AND the
  // blocking-pool work still capable of producing one (`pending_spawns`,
  // `pending_teardowns`) — then drain what already arrived and deliver what
  // fits. The final event drain is documented best-effort (loss and death
  // signals are in-band messages, so anything undrained here is part of that
  // same best-effort remainder). Uncommitted grants racing this close need no
  // unwind processing: their scopes were either swept here (live handle) or
  // settle below as late spawns; the unread unwind message dies with its
  // channel.
  for (scope, handle) in std::mem::take(&mut handles) {
    registry.scope_dead(scope);
    *pending_teardowns.entry(scope).or_insert(0) += 1;
    let tx = op_tx.clone();
    R::spawn_blocking_detach(move || {
      handle.shutdown();
      let _ = tx.try_send(OpResult::TornDown { scope });
    });
  }
  // A descending replace's pre-arm holds a spawned-but-uncommitted stream
  // the maps above no longer cover: retire it inside the same accounting.
  // Drain `replace_states` whole so the scope-quiescence fence below no
  // longer counts these as outstanding replace obligations; each entry's
  // reservation and reply drop here — the caller sees `Closed`.
  for (scope, mut replace) in std::mem::take(&mut replace_states) {
    if let Some(spawned) = replace.arming.take() {
      *pending_teardowns.entry(scope).or_insert(0) += 1;
      let tx = op_tx.clone();
      R::spawn_blocking_detach(move || {
        spawned.handle.shutdown();
        let _ = tx.try_send(OpResult::TornDown { scope });
      });
    }
  }
  // Route every cookie the registry owns through the removal state machine
  // BEFORE the grace, so a hung unlink makes close report `NotQuiesced` honestly
  // rather than wedging — never a synchronous unlink in the registry's `Drop`.
  // Raise the shutdown flag first: a write still in the pool then finds its
  // claim refused and self-reaps rather than landing a cookie owned but unswept
  // behind this sweep. A straggler write's FAILED self-reap landing mid-drain
  // re-inserts a `RemoveFailed` record — the live-ledger drain condition below
  // cannot miss it (finding 4, closed structurally rather than by counting).
  cookies.begin_shutdown();
  cookies.sweep_owned::<R>(&op_tx);
  // A sync still PARKED at close never had a write dispatched, so there is nothing
  // to sweep for it and nothing to wait on: it reaches the pre-physical terminal
  // here, its caller answered `Retired` rather than left to read a bare `Closed`.
  // Retiring them BEFORE the drain is what keeps the drain's ledger-quiescence
  // condition honest — a pre-physical obligation nothing will ever complete must
  // not hold close open for the grace, nor be reported as a non-quiesced cookie.
  retire_parked_cookies(&mut core, &mut parked_cookies, &cookies, &|_, _| true);
  // The sweep re-armed every `Owned`/parked record (dispatched now); a record
  // still mid-backoff was coalesced and keeps its far retry deadline, which the
  // ~1 s grace could outrun — close would then report `NotQuiesced` where a
  // prompt retry inside the grace would have confirmed. Pull every remaining
  // deadline forward to one base delay so the drain's retry arm services it in
  // time (the design's flat-base-during-close intent); a still-failing unlink
  // still ends `NotQuiesced`, only never spuriously.
  cookies.pull_retries_forward(now() + config.cookie_retry_base);
  let drain = async {
    loop {
      // The LIVE-ledger quiescence condition: every cookie obligation — a write
      // still in the pool, an owned cookie, an unconfirmed removal — is one record
      // in the one ledger, so the drain cannot exit while any stands. A post-sweep
      // straggler is impossible to miss: its record was born before its write
      // could create anything, and only a typed terminal removes it.
      if pending_teardowns.is_empty() && pending_spawns.is_empty() && cookies.unremoved() == 0 {
        break;
      }
      futures_util::select_biased! {
        res = op_rx.recv().fuse() => match res {
          Ok(OpResult::TornDown { scope }) => {
            if let Some(owed) = pending_teardowns.get_mut(&scope) {
              *owed -= 1;
              if *owed == 0 {
                pending_teardowns.remove(&scope);
              }
            }
            // The same per-scope quiescence fence as the live arm. Close has
            // already drained `handles` and `replace_states` (both provably
            // empty here), and referencing the non-`Sync` handle map inside
            // this future would poison its `Send`ness — so the fence reduces to
            // the two obligations that can still be outstanding in the drain.
            if !pending_spawns.contains(&scope) && !pending_teardowns.contains_key(&scope) {
              resolve_unwatch_waiters(&mut unwatch_replies, scope);
            }
          }
          Ok(OpResult::Probed { probe, outcome }) => core.on_probe_result(probe, outcome, now()),
          Ok(OpResult::WatchInstalled { watch, outcome }) => {
            core.on_watch_installed(watch, outcome);
          }
          Ok(OpResult::Enumerated { req, raw }) => core.on_enumerated(req, raw),
          Ok(OpResult::MountsRefreshed { scope, refresh }) => {
            core.on_mounts_refreshed(scope, refresh, now())
          }
          // A spawn that raced the close: the stream is live but has no owner —
          // tear it down INSIDE the close accounting (the handle's Drop is only
          // the backstop past the grace) and hold the close reply for its
          // confirmation. Its scope never went registry-live, so there is no
          // entry to reclaim; a failed spawn just settles its slot.
          Ok(OpResult::Spawned { scope, result }) => {
            pending_spawns.remove(&scope);
            if let Ok(spawned) = result {
              *pending_teardowns.entry(scope).or_insert(0) += 1;
              let tx = op_tx.clone();
              R::spawn_blocking_detach(move || {
                spawned.handle.shutdown();
                let _ = tx.try_send(OpResult::TornDown { scope });
              });
            }
            // A FAILED spawn enqueues no teardown, so — exactly as the live
            // loop's spawn-failed arm does — a parked unwatch waiting on this
            // scope would otherwise never be re-checked and would drop as
            // `Closed` at return. Resolve it here if the failed spawn was the
            // scope's last obligation.
            if !pending_spawns.contains(&scope) && !pending_teardowns.contains_key(&scope) {
              resolve_unwatch_waiters(&mut unwatch_replies, scope);
            }
          }
          // A pre-arm outcome for a replace the close sweep already retired:
          // nothing left to commit or unwind.
          Ok(OpResult::RebindArmed { .. }) => {}
          // A dispatched write finished during the drain: its own verdict is
          // already on its record, so if a FAILED self-reap parked it
          // `RemoveFailed`, schedule its retry at the flat base so the drain's own
          // retry arm drives it to confirmation inside the grace (T3 caught by the
          // live ledger).
          Ok(OpResult::CookieWriteDone { id }) => {
            cookies.schedule_retry(&config, id, now(), true);
          }
          // An unlink finished: a confirm already dropped the record (the pool did
          // it, id-keyed); a transient failure parked it, and this re-schedules at
          // the flat base (the 1 s grace bounds attempts here — §5.2) or leaves it
          // parked past the budget.
          Ok(OpResult::CookieRemoveDone { id, confirmed }) => {
            on_cookie_remove_done(&cookies, &config, id, confirmed, now(), true);
          }
          Err(_) => break,
        },
        // Service due cookie-unlink retries inside the grace. No arm fires when
        // the schedule is empty (a `pending()` future), so this can never spin.
        () = async {
          match cookies.min_retry_at() {
            Some(at) => {
              R::sleep_until(origin + at.elapsed_since_origin()).await;
            }
            None => futures_util::future::pending::<()>().await,
          }
        }
        .fuse() => {
          dispatch_due_cookie_retries::<R, F>(&cookies, &op_tx, now());
        },
      }
    }
  };
  // Grace expiry with work still pending means a wedged blocking pool: the
  // close reply goes out anyway (a wedged pool must not hang close forever),
  // and it reports EVERY pending set — quiescence cannot be claimed while any
  // is non-empty. A still-pending TEARDOWN already moved its handle INTO the
  // wedged shutdown call, so nothing can reclaim that stream until the call
  // returns. A still-pending SPAWN may ALREADY OWN A LIVE STREAM — the backend
  // starts it and then performs post-live metadata reads inside the same call —
  // and only self-reclaims once the wedge clears (its undeliverable result
  // drops and the handle's Drop runs the teardown), so it is just as
  // non-quiescent at reply time. A still-owned COOKIE is a physical write or
  // unlink the sweep dispatched whose file a hung mount will not release until
  // it unwedges (the registry's best-effort Drop retries it), so it too is
  // non-quiescent. One shared grace for all: a wedged FFI or FS call rarely
  // unwedges with more time, so a longer window would only delay the honest
  // signal.
  let _ = R::timeout(Duration::from_secs(1), drain).await;
  execute_effects::<R, F>(
    &mut core,
    &ops,
    &config,
    &op_tx,
    &mut handles,
    &mut pending_spawns,
    &mut pending_teardowns,
    &mut scope_backends,
    &mut lanes,
    &events,
    &mut unwatch_replies,
    &mut deferred_grants,
    &mut cookies,
    &registry,
    &now,
  );
  // One final settlement poll: a fence whose re-arm work quiesced during the
  // drain resolves with its honest verdict instead of spuriously reading as
  // `Closed`. Whatever is still pending drops with `cover_replies` — the
  // ratified close-mid-fence semantics: the caller sees `Closed`, never an
  // outcome fabricated over a torn-down driver. No cookie can be dispatched
  // here (no scope is live to this poll, and shutdown already refuses claims),
  // so the registry may retire next.
  resolve_cover_settlements::<R, F>(
    &mut core,
    &ops,
    &op_tx,
    &mut cover_replies,
    &mut parked_cookies,
    &mut cookies,
    &|_| false,
  );
  // The close reply counts every distinct outstanding obligation exactly once:
  // a straggler teardown/spawn, and every cookie obligation the ledger still
  // holds — a write in the pool, an owned cookie, an unconfirmed removal — each
  // ONE record, so one physical obligation can never be tallied twice nor omitted.
  // `Ok(0)` now proves every stream torn down AND every cookie this driver ever
  // wrote is CONFIRMED removed — the strengthened close guarantee.
  let outstanding =
    pending_teardowns.values().sum::<usize>() + pending_spawns.len() + cookies.unremoved();
  // Drop the registry LAST. The orderly sweep above already dispatched an unlink
  // for every owned cookie under the grace, so on a healthy fs this finds the
  // ledger empty; whatever a hung mount would not let go was already counted in
  // the `NotQuiesced` reply above, and this `Drop` fires its best-effort DETACHED
  // retry without blocking. The `Drop` is the guarantee's backstop: a panicking
  // or cancelled driver — one that never reaches this line — still runs it,
  // detached, on exit.
  drop(cookies);
  if let Some(reply) = close_reply {
    let _ = reply.send(outstanding);
  }
}

/// Resolves and drops EVERY awaited unwatch parked for `scope`, each with
/// its own verdict (`true` for a live unwatch, `false` for an already-dead
/// scope). Called only once the scope is quiescent; a `RootHandle` is `Copy`
/// so more than one waiter can be queued, and all must be answered — a
/// dropped sender reads to its caller as driver death.
fn resolve_unwatch_waiters(
  unwatch_replies: &mut BTreeMap<ScopeId, Vec<(futures_channel::oneshot::Sender<bool>, bool)>>,
  scope: ScopeId,
) {
  if let Some(waiters) = unwatch_replies.remove(&scope) {
    for (reply, verdict) in waiters {
      let _ = reply.send(verdict);
    }
  }
}

/// Whether `scope` holds NO outstanding native obligation — no live handle,
/// no spawn in flight, no counted teardown, and no replace mid-commit. This
/// is the unwatch fence: a replace can leave the current handle down while a
/// replacement is still spawning or pre-arming (and will itself end in a
/// counted teardown), so the unwatch reply must wait for the whole scope to
/// go quiet, not merely for the one stream the unwatch retired.
fn scope_quiesced<H>(
  scope: ScopeId,
  handles: &BTreeMap<ScopeId, H>,
  pending_spawns: &BTreeSet<ScopeId>,
  pending_teardowns: &BTreeMap<ScopeId, usize>,
  replace_states: &BTreeMap<ScopeId, ReplaceState<H>>,
) -> bool {
  !handles.contains_key(&scope)
    && !pending_spawns.contains(&scope)
    && !pending_teardowns.contains_key(&scope)
    && !replace_states.contains_key(&scope)
}

/// Retires a spawned-but-refused replacement stream inside the counted
/// teardown accounting: it never becomes the scope's lane.
fn retire_refused<R, F>(
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  scope: ScopeId,
  spawned: SpawnedSource<F::Handle>,
) where
  R: RuntimeLite,
  F: FsOps,
{
  *pending_teardowns.entry(scope).or_insert(0) += 1;
  let tx = op_tx.clone();
  R::spawn_blocking_detach(move || {
    spawned.handle.shutdown();
    let _ = tx.try_send(OpResult::TornDown { scope });
  });
}

/// Lowers a pre-arm refusal into the io flavor
/// [`SourceError::RootUnavailable`] carries.
fn arm_failure(err: WatchError) -> std::io::Error {
  let kind = match err {
    WatchError::NotFound | WatchError::Gone => std::io::ErrorKind::NotFound,
    WatchError::Permission => std::io::ErrorKind::PermissionDenied,
    WatchError::NoSpace => std::io::ErrorKind::StorageFull,
    _ => std::io::ErrorKind::Other,
  };
  std::io::Error::new(kind, err.as_str())
}

/// Commits (or refuses) one root replacement that already passed the
/// router's death-wins and lowering gates (they also guard the descending
/// pre-arm, which runs before this point). Every failure path tears the NEW
/// stream down inside the counted accounting and leaves the old root
/// untouched — atomic-on-failure. Success retires the old stream (counted),
/// installs the new lane, and feeds the core's
/// [`on_root_replaced`](DriverCore::on_root_replaced) cut; a descending
/// commit then replays the pre-armed root outcome (`replay`) so the rebound
/// root's re-arm-flavored rebuild starts on the new transport.
#[allow(clippy::too_many_arguments)]
fn commit_replace<R, F>(
  core: &mut DriverCore,
  ops: &F,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  handles: &mut BTreeMap<ScopeId, F::Handle>,
  lanes: &mut BTreeMap<ScopeId, u64>,
  next_lane: &mut u64,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  os: &mut SelectAll<
    futures_util::stream::BoxStream<'static, (ScopeId, u64, Option<SourceMessage>)>,
  >,
  registry: &impl ScopeRegistry,
  cookies: &CookieRegistry<F>,
  scope: ScopeId,
  spawned: SpawnedSource<F::Handle>,
  reserved: &Path,
  replay: Option<WatchOutcome>,
  now: &impl Fn() -> Instant,
) -> Result<BackendKind, crate::error::ReplaceRootError>
where
  R: RuntimeLite,
  F: FsOps,
{
  use crate::error::ReplaceRootError;

  // The single-writer final check: the spawn re-canonicalized, so the
  // FINAL root's disjointness (exempting this scope AND the command's own
  // reservation) is settled here, immediately before commit.
  if let Some(existing) = registry.final_root_conflict(
    &spawned.meta.root,
    spawned.meta.identity,
    &spawned.meta.ancestors,
    Some(reserved),
    Some(scope),
  ) {
    let err = ReplaceRootError::Overlaps {
      path: spawned.meta.root.clone(),
      existing,
    };
    // Refused: the new stream never becomes the scope's lane.
    retire_refused::<R, F>(op_tx, pending_teardowns, scope, spawned);
    return Err(err);
  }

  // Make-before-break: the new stream is live; retire the old one now,
  // inside the counted accounting.
  if let Some(old) = handles.remove(&scope) {
    *pending_teardowns.entry(scope).or_insert(0) += 1;
    let tx = op_tx.clone();
    R::spawn_blocking_detach(move || {
      old.shutdown();
      let _ = tx.try_send(OpResult::TornDown { scope });
    });
  }
  // Bump the cookie root generation AT the lane swap, under the ledger lock: a
  // write dispatched under the retiring root can no longer claim once the new
  // stream is live (it sees the newer generation and self-reaps), while one
  // that already claimed belongs to the still-current old stream. This IS the
  // swap's linearization point — the transport generation mint below is its
  // control-plane twin.
  cookies.advance_generation_locked(scope);
  // Mint the replacement's transport generation FIRST, then detach the old
  // port and attach the new one under it: any old-generation control batch
  // still in flight now fails the front-check against this newer generation.
  let lane = *next_lane;
  *next_lane += 1;
  lanes.insert(scope, lane);
  ops.detach_scope(scope);
  ops.attach_scope(scope, spawned.handle.scope_port(), lane);
  let backend = spawned.meta.backend;
  let stats = spawned.handle.backend_stats();
  handles.insert(scope, spawned.handle);
  os.push(
    spawned
      .receiver
      .map(move |msg| (scope, lane, Some(msg)))
      .chain(futures_util::stream::once(
        async move { (scope, lane, None) },
      ))
      .boxed(),
  );
  // Registry overwrite BEFORE the core commit — the same program order
  // birth uses, on the same single-writer task.
  registry.scope_live(
    scope,
    &spawned.meta.root,
    spawned.meta.identity,
    &spawned.meta.ancestors,
    backend,
    stats,
  );
  let watch = core.root_watch(scope);
  core.on_root_replaced(scope, spawned.meta, now());
  // Descending: replay the pre-armed root outcome the commit adopted; the
  // rebound root is a pending re-arm, and this is the arm it awaits.
  if let (Some(outcome), Some(watch)) = (replay, watch) {
    core.on_watch_installed(watch, outcome);
  }
  Ok(backend)
}

/// Executes the core's queued effects, feeding each outcome straight back.
#[allow(clippy::too_many_arguments)]
fn execute_effects<R, F>(
  core: &mut DriverCore,
  ops: &F,
  config: &DriverConfig,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  handles: &mut BTreeMap<ScopeId, F::Handle>,
  pending_spawns: &mut BTreeSet<ScopeId>,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  scope_backends: &mut BTreeMap<ScopeId, BackendKind>,
  lanes: &mut BTreeMap<ScopeId, u64>,
  events: &async_channel::Sender<(ScopeId, Arc<PathBuf>, Change)>,
  unwatch_replies: &mut BTreeMap<ScopeId, Vec<(futures_channel::oneshot::Sender<bool>, bool)>>,
  deferred_grants: &mut BTreeMap<ScopeId, DeferredGrant>,
  cookies: &mut CookieRegistry<F>,
  registry: &impl ScopeRegistry,
  now: &impl Fn() -> Instant,
) where
  R: RuntimeLite,
  F: FsOps,
{
  // Arms/disarms from this whole drain, grouped by scope: dispatched as one
  // batch per scope AFTER the drain, so a cycle that arms N directories sends
  // one control message (one potential reader wake) instead of N. Non-control
  // effects still dispatch inline in emission order.
  let mut control_batches: BTreeMap<ScopeId, Vec<ControlRequest>> = BTreeMap::new();
  while let Some(effect) = core.poll_effect() {
    match effect {
      Effect::SpawnStream { scope, root } => {
        pending_spawns.insert(scope);
        let mut source_config = SourceConfig::new(vec![root]);
        source_config.exclusions = config.exclusions.clone();
        source_config.latency = config.latency;
        source_config.channel_capacity = config.os_batch_capacity;
        // The spawn selector carries the consumer's backend choice straight to
        // the barrier: `Backend::Auto` probes and falls back, a forced backend
        // pins it (and surfaces a typed error rather than falling back).
        // (macOS ignores the selector — FSEvents is its one backend.)
        source_config.backend = config.backend;
        source_config.max_map_directories = config.max_map_directories;
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let result = ops.spawn_source(source_config);
          let _ = tx.try_send(OpResult::Spawned { scope, result });
        });
      }
      Effect::TeardownStream { scope } => {
        scope_backends.remove(&scope);
        // The delivery lane (the transport generation) is reclaimed with the
        // scope — scope ids are never reused, so leaving it would grow `lanes`
        // unbounded under ordinary watch/unwatch churn. A late control batch
        // for the gone scope then resolves no lane and refuses (the `u64::MAX`
        // sentinel), exactly the right answer for a torn-down transport.
        lanes.remove(&scope);
        // Every scope end — explicit unwatch, root death, stream fatal —
        // funnels through this effect: reclaim the registry entry, so a dead
        // root stops participating in liveness checks immediately. The arm
        // port detaches with it (late arms answer the typed refusal), and a
        // registration still waiting on its root arm resolves as a failure
        // (the scope died before coverage ever started).
        registry.scope_dead(scope);
        ops.detach_scope(scope);
        // The scope's cookies retire with its stream: no cleanup reap will
        // arrive for a write whose reply was abandoned, and there will be no
        // stream left to report one on. The registry raises the scope's flag
        // before it dispatches its tracked unlinks, so a write still in the pool
        // reaps itself rather than landing a file behind this sweep.
        cookies.retire_scope::<R>(scope, op_tx);
        if let Some(DeferredGrant { pending, root }) = deferred_grants.remove(&scope) {
          let _ = pending
            .reply
            .send(Err(WatchRootError::Source(SourceError::RootUnavailable {
              root,
              source: std::io::Error::other("the source died before the root watch armed"),
            })));
        }
        if let Some(handle) = handles.remove(&scope) {
          *pending_teardowns.entry(scope).or_insert(0) += 1;
          let tx = op_tx.clone();
          R::spawn_blocking_detach(move || {
            handle.shutdown();
            let _ = tx.try_send(OpResult::TornDown { scope });
          });
        } else {
          // No stream ever existed (a failed spawn); every awaited unwatch is
          // complete now.
          resolve_unwatch_waiters(unwatch_replies, scope);
        }
      }
      Effect::AddWatch {
        scope,
        watch,
        parent,
        name,
        path,
        expected,
      } => {
        // Droppable at close, unlike spawns and teardowns: a result that
        // never lands leaves the Monitor node Arming, and the node dies with
        // its scope. The kernel watch (if the arm did install one) is not
        // leaked either — every wd on the source's fd is reclaimed when the
        // scope's stream teardown closes that fd. No pending-set entry.
        // Collected here and dispatched as part of the scope's batch below.
        control_batches
          .entry(scope)
          .or_default()
          .push(ControlRequest::Arm {
            watch,
            parent,
            name,
            path,
            expected,
          });
      }
      Effect::RemoveWatch { scope, watch } => {
        // Fire-and-forget by contract; droppable at close for the same
        // fd-reclamation reason as AddWatch. Batched with this scope's arms.
        control_batches
          .entry(scope)
          .or_default()
          .push(ControlRequest::Disarm { watch });
      }
      Effect::Enumerate { req, watch, path } => {
        // Droppable at close: a listing that never lands leaves the Monitor
        // node Enumerating; the scope teardown clears its pending request.
        // No OS resource is held by a readdir.
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let raw = ops.enumerate(watch, &path);
          let _ = tx.try_send(OpResult::Enumerated { req, raw });
        });
      }
      Effect::Probe { probe, path } => {
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let outcome = ops.probe(&path);
          let _ = tx.try_send(OpResult::Probed { probe, outcome });
        });
      }
      Effect::RefreshMounts { scope, root } => {
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let refresh = ops.refresh_mounts(&root);
          let _ = tx.try_send(OpResult::MountsRefreshed { scope, refresh });
        });
      }
      Effect::Emit {
        scope,
        root,
        change,
      } => match events.try_send((scope, root, change)) {
        Ok(()) => core.on_delivery(scope, Delivery::Accepted, now()),
        Err(async_channel::TrySendError::Full(_)) => {
          core.on_delivery(scope, Delivery::Refused, now());
        }
        // The consumer dropped its stream; shutdown arrives via the command
        // channel closing, so undeliverable changes are simply gone.
        Err(async_channel::TrySendError::Closed(_)) => {}
      },
    }
  }

  // Dispatch each scope's collected arms/disarms as ONE batch on the blocking
  // pool: the source ships it as a single control message (one potential reader
  // wake for the whole batch), and each arm still feeds back its own
  // `WatchInstalled`. Disarms are fire-and-forget (no reply). The scope's
  // CURRENT transport generation is captured here, at emission, and carried
  // into the batch: if a replace swaps the transport before this batch runs,
  // it fails the generation check and neither arms the replacement's fd nor
  // publishes a stale anchor into the swapped scope.
  for (scope, requests) in control_batches {
    let ops = ops.clone();
    let tx = op_tx.clone();
    let generation = lanes.get(&scope).copied().unwrap_or(u64::MAX);
    R::spawn_blocking_detach(move || {
      for (watch, outcome) in ops.batch_control(scope, generation, requests) {
        let _ = tx.try_send(OpResult::WatchInstalled { watch, outcome });
      }
    });
  }
}

/// Clones the driver-relevant shape of a spawn error: the core needs the
/// class, the caller keeps the original (io::Error is not Clone).
fn clone_error(err: &SourceError) -> SourceError {
  match err {
    SourceError::RootUnavailable { root, source } => SourceError::RootUnavailable {
      root: root.clone(),
      source: std::io::Error::new(source.kind(), source.kind().to_string()),
    },
    SourceError::Unsupported => SourceError::Unsupported,
    SourceError::NoRoots => SourceError::NoRoots,
    SourceError::NotADirectory { root } => SourceError::NotADirectory { root: root.clone() },
    SourceError::RootReplaced { root } => SourceError::RootReplaced { root: root.clone() },
    SourceError::TooManyExclusions { supplied } => SourceError::TooManyExclusions {
      supplied: *supplied,
    },
    SourceError::ExclusionRejected => SourceError::ExclusionRejected,
    SourceError::CreateFailed => SourceError::CreateFailed,
    SourceError::InstanceLimit => SourceError::InstanceLimit,
    SourceError::ReadFailed { source } => SourceError::ReadFailed {
      source: std::io::Error::new(source.kind(), source.kind().to_string()),
    },
    SourceError::StartFailed => SourceError::StartFailed,
    SourceError::BackendProbeFailed { stage } => SourceError::BackendProbeFailed { stage: *stage },
    SourceError::ForeignBackend { requested } => SourceError::ForeignBackend {
      requested: *requested,
    },
    SourceError::CallbackPanic => SourceError::CallbackPanic,
  }
}
