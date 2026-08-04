//! The consumer-facing watcher.

use std::{
  collections::{BTreeMap, BTreeSet, HashMap},
  marker::PhantomData,
  path::{Path, PathBuf},
  pin::Pin,
  sync::{
    Arc, PoisonError, RwLock,
    atomic::{AtomicU64, Ordering},
  },
  task::{Context, Poll},
};

use agnostic_lite::RuntimeLite;
use futures_core::Stream;
use tributary_proto::{Change, Interest, ScopeId};

use crate::{
  driver::{Command, CookieIngress, DriverConfig, RealFs, ScopeRegistry, run},
  error::{BuildError, CloseError, ReplaceRootError, SyncRootError, UnwatchError, WatchRootError},
  event::Event,
  options::WatcherOptions,
  os::{BackendKind, BackendStats, RootIdentity, SourceError},
};

#[cfg(all(test, feature = "tokio"))]
mod tests;

// Real-kernel regression suite for the set-cover pair: the in-place prune/grow
// reconciles end to end, plus the effect-completion fence's acceptance test
// (`set_cover_ack_resolves_at_watch_live`). In-crate rather than an external
// integration binary so it runs inside the parallel lib-test harness with
// object-scoped watch-descriptor assertions (see the module docs). not(miri):
// drives real inotify syscalls and a tokio runtime.
#[cfg(all(test, target_os = "linux", feature = "tokio", not(miri)))]
mod linux_kernel_tests;

/// Mints one id per [`Watcher`], branding its handles (see [`RootHandle`]).
static WATCHER_INSTANCES: AtomicU64 = AtomicU64::new(1);

/// An opaque handle to one watched root of a [`Watcher`].
///
/// A handle is a capability scoped to the watcher that issued it: scope ids
/// are minted per driver instance, so two watchers routinely share the same
/// numeric scope. Every handle therefore also carries its watcher's instance
/// brand, and using it with any other watcher is rejected
/// ([`UnwatchError::UnknownRoot`] / a `None` path) instead of silently
/// addressing that watcher's unrelated root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootHandle {
  instance: u64,
  scope: ScopeId,
}

impl RootHandle {
  /// Wraps a driver-minted scope under the issuing watcher's brand.
  pub(crate) const fn new(instance: u64, scope: ScopeId) -> Self {
    Self { instance, scope }
  }

  /// The underlying scope id (the value [`Event`]s of this root carry).
  #[inline]
  pub const fn scope(&self) -> ScopeId {
    self.scope
  }

  /// The issuing watcher's brand.
  pub(crate) const fn instance(&self) -> u64 {
    self.instance
  }
}

/// An opaque, `Copy` cancellation/reap key for one
/// [`sync_root`](Watcher::sync_root) admission, minted by THIS watcher and paired
/// at mint with the move-only [`SyncAdmission`] that admits the same sequence.
///
/// The pair splits the two authorities a sync needs. The [`SyncAdmission`]
/// **admits once**: [`sync_root`](Watcher::sync_root) consumes it by value, so the
/// type system forbids presenting one sequence to two admissions. The `SyncTicket`
/// **cancels forever**: [`request_cancel_sync`](Watcher::request_cancel_sync) takes
/// it — being `Copy`, the caller keeps it across the sync's whole life — and marks
/// the sequence's obligation at any phase, a no-op once the sync has retired.
///
/// A ticket addresses **at most one incarnation, ever** — now by construction, not
/// by convention. [`mint_sync_ticket`](Watcher::mint_sync_ticket) draws a
/// per-watcher monotonic sequence that is never re-minted, and the paired
/// admission is move-only, so that sequence is admitted at most once across all
/// time. A cookie NAME, by contrast, is freed at its holder's terminal and
/// re-bindable (sequential reuse admits), so a cancel delayed across a holder's
/// retirement and a same-name successor's admission would resolve the SUCCESSOR —
/// but the successor holds a DIFFERENT ticket, so a delayed cancel through this one
/// resolves the retired sync (a true no-op), never the successor.
///
/// Opaque: its fields are the minting watcher's brand and the mint sequence, both
/// private. It carries no path and no server-side state until the sync it keys is
/// admitted, so minting one — even in a flood — retains nothing. Exported like
/// [`RootHandle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SyncTicket {
  /// The minting watcher's brand — a ticket presented to a DIFFERENT watcher is
  /// refused at the door ([`SyncRootError::ForeignTicket`] on `sync_root`, a
  /// silent drop on `request_cancel_sync`) rather than aliasing that watcher's
  /// unrelated sequence numbering.
  instance: u64,
  /// The per-watcher monotonic mint sequence, never re-minted, so the ticket maps
  /// to one incarnation across all time — the ledger's `by_ticket` key.
  seq: u64,
}

impl SyncTicket {
  /// Brands a mint sequence under the issuing watcher.
  pub(crate) const fn new(instance: u64, seq: u64) -> Self {
    Self { instance, seq }
  }

  /// The issuing watcher's brand.
  pub(crate) const fn instance(&self) -> u64 {
    self.instance
  }

  /// The per-watcher mint sequence — the ledger's `by_ticket` key.
  pub(crate) const fn seq(&self) -> u64 {
    self.seq
  }
}

/// An opaque, **move-only** capability admitting exactly one
/// [`sync_root`](Watcher::sync_root) call, minted by THIS watcher and paired at
/// mint with the [`SyncTicket`] that cancels the same sequence.
///
/// It admits **once**: [`sync_root`](Watcher::sync_root) consumes it by value, and
/// the type carries no `Clone`, no `Copy`, and no `Drop`, so safe Rust cannot
/// present one admission — hence one mint sequence — to two admissions. That is
/// what turns "a ticket addresses at most one incarnation, ever" (see
/// [`SyncTicket`]) into a compile-time theorem: `by_ticket[seq]` is written at most
/// once, so a delayed [`request_cancel_sync`](Watcher::request_cancel_sync) can
/// only ever resolve that sequence's own incarnation or nothing.
///
/// A pre-birth refusal HANDS THE ADMISSION BACK
/// ([`SyncRootDenied::admission`]): the refusal admitted nothing, so the same
/// sequence may be re-presented (retry under the same ticket). Carrying **no**
/// `Drop` obligation, it is a pure capability — leaking one (drop,
/// [`mem::forget`](std::mem::forget)) simply means its sequence is never admitted,
/// which retains nothing server-side. Plain `Send` data — its two private fields
/// are the watcher brand and the mint sequence — so it holds across
/// [`sync_root`](Watcher::sync_root)'s await without perturbing the future's
/// `Send`. Exported like [`SyncTicket`].
#[derive(Debug)]
pub struct SyncAdmission {
  /// The minting watcher's brand — an admission presented to a DIFFERENT watcher
  /// is refused at the door ([`SyncRootError::ForeignTicket`]), never aliasing
  /// that watcher's unrelated sequence numbering.
  instance: u64,
  /// The per-watcher monotonic mint sequence, never re-minted and — being
  /// move-only — admitted at most once: the wire ticket
  /// [`sync_root`](Watcher::sync_root) builds and the ledger's `by_ticket` key.
  seq: u64,
}

impl SyncAdmission {
  /// Mints an admission under the issuing watcher's brand and sequence. The sole
  /// constructor, called only by [`mint_sync_ticket`](Watcher::mint_sync_ticket),
  /// which mints the paired [`SyncTicket`] from the same brand and sequence.
  pub(crate) const fn new(instance: u64, seq: u64) -> Self {
    Self { instance, seq }
  }

  /// The issuing watcher's brand.
  pub(crate) const fn instance(&self) -> u64 {
    self.instance
  }

  /// The per-watcher mint sequence — the wire ticket
  /// [`sync_root`](Watcher::sync_root) builds and the ledger's `by_ticket` key.
  pub(crate) const fn seq(&self) -> u64 {
    self.seq
  }
}

/// Why a [`sync_root`](Watcher::sync_root) call did not place a cookie, plus — for
/// a refusal that provably created nothing — the [`SyncAdmission`] handed back for
/// a same-sequence retry.
///
/// `admission` is `Some` **iff** the refusal is provably PRE-BIRTH: a synchronous
/// door refusal, or a driver refusal raised before the sync was admitted
/// ([`WriteInFlight`](SyncRootError::WriteInFlight),
/// [`NameInUse`](SyncRootError::NameInUse),
/// [`TicketInUse`](SyncRootError::TicketInUse),
/// [`CleanupBacklog`](SyncRootError::CleanupBacklog), and the reply-borne
/// [`UnknownRoot`](SyncRootError::UnknownRoot) /
/// [`BadCookieName`](SyncRootError::BadCookieName) /
/// [`DirOutsideRoot`](SyncRootError::DirOutsideRoot)). Such a refusal burns
/// nothing, so re-present the returned admission to
/// [`sync_root`](Watcher::sync_root) to retry under the SAME sequence — the paired
/// [`SyncTicket`] stays valid. `None` means the sequence is spent or its fate is
/// ambiguous — the write was admitted then retired
/// ([`Write`](SyncRootError::Write)), the sync reached a post-birth terminal
/// ([`Retired`](SyncRootError::Retired)), or the watcher is
/// [`Closed`](SyncRootError::Closed) — so a retry must re-mint through
/// [`mint_sync_ticket`](Watcher::mint_sync_ticket).
#[derive(Debug)]
pub struct SyncRootDenied {
  /// The placement failure — the same vocabulary the pre-split
  /// [`sync_root`](Watcher::sync_root) returned directly.
  pub error: SyncRootError,
  /// The admission handed back for a same-sequence retry: `Some` iff `error` is a
  /// provably pre-birth refusal (see the type docs), `None` when the sequence is
  /// spent or its fate is ambiguous.
  pub admission: Option<SyncAdmission>,
}

impl SyncRootDenied {
  /// Wraps a [`sync_root`](Watcher::sync_root) refusal, returning the admission for
  /// a same-sequence retry only when `error` is provably PRE-BIRTH (the refusal
  /// created nothing); otherwise the sequence is spent (or its fate ambiguous) and
  /// the admission is consumed. The SINGLE audit point for the pre/post-birth
  /// classification: a variant not listed here consumes the admission by default,
  /// so a future refusal is fail-safe — an unnecessary re-mint, never a reused
  /// sequence. Post-birth by construction and therefore deliberately absent from
  /// the returned set: `Write` (admitted, then retired before the reply — the
  /// sequence is burned), `Retired` (a post-admission terminal), and `Closed`.
  pub(crate) fn classify(error: SyncRootError, admission: SyncAdmission) -> Self {
    let admission = if matches!(
      error,
      SyncRootError::UnknownRoot
        | SyncRootError::ForeignTicket
        | SyncRootError::BadCookieName { .. }
        | SyncRootError::DirOutsideRoot { .. }
        | SyncRootError::DirExcluded { .. }
        | SyncRootError::WriteInFlight
        | SyncRootError::NameInUse { .. }
        | SyncRootError::TicketInUse {}
        | SyncRootError::CleanupBacklog
    ) {
      Some(admission)
    } else {
      None
    };
    Self { error, admission }
  }
}

/// The disposition of a non-blocking, reply-less control request
/// ([`request_unwatch`](Watcher::request_unwatch),
/// [`request_set_cover`](Watcher::request_set_cover)).
///
/// It splits the fire-and-forget outcome into the distinction a caller must act on:
/// [`Busy`](Self::Busy) is TRANSIENT — the control channel is momentarily full, so the caller
/// re-tries at its next opportunity — whereas [`Rejected`](Self::Rejected) is PERMANENT — a foreign
/// handle's brand, or a closed watcher, can never accept the request, so the intent must be dropped.
/// Collapsing the two (reading every non-acceptance as retryable backpressure) is what lets a
/// foreign handle be re-queued forever; keeping them apart at the boundary lets every present and
/// future caller drop never-valid work at its door while still honoring genuine backpressure.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestOutcome {
  /// Accepted onto the control channel.
  Enqueued,
  /// The control channel is momentarily full — retry at the next opportunity.
  Busy,
  /// The request can never be enqueued: a foreign handle (another watcher's
  /// brand) or a closed watcher. Do not retry; drop the intent.
  Rejected,
}

/// How an awaited coverage reconcile ([`Watcher::set_cover`]) completed.
///
/// The acknowledgement is an **effect-completion fence**: for a reconcile that
/// actually ran, it resolves when the reconcile has *settled* — every re-arm
/// the grow half started has quiesced — never when its effects were merely
/// queued. The settled verdicts ([`Applied`](Self::Applied) /
/// [`Degraded`](Self::Degraded)) are constructed only by that settlement, so
/// no code path can resolve them early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoverOutcome {
  /// The reconcile settled **clean**: every watch the grow half re-armed is
  /// live and no coverage loss was signaled inside the window — writes under
  /// the retained cover from the moment the ack resolves are delivered. A
  /// caller that shrank coverage, grew it back, and writes immediately on
  /// this resolution races nothing.
  Applied,
  /// The reconcile settled, but coverage loss was signaled since the root's
  /// last settled window (a failed re-arm, an unreadable re-arm read, an
  /// overflow, or the root tearing down mid-fence) — the loss memory is
  /// per-root, so a loss landing just BEFORE the reconcile degrades it too:
  /// coverage may be partial, and the covering
  /// [`Rescan`](crate::EventKind::Rescan) — already delivered in-band —
  /// dominates the gap. Any loss also drops the root's recorded coverage
  /// claim, so re-issuing the same cover re-attempts the FULL grow (re-proving
  /// the requested coverage), and a clean re-issue resolves `Applied`.
  Degraded,
  /// The root is backed by a kernel-recursive backend (fanotify / FSEvents),
  /// whose single whole-subtree stream never narrowed: there is nothing to
  /// prune or re-arm, ever, for this root. Reported explicitly — "coverage
  /// was never reduced" — rather than as a hollow `Applied`;
  /// [`BackendKind::is_kernel_recursive`](crate::BackendKind::is_kernel_recursive)
  /// on [`Watcher::backend_of`]'s report lets a caller skip the round-trip
  /// a priori.
  Recursive,
  /// No reconcile ran; the payload says why. Prior coverage — and the record
  /// the next reconcile's grow is computed against — is untouched.
  Skipped(SkipReason),
}

impl CoverOutcome {
  /// The stable snake_case name of this outcome (independent of any carried
  /// data).
  #[inline]
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Applied => "applied",
      Self::Degraded => "degraded",
      Self::Recursive => "recursive",
      Self::Skipped(_) => "skipped",
    }
  }

  /// Whether this is [`Applied`](Self::Applied).
  #[inline]
  pub const fn is_applied(&self) -> bool {
    matches!(self, Self::Applied)
  }

  /// Whether this is [`Degraded`](Self::Degraded).
  #[inline]
  pub const fn is_degraded(&self) -> bool {
    matches!(self, Self::Degraded)
  }

  /// Whether this is [`Recursive`](Self::Recursive).
  #[inline]
  pub const fn is_recursive(&self) -> bool {
    matches!(self, Self::Recursive)
  }

  /// Whether this is [`Skipped`](Self::Skipped).
  #[inline]
  pub const fn is_skipped(&self) -> bool {
    matches!(self, Self::Skipped(_))
  }

  /// The skip reason, if this is [`Skipped`](Self::Skipped).
  #[inline]
  pub const fn skip_reason(&self) -> Option<SkipReason> {
    match self {
      Self::Skipped(reason) => Some(*reason),
      _ => None,
    }
  }
}

impl core::fmt::Display for CoverOutcome {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// Why a [`Watcher::set_cover`] reconcile was [`Skipped`](CoverOutcome::Skipped):
/// the driver refused to run it, and prior coverage is untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
  /// The handle does not name a live root of the driver: never watched,
  /// already unwatched, or torn down (root death, stream fatal) concurrently
  /// with this call — indistinguishable from a root that died right after the
  /// call was made, exactly like [`Watcher::unwatch`]'s unknown-root answer.
  UnknownRoot,
  /// The root is not publicly live yet: between a descending root's stream
  /// spawn and the root arm that commits its registration there is no
  /// coverage to reconcile, and a grow in that window would convert the
  /// root's cold discovery into a `Created`-suppressing re-arm. Re-issue once
  /// [`Watcher::watch`] has resolved.
  NotLive,
  /// The retained cover was refused: empty, or entirely outside the live root
  /// (a typo, a relative path, a stale path) — acting on either would prune
  /// the whole scope's coverage.
  RefusedCover,
  /// This root already has the maximum number of awaited reconciles parked on a
  /// coverage fence that has not settled. Each admitted call is retained — one
  /// reply sender in the driver, one pending fence record in the core — until
  /// its window settles, and a root whose native control round trip is stalled
  /// never settles, so admission stops rather than growing driver state with
  /// total calls. Nothing was reconciled and prior coverage is untouched;
  /// retryable once the outstanding reconciles settle or their callers go away.
  Backlogged,
}

impl SkipReason {
  /// The stable snake_case name of this reason.
  #[inline]
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::UnknownRoot => "unknown_root",
      Self::NotLive => "not_live",
      Self::RefusedCover => "refused_cover",
      Self::Backlogged => "backlogged",
    }
  }

  /// Whether this is [`UnknownRoot`](Self::UnknownRoot).
  #[inline]
  pub const fn is_unknown_root(&self) -> bool {
    matches!(self, Self::UnknownRoot)
  }

  /// Whether this is [`NotLive`](Self::NotLive).
  #[inline]
  pub const fn is_not_live(&self) -> bool {
    matches!(self, Self::NotLive)
  }

  /// Whether this is [`Backlogged`](Self::Backlogged).
  #[inline]
  pub const fn is_backlogged(&self) -> bool {
    matches!(self, Self::Backlogged)
  }

  /// Whether this is [`RefusedCover`](Self::RefusedCover).
  #[inline]
  pub const fn is_refused_cover(&self) -> bool {
    matches!(self, Self::RefusedCover)
  }
}

impl core::fmt::Display for SkipReason {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// One live root's registry record: its canonical path plus the object
/// identities disjointness is decided on (the root's own and every strict
/// ancestor's), captured at the spawn barrier, plus the backend the barrier
/// selected (what [`Watcher::backend_of`] reports) and — for a fanotify root —
/// the live stats handle [`Watcher::backend_stats`] snapshots.
#[derive(Debug)]
struct RootEntry {
  path: Arc<PathBuf>,
  identity: RootIdentity,
  ancestors: Arc<[RootIdentity]>,
  backend: BackendKind,
  stats: Option<crate::os::BackendStatsHandle>,
}

/// One in-flight `watch`'s reservation record: the watcher-side canonical
/// path plus the identity its pre-flight stat observed (`None` off-unix).
#[derive(Debug)]
struct PendingRoot {
  path: PathBuf,
  identity: Option<RootIdentity>,
}

// Registry entries INSPECTED by one conflict query or one release — the quantity the indexes
// below exist to keep proportional to the candidate's depth rather than to the registry. Both
// run under the registry's single write lock, so a full scan does not merely cost the caller:
// it serializes every other admission, release and reader behind it, and it does so once per
// root, making a batch of N disjoint roots quadratic in lock-held CPU.
//
// Thread-local so libtest's parallel cells cannot perturb one another's count (each test body
// owns its thread).
#[cfg(test)]
thread_local! {
  pub(crate) static REGISTRY_PROBES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Records that a registry query inspected `n` entries.
#[cfg(test)]
fn note_registry_probes(n: usize) {
  REGISTRY_PROBES.with(|probes| probes.set(probes.get() + n));
}

#[cfg(not(test))]
#[inline(always)]
fn note_registry_probes(_n: usize) {}

/// The first key in `index` that is a **strict descendant** of `path`, skipping any whose
/// value the caller rejects.
///
/// [`Path`]'s [`Ord`] compares **components**, so every strict descendant of `path` sorts
/// immediately after it and before any non-descendant that is greater — `/a/b/c` precedes both
/// `/a/b.txt` and `/a/bc`, because the third component `b` precedes `b.txt` and `bc`. The walk
/// may therefore stop at the first key that is not a descendant. (Byte ordering would not have
/// this property; `descendants_are_adjacent_under_path_ordering` pins it.)
fn descendant_in<'a, V>(
  index: &'a BTreeMap<PathBuf, V>,
  path: &Path,
  mut accept: impl FnMut(&V) -> bool,
) -> Option<&'a PathBuf> {
  let mut probes = 0;
  let found = index
    .range::<Path, _>((
      core::ops::Bound::Excluded(path),
      core::ops::Bound::Unbounded,
    ))
    .inspect(|_| probes += 1)
    .take_while(|(key, _)| key.starts_with(path))
    .find(|(_, value)| accept(value))
    .map(|(key, _)| key);
  note_registry_probes(probes);
  found
}

/// The nearest key in `index` that is an **ancestor-or-equal** of `path`, skipping any whose
/// value the caller rejects — a walk up `path`'s own ancestors, so it costs the candidate's
/// depth and a lookup each, never the registry's size.
fn ancestor_in<'a, V>(
  index: &'a BTreeMap<PathBuf, V>,
  path: &Path,
  mut accept: impl FnMut(&V) -> bool,
) -> Option<&'a PathBuf> {
  let mut probes = 0;
  let found = path.ancestors().find_map(|ancestor| {
    probes += 1;
    index
      .get_key_value(ancestor)
      .filter(|(_, value)| accept(value))
      .map(|(key, _)| key)
  });
  note_registry_probes(probes);
  found
}

/// The watcher-side registry of live roots, keyed by scope. Entries exist
/// exactly while their root is watched: every scope end (unwatch, root death,
/// stream fatal, close) removes its entry, so the registry is bounded by the
/// number of LIVE roots — deliveries carry their own root path, so nothing
/// here is needed to assemble trailing events of a dead scope.
///
/// `entries` has ONE writer: the driver task, through [`RegistryWriter`] —
/// scope-live and scope-dead execute on that single task in program order, so
/// an insert can never race a removal. The watcher side only reads entries
/// (and owns the `pending` reservations, which no one else writes).
///
/// # Conflict indexes
///
/// Every predicate the disjointness check asks — "is some covered root an ancestor of this
/// candidate", "a descendant of it", "the same object under another spelling", "an ancestor of
/// it across spellings" — gets an index that answers it in `O(depth · log N)` or `O(1)`.
///
/// The scanned form these replace was `Θ(N)` per query on a registry of `N` roots, on **both**
/// admission and release, all of it under one exclusive lock. Admitting `N` mutually disjoint
/// roots therefore cost `N(N-1)/2` comparisons and releasing them another `N(N+1)/2`, with the
/// whole registry — readers included — serialized behind each one.
#[derive(Debug, Default)]
struct RootSet {
  entries: BTreeMap<ScopeId, RootEntry>,
  /// Live root path → its scope. Ordered, so containment in either direction is a bounded
  /// probe rather than a scan (see [`descendant_in`] / [`ancestor_in`]).
  live_by_path: BTreeMap<PathBuf, ScopeId>,
  /// Live root **own** identity → its scope: the cross-spelling "same object" test.
  live_by_identity: HashMap<RootIdentity, ScopeId>,
  /// Live root **ancestor** identity → every scope whose root sits under that object. A set,
  /// not a single scope: several disjoint live roots can share an ancestor.
  live_by_ancestor: HashMap<RootIdentity, BTreeSet<ScopeId>>,
  /// Roots with a `watch` in flight, reserved so two concurrent overlapping
  /// `watch` calls cannot both pass the disjointness check. Keyed by path so a release is a
  /// single removal instead of a whole-vector retain under the write lock.
  pending: BTreeMap<PathBuf, PendingRoot>,
  /// Reserved identity → the path holding it: the pre-flight cross-spelling collision, so two
  /// aliased concurrent `watch` calls settle here rather than both spending a spawn.
  pending_by_identity: HashMap<RootIdentity, PathBuf>,
}

impl RootSet {
  /// Records a live root: every index plus `entries`, so the two can never disagree. Any
  /// entry this displaces (a re-live of the same scope) is unindexed first — the single
  /// mutation point for a live root, so no caller can index half of one.
  fn insert_live(&mut self, scope: ScopeId, entry: RootEntry) {
    if let Some(previous) = self.entries.remove(&scope) {
      self.unindex_live(scope, &previous);
    }
    self.index_live(scope, &entry);
    self.entries.insert(scope, entry);
  }

  /// Records a live root in every index. The `entries` insert stays the caller's.
  fn index_live(&mut self, scope: ScopeId, entry: &RootEntry) {
    self.live_by_path.insert(entry.path.as_ref().clone(), scope);
    self.live_by_identity.insert(entry.identity, scope);
    for ancestor in entry.ancestors.iter() {
      self
        .live_by_ancestor
        .entry(*ancestor)
        .or_default()
        .insert(scope);
    }
  }

  /// Drops a live root from every index — the exact inverse of
  /// [`index_live`](Self::index_live), so a scope's death leaves nothing behind that could
  /// block a later admission forever.
  fn unindex_live(&mut self, scope: ScopeId, entry: &RootEntry) {
    self.live_by_path.remove(entry.path.as_path());
    self.live_by_identity.remove(&entry.identity);
    for ancestor in entry.ancestors.iter() {
      if let Some(scopes) = self.live_by_ancestor.get_mut(ancestor) {
        scopes.remove(&scope);
        if scopes.is_empty() {
          self.live_by_ancestor.remove(ancestor);
        }
      }
    }
  }

  /// The live root that overlaps `candidate` by containment or by object identity, if any.
  fn live_overlap(
    &self,
    candidate: &Path,
    identity: Option<RootIdentity>,
    exempt: Option<ScopeId>,
  ) -> Option<PathBuf> {
    let allowed = |scope: &ScopeId| Some(*scope) != exempt;
    if let Some(path) = ancestor_in(&self.live_by_path, candidate, allowed) {
      return Some(path.clone());
    }
    if let Some(path) = descendant_in(&self.live_by_path, candidate, allowed) {
      return Some(path.clone());
    }
    let same_object = *identity
      .and_then(|id| self.live_by_identity.get(&id))
      .filter(|scope| allowed(scope))?;
    note_registry_probes(1);
    self
      .entries
      .get(&same_object)
      .map(|entry| entry.path.as_ref().clone())
  }

  /// The already-covered root (live or pending) that overlaps `candidate`, if
  /// any. Two roots overlap when either contains the other by path — or when
  /// they are one object under two spellings (`identity` equality), which
  /// path comparison cannot see on case- or normalization-insensitive
  /// volumes. Ancestor containment across spellings needs the candidate's
  /// ancestor identities, which only the spawn barrier reads: the driver's
  /// [`ScopeRegistry::final_root_conflict`] settles those before anything
  /// goes live.
  ///
  /// `exempt` excludes ONE live scope from the check — the root a
  /// `replace_root` is replacing: its coverage is the thing being widened,
  /// so overlapping IT is the operation's whole point, never a conflict.
  fn overlap_of(
    &self,
    candidate: &Path,
    identity: Option<RootIdentity>,
    exempt: Option<ScopeId>,
  ) -> Option<PathBuf> {
    if let Some(path) = self.live_overlap(candidate, identity, exempt) {
      return Some(path);
    }
    if let Some(path) = ancestor_in(&self.pending, candidate, |_| true) {
      return Some(path.clone());
    }
    if let Some(path) = descendant_in(&self.pending, candidate, |_| true) {
      return Some(path.clone());
    }
    identity.and_then(|id| {
      note_registry_probes(1);
      self.pending_by_identity.get(&id).cloned()
    })
  }
}

/// The driver task's write end of the registry — the SOLE mutator of
/// `RootSet::entries` (see the single-writer note on [`RootSet`]).
struct RegistryWriter {
  roots: Arc<RwLock<RootSet>>,
}

impl ScopeRegistry for RegistryWriter {
  fn scope_live(
    &self,
    scope: ScopeId,
    root: &Path,
    identity: RootIdentity,
    ancestors: &[RootIdentity],
    backend: BackendKind,
    stats: Option<crate::os::BackendStatsHandle>,
  ) {
    let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
    set.insert_live(
      scope,
      RootEntry {
        path: Arc::new(root.to_path_buf()),
        identity,
        ancestors: ancestors.into(),
        backend,
        stats,
      },
    );
  }

  fn scope_dead(&self, scope: ScopeId) {
    let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
    if let Some(entry) = set.entries.remove(&scope) {
      set.unindex_live(scope, &entry);
    }
  }

  fn final_root_conflict(
    &self,
    final_root: &Path,
    identity: RootIdentity,
    ancestors: &[RootIdentity],
    reserved: Option<&Path>,
    exempt: Option<ScopeId>,
  ) -> Option<PathBuf> {
    let set = self.roots.read().unwrap_or_else(PoisonError::into_inner);
    if let Some(path) = set.live_overlap(final_root, Some(identity), exempt) {
      return Some(path);
    }
    // The two cross-spelling ANCESTOR tests, each indexed rather than scanned: a live root that
    // IS one of this candidate's ancestors under another spelling, and a live root whose own
    // ancestors include this candidate's object.
    let path_of = |scope: &ScopeId| {
      note_registry_probes(1);
      set
        .entries
        .get(scope)
        .map(|entry| entry.path.as_ref().clone())
    };
    for ancestor in ancestors {
      note_registry_probes(1);
      if let Some(scope) = set
        .live_by_identity
        .get(ancestor)
        .filter(|scope| Some(**scope) != exempt)
      {
        return path_of(scope);
      }
    }
    note_registry_probes(1);
    if let Some(scope) = set
      .live_by_ancestor
      .get(&identity)
      .and_then(|scopes| scopes.iter().find(|scope| Some(**scope) != exempt))
    {
      return path_of(scope);
    }
    // A reservation holds at most one entry per path (an overlapping
    // second take is rejected), so skipping by equality skips exactly
    // the checking watch's own.
    let not_self = |pending: &PendingRoot| Some(pending.path.as_path()) != reserved;
    if let Some(path) = ancestor_in(&set.pending, final_root, not_self) {
      return Some(path.clone());
    }
    if let Some(path) = descendant_in(&set.pending, final_root, not_self) {
      return Some(path.clone());
    }
    note_registry_probes(1);
    set
      .pending_by_identity
      .get(&identity)
      .filter(|path| Some(path.as_path()) != reserved)
      .cloned()
  }
}

/// A pending-root reservation, held across `watch`'s awaits. Dropping it —
/// on success, failure, OR a cancelled future — releases the reservation, so
/// an abandoned `watch` can never leave a permanent overlap blocker. On
/// success the real `RootEntry` is inserted BEFORE the guard drops, so the
/// path is covered continuously.
///
/// The reserved path is ADVISORY: it holds the watcher-side canonical form,
/// which mutually excludes concurrent `watch` calls, but the backend
/// re-canonicalizes during spawn — the driver's final-root check
/// ([`ScopeRegistry::final_root_conflict`]) is the authority on what actually
/// goes live.
#[derive(Debug)]
pub(crate) struct Reservation {
  roots: Arc<RwLock<RootSet>>,
  path: PathBuf,
}

/// The reservation guard as the driver holds it during a replace: the
/// watcher takes it (with the replaced scope exempted) before the command
/// round-trip, and the DRIVER drops it at commit or failure — so cancelling
/// the caller's future can never release the new root's reservation out
/// from under an in-flight swap.
pub(crate) type ReservationGuard = Reservation;

impl Reservation {
  /// Reserves `path`, or reports the covering root when it overlaps. The
  /// pre-flight identity lets two concurrent spelling-aliased `watch` calls
  /// collide right here — the first reserver wins deterministically — instead
  /// of both spending a spawn to lose at the driver's final check. `exempt`
  /// is `replace_root`'s own scope (see [`RootSet::overlap_of`]).
  fn take(
    roots: &Arc<RwLock<RootSet>>,
    path: PathBuf,
    identity: Option<RootIdentity>,
    exempt: Option<ScopeId>,
  ) -> Result<Self, WatchRootError> {
    let mut set = roots.write().unwrap_or_else(PoisonError::into_inner);
    if let Some(existing) = set.overlap_of(&path, identity, exempt) {
      return Err(WatchRootError::Overlaps { path, existing });
    }
    if let Some(identity) = identity {
      set.pending_by_identity.insert(identity, path.clone());
    }
    set.pending.insert(
      path.clone(),
      PendingRoot {
        path: path.clone(),
        identity,
      },
    );
    drop(set);
    Ok(Self {
      roots: Arc::clone(roots),
      path,
    })
  }
}

impl Reservation {
  /// The reserved canonical path — the driver's final-check self-exemption
  /// for the reservation a `Replace` command itself carries.
  pub(crate) fn path(&self) -> &Path {
    &self.path
  }

  /// A detached guard over an isolated set — the driver suites' stand-in
  /// (reservation SEMANTICS have their own suites; the driver only drops
  /// the guard it is handed).
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn detached_for_tests(path: PathBuf) -> Self {
    Self {
      roots: Arc::new(RwLock::new(RootSet::default())),
      path,
    }
  }
}

impl Drop for Reservation {
  fn drop(&mut self) {
    let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
    // One keyed removal, not a retain over every reservation: release runs under the same
    // exclusive lock admission does, so a scan here is a second quadratic term AND a second
    // source of registry-wide stalling. Both indexes are cleared from THIS reservation's own
    // record, so a concurrent alias that reserved after us cannot have its identity dropped.
    if let Some(identity) = set.pending.remove(&self.path).and_then(|p| p.identity)
      && set.pending_by_identity.get(&identity) == Some(&self.path)
    {
      set.pending_by_identity.remove(&identity);
    }
  }
}

/// An asynchronous filesystem watcher: the consumer surface of the
/// `tributary-fs` driver.
///
/// A watcher owns one driver task and any number of **disjoint** watched
/// roots. It implements [`Stream`] (and offers the inherent
/// [`next`](Self::next)), yielding [`Event`]s.
///
/// # Watching means "changes from now on"
///
/// Registering a root delivers no initial inventory. A consumer that needs a
/// snapshot starts the watch **first**, then crawls the tree itself: any
/// change racing the crawl is delivered as an event, and because events are
/// grounded in what is actually on disk, applying them over the crawl's
/// result converges.
///
/// # Loss is never silent
///
/// Kernel-side drops, a full event buffer, a vanished root — every coverage
/// gap surfaces as a [`Rescan`](crate::EventKind::Rescan) event whose
/// [`epoch`](Event::epoch) dominates everything delivered before it. See
/// [`Event::epoch`] for the re-enumeration contract.
///
/// # Dropping
///
/// Dropping a watcher closes its command channel; the driver observes the
/// close and performs the same orderly stream teardown as
/// [`close`](Self::close), without anyone to confirm it to. Prefer `close()`
/// in orderly programs — it awaits the teardown.
pub struct Watcher<R> {
  /// This watcher's handle brand (see [`RootHandle`]).
  instance: u64,
  commands: async_channel::Sender<Command>,
  /// The cookie-cleanup ingress: the driver's own obligation ledger, shared under
  /// one mutex (the same sharing shape `roots` has), plus a coalescing wake. A
  /// public reap or cancel is a mark ON the obligation it names — never a message
  /// about it — so it rides no channel that a command burst could saturate, and no
  /// channel that a flood could grow.
  cleanup: CookieIngress,
  /// The sync-ticket mint: a per-watcher monotonic sequence, held behind an `Arc`
  /// so it is shared (and stays unique) across any `Watcher` clones. Bumped once
  /// per [`mint_sync_ticket`](Self::mint_sync_ticket) with a `Relaxed` fetch-add
  /// (uniqueness, not ordering, is all a ticket needs). `u64` and driver-lifetime,
  /// so it never wraps — the same non-exhaustion argument the cookie id mint
  /// stands on.
  sync_tickets: Arc<AtomicU64>,
  events: EventStream,
  roots: Arc<RwLock<RootSet>>,
  // `fn() -> R`, not `R`: the watcher holds no runtime value, so its auto
  // traits (`Send`/`Sync`/`Unpin`) must not condition on `R`'s.
  _runtime: PhantomData<fn() -> R>,
}

/// The watcher's inbound event stream: the driver's `async_channel::Receiver`,
/// type-erased. Boxed because the `Receiver` embeds a pinned listener (it is
/// not `Unpin`), so the `Pin<Box<…>>` keeps `Watcher` itself `Unpin` for
/// consumers. The `+ Send + Sync` bound (the `Receiver` is both) keeps
/// `Watcher: Sync`, hence `&Watcher: Send`.
type EventStream =
  Pin<Box<dyn Stream<Item = (ScopeId, Arc<PathBuf>, Change)> + Send + Sync + 'static>>;

impl<R> core::fmt::Debug for Watcher<R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Watcher")
      .field("roots", &self.roots)
      .finish_non_exhaustive()
  }
}

impl<R: RuntimeLite> Watcher<R> {
  /// Builds a watcher and spawns its driver task on `R`.
  ///
  /// # Errors
  ///
  /// [`BuildError::InvalidOptions`] when any option lies outside its documented
  /// range — checked HERE, before the event channel is allocated or the driver
  /// task exists, so an out-of-range value can never reach the arithmetic or the
  /// kernel call that has no answer for it. See
  /// [`WatcherOptions::validate`].
  pub fn new(options: WatcherOptions) -> Result<Self, BuildError> {
    options.validate()?;
    let config = driver_config(&options, DriverConfig::platform_profile());
    Self::spawn_with(options, config, RealFs::new())
  }

  /// Builds the watcher around `ops` — the seam the hermetic lifecycle tests
  /// drive with a fake filesystem; production always passes [`RealFs`].
  fn spawn_with(
    options: WatcherOptions,
    config: DriverConfig,
    ops: impl crate::driver::FsOps,
  ) -> Result<Self, BuildError> {
    let (command_tx, command_rx) = async_channel::bounded(16);
    // The cookie-cleanup ingress: ONE ledger, minted HERE and shared between this
    // handle and the driver task below, because a public cleanup request must
    // address the very records that driver admits. Its two halves are created
    // together for the same reason the command channel's are.
    let (cleanup, cookie_wake) = crate::driver::cookie_ingress();
    let (event_tx, event_rx) = async_channel::bounded(options.event_capacity().get());
    let roots = Arc::new(RwLock::new(RootSet::default()));
    // The registry's entries are written only by the driver task: live at
    // spawn (before the grant is sent), dead at every teardown — one writer,
    // program order, no insert/remove race. This side only reads.
    let registry = RegistryWriter {
      roots: Arc::clone(&roots),
    };
    R::spawn_detach(run::<R, _>(
      config,
      ops,
      command_rx,
      cookie_wake,
      event_tx,
      registry,
    ));
    Ok(Self {
      instance: WATCHER_INSTANCES.fetch_add(1, Ordering::Relaxed),
      commands: command_tx,
      cleanup,
      sync_tickets: Arc::new(AtomicU64::new(0)),
      events: Box::pin(event_rx),
      roots,
      _runtime: PhantomData,
    })
  }

  /// A watcher over a fake platform, for hermetic lifecycle tests.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn new_with(
    options: WatcherOptions,
    ops: impl crate::driver::FsOps,
  ) -> Result<Self, BuildError> {
    options.validate()?;
    // The hermetic lifecycle suites drive the backend-agnostic scope machinery
    // over the KR profile with FSEvents-shaped payloads, regardless of host —
    // the descending profile has its own driver suites. Pinning the profile here
    // keeps them host-independent.
    let config = driver_config(&options, crate::os::BackendKind::FsEvents);
    Self::spawn_with(options, config, ops)
  }
}

/// The ONE lowering of public options into driver knobs, shared by the real
/// constructor and the hermetic one so the two can never drift on what a knob
/// means — only on the provisional lowering `profile`, which is the single thing
/// they legitimately disagree about.
///
/// Callers have already run [`WatcherOptions::validate`]: every value here is in
/// range, which is what makes the downstream arithmetic total.
fn driver_config(options: &WatcherOptions, profile: crate::os::BackendKind) -> DriverConfig {
  DriverConfig {
    latency: options.latency(),
    move_window: options.move_window(),
    os_batch_capacity: options.os_batch_capacity(),
    os_buffer_bytes: options.os_buffer_bytes(),
    exclusions: options.exclusions_slice().to_vec(),
    profile,
    backend: options.backend(),
    root_liveness_interval: options.root_liveness_interval(),
    max_map_directories: options.max_map_directories(),
    cookie_retry_base: DriverConfig::DEFAULT_COOKIE_RETRY_BASE,
    cookie_retry_cap: DriverConfig::DEFAULT_COOKIE_RETRY_CAP,
    cookie_retry_budget: DriverConfig::DEFAULT_COOKIE_RETRY_BUDGET,
    cookie_backlog_cap: DriverConfig::DEFAULT_COOKIE_BACKLOG_CAP,
    cookie_global_cap: DriverConfig::DEFAULT_COOKIE_GLOBAL_CAP,
  }
}

// Everything below is channel and registry work: no method names an `R` item,
// so the runtime bound stays on the constructors above (the one place the
// driver task is spawned) and a `Watcher<R>` in a signature needs no bound.
impl<R> Watcher<R> {
  /// Watches `root`, resolving once the native stream is live. From that
  /// moment every change under the root is delivered per `interest`
  /// (`Rescan`s are always delivered).
  ///
  /// The root is canonicalized first (a symlinked root would otherwise
  /// observe nothing), which performs a few blocking metadata syscalls
  /// inline.
  ///
  /// # A handle can be dead on arrival
  ///
  /// The returned handle names a root that was live when the stream started —
  /// but a root can die (be deleted, unmount, the stream fail) at any moment,
  /// including between the stream going live and this call resolving. Such a
  /// handle is indistinguishable from one whose root died right after
  /// `watch()` returned, which no design can prevent: [`root_path`] answers
  /// `None`, [`unwatch`] answers [`UnknownRoot`], and the root's terminal
  /// [`Rescan`](crate::EventKind::Rescan) is still delivered.
  ///
  /// [`root_path`]: Self::root_path
  /// [`unwatch`]: Self::unwatch
  /// [`UnknownRoot`]: UnwatchError::UnknownRoot
  ///
  /// # Errors
  ///
  /// - [`WatchRootError::NotFound`] / [`WatchRootError::NotADirectory`] when
  ///   the root cannot serve as a watch target;
  /// - [`WatchRootError::Overlaps`] when it is not disjoint from an
  ///   already-watched root (subsumption is the layer above's job). The check
  ///   binds to the FINAL canonical root: a path retargeted between this call
  ///   and the stream spawn is revalidated by the driver, so the disjointness
  ///   invariant holds for what is actually watched;
  /// - [`WatchRootError::Source`] when the platform stream could not start;
  /// - [`WatchRootError::Closed`] when the watcher is already closed.
  pub async fn watch(
    &self,
    root: impl Into<PathBuf>,
    interest: Interest,
  ) -> Result<RootHandle, WatchRootError> {
    let supplied = root.into();
    let canonical = std::fs::canonicalize(&supplied).map_err(|err| {
      if err.kind() == std::io::ErrorKind::NotFound {
        WatchRootError::NotFound { path: supplied }
      } else {
        WatchRootError::Source(SourceError::RootUnavailable {
          root: supplied,
          source: err,
        })
      }
    })?;
    let meta = std::fs::metadata(&canonical).ok();
    if !meta.as_ref().is_some_and(|meta| meta.is_dir()) {
      return Err(WatchRootError::NotADirectory { path: canonical });
    }
    let identity = meta.as_ref().and_then(identity_of);

    // Reserve the root before the round-trip so a concurrent overlapping
    // `watch` cannot also pass the disjointness check. The guard's Drop
    // releases the reservation on every exit — including this future being
    // cancelled at either await below. An orphaned stream cannot outlive a
    // cancellation on either side of the reply: a reply finding no receiver
    // is torn down by the driver directly, and a delivered-but-never-polled
    // reply unwinds through its `WatchGrant`.
    let reservation = Reservation::take(&self.roots, canonical.clone(), identity, None)?;

    let (reply, response) = futures_channel::oneshot::channel();
    let sent = self
      .commands
      .send(Command::Watch {
        root: canonical,
        interest,
        reply,
      })
      .await;
    if sent.is_err() {
      self.driver_gone();
      return Err(WatchRootError::Closed);
    }
    match response.await {
      Ok(Ok(grant)) => {
        // The driver inserted the registry entry BEFORE sending this grant
        // (and removes it at every teardown — one writer, program order), so
        // the path is covered continuously while the reservation still
        // holds: defusing is the whole commit. A scope that died in the
        // window since simply hands back a dead-on-arrival handle (see the
        // method docs).
        let scope = grant.scope();
        drop(reservation);
        grant.defuse();
        Ok(RootHandle::new(self.instance, scope))
      }
      Ok(Err(err)) => Err(err),
      Err(_) => {
        self.driver_gone();
        Err(WatchRootError::Closed)
      }
    }
  }

  /// Replaces `root`'s coverage with `new_root` — the sanctioned transition
  /// between disjoint coverage states (the canonical case: widening `/a/b`
  /// to `/a`). The `RootHandle`, scope, and epoch stream survive. Two commit
  /// shapes:
  ///
  /// - **A WIDENING replace on the descending (inotify) backend** — the old
  ///   root strictly inside the new, same mount frame — is CONTINUOUS: the
  ///   live stream is kept and the new root adopted above the old one, so
  ///   coverage of the old subtree never gaps, no covering `Rescan` is
  ///   emitted, no epoch is bumped, and every change recorded before the
  ///   swap is still individually delivered (a
  ///   [`sync_root`](Self::sync_root) barrier across the widen resolves by
  ///   delivery, not domination). The newly covered ground is announced as
  ///   `Created` discovery, exactly like a fresh watch's initial crawl.
  /// - **Every other replace** (kernel-recursive backends, and disjoint or
  ///   narrowing targets on the descending backend) is make-before-break:
  ///   the new stream is live before the old one is retired, and the commit
  ///   delivers one epoch-bumped full-root `Rescan` instructing the consumer
  ///   to re-read the (re-rooted) world — which covers the swap window and
  ///   the newly covered delta alike.
  ///
  /// Locations are relative to [`root_path(handle)`](Self::root_path) at
  /// delivery time.
  ///
  /// Atomic-on-failure: every error leaves the old root's coverage
  /// untouched. NOT cancel-abortive: the reservation travels with the
  /// command and the driver commits independently, so dropping this future
  /// abandons the notification, never the swap.
  ///
  /// # Errors
  ///
  /// [`ReplaceRootError::NotFound`] / [`NotADirectory`](ReplaceRootError::NotADirectory)
  /// when `new_root` cannot anchor a watch;
  /// [`Overlaps`](ReplaceRootError::Overlaps) when it overlaps a DIFFERENT
  /// live root (the replaced root is exempt);
  /// [`UnknownRoot`](ReplaceRootError::UnknownRoot) /
  /// [`ReplaceInFlight`](ReplaceRootError::ReplaceInFlight) for handle
  /// misuse; [`BackendDiverged`](ReplaceRootError::BackendDiverged) when the
  /// replacement resolves to a different lowering profile;
  /// [`Retired`](ReplaceRootError::Retired) when the root died mid-swap
  /// (death wins — retry with a fresh [`watch`](Self::watch));
  /// [`Closed`](ReplaceRootError::Closed) once the watcher is closed;
  /// [`Source`](ReplaceRootError::Source) when the replacement stream could
  /// not start.
  pub async fn replace_root(
    &self,
    root: RootHandle,
    new_root: impl Into<PathBuf>,
  ) -> Result<(), ReplaceRootError> {
    if root.instance() != self.instance {
      return Err(ReplaceRootError::UnknownRoot);
    }
    let supplied = new_root.into();
    let canonical = std::fs::canonicalize(&supplied).map_err(|err| {
      if err.kind() == std::io::ErrorKind::NotFound {
        ReplaceRootError::NotFound { path: supplied }
      } else {
        ReplaceRootError::Source(SourceError::RootUnavailable {
          root: supplied,
          source: err,
        })
      }
    })?;
    let meta = std::fs::metadata(&canonical).ok();
    if !meta.as_ref().is_some_and(|meta| meta.is_dir()) {
      return Err(ReplaceRootError::NotADirectory { path: canonical });
    }
    let identity = meta.as_ref().and_then(identity_of);
    let reservation =
      Reservation::take(&self.roots, canonical.clone(), identity, Some(root.scope())).map_err(
        |err| match err {
          WatchRootError::Overlaps { path, existing } => {
            ReplaceRootError::Overlaps { path, existing }
          }
          _ => ReplaceRootError::UnknownRoot,
        },
      )?;

    let (reply, response) = futures_channel::oneshot::channel();
    let sent = self
      .commands
      .send(Command::Replace {
        scope: root.scope(),
        root: canonical,
        reservation,
        reply,
      })
      .await;
    if sent.is_err() {
      self.driver_gone();
      return Err(ReplaceRootError::Closed);
    }
    match response.await {
      Ok(outcome) => outcome,
      Err(_) => {
        self.driver_gone();
        Err(ReplaceRootError::Closed)
      }
    }
  }

  /// Stops watching a root, resolving once its native stream is torn down.
  /// Events already decoded may still trail out of the stream afterwards.
  ///
  /// # Errors
  ///
  /// - [`UnwatchError::UnknownRoot`] when the handle does not name a live
  ///   root of THIS watcher (never watched, already unwatched, torn down by
  ///   root death, or issued by a different watcher);
  /// - [`UnwatchError::Backlogged`] when this root already holds the maximum
  ///   number of awaited unwatches parked on a teardown that has not quiesced —
  ///   retryable, and the teardown the first call triggered is unaffected;
  /// - [`UnwatchError::NotQuiesced`] when the root is no longer watched but one
  ///   of its teardowns UNWOUND, so nothing ever proved the native stream
  ///   stopped. `Ok(())` is the release licence — it says the stream, its reader
  ///   and its callbacks are gone — and this error is precisely the case where
  ///   that cannot be said, so it is reported rather than folded into success;
  /// - [`UnwatchError::Closed`] when the watcher is already closed.
  pub async fn unwatch(&self, root: RootHandle) -> Result<(), UnwatchError> {
    // A foreign handle must be rejected before anything is sent: its scope
    // number can name THIS watcher's unrelated root.
    if root.instance() != self.instance {
      return Err(UnwatchError::UnknownRoot);
    }
    let (reply, response) = futures_channel::oneshot::channel();
    if self
      .commands
      .send(Command::Unwatch {
        scope: root.scope(),
        reply: Some(reply),
      })
      .await
      .is_err()
    {
      self.driver_gone();
      return Err(UnwatchError::Closed);
    }
    match response.await {
      // The registry entry is reclaimed by the driver's scope-dead signal;
      // nothing to reconcile here on either outcome.
      Ok(crate::driver::UnwatchAck::Torn) => Ok(()),
      // Refused before anything was parked: the driver's own state is unchanged,
      // so there is no registry claim to reason about either way.
      Ok(crate::driver::UnwatchAck::Backlogged) => Err(UnwatchError::Backlogged),
      // The teardown ran and the registry entry is reclaimed exactly as for
      // `Torn` — what is missing is the PROOF that the native stream stopped, so
      // the one thing `Ok(())` licences (releasing what the stream can still
      // reach) is withheld.
      Ok(crate::driver::UnwatchAck::Unproven) => Err(UnwatchError::NotQuiesced),
      Ok(crate::driver::UnwatchAck::Unknown) => {
        // The driver never knew the scope, so its single-writer registry
        // cannot still hold an entry for it.
        debug_assert!(
          !self
            .roots
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .contains_key(&root.scope()),
          "an unknown scope must have no registry entry"
        );
        Err(UnwatchError::UnknownRoot)
      }
      Err(_) => {
        self.driver_gone();
        Err(UnwatchError::Closed)
      }
    }
  }

  /// Requests teardown of a root like [`unwatch`](Self::unwatch), but as a NON-BLOCKING,
  /// REPLY-LESS fire-and-forget: it `try_send`s the ack-less command and reports whether the
  /// control channel accepted it. Unlike `unwatch` it never awaits — so the layer above can apply
  /// a queued release opportunistically without coupling a disjoint arm (and any `close` queued
  /// behind it) to that release's teardown latency.
  ///
  /// The driver tears a reply-less `Unwatch` down exactly like the awaited one — the same stream
  /// teardown and registry reclamation — it simply sends no acknowledgement, so the caller cannot
  /// observe completion (nor the scope-existed bool). A caller that must KNOW the root is gone — to
  /// clear a just-surfaced [`Overlaps`](WatchRootError::Overlaps) naming it — awaits
  /// [`unwatch`](Self::unwatch) instead; enqueued after this reply-less request on the one FIFO
  /// control channel, that awaited `unwatch` resolves only once the driver has processed this
  /// teardown and reclaimed the registry entry.
  ///
  /// Reports the request's [`RequestOutcome`]: [`Enqueued`](RequestOutcome::Enqueued) when the
  /// control channel accepted it; [`Busy`](RequestOutcome::Busy) when the channel is momentarily
  /// full, so the caller re-tries at its next opportunity; [`Rejected`](RequestOutcome::Rejected)
  /// when the request can NEVER be enqueued — `root` is a foreign handle (another watcher's brand)
  /// or the watcher is closed — so the caller must drop the intent rather than retry. Never blocks
  /// and never panics.
  pub fn request_unwatch(&self, root: RootHandle) -> RequestOutcome {
    // A foreign handle's scope number can name THIS watcher's unrelated root — reject it (never
    // retryable) before touching the channel, exactly as the awaited `unwatch` does.
    if root.instance() != self.instance {
      return RequestOutcome::Rejected;
    }
    match self.commands.try_send(Command::Unwatch {
      scope: root.scope(),
      reply: None,
    }) {
      Ok(()) => RequestOutcome::Enqueued,
      // A momentarily full channel is TRANSIENT — the caller re-tries at its next opportunity.
      Err(async_channel::TrySendError::Full(_)) => RequestOutcome::Busy,
      // A closed channel means the driver is gone — retrying can never succeed.
      Err(async_channel::TrySendError::Closed(_)) => RequestOutcome::Rejected,
    }
  }

  /// Mints a fresh [`SyncAdmission`]/[`SyncTicket`] pair for one
  /// [`sync_root`](Self::sync_root): the move-only admission
  /// [`sync_root`](Self::sync_root) consumes to admit the sync, and the `Copy`
  /// ticket held back for [`request_cancel_sync`](Self::request_cancel_sync). Both
  /// carry the SAME mint sequence, so the ticket cancels exactly the incarnation
  /// the admission admits.
  ///
  /// Pure memory: one `Relaxed` atomic increment, no channel, no allocation.
  /// Neither half has server-side state until the sync the admission admits is
  /// born, so minting a flood that is never used retains nothing. The mint is
  /// monotonic and driver-lifetime, so a sequence is never re-minted — and, the
  /// admission being move-only, that sequence is admitted at most once: the two
  /// facts that make a cancel through the ticket address at most one incarnation,
  /// ever.
  pub fn mint_sync_ticket(&self) -> (SyncAdmission, SyncTicket) {
    let seq = self.sync_tickets.fetch_add(1, Ordering::Relaxed);
    (
      SyncAdmission::new(self.instance, seq),
      SyncTicket::new(self.instance, seq),
    )
  }

  /// Places a **sync cookie** — the kernel-mediated barrier marker — under
  /// `dir` (which must lie within `root`'s coverage) and resolves with the
  /// path it landed at, at WRITE-complete.
  ///
  /// The cookie's whole value is the event its creation mints: that event
  /// rides the root's ordered queue BEHIND every change the backend reported
  /// before the write, so a caller that watches for the cookie on its own
  /// stream learns that all of those changes have already exited the
  /// pipeline. This method never waits for the observation — doing so from
  /// inside the watcher would deadlock the very stream the cookie must
  /// arrive on. Observation is the caller's (or the umbrella's) job.
  ///
  /// # The returned path is the only authority on where the cookie is
  ///
  /// The cookie does NOT land at `dir.join(name)`. It lands one level deeper, in
  /// a reserved-namespace directory the watcher creates and owns inside `dir`,
  /// because a cookie's removal must be anchored to a directory nobody else may
  /// write — a name in a directory the watched tree owns can be rebound between
  /// the removal's proof and its unlink, and no amount of re-checking closes
  /// that. Reap what this call RETURNED; a path re-derived from `dir` and `name`
  /// names nothing.
  ///
  /// The write is parked on the scope's coverage-settle fence: under a
  /// descending backend, a change inside a subtree whose per-directory watch
  /// is mid-re-arm was never kernel-reported and no queue ordering covers it,
  /// so the cookie must not be written until every re-arm terminal is
  /// armed-live or dropped-with-a-standing-`Rescan`. A kernel-recursive root
  /// has no re-arm work and writes immediately. A DEGRADED settle still
  /// writes: the loss already stood a covering `Rescan` ahead of the cookie,
  /// so the barrier holds by domination.
  ///
  /// Reap the cookie with [`request_remove_cookie`](Self::request_remove_cookie)
  /// once it has been observed, or cancel/reap it incarnation-precisely with
  /// [`request_cancel_sync`](Self::request_cancel_sync) through the paired
  /// [`SyncTicket`]. Both the create and the unlink are suppressed from consumer
  /// streams by the reserved-namespace rule at the layer that owns the namespace.
  ///
  /// `admission` is the move-only [`SyncAdmission`] half of a fresh
  /// [`mint_sync_ticket`](Self::mint_sync_ticket) pair, consumed BY VALUE to admit
  /// THIS sync. The type system thus forbids presenting one admission — one mint
  /// sequence — to two syncs, so a later cancel through the paired ticket can never
  /// alias a second incarnation. A pre-birth refusal hands the admission back in
  /// [`SyncRootDenied`] for a same-sequence retry (a refusal burns nothing); see
  /// the Errors section.
  ///
  /// # Errors
  ///
  /// Every failure is a [`SyncRootDenied`] carrying one of these
  /// [`SyncRootError`]s and — for a provably pre-birth refusal — the
  /// [`SyncAdmission`] to retry under the same sequence:
  /// [`SyncRootError::UnknownRoot`] for a foreign or dead handle;
  /// [`ForeignTicket`](SyncRootError::ForeignTicket) when `admission` was minted by
  /// a different watcher; [`BadCookieName`](SyncRootError::BadCookieName) when
  /// `name` is not a single normal component;
  /// [`DirOutsideRoot`](SyncRootError::DirOutsideRoot) when `dir` is not inside the
  /// root (including via `..` traversal);
  /// [`DirExcluded`](SyncRootError::DirExcluded) when `dir` is inside the root but
  /// under one of the configured exclusions, whose whole purpose is to keep that
  /// subtree's events off the stream the barrier waits on;
  /// [`Write`](SyncRootError::Write) when the
  /// create fails (a read-only tree surfaces as `PermissionDenied`);
  /// [`WriteInFlight`](SyncRootError::WriteInFlight) when a physical write for this
  /// root is already in flight; [`NameInUse`](SyncRootError::NameInUse) when a live
  /// sync of this watcher already holds `name`;
  /// [`TicketInUse`](SyncRootError::TicketInUse) when a live sync of this watcher
  /// already holds this admission's sequence;
  /// [`CleanupBacklog`](SyncRootError::CleanupBacklog) when the root's cookie
  /// cleanup backlog cap is reached; [`Retired`](SyncRootError::Retired) when the
  /// root died while the write was parked; [`Closed`](SyncRootError::Closed) once
  /// the watcher is closed. The admission is returned (retryable) for every refusal
  /// except [`Write`](SyncRootError::Write), [`Retired`](SyncRootError::Retired),
  /// and [`Closed`](SyncRootError::Closed), whose sequence is spent — re-mint to
  /// retry those.
  pub async fn sync_root(
    &self,
    root: RootHandle,
    dir: impl Into<PathBuf>,
    name: impl Into<String>,
    admission: SyncAdmission,
  ) -> Result<PathBuf, SyncRootDenied> {
    if root.instance() != self.instance {
      return Err(SyncRootDenied::classify(
        SyncRootError::UnknownRoot,
        admission,
      ));
    }
    // An admission minted by a DIFFERENT watcher must be refused before the send:
    // its sequence numbering is unrelated to this watcher's `by_ticket`, so honoring
    // it would let a foreign sequence alias one of our incarnations. Same
    // synchronous door as the foreign-handle check above.
    if admission.instance() != self.instance {
      return Err(SyncRootDenied::classify(
        SyncRootError::ForeignTicket,
        admission,
      ));
    }
    let dir = dir.into();
    let name = name.into();
    // The name the caller supplies must be a single normal component — a
    // separator, `..`, or absolute name would escape the directory on a join.
    if !crate::driver::is_normal_cookie_name(&name) {
      return Err(SyncRootDenied::classify(
        SyncRootError::BadCookieName { name },
        admission,
      ));
    }
    // The cookie must be reportable on THIS root's stream: a directory outside
    // its coverage could never mint an event the caller will see. Containment is
    // checked on LEXICALLY NORMALIZED components — a plain `starts_with` accepts
    // `<root>/../outside`, which escapes the tree.
    let Some(root_path) = self.root_path(root) else {
      return Err(SyncRootDenied::classify(
        SyncRootError::UnknownRoot,
        admission,
      ));
    };
    if !crate::driver::cookie_dir_within_root(&root_path, &dir) {
      return Err(SyncRootDenied::classify(
        SyncRootError::DirOutsideRoot {
          dir,
          root: root_path,
        },
        admission,
      ));
    }

    // The wire is UNCHANGED: build the seq-bearing ticket the driver still keys
    // `by_ticket` on FROM the admission (a plain read of its two fields, no move),
    // so the affine admission stays in this frame across the await — "returning" it
    // on a refusal is then a local move, never a trip across the channel.
    let ticket = SyncTicket::new(admission.instance(), admission.seq());

    let (reply, response) = futures_channel::oneshot::channel();
    if self
      .commands
      .send(Command::SyncRoot {
        scope: root.scope(),
        dir,
        name,
        ticket,
        reply,
      })
      .await
      .is_err()
    {
      self.driver_gone();
      return Err(SyncRootDenied::classify(SyncRootError::Closed, admission));
    }
    match response.await {
      // Admitted and written: the admission is spent — drop it, return the path.
      Ok(Ok(path)) => Ok(path),
      // A server-side refusal: `classify` returns the admission iff it is provably
      // pre-birth (the single audit point for the pre/post-birth split).
      Ok(Err(error)) => Err(SyncRootDenied::classify(error, admission)),
      Err(_) => {
        self.driver_gone();
        Err(SyncRootDenied::classify(SyncRootError::Closed, admission))
      }
    }
  }

  /// Reaps a sync cookie — a NON-BLOCKING, reply-less fire-and-forget unlink
  /// in the [`request_set_cover`](Self::request_set_cover) mold. Idempotent:
  /// a cookie already gone is success.
  ///
  /// Admission is GUARANTEED, and by TYPE rather than by sizing: the request is
  /// not a message about the cookie but a MARK ON IT — one bool on the obligation
  /// the driver has held since it admitted the sync. There is no queue to fill and
  /// no capacity to refuse, so no burst of watch/unwatch/sync traffic and no
  /// hostile flood can drop a genuine reap. A caller can only learn `path` from
  /// the [`sync_root`](Self::sync_root) that returned it, and the write publishes
  /// the landing path before that reply is sent, so a legitimately-held path
  /// always resolves.
  ///
  /// The driver OWNS every cookie it wrote and unlinks it at scope or driver
  /// teardown regardless, so even a request to an already-closed driver leaks
  /// nothing.
  ///
  /// # An unknown path is dropped, not queued
  ///
  /// A path naming no live cookie of this watcher is dropped right here — the same
  /// net effect as before (it was a no-op then too, merely discovered later), now
  /// by construction. The one nuance: a caller that PREDICTS a cookie's path
  /// before its `sync_root` reply arrives — possible only by re-deriving it
  /// out-of-contract — is dropped rather than acted on. Reap the path the reply
  /// gave you.
  ///
  /// # Path addresses the path's CURRENT holder
  ///
  /// A path resolves to whatever live cookie occupies it NOW, not the incarnation
  /// live when the request was issued. Two syncs that reuse one `name` in one `dir`
  /// sequentially land at one path: a reap delayed across the first sync's
  /// retirement and a second sync's claim of the same path reaps the SECOND. This
  /// is harmless for the intended reap-what-you-were-given use, and cannot arise
  /// for the umbrella (its cookie names are per-sync unique). A caller that both
  /// reuses names and needs incarnation precision reaps through its [`SyncTicket`]
  /// instead — [`request_cancel_sync`](Self::request_cancel_sync) addresses exactly
  /// one incarnation for all time and is a no-op after it resolves.
  pub fn request_remove_cookie(&self, path: impl Into<PathBuf>) {
    self.cleanup.request_remove(&path.into());
  }

  /// Cancels (or, after it resolves, incarnation-precisely reaps) the sync `ticket`
  /// keys — a NON-BLOCKING, reply-less fire-and-forget request in the
  /// [`request_remove_cookie`](Self::request_remove_cookie) mold. At ANY phase of
  /// that sync the driver reaps a delivered-but-unread cookie, refuses the claim of
  /// one whose write is still in flight (so it self-reaps), or retires one whose
  /// write was never dispatched. Idempotent; never blocks.
  ///
  /// `ticket` must be the one paired at mint with the [`SyncAdmission`] passed to
  /// the [`sync_root`](Self::sync_root) call being cancelled. Because that sequence
  /// is minted once and never re-minted AND the paired admission is move-only (so
  /// the sequence is admitted at most once), the ticket addresses exactly one
  /// incarnation for all time:
  ///
  /// - a foreign ticket (another watcher's brand) resolves nothing — dropped at
  ///   the door, so it can never alias one of this watcher's incarnations;
  /// - after the sync reaches its terminal the ticket resolves nothing — the
  ///   documented "a cancel after resolution is a no-op" is now true BY
  ///   CONSTRUCTION, not by a caller convention: the move-only admission makes
  ///   presenting one sequence twice a compile error, so `by_ticket[seq]` is
  ///   written at most once, and a successor admitted under the same cookie NAME
  ///   holds a DIFFERENT ticket and is unreachable through this one — a delayed
  ///   cancel can never kill it.
  ///
  /// Public because the umbrella `FsSource` — in a different crate — calls it from
  /// its `cancel_sync` seam method when the owner abandons an in-flight sync (a
  /// caller timeout, or a close winning the race), so a cookie the write already
  /// created but whose completion the owner never read can never orphan. Admission
  /// is GUARANTEED — the ticket is recorded when the sync is admitted, so a cancel
  /// has a record to mark whatever the sync's stage, including a write still in the
  /// pool — and the driver owns every cookie it writes regardless, so a cancel to
  /// an already-closed driver leaks nothing.
  pub fn request_cancel_sync(&self, ticket: SyncTicket) {
    // A foreign ticket's sequence is unrelated to this watcher's `by_ticket`;
    // resolving it could alias one of our incarnations, so drop it at the door
    // (the same brand check `sync_root` makes, here reply-lessly).
    if ticket.instance() != self.instance {
      return;
    }
    self.cleanup.request_cancel(ticket);
  }

  /// Reconciles a watched root's per-directory coverage to the `retained` cover **in place**,
  /// **bidirectionally**: it prunes every descended kernel watch strictly outside the cover
  /// — the canonical absolute paths whose coverage must survive — AND re-arms any retained
  /// subtree an earlier, narrower cover pruned, while leaving every already-covered retained
  /// subtree and the connecting ancestors from the root down to each of them armed. The
  /// retained-and-covered watches are **never re-armed**, so their events keep flowing with
  /// **no gap and no re-crawl**; only a previously-pruned corner is grown back.
  ///
  /// A **best-effort optimization** the layer above uses to reclaim (and, when a survivor
  /// returns, restore) inotify watch budget after a wide root outlived the consumer whose key
  /// equalled it (the set-cover design): it only ever removes coverage no consumer is subscribed under
  /// and only ever re-arms coverage a survivor needs, emits **no**
  /// [`Rescan`](crate::EventKind::Rescan), and is a **no-op** for a kernel-recursive backend
  /// (fanotify / FSEvents), whose single whole-subtree stream has no per-directory watches to
  /// prune or grow. A watch is kept by the prune iff its path lies under a retained prefix OR
  /// is an ancestor one descends from; a retained prefix not currently covered is re-armed.
  /// `retained` are the watcher's own canonical coordinates (as
  /// [`root_path`](Self::root_path) reports), so they line up with the watches' addressing.
  ///
  /// # The acknowledgement is an effect-completion fence
  ///
  /// The returned future resolves when the reconcile has **settled** — every re-arm the grow
  /// half started has quiesced, each terminal being an armed-live watch or a loss already
  /// signaled in-band — never when its effects were merely queued or applied to the in-memory
  /// tree. What settled means is the [`CoverOutcome`]:
  ///
  /// - [`Applied`](CoverOutcome::Applied): the window was clean — **writes under the retained
  ///   cover from the moment the ack resolves are delivered**. Shrinking, growing back, and
  ///   writing immediately on the resolved ack races nothing.
  /// - [`Degraded`](CoverOutcome::Degraded): the reconcile settled, but coverage loss was
  ///   signaled since the root's last settled window (a failed re-arm, an unreadable re-arm
  ///   read, an overflow, a teardown racing the fence): coverage may be partial, and the
  ///   covering [`Rescan`](crate::EventKind::Rescan) — already delivered in-band — dominates
  ///   the gap. The loss memory is per-root, not per-fence: a loss that landed BEFORE this
  ///   reconcile (with no reconcile in flight) both degrades this acknowledgement and drops
  ///   the root's recorded coverage claim, so re-issuing the same cover re-attempts the FULL
  ///   grow — re-proving the requested coverage rather than trusting the pre-loss record —
  ///   and a clean re-issue then resolves `Applied` honestly.
  /// - [`Recursive`](CoverOutcome::Recursive): the root is backed by a kernel-recursive
  ///   backend, whose coverage never narrowed — nothing to reconcile, answered immediately.
  /// - [`Skipped`](CoverOutcome::Skipped): no reconcile ran — the scope is unknown to the
  ///   driver ([`UnknownRoot`](SkipReason::UnknownRoot)), not yet publicly live
  ///   ([`NotLive`](SkipReason::NotLive)), or the cover was refused
  ///   ([`RefusedCover`](SkipReason::RefusedCover)). Prior coverage is untouched.
  ///
  /// A root torn down mid-fence (unwatch, root death) settles `Degraded` — its terminal
  /// `Rescan` covers the caller. Several in-flight reconciles of one root apply in command
  /// order (latest wins) and settle together, each acknowledged with the shared window's
  /// verdict.
  ///
  /// # Errors
  ///
  /// - [`UnwatchError::UnknownRoot`] when `root` was issued by a DIFFERENT watcher — rejected
  ///   before anything is sent, exactly as [`unwatch`](Self::unwatch) does (a live handle of
  ///   this watcher whose root just died answers `Ok(Skipped(UnknownRoot))` instead: the
  ///   driver, not the handle check, is the authority on scope liveness);
  /// - [`UnwatchError::Closed`] when the watcher is already closed, or closes (or its driver
  ///   dies) mid-fence — the ratified close semantics drop parked acknowledgements rather
  ///   than resolve them over a torn-down driver.
  pub async fn set_cover(
    &self,
    root: RootHandle,
    retained: Vec<PathBuf>,
  ) -> Result<CoverOutcome, UnwatchError> {
    // A foreign handle's scope number can name THIS watcher's unrelated root — reject
    // before anything is sent, exactly as `unwatch` does.
    if root.instance() != self.instance {
      return Err(UnwatchError::UnknownRoot);
    }
    let (reply, response) = futures_channel::oneshot::channel();
    if self
      .commands
      .send(Command::SetCover {
        scope: root.scope(),
        retained,
        reply: Some(reply),
      })
      .await
      .is_err()
    {
      self.driver_gone();
      return Err(UnwatchError::Closed);
    }
    match response.await {
      Ok(outcome) => Ok(outcome),
      // The driver dropped the reply: it closed (or died) mid-fence, so the reconcile's
      // settlement was never observed. Surface the closed state like `unwatch` — the layer
      // above keeps the (harmless) over-broad coverage and re-issues against a live watcher.
      Err(_) => {
        self.driver_gone();
        Err(UnwatchError::Closed)
      }
    }
  }

  /// Requests a coverage reconcile like [`set_cover`](Self::set_cover), but as a NON-BLOCKING,
  /// REPLY-LESS fire-and-forget: it `try_send`s the ack-less command and reports whether the
  /// control channel accepted it. Unlike `set_cover` it never awaits — so it applies a deferred
  /// reconcile PROMPTLY, without waiting for a later watcher operation to carry it (a
  /// `Covered`-outside grow arms nothing, so a queue-only reconcile would otherwise wait for an
  /// unrelated arm).
  ///
  /// The driver applies a reply-less `SetCover` exactly like the awaited one — the same in-place
  /// bidirectional reconcile, the same latest-wins ordering against other covers of the root —
  /// it simply sends no acknowledgement: an [`Enqueued`](RequestOutcome::Enqueued) outcome says the
  /// request was accepted, nothing about when (or whether) the retained cover's kernel coverage is
  /// live. A caller that must know — to write into a just-regrown subtree without racing the re-arm
  /// — awaits [`set_cover`](Self::set_cover) instead, whose acknowledgement is the effect-completion
  /// fence; a reconcile requested here still participates in that fence's bookkeeping (its
  /// window is observed at the next settlement), it just has no reply to resolve.
  ///
  /// Reports the request's [`RequestOutcome`]: [`Enqueued`](RequestOutcome::Enqueued) when the
  /// control channel accepted it; [`Busy`](RequestOutcome::Busy) when the channel is momentarily
  /// full, so the caller re-tries at its next opportunity; [`Rejected`](RequestOutcome::Rejected)
  /// when the request can NEVER be enqueued — `root` is a foreign handle (another watcher's brand)
  /// or the watcher is closed — so the caller must drop the intent rather than retry. Never blocks
  /// and never panics.
  pub fn request_set_cover(&self, root: RootHandle, retained: Vec<PathBuf>) -> RequestOutcome {
    // A foreign handle's scope number can name THIS watcher's unrelated root — reject it (never
    // retryable) before touching the channel, exactly as the awaited `set_cover` does.
    if root.instance() != self.instance {
      return RequestOutcome::Rejected;
    }
    match self.commands.try_send(Command::SetCover {
      scope: root.scope(),
      retained,
      reply: None,
    }) {
      Ok(()) => RequestOutcome::Enqueued,
      // A momentarily full channel is TRANSIENT — the caller re-tries at its next opportunity.
      Err(async_channel::TrySendError::Full(_)) => RequestOutcome::Busy,
      // A closed channel means the driver is gone — retrying can never succeed.
      Err(async_channel::TrySendError::Closed(_)) => RequestOutcome::Rejected,
    }
  }

  /// The driver is gone (its command channel closed without an orderly
  /// confirmation): clear the read view so the registry is empty-and-honest
  /// rather than frozen at its last state. The single-writer rule is intact —
  /// there is no writer left to race.
  fn driver_gone(&self) {
    let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
    set.entries.clear();
  }

  /// The canonical path of a watched root, if the handle names a live root
  /// of this watcher.
  pub fn root_path(&self, root: RootHandle) -> Option<PathBuf> {
    if root.instance() != self.instance {
      return None;
    }
    self
      .roots
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .entries
      .get(&root.scope())
      .map(|entry| entry.path.as_ref().clone())
  }

  /// The backend the spawn barrier selected for a watched root — the capability
  /// report for a `Backend::Auto` outcome (fanotify when the privileged probe
  /// passed, inotify on the fallback). `None` when the handle does not name a
  /// live root of this watcher (never watched, already gone, or foreign), which
  /// is indistinguishable from a root that died right after `watch` returned.
  pub fn backend_of(&self, root: RootHandle) -> Option<BackendKind> {
    if root.instance() != self.instance {
      return None;
    }
    self
      .roots
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .entries
      .get(&root.scope())
      .map(|entry| entry.backend)
  }

  /// A pollable snapshot of a watched root's backend internals (design §4.9):
  /// the fanotify admission map's size and generation, its seed/reseed walk
  /// timings and count, and the batch-memo hit/miss tallies. `None` unless the
  /// handle names a LIVE fanotify root of this watcher — a non-fanotify backend
  /// keeps no such state, and a handle that never named a live root (never
  /// watched, already gone, or foreign) reports `None` just as
  /// [`backend_of`](Self::backend_of) does.
  ///
  /// A snapshot, not a live view: the returned [`BackendStats`] holds the counter
  /// values at the moment of the call. Poll it to watch the map grow or the memo
  /// hit rate move; it costs one read-lock and a handful of atomic loads.
  pub fn backend_stats(&self, root: RootHandle) -> Option<BackendStats> {
    if root.instance() != self.instance {
      return None;
    }
    self
      .roots
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .entries
      .get(&root.scope())
      .and_then(|entry| entry.stats.as_ref())
      .map(|stats| stats.snapshot())
  }

  /// The number of registry entries — live roots only, by construction.
  // Consumed only by the runtime-backed suite, so the gate matches it: a
  // featureless test build (miri, the bare powerset combo) has no consumer.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn registry_len(&self) -> usize {
    self
      .roots
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .entries
      .len()
  }

  /// The next event, or `None` once the watcher is closed and drained.
  #[inline]
  pub async fn next(&mut self) -> Option<Event> {
    futures_util::StreamExt::next(self).await
  }

  /// Closes the watcher: tears every native stream down — including streams
  /// still being spawned or torn down on the blocking pool, which are settled
  /// inside the close accounting — sweeps every cookie the driver ever wrote and
  /// waits for each unlink to CONFIRM (retrying a transiently-failing one within
  /// the grace), drains what already arrived, and resolves once the driver has
  /// quiesced. The final drain into a full event buffer is best-effort, and
  /// quiescence is bounded by a ~1 s grace: a blocking pool wedged past it no
  /// longer holds the close.
  ///
  /// `Ok` PROVES two things: every native stream was torn down, AND every sync
  /// cookie this watcher ever wrote was confirmed removed from disk. A stream
  /// spawn/teardown or a cookie unlink still outstanding past the grace is
  /// reported, never papered over (a wedged spawn may already own a live stream:
  /// the backend starts it and then runs post-live metadata reads inside the same
  /// call).
  ///
  /// # Errors
  ///
  /// [`CloseError::Stopped`] when the driver stopped before confirming (a panic
  /// or an external teardown) — including when the close command cannot be
  /// delivered at all — and [`CloseError::NotQuiesced`] when work was still
  /// outstanding at grace expiry: stream spawns or teardowns still executing, or
  /// cookies not yet confirmed removed (a hung unlink, or one whose retries the
  /// grace outran). A wedged stream stays live until its call returns (a wedged
  /// spawn's self-reclaims via its dropped result once the wedge clears; a wedged
  /// teardown's is unreachable until the call returns); an unremoved cookie is
  /// still swept best-effort as the driver drops. The OS reclaims streams at
  /// process exit either way.
  pub async fn close(self) -> Result<(), CloseError> {
    self.close_in_place().await
  }

  /// [`close`](Self::close) for a watcher OWNED BY ANOTHER OBJECT — identical
  /// operation, identical result, borrowing instead of consuming.
  ///
  /// `close` takes `self` so an orderly program cannot keep using a watcher it
  /// has shut down, and that is the right default. It is the wrong shape for a
  /// watcher embedded in a larger type that itself has no `self`-consuming
  /// teardown seam: without this, such an owner can only end the watcher by
  /// DROPPING it, which starts the same teardown but can neither await it nor
  /// report it — so the lower layer's `NotQuiesced` evidence, the strongest
  /// lifecycle fact this crate produces, is thrown away exactly where an upper
  /// `close()` wanted to forward it. The standard `tributaries` filesystem
  /// source is that owner.
  ///
  /// Calling it more than once is safe and honest rather than idempotent: the
  /// first call closes the driver, so a second reports
  /// [`Stopped`](CloseError::Stopped) — no quiescence was proven BY THAT CALL.
  ///
  /// # Errors
  ///
  /// Exactly as [`close`](Self::close).
  pub async fn close_in_place(&self) -> Result<(), CloseError> {
    let (reply, response) = futures_channel::oneshot::channel();
    if self.commands.send(Command::Close { reply }).await.is_err() {
      // The receiver vanished while this watcher still held a sender: the
      // driver stopped (a panic, an external abort) without acknowledging
      // this close, and whatever spawn/teardown work it held went
      // unobserved — that is not proof of quiescence.
      self.driver_gone();
      return Err(CloseError::Stopped);
    }
    match response.await {
      Ok(0) => Ok(()),
      Ok(pending) => Err(CloseError::NotQuiesced { pending }),
      Err(_) => {
        self.driver_gone();
        Err(CloseError::Stopped)
      }
    }
  }

  /// Wraps a scope-stamped change into the consumer event. Deliveries carry
  /// their own root path, so assembly is total — a dead, already-reclaimed
  /// scope's trailing changes (above all its terminal `Rescan`) still
  /// assemble.
  fn assemble(&self, scope: ScopeId, root_path: &Path, change: &Change) -> Event {
    Event::from_change(RootHandle::new(self.instance, scope), root_path, change)
  }
}

/// The stat-read object identity of a root, deciding disjointness where byte
/// forms cannot (spelling aliases on case-insensitive volumes).
fn identity_of(meta: &std::fs::Metadata) -> Option<RootIdentity> {
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    Some(RootIdentity::new(meta.dev(), meta.ino().into()))
  }
  #[cfg(not(unix))]
  {
    let _ = meta;
    None
  }
}

impl<R> Stream for Watcher<R> {
  type Item = Event;

  fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    let this = self.get_mut();
    match this.events.as_mut().poll_next(cx) {
      Poll::Ready(Some((scope, root, change))) => {
        Poll::Ready(Some(this.assemble(scope, root.as_path(), &change)))
      }
      Poll::Ready(None) => Poll::Ready(None),
      Poll::Pending => Poll::Pending,
    }
  }
}
