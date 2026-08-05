//! The default local-filesystem [`Source`]: [`FsSource`] over one
//! [`tributary_fs::Watcher`], gated behind the crate's default `fs` feature.
//!
//! This is the fs half of the seam [`source`](crate::source) defines: it binds
//! `C = OsString` (a path's components) to real kernel watches, and it is the only
//! place the crate maps a key to a path and reverses a raw filesystem event back into
//! a key. The neutral traits, carriers, and their contracts live in the parent module;
//! everything here is the binding's own business.

use std::{
  collections::{HashMap, HashSet, VecDeque},
  ffi::OsString,
  path::PathBuf,
  vec::Vec,
};

use agnostic_lite::RuntimeLite;
use tributary_fs::{
  CloseError as FsCloseError, CoverOutcome, Event as FsEvent, EventKind as FsEventKind,
  ReplaceRootError, RequestOutcome, RootHandle, SkipReason, SourceError, SyncRootDenied,
  SyncRootError, SyncTicket, UnwatchError as FsUnwatchError, WatchRootError, Watcher,
  WatcherOptions,
};
use tributary_proto::Interest;

use super::{Armed, Source, SourceEvent, SyncToken};
use crate::{
  error::{BuildError, FaultKind, SourceCloseError, SourceFault, SyncError, WatchError},
  event::{EventKind, path_components},
};

#[cfg(test)]
mod tests;

/// The default source: the local filesystem, over one [`tributary_fs::Watcher`].
///
/// Binds `C = OsString` (a path's [components](std::path::Path::components)) to real
/// kernel watches. This is the only place the crate maps a key to a path and reverses a
/// raw filesystem event back into a key.
pub struct FsSource<R> {
  watcher: Watcher<R>,
  /// Roots whose release was requested (via the synchronous [`disarm`](Source::disarm)) but not yet
  /// handed to the [`Watcher`]'s control channel, each paired with the released root's **canonical
  /// path** captured at `disarm` time (while it was still live in the registry). [`arm`](Source::arm)
  /// drains this queue two ways (contract clause 2): (1) **opportunistically** it walks
  /// the queue and hands each entry to the watcher via the NON-BLOCKING, reply-less
  /// [`request_unwatch`](tributary_fs::Watcher::request_unwatch) — moving it to the in-flight
  /// [`enqueued`](Self::enqueued) sidecar — so the arm AWAITS NOTHING for a release that does not
  /// overlap it (keeping clause 5 eventual: every queued release is enqueued the moment the control
  /// channel has room), and (2) **on demand** it resolves any
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps) the watch attempt reports by AWAITING an
  /// [`unwatch`](tributary_fs::Watcher::unwatch) of the entry the watcher *named* as the conflict
  /// (identity-aware — it catches case/normalization aliases) and retrying. The only release work a
  /// single arm AWAITS is (2) — bounded by that arm's OWN overlapping conflicts, never the (disjoint)
  /// backlog — so a caller-bounded `Watch`, and any [`close`](crate::Tributaries::close) queued behind
  /// it, never waits on unrelated teardown latency. The [`disarm`](Source::disarm) DOOR drops any
  /// release whose root already answered [`root_path`](tributary_fs::Watcher::root_path) `None` (a
  /// foreign brand or an already-torn-down own root), so every entry here carries `Some(path)` and
  /// names a live-at-disarm root of THIS instance — the stored path is always present for the (2)
  /// exact-match (the `Option` is the shape shared with [`enqueued`](Self::enqueued); the door makes
  /// `Some` an invariant, not merely a possibility). Bounded by the live-root count: each
  /// generation-unique handle is released at most once, and a hostile `disarm(fresh_foreign)` flood
  /// adds nothing — every foreign disarm dies at the door.
  pending_releases: VecDeque<(RootHandle, Option<PathBuf>)>,
  /// Requested releases whose reply-less [`request_unwatch`](tributary_fs::Watcher::request_unwatch)
  /// the control channel ACCEPTED but the watcher registry may not yet reflect — the **in-flight**
  /// releases. Kept so a conflicting later arm can still resolve an
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps) the watcher NAMES against a release whose
  /// fire-and-forget teardown has not landed yet: the entry is no longer in
  /// [`pending_releases`](Self::pending_releases), so without this sidecar the exact-match would miss
  /// and the arm would wrongly surface the overlap. On such a match the arm AWAITS an
  /// [`unwatch`](tributary_fs::Watcher::unwatch) of the named handle — which, enqueued after the
  /// reply-less request on the one FIFO channel, forces the teardown to land — then retries. Pruned at
  /// each arm's top of every entry the watcher has since applied
  /// ([`root_path`](tributary_fs::Watcher::root_path) `None`) — once the registry has forgotten a root
  /// it can never NAME it — so it is bounded by the in-flight (requested-but-unapplied) release count,
  /// never the watcher's lifetime.
  enqueued: Vec<(RootHandle, Option<PathBuf>)>,
  /// Union mirror of the requested releases — queued in [`pending_releases`](Self::pending_releases)
  /// AND in-flight in [`enqueued`](Self::enqueued) — for O(1) [`root_key`](Source::root_key) liveness
  /// answers (contract clause 3: a requested release is logically dead **immediately**, before its
  /// teardown lands). A handle stays dead-marked here exactly while the watcher still reports its root
  /// live; the same top-of-arm prune drops the mark the instant
  /// [`root_path`](tributary_fs::Watcher::root_path) takes over answering `None`, so the invariant
  /// "`root_key` is `None` from `disarm` until the handle is fully gone" holds unbroken while the set
  /// stays bounded by in-flight releases.
  pending_set: HashSet<RootHandle>,
  /// Prunes ([`set_cover`](Source::set_cover) requests) the watcher's control channel was momentarily
  /// too full to accept — the contract's full-channel deferral (clause 3), **latest-wins per handle**
  /// (clause 6): a re-request for a queued handle REPLACES its stale snapshot, and an awaited
  /// [`grow`](Source::grow) for the handle REMOVES the queued prune outright (the grow's fresh cover
  /// is newer and its applied coverage authoritative). Re-forwarded via
  /// [`flush_deferred_prunes`](Self::flush_deferred_prunes) at the next op that touches the watcher
  /// (`set_cover`, `grow`, `disarm`, `arm`). Bounded by the live-root count (one entry per handle);
  /// entries for since-dead roots self-drain on the next flush (the reply-less request enqueues and
  /// the driver skips the unknown scope). Losslessness is NOT required here (clause 5): entries still
  /// queued at `Drop` are simply dropped — an unpruned root is merely over-broad, self-healing.
  deferred_prunes: HashMap<RootHandle, Vec<PathBuf>>,
  /// The ticket (and the token that minted it) for each root's IN-FLIGHT
  /// [`begin_sync`](Source::begin_sync) — the incarnation-precise cancel address
  /// the abandonment path consumes. [`begin_sync`](Source::begin_sync) inserts the
  /// entry BEFORE it awaits [`Watcher::sync_root`] and removes it on a normal
  /// return (Ok or Err); if that future is DROPPED mid-await (a caller cancel or a
  /// close won the owner's race), the entry deliberately REMAINS, and
  /// [`cancel_sync`](Source::cancel_sync) takes it to address the sync by the
  /// watcher-minted [`SyncTicket`] — the only precise handle on a write the owner
  /// abandoned before it learned the cookie path. The stored [`SyncToken`] is the
  /// umbrella-level incarnation guard: a `cancel_sync` whose token does not match
  /// the stored one is stale (for an older incarnation) and dropped. Bounded by the
  /// live-root count, and in practice ≤ 1 (the owner awaits `begin_sync` inline, so
  /// at most one sync is in flight at a time); entries for since-released roots are
  /// pruned at the top of [`arm`](Source::arm) alongside `pending_set`/`enqueued`.
  pending_syncs: HashMap<RootHandle, (SyncToken, SyncTicket)>,
  /// Awaited [`Watcher::set_cover`] round-trips [`grow`](Source::grow) actually performed — proves
  /// the kernel-recursive short-circuit skipped the round-trip.
  #[cfg(test)]
  cover_round_trips: usize,
  /// Deferred prunes successfully re-forwarded by [`flush_deferred_prunes`](Self::flush_deferred_prunes)
  /// — distinguishes a grow's SUPERSEDED (removed, never forwarded) queued prune from a flushed one.
  #[cfg(test)]
  deferred_forwards: usize,
  /// [`Watcher::request_cancel_sync`] calls [`cancel_sync`](Source::cancel_sync) actually issued —
  /// distinguishes a stale/mismatched-token cancel (touches nothing) from a matching-token cancel of
  /// a live entry, which removes it and fires the watcher-side cancel.
  #[cfg(test)]
  sync_cancels_requested: usize,
}

impl<R> core::fmt::Debug for FsSource<R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("FsSource")
      .field("watcher", &self.watcher)
      .finish()
  }
}

impl<R: RuntimeLite> FsSource<R> {
  /// Builds a local-filesystem source, spawning the underlying `tributary-fs` watcher on
  /// `R`.
  ///
  /// # Errors
  ///
  /// [`BuildError::Source`] when the underlying `tributary-fs` watcher cannot be built.
  pub fn new(options: WatcherOptions) -> Result<Self, BuildError> {
    // The only fs build failure is a configuration bound (too many exclusion paths); it
    // has no dedicated neutral kind, so it folds to `Other` with the whole fs error
    // preserved in the box for `BuildError::as_fs` recovery.
    let watcher = Watcher::new(options)
      .map_err(|err| BuildError::Source(SourceFault::new(FaultKind::Other).with_source(err)))?;
    Ok(Self {
      watcher,
      pending_releases: VecDeque::new(),
      enqueued: Vec::new(),
      pending_set: HashSet::new(),
      deferred_prunes: HashMap::new(),
      pending_syncs: HashMap::new(),
      #[cfg(test)]
      cover_round_trips: 0,
      #[cfg(test)]
      deferred_forwards: 0,
      #[cfg(test)]
      sync_cancels_requested: 0,
    })
  }
}

// The deferral queue and the Source seam below are channel and registry work:
// no method names an `R` item (the runtime bound lives on `new`, the one
// place the watcher driver is spawned).
impl<R> FsSource<R> {
  /// Queues a prune the control channel refused (momentarily full), **latest-wins per handle**
  /// ([`Source::set_cover`] contract clause 6): a newer request for the same handle replaces the
  /// stale snapshot, so a later flush never applies an outdated cover.
  fn defer_prune(&mut self, handle: RootHandle, retained: Vec<PathBuf>) {
    self.deferred_prunes.insert(handle, retained);
  }

  /// Re-forwards every deferred prune the control channel now has room for — the re-forward half of
  /// the full-channel deferral ([`Source::set_cover`] contract clause 3), called at the top of every
  /// op that touches the watcher (`set_cover`, `grow`, `disarm`, `arm`). Purely non-blocking: each
  /// entry is handed over via the reply-less [`Watcher::request_set_cover`] `try_send`; an entry the
  /// channel still refuses stays queued for the next flush (or is dropped at `Drop` — clause 5,
  /// losslessness not required for a prune).
  fn flush_deferred_prunes(&mut self) {
    // Split-borrow: the watcher is a shared reborrow so `retain` can mutate the map.
    let watcher = &self.watcher;
    #[cfg(test)]
    let mut forwards = 0usize;
    self.deferred_prunes.retain(|handle, retained| {
      match watcher.request_set_cover(*handle, retained.clone()) {
        // Forwarded onto the control channel — drop the deferral (its work is on its way).
        RequestOutcome::Enqueued => {
          #[cfg(test)]
          {
            forwards += 1;
          }
          false
        }
        // The channel is momentarily full — keep the deferral for the next flush (clause 3). This
        // is the ONLY retain: a genuinely full channel is transient, so a genuine prune re-tries.
        RequestOutcome::Busy => true,
        // A dead or foreign root (never enqueueable): pruning it is pointless (clause 5 does not
        // require prune losslessness). DROP it — a retained never-valid entry drives the
        // monotone growth (the retired `bool` read this as backpressure and re-tried it forever).
        RequestOutcome::Rejected => false,
      }
    });
    #[cfg(test)]
    {
      self.deferred_forwards += forwards;
    }
  }
}

/// How many pending releases one `arm` hands to the watcher's control channel via the
/// reply-less [`Watcher::request_unwatch`] — the HARD per-arm opportunistic budget (
/// ). A channel-full stop is not a bound (the driver drains concurrently, so `try_send`
/// can keep succeeding), and every reply-less `Unwatch` handed off here is processed BEFORE this
/// arm's own `watch` command on the same FIFO control channel — so an unbounded walk would couple
/// the caller (and any close behind it) to the entire unrelated release backlog. A fixed few per
/// arm keeps that pre-watch FIFO work O(1) while preserving clause 5's eventual application
/// (later arms, the conflict-triggered path, or `Drop` take the rest).
const OPPORTUNISTIC_RELEASE_HANDOFFS: usize = 2;

impl<R> Source<OsString> for FsSource<R> {
  type Handle = RootHandle;

  fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
    // Resolve the path with the SAME canonicalization `arm` applies (via
    // `tributary_fs::Watcher::watch`, which `std::fs::canonicalize`s its root before spawning the
    // stream), so the umbrella classifies and commits on the coordinate events arrive under. A
    // non-existent or unreadable path fails here — the umbrella refuses to commit a key backed by
    // no real location, rather than accepting it silently and then never delivering an event.
    // Idempotent on an already-canonical path (`canonicalize` is a fixed point there), as the
    // trait's idempotence contract requires.
    let supplied = key_to_path(key);
    let canonical = std::fs::canonicalize(&supplied).map_err(|source| {
      // Classify by the io error's kind — the two cases a caller can act on distinctly
      // (a missing path vs a permission wall) — and fold the rest to `Other`; the whole
      // io error is preserved in the box either way. The key's display form is this
      // binding's own rendering (the neutral error is not path-typed).
      let kind = match source.kind() {
        std::io::ErrorKind::NotFound => FaultKind::NotFound,
        std::io::ErrorKind::PermissionDenied => FaultKind::PermissionDenied,
        _ => FaultKind::Other,
      };
      WatchError::canonicalize(
        supplied.display().to_string(),
        SourceFault::new(kind).with_source(source),
      )
    })?;
    Ok(path_components(&canonical))
  }

  async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, RootHandle>, WatchError> {
    // (0) MAINTENANCE: drop every in-flight release the watcher has SINCE applied, and its dead-mark.
    // Once the watcher's registry has forgotten a root, it can never NAME it as a conflict again, and
    // `root_path` now answers the same `None` the mirror did — so pruning here keeps both the in-flight
    // sidecar and `pending_set` bounded by the in-flight (requested-but-unapplied) release count (never
    // the watcher's lifetime), while preserving the clause-3 invariant: a handle stays dead-marked in
    // `pending_set` exactly while the watcher still reports its root live, and the prune drops the mark
    // the instant `root_path` takes over answering `None`. Split-borrow: `watcher` is a shared reborrow
    // so each `retain` can mutate a DIFFERENT field.
    {
      let watcher = &self.watcher;
      self
        .enqueued
        .retain(|(handle, _)| watcher.root_path(*handle).is_some());
      self
        .pending_set
        .retain(|handle| watcher.root_path(*handle).is_some());
      // A released/retired root can never have another in-flight sync cancelled
      // against it, so drop its cancel-address entry here too (belt-and-suspenders:
      // the abandonment path already removes it via `cancel_sync`, and the owner's
      // teardown drops the whole source). Keeps `pending_syncs` bounded by the live
      // handles, exactly like `pending_set`/`enqueued`.
      self
        .pending_syncs
        .retain(|handle, _| watcher.root_path(*handle).is_some());
    }
    // An arm touches the watcher, so re-forward any full-channel-deferred prunes first
    // (set_cover contract clause 3) — non-blocking `try_send`s, nothing awaited.
    self.flush_deferred_prunes();

    // (a) OPPORTUNISTIC NON-BLOCKING application: hand a HARD-BOUNDED few pending releases to the
    // watcher's control channel via the reply-less `request_unwatch` (a `try_send`). On acceptance
    // the entry moves from the queue to the in-flight `enqueued` sidecar and STAYS dead-marked in
    // `pending_set` (it is logically dead until its teardown lands, clause 3). This AWAITS NOTHING — a
    // disjoint arm is decoupled from every release's teardown latency. The bound is a
    // FIXED per-arm handoff budget, NOT the channel-full stop: on a multi-threaded
    // runtime the driver drains the channel concurrently, so try_send could keep succeeding and an
    // unbounded walk would enqueue the ENTIRE unrelated backlog ahead of this arm's own watch
    // command on the same FIFO channel — coupling the caller (and any close behind it) to unrelated
    // release processing. At most a fixed few per arm keeps that pre-watch FIFO work O(1); the rest
    // stay queued for later arms, the conflict-triggered path (c), or `Drop` (clause 5's three
    // routes unchanged). This is NOT the correctness mechanism — (c) is — so enqueuing an unrelated
    // release here is harmless (it was going to be released anyway).
    for _ in 0..OPPORTUNISTIC_RELEASE_HANDOFFS {
      let Some(entry) = self.pending_releases.pop_front() else {
        break;
      };
      // `entry.0` is `Copy` (a `RootHandle`), so the try_send borrows nothing of `entry`.
      match self.watcher.request_unwatch(entry.0) {
        // Accepted onto the control channel: move queue → in-flight sidecar (the success path).
        RequestOutcome::Enqueued => self.enqueued.push(entry),
        // The channel is momentarily full: return the entry to the FRONT (FIFO preserved) and
        // stop — the driver drains concurrently, so a later arm retries it (backpressure, clause
        // 5's eventual application). This is the ONLY re-front: a full channel is transient.
        RequestOutcome::Busy => {
          self.pending_releases.push_front(entry);
          break;
        }
        // Never enqueueable — a foreign brand or a closed watcher. DROP the entry AND its
        // dead-mark, then CONTINUE (do NOT re-front): re-fronting a never-valid entry wedges the
        // queue permanently and starves every genuine release behind it.
        // The `disarm` door already keeps foreign brands out of the queue; this is the
        // belt-and-suspenders drain-side kill, and it lets the genuine releases behind it drain.
        RequestOutcome::Rejected => {
          self.pending_set.remove(&entry.0);
        }
      }
    }
    // (b)+(c) Arm the root, resolving on demand any `Overlaps` the watcher reports against a
    // released-but-still-lingering root. Roots are always armed `Interest::all` (design §4): the kernel
    // watch never narrows what it collects, so a covered subscription can ask for any kind and the root
    // already carries it (interest becomes a pure fan-out gate at the umbrella).
    //
    // The correctness guarantee — a conforming source never SURFACES an `Overlaps` for a root whose
    // release was requested, QUEUED or IN-FLIGHT (disarm contract clause 2) — is upheld here by
    // construction: the WATCHER itself names the conflicting `existing` root (it rejects by
    // object/ancestor IDENTITY, so it catches case/normalization aliases a byte-prefix overlap test
    // would miss). While the watcher's registry still reports a requested release live
    // (so it can name it), that release is in `pending_releases` (not yet handed over) OR in `enqueued`
    // (handed over, teardown not landed) — never neither — so the named `existing` EXACT-matches one of
    // the two. Retry is a **structural progress bound**, not a fixed cap: on a match
    // remove exactly that entry, AWAIT its `unwatch`, and re-attempt. An `enqueued` match awaits an
    // acked `unwatch` that — enqueued after the earlier reply-less request on the one FIFO channel —
    // resolves only once the driver has processed that teardown and reclaimed the registry entry, so
    // the retry sees the root gone. Each retry strictly SHRINKS `pending_releases` + `enqueued` (one
    // exact-matched entry removed, neither grows in the loop), so it terminates in ≤ (queued + in-flight)
    // retries with no arbitrary ceiling (the common case is ≤1; an ancestor arm over N released
    // descendants is bounded by the N the watcher names one at a time — however large N is). A rejection
    // whose named conflict is in NEITHER set — a genuine LIVE conflict (an umbrella-side disjointness
    // bug), never a lingering released root — surfaces the overlap IMMEDIATELY: there is no index-0
    // fallback, so we never unwatch an unrelated pending root to mask a real conflict.
    let arm_path = key_to_path(key);
    // Progress tripwire (debug-only): the exact-match retry can run at most one more iteration than the
    // queued-plus-in-flight release count was deep, since that total strictly shrinks each retry and a
    // non-matching rejection exits immediately.
    #[cfg(debug_assertions)]
    let initial_pending = self.pending_releases.len() + self.enqueued.len();
    #[cfg(debug_assertions)]
    let mut iterations = 0usize;
    let handle = loop {
      #[cfg(debug_assertions)]
      {
        iterations += 1;
        debug_assert!(
          iterations <= initial_pending + 1,
          "FsSource::arm conflict-retry exceeded (queued + in-flight)+1 iterations — the queued and \
           in-flight release sets must strictly shrink each retry (structural progress bound)"
        );
      }
      match self.watcher.watch(arm_path.clone(), Interest::all()).await {
        Ok(handle) => break handle,
        Err(WatchRootError::Overlaps { path, existing }) => {
          // Resolve ONLY a conflict the watcher NAMES against a release we requested — QUEUED (not yet
          // handed to the channel) or IN-FLIGHT (handed over, teardown not landed). Await its teardown
          // and retry; a named conflict in neither set is a genuine live overlap, surfaced as-is.
          if let Some(index) = self
            .pending_releases
            .iter()
            .position(|(_, stored)| stored.as_deref() == Some(existing.as_path()))
          {
            let (released, _) = self
              .pending_releases
              .remove(index)
              .expect("index in bounds");
            let _ = self.watcher.unwatch(released).await;
            self.pending_set.remove(&released);
          } else if let Some(index) = self
            .enqueued
            .iter()
            .position(|(_, stored)| stored.as_deref() == Some(existing.as_path()))
          {
            let (released, _) = self.enqueued.remove(index);
            let _ = self.watcher.unwatch(released).await;
            self.pending_set.remove(&released);
          } else {
            return Err(watch_error_from_fs(WatchRootError::Overlaps {
              path,
              existing,
            }));
          }
        }
        Err(err) => return Err(watch_error_from_fs(err)),
      }
    };
    // Adopt the filesystem-authoritative canonical path as the committed key (design §4, the
    // TOCTOU close): events are reported in canonical coordinates, so the index must key on
    // them. A `None` here means the root was already torn down (deleted between the request and
    // this arm completing) — a dead-on-arrival handle backing no live watch. Do NOT fall back
    // and report it armed: best-effort release it and fail, so the source never claims a dead
    // handle armed. Belt-and-suspenders under the driver's own arm-choke-point liveness check
    // (invariant I2), which guarantees this for every `Source` impl regardless.
    let Some(path) = self.watcher.root_path(handle) else {
      let _ = self.watcher.unwatch(handle).await;
      return Err(WatchError::DeadOnArrival);
    };
    Ok(Armed::new(handle, path_components(&path)))
  }

  fn disarm(&mut self, handle: RootHandle) {
    // Synchronous, non-blocking release REQUEST (contract clauses 1 & 3): queue it — paired with the
    // released root's canonical path captured NOW, while the root is still live in the registry — never
    // apply it inline. A later `arm` hands it to the watcher via the NON-BLOCKING `request_unwatch`
    // (the common path, which awaits nothing), or — if that arm's key overlaps this release — resolves
    // the conflict the watcher NAMES by awaiting exactly its `unwatch` (contract clause 2); `Drop`
    // releases whatever is left (the `Watcher`'s own teardown reclaims every live root). The
    // `pending_set` mirror makes the handle logically dead the instant this returns — `root_key`
    // answers `None`. Idempotent by the set: re-requesting an already-pending handle is a no-op.
    //
    // A queued PRUNE of the released handle is superseded by the release (set_cover contract
    // clause 4 — the whole root is going away), and a disarm is a watcher-touching op, so the other
    // deferred prunes get their non-blocking re-forward here too (clause 3).
    self.deferred_prunes.remove(&handle);
    self.flush_deferred_prunes();
    // DOOR: `root_path` answers `None` for a foreign brand OR an already-torn-down own handle. Drop
    // the disarm ENTIRELY for either — no `pending_releases` entry, no `pending_set` mark: a
    // `None`-path entry can never be the named `Overlaps` conflict (its only effect was a no-op
    // `request_unwatch`), and `root_key` correctness is preserved because `root_path` already
    // answers `None` for the handle. Post-door invariant: every `pending_releases` entry carries
    // `Some(path)` and names a live-at-disarm root of THIS instance — so the queue (and its
    // `pending_set` mirror) is bounded by the live-root count, and a hostile `disarm(fresh_foreign)`
    // flood retains nothing (every foreign disarm dies at the door).
    let Some(root_path) = self.watcher.root_path(handle) else {
      return;
    };
    if self.pending_set.insert(handle) {
      self.pending_releases.push_back((handle, Some(root_path)));
    }
  }

  /// The awaited GROW half of in-place coverage reconcile, over the watcher's
  /// **effect-completion fence**: [`Watcher::set_cover`]'s acknowledgement resolves when the
  /// reconcile has *settled* — every re-armed watch live, or a loss already signaled in-band —
  /// never at effect-queue time, which is exactly the applied-before-`Ok` fence the trait's
  /// clause 1 demands. A kernel-recursive root (fanotify / FSEvents) short-circuits to `Ok`
  /// before the round-trip: its single whole-subtree stream never narrowed, so there is nothing
  /// to grow back ([`Watcher::backend_of`] is the a-priori report; the driver's own
  /// [`Recursive`](CoverOutcome::Recursive) answer stays authoritative if the report races a
  /// backend change and the round-trip runs anyway).
  ///
  /// A grow for `handle` supersedes its queued full-channel-deferred prune (set_cover contract
  /// clause 6 — the grow's fresh cover is newer), and as a watcher-touching op re-forwards the
  /// other deferred prunes first (clause 3).
  ///
  /// # Errors
  ///
  /// The settled outcome maps per the trait's error contract — on every `Err` the fs layer has
  /// already emitted the dominating in-band `Rescan` wherever one is owed, and the umbrella
  /// keeps its record unbroadened and fails the watch retryably:
  ///
  /// - [`Degraded`](CoverOutcome::Degraded) → [`WatchError::CoverageIncomplete`]: the reconcile
  ///   settled but coverage loss was signaled inside the window, so some `retained` key may not
  ///   be backed;
  /// - [`Skipped(UnknownRoot)`](SkipReason::UnknownRoot) → a [`FaultKind::NotFound`] fault: the
  ///   covering root died concurrently with this grow (root death, stream fatal). Deliberately
  ///   NOT `CoverageIncomplete` — nothing degraded; the root is *gone* — and the caller's retry
  ///   re-plans, finds the dead root via `root_key`, retires it with terminal `Rescan`s, and
  ///   arms fresh. `Err(UnknownRoot)` (the watcher's foreign-handle pre-check) maps the same
  ///   way: either form means "no such root here";
  /// - [`Closed`](FsUnwatchError::Closed) → [`WatchError::Closed`], including a close mid-fence
  ///   (the ratified close semantics drop parked acknowledgements);
  /// - [`Skipped(NotLive)`](SkipReason::NotLive) / [`Skipped(RefusedCover)`](SkipReason::RefusedCover)
  ///   are unreachable from the umbrella (a `Covered` grow implies a committed, publicly-live
  ///   root, and the umbrella's covers are never empty or out-of-root): `debug_assert!` tripwires
  ///   plus a conservative fault in release.
  async fn grow(
    &mut self,
    handle: RootHandle,
    retained: &[Vec<OsString>],
  ) -> Result<(), WatchError> {
    // Supersede this handle's queued prune BEFORE the flush, so a stale narrower cover is never
    // re-forwarded ahead of (or instead of) this grow's fresh one.
    self.deferred_prunes.remove(&handle);
    self.flush_deferred_prunes();
    // Kernel-recursive short-circuit: coverage never narrowed, nothing to reconcile — skip the
    // command round-trip inside the caller-bounded reconcile.
    if self
      .watcher
      .backend_of(handle)
      .is_some_and(|backend| backend.is_kernel_recursive())
    {
      return Ok(());
    }
    let paths: Vec<PathBuf> = retained.iter().map(|key| key_to_path(key)).collect();
    #[cfg(test)]
    {
      self.cover_round_trips += 1;
    }
    match self.watcher.set_cover(handle, paths).await {
      Ok(CoverOutcome::Applied | CoverOutcome::Recursive) => Ok(()),
      Ok(CoverOutcome::Degraded) => Err(WatchError::CoverageIncomplete),
      Ok(CoverOutcome::Skipped(SkipReason::UnknownRoot)) => Err(WatchError::source(
        SourceFault::new(FaultKind::NotFound).with_source(format!(
          "the covering root (scope {}) died before the grow could be applied",
          handle.scope()
        )),
      )),
      Ok(CoverOutcome::Skipped(reason)) => {
        // NotLive / RefusedCover (or a future skip): unreachable from the umbrella — a grow is
        // only ever issued for a committed live root with a non-empty in-root cover — so a hit
        // here is an umbrella bug, not a runtime condition. Trip loudly in debug; fail the
        // watch conservatively in release (prior coverage is untouched, the record does not
        // broaden, the retry re-plans).
        debug_assert!(
          false,
          "FsSource::grow was skipped ({reason}) — the umbrella issued a grow for a root that \
           is not publicly live or with a refused cover"
        );
        Err(WatchError::source(
          SourceFault::new(FaultKind::Other).with_source(format!(
            "the coverage grow was skipped ({reason}) without reconciling"
          )),
        ))
      }
      // An unknown future settled outcome: fail conservatively (no broaden, retryable) with the
      // outcome preserved in the fault's message.
      Ok(outcome) => Err(WatchError::source(
        SourceFault::new(FaultKind::Other)
          .with_source(format!("unrecognized coverage-grow outcome ({outcome})")),
      )),
      // The foreign-handle pre-check — "no such root of this watcher", same answer as a
      // concurrently-dead root.
      Err(err @ FsUnwatchError::UnknownRoot) => Err(WatchError::source(
        SourceFault::new(FaultKind::NotFound).with_source(err),
      )),
      // Closed, or closed/died mid-fence: the uniform closed signal.
      Err(FsUnwatchError::Closed) => Err(WatchError::Closed),
      // An unknown future error case degrades conservatively, the whole fs error preserved.
      Err(err) => Err(WatchError::source(
        SourceFault::new(FaultKind::Other).with_source(err),
      )),
    }
  }

  /// The PRUNE half of in-place coverage reconcile: forwarded to the watcher the instant it is
  /// called via the NON-BLOCKING, reply-less [`Watcher::request_set_cover`] `try_send` (contract
  /// clause 3 — prompt), falling back to the **latest-wins per-handle deferral queue** only when
  /// the control channel is momentarily full (re-forwarded at the next watcher-touching op; a
  /// [`grow`](Self::grow) of the handle supersedes its queued prune — clause 6). The driver
  /// applies a reply-less reconcile exactly like the awaited one, latest-wins by FIFO order, so
  /// a prune followed by an awaited grow always ends at the grow's fresh cover.
  ///
  /// A handle whose [`disarm`](Self::disarm) was already requested is logically dead, so its
  /// prune is skipped outright — superseded by the release (clause 4: the whole root is going
  /// away). No result and no fence: a lost or deferred prune merely leaves the root over-broad,
  /// which is correctness-neutral and self-healing (clause 5).
  fn set_cover(&mut self, handle: RootHandle, retained: &[Vec<OsString>]) {
    if self.pending_set.contains(&handle) {
      return;
    }
    // DOOR: `root_path` answers `None` for a foreign brand OR an already-torn-down own root. A prune
    // of such a root is pointless — clause 5 does not require prune losslessness — so drop it at the
    // door rather than queue or defer it. Deferring never-valid work drives the monotone
    // `deferred_prunes` growth.
    if self.watcher.root_path(handle).is_none() {
      return;
    }
    // This request SUPERSEDES any queued older snapshot for the same handle (latest-wins,
    // clause 6) — drop it BEFORE the flush. Were the stale entry left for the flush, a full
    // channel there followed by room for the direct request below would leave the stale
    // snapshot queued BEHIND the newer applied one, and a later flush would re-apply it —
    // exactly the older-snapshot regression the clause forbids.
    self.deferred_prunes.remove(&handle);
    self.flush_deferred_prunes();
    let paths: Vec<PathBuf> = retained.iter().map(|key| key_to_path(key)).collect();
    match self.watcher.request_set_cover(handle, paths.clone()) {
      // Forwarded onto the control channel — nothing to defer.
      RequestOutcome::Enqueued => {}
      // The channel is momentarily full: fall back to the latest-wins deferral queue (clause 3),
      // re-forwarded at the next watcher-touching op.
      RequestOutcome::Busy => self.defer_prune(handle, paths),
      // A closed watcher (the door already excluded foreign/dead roots): never enqueueable, so
      // drop rather than defer — a deferral that can never forward grows without bound.
      RequestOutcome::Rejected => {}
    }
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, RootHandle>> {
    let raw = self.watcher.next().await?;
    Some(SourceEvent::from_fs(&raw))
  }

  async fn replace(
    &mut self,
    handle: RootHandle,
    new_key: &[OsString],
  ) -> Result<Armed<OsString, RootHandle>, WatchError> {
    // Supersede this handle's queued prune BEFORE the flush, exactly as `grow`
    // does: the widen re-covers this root, so a prune still holding the OLD
    // retained set is stale. Left queued, a later watcher-touching op would
    // re-forward it AFTER the replace committed and narrow the widened root
    // back to the old subtree — a silent coverage loss with no `Rescan`. A
    // dropped prune is merely over-broad coverage, which self-heals.
    self.deferred_prunes.remove(&handle);
    self.flush_deferred_prunes();
    let new_root = key_to_path(new_key);
    // Make-before-break inside the fs layer: the replacement stream is live
    // BEFORE the old one retires, and the commit delivers one epoch-bumped
    // full-root `Rescan`. Atomic on failure — every error leaves the old
    // root's coverage untouched, which is exactly what lets the umbrella fall
    // back to release-and-rearm.
    match self.watcher.replace_root(handle, new_root.clone()).await {
      // The handle is PRESERVED (that is the point): the root the umbrella
      // already records simply covers more ground now.
      Ok(()) => {
        let canonical = self
          .watcher
          .root_path(handle)
          .ok_or_else(|| WatchError::Source(SourceFault::new(FaultKind::NotFound)))?;
        Ok(Armed::new(handle, path_components(&canonical)))
      }
      Err(err) => Err(replace_error_to_watch_error(err, &new_root)),
    }
  }

  async fn begin_sync(
    &mut self,
    handle: RootHandle,
    dir_key: &[OsString],
    token: SyncToken,
  ) -> Result<Vec<OsString>, SyncError> {
    // Any op that touches the watcher first re-forwards deferred prunes, so a
    // stale narrower cover never trails behind this write.
    self.flush_deferred_prunes();
    let name = cookie_name(token);
    let dir = key_to_path(dir_key);
    // Mint the cancel address and record it BEFORE the await: if this future is
    // dropped mid-await (a caller cancel or a close won the owner's race), the
    // entry deliberately REMAINS for `cancel_sync` to consume — the owner never
    // learned the cookie path, so the ticket is the only precise handle on a write
    // that may still land. The token is stored beside it as the incarnation guard.
    let (admission, ticket) = self.watcher.mint_sync_ticket();
    self.pending_syncs.insert(handle, (token, ticket));
    // The fs watcher parks the write on the root's coverage-settle fence and
    // resolves at write-complete — never at observe. That is exactly the
    // bounded initiation this seam promises. The move-only admission is consumed
    // by the call; the `Copy` ticket stays recorded above for the abandonment
    // cancel.
    let result = self.watcher.sync_root(handle, dir, name, admission).await;
    // A NORMAL return (Ok or Err) means the sync resolved server-side, so drop the
    // in-flight entry here; only the dropped-future path above leaves it behind.
    self.pending_syncs.remove(&handle);
    match result {
      Ok(path) => Ok(path_components(&path)),
      // The umbrella never retries `sync_root` at this level, so a returned
      // admission is dropped; the mapping is over the carried `error`.
      Err(SyncRootDenied { error, .. }) => Err(match error {
        SyncRootError::UnknownRoot | SyncRootError::Retired => SyncError::Retired,
        SyncRootError::DirOutsideRoot { .. } => SyncError::CookieDirUncovered,
        SyncRootError::Write { source, .. } => {
          let kind = match source.kind() {
            std::io::ErrorKind::NotFound => FaultKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FaultKind::PermissionDenied,
            _ => FaultKind::Other,
          };
          SyncError::CookieWrite(SourceFault::new(kind).with_source(source))
        }
        // A second sync raced one already in flight for this root: no physical write happened, and it
        // is a transient, retryable refusal — surfaced as the dedicated `Busy` rather than a
        // write-failure the caller might read as terminal.
        SyncRootError::WriteInFlight => SyncError::Busy,
        // The root's cookie cleanup is backlogged (too many unremoved cookies —
        // a failing unlink the driver is retrying). No physical write happened;
        // it is transient and retryable, the same shape as `WriteInFlight`.
        SyncRootError::CleanupBacklog => SyncError::Busy,
        SyncRootError::Closed => SyncError::Closed,
        // The fs error type is `#[non_exhaustive]`: a variant added later is a
        // failed write until it is classified here, never a silent success.
        _ => SyncError::CookieWrite(SourceFault::new(FaultKind::Other)),
      }),
    }
  }

  fn end_sync(&mut self, _handle: RootHandle, cookie_key: &[OsString]) {
    // A prompt request to reap the cookie now: it MARKS the obligation the driver
    // has held since it admitted the sync, so admission is guaranteed by type —
    // there is no queue a burst of control traffic could saturate. This path came
    // from the `begin_sync` reply, and the write published it before that reply
    // was sent, so the mark always finds its record. The driver OWNS every cookie
    // it wrote and unlinks it at scope or driver teardown regardless, so even a
    // reap to an already-closed driver leaks nothing. Runtime-free by design
    // (this seam carries no `R` bound): the runtime-bearing cleanup lives in the
    // driver.
    let path = key_to_path(cookie_key);
    self.flush_deferred_prunes();
    self.watcher.request_remove_cookie(path);
  }

  fn cancel_sync(&mut self, handle: RootHandle, token: SyncToken) {
    // The owner abandoned an in-flight `begin_sync` and never learned the cookie
    // path — but `begin_sync` recorded the watcher-minted ticket for this handle
    // before it awaited, so peek it and cancel by that ticket: the incarnation-
    // precise address the driver records at ADMISSION and therefore always resolves
    // while the sync is live. The stored token is the incarnation guard — a cancel
    // whose token does not match the recorded one is stale (a later incarnation
    // superseded it), and the entry is removed and the cancel issued ONLY on a
    // match, so a stale cancel leaves a live successor's entry INTACT for that
    // successor's own cancel to find; a missing entry means the sync already
    // returned (nothing to cancel). The driver reaps the cookie if the write
    // already landed, refuses the claim of a write still in the pool (so it
    // self-reaps the file it creates), retires a sync whose write was never
    // dispatched, or drops the request if the sync already resolved. Runtime-free
    // (a map lookup, a lock, and a `try_send`), like `end_sync`; the runtime-bearing
    // cleanup lives in the driver.
    self.flush_deferred_prunes();
    if let Some(&(stored, ticket)) = self.pending_syncs.get(&handle)
      && stored == token
    {
      self.pending_syncs.remove(&handle);
      #[cfg(test)]
      {
        self.sync_cancels_requested += 1;
      }
      self.watcher.request_cancel_sync(ticket);
    }
  }

  fn is_sync_artifact(&self, key: &[OsString]) -> bool {
    // Two independent grounds, because the sync namespace has two shapes and only
    // one of them carries a name this crate can predict.
    //
    // GROUND 1 — the LEAF is a name this workspace mints: the fs layer's cookie
    // DIRECTORY (whose own create is that driver's artifact, never a user change),
    // or a cookie sitting directly in the sync directory, which is where every
    // version of this binding put its cookies before the cookie directory existed.
    // Matching the older shape too is what keeps a crash leftover suppressed across
    // an upgrade instead of resurfacing as a user create — see `is_cookie_name`.
    //
    // GROUND 2 — the leaf's IMMEDIATE parent is exactly a cookie directory, whatever
    // the leaf. `tributary_fs::Watcher::sync_root` takes the cookie's name from ITS
    // caller and accepts any normal component, so a second consumer of the lower
    // crate watching this same tree mints cookie names with no grammar this crate
    // could know; the directory they land in is the only thing that identifies them.
    // Suppressing on the directory costs at most a file someone created inside a
    // `0o700` directory this driver owns — while a leaf grammar alone would surface
    // another watcher's GENUINE cookies as user changes, which is the failure this
    // classifier exists to prevent and strictly worse than the cost.
    //
    // Neither ground reads any deeper component, so a user file merely living under
    // some ancestor whose name shares the stem stays a user change.
    //
    // GROUND 2 IS DECIDED FIRST, and reads only the PARENT component — because "whatever
    // the leaf" has to include a leaf that is not UTF-8. Paths on Unix are bytes, so an
    // active cookie can be renamed to an undecodable name while staying inside the
    // directory that reserves it; testing the leaf's `to_str()` first classified exactly
    // that move as reserved at its source alone, and the routing then projected the
    // internal destination onto consumer streams as a user-visible `Created`.
    //
    // The parent still converts, and needs no lossy fallback: a cookie directory's name is
    // minted as `format!("{prefix}-{euid}")`, pure ASCII, so a component that fails
    // `to_str()` cannot be one — the conversion rejects only names the classifier rejects
    // anyway. It is the LEAF whose text is optional, and only Ground 1 needs it.
    let parent_is_cookie_dir = key
      .len()
      .checked_sub(2)
      .and_then(|parent| key[parent].to_str())
      .is_some_and(tributary_fs::is_sync_cookie_dir_name);
    if parent_is_cookie_dir {
      return true;
    }
    // GROUND 1 is a grammar over TEXT, so a leaf this crate could have minted is UTF-8 by
    // construction; an undecodable leaf simply matches no minted shape and is left to the
    // ground above, which has already answered.
    key
      .last()
      .and_then(|leaf| leaf.to_str())
      .is_some_and(|leaf| is_cookie_name(leaf) || tributary_fs::is_sync_cookie_dir_name(leaf))
  }

  fn root_key(&self, handle: RootHandle) -> Option<Vec<OsString>> {
    // A requested release is logically dead immediately (contract clause 3), even while its
    // transport teardown is still queued: answer `None` for a pending handle before consulting the
    // live registry, so a re-`watch` of a just-released key classifies it as gone.
    if self.pending_set.contains(&handle) {
      return None;
    }
    // `tributary_fs::Watcher::root_path` reads its live-root registry synchronously and
    // answers `None` for a torn-down handle, so a terminal `Rescan` (whose root fs has
    // forgotten) reports `None` here — exactly the dead/retired signal the owner needs.
    self
      .watcher
      .root_path(handle)
      .map(|path| path_components(&path))
  }

  /// Nothing to initiate ahead of the wait: the lower watcher's close is ONE command, and
  /// [`join_close`](Self::join_close) issues it. There is no cheaper, non-blocking half to split off
  /// — sending the command is itself the initiation, and it already awaits only mailbox room.
  fn begin_close(&mut self) {}

  /// Forwards the LOWER watcher's close — the strongest lifecycle fact this stack produces — as this
  /// source's quiescence result.
  ///
  /// `tributary_fs::Watcher::close`'s `Ok` proves every native stream torn down AND every sync
  /// cookie this watcher ever wrote confirmed removed from disk, and its `NotQuiesced` names how
  /// much was still outstanding when its own grace expired. Dropping the watcher instead — the only
  /// teardown available before this seam existed — starts the identical work but can neither await
  /// it nor report it, so an upper `close()` acknowledged over a live reader thread and an unlinked
  /// cookie still in flight, and a caller that shut its runtime down on that acknowledgement
  /// abandoned both.
  ///
  /// It is bounded by the lower close's own ~1 s grace, so a wedged mount produces a
  /// [`NotQuiesced`](SourceCloseError::NotQuiesced) report rather than an unbounded wait.
  ///
  /// The lower watcher is borrowed rather than consumed (`close_in_place`) because this source
  /// outlives the call by exactly as long as it takes the owner to drop it; a second call — there is
  /// none on the owner's path — would honestly report `Stopped`, since that call proves nothing.
  async fn join_close(&mut self) -> Result<(), SourceCloseError> {
    match self.watcher.close_in_place().await {
      Ok(()) => Ok(()),
      Err(FsCloseError::Stopped) => Err(SourceCloseError::Stopped),
      Err(FsCloseError::NotQuiesced { pending }) => Err(SourceCloseError::NotQuiesced { pending }),
      // The lower error type is `#[non_exhaustive]`: a variant added there is, by construction, a
      // close that did not prove quiescence.
      Err(_) => Err(SourceCloseError::NotQuiesced { pending: 1 }),
    }
  }
}

impl SourceEvent<OsString, RootHandle> {
  /// Reverses a raw `tributary-fs` event into a source event — **the** fs-to-neutral
  /// map: its absolute path back into key components, and its
  /// [`tributary_fs::EventKind`] into the umbrella's source-neutral [`EventKind`]
  /// (a move's source path becomes the [`Moved`](EventKind::Moved) kind's in-kind
  /// source key). The one place the fs vocabulary and a raw filesystem event's key are
  /// converted at this binding.
  fn from_fs(event: &FsEvent) -> Self {
    // The move's SOURCE coordinate, measured against the same root as the destination's:
    // the fs layer reports a `Moved` only when both endpoints lie under the watched root,
    // so this is a real location whenever the kind is a move.
    let move_from_location = event.kind().moved().map(|moved| moved.location().clone());
    let kind = match event.kind() {
      FsEventKind::Created => EventKind::Created,
      FsEventKind::Modified => EventKind::Modified,
      FsEventKind::Removed => EventKind::Removed,
      FsEventKind::Moved(moved) => EventKind::Moved {
        from: path_components(moved.from()),
      },
      FsEventKind::Rescan => EventKind::Rescan,
      // The fs enum is #[non_exhaustive]: an unknown future kind degrades to the
      // conservative re-read signal at this binding, exactly as fs itself folds
      // unknown proto kinds (the source-honesty contract).
      _ => EventKind::Rescan,
    };
    let source_event = Self::new(
      event.root(),
      path_components(event.path()),
      kind,
      event.location().clone(),
      event.epoch(),
      Some(event.change_id()),
    );
    match move_from_location {
      Some(location) => source_event.with_move_from_location(location),
      None => source_event,
    }
  }
}

/// Maps a raw `tributary-fs` watch-root error into the umbrella's neutral error
/// vocabulary — the error half of the fs-to-neutral binding (its event half is
/// [`SourceEvent::from_fs`]), and the one place the fs error enum crosses the seam.
///
/// Classification is honest-and-conservative, mirroring the source-honesty contract on
/// [`EventKind`]: each fs case maps to its neutral [`FaultKind`], an unknown future case
/// degrades to [`Other`](FaultKind::Other), and a closed watcher maps to the umbrella's
/// own [`WatchError::Closed`] (the uniform "the stack is closed" signal). The whole fs
/// error is always preserved in the fault's box, so [`WatchError::as_fs`] recovers full
/// fidelity.
fn watch_error_from_fs(err: WatchRootError) -> WatchError {
  let kind = match &err {
    WatchRootError::NotFound { .. } => FaultKind::NotFound,
    WatchRootError::NotADirectory { .. } => FaultKind::NotADirectory,
    WatchRootError::Overlaps { .. } => FaultKind::Conflict,
    WatchRootError::Source(source) => match source {
      SourceError::Unsupported => FaultKind::Unsupported,
      SourceError::InstanceLimit => FaultKind::Capacity,
      _ => FaultKind::Other,
    },
    WatchRootError::Closed => return WatchError::Closed,
    _ => FaultKind::Other,
  };
  WatchError::source(SourceFault::new(kind).with_source(err))
}

/// Classifies a failed in-place root replacement into the neutral vocabulary.
/// Every variant is honest and NON-fatal to the caller's watch: the umbrella
/// falls back to release-and-rearm on any of them, because `replace_root` is
/// atomic on failure — the old root's coverage is exactly as it was.
fn replace_error_to_watch_error(err: ReplaceRootError, root: &std::path::Path) -> WatchError {
  let kind = match err {
    ReplaceRootError::NotFound { .. } => FaultKind::NotFound,
    ReplaceRootError::NotADirectory { .. } => FaultKind::NotADirectory,
    ReplaceRootError::Overlaps { .. } => FaultKind::Conflict,
    // A live scope never swaps lowering profiles, and a root that died (or a
    // replace already in flight) is not something to retry in place — the
    // release-and-rearm fallback handles all of them.
    ReplaceRootError::BackendDiverged
    | ReplaceRootError::Retired
    | ReplaceRootError::UnknownRoot
    | ReplaceRootError::ReplaceInFlight => FaultKind::Unsupported,
    ReplaceRootError::Closed => return WatchError::Closed,
    ReplaceRootError::Source(source) => {
      return WatchError::Source(SourceFault::new(FaultKind::Other).with_source(source));
    }
    _ => FaultKind::Other,
  };
  let _ = root;
  WatchError::Source(SourceFault::new(kind))
}

/// The reserved sync-cookie namespace. (Watchman's `.watchman-cookie-`
/// precedent.) A cookie's leaf begins with this — but the prefix alone does not
/// make a leaf a cookie: see [`is_cookie_name`] for the grammar that does.
const COOKIE_PREFIX: &str = ".tributaries-sync-";

/// The nonce's rendered width: `{:016x}` on a `u64`, so exactly sixteen lowercase
/// hex digits, zero-padded — never fewer, never more, whatever the value.
const COOKIE_NONCE_DIGITS: usize = 16;

/// Renders a cookie's file name from the owner's token. Unique across
/// concurrent syncs (seq), watcher instances in one process (instance), and
/// processes (pid) — so a crashed prior process's leftovers collide with
/// nothing.
///
/// This is the only minter of the name [`is_cookie_name`] recognizes; the two must
/// be changed together, and the round-trip cell pins that they are.
fn cookie_name(token: SyncToken) -> String {
  // The trailing nonce (lowercase hex) is what makes the name unpredictable to
  // any other writer — see `SyncToken::new`.
  format!(
    "{COOKIE_PREFIX}{}-{}-{}-{:0width$x}",
    token.instance(),
    token.pid(),
    token.seq(),
    token.nonce(),
    width = COOKIE_NONCE_DIGITS,
  )
}

/// Whether `leaf` is a sync cookie's file name as SOME release of this binding minted
/// it directly in the sync directory: the reserved prefix, then `instance-pid-seq`
/// rendered decimal — each inside the range its own minter can produce, never merely
/// well-formed — then, for the shape [`cookie_name`] mints today, a `nonce` of sixteen
/// lowercase hex digits.
///
/// # Why both shapes
///
/// The three-field form is what this binding minted before the cookie name carried a
/// nonce, and a cookie's whole point is that it may outlive the process that wrote it:
/// a crash leftover on disk was named by whichever release was running then, not by the
/// one that later watches the tree. Dropping the older shape would make the first watch
/// after an upgrade report every stale cookie as a user create.
///
/// # Why the grammar is checked rather than the prefix alone
///
/// Suppression removes a change from every consumer stream, so whatever it matches
/// vanishes. A bare prefix test therefore swallows any user file whose name happens to
/// begin with the reserved stem — silently, with no `Rescan` and no diagnostic, for the
/// life of the watch. These names are minted **by this crate**, so their shapes are
/// knowable exactly; checking them keeps the reserved namespace total over the cookies
/// this binding itself writes at the sync directory, while leaving every other name
/// there a user change. Cookies written by a DIFFERENT consumer of `tributary-fs` carry
/// no shape this crate can know — those are identified by the directory they land in
/// instead (see `is_sync_artifact`).
fn is_cookie_name(leaf: &str) -> bool {
  let Some(rest) = leaf.strip_prefix(COOKIE_PREFIX) else {
    return false;
  };
  let mut fields = rest.split('-');
  let (Some(instance), Some(pid), Some(seq)) = (fields.next(), fields.next(), fields.next()) else {
    return false;
  };
  // Every decimal field is bounded to EXACTLY what its minter can render, and each
  // bound must hold for the three-field release as well as for today's, since both
  // shapes are accepted here. Too wide swallows a user file — silently, with no
  // `Rescan`; too narrow surfaces a GENUINE cookie as a user create, which is the
  // worse direction, so no bound below is a guess about a field's range.
  //
  // * `instance` — `Owner::on_sync` renders `sub.instance().get()`, and an
  //   [`InstanceId`](crate::subscription::InstanceId) is a `NonZeroU64` minted as
  //   `fetch_add(1) + 1`: the first owner in a process brands 1, and 0 is not
  //   representable at all. The three-field release rendered this field from the
  //   same type, so the floor holds for both shapes.
  // * `pid` — `std::process::id()`, a `u32`, which is where the ceiling comes from.
  //   Its FLOOR is the one bound here resting on OS semantics rather than on this
  //   workspace's own source: pid 0 is the scheduler on Unix and the System Idle
  //   pseudo-process on Windows, never a process that can execute this code. It is
  //   therefore the first bound to drop should that evidence ever be questioned.
  // * `seq` — `Owner::sync_seq`, which starts at 0 and is PRE-incremented before the
  //   token is minted, so the first sync of every owner renders 1 and no sync ever
  //   renders 0; the three-field release pre-incremented identically. (The lower
  //   crate's `sync_tickets` does start at 0, but that sequence brands a
  //   [`SyncTicket`](tributary_fs::SyncTicket) — an in-memory cancel address — and
  //   never reaches a file name.)
  //
  // The `nonce` deliberately gets NO value bound: it is a hash output, so every
  // `u64` including 0 is mintable, and its sixteen-lowercase-hex shape is the whole
  // of what can be checked.
  if !(is_minted_decimal(instance, 1, u64::MAX)
    && is_minted_decimal(pid, 1, u64::from(u32::MAX))
    && is_minted_decimal(seq, 1, u64::MAX))
  {
    return false;
  }
  match fields.next() {
    // The historical three-field shape, exhausted.
    None => true,
    // Today's shape: the nonce, and nothing after it.
    Some(nonce) => {
      fields.next().is_none()
        && nonce.len() == COOKIE_NONCE_DIGITS
        && nonce
          .bytes()
          .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() && b <= b'f')
    }
  }
}

/// Whether `field` is exactly what `format!("{n}")` renders for some `n` in `min..=max`:
/// decimal digits, no sign, and no redundant leading zero (`0` itself is the one-digit
/// case).
///
/// The range is the caller's to justify from the field's minter — see the per-field
/// derivation in [`is_cookie_name`], the only caller.
fn is_minted_decimal(field: &str, min: u64, max: u64) -> bool {
  field.bytes().all(|b| b.is_ascii_digit())
    && (field.len() == 1 || !field.starts_with('0'))
    && field
      .parse::<u64>()
      .is_ok_and(|value| (min..=max).contains(&value))
}

/// Rebuilds a filesystem path from key components — the reverse of
/// [`path_components`](crate::event::path_components), and the only key → path conversion
/// the fs binding performs. `[a, b, c]` becomes `a/b/c`; an absolute key round-trips
/// through its leading root component.
pub(super) fn key_to_path(key: &[OsString]) -> PathBuf {
  key.iter().collect()
}
