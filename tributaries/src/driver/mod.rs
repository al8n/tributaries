//! The public async watcher and the machinery wiring one [`tributary_fs::Watcher`]
//! to the sans-I/O [`Subsumer`](crate::subsume::Subsumer), the
//! [`fan_out`](crate::route::fan_out) router, and the per-subscription
//! [`EpochLedger`](epoch::EpochLedger).
//!
//! All I/O lives here; the engines it drives (subsumption, routing, epoch rebasing)
//! are pure and generic over the key component `C`. This local-fs driver instantiates
//! them at `C = OsString` (a path's components), value `V = ()` (the fs source carries
//! no per-watch value at this layer), and handle `H = RootHandle`. A [`Tributaries`]
//! owns exactly one `tributary-fs` watcher and subsumes every caller subscription onto
//! its disjoint roots, so N overlapping `watch` calls collapse to one kernel watch
//! (design §4); each raw event fans out to every covering subscription (design §5),
//! stamped in that subscription's own monotone epoch space (design §8).

use std::{
  collections::{HashMap, VecDeque},
  ffi::OsString,
  hash::Hash,
  path::{Path, PathBuf},
  vec::Vec,
};

use agnostic_lite::RuntimeLite;
use tributary_fs::{Interest, MovedEvent, RootHandle, Watcher};

use crate::{
  coalesce::Coalescer,
  error::{BuildError, CloseError, UnwatchError, WatchError},
  event::{Event, path_components},
  filter::Filter,
  options::TributariesOptions,
  route::RoutableEvent,
  subscription::Subscription,
  subsume::{Subsumer, UnwatchOutcome, WatchOutcome},
  view::WatchView,
};

/// An in-flight widen the driver journaled before it began releasing kernel watches, so a
/// dropped `watch()` future (a `select!`/timeout that cancels mid-transaction) can be
/// repaired on the next public entry point (design §4, cancellation-safety journaling).
///
/// A widen is multi-step async I/O — it disarms N subsumed roots, then arms the wider one
/// — and `watch()` is `&mut self async`, so a caller that drops its future between a
/// disarm and the commit leaves subsumed roots disarmed with **no** async cleanup (Rust
/// cannot `await` in `Drop`). The driver therefore records this journal **before the
/// first disarm** and clears it only when the widen fully commits or fully rolls back.
/// Every public entry point first calls [`resume_pending_widen`] to bring a journaled-but-
/// incomplete widen back to a consistent pre-widen coverage.
///
/// It carries the plan [`WatchOutcome`] the widen was executing: its `unwatch` handles
/// (the subsumed roots whose liveness resume probes), and — through the same outcome — the
/// newcomer's pending reservation, which resume aborts ([`Subsumer::abort_watch`]) since a
/// dropped `watch()` handed out no [`Subscription`].
#[derive(Debug)]
struct WidenJournal<C, H> {
  /// The widen plan being executed: `unwatch` names the subsumed roots to probe/restore,
  /// and the whole outcome carries the newcomer's pending id for [`Subsumer::abort_watch`].
  outcome: WatchOutcome<C, H>,
}

use self::epoch::EpochLedger;

mod epoch;

#[cfg(all(test, feature = "tokio"))]
mod tests;

/// The seam the driver arms kernel watches through: the two operations the widen
/// re-point and the arm-failure unwind must sequence, factored out of the concrete
/// [`Watcher`] so those paths are testable with a fake that records call order and
/// can inject an arm failure.
///
/// This is a private *internal* seam — not the public `Source` trait (reserved for
/// M2). It is generic over its `Handle` (the fs root id) so a test fake can mint
/// trivial handles in place of the un-constructible [`RootHandle`]; production
/// implements it for [`Watcher`] with `Handle = RootHandle`. Methods take `&self`
/// (the watcher's `watch`/`unwatch` do), so the fake uses interior mutability.
pub(crate) trait RootArmer {
  /// The fs root id an arm yields (`RootHandle` in production).
  type Handle: Copy + Eq + Hash;

  /// Arms a kernel watch of `path` with `interest`, yielding its fresh handle.
  fn arm(
    &self,
    path: &Path,
    interest: Interest,
  ) -> impl Future<Output = Result<Self::Handle, WatchError>>;

  /// The **authoritative canonical path** fs recorded for `handle` (the umbrella keys
  /// its subsumption index off this, not off its own provisional canonicalization —
  /// design §4, the TOCTOU close). `None` once the handle no longer names a live root.
  fn root_path(&self, handle: Self::Handle) -> Option<PathBuf>;

  /// Releases the kernel watch named by `handle`.
  fn disarm(&self, handle: Self::Handle) -> impl Future<Output = Result<(), UnwatchError>>;
}

impl<R: RuntimeLite> RootArmer for Watcher<R> {
  type Handle = RootHandle;

  async fn arm(&self, path: &Path, interest: Interest) -> Result<RootHandle, WatchError> {
    Ok(self.watch(path.to_path_buf(), interest).await?)
  }

  fn root_path(&self, handle: RootHandle) -> Option<PathBuf> {
    Watcher::root_path(self, handle)
  }

  async fn disarm(&self, handle: RootHandle) -> Result<(), UnwatchError> {
    Ok(self.unwatch(handle).await?)
  }
}

/// The public top-level watcher: overlapping subscriptions in, attributed events
/// out.
///
/// Wraps one [`tributary_fs::Watcher`] concretely (design call A) plus the
/// sans-I/O subsumption engine (instantiated at `C = OsString`, `V = ()`, `H =
/// RootHandle`). Use the [`TokioTributaries`] / [`SmolTributaries`] aliases, or any
/// other [`RuntimeLite`].
///
/// # Watching means "changes from now on"
///
/// Like the layer below, registering a subscription delivers no initial inventory
/// — start the watch, then crawl. See [`tributary_fs::Watcher`].
///
/// # Loss is never silent
///
/// Every coverage gap surfaces as a [`Rescan`](tributary_fs::EventKind::Rescan)
/// whose [`epoch`](Event::epoch) dominates everything delivered before it, fanned
/// out to *every* subscriber of the affected root (design §5/§8). Widening a watch
/// (design §4) emits a synthetic dominating `Rescan` per re-pointed subscription so
/// a consumer re-enumerates against the new, wider root.
///
/// # Concurrent read plane
///
/// [`view`](Self::view) hands out a cheap `Clone` [`WatchView`] any thread reads
/// wait-free for membership (`is_watched`) and attribution (`resolve`), reflecting the
/// last committed watch-set (design §5).
pub struct Tributaries<R: RuntimeLite> {
  watcher: Watcher<R>,
  subsumer: Subsumer<OsString, (), RootHandle>,
  /// Attributed events staged for the coalescer, or — with debounce disabled —
  /// awaiting direct delivery. One raw event can produce several (one per covering
  /// subscriber), and a widen queues a synthetic dominating `Rescan` per re-pointed
  /// subscription. With no coalescer, `next` hands these out one per call; with a
  /// coalescer, `next` drains them into it (a `Rescan` here flushes + bypasses).
  queue: VecDeque<Event<OsString, ()>>,
  /// Coalescer output awaiting hand-off, one per `next` call — populated by draining
  /// the coalescer on a settle-timer edge (empty and unused when debounce is off).
  delivered: VecDeque<Event<OsString, ()>>,
  /// The per-subscription monotone-epoch ledger (design §8): stamps every delivered
  /// event in its subscription's own epoch space (rebasing on each widen) so the raw
  /// per-`ScopeId` fs epoch — which restarts at `START` on every kernel arm — never
  /// leaks as a dominance order across a re-point.
  epochs: EpochLedger,
  /// Each live subscription's admission [`Filter`] (design §7): the fan-out gate a
  /// non-`Rescan` event must pass, on top of key coverage. The driver holds a clone
  /// that **shares the swappable slot** with the [`Filter`] the caller kept from
  /// [`watch`](Tributaries::watch), so a caller [`swap`](Filter::swap) re-scopes the
  /// subscription live — no re-watch, and the very next event sees the new predicate.
  /// A `Rescan` bypasses this map entirely (coverage loss is never filtered away).
  filters: HashMap<Subscription, Filter<OsString, ()>>,
  /// The opt-in settle/debounce coalescer (design §6), present only when the caller
  /// supplied a [`DebounceConfig`](crate::DebounceConfig). When [`None`], `next`
  /// passes attributed events through untouched (zero overhead — no coalescer is
  /// instantiated); when [`Some`], `next` admits them and delivers on the settle
  /// timer.
  coalescer: Option<Coalescer<OsString, ()>>,
  /// An in-flight widen journaled before its first disarm (design §4, cancellation
  /// safety), or [`None`] when no widen is mid-flight. Set inside
  /// [`apply_watch`] before the subsumed kernel watches are released and cleared when
  /// the widen commits or rolls back; a dropped `watch()` future leaves it [`Some`], and
  /// every public entry point calls [`resume_pending_widen`] first to repair it.
  pending_widen: Option<WidenJournal<OsString, RootHandle>>,
}

impl<R: RuntimeLite> core::fmt::Debug for Tributaries<R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Tributaries")
      .field("subsumer", &self.subsumer)
      .field("queued", &self.queue.len())
      .finish_non_exhaustive()
  }
}

impl<R: RuntimeLite> Tributaries<R> {
  /// Builds a watcher, spawning the underlying `tributary-fs` driver on `R`.
  ///
  /// Enable the opt-in settle/debounce coalescer (design §6) by setting a
  /// [`DebounceConfig`](crate::DebounceConfig) on `options`
  /// ([`TributariesOptions::debounce`]); absent it, events pass through untouched.
  ///
  /// # Errors
  ///
  /// [`BuildError::Fs`] when the underlying `tributary-fs` watcher cannot be built.
  pub fn new(options: impl Into<TributariesOptions>) -> Result<Self, BuildError> {
    let (watcher_options, debounce) = options.into().into_parts();
    Ok(Self {
      watcher: Watcher::new(watcher_options)?,
      subsumer: Subsumer::new(),
      queue: VecDeque::new(),
      delivered: VecDeque::new(),
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
      coalescer: debounce.map(Coalescer::new),
      pending_widen: None,
    })
  }

  /// A cheap `Clone` concurrent read handle over the watch-set (design §5): any thread
  /// answers `is_watched` / `resolve` from it wait-free, reflecting the last committed
  /// watch-set. See [`WatchView`].
  #[inline]
  #[must_use]
  pub fn view(&self) -> WatchView<OsString, (), RootHandle> {
    self.subsumer.view()
  }

  /// Subscribes to `path` with `interest` and admission `filter`, returning its
  /// [`Subscription`].
  ///
  /// Overlapping paths are accepted: they are subsumed onto a shared kernel watch
  /// (design §4), so this never surfaces the `Overlaps` the layer below rejects.
  /// Widening an existing watch re-points the subsumed subscriptions onto the new
  /// wider root and delivers each a synthetic dominating
  /// [`Rescan`](tributary_fs::EventKind::Rescan) (design §8).
  ///
  /// # Filtering, and swapping it live
  ///
  /// `filter` is this subscription's admission gate (design §7): a non-`Rescan` event
  /// is delivered to it only if its key covers the event **and** `filter` admits the
  /// delivery. Pass [`Filter::all`] to admit everything. A
  /// [`Rescan`](tributary_fs::EventKind::Rescan) always bypasses the filter — coverage
  /// loss is never filtered away.
  ///
  /// The `filter` is **live-swappable**: the driver keeps a clone that shares the
  /// swappable slot with the [`Filter`] you pass, so retaining your own handle (a
  /// [`Filter`] is [`Clone`], and a clone shares the slot) lets you call
  /// [`Filter::swap`] at any time to re-scope what this subscription delivers —
  /// without a re-watch. Construct the filter, keep a clone, hand one to `watch`:
  ///
  /// ```no_run
  /// # async fn ex(w: &mut tributaries::TokioTributaries) -> Result<(), Box<dyn std::error::Error>> {
  /// use tributaries::{Filter, Interest};
  /// let filter = Filter::new(|e| e.path().extension().is_some_and(|x| x == "rs"));
  /// let handle = filter.clone(); // shares the slot with the one `watch` holds
  /// let sub = w.watch("/project", Interest::all(), filter).await?;
  /// // Later, widen what `sub` delivers — live, no re-watch:
  /// handle.swap(|_| true);
  /// # Ok(()) }
  /// ```
  ///
  /// # Errors
  ///
  /// - [`WatchError::Canonicalize`] when `path` cannot be canonicalized;
  /// - [`WatchError::Fs`] when arming the kernel watch fails.
  pub async fn watch(
    &mut self,
    path: impl AsRef<Path>,
    interest: Interest,
    filter: Filter<OsString, ()>,
  ) -> Result<Subscription, WatchError> {
    // Repair any widen a previously-dropped `watch()` future left mid-transaction before
    // starting our own (design §4, cancellation safety).
    self.resume_pending_widen().await;
    let supplied = path.as_ref();
    let canonical = std::fs::canonicalize(supplied).map_err(|source| WatchError::Canonicalize {
      path: supplied.to_path_buf(),
      source,
    })?;
    let sub = apply_watch(
      &mut self.subsumer,
      &mut self.epochs,
      &mut self.filters,
      &mut self.queue,
      &mut self.pending_widen,
      &self.watcher,
      &canonical,
      interest,
    )
    .await?;
    // The subscription is live: record its filter (a clone shares the caller's
    // swappable slot, so a later `Filter::swap` re-scopes delivery live). Only
    // recorded on success — a failed arm establishes no subscription.
    self.filters.insert(sub, filter);
    Ok(sub)
  }

  /// Drops `sub`, releasing its kernel watch once it was the last subscriber of its
  /// (possibly shared) root.
  ///
  /// # Errors
  ///
  /// - [`UnwatchError::UnknownSubscription`] when `sub` is not live;
  /// - [`UnwatchError::Fs`] when releasing the now-empty kernel watch fails.
  pub async fn unwatch(&mut self, sub: Subscription) -> Result<(), UnwatchError> {
    // Repair any widen a previously-dropped `watch()` future left mid-transaction before
    // touching subscription state (design §4, cancellation safety).
    self.resume_pending_widen().await;
    match self.subsumer.plan_unwatch(sub) {
      None => Err(UnwatchError::UnknownSubscription),
      Some(UnwatchOutcome::Dropped) => {
        // The subscription is gone; drop its per-sub state (filter + epoch ledger) so
        // both maps track only live subs — an unwatch must reclaim the epoch base and
        // high-water too, or a watch → repoint → unwatch churn leaks them unbounded.
        self.filters.remove(&sub);
        self.epochs.remove(sub);
        Ok(())
      }
      Some(UnwatchOutcome::RootEmptied { fs_root }) => {
        self.filters.remove(&sub);
        self.epochs.remove(sub);
        self.watcher.disarm(fs_root).await
      }
    }
  }

  /// The next attributed event, or `None` once the watcher is closed and drained.
  ///
  /// Pulls from the underlying stream, resolves each raw event's root by its
  /// `root()` handle (O(1), not a radix walk), fans it out to every covering
  /// subscription (design §5), and hands the results out one per call.
  ///
  /// With the settle coalescer enabled (design §6) each attributed event is admitted
  /// into it and deliveries come out on the settle timer — a burst to one key
  /// collapses to a single event, while a [`Moved`](tributary_fs::EventKind::Moved)
  /// stays atomic and a [`Rescan`](tributary_fs::EventKind::Rescan) jumps the queue.
  /// Absent the coalescer, events pass through untouched.
  pub async fn next(&mut self) -> Option<Event<OsString, ()>> {
    // Repair any widen a previously-dropped `watch()` future left mid-transaction before
    // draining events (design §4, cancellation safety); its restore queues the dominating
    // Rescans the loops below then deliver.
    self.resume_pending_widen().await;
    if self.coalescer.is_some() {
      self.next_debounced().await
    } else {
      self.next_passthrough().await
    }
  }

  /// The debounce-disabled path: fan out and deliver directly, one per call.
  async fn next_passthrough(&mut self) -> Option<Event<OsString, ()>> {
    loop {
      if let Some(event) = self.queue.pop_front() {
        return Some(event);
      }
      let raw = self.watcher.next().await?;
      let fanned = self.fan_out_raw(&raw);
      self.queue.extend(fanned);
      self.retire_if_dead_root(&raw).await;
    }
  }

  /// The debounce-enabled path (design §6): admit every attributed event into the
  /// coalescer and deliver its output on the settle timer.
  ///
  /// Each iteration first hands off any already-coalesced event; else it feeds the
  /// coalescer whatever fan-out/widen events are staged in `queue`, drains what has
  /// come due, and — if nothing is due — races the underlying stream against the
  /// coalescer's next deadline. A stream close force-flushes the coalesced tail so a
  /// still-settling burst is never dropped (no-silent-loss).
  async fn next_debounced(&mut self) -> Option<Event<OsString, ()>> {
    loop {
      if let Some(event) = self.delivered.pop_front() {
        return Some(event);
      }

      // Admit every staged attributed event (fan-out results and widen Rescans) into
      // the coalescer at the current instant, then release everything now due.
      let now = R::now();
      let coalescer = self
        .coalescer
        .as_mut()
        .expect("debounced path holds a coalescer");
      for event in self.queue.drain(..) {
        coalescer.admit(event, now.into());
      }
      let mut ready = Vec::new();
      coalescer.drain_ready(now.into(), &mut ready);
      if !ready.is_empty() {
        self.delivered.extend(ready);
        continue;
      }

      // Nothing due yet. Race the stream against the nearest settle deadline: whichever
      // fires first, loop and re-drain. With no deadline (the coalescer is empty) just
      // await the stream.
      let deadline = coalescer.next_deadline();
      let raw = match deadline {
        Some(at) => match R::timeout_at(at.into(), self.watcher.next()).await {
          // The stream produced an event before the deadline: fan it out and admit it.
          Ok(Some(raw)) => raw,
          // The stream closed while entries were still settling: force-emit the tail.
          Ok(None) => {
            let mut tail = Vec::new();
            self
              .coalescer
              .as_mut()
              .expect("debounced path holds a coalescer")
              .flush_all(&mut tail);
            if tail.is_empty() {
              return None;
            }
            self.delivered.extend(tail);
            continue;
          }
          // The deadline arrived first: loop to drain the now-due entries.
          Err(_elapsed) => continue,
        },
        // The coalescer is empty: nothing to time out on, just await the stream.
        None => self.watcher.next().await?,
      };
      let fanned = self.fan_out_raw(&raw);
      self.queue.extend(fanned);
      self.retire_if_dead_root(&raw).await;
    }
  }

  /// Resolves one raw event's root and fans it out to every covering, admitting
  /// subscriber, stamping each delivery in that subscriber's own monotone epoch space
  /// (design §5/§7/§8). An event whose root has no live entry (its subscription(s) were
  /// dropped between the kernel emitting it and us routing it) fans out to nothing.
  ///
  /// A [`Moved`](tributary_fs::EventKind::Moved) is decomposed per subscriber inside
  /// [`fan_out`](crate::route::fan_out) (both endpoints → the whole move; source only →
  /// a synthesized `Removed`; destination only → a synthesized `Created`), and the
  /// filter + interest gate below runs against that already-projected delivery — so a
  /// move-out is gated by `removed` interest, a move-in by `created`, a whole move by
  /// `moved`.
  fn fan_out_raw(&mut self, raw: &tributary_fs::Event) -> Vec<Event<OsString, ()>> {
    // Disjoint field borrows: `subsumer` resolves the root/coverage/interest, `filters`
    // the per-subscription filter, `epochs` owns the per-subscription stamp state.
    let (subsumer, filters, epochs) = (&self.subsumer, &self.filters, &mut self.epochs);
    let Some(record) = subsumer.entry(raw.root()) else {
      return Vec::new();
    };
    let subscribers = record.subscribers.as_slice();
    // Adapt the raw fs event into the pure `RoutableEvent<OsString>` seam, precomputing
    // its located key (and, for a move, its source key) in the OsString-component space
    // the router covers over.
    let routable = FsRoutable::new(raw);
    // `raw.epoch()` is the fs epoch of this event on its current root; `set_epoch`
    // binds the umbrella stamp, rebasing away the raw fs epoch (which restarts per
    // kernel arm).
    let raw_epoch = raw.epoch();
    epochs.stamp_and_fan_out(
      &routable,
      raw_epoch,
      subscribers,
      |sub| subsumer.subscription_key(sub),
      // The admission gate (design §5/§7): a covered non-`Rescan` projection is kept
      // only if the subscription's **interest** admits its (projected) kind AND its
      // **filter** admits it. Interest is a pure fan-out gate here because every root is
      // armed `Interest::all` (design §4). A subscription with no recorded
      // interest/filter (raced concurrent drop) admits nothing. A `Rescan` never
      // reaches here (fan_out bypasses both gates for it).
      |sub, event: &Event<OsString, ()>| {
        subsumer
          .subscription_interest(sub)
          .is_some_and(|interest| interest_admits(interest, event.kind()))
          && filters.get(&sub).is_some_and(|filter| filter.admits(event))
      },
      |event: &Event<OsString, ()>| event.subscription(),
      |mut event, stamp| {
        event.set_epoch(stamp);
        event
      },
    )
  }

  /// Retires a lower root that has died, **after** its terminal signal was fanned out
  /// (design §4, dead-root retirement). When a watched root is deleted, `tributary-fs`
  /// tears its handle down and emits a terminal [`Rescan`](tributary_fs::EventKind::Rescan);
  /// the fan-out above delivered that Rescan to every subscriber (so the loss is never
  /// silent), and this then removes the now-dead root from the subsumer and reclaims its
  /// subscribers' per-subscription state (filter + epoch ledger).
  ///
  /// Without this, the stale subsumer entry makes a later [`watch`](Self::watch) of the
  /// recreated path resolve as `Covered` against a **dead** handle — the new subscription
  /// would receive nothing, with no loss signal. Retirement lets a subsequent watch
  /// re-arm a fresh kernel root (`Disjoint`, not `Covered`).
  ///
  /// The liveness probe is [`RootArmer::root_path`] returning [`None`] on a terminal
  /// `Rescan`: `tributary-fs` clears a torn-down handle from its read view, so `root_path`
  /// answers `None` exactly for a dead root (a live root, or a non-terminal Rescan on a
  /// still-live root, keeps a `Some` path and is left alone). Only an fs-sourced terminal
  /// signal reaches here — the synthetic widen/rollback Rescans are queued directly, never
  /// pulled from the stream — so this never races an in-flight journaled widen (which is
  /// already resumed at every entry point before a raw event is pulled).
  async fn retire_if_dead_root(&mut self, raw: &tributary_fs::Event) {
    // Only a terminal Rescan whose root fs no longer knows about is retired. A non-Rescan
    // event, or a Rescan on a still-live root (overflow re-enumeration), leaves the root.
    if !raw.is_rescan() || RootArmer::root_path(&self.watcher, raw.root()).is_some() {
      return;
    }
    // Tear the dead root out and reclaim each subscriber's filter + epoch state. The
    // terminal Rescan was already queued above, so subscribers keep their loss signal.
    for sub in self.subsumer.force_remove_root(raw.root()) {
      self.filters.remove(&sub);
      self.epochs.remove(sub);
    }
  }

  /// Closes the watcher: tears the underlying `tributary-fs` watcher down and
  /// resolves once its driver has quiesced. Buffered attributed events (and any
  /// still-settling coalescer entries) are dropped.
  ///
  /// # Errors
  ///
  /// [`CloseError::Fs`] when the underlying watcher cannot confirm its shutdown.
  pub async fn close(mut self) -> Result<(), CloseError> {
    // Repair any widen a previously-dropped `watch()` future left mid-transaction so the
    // subsumed roots are not torn down still-disarmed (design §4, cancellation safety).
    // Its queued Rescans are dropped with the watcher on close, as any buffered event is.
    self.resume_pending_widen().await;
    Ok(self.watcher.close().await?)
  }

  /// Repairs a widen a previously-dropped `watch()` future left mid-transaction, bringing
  /// state back to a consistent pre-widen coverage (design §4, cancellation-safety
  /// journaling). Called at the top of every public entry point ([`watch`](Self::watch),
  /// [`next`](Self::next), [`unwatch`](Self::unwatch), [`close`](Self::close)) before it
  /// does its own work. A no-op when nothing is journaled, and idempotent (see
  /// [`resume_pending_widen`]).
  async fn resume_pending_widen(&mut self) {
    resume_pending_widen(
      &mut self.subsumer,
      &mut self.epochs,
      &mut self.filters,
      &mut self.queue,
      &mut self.pending_widen,
      &self.watcher,
    )
    .await;
  }
}

/// The pure `RoutableEvent<OsString>` adapter over one raw fs event (design §5): it
/// precomputes the event's located key — and, for a move, its source key — in the
/// `OsString`-component space the router covers over, and mints each delivery by
/// retagging the wrapped fs event. The router thus stays key-generic and I/O-free while
/// the fs-specific key extraction lives at this one boundary.
struct FsRoutable<'a> {
  event: &'a tributary_fs::Event,
  key: Vec<OsString>,
  from: Option<Vec<OsString>>,
}

impl<'a> FsRoutable<'a> {
  fn new(event: &'a tributary_fs::Event) -> Self {
    let key = path_components(event.path());
    let from = event
      .kind()
      .moved()
      .map(|m| path_components(MovedEvent::from(m)));
    Self { event, key, from }
  }
}

impl RoutableEvent<OsString> for FsRoutable<'_> {
  type Delivered = Event<OsString, ()>;

  #[inline]
  fn key(&self) -> &[OsString] {
    &self.key
  }

  #[inline]
  fn move_from(&self) -> Option<&[OsString]> {
    self.from.as_deref()
  }

  #[inline]
  fn is_rescan(&self) -> bool {
    self.event.is_rescan()
  }

  #[inline]
  fn deliver(&self, sub: Subscription) -> Event<OsString, ()> {
    Event::from_fs(sub, self.event.clone())
  }

  #[inline]
  fn deliver_move_out(&self, sub: Subscription) -> Event<OsString, ()> {
    Event::move_out(sub, self.event)
  }

  #[inline]
  fn deliver_move_in(&self, sub: Subscription) -> Event<OsString, ()> {
    Event::move_in(sub, self.event)
  }
}

/// Plans and applies one `watch` against `armer`, threading the outcome through the
/// sans-I/O [`Subsumer`]. Factored out of [`Tributaries::watch`] so the widen
/// ordering, the arm-failure unwind, and the fs-canonical re-key are testable with a
/// fake [`RootArmer`].
///
/// **Roots are always armed [`Interest::all`]** (design §4): the kernel watch never
/// narrows what it collects, so a covered/subsumed subscription can ask for any kind
/// and the root already carries it (interest becomes a pure fan-out gate, §5). The
/// caller's `interest` is recorded on the subscription (for that gate), not passed to
/// the arm.
///
/// **The committed key is fs's, not the umbrella's** (design §4, TOCTOU close): after
/// arming, the fs-authoritative canonical path is read from [`RootArmer::root_path`]
/// and its components used as the subsumption key, so events (which are fs-canonical)
/// always route. If that path diverges from the plan in a way that changes subsumption,
/// the just-armed root is disarmed and the watch aborts cleanly rather than committing
/// a mis-keyed or overlapping entry.
///
/// The ordering contract (design §4): on a widen, **unwatch the subsumed roots first,
/// then arm the wider root** — the lower watcher rejects a root overlapping a live one
/// with `Overlaps`, so the wider root cannot be armed while a subsumed one is still
/// live. The brief coverage gap is closed by the dominating
/// [`Rescan`](tributary_fs::EventKind::Rescan) each re-pointed subscription receives.
/// If the wider arm fails the subsumed roots are **rolled back** (re-armed, each
/// subscriber re-pointed with its own dominating `Rescan`); if a rollback re-arm itself
/// fails, the affected subscribers are signalled a loss `Rescan` and their now-uncoverable
/// root is torn out. Every path either commits or aborts ([`Subsumer::abort_watch`]) so
/// no pending reservation leaks.
// The driver threads its per-widen state (subsumer, epoch ledger, filters, event queue,
// cancellation journal) plus the armer and the plan inputs; bundling them into a struct
// would only obscure the plain data-flow of a single `watch` transaction.
#[allow(clippy::too_many_arguments)]
async fn apply_watch<A: RootArmer>(
  subsumer: &mut Subsumer<OsString, (), A::Handle>,
  epochs: &mut EpochLedger,
  filters: &mut HashMap<Subscription, Filter<OsString, ()>>,
  queue: &mut VecDeque<Event<OsString, ()>>,
  journal: &mut Option<WidenJournal<OsString, A::Handle>>,
  armer: &A,
  canonical: &Path,
  interest: Interest,
) -> Result<Subscription, WatchError> {
  let key = path_components(canonical);
  let outcome = subsumer.plan_watch(&key, (), interest);
  match &outcome {
    WatchOutcome::Covered { fs_root, sub } => {
      // Already covered by a live (Interest::all-armed) root: no kernel call. The
      // covering root's key was validated when it was first armed, so the newcomer's
      // own key is used unchanged (commit ignores the fs-key arg for Covered).
      let (fs_root, sub) = (*fs_root, *sub);
      subsumer.commit_watch(&outcome, fs_root, &key);
      Ok(sub)
    }
    WatchOutcome::Disjoint { sub, .. } => {
      let sub = *sub;
      let fs_root = match armer.arm(canonical, Interest::all()).await {
        Ok(fs_root) => fs_root,
        Err(err) => {
          // Arm failed: abandon the plan so its pending reservation cannot leak.
          subsumer.abort_watch(&outcome);
          return Err(err);
        }
      };
      // Re-key onto fs's authoritative canonical path (design §4). If it diverges in a
      // way that changes subsumption, disarm and abort cleanly — no mis-keyed entry.
      let fs_path = fs_canonical_root(armer, fs_root, canonical);
      let fs_key = path_components(&fs_path);
      if !subsumer.fs_path_preserves_plan(&fs_key, &[]) {
        let _ = armer.disarm(fs_root).await;
        subsumer.abort_watch(&outcome);
        return Err(canonical_race(canonical, &fs_path));
      }
      subsumer.commit_watch(&outcome, fs_root, &fs_key);
      Ok(sub)
    }
    WatchOutcome::Widen {
      repointed,
      unwatch,
      sub,
      ..
    } => {
      let sub = *sub;

      // Journal the widen BEFORE the first disarm (design §4, cancellation safety): if
      // this future is dropped between a disarm and the commit/rollback below, no async
      // cleanup can run in `Drop`, so the next public entry point reads this journal and
      // repairs the disarmed roots. Cleared on EVERY exit path (commit or either
      // rollback) below.
      *journal = Some(WidenJournal {
        outcome: outcome.clone(),
      });

      // Unwatch-old-then-arm-new (design §4): the lower watcher rejects a root that
      // overlaps a live one, so the wider root cannot be armed while a subsumed one is
      // still live. Release the subsumed *kernel* watches FIRST (the subsumer's own
      // index is untouched here, so `commit_watch`'s index transition stays atomic on
      // success). The coverage gap this opens is closed by the dominating Rescan each
      // re-pointed subscription receives below.
      for old in unwatch {
        let _ = armer.disarm(*old).await;
      }

      // Now arm the wider root — no live overlap remains to reject it. The new wider
      // root's key equals the newcomer's own `canonical`.
      let fs_root = match armer.arm(canonical, Interest::all()).await {
        Ok(fs_root) => fs_root,
        Err(err) => {
          rollback_widen(subsumer, epochs, filters, queue, armer, unwatch).await;
          subsumer.abort_watch(&outcome);
          *journal = None;
          return Err(err);
        }
      };
      // Re-key onto fs's authoritative canonical path (design §4). A divergence that
      // changes which roots this widens over (or makes it covered) invalidates the plan.
      let fs_path = fs_canonical_root(armer, fs_root, canonical);
      let fs_key = path_components(&fs_path);
      if !subsumer.fs_path_preserves_plan(&fs_key, unwatch) {
        let _ = armer.disarm(fs_root).await;
        rollback_widen(subsumer, epochs, filters, queue, armer, unwatch).await;
        subsumer.abort_watch(&outcome);
        *journal = None;
        return Err(canonical_race(canonical, &fs_path));
      }

      // The wider root is live and adopts every re-pointed subscription. `commit_watch`
      // drops the subsumed roots' index keys + entries and installs the wider root
      // atomically. The widen has now fully committed, so the journal is cleared.
      let repointed = repointed.clone();
      subsumer.commit_watch(&outcome, fs_root, &fs_key);
      *journal = None;

      // Rebase each re-pointed subscription onto the new wider root (design §8): emit its
      // synthetic dominating Rescan at its high-water `.next()` and set its `epoch_base`
      // to that same value, so the Rescan strictly dominates the subscription's
      // pre-widening stream while the new root's genuine events tie-or-exceed it. The
      // Rescan names fs's canonical root key AND closes the unwatch→arm coverage gap.
      for moved in repointed {
        let rescan = epochs.repoint(moved);
        queue.push_back(Event::rescan(moved, fs_key.clone(), rescan));
      }

      Ok(sub)
    }
  }
}

/// Rolls a failed widen back: restores every subsumed root the widen already disarmed,
/// re-pointing its subscribers onto a fresh handle with a dominating `Rescan`, restoring
/// the pre-widen state (design §4/§8). Called when the wider arm fails (or its fs path
/// diverges) after the subsumed kernel watches were released. Each root is restored by
/// [`restore_subsumed_root`] (which handles the degenerate re-arm-also-fails case).
async fn rollback_widen<A: RootArmer>(
  subsumer: &mut Subsumer<OsString, (), A::Handle>,
  epochs: &mut EpochLedger,
  filters: &mut HashMap<Subscription, Filter<OsString, ()>>,
  queue: &mut VecDeque<Event<OsString, ()>>,
  armer: &A,
  unwatch: &[A::Handle],
) {
  // Called synchronously right after the disarm loop, so every root in `unwatch` is
  // disarmed — restore all of them unconditionally.
  for &old in unwatch {
    restore_subsumed_root(subsumer, epochs, filters, queue, armer, old).await;
  }
}

/// Restores one subsumed root a widen disarmed: re-arms it (fresh handle), re-keys the
/// subsumer entry onto that handle, and re-points every subscriber with a dominating
/// `Rescan` (design §4/§8). On the **degenerate** double-failure — the re-arm itself fails
/// — the root cannot be restored, so each subscriber is signalled a loss `Rescan` and the
/// dead root is torn out with its subscribers' per-subscription state reclaimed, rather
/// than left dangling on a never-armed handle.
///
/// A no-op if `old` has no subsumer entry (already restored or never present), so it is
/// safe to call on a root the caller is unsure about — the idempotency the
/// [`resume_pending_widen`] repair relies on. The entry's key and subscribers are read
/// straight from the subsumer (a widen commits its index transition only on success, so a
/// mid-widen entry is exactly the pre-widen state to restore).
async fn restore_subsumed_root<A: RootArmer>(
  subsumer: &mut Subsumer<OsString, (), A::Handle>,
  epochs: &mut EpochLedger,
  filters: &mut HashMap<Subscription, Filter<OsString, ()>>,
  queue: &mut VecDeque<Event<OsString, ()>>,
  armer: &A,
  old: A::Handle,
) {
  let Some(record) = subsumer.entry(old) else {
    return;
  };
  let root_key = record.key.clone();
  let subscribers = record.subscribers.clone();
  let root_path = PathBuf::from_iter(&root_key);
  match armer.arm(&root_path, Interest::all()).await {
    Ok(fresh) => {
      // Restored: re-key the root onto the fresh handle and re-point every subscriber
      // with its own dominating Rescan (the re-arm restarted fs epochs at 0).
      subsumer.rekey_root(old, fresh);
      for moved in subscribers {
        let rescan = epochs.repoint(moved);
        queue.push_back(Event::rescan(moved, root_key.clone(), rescan));
      }
    }
    Err(_) => {
      // Degenerate: the root cannot be restored. Signal each subscriber a loss Rescan
      // (no silent loss), then tear the dead root out and reclaim its subscribers'
      // per-subscription state so nothing dangles on a never-armed handle.
      for lost in subsumer.force_remove_root(old) {
        let rescan = epochs.repoint(lost);
        queue.push_back(Event::rescan(lost, root_key.clone(), rescan));
        filters.remove(&lost);
        epochs.remove(lost);
      }
    }
  }
}

/// Repairs a widen a dropped `watch()` future left mid-transaction, restoring a consistent
/// pre-widen coverage (design §4, cancellation-safety journaling). Called at the top of
/// every public entry point via [`Tributaries::resume_pending_widen`].
///
/// A dropped `watch()` future never handed out a [`Subscription`], so resuming to the
/// **pre-widen** state — the subsumed roots live-armed again, each re-pointed subscriber
/// re-enumerating via a dominating `Rescan` — leaves no subscriber uncovered and is the
/// correct repair (the newcomer simply never happened). Concretely, if `journal` is set:
///
/// 1. For each subsumed root the plan named: if fs still knows it
///    ([`RootArmer::root_path`] is `Some`), the drop happened before that disarm — leave
///    it live. If fs no longer knows it (`None` — it was disarmed), restore it via
///    [`restore_subsumed_root`].
/// 2. Abort the newcomer's partial plan ([`Subsumer::abort_watch`]) so its pending
///    reservation cannot leak.
/// 3. Clear the journal.
///
/// **Idempotent:** a no-op when `journal` is `None`, and — because step 1 probes each
/// root's liveness and [`restore_subsumed_root`] no-ops an absent entry — safe to call
/// when only some subsumed roots were disarmed, or when a prior resume already ran.
async fn resume_pending_widen<A: RootArmer>(
  subsumer: &mut Subsumer<OsString, (), A::Handle>,
  epochs: &mut EpochLedger,
  filters: &mut HashMap<Subscription, Filter<OsString, ()>>,
  queue: &mut VecDeque<Event<OsString, ()>>,
  journal: &mut Option<WidenJournal<OsString, A::Handle>>,
  armer: &A,
) {
  let Some(WidenJournal { outcome }) = journal.take() else {
    return;
  };
  let WatchOutcome::Widen { unwatch, .. } = &outcome else {
    // Only a Widen is ever journaled; a non-Widen outcome cannot occur, but clearing the
    // journal (already taken) and returning keeps this total and non-panicking.
    return;
  };
  // Restore only the subsumed roots fs no longer knows about (they were disarmed by the
  // dropped widen); leave any still-live root (its disarm never ran) untouched.
  for &old in unwatch {
    if armer.root_path(old).is_none() {
      restore_subsumed_root(subsumer, epochs, filters, queue, armer, old).await;
    }
  }
  // Discard the newcomer's pending reservation: the dropped future handed out no
  // subscription and inserted no filter, so aborting its plan fully unwinds it.
  subsumer.abort_watch(&outcome);
}

/// Whether `interest` subscribes to a delivery of `kind` — the per-subscription
/// fan-out gate (design §5). Every umbrella root is armed [`Interest::all`], so this
/// narrows *delivery* only, never the kernel watch (design §4).
///
/// A [`Rescan`](tributary_fs::EventKind::Rescan) is always admitted: it is a
/// coverage-loss signal that bypasses interest (as it bypasses coverage and the
/// filter) — though in practice a `Rescan` never reaches this gate, since
/// [`fan_out`](crate::route::fan_out) short-circuits it. An unknown future kind
/// (the vocabulary is `non_exhaustive`) is admitted conservatively rather than
/// silently dropped.
fn interest_admits(interest: Interest, kind: &tributary_fs::EventKind) -> bool {
  match kind {
    tributary_fs::EventKind::Created => interest.created(),
    tributary_fs::EventKind::Modified => interest.modified(),
    tributary_fs::EventKind::Removed => interest.removed(),
    tributary_fs::EventKind::Moved(_) => interest.moved(),
    tributary_fs::EventKind::Rescan => true,
    _ => true,
  }
}

/// The fs-authoritative canonical path for a freshly-armed root (design §4). Falls
/// back to the planned path if fs cannot report one (the handle raced a teardown) —
/// the planned path was the best canonicalization available, and a subsequent event
/// under a now-dead root routes to nothing regardless.
fn fs_canonical_root<A: RootArmer>(armer: &A, fs_root: A::Handle, planned: &Path) -> PathBuf {
  armer
    .root_path(fs_root)
    .unwrap_or_else(|| planned.to_path_buf())
}

/// The error for a canonicalization TOCTOU where fs's reported root path diverged from
/// the umbrella's provisional one in a way that changes subsumption (design §4). Framed
/// as a canonicalize failure — it *is* a canonical-coordinate mismatch — carrying the
/// planned path and the divergent fs path in the message so the cause is legible.
fn canonical_race(planned: &Path, fs_path: &Path) -> WatchError {
  WatchError::Canonicalize {
    path: planned.to_path_buf(),
    source: std::io::Error::other(format!(
      "watch root's filesystem-canonical path {} diverged from the planned {} and \
       changed subsumption; retry the watch",
      fs_path.display(),
      planned.display()
    )),
  }
}

/// A [`Tributaries`] driven by the tokio runtime.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub type TokioTributaries = Tributaries<agnostic_lite::tokio::TokioRuntime>;

/// A [`Tributaries`] driven by the smol runtime.
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub type SmolTributaries = Tributaries<agnostic_lite::smol::SmolRuntime>;
