//! The public async watcher — an **owned-task actor** — and the machinery wiring a
//! [`Source<C>`](crate::Source) to the sans-I/O
//! [`Subsumer`](crate::subsume::Subsumer), the [`fan_out`](crate::route::fan_out)
//! router, and the per-subscription [`EpochLedger`](epoch::EpochLedger).
//!
//! # The actor split (design driver-golden doc)
//!
//! One [`Owner`] task owns all the authoritative state — the [`Source`](crate::Source),
//! the [`Subsumer`](crate::subsume::Subsumer), the [`EpochLedger`](epoch::EpochLedger),
//! the per-subscription filter map, and the opt-in [`Coalescer`](crate::coalesce::Coalescer)
//! — and runs a single [`select!`](futures_util::select_biased) loop
//! ([`run`]), spawned once at construction via
//! [`R::spawn_detach`](agnostic_lite::RuntimeLite::spawn_detach). The public
//! [`Tributaries`] is a cheap `Clone` **handle** over two channels (a command mailbox
//! and a separate event stream) plus a [`WatchView`] read plane — it owns nothing whose
//! `Drop` must run async. `watch`/`unwatch`/`close` are cancellable *waits* (a `oneshot`
//! reply); dropping one drops only the waiting, never the owner's run-to-completion work
//! (invariant I1). Because event delivery is a **separate** channel from the command
//! mailbox, a mid-reconcile command never blocks [`next`](Tributaries::next).
//!
//! All I/O lives in the [`Source`](crate::Source) the owner drives; the engines it
//! orchestrates (subsumption, routing, epoch rebasing, coalescing) are pure and generic
//! over the key component `C` and caller value `V`. The pure-fs convenience fixes
//! `C = OsString`, `V = ()`, and a [`FsSource`] over one [`tributary_fs::Watcher`] (the
//! [`TokioTributaries`] / [`SmolTributaries`] aliases).

use std::{
  collections::{BTreeMap, HashMap},
  ffi::OsString,
  hash::Hash,
  marker::PhantomData,
  path::PathBuf,
  time::{Duration, Instant},
  vec::Vec,
};

use agnostic_lite::RuntimeLite;
use futures_util::FutureExt;
use tributary_fs::{Epoch, Interest, RootHandle, WatchRootError};

use crate::{
  coalesce::Coalescer,
  error::{BuildError, CloseError, UnwatchError, WatchError},
  event::Event,
  filter::{Filter, FilterInput},
  options::TributariesOptions,
  route::RoutableEvent,
  source::{FsSource, Source, SourceEvent},
  subscription::Subscription,
  subsume::{Subsumer, UnwatchOutcome, WatchOutcome},
  view::WatchView,
};

use self::epoch::EpochLedger;

mod epoch;

#[cfg(all(test, feature = "tokio"))]
mod tests;

/// A control-plane request from a [`Tributaries`] handle to its [`Owner`] — mostly carrying a
/// `oneshot` reply the caller's cancellable wait reads.
///
/// The owner processes each to completion (invariant I1): dropping the caller's returned
/// future drops only the [`oneshot::Receiver`](futures_channel::oneshot::Receiver), never
/// the reconcile the owner runs. Two variants are **reply-less**, and are the paired resolution of
/// a single committed-but-unclaimed [`WatchGrant`] — **exactly one** ever fires per grant (see
/// [`WatchGrant`]): [`ClaimGrant`](Self::ClaimGrant), enqueued by the grant's
/// [`defuse`](WatchGrant::defuse) when the caller claims the subscription, and
/// [`DropOrphan`](Self::DropOrphan), enqueued by the grant's `Drop` when the caller's `watch` wait
/// was dropped after the owner had already committed it (closing the invariant-I1 orphan window a
/// bare `Subscription` reply left open). Both drive the owner's [`unclaimed`](Owner::unclaimed)
/// suppression state — a claim lifts it (the debt is now genuinely owed), a drop purges it.
enum Command<C, V> {
  /// Subscribe to `key` (carrying caller `value`), with the given fan-out `interest` and
  /// admission `filter`.
  Watch {
    /// The located key to subsume/arm.
    key: Vec<C>,
    /// The caller value attribution returns for this watch (design §3).
    value: V,
    /// The per-subscription fan-out interest gate (design §5).
    interest: Interest,
    /// The per-subscription admission [`Filter`] (design §7).
    filter: Filter<C>,
    /// The reply channel: a [`WatchGrant`] guarding the minted [`Subscription`] (so a dropped
    /// wait cannot strand it — invariant I1), or the arm error.
    reply: futures_channel::oneshot::Sender<Result<WatchGrant<C, V>, WatchError>>,
  },
  /// Drop a live subscription.
  Unwatch {
    /// The subscription to retire.
    sub: Subscription,
    /// The reply channel: success, or why the drop failed.
    reply: futures_channel::oneshot::Sender<Result<(), UnwatchError>>,
  },
  /// Tear the owner down: flush the coalesced tail, then quiesce.
  Close {
    /// The reply channel, resolved once the owner has flushed and is tearing down.
    reply: futures_channel::oneshot::Sender<Result<(), CloseError>>,
  },
  /// Reconcile away a subscription whose caller's `watch` wait was dropped **after** the owner
  /// committed it (invariant I1). Emitted **only** by a [`WatchGrant`]'s `Drop`, so it carries no
  /// `oneshot` reply: a `Drop` is synchronous and cannot await, so the grant enqueues this with a
  /// non-blocking `try_send`. The owner treats it exactly like an [`Unwatch`](Self::Unwatch) —
  /// releasing it through the synchronous [`release_subscription`](Owner::release_subscription),
  /// whose emptied-root [`disarm`](crate::Source::disarm) is a fire-and-forget request — and ignores
  /// the result (it is cleanup, not a caller request). Because that release awaits nothing, a `Close`
  /// queued behind a `DropOrphan` is never blocked (invariant II — Close-responsive by construction).
  /// `release_subscription` also removes the sub from [`unclaimed`](Owner::unclaimed) (purging its
  /// suppressed parked debt). The **exactly-one-of-two** twin of [`ClaimGrant`](Self::ClaimGrant).
  DropOrphan(Subscription),
  /// Lift the [`unclaimed`](Owner::unclaimed) suppression for a subscription the caller **claimed**
  /// (invariant I1). Enqueued **only** by a [`WatchGrant`]'s [`defuse`](WatchGrant::defuse), which is
  /// synchronous, so it too carries no `oneshot` reply and rides a non-blocking `try_send` on the
  /// grant's held strong `commands` sender. Processing it just removes the sub from `unclaimed`, so
  /// its parked overflow/terminal `Rescan` (if any) is no longer suppressed — a claimed subscription
  /// is genuinely owed its debt (see [`flush_pending_rescans`](Owner::flush_pending_rescans)). A pure
  /// [`HashSet`](std::collections::HashSet) remove that awaits nothing, so a `Close` behind it is
  /// never blocked (invariant II). The **exactly-one-of-two** twin of [`DropOrphan`](Self::DropOrphan):
  /// `defuse` consumes the grant and sets `defused`, so the grant's `Drop` then no-ops.
  ClaimGrant(Subscription),
}

/// A single-use RAII grant carrying a freshly-committed [`Subscription`] back to a waiting
/// [`watch`](Tributaries::watch) call — the fix that closes the invariant-I1 orphan window
/// (design driver-golden doc, mirroring the lower fs layer's arm-grant pattern).
///
/// The owner commits the subscription (subsumer entry, filter, epoch state, possibly an armed
/// root), records it in [`unclaimed`](Owner::unclaimed) (so its parked debt is suppressed while in
/// flight — see [`flush_pending_rescans`](Owner::flush_pending_rescans)), and sends the grant
/// through the reply `oneshot`. **Exactly one** of two reply-less commands then fires per grant,
/// resolving that suppression:
///
/// - the caller's wait observes the reply → it [`defuse`](Self::defuse)s the grant, which enqueues
///   a [`ClaimGrant`](Command::ClaimGrant) (lifting the suppression — the caller now holds the sub,
///   so its debt is genuinely owed) and takes the [`Subscription`]; the grant's `Drop` then no-ops,
///   so a normal successful `watch` runs **no** extra reconcile;
/// - the caller's wait is dropped before it observes the reply — whether the receiver was already
///   gone the instant the owner sent, OR it vanished in the **post-send, pre-poll** window that a
///   bare `Subscription` reply could not cover — the grant is dropped instead, and its `Drop`
///   best-effort enqueues a reply-less [`DropOrphan`](Command::DropOrphan) the owner reconciles
///   away, releasing the root / filter / epoch / `unclaimed` entry exactly like an
///   [`unwatch`](Tributaries::unwatch).
///
/// `defuse` consuming the grant (setting `defused`) is what makes it exactly-one-of-two: a defused
/// grant's `Drop` enqueues nothing, so `ClaimGrant` and `DropOrphan` are mutually exclusive.
///
/// So a committed-but-unclaimed subscription can never be stranded advertised-yet-unreachable.
/// The `Drop` fires at most once (Rust drops each value once) and is idempotent even against a
/// racing retire — [`release_subscription`](Owner::release_subscription) treats an already-gone
/// subscription as `Unknown` and no-ops — so it can neither double-fire nor double-free.
struct WatchGrant<C, V> {
  /// The committed subscription this grant guards until the caller claims it.
  sub: Subscription,
  /// A **strong** clone of the owner's command `Sender`, kept alive for the whole life of the
  /// grant so the command channel stays open across its `Drop`'s non-blocking enqueue — the
  /// grant's own live `Sender` is what makes the `DropOrphan` `try_send` unloseable, independent
  /// of whether any [`Tributaries`] handle still exists.
  commands: async_channel::Sender<Command<C, V>>,
  /// Set by [`defuse`](Self::defuse) once the caller has claimed the subscription: a defused
  /// grant's `Drop` enqueues nothing.
  defused: bool,
}

impl<C, V> WatchGrant<C, V> {
  /// Wraps a just-committed `sub` with the command `Sender` its `Drop` uses to reconcile it
  /// away should the caller's wait never claim it.
  fn new(sub: Subscription, commands: async_channel::Sender<Command<C, V>>) -> Self {
    Self {
      sub,
      commands,
      defused: false,
    }
  }

  /// Claims the subscription for a caller that observed the reply, defusing the grant so its
  /// `Drop` enqueues no cleanup — the normal successful `watch` path.
  ///
  /// Before returning the [`Subscription`], best-effort enqueue a reply-less
  /// [`ClaimGrant`](Command::ClaimGrant) on the grant's held strong `commands` sender so the owner
  /// lifts this sub's [`unclaimed`](Owner::unclaimed) suppression (the caller now holds it, so any
  /// parked debt is genuinely owed). A `defuse` is synchronous and cannot await, so it is a
  /// non-blocking [`try_send`](async_channel::Sender::try_send); a closed channel means the owner is
  /// already tearing down and the claim is moot (the sub is dead like any post-teardown sub). This
  /// and the `Drop`'s [`DropOrphan`](Command::DropOrphan) are **exactly-one-of-two**: setting
  /// `defused` makes the subsequent `Drop` a no-op.
  fn defuse(mut self) -> Subscription {
    self.defused = true;
    let _ = self.commands.try_send(Command::ClaimGrant(self.sub));
    self.sub
  }
}

impl<C, V> Drop for WatchGrant<C, V> {
  /// If the grant was never [`defuse`](Self::defuse)d — the caller's wait was dropped before it
  /// claimed the subscription — best-effort enqueue a reply-less [`DropOrphan`](Command::DropOrphan)
  /// so the owner reconciles the orphan away (invariant I1). A `Drop` cannot block or await, so this
  /// is a non-blocking [`try_send`](async_channel::Sender::try_send); the command channel is
  /// unbounded (a control plane) and this grant still holds a live `Sender`, so the enqueue can be
  /// lost neither to a full channel nor to a closed one.
  fn drop(&mut self) {
    if !self.defused {
      let _ = self.commands.try_send(Command::DropOrphan(self.sub));
    }
  }
}

/// The public top-level watcher: overlapping subscriptions in, attributed events out.
///
/// A cheap `Clone` **handle** over an owned-task actor (design driver-golden doc): a
/// command mailbox to the owner task, a separate event stream the owner pushes to, and a
/// concurrent-read [`WatchView`]. It is generic over the key component `C`, the caller
/// value `V`, the runtime `R`, and the source's armed-root handle `H` (defaulting to the
/// filesystem [`RootHandle`]). Build one over any [`Source`] with
/// [`with_source`](Self::with_source), or use the pure-fs [`TokioTributaries`] /
/// [`SmolTributaries`] aliases and their [`new`](Self::new) constructor.
///
/// # Watching means "changes from now on"
///
/// Like the layer below, registering a subscription delivers no initial inventory —
/// start the watch, then crawl. See [`tributary_fs::Watcher`].
///
/// # Loss is never silent
///
/// Every coverage gap surfaces as a [`Rescan`](tributary_fs::EventKind::Rescan) whose
/// [`epoch`](Event::epoch) dominates everything delivered before it, fanned out to
/// *every* subscriber of the affected root (design §5/§8). Widening a watch (design §4)
/// emits a synthetic dominating `Rescan` per re-pointed subscription so a consumer
/// re-enumerates against the new, wider root.
///
/// # Concurrent read plane
///
/// [`view`](Self::view) hands out a cheap `Clone` [`WatchView`] any thread reads
/// wait-free for membership (`is_watched`) and attribution (`resolve`), reflecting the
/// last committed watch-set (design §5).
pub struct Tributaries<C, V, R: RuntimeLite, H = RootHandle> {
  /// The control plane: `watch`/`unwatch`/`close` send a [`Command`] here and await its
  /// `oneshot` reply. Dropping every handle clone closes this channel, so the owner's
  /// `recv` errors and it tears down (design driver-golden doc, Close/Drop).
  commands: async_channel::Sender<Command<C, V>>,
  /// The data plane: [`next`](Self::next) drains attributed, epoch-stamped, coalesced
  /// events the owner pushes here — a **separate** channel from the command mailbox, so a
  /// mid-reconcile command never blocks delivery.
  events: async_channel::Receiver<Event<C, V>>,
  /// The concurrent read plane (design §5): a cheap `Clone` handle over the last
  /// committed watch-set, read wait-free by any thread.
  view: WatchView<C, V, H>,
  _rt: PhantomData<R>,
}

impl<C, V, R: RuntimeLite, H> core::fmt::Debug for Tributaries<C, V, R, H> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Tributaries")
      .field("view", &self.view)
      .finish_non_exhaustive()
  }
}

impl<C, V, R: RuntimeLite, H> Clone for Tributaries<C, V, R, H> {
  /// Shares the same actor: every clone sends to the one command mailbox, draws from the
  /// one event stream, and reads the one published watch-set. The last clone dropped
  /// closes the command channel and tears the owner down.
  #[inline]
  fn clone(&self) -> Self {
    Self {
      commands: self.commands.clone(),
      events: self.events.clone(),
      view: self.view.clone(),
      _rt: PhantomData,
    }
  }
}

impl<C, V, R, H> Tributaries<C, V, R, H>
where
  C: Ord + Clone + Send + Sync + 'static,
  V: Clone + Send + Sync + 'static,
  R: RuntimeLite,
  H: Copy + Eq + Hash + Send + Sync + 'static,
{
  /// Builds a watcher over any [`Source`], spawning the owned-task owner on `R`.
  ///
  /// Enable the opt-in settle/debounce coalescer (design §6) by setting a
  /// [`DebounceConfig`](crate::DebounceConfig) on `options`
  /// ([`TributariesOptions::debounce`]); absent it,
  /// events pass through untouched. For a pre-built source only the debounce policy is
  /// read (the source owns its own transport configuration), so the watcher options
  /// embedded in `options` are unused here.
  ///
  /// This is the generic construction path; the pure-fs [`new`](Self::new) builds a
  /// [`FsSource`] and delegates here.
  pub fn with_source<S>(source: S, options: impl Into<TributariesOptions>) -> Self
  where
    S: Source<C, Handle = H> + Send + 'static,
  {
    // The source is already constructed, so its watcher options no longer apply here; the
    // event-channel capacity and the debounce policy are what the owner still wires up.
    let (_watcher_options, event_capacity, debounce) = options.into().into_parts();
    let subsumer = Subsumer::new();
    let view = subsumer.view();
    // Bounded (design backpressure doc): the owner **never awaits** this channel — every
    // emit is a non-blocking `try_send` (`try_emit`), so `Close` is always serviced and the
    // loop can never deadlock mid-push. A generous capacity absorbs ordinary bursts
    // in-order; when a stalled consumer fills it, the owner sheds the affected subscription
    // to a durable dominating `Rescan` (`needs_rescan`) rather than growing memory without
    // bound — bounded memory with no silent loss.
    let (event_tx, event_rx) = async_channel::bounded(event_capacity.get());
    let (command_tx, command_rx) = async_channel::unbounded();
    let owner = Owner {
      source,
      subsumer,
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
      needs_rescan: BTreeMap::new(),
      unclaimed: std::collections::HashSet::new(),
      coalescer: debounce.map(Coalescer::new),
      // A weak self-clone (downgrade takes `&self`, so `command_tx` is still moved into the handle
      // below): grants upgrade it to enqueue a `DropOrphan` without keeping the channel open.
      commands_weak: command_tx.downgrade(),
      commands: command_rx,
      events: event_tx,
      #[cfg(debug_assertions)]
      observed_handles: std::collections::HashSet::new(),
      _rt: PhantomData::<R>,
    };
    R::spawn_detach(run(owner));
    Self {
      commands: command_tx,
      events: event_rx,
      view,
      _rt: PhantomData,
    }
  }
}

impl<C, V, R: RuntimeLite, H> Tributaries<C, V, R, H> {
  /// A cheap `Clone` concurrent read handle over the watch-set (design §5): any thread
  /// answers `is_watched` / `resolve` from it wait-free, reflecting the last committed
  /// watch-set. See [`WatchView`].
  #[inline]
  #[must_use]
  pub fn view(&self) -> WatchView<C, V, H> {
    self.view.clone()
  }

  /// Subscribes to `key` (carrying caller `value`) with `interest` and admission
  /// `filter`, returning its [`Subscription`].
  ///
  /// Overlapping keys are accepted: they are subsumed onto a shared root (design §4), so
  /// this never surfaces the overlap the layer below rejects. Widening an existing watch
  /// re-points the subsumed subscriptions onto the new wider root and delivers each a
  /// synthetic dominating [`Rescan`](tributary_fs::EventKind::Rescan) (design §8).
  ///
  /// # Key canonicalization
  ///
  /// Every watch `key` is canonicalized at the driver's single arm-and-key choke point — via
  /// [`Source::canonicalize_key`] — **before** it is classified against the watch-set, so a
  /// subscription is always keyed on the source's canonical coordinate (the one its events arrive
  /// under). For the filesystem source a non-canonical `key` (a symlinked or `.`/`..`-laden path)
  /// is resolved to its real path; a key that cannot be canonicalized (for the fs source, one that
  /// does not exist) is rejected with [`WatchError::Canonicalize`]. This closes the trap the old
  /// contract warned about — where a non-canonical key subsumed under an already-watched canonical
  /// root was committed verbatim and then silently missed every event, because real events arrived
  /// under the canonical coordinate its key never matched. A source whose keys are already
  /// canonical (a generic component key) implements
  /// [`canonicalize_key`](Source::canonicalize_key) as the identity.
  ///
  /// This sends a watch command to the owner and awaits its reply. Dropping the
  /// returned future drops only the wait — the owner still runs the reconcile to
  /// completion, and if the caller vanished after the watch committed the owner retires
  /// the orphaned subscription itself (invariant I1).
  ///
  /// `filter` is this subscription's admission gate (design §7): a non-`Rescan` event is
  /// delivered only if its key covers the event **and** `filter` admits it. Pass
  /// [`Filter::all`] to admit everything; a [`Rescan`](tributary_fs::EventKind::Rescan)
  /// always bypasses it. The filter is live-swappable: keep a [`clone`](Filter::clone)
  /// and [`swap`](Filter::swap) it to re-scope delivery without a re-watch.
  ///
  /// # Errors
  ///
  /// - [`WatchError::Canonicalize`] when `key` cannot be canonicalized (for the fs source, the
  ///   path does not exist), or the source's committed key diverged and changed subsumption;
  /// - [`WatchError::Fs`] when arming the source watch fails;
  /// - [`WatchError::Fs(WatchRootError::Closed)`](tributary_fs::WatchRootError::Closed)
  ///   when the owner is gone.
  pub async fn watch(
    &self,
    key: Vec<C>,
    value: V,
    interest: Interest,
    filter: Filter<C>,
  ) -> Result<Subscription, WatchError> {
    let (reply, response) = futures_channel::oneshot::channel();
    if self
      .commands
      .send(Command::Watch {
        key,
        value,
        interest,
        filter,
        reply,
      })
      .await
      .is_err()
    {
      return Err(WatchError::Fs(WatchRootError::Closed));
    }
    // Awaiting the reply is the only cancellable part: dropping this future drops the
    // `oneshot::Receiver`, which drops the [`WatchGrant`] sitting in its slot — whose `Drop`
    // enqueues a [`DropOrphan`](Command::DropOrphan) so the owner reconciles the
    // committed-but-unclaimed subscription away (invariant I1). On success we **defuse** the grant
    // (its `Drop` becomes a no-op) and take the [`Subscription`]; a closed reply (the owner is
    // gone) surfaces `Closed`.
    match response.await {
      Ok(Ok(grant)) => Ok(grant.defuse()),
      Ok(Err(err)) => Err(err),
      Err(_) => Err(WatchError::Fs(WatchRootError::Closed)),
    }
  }

  /// Drops `sub`; once it was the last subscriber of its (possibly shared) root, the root's
  /// source release is **requested** — the synchronous fire-and-forget [`Source::disarm`],
  /// applied by the source no later than its next arm or its teardown. The subscription's
  /// coverage is gone the moment this resolves; the transport release follows.
  ///
  /// Sends an unwatch command to the owner and awaits its reply; dropping the
  /// returned future drops only the wait.
  ///
  /// # Errors
  ///
  /// - [`UnwatchError::UnknownSubscription`] when `sub` is not live;
  /// - [`UnwatchError::Fs(Closed)`](tributary_fs::UnwatchError::Closed) when the owner is
  ///   gone.
  pub async fn unwatch(&self, sub: Subscription) -> Result<(), UnwatchError> {
    let (reply, response) = futures_channel::oneshot::channel();
    if self
      .commands
      .send(Command::Unwatch { sub, reply })
      .await
      .is_err()
    {
      return Err(UnwatchError::Fs(tributary_fs::UnwatchError::Closed));
    }
    response
      .await
      .unwrap_or(Err(UnwatchError::Fs(tributary_fs::UnwatchError::Closed)))
  }

  /// The next attributed event, or `None` once the owner is closed and the stream is
  /// drained.
  ///
  /// A plain drain of the event channel the owner pushes to — cancel-safe by definition:
  /// a dropped `next()` loses nothing (queued events stay queued). With the settle
  /// coalescer enabled (design §6) events arrive collapsed on the settle timer; absent
  /// it, untouched.
  #[inline]
  pub async fn next(&mut self) -> Option<Event<C, V>> {
    self.events.recv().await.ok()
  }

  /// Closes the watcher: asks the owner to flush its coalesced tail and tear the source
  /// down, resolving once it has.
  ///
  /// `close` resolves once the owner has flushed pending events (best-effort — the
  /// undrained tail on a full/stalled event channel is lost with the stream) and its run
  /// loop has exited. The underlying source teardown then completes **asynchronously**
  /// afterward, as the dropped owner task drops its source; `close` does **not** wait for or
  /// surface a source-teardown error (the [`Source`](crate::Source) trait has no `close`
  /// hook — a released root's runtime conditions reach a consumer in-band as events, not
  /// out of band here). It is [`Close`-responsive by construction](Self): the owner never
  /// awaits the event channel, so `close` returns promptly even while that channel is full.
  ///
  /// # Errors
  ///
  /// [`CloseError::Fs(Stopped)`](tributary_fs::CloseError::Stopped) when the owner had
  /// already stopped (a dropped last handle, or the source closed itself).
  pub async fn close(self) -> Result<(), CloseError> {
    let (reply, response) = futures_channel::oneshot::channel();
    if self.commands.send(Command::Close { reply }).await.is_err() {
      return Err(CloseError::Fs(tributary_fs::CloseError::Stopped));
    }
    response
      .await
      .unwrap_or(Err(CloseError::Fs(tributary_fs::CloseError::Stopped)))
  }
}

impl<R: RuntimeLite> Tributaries<OsString, (), R, RootHandle> {
  /// Builds a pure-filesystem watcher over one `tributary-fs` watcher, spawning its
  /// owned-task owner on `R` — the convenience mirroring the layer below's
  /// constructor.
  ///
  /// Enable the opt-in settle/debounce coalescer (design §6) with a
  /// [`DebounceConfig`](crate::DebounceConfig) on `options`
  /// ([`TributariesOptions::debounce`]); absent it, events pass through
  /// untouched.
  ///
  /// # Errors
  ///
  /// [`BuildError::Fs`] when the underlying `tributary-fs` watcher cannot be built.
  pub fn new(options: impl Into<TributariesOptions>) -> Result<Self, BuildError> {
    let options = options.into();
    let source = FsSource::<R>::new(options.watcher().clone())?;
    Ok(Self::with_source(source, options))
  }
}

/// The owned-task actor: the sole writer of every authoritative state, driving the
/// [`Source`] and the sans-I/O engines from one [`run`] `select!` loop.
///
/// Spawned once at [`Tributaries::with_source`] and never shared: it owns the
/// [`Source`], the [`Subsumer`](crate::subsume::Subsumer), the
/// [`EpochLedger`](epoch::EpochLedger), the per-subscription filter map, and the opt-in
/// [`Coalescer`](crate::coalesce::Coalescer). All arming and every state mutation run here, to
/// completion (invariant I1); releasing a root is a **synchronous** fire-and-forget
/// [`Source::disarm`] request, so no cleanup path awaits source I/O and `Close`-responsiveness
/// (invariant II) holds by construction. No journal, no rollback, no pending-widen: an
/// interrupted or failed reconcile is repaired by reconciling again (invariant I3).
struct Owner<C, V, R, S>
where
  S: Source<C>,
{
  source: S,
  subsumer: Subsumer<C, V, S::Handle>,
  epochs: EpochLedger,
  filters: HashMap<Subscription, Filter<C>>,
  /// The per-subscription overflow dirty-set (design backpressure doc): a subscription
  /// whose delivery hit a full event channel parks a durable **dominating**
  /// [`Rescan`](tributary_fs::EventKind::Rescan) here — a [`ParkedRescan`] holding its covered
  /// key, a strictly-dominating epoch, and the owning subscription's **baked value** (captured
  /// while the sub is live, so the flushed Rescan stays attributable after retirement — R4). A
  /// [`BTreeMap`] for a deterministic drain order.
  /// [`flush_pending_rescans`](Self::flush_pending_rescans) re-offers each every loop tick
  /// until `try_send` accepts it, and [`try_emit`](Self::try_emit) suppresses further
  /// ordinary deliveries to a parked subscription (they are dominated by its `Rescan`), so
  /// a shed can never be lost to a full channel (no-silent-loss).
  needs_rescan: BTreeMap<Subscription, ParkedRescan<C, V>>,
  /// The subscriptions whose committed [`WatchGrant`] is still **in flight** — grant sent, not yet
  /// claimed or dropped (design driver-golden doc, Codex R24). A sub is inserted by
  /// [`on_watch`](Self::on_watch) the instant the grant send **succeeds**, and removed by exactly one
  /// of: its [`ClaimGrant`](Command::ClaimGrant) (the caller [`defuse`](WatchGrant::defuse)d it — now
  /// genuinely owed), its [`DropOrphan`](Command::DropOrphan) via
  /// [`release_subscription`](Self::release_subscription) (the caller's wait was dropped — purged), or
  /// any other `release_subscription` (unwatch/orphan/teardown).
  ///
  /// This is the **correctness boundary** that replaces the old mailbox-idle flush gate (Codex R23):
  /// [`flush_pending_rescans`](Self::flush_pending_rescans) **suppresses** (retains without sending)
  /// any parked `Rescan` whose sub is in this set. Parked debt for a still-unclaimed grant is owed to
  /// **nobody** — the caller never obtained the subscription — so offering it would deliver a `Rescan`
  /// for a subscription the caller never received. It is owner-local state mutated **only** by the
  /// owner while processing a command, so it is consulted at flush time with no probe and no timing
  /// window (unlike a mailbox-emptiness gate, which is neither a correctness nor a starvation
  /// boundary). Ordinary (non-parked) deliveries during the in-flight window are unaffected — only the
  /// durable `needs_rescan` debt is state-gated.
  unclaimed: std::collections::HashSet<Subscription>,
  coalescer: Option<Coalescer<C, V>>,
  commands: async_channel::Receiver<Command<C, V>>,
  /// A **weak** clone of the owner's own command `Sender`, upgraded to a strong `Sender` and
  /// handed into each [`WatchGrant`] so a dropped `watch` wait can enqueue a reply-less
  /// [`DropOrphan`](Command::DropOrphan) that reconciles its committed-but-unclaimed subscription
  /// away (invariant I1). It is **weak** by construction: a strong clone held here would keep the
  /// command channel open forever, so dropping every public [`Tributaries`] handle would no longer
  /// close it and the owner would never reach its dropped-handles teardown (the design's Close/Drop
  /// path). Each grant [`upgrade`](async_channel::WeakSender::upgrade)s it — succeeding while any
  /// handle is live, including the one the borrowing `watch` call holds — and carries its **own**
  /// strong `Sender`, so the channel is held open only for the brief life of the grant.
  commands_weak: async_channel::WeakSender<Command<C, V>>,
  events: async_channel::Sender<Event<C, V>>,
  /// A **debug-only** exhaustive tripwire for the generation-unique [`Source::Handle`] contract:
  /// every handle this owner has ever observed from a successful live [`arm`](Self::arm). The arm
  /// choke point asserts each freshly-armed handle was **never** seen before, catching ANY reuse —
  /// a still-recorded sibling, or one already removed from the live index by unwatch or terminal
  /// retirement (the post-retirement reuse the per-site live-index checks missed, Codex R17). It is
  /// only ever inserted into, never pruned, so a retired-then-reused handle is still caught;
  /// `#[cfg(debug_assertions)]` so the field, its init, and its assert add zero release-build cost.
  #[cfg(debug_assertions)]
  observed_handles: std::collections::HashSet<S::Handle>,
  _rt: PhantomData<R>,
}

impl<C, V, R, S> Drop for Owner<C, V, R, S>
where
  S: Source<C>,
{
  /// The synchronous teardown guard that empties the read plane on **any** owner termination —
  /// normal exit OR a panic unwinding through a caller-provided callback the owner runs (the
  /// [`Filter`] predicate, a [`Source`] method, `V`/`C`/`H` ops). The normal path already publishes
  /// empty after draining owed Rescans; this covers every panic path at once, so a retained
  /// [`WatchView`] never keeps advertising subscriptions whose owner task and source have died (the
  /// stale-read-plane mode the teardown publish prevents — design §5). Drop runs before the owner's
  /// fields drop, so `self.subsumer` is still alive; [`publish_empty`](Subsumer::publish_empty) is a
  /// single synchronous `arc_swap` store that runs no caller code, so it is idempotent (the normal
  /// path's double publish is a no-op) and cannot double-panic while unwinding. Owed Rescans cannot
  /// be drained mid-unwind and are necessarily lost on a panic; emptying the plane is the achievable
  /// guarantee.
  fn drop(&mut self) {
    self.subsumer.publish_empty();
  }
}

/// The [`run`] loop's control-flow after handling one ready arm: keep looping, or break out to
/// teardown. Returned by [`Owner::dispatch_command`] and matched by the [`run`] loop — above all a
/// `Close`, which breaks out to teardown (invariant II).
enum Flow {
  /// Keep looping (a command reconciled, an event fanned out, a timer tick).
  Continue,
  /// Break out to teardown, carrying the `Close` acknowledgement and the source-drain flag.
  Break {
    /// The `Close` reply to acknowledge after teardown, or [`None`] when the break was a dropped
    /// last handle or a source drain (nobody to confirm to).
    closing: Option<futures_channel::oneshot::Sender<Result<(), CloseError>>>,
    /// `true` only on a **source drain** (`next` yielded `None` with a consumer still attached),
    /// which owes that consumer every parked Rescan before the stream ends.
    drain_owed: bool,
  },
}

/// The owner's single `select!` loop (design driver-golden doc): reconcile a command,
/// fan out a raw source event, or drain the coalescer's due entries — whichever is ready, each to
/// completion. The only [`Source`] calls it awaits are [`next`](Source::next) (one cancel-safe
/// `select!` arm) and, inside a caller-bounded `Watch` reconcile, [`arm`](Source::arm); releasing a
/// root is the **synchronous** [`disarm`](Source::disarm) request, so **no** loop path awaits it and
/// Close-responsiveness (invariant II) holds *by construction*.
///
/// Biased to the command mailbox so control-plane requests (including `Close`) are never
/// starved by a busy event stream. On a `Close` command or a dropped last handle (the
/// command channel closed) or the source draining (`next` yields `None`), it breaks,
/// flushes the coalesced tail (no-silent-loss), and tears down — dropping the [`Owner`]
/// (and its source, whose own `Drop` performs the orderly source teardown). Nothing is
/// owed to `Drop`.
async fn run<C, V, R, S>(mut owner: Owner<C, V, R, S>)
where
  C: Ord + Clone,
  V: Clone,
  R: RuntimeLite,
  S: Source<C>,
{
  // Command-fairness valve state (Codex R25-F2): consecutive command-arm wins since the data plane
  // was last serviced. See [`COMMAND_FAIRNESS_BUDGET`].
  let mut command_streak: u32 = 0;
  // The loop yields `(reply, drain_owed)`: `reply` is the `Close` acknowledgement (if any);
  // `drain_owed` is true only on a **source drain** (the source's `next` yielded `None` while
  // a consumer is still attached), which owes that consumer every parked Rescan before the
  // stream ends. A consumer-initiated `Close` or a dropped last handle owes nothing (the
  // consumer asked to stop / nobody is left), and must never block teardown on a full channel.
  let (closing, drain_owed) = loop {
    // Re-offer the parked per-subscription overflow Rescans ahead of new deltas — **unconditionally**
    // every tick (Codex R24). Which parked debt is *offered* is decided by owner STATE, not mailbox
    // timing: [`flush_pending_rescans`](Owner::flush_pending_rescans) suppresses any entry whose sub
    // is still `unclaimed` (its `WatchGrant` in flight), so an orphaned committed-but-unclaimed
    // subscription's parked terminal `Rescan` is never delivered — no probe, no window — while a
    // LIVE claimed subscription's parked Rescan is flushed every tick regardless of how busy the
    // (command-biased, unbounded) mailbox is. The old idle-mailbox gate did neither correctly: it was
    // a TOCTOU race (a `DropOrphan` could enqueue after the emptiness probe but before the flush's
    // `try_send`, Codex R24-F1) AND it let a sustained watch/unwatch stream starve live subscriptions'
    // parked Rescans by keeping `is_empty()` false forever (Codex R24-F2). Per-subscription ordering
    // and durability are unaffected (a parked sub's ordinary deltas are suppressed and its `Rescan`s
    // merged by `try_emit`; `needs_rescan` entries persist until delivered or purged).
    owner.flush_pending_rescans();

    // The command-fairness valve (Codex R25-F2): the select below is command-biased, so a
    // CONTINUOUS command flood would otherwise starve the data plane entirely — the source arm
    // never pumped (claimed subscriptions miss ordinary events for the flood's whole duration) and
    // the timer arm never fired (due coalescer output held past its bounds). After
    // [`COMMAND_FAIRNESS_BUDGET`] consecutive command wins, service the data plane ONCE,
    // non-blockingly: poll one source event — `now_or_never` drops a still-pending `next()`, which
    // is safe solely by its cancellation-safety contract — and drain any due coalescer output.
    // `Close`-responsiveness is untouched: nothing here awaits (a pending poll is dropped
    // instantly), so a queued `Close` is delayed by at most this bounded, non-awaiting service.
    if command_streak >= COMMAND_FAIRNESS_BUDGET {
      command_streak = 0;
      match owner.source.next().now_or_never() {
        Some(Some(event)) => {
          if !owner.retire_if_dead(&event) {
            owner.fan_out_and_push(&event);
          }
        }
        // The source drained during the forced poll: break to the owed drain exactly as the
        // select arm does (no silent loss on source drain).
        Some(None) => break (None, true),
        None => {}
      }
      owner.drain_coalescer_due();
    }

    // The sleep target: the coalescer's next settle deadline, floored by a short retry
    // while any parked Rescan still awaits a channel slot — so a resuming consumer gets its
    // Rescan promptly. The floor is latency-only (a later command/event tick would retry it
    // anyway); without it correctness still holds. Absent both, the timer parks forever
    // (debounce disabled and nothing shed).
    let coalescer_deadline = owner.coalescer.as_ref().and_then(Coalescer::next_deadline);
    let retry_deadline =
      (!owner.needs_rescan.is_empty()).then(|| Into::<Instant>::into(R::now()) + RETRY);
    let deadline = min_deadline(coalescer_deadline, retry_deadline);
    let timer = async {
      match deadline {
        Some(at) => {
          R::sleep_until(at.into()).await;
        }
        None => futures_util::future::pending::<()>().await,
      }
    }
    .fuse();
    futures_util::pin_mut!(timer);

    // The one owner `select!`: dispatch a command, pump one source event, or fire the settle/retry
    // timer — whichever is ready. Command-biased so control-plane requests (above all a `Close`) are
    // never starved by a busy event stream. `source.next()` is the ONLY [`Source`] call polled in a
    // cancellable arm: a command/timer branch winning **drops** the in-flight `next()` future, which
    // is safe solely because [`Source::next`] is a hard-contract **cancellation-safe** read (see its
    // docs) — dropping it loses/acks no event. Releasing a root is the synchronous
    // [`Source::disarm`] request, never awaited, so it is never raced here.
    let flow = futures_util::select_biased! {
      cmd = owner.commands.recv().fuse() => {
        command_streak += 1;
        owner.dispatch_command(cmd).await
      }
      raw = owner.source.next().fuse() => { command_streak = 0; match raw {
        // A terminal event on a **dead root** (the source has forgotten its handle) retires that
        // root through the unified park-terminal-Rescan-then-retire primitive — which durably owes
        // every subscriber a dominating `Rescan` *before* freeing the subsumer state, so a full
        // channel cannot drop it — and `retire_if_dead` returns `true`, so the ordinary fan-out is
        // skipped here. A dead-root NON-`Rescan` terminal event (e.g. a root `Removed`) is NOT
        // separately fanned out: the parked terminal `Rescan` dominates and re-enumerates it, and
        // fanning it through the coalescer under debounce would buffer-then-drop it (Codex R12 F2).
        // Every event on a still-live root (an ordinary delivery, or an overflow `Rescan` on a live
        // root) returns `false` and fans out normally here.
        Some(event) => {
          if !owner.retire_if_dead(&event) {
            owner.fan_out_and_push(&event);
          }
          Flow::Continue
        }
        // The source drained while a consumer is still attached: it is OWED every parked
        // Rescan before the stream ends (no silent loss on source drain).
        None => Flow::Break { closing: None, drain_owed: true },
      } },
      _ = timer => {
        command_streak = 0;
        owner.drain_coalescer_due();
        Flow::Continue
      }
    };

    match flow {
      Flow::Continue => {}
      Flow::Break {
        closing,
        drain_owed,
      } => break (closing, drain_owed),
    }
  };

  // Whichever `Close` we owe an acknowledgement: the loop-break `Close` (consumer-initiated),
  // or a `Close` that interrupted the source-drain retry (returned by
  // `drain_owed_before_shutdown` so the blocking retry could stop and stay responsive). The two
  // are mutually exclusive — a source-drain break carries no `closing`.
  let ack = if drain_owed {
    // Source drain: deliver the coalesced tail AND every owed parked Rescan before the stream
    // ends — ordered so a parked subscription's tail delta never precedes its dominating Rescan
    // — retrying as the consumer drains, while servicing the command mailbox so a `Close` behind
    // a full channel is always answered (no silent loss, without an unserviceable `Close`).
    owner.drain_owed_before_shutdown().await
  } else {
    // Consumer-initiated `Close`, or every handle dropped: one best-effort non-blocking pass that
    // delivers the owed tail when the channel has room. An unclaimed sub's parked debt is SUPPRESSED
    // by owner state inside this `drain_owed_once` (its `flush_pending_rescans`), so a residual
    // `DropOrphan`/`ClaimGrant` still queued behind the `Close` may go unprocessed with no harm —
    // nothing is delivered for a still-unclaimed sub and the owner is exiting. Teardown never blocks
    // on the channel, so `Close` stays responsive.
    owner.drain_owed_once();
    closing
  };
  // Every teardown exit funnels here — a `Close` command, a dropped last handle, or the source
  // draining — AFTER the owed Rescans above are made durable/delivered (nothing owed is lost).
  // Publish an EMPTY read plane so a retained `WatchView` clone stops advertising subscriptions
  // whose owner task and source are about to be gone: otherwise it keeps answering
  // `is_watched`/`covering` from the last snapshot, and a dedup caller (the indexer) skips
  // re-installing that coverage and silently misses changes after rebuilding a fresh watcher
  // (design §5). It is a synchronous `arc_swap` store — the owner still never awaits the event
  // sender, so no-deadlock (III) holds.
  owner.subsumer.publish_empty();
  // Dropping `owner` (and its source) performs the orderly source teardown.
  if let Some(reply) = ack {
    let _ = reply.send(Ok(()));
  }
}

/// How long the owner waits before re-attempting delivery of a parked per-subscription
/// overflow [`Rescan`](tributary_fs::EventKind::Rescan) when the event channel is full
/// (design backpressure doc). Mirrors the fs layer's `DELIVERY_RETRY`. Latency-only: a
/// resuming consumer's next drained slot is also retried on the following command/event
/// tick; this bounds the wait when the stream is otherwise idle.
const RETRY: Duration = Duration::from_millis(25);

/// How many consecutive command-arm wins the [`run`] loop tolerates before forcing one
/// non-blocking data-plane service — a `now_or_never` source poll plus a due-coalescer drain —
/// the command-fairness valve (Codex R25-F2). The `select!` is command-biased so `Close` is never
/// starved; without a budget, a CONTINUOUS watch/unwatch flood keeps the command arm ready
/// forever and the source/timer arms never win: claimed subscriptions would miss ordinary source
/// events and the coalescer its hold bounds for the flood's whole duration. Small enough to bound
/// data-plane staleness tightly under load, large enough to amortize the extra poll.
const COMMAND_FAIRNESS_BUDGET: u32 = 32;

/// The earlier of two optional deadlines, treating [`None`] as infinitely far — the sleep
/// target combining the coalescer's settle deadline with the parked-Rescan retry.
fn min_deadline(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
  match (a, b) {
    (Some(a), Some(b)) => Some(a.min(b)),
    (a, b) => a.or(b),
  }
}

impl<C, V, R, S> Owner<C, V, R, S>
where
  C: Ord + Clone,
  V: Clone,
  R: RuntimeLite,
  S: Source<C>,
{
  /// Dispatches one command from the mailbox, returning whether the [`run`] loop should keep
  /// looping or break to teardown ([`Flow`]). Called from the [`run`] loop's single `select` — above
  /// all a `Close`, which breaks out to teardown (invariant II).
  ///
  /// [`DropOrphan`](Command::DropOrphan) is the load-bearing case: a `watch` orphaned by a dropped
  /// caller wait. It routes through the unified [`release_subscription`](Self::release_subscription),
  /// which purges the orphan's owner-local state and, if that emptied a root, issues the emptied
  /// root's **synchronous** [`disarm`](Source::disarm) request — it awaits nothing. A `DropOrphan` is
  /// an **internal** owner action (no caller is waiting on it) and its result is ignored, so a `Close`
  /// queued behind it is serviced with no delay (invariant II — Close-responsive by construction).
  async fn dispatch_command(
    &mut self,
    cmd: Result<Command<C, V>, async_channel::RecvError>,
  ) -> Flow {
    match cmd {
      Ok(Command::Watch {
        key,
        value,
        interest,
        filter,
        reply,
      }) => {
        self.on_watch(key, value, interest, filter, reply).await;
        Flow::Continue
      }
      Ok(Command::Unwatch { sub, reply }) => {
        self.on_unwatch(sub, reply);
        Flow::Continue
      }
      // A watch orphaned by a dropped caller wait (its [`WatchGrant`] fired): release it through the
      // unified [`release_subscription`](Self::release_subscription) — purge its owner-local state and
      // request the emptied root's synchronous `source.disarm`. It is cleanup, not a caller request
      // (invariant I1), so the result is ignored; the release awaits nothing, so a `Close` queued
      // behind this `DropOrphan` is never blocked (invariant II).
      Ok(Command::DropOrphan(sub)) => {
        let _ = self.release_subscription(sub);
        Flow::Continue
      }
      // A grant the caller CLAIMED (its `defuse` fired): lift the sub's `unclaimed` suppression, so
      // its parked debt (if any) is offered by the next `flush_pending_rescans` — a claimed
      // subscription is genuinely owed its Rescan. A `HashSet` remove that awaits nothing, so a
      // `Close` queued behind it is never blocked (invariant II).
      Ok(Command::ClaimGrant(sub)) => {
        self.unclaimed.remove(&sub);
        Flow::Continue
      }
      Ok(Command::Close { reply }) => Flow::Break {
        closing: Some(reply),
        drain_owed: false,
      },
      // Every handle dropped: same orderly teardown, nobody to confirm it to. Nobody is left to
      // receive, so nothing is owed.
      Err(_) => Flow::Break {
        closing: None,
        drain_owed: false,
      },
    }
  }

  /// Handles a [`Command::Watch`]: reconcile it, then hand the committed subscription back inside
  /// a RAII [`WatchGrant`] so a dropped caller wait can never strand it (design driver-golden doc,
  /// invariant I1).
  ///
  /// The grant guards the whole "dropped wait" window, not just the receiver-gone-at-send-time
  /// edge the old bare-`Subscription` reply covered:
  ///
  /// - if the receiver is already gone the instant we send, `reply.send` fails and hands the grant
  ///   back; we defuse it and release the orphan through
  ///   [`release_subscription`](Self::release_subscription) — purge owner-local state, request the
  ///   emptied root's synchronous `source.disarm`. The release awaits nothing, so a `Close` queued
  ///   behind this `Watch` is never blocked on source I/O;
  /// - if the command channel is already closed (every handle gone), no caller can observe the reply
  ///   and the owner is tearing down; we release the subscription the SAME way, so dropping all
  ///   handles never leaves the owner awaiting a disarm before its source is dropped (any still-
  ///   pending transport release is applied by the source's own `Drop` at teardown);
  /// - if the send succeeds but the caller drops its wait **before polling** the reply, the grant
  ///   sitting in the `oneshot` slot is dropped and its `Drop` enqueues a
  ///   [`DropOrphan`](Command::DropOrphan) the owner reconciles away — the residual hole a bare
  ///   `Subscription` left open;
  /// - a caller that observes the reply defuses the grant, so a normal successful `watch` runs no
  ///   extra reconcile.
  async fn on_watch(
    &mut self,
    key: Vec<C>,
    value: V,
    interest: Interest,
    filter: Filter<C>,
    reply: futures_channel::oneshot::Sender<Result<WatchGrant<C, V>, WatchError>>,
  ) {
    match self.reconcile_watch(&key, value, interest, filter).await {
      Ok(sub) => {
        // Hand the committed subscription back inside a grant, unless there is no caller to receive
        // it. Two paths orphan it HERE (a send that succeeds but is dropped pre-poll is instead
        // caught by the grant's own `Drop` → `DropOrphan`):
        let orphan = match self.commands_weak.upgrade() {
          // The command channel is still open: try to hand the grant to the waiting `watch`.
          Some(commands) => match reply.send(Ok(WatchGrant::new(sub, commands))) {
            // Delivered: the grant now guards the committed subscription **in flight**. Record it in
            // `unclaimed` — the ONLY insert site — so `flush_pending_rescans` suppresses its parked
            // debt until the caller claims it (`ClaimGrant` → genuinely owed) or drops it
            // (`DropOrphan` → purged). No orphan.
            Ok(()) => {
              self.unclaimed.insert(sub);
              None
            }
            // The receiver was already gone the instant we sent: the grant bounced back — defuse it
            // (so its own `Drop` enqueues nothing) and orphan the subscription here. Nothing was ever
            // in flight, so it is NOT recorded `unclaimed`.
            Err(Ok(grant)) => Some(grant.defuse()),
            // Unreachable (we always send `Ok`): no grant in flight, nothing to record or orphan.
            Err(Err(_)) => None,
          },
          // Every handle is gone (the command channel is closed): no caller can observe the reply and
          // the owner is about to tear down. Orphan the subscription here (never in flight, so not
          // `unclaimed`).
          None => Some(sub),
        };
        // Both orphan paths release the committed-but-unclaimed subscription with the SAME unified
        // [`release_subscription`](Self::release_subscription) as a [`DropOrphan`](Command::DropOrphan):
        // purge owner-local state and request the emptied root's synchronous `source.disarm`. The
        // release awaits nothing, so a `Close` queued behind this `Watch` is never blocked; in the
        // `None` case dropping all handles never leaves the owner awaiting a disarm before the source
        // is dropped (any still-pending transport release is applied by the source's own `Drop`).
        if let Some(sub) = orphan {
          let _ = self.release_subscription(sub);
        }
      }
      Err(err) => {
        let _ = reply.send(Err(err));
      }
    }
  }

  /// Handles a [`Command::Unwatch`]: release the subscription and reply. Synchronous — the unified
  /// [`release_subscription`](Self::release_subscription) requests the emptied root's `source.disarm`
  /// without awaiting, so an `unwatch` never blocks the owner (or a `Close` behind it) on source I/O.
  fn on_unwatch(
    &mut self,
    sub: Subscription,
    reply: futures_channel::oneshot::Sender<Result<(), UnwatchError>>,
  ) {
    let result = self.release_subscription(sub);
    let _ = reply.send(result);
  }

  /// Reconciles one `watch` toward the target watch-set (invariant I3): plans it through
  /// the kept [`Subsumer::plan_watch`], drives arm/disarm to completion through the
  /// single **arm-and-key choke point** (invariant I2), commits, and mints per-subscriber
  /// dominating Rescans on a widen (design §8). No journal, no rollback — a failed arm
  /// leaves the affected subscriptions uncovered with a dominating Rescan (no silent
  /// loss), to be re-covered by a later reconcile.
  ///
  /// **Roots are always armed by the source's own policy** ([`FsSource`] uses
  /// [`Interest::all`], design §4): the caller's `interest` is recorded on the
  /// subscription as a fan-out gate, never passed to the arm.
  async fn reconcile_watch(
    &mut self,
    key: &[C],
    value: V,
    interest: Interest,
    filter: Filter<C>,
  ) -> Result<Subscription, WatchError> {
    // Canonicalize the caller key at the single arm-and-key choke point, BEFORE classification
    // (invariant I2 — "one fs-canonical coordinate at one choke point"). Every downstream step —
    // `plan_watch`, the Covered-liveness re-plan, the arm, and the commit — then keys on the
    // source's canonical coordinate, so the `Covered` path (which arms nothing, and so never
    // adopts a canonical key at arm time) can no longer commit a raw non-canonical key that later
    // canonical events fail to match: real events arrive under the canonical coordinate, so a
    // verbatim non-canonical key would receive nothing with no `Rescan` to signal the gap (Codex
    // R14 F1 — the Covered-path silent-loss close). A source that cannot canonicalize the key
    // rejects the watch here (FsSource: the path does not exist → `WatchError::Canonicalize`)
    // rather than silently committing an eventless key; a source whose keys are already canonical
    // (a generic component key) canonicalizes as the identity. The arm path still re-keys onto
    // `Armed::canonical_key` and guards it with `fs_path_preserves_plan`, closing the residual
    // TOCTOU where the coordinate changes between this canonicalization and the arm.
    let canonical_key = self.source.canonicalize_key(key)?;
    let key = canonical_key.as_slice();
    // Plan the watch, **re-planning past any dead covering root** so no subscription ever binds a
    // source-forgotten handle (Codex R12 F1 — the structural close of the dead-root-coverage class).
    // The owner loop is command-biased, so a `watch` queued while a dead root's terminal event is
    // still pending runs FIRST — before [`retire_if_dead`](Self::retire_if_dead) consumes that event
    // and force-removes the root. `plan_watch` would then classify `Covered` against the
    // still-recorded dead handle and bind the newcomer to a root NO live source watch backs; the
    // later terminal event retires that subscription, silently missing writes under a recreated root.
    // So before committing a `Covered` plan, synchronously VALIDATE the covering root's liveness
    // ([`Source::root_key`]): if the source has forgotten it, retire that dead root through the shared
    // park-terminal-Rescan-then-retire primitive (durably owing every subscriber a dominating
    // terminal `Rescan` — no silent loss) and re-plan against the now-updated subsumer.
    //
    // Deep-audit of every coverage classification vs handle liveness: `Disjoint` and `Widen` each
    // [`arm`](Self::arm) a FRESH (hence live) root, and `Widen` re-points the subscribers of its
    // subsumed roots — dead or not — onto that fresh root with dominating Rescans, so neither can
    // commit a dead binding; only `Covered` reuses a recorded root, and it now breaks the loop solely
    // once that root is validated live. The loop terminates: each re-plan force-removes exactly one
    // root from the finite, pairwise-disjoint index, and a retired ancestor cannot reappear
    // (disjointness leaves at most one ancestor of `key`, so the next plan finds none). It never
    // double-arms — the `Covered` path arms nothing; only the terminal `Disjoint`/`Widen` arms, once,
    // after the loop exits.
    let outcome = loop {
      let outcome = self.subsumer.plan_watch(key, value.clone(), interest);
      if let WatchOutcome::Covered { fs_root, .. } = &outcome {
        let covering = *fs_root;
        if self.source.root_key(covering).is_none() {
          // The covering root is source-forgotten (dead): discard this plan's pending reservation,
          // retire the dead root (parking every subscriber's dominating terminal Rescan before its
          // state is freed), and re-plan — never binding a `Covered` subscription to a dead handle.
          self.subsumer.abort_watch(&outcome);
          self.retire_root_with_terminal_rescan(covering);
          continue;
        }
      }
      break outcome;
    };
    match &outcome {
      WatchOutcome::Covered { fs_root, sub } => {
        // Already covered by a root the re-plan loop just validated LIVE: no arm. The newcomer's
        // key was canonicalized at the top of this method (the single choke point), so committing
        // it verbatim keys the subscription on the source's canonical coordinate — the one its
        // events arrive under — closing the old Covered-path silent-loss where a raw non-canonical
        // key was committed and then never matched a canonical event (Codex R14 F1).
        let (fs_root, sub) = (*fs_root, *sub);
        self.subsumer.commit_watch(&outcome, fs_root, key);
        self.filters.insert(sub, filter);
        Ok(sub)
      }
      WatchOutcome::Disjoint { sub, .. } => {
        let sub = *sub;
        let armed = match self.arm(key).await {
          Ok(armed) => armed,
          Err(err) => {
            self.subsumer.abort_watch(&outcome);
            return Err(err);
          }
        };
        // Re-key onto the source's authoritative canonical key (invariant I2). A
        // divergence that changes subsumption is a canonicalization race: disarm and
        // abort cleanly rather than commit a mis-keyed or overlapping entry.
        let (handle, fs_key) = armed;
        if !self.subsumer.fs_path_preserves_plan(&fs_key, &[]) {
          self.source.disarm(handle);
          self.subsumer.abort_watch(&outcome);
          return Err(canonical_race());
        }
        // A fresh arm's handle is generation-unique (see `Source::Handle`), so it is absent from the
        // reverse index and `commit_watch`'s `by_handle` insert cannot clobber a live root's entry.
        // A contract-violating source is caught by the arm choke point's exhaustive observed-handle
        // tripwire (Codex R17), which fires on ANY reuse before this commit is ever reached.
        self.subsumer.commit_watch(&outcome, handle, &fs_key);
        self.filters.insert(sub, filter);
        Ok(sub)
      }
      WatchOutcome::Widen {
        repointed,
        unwatch,
        sub,
        ..
      } => {
        let sub = *sub;
        let repointed = repointed.clone();
        // Unwatch-old-then-arm-new (design §4): the source rejects a root overlapping a
        // live one, so the wider root cannot be armed while a subsumed one is live.
        // Request release of the subsumed watches first — the source applies every requested
        // release before the wider arm it drains them into (disarm contract clause 2), so the arm
        // cannot race a still-live subsumed root. The coverage gap is closed by the dominating
        // Rescan each re-pointed subscription receives below.
        for &old in unwatch {
          self.source.disarm(old);
        }
        let armed = match self.arm(key).await {
          Ok(armed) => armed,
          Err(err) => {
            // The wider arm failed after the subsumed roots were released. Do NOT leave their live
            // subscriptions bound to released handles (they would read watched yet never see another
            // event). Restore the pre-widen armed state: re-arm each released root through the choke
            // point, or — for one that is genuinely dead — retire it with a dominating Rescan so its
            // subs re-enumerate and it leaves the view (design driver-golden doc, invariant I3). This
            // re-arm is the awaited step; the future is bound before the `.await` so it never shares a
            // line with a `disarm` — the owner's await surface (only `arm`/`next` are awaited; every
            // `disarm` is now synchronous) stays greppable. Then abort the newcomer's plan.
            let restore = self.restore_disarmed_roots(unwatch);
            restore.await;
            self.subsumer.abort_watch(&outcome);
            return Err(err);
          }
        };
        let (handle, fs_key) = armed;
        if !self.subsumer.fs_path_preserves_plan(&fs_key, unwatch) {
          // The wider root armed but its committed key diverged (a canonicalization race): request
          // its release, then restore the released subsumed roots exactly as above — the same
          // strand-avoidance the arm-failure branch runs (both post-release exits must restore, never
          // signal-and-strand). The restore future is bound before the `.await` for the same reason
          // as that branch (keeping the owner's await surface greppable — no `disarm` shares an
          // `.await` line).
          self.source.disarm(handle);
          let restore = self.restore_disarmed_roots(unwatch);
          restore.await;
          self.subsumer.abort_watch(&outcome);
          return Err(canonical_race());
        }
        // The wider arm's handle is generation-unique (see `Source::Handle`): it aliases none of the
        // still-recorded subsumed roots `commit_watch` is about to drop, nor any other live root, so
        // its `by_handle` insert cannot clobber a live entry. A contract-violating source is caught
        // by the arm choke point's exhaustive observed-handle tripwire (Codex R17) before this
        // commit is ever reached.
        self.subsumer.commit_watch(&outcome, handle, &fs_key);
        self.filters.insert(sub, filter);
        // Rebase each re-pointed subscription onto the wider root (design §8): its
        // synthetic dominating Rescan strictly dominates its pre-widen stream while the
        // new root's genuine events tie-or-exceed it, and names the widened root to
        // re-enumerate — closing the unwatch→arm coverage gap.
        let mut rescans = Vec::with_capacity(repointed.len());
        for moved in repointed {
          // The re-point Rescan re-enumerates the whole subscription, so it dominates any
          // pre-widen deltas still buffered in the coalescer. Drop them before delivering it:
          // otherwise, on a full channel, a buffered delta flushes ahead of the Rescan (the
          // coalescer admits before `try_emit` suppresses) and parks at a fresh `shed_rescan`
          // one epoch above the new root's raw-0, sorting the Rescan behind it and silently
          // dropping post-widen events (the coalescer sibling of the Codex R5 re-point-epoch fix).
          if let Some(coalescer) = self.coalescer.as_mut() {
            coalescer.drop_subscription(moved);
          }
          let rescan = self.epochs.repoint(moved);
          let mut event = Event::rescan(moved, fs_key.clone(), rescan);
          // The specific re-pointed subscription owns this Rescan (its key is invariant under the
          // widen, so its own value is still recorded); bake it so attribution is the sub's own
          // value, not the widening root's (design §3).
          event.set_value(self.subsumer.subscription_value(moved).cloned());
          rescans.push(event);
        }
        self.push_all(rescans);
        Ok(sub)
      }
    }
  }

  /// The single **arm-and-key choke point** (invariant I2): arms `key` through the
  /// [`Source`], validates the armed root is **live**, and adopts the source's reported
  /// **canonical key** as the committed coordinate. Every arming path — the fresh `Disjoint`
  /// arm, the `Widen` arm, and the [`restore_disarmed_roots`](Self::restore_disarmed_roots)
  /// re-arm — funnels through here, so no coverage check ever runs against a provisional key
  /// AND no dead-on-arrival handle ever becomes a committed root, for **any** [`Source`] impl.
  ///
  /// A successful [`Source::arm`] does **not** by itself guarantee liveness: a source may
  /// report an arm as succeeded for a root it has **already forgotten** — one removed between
  /// the request and the arm completing ([`FsSource`] historically fell back to the requested
  /// key when [`root_path`](tributary_fs::Watcher::root_path) was `None`). Committing such a
  /// dead-on-arrival handle publishes the key as watched yet backs it with **no live watch**:
  /// changes would rely on a later terminal event instead of being streamed. So after the arm
  /// this synchronously validates the handle through the same out-of-band [`Source::root_key`]
  /// probe the Covered-reuse loop (Codex R12) and terminal retirement (R11) use; on a dead
  /// handle it best-effort [`disarm`](Source::disarm)s the stray root (a synchronous
  /// fire-and-forget release request) and fails the arm with [`WatchError::DeadOnArrival`].
  /// Arm-time (R13) + reuse-time (R12) + terminal-time (R11) liveness together close the
  /// handle-liveness class.
  ///
  /// Because every arming path funnels through here, this is also where the **exhaustive**
  /// generation-unique [`Source::Handle`] tripwire lives (Codex R17): a debug-only assert that the
  /// freshly-armed, live handle was NEVER observed by this owner before. It subsumes the old
  /// per-site live-index checks AND additionally catches reuse of a handle already removed from the
  /// live index by unwatch or terminal retirement (see `observed_handles`).
  ///
  /// An [`Overlaps`](tributary_fs::WatchRootError::Overlaps) from a conforming source is now
  /// **unreachable**, so there is no overlap-retry here. [`Source::disarm`]'s
  /// release-before-subsequent-arm ordering (contract clause 2) guarantees every release the
  /// umbrella already requested — a widen's subsumed roots, or a just-orphaned root's — is applied
  /// before this arm, and the umbrella's own index is pairwise-disjoint, so an arm can never conflict
  /// with a root the umbrella still considers live. A re-`watch` of a just-orphaned key is classified
  /// `Disjoint`/`Widen` (the subsumer no longer records it) and the source drains the prior release
  /// before re-arming, so the umbrella never surfaces `Overlaps` to a caller (see [`WatchError`])
  /// with no flushing of its own. Should a contract-violating source return `Overlaps` anyway, it
  /// surfaces as the [`WatchError`] it maps to — a documented source-contract violation, never
  /// silently retried.
  async fn arm(&mut self, key: &[C]) -> Result<(S::Handle, Vec<C>), WatchError> {
    let armed = self.source.arm(key).await?;
    let handle = armed.handle();
    if self.source.root_key(handle).is_none() {
      self.source.disarm(handle);
      return Err(WatchError::DeadOnArrival);
    }
    // The single exhaustive tripwire for the generation-unique `Source::Handle` contract (Codex
    // R17): a freshly-armed, live handle must NEVER have been observed by this owner before. This
    // one choke-point check subsumes the old per-site live-index `entry(handle).is_none()` asserts
    // (Disjoint/Widen commit, restore rebind) AND additionally catches reuse of a handle already
    // removed from the live index by unwatch or terminal retirement — which those per-site checks
    // missed, because a stale event still carrying it could then route through the re-armed root.
    // `HashSet::insert` returns `false` on any prior value, and the set is only added to (never
    // pruned), so a retired-then-reused handle still trips. Debug-only: the field, this assert, and
    // its cost all vanish in release builds.
    #[cfg(debug_assertions)]
    debug_assert!(
      self.observed_handles.insert(handle),
      "Source::arm returned a handle already observed by this owner (a reused handle, even after \
       retirement) — a generation-unique Source::Handle contract violation; see Source::Handle"
    );
    Ok((handle, armed.canonical_key().to_vec()))
  }

  /// The single synchronous subscription-release primitive (invariant I4): brand-check, purge the
  /// subscription's owner-local per-sub state (filter, epoch, parked overflow Rescan, buffered
  /// coalescer deltas — BEFORE the subsumer is consulted, so a terminal-retired orphan leaves no
  /// false debt: Codex R20-F2), `plan_unwatch`, and — if that emptied the root — request the source
  /// release via the **synchronous** fire-and-forget [`Source::disarm`].
  ///
  /// Every subscription teardown funnels through here: the caller-initiated
  /// [`unwatch`](Self::on_unwatch) (which reports the [`Result`]); a
  /// [`DropOrphan`](Command::DropOrphan) and both [`on_watch`](Self::on_watch) orphan paths
  /// (reply-send-failure and closed-channel), which ignore it; and the source-drain teardown loop
  /// ([`drain_owed_before_shutdown`](Self::drain_owed_before_shutdown)), which likewise ignores it.
  /// Because the release is a synchronous request that awaits nothing, this never blocks `Close` on
  /// source I/O — Close-responsiveness (invariant II) holds by construction on every path, with no
  /// per-path special-casing (the old defer / idle-drain / teardown-purge split collapses to one
  /// call).
  ///
  /// The **ordering is load-bearing** (Codex R20-F2): the owner-local reclaim runs FIRST, keyed on
  /// `sub` alone, EVEN WHEN the subscription is already absent from the subsumer. A
  /// committed-but-unclaimed watch can be **terminal-retired** while its [`WatchGrant`] still sits in
  /// the reply slot — root death (`retire_if_dead`) parks that sub's terminal Rescan and
  /// force-removes it from the subsumer — and the later [`DropOrphan`](Command::DropOrphan) must
  /// still clear that parked Rescan, or it lingers as FALSE debt: a Rescan
  /// [`flush_pending_rescans`](Self::flush_pending_rescans) would deliver for a subscription the
  /// caller never received, or endlessly retry on a full channel at source-drain. Purging before the
  /// `plan_unwatch` `Unknown` early return closes exactly that.
  ///
  /// Every caller reclaims `sub` as a request to **stop watching** it, so this drops its parked
  /// overflow Rescan AND its buffered coalescer deltas alongside its filter and epoch — a
  /// cancelled/unwatched subscription owes NO coverage-loss re-enumeration, unlike the root-death
  /// path (`retire_if_dead`), which KEEPS the parked terminal Rescan so its owed re-enumeration
  /// self-drains (design backpressure doc, no silent loss). Every purge here is keyed on `sub`
  /// alone, so a still-live sibling subscription's owed parked Rescan is never dropped.
  ///
  /// # Errors
  ///
  /// [`UnwatchError::UnknownSubscription`] for a foreign/forged handle or an already-retired
  /// subscription (its owner-local cleanup still ran).
  fn release_subscription(&mut self, sub: Subscription) -> Result<(), UnwatchError> {
    // Reject a foreign/forged handle BEFORE mutating any state: a `Subscription` minted by a
    // DIFFERENT watcher instance carries a different brand even when its `ScopeId` collides with a
    // live local subscription's (every owner mints scope ids from 1). Without this brand check the
    // colliding foreign handle would `plan_unwatch` — and retire — THIS owner's unrelated
    // subscription. It is not one of ours, so it is Unknown.
    if sub.instance() != self.subsumer.instance() {
      return Err(UnwatchError::UnknownSubscription);
    }
    // Reclaim this subscription's owner-local per-sub state FIRST — its filter, epoch entry, parked
    // overflow Rescan, `unclaimed` suppression flag, and buffered coalescer deltas — keyed on `sub`
    // ALONE, BEFORE the subsumer outcome is consulted (Codex R20-F2 — see the ordering note above).
    // Neither `drain_coalescer_due`/`try_emit` re-checks live-subscription membership, so a coalescer
    // delta buffered before the reclaim must be dropped here or it would deliver for a gone
    // subscription. Removing the `unclaimed` entry here is what makes a `DropOrphan` (and both
    // `on_watch` orphan paths, and the Unknown path) clear an in-flight grant's suppression: exactly
    // one of `ClaimGrant`/`DropOrphan` fires per grant, and this is the `DropOrphan` side.
    self.retire_sub_state(sub);
    self.needs_rescan.remove(&sub);
    self.unclaimed.remove(&sub);
    if let Some(coalescer) = self.coalescer.as_mut() {
      coalescer.drop_subscription(sub);
    }
    // Now consult the subsumer. An already-retired sub is `Unknown` (its owner-local cleanup above
    // has already run); a live one reports whether its root emptied.
    let Some(outcome) = self.subsumer.plan_unwatch(sub) else {
      return Err(UnwatchError::UnknownSubscription);
    };
    if let UnwatchOutcome::RootEmptied { fs_root } = outcome {
      // The subscription was its root's last: request release of the kernel watch — a synchronous,
      // fire-and-forget [`Source::disarm`] (the source queues any async teardown and applies it at
      // its next arm or `Drop`). Nothing is awaited, so no teardown path blocks `Close`.
      self.source.disarm(fs_root);
    }
    Ok(())
  }

  /// Frees the per-subscription driver state that is **always** reclaimed when a `sub`
  /// retires — its admission [`Filter`] and its [`EpochLedger`](epoch::EpochLedger) entry —
  /// the shared core both retire paths route through (invariant I4).
  ///
  /// The parked overflow [`Rescan`](tributary_fs::EventKind::Rescan) (`needs_rescan`) is
  /// **deliberately not** freed here, because whether it survives retirement is
  /// path-dependent (design backpressure doc, no silent loss):
  ///
  /// - the consumer-initiated unwatch path ([`release_subscription`](Self::release_subscription))
  ///   drops it — the caller asked to stop watching, so no coverage-loss re-enumeration is
  ///   owed;
  /// - both root-retirement paths
  ///   ([`retire_root_with_terminal_rescan`](Self::retire_root_with_terminal_rescan)) **keep**
  ///   it — the terminal coverage-loss `Rescan`, parked there *before* this frees the state, IS
  ///   owed, and self-drains via [`flush_pending_rescans`](Self::flush_pending_rescans) after
  ///   retirement. It cannot leak (that flush clears the entry on `Ok`/`Closed`, and the set
  ///   is owner-private and bounded by the live-subscription count), and its stored `Epoch`
  ///   was captured independently of the just-freed ledger entry, so delivering it
  ///   post-retire is correct: the consumer re-enumerates the sub's key and learns its root
  ///   is gone.
  fn retire_sub_state(&mut self, sub: Subscription) {
    self.filters.remove(&sub);
    self.epochs.remove(sub);
  }

  /// Restores the pre-widen armed state after a widen disarmed its subsumed roots but then
  /// failed (arm error, or a divergent committed key) — the bounded synchronous restore
  /// that keeps a failed widen from stranding live subscriptions on disarmed handles
  /// (design driver-golden doc, invariant I3).
  ///
  /// The widen never committed, so the subsumer still holds each subsumed root at its key
  /// with its subscribers — only the **source handle** was released. For each:
  ///
  /// - **re-arm at the same key** through the [`arm`](Self::arm) choke point. On success whose
  ///   committed key is unchanged, [`rebind`](Subsumer::rebind_root) the root onto the fresh handle
  ///   and mint a dominating [`Rescan`](tributary_fs::EventKind::Rescan) per subscriber — the re-arm
  ///   restarts the source's raw epochs at zero, so each subscriber
  ///   [`repoint`](epoch::EpochLedger::repoint)s onto the new handle (exactly a widen re-point) and
  ///   re-enumerates. The subscription is live-and-covered again. The re-arm returns a
  ///   **generation-unique** handle by contract (see [`Source::Handle`]), so it can alias neither
  ///   `old` nor a not-yet-restored sibling still recorded here; the earlier defensive
  ///   alias-detection is gone (Codex R15 — it was incomplete, and disarming an aliased handle
  ///   stranded an *unrelated live* root), replaced by the arm choke point's exhaustive
  ///   observed-handle `debug_assert` tripwire (Codex R17) that fires loudly on a contract-violating
  ///   source without corrupting release builds.
  /// - if the re-arm **fails** (the root is genuinely dead) or its committed key **diverged** (a
  ///   canonicalization race we cannot cleanly rebind), **retire** the root through the shared
  ///   [`retire_root_with_terminal_rescan`](Self::retire_root_with_terminal_rescan): a durable
  ///   dominating terminal Rescan per subscriber, then free its index / filter / epoch and drop it
  ///   from the view.
  ///
  /// Either way no subscription is left recorded-live-but-disarmed-and-published-watched.
  async fn restore_disarmed_roots(&mut self, unwatch: &[S::Handle]) {
    for &old in unwatch {
      // The subsumed root is still recorded (the widen never committed); recover its key
      // and subscribers before any re-arm/retire mutates the subsumer.
      let Some((root_key, subscribers)) = self
        .subsumer
        .entry(old)
        .map(|record| (record.key.clone(), record.subscribers.clone()))
      else {
        continue;
      };
      match self.arm(&root_key).await {
        Ok((new_handle, fs_key)) if fs_key == root_key => {
          // The re-arm returns a GENERATION-UNIQUE handle by contract (see `Source::Handle`), so it
          // aliases neither `old` nor any not-yet-restored sibling still recorded here — a fresh
          // value is absent from the reverse index, so `rebind_root` cannot overwrite another root's
          // entry. The earlier defensive alias-detection (disarm the aliased handle + retire `old`)
          // is retired: it was incomplete AND, when the alias was an unrelated *live* root, its
          // `disarm` released that root's real source watch while its record/coverage stayed live,
          // silently missing future changes (Codex R15-F2). The generation-unique contract also
          // forbids reusing a handle even for a *same-key* re-arm (Codex R16): if a stale pre-disarm
          // event still carrying `old` is queued, re-arming `old` would let it route through the
          // re-armed root and be stamped in the new generation past the restore Rescan — so `old`
          // must fall to the dead-root drain path, and reusing `old` is NOT exempt. Any reuse —
          // a sibling, `old`, or a handle already removed from the live index by a prior retirement —
          // is caught by the arm choke point's exhaustive observed-handle tripwire (Codex R17)
          // before this rebind is ever reached.
          //
          // Re-armed at the same coordinate with a fresh handle: rebind onto it and re-point each
          // subscriber (raw epochs restarted at zero) with a dominating Rescan.
          self.subsumer.rebind_root(old, new_handle);
          let mut rescans = Vec::with_capacity(subscribers.len());
          for sub in subscribers {
            // As in the widen path: the restore re-point Rescan dominates the subscriber's
            // buffered pre-widen coalescer deltas, so drop them before delivering it — else a
            // buffered delta can flush ahead of the Rescan on a full channel and park one epoch
            // above the new root's raw-0 (the coalescer sibling of the Codex R5 fix).
            if let Some(coalescer) = self.coalescer.as_mut() {
              coalescer.drop_subscription(sub);
            }
            let rescan = self.epochs.repoint(sub);
            let mut event = Event::rescan(sub, root_key.clone(), rescan);
            // The re-armed root kept each subscriber's key (rebind touches only the handle), so
            // bake the subscriber's own recorded value onto its restore Rescan (design §3).
            event.set_value(self.subsumer.subscription_value(sub).cloned());
            rescans.push(event);
          }
          self.push_all(rescans);
        }
        Ok((new_handle, _diverged)) => {
          // Re-armed, but at a divergent key we cannot cleanly rebind: request release of the stray
          // new handle (synchronous, fire-and-forget) and retire the old root so its subs
          // re-enumerate and it leaves the view.
          self.source.disarm(new_handle);
          self.retire_root_with_terminal_rescan(old);
        }
        Err(_) => self.retire_root_with_terminal_rescan(old),
      }
    }
  }

  /// The single **park-terminal-Rescan-then-retire** primitive (invariant I4, no silent loss):
  /// retires a root while durably owing every subscriber a dominating terminal
  /// [`Rescan`](tributary_fs::EventKind::Rescan), so each re-enumerates its key and learns the
  /// root is gone. Both retirement paths route through it — root death
  /// ([`retire_if_dead`](Self::retire_if_dead)) and a failed widen whose subsumed root cannot
  /// re-arm ([`restore_disarmed_roots`](Self::restore_disarmed_roots)) — so the class cannot
  /// recur per-path. After this the root no longer reads watched, so a dedup caller re-installs
  /// it.
  ///
  /// The **order is load-bearing**. For each subscriber it *parks* a dominating terminal
  /// `Rescan` straight into `needs_rescan` — the root's own key (captured while the root is
  /// still recorded) plus a non-rebasing strictly-dominating
  /// [`shed_rescan`](epoch::EpochLedger::shed_rescan) epoch — **before**
  /// [`force_remove_root`](Subsumer::force_remove_root) frees the subsumer state. Parking
  /// directly (via [`merge_max`]) rather than pushing through [`try_emit`](Self::try_emit) is
  /// what closes the overflow hole: `try_emit`'s [`park_rescan`](Self::park_rescan) resolves the
  /// key via `subscription_key`, which is **gone** once the root is force-removed, so on a full
  /// channel the owed terminal Rescan would be silently dropped. The parked entry carries its
  /// own key + epoch and depends on no later lookup;
  /// [`flush_pending_rescans`](Self::flush_pending_rescans) self-drains it once the consumer
  /// resumes (`needs_rescan` is deliberately **kept** across retirement — see
  /// [`retire_sub_state`](Self::retire_sub_state)). Its stored epoch is captured before the
  /// ledger entry is freed, so delivering it post-retire is correct.
  ///
  /// A no-op if `handle` is not a live root.
  fn retire_root_with_terminal_rescan(&mut self, handle: S::Handle) {
    // Capture the root's key + subscribers while it is still recorded; force_remove is deferred
    // until every owed terminal Rescan is durably parked.
    let Some((root_key, subscribers)) = self
      .subsumer
      .entry(handle)
      .map(|record| (record.key.clone(), record.subscribers.clone()))
    else {
      return;
    };
    for &sub in &subscribers {
      // Park a dominating terminal Rescan straight into `needs_rescan` (the root's key + a
      // strictly-dominating epoch + the subscriber's baked value), independent of any later
      // lookup, so a full channel cannot drop it AND the flushed Rescan stays attributable once
      // `force_remove_root` (below) frees the sub's subsumer state — after which
      // `subscription_value` is gone, so the value MUST be captured here while the sub is still
      // live (R4). Drop the sub's now-suspect buffered coalescer deltas — the Rescan dominates
      // and re-enumerates them.
      let value = self.subsumer.subscription_value(sub).cloned();
      let epoch = self.epochs.shed_rescan(sub);
      merge_max(&mut self.needs_rescan, sub, root_key.clone(), epoch, value);
      if let Some(coalescer) = self.coalescer.as_mut() {
        coalescer.drop_subscription(sub);
      }
    }
    // The owed Rescans are now durable: tear the dead root out of the index and free each
    // subscriber's per-sub filter + epoch state (the parked `needs_rescan` entry is kept).
    for sub in self.subsumer.force_remove_root(handle) {
      self.retire_sub_state(sub);
    }
  }

  /// Fans one raw source event out to its covering, admitting subscribers and pushes the
  /// results (through the coalescer, if enabled) to the event stream.
  fn fan_out_and_push(&mut self, raw: &SourceEvent<C, S::Handle>) {
    let fanned = self.fan_out_raw(raw);
    self.push_all(fanned);
  }

  /// The single event-emit funnel (design backpressure doc): the owner **never awaits** the
  /// event channel, so `Close`-responsiveness (II) and deadlock-freedom (III) hold *by
  /// inspection* — this is the only place an ordinary delivery reaches the channel, and it
  /// is a non-blocking [`try_send`](async_channel::Sender::try_send).
  ///
  /// Three outcomes:
  /// - the subscription already carries a parked overflow `Rescan` (`needs_rescan`) → for an
  ///   **ordinary delta**, **suppress** the emit: it is dominated by that pending `Rescan`, and
  ///   delivering it would put an ordinary event ahead of the `Rescan` that covers the drop (the
  ///   fan-out atomicity guarantee — Lens 2 — holds across iterations through this check). A
  ///   source-emitted `Rescan` arriving while parked is instead **merged** into the debt
  ///   ([`park_rescan_event`](Self::park_rescan_event)): it is an independent coverage-loss signal
  ///   that may name a *different* key under the same root, so discarding it would leave its
  ///   subtree never re-enumerated (Codex R8, no silent loss under backpressure);
  /// - [`Ok`] → delivered;
  /// - [`Full`](async_channel::TrySendError::Full) → shed to a dominating `Rescan`, the mint
  ///   depending on **what** overflowed. An already-minted synthetic `Rescan` (a widen/restore
  ///   re-point, a fanned source-overflow, a terminal `Rescan`) is **parked UNCHANGED** at its own
  ///   dominating epoch ([`park_rescan_event`](Self::park_rescan_event)): re-minting it via
  ///   `shed_rescan` would push its epoch one *above* a re-point's calibrated new-root events and
  ///   silently drop them (Codex R5). An ordinary delta instead sheds to a fresh
  ///   [`shed_rescan`](epoch::EpochLedger::shed_rescan) ([`park_rescan`](Self::park_rescan)), whose
  ///   new dominating `Rescan` covers its loss;
  /// - [`Closed`](async_channel::TrySendError::Closed) → no-op: the consumer is gone and
  ///   teardown arrives on the command mailbox.
  fn try_emit(&mut self, ev: Event<C, V>) {
    let sub = ev.subscription();
    if self.needs_rescan.contains_key(&sub) {
      // An ordinary delta is dominated by the parked `Rescan` — suppress it. But a source
      // `Rescan` is an INDEPENDENT coverage-loss signal that may name a different located key
      // under the same root; merge it into the parked debt (`merge_max` widens the key to the
      // common ancestor covering both losses) instead of discarding it, or its subtree is
      // never re-enumerated (Codex R8, no silent loss under backpressure).
      if ev.is_rescan() {
        self.park_rescan_event(ev);
      }
      return;
    }
    match self.events.try_send(ev) {
      Ok(()) => {}
      // An already-minted `Rescan` carries its own strictly-dominating epoch — a re-point's is the
      // rebased base its new root's raw-0/raw-1 events tie-or-exceed, so a fresh `shed_rescan` (one
      // past the high-water) would dominate and silently drop them (Codex R5). Park it UNCHANGED; an
      // ordinary delta sheds to a fresh dominating `shed_rescan`.
      Err(async_channel::TrySendError::Full(ev)) => {
        if ev.is_rescan() {
          self.park_rescan_event(ev);
        } else {
          self.park_rescan(sub);
        }
      }
      Err(async_channel::TrySendError::Closed(_)) => {}
    }
  }

  /// Sheds `sub` to a parked dominating [`Rescan`](tributary_fs::EventKind::Rescan) after an
  /// **ordinary delta** to it found the channel full (design backpressure doc): the
  /// per-subscription overflow shed, mirroring the fs layer's `LagState::Lagged` one level up. An
  /// already-minted `Rescan` that overflows takes [`park_rescan_event`](Self::park_rescan_event)
  /// instead (parked unchanged at its own epoch, never re-minted).
  ///
  /// Looks up `sub`'s covered key (the subtree the consumer must re-enumerate) and its recorded
  /// caller value, mints a **non-rebasing** strictly-dominating epoch
  /// ([`EpochLedger::shed_rescan`]), and merges them into `needs_rescan` keeping the newest/widest
  /// key, the max epoch, and the baked value (widen-safe: [`merge_max`]) so the flushed Rescan is
  /// attributable after teardown (design §3). Finally it drops `sub`'s now-suspect buffered
  /// coalescer deltas — they are dominated by the parked `Rescan`, so emitting them later would
  /// deliver a stale epoch after it.
  ///
  /// A subscription with no live key (raced retirement) is not parked — a stale parked
  /// `Rescan` would be co-retired anyway, and there is no subtree left to name.
  fn park_rescan(&mut self, sub: Subscription) {
    let Some(key) = self.subsumer.subscription_key(sub).map(<[C]>::to_vec) else {
      return;
    };
    let value = self.subsumer.subscription_value(sub).cloned();
    let epoch = self.epochs.shed_rescan(sub);
    merge_max(&mut self.needs_rescan, sub, key, epoch, value);
    if let Some(coalescer) = self.coalescer.as_mut() {
      coalescer.drop_subscription(sub);
    }
  }

  /// Parks an already-minted synthetic [`Rescan`](tributary_fs::EventKind::Rescan) that overflowed
  /// the channel **UNCHANGED** (design backpressure doc, Codex R5): merges its own `key`, `epoch`,
  /// and baked `value` into `needs_rescan` via [`merge_max`], **without** minting a fresh
  /// [`shed_rescan`](epoch::EpochLedger::shed_rescan).
  ///
  /// The distinction from [`park_rescan`](Self::park_rescan) is load-bearing for a widen/restore
  /// re-point `Rescan`: [`repoint`](epoch::EpochLedger::repoint) rebased the subscription's
  /// `epoch_base` to this `Rescan`'s epoch, so its new root's genuine raw-0/raw-1 events stamp
  /// `base + 0`, `base + 1` — they **tie-or-exceed** the `Rescan` and must not be dominated by it.
  /// A fresh `shed_rescan` mints `high_water.next()`, one *above* the re-point epoch, which would
  /// dominate the new root's raw-0 event and silently drop it under backpressure. Parking the
  /// `Rescan` at its own epoch keeps that calibration. `merge_max`'s epoch `max` means a
  /// higher-epoch `Rescan` already parked for the sub still wins (still dominating).
  ///
  /// No coalescer purge runs here (unlike [`park_rescan`](Self::park_rescan)): whatever admitted
  /// this `Rescan` to the [`Coalescer`](crate::coalesce::Coalescer) already flushed the sub's
  /// buffered deltas (a `Rescan` flushes its subscription's buffer), so none linger to be
  /// dominated.
  fn park_rescan_event(&mut self, ev: Event<C, V>) {
    merge_max(
      &mut self.needs_rescan,
      ev.subscription(),
      ev.key().to_vec(),
      ev.epoch(),
      ev.value().cloned(),
    );
  }

  /// Re-offers every parked per-subscription overflow `Rescan` at the top of each loop
  /// iteration, ahead of new deltas (design backpressure doc): a shed `Rescan` lives in the
  /// durable `needs_rescan` set and is retried every tick until [`try_send`] accepts it, so
  /// it can never be lost to a full channel (checklist #1, no-silent-loss).
  ///
  /// **Suppression by owner state** (Codex R24, the correctness boundary): an entry whose sub is in
  /// [`unclaimed`](Self::unclaimed) — its committed [`WatchGrant`] still in flight — is **retained
  /// without being offered**. That debt is owed to nobody yet (the caller never obtained the
  /// subscription), so delivering it would emit a `Rescan` for a subscription the caller never
  /// received. The suppression lifts the instant the owner processes the grant's
  /// [`ClaimGrant`](Command::ClaimGrant) (the caller claimed it — now genuinely owed) and the entry
  /// is purged if instead its [`DropOrphan`](Command::DropOrphan) fires. Because `unclaimed` is
  /// mutated only by the owner between flushes, this replaces the old mailbox-idle gate's TOCTOU
  /// probe with a decision that is always consistent at flush time — and, being per-sub, never
  /// starves a LIVE claimed subscription's parked Rescan under control-plane load. Every
  /// [`flush_pending_rescans`](Self) caller (the run-loop tick and [`drain_owed_once`](Self::drain_owed_once))
  /// inherits this suppression, since it lives inside the one method.
  ///
  /// A [`Full`](async_channel::TrySendError::Full) channel keeps the (offered) entry for the next
  /// tick; an accepted or [`Closed`](async_channel::TrySendError::Closed) one clears it
  /// (delivered, or the consumer is gone with nobody left to receive it).
  ///
  /// [`try_send`]: async_channel::Sender::try_send
  fn flush_pending_rescans(&mut self) {
    let events = &self.events;
    let unclaimed = &self.unclaimed;
    self.needs_rescan.retain(|&sub, parked| {
      // Suppress — retain without offering — a still-unclaimed sub's parked debt: it is owed to
      // nobody until the caller claims (`ClaimGrant`) or drops (`DropOrphan`) the in-flight grant.
      if unclaimed.contains(&sub) {
        return true;
      }
      // Mint the owed Rescan carrying the value captured at park time (design §3): the sub or its
      // root may already be retired, so the value cannot be re-resolved here — it rides the entry.
      let mut event = Event::rescan(sub, parked.key.clone(), parked.epoch);
      event.set_value(parked.value.clone());
      match events.try_send(event) {
        Ok(()) | Err(async_channel::TrySendError::Closed(_)) => false,
        Err(async_channel::TrySendError::Full(_)) => true,
      }
    });
  }

  /// Resolves one raw event's root and fans it out to every covering, admitting
  /// subscriber, stamping each delivery in that subscriber's own monotone epoch space
  /// (design §5/§7/§8). An event whose root has no live entry (its subscription(s) were
  /// dropped between the source emitting it and us routing it) fans out to nothing.
  ///
  /// A [`Moved`](tributary_fs::EventKind::Moved) is decomposed per subscriber inside
  /// [`fan_out`](crate::route::fan_out) (both endpoints → the whole move; source only → a
  /// synthesized `Removed`; destination only → a synthesized `Created`), and the filter +
  /// interest gate below runs against that already-projected delivery.
  fn fan_out_raw(&mut self, raw: &SourceEvent<C, S::Handle>) -> Vec<Event<C, V>> {
    // Disjoint field borrows: `subsumer` resolves the root/coverage/interest, `filters`
    // the per-subscription filter, `epochs` owns the per-subscription stamp state.
    let (subsumer, filters, epochs) = (&self.subsumer, &self.filters, &mut self.epochs);
    let Some(record) = subsumer.entry(raw.handle()) else {
      return Vec::new();
    };
    let subscribers = record.subscribers.as_slice();
    let routable = SourceRoutable::<C, V, S::Handle>::new(raw);
    // `raw.epoch()` is the raw source epoch on the event's current root; `set_epoch` binds
    // the umbrella stamp, rebasing away the raw epoch (which restarts per kernel arm).
    let raw_epoch = raw.epoch();
    epochs.stamp_and_fan_out(
      &routable,
      raw_epoch,
      subscribers,
      |sub| subsumer.subscription_key(sub),
      // The admission gate (design §5/§7): a covered non-`Rescan` projection is kept only
      // if the subscription's **interest** admits its (projected) kind AND its **filter**
      // admits it. A subscription with no recorded interest/filter (raced concurrent drop)
      // admits nothing. A `Rescan` never reaches here (fan_out bypasses both gates).
      //
      // The filter sees a pre-delivery [`FilterInput`] (key/kind/location), NOT this projected
      // `Event` — whose epoch is still the raw source stamp and whose value is not yet baked
      // here (both are set by `stamp_into` below, only for an admitted delivery). Handing the
      // filter the raw event would let it mis-read a provisional epoch/absent value (Codex R7);
      // the pre-delivery view makes that impossible while exposing the correct key/kind/path.
      |sub, event: &Event<C, V>| {
        subsumer
          .subscription_interest(sub)
          .is_some_and(|interest| interest_admits(interest, event.kind()))
          && filters.get(&sub).is_some_and(|filter| {
            filter.admits(&FilterInput::new(
              event.key(),
              event.kind(),
              event.location(),
            ))
          })
      },
      |event: &Event<C, V>| event.subscription(),
      |mut event, stamp| {
        event.set_epoch(stamp);
        // Bake the owning subscription's value onto the delivery (design §3): the exact `sub`
        // this copy was routed to — a covering subscription for an ordinary delta, or the
        // specific subscriber for a fanned-out `Rescan` — read from the live coverage plane. This
        // is the per-event attribution, stable across the teardown that empties the `WatchView`;
        // the coalescer preserves it through buffering.
        event.set_value(subsumer.subscription_value(event.subscription()).cloned());
        event
      },
    )
  }

  /// Reconciles a raw source event whose root the [`Source`] has already forgotten
  /// ([`Source::root_key`] answers `None`) by retiring that **dead root** through the shared
  /// [`retire_root_with_terminal_rescan`](Self::retire_root_with_terminal_rescan) primitive and
  /// returning `true` (the run loop then skips its ordinary fan-out). Returns `false` for an
  /// event on a still-live root (an ordinary delivery, or an overflow `Rescan` on a live root),
  /// which the caller fans out normally — an overflow re-enumeration is a coverage-loss signal,
  /// not a retirement.
  ///
  /// A dead root is retired on **any** terminal event kind, not just a `Rescan` (Codex R11 F1).
  /// The lower fs layer can surface a watched-root deletion as a user-visible `Removed` FOLLOWED
  /// BY a terminal `Rescan`; retiring only on the `Rescan` would leave the dead root recorded
  /// across the `Removed`, so a caller that observes the `Removed` and re-`watch`es the same path
  /// **before** the queued `Rescan` is processed (the command-biased select loop runs the `watch`
  /// first) is classified `Covered` by the still-recorded dead handle. Retiring eagerly on the
  /// `Removed` narrows that window; the structural close is [`reconcile_watch`](Self::reconcile_watch),
  /// which validates a `Covered` plan's covering root against [`Source::root_key`] and retires-and-
  /// re-plans past a dead one regardless of terminal-event timing (Codex R12 F1).
  ///
  /// A non-`Rescan` terminal event (a root `Removed`) is **not** separately fanned out: it is
  /// dominated by the terminal `Rescan` this retire parks for every subscriber (redundant), and
  /// routing it through `fan_out_and_push` under debounce would admit it to the coalescer, where the
  /// retire's `drop_subscription` then discards it — buffered-then-dropped, silently losing the
  /// promised event (Codex R12 F2). The coverage loss is signaled by the parked `Rescan` alone, which
  /// [`retire_root_with_terminal_rescan`](Self::retire_root_with_terminal_rescan) parks into
  /// `needs_rescan` **before** the subsumer state is freed, so a full channel can never drop it — the
  /// dead-root path is then uniform (debounce or not) with nothing buffered-away, and both retirement
  /// paths share one primitive.
  ///
  /// The terminal-vs-live distinction is the source liveness hook [`Source::root_key`]; only a
  /// source-emitted terminal signal reaches here (synthetic widen Rescans are minted directly,
  /// never pulled from the stream). Retirement is idempotent: a second terminal event for the
  /// same dead handle (e.g. the `Rescan` after a `Removed` already retired the root) finds no
  /// live root, so [`retire_root_with_terminal_rescan`](Self::retire_root_with_terminal_rescan)
  /// returns early and nothing is double-retired.
  fn retire_if_dead(&mut self, raw: &SourceEvent<C, S::Handle>) -> bool {
    // A still-live root: normal fan-out (an overflow `Rescan` on a live root is NOT a retirement).
    if self.source.root_key(raw.handle()).is_some() {
      return false;
    }
    // The root is dead. Retire it through the shared park-terminal-Rescan-then-retire primitive,
    // which durably owes EVERY subscriber a dominating terminal `Rescan` (parked before the subsumer
    // state is freed) — the coverage-loss signal that re-enumerates each subtree so the consumer
    // learns the root is gone. A non-`Rescan` terminal event (a root `Removed`) is NOT separately
    // fanned out: it is dominated by that terminal `Rescan` (redundant), and routing it through
    // `fan_out_and_push` under debounce would admit it to the coalescer, where the retire's
    // `drop_subscription` then discards it — buffered-then-dropped, silently losing the promised
    // event (Codex R12 F2). Signaling the loss via the parked `Rescan` alone keeps the dead-root path
    // uniform (debounce or not) with nothing buffered-away.
    self.retire_root_with_terminal_rescan(raw.handle());
    true
  }

  /// Pushes attributed events to the event stream: through the coalescer (admit + drain
  /// what is due) when debounce is enabled (design §6), else directly. Every emit funnels
  /// through the non-blocking [`try_emit`](Self::try_emit), so a full channel sheds the
  /// affected subscription to a dominating `Rescan` rather than blocking (no-silent-loss,
  /// bounded memory).
  fn push_all(&mut self, events: Vec<Event<C, V>>) {
    let ready = match self.coalescer.as_mut() {
      Some(coalescer) => {
        let now: Instant = R::now().into();
        for event in events {
          coalescer.admit(event, now);
        }
        let mut ready = Vec::new();
        coalescer.drain_ready(now, &mut ready);
        ready
      }
      None => events,
    };
    for event in ready {
      self.try_emit(event);
    }
  }

  /// Drains the coalescer's now-due entries onto the event stream — the settle-timer edge
  /// (design §6). A no-op when debounce is disabled.
  fn drain_coalescer_due(&mut self) {
    let mut ready = Vec::new();
    if let Some(coalescer) = self.coalescer.as_mut() {
      let now: Instant = R::now().into();
      coalescer.drain_ready(now, &mut ready);
    }
    for event in ready {
      self.try_emit(event);
    }
  }

  /// One best-effort **ordered** delivery pass of everything owed at teardown — the coalesced
  /// tail AND every parked per-subscription overflow [`Rescan`](tributary_fs::EventKind::Rescan)
  /// — ordered so a parked subscription's buffered tail delta never precedes its dominating
  /// `Rescan` (design backpressure doc, checklist #1/#5, no silent loss).
  ///
  /// The seam this closes (the coalescer admit-vs-suppress ordering): [`push_all`](Self::push_all)
  /// admits to the coalescer *before* [`try_emit`](Self::try_emit) suppresses a parked
  /// subscription, so a parked sub can still hold buffered tail deltas whose epoch sits **at or
  /// above** its parked `Rescan`'s (the non-rebasing [`shed_rescan`](epoch::EpochLedger::shed_rescan)
  /// keeps later same-root deltas climbing). Delivering those first would put a delta at/above
  /// the `Rescan`'s epoch ahead of it, so a high-water consumer would ignore the owed `Rescan`
  /// and the overflow loss would go unrecovered. So this:
  ///
  /// 1. flushes the coalescer tail, then **drops every entry for a subscription in
  ///    `needs_rescan`** — its owed dominating `Rescan` re-enumerates and dominates them;
  /// 2. delivers the owed `Rescan`s ([`flush_pending_rescans`](Self::flush_pending_rescans))
  ///    **before** the tail, so a parked sub gets *only* its dominating `Rescan`;
  /// 3. routes the remaining (non-parked) tail through the suppress-safe
  ///    [`try_emit`](Self::try_emit) — never a bare `try_send` — so a full channel sheds a tail
  ///    delta to a *durable* dominating `Rescan` (recovered on a later pass) rather than dropping
  ///    it or ordering it after a `Rescan`.
  ///
  /// Every emit is non-blocking (the owner never awaits the event sender). A caller that must
  /// not lose an owed `Rescan` on a full channel (source drain) re-runs this across a retry;
  /// [`drain_owed_before_shutdown`](Self::drain_owed_before_shutdown) does exactly that.
  fn drain_owed_once(&mut self) {
    let mut tail = Vec::new();
    if let Some(coalescer) = self.coalescer.as_mut() {
      coalescer.flush_all(&mut tail);
    }
    // Drop parked subs' tail deltas — their owed dominating Rescan (delivered next) dominates
    // and re-enumerates them; a non-parked sub's tail is kept.
    tail.retain(|event| !self.needs_rescan.contains_key(&event.subscription()));
    // Owed Rescans first, then the non-parked tail through the suppress-safe funnel.
    self.flush_pending_rescans();
    for event in tail {
      self.try_emit(event);
    }
  }

  /// The **source-drain** shutdown drain (design backpressure doc, checklist #1): when the
  /// source's `next` yields `None` while a consumer is still attached, deliver everything OWED
  /// — the coalesced tail AND every parked per-subscription overflow Rescan — before the stream
  /// ends, so a resuming consumer never reaches stream-end missing an owed dominating Rescan
  /// (no silent loss on source drain).
  ///
  /// Each pass runs an ordered [`drain_owed_once`](Self::drain_owed_once) (a parked sub's tail delta
  /// never precedes its `Rescan`), retried across a short [`RETRY`] sleep while the channel is full —
  /// reclaiming refused tail events (shed to durable `Rescan`s) and re-offering each parked `Rescan`.
  /// A still-**unclaimed** sub's parked debt is **suppressed by owner state** inside that flush (Codex
  /// R24), never delivered for a subscription the caller never obtained — no pre-drain, no timing
  /// window. So the exit condition is "nothing owed to a **claimed** subscription": the drain stops
  /// once every remaining `needs_rescan` key is still `unclaimed` (or the set is empty), or the
  /// consumer is gone ([`is_closed`](async_channel::Sender::is_closed) short-circuits an all-refused
  /// channel whose receivers have all dropped). An unclaimed sub's debt is owed to nobody, so it must
  /// not spin the drain forever waiting for a grant that may never be claimed; a claim arriving
  /// mid-drain is processed by the `select!` below ([`ClaimGrant`](Command::ClaimGrant) lifts the
  /// suppression, so the next pass delivers that sub's Rescan before exiting), and a post-teardown
  /// claim holds a dead subscription exactly like any subscription after teardown (the read plane is
  /// already empty). The owner **never awaits the event sender** (invariant III preserved even at
  /// teardown) — only the command receiver and the retry timer.
  ///
  /// The retry **stays responsive to the command mailbox** (invariant II): a blind sleep would
  /// let a [`Close`](Command::Close) queue forever while the drain spins — behind a full channel
  /// a held-but-not-draining receiver keeps the channel both full and un-closed, so neither the
  /// slot-freed nor the all-receivers-dropped exit ever fires. So it
  /// [`select!`](futures_util::select_biased)s the retry timer against
  /// [`commands.recv`](async_channel::Receiver::recv): a `Close` (or the command channel closing
  /// = every handle dropped) stops the blocking retry, and the `Close` reply is returned to the
  /// caller (which does a non-blocking best-effort teardown and acks it) so `close()` always
  /// completes even mid-drain. A `watch`/`unwatch` arriving mid-teardown is failed fast (the
  /// owner is quiescing) and the owed-`Rescan` drain continues.
  ///
  /// Returns the [`Close`](Command::Close) reply if a `Close` interrupted the drain, else
  /// [`None`].
  async fn drain_owed_before_shutdown(
    &mut self,
  ) -> Option<futures_channel::oneshot::Sender<Result<(), CloseError>>> {
    loop {
      // Service everything already queued BEFORE the owed pass and its exit check (Codex R25-F1):
      // a `ClaimGrant` sitting in the mailbox must lift its subscription's suppression FIRST — the
      // caller defused the grant and genuinely holds the sub, so its parked Rescan is owed — or the
      // all-unclaimed exit below would read the STALE `unclaimed` set and tear down having never
      // delivered it: suppression become permanent loss. This pre-drain is non-blocking; a `Close`
      // found here stops the drain exactly as the `select!` arm does. (It is NOT the suppression
      // boundary — owner state is, R24 — it only makes the EXIT PREDICATE read post-claim state.)
      while let Ok(cmd) = self.commands.try_recv() {
        if let Some(reply) = self.handle_teardown_command(cmd) {
          return Some(reply);
        }
      }
      self.drain_owed_once();
      // Exit once nothing is owed to a CLAIMED subscription AND the mailbox has been observed
      // empty after that pass — the linearization point (Codex R25-F1): a claim observable by now
      // was processed by the pre-drain above and its Rescan delivered by this pass; one arriving
      // after this observation is post-teardown, its subscription dead like any subscription after
      // teardown. Every remaining `needs_rescan` key still `unclaimed` means the debt is owed to
      // nobody (and must not spin the drain waiting for a grant that may never resolve); or the
      // consumer is gone entirely.
      if (self
        .needs_rescan
        .keys()
        .all(|sub| self.unclaimed.contains(sub))
        && self.commands.is_empty())
        || self.events.is_closed()
      {
        return None;
      }
      let sleep = R::sleep(RETRY).fuse();
      futures_util::pin_mut!(sleep);
      futures_util::select_biased! {
        cmd = self.commands.recv().fuse() => match cmd {
          // A queued command mid-drain: a `Close` (handed back so the caller acks it — `close()`
          // completes), a `DropOrphan` (released synchronously — its parked entry purged), or a
          // `watch`/`unwatch` (failed fast — the owner is quiescing). Shared with the pre-drain above.
          Ok(command) => {
            if let Some(reply) = self.handle_teardown_command(command) {
              return Some(reply);
            }
          }
          // Every handle dropped: nobody is left to receive the owed Rescans — stop and tear
          // down (the caller's best-effort final pass runs next).
          Err(_) => return None,
        },
        _ = sleep => {}
      }
    }
  }

  /// Handles one command won by the [`drain_owed_before_shutdown`](Self::drain_owed_before_shutdown)
  /// `select!` while the owner is quiescing (the shared source-drain teardown-command core):
  ///
  /// - a [`DropOrphan`](Command::DropOrphan) is released through the synchronous
  ///   [`release_subscription`](Self::release_subscription) — purging its owner-local state (its
  ///   `unclaimed` flag and any parked terminal `Rescan` among it) and requesting the emptied root's
  ///   fire-and-forget `source.disarm`;
  /// - a [`ClaimGrant`](Command::ClaimGrant) removes the sub from [`unclaimed`](Self::unclaimed),
  ///   lifting the suppression so the next drain pass can deliver that sub's owed `Rescan` before
  ///   exiting (a claim arriving mid-teardown is genuinely owed its debt);
  /// - a [`Watch`](Command::Watch)/[`Unwatch`](Command::Unwatch) is **failed fast** — the owner is
  ///   stopping, so the caller's handle surfaces `Closed`;
  /// - a [`Close`](Command::Close) is handed back (as [`Some`]) for the caller to acknowledge.
  ///
  /// It awaits nothing, so it can never park teardown behind a queued `Close` (invariant II).
  fn handle_teardown_command(
    &mut self,
    cmd: Command<C, V>,
  ) -> Option<futures_channel::oneshot::Sender<Result<(), CloseError>>> {
    match cmd {
      // A watch orphaned mid-teardown (a dropped wait's [`WatchGrant`] fired): release it through the
      // unified [`release_subscription`](Self::release_subscription), which awaits nothing. A
      // released-at-teardown handle is moot anyway (the owner drops the source wholesale on exit), but
      // uniformity beats a purge-only special case — and its `unclaimed`/parked state is purged.
      Command::DropOrphan(sub) => {
        let _ = self.release_subscription(sub);
        None
      }
      // A claim arriving mid-teardown lifts the suppression so the drain delivers that sub's owed
      // Rescan (a claimed sub is genuinely owed). A `HashSet` remove — awaits nothing.
      Command::ClaimGrant(sub) => {
        self.unclaimed.remove(&sub);
        None
      }
      Command::Watch { reply, .. } => {
        let _ = reply.send(Err(WatchError::Fs(WatchRootError::Closed)));
        None
      }
      Command::Unwatch { reply, .. } => {
        let _ = reply.send(Err(UnwatchError::Fs(tributary_fs::UnwatchError::Closed)));
        None
      }
      Command::Close { reply } => Some(reply),
    }
  }
}

/// One subscription's parked dominating [`Rescan`](tributary_fs::EventKind::Rescan) (design
/// backpressure doc): the covered `key` to re-enumerate, a strictly-dominating `epoch`, and the
/// owning subscription's baked `value` — the latter captured **while the subscription is live**
/// (at park / retire time), so the Rescan minted from this entry by
/// [`flush_pending_rescans`](Owner::flush_pending_rescans) stays attributable even after the
/// subscription/root is retired and the [`WatchView`] is emptied (design §3, R4).
struct ParkedRescan<C, V> {
  /// The subscription's covered key — the subtree the consumer re-enumerates.
  key: Vec<C>,
  /// The non-rebasing strictly-dominating shed epoch.
  epoch: Epoch,
  /// The owning subscription's baked caller value (`None` only when the sub had no live value at
  /// capture — a raced retirement).
  value: Option<V>,
}

/// Merges a parked overflow [`Rescan`](tributary_fs::EventKind::Rescan) into the dirty-set,
/// keeping the `key`, the max `epoch`, and the baked `value` (design backpressure doc, checklist
/// #3/#4; design §3 for the value).
///
/// The load-bearing effect is the epoch `max`: repeated sheds of one subscription collapse to
/// a single dominating `Rescan` at the greatest
/// [`shed_rescan`](epoch::EpochLedger::shed_rescan) epoch (that mint is strictly increasing,
/// so the newest shed already carries it; the `max` states the dominance intent regardless).
/// The `key` **and** `value` overwrites are both **defensive no-ops**: a subscription's own key
/// and its caller value are each invariant across its lifetime — `commit_watch` repoints only
/// which root a widened sub *rides*, never its own key, and a value is set once at `watch` and
/// never re-assigned — so every shed of a given `sub` carries the same
/// `subscription_key(sub)`/`subscription_value(sub)`. They uphold the "keys only ever widen"
/// invariant without ever needing to exercise it (a widen's own synthetic `Rescan` for an
/// already-parked sub is suppressed by `try_emit`, so it never reaches this merge).
fn merge_max<C: PartialEq, V>(
  needs_rescan: &mut BTreeMap<Subscription, ParkedRescan<C, V>>,
  sub: Subscription,
  key: Vec<C>,
  epoch: Epoch,
  value: Option<V>,
) {
  use std::collections::btree_map::Entry;
  match needs_rescan.entry(sub) {
    Entry::Occupied(mut occupied) => {
      let parked = occupied.get_mut();
      // Widen the parked key to the longest common prefix of the two keys, so the single
      // parked `Rescan` covers BOTH re-enumeration debts. Overwriting with `key` is correct
      // only when it is an ancestor of the parked key; two independent source `Rescan`s under
      // one root (say /a/x then /a/y) are siblings, and dropping either's coverage is silent
      // loss (Codex R8). Their common prefix (/a) re-enumerates a superset of both, and where
      // `key` *is* an ancestor of the parked key the prefix is exactly `key` (unchanged
      // behavior for the re-point/terminal/ordinary-shed paths).
      let common = key
        .iter()
        .zip(parked.key.iter())
        .take_while(|(a, b)| a == b)
        .count();
      parked.key.truncate(common);
      parked.epoch = parked.epoch.max(epoch);
      parked.value = value;
    }
    Entry::Vacant(vacant) => {
      vacant.insert(ParkedRescan { key, epoch, value });
    }
  }
}

/// The pure `RoutableEvent<C>` adapter over one raw [`SourceEvent`] (design §5): it
/// exposes the event's located key — and, for a move, its source key — and mints each
/// per-subscriber delivery as a flat owned [`Event`]. The router thus stays key-generic
/// and I/O-free while the source-specific key extraction already happened at the
/// [`Source`] binding.
struct SourceRoutable<'a, C, V, H> {
  event: &'a SourceEvent<C, H>,
  _value: PhantomData<V>,
}

impl<'a, C, V, H> SourceRoutable<'a, C, V, H> {
  #[inline]
  fn new(event: &'a SourceEvent<C, H>) -> Self {
    Self {
      event,
      _value: PhantomData,
    }
  }
}

impl<C, V, H> RoutableEvent<C> for SourceRoutable<'_, C, V, H>
where
  C: Clone,
{
  type Delivered = Event<C, V>;

  #[inline]
  fn key(&self) -> &[C] {
    self.event.key()
  }

  #[inline]
  fn move_from(&self) -> Option<&[C]> {
    self.event.from()
  }

  #[inline]
  fn is_rescan(&self) -> bool {
    self.event.is_rescan()
  }

  #[inline]
  fn deliver(&self, sub: Subscription) -> Event<C, V> {
    Event::from_source(sub, self.event)
  }

  #[inline]
  fn deliver_move_out(&self, sub: Subscription) -> Event<C, V> {
    Event::source_move_out(sub, self.event)
  }

  #[inline]
  fn deliver_move_in(&self, sub: Subscription) -> Event<C, V> {
    Event::source_move_in(sub, self.event)
  }
}

/// Whether `interest` subscribes to a delivery of `kind` — the per-subscription fan-out
/// gate (design §5). Every umbrella root is armed [`Interest::all`], so this narrows
/// *delivery* only, never the source watch (design §4).
///
/// A [`Rescan`](tributary_fs::EventKind::Rescan) is always admitted (though in practice it
/// never reaches this gate — [`fan_out`](crate::route::fan_out) short-circuits it), and an
/// unknown future kind is admitted conservatively rather than silently dropped.
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

/// The error for a canonicalization race where the source's committed canonical key
/// diverged from the planned one in a way that changes subsumption (design §4, invariant
/// I2). Framed as a [`Canonicalize`](WatchError::Canonicalize) failure — it *is* a
/// canonical-coordinate mismatch — carrying a generic message (the key space is `C`, not
/// necessarily a path, so no path is encoded).
fn canonical_race() -> WatchError {
  WatchError::Canonicalize {
    path: PathBuf::new(),
    source: std::io::Error::other(
      "the source's committed canonical key diverged from the planned one and changed \
       subsumption; retry the watch",
    ),
  }
}

/// Compile-time proof that the pure-fs [`Tributaries`] constructs and its owner future is
/// `Send`, so it can be spawned via
/// [`R::spawn_detach`](agnostic_lite::RuntimeLite::spawn_detach) on a multi-threaded
/// executor. Never invoked — it only has to type-check.
#[cfg(feature = "tokio")]
#[allow(dead_code)]
fn assert_fs_owner_send() {
  fn is_send<T: Send>() {}
  is_send::<Tributaries<OsString, (), agnostic_lite::tokio::TokioRuntime>>();
  fn owner_future_is_send(
    owner: Owner<
      OsString,
      (),
      agnostic_lite::tokio::TokioRuntime,
      FsSource<agnostic_lite::tokio::TokioRuntime>,
    >,
  ) {
    fn needs_send<F: Send>(_: F) {}
    needs_send(run(owner));
  }
  let _ = owner_future_is_send;
}

/// Compile-time proof that the owner future is `Send` for **any** `Send` source (not just
/// [`FsSource`]) — the guarantee that a generic `S: Source<C>` owner is structurally
/// spawnable, since [`Source`]'s three futures are all `Send`. Never invoked.
#[allow(dead_code)]
fn assert_generic_owner_send<C, V, R, S>(owner: Owner<C, V, R, S>)
where
  C: Ord + Clone + Send + Sync + 'static,
  V: Clone + Send + Sync + 'static,
  R: RuntimeLite,
  S: Source<C> + Send + 'static,
  S::Handle: Send + Sync + 'static,
{
  fn needs_send<F: Send>(_: F) {}
  needs_send(run(owner));
}

/// A [`Tributaries`] driven by the tokio runtime, over the local filesystem.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub type TokioTributaries = Tributaries<OsString, (), agnostic_lite::tokio::TokioRuntime>;

/// A [`Tributaries`] driven by the smol runtime, over the local filesystem.
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub type SmolTributaries = Tributaries<OsString, (), agnostic_lite::smol::SmolRuntime>;
