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
  filter::Filter,
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

/// A control-plane request from a [`Tributaries`] handle to its [`Owner`], carrying a
/// `oneshot` reply the caller's cancellable wait reads.
///
/// The owner processes each to completion (invariant I1): dropping the caller's returned
/// future drops only the [`oneshot::Receiver`](futures_channel::oneshot::Receiver), never
/// the reconcile the owner runs.
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
    filter: Filter<C, V>,
    /// The reply channel: the minted [`Subscription`], or the arm error.
    reply: futures_channel::oneshot::Sender<Result<Subscription, WatchError>>,
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
      coalescer: debounce.map(Coalescer::new),
      commands: command_rx,
      events: event_tx,
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
  /// # Callers MUST pass canonical keys (hard contract)
  ///
  /// For the filesystem source, `key` **must** be canonical (fully resolved: no symlink,
  /// `.`, or `..` components). The source keys its subsumption index and reports its events
  /// in canonical coordinates. A non-canonical `key` that resolves *under an already-watched
  /// canonical root* is accepted as a `Covered` subscription keyed on the **non-canonical**
  /// path — but later events arrive under the canonical path, fail this subscription's
  /// ancestor/coverage match, and are **silently dropped with no `Rescan`** (there is no
  /// coverage-loss to detect: the root is alive and delivering; only *this* subscription's
  /// key never matches). Passing canonical keys is therefore a caller obligation this layer
  /// cannot police. (A *disjoint* non-canonical key is re-keyed onto the source's reported
  /// canonical key when it is armed — design §4 — so this trap is specific to a key subsumed
  /// under an existing root, where no fresh arm re-keys it.)
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
  /// - [`WatchError::Fs`] when arming the source watch fails (or the source's
  ///   committed key diverged and changed subsumption — surfaced as
  ///   [`WatchError::Canonicalize`]);
  /// - [`WatchError::Fs(WatchRootError::Closed)`](tributary_fs::WatchRootError::Closed)
  ///   when the owner is gone.
  pub async fn watch(
    &self,
    key: Vec<C>,
    value: V,
    interest: Interest,
    filter: Filter<C, V>,
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
    // `oneshot::Receiver` alone; the owner's reconcile is unaffected (I1).
    response
      .await
      .unwrap_or(Err(WatchError::Fs(WatchRootError::Closed)))
  }

  /// Drops `sub`, releasing its source watch once it was the last subscriber of its
  /// (possibly shared) root.
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
/// [`Coalescer`](crate::coalesce::Coalescer). All arm/disarm and every state mutation run
/// here, to completion (invariant I1). No journal, no rollback, no pending-widen: an
/// interrupted or failed reconcile is repaired by reconciling again (invariant I3).
struct Owner<C, V, R, S>
where
  S: Source<C>,
{
  source: S,
  subsumer: Subsumer<C, V, S::Handle>,
  epochs: EpochLedger,
  filters: HashMap<Subscription, Filter<C, V>>,
  /// The per-subscription overflow dirty-set (design backpressure doc): a subscription
  /// whose delivery hit a full event channel parks a durable **dominating**
  /// [`Rescan`](tributary_fs::EventKind::Rescan) here — its covered key plus a
  /// strictly-dominating epoch. A [`BTreeMap`] for a deterministic drain order.
  /// [`flush_pending_rescans`](Self::flush_pending_rescans) re-offers each every loop tick
  /// until `try_send` accepts it, and [`try_emit`](Self::try_emit) suppresses further
  /// ordinary deliveries to a parked subscription (they are dominated by its `Rescan`), so
  /// a shed can never be lost to a full channel (no-silent-loss).
  needs_rescan: BTreeMap<Subscription, (Vec<C>, Epoch)>,
  coalescer: Option<Coalescer<C, V>>,
  commands: async_channel::Receiver<Command<C, V>>,
  events: async_channel::Sender<Event<C, V>>,
  _rt: PhantomData<R>,
}

/// The owner's single `select!` loop (design driver-golden doc): reconcile a command,
/// fan out a raw source event, or drain the coalescer's due entries — whichever is ready,
/// each to completion.
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
  // The loop yields `(reply, drain_owed)`: `reply` is the `Close` acknowledgement (if any);
  // `drain_owed` is true only on a **source drain** (the source's `next` yielded `None` while
  // a consumer is still attached), which owes that consumer every parked Rescan before the
  // stream ends. A consumer-initiated `Close` or a dropped last handle owes nothing (the
  // consumer asked to stop / nobody is left), and must never block teardown on a full channel.
  let (closing, drain_owed) = loop {
    // Drain the parked per-subscription overflow Rescans ahead of everything else, so a
    // shed Rescan never needs a free channel slot at overflow time and is retried until
    // accepted (design backpressure doc, no-silent-loss).
    owner.flush_pending_rescans();

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

    futures_util::select_biased! {
      cmd = owner.commands.recv().fuse() => match cmd {
        Ok(Command::Watch { key, value, interest, filter, reply }) => {
          owner.on_watch(key, value, interest, filter, reply).await;
        }
        Ok(Command::Unwatch { sub, reply }) => owner.on_unwatch(sub, reply).await,
        Ok(Command::Close { reply }) => break (Some(reply), false),
        // Every handle dropped: same orderly teardown, nobody to confirm it to. Nobody is
        // left to receive, so nothing is owed.
        Err(_) => break (None, false),
      },
      // `source.next()` is one `select!` arm: a command/timer branch winning **drops** this
      // in-flight future. That is safe only because [`Source::next`] is a hard-contract
      // **cancellation-safe** read (see its docs) — dropping the future loses/acks no event.
      raw = owner.source.next().fuse() => match raw {
        Some(event) => {
          owner.fan_out_and_push(&event);
          owner.retire_if_dead(&event);
        }
        // The source drained while a consumer is still attached: it is OWED every parked
        // Rescan before the stream ends (no silent loss on source drain).
        None => break (None, true),
      },
      _ = timer => owner.drain_coalescer_due(),
    }
  };

  if drain_owed {
    // Source drain: deliver the coalesced tail AND every owed parked Rescan before ending
    // the stream, retrying as the consumer drains (design backpressure doc, checklist #1).
    owner.drain_owed_before_shutdown().await;
  } else {
    // Consumer-initiated `Close`, or every handle dropped: best-effort force-emit the
    // still-settling coalescer tail and one pass of any parked Rescans so a burst interrupted
    // by the close is delivered when the channel has room. The undrained tail / owed Rescan on
    // a full channel is permitted to be lost here (the consumer asked to stop, or nobody is
    // left) — teardown never blocks on the channel, so `Close` stays responsive.
    owner.flush_coalescer_tail();
    owner.flush_pending_rescans();
  }
  // Dropping `owner` (and its source) performs the orderly source teardown.
  if let Some(reply) = closing {
    let _ = reply.send(Ok(()));
  }
}

/// How long the owner waits before re-attempting delivery of a parked per-subscription
/// overflow [`Rescan`](tributary_fs::EventKind::Rescan) when the event channel is full
/// (design backpressure doc). Mirrors the fs layer's `DELIVERY_RETRY`. Latency-only: a
/// resuming consumer's next drained slot is also retried on the following command/event
/// tick; this bounds the wait when the stream is otherwise idle.
const RETRY: Duration = Duration::from_millis(25);

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
  /// Handles a [`Command::Watch`]: reconcile it, then reply. If the caller vanished after
  /// the watch committed (the reply `oneshot` is closed), retire the orphaned
  /// subscription immediately — the one residual "dropped wait" case (design
  /// driver-golden doc, invariant I1).
  async fn on_watch(
    &mut self,
    key: Vec<C>,
    value: V,
    interest: Interest,
    filter: Filter<C, V>,
    reply: futures_channel::oneshot::Sender<Result<Subscription, WatchError>>,
  ) {
    match self.reconcile_watch(&key, value, interest, filter).await {
      Ok(sub) => {
        if reply.send(Ok(sub)).is_err() {
          let _ = self.reconcile_unwatch(sub).await;
        }
      }
      Err(err) => {
        let _ = reply.send(Err(err));
      }
    }
  }

  /// Handles a [`Command::Unwatch`]: reconcile it and reply.
  async fn on_unwatch(
    &mut self,
    sub: Subscription,
    reply: futures_channel::oneshot::Sender<Result<(), UnwatchError>>,
  ) {
    let result = self.reconcile_unwatch(sub).await;
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
    filter: Filter<C, V>,
  ) -> Result<Subscription, WatchError> {
    let outcome = self.subsumer.plan_watch(key, value, interest);
    match &outcome {
      WatchOutcome::Covered { fs_root, sub } => {
        // Already covered by a live root: no arm. The covering root's key was validated
        // when first armed, so the newcomer's own key is used unchanged.
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
          self.source.disarm(handle).await;
          self.subsumer.abort_watch(&outcome);
          return Err(canonical_race());
        }
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
        // Release the subsumed watches first; the coverage gap is closed by the
        // dominating Rescan each re-pointed subscription receives below.
        for &old in unwatch {
          self.source.disarm(old).await;
        }
        let armed = match self.arm(key).await {
          Ok(armed) => armed,
          Err(err) => {
            // The wider arm failed after the subsumed roots were disarmed. Do NOT leave
            // their live subscriptions bound to disarmed handles (they would read watched
            // yet never see another event). Restore the pre-widen armed state: re-arm each
            // disarmed root through the choke point, or — for one that is genuinely dead —
            // retire it with a dominating Rescan so its subs re-enumerate and it leaves the
            // view (design driver-golden doc, invariant I3). Then abort the newcomer's plan.
            self.restore_disarmed_roots(unwatch).await;
            self.subsumer.abort_watch(&outcome);
            return Err(err);
          }
        };
        let (handle, fs_key) = armed;
        if !self.subsumer.fs_path_preserves_plan(&fs_key, unwatch) {
          // The wider root armed but its committed key diverged (a canonicalization race):
          // disarm it, then restore the disarmed subsumed roots exactly as above — the same
          // strand-avoidance the arm-failure branch runs (both post-disarm exits must restore,
          // never signal-and-strand).
          self.source.disarm(handle).await;
          self.restore_disarmed_roots(unwatch).await;
          self.subsumer.abort_watch(&outcome);
          return Err(canonical_race());
        }
        self.subsumer.commit_watch(&outcome, handle, &fs_key);
        self.filters.insert(sub, filter);
        // Rebase each re-pointed subscription onto the wider root (design §8): its
        // synthetic dominating Rescan strictly dominates its pre-widen stream while the
        // new root's genuine events tie-or-exceed it, and names the widened root to
        // re-enumerate — closing the unwatch→arm coverage gap.
        let mut rescans = Vec::with_capacity(repointed.len());
        for moved in repointed {
          let rescan = self.epochs.repoint(moved);
          rescans.push(Event::rescan(moved, fs_key.clone(), rescan));
        }
        self.push_all(rescans);
        Ok(sub)
      }
    }
  }

  /// The single **arm-and-key choke point** (invariant I2): arms `key` through the
  /// [`Source`], and adopts the source's reported **canonical key** as the committed
  /// coordinate. Every arming path (fresh, widen) funnels through here, so no coverage
  /// check ever runs against a provisional key.
  async fn arm(&mut self, key: &[C]) -> Result<(S::Handle, Vec<C>), WatchError> {
    let armed = self.source.arm(key).await?;
    Ok((armed.handle(), armed.canonical_key().to_vec()))
  }

  /// Reconciles one `unwatch` (invariant I4): retires the subscription's per-source and
  /// per-subscription state, releasing the source watch once it was the root's last
  /// subscriber.
  async fn reconcile_unwatch(&mut self, sub: Subscription) -> Result<(), UnwatchError> {
    let Some(outcome) = self.subsumer.plan_unwatch(sub) else {
      return Err(UnwatchError::UnknownSubscription);
    };
    // Reclaim this subscription's per-sub state so a watch → repoint → unwatch churn cannot
    // leak it. A consumer-initiated unwatch owes NO coverage-loss re-enumeration (the caller
    // asked to stop watching), so drop its parked overflow Rescan alongside its filter and
    // epoch — unlike the root-death path (`retire_if_dead`), which KEEPS the parked terminal
    // Rescan so its owed re-enumeration self-drains (design backpressure doc, no silent loss).
    self.retire_sub_state(sub);
    self.needs_rescan.remove(&sub);
    if let UnwatchOutcome::RootEmptied { fs_root } = outcome {
      // The subscription was its root's last: release the kernel watch.
      self.source.disarm(fs_root).await;
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
  /// - the consumer-initiated unwatch path ([`reconcile_unwatch`](Self::reconcile_unwatch))
  ///   drops it — the caller asked to stop watching, so no coverage-loss re-enumeration is
  ///   owed;
  /// - the root-death path ([`retire_if_dead`](Self::retire_if_dead)) **keeps** it — the
  ///   terminal coverage-loss `Rescan`, parked here only because the channel was full, IS
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
  /// - **re-arm at the same key** through the [`arm`](Self::arm) choke point. On success
  ///   whose committed key is unchanged, [`rebind`](Subsumer::rebind_root) the root onto the
  ///   fresh handle and mint a dominating [`Rescan`](tributary_fs::EventKind::Rescan) per
  ///   subscriber — the re-arm restarts the source's raw epochs at zero, so each subscriber
  ///   [`repoint`](epoch::EpochLedger::repoint)s onto the new handle (exactly a widen
  ///   re-point) and re-enumerates. The subscription is live-and-covered again.
  /// - if the re-arm **fails** (the root is genuinely dead), or its committed key **diverged**
  ///   (a canonicalization race we cannot cleanly rebind), **retire** the root
  ///   ([`retire_disarmed_root`](Self::retire_disarmed_root)): a dominating terminal Rescan
  ///   per subscriber, then free its index / filter / epoch and drop it from the view.
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
          // Re-armed at the same coordinate: rebind onto the fresh handle and re-point each
          // subscriber (raw epochs restarted at zero) with a dominating Rescan.
          self.subsumer.rebind_root(old, new_handle);
          let mut rescans = Vec::with_capacity(subscribers.len());
          for sub in subscribers {
            let rescan = self.epochs.repoint(sub);
            rescans.push(Event::rescan(sub, root_key.clone(), rescan));
          }
          self.push_all(rescans);
        }
        Ok((new_handle, _diverged)) => {
          // Re-armed, but at a divergent key we cannot cleanly rebind: disarm the stray new
          // handle and retire the old root so its subs re-enumerate and it leaves the view.
          self.source.disarm(new_handle).await;
          self.retire_disarmed_root(old, &root_key);
        }
        Err(_) => self.retire_disarmed_root(old, &root_key),
      }
    }
  }

  /// Retires a subsumed root that could not be re-armed after a failed widen: a dominating
  /// terminal [`Rescan`](tributary_fs::EventKind::Rescan) per subscriber (so each
  /// re-enumerates and learns the root is gone), then frees its index / reverse-index / side
  /// table (via [`force_remove_root`](Subsumer::force_remove_root)) and every subscriber's
  /// per-sub filter + epoch state (invariant I4). After this the root no longer reads
  /// watched, so a dedup caller re-installs it (no silent loss).
  fn retire_disarmed_root(&mut self, old: S::Handle, root_key: &[C]) {
    let subscribers = self.subsumer.force_remove_root(old);
    let mut rescans = Vec::with_capacity(subscribers.len());
    for &sub in &subscribers {
      // Mint the dominating Rescan before freeing the ledger entry (repoint reads it); the
      // built event carries its epoch, so the subsequent free cannot perturb it.
      let rescan = self.epochs.repoint(sub);
      rescans.push(Event::rescan(sub, root_key.to_vec(), rescan));
    }
    for sub in subscribers {
      self.retire_sub_state(sub);
    }
    self.push_all(rescans);
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
  /// - the subscription already carries a parked overflow `Rescan` (`needs_rescan`) →
  ///   **suppress** the emit: it is dominated by that pending `Rescan`, and delivering it
  ///   would put an ordinary event ahead of the `Rescan` that covers the drop (the fan-out
  ///   atomicity guarantee — Lens 2 — holds across iterations through this check);
  /// - [`Ok`] → delivered;
  /// - [`Full`](async_channel::TrySendError::Full) → shed this subscription to a dominating
  ///   `Rescan` ([`park_rescan`](Self::park_rescan));
  /// - [`Closed`](async_channel::TrySendError::Closed) → no-op: the consumer is gone and
  ///   teardown arrives on the command mailbox.
  fn try_emit(&mut self, ev: Event<C, V>) {
    let sub = ev.subscription();
    if self.needs_rescan.contains_key(&sub) {
      return;
    }
    match self.events.try_send(ev) {
      Ok(()) => {}
      Err(async_channel::TrySendError::Full(_)) => self.park_rescan(sub),
      Err(async_channel::TrySendError::Closed(_)) => {}
    }
  }

  /// Sheds `sub` to a parked dominating [`Rescan`](tributary_fs::EventKind::Rescan) after a
  /// delivery to it found the channel full (design backpressure doc): the per-subscription
  /// overflow shed, mirroring the fs layer's `LagState::Lagged` one level up.
  ///
  /// Looks up `sub`'s covered key (the subtree the consumer must re-enumerate), mints a
  /// **non-rebasing** strictly-dominating epoch ([`EpochLedger::shed_rescan`]), and merges
  /// it into `needs_rescan` keeping the newest/widest key and the max epoch (widen-safe:
  /// [`merge_max`]). Finally it drops `sub`'s now-suspect buffered coalescer deltas — they
  /// are dominated by the parked `Rescan`, so emitting them later would deliver a stale
  /// epoch after it.
  ///
  /// A subscription with no live key (raced retirement) is not parked — a stale parked
  /// `Rescan` would be co-retired anyway, and there is no subtree left to name.
  fn park_rescan(&mut self, sub: Subscription) {
    let Some(key) = self.subsumer.subscription_key(sub).map(<[C]>::to_vec) else {
      return;
    };
    let epoch = self.epochs.shed_rescan(sub);
    merge_max(&mut self.needs_rescan, sub, key, epoch);
    if let Some(coalescer) = self.coalescer.as_mut() {
      coalescer.drop_subscription(sub);
    }
  }

  /// Re-offers every parked per-subscription overflow `Rescan` at the top of each loop
  /// iteration, ahead of new deltas (design backpressure doc): a shed `Rescan` lives in the
  /// durable `needs_rescan` set and is retried every tick until [`try_send`] accepts it, so
  /// it can never be lost to a full channel (checklist #1, no-silent-loss).
  ///
  /// A [`Full`](async_channel::TrySendError::Full) channel keeps the entry for the next
  /// tick; an accepted or [`Closed`](async_channel::TrySendError::Closed) one clears it
  /// (delivered, or the consumer is gone with nobody left to receive it).
  ///
  /// [`try_send`]: async_channel::Sender::try_send
  fn flush_pending_rescans(&mut self) {
    let events = &self.events;
    self.needs_rescan.retain(|&sub, (key, epoch)| {
      match events.try_send(Event::rescan(sub, key.clone(), *epoch)) {
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
      |sub, event: &Event<C, V>| {
        subsumer
          .subscription_interest(sub)
          .is_some_and(|interest| interest_admits(interest, event.kind()))
          && filters.get(&sub).is_some_and(|filter| filter.admits(event))
      },
      |event: &Event<C, V>| event.subscription(),
      |mut event, stamp| {
        event.set_epoch(stamp);
        event
      },
    )
  }

  /// Retires a source root that has **died**, after its terminal signal was fanned out
  /// (invariant I4). When a watched root is deleted, the source tears its handle down and
  /// emits a terminal [`Rescan`](tributary_fs::EventKind::Rescan); the fan-out on this same
  /// event (run just before this call) either delivered that Rescan to every subscriber or —
  /// if the event channel was full — **parked it** in `needs_rescan`, where
  /// [`flush_pending_rescans`](Self::flush_pending_rescans) self-drains it once the consumer
  /// resumes (loss is never silent). This then frees the now-dead root's index / filter /
  /// epoch state while **keeping** each subscription's parked terminal Rescan, so its owed
  /// re-enumeration survives retirement (design backpressure doc).
  ///
  /// The terminal-vs-overflow distinction is the source liveness hook
  /// [`Source::root_key`]: it answers `None` exactly for a dead/retired root, so a
  /// terminal `Rescan` (whose root the source has forgotten) is retired while an overflow
  /// re-enumeration on a still-live root is left alone. Only a source-emitted terminal
  /// signal reaches here — synthetic widen Rescans are pushed directly, never pulled from
  /// the stream.
  fn retire_if_dead(&mut self, raw: &SourceEvent<C, S::Handle>) {
    if !raw.is_rescan() || self.source.root_key(raw.handle()).is_some() {
      return;
    }
    // The single retirement point (invariant I4): drop the dead root from the index and free
    // each subscriber's filter + epoch — but do NOT co-retire `needs_rescan`. The terminal
    // coverage-loss Rescan fanned out just above parks there when the channel is full, and it
    // must survive retirement to self-drain so the consumer still learns the root is gone
    // (design backpressure doc, no silent loss on root death). This is why the death path
    // calls `retire_sub_state` bare, unlike the consumer-initiated unwatch path.
    for sub in self.subsumer.force_remove_root(raw.handle()) {
      self.retire_sub_state(sub);
    }
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

  /// Best-effort force-emits every still-settling coalescer entry onto the event stream,
  /// regardless of deadline — the close/drain path (design §6). A no-op when debounce is
  /// disabled.
  ///
  /// This is teardown, so it emits with a bare non-blocking
  /// [`try_send`](async_channel::Sender::try_send) rather than the ordinary
  /// [`try_emit`](Self::try_emit) funnel: the owner (and its `needs_rescan` set) is about to
  /// drop, so there is no point parking an overflow `Rescan` for a subscription that will not
  /// outlive this call. The tail is delivered when the channel has room, but a
  /// consumer-initiated close is permitted to lose the undrained tail on a full channel
  /// rather than block teardown. Bypassing [`try_emit`](Self::try_emit)'s suppression check
  /// is harmless even when the tail carries a parked subscription's deltas: `push_all` admits
  /// to the coalescer unconditionally (suppression is applied at drain time, not admit time),
  /// so a parked sub can re-buffer deltas after its `park_rescan` dropped the old ones. Those
  /// deltas stamp `base + raw`, which by the non-rebasing `shed_rescan` design sort at or above
  /// the parked `Rescan`'s epoch — and teardown never runs
  /// [`flush_pending_rescans`](Self::flush_pending_rescans), so that `Rescan` is not delivered
  /// here. They are therefore extra best-effort deliveries, never losses and never deltas
  /// ordered after their own dominating `Rescan`.
  fn flush_coalescer_tail(&mut self) {
    let mut tail = Vec::new();
    if let Some(coalescer) = self.coalescer.as_mut() {
      coalescer.flush_all(&mut tail);
    }
    for event in tail {
      let _ = self.events.try_send(event);
    }
  }

  /// The **source-drain** shutdown drain (design backpressure doc, checklist #1): when the
  /// source's `next` yields `None` while a consumer is still attached, deliver everything
  /// OWED — the coalesced tail AND every parked per-subscription overflow Rescan — *before*
  /// the stream ends, so a resuming consumer never reaches stream-end missing an owed
  /// dominating Rescan (no silent loss on source drain).
  ///
  /// Every emit is a non-blocking [`try_send`](async_channel::Sender::try_send) — the owner
  /// **never awaits the event-stream sender** (invariant III preserved even at teardown) —
  /// retried across a short [`RETRY`] sleep while the channel is full, reclaiming each refused
  /// tail event and re-offering each parked Rescan. Bounded: it returns once everything owed is
  /// delivered, or the consumer is gone ([`flush_pending_rescans`](Self::flush_pending_rescans)
  /// clears parked entries on [`Closed`](async_channel::TrySendError::Closed), and
  /// [`is_closed`](async_channel::Sender::is_closed) short-circuits an all-refused channel whose
  /// receivers have all dropped).
  ///
  /// This runs **only** on the source-drain break — a consumer-initiated `Close` or a dropped
  /// last handle owes nothing and takes the non-blocking best-effort path instead, so this
  /// retry can never block a `Close`.
  async fn drain_owed_before_shutdown(&mut self) {
    let mut tail = Vec::new();
    if let Some(coalescer) = self.coalescer.as_mut() {
      coalescer.flush_all(&mut tail);
    }
    loop {
      // Re-offer the coalesced tail, keeping only the events the (full) channel still refuses.
      tail = tail
        .into_iter()
        .filter_map(|event| match self.events.try_send(event) {
          Ok(()) | Err(async_channel::TrySendError::Closed(_)) => None,
          Err(async_channel::TrySendError::Full(returned)) => Some(returned),
        })
        .collect();
      // Re-offer every owed parked Rescan (clears delivered / consumer-gone entries).
      self.flush_pending_rescans();
      if (tail.is_empty() && self.needs_rescan.is_empty()) || self.events.is_closed() {
        break;
      }
      // Wait for the consumer to drain a slot, then retry — never awaiting the sender itself.
      R::sleep(RETRY).await;
    }
  }
}

/// Merges a parked overflow [`Rescan`](tributary_fs::EventKind::Rescan) into the dirty-set,
/// keeping the `key` and the max `epoch` (design backpressure doc, checklist #3/#4).
///
/// The load-bearing effect is the epoch `max`: repeated sheds of one subscription collapse to
/// a single dominating `Rescan` at the greatest
/// [`shed_rescan`](epoch::EpochLedger::shed_rescan) epoch (that mint is strictly increasing,
/// so the newest shed already carries it; the `max` states the dominance intent regardless).
/// The `key` overwrite is a **defensive no-op**: a subscription's own key is invariant across
/// its lifetime — `commit_watch` repoints only which root a widened sub *rides*, never its own
/// key — so every shed of a given `sub` carries the same `subscription_key(sub)`. It upholds
/// the "keys only ever widen" invariant without ever needing to exercise it (a widen's own
/// synthetic `Rescan` for an already-parked sub is suppressed by `try_emit`, so it never
/// reaches this merge).
fn merge_max<C>(
  needs_rescan: &mut BTreeMap<Subscription, (Vec<C>, Epoch)>,
  sub: Subscription,
  key: Vec<C>,
  epoch: Epoch,
) {
  use std::collections::btree_map::Entry;
  match needs_rescan.entry(sub) {
    Entry::Occupied(mut occupied) => {
      let (existing_key, existing_epoch) = occupied.get_mut();
      *existing_key = key;
      *existing_epoch = (*existing_epoch).max(epoch);
    }
    Entry::Vacant(vacant) => {
      vacant.insert((key, epoch));
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
