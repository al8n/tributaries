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
  collections::HashMap, ffi::OsString, hash::Hash, marker::PhantomData, path::PathBuf, vec::Vec,
};

use agnostic_lite::RuntimeLite;
use futures_util::FutureExt;
use tributary_fs::{Interest, RootHandle, WatchRootError};

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
    // Only the debounce policy applies to a pre-built source; the watcher options it would
    // otherwise carry are the source's own concern (it is already constructed).
    let (_watcher_options, debounce) = options.into().into_parts();
    let subsumer = Subsumer::new();
    let view = subsumer.view();
    // Unbounded so the owner's inline fan-out and reconcile Rescans never block the
    // `select!` loop mid-push (which would strand a concurrent `Close`); the lower source
    // is the natural backpressure point. A slow consumer buffers here rather than
    // deadlocking the owner — no event is ever dropped (no-silent-loss).
    let (event_tx, event_rx) = async_channel::unbounded();
    let (command_tx, command_rx) = async_channel::unbounded();
    let owner = Owner {
      source,
      subsumer,
      epochs: EpochLedger::new(),
      filters: HashMap::new(),
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
  /// down, resolving once it has. Buffered events not yet drained are lost with the
  /// stream.
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
  let closing = loop {
    // Only a coalescer with buffered/ready entries has a settle deadline; otherwise the
    // timer arm parks forever and never fires (debounce disabled, or nothing pending).
    let deadline = owner.coalescer.as_ref().and_then(Coalescer::next_deadline);
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
        Ok(Command::Close { reply }) => break Some(reply),
        // Every handle dropped: same orderly teardown, nobody to confirm it to.
        Err(_) => break None,
      },
      raw = owner.source.next().fuse() => match raw {
        Some(event) => {
          owner.fan_out_and_push(&event).await;
          owner.retire_if_dead(&event).await;
        }
        // The source drained: flush the coalesced tail below, then tear down.
        None => break None,
      },
      _ = timer => owner.drain_coalescer_due().await,
    }
  };

  // Teardown: force-emit any still-settling coalescer tail so a burst interrupted by the
  // close/drain is never silently dropped, then confirm the close. Dropping `owner` (and
  // its source) performs the orderly source teardown.
  owner.flush_coalescer_tail().await;
  if let Some(reply) = closing {
    let _ = reply.send(Ok(()));
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
            // No rollback (invariant I3): the subsumed roots stay disarmed and their
            // subscriptions uncovered. Signal each a dominating Rescan (no silent loss);
            // a later reconcile re-covers them. Abort the newcomer's plan.
            self.signal_uncovered(unwatch).await;
            self.subsumer.abort_watch(&outcome);
            return Err(err);
          }
        };
        let (handle, fs_key) = armed;
        if !self.subsumer.fs_path_preserves_plan(&fs_key, unwatch) {
          self.source.disarm(handle).await;
          self.signal_uncovered(unwatch).await;
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
        self.push_all(rescans).await;
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
    match self.subsumer.plan_unwatch(sub) {
      None => Err(UnwatchError::UnknownSubscription),
      Some(UnwatchOutcome::Dropped) => {
        // The root still serves others; reclaim only this subscription's per-sub state so
        // a watch → repoint → unwatch churn cannot leak the filter or epoch ledger.
        self.filters.remove(&sub);
        self.epochs.remove(sub);
        Ok(())
      }
      Some(UnwatchOutcome::RootEmptied { fs_root }) => {
        self.filters.remove(&sub);
        self.epochs.remove(sub);
        self.source.disarm(fs_root).await;
        Ok(())
      }
    }
  }

  /// Signals every subscriber of the still-disarmed subsumed roots a dominating
  /// [`Rescan`](tributary_fs::EventKind::Rescan) at that root's key (no silent loss) — the
  /// "uncovered by a failed widen arm" repair (invariant I3): the subsumed roots stayed
  /// disarmed (no rollback), so their subscribers must re-enumerate the root they rode.
  ///
  /// The subsumer still holds the subsumed roots (the widen never committed), so each
  /// handle resolves to its live record; its key names the subtree to re-enumerate.
  async fn signal_uncovered(&mut self, unwatch: &[S::Handle]) {
    // Snapshot each still-present subsumed root's (key, subscribers) before repointing, so
    // the immutable subsumer borrow is released before the mutable epoch bumps.
    let roots: Vec<(Vec<C>, Vec<Subscription>)> = unwatch
      .iter()
      .filter_map(|&handle| {
        self
          .subsumer
          .entry(handle)
          .map(|record| (record.key.clone(), record.subscribers.clone()))
      })
      .collect();
    let mut rescans = Vec::new();
    for (root_key, subscribers) in roots {
      for sub in subscribers {
        let rescan = self.epochs.repoint(sub);
        rescans.push(Event::rescan(sub, root_key.clone(), rescan));
      }
    }
    self.push_all(rescans).await;
  }

  /// Fans one raw source event out to its covering, admitting subscribers and pushes the
  /// results (through the coalescer, if enabled) to the event stream.
  async fn fan_out_and_push(&mut self, raw: &SourceEvent<C, S::Handle>) {
    let fanned = self.fan_out_raw(raw);
    self.push_all(fanned).await;
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
  /// emits a terminal [`Rescan`](tributary_fs::EventKind::Rescan); the fan-out above
  /// delivered that Rescan to every subscriber (loss is never silent), and this then frees
  /// the now-dead root's index / filter / epoch state.
  ///
  /// The terminal-vs-overflow distinction is the source liveness hook
  /// [`Source::root_key`]: it answers `None` exactly for a dead/retired root, so a
  /// terminal `Rescan` (whose root the source has forgotten) is retired while an overflow
  /// re-enumeration on a still-live root is left alone. Only a source-emitted terminal
  /// signal reaches here — synthetic widen Rescans are pushed directly, never pulled from
  /// the stream.
  async fn retire_if_dead(&mut self, raw: &SourceEvent<C, S::Handle>) {
    if !raw.is_rescan() || self.source.root_key(raw.handle()).is_some() {
      return;
    }
    // The single retirement point (invariant I4): free index + filter + epoch together.
    for sub in self.subsumer.force_remove_root(raw.handle()) {
      self.filters.remove(&sub);
      self.epochs.remove(sub);
    }
  }

  /// Pushes attributed events to the event stream: through the coalescer (admit + drain
  /// what is due) when debounce is enabled (design §6), else directly. No event is ever
  /// dropped (no-silent-loss) — a full/slow consumer buffers on the unbounded channel.
  async fn push_all(&mut self, events: Vec<Event<C, V>>) {
    let ready = match self.coalescer.as_mut() {
      Some(coalescer) => {
        let now: std::time::Instant = R::now().into();
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
      let _ = self.events.send(event).await;
    }
  }

  /// Drains the coalescer's now-due entries onto the event stream — the settle-timer edge
  /// (design §6). A no-op when debounce is disabled.
  async fn drain_coalescer_due(&mut self) {
    let mut ready = Vec::new();
    if let Some(coalescer) = self.coalescer.as_mut() {
      let now: std::time::Instant = R::now().into();
      coalescer.drain_ready(now, &mut ready);
    }
    for event in ready {
      let _ = self.events.send(event).await;
    }
  }

  /// Force-emits every still-settling coalescer entry onto the event stream, regardless
  /// of deadline — the close/drain path (design §6, no-silent-loss). A no-op when debounce
  /// is disabled.
  async fn flush_coalescer_tail(&mut self) {
    let mut tail = Vec::new();
    if let Some(coalescer) = self.coalescer.as_mut() {
      coalescer.flush_all(&mut tail);
    }
    for event in tail {
      let _ = self.events.send(event).await;
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
