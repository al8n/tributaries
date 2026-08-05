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
//! over the key component `C` and caller value `V`. The pure-fs convenience — behind
//! the default `fs` feature — fixes `C = OsString`, `V = ()`, and a [`FsSource`] over
//! one `tributary-fs` watcher (the [`TokioTributaries`] / [`SmolTributaries`] aliases).

use std::{
  collections::{BTreeMap, HashMap},
  ffi::OsString,
  hash::Hash,
  marker::PhantomData,
  sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
  },
  time::{Duration, Instant},
  vec::Vec,
};

use agnostic_lite::RuntimeLite;
use futures_util::FutureExt;
use tributary_proto::{Epoch, unwind::dispose_panic_payload};

#[cfg(feature = "fs")]
use tributary_fs::{RootHandle, WatcherOptions};

use crate::{
  coalesce::Coalescer,
  error::{CloseError, SyncError, UnwatchError, WatchError},
  event::Event,
  filter::{Filter, FilterInput},
  options::{Debounce, DebounceConfig, TributariesOptions, WatchOptions},
  route::RoutableEvent,
  source::{Armed, LocalSource, Source, SourceEvent, SyncOutcome, SyncToken},
  subscription::Subscription,
  subsume::{Subsumer, UnwatchOutcome, WatchOutcome},
  view::WatchView,
};

#[cfg(feature = "fs")]
use crate::{error::BuildError, source::FsSource};

use self::epoch::EpochLedger;

mod epoch;

#[cfg(all(test, feature = "tokio"))]
mod tests;

/// The reply a [`close`](Tributaries::close) hands the owner over the dedicated **close signal**:
/// resolved `Ok(())` once the owner has flushed its coalesced tail and its run loop has exited, or
/// dropped by the owner (→ the caller's `close()` sees [`Stopped`](CloseError::Stopped))
/// when the owner is already gone. Close rides its **own** [`async_channel`] — checked at the top
/// priority everywhere the owner selects — so a requested shutdown can never be starved behind the
/// command mailbox ; it is deliberately NOT a [`Command`] variant, so there is
/// one shutdown path and no dual plumbing.
type CloseReply = futures_channel::oneshot::Sender<Result<(), CloseError>>;

/// A control-plane request from a [`Tributaries`] handle to its [`Owner`], carrying a `oneshot`
/// reply the caller's cancellable wait reads.
///
/// Shutdown is **not** here: `close` rides a dedicated high-priority [`CloseReply`] channel (
/// ), never the mailbox, so it cannot queue behind a `Watch`/`Unwatch` flood. Grant resolution is
/// **not** here either: a committed-but-unclaimed [`WatchGrant`]'s claim/drop rides the dedicated
/// reply-less [`Cleanup`] channel, so the owner's close-time grant-resolution drain is
/// bounded by the grants in flight, never by the public command backlog a mailbox scan would walk.
///
/// The owner processes each to completion (invariant I1): dropping the caller's returned future drops
/// only the [`oneshot::Receiver`](futures_channel::oneshot::Receiver), never the reconcile the owner
/// runs. Every variant carries a `oneshot` reply; the only teardown break a command drives is the
/// dropped-last-handle one (the mailbox closing).
enum Command<C, V> {
  /// Subscribe to `key` (carrying caller `value`), with the given per-watch `options`.
  Watch {
    /// The located key to subsume/arm.
    key: Vec<C>,
    /// The caller value attribution returns for this watch (design §3).
    value: V,
    /// The per-subscription delivery options (design §5/§6/§7): the fan-out
    /// [`Interest`](crate::Interest) gate, the admission [`Filter`], and the
    /// [`Debounce`] posture.
    options: WatchOptions<C>,
    /// The reply channel: a [`WatchGrant`] guarding the minted [`Subscription`] (so a dropped
    /// wait cannot strand it — invariant I1), or the arm error.
    reply: futures_channel::oneshot::Sender<Result<WatchGrant, WatchError>>,
  },
  /// Drop a live subscription.
  Unwatch {
    /// The subscription to retire.
    sub: Subscription,
    /// The reply channel: success, or why the drop failed.
    reply: futures_channel::oneshot::Sender<Result<(), UnwatchError>>,
  },
}

/// A **sync-barrier request** riding sync's OWN mailbox — deliberately concrete (no `C`/`V`), so
/// `async_channel::Send<SyncRequest>` is unconditionally `Send` and [`Tributaries::sync`] can bound
/// admission AND observation inside one `R::timeout`. The public [`Command`] mailbox carries
/// key/value-bearing variants whose `async_channel::Send` is not `Send` for all `C`/`V`, so a sync's
/// admission must never queue behind it — hence its own channel.
struct SyncRequest {
  /// The subscription the barrier is for.
  sub: Subscription,
  /// The shared [`loss_gen`](Owner::loss_gen) snapshotted by [`Tributaries::sync`] BEFORE this
  /// request was enqueued — the barrier's loss window therefore opens at the CALLER'S CALL, not at
  /// the owner's install. Compared against the live generation in [`Owner::on_sync`]: any coverage
  /// loss the owner processed while this request sat in the mailbox moves the generation, so the
  /// barrier is `Dominated` even when that loss has since published-and-cleared and left no trace
  /// in the install-time debt maps or the per-subscription loss serial.
  loss_gen_at_call: u64,
  /// Resolved at OBSERVATION (or domination), not at cookie-write: the owner parks it in
  /// `pending_syncs` until the funnel matches. The caller's deadline is enforced by the `R::timeout`
  /// in [`Tributaries::sync`], never here.
  reply: futures_channel::oneshot::Sender<Result<SyncOutcome, SyncError>>,
}

/// One in-flight sync barrier: the cookie the owner is waiting to see, whose
/// subscription (and root) it belongs to, and the caller's parked reply.
struct PendingSync<C, H> {
  /// The cookie's canonical key — matched EXACTLY against arriving events.
  cookie_key: Vec<C>,
  /// The subscription whose barrier this is.
  sub: Subscription,
  /// The root the cookie was written under: a root death dominates it.
  root: H,
  /// The subscription's loss serial at the moment this sync was installed. If
  /// the sub's serial has ADVANCED by resolution time, a coverage loss touched
  /// it DURING the barrier's window (parked then possibly already published),
  /// so the barrier is met by re-enumeration — `Dominated`, not `Delivered`,
  /// even when no debt remains parked at the instant of resolution.
  loss_serial_at_install: u64,
  /// A loss the cookie cannot un-owe already stood when the barrier was installed, so the barrier
  /// must resolve `Dominated` regardless of the flush. Two shapes fold into this one flag:
  /// standing parked debt (a pre-call loss still owed at install), and a **generation change
  /// across the caller's call-to-install window** — a loss the owner processed while the request
  /// sat in the mailbox, which may have published-and-cleared before install and so left neither
  /// standing debt nor a serial the install-time snapshot could still see advance.
  dominated_at_install: bool,
  /// Resolved `Delivered` when the cookie is seen, `Dominated` when a covering
  /// `Rescan` (or a root death) stands in for it.
  reply: futures_channel::oneshot::Sender<Result<SyncOutcome, SyncError>>,
}

/// A reply-less grant-resolution notice on the [`Owner`]'s dedicated [`cleanup_rx`](Owner::cleanup_rx)
/// channel: the paired resolution of a single committed-but-unclaimed [`WatchGrant`] —
/// **exactly one** ever fires per grant (see [`WatchGrant`]).
///
/// It rides its **own** unbounded channel, separate from the [`Command`] mailbox, so the owner's
/// close-time grant-resolution drain ([`drain_pending_cleanup`](Owner::drain_pending_cleanup)) is
/// bounded by the number of grants in flight — **each grant sends exactly one `Cleanup`** — rather
/// than by the `Watch`/`Unwatch` backlog the old in-mailbox scan walked (the
/// O(public backlog) close-ack). Both variants are synchronous fire-and-forget `try_send`s from a
/// grant (a `Drop`/`defuse` cannot await); the owner keeps a **strong** keep-alive
/// [`cleanup_tx`](Owner::cleanup_tx), so the channel never closes while the owner lives and neither
/// send can be lost to a closed channel.
enum Cleanup {
  /// Lift the [`unclaimed`](Owner::unclaimed) suppression for a subscription the caller **claimed**
  /// (invariant I1). Enqueued **only** by a [`WatchGrant`]'s [`defuse`](WatchGrant::defuse) when the
  /// caller observed the reply. Processing it removes the sub from `unclaimed`, so its parked
  /// overflow/terminal `Rescan` (if any) is no longer suppressed — a claimed subscription is
  /// genuinely owed its debt (see [`flush_pending_rescans`](Owner::flush_pending_rescans)). A pure
  /// [`HashSet`](std::collections::HashSet) remove that awaits nothing. The **exactly-one-of-two**
  /// twin of [`DropOrphan`](Self::DropOrphan): `defuse` consumes the grant and sets `defused`, so the
  /// grant's `Drop` then no-ops.
  Claim(Subscription),
  /// Reconcile away a subscription whose caller's `watch` wait was dropped **after** the owner
  /// committed it (invariant I1). Enqueued **only** by a [`WatchGrant`]'s `Drop`. The owner treats it
  /// exactly like an [`Unwatch`](Command::Unwatch) — releasing it through the synchronous
  /// [`release_subscription`](Owner::release_subscription), whose emptied-root
  /// [`disarm`](crate::Source::disarm) is a fire-and-forget request — and ignores the result (it is
  /// cleanup, not a caller request). Because that release awaits nothing, it never stalls the owner;
  /// shutdown is independent regardless (it rides the dedicated [`CloseReply`] channel — invariant II,
  /// Close-responsive by construction). `release_subscription` also removes the sub from
  /// [`unclaimed`](Owner::unclaimed) (purging its suppressed parked debt). The **exactly-one-of-two**
  /// twin of [`Claim`](Self::Claim).
  DropOrphan(Subscription),
}

/// A single-use RAII grant carrying a freshly-committed [`Subscription`] back to a waiting
/// [`watch`](Tributaries::watch) call — the fix that closes the invariant-I1 orphan window
/// (design driver-golden doc, mirroring the lower fs layer's arm-grant pattern).
///
/// The owner commits the subscription (subsumer entry, filter, epoch state, possibly an armed
/// root), records it in [`unclaimed`](Owner::unclaimed) (so its parked debt is suppressed while in
/// flight — see [`flush_pending_rescans`](Owner::flush_pending_rescans)), and sends the grant
/// through the reply `oneshot`. **Exactly one** of two reply-less [`Cleanup`] notices then fires per
/// grant, resolving that suppression:
///
/// - the caller's wait observes the reply → it [`defuse`](Self::defuse)s the grant, which enqueues
///   a [`Cleanup::Claim`] (lifting the suppression — the caller now holds the sub, so its debt is
///   genuinely owed) and takes the [`Subscription`]; the grant's `Drop` then no-ops, so a normal
///   successful `watch` runs **no** extra reconcile;
/// - the caller's wait is dropped before it observes the reply — whether the receiver was already
///   gone the instant the owner sent, OR it vanished in the **post-send, pre-poll** window that a
///   bare `Subscription` reply could not cover — the grant is dropped instead, and its `Drop`
///   best-effort enqueues a reply-less [`Cleanup::DropOrphan`] the owner reconciles away, releasing
///   the root / filter / epoch / `unclaimed` entry exactly like an [`unwatch`](Tributaries::unwatch).
///
/// `defuse` consuming the grant (setting `defused`) is what makes it exactly-one-of-two: a defused
/// grant's `Drop` enqueues nothing, so `Claim` and `DropOrphan` are mutually exclusive.
///
/// So a committed-but-unclaimed subscription can never be stranded advertised-yet-unreachable.
/// The `Drop` fires at most once (Rust drops each value once) and is idempotent even against a
/// racing retire — [`release_subscription`](Owner::release_subscription) treats an already-gone
/// subscription as `Unknown` and no-ops — so it can neither double-fire nor double-free.
struct WatchGrant {
  /// The committed subscription this grant guards until the caller claims it.
  sub: Subscription,
  /// A clone of the owner's **strong** [`cleanup_tx`](Owner::cleanup_tx), kept alive for the whole
  /// life of the grant so its `Drop`/`defuse` `try_send` can be lost neither to a full channel (it is
  /// unbounded) nor to a closed one (the owner's own keep-alive strong sender holds it open). A
  /// non-generic [`Cleanup`] carries only the `Subscription`, so the grant is non-generic too.
  cleanup: async_channel::Sender<Cleanup>,
  /// Set by [`defuse`](Self::defuse) once the caller has claimed the subscription: a defused
  /// grant's `Drop` enqueues nothing.
  defused: bool,
}

impl WatchGrant {
  /// Wraps a just-committed `sub` with the [`cleanup`](Self::cleanup) sender its `Drop`/`defuse`
  /// uses to notify the owner whether the caller's wait claimed it.
  fn new(sub: Subscription, cleanup: async_channel::Sender<Cleanup>) -> Self {
    Self {
      sub,
      cleanup,
      defused: false,
    }
  }

  /// Claims the subscription for a caller that observed the reply, defusing the grant so its
  /// `Drop` enqueues no cleanup — the normal successful `watch` path.
  ///
  /// Before returning the [`Subscription`], enqueue a reply-less [`Cleanup::Claim`] on the grant's
  /// held [`cleanup`](Self::cleanup) sender so the owner lifts this sub's
  /// [`unclaimed`](Owner::unclaimed) suppression (the caller now holds it, so any parked debt is
  /// genuinely owed). A `defuse` is synchronous and cannot await, so it is a non-blocking
  /// [`try_send`](async_channel::Sender::try_send). This and the `Drop`'s
  /// [`Cleanup::DropOrphan`] are **exactly-one-of-two**: setting `defused` makes the subsequent
  /// `Drop` a no-op.
  ///
  /// # Poisoned grants
  ///
  /// A FAILED claim send — the cleanup receiver is gone, i.e. the owner has already torn down —
  /// **poisons** the grant: `Err(sub)` is returned instead of a claimed subscription. A grant can
  /// sit unpolled in the watch reply slot across a source-drain teardown: it has fired neither
  /// `Claim` nor `DropOrphan`, so the teardown's grant linearization (the cleanup channel) cannot
  /// see it, its suppressed parked debt is dropped with the owner, and the stream has already
  /// ended. Returning `Ok` there would hand the caller a subscription that looks live but never
  /// received its owed `Rescan`; the public [`watch`](Tributaries::watch) instead surfaces
  /// `Closed`, exactly like every other owner-gone path. The owner's own internal bounce path
  /// ignores the distinction (both arms carry the [`Subscription`]) — its channel is necessarily
  /// open while it runs.
  fn defuse(mut self) -> Result<Subscription, Subscription> {
    self.defused = true;
    match self.cleanup.try_send(Cleanup::Claim(self.sub)) {
      Ok(()) => Ok(self.sub),
      Err(_) => Err(self.sub),
    }
  }
}

impl Drop for WatchGrant {
  /// If the grant was never [`defuse`](Self::defuse)d — the caller's wait was dropped before it
  /// claimed the subscription — best-effort enqueue a reply-less [`Cleanup::DropOrphan`] so the owner
  /// reconciles the orphan away (invariant I1). A `Drop` cannot block or await, so this is a
  /// non-blocking [`try_send`](async_channel::Sender::try_send); the cleanup channel is unbounded and
  /// the owner holds a live keep-alive `Sender`, so the enqueue can be lost neither to a full channel
  /// nor to a closed one.
  fn drop(&mut self) {
    if !self.defused {
      let _ = self.cleanup.try_send(Cleanup::DropOrphan(self.sub));
    }
  }
}

/// The public top-level watcher: overlapping subscriptions in, attributed events out.
///
/// A cheap `Clone` **handle** over an owned-task actor (design driver-golden doc): a
/// command mailbox to the owner task, a separate event stream the owner pushes to, and a
/// concurrent-read [`WatchView`]. It is generic over the key component `C`, the caller
/// value `V`, the runtime `R`, and the source's armed-root handle `H` (inferred from the
/// source at construction; the fs binding's aliases carry its `RootHandle`). Build one
/// over any [`Source`] with [`with_source`](Self::with_source), or — with the default
/// `fs` feature — use the pure-fs `TokioTributaries` / `SmolTributaries` aliases and
/// their `new` constructor.
///
/// # Watching means "changes from now on"
///
/// Like the layer below (the `tributary-fs` watcher), registering a subscription
/// delivers no initial inventory — start the watch, then crawl.
///
/// # Loss is never silent
///
/// Every coverage gap surfaces as a [`Rescan`](crate::EventKind::Rescan) whose
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
pub struct Tributaries<C, V, R, H> {
  /// The control plane: `watch`/`unwatch` send a [`Command`] here and await its `oneshot`
  /// reply. Dropping every handle clone closes this channel, so the owner's `recv` errors and
  /// it tears down (design driver-golden doc, Close/Drop). `close` does **not** ride here — see
  /// [`closes`](Self::closes).
  commands: async_channel::Sender<Command<C, V>>,
  /// Sync's **dedicated** admission mailbox, carrying the concrete [`SyncRequest`] (no `C`/`V`).
  /// [`sync`](Self::sync) sends here so its whole admission-plus-observation rides inside one
  /// `R::timeout` — impossible over [`commands`](Self::commands), whose `async_channel::Send` is not
  /// `Send` for all `C`/`V`. Cloned and dropped in lockstep with `commands`, so the last handle
  /// dropped closes both.
  sync_commands: async_channel::Sender<SyncRequest>,
  /// The shared **coverage-loss generation**, bumped by the owner's single loss choke point
  /// ([`Owner::note_loss`]) and readable by any handle without touching the owner.
  ///
  /// [`sync`](Self::sync) snapshots it BEFORE enqueueing its request, so the barrier's loss window
  /// opens at the caller's call rather than at the owner's install — closing the window in which
  /// the owner processes a loss for the sub (whose kernel event predates the call), publishes and
  /// clears it, and only then dispatches the queued request onto a state that looks pristine.
  loss_gen: Arc<AtomicU64>,
  /// The dedicated **high-priority shutdown signal**: [`close`](Self::close) sends its
  /// [`CloseReply`] here, never the command mailbox, so a requested shutdown can never be starved
  /// behind the `Watch`/`Unwatch` backlog. It is checked at the TOP priority in every place
  /// the owner selects (the [`run`] loop and the source-drain teardown), both non-blockingly each
  /// iteration and as the first `select!` arm. Bounded at one slot — the **first** close to reach the
  /// owner wins; any racing close resolves to [`Stopped`](CloseError::Stopped) once the
  /// owner is gone (the channel closed), mirroring the command-send-failure mapping.
  closes: async_channel::Sender<CloseReply>,
  /// The data plane: [`next`](Self::next) drains attributed, epoch-stamped, coalesced
  /// events the owner pushes here — a **separate** channel from the command mailbox, so a
  /// mid-reconcile command never blocks delivery.
  events: async_channel::Receiver<Event<C, V>>,
  /// The concurrent read plane (design §5): a cheap `Clone` handle over the last
  /// committed watch-set, read wait-free by any thread.
  view: WatchView<C, V, H>,
  // `fn() -> R`, not `R`: the handle holds no runtime value, so its auto
  // traits (`Send`/`Sync`) must not condition on `R`'s.
  _rt: PhantomData<fn() -> R>,
}

impl<C, V, R, H> core::fmt::Debug for Tributaries<C, V, R, H> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Tributaries")
      .field("view", &self.view)
      .finish_non_exhaustive()
  }
}

impl<C, V, R, H> Clone for Tributaries<C, V, R, H> {
  /// Shares the same actor: every clone sends to the one command mailbox, draws from the
  /// one event stream, and reads the one published watch-set. The last clone dropped
  /// closes the command channel and tears the owner down.
  ///
  /// # Clones share ONE event stream — competing consumers, not broadcast
  ///
  /// All clones draw from a single shared MPMC stream: each event is consumed by exactly
  /// **one** of the competing [`next`](Tributaries::next) callers (stealing, not
  /// broadcast). Cloning does not duplicate delivery, so exactly one task should drain
  /// `next()`; the other clones are for `watch`/`unwatch`/`close` and the read plane. To
  /// hand independent tasks their own per-subscription streams, use the
  /// [`Demux`](crate::Demux) fan-out layer — the supported shape — rather than competing
  /// `next()` callers.
  #[inline]
  fn clone(&self) -> Self {
    Self {
      commands: self.commands.clone(),
      sync_commands: self.sync_commands.clone(),
      loss_gen: Arc::clone(&self.loss_gen),
      closes: self.closes.clone(),
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
  /// events pass through untouched. `options` carries purely umbrella knobs (channel
  /// capacities, debounce); the pre-built source owns its own transport configuration.
  ///
  /// This is the generic construction path; the pure-fs `new` (under the
  /// default `fs` feature) builds a `FsSource` and delegates here. For caller-owned
  /// spawning — structured
  /// concurrency, a `LocalSet`, or an executor outside `agnostic-lite` — use
  /// [`parts`](Self::parts) and spawn the returned driver future yourself; for a
  /// thread-local source that cannot promise `Send` futures (a [`LocalSource`]
  /// implementor), use [`parts_local`](Self::parts_local).
  pub fn with_source<S>(source: S, options: impl Into<TributariesOptions>) -> Self
  where
    S: Source<C, Handle = H> + Send + 'static,
  {
    let (this, driver) = Self::parts(source, options);
    R::spawn_detach(driver);
    this
  }

  /// Builds a watcher over any [`Source`] WITHOUT spawning: returns the handle and the
  /// owner's driver future for the CALLER to spawn — on `R` via
  /// [`with_source`](Self::with_source)'s one-liner, on a `LocalSet`, under structured
  /// concurrency, or on any executor compatible with `R`'s timers.
  ///
  /// Three caveats bind the caller:
  ///
  /// - **Liveness is yours.** The watcher makes progress only while the driver future
  ///   is being polled. A future that is held but never polled leaves every submitted
  ///   [`watch`](Self::watch)/[`unwatch`](Self::unwatch)/[`close`](Self::close)
  ///   pending forever — nothing errors, nothing times out.
  /// - **Dropping the future is hard teardown.** The owner's drop publishes an empty
  ///   read plane and closes every channel: in-flight and later calls surface
  ///   `Closed`/`Stopped`, [`next`](Self::next) drains then ends. A drop mid-poll also
  ///   CANCELS whatever the owner was awaiting — an in-flight [`Source::arm`]/
  ///   [`Source::grow`] stops at its await point — and the SOURCE is dropped with the
  ///   owner: per the Source contract's cancellation clause, the source's
  ///   own `Drop` is the reclamation boundary that tears down any external effect the
  ///   cancelled operation had already initiated. Orderly shutdown is
  ///   [`close`](Self::close) — polled to completion — not dropping the driver.
  /// - **Timer compatibility.** The driver awaits `R`'s timers
  ///   ([`RuntimeLite::sleep_until`]) for the coalescer and the parked-Rescan retry
  ///   floor, so it must be polled on an executor those timers work under — a
  ///   tokio-flavored `R` panics off a tokio reactor, while async-io-backed runtimes
  ///   run anywhere.
  ///
  /// The returned future is `Send` (pinned by the crate's compile-time owner proofs),
  /// so it is spawnable on both work-stealing and local executors. For a source that
  /// cannot promise `Send` futures at all, use [`parts_local`](Self::parts_local).
  pub fn parts<S>(
    source: S,
    options: impl Into<TributariesOptions>,
  ) -> (Self, impl Future<Output = ()> + Send + 'static)
  where
    S: Source<C, Handle = H> + Send + 'static,
  {
    let (this, owner) = Self::assemble(source, options.into());
    (this, run(owner))
  }

  /// Builds a watcher over a **thread-local** [`LocalSource`] WITHOUT spawning — the
  /// `!Send` twin of [`parts`](Self::parts), for a source whose futures cannot cross
  /// threads (`Rc`/`RefCell` state, a completion ring's handles). Identical
  /// construction, identical handle plane; only the returned driver future differs: it
  /// makes **no `Send` promise**, so the caller must poll it on the thread that owns the
  /// source.
  ///
  /// The handle plane still crosses threads freely — `C`/`V`/`H` keep their
  /// `Send + Sync` bounds because this [`Tributaries`] handle, its [`WatchView`], and the
  /// event stream are exactly as thread-mobile as under [`parts`](Self::parts); only the
  /// SOURCE (and with it the driver future that owns it) is pinned. Hand the handle to
  /// any thread; keep the future home.
  ///
  /// [`parts`](Self::parts)' three caveats bind here identically — liveness is yours,
  /// dropping the future is hard teardown, and the polling executor must support `R`'s
  /// timers — plus the locality one:
  ///
  /// - **Poll it where the source lives.** Drive the returned future on the owning
  ///   thread: directly (`block_on`, or as one arm of that thread's own select loop) or
  ///   through the executor's own local-spawn API (`tokio::task::spawn_local` inside a
  ///   `LocalSet`, a smol `LocalExecutor` the thread actually runs). Do NOT reach for
  ///   `agnostic-lite`'s `spawn_local*` here: its smol implementation panics — smol has
  ///   no ambient thread-local executor to target — and its tokio implementation panics
  ///   outside a `LocalSet`. (That is also why there is no `with_source_local`
  ///   convenience.)
  ///
  /// Every [`Source`] is a [`LocalSource`] through the crate's blanket impl, so a `Send`
  /// source constructs here too — but then [`parts`](Self::parts) is strictly more
  /// capable (its driver future can ALSO be polled locally).
  pub fn parts_local<S>(
    source: S,
    options: impl Into<TributariesOptions>,
  ) -> (Self, impl Future<Output = ()> + 'static)
  where
    S: LocalSource<C, Handle = H> + 'static,
  {
    let (this, owner) = Self::assemble(source, options.into());
    (this, run(owner))
  }

  /// The shared construction body of [`parts`](Self::parts) and
  /// [`parts_local`](Self::parts_local): channels, [`Owner`], handle. Each public
  /// constructor wraps [`run`]`(owner)` in its own opaque return type itself, so its
  /// `Send` promise (or [`parts_local`](Self::parts_local)'s deliberate lack of one) is
  /// proven directly against the owner future's hidden type.
  fn assemble<S>(source: S, options: TributariesOptions) -> (Self, Owner<C, V, R, S>)
  where
    S: LocalSource<C, Handle = H>,
  {
    let (event_capacity, command_capacity, debounce) = options.into_parts();
    let subsumer = Subsumer::new();
    let view = subsumer.view();
    // Bounded (design backpressure doc): the owner **never awaits** this channel — every
    // emit is a non-blocking `try_send` (`try_emit`), so `Close` is always serviced and the
    // loop can never deadlock mid-push. A generous capacity absorbs ordinary bursts
    // in-order; when a stalled consumer fills it, the owner sheds the affected subscription
    // to a durable dominating `Rescan` (`needs_rescan`) rather than growing memory without
    // bound — bounded memory with no silent loss.
    let (event_tx, event_rx) = async_channel::bounded(event_capacity.get());
    // Bounded too: each queued command owns its key/value/filter, so an
    // unbounded mailbox let poll-then-cancel callers retain arbitrary memory in
    // abandoned requests. Submissions AWAIT admission when the owner is mid-reconcile
    // (`watch`/`unwatch` are caller-cancellable up to admission); `close` never queues
    // here — it rides its own dedicated channel below.
    let (command_tx, command_rx) = async_channel::bounded(command_capacity.get());
    // Sync's dedicated admission mailbox, the SAME capacity as the command mailbox. Its item type is
    // concrete (`SyncRequest`, no `C`/`V`), so `async_channel::Send<SyncRequest>` is `Send` for every
    // `C`/`V` — exactly what lets `Tributaries::sync` bound admission inside `R::timeout`.
    let (sync_command_tx, sync_command_rx) = async_channel::bounded(command_capacity.get());
    // The dedicated shutdown signal, bounded at one slot: the first close wins, and any
    // racing close resolves to `Stopped` once the owner is gone. It carries ONLY close replies, so
    // the command backlog can never delay it.
    let (close_tx, close_rx) = async_channel::bounded(1);
    // The dedicated grant-resolution channel, unbounded and reply-less: each in-flight
    // [`WatchGrant`] sends exactly one [`Cleanup`] here, so the owner's close-time drain is bounded by
    // grants in flight, not by the public mailbox backlog. The owner keeps the STRONG `cleanup_tx`
    // (cloned into each grant), so the channel never closes while the owner lives — the old weak
    // `commands` self-clone (and its `upgrade() == None` orphan branch) is gone.
    let (cleanup_tx, cleanup_rx) = async_channel::unbounded();
    // The shared coverage-loss generation, minted ONCE here and held by both planes: the owner
    // bumps it at its single loss choke point (`note_loss`), and every handle clone reads it in
    // `sync` to stamp the barrier's window with the caller's call instead of the owner's install.
    let loss_gen = Arc::new(AtomicU64::new(0));
    let owner = Owner {
      source,
      subsumer,
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
      debounce,
      // Eager when the watcher-global debounce is on; a per-subscription Custom
      // override instantiates it lazily at commit otherwise (`register_debounce`).
      coalescer: debounce.map(|config| Coalescer::new(Some(config))),
      pending_syncs: Vec::new(),
      sync_seq: 0,
      sync_nonce_seed: std::collections::hash_map::RandomState::new(),
      loss_serial: HashMap::new(),
      loss_gen: Arc::clone(&loss_gen),
      cleanup_tx,
      cleanup_rx,
      commands: command_rx,
      sync_commands: sync_command_rx,
      closes: close_rx,
      events: event_tx,
      #[cfg(debug_assertions)]
      observed_handles: ObservedHandles::new(),
      _rt: PhantomData::<R>,
    };
    (
      Self {
        commands: command_tx,
        sync_commands: sync_command_tx,
        loss_gen,
        closes: close_tx,
        events: event_rx,
        view,
        _rt: PhantomData,
      },
      owner,
    )
  }
}

// The handle plane is pure channel and read-plane work: no method names an
// `R` item, so the runtime bound lives only where the driver is built and
// spawned (`with_source`, `parts`, `parts_local`, and the fs constructor).
impl<C, V, R, H> Tributaries<C, V, R, H> {
  /// A cheap `Clone` concurrent read handle over the watch-set (design §5): any thread
  /// answers `is_watched` / `resolve` from it wait-free, reflecting the last committed
  /// watch-set. See [`WatchView`].
  #[inline]
  #[must_use]
  pub fn view(&self) -> WatchView<C, V, H> {
    self.view.clone()
  }

  /// Subscribes to `key` (carrying caller `value`) under the per-watch
  /// [`WatchOptions`], returning its [`Subscription`].
  ///
  /// Overlapping keys are accepted: they are subsumed onto a shared root (design §4), so
  /// this never surfaces the overlap the layer below rejects. Widening an existing watch
  /// re-points the subsumed subscriptions onto the new wider root and delivers each a
  /// synthetic dominating [`Rescan`](crate::EventKind::Rescan) (design §8).
  ///
  /// # Per-watch options
  ///
  /// `options` batches this subscription's delivery knobs ([`WatchOptions::new`] =
  /// deliver everything, admit everything, inherit the watcher-global debounce):
  ///
  /// - **[`interest`](WatchOptions::with_interest)** (design §5) gates which
  ///   **projected** kinds are delivered — it narrows delivery only, never the
  ///   underlying source watch (every root is armed with the source's widest policy);
  /// - **[`filter`](WatchOptions::with_filter)** (design §7) is the admission gate: a
  ///   non-`Rescan` event is delivered only if the subscription's key covers it **and**
  ///   the filter admits it; a [`Rescan`](crate::EventKind::Rescan) always bypasses
  ///   both. The filter is live-swappable: keep a [`clone`](Filter::clone) and
  ///   [`swap`](Filter::swap) it to re-scope delivery without a re-watch;
  /// - **[`debounce`](WatchOptions::with_debounce)** (design §6) is this subscription's
  ///   settle posture, resolved against the watcher-global default
  ///   ([`TributariesOptions::debounce`](crate::TributariesOptions::debounce)):
  ///   [`Debounce::Off`] passes its events through raw even while siblings settle, and
  ///   [`Debounce::Custom`] settles under its own windows even when the global debounce
  ///   is off.
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
  /// This submits a watch command into the bounded mailbox
  /// ([`command_capacity`](crate::TributariesOptions::command_capacity)) and awaits the
  /// owner's reply. When the mailbox is full — the owner busy inside a caller-bounded
  /// reconcile — the submission awaits ADMISSION first, so abandoned
  /// requests can never pile up without bound: dropping the returned future before
  /// admission leaves nothing queued at all. Dropping it after admission drops only the
  /// wait — the owner still runs the reconcile to completion, and if the caller
  /// vanished after the watch committed the owner retires the orphaned subscription
  /// itself (invariant I1).
  ///
  /// # Errors
  ///
  /// - [`WatchError::Canonicalize`] when `key` cannot be canonicalized (for the fs source, the
  ///   path does not exist);
  /// - [`WatchError::CanonicalRace`] when the source's committed key diverged from the planned
  ///   one and changed subsumption — a retryable race;
  /// - [`WatchError::Source`] when arming the source watch fails;
  /// - [`WatchError::CoverageIncomplete`] when the key is covered by a root whose coverage was
  ///   narrowed and the awaited coverage grow could not be applied — nothing was committed and
  ///   the coverage record did not broaden; retryable;
  /// - [`WatchError::Closed`] when the owner is gone.
  pub async fn watch(
    &self,
    key: Vec<C>,
    value: V,
    options: WatchOptions<C>,
  ) -> Result<Subscription, WatchError> {
    let (reply, response) = futures_channel::oneshot::channel();
    if self
      .commands
      .send(Command::Watch {
        key,
        value,
        options,
        reply,
      })
      .await
      .is_err()
    {
      return Err(WatchError::Closed);
    }
    // Awaiting the reply is the only cancellable part: dropping this future drops the
    // `oneshot::Receiver`, which drops the [`WatchGrant`] sitting in its slot — whose `Drop`
    // enqueues a [`Cleanup::DropOrphan`] so the owner reconciles the committed-but-unclaimed
    // subscription away (invariant I1). On success we **defuse** the grant (its `Drop` becomes a
    // no-op) and take the [`Subscription`]; a closed reply (the owner is gone) surfaces `Closed`.
    match response.await {
      // A POISONED grant — the claim's try_send found the owner already gone (a grant
      // polled only after a source-drain teardown) — surfaces `Closed` like every other
      // owner-gone path, never an `Ok` subscription whose stream already ended without its owed
      // Rescan.
      Ok(Ok(grant)) => grant.defuse().map_err(|_| WatchError::Closed),
      Ok(Err(err)) => Err(err),
      Err(_) => Err(WatchError::Closed),
    }
  }

  /// Drops `sub`; once it was the last subscriber of its (possibly shared) root, the root's
  /// source release is **requested** — the synchronous fire-and-forget [`Source::disarm`],
  /// applied by the source no later than its next arm or its teardown. The subscription's
  /// coverage is gone the moment this resolves; the transport release follows.
  ///
  /// If instead the drop leaves a shared root broader than its survivors need — the departing
  /// subscription pinned the root at its own key, or a survivor under an already-narrowed cover
  /// departed (a non-root unwatch that lets the cover shrink further) — the root stays armed for its
  /// survivors, and the excess kernel coverage is reclaimed **in place** via the synchronous
  /// fire-and-forget [`Source::set_cover`] PRUNE (design §5): survivor coverage never moves,
  /// so there is no gap and no re-crawl. Over-broadness is correctness-neutral and self-healing, so
  /// this is a pure budget-reclaim optimization the source may apply, defer, or ignore.
  ///
  /// Sends an unwatch command to the owner and awaits its reply; dropping the
  /// returned future drops only the wait.
  ///
  /// # Stragglers: events already queued keep the retired subscription
  ///
  /// Unwatching stops *future* fan-out; it does not reach back into the event stream.
  /// Events already queued at unwatch time still arrive through
  /// [`next`](Tributaries::next) carrying the retired [`Subscription`] — a consumer
  /// tolerates and ignores such stragglers (their baked [`value`](Event::value) survives
  /// the teardown, so they remain attributable if inspected).
  ///
  /// Like [`watch`](Self::watch), the command is submitted into the bounded mailbox: a
  /// full mailbox makes this await admission, and cancellation before
  /// admission leaves nothing queued.
  ///
  /// # Errors
  ///
  /// - [`UnwatchError::UnknownSubscription`] when `sub` is not live;
  /// - [`UnwatchError::Closed`] when the owner is gone.
  pub async fn unwatch(&self, sub: Subscription) -> Result<(), UnwatchError> {
    let (reply, response) = futures_channel::oneshot::channel();
    if self
      .commands
      .send(Command::Unwatch { sub, reply })
      .await
      .is_err()
    {
      return Err(UnwatchError::Closed);
    }
    response.await.unwrap_or(Err(UnwatchError::Closed))
  }

  /// The next attributed event, or `None` once the owner is closed and the stream is
  /// drained.
  ///
  /// A plain drain of the event channel the owner pushes to — cancel-safe by definition:
  /// a dropped `next()` loses nothing (queued events stay queued). With the settle
  /// coalescer enabled (design §6) events arrive collapsed on the settle timer; absent
  /// it, untouched.
  ///
  /// # One shared stream — exactly one drainer
  ///
  /// Every [`Clone`] of this handle draws from the same MPMC stream: each event is
  /// consumed by exactly **one** of the competing `next()` callers (stealing, not
  /// broadcast). Exactly one task should drain `next()`; to give independent tasks their
  /// own per-subscription streams, hand the drained handle to the
  /// [`Demux`](crate::Demux) fan-out layer instead of racing a second caller.
  ///
  /// # Stragglers after an unwatch
  ///
  /// An [`unwatch`](Tributaries::unwatch) does not reach back into the queue: events
  /// already queued when it resolved still arrive here carrying the retired
  /// [`Subscription`]. Consumers tolerate and ignore such stragglers.
  #[inline]
  pub async fn next(&mut self) -> Option<Event<C, V>> {
    self.events.recv().await.ok()
  }

  /// How many delivered events currently sit in the shared stream's buffer — the
  /// demux shutdown barrier's SNAPSHOT bound: it drains at most this many,
  /// so the barrier is finite under a live producer. The count identifies the pre-stop
  /// backlog only under the demux's SOLE-DRAINER precondition (no competing `next()`
  /// through the whole barrier); post-stop events stay on the stream
  /// for clones that resume `next()` only after the routing future resolves.
  pub(crate) fn queued_events(&self) -> usize {
    self.events.len()
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
  /// # Bounded latency independent of the command backlog
  ///
  /// The reply rides a **dedicated** high-priority channel, NOT the command mailbox, and the owner
  /// checks it at the TOP priority everywhere it selects — so `close` resolves within a bounded window
  /// **regardless** of how deep the queued `Watch`/`Unwatch` backlog is. A sustained
  /// command flood can no longer starve shutdown.
  ///
  /// # Errors
  ///
  /// [`CloseError::Stopped`] when the owner had already stopped (a dropped last handle,
  /// the source closed itself, or another racing `close` already won and tore the owner
  /// down).
  pub async fn close(self) -> Result<(), CloseError> {
    let (reply, response) = futures_channel::oneshot::channel();
    // Send on the dedicated close signal, never the command mailbox — the whole point of the dedicated signal. A
    // send failure means the owner's close receiver is gone (it already tore down): map to
    // `Stopped`, mirroring the old command-send-failure path.
    if self.closes.send(reply).await.is_err() {
      return Err(CloseError::Stopped);
    }
    response.await.unwrap_or(Err(CloseError::Stopped))
  }
}

/// The timed barrier lives in its OWN `R`-bounded block: the handle plane is
/// deliberately runtime-free, and a timeout needs a timer. A method-scoped
/// bound changes no auto-traits and touches no other method.
impl<C, V, R, H> Tributaries<C, V, R, H>
where
  R: RuntimeLite,
{
  /// Establishes a **sync barrier** on `sub` and resolves once it is met.
  ///
  /// After this resolves `Ok`, every filesystem change under the
  /// subscription's key that happened **before this call began** is either
  /// already emitted into the event stream (an ordinary delivery, subject to
  /// the sub's interest and filter gates), or dominated by a `Rescan` that is
  /// itself on the stream — or durably parked such that no later delta of the
  /// sub can precede it. [`SyncOutcome`] says which arm met it.
  ///
  /// The barrier is kernel-mediated, not an owner-side drain: a cookie file is
  /// written under the subscription's coverage, and its own event — riding the
  /// root's ordered queue behind every change the backend reported before the
  /// write — is what proves those changes have exited the pipeline. An
  /// owner-side flush alone could never bound the kernel queue, and this API
  /// deliberately does not pretend otherwise.
  ///
  /// It does NOT promise: anything about changes CONCURRENT with the call
  /// (only happened-before); any cross-root or cross-subscription ordering;
  /// that the consumer has DRAINED (resolution means deliverable-or-dominated,
  /// so a single task may `sync().await` and then read); anything for events
  /// the sub's interest or filter gates reject; nor durability (it is an
  /// event-visibility barrier, not an `fsync`).
  ///
  /// Dropping this future (or timing out) is safe: it abandons only the reply
  /// wait. The owner reaps the abandoned cookie, whose events are suppressed
  /// by the reserved namespace regardless.
  ///
  /// # Errors
  ///
  /// [`SyncError::UnknownSubscription`] when `sub` is not live;
  /// [`Unsupported`](SyncError::Unsupported) when the source offers no
  /// barrier; [`CookieWrite`](SyncError::CookieWrite) when the cookie cannot
  /// be written (a read-only tree is `PermissionDenied` — the honest refusal);
  /// [`CookieDirUncovered`](SyncError::CookieDirUncovered) when the resolved
  /// cookie directory is outside the sub's coverage;
  /// [`Retired`](SyncError::Retired) when the CALLER unwatched the sub while
  /// the sync was pending (a root DEATH instead resolves
  /// [`Dominated`](SyncOutcome::Dominated)); [`Timeout`](SyncError::Timeout);
  /// [`Closed`](SyncError::Closed).
  pub async fn sync(
    &self,
    sub: Subscription,
    timeout: core::time::Duration,
  ) -> Result<SyncOutcome, SyncError> {
    let (reply, response) = futures_channel::oneshot::channel();
    // Sync's OWN mailbox carries the concrete `SyncRequest`, so this send future is `Send` for every
    // `C`/`V` and BOTH admission and observation ride inside one `R::timeout`: the caller's deadline
    // now bounds getting into the mailbox too, not just the wait for the cookie. Over the
    // key/value-bearing command mailbox that was impossible — its `Send` is `!Send`, so admission sat
    // OUTSIDE the timeout and an arbitrarily deep sync backlog (or an admitted sync stalled in inline
    // `begin_sync`) could blow the deadline unbounded. Clone the sender before the async block so it
    // borrows no `self` across the await.
    let tx = self.sync_commands.clone();
    // Snapshot the shared coverage-loss generation BEFORE the request is enqueued: this is what
    // makes the barrier's loss window start HERE, at the caller's call, rather than at the owner's
    // install. Any loss the owner processes for ANY subscription while this request waits in the
    // mailbox moves the generation, and `on_sync` reads the divergence as domination — so a loss
    // whose kernel event predates this call can no longer publish-and-clear itself into invisibility
    // before the barrier is installed and be reported as a false `Delivered`.
    let loss_gen_at_call = self.loss_gen.load(Ordering::SeqCst);
    let req = SyncRequest {
      sub,
      loss_gen_at_call,
      reply,
    };
    match R::timeout(timeout, async move {
      if tx.send(req).await.is_err() {
        return Err(SyncError::Closed);
      }
      match response.await {
        Ok(outcome) => outcome,
        // The owner dropped the reply: it closed (or died) mid-barrier.
        Err(_) => Err(SyncError::Closed),
      }
    })
    .await
    {
      Ok(res) => res,
      Err(_) => Err(SyncError::Timeout),
    }
  }
}

#[cfg(feature = "fs")]
#[cfg_attr(docsrs, doc(cfg(feature = "fs")))]
impl<R: RuntimeLite> Tributaries<OsString, (), R, RootHandle> {
  /// Builds a pure-filesystem watcher over one `tributary-fs` watcher, spawning its
  /// owned-task owner on `R` — the convenience mirroring the layer below's
  /// constructor.
  ///
  /// `watcher` configures the underlying filesystem watcher (its transport knobs);
  /// `options` carries the umbrella's own knobs. Enable the opt-in settle/debounce
  /// coalescer (design §6) with a [`DebounceConfig`](crate::DebounceConfig) on
  /// `options` ([`TributariesOptions::debounce`]); absent it, events pass through
  /// untouched.
  ///
  /// # Errors
  ///
  /// [`BuildError::Source`] when the underlying `tributary-fs` watcher cannot be built.
  pub fn new(watcher: WatcherOptions, options: TributariesOptions) -> Result<Self, BuildError> {
    let source = FsSource::<R>::new(watcher)?;
    Ok(Self::with_source(source, options))
  }
}

/// One subscription's admission gate as the owner holds it: the caller-facing
/// [`Filter`] and this owner's own verdict on whether that filter is still allowed to
/// run for **this** subscription.
///
/// # Why quarantine is driver state and not a swap through the filter
///
/// A [`Filter`] is a handle onto a **shared** predicate slot: cloning one — which
/// [`WatchOptions`](crate::WatchOptions) does, and which a caller does deliberately to
/// re-scope a live subscription — hands out another handle onto the *same*
/// [`ArcSwap`](arc_swap::ArcSwap). That sharing is a feature for a caller-initiated
/// [`swap`](Filter::swap): every holder should see a re-scope.
///
/// It is a blast radius for a quarantine. Retiring a panicking predicate by swapping
/// admit-everything into that slot retires it for **every** subscription registered with
/// a clone of the same filter, while only the one whose invocation unwound is recorded as
/// having lost coverage. Two tenants configured from one shared `Filter` value would then
/// have one tenant's panic silently disable the other's admission gate: no `Rescan`, no
/// loss marker, and a filtering or tenant boundary crossed with nothing on the stream to
/// say so. The isolation the containment promises ("every other subscription is
/// unaffected" — see [`Filter::new`]) is only true if the verdict is per-subscription.
///
/// So the flag lives here, in the owner's own per-subscription map, and the caller's
/// slot is never written. It is born with the subscription's entry and reclaimed with it
/// ([`retire_sub_state`](Owner::retire_sub_state)), so it can neither leak nor be missed
/// by a cleanup path — and the subscriptions sharing that `Filter` keep filtering
/// exactly as they were configured to.
struct SubscriptionFilter<C> {
  filter: Filter<C>,
  /// Set once this subscription's predicate has unwound: its gate is retired
  /// **fail-open** (every later change is admitted without entering caller code) and it
  /// has been owed a dominating [`Rescan`](crate::EventKind::Rescan). Never cleared — a
  /// predicate that panicked once is not trustworthy, and re-entering it would cost an
  /// unwind per event on top of leaving the verdict undefined.
  quarantined: bool,
}

impl<C> SubscriptionFilter<C> {
  /// A freshly registered gate: the caller's filter, not quarantined.
  fn new(filter: Filter<C>) -> Self {
    Self {
      filter,
      quarantined: false,
    }
  }
}

/// The owned-task actor: the sole writer of every authoritative state, driving the
/// source and the sans-I/O engines from one [`run`] `select!` loop. Bounded on
/// [`LocalSource`] — the base seam — so ONE owner body serves both construction paths:
/// [`Tributaries::parts`] (whose `S: Source` `Send` futures leak through the blanket
/// impl and keep `run(owner)` spawnable) and [`Tributaries::parts_local`] (a genuinely
/// thread-local source, polled where it lives).
///
/// Spawned once at [`Tributaries::with_source`] (or handed to the caller by the two
/// `parts` constructors) and never shared: it owns the source, the
/// [`Subsumer`](crate::subsume::Subsumer), the
/// [`EpochLedger`](epoch::EpochLedger), the per-subscription filter map, and the opt-in
/// [`Coalescer`](crate::coalesce::Coalescer). All arming and every state mutation run here, to
/// completion (invariant I1); releasing a root is a **synchronous** fire-and-forget
/// [`LocalSource::disarm`] request, so no cleanup path awaits source I/O and `Close`-responsiveness
/// (invariant II) holds by construction. No journal, no rollback, no pending-widen: an
/// interrupted or failed reconcile is repaired by reconciling again (invariant I3).
struct Owner<C, V, R, S>
where
  S: LocalSource<C>,
{
  source: S,
  subsumer: Subsumer<C, V, S::Handle>,
  epochs: EpochLedger,
  /// Each live subscription's admission gate, as the driver holds it: the caller's
  /// [`Filter`] plus this owner's own quarantine verdict on it
  /// ([`SubscriptionFilter`]). One entry per subscription, born and reclaimed with the
  /// subscription itself.
  filters: HashMap<Subscription, SubscriptionFilter<C>>,
  /// Set once this owner has had to **forget** a filter panic payload, which permanently
  /// retires its whole filter plane.
  ///
  /// # What this bounds, and why per-subscription was not enough
  ///
  /// Containing a filter panic means disposing of the payload it carried, and a payload
  /// whose own destructor panics can only be
  /// [forgotten](tributary_proto::unwind::PayloadDisposal::Forgotten) — dropping it would
  /// start a second unwind through the owner, which is the blast radius the containment
  /// exists to prevent. Forgetting leaks that one payload, and the payload is caller data
  /// of any size.
  ///
  /// Quarantining the SUBSCRIPTION bounds that leak to one per subscription, and a
  /// subscription is a caller-churnable object: create one with a panicking filter, feed it
  /// one change, drop it, repeat — each cycle retains another arbitrary allocation, forever,
  /// until the process is out of memory. Quarantine per subscription is a bound in the shape
  /// of the state it protects, not in the shape of the resource.
  ///
  /// So the latch is the OWNER's. Once set, no predicate is ever entered again here — every
  /// still-unquarantined subscription is quarantined on its next touch, through the same
  /// path a panicking predicate takes, so each keeps the established terms: it FAILS OPEN,
  /// stays live and covered, and is owed a dominating [`Rescan`](crate::EventKind::Rescan) so
  /// its consumer learns in-band that its admission gate is gone. The bound is then exactly
  /// **one forgotten payload per watcher, ever**, independent of how many subscriptions the
  /// caller creates, destroys, or hot-swaps predicates into.
  ///
  /// A caller that asks for a NEW filtered subscription past this point is refused with
  /// [`WatchError::FilterRetired`] rather than silently handed an unfiltered one — the leak
  /// is bounded either way (its predicate would never be entered), but a filter that is not
  /// applied and not reported is the silent behaviour change this codebase does not ship.
  filter_payload_forgotten: bool,
  /// The per-subscription overflow dirty-set (design backpressure doc): a subscription
  /// whose delivery hit a full event channel parks a durable **dominating**
  /// [`Rescan`](crate::EventKind::Rescan) here — a [`ParkedRescan`] holding its covered
  /// key, a strictly-dominating epoch, and the owning subscription's **baked value** (captured
  /// while the sub is live, so the flushed Rescan stays attributable after retirement). A
  /// [`BTreeMap`] for a deterministic drain order.
  /// [`flush_pending_rescans`](Self::flush_pending_rescans) re-offers each every loop tick
  /// until `try_send` accepts it, and [`try_emit`](Self::try_emit) suppresses further
  /// ordinary deliveries to a parked subscription (they are dominated by its `Rescan`), so
  /// a shed can never be lost to a full channel (no-silent-loss).
  needs_rescan: BTreeMap<Subscription, ParkedRescan<C, V>>,
  /// Parked debt owed to a still-UNCLAIMED subscription (its grant unresolved), kept
  /// APART from the offerable map: suppressed entries cost the flush and
  /// the retry timer nothing — an all-unclaimed retired cohort no longer burns
  /// full-map probes every tick. A `Cleanup::Claim` moves the entry into
  /// [`needs_rescan`](Self::needs_rescan); a `DropOrphan`/release removes it.
  suppressed_rescan: BTreeMap<Subscription, ParkedRescan<C, V>>,
  /// The subscriptions whose committed [`WatchGrant`] is still **in flight** — grant sent, not yet
  /// claimed or dropped (design driver-golden doc). A sub is inserted by
  /// [`on_watch`](Self::on_watch) the instant the grant send **succeeds**, and removed by exactly one
  /// of: its [`Cleanup::Claim`] (the caller [`defuse`](WatchGrant::defuse)d it — now genuinely owed),
  /// its [`Cleanup::DropOrphan`] via [`release_subscription`](Self::release_subscription) (the
  /// caller's wait was dropped — purged), or any other `release_subscription` (unwatch/orphan/
  /// teardown).
  ///
  /// This is the **correctness boundary** that replaces the old mailbox-idle flush gate:
  /// [`flush_pending_rescans`](Self::flush_pending_rescans) **suppresses** (retains without sending)
  /// any parked `Rescan` whose sub is in this set. Parked debt for a still-unclaimed grant is owed to
  /// **nobody** — the caller never obtained the subscription — so offering it would deliver a `Rescan`
  /// for a subscription the caller never received. It is owner-local state mutated **only** by the
  /// owner while processing a command, so it is consulted at flush time with no probe and no timing
  /// window (unlike a mailbox-emptiness gate, which is neither a correctness nor a starvation
  /// boundary). Ordinary (non-parked) deliveries during the in-flight window are unaffected — only the
  /// durable `needs_rescan` debt is state-gated.
  unclaimed: std::collections::HashSet<Subscription>,
  /// Where the next [`flush_pending_rescans`](Self::flush_pending_rescans) pass
  /// resumes: the subscription whose offer found the channel full last pass —
  /// retried first (inclusive), then round-robin past it — fairness over a parked map
  /// that can legitimately be as large as a caller's peak cohort, with per-pass work
  /// proportional to channel room plus unclaimed skips.
  flush_cursor: Option<Subscription>,
  /// Test instrumentation: how many candidate keys the last flush pass
  /// visited — pins the room-proportional bound without production cost.
  #[cfg(test)]
  last_flush_visited: usize,
  /// Test injection point: claims staged here are sent onto the still-open
  /// cleanup channel at EXACTLY the raced instant — after the source-drain exit
  /// predicate's emptiness observation, before the atomic cut — the sub-instruction
  /// window no external test can hit deterministically. Empty in every real run.
  #[cfg(test)]
  test_pre_cut_claims: Vec<Cleanup>,
  /// The watcher-global debounce default ([`TributariesOptions::debounce`]): what an
  /// [`Inherit`](Debounce::Inherit) subscription resolves to, kept apart from the live
  /// [`coalescer`](Owner::coalescer) so a LAZY instantiation — the first
  /// [`Custom`](Debounce::Custom) commit when this is `None`, see
  /// [`register_debounce`](Self::register_debounce) — still knows the global posture to
  /// construct with.
  debounce: Option<DebounceConfig>,
  /// The settle coalescer (design §6): eagerly created when [`debounce`](Owner::debounce)
  /// is `Some`, lazily by the first committed [`Custom`](Debounce::Custom) override, and
  /// **never** otherwise — the zero-cost claim for consumers who never opt in anywhere.
  coalescer: Option<Coalescer<C, V>>,
  /// Sync barriers awaiting their cookie's event (or a dominating `Rescan`),
  /// capped at [`MAX_PENDING_SYNCS`] live entries. A caller that drops its future
  /// (or times out) has its entry reaped at the next funnel pass by the
  /// cancelled-reply check.
  ///
  /// The cap is the reason this can stay a vector. Every owner iteration scans it
  /// for abandoned callers and every observed cookie searches it by key, so an
  /// unbounded population would make the owner's own bookkeeping grow with the
  /// barriers it is trying to finish; bounded, both scans are a small constant.
  pending_syncs: Vec<PendingSync<C, S::Handle>>,
  /// The per-owner monotonic cookie sequence — the `seq` of every `SyncToken`.
  sync_seq: u64,
  /// The owner's secret hasher seed: OS-random at construction, unknown to any
  /// other process, so a per-sync nonce derived from it (hashing `sync_seq`)
  /// is unpredictable externally — the cookie name cannot be pre-created.
  sync_nonce_seed: std::collections::hash_map::RandomState,
  /// Per-subscription monotonic **loss serial**, bumped every time the sub
  /// sheds a delta to (or overflows) a parked `Rescan`, and NEVER decremented
  /// on publish. A pending sync snapshots it at install; if it has advanced by
  /// resolution, a loss covered pre-cookie changes during the barrier and the
  /// barrier is `Dominated` even if the parked debt has since been published
  /// and cleared from `needs_rescan`. Bounded by live subs (cleaned on
  /// retirement).
  loss_serial: HashMap<Subscription, u64>,
  /// The **shared coverage-loss generation**: a global monotonic counter bumped by
  /// [`note_loss`](Self::note_loss) — the same choke point that bumps the per-subscription
  /// [`loss_serial`](Self::loss_serial) — and shared with every [`Tributaries`] handle, which reads
  /// it in [`sync`](Tributaries::sync) BEFORE enqueueing a [`SyncRequest`].
  ///
  /// It exists because the per-subscription serial can only be snapshotted at INSTALL, which leaves
  /// the caller's call-to-install window uncovered: the owner can process a loss for the sub (whose
  /// kernel event predates the call), park it, publish it and clear it — all while the request sits
  /// in the mailbox — so that at install the serial has *already* advanced and the debt maps are
  /// empty again. Both install-time probes then read a pristine state and the cookie reports a false
  /// `Delivered` for a pre-call change that was never emitted. Comparing the live generation against
  /// the CALLER'S snapshot closes that window structurally, rather than patching one loss shape at a
  /// time.
  ///
  /// It is deliberately GLOBAL, not per-subscription: a loss on an UNRELATED subscription inside the
  /// window also dominates this barrier. That yields a false `Dominated` (the caller merely
  /// re-enumerates — safe), never a false `Delivered`, and the imprecision is bounded by a window of
  /// a few owner-loop iterations. The precise per-subscription `loss_serial` still governs the long
  /// install-to-resolve window, where precision is worth having. Correctness beats precision here.
  loss_gen: Arc<AtomicU64>,
  commands: async_channel::Receiver<Command<C, V>>,
  /// The receive end of sync's **dedicated** admission mailbox (the concrete [`SyncRequest`]), so a
  /// sync no longer rides the key/value-bearing [`Command`] mailbox — which is what lets
  /// [`Tributaries::sync`] bound admission inside `R::timeout`.
  ///
  /// The [`run`] loop dispatches from it on TWO paths, and both are needed: a non-blocking
  /// take-at-most-one at the top of every iteration (the fairness path — the biased `select!` polls
  /// the command mailbox first, so a sustained command flood would otherwise starve the sync arm
  /// indefinitely), and its own `select!` arm (the wake path — what serves a sync that is the only
  /// ready work on an idle loop). Its senders drop with the public handles; a closed receiver merely
  /// disables the arm and is inert to the loop-top take (teardown stays governed by the command
  /// channel and the close signal), and any request still queued at teardown is replied `Closed`.
  sync_commands: async_channel::Receiver<SyncRequest>,
  /// The receive end of the dedicated **high-priority shutdown signal**: a
  /// [`close`](Tributaries::close) sends its [`CloseReply`] here, NOT the command mailbox. The
  /// [`run`] loop and [`drain_owed_before_shutdown`](Self::drain_owed_before_shutdown) check it at
  /// the TOP priority — both non-blockingly (a `try_recv`) each iteration and as the first
  /// `select!` arm — so a queued close never waits behind the `Watch`/`Unwatch` backlog.
  /// When it reports `Ok(reply)` the owner breaks to teardown with that reply to ack; when it
  /// reports **closed** (every [`Tributaries`] handle dropped) that is NOT itself a teardown signal
  /// — the **command** channel closing remains the dropped-handles signal — so the close arm merely
  /// disables itself and defers to the command channel. A live [`WatchGrant`] no longer holds the
  /// command channel open (it holds the dedicated [`cleanup_tx`](Self::cleanup_tx) instead), so dropping every public handle closes the mailbox promptly; any in-flight grant's
  /// [`Cleanup`] still lands on the owner-kept cleanup channel and is drained at teardown.
  closes: async_channel::Receiver<CloseReply>,
  /// The owner's **strong** keep-alive sender for the dedicated grant-resolution channel,
  /// cloned into each [`WatchGrant`] so a claimed/dropped `watch` wait can enqueue its reply-less
  /// [`Cleanup`] (a [`Claim`](Cleanup::Claim) lifting [`unclaimed`](Self::unclaimed) suppression, or a
  /// [`DropOrphan`](Cleanup::DropOrphan) reconciling the committed-but-unclaimed subscription away —
  /// invariant I1). Holding it **strong** here keeps the channel open for the whole owner lifetime, so
  /// every grant's `try_send` is unloseable independent of any [`Tributaries`] handle — unlike the old
  /// weak `commands` self-clone, this is a SEPARATE channel, so keeping it open does NOT hold the
  /// command mailbox open past the last public handle (the dropped-handles teardown still fires). It
  /// is never received from; the receive end is [`cleanup_rx`](Self::cleanup_rx).
  cleanup_tx: async_channel::Sender<Cleanup>,
  /// The receive end of the dedicated grant-resolution channel. The [`run`] loop and
  /// [`drain_owed_before_shutdown`](Self::drain_owed_before_shutdown) drain it at the **second**
  /// priority (below the close signal, above the command mailbox): a top-of-iteration full
  /// non-blocking [`drain_pending_cleanup`](Self::drain_pending_cleanup) AND a `recv()` `select!` arm.
  /// Traffic is bounded by the grants in flight (each sends exactly one [`Cleanup`]), so the full
  /// drain — including the close-time one that replaced the O(public backlog) mailbox scan (
  /// ) — is bounded and never awaits.
  cleanup_rx: async_channel::Receiver<Cleanup>,
  events: async_channel::Sender<Event<C, V>>,
  /// The **debug-only** RETIREMENT half of the generation-unique [`Source::Handle`] tripwire: the
  /// most recent [`OBSERVED_HANDLE_HISTORY`] handles this owner observed from a successful live
  /// [`arm`](Self::arm). It exists for the case no live structure can testify to — reuse of a
  /// handle already removed from the live index by unwatch or terminal retirement, which the old
  /// per-site live-index checks missed. Reuse of a handle that is STILL live is decided at the
  /// same choke point against [`subsumer`](Self::subsumer)'s own index instead, exhaustively,
  /// because observations leave this window by eviction and eviction is keyed on arm history
  /// rather than on live population. The window is what bounds the debug build's memory by itself
  /// rather than by the owner's lifetime arm count — see [`OBSERVED_HANDLE_HISTORY`].
  /// `#[cfg(debug_assertions)]` so the field, its init, and its assert add zero release-build
  /// cost.
  #[cfg(debug_assertions)]
  observed_handles: ObservedHandles<S::Handle>,
  _rt: PhantomData<R>,
}

impl<C, V, R, S> Drop for Owner<C, V, R, S>
where
  S: LocalSource<C>,
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
    // The state-safety operation comes FIRST, before any fallible or caller-defined work.
    // `publish_empty` is a single synchronous `arc_swap` store that runs no caller code, so it
    // always succeeds; the reap below calls `LocalSource::end_sync`, which is a PUBLIC extension
    // point whose contract requires synchronous fire-and-forget behavior but cannot require
    // panic-freedom. Reaping first meant one panicking `end_sync` implementation left the read plane
    // published: on an ordinary cancellation a retained `WatchView` kept advertising subscriptions
    // whose owner was gone, and during an unwind the second panic aborted the process before the
    // plane was ever cleared. Ordering it first makes the guarantee this destructor exists for
    // unconditional.
    self.subsumer.publish_empty();
    // Best-effort reap of any cookie still pending — a panic from a caller
    // callback (a `Filter`) unwinds through here, bypassing the normal-exit
    // `reap_all_pending_syncs`, and the marker files must not survive.
    //
    // Each reap is contained on its own, so ONE panicking `end_sync` cannot both abort a process
    // that is already unwinding and skip every remaining cookie behind it. Containment here is not
    // an alternative to the ordering above: it bounds the blast radius of a misbehaving source,
    // while the ordering is what makes the read plane safe regardless.
    //
    // The containment runs through [`contain`](tributary_proto::unwind::contain) — which retires
    // the caught PAYLOAD inside a boundary too — because this destructor's own frame is the worst
    // possible place to drop one. Payload disposal is the panicking source's `Drop`, so a payload
    // whose destructor panics would unwind out of here; and this destructor runs on the owner's
    // panic path as well as its normal one, where a second unwind is not a contained failure but
    // an immediate process ABORT — before the remaining cookies are reaped, and with nothing
    // reported about any of it.
    for pending in std::mem::take(&mut self.pending_syncs) {
      let source = &mut self.source;
      let _ = tributary_proto::unwind::contain(move || {
        source.end_sync(pending.root, &pending.cookie_key);
      });
    }
  }
}

/// The [`run`] loop's control-flow after handling one ready arm: keep looping, or break out to
/// teardown. Returned by [`Owner::dispatch_command`] and matched by the [`run`] loop. A close request
/// (won by the dedicated close arm) and a dropped last handle break the same way; only the source
/// drain owes a final Rescan pass first (invariant II).
enum Flow {
  /// Keep looping (a command reconciled, an event fanned out, a timer tick, or the close arm
  /// disabling itself when its channel closed).
  Continue,
  /// Break out to teardown, carrying the close acknowledgement and the source-drain flag.
  Break {
    /// The close reply to acknowledge after teardown, or [`None`] when the break was a dropped
    /// last handle or a source drain (nobody to confirm to).
    closing: Option<CloseReply>,
    /// `true` only on a **source drain** (`next` yielded `None` with a consumer still attached),
    /// which owes that consumer every parked Rescan before the stream ends.
    drain_owed: bool,
  },
}

/// [`Owner::on_sync`]'s verdict for the [`run`] loop. The cookie write ([`Source::begin_sync`]) is
/// awaited under a race against the caller's cancellation and the owner's close signal, so a backend
/// write that never returns (a hung FUSE/NFS mount) can no longer wedge the loop — a timed-out sync
/// frees the owner within the caller's own deadline, and a close during a held write tears down at
/// once instead of waiting the write out.
enum SyncAdmit {
  /// The barrier was parked (awaiting its cookie), errored to its caller, or abandoned because the
  /// caller went away — either way the owner keeps looping.
  Done,
  /// A close won the race while the write was in flight: its consumed [`CloseReply`] rides back so the
  /// [`run`] loop drives teardown exactly as its own close arm would. The barrier is abandoned and its
  /// caller (if any is left) sees `Closed`.
  CloseRequested(CloseReply),
}

/// Which arm of [`Owner::on_sync`]'s admission race resolved, carrying only OWNED data out of the
/// `select`. The cancellation arm holds `&mut reply` for the race's whole duration, so `reply` cannot
/// be moved or sent until the `select` block ends; funneling the winner through this owned enum defers
/// every use of `reply` to after that borrow is released.
enum SyncStep<C> {
  /// A [`CloseReply`] arrived on the dedicated close signal.
  Close(CloseReply),
  /// The caller dropped its `sync()` wait (timed out or cancelled), or every handle went away.
  Canceled,
  /// The cookie write finished: the cookie's canonical key to park a [`PendingSync`] on, or the error.
  Began(Result<Vec<C>, SyncError>),
}

/// [`Owner::reconcile_watch`]'s early exit. The in-place widen's retarget
/// ([`Source::replace`]) and its rollback are awaited under a race against the owner's close signal —
/// exactly as the cookie write is in [`Owner::on_sync`] — so a backend retarget that never returns (a
/// hung FUSE/NFS mount) can no longer wedge the loop: a close during a held replace tears down at once
/// instead of waiting the retarget out.
///
/// It rides the `Err` channel because every variant ABANDONS the reconcile, leaving the committing
/// paths (`Ok(sub)`) untouched: [`Failed`](Self::Failed) is the ordinary [`WatchError`] each
/// pre-existing exit already returned — a [`From`] impl keeps those sites, and `canonicalize_key`'s
/// `?`, verbatim — and [`CloseRequested`](Self::CloseRequested) diverts to teardown.
#[derive(Debug)]
enum ReconcileStop {
  /// The reconcile failed: the error for the `watch()` caller.
  Failed(WatchError),
  /// A close won the race while an in-place widen `replace` was in flight: its consumed
  /// [`CloseReply`] rides back so [`Owner::dispatch_command`] hands the [`run`] loop the same
  /// [`Flow::Break`] its own close arm produces. The widen is abandoned and the `watch()` caller's
  /// dropped reply surfaces `Closed`.
  CloseRequested(CloseReply),
}

impl From<WatchError> for ReconcileStop {
  fn from(err: WatchError) -> Self {
    Self::Failed(err)
  }
}

/// Which arm of [`Owner::replace_racing_close`]'s race resolved, carrying only OWNED data out of the
/// `select` so both borrows it takes (`&self.closes`, `&mut self.source`) are released before the
/// winner is used — the same discipline [`SyncStep`] keeps.
enum ReplaceStep<C, H> {
  /// A [`CloseReply`] arrived on the dedicated close signal: thread it back to teardown.
  Close(CloseReply),
  /// The close channel closed — every handle is gone. Like [`SyncStep::Canceled`], that is an
  /// ABANDON rather than a threaded close: no one is left to acknowledge, and the command channel —
  /// whose sender drops in lockstep with the close sender — stays the dropped-handles teardown
  /// signal, exactly as [`on_sync`](Owner::on_sync) leaves it.
  HandlesGone,
  /// The retarget finished: the armed root it committed, or the error that falls through to
  /// release-and-rearm.
  Replaced(Result<Armed<C, H>, WatchError>),
}

/// The owner's single `select!` loop (design driver-golden doc): reconcile a command,
/// fan out a raw source event, or drain the coalescer's due entries — whichever is ready, each to
/// completion. The only source calls it awaits are [`next`](LocalSource::next) (one cancel-safe
/// `select!` arm) and, inside a caller-bounded `Watch` reconcile, [`arm`](LocalSource::arm),
/// [`grow`](LocalSource::grow) and [`replace`](LocalSource::replace); releasing a root is the
/// **synchronous** [`disarm`](LocalSource::disarm) request, so **no** loop path awaits it.
///
/// Shutdown rides a **dedicated** [`closes`](Owner::closes) channel checked at the TOP priority — the
/// first `select!` arm AND a non-blocking `try_recv` at the very top of each iteration (before the
/// flush/valve) — so a requested close is serviced within a bounded window no matter how deep the
/// unbounded command backlog is.
///
/// A queued close being at the top of the `select!` is necessary but NOT sufficient, and that gap is
/// the reason every awaited source call above is itself a biased race against the same close
/// receiver. The loop selects a command and then awaits the entire reconcile INSIDE that branch, so
/// while a `Source::arm` or `grow` against a hung mount is pending the loop never returns to its
/// `select!` at all — the dedicated lane exists but nothing polls it, and `close()` stays pending for
/// as long as the mount does. Racing each awaited call means a close arriving mid-reconcile abandons
/// the reconcile (its `watch()` caller's dropped reply reads as `Closed`) and drives teardown, which
/// drops the source. Close-responsiveness therefore holds against a source that violates its own
/// bounded-progress requirement — but only for the AWAITED surface: a source's synchronous
/// callbacks ([`canonicalize_key`](LocalSource::canonicalize_key)) and a subscription's
/// [`Filter`](crate::Filter) predicate run on this thread with nothing to race against, and the
/// [`LocalSource`] contract says so plainly rather than promising what an actor cannot do. Grant resolution rides the dedicated
/// [`cleanup_rx`](Owner::cleanup_rx) channel at the **second** priority (below close, above the
/// mailbox): a top-of-iteration full [`drain_pending_cleanup`](Owner::drain_pending_cleanup)
/// AND a `select!` arm between close and commands. The command mailbox is otherwise biased above the
/// data plane so `watch`/`unwatch` are not starved by a busy event stream — and the two control
/// mailboxes get FAIR service, because the biased `select!` alone would let a continuously-ready
/// command mailbox starve the sync arm forever: at most one queued sync is taken non-blockingly at
/// the top of each iteration and dispatched inline, against the at-most-one command the `select!`
/// below dispatches, so the two are served 1:1 under any flood. On a close request, a
/// dropped last handle (the command channel closed), or the source draining (`next` yields `None`), it
/// breaks, flushes the coalesced tail (no-silent-loss), and tears down — dropping the [`Owner`] (and
/// its source, whose own `Drop` performs the orderly source teardown). Nothing is owed to `Drop`.
async fn run<C, V, R, S>(mut owner: Owner<C, V, R, S>)
where
  C: Ord + Clone,
  V: Clone,
  R: RuntimeLite,
  S: LocalSource<C>,
{
  // Command-fairness valve state: consecutive command-arm wins since the data plane
  // was last serviced. See [`COMMAND_FAIRNESS_BUDGET`].
  let mut command_streak: u32 = 0;
  // Whether the dedicated close channel is still open. It closes when every [`Tributaries`] handle is
  // dropped — but that is NOT itself a teardown signal (the command channel closing remains the
  // dropped-handles teardown signal). So on a closed close channel the arm just disables itself
  // (stops winning the biased select) and defers to the command channel.
  let mut close_open = true;
  // Whether sync's dedicated admission mailbox is still open. Its senders drop in lockstep with the
  // public command senders, so it closes when every handle is dropped — but, like the close signal,
  // that is NOT itself a teardown signal (the command channel closing remains the dropped-handles
  // one). A closed sync mailbox merely disables its arm.
  let mut sync_open = true;
  // The loop yields `(reply, drain_owed)`: `reply` is the close acknowledgement (if any);
  // `drain_owed` is true only on a **source drain** (the source's `next` yielded `None` while
  // a consumer is still attached), which owes that consumer every parked Rescan before the
  // stream ends. A consumer-initiated close or a dropped last handle owes nothing (the
  // consumer asked to stop / nobody is left), and must never block teardown on a full channel.
  let (closing, drain_owed) = loop {
    // Reap barriers whose caller went away (timed out, or dropped the future):
    // their cookies are inert — namespace-suppressed forever — so this map
    // stays bounded by LIVE waiters, never by every sync ever issued.
    owner.prune_abandoned_syncs();

    // The dedicated shutdown signal is checked FIRST every iteration, non-blockingly, BEFORE the
    // flush and the fairness valve: a requested close breaks to teardown without waiting
    // even one command dispatch or one forced data-plane service, so it can never be starved behind
    // the unbounded command backlog. A closed channel (every handle dropped) disables the check and
    // lets the command channel drive teardown; an empty one falls through to the select below.
    if close_open {
      match owner.closes.try_recv() {
        Ok(reply) => break (Some(reply), false),
        Err(async_channel::TryRecvError::Closed) => close_open = false,
        Err(async_channel::TryRecvError::Empty) => {}
      }
    }

    // MAILBOX FAIRNESS between the two control planes. The `select!` below is biased, and
    // `commands.recv()` is polled ahead of the sync arm — so a CONTINUOUSLY-ready command mailbox
    // means the sync arm never wins and an admitted `SyncRequest` sits until its caller's deadline
    // expires, even though the owner is perfectly healthy. (The command-fairness valve does not help:
    // it forces one SOURCE service, then returns to the same ordering.) So take at most ONE queued
    // sync per iteration here, non-blockingly, and dispatch it inline. The biased `select!` below
    // dispatches at most one command per iteration, so this yields 1:1 service between the two
    // control mailboxes under any command flood — no starvation — while leaving close/cleanup
    // priority and the source-service valve exactly as they were.
    //
    // The `select!`'s sync arm STAYS: it is what wakes an otherwise-idle loop when a sync is the only
    // ready work (this `try_recv` cannot block). A closed mailbox is inert here — `Err(Closed)` and
    // `Err(Empty)` alike fall through, driving neither teardown (the COMMAND channel closing remains
    // the dropped-handles signal) nor a spin.
    if let Ok(req) = owner.sync_commands.try_recv() {
      // Counted against the data-plane fairness valve like the `select!`'s own sync arm. A barrier is
      // completed BY a source event, so admitting one is control-plane work that CREATES data-plane
      // work — leaving this drain uncounted let two cookies be initiated per iteration while only one
      // counted toward the budget that forces a source poll, so initiation outran the observation it
      // depends on and every admitted barrier waited longer for it.
      command_streak += 1;
      // A close can win the race inside `on_sync`'s in-flight cookie write: thread its reply back and
      // break to teardown exactly as the top-of-iteration close check above does.
      if let SyncAdmit::CloseRequested(reply) = owner
        .on_sync(req.sub, req.loss_gen_at_call, req.reply)
        .await
      {
        break (Some(reply), false);
      }
    }

    // Grant resolution is drained SECOND — below the close check, above the flush and the command
    // mailbox. A full non-blocking drain of the dedicated cleanup channel: a
    // [`Cleanup::Claim`] lifts its sub's `unclaimed` suppression BEFORE the flush below offers parked
    // Rescans (so a just-claimed sub's debt is delivered this tick), and a [`Cleanup::DropOrphan`]
    // releases the committed-but-unclaimed orphan. Traffic is bounded by the grants in flight (each
    // sends exactly one `Cleanup`), so this full drain is bounded and awaits nothing.
    owner.drain_pending_cleanup();

    // Re-offer the parked per-subscription overflow Rescans ahead of new deltas — **unconditionally**
    // every tick. Which parked debt is *offered* is decided by owner STATE, not mailbox
    // timing: [`flush_pending_rescans`](Owner::flush_pending_rescans) suppresses any entry whose sub
    // is still `unclaimed` (its `WatchGrant` in flight), so an orphaned committed-but-unclaimed
    // subscription's parked terminal `Rescan` is never delivered — no probe, no window — while a
    // LIVE claimed subscription's parked Rescan is flushed every tick regardless of how busy the
    // (command-biased, unbounded) mailbox is. The old idle-mailbox gate did neither correctly: it was
    // a TOCTOU race (a `DropOrphan` could enqueue after the emptiness probe but before the flush's
    // `try_send`) AND it let a sustained watch/unwatch stream starve live subscriptions'
    // parked Rescans by keeping `is_empty()` false forever. Per-subscription ordering
    // and durability are unaffected (a parked sub's ordinary deltas are suppressed and its `Rescan`s
    // merged by `try_emit`; `needs_rescan` entries persist until delivered or purged).
    owner.flush_pending_rescans();

    // The command-fairness valve: the select below is command-biased, so a
    // CONTINUOUS command flood would otherwise starve the data plane entirely — the source arm
    // never pumped (claimed subscriptions miss ordinary events for the flood's whole duration) and
    // the timer arm never fired (due coalescer output held past its bounds). After
    // [`COMMAND_FAIRNESS_BUDGET`] consecutive command wins, service the data plane ONCE,
    // non-blockingly: poll one source event — `now_or_never` drops a still-pending `next()`, which
    // is safe solely by its cancellation-safety contract — and drain any due coalescer output.
    // Close-responsiveness is untouched: nothing here awaits, and a queued close was already handled
    // by the non-blocking close check at the top of this iteration (it rides its own channel, not the
    // command mailbox this valve services).
    if command_streak >= COMMAND_FAIRNESS_BUDGET {
      command_streak = 0;
      match owner.source.next().now_or_never() {
        Some(Some(event)) => owner.consume_source_event(&event),
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

    // The dedicated close arm's future, borrowing ONLY the close receiver (a field reborrow, so it
    // does not conflict with the disjoint `commands`/`source` borrows the other arms take). When the
    // channel is closed it resolves `None` (→ disable the arm); when disabled it parks forever, so it
    // never spins the biased select. It stays the FIRST arm below so a close always wins over a ready
    // command.
    let closes = &owner.closes;
    let close_arm = async move {
      if close_open {
        // `Ok(reply)` → a close request; `Err` (channel closed) → `None` = disable the arm.
        closes.recv().await.ok()
      } else {
        futures_util::future::pending::<Option<CloseReply>>().await
      }
    };

    // The dedicated cleanup arm, borrowing ONLY the cleanup receiver (disjoint from the close/commands/
    // source borrows the other arms take). It wakes the parked loop when a grant resolves; the
    // top-of-iteration full drain already services everything queued, so this mainly exists so a
    // `Cleanup` arriving while the loop is otherwise idle is applied promptly. It is the SECOND arm
    // (below close, above commands) and never errors while the owner lives (the owner holds
    // the strong `cleanup_tx`).
    let cleanup_rx = &owner.cleanup_rx;
    let cleanup_arm = async move { cleanup_rx.recv().await };

    // Sync's dedicated admission arm, borrowing ONLY the sync receiver (disjoint from the close/
    // cleanup/commands/source borrows the other arms take). It sits just below the command arm —
    // control-plane, above the data plane — and on a closed mailbox (every handle dropped) resolves
    // `None` to disable itself, deferring teardown to the command channel (mirroring the close arm),
    // never spinning the biased select.
    let sync_commands = &owner.sync_commands;
    let sync_arm = async move {
      if sync_open {
        // `Ok(req)` → a sync request; `Err` (mailbox closed) → `None` = disable the arm.
        sync_commands.recv().await.ok()
      } else {
        futures_util::future::pending::<Option<SyncRequest>>().await
      }
    };

    // The one owner `select!`: acknowledge a close, apply a grant resolution, dispatch a command, pump
    // one source event, or fire the settle/retry timer — whichever is ready. The close arm is FIRST (a
    // requested shutdown wins over everything); the cleanup arm is next (grant resolution outranks the
    // public mailbox); the command arm follows (control-plane requests are not starved by a busy event
    // stream). `source.next()` is the ONLY [`Source`] call polled in a cancellable arm: a
    // close/cleanup/command/timer branch winning **drops** the in-flight `next()` future, which is safe
    // solely because [`Source::next`] is a hard-contract **cancellation-safe** read (see its docs) —
    // dropping it loses/acks no event. Releasing a root is the synchronous [`Source::disarm`] request,
    // never awaited, so it is never raced here.
    let flow = futures_util::select_biased! {
      maybe_reply = close_arm.fuse() => match maybe_reply {
        // A close request: break to teardown carrying its reply — consumer-initiated, so it owes no
        // source-drain pass (`drain_owed: false`).
        Some(reply) => Flow::Break { closing: Some(reply), drain_owed: false },
        // The close channel closed (every handle dropped): NOT a teardown signal on its own. Disable
        // the arm and let the command channel observe its own close.
        None => {
          close_open = false;
          Flow::Continue
        }
      },
      cleanup = cleanup_arm.fuse() => {
        // Never `Err` while the owner lives (it holds the strong `cleanup_tx`); apply the one resolution
        // and loop (the next iteration's top drain handles any more).
        if let Ok(cleanup) = cleanup {
          owner.apply_cleanup(cleanup);
        }
        Flow::Continue
      }
      cmd = owner.commands.recv().fuse() => {
        command_streak += 1;
        owner.dispatch_command(cmd).await
      }
      maybe_req = sync_arm.fuse() => match maybe_req {
        // A sync request on the dedicated mailbox: dispatch inline exactly as the old command-borne
        // `Sync` did, counting it a control-plane win against the fairness valve. This arm is what
        // wakes an IDLE loop on a sync; a sync arriving under a command flood is served by the
        // loop-top drain above, which the biased select can never starve.
        Some(req) => {
          command_streak += 1;
          match owner.on_sync(req.sub, req.loss_gen_at_call, req.reply).await {
            SyncAdmit::Done => Flow::Continue,
            // A close won the race inside the in-flight cookie write: break to teardown carrying its
            // reply, exactly as the dedicated close arm above does.
            SyncAdmit::CloseRequested(reply) => Flow::Break {
              closing: Some(reply),
              drain_owed: false,
            },
          }
        }
        // The sync mailbox closed (every handle dropped): disable the arm and let the command channel
        // observe its own close — the sync channel closing is not a teardown signal on its own.
        None => {
          sync_open = false;
          Flow::Continue
        }
      },
      raw = owner.source.next().fuse() => { command_streak = 0; match raw {
        // A terminal event on a **dead root** (the source has forgotten its handle) retires that
        // root through the unified park-terminal-Rescan-then-retire primitive — which durably owes
        // every subscriber a dominating `Rescan` *before* freeing the subsumer state, so a full
        // channel cannot drop it — and `retire_if_dead` returns `true`, so the ordinary fan-out is
        // skipped here. A dead-root NON-`Rescan` terminal event (e.g. a root `Removed`) is NOT
        // separately fanned out: the parked terminal `Rescan` dominates and re-enumerates it, and
        // fanning it through the coalescer under debounce would buffer-then-drop it.
        // Every event on a still-live root (an ordinary delivery, or an overflow `Rescan` on a live
        // root) returns `false` and fans out normally here.
        Some(event) => {
          owner.consume_source_event(&event);
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

  // Reap every cookie still riding a pending sync: their callers will see the
  // dropped reply as `Closed`, but the marker FILES must not survive the owner
  // (their names are unique, so unreaped they accrue in the watched trees).
  owner.reap_all_pending_syncs();

  // Fail every sync request still queued on the dedicated admission mailbox. Sync has its own channel
  // now, so — mirroring the old teardown reply of `Closed` to a queued `Command::Sync` — each
  // undispatched `SyncRequest` is answered `Closed` here, so its caller resolves promptly instead of
  // waiting out its own deadline. An undispatched request placed no cookie, so none leaks.
  while let Ok(req) = owner.sync_commands.try_recv() {
    let _ = req.reply.send(Err(SyncError::Closed));
  }

  // Whichever close we owe an acknowledgement: the loop-break close (consumer-initiated, from the
  // dedicated close arm), or a close that interrupted the source-drain retry (returned by
  // `drain_owed_before_shutdown` so the blocking retry could stop and stay responsive). The two
  // are mutually exclusive — a source-drain break carries no `closing`.
  let ack = if drain_owed {
    // Source drain: deliver the coalesced tail AND every owed parked Rescan before the stream
    // ends — ordered so a parked subscription's tail delta never precedes its dominating Rescan
    // — retrying as the consumer drains, while checking the dedicated close signal so a close during
    // the drain is always answered (no silent loss, without an unserviceable close).
    let interrupted = owner.drain_owed_before_shutdown().await;
    // If a close INTERRUPTED that drain (it returned the reply), the drain stopped at its
    // top-priority close check WITHOUT running a final owed pass — yet a resuming consumer may have
    // freed a channel slot in the window between the drain's last pass and the close arriving. Run
    // ONE more non-blocking best-effort `drain_owed_once` so a now-sendable CLAIMED parked Rescan
    // gets its last offer before teardown, mirroring the non-drain close path below.
    // A `None` return needs none: it already delivered everything owed to a claimed sub in its final
    // pass, or the consumer is gone. Still non-blocking, so `close` stays responsive (invariant II).
    // The ATOMIC claim cut, UNCONDITIONAL on every drain exit (the
    // dropped-handles `commands.recv()` Err exit returns without the drain's internal cut, and a
    // grant holds `cleanup_tx` independently of the public senders, so it can still defuse in the
    // pre-drop gap): close the cleanup channel FIRST — a grant defused after this instant fails
    // its claim try_send and is POISONED (`watch` surfaces `Closed`) — then drain what landed
    // BEFORE the cut and run the final owed pass, so a pre-cut claim still gets its parked Rescan
    // delivered while no post-cut claim can ever return a live-looking subscription
    // no drain will service. Bounded by grants in flight, never by the public backlog (
    // ); awaits nothing (invariant II). `close` is idempotent with the drain's internal cut.
    owner.cleanup_rx.close();
    owner.drain_pending_cleanup();
    owner.drain_owed_once();
    interrupted
  } else {
    // Consumer-initiated close, or every handle dropped: drain any grant-resolution already queued at
    // close time from the dedicated cleanup channel — the same bounded pre-drain as the drain-interrupt
    // path above, for uniformity — so a `Cleanup::Claim` lifts its sub's `unclaimed` suppression BEFORE
    // the final pass. Then one best-effort non-blocking `drain_owed_once` that
    // delivers the owed tail — including that just-claimed sub's now-owed debt — when the channel has
    // room. A sub STILL unclaimed after the drain stays SUPPRESSED by owner state inside
    // `drain_owed_once` (its `flush_pending_rescans`): its debt is owed to nobody and correctly
    // withheld, and the owner is exiting. Both steps await nothing, so close stays responsive.
    // The ATOMIC claim cut first: close the cleanup channel so a grant defused after
    // this instant is POISONED (`watch` surfaces `Closed`), then drain the pre-cut claims below.
    owner.cleanup_rx.close();
    owner.drain_pending_cleanup();
    owner.drain_owed_once();
    closing
  };
  // Every teardown exit funnels here — a close request, a dropped last handle, or the source
  // draining — AFTER the owed Rescans above are made durable/delivered (nothing owed is lost).
  // Publish an EMPTY read plane so a retained `WatchView` clone stops advertising subscriptions
  // whose owner task and source are about to be gone: otherwise it keeps answering
  // `is_watched`/`covering` from the last snapshot, and a dedup caller (the indexer) skips
  // re-installing that coverage and silently misses changes after rebuilding a fresh watcher
  // (design §5). It is a synchronous `arc_swap` store — the owner still never awaits the event
  // sender, so no-deadlock (III) holds.
  owner.subsumer.publish_empty();
  // The source lifecycle split. `begin_close` is the synchronous, non-blocking initiation — it
  // starts the source winding down at the instant the owner decides to stop, and can block nothing
  // — and `join_close` is the bounded wait that produces an HONEST quiescence result.
  //
  // Awaiting it before the acknowledgement is the whole point. Publishing empty and replying `Ok`
  // while the source is merely DROPPED afterwards means the caller's `close()` resolves over a
  // teardown nobody waited for: the caller may resume on another thread and terminate the runtime
  // before the source's own driver has finished, abandoning native threads, OS handles and any
  // marker files it wrote — and the source's `NotQuiesced` evidence, the strongest lifecycle fact
  // the lower layer produces, is discarded unread. So the reply now carries the source's verdict.
  //
  // The default seam is immediately `Ok(())`, so a source with no native resources pays nothing.
  owner.source.begin_close();
  let quiesced = owner.source.join_close().await;
  // Dropping `owner` (and its source) performs the orderly source teardown.
  if let Some(reply) = ack {
    let _ = reply.send(quiesced.map_err(CloseError::Source));
  }
}

/// How long the owner waits before re-attempting delivery of a parked per-subscription
/// overflow [`Rescan`](crate::EventKind::Rescan) when the event channel is full
/// (design backpressure doc). Mirrors the fs layer's `DELIVERY_RETRY`. Latency-only: a
/// resuming consumer's next drained slot is also retried on the following command/event
/// tick; this bounds the wait when the stream is otherwise idle.
const RETRY: Duration = Duration::from_millis(25);

/// How many consecutive command-arm wins the [`run`] loop tolerates before forcing one
/// non-blocking data-plane service — a `now_or_never` source poll plus a due-coalescer drain —
/// the command-fairness valve. The `select!` is command-biased so `Close` is never
/// starved; without a budget, a CONTINUOUS watch/unwatch flood keeps the command arm ready
/// forever and the source/timer arms never win: claimed subscriptions would miss ordinary source
/// events and the coalescer its hold bounds for the flood's whole duration. Small enough to bound
/// data-plane staleness tightly under load, large enough to amortize the extra poll.
const COMMAND_FAIRNESS_BUDGET: u32 = 32;

/// The most sync barriers one owner may hold in flight at once.
///
/// The sync mailbox is bounded, and that bound was mistaken for a bound on live
/// barriers. It is not: the owner drains the mailbox, releasing each slot, and
/// then RETAINS the request — a [`PendingSync`] plus a real cookie FILE on the
/// watched filesystem — until its cookie is observed, dominated, cancelled or
/// retired. The caller chooses its own timeout, so a stream of callers with long
/// deadlines can be admitted far faster than their cookies come back, and the
/// growth is in both owner memory and filesystem entries. The topology makes it
/// worse rather than self-correcting: barriers are completed BY source events,
/// and a sync-heavy control plane is precisely what delays the source service
/// those events need.
///
/// So admission is bounded over the retained obligation. Past this many live
/// barriers a request is refused with the typed, retryable
/// [`SyncError::Busy`] BEFORE any cookie is written — a refusal that leaves
/// nothing on disk — rather than admitted into an unbounded park.
///
/// Chosen well above any plausible legitimate concurrency (a barrier is a
/// coarse-grained, whole-subscription operation) and independent of the
/// configured mailbox capacity, because the two bound different things: the
/// mailbox bounds requests waiting to be RECEIVED, this bounds requests already
/// admitted and not yet finished.
const MAX_PENDING_SYNCS: usize = 256;

/// How many recently-armed [`Source::Handle`]s the debug-only generation-uniqueness
/// tripwire remembers ([`ObservedHandles`]) **beyond** what the subsumer's live index
/// already answers.
///
/// An all-time history changes the debug build's resource model from "peak live roots
/// plus bounded debt" to "every arm since the owner was constructed": a long-running
/// debug or staging watcher that churns disjoint roots grows without bound even when
/// every live root and delivery obligation is reclaimed correctly — a soak meant to
/// expose leaks then contains a growth source of its own.
///
/// So the history is a bounded most-recent window, and it is deliberately NOT what
/// answers the live-alias question: eviction here is keyed on arm history, not on live
/// population, so a root held live across more than this many intervening arms would
/// fall out of the window while it is still recorded. That case — the alias that can
/// overwrite the reverse handle mapping and strand a live root — is answered
/// exhaustively by the subsumer's own live index, at the arm choke point, whatever this
/// window holds. What is left for the window is reuse **after** retirement, which no
/// live structure can testify to; that is caught within this many intervening arms, the
/// shape a handle-recycling source actually has. Beyond it the retirement check is
/// silent; it is a debug tripwire for a contract violation, never a correctness
/// mechanism.
#[cfg(debug_assertions)]
const OBSERVED_HANDLE_HISTORY: usize = 4096;

/// The debug-only history behind the generation-unique [`Source::Handle`] tripwire: the
/// most recent [`OBSERVED_HANDLE_HISTORY`] handles a successful live arm returned, in
/// arrival order, with membership in O(1).
///
/// Bounded by construction — the oldest observation is evicted to make room — so the
/// debug build's memory stays proportional to the window rather than to the number of
/// arms the owner has ever performed. That eviction is exactly why the window does not
/// decide the live-alias case; see [`OBSERVED_HANDLE_HISTORY`].
#[cfg(debug_assertions)]
struct ObservedHandles<H> {
  seen: std::collections::HashSet<H>,
  order: std::collections::VecDeque<H>,
}

#[cfg(debug_assertions)]
impl<H> ObservedHandles<H>
where
  H: Copy + Eq + core::hash::Hash,
{
  fn new() -> Self {
    Self {
      seen: std::collections::HashSet::new(),
      order: std::collections::VecDeque::new(),
    }
  }

  /// Records `handle` as observed, reporting `false` if it is **still in the window** —
  /// half the tripwire's verdict, the half no live structure could give. Evicting the
  /// oldest observation keeps the window bounded; eviction is the only way an
  /// observation ever leaves.
  fn observe(&mut self, handle: H) -> bool {
    if !self.seen.insert(handle) {
      return false;
    }
    self.order.push_back(handle);
    if self.order.len() > OBSERVED_HANDLE_HISTORY
      && let Some(evicted) = self.order.pop_front()
    {
      self.seen.remove(&evicted);
    }
    true
  }

  /// How many observations the window currently holds — never more than
  /// [`OBSERVED_HANDLE_HISTORY`].
  #[cfg(test)]
  fn len(&self) -> usize {
    self.seen.len()
  }
}

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
  S: LocalSource<C>,
{
  /// Dispatches one command from the mailbox, returning whether the [`run`] loop should keep
  /// looping or break to teardown ([`Flow`]). Called from the [`run`] loop's single `select`, one
  /// priority below the dedicated close and cleanup arms — so shutdown and grant resolution both
  /// outrank a queued command (invariant II). The mailbox now carries ONLY the two
  /// caller-reply commands ([`Watch`](Command::Watch)/[`Unwatch`](Command::Unwatch)); grant
  /// resolution moved to the dedicated [`cleanup_rx`](Self::cleanup_rx) channel.
  ///
  /// It breaks to teardown on two signals, neither of them a close command (a close is never a
  /// command — it rides the dedicated [`closes`](Self::closes) channel): the dropped-last-handle
  /// `Err`, and a close that [`on_watch`](Self::on_watch) THREADED back after winning the race
  /// inside an in-flight in-place widen [`replace`](Source::replace) — that reply was consumed off
  /// the close channel mid-reconcile, so this break is the one path that delivers it to teardown.
  async fn dispatch_command(
    &mut self,
    cmd: Result<Command<C, V>, async_channel::RecvError>,
  ) -> Flow {
    match cmd {
      Ok(Command::Watch {
        key,
        value,
        options,
        reply,
      }) => match self.on_watch(key, value, options, reply).await {
        None => Flow::Continue,
        // A close won the race inside an in-flight in-place widen `replace`: break to teardown
        // carrying its reply, exactly as the dedicated close arm — and `on_sync`'s threaded close —
        // does. Consumer-initiated, so it owes no source-drain pass.
        Some(close_reply) => Flow::Break {
          closing: Some(close_reply),
          drain_owed: false,
        },
      },
      Ok(Command::Unwatch { sub, reply }) => {
        self.on_unwatch(sub, reply);
        Flow::Continue
      }
      // Every handle dropped: same orderly teardown, nobody to confirm it to. Nobody is left to
      // receive, so nothing is owed.
      Err(_) => Flow::Break {
        closing: None,
        drain_owed: false,
      },
    }
  }

  /// Applies one grant-resolution [`Cleanup`] from the dedicated [`cleanup_rx`](Self::cleanup_rx)
  /// channel. Both cases await nothing, so neither can ever park teardown (invariant II —
  /// shutdown rides its own channel regardless):
  ///
  /// - a [`Claim`](Cleanup::Claim) removes the sub from [`unclaimed`](Self::unclaimed), lifting the
  ///   suppression so its parked debt (if any) is offered by the next
  ///   [`flush_pending_rescans`](Self::flush_pending_rescans) — a claimed subscription is genuinely
  ///   owed its Rescan;
  /// - a [`DropOrphan`](Cleanup::DropOrphan) is a `watch` orphaned by a dropped caller wait: it routes
  ///   through the unified [`release_subscription`](Self::release_subscription), which purges the
  ///   orphan's owner-local state (including its `unclaimed` flag and any parked terminal `Rescan`) and,
  ///   if that emptied a root, issues the root's **synchronous** [`disarm`](Source::disarm) request.
  ///   Its result is ignored — it is cleanup, not a caller request (invariant I1).
  fn apply_cleanup(&mut self, cleanup: Cleanup) {
    match cleanup {
      Cleanup::Claim(sub) => {
        self.unclaimed.remove(&sub);
        // The claim lifts the suppression: any debt parked while the grant was
        // unclaimed becomes OFFERABLE now (it was kept apart so it cost
        // the flush nothing until this moment).
        if let Some(parked) = self.suppressed_rescan.remove(&sub) {
          merge_max(
            &mut self.needs_rescan,
            sub,
            parked.key,
            parked.epoch,
            parked.value,
          );
        }
      }
      Cleanup::DropOrphan(sub) => {
        let _ = self.release_subscription(sub);
      }
    }
  }

  /// Drains the dedicated [`cleanup_rx`](Self::cleanup_rx) channel to empty, applying each queued
  /// [`Cleanup`] via [`apply_cleanup`](Self::apply_cleanup). Non-blocking and **bounded by
  /// the grants in flight** (each [`WatchGrant`] sends exactly one `Cleanup`), so this full drain —
  /// run at the top of every [`run`]/[`drain_owed_before_shutdown`](Self::drain_owed_before_shutdown)
  /// iteration AND at the close-time run tail — is bounded and awaits nothing. It replaces the old
  /// O(public backlog) close-time mailbox scan: a `Cleanup::Claim` queued at close time lifts its sub's
  /// suppression before the final owed pass, without walking the unbounded `Watch`/`Unwatch` backlog
  ///. The strong owner-held `cleanup_tx` keeps the
  /// channel open, so `try_recv` never reports `Closed` while the owner lives — the loop stops on the
  /// first `Empty`.
  fn drain_pending_cleanup(&mut self) {
    while let Ok(cleanup) = self.cleanup_rx.try_recv() {
      self.apply_cleanup(cleanup);
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
  ///   emptied root's synchronous `source.disarm`. The release awaits nothing, so this `Watch` never
  ///   blocks the owner on source I/O (and shutdown rides its own channel regardless);
  /// - if the send succeeds but the caller drops its wait **before polling** the reply, the grant
  ///   sitting in the `oneshot` slot is dropped and its `Drop` enqueues a [`Cleanup::DropOrphan`] the
  ///   owner reconciles away — the residual hole a bare `Subscription` left open;
  /// - a caller that observes the reply defuses the grant, so a normal successful `watch` runs no
  ///   extra reconcile.
  ///
  /// The grant carries a clone of the owner's **strong** [`cleanup_tx`](Self::cleanup_tx), so its
  /// `Drop`/`defuse` `try_send` is unloseable regardless of any [`Tributaries`] handle — the old
  /// weak-`commands`-upgrade dance (and its "every handle gone at send time → no caller can observe
  /// the reply" orphan branch) is gone: the owner is running this reconcile, so it is alive, and the
  /// cleanup channel it keeps is open.
  ///
  /// Returns the [`CloseReply`] of a close that won the race inside an in-flight in-place widen
  /// [`replace`](Source::replace) (see [`replace_racing_close`](Self::replace_racing_close)), for
  /// [`dispatch_command`](Self::dispatch_command) to turn into the [`Flow::Break`] the [`run`] loop's
  /// own close arm produces — and [`None`] whenever the reconcile settled, which is every other case.
  async fn on_watch(
    &mut self,
    key: Vec<C>,
    value: V,
    options: WatchOptions<C>,
    reply: futures_channel::oneshot::Sender<Result<WatchGrant, WatchError>>,
  ) -> Option<CloseReply> {
    match self.reconcile_watch(&key, value, options).await {
      Ok(sub) => {
        // Hand the committed subscription back inside a grant carrying a clone of the owner's strong
        // cleanup sender.
        match reply.send(Ok(WatchGrant::new(sub, self.cleanup_tx.clone()))) {
          // Delivered: the grant now guards the committed subscription **in flight**. Record it in
          // `unclaimed` — the ONLY insert site — so `flush_pending_rescans` suppresses its parked debt
          // until the caller claims it (`Cleanup::Claim` → genuinely owed) or drops it
          // (`Cleanup::DropOrphan` → purged).
          Ok(()) => {
            self.unclaimed.insert(sub);
          }
          // The receiver was already gone the instant we sent: the grant bounced back — defuse it (so
          // its own `Drop` enqueues nothing) and orphan the subscription here through the SAME unified
          // [`release_subscription`](Self::release_subscription) a [`Cleanup::DropOrphan`] takes. It
          // was never in flight, so it is NOT recorded `unclaimed`. The release awaits nothing, so this
          // `Watch` never blocks the owner on source I/O (and shutdown rides its own channel regardless).
          Err(Ok(grant)) => {
            // The owner's own cleanup channel is necessarily open while it runs, so the poisoned
            // arm is unreachable here — both arms carry the sub either way.
            let sub = match grant.defuse() {
              Ok(sub) | Err(sub) => sub,
            };
            let _ = self.release_subscription(sub);
          }
          // Unreachable (we always send `Ok`): no grant in flight, nothing to record or orphan.
          Err(Err(_)) => {}
        }
        None
      }
      Err(ReconcileStop::Failed(err)) => {
        let _ = reply.send(Err(err));
        None
      }
      // A close won inside an in-flight in-place widen `replace`: the widen is abandoned, so there is
      // no subscription to grant and no grant to orphan. DROP the caller's reply rather than send on
      // it — a dropped sender is exactly what `watch()` reads as `Closed` (the same way an abandoned
      // held sync's caller sees it) — and hand the reply up to drive teardown.
      Err(ReconcileStop::CloseRequested(close_reply)) => {
        drop(reply);
        Some(close_reply)
      }
    }
  }

  /// Handles a [`Command::Unwatch`]: release the subscription and reply. Synchronous — the unified
  /// [`release_subscription`](Self::release_subscription) requests the emptied root's `source.disarm`
  /// without awaiting, so an `unwatch` never blocks the owner on source I/O (and shutdown, on its own
  /// channel, is independent regardless).
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
  /// **Roots are always armed by the source's own policy** ([`FsSource`] arms at the
  /// fs level's widest all-interest mask, design §4): the caller's
  /// interest (from its [`WatchOptions`]) is recorded on the subscription as a fan-out
  /// gate, never passed to the arm. The options' filter and debounce posture are
  /// registered adjacently at commit.
  /// The retired terminal parked-`Rescan` debt threshold: `needs_rescan`
  /// entries whose subscription is already retired — kept so a root death parked
  /// against a full channel is never silently lost. Watch ADMISSION is refused while
  /// the count sits at or above this ([`WatchError::RescanBacklog`]): retirement only
  /// ever converts live state 1:1 (a batch conversion may stand above the threshold,
  /// bounded by the caller's own peak concurrent subscriptions), and admission is the
  /// only growth of the live-plus-retired total — so gating admission bounds the map
  /// at peak-live-plus-threshold. Generous enough that a draining consumer never
  /// sees it.
  const RETIRED_RESCAN_DEBT_LIMIT: usize = 1024;

  async fn reconcile_watch(
    &mut self,
    key: &[C],
    value: V,
    options: WatchOptions<C>,
  ) -> Result<Subscription, ReconcileStop> {
    let (interest, filter, debounce) = options.into_parts();
    // FILTER-PLANE GATE, before anything is canonicalized, planned, armed or committed. This
    // owner has forgotten a filter panic payload, so it enters no predicate again
    // ([`Owner::filter_payload_forgotten`]) — and a subscription registered here would
    // therefore be created with an admission gate that never runs. The leak is bounded either
    // way; what the refusal buys is that the caller is TOLD, instead of receiving a
    // subscription that quietly delivers everything its filter was written to exclude.
    //
    // Only a watch that asks for filtering is refused: a `Filter::all` default filters nothing,
    // so admitting it changes no behaviour and denies the caller nothing.
    if filter.is_custom() && self.filter_payload_forgotten {
      return Err(WatchError::FilterRetired.into());
    }
    // RETIRED-DEBT ADMISSION GATE. The invariant this enforces, stated
    // honestly: retirement CONVERTS a live subscription's state into one retired parked
    // entry 1:1 (`force_remove_root` frees the subsumer/filter/epoch state as the entry
    // is parked — no growth at conversion), so a single root death can convert an
    // entire covered cohort at once and legitimately stand ABOVE this cap — bounded by
    // the caller's own peak concurrent subscriptions, memory it was already paying for
    // while they lived (the cap is not a ceiling on one batch). What the
    // gate bounds is GROWTH: admission is the only operation that increases the
    // live-plus-retired total, so refusing fresh watches while retired debt sits at or
    // above the cap breaks every replenishment cycle — the map can never exceed
    // peak-live-plus-cap. The refused caller drains the owed Rescans (each flush
    // Ok/Closed frees an entry) and retries. Close is untouched — its own channel.
    let retired_debt = self
      .needs_rescan
      .keys()
      .chain(self.suppressed_rescan.keys())
      .filter(|&&sub| self.subsumer.subscription_key(sub).is_none())
      .count();
    if retired_debt >= Self::RETIRED_RESCAN_DEBT_LIMIT {
      return Err(WatchError::RescanBacklog.into());
    }
    // Canonicalize the caller key at the single arm-and-key choke point, BEFORE classification
    // (invariant I2 — "one fs-canonical coordinate at one choke point"). Every downstream step —
    // `plan_watch`, the Covered-liveness re-plan, the arm, and the commit — then keys on the
    // source's canonical coordinate, so the `Covered` path (which arms nothing, and so never
    // adopts a canonical key at arm time) can no longer commit a raw non-canonical key that later
    // canonical events fail to match: real events arrive under the canonical coordinate, so a
    // verbatim non-canonical key would receive nothing with no `Rescan` to signal the gap (
    // — the Covered-path silent-loss close). A source that cannot canonicalize the key
    // rejects the watch here (FsSource: the path does not exist → `WatchError::Canonicalize`)
    // rather than silently committing an eventless key; a source whose keys are already canonical
    // (a generic component key) canonicalizes as the identity. The arm path still re-keys onto
    // `Armed::canonical_key` and guards it with `fs_path_preserves_plan`, closing the residual
    // TOCTOU where the coordinate changes between this canonicalization and the arm.
    let canonical_key = self.source.canonicalize_key(key)?;
    let key = canonical_key.as_slice();
    // Plan the watch, **re-planning past any dead covering root** so no subscription ever binds a
    // source-forgotten handle (the structural close of the dead-root-coverage class).
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
      WatchOutcome::Covered {
        fs_root,
        sub,
        outside_cover,
      } => {
        // Already covered by a root the re-plan loop just validated LIVE: no arm. The newcomer's
        // key was canonicalized at the top of this method (the single choke point), so committing
        // it verbatim keys the subscription on the source's canonical coordinate — the one its
        // events arrive under — closing the old Covered-path silent-loss where a raw non-canonical
        // key was committed and then never matched a canonical event.
        let (fs_root, sub, outside_cover) = (*fs_root, *sub, *outside_cover);
        // Covered-OUTSIDE grow, grow-BEFORE-commit (set-cover, ratified R1): the covering root's
        // source coverage was NARROWED below this newcomer's key by an earlier prune, so a `Covered`
        // commit — which arms nothing — would regain no real kernel coverage on its own. GROW the
        // source back up to a fresh cover that INCLUDES the newcomer's key — passed EXPLICITLY,
        // since nothing is committed yet — and AWAIT it inside this caller-bounded reconcile
        // (invariant I1, the ratified fence — exactly like `arm`; the owner runs the reconcile to
        // completion, so no other command can classify against the uncommitted state mid-await).
        //
        // - On `Ok` the grow is applied-before-return, so the newcomer's subtree is live before
        //   `watch()` returns and NO bridging `Rescan` is owed: a new watch is "changes from now
        //   on", and there is no request→apply window in which a write under the newly-covered
        //   subtree could be silently lost. Only then commit, and record the grown cover EXACTLY —
        //   the record broadens on grow-`Ok`, never optimistically at issuance, so it always names
        //   the source's true current coverage: a second Covered newcomer landing later still
        //   classifies against the exact record (OUTSIDE the old narrow one only until this commit
        //   lands — reconciles never interleave — and correctly INSIDE the broadened one after).
        // - On `Err` the watch FAILS instead: coverage for the newcomer's subtree could not be
        //   restored, and committing anyway would publish a subscription whose subtree has no
        //   kernel backing and no retry owner — the parked-Rescan retry timer retries DELIVERY,
        //   never coverage, so nothing would ever re-drive the grow (the same honesty as the
        //   DeadOnArrival choke point). The record is NOT broadened, so the next newcomer under
        //   the pruned region classifies outside-cover and re-issues the grow (self-healing), and
        //   the not-yet-committed plan unwinds through `abort_watch` — the identical pre-commit
        //   state the dead-covering-root re-plan above aborts from — leaking no reservation and
        //   orphaning no grant (none was minted). Existing subscribers lost nothing silently: the
        //   source owes them its in-band dominating Rescan on every degraded grow (grow's error
        //   contract).
        //
        // When the newcomer is already inside the retained cover, or the root was never narrowed
        // (`outside_cover == false`), the source already backs it and no grow is issued. On a
        // whole-subtree source `grow` is the default `Ok` no-op (its actual coverage never
        // shrank), so this is inert there. Only `Covered` needs any of this: `Widen`/`Disjoint`
        // each arm a FRESH root at full coverage.
        //
        // `record_cover` is `Some(record)` when a grow succeeded and the retained-cover record
        // must be set to `record` after the commit: `Some(cover)` for the fresh
        // survivors+newcomer antichain, `None` for the cancel-equivalent (full coverage).
        let record_cover = if outside_cover {
          match self.subsumer.retained_cover_for(fs_root, Some(key)) {
            Some(cover) => {
              if let Err(stop) = self.grow(fs_root, &cover).await {
                self.subsumer.abort_watch(&outcome);
                return Err(stop);
              }
              Some(Some(cover))
            }
            None => {
              // A key (a survivor's, or the newcomer's own — it equals the root key) pins the
              // root at its OWN key: grow back to FULL coverage (the cancel-equivalent) and
              // record `None`.
              match self
                .subsumer
                .entry(fs_root)
                .map(|record| record.key.clone())
              {
                Some(root_key) => {
                  if let Err(stop) = self.grow(fs_root, &[root_key]).await {
                    self.subsumer.abort_watch(&outcome);
                    return Err(stop);
                  }
                  Some(None)
                }
                // Unreachable in practice — the re-plan loop just validated the covering root
                // live, and nothing ran since (the owner is single-threaded) — but if the record
                // is somehow gone there is nothing to grow or re-record: commit as a plain
                // Covered, exactly as the pre-reorder code did.
                None => None,
              }
            }
          }
        } else {
          None
        };
        self.subsumer.commit_watch(&outcome, fs_root, key);
        self.filters.insert(sub, SubscriptionFilter::new(filter));
        self.register_debounce(sub, debounce);
        if let Some(cover) = record_cover {
          self.subsumer.set_retained_cover(fs_root, cover);
        }
        Ok(sub)
      }
      WatchOutcome::Disjoint { sub, .. } => {
        let sub = *sub;
        let armed = match self.arm(key).await {
          Ok(armed) => armed,
          Err(stop) => {
            self.subsumer.abort_watch(&outcome);
            return Err(stop);
          }
        };
        // Re-key onto the source's authoritative canonical key (invariant I2). A
        // divergence that changes subsumption is a canonicalization race: disarm and
        // abort cleanly rather than commit a mis-keyed or overlapping entry.
        let (handle, fs_key) = armed;
        if !self.subsumer.fs_path_preserves_plan(&fs_key, &[]) {
          self.source.disarm(handle);
          self.subsumer.abort_watch(&outcome);
          return Err(canonical_race().into());
        }
        // A fresh arm's handle is generation-unique (see `Source::Handle`), so it is absent from the
        // reverse index and `commit_watch`'s `by_handle` insert cannot clobber a live root's entry.
        // A contract-violating source is caught by the arm choke point's handle tripwire, whose
        // live-index half fires on ANY still-live alias before this commit is ever reached.
        self.subsumer.commit_watch(&outcome, handle, &fs_key);
        self.filters.insert(sub, SubscriptionFilter::new(filter));
        self.register_debounce(sub, debounce);
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
        // GAPLESS FIRST: when the widen subsumes exactly ONE root, ask the source
        // to retarget it IN PLACE. The fs binding does that make-before-break (the
        // replacement stream is live before the old retires), so no window exists
        // where the old subtree is unwatched — a strict improvement on the
        // release-and-rearm below, whose gap the re-point `Rescan` can only cover,
        // never un-lose. The handle is PRESERVED, which is sound exactly because
        // no fresh handle is minted (nothing can alias it), and `commit_watch`
        // re-keys by handle remove-then-insert, so the surviving handle lands back
        // in `by_handle` under the WIDER key.
        //
        // `replace` is atomic on failure, so ANY error — including the default
        // "this source cannot widen in place" — falls through to the old dance with
        // the old root's coverage untouched. Nothing has been disarmed yet.
        // Capture the sole subsumed root's key BEFORE the retarget, so a
        // canonicalization race can be rolled back exactly.
        let in_place = match unwatch.as_slice() {
          [only] => self
            .source
            .root_key(*only)
            .map(|only_key| (*only, only_key)),
          _ => None,
        };
        // The retarget is RACED against the owner's close signal (see
        // [`replace_racing_close`](Self::replace_racing_close)): a mount that hangs
        // in `replace` must not wedge the run loop and with it `close()`. ONLY a
        // close diverts — every replace-completes path below is exactly the
        // pre-race one — and the caller's own cancellation is deliberately not
        // raced (it cannot reach the owner, and abandoning a retarget outside a
        // teardown would strand the source at the wider key).
        //
        // `retargeted` is `Some` only when the sole subsumed root's retarget
        // COMMITTED. A retarget that fails resolves `Err` → `None` and falls
        // through to release-and-rearm — the source left the old root's coverage
        // untouched (atomic on failure), and nothing has been disarmed yet.
        let retargeted = match in_place {
          Some((only, only_key)) => match self.replace_racing_close(only, key).await {
            ReplaceStep::Replaced(Ok(armed)) => Some((armed, only_key)),
            ReplaceStep::Replaced(Err(_)) => None,
            // A close won while the retarget was in flight: abandon the widen (the
            // plan unwinds exactly as every other non-committing exit unwinds it)
            // and ride the reply back so the run loop tears down through its own
            // close path. The `watch()` caller's dropped reply surfaces `Closed`.
            ReplaceStep::Close(close_reply) => {
              self.subsumer.abort_watch(&outcome);
              return Err(ReconcileStop::CloseRequested(close_reply));
            }
            // Every handle is gone, so there is no reply to thread and nobody to
            // acknowledge: abandon the widen and fail the watch `Closed` — the
            // error's own "every handle dropped" case — leaving the command channel
            // to drive teardown, exactly as `on_sync` leaves it.
            ReplaceStep::HandlesGone => {
              self.subsumer.abort_watch(&outcome);
              return Err(WatchError::Closed.into());
            }
          },
          None => None,
        };
        if let Some((armed, only_key)) = retargeted {
          let handle = armed.handle();
          let fs_key = armed.canonical_key().to_vec();
          if self.subsumer.fs_path_preserves_plan(&fs_key, unwatch) {
            self.commit_widen(&outcome, handle, &fs_key, sub, filter, debounce, &repointed);
            return Ok(sub);
          }
          // A canonicalization race: the retarget committed a key that does
          // NOT contain every subsumed root, so the widened coverage would
          // strand an old subscriber. The handle is PRESERVED and its
          // subscribers are still committed to it — so we must NOT disarm it
          // (that was the strand bug). ROLL THE RETARGET BACK to the sole
          // root's original key, and accept the rollback ONLY when it restored
          // the handle to that EXACT key — a rollback that itself diverges (an
          // `Ok` at a different key) is not a restore.
          //
          // The rollback is raced against close for the same reason the retarget
          // above is: a mount that hangs HERE would wedge the loop just as surely.
          // A close abandons the rollback, leaving the handle at the divergent
          // wider key — which strands nothing, because the reply rides back to a
          // teardown that drops the source and reclaims that stream outright.
          let restored = match self.replace_racing_close(handle, &only_key).await {
            ReplaceStep::Replaced(res) => {
              matches!(res, Ok(armed) if armed.canonical_key() == only_key.as_slice())
            }
            ReplaceStep::Close(close_reply) => {
              self.subsumer.abort_watch(&outcome);
              return Err(ReconcileStop::CloseRequested(close_reply));
            }
            ReplaceStep::HandlesGone => {
              self.subsumer.abort_watch(&outcome);
              return Err(WatchError::Closed.into());
            }
          };
          if restored {
            // The sole live root is rolled back to its original key on the PRESERVED handle — but it
            // was retargeted to the divergent wider key and back, and `Source::replace` emits no
            // `Rescan`, so any change under it during that window was silently missed. Treat the
            // rollback as a stream rebind: owe every subscriber a durable dominating `Rescan` and
            // resolve their pending syncs `Dominated`, WITHOUT retiring the root (it stays live at
            // `only_key`). `replace` preserves the handle, so the subsumer still keys the sole root's
            // subscribers by `handle` — exactly the coordinate `rescan_live_root` enumerates.
            self.rescan_live_root(handle);
            self.subsumer.abort_watch(&outcome);
            return Err(canonical_race().into());
          }
          // The rollback did not restore the original coverage — it diverged
          // again (a double canonicalization pathology) or failed atomically,
          // leaving the handle watching somewhere its old subscribers do not
          // cover. Retire the root with a durable dominating terminal `Rescan`
          // so each subscriber re-enumerates, THEN release the still-live
          // source watch — otherwise it leaks coverage and trips future
          // overlap checks (never a silent strand).
          self.retire_root_with_terminal_rescan(handle);
          self.source.disarm(handle);
          self.subsumer.abort_watch(&outcome);
          return Err(canonical_race().into());
        }

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
            let closed = restore.await;
            self.subsumer.abort_watch(&outcome);
            // A close consumed during the restore outranks the arm's own error:
            // dropping its reply would leave `close()` pending forever, while the
            // caller's dropped `watch()` reply already reads as `Closed`.
            return Err(closed.map_or(err, ReconcileStop::CloseRequested));
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
          let closed = restore.await;
          self.subsumer.abort_watch(&outcome);
          return Err(
            closed.map_or_else(|| canonical_race().into(), ReconcileStop::CloseRequested),
          );
        }
        // The wider arm's handle is generation-unique (see `Source::Handle`): it aliases none of the
        // still-recorded subsumed roots `commit_watch` is about to drop, nor any other live root, so
        // its `by_handle` insert cannot clobber a live entry. A contract-violating source is caught
        // by the arm choke point's handle tripwire — its live-index half covers exactly these
        // still-recorded roots — before this commit is ever reached.
        self.commit_widen(&outcome, handle, &fs_key, sub, filter, debounce, &repointed);
        Ok(sub)
      }
    }
  }

  /// Awaits one [`Source::replace`] under a race against the owner's dedicated close signal, so a
  /// backend retarget that never returns cannot wedge the run loop — and with it `close()`, whose
  /// contract is bounded teardown latency. The in-place widen's two retargets are the owner's only
  /// unbounded source awaits outside [`on_sync`](Self::on_sync)'s cookie write, which is raced for
  /// exactly the same reason.
  ///
  /// The await is FORCED onto this loop by the `&mut self.source` + conditional-`Send` seam, exactly
  /// as that write is: [`R::timeout`](RuntimeLite::timeout) needs a `Send` inner future (which
  /// [`LocalSource::replace`] is not) and `R::timeout_local` is unconditionally `!Send` (which would
  /// break the `Send` promise [`Tributaries::parts`] makes on the [`Source`] path), so no generic timer
  /// can bound the retarget while preserving the run future's conditional `Send`. So instead of a
  /// timer, RACE it against the unconditionally-`Send` close receiver: a `select` of the two is `Send`
  /// iff `replace` is, so the combined future keeps EXACTLY the conditional `Send` the run loop needs —
  /// [`parts`](Tributaries::parts)' promise still proves out and `parts_local` still withholds it, so
  /// both compile-time owner-`Send` assertions still hold.
  ///
  /// ONLY the close is raced — deliberately NOT the `watch()` caller's cancellation, unlike `on_sync`:
  ///
  /// - there is nothing to race. The owner holds the `watch()` reply SENDER and runs this reconcile to
  ///   completion; a caller that drops its `watch()` wait drops only the reply RECEIVER, which cannot
  ///   interrupt the owner. (`on_sync` races `reply.cancellation()` precisely because a sync's caller
  ///   TIMEOUT must free the owner within the caller's own deadline — a `watch` has no such deadline.)
  /// - it would not be cancellation-safe. [`Source::replace`] is NOT cancel-abortive: dropping the
  ///   future abandons only the notification, never the swap — the fs driver still commits the lane
  ///   retarget it parked. Abandoning one OUTSIDE a teardown would therefore leave the source committed
  ///   to the wider key while this reconcile unwound the widen: a divergent fs-vs-umbrella coverage
  ///   strand. Under a close that divergence cannot outlive the race — the won close breaks the loop
  ///   straight to teardown, which drops the source, and the fs driver's close sweep reclaims every
  ///   in-flight replace (its parked reservation, its pre-armed stream, and its committed one alike)
  ///   before it returns.
  ///
  /// So a hung mount's owner is freed by `close()` — the bounded contract — and by nothing else.
  async fn replace_racing_close(
    &mut self,
    handle: S::Handle,
    new_key: &[C],
  ) -> ReplaceStep<C, S::Handle> {
    // Split-borrow the two owner fields the race touches so they stay disjoint: the close arm reads
    // `&self.closes` while `replace` reborrows `&mut self.source`. Both futures are dropped with this
    // block, so the winner is used against a fully released `self`.
    let closes = &self.closes;
    let source = &mut self.source;
    futures_util::select_biased! {
      // Close is polled FIRST — a requested shutdown wins over everything, exactly as in the run
      // loop's own biased `select!`. So a close already queued when this race begins abandons the
      // retarget before `replace` is ever polled: the request is never even issued.
      //
      // Unlike `on_sync`'s write — which is polled first because dropping an ALREADY-ready `Ok(path)`
      // would strand the cookie FILE it names, a resource that outlives the process — a ready-but-
      // dropped `Armed` here names a source STREAM, and the only arm that can drop one is this close,
      // which tears down at once: the fs driver's close sweep reclaims that stream (committed or not)
      // during the very teardown this reply drives. So the tie costs a discarded retarget, never a
      // leak, and close keeps the strictest bound.
      close = closes.recv().fuse() => match close {
        Ok(close_reply) => ReplaceStep::Close(close_reply),
        Err(_) => ReplaceStep::HandlesGone,
      },
      res = source.replace(handle, new_key).fuse() => ReplaceStep::Replaced(res),
    }
  }

  /// The shared commit tail of a widen, whichever way its wider root was obtained:
  /// freshly armed (release-and-rearm) or retargeted IN PLACE
  /// ([`Source::replace`] — same handle, no coverage gap).
  ///
  /// The subsumer's `by_handle` re-key is remove-then-insert, so a PRESERVED handle
  /// lands back under the wider key rather than being dropped — which is exactly why
  /// the in-place path needs no separate index surgery.
  ///
  /// Every re-pointed subscription is rebased onto the wider root with a synthetic
  /// dominating `Rescan` (design §8): it strictly dominates that sub's pre-widen
  /// stream while the new root's genuine events tie-or-exceed it, and names the
  /// widened root to re-enumerate. It is owed on BOTH paths — the release-and-rearm
  /// gap makes it a loss cover, and the in-place path (no gap) still changes the
  /// sub's root, so its view must re-base.
  #[allow(clippy::too_many_arguments)]
  fn commit_widen(
    &mut self,
    outcome: &WatchOutcome<C, S::Handle>,
    handle: S::Handle,
    fs_key: &[C],
    sub: Subscription,
    filter: Filter<C>,
    debounce: Debounce,
    repointed: &[Subscription],
  ) {
    self.subsumer.commit_watch(outcome, handle, fs_key);
    self.filters.insert(sub, SubscriptionFilter::new(filter));
    self.register_debounce(sub, debounce);
    let mut rescans = Vec::with_capacity(repointed.len());
    for &moved in repointed {
      // The re-point Rescan re-enumerates the whole subscription, so it dominates any
      // pre-widen deltas still buffered in the coalescer. Drop them before delivering it:
      // otherwise, on a full channel, a buffered delta flushes ahead of the Rescan (the
      // coalescer admits before `try_emit` suppresses) and parks at a fresh `shed_rescan`
      // one epoch above the new root's raw-0, sorting the Rescan behind it and silently
      // dropping post-widen events (the coalescer sibling of the re-point-epoch calibration).
      // DROP, not forget: the re-pointed subscription stays live on the wider root, so its
      // registered debounce policy must keep governing its post-widen events.
      if let Some(coalescer) = self.coalescer.as_mut() {
        coalescer.drop_subscription(moved);
      }
      let rescan = self.epochs.repoint(moved);
      // Keyed at the SUBSCRIPTION, not at the new wider root: the gap this Rescan closes is
      // the disarm/re-arm window, and within this subscription that window made exactly its
      // own subtree uncertain. Naming the wider root would hand a per-subscription consumer
      // a path outside its watch (see `route`'s rescan geometry).
      let key = self.rescan_key_for(moved, fs_key);
      let mut event = Event::rescan(moved, key, rescan);
      // The specific re-pointed subscription owns this Rescan (its key is invariant under the
      // widen, so its own value is still recorded); bake it so attribution is the sub's own
      // value, not the widening root's (design §3).
      event.set_value(self.subsumer.subscription_value(moved).cloned());
      rescans.push(event);
    }
    self.push_all(rescans);
    // Each re-pointed subscription now carries a durable dominating `Rescan`
    // (published or parked by `push_all`): resolve any barrier riding it
    // `Dominated`, so a pending sync does not wait for a cookie on a stream
    // that just re-based onto the wider root.
    for &moved in repointed {
      self.dominate_syncs_of_subscription(moved);
    }
  }

  /// Registers a freshly-committed subscription's [`Debounce`] posture with the
  /// coalescer — the debounce half of the commit, adjacent to the filter-map insert
  /// (design §6).
  ///
  /// Lazy instantiation preserves the zero-cost claim — absent a config the coalescer
  /// is never even instantiated (design §6) — for consumers who never opt in
  /// **anywhere**:
  ///
  /// - [`Inherit`](Debounce::Inherit) records nothing: an absent policy entry IS the
  ///   inherit resolution (and a fresh subscription never has a stale one to remove),
  ///   so it never instantiates;
  /// - [`Off`](Debounce::Off) with no coalescer is a no-op — events already pass
  ///   through untouched, so there is nothing to switch off and nothing is
  ///   instantiated; with a live coalescer it records the raw pass-through override;
  /// - [`Custom`](Debounce::Custom) is the one opt-in act: it creates the coalescer on
  ///   first use — carrying the watcher-global [`debounce`](Owner::debounce) default
  ///   (`None` here, or the eager path would already have built it) so sibling
  ///   subscriptions' inherit resolution stays honest — and records the override.
  fn register_debounce(&mut self, sub: Subscription, debounce: Debounce) {
    match debounce {
      Debounce::Inherit => {}
      Debounce::Off => {
        if let Some(coalescer) = self.coalescer.as_mut() {
          coalescer.set_policy(sub, debounce);
        }
      }
      Debounce::Custom(_) => {
        let default = self.debounce;
        self
          .coalescer
          .get_or_insert_with(|| Coalescer::new(default))
          .set_policy(sub, debounce);
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
  /// key when the fs watcher's `root_path` was `None`). Committing such a
  /// dead-on-arrival handle publishes the key as watched yet backs it with **no live watch**:
  /// changes would rely on a later terminal event instead of being streamed. So after the arm
  /// this synchronously validates the handle through the same out-of-band [`Source::root_key`]
  /// probe the Covered-reuse loop and terminal retirement use; on a dead
  /// handle it best-effort [`disarm`](Source::disarm)s the stray root (a synchronous
  /// fire-and-forget release request) and fails the arm with [`WatchError::DeadOnArrival`].
  /// Arm-time + reuse-time + terminal-time liveness together close the
  /// handle-liveness class.
  ///
  /// Because every arming path funnels through here, this is also where the generation-unique
  /// [`Source::Handle`] tripwire lives: a debug-only assert that the freshly-armed, live handle
  /// was never observed by this owner before. It reads the subsumer's live index — **exhaustively**
  /// subsuming the old per-site live-index checks, with no window a still-live root can age out of
  /// — AND a bounded history of recent arms, which additionally catches reuse of a handle already
  /// removed from that index by unwatch or terminal retirement (see `observed_handles`).
  ///
  /// An overlap rejection (the fs binding's `Overlaps`) from a conforming source is now
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
  /// Grows a covering root's source coverage back up to `cover`, RACED against the dedicated close
  /// receiver for the same reason [`arm`](Self::arm) is: this call is awaited inside the run loop's
  /// selected command branch, so an unraced grow against a hung mount leaves the already-queued
  /// close receiver unpolled and `close()` pending forever. The stock binding's `grow` waits on the
  /// lower cover-settle fence, so this is not a hypothetical hostile source.
  ///
  /// Dropping a pending grow abandons only a COVERAGE WIDENING, never a commitment: the caller's
  /// reconcile unwinds through `abort_watch`, the retained-cover record is not broadened (so the
  /// next newcomer under the pruned region re-issues the grow), and the close this lost to tears
  /// the source down immediately.
  async fn grow(&mut self, root: S::Handle, cover: &[Vec<C>]) -> Result<(), ReconcileStop> {
    let closes = &self.closes;
    let source = &mut self.source;
    futures_util::select_biased! {
      close = closes.recv().fuse() => match close {
        Ok(close_reply) => Err(ReconcileStop::CloseRequested(close_reply)),
        // Every handle is gone: an abandon, not a threaded close (see `arm`). The
        // grow is left to the caller's next attempt; the command channel drives
        // teardown.
        Err(_) => Err(WatchError::Closed.into()),
      },
      res = source.grow(root, cover).fuse() => res.map_err(Into::into),
    }
  }

  /// The arm itself is RACED against the dedicated close receiver, exactly as
  /// [`replace`](Self::replace_racing_close) and `on_sync`'s cookie write are.
  /// Without that race the owner's advertised close lane is not a lane at all:
  /// the run loop selects a command, awaits the whole reconcile inside that
  /// branch, and the reconcile awaits this arm — so a `Source::arm` against a
  /// hung mount (the stock binding waits on lower registration, and possibly on
  /// lower unwatch acknowledgements) means the already-queued close receiver is
  /// never polled again and `close()` stays pending forever, with the read plane
  /// and every source resource still live. Racing it makes close bounded against
  /// a source that violates its own bounded-progress requirement, which is what
  /// the run loop and the [`Source`] contract both promise.
  ///
  /// Dropping a pending `arm` is safe for the same reason dropping a pending
  /// `replace` is: only a close can drop it, and a close tears down at once —
  /// the source's own `Drop` reclamation covers an in-flight arm, and an
  /// already-created stream the abandoned future would have reported is
  /// reclaimed by the lower driver's close sweep.
  async fn arm(&mut self, key: &[C]) -> Result<(S::Handle, Vec<C>), ReconcileStop> {
    let armed = {
      // Split-borrow so the two arms stay disjoint: the close arm reads
      // `&self.closes` while `arm` reborrows `&mut self.source`.
      let closes = &self.closes;
      let source = &mut self.source;
      futures_util::select_biased! {
        // Close is polled FIRST — a requested shutdown wins over everything, so an
        // arm not yet started is never issued at all. Every handle being gone is an
        // ABANDON rather than a threaded close (`None`): the command channel remains
        // the dropped-handles teardown signal, so the arm is left to finish rather
        // than inventing a reply nobody is waiting for.
        close = closes.recv().fuse() => close.ok(),
        res = source.arm(key).fuse() => return match res {
          Ok(armed) => self.adopt_armed(armed),
          Err(err) => Err(err.into()),
        },
      }
    };
    match armed {
      Some(close_reply) => Err(ReconcileStop::CloseRequested(close_reply)),
      // The close channel closed mid-arm. Re-issue against the source: this is
      // the abandon case above, and the reconcile still owes its caller a
      // verdict.
      None => match self.source.arm(key).await {
        Ok(armed) => self.adopt_armed(armed),
        Err(err) => Err(err.into()),
      },
    }
  }

  /// The post-arm half of the choke point: liveness validation, the
  /// generation-unique handle tripwire, and adoption of the source's canonical
  /// key. Shared by both of [`arm`](Self::arm)'s issue paths so the choke point
  /// stays single even though the arm is raced.
  fn adopt_armed(
    &mut self,
    armed: crate::source::Armed<C, S::Handle>,
  ) -> Result<(S::Handle, Vec<C>), ReconcileStop> {
    let handle = armed.handle();
    if self.source.root_key(handle).is_none() {
      self.source.disarm(handle);
      return Err(WatchError::DeadOnArrival.into());
    }
    // The single tripwire for the generation-unique `Source::Handle` contract: a freshly-armed,
    // live handle must be one this owner has never seen. It reads TWO structures, because each
    // answers a case the other cannot.
    //
    // The subsumer's live index is EXHAUSTIVE and is what covers the case that matters most: a
    // handle still naming a live root. That is the alias `commit_watch` / `rebind_root` would let
    // overwrite the reverse handle mapping, stranding the original root and misrouting its events
    // into the new one. It subsumes the old per-site `entry(handle).is_none()` asserts
    // (Disjoint/Widen commit, restore rebind) with no window to fall out of — a root may stay live
    // across arbitrarily many arms of other roots, so a bounded most-recent history CANNOT decide
    // this and must not be asked to.
    //
    // The bounded observed-handle window covers what no live structure remembers: a handle already
    // removed from the live index by unwatch or terminal retirement, whose reuse is equally a
    // violation because a stale event still carrying it would route through the re-armed root.
    // `observe` reports `false` while the handle is still in the window
    // (`OBSERVED_HANDLE_HISTORY` states the bound and what it costs).
    //
    // Both are evaluated before the assert so the window records this arm either way.
    // Debug-only: the field, this assert, and its cost all vanish in release builds.
    #[cfg(debug_assertions)]
    {
      let aliases_a_live_root = self.subsumer.entry(handle).is_some();
      let unseen_recently = self.observed_handles.observe(handle);
      debug_assert!(
        !aliases_a_live_root && unseen_recently,
        "Source::arm returned a handle already observed by this owner (a reused handle, even \
         after retirement) — a generation-unique Source::Handle contract violation; see \
         Source::Handle"
      );
    }
    Ok((handle, armed.canonical_key().to_vec()))
  }

  /// The single synchronous subscription-release primitive (invariant I4): brand-check, purge the
  /// subscription's owner-local per-sub state (filter, epoch, parked overflow Rescan, buffered
  /// coalescer deltas — BEFORE the subsumer is consulted, so a terminal-retired orphan leaves no
  /// false debt), `plan_unwatch`, and — if that emptied the root — request the source
  /// release via the **synchronous** fire-and-forget [`Source::disarm`].
  ///
  /// Every subscription teardown funnels through here: the caller-initiated
  /// [`unwatch`](Self::on_unwatch) (which reports the [`Result`]); a [`Cleanup::DropOrphan`] (via
  /// [`apply_cleanup`](Self::apply_cleanup)) and the [`on_watch`](Self::on_watch) send-failure orphan
  /// path, which ignore it; and the source-drain teardown loop
  /// ([`drain_owed_before_shutdown`](Self::drain_owed_before_shutdown)), which likewise ignores it.
  /// Because the release is a synchronous request that awaits nothing, this never blocks the owner on
  /// source I/O — and shutdown, riding the dedicated [`closes`](Self::closes) channel checked at the
  /// top priority, is bounded independent of any of this — so Close-responsiveness (invariant II)
  /// holds by construction on every path, with no per-path special-casing (the old defer / idle-drain
  /// / teardown-purge split collapses to one call).
  ///
  /// The **ordering is load-bearing**: the owner-local reclaim runs FIRST, keyed on
  /// `sub` alone, EVEN WHEN the subscription is already absent from the subsumer. A
  /// committed-but-unclaimed watch can be **terminal-retired** while its [`WatchGrant`] still sits in
  /// the reply slot — root death (`retire_if_dead`) parks that sub's terminal Rescan and
  /// force-removes it from the subsumer — and the later [`Cleanup::DropOrphan`] must
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
    // A CALLER unwatch owes no `Rescan`, so a barrier on this sub can never be
    // met honestly — fail it typed rather than resolve it over a subscription
    // that is going away. (A ROOT DEATH is the asymmetric case: its terminal
    // `Rescan` dominates, so those resolve `Dominated`.)
    self.retire_syncs_of_subscription(sub);
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
    // ALONE, BEFORE the subsumer outcome is consulted (see the ordering note above).
    // Neither `drain_coalescer_due`/`try_emit` re-checks live-subscription membership, so a coalescer
    // delta buffered before the reclaim must be dropped here or it would deliver for a gone
    // subscription. Removing the `unclaimed` entry here is what makes a `Cleanup::DropOrphan` (and the
    // `on_watch` send-failure orphan path, and the Unknown path) clear an in-flight grant's
    // suppression: exactly one of `Cleanup::Claim`/`Cleanup::DropOrphan` fires per grant, and this is
    // the `DropOrphan` side.
    self.retire_sub_state(sub);
    self.needs_rescan.remove(&sub);
    self.suppressed_rescan.remove(&sub);
    self.unclaimed.remove(&sub);
    self.loss_serial.remove(&sub);
    if let Some(coalescer) = self.coalescer.as_mut() {
      // FORGET, not drop: the subscription is ending, so its registered debounce policy
      // goes with its buffered deltas — unlike the still-live shed paths (a widen/restore
      // re-point, an overflow park), which purge buffers but keep the policy.
      coalescer.forget_subscription(sub);
    }
    // Now consult the subsumer. An already-retired sub is `Unknown` (its owner-local cleanup above
    // has already run); a live one reports whether its root emptied — or, on the non-emptied path,
    // whether the departure left the root OVER-BROAD (the set-cover design).
    let Some(outcome) = self.subsumer.plan_unwatch(sub) else {
      return Err(UnwatchError::UnknownSubscription);
    };
    match outcome {
      UnwatchOutcome::RootEmptied { fs_root } => {
        // The subscription was its root's last: request release of the kernel watch — a synchronous,
        // fire-and-forget [`Source::disarm`] (the source queues any async teardown and applies it at
        // its next arm or `Drop`). Nothing is awaited, so no teardown path blocks the owner (and
        // shutdown rides its own channel regardless).
        self.source.disarm(fs_root);
      }
      UnwatchOutcome::Dropped {
        shrink: Some((handle, retained)),
      } => {
        // The root survives for narrower subscribers but its source coverage is now reclaimable — it
        // covers more than `retained`, the antichain every live subscriber still sits under. This
        // fires in BOTH shrink cases (`detect_shrink`): a full-coverage root whose root-key sub
        // departed (over-broad), AND an already-narrowed root a non-root departure lets shrink further
        // (F2). Request the source PRUNE its kernel coverage in place down to `retained`
        // via [`Source::set_cover`]: a synchronous fire-and-forget request modeled exactly on
        // [`Source::disarm`], so it is uniform and safe on EVERY release path (caller unwatch AND the
        // [`Cleanup::DropOrphan`] orphan AND source-drain teardown) with no async-seam split — the
        // sync nature is what licenses one call at the one release primitive. It reclaims watch budget
        // with no gap and no re-crawl; a no-op source (the default) conforms, since over-broadness is
        // correctness-neutral and self-healing. Record the pruned cover in the subsumer's retained
        // bookkeeping (narrow-on-issue — safe pessimism for a fire-and-forget prune), so a later
        // `Covered` newcomer under the now-pruned region is classified `outside_cover` and gets its
        // awaited grow.
        self.source.set_cover(handle, &retained);
        self.subsumer.set_retained_cover(handle, Some(retained));
      }
      // Nothing reclaimable: the root is exactly as wide as a live subscriber still needs it.
      UnwatchOutcome::Dropped { shrink: None } => {}
    }
    Ok(())
  }

  /// Frees the per-subscription driver state that is **always** reclaimed when a `sub`
  /// retires — its admission [`Filter`] and its [`EpochLedger`](epoch::EpochLedger) entry —
  /// the shared core both retire paths route through (invariant I4).
  ///
  /// The parked overflow [`Rescan`](crate::EventKind::Rescan) (`needs_rescan`) is
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
    self.loss_serial.remove(&sub);
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
  ///   and mint a dominating [`Rescan`](crate::EventKind::Rescan) per subscriber — the re-arm
  ///   restarts the source's raw epochs at zero, so each subscriber
  ///   [`repoint`](epoch::EpochLedger::repoint)s onto the new handle (exactly a widen re-point) and
  ///   re-enumerates. The subscription is live-and-covered again. The re-arm returns a
  ///   **generation-unique** handle by contract (see [`Source::Handle`]), so it can alias neither
  ///   `old` nor a not-yet-restored sibling still recorded here; the earlier defensive
  ///   alias-detection is gone (it was incomplete, and disarming an aliased handle
  ///   stranded an *unrelated live* root), replaced by the arm choke point's `debug_assert`
  ///   tripwire — whose live-index half covers every still-recorded root exhaustively — which
  ///   fires loudly on a contract-violating source without corrupting release builds.
  /// - if the re-arm **fails** (the root is genuinely dead) or its committed key **diverged** (a
  ///   canonicalization race we cannot cleanly rebind), **retire** the root through the shared
  ///   [`retire_root_with_terminal_rescan`](Self::retire_root_with_terminal_rescan): a durable
  ///   dominating terminal Rescan per subscriber, then free its index / filter / epoch and drop it
  ///   from the view.
  ///
  /// Either way no subscription is left recorded-live-but-disarmed-and-published-watched.
  ///
  /// Returns the [`CloseReply`] a close won from a re-arm, if one did. The re-arms run through the
  /// close-raced [`arm`](Self::arm) choke point, so a close during this restore consumes the
  /// dedicated close signal — and a consumed reply that were merely dropped here would leave
  /// `close()` pending forever, the exact wedge the race exists to remove. The restore stops at
  /// that point: the remaining subsumed roots are retired with their terminal `Rescan`s (no
  /// subscription is left bound to a released handle) and the reply is handed back to drive
  /// teardown, which drops the source and reclaims everything the abandoned re-arms would have
  /// restored.
  async fn restore_disarmed_roots(&mut self, unwatch: &[S::Handle]) -> Option<CloseReply> {
    for &old in unwatch {
      // The subsumed root is still recorded (the widen never committed); recover its key
      // and subscribers before any re-arm/retire mutates the subsumer.
      let Some((root_key, subscribers)) = self
        .subsumer
        .root_view(old)
        .map(|(key, cohort)| (key.to_vec(), cohort.to_vec()))
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
          // silently missing future changes. The generation-unique contract also
          // forbids reusing a handle even for a *same-key* re-arm: if a stale pre-disarm
          // event still carrying `old` is queued, re-arming `old` would let it route through the
          // re-armed root and be stamped in the new generation past the restore Rescan — so `old`
          // must fall to the dead-root drain path, and reusing `old` is NOT exempt. Any reuse —
          // a sibling, `old`, or a handle already removed from the live index by a prior retirement —
          // is caught by the arm choke point's handle tripwire (the live index for the first two,
          // the observed-handle window for the third) before this rebind is ever reached.
          //
          // Re-armed at the same coordinate with a fresh handle: rebind onto it and re-point each
          // subscriber (raw epochs restarted at zero) with a dominating Rescan.
          self.subsumer.rebind_root(old, new_handle);
          let mut rescans = Vec::with_capacity(subscribers.len());
          for &sub in &subscribers {
            // As in the widen path: the restore re-point Rescan dominates the subscriber's
            // buffered pre-widen coalescer deltas, so drop them before delivering it — else a
            // buffered delta can flush ahead of the Rescan on a full channel and park one epoch
            // above the new root's raw-0 (the coalescer sibling of the re-point-epoch calibration).
            // DROP, not forget: the re-bound subscription stays live and keeps its policy.
            if let Some(coalescer) = self.coalescer.as_mut() {
              coalescer.drop_subscription(sub);
            }
            let rescan = self.epochs.repoint(sub);
            // Scoped to the subscription's own key, like every other per-subscription
            // recovery instruction (see `rescan_key_for`).
            let key = self.rescan_key_for(sub, &root_key);
            let mut event = Event::rescan(sub, key, rescan);
            // The re-armed root kept each subscriber's key (rebind touches only the handle), so
            // bake the subscriber's own recorded value onto its restore Rescan (design §3).
            event.set_value(self.subsumer.subscription_value(sub).cloned());
            rescans.push(event);
          }
          self.push_all(rescans);
          // Each re-bound subscriber now carries a durable dominating restore
          // `Rescan`: resolve any barrier riding it `Dominated` (its stream
          // re-based onto the fresh handle), rather than waiting for a cookie
          // whose old handle is dead.
          for &sub in &subscribers {
            self.dominate_syncs_of_subscription(sub);
          }
        }
        Ok((new_handle, _diverged)) => {
          // Re-armed, but at a divergent key we cannot cleanly rebind: request release of the stray
          // new handle (synchronous, fire-and-forget) and retire the old root so its subs
          // re-enumerate and it leaves the view.
          self.source.disarm(new_handle);
          self.retire_root_with_terminal_rescan(old);
        }
        Err(ReconcileStop::Failed(_)) => self.retire_root_with_terminal_rescan(old),
        Err(ReconcileStop::CloseRequested(close_reply)) => {
          // Close won this re-arm. Retire every root still awaiting restoration —
          // this one included — so none is left recorded live on a released
          // handle, then hand the reply back rather than dropping it.
          self.retire_root_with_terminal_rescan(old);
          for &pending in unwatch {
            if pending != old {
              self.retire_root_with_terminal_rescan(pending);
            }
          }
          return Some(close_reply);
        }
      }
    }
    None
  }

  /// The single **park-terminal-Rescan-then-retire** primitive (invariant I4, no silent loss):
  /// retires a root while durably owing every subscriber a dominating terminal
  /// [`Rescan`](crate::EventKind::Rescan), so each re-enumerates its key and learns the
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
    // Owe every subscriber a dominating terminal `Rescan` and resolve their pending syncs
    // `Dominated` while the root is still recorded — the shared live-root core — BEFORE freeing any
    // subsumer state, so a full channel can never drop an owed terminal Rescan.
    self.rescan_live_root(handle);
    // The owed Rescans are now durable: tear the dead root out of the index and free each
    // subscriber's per-sub filter + epoch state (the parked `needs_rescan` entry is kept). FORGET
    // each sub's coalescer policy too — `rescan_live_root` only DROPPED its buffered deltas (keeping
    // the policy for the live-root path), and terminal retirement ends the subscription.
    for sub in self.subsumer.force_remove_root(handle) {
      if let Some(coalescer) = self.coalescer.as_mut() {
        coalescer.forget_subscription(sub);
      }
      self.retire_sub_state(sub);
    }
  }

  /// Owes every subscriber of a **still-live** root a durable dominating terminal
  /// [`Rescan`](crate::EventKind::Rescan) and resolves each of its pending barriers `Dominated` —
  /// WITHOUT retiring the root. The park-for-each-sub +
  /// [`dominate_syncs_of_root`](Self::dominate_syncs_of_root) core shared by two callers:
  /// [`retire_root_with_terminal_rescan`](Self::retire_root_with_terminal_rescan) (which then
  /// force-removes the root) and the in-place-widen exact-rollback (which keeps the root LIVE at its
  /// original key after a divergent retarget was rolled back — a silent coverage gap the preserved
  /// stream's [`replace`](crate::Source::replace) never signals, so a `Rescan` must stand in).
  ///
  /// For each subscriber it parks a dominating terminal `Rescan` straight into `needs_rescan` (or
  /// `suppressed_rescan` for an unclaimed sub) via [`merge_max`] — the root's key (captured while it
  /// is recorded) + a strictly-dominating [`shed_rescan`](epoch::EpochLedger::shed_rescan) epoch + the
  /// subscriber's baked value — so a full channel cannot drop it and it stays attributable, and DROPS
  /// the sub's now-suspect buffered coalescer deltas while KEEPING its policy (the sub stays live on
  /// this path; the retiring caller forgets the policy itself after force-removal). Every owed `Rescan`
  /// is parked BEFORE the syncs are dominated, so a caller waking on another thread re-enumerates
  /// against a `Rescan` already parked ahead of any later delta — never a reply that outruns its cover.
  ///
  /// A no-op if `root` is not a live recorded root.
  fn rescan_live_root(&mut self, root: S::Handle) {
    let Some((root_key, subscribers)) = self
      .subsumer
      .root_view(root)
      .map(|(key, cohort)| (key.to_vec(), cohort.to_vec()))
    else {
      return;
    };
    for &sub in &subscribers {
      // Route the park through the ONE loss choke point (like every other park), so both loss clocks
      // move: this is a genuine coverage loss — a root death, or a rollback whose preserved stream
      // was retargeted away and back with no `Rescan`, silently dropping whatever the old stream
      // still had queued, INCLUDING changes that predate a caller's in-flight `sync()`. Parking
      // straight into `merge_max` without noting it left the shared generation still, so such a
      // caller's barrier could install onto a state that looked pristine and report a false
      // `Delivered`. `dominate_syncs_of_root` below only reaches barriers ALREADY installed.
      self.note_loss(sub);
      let value = self.subsumer.subscription_value(sub).cloned();
      let epoch = self.epochs.shed_rescan(sub);
      // Scoped to the subscription's own key: the root died or its stream was silently
      // retargeted, which makes everything this subscriber owns uncertain — and nothing
      // above it, which is not its to re-enumerate (see `rescan_key_for`).
      let key = self.rescan_key_for(sub, &root_key);
      let target = if self.unclaimed.contains(&sub) {
        &mut self.suppressed_rescan
      } else {
        &mut self.needs_rescan
      };
      merge_max(target, sub, key, epoch, value);
      // DROP (not forget) the buffered deltas: the sub stays live here, so its registered debounce
      // policy must keep governing later events. A retiring caller forgets the policy afterward.
      if let Some(coalescer) = self.coalescer.as_mut() {
        coalescer.drop_subscription(sub);
      }
    }
    self.dominate_syncs_of_root(root);
  }

  /// Fans one raw source event out to its covering, admitting subscribers and pushes the
  /// results (through the coalescer, if enabled) to the event stream.
  ///
  /// # The delivery that a panicking filter admitted goes through the debt gate, not the
  /// coalescer
  ///
  /// A subscription whose predicate unwound during this fan-out is quarantined *here*,
  /// between the fan-out and the push — which means the delivery its panic fail-opened
  /// was **stamped before** [`quarantine_filters`](Self::quarantine_filters) minted that
  /// subscription's dominating `Rescan`, and is therefore strictly dominated by it.
  ///
  /// Routing it through [`push_all`](Self::push_all) would admit it to the
  /// [`Coalescer`](crate::coalesce::Coalescer) (which buffers *before*
  /// [`try_emit`](Self::try_emit) suppresses), where it would sit behind a settle window
  /// while the parked `Rescan` is flushed and cleared — and then be released *after* it,
  /// at a lower epoch. A high-water consumer discards the older delivery it needed; a
  /// naive one re-applies a change the enumeration already superseded and re-diverges.
  /// So a just-quarantined subscription's deliveries take `try_emit` directly: the
  /// standing debt suppresses each one and
  /// [`widen_parked_debt`](Self::widen_parked_debt) grows the `Rescan` to cover it —
  /// the same treatment every other event suppressed behind standing debt gets, and no
  /// silent loss, because the `Rescan` re-enumerates exactly what was suppressed.
  fn fan_out_and_push(&mut self, raw: &SourceEvent<C, S::Handle>) {
    let (fanned, poisoned) = self.fan_out_raw(raw);
    if poisoned.is_empty() {
      self.push_all(fanned);
      return;
    }
    self.quarantine_filters(&poisoned);
    let (behind_new_debt, rest): (Vec<_>, Vec<_>) = fanned
      .into_iter()
      .partition(|event| poisoned.contains(&event.subscription()));
    for event in behind_new_debt {
      self.try_emit(event);
    }
    self.push_all(rest);
  }

  /// The single event-emit funnel (design backpressure doc): the owner **never awaits** the
  /// event channel, so `Close`-responsiveness (II) and deadlock-freedom (III) hold *by
  /// inspection* — this is the only place an ordinary delivery reaches the channel, and it
  /// is a non-blocking [`try_send`](async_channel::Sender::try_send).
  ///
  /// # The parked-debt invariant
  ///
  /// For every event suppressed behind standing debt, the `Rescan` eventually delivered for
  /// that subscription must **spatially cover** the suppressed event's affected key(s) **and**
  /// carry an epoch that **strictly dominates** it. Suppression is only sound while that holds,
  /// and it does not hold for free: a parked debt may be a *located* `Rescan` (source-emitted,
  /// terminal, restore, or re-point) whose key names a narrower subtree, and whose epoch was
  /// calibrated before the suppressed event existed. Every suppression therefore repairs the
  /// debt through [`widen_parked_debt`](Self::widen_parked_debt) rather than assuming it.
  ///
  /// Three outcomes:
  /// - the subscription already carries a parked overflow `Rescan` (`needs_rescan`) → for an
  ///   **ordinary delta**, **suppress** the emit and widen the debt to cover it: delivering it
  ///   would put an ordinary event ahead of the `Rescan` that covers the drop (the
  ///   fan-out atomicity guarantee — Lens 2 — holds across iterations through this check). A
  ///   source-emitted `Rescan` arriving while parked is instead **merged** into the debt
  ///   ([`park_rescan_event`](Self::park_rescan_event)): it is an independent coverage-loss signal
  ///   that may name a *different* key under the same root, so discarding it would leave its
  ///   subtree never re-enumerated (no silent loss under backpressure);
  /// - [`Ok`] → delivered;
  /// - [`Full`](async_channel::TrySendError::Full) → shed to a dominating `Rescan`, the mint
  ///   depending on **what** overflowed. An already-minted synthetic `Rescan` (a widen/restore
  ///   re-point, a fanned source-overflow, a terminal `Rescan`) is **parked UNCHANGED** at its own
  ///   dominating epoch ([`park_rescan_event`](Self::park_rescan_event)): re-minting it via
  ///   `shed_rescan` would push its epoch one *above* a re-point's calibrated new-root events and
  ///   silently drop them. An ordinary delta instead sheds to a fresh
  ///   [`shed_rescan`](epoch::EpochLedger::shed_rescan) ([`park_rescan`](Self::park_rescan)), whose
  ///   new dominating `Rescan` covers its loss;
  /// - [`Closed`](async_channel::TrySendError::Closed) → no-op: the consumer is gone and
  ///   teardown arrives on the command mailbox.
  fn try_emit(&mut self, ev: Event<C, V>) {
    let sub = ev.subscription();
    if self.needs_rescan.contains_key(&sub) || self.suppressed_rescan.contains_key(&sub) {
      // An ordinary delta is dominated by the parked `Rescan` — suppress it. But a source
      // `Rescan` is an INDEPENDENT coverage-loss signal that may name a different located key
      // under the same root; merge it into the parked debt (`merge_max` widens the key to the
      // common ancestor covering both losses) instead of discarding it, or its subtree is
      // never re-enumerated (no silent loss under backpressure).
      if ev.is_rescan() {
        self.park_rescan_event(ev);
      } else {
        // A suppressed ordinary delta is still a coverage loss for the sub: advance its sticky
        // loss serial (the rescan-merge path already does so, inside `park_rescan_event`). A
        // barrier installed BEFORE this suppression then observes the advance and resolves
        // `Dominated`, never a false `Delivered` for a change it hid behind the parked `Rescan`.
        // And the parked debt must be made to actually COVER what was just dropped, both
        // spatially and temporally — see `widen_parked_debt`.
        self.widen_parked_debt(&ev);
      }
      return;
    }
    match self.events.try_send(ev) {
      Ok(()) => {}
      // An already-minted `Rescan` carries its own strictly-dominating epoch — a re-point's is the
      // rebased base its new root's raw-0/raw-1 events tie-or-exceed, so a fresh `shed_rescan` (one
      // past the high-water) would dominate and silently drop them. Park it UNCHANGED; an
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

  /// The single **coverage-loss choke point**: records that `sub` just lost coverage — its change
  /// is now owed as a dominating `Rescan` rather than as a delivery — and moves BOTH loss clocks a
  /// pending sync reads.
  ///
  /// - the per-subscription sticky [`loss_serial`](Self::loss_serial), snapshotted at INSTALL, so a
  ///   loss during the install-to-resolve window resolves the barrier `Dominated` even after the
  ///   parked debt has been published and cleared;
  /// - the shared [`loss_gen`](Self::loss_gen), snapshotted by the CALLER in
  ///   [`Tributaries::sync`], so a loss the owner processes in the call-to-install window — which
  ///   the install-time snapshot is structurally blind to — dominates the barrier too.
  ///
  /// Every path that leaves a subscription owing a re-enumeration instead of a delivery must route
  /// through here, and exactly one bump site is what keeps the two clocks in step: the ordinary
  /// delta suppressed behind standing debt ([`try_emit`](Self::try_emit)), the overflow shed
  /// ([`park_rescan`](Self::park_rescan)), the already-minted `Rescan` parked unchanged
  /// ([`park_rescan_event`](Self::park_rescan_event)), and the terminal/rollback `Rescan` parked for
  /// every subscriber of a root ([`rescan_live_root`](Self::rescan_live_root)). A `Rescan` that is
  /// successfully DELIVERED is not a loss to note here — it is on the stream, and the
  /// `dominate_syncs_*` family resolves the barriers riding it.
  fn note_loss(&mut self, sub: Subscription) {
    *self.loss_serial.entry(sub).or_insert(0) += 1;
    self.loss_gen.fetch_add(1, Ordering::SeqCst);
  }

  /// Advances ONLY the shared generation — never a subscription's `loss_serial` — for a `Rescan`
  /// that is **delivered** rather than parked: it stands in for the barriers already installed
  /// under it (which the `dominate_*` family resolves directly), and it must equally stand in for
  /// one whose caller had already CALLED but whose install has not run yet. Without this, that
  /// caller's barrier would find no debt parked, an unmoved `loss_serial`, and a clean flush, and
  /// would report `Delivered` for a change the `Rescan` replaced — the very asymmetry the
  /// installed case is careful to avoid.
  ///
  /// The serial is deliberately left alone. A `Rescan` fans out to every subscriber of its root,
  /// so bumping the serial here would move it for SIBLING subscriptions and silently redefine
  /// their install-to-resolve window; the shared generation only governs the call-to-install
  /// window, where over-domination costs a caller nothing but a re-enumeration.
  fn note_domination(&self) {
    self.loss_gen.fetch_add(1, Ordering::SeqCst);
  }

  /// Sheds `sub` to a parked dominating [`Rescan`](crate::EventKind::Rescan) — the
  /// per-subscription overflow shed after an **ordinary delta** to it found the channel full
  /// (design backpressure doc), mirroring the fs layer's `LagState::Lagged` one level up. An
  /// already-minted `Rescan` that overflows takes [`park_rescan_event`](Self::park_rescan_event)
  /// instead (parked unchanged at its own epoch, never re-minted).
  ///
  /// This is the sole overflow-shed primitive now: a `Covered`-outside newcomer no longer bridges
  /// through here — set-cover grows the source's coverage with an **awaited** [`Source::grow`]
  /// applied before its `Ok` (a failed grow fails the watch instead, grow-before-commit R1), so a
  /// committed newcomer's coverage is live before `watch()` returns and owes no bridging `Rescan`.
  ///
  /// Looks up `sub`'s covered key (the subtree the consumer must re-enumerate) and its recorded
  /// caller value, mints a **non-rebasing** strictly-dominating epoch
  /// ([`EpochLedger::shed_rescan`]), and merges them into `needs_rescan` keeping the newest/widest
  /// key, the max epoch, and the baked value (widen-safe: [`merge_max`]) so the flushed Rescan is
  /// attributable after teardown (design §3). Finally it drops `sub`'s now-suspect buffered
  /// coalescer deltas — they are dominated by the parked `Rescan`, so emitting them later would
  /// deliver a stale epoch after it. It DROPS rather than forgets: a parked subscription is
  /// still live (its stream resumes with the flushed `Rescan`), so its registered debounce
  /// policy keeps governing its later events.
  ///
  /// A subscription with no live key (raced retirement) is not parked — a stale parked
  /// `Rescan` would be co-retired anyway, and there is no subtree left to name.
  fn park_rescan(&mut self, sub: Subscription) {
    self.note_loss(sub);
    let Some(key) = self.subsumer.subscription_key(sub).map(<[C]>::to_vec) else {
      return;
    };
    let value = self.subsumer.subscription_value(sub).cloned();
    let epoch = self.epochs.shed_rescan(sub);
    let target = if self.unclaimed.contains(&sub) {
      &mut self.suppressed_rescan
    } else {
      &mut self.needs_rescan
    };
    merge_max(target, sub, key, epoch, value);
    if let Some(coalescer) = self.coalescer.as_mut() {
      coalescer.drop_subscription(sub);
    }
  }

  /// The key a per-subscription recovery [`Rescan`](crate::EventKind::Rescan) for `sub` must
  /// name: `sub`'s **own registered key**, falling back to `root_key` only for a subscription
  /// the side table can no longer resolve (a raced retirement, where the wider key is the
  /// only honest thing left to say and nobody is left to act on it anyway).
  ///
  /// Every subscription's key is at-or-under the armed root it rides, so this only ever
  /// **narrows** — and narrowing is what keeps a recovery instruction inside the boundary the
  /// caller actually subscribed to. A root-wide loss (a death, a rollback, a widen's
  /// disarm/re-arm gap) makes everything each subscriber owns uncertain and nothing more:
  /// naming the shared physical root instead would tell a consumer watching `/a/b/deep` to
  /// re-enumerate `/a`, which is neither its data nor its business, and would make one
  /// subscriber's localized recovery cost every sibling a full re-crawl.
  fn rescan_key_for(&self, sub: Subscription, root_key: &[C]) -> Vec<C> {
    self
      .subsumer
      .subscription_key(sub)
      .map_or_else(|| root_key.to_vec(), <[C]>::to_vec)
  }

  /// Repairs the parked debt of `ev`'s subscription so it genuinely covers `ev`, which
  /// [`try_emit`](Self::try_emit) is about to discard behind that debt: widens the parked key
  /// to the common ancestor of itself and **every** affected endpoint of `ev`, and lifts the
  /// parked epoch to a freshly-minted strictly-dominating
  /// [`shed_rescan`](epoch::EpochLedger::shed_rescan). Also moves both loss clocks, exactly as
  /// every other coverage loss does ([`note_loss`](Self::note_loss)).
  ///
  /// Neither half is optional, and neither was safe to assume:
  ///
  /// - **Spatially** — a parked debt is not always the whole subscription. A source-emitted,
  ///   terminal, restore or re-point `Rescan` is parked *unchanged* at its own located key
  ///   ([`park_rescan_event`](Self::park_rescan_event)), and a later delta in a disjoint
  ///   sibling subtree is not covered by it. Suppressing that delta against `Rescan(a/x)`
  ///   loses `a/y/file` outright: no event, and no recovery instruction that reaches it.
  /// - **Temporally** — the parked epoch was minted *before* this event. A consumer applying
  ///   dominance would sort the recovery signal **below** the change it is supposed to
  ///   replace, and could legitimately ignore it. Only a post-loss mint restores strict
  ///   domination.
  ///
  /// The fresh mint is taken here, at the moment a later event is actually suppressed —
  /// **not** when the `Rescan` was parked. Re-minting at park time is precisely what
  /// [`park_rescan_event`](Self::park_rescan_event) must not do: a re-point `Rescan`'s epoch
  /// is the rebased floor its new root's raw-0 events tie, and inflating it would dominate
  /// and silently drop them. That calibration is valid right up until a later event is lost
  /// behind it, which is here. By then the lost event has already been stamped, so
  /// `high_water.next()` strictly exceeds it while later same-generation deliveries — clamped
  /// up to high-water by [`stamp`](epoch::EpochLedger::stamp) — still tie rather than sort
  /// under it.
  ///
  /// A subscription with no parked entry in either map cannot reach here (`try_emit` gates on
  /// exactly that), but the lookup is fallible anyway: both maps are checked, so a debt that
  /// moved between them on a claim is still repaired.
  fn widen_parked_debt(&mut self, ev: &Event<C, V>) {
    let sub = ev.subscription();
    self.note_loss(sub);
    let epoch = self.epochs.shed_rescan(sub);
    for target in [&mut self.needs_rescan, &mut self.suppressed_rescan] {
      let Some(parked) = target.get_mut(&sub) else {
        continue;
      };
      widen_to_cover(&mut parked.key, ev.key());
      // A whole `Moved` has two affected endpoints, and the debt must cover both — the
      // subscription that lost it saw the object leave one key and arrive at another.
      if let Some(from) = ev.move_from() {
        widen_to_cover(&mut parked.key, from);
      }
      parked.epoch = parked.epoch.max(epoch);
    }
  }

  /// Parks an already-minted synthetic [`Rescan`](crate::EventKind::Rescan) that overflowed
  /// the channel **UNCHANGED** (design backpressure doc): merges its own `key`, `epoch`,
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
    let sub = ev.subscription();
    self.note_loss(sub);
    let target = if self.unclaimed.contains(&sub) {
      &mut self.suppressed_rescan
    } else {
      &mut self.needs_rescan
    };
    merge_max(
      target,
      sub,
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
  /// **Suppression by owner state** (the correctness boundary): an entry whose sub is in
  /// [`unclaimed`](Self::unclaimed) — its committed [`WatchGrant`] still in flight — is **retained
  /// without being offered**. That debt is owed to nobody yet (the caller never obtained the
  /// subscription), so delivering it would emit a `Rescan` for a subscription the caller never
  /// received. The suppression lifts the instant the owner processes the grant's
  /// [`Cleanup::Claim`] (the caller claimed it — now genuinely owed) and the entry
  /// is purged if instead its [`Cleanup::DropOrphan`] fires. Because `unclaimed` is
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
    #[cfg(test)]
    {
      self.last_flush_visited = 0;
    }
    // A full channel accepts nothing this pass — skip even the walk (// a pass used to clone, then merely traverse, every retained entry against an
    // already-full channel; with the map legitimately as large as a caller's peak
    // cohort, an O(map) walk per tick is real CPU).
    if self.events.is_full() {
      return;
    }
    let len = self.needs_rescan.len();
    if len == 0 {
      return;
    }
    // LAZY round-robin resume: candidates come one BTreeMap range
    // probe at a time — never a materialized snapshot of the map (a capacity-one
    // drain over a cohort-sized map would otherwise pay an O(map) collect per
    // delivered slot, O(map squared) overall). `resume` = retry this key first,
    // inclusive (its offer found the channel full last pass — it was NOT delivered;
    // sound even if it was removed meanwhile: the range just starts at the next
    // greater key). After each handled key the probe continues EXCLUSIVE past it,
    // wrapping once; the pass visits at most `len` keys, and ends at the first Full.
    // Per-pass work is proportional to the offers the channel had room for plus the
    // one Full probe — unclaimed debt lives in `suppressed_rescan` and costs this
    // pass nothing.
    let mut resume = self.flush_cursor.take();
    let mut exclusive = false;
    for _ in 0..len {
      #[cfg(test)]
      {
        self.last_flush_visited += 1;
      }
      let bound = match (&resume, exclusive) {
        (Some(at), false) => (std::ops::Bound::Included(*at), std::ops::Bound::Unbounded),
        (Some(at), true) => (std::ops::Bound::Excluded(*at), std::ops::Bound::Unbounded),
        (None, _) => (std::ops::Bound::Unbounded, std::ops::Bound::Unbounded),
      };
      let next = self
        .needs_rescan
        .range(bound)
        .next()
        .or_else(|| self.needs_rescan.iter().next())
        .map(|(&sub, _)| sub);
      let Some(sub) = next else {
        break;
      };
      resume = Some(sub);
      exclusive = true;
      // An unclaimed sub's debt lives in `suppressed_rescan`, never here (// the partition is what keeps this pass's cost offer-proportional): parks target
      // the map matching the sub's claim state, and the claim/orphan transitions move
      // or purge entries.
      debug_assert!(
        !self.unclaimed.contains(&sub),
        "offerable parked debt for an unclaimed sub — a park missed the partition"
      );
      let Some(parked) = self.needs_rescan.get(&sub) else {
        continue;
      };
      // Mint the owed Rescan carrying the value captured at park time (design §3): the sub or its
      // root may already be retired, so the value cannot be re-resolved here — it rides the entry.
      let mut event = Event::rescan(sub, parked.key.clone(), parked.epoch);
      event.set_value(parked.value.clone());
      match self.events.try_send(event) {
        Ok(()) => {
          // The PUBLISH half of the same invariant `note_domination` enforces at the
          // delivered-`Rescan` choke point: a parked re-enumeration reaching the stream IS a
          // delivered covering `Rescan`, so any barrier whose caller's `sync()` preceded it must be
          // dominated by it too. A caller who snapshotted the generation AFTER this debt parked (its
          // bump already folded into the snapshot) and installs after this publish-and-clear would
          // otherwise find an empty debt map, an unmoved `loss_serial`, and a clean flush — and
          // falsely resolve `Delivered` for a pre-call re-enumeration this publish just handed it.
          // Advancing the shared generation here is the only trace that survives the clear.
          self.note_domination();
          self.needs_rescan.remove(&sub);
        }
        Err(async_channel::TrySendError::Closed(_)) => {
          // Teardown: the consumer is gone, so nothing was published — clear the entry WITHOUT
          // dominating (no re-enumeration reached any barrier).
          self.needs_rescan.remove(&sub);
        }
        Err(async_channel::TrySendError::Full(_)) => {
          // The channel filled: retry THIS key (inclusive) next tick. Not published, so no
          // domination.
          self.flush_cursor = Some(sub);
          return;
        }
      }
    }
    self.flush_cursor = None;
  }

  /// Resolves one raw event's root and fans it out to every covering, admitting
  /// subscriber, stamping each delivery in that subscriber's own monotone epoch space
  /// (design §5/§7/§8). An event whose root has no live entry (its subscription(s) were
  /// dropped between the source emitting it and us routing it) fans out to nothing.
  ///
  /// A [`Moved`](crate::EventKind::Moved) is decomposed per subscriber inside
  /// [`fan_out`](crate::route::fan_out) (both endpoints → the whole move; source only → a
  /// synthesized `Removed`; destination only → a synthesized `Created`), and the filter +
  /// interest gate below runs against that already-projected delivery.
  ///
  /// Returns the stamped deliveries **and** the subscriptions whose filter predicate
  /// unwound while producing them. The caller applies the quarantine and decides where
  /// each delivery goes, because a delivery a panic fail-opened must not follow the
  /// ordinary buffered path (see [`fan_out_and_push`](Self::fan_out_and_push)).
  fn fan_out_raw(
    &mut self,
    raw: &SourceEvent<C, S::Handle>,
  ) -> (Vec<Event<C, V>>, Vec<Subscription>) {
    // Disjoint field borrows: `subsumer` resolves the root/coverage/interest, `filters`
    // the per-subscription filter, `epochs` owns the per-subscription stamp state.
    let (subsumer, filters, epochs) = (&self.subsumer, &self.filters, &mut self.epochs);
    let Some((_root_key, subscribers)) = subsumer.root_view(raw.handle()) else {
      return (Vec::new(), Vec::new());
    };
    // The coordinate this raw event's location is expressed in rides on the EVENT
    // (`RoutableEvent::captured_root_depth`), not on the root the handle resolves to
    // here: an in-place widen keeps the handle — and its queue — so a change captured
    // under the older, deeper root is still drained on this path afterwards.
    let routable = SourceRoutable::<C, V, S::Handle>::new(raw);
    // Subscriptions whose filter predicate UNWOUND during this fan-out. The gate
    // below borrows `filters` immutably, so the quarantine is applied by the caller,
    // after the fan-out returns (see [`quarantine_filters`](Self::quarantine_filters)).
    let poisoned: core::cell::RefCell<Vec<Subscription>> = core::cell::RefCell::new(Vec::new());
    // This owner's filter-plane latch, carried through the gate's immutable borrows and
    // written back to `self` once they end. Seeded from the standing latch so a batch
    // fanned out after one was set enters no predicate at all, and set by a disposal that
    // had to forget its payload (see [`Owner::filter_payload_forgotten`]).
    let forgotten = core::cell::Cell::new(self.filter_payload_forgotten);
    // `raw.epoch()` is the raw source epoch on the event's current root; `set_epoch` binds
    // the umbrella stamp, rebasing away the raw epoch (which restarts per kernel arm).
    let raw_epoch = raw.epoch();
    let events = epochs.stamp_and_fan_out(
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
      // filter the raw event would let it mis-read a provisional epoch/absent value;
      // the pre-delivery view makes that impossible while exposing the correct key/kind/path.
      |sub, event: &Event<C, V>| {
        subsumer
          .subscription_interest(sub)
          .is_some_and(|interest| interest.admits(event.kind()))
          && filters.get(&sub).is_some_and(|gate| {
            // This subscription's gate was already retired by an earlier unwind: admit
            // without entering the predicate again. The check is per-SUBSCRIPTION, so a
            // sibling registered with a clone of the same `Filter` still runs it — see
            // [`SubscriptionFilter`].
            if gate.quarantined {
              return true;
            }
            // This OWNER has already had to forget a filter payload, so no predicate is
            // entered here again — see [`Owner::filter_payload_forgotten`]. The
            // subscription joins the quarantine list, which gives it exactly the terms a
            // predicate of its own would have earned: fail open, stay live and covered,
            // and be owed a dominating `Rescan` that tells its consumer in-band that its
            // admission gate is gone. Read live rather than captured, so a subscription
            // fanned out later in THIS batch is covered by a latch this batch set.
            if forgotten.get() {
              poisoned.borrow_mut().push(sub);
              return true;
            }
            // The predicate is ARBITRARY caller code running inline in the one
            // owner task, so its unwind is contained here rather than allowed to
            // propagate. Uncontained it takes the whole owner with it: the shared
            // event stream closes, every UNRELATED subscription stops, and later
            // `watch` calls answer `Closed` — one tenant's filter denying service
            // to every other, reported as an ordinary end of stream.
            //
            // A panicking predicate FAILS OPEN. It admits this delivery and, at
            // `quarantine_filters` below, has THIS SUBSCRIPTION's gate marked retired
            // so it never runs again for it. Over-delivery is a
            // subscription receiving changes it would have filtered out; the
            // alternative — treating the panic as a rejection — silently drops
            // changes the subscription is covered for, which is exactly the loss
            // this codebase never allows to be silent. The quarantined
            // subscription is also owed a dominating `Rescan`, so its consumer
            // learns in-band that its admission gate is gone and re-enumerates.
            //
            // The caught PAYLOAD is caller data too, and disposing of it runs caller
            // code: a `panic_any` payload's `Drop` is as arbitrary as the predicate
            // was. Dropping it here — outside the boundary that just caught it —
            // would let a panicking destructor start a SECOND unwind straight through
            // the owner, defeating the containment for every unrelated subscription.
            // It is retired in its own contained domain instead — and a payload that
            // had to be FORGOTTEN there latches the owner's whole filter plane, which
            // is what turns "one leak per subscription" into "one leak per watcher"
            // (see [`Owner::filter_payload_forgotten`]).
            let input = FilterInput::new(event.key(), event.kind(), event.location());
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
              gate.filter.admits(&input)
            })) {
              Ok(verdict) => verdict,
              Err(payload) => {
                poisoned.borrow_mut().push(sub);
                if dispose_panic_payload(payload).is_forgotten() {
                  forgotten.set(true);
                }
                true
              }
            }
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
    );
    self.filter_payload_forgotten = forgotten.get();
    (events, poisoned.into_inner())
  }

  /// Retires the admission gate of every subscription whose filter predicate
  /// unwound during a fan-out, and owes each one a dominating
  /// [`Rescan`](crate::EventKind::Rescan).
  ///
  /// The gate is marked retired rather than left in place: a filter that panicked once is
  /// not trustworthy, and re-entering it for every later change would cost the owner an
  /// unwind per event on top of leaving the verdict undefined. The mark is written to
  /// **this owner's per-subscription entry** and never to the caller's `Filter` slot,
  /// which is shared by every clone of that filter — see [`SubscriptionFilter`] for why
  /// retiring through the shared slot would take unrelated subscriptions' filtering down
  /// with it, unrecorded.
  ///
  /// The subscription STAYS LIVE and stays covered. Retiring it instead would
  /// convert a caller's programming error into a coverage loss with no way to
  /// deliver the notice, whereas an over-delivering subscription loses nothing;
  /// the parked `Rescan` — routed through the same loss choke point every other
  /// coverage-loss uses, so both loss clocks move and any barrier riding this
  /// subscription resolves `Dominated` rather than falsely `Delivered` — is what
  /// makes the change of behavior observable in-band.
  ///
  /// The subscription's buffered coalescer entries are **dropped** before that `Rescan` is
  /// parked, exactly as every other path that owes a subscription a dominating `Rescan`
  /// does ([`commit_widen`](Self::commit_widen),
  /// [`rescan_live_root`](Self::rescan_live_root),
  /// [`park_rescan`](Self::park_rescan)). They are older than the debt and re-enumerating
  /// its key covers every one of them; left buffered, the settle timer releases them after
  /// the `Rescan` has been published and cleared, sorting a lower epoch behind a signal
  /// that claims to dominate it. DROP, not forget: the subscription stays live, so its
  /// registered debounce policy must keep governing its later events.
  fn quarantine_filters(&mut self, poisoned: &[Subscription]) {
    for &sub in poisoned {
      let Some(gate) = self.filters.get_mut(&sub) else {
        continue;
      };
      gate.quarantined = true;
      let Some(key) = self.subsumer.subscription_key(sub).map(<[C]>::to_vec) else {
        continue;
      };
      if let Some(coalescer) = self.coalescer.as_mut() {
        coalescer.drop_subscription(sub);
      }
      self.note_loss(sub);
      let value = self.subsumer.subscription_value(sub).cloned();
      let epoch = self.epochs.shed_rescan(sub);
      let target = if self.unclaimed.contains(&sub) {
        &mut self.suppressed_rescan
      } else {
        &mut self.needs_rescan
      };
      merge_max(target, sub, key, epoch, value);
      self.dominate_syncs_of_subscription(sub);
    }
  }

  /// Reconciles a raw source event whose root the [`Source`] has already forgotten
  /// ([`Source::root_key`] answers `None`) by retiring that **dead root** through the shared
  /// [`retire_root_with_terminal_rescan`](Self::retire_root_with_terminal_rescan) primitive and
  /// returning `true` (the run loop then skips its ordinary fan-out). Returns `false` for an
  /// event on a still-live root (an ordinary delivery, or an overflow `Rescan` on a live root),
  /// which the caller fans out normally — an overflow re-enumeration is a coverage-loss signal,
  /// not a retirement.
  ///
  /// A dead root is retired on **any** terminal event kind, not just a `Rescan`.
  /// The lower fs layer can surface a watched-root deletion as a user-visible `Removed` FOLLOWED
  /// BY a terminal `Rescan`; retiring only on the `Rescan` would leave the dead root recorded
  /// across the `Removed`, so a caller that observes the `Removed` and re-`watch`es the same path
  /// **before** the queued `Rescan` is processed (the command-biased select loop runs the `watch`
  /// first) is classified `Covered` by the still-recorded dead handle. Retiring eagerly on the
  /// `Removed` narrows that window; the structural close is [`reconcile_watch`](Self::reconcile_watch),
  /// which validates a `Covered` plan's covering root against [`Source::root_key`] and retires-and-
  /// re-plans past a dead one regardless of terminal-event timing.
  ///
  /// A non-`Rescan` terminal event (a root `Removed`) is **not** separately fanned out: it is
  /// dominated by the terminal `Rescan` this retire parks for every subscriber (redundant), and
  /// routing it through `fan_out_and_push` under debounce would admit it to the coalescer, where the
  /// retire's `drop_subscription` then discards it — buffered-then-dropped, silently losing the
  /// promised event. The coverage loss is signaled by the parked `Rescan` alone, which
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
  /// The single live-event consumption funnel BOTH source paths share — the select arm and
  /// the command-fairness valve's forced poll: dead-root retirement, retained-cover
  /// degradation on a live-root `Rescan`, then fan-out, in that one order. A coverage-loss
  /// signal can never reach subscribers with the stale claim left standing on either path.
  fn consume_source_event(&mut self, event: &SourceEvent<C, S::Handle>) {
    if !self.retire_if_dead(event) {
      // A cookie (ours, another instance's, or a crashed process's leftover —
      // and the unlink events of all of them) is CONSUMED here: never fanned
      // out, never coalesced, never delivered. Suppression is namespace-total,
      // so it can never depend on the pending map. A `Rescan` is never a
      // cookie (checked first), because it is coverage information and is
      // structurally unmaskable.
      if !event.kind().is_rescan() && self.source.is_sync_artifact(event.key()) {
        self.resolve_matching_pending_sync(event);
        return;
      }
      // A make-before-break `replace` commits an epoch-bumped full-root `Rescan` on the PRESERVED
      // handle for each leg, so a diverging-then-rolled-back widen leaves a stale `Rescan` whose key
      // names the transient divergent root the handle no longer watches. `retire_if_dead` saw the
      // handle LIVE (rolled back to its current root), so this reaches here as a live-root `Rescan`;
      // fanning or parking it at its stale, DISJOINT key would merge into the rollback's parked debt
      // and widen the owed re-enumeration to their common ancestor (up to `/`). The handle's CURRENT
      // `root_key` is authoritative: clamp such a disjoint live-root `Rescan` to it (a current-root
      // `Rescan` correctly and safely dominates everything under the live root), so BOTH the fan-out
      // and the domination below use the safe current-root key.
      let clamped = self.clamp_disjoint_live_root_rescan(event);
      let event = clamped.as_ref().unwrap_or(event);
      self.degrade_retained_cover_on_rescan(event);
      self.fan_out_and_push(event);
      // A `Rescan` can DOMINATE a pending cookie — a loss that ate the
      // cookie's own event elects a covering signal at that position, and
      // re-enumeration meets the barrier just as delivery would. It is
      // resolved ONLY NOW, strictly AFTER `fan_out_and_push` has published or
      // durably parked the `Rescan`: a barrier that resolved first would let
      // a caller waking on another thread drain past a `Rescan` that is not
      // yet in the channel or `needs_rescan` — the prohibited half-barrier.
      if event.kind().is_rescan() {
        self.dominate_pending_syncs(event);
      }
    }
  }

  /// A live-root `Rescan` whose key is DISJOINT from the handle's current
  /// [`root_key`](LocalSource::root_key) is the stale transient-root artifact a make-before-break
  /// [`replace`](LocalSource::replace)/rollback left on the preserved handle (see
  /// [`consume_source_event`](Self::consume_source_event)); return a copy clamped to the current root
  /// so it dominates the live root's subtree without widening any parked debt to a common ancestor.
  ///
  /// Returns `None` — use the event unchanged — for a non-`Rescan`, a handle with no live root, or a
  /// `Rescan` already at/under the current root or an ancestor of it (either already covers the live
  /// root's subtree correctly and safely).
  ///
  /// # The clamp restates the coordinate, it does not just re-key
  ///
  /// The stale event's `location` was minted against the TRANSIENT root, and the capture anchor every
  /// delivery is rebased by is the `key`/`location` pair
  /// ([`captured_root_depth`](crate::route::RoutableEvent::captured_root_depth)). Rewriting the key to
  /// the live root while carrying that location forward would hand fan-out a pair describing no root at
  /// all — for a live `/a` and a stale `Rescan(/z/d1/d2/d3)` located `[d1, d2, d3]`, the inferred anchor
  /// underflows to zero and the subscription at `/a` is told to re-enumerate `/a` at `[d2, d3]`: a
  /// subtree of its own watch that the loss never touched, and one whose stale state it would then
  /// keep. The re-key therefore goes through [`SourceEvent::rekeyed_at_root`], which root-anchors the
  /// location as part of the same step — the clamped key IS the live root, so the empty location is
  /// exactly what it means, and the pair stays the coordinate it claims to be.
  fn clamp_disjoint_live_root_rescan(
    &self,
    event: &SourceEvent<C, S::Handle>,
  ) -> Option<SourceEvent<C, S::Handle>> {
    if !event.kind().is_rescan() {
      return None;
    }
    let root_key = self.source.root_key(event.handle())?;
    let key = event.key();
    // Disjoint = the `Rescan`'s key is neither at/under the current root (`key` has `root_key` as a
    // prefix) nor an ancestor of it (`root_key` has `key` as a prefix). Only a disjoint key is the
    // stale transient-root event; a `Rescan` on either side of the current root already covers it.
    if key.starts_with(root_key.as_slice()) || root_key.starts_with(key) {
      return None;
    }
    Some(event.rekeyed_at_root(root_key))
  }

  /// Initiates one sync barrier: place the cookie (awaited, caller-bounded,
  /// resolving at WRITE-complete) and park the caller's reply until the funnel
  /// sees the cookie's own event — or a covering `Rescan` dominates it.
  ///
  /// The subscription's own key IS the cookie's directory hint: the binding
  /// owns path shapes (it resolves a file key to its parent), and the key is
  /// always inside the root's retained cover — the ROOT's directory need not
  /// be, since set-cover pruning can leave it outside actual kernel coverage.
  ///
  /// `loss_gen_at_call` is the shared [`loss_gen`](Self::loss_gen) the CALLER snapshotted before it
  /// enqueued the request; comparing it against the live generation is what makes the barrier's loss
  /// window open at the call rather than here.
  async fn on_sync(
    &mut self,
    sub: Subscription,
    loss_gen_at_call: u64,
    mut reply: futures_channel::oneshot::Sender<Result<SyncOutcome, SyncError>>,
  ) -> SyncAdmit {
    // The caller's `sync()` deadline can fire during admission — dropping the response receiver —
    // before the owner ever dispatches this request. Minting a token, awaiting `begin_sync`, and
    // parking a PendingSync for a reply nobody will read is wasted cookie work and a strand the
    // loop-top prune must later reap. A canceled reply owes nothing: skip it before any cookie work.
    if reply.is_canceled() {
      return SyncAdmit::Done;
    }
    // The in-flight bound, read BEFORE any cookie work: a refused barrier must
    // leave no marker on the filesystem, so it has to be refused ahead of
    // `begin_sync`, not after it (see [`MAX_PENDING_SYNCS`]). Reaping the
    // callers who already went away first means a caller is only ever refused
    // against barriers that are genuinely still live.
    self.prune_abandoned_syncs();
    if self.pending_syncs.len() >= MAX_PENDING_SYNCS {
      let _ = reply.send(Err(SyncError::Busy));
      return SyncAdmit::Done;
    }
    let (Some(root), Some(dir_key)) = (
      self.subsumer.subscription_root(sub),
      self.subsumer.subscription_key(sub).map(<[C]>::to_vec),
    ) else {
      let _ = reply.send(Err(SyncError::UnknownSubscription));
      return SyncAdmit::Done;
    };
    self.sync_seq += 1;
    // An unguessable nonce keyed by the owner's OS-random secret: another
    // writer under the tree cannot predict it, so it cannot pre-create a
    // colliding marker whose stale event would falsely complete this sync.
    let nonce = {
      use std::hash::{BuildHasher, Hasher};
      let mut hasher = self.sync_nonce_seed.build_hasher();
      hasher.write_u64(self.sync_seq);
      hasher.finish()
    };
    let token = SyncToken::new(
      sub.instance().get(),
      std::process::id(),
      self.sync_seq,
      nonce,
    );
    // The cookie write is AWAITED here — never the OBSERVATION, which arrives through the very `next`
    // pump this owner drives (awaiting that would deadlock by construction). The await is FORCED onto
    // this loop by the `&mut self.source` + conditional-`Send` seam, exactly as `arm`/`grow` are:
    // `R::timeout` needs a `Send` inner future (which `LocalSource::begin_sync` is not) and
    // `R::timeout_local` is unconditionally `!Send` (which would break the `Send` promise `parts()`
    // makes on the `Source` path), so no generic timer can bound the write while preserving the run
    // future's conditional `Send`.
    //
    // So instead of a timer, RACE the write against two unconditionally-`Send` signals: the caller's
    // `reply.cancellation()` and the owner's close receiver. A held write (a hung FUSE/NFS mount) can
    // then no longer wedge the loop — cancellation frees the owner within the caller's own deadline,
    // and a close tears down at once. The seam is preserved precisely because both extra arms are
    // `Send` for every source: a `select` of them and `begin_sync` is `Send` iff `begin_sync` is, so
    // the combined future keeps EXACTLY the conditional `Send` the run loop needs (the compile-time
    // owner-`Send` assertions still hold). A cookie the write had already begun self-reaps as the
    // dropped `begin_sync` future unwinds the fs write; a since-parked pending sync is reaped at the
    // loop-top prune.
    let step = {
      // Split-borrow the two owner fields the race touches so they stay disjoint: the close arm reads
      // `&self.closes`, `begin_sync` reborrows `&mut self.source`, and the cancellation arm borrows
      // `&mut reply` (a local, disjoint from both). Every use of `reply` is deferred to AFTER this
      // block, once the cancellation future's borrow of it is released.
      let closes = &self.closes;
      let source = &mut self.source;
      futures_util::select_biased! {
        // The write is polled FIRST so a result that is ALREADY ready wins over a simultaneously-ready
        // cancellation or close: the fs driver may have buffered its `Ok(path)` (its own
        // `reply.send(Ok)` already succeeded, so its send-failure self-reap will NOT run), and dropping
        // that ready result unread would strand the cookie it names. Taking it here means an abandoned
        // caller's cookie is reaped deterministically below, never orphaned. A still-PENDING write (a
        // hung mount) is not ready, so close and cancellation below still win and free the owner — the
        // bias only decides a tie, and only a completed write can tie.
        res = source.begin_sync(root, &dir_key, token).fuse() => SyncStep::Began(res),
        // Close outranks cancellation: a requested shutdown abandons a still-in-flight write. A CLOSED
        // close channel means every handle is gone (the caller with them), so it lands as an abandon,
        // not a threaded close — no one is left to acknowledge, and the command channel drives teardown.
        close = closes.recv().fuse() => match close {
          Ok(close_reply) => SyncStep::Close(close_reply),
          Err(_) => SyncStep::Canceled,
        },
        // The caller timed out or dropped its `sync()` wait: its receiver is gone.
        () = reply.cancellation().fuse() => SyncStep::Canceled,
      }
    };

    match step {
      // Thread the close back so the run loop's teardown consumes it exactly once — no loss, no
      // double-acknowledge.
      SyncStep::Close(close_reply) => {
        // Abandoning an in-flight write: hand the source the token so a cookie the write already
        // created (a delivered-but-unread `Ok` — the fs `reply.send` succeeded, so its own
        // self-reap will NOT run) is reaped, and one still in the pool tombstones so its claim
        // self-reaps. The owner never learned the cookie key here (only a completed `begin_sync`
        // returns it), so this token-cancel is the only thing that can free the file.
        self.source.cancel_sync(root, token);
        SyncAdmit::CloseRequested(close_reply)
      }
      // Abandon: drop `reply` without parking or writing further. The caller is gone (timeout, drop,
      // or every handle away); a cookie the write began self-reaps as the dropped write unwinds, and
      // the cookie's own event — should it still arrive — is suppressed as a sync artifact, so nothing
      // spurious is delivered.
      SyncStep::Canceled => {
        // Same as the close arm: the caller is gone and never received the cookie key, so cancel
        // by token — the only handle on a write that may have landed after this arm won the race.
        self.source.cancel_sync(root, token);
        SyncAdmit::Done
      }
      SyncStep::Began(Ok(cookie_key)) => {
        self.admit_begun_cookie(cookie_key, sub, root, loss_gen_at_call, reply);
        SyncAdmit::Done
      }
      SyncStep::Began(Err(err)) => {
        let _ = reply.send(Err(err));
        SyncAdmit::Done
      }
    }
  }

  /// Admits a COMPLETED cookie write (its `begin_sync` returned `Ok`): reaps it inline when the caller
  /// has ALREADY gone, otherwise parks the [`PendingSync`].
  ///
  /// The reap path is why the write is polled first in [`on_sync`](Self::on_sync)'s race: the fs driver
  /// may buffer a successful `Ok(path)` reply just as the caller's deadline fires, and taking that ready
  /// result (rather than dropping it for the simultaneously-ready cancellation) is the ONLY thing that
  /// frees its file — the driver already saw its own `reply.send(Ok)` succeed, so its send-failure
  /// self-reap will not run. Skipping the install also spares `pending_syncs` an entry the loop-top
  /// prune would immediately reap.
  fn admit_begun_cookie(
    &mut self,
    cookie_key: Vec<C>,
    sub: Subscription,
    root: S::Handle,
    loss_gen_at_call: u64,
    reply: futures_channel::oneshot::Sender<Result<SyncOutcome, SyncError>>,
  ) {
    if reply.is_canceled() {
      self.source.end_sync(root, &cookie_key);
      return;
    }
    let loss_serial_at_install = self.loss_serial.get(&sub).copied().unwrap_or(0);
    // Domination the cookie cannot un-owe, decided from the CALLER'S call rather than from this
    // install — the two probes cover disjoint halves of the pre-cookie past:
    //
    // - standing parked debt: a loss still owed at install (it publishing-and-clearing before the
    //   cookie would leave the serial unchanged and `needs_rescan` empty at resolution, so only this
    //   snapshot still separates it from a clean sync);
    // - a moved loss GENERATION: a loss the owner processed while the request sat in the mailbox. Its
    //   kernel event predates the caller's `sync()`, yet it can have parked, published and cleared
    //   entirely inside that window — advancing `loss_serial` BEFORE the snapshot above is taken and
    //   emptying the debt maps again — so neither the standing-debt probe nor the install-to-resolve
    //   `lost_during_window` comparison can see it. Only the caller's own pre-enqueue snapshot can.
    //
    // The generation is GLOBAL, so a loss on an UNRELATED subscription inside that window dominates
    // this barrier too. That is a deliberate conservatism: it costs a false `Dominated` (the caller
    // re-enumerates — safe), never a false `Delivered`; the window is a few owner-loop iterations wide;
    // and the precise per-subscription `loss_serial` still governs the long install-to-resolve window.
    let dominated_at_install = self.needs_rescan.contains_key(&sub)
      || self.suppressed_rescan.contains_key(&sub)
      || self.loss_gen.load(Ordering::SeqCst) != loss_gen_at_call;
    self.pending_syncs.push(PendingSync {
      cookie_key,
      sub,
      root,
      loss_serial_at_install,
      dominated_at_install,
      reply,
    });
  }

  /// The cookie arrived: everything the backend reported before its write has
  /// already exited the pipeline ahead of it (per-source FIFO). Flush what the
  /// debounce still holds for that subscription, then resolve the barrier —
  /// `Delivered` when that flush was clean, `Dominated` when the subscription
  /// owes a `Rescan` instead (an earlier loss, or a delta shed to a parked
  /// `Rescan` by a full channel during the flush): the caller must re-read,
  /// not replay, so telling it `Delivered` would risk stale state.
  fn resolve_matching_pending_sync(&mut self, event: &SourceEvent<C, S::Handle>) {
    let Some(idx) = self
      .pending_syncs
      .iter()
      .position(|pending| pending.cookie_key.as_slice() == event.key())
    else {
      return;
    };
    let pending = self.pending_syncs.swap_remove(idx);
    // A loss touched the sub DURING the barrier (serial advanced) — even if its parked Rescan has
    // since been published and cleared — OR debt already stood at install (a pre-call loss the cookie
    // cannot un-owe): either way re-enumeration stands in for delivery.
    let lost_during_window =
      self.loss_serial.get(&pending.sub).copied().unwrap_or(0) != pending.loss_serial_at_install;
    let dominated_at_install = pending.dominated_at_install;
    // Reap the cookie BEFORE the flush. Its observation already happened (its own event is what
    // matched here), and `flush_subscription_now` can UNWIND — it runs `R::now` and clones/orders
    // caller key/value types in the coalescer. Reaping first keeps a flush panic from leaking the
    // marker: once swap-removed, this entry is out of `pending_syncs`, so `Owner::drop` (which reaps
    // only entries still in the vector) would never reap it. The outcome still uses the flush result.
    self.reap_cookie(pending.root, &pending.cookie_key);
    let clean =
      self.flush_subscription_now(pending.sub) && !lost_during_window && !dominated_at_install;
    let outcome = if clean {
      SyncOutcome::Delivered
    } else {
      SyncOutcome::Dominated
    };
    let _ = pending.reply.send(Ok(outcome));
  }

  /// A live-root `Rescan` at or above a pending cookie's key stands in for it:
  /// the loss that ate the cookie already owes the subscriber a
  /// re-enumeration, which is the barrier — met by domination rather than by
  /// delivery.
  fn dominate_pending_syncs(&mut self, event: &SourceEvent<C, S::Handle>) {
    // Reached only for a `Rescan` (the caller gates on it), so this is the delivered-`Rescan`
    // choke point: a barrier already CALLED but not yet installed must be dominated by it too.
    self.note_domination();
    // Dominate by the AFFECTED SUBSCRIPTION, not by cookie-path ancestry — and the affected
    // set is exactly the one `route::fan_out` delivers this `Rescan` to: the subscribers of
    // this root whose own subtree INTERSECTS the rescan's. Cookie-path ancestry
    // (`cookie_key.starts_with(event.key())`) under-killed — a barrier for `/r` (cookie
    // `/r/.cookie`) is not dominated by a descendant loss `Rescan(/r/x)`, so it falsely
    // resolved `Delivered` though its subscriber owes a re-scan. Whole-root equality
    // over-killed the other way: a located `Rescan(/r/x)` is not delivered to a disjoint
    // sibling subscription at `/r/y`, so resolving that sibling's barrier `Dominated` would
    // report a re-enumeration it will never be handed. Matching the delivery set exactly is
    // what keeps both halves honest.
    let handle = event.handle();
    let at = event.key();
    let mut i = 0;
    while i < self.pending_syncs.len() {
      if self.pending_syncs[i].root == handle && self.rescan_affects(self.pending_syncs[i].sub, at)
      {
        let pending = self.pending_syncs.swap_remove(i);
        // Reap BEFORE the (unwinding-capable) flush: once swap-removed, `Owner::drop` no longer reaps
        // this entry, so a flush panic must not precede the reap or the marker leaks.
        self.reap_cookie(pending.root, &pending.cookie_key);
        self.flush_subscription_now(pending.sub);
        let _ = pending.reply.send(Ok(SyncOutcome::Dominated));
      } else {
        i += 1;
      }
    }
  }

  /// Whether a [`Rescan`](crate::EventKind::Rescan) located at `at` is delivered to `sub` —
  /// the router's intersection test ([`route::fan_out`](crate::route::fan_out)), read back
  /// so every consequence of a rescan (domination, debt) applies to exactly the set that
  /// receives it, and never to a disjoint sibling.
  ///
  /// A subscription whose key can no longer be resolved (raced retirement) answers `true`:
  /// over-domination costs its caller a re-enumeration it can still perform, whereas
  /// under-domination would resolve a barrier `Delivered` for a stream that is gone.
  fn rescan_affects(&self, sub: Subscription, at: &[C]) -> bool
  where
    C: PartialEq,
  {
    self
      .subsumer
      .subscription_key(sub)
      .is_none_or(|key| at.starts_with(key) || key.starts_with(at))
  }

  /// Resolves every barrier riding `root` as `Dominated` — the root died, and
  /// `retire_if_dead` has already parked each subscriber a durable terminal
  /// `Rescan` that dominates anything the cookie would have proven.
  fn dominate_syncs_of_root(&mut self, root: S::Handle)
  where
    S::Handle: PartialEq,
  {
    self.note_domination();
    let mut i = 0;
    while i < self.pending_syncs.len() {
      if self.pending_syncs[i].root == root {
        let pending = self.pending_syncs.swap_remove(i);
        let _ = pending.reply.send(Ok(SyncOutcome::Dominated));
        // Best-effort reap even on a dead root: the file may linger (the
        // directory outlived the watch), and `remove_cookie` is idempotent.
        self.reap_cookie(pending.root, &pending.cookie_key);
      } else {
        i += 1;
      }
    }
  }

  /// Resolves every barrier of `sub` as `Dominated` and reaps its cookie —
  /// used when the subscription has just been handed a durable dominating
  /// `Rescan` (a widen re-point, a restore rebind): re-enumeration meets the
  /// barrier, so it must not wait for a cookie whose stream may have moved
  /// under it.
  fn dominate_syncs_of_subscription(&mut self, sub: Subscription) {
    self.note_domination();
    let mut i = 0;
    while i < self.pending_syncs.len() {
      if self.pending_syncs[i].sub == sub {
        let pending = self.pending_syncs.swap_remove(i);
        let _ = pending.reply.send(Ok(SyncOutcome::Dominated));
        self.reap_cookie(pending.root, &pending.cookie_key);
      } else {
        i += 1;
      }
    }
  }

  /// Fails every barrier of `sub` typed — the CALLER unwatched it, which owes
  /// no `Rescan`, so the barrier cannot be met honestly. (Asymmetric with a
  /// root death, which resolves `Dominated`.)
  fn retire_syncs_of_subscription(&mut self, sub: Subscription) {
    let mut i = 0;
    while i < self.pending_syncs.len() {
      if self.pending_syncs[i].sub == sub {
        let pending = self.pending_syncs.swap_remove(i);
        let _ = pending.reply.send(Err(SyncError::Retired));
        // The root lives on — the cookie is a real file that must not leak.
        self.reap_cookie(pending.root, &pending.cookie_key);
      } else {
        i += 1;
      }
    }
  }

  /// Drops barriers whose caller went away (timed out, or dropped the future):
  /// the cookie is inert — its events are suppressed by the namespace forever
  /// — so the entry is simply reaped, keeping the map bounded by LIVE waiters
  /// rather than by total syncs ever issued.
  fn prune_abandoned_syncs(&mut self) {
    let mut i = 0;
    while i < self.pending_syncs.len() {
      if self.pending_syncs[i].reply.is_canceled() {
        let pending = self.pending_syncs.swap_remove(i);
        self.reap_cookie(pending.root, &pending.cookie_key);
      } else {
        i += 1;
      }
    }
  }

  /// Reaps a resolved (or abandoned) cookie — fire-and-forget, in the `disarm`
  /// mold. Its unlink event is suppressed by the namespace, never by the
  /// pending map (which no longer holds it).
  fn reap_cookie(&mut self, root: S::Handle, cookie_key: &[C]) {
    self.source.end_sync(root, cookie_key);
  }

  /// Reaps every still-pending cookie at owner teardown — the marker files must
  /// not outlive the owner.
  fn reap_all_pending_syncs(&mut self) {
    for pending in std::mem::take(&mut self.pending_syncs) {
      self.source.end_sync(pending.root, &pending.cookie_key);
    }
  }

  /// Emits everything the debounce is holding for ONE subscription, in
  /// admission (= epoch) order — the barrier's flush stage. Other
  /// subscriptions' buffers are untouched.
  /// Emits everything the debounce holds for `sub`, in admission (= epoch)
  /// order, and reports whether that delivery was **clean**: `true` when the
  /// subscription owes NO dominating `Rescan` afterward, `false` when it does
  /// — either it already carried `needs_rescan` debt (an earlier loss), or a
  /// full event channel forced `try_emit` to shed a delta to a parked `Rescan`
  /// during this very flush. A `false` means the barrier is met by
  /// re-enumeration, not by delivery, so the caller must be told `Dominated`.
  fn flush_subscription_now(&mut self, sub: Subscription) -> bool {
    let now: Instant = R::now().into();
    let mut due = Vec::new();
    if let Some(coalescer) = self.coalescer.as_mut() {
      coalescer.flush_subscription(sub, now);
      coalescer.drain_ready(now, &mut due);
    }
    for event in due {
      self.try_emit(event);
    }
    // Debt after the flush — pre-existing OR just shed by a full channel —
    // means a `Rescan` stands in for delivery: not a clean deliver.
    !self.needs_rescan.contains_key(&sub)
  }

  /// A live-root source `Rescan` is a coverage-loss signal from the layer that owns the
  /// kernel watches: whatever narrowing the retained-cover record claims for that root may
  /// now span the lost region — trusting it would let a later newcomer classify
  /// Covered-INSIDE and commit without a [`grow`](LocalSource::grow), silently unwatched.
  /// Degrade a narrowed record (`Some(cover)`) to the EMPTY cover — claiming nothing below
  /// the root — so the next newcomer under it classifies Covered-OUTSIDE and drives `grow`,
  /// which re-proves coverage against the source's own (equally degraded) claim before the
  /// commit broadens anything. A never-narrowed record (`None`) has no stale claim: the
  /// source's own re-arm machinery heals plain overflow, and the delivered `Rescan` already
  /// tells every subscriber to re-scan. Umbrella-minted `Rescan`s (sheds, re-points,
  /// terminals) never pass through the source-drain path, so no spurious degrade can occur.
  fn degrade_retained_cover_on_rescan(&mut self, raw: &SourceEvent<C, S::Handle>) {
    if !raw.kind().is_rescan() {
      return;
    }
    self.subsumer.degrade_retained_cover(raw.handle());
  }

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
    // event. Signaling the loss via the parked `Rescan` alone keeps the dead-root path
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
    let (ready, overflowed) = match self.coalescer.as_mut() {
      Some(coalescer) => {
        let now: Instant = R::now().into();
        // Subscriptions the coalescer SHED at its buffered-entry cap: each
        // is owed the same dominating parked Rescan as a full event channel —
        // `park_rescan` mints it and purges the sub's buffered entries, so the bound
        // holds with no silent loss.
        let mut overflowed = Vec::new();
        for event in events {
          if let Some(sub) = coalescer.admit(event, now) {
            overflowed.push(sub);
          }
        }
        let mut ready = Vec::new();
        coalescer.drain_ready(now, &mut ready);
        (ready, overflowed)
      }
      None => (events, Vec::new()),
    };
    for sub in overflowed {
      self.park_rescan(sub);
    }
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
  /// tail AND every parked per-subscription overflow [`Rescan`](crate::EventKind::Rescan)
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
    tail.retain(|event| {
      let sub = event.subscription();
      !self.needs_rescan.contains_key(&sub) && !self.suppressed_rescan.contains_key(&sub)
    });
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
  /// A still-**unclaimed** sub's parked debt is **suppressed by owner state** inside that flush (
  /// ), never delivered for a subscription the caller never obtained — no timing window. So the
  /// exit condition is "nothing owed to a **claimed** subscription AND no pending grant resolution":
  /// the drain stops once every remaining `needs_rescan` key is still `unclaimed` (or the set is
  /// empty) **and** the dedicated cleanup channel is empty (the linearization point — a
  /// [`Cleanup::Claim`] arriving after the top-of-iteration drain keeps `cleanup_rx` non-empty, so the
  /// drain loops again and delivers it), or the consumer is gone
  /// ([`is_closed`](async_channel::Sender::is_closed) short-circuits an all-refused channel whose
  /// receivers have all dropped). An unclaimed sub's debt is owed to nobody, so it must not spin the
  /// drain forever waiting for a grant that may never be claimed; a claim arriving mid-drain is drained
  /// by the cleanup handling below (top-of-iteration [`drain_pending_cleanup`](Self::drain_pending_cleanup)
  /// AND a `select!` arm — [`Cleanup::Claim`] lifts the suppression, so the next pass delivers that
  /// sub's Rescan before exiting), and a post-teardown claim holds a dead subscription exactly like any
  /// subscription after teardown (the read plane is already empty). The owner **never awaits the event
  /// sender** (invariant III preserved even at teardown) — only the close receiver, the cleanup
  /// receiver, the command receiver, and the retry timer.
  ///
  /// The retry **stays responsive to shutdown** (invariant II): a blind sleep would let a close
  /// request wait forever while the drain spins — behind a full channel a held-but-not-draining
  /// receiver keeps the channel both full and un-closed, so neither the slot-freed nor the
  /// all-receivers-dropped exit ever fires. So the dedicated [`closes`](Self::closes) signal is
  /// checked at the TOP priority here too: a non-blocking `try_recv` at the top of each
  /// iteration AND the first arm of the retry [`select!`](futures_util::select_biased). Grant
  /// resolution is drained at the **second** priority: a full non-blocking
  /// [`drain_pending_cleanup`](Self::drain_pending_cleanup) at the top of each iteration AND the second
  /// `select!` arm. A close interrupting the drain is returned to the caller (which does a non-blocking
  /// best-effort teardown and acks it) so `close()` always completes even mid-drain — no matter how
  /// deep the command backlog is. The command receiver is `select!`ed too so a dropped last handle (its
  /// `Err`) also stops the retry; a `watch`/`unwatch` arriving mid-teardown is failed fast (the owner
  /// is quiescing) and the owed-`Rescan` drain continues.
  ///
  /// Returns the [`CloseReply`] if a close interrupted the drain, else [`None`].
  async fn drain_owed_before_shutdown(&mut self) -> Option<CloseReply> {
    // Whether the dedicated close channel is still open (see [`closes`](Self::closes)). A closed
    // channel is NOT a teardown signal here either — the command channel's `Err` is — so on close the
    // arm just disables itself and the drain keeps going until the command channel closes or the debt
    // is delivered.
    let mut close_open = true;
    // Disabled once the atomic cut closes the cleanup channel: a closed,
    // drained channel's recv errors immediately — an enabled arm would spin the select.
    let mut cleanup_open = true;
    loop {
      // The dedicated shutdown signal is checked FIRST, non-blockingly, before the cleanup drain and
      // the owed pass: a close interrupts the drain without waiting behind the (possibly
      // flooded) command mailbox.
      if close_open {
        match self.closes.try_recv() {
          Ok(reply) => return Some(reply),
          Err(async_channel::TryRecvError::Closed) => close_open = false,
          Err(async_channel::TryRecvError::Empty) => {}
        }
      }
      // Grant resolution SECOND: a full non-blocking drain of the dedicated cleanup channel
      // BEFORE the owed pass and its exit check. A `Cleanup::Claim` sitting here must lift its
      // subscription's suppression FIRST — the caller defused the grant and genuinely holds the sub, so
      // its parked Rescan is owed — or the all-unclaimed exit below would read STALE `unclaimed` state
      // and tear down having never delivered it: suppression become permanent loss. It
      // is bounded by the grants in flight (not the unbounded mailbox the old bounded pre-drain
      // serviced), so a public `Watch`/`Unwatch` flood cannot starve the owed pass — owed delivery
      // makes progress every iteration. (It is NOT the suppression boundary — owner state is — it
      // only makes the EXIT PREDICATE read post-claim state.)
      self.drain_pending_cleanup();
      self.drain_owed_once();
      // Exit once nothing is owed to a CLAIMED subscription AND no grant resolution is still pending —
      // the linearization point: a claim observable by now was drained above and its
      // Rescan delivered by this pass; one arriving after the drain keeps `cleanup_rx` non-empty, so
      // this predicate fails and the loop delivers it next iteration; one arriving after this
      // observation is post-teardown, its subscription dead like any subscription after teardown. Every
      // remaining `needs_rescan` key still `unclaimed` means the debt is owed to nobody (and must not
      // spin the drain waiting for a grant that may never resolve); or the consumer is gone entirely.
      if (self.needs_rescan.is_empty() && self.cleanup_rx.is_empty()) || self.events.is_closed() {
        // Test-only race injection: stage claims land HERE — between the
        // emptiness observation and the cut — the exact window the fix below covers.
        #[cfg(test)]
        for staged in self.test_pre_cut_claims.drain(..) {
          let _ = self.cleanup_tx.try_send(staged);
        }
        // Make the exit ATOMIC with respect to grant claims: another thread holding an
        // unpolled grant could `defuse` between the emptiness observation above and the owner's
        // drop — its claim would land on a still-open channel (a live-looking Ok) that no later
        // drain will ever process. CLOSE the cleanup channel FIRST — every subsequent claim
        // try_send fails, poisoning its grant so the public `watch` surfaces `Closed` — then drain
        // whatever landed BEFORE the cut (async_channel keeps queued messages receivable after
        // close) and run one final owed pass so a pre-cut claim still gets its Rescan delivered.
        self.cleanup_rx.close();
        cleanup_open = false;
        self.drain_pending_cleanup();
        self.drain_owed_once();
        // A claim that RACED the cut — sent successfully after the emptiness observation
        // above but before the close — was drained just now and may have re-armed
        // OFFERABLE debt against a full event channel, where the single best-effort pass
        // above could not deliver it (its caller holds a live Ok subscription;
        // returning here would strand its terminal Rescan forever). Exit only once no
        // offerable debt remains (or nobody is left listening); otherwise stay in the
        // drain loop — the cut is done, so no NEW claims can land (they poison), the
        // cleanup channel is closed-and-drained, and the retry machinery below delivers
        // the raced debt as the consumer drains, exactly like any other owed Rescan.
        if self.needs_rescan.is_empty() || self.events.is_closed() {
          return None;
        }
        continue;
      }
      let sleep = R::sleep(RETRY).fuse();
      futures_util::pin_mut!(sleep);
      // The dedicated close arm, borrowing ONLY the close receiver (disjoint from the cleanup/commands
      // borrows the next arms take). It is the FIRST arm so a close always wins over a queued cleanup or
      // command; on a closed channel it resolves `None` (→ disable) and on disable it parks.
      let closes = &self.closes;
      let close_arm = async move {
        if close_open {
          // `Ok(reply)` → a close request; `Err` (channel closed) → `None` = disable the arm.
          closes.recv().await.ok()
        } else {
          futures_util::future::pending::<Option<CloseReply>>().await
        }
      };
      // The dedicated cleanup arm (SECOND, below close, above commands): wakes the drain
      // when a grant resolves mid-retry so its `Cleanup::Claim` lifts suppression / `Cleanup::DropOrphan`
      // purges before the next owed pass. Never errors while the owner lives (it holds `cleanup_tx`).
      let cleanup_rx = &self.cleanup_rx;
      let cleanup_arm = async move {
        if cleanup_open {
          cleanup_rx.recv().await.ok()
        } else {
          futures_util::future::pending::<Option<Cleanup>>().await
        }
      };
      futures_util::select_biased! {
        maybe_reply = close_arm.fuse() => match maybe_reply {
          // A close interrupted the drain: hand its reply back so the caller acks it — `close()`
          // completes even mid-drain.
          Some(reply) => return Some(reply),
          // The close channel closed (every handle dropped): disable the arm; the command channel's
          // own `Err` (below) remains the dropped-handles stop signal.
          None => close_open = false,
        },
        cleanup = cleanup_arm.fuse() => match cleanup {
          // A grant resolution mid-drain: apply it and loop (the next iteration's top drain handles any
          // more).
          Some(cleanup) => self.apply_cleanup(cleanup),
          // Closed (the post-cut iterations): disable the arm — the cut already drained
          // every pre-cut claim, and later grants poison at their own try_send.
          None => cleanup_open = false,
        },
        cmd = self.commands.recv().fuse() => match cmd {
          // A queued PUBLIC command mid-drain — a `watch`/`unwatch` — failed fast (the owner is
          // quiescing). A close never arrives here (its own arm above); grant resolution never arrives
          // here (the cleanup arm above).
          Ok(command) => self.handle_teardown_command(command),
          // Every handle dropped: nobody is left to receive the owed Rescans — stop and tear
          // down (the caller's best-effort final pass runs next).
          Err(_) => return None,
        },
        _ = sleep => {}
      }
    }
  }

  /// Handles one PUBLIC command won by the
  /// [`drain_owed_before_shutdown`](Self::drain_owed_before_shutdown) `select!` while the owner is
  /// quiescing: a [`Watch`](Command::Watch)/[`Unwatch`](Command::Unwatch) is **failed fast** — the
  /// owner is stopping, so the caller's handle surfaces `Closed`.
  ///
  /// The mailbox now carries ONLY these two caller-reply commands; grant resolution
  /// ([`Cleanup::Claim`]/[`Cleanup::DropOrphan`]) rides the dedicated cleanup channel, handled by
  /// [`apply_cleanup`](Self::apply_cleanup). A close is **never** one of these either:
  /// shutdown rides the dedicated [`closes`](Self::closes) signal, handled by its own arm. This awaits
  /// nothing, so it can never park teardown (invariant II).
  fn handle_teardown_command(&mut self, cmd: Command<C, V>) {
    match cmd {
      Command::Watch { reply, .. } => {
        let _ = reply.send(Err(WatchError::Closed));
      }
      Command::Unwatch { reply, .. } => {
        let _ = reply.send(Err(UnwatchError::Closed));
      }
    }
  }
}

/// One subscription's parked dominating [`Rescan`](crate::EventKind::Rescan) (design
/// backpressure doc): the covered `key` to re-enumerate, a strictly-dominating `epoch`, and the
/// owning subscription's baked `value` — the latter captured **while the subscription is live**
/// (at park / retire time), so the Rescan minted from this entry by
/// [`flush_pending_rescans`](Owner::flush_pending_rescans) stays attributable even after the
/// subscription/root is retired and the [`WatchView`] is emptied (design §3).
struct ParkedRescan<C, V> {
  /// The subscription's covered key — the subtree the consumer re-enumerates.
  key: Vec<C>,
  /// The non-rebasing strictly-dominating shed epoch.
  epoch: Epoch,
  /// The owning subscription's baked caller value (`None` only when the sub had no live value at
  /// capture — a raced retirement).
  value: Option<V>,
}

/// Merges a parked overflow [`Rescan`](crate::EventKind::Rescan) into the dirty-set,
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
      // Widen the parked key so the single parked `Rescan` covers BOTH re-enumeration debts
      // (see [`widen_to_cover`]).
      widen_to_cover(&mut parked.key, &key);
      parked.epoch = parked.epoch.max(epoch);
      parked.value = value;
    }
    Entry::Vacant(vacant) => {
      vacant.insert(ParkedRescan { key, epoch, value });
    }
  }
}

/// Widens `parked` — a parked [`Rescan`](crate::EventKind::Rescan)'s key — in place until it
/// also covers `key`: truncates it to the two keys' longest common prefix.
///
/// Overwriting with `key` would be correct only when `key` is an ancestor of `parked`. Two
/// independent losses under one subscription (say `/a/x` then `/a/y`) are siblings, and
/// dropping either's coverage is silent loss; their common prefix (`/a`) re-enumerates a
/// superset of both. Where `key` *is* an ancestor of `parked` the common prefix is exactly
/// `key`, so the ancestor case is unchanged. The result is always an ancestor-or-equal of the
/// previous `parked` key, so coverage only ever grows — the "keys only ever widen" invariant.
fn widen_to_cover<C: PartialEq>(parked: &mut Vec<C>, key: &[C]) {
  let common = key
    .iter()
    .zip(parked.iter())
    .take_while(|(a, b)| a == b)
    .count();
  parked.truncate(common);
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
    self.event.kind().moved_from()
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

  #[inline]
  fn deliver_rescan_clamped(&self, sub: Subscription, key: &[C]) -> Event<C, V> {
    Event::source_rescan_clamped(sub, self.event, key)
  }

  /// The depth of the root this change's `location` was measured against, recovered from
  /// the change itself: its location names the components of its key below that root, so
  /// the root accounts for exactly the rest.
  ///
  /// This is why the anchor survives a widen. Both halves were fixed when the source
  /// recorded the change — the absolute key and the root-relative location — so their
  /// difference is the depth that was true *then*, whatever root the handle covers by
  /// the time the umbrella drains it. `saturating_sub` keeps a source that reports a
  /// location longer than its key from underflowing; such an event degrades to a
  /// root-anchored delivery rather than panicking.
  ///
  /// Reading the anchor off the pair is sound because the pair is what
  /// [`SourceEvent::new`]'s contract binds together, and because nothing between that mint
  /// and this read may rewrite one half alone: the only re-key of a raw [`SourceEvent`],
  /// [`SourceEvent::rekeyed_at_root`], restates the location in the same step. A future
  /// transformation that rewrites a key while carrying a foreign location forward does not
  /// merely mis-derive this number — it makes the delivered location itself name a path that
  /// is not under the delivered key, which no representation of the anchor could repair.
  #[inline]
  fn captured_root_depth(&self) -> usize {
    self
      .event
      .key()
      .len()
      .saturating_sub(self.event.location().len())
  }

  #[inline]
  fn rebase(&self, delivered: &mut Event<C, V>, strip: usize) {
    delivered.rebase_location(strip);
  }

  #[inline]
  fn anchor_at_root(&self, delivered: &mut Event<C, V>) {
    delivered.anchor_location_at_root();
  }
}

/// The error for a canonicalization race where the source's committed canonical key
/// diverged from the planned one in a way that changes subsumption (design §4, invariant
/// I2) — the honest retryable-race variant, keyed in no coordinate (the key space is
/// `C`, not necessarily a path, and the caller already holds the key it passed).
fn canonical_race() -> WatchError {
  WatchError::CanonicalRace
}

/// Compile-time proof that the pure-fs [`Tributaries`] constructs and its owner future is
/// `Send`, so it can be spawned via
/// [`R::spawn_detach`](agnostic_lite::RuntimeLite::spawn_detach) on a multi-threaded
/// executor. Never invoked — it only has to type-check.
#[cfg(all(feature = "fs", feature = "tokio"))]
#[allow(dead_code)]
fn assert_fs_owner_send() {
  fn is_send<T: Send>() {}
  is_send::<Tributaries<OsString, (), agnostic_lite::tokio::TokioRuntime, RootHandle>>();
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

/// Compile-time proof of the `!Send` construction path: a genuinely thread-local source —
/// `Rc` state captured by its futures, so it cannot promise `Send` and can implement only
/// [`LocalSource`] — constructs through [`Tributaries::parts_local`]. The twin of
/// [`assert_generic_owner_send`], which pins the `Send` half (the blanket impl must keep
/// [`Tributaries::parts`]' promise provable for a generic `S: Source`); this half pins
/// that the base seam genuinely hosts a source no [`Source`] impl could be written for.
/// Generic over `R`, so it type-checks under every runtime feature set. Never invoked.
#[allow(dead_code)]
fn assert_rc_local_source_constructs<R: RuntimeLite>() {
  use std::{cell::Cell, rc::Rc};

  struct RcSource {
    state: Rc<Cell<u32>>,
  }

  impl LocalSource<OsString> for RcSource {
    type Handle = u32;

    fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
      Ok(key.to_vec())
    }

    fn arm(
      &mut self,
      key: &[OsString],
    ) -> impl Future<Output = Result<Armed<OsString, u32>, WatchError>> {
      let state = Rc::clone(&self.state);
      let canonical = key.to_vec();
      async move {
        let handle = state.get() + 1;
        state.set(handle);
        Ok(Armed::new(handle, canonical))
      }
    }

    fn disarm(&mut self, _handle: u32) {}

    fn next(&mut self) -> impl Future<Output = Option<SourceEvent<OsString, u32>>> {
      let state = Rc::clone(&self.state);
      async move {
        let _ = state.get();
        core::future::pending().await
      }
    }

    fn root_key(&self, _handle: u32) -> Option<Vec<OsString>> {
      None
    }
  }

  let (_handle, _driver): (Tributaries<OsString, (), R, u32>, _) = Tributaries::parts_local(
    RcSource {
      state: Rc::new(Cell::new(0)),
    },
    TributariesOptions::new(),
  );
}

/// A [`Tributaries`] driven by the tokio runtime, over the local filesystem.
#[cfg(all(feature = "fs", feature = "tokio"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "fs", feature = "tokio"))))]
pub type TokioTributaries =
  Tributaries<OsString, (), agnostic_lite::tokio::TokioRuntime, RootHandle>;

/// A [`Tributaries`] driven by the smol runtime, over the local filesystem.
#[cfg(all(feature = "fs", feature = "smol"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "fs", feature = "smol"))))]
pub type SmolTributaries = Tributaries<OsString, (), agnostic_lite::smol::SmolRuntime, RootHandle>;
