//! Per-subscription fan-out **outside** the actor: a [`Demux`] task consumes one
//! [`Tributaries`] handle as the shared stream's sole drainer and routes every event to
//! its subscription's own bounded [`Lane`] — stalling, never shedding, when a lane is
//! full. The full public contract (loss authority stays in the actor; sole drainer;
//! lane/rest routing; end-of-stream fan-in) lives on [`Demux`], the crate-root-exported
//! entry point.

use std::{
  collections::HashMap,
  sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
  },
};

use std::future::Future;

use agnostic_lite::RuntimeLite;
use futures_util::FutureExt;

use crate::{driver::Tributaries, event::Event, subscription::Subscription};

#[cfg(all(test, feature = "tokio"))]
mod tests;

/// The control queue's depth. Small on purpose: control messages are tiny and rare, and
/// a BOUNDED queue is what keeps a stalled routing task from turning registration into
/// an unbounded memory-growth path — while the task is parked on a full
/// lane's awaited send it services no control messages, so registrants must feel
/// backpressure instead of queueing without limit.
const CONTROL_CAPACITY: usize = 16;

/// The release a registered [`Lane`] owes on drop: its subscription, its registration
/// brand, and the control queue to notify.
struct OwedRelease<C, V> {
  sub: Subscription,
  generation: u64,
  control: async_channel::Sender<Control<C, V>>,
}

/// A control message into the routing task.
enum Control<C, V> {
  /// A lane registration: from application onward, `sub`'s events are delivered into
  /// `lane`. `generation` brands this registration so a stale release (a previous lane object
  /// for the same subscription, dropped after a re-point) cannot evict its successor.
  Register {
    /// The subscription whose events the lane claims.
    sub: Subscription,
    /// This registration's brand, minted by [`Demux::lane`].
    generation: u64,
    /// The bounded send side the routing task delivers into; the matching receiver
    /// lives in the caller's [`Lane`].
    lane: async_channel::Sender<Event<C, V>>,
  },
  /// An orderly stop request ([`Demux::shutdown`]): the routing task
  /// finishes its current delivery — never mid-send — drains the snapshot-bounded
  /// pre-stop backlog, then drops every lane sender so each lane drains its buffered
  /// tail to a clean end-of-stream. Loss-free UNDER the module's sole-drainer
  /// precondition (held through the whole barrier); post-stop events stay on the
  /// shared stream for clones that resume `next()` after the routing future resolves.
  Shutdown,
  /// A best-effort release sent by a dropped [`Lane`]: remove the
  /// subscription's slot — IF it still holds generation `generation` — returning the
  /// subscription to unclaimed (rest) routing. Lost releases (full/closed control
  /// queue) are covered by send-time reclamation in the routing loop.
  Release {
    /// The subscription whose lane was dropped.
    sub: Subscription,
    /// The dropped lane's registration brand; a mismatch means a fresh lane already
    /// re-claimed the subscription and the release is stale — a no-op.
    generation: u64,
  },
}

/// The per-subscription fan-out layer **outside** the actor: a routing task that
/// consumes one [`Tributaries`] handle as the shared stream's sole drainer and delivers
/// every event into its subscription's own bounded [`Lane`] — stalling, never shedding,
/// when a lane is full.
///
/// [`Tributaries`] clones share ONE MPMC event stream: competing
/// [`next`](Tributaries::next) callers steal from each other, so "each subscription its
/// own task" cannot be built by cloning the handle. The demux is the supported shape —
/// one routing task drains the shared stream and fans events out by their
/// [`Subscription`] token. A `Demux` is the *control* handle over that task:
/// [`lane`](Self::lane) registers per-subscription lanes with the routing task
/// [`spawn`](Self::spawn) started. Dropping it only closes the control channel — the
/// routing task keeps routing until the shared stream ends.
///
/// # Loss authority stays in the actor
///
/// The demux never drops a known event, and it never synthesizes or mints events or
/// `Rescan`s of its own. Its **only** backpressure move is to *stop receiving* from the
/// shared stream: delivery into a full lane is an awaited send, and while that send
/// waits the shared channel fills behind it — where the **actor's** own overflow
/// machinery sheds, minting genuine parked, epoch-dominating
/// [`Rescan`](crate::EventKind::Rescan)s. Every loss therefore remains a contract-grade,
/// actor-minted `Rescan`; nothing is lost at this layer. The cost, stated plainly: this
/// buys **loss-isolation, not latency-isolation** — a stalled lane head-of-line delays
/// the other lanes' *delivery*, never their loss accounting.
///
/// # Sole drainer
///
/// [`spawn`](Self::spawn) **consumes** a `Tributaries` handle and drains its stream from
/// the spawned routing task. The consumed handle's stream must not be drained by any
/// other clone: clones the caller kept are for `watch`/`unwatch`/`close` (and the read
/// plane) ONLY — a second `next()` caller steals events out from under the demux and
/// voids routing. This is convention-enforced; it cannot be made static, because every
/// clone carries the same `next()`.
///
/// # Lanes, and the rest lane
///
/// [`lane`](Self::lane) registers a bounded per-subscription lane over a **bounded**
/// control channel into the routing task; the registration send is awaited, so while
/// the routing task is stalled on a full lane, registrants feel backpressure instead of
/// growing an unbounded control queue. Events whose subscription has no
/// registered lane land on the **rest** lane returned by [`spawn`](Self::spawn). A
/// registration is applied before the routing of any event that enters the shared
/// stream after it returns, so events emitted after `lane` returns reach the lane;
/// events already in flight may still land on rest — register the lane before its
/// events flow, or drain rest.
///
/// # Dropped lanes release their subscription back to unclaimed
///
/// A dropped [`Lane`] sends a best-effort release to the routing task, a delivery
/// that observes the dropped receiver reclaims the slot on the spot (recovering that
/// very event), and — the structural backstop — every registration first sweeps all
/// entries whose receiver is gone before installing (registration being the table's
/// only growth site; a release lost to a full control queue on an idle
/// subscription is reclaimed at the latest by the next registration). All three paths
/// REMOVE the entry, so the lane table is bounded by *peak-concurrent* lanes, never by
/// lifetime registrations. From the
/// release onward the subscription is unclaimed again: its late stragglers surface on
/// the rest lane exactly like pre-registration traffic — while a lane is registered it
/// exclusively owns its subscription's events; there is no split delivery. A consumer
/// that wants zero stragglers unwatches first and drains its lane before dropping it.
/// Once the rest receiver is dropped, unrouted events are discarded from then on.
/// Registering a fresh lane for the subscription re-claims it from that point onward.
///
/// # End of stream, and who owns which lifecycle
///
/// When the shared stream ends — the actor is gone and the tail is drained, `next()`
/// returning `None` — the routing task drops every lane sender and exits: each
/// [`Lane::recv`] then drains its buffered tail and returns `None`. Dropping the
/// `Demux` handle only closes the control channel — the task keeps routing; it just
/// accepts no new lanes. The underlying watcher lifecycle stays entirely with the
/// caller's own clones: `close()`/`unwatch` there — a closed watcher ends the stream,
/// which ends the lanes. Note that the routing task's consumed handle keeps the actor's
/// command mailbox open, so dropping the caller's clones alone does not tear the
/// watcher down; ask for it with [`close`](Tributaries::close) (or let the source
/// drain). The task holds the consumed handle for `next()` only — it never calls
/// `watch`/`unwatch`/`close` itself.
///
/// # Example
///
/// ```rust,no_run
/// # #[cfg(all(feature = "tokio", feature = "fs"))]
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use std::{ffi::OsString, path::Path};
///
/// use tributaries::{Demux, TokioTributaries, TributariesOptions, WatchOptions, WatcherOptions};
///
/// fn key(path: &str) -> Vec<OsString> {
///   Path::new(path)
///     .components()
///     .map(|c| c.as_os_str().to_os_string())
///     .collect()
/// }
///
/// let w = TokioTributaries::new(WatcherOptions::new(), TributariesOptions::new())?;
/// let project = key("/path/to/project");
/// let sub = w.watch(project.clone(), (), WatchOptions::new()).await?;
///
/// // The demux CONSUMES one handle (the sole drainer); `w` stays behind for
/// // watch/unwatch/close only — never for next().
/// let (demux, rest) = Demux::spawn(w.clone(), 64);
/// let lane = demux.lane(sub, 64).await;
///
/// // One independent task per lane; a full lane stalls the demux (latency), while the
/// // actor keeps the loss accounting (a dominating Rescan on overflow).
/// let consumer = tokio::spawn(async move {
///   while let Some(event) = lane.recv().await {
///     if event.reaches(&project) {
///       // re-enumerate / re-read below `event.key()`
///     }
///   }
///   // None: the watcher closed and the lane's buffered tail is drained.
/// });
/// // Unclaimed subscriptions' events arrive on the rest lane.
/// tokio::spawn(async move { while let Some(_event) = rest.recv().await {} });
///
/// // Teardown: retire the subscription (queued stragglers still drain through the
/// // lane), then close the watcher — the ended stream ends every lane, and the lane
/// // task drops its Lane on exit.
/// w.unwatch(sub).await?;
/// w.close().await?;
/// consumer.await?;
/// # Ok(())
/// # }
/// ```
pub struct Demux<C, V> {
  /// The bounded control channel into the routing task (capacity
  /// [`CONTROL_CAPACITY`]; a stalled task backpressures registrants).
  control: async_channel::Sender<Control<C, V>>,
  /// Brands each registration (see [`Control::Register::generation`]).
  next_gen: AtomicU64,
  /// The routing task's current lane-table size, maintained by the loop after every
  /// mutation — the observable that proves the table is bounded by live lanes.
  tracked: Arc<AtomicUsize>,
}

/// One bounded per-subscription event stream fed by a [`Demux`] routing task — either a
/// claimed subscription's own lane ([`Demux::lane`]) or the rest lane
/// ([`Demux::spawn`]).
///
/// Deliberately not `Clone`: a lane has a single consumer. [`recv`](Self::recv) yields
/// the lane's events in delivery order and `None` at end-of-stream (the watcher closed
/// and the buffered tail is drained).
pub struct Lane<C, V> {
  /// The bounded receive side; the send side lives in the routing task's lane table.
  events: async_channel::Receiver<Event<C, V>>,
  /// `Some` on a registered lane; `None` on the rest lane, which owes no release.
  release: Option<OwedRelease<C, V>>,
}

impl<C, V> Drop for Lane<C, V> {
  fn drop(&mut self) {
    if let Some(OwedRelease {
      sub,
      generation,
      control,
    }) = self.release.take()
    {
      // Best-effort PROMPT path: a full or closed control queue skips the notice. A
      // lost release is still reclaimed — at the next delivery against the dropped
      // receiver (recovering that event to rest), or structurally by the next
      // registration's sweep — so it costs staleness, never unboundedness.
      let _ = control.try_send(Control::Release { sub, generation });
    }
  }
}

impl<C, V> Demux<C, V> {
  /// Spawns the routing task on `R` over the **consumed** `watcher` handle — the shared
  /// stream's sole drainer — returning the control handle and the **rest** lane
  /// (bounded at `rest_capacity`) that receives every event whose subscription has no
  /// registered lane.
  ///
  /// The consumed handle's stream must not be drained by any other clone: clones the
  /// caller kept are for `watch`/`unwatch`/`close` only — a second
  /// [`next`](Tributaries::next) caller steals events and voids routing (see the
  /// [type docs](Self)). The task holds the handle for `next()` only; it never calls
  /// `watch`/`unwatch`/`close`. Mirroring the owner task itself, the routing task is
  /// spawned detached via [`RuntimeLite::spawn_detach`].
  ///
  /// # Panics
  ///
  /// Panics if `rest_capacity` is zero (a lane must be able to buffer at least one
  /// event).
  pub fn spawn<R, H>(watcher: Tributaries<C, V, R, H>, rest_capacity: usize) -> (Self, Lane<C, V>)
  where
    C: Send + Sync + 'static,
    V: Send + Sync + 'static,
    R: RuntimeLite,
    H: Send + Sync + 'static,
  {
    let (demux, rest, driver) = Self::parts(watcher, rest_capacity);
    R::spawn_detach(driver);
    (demux, rest)
  }

  /// Like [`spawn`](Self::spawn) but WITHOUT spawning: returns the control handle, the
  /// rest lane, and the routing future for the CALLER to spawn — the demux twin
  /// of [`Tributaries::parts`]. Routing progresses only while the future is polled
  /// (unpolled = every lane silent), and the future is `Send` so any executor may host
  /// it (the routing loop itself uses no timers).
  ///
  /// **Aborting the future is a hard stop**: dropping it mid-poll may drop
  /// the single delivery in flight at that moment — an event already pulled off the
  /// shared stream and parked in a stalled lane send dies with the future, and the
  /// actor cannot re-issue it (it left the actor's channel; no Rescan is owed). Lanes
  /// then end after their buffered tails, indistinguishable from a clean end. The
  /// no-known-event-drop guarantee is therefore scoped to routing that runs to
  /// completion: stop LOSS-FREE via [`shutdown`](Self::shutdown) (finish current
  /// delivery, then drain-and-end) or by closing the watcher (end-of-stream fan-in);
  /// abort only when losing one in-flight event is acceptable. Remaining `Tributaries`
  /// clones can still drain the shared stream after an abort — the events channel is
  /// MPMC.
  ///
  /// # Panics
  ///
  /// Panics if `rest_capacity` is zero (a lane must be able to buffer at least one
  /// event).
  pub fn parts<R, H>(
    watcher: Tributaries<C, V, R, H>,
    rest_capacity: usize,
  ) -> (Self, Lane<C, V>, impl Future<Output = ()> + Send + 'static)
  where
    C: Send + Sync + 'static,
    V: Send + Sync + 'static,
    R: RuntimeLite,
    H: Send + Sync + 'static,
  {
    let (control_tx, control_rx) = async_channel::bounded(CONTROL_CAPACITY);
    let (rest_tx, rest_rx) = async_channel::bounded(rest_capacity);
    let tracked = Arc::new(AtomicUsize::new(0));
    let driver = run(watcher, control_rx, rest_tx, Arc::clone(&tracked));
    (
      Self {
        control: control_tx,
        next_gen: AtomicU64::new(0),
        tracked,
      },
      Lane {
        events: rest_rx,
        release: None,
      },
      driver,
    )
  }

  /// How many subscriptions the routing task currently tracks (registered lanes not
  /// yet released or reclaimed). Bounded by concurrently live lanes — never by
  /// lifetime registrations; the churn test pins that property.
  pub fn tracked_lanes(&self) -> usize {
    self.tracked.load(Ordering::Acquire)
  }

  /// Requests an ORDERLY stop of the routing task: it
  /// finishes the delivery it is currently awaiting — a stalled send completes when
  /// that lane drains, never mid-send — then routes the backlog the shared stream
  /// holds at the instant the stop is processed (the drain barrier, bounded by a
  /// COUNT SNAPSHOT taken at that moment, so it is finite even under a producer that
  /// keeps the stream non-empty), and only then exits, dropping every lane sender so
  /// each [`Lane::recv`] drains its buffered tail and reads `None`.
  ///
  /// The loss-free pre-stop/post-stop split holds under the module's SOLE-DRAINER
  /// precondition (the [type docs](Self)): while the routing task runs — the barrier
  /// included — no other clone may call `next()`; a competing drainer voids the split
  /// exactly as it voids routing generally. Under that precondition,
  /// nothing emitted before the stop took effect is lost, and events emitted
  /// afterwards — past the snapshot — are post-stop: they stay on the shared MPMC
  /// stream, drainable by the caller's clones once the routing future has resolved.
  ///
  /// This is the loss-free way to stop routing without ending the watcher itself
  /// (closing the watcher ends the shared stream and the lanes with it). By contrast,
  /// ABORTING the routing future (dropping the [`parts`](Self::parts) driver mid-poll)
  /// is a hard stop that may drop the single in-flight delivery — see `parts`.
  ///
  /// Awaits admission on the bounded control queue like [`lane`](Self::lane); returns
  /// once the request is admitted (the stop itself completes when the driver future
  /// resolves — callers holding the `parts` driver await that for the drain barrier).
  /// A no-op if the routing task already exited.
  pub async fn shutdown(&self) {
    let _ = self.control.send(Control::Shutdown).await;
  }

  /// Registers a bounded lane (of `capacity` events) for `sub` with the routing task,
  /// returning its receive side.
  ///
  /// The registration send is **awaited on the bounded control queue**: while the
  /// routing task is stalled on a full lane it services no control messages, so this
  /// call backpressures instead of growing an unbounded queue — do not
  /// call it from the one task responsible for draining a currently-full lane. The
  /// registration is admitted before this returns and is applied before the routing of
  /// any event that enters the shared stream afterwards, so events emitted after this
  /// returns reach the lane; events already in flight may still land on rest —
  /// register before the subscription's events flow, or drain rest. Registering a
  /// second lane for the same subscription re-points routing to it (the previous lane
  /// drains its buffer and ends; its later drop-release is generation-stale and
  /// ignored), and re-claims a subscription whose earlier lane was dropped or
  /// released. A registration displaces the predecessor UNCONDITIONALLY — even one
  /// whose own receiver is already gone by processing time (registered, then dropped
  /// before the router got to it): that claim-then-release still ends the predecessor
  /// and reverts the subscription to unclaimed.
  ///
  /// A lane registered after the routing task has exited (the stream already ended)
  /// yields `None` immediately — indistinguishable from a lane at end-of-stream.
  ///
  /// # Panics
  ///
  /// Panics if `capacity` is zero (a lane must be able to buffer at least one event).
  pub async fn lane(&self, sub: Subscription, capacity: usize) -> Lane<C, V> {
    let (lane_tx, lane_rx) = async_channel::bounded(capacity);
    let generation = self.next_gen.fetch_add(1, Ordering::Relaxed);
    // The send fails only when the routing task is gone (end-of-stream), in which case
    // `lane_tx` drops with the message and the returned lane immediately reads
    // end-of-stream.
    let _ = self
      .control
      .send(Control::Register {
        sub,
        generation,
        lane: lane_tx,
      })
      .await;
    Lane {
      events: lane_rx,
      release: Some(OwedRelease {
        sub,
        generation,
        control: self.control.clone(),
      }),
    }
  }
}

impl<C, V> Lane<C, V> {
  /// The next event routed to this lane, or `None` at end-of-stream — the watcher
  /// closed (or the source drained), the routing task exited, and this lane's buffered
  /// tail is fully drained.
  ///
  /// Cancel-safe: a dropped `recv()` loses nothing (queued events stay queued). Events
  /// arrive in delivery order; a subscription retired by
  /// [`unwatch`](Tributaries::unwatch) may still have queued stragglers arrive here —
  /// tolerate and ignore them.
  pub async fn recv(&self) -> Option<Event<C, V>> {
    self.events.recv().await.ok()
  }
}

/// The routing loop: drain the consumed `watcher` stream, deliver each event to its
/// subscription's lane (an **awaited** send — the deliberate stall that pushes
/// backpressure into the shared channel, where the actor keeps the loss authority), or
/// to `rest` when unclaimed. Exits when the stream ends, dropping every lane sender so
/// each [`Lane`] drains then reads `None`.
async fn run<C, V, R, H>(
  mut watcher: Tributaries<C, V, R, H>,
  control: async_channel::Receiver<Control<C, V>>,
  rest: async_channel::Sender<Event<C, V>>,
  tracked: Arc<AtomicUsize>,
) where
  R: RuntimeLite,
{
  // Value = (registration generation, send side). Entries are REMOVED on release or
  // send-time reclamation — the table is bounded by live lanes, not lifetime
  // registrations.
  let mut lanes: LaneTable<C, V> = HashMap::new();
  // `None` once the rest receiver is dropped: unrouted events are discarded from then on.
  let mut rest = Some(rest);
  // The control channel closes when the `Demux` handle drops — NOT a stop signal: the
  // loop stops selecting on control (so a closed channel cannot spin the select) and
  // keeps routing straight off the stream until it ends.
  let mut control_open = true;
  loop {
    // One registration applied, or one event pulled, per iteration. The select is
    // biased control-first, so every registration already queued is applied before the
    // next event is pulled — the ordering that makes "events emitted after `lane`
    // returns reach the lane" hold. Both arms are cancel-safe reads (`Tributaries::next`
    // by contract, `async_channel` recv by construction), so the loser's dropped future
    // loses nothing.
    let event = if control_open {
      futures_util::select_biased! {
        message = control.recv().fuse() => {
          match message {
            Ok(Control::Register { sub, generation, lane }) => {
              // Registration is the table's ONLY growth site, so it is also the sweep
              // site: purge every entry whose receiver is gone before
              // inserting. A dropped lane's best-effort release can be LOST on a full
              // control queue, and an idle subscription never triggers send-time
              // reclamation — but the table cannot grow without a registration passing
              // through here, so sweeping here bounds it by peak-concurrent lanes
              // regardless of lost releases.
              lanes.retain(|_, (_, sender)| !sender.is_closed());
              // A registration ALWAYS DISPLACES the subscription's predecessor — even
              // when its own receiver already died (admitted, then dropped while the
              // router was stalled): claim-then-drop means the caller re-pointed and
              // released, so the predecessor must stop routing and the subscription
              // reverts to unclaimed (skip-install alone left a live
              // predecessor routing forever, with the queued release carrying the
              // replacement's generation and so unable to remove it). A dead
              // replacement is then simply not installed (the lost-release repro's dead
              // installs still never happen).
              lanes.remove(&sub);
              if !lane.is_closed() {
                lanes.insert(sub, (generation, lane));
              }
            }
            Ok(Control::Shutdown) => {
              // Orderly stop-and-DRAIN: the delivery this
              // loop completed before selecting again is already done — and the
              // backlog the shared stream holds AT THIS INSTANT is routed too,
              // bounded by a COUNT SNAPSHOT taken now (an until-empty
              // loop has no finite boundary — a lane stall mid-barrier lets the
              // producer refill the stream, so it could absorb post-stop traffic
              // forever). At most `owed` events drain: each `now_or_never` poll of
              // `next()` is one cancel-safe channel poll, and each drained event
              // routes through the normal awaited-lane delivery (finite stalls,
              // `owed` of them at worst).
              //
              // The pre-stop/post-stop split this implements holds under the module's
              // SOLE-DRAINER precondition (see the type docs): with no competing
              // `next()` caller, the count identifies exactly the pre-stop backlog.
              // A caller who violates that precondition mid-barrier voids the split —
              // a competing drainer shifts which events the counted pulls take, just
              // as it voids routing at any other time (the count carries
              // no event identities; exclusivity is the contract, not an option).
              // The early break below is purely defensive termination for that
              // violated state, not support for it.
              let owed = watcher.queued_events();
              for _ in 0..owed {
                match watcher.next().now_or_never() {
                  Some(Some(event)) => deliver(&mut lanes, &mut rest, &tracked, event).await,
                  _ => break,
                }
              }
              break;
            }
            Ok(Control::Release { sub, generation }) => {
              // Remove only the matching generation: a stale release from a lane that
              // was already re-pointed must not evict its successor.
              if lanes.get(&sub).is_some_and(|(live, _)| *live == generation) {
                lanes.remove(&sub);
              }
            }
            Err(_) => control_open = false,
          }
          tracked.store(lanes.len(), Ordering::Release);
          continue;
        }
        event = watcher.next().fuse() => event,
      }
    } else {
      watcher.next().await
    };
    // End-of-stream fan-in: the actor is gone and the shared tail is drained.
    let Some(event) = event else {
      break;
    };
    deliver(&mut lanes, &mut rest, &tracked, event).await;
  }
  // Returning drops every lane sender (the table) and the rest sender: each `Lane`
  // drains its buffered tail, then reads `None`.
}

/// The routing task's lane table: each claimed subscription's registration generation
/// and bounded send side.
type LaneTable<C, V> = HashMap<Subscription, (u64, async_channel::Sender<Event<C, V>>)>;

/// One delivery: route `event` to its subscription's lane — THE deliberate stall
/// (stall-not-shed): the bounded lane send is awaited, so a full lane parks the caller
/// while the shared channel fills and the ACTOR's overflow machinery mints the genuine
/// dominating Rescans; the demux itself never sheds. A send that observes the lane's
/// receiver dropped reclaims the slot on the spot (send-time reclamation, /// covers a lost drop-release) and RECOVERS the very event the failed send handed
/// back: the subscription is unclaimed again, and the recovered event flows to rest
/// like any unclaimed traffic. A dropped rest receiver discards unrouted events from
/// then on.
async fn deliver<C, V>(
  lanes: &mut LaneTable<C, V>,
  rest: &mut Option<async_channel::Sender<Event<C, V>>>,
  tracked: &Arc<AtomicUsize>,
  event: Event<C, V>,
) {
  let sub = event.subscription();
  let unclaimed = match lanes.get(&sub) {
    Some((_, lane)) => match lane.send(event).await {
      Ok(()) => None,
      Err(async_channel::SendError(event)) => {
        lanes.remove(&sub);
        tracked.store(lanes.len(), Ordering::Release);
        Some(event)
      }
    },
    None => Some(event),
  };
  if let Some(event) = unclaimed
    && let Some(lane) = &*rest
    && lane.send(event).await.is_err()
  {
    *rest = None;
  }
}
