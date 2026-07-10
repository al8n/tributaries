//! Per-subscription fan-out **outside** the actor: a [`Demux`] task consumes one
//! [`Tributaries`] handle as the shared stream's sole drainer and routes every event to
//! its subscription's own bounded [`Lane`] — stalling, never shedding, when a lane is
//! full. The full public contract (loss authority stays in the actor; sole drainer;
//! lane/rest routing; end-of-stream fan-in) lives on [`Demux`], the crate-root-exported
//! entry point.

use std::collections::HashMap;

use agnostic_lite::RuntimeLite;
use futures_util::FutureExt;

use crate::{driver::Tributaries, event::Event, subscription::Subscription};

#[cfg(all(test, feature = "tokio"))]
mod tests;

/// A lane registration, carried to the routing task over the unbounded control channel:
/// from application onward, `sub`'s events are delivered into `lane`.
struct Register<C, V> {
  /// The subscription whose events the lane claims.
  sub: Subscription,
  /// The bounded send side the routing task delivers into; the matching receiver lives
  /// in the caller's [`Lane`].
  lane: async_channel::Sender<Event<C, V>>,
}

/// One subscription's routing slot inside the task's lane table.
enum LaneSlot<C, V> {
  /// A registered, live lane: deliveries are awaited sends into it (the deliberate
  /// stall when it is full).
  Open(async_channel::Sender<Event<C, V>>),
  /// The lane's receiver was dropped: the consumer walked away, so this subscription's
  /// traffic is discarded — never rerouted to rest. Kept as a tombstone so a later
  /// event cannot fall through to the rest lane; the table grows only with lanes ever
  /// claimed, so this stays bounded by the caller's own registrations.
  Retired,
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
/// [`lane`](Self::lane) registers a bounded per-subscription lane over an **unbounded**
/// control channel into the routing task — control messages are tiny and rare, so
/// registration is fire-and-forget. Events whose subscription has no registered lane
/// land on the **rest** lane returned by [`spawn`](Self::spawn). A registration is
/// applied before the routing of any event that enters the shared stream after it, so
/// events emitted after `lane` returns reach the lane; events already in flight may
/// still land on rest — register the lane before its events flow, or drain rest.
///
/// # Dropped lanes retire their subscription
///
/// A lane whose receiver is dropped mid-traffic is removed, and the event that found it
/// dropped — plus **all subsequent events for that subscription** — are discarded: the
/// lane consumer walked away, the same choice as an unwatch dropping parked debt. A
/// claimed subscription's traffic is **never** rerouted to rest (rest is for the
/// never-claimed). Likewise, once the rest receiver is dropped, unrouted events are
/// discarded from then on. Registering a fresh lane for the subscription re-claims it
/// from that point onward.
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
/// # #[cfg(feature = "tokio")]
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use std::{ffi::OsString, path::Path};
///
/// use tributaries::{Demux, Filter, Interest, TokioTributaries, TributariesOptions};
///
/// fn key(path: &str) -> Vec<OsString> {
///   Path::new(path)
///     .components()
///     .map(|c| c.as_os_str().to_os_string())
///     .collect()
/// }
///
/// let w = TokioTributaries::new(TributariesOptions::new())?;
/// let project = key("/path/to/project");
/// let sub = w
///   .watch(project.clone(), (), Interest::all(), Filter::all())
///   .await?;
///
/// // The demux CONSUMES one handle (the sole drainer); `w` stays behind for
/// // watch/unwatch/close only — never for next().
/// let (demux, rest) = Demux::spawn(w.clone(), 64);
/// let lane = demux.lane(sub, 64);
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
  /// The unbounded registration channel into the routing task.
  control: async_channel::Sender<Register<C, V>>,
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
    let (control_tx, control_rx) = async_channel::unbounded();
    let (rest_tx, rest_rx) = async_channel::bounded(rest_capacity);
    R::spawn_detach(run(watcher, control_rx, rest_tx));
    (
      Self {
        control: control_tx,
      },
      Lane { events: rest_rx },
    )
  }

  /// Registers a bounded lane (of `capacity` events) for `sub` with the routing task,
  /// returning its receive side.
  ///
  /// Registration is **fire-and-forget** over the unbounded control channel. It is
  /// applied before the routing of any event that enters the shared stream after it,
  /// so events emitted after this returns reach the lane; events already in flight may
  /// still land on rest — register before the subscription's events flow, or drain
  /// rest. Registering a second lane for the same subscription re-points routing to it
  /// (the previous lane drains its buffer and ends), and re-claims a subscription whose
  /// earlier lane was dropped.
  ///
  /// A lane registered after the routing task has exited (the stream already ended)
  /// yields `None` immediately — indistinguishable from a lane at end-of-stream.
  ///
  /// # Panics
  ///
  /// Panics if `capacity` is zero (a lane must be able to buffer at least one event).
  pub fn lane(&self, sub: Subscription, capacity: usize) -> Lane<C, V> {
    let (lane_tx, lane_rx) = async_channel::bounded(capacity);
    // Fire-and-forget on an unbounded channel: the send fails only when the routing
    // task is gone (end-of-stream), in which case `lane_tx` drops with the message and
    // the returned lane immediately reads end-of-stream.
    let _ = self.control.try_send(Register { sub, lane: lane_tx });
    Lane { events: lane_rx }
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
  control: async_channel::Receiver<Register<C, V>>,
  rest: async_channel::Sender<Event<C, V>>,
) where
  R: RuntimeLite,
{
  let mut lanes: HashMap<Subscription, LaneSlot<C, V>> = HashMap::new();
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
        register = control.recv().fuse() => {
          match register {
            Ok(Register { sub, lane }) => {
              // Insert unconditionally: a fresh lane re-points (or re-claims) the sub.
              lanes.insert(sub, LaneSlot::Open(lane));
            }
            Err(_) => control_open = false,
          }
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
    let sub = event.subscription();
    let lane_gone = match lanes.get(&sub) {
      // THE deliberate stall (stall-not-shed): await the bounded lane send. While a
      // full lane holds this send, the task stops receiving from the shared stream;
      // the shared channel fills and the ACTOR's overflow machinery mints the genuine
      // dominating Rescans. The demux itself never sheds here.
      Some(LaneSlot::Open(lane)) => lane.send(event).await.is_err(),
      // The lane consumer walked away earlier: discard, never reroute to rest.
      Some(LaneSlot::Retired) => false,
      // Unclaimed subscription: the rest lane — same awaited-send stall. A dropped
      // rest receiver discards unrouted events from then on.
      None => {
        if let Some(lane) = &rest
          && lane.send(event).await.is_err()
        {
          rest = None;
        }
        false
      }
    };
    if lane_gone {
      // The send observed the lane's receiver dropped (the event it carried is
      // discarded with it): retire the subscription's slot.
      lanes.insert(sub, LaneSlot::Retired);
    }
  }
  // Returning drops every lane sender (the table) and the rest sender: each `Lane`
  // drains its buffered tail, then reads `None`.
}
