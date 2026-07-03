//! The payload-generic source transport: one ordered queue per source.
//!
//! Every message of a source — `Batch`, `Overflow`, `Fatal` — rides ONE
//! unbounded FIFO queue, so per-source ordering between data and the signals
//! covering it holds by construction (there is no second lane to race) and a
//! signal send can never fail for capacity. The queue being unbounded, memory
//! is bounded here instead: a batch may enqueue only under a [`BudgetPermit`],
//! and the dedups keep at most one `Overflow` (per acknowledgement) and one
//! `Fatal` (ever) in flight.
//!
//! The machinery is generic over the decoded event payload `E` — each backend
//! supplies its own (`os::fsevent::RawOsEvent` on macOS); the protocol never
//! reads the events it carries. Producers differ per backend (a dispatch-queue
//! callback, a reader thread) but are all one serial sender, which is the only
//! shape the protocol assumes.

use std::sync::{
  Arc,
  atomic::{AtomicBool, AtomicUsize, Ordering},
};

use super::SourceError;

/// The transport-side state one source's producer owns: the batch budget and
/// the two signal dedups.
// The producer-side machinery is driven only by a real backend; the gate
// mirrors that consumer's exact cfg so a build with no backend carries none of
// it, while the interleaving/protocol suites compile it everywhere under test
// (including miri).
#[cfg(any(all(any(target_os = "macos", target_os = "linux"), not(miri)), test))]
#[derive(Debug)]
pub(crate) struct TransportState {
  /// Batches currently enqueued (or being processed); the budget cap bounds
  /// the queue's memory since the queue itself is unbounded.
  in_flight: Arc<AtomicUsize>,
  /// The most batches allowed in flight at once.
  budget: usize,
  /// One `Overflow` is enqueued and not yet acknowledged; further losses are
  /// covered by it (the rescan it becomes reads current state).
  overflow_pending: Arc<AtomicBool>,
  /// The terminal `Fatal` was sent; later failures are no-ops.
  fatal_sent: AtomicBool,
}

#[cfg(any(all(any(target_os = "macos", target_os = "linux"), not(miri)), test))]
impl TransportState {
  /// A fresh transport allowing `budget` batches in flight.
  pub(crate) fn new(budget: usize) -> Self {
    Self {
      in_flight: Arc::new(AtomicUsize::new(0)),
      budget,
      overflow_pending: Arc::new(AtomicBool::new(false)),
      fatal_sent: AtomicBool::new(false),
    }
  }

  /// Batches currently holding a permit (in the queue or being processed).
  #[cfg(test)]
  pub(crate) fn in_flight(&self) -> usize {
    self.in_flight.load(Ordering::Acquire)
  }

  /// Whether an unacknowledged `Overflow` is in flight.
  #[cfg(test)]
  pub(crate) fn overflow_pending(&self) -> bool {
    self.overflow_pending.load(Ordering::Acquire)
  }
}

/// The RAII budget slot one enqueued batch holds; dropping it — after
/// processing, on a discarded payload, in a shutdown drain, anywhere —
/// returns the slot, so the budget cannot leak on any path.
#[derive(Debug)]
pub(crate) struct BudgetPermit(Arc<AtomicUsize>);

#[cfg(any(all(any(target_os = "macos", target_os = "linux"), not(miri)), test))]
impl BudgetPermit {
  /// Claims a slot, or `None` when the budget is exhausted.
  fn acquire(transport: &TransportState) -> Option<Self> {
    let cap = transport.budget;
    transport
      .in_flight
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
        (n < cap).then_some(n + 1)
      })
      .ok()?;
    Some(Self(Arc::clone(&transport.in_flight)))
  }
}

impl BudgetPermit {
  /// A permit against a private, standalone counter — for tests that need a
  /// payload without a live [`TransportState`]. Dropping it balances its own
  /// counter and nothing else.
  #[cfg(test)]
  pub(crate) fn detached() -> Self {
    Self(Arc::new(AtomicUsize::new(1)))
  }
}

impl Drop for BudgetPermit {
  fn drop(&mut self) {
    self.0.fetch_sub(1, Ordering::AcqRel);
  }
}

/// One producer invocation's decoded events plus the budget slot they occupy.
/// The batch boundary is preserved (it is the natural rename-pairing window).
///
/// The slot covers the batch's WHOLE retention, not just its queue residency:
/// the driver hands the payload to the core intact, so events parked behind
/// in-flight probes keep holding their permit until the batch settles or is
/// discarded — a stuck probe therefore back-pressures the producer into the
/// ordered loss degrade instead of letting parked memory grow unbudgeted.
#[derive(Debug)]
pub(crate) struct BatchPayload<E> {
  /// The decoded events, in producer order.
  pub(crate) events: Vec<E>,
  /// The budget slot; released when the payload drops.
  pub(crate) permit: BudgetPermit,
}

impl<E> BatchPayload<E> {
  /// A payload holding a detached permit — for tests without a transport.
  #[cfg(test)]
  pub(crate) fn detached(events: Vec<E>) -> Self {
    Self {
      events,
      permit: BudgetPermit::detached(),
    }
  }
}

/// The RAII acknowledgement riding an `Overflow` message: dropping it —
/// normally by the driver just before it acts on the loss, but equally by a
/// refused send or a shutdown drain — re-arms the dedup so the next loss
/// signals afresh. A loss racing the acknowledgement either elects a fresh
/// message or is covered by the rescan the acknowledged one is about to
/// become.
#[derive(Debug)]
pub(crate) struct OverflowAck(Arc<AtomicBool>);

impl Drop for OverflowAck {
  fn drop(&mut self) {
    self.0.store(false, Ordering::Release);
  }
}

/// One message from the OS producer to the driver task, on the source's
/// single ordered queue.
// Only a platform backend (or the protocol suites under test) constructs
// messages — the stub platform has none — so a backend-less lib build sees
// the variants as never built. The driver consumes every variant on all
// platforms; cfg-gating them would fracture that match.
#[cfg_attr(
  not(any(all(any(target_os = "macos", target_os = "linux"), not(miri)), test)),
  allow(dead_code)
)]
#[derive(Debug)]
pub(crate) enum SourceMessage<E> {
  /// One producer invocation's decoded events, holding their budget slot.
  Batch(BatchPayload<E>),
  /// Transport-level loss AT THIS QUEUE POSITION: a batch was dropped over
  /// budget, or an event could not be decoded. The receiver treats the
  /// source's subtrees as needing a rescan; dropping the carried
  /// [`OverflowAck`] (before acting) re-arms the dedup for the next loss.
  Overflow(OverflowAck),
  /// The stream is dead and will deliver nothing more (sent at most once).
  /// The driver reacts to the death itself (root invalidation); the carried
  /// class is diagnostic surface for a future health-reporting channel.
  Fatal(#[allow(dead_code)] SourceError),
}

/// The driver's receiving end of a source's messages.
pub(crate) type EventReceiver<E> = async_channel::Receiver<SourceMessage<E>>;

/// Forwards one decoded producer batch onto the source's single ordered
/// queue.
///
/// `send` returning `false` means the receiver is gone (the queue is
/// unbounded, so capacity is never the reason); nothing further is signaled —
/// a refused `Overflow` is dropped by the send itself, and its
/// [`OverflowAck`] resets the dedup so a future generation is not muted.
///
/// A batch over budget and an undecodable entry both degrade to the same
/// in-order `Overflow`.
#[cfg(any(all(any(target_os = "macos", target_os = "linux"), not(miri)), test))]
pub(crate) fn forward_batch<E, S>(
  transport: &TransportState,
  events: Vec<E>,
  lossy: bool,
  mut send: S,
) where
  S: FnMut(SourceMessage<E>) -> bool,
{
  let mut lost = lossy;
  if !events.is_empty() {
    match BudgetPermit::acquire(transport) {
      Some(permit) => {
        if !send(SourceMessage::Batch(BatchPayload { events, permit })) {
          return;
        }
      }
      None => lost = true,
    }
  }
  if lost {
    signal_loss(transport, send);
  }
}

/// Enqueues one deduplicated `Overflow`.
///
/// The dedup's false→true transition elects exactly one sender; the flag
/// stays set until the message's [`OverflowAck`] drops (the driver
/// acknowledging, a refused send, a drain), so at most one `Overflow` is ever
/// in flight and losses meanwhile are covered by it.
#[cfg(any(all(any(target_os = "macos", target_os = "linux"), not(miri)), test))]
pub(crate) fn signal_loss<E, S>(transport: &TransportState, mut send: S)
where
  S: FnMut(SourceMessage<E>) -> bool,
{
  if !transport.overflow_pending.swap(true, Ordering::AcqRel) {
    let ack = OverflowAck(Arc::clone(&transport.overflow_pending));
    // A refused send drops the message here, whose ack re-arms the dedup.
    let _ = send(SourceMessage::Overflow(ack));
  }
}

/// Enqueues the stream's one terminal `Fatal`, at most once ever.
#[cfg(any(all(any(target_os = "macos", target_os = "linux"), not(miri)), test))]
pub(crate) fn signal_fatal_once<E, S>(transport: &TransportState, err: SourceError, mut send: S)
where
  S: FnMut(SourceMessage<E>) -> bool,
{
  if !transport.fatal_sent.swap(true, Ordering::AcqRel) {
    let _ = send(SourceMessage::Fatal(err));
  }
}

#[cfg(test)]
mod tests;
