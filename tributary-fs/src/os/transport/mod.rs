//! The payload-generic source transport: one ordered queue per source.
//!
//! Every message of a source — `Batch`, `Overflow`, `Fatal` — rides ONE
//! unbounded FIFO queue, so per-source ordering between data and the signals
//! covering it holds by construction (there is no second lane to race) and a
//! signal send can never fail for capacity. The queue being unbounded, memory
//! is bounded here instead: a batch may enqueue only under a [`BudgetPermit`],
//! the overflow dedup keeps at most one `Overflow` per ADJACENT run of losses,
//! and the `Fatal` dedup one terminal message ever.
//!
//! The overflow dedup is queue-position-aware, not a single latch: it
//! collapses only losses with nothing enqueued between them. A `Batch`
//! enqueued behind a pending `Overflow` ends that run, so a later loss elects a
//! FRESH `Overflow` behind the batch. This is the invariant the driver relies
//! on — every `Batch` is followed by a covering `Overflow` if any loss
//! postdates it — because an `Overflow`'s consumption rescans state as of that
//! queue position, and a loss that postdates an interposed batch is stale
//! relative to it: only a second `Overflow` behind the batch covers that
//! staleness (see [`signal_loss`] and [`forward_batch`]).
//!
//! The machinery is generic over the decoded event payload `E` — each backend
//! supplies its own (`os::fsevent::RawOsEvent` on macOS); the protocol never
//! reads the events it carries. Producers differ per backend (a dispatch-queue
//! callback, a reader thread) but are all one serial sender, which is the only
//! shape the protocol assumes.

use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};
// `AtomicBool` backs only the `fatal_sent` dedup, which lives inside the
// backend-gated `TransportState`; the always-compiled RAII types
// (`BudgetPermit`, `OverflowAck`) use `AtomicUsize`. Gating the import to that
// same cfg keeps a backend-less build (wasm lib) warning-clean.
#[cfg(any(
  all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    not(miri)
  ),
  test
))]
use std::sync::atomic::AtomicBool;

use super::{ResumeToken, SourceError};

/// The PUBLISHED half of one source's resume point: the journal position the
/// driver has provably ingested, and nothing beyond it.
///
/// The producer never writes here. It stages a candidate with the batch that
/// reaches that position ([`ResumeAck`]) and the driver publishes it at ingest,
/// so the three ways a batch can fail to arrive — dropped over budget, refused
/// by a gone receiver, still queued when the stream is retired — all leave the
/// point exactly where the last ingested batch left it.
///
/// A gap between two published points is always covered: a batch that did not
/// land degrades to an in-band `Overflow` at its own queue position, which is
/// AHEAD of any later batch on the source's one ordered queue — so a later
/// publish can only happen after the driver already turned that loss into a
/// rescan.
#[derive(Debug, Default)]
pub(crate) struct ResumeShared {
  published: std::sync::Mutex<Option<ResumeToken>>,
}

// Only a journal-bearing backend stages resume points; a Linux or stub build
// carries the type because the transport is shared, and never mints one.
#[cfg_attr(
  not(any(all(any(target_os = "macos", target_os = "windows"), not(miri)), test)),
  allow(dead_code)
)]
impl ResumeShared {
  /// The last acknowledged point, or `None` before any batch was ingested.
  pub(crate) fn published(&self) -> Option<ResumeToken> {
    *self.published.lock().unwrap_or_else(|err| err.into_inner())
  }

  /// Publishes `token` unless it would move the point BACKWARD within its own
  /// scope. A token from a DIFFERENT scope replaces outright: a re-anchored
  /// journal (a wrap, a purge, a recreated journal id) mints a cursor that is
  /// numerically smaller and semantically newer, and keeping the stale one would
  /// hand the successor a cursor its journal never had.
  fn publish(&self, token: ResumeToken) {
    let mut slot = self.published.lock().unwrap_or_else(|err| err.into_inner());
    match slot.as_ref() {
      Some(current) if current.same_scope(&token) && !token.reaches(current) => {}
      _ => *slot = Some(token),
    }
  }
}

/// The resume candidate one enqueued batch carries: the point a successor may
/// resume from ONCE this batch has been ingested.
///
/// Publishing is explicit ([`acknowledge`](Self::acknowledge)) and dropping
/// publishes nothing, which is the whole mechanism: a payload discarded anywhere
/// on its way to the core silently takes its candidate with it.
#[derive(Debug)]
pub(crate) struct ResumeAck {
  shared: Arc<ResumeShared>,
  candidate: ResumeToken,
}

impl ResumeAck {
  /// Publishes this batch's candidate — called only where the batch is handed
  /// to the core.
  fn acknowledge(self) {
    self.shared.publish(self.candidate);
  }
}

/// The transport-side state one source's producer owns: the batch budget and
/// the two signal dedups.
// The producer-side machinery is driven only by a real backend; the gate
// mirrors that consumer's exact cfg so a build with no backend carries none of
// it, while the interleaving/protocol suites compile it everywhere under test
// (including miri).
#[cfg(any(
  all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    not(miri)
  ),
  test
))]
#[derive(Debug)]
pub(crate) struct TransportState {
  /// Batches currently enqueued (or being processed); the budget cap bounds
  /// the queue's memory since the queue itself is unbounded.
  in_flight: Arc<AtomicUsize>,
  /// The most batches allowed in flight at once.
  budget: usize,
  /// The overflow dedup generation. Its low bit is the "an `Overflow` is
  /// pending" flag; the rest is a monotone counter advanced on every
  /// transition. A loss elects an `Overflow` only when the flag is clear
  /// (even); enqueuing a `Batch` while it is set advances the generation to
  /// EVEN (a batch now trails the pending signal, so a later loss is no longer
  /// adjacent and must elect afresh); an [`OverflowAck`] re-arms only if the
  /// generation still holds the exact value its election set — a batch or a
  /// newer election having advanced it makes the ack a no-op, so a stale ack
  /// can never clear a live pending signal. This is what makes the dedup
  /// queue-position-aware rather than a single latch.
  overflow_gen: Arc<AtomicUsize>,
  /// The terminal `Fatal` was sent; later failures are no-ops.
  fatal_sent: AtomicBool,
}

#[cfg(any(
  all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    not(miri)
  ),
  test
))]
impl TransportState {
  /// A fresh transport allowing `budget` batches in flight.
  pub(crate) fn new(budget: usize) -> Self {
    Self {
      in_flight: Arc::new(AtomicUsize::new(0)),
      budget,
      overflow_gen: Arc::new(AtomicUsize::new(0)),
      fatal_sent: AtomicBool::new(false),
    }
  }

  /// Batches currently holding a permit (in the queue or being processed).
  #[cfg(test)]
  pub(crate) fn in_flight(&self) -> usize {
    self.in_flight.load(Ordering::Acquire)
  }

  /// Whether an `Overflow` is pending at the tail of the queue (the low bit of
  /// the dedup generation) — a subsequent adjacent loss rides it.
  #[cfg(test)]
  pub(crate) fn overflow_pending(&self) -> bool {
    self.overflow_gen.load(Ordering::Acquire) & 1 == 1
  }

  /// Ends any pending-`Overflow` run because a `Batch` now trails it: advances
  /// the generation to the next EVEN value so a later loss elects a fresh
  /// `Overflow` behind this batch, and the pending signal's ack — pinned to the
  /// old odd generation — no longer re-arms (a newer election owns that). A
  /// no-op when no `Overflow` is pending (the generation is already even).
  ///
  /// Called ONLY after a `Batch` actually landed on the queue: a refused send
  /// enqueues nothing, so it must not advance the position.
  fn batch_superseded_pending_overflow(&self) {
    // `fetch_update` is deprecated for `try_update` (nightly), still unstable — keep it.
    #[allow(deprecated)]
    let _ = self
      .overflow_gen
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |g| {
        (g & 1 == 1).then_some(g.wrapping_add(1))
      });
  }
}

/// The RAII budget slot one enqueued batch holds; dropping it — after
/// processing, on a discarded payload, in a shutdown drain, anywhere —
/// returns the slot, so the budget cannot leak on any path.
#[derive(Debug)]
pub(crate) struct BudgetPermit(Arc<AtomicUsize>);

#[cfg(any(
  all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    not(miri)
  ),
  test
))]
impl BudgetPermit {
  /// Claims a slot, or `None` when the budget is exhausted.
  fn acquire(transport: &TransportState) -> Option<Self> {
    let cap = transport.budget;
    // `fetch_update` is deprecated for `try_update` (nightly), still unstable — keep it.
    #[allow(deprecated)]
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
  /// The journal position this batch reaches, for a backend that keeps one.
  /// Unpublished until [`acknowledge_resume`](Self::acknowledge_resume).
  resume: Option<ResumeAck>,
}

impl<E> BatchPayload<E> {
  /// A payload holding a detached permit — for tests without a transport.
  #[cfg(test)]
  pub(crate) fn detached(events: Vec<E>) -> Self {
    Self {
      events,
      permit: BudgetPermit::detached(),
      resume: None,
    }
  }

  /// Publishes this batch's resume candidate, if it carries one.
  ///
  /// Called at the ONE place the driver hands a batch to the core, so the
  /// source's resume point advances over exactly the batches the core was given
  /// — never over one the transport dropped, and never over one still waiting in
  /// the queue when the stream is retired.
  pub(crate) fn acknowledge_resume(&mut self) {
    if let Some(ack) = self.resume.take() {
      ack.acknowledge();
    }
  }
}

/// The RAII acknowledgement riding an `Overflow` message: dropping it —
/// normally by the driver just before it acts on the loss, but equally by a
/// refused send or a shutdown drain — re-arms the dedup so the next loss
/// signals afresh. A loss racing the acknowledgement either elects a fresh
/// message or is covered by the rescan the acknowledged one is about to
/// become.
///
/// The ack is pinned to `elected` — the odd generation the election set. It
/// re-arms (advances that odd generation to the next even) ONLY by a CAS on
/// that exact value: if a later `Batch` superseded this signal, or a newer
/// election advanced past it, the generation no longer matches and the drop is
/// a no-op — so acknowledging an OLDER `Overflow` can never clear a NEWER one
/// still pending behind an interposed batch (the position-aware guarantee).
#[derive(Debug)]
pub(crate) struct OverflowAck {
  generation: Arc<AtomicUsize>,
  elected: usize,
}

impl Drop for OverflowAck {
  fn drop(&mut self) {
    let _ = self.generation.compare_exchange(
      self.elected,
      self.elected.wrapping_add(1),
      Ordering::AcqRel,
      Ordering::Acquire,
    );
  }
}

/// One message from the OS producer to the driver task, on the source's
/// single ordered queue.
// Only a platform backend (or the protocol suites under test) constructs
// messages — the stub platform has none — so a backend-less lib build sees
// the variants as never built. The driver consumes every variant on all
// platforms; cfg-gating them would fracture that match.
#[cfg_attr(
  not(any(
    all(
      any(target_os = "macos", target_os = "linux", target_os = "windows"),
      not(miri)
    ),
    test
  )),
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
///
/// A batch that actually LANDS ends any pending-`Overflow` run: it advances the
/// dedup position so a loss postdating this batch elects a fresh `Overflow`
/// BEHIND it (the batch's own staleness is not covered by the prior signal,
/// which rescanned as of its earlier queue position). A batch refused over
/// budget degrades to a loss instead and does not advance the position.
// Every producer with no journal position to stage forwards through this. The
// one macOS backend always has one, so a macOS lib build reaches it only from
// the suites.
#[cfg_attr(
  not(any(all(any(target_os = "linux", target_os = "windows"), not(miri)), test)),
  allow(dead_code)
)]
#[cfg(any(
  all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    not(miri)
  ),
  test
))]
pub(crate) fn forward_batch<E, S>(transport: &TransportState, events: Vec<E>, lossy: bool, send: S)
where
  S: FnMut(SourceMessage<E>) -> bool,
{
  forward_batch_resuming(transport, events, lossy, None, send);
}

/// [`forward_batch`] for a journal-bearing producer, staging the position this
/// batch reaches so the driver's ingest can publish it.
///
/// The candidate rides the batch and NOTHING else, so every way the batch fails
/// to reach the core takes the candidate with it: refused for budget (the events
/// never leave the producer), refused by a gone receiver, or ingested never
/// because the stream was retired first.
///
/// A LOSSY batch stages nothing whatever its candidate. `lossy` means records in
/// this very read could not be decoded, and no cursor distinguishes the decoded
/// ones from the lost ones — so the position stays behind them and the successor
/// re-reads the span. Replaying is always legal (duplicates are); skipping is
/// not.
#[cfg(any(
  all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    not(miri)
  ),
  test
))]
pub(crate) fn forward_batch_resuming<E, S>(
  transport: &TransportState,
  events: Vec<E>,
  lossy: bool,
  resume: Option<(&Arc<ResumeShared>, ResumeToken)>,
  mut send: S,
) where
  S: FnMut(SourceMessage<E>) -> bool,
{
  let mut lost = lossy;
  if !events.is_empty() {
    match BudgetPermit::acquire(transport) {
      Some(permit) => {
        let resume = (!lossy)
          .then_some(resume)
          .flatten()
          .map(|(shared, candidate)| ResumeAck {
            shared: Arc::clone(shared),
            candidate,
          });
        if !send(SourceMessage::Batch(BatchPayload {
          events,
          permit,
          resume,
        })) {
          return;
        }
        // The batch is now the tail: a pending `Overflow` no longer covers a
        // loss that postdates this batch, so end its run.
        transport.batch_superseded_pending_overflow();
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
/// Election is the generation's even→odd transition: it fires only when no
/// `Overflow` is pending at the tail (the low bit is clear), so ADJACENT losses
/// — nothing enqueued between them — collapse onto the one message. The elected
/// generation tags the [`OverflowAck`]; the signal stays pending until that ack
/// re-arms it (the driver acknowledging, a refused send, a drain) OR a `Batch`
/// supersedes it. A loss postdating an interposed batch finds the low bit clear
/// again and elects a FRESH `Overflow`, so the batch's staleness is covered.
#[cfg(any(
  all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    not(miri)
  ),
  test
))]
pub(crate) fn signal_loss<E, S>(transport: &TransportState, mut send: S)
where
  S: FnMut(SourceMessage<E>) -> bool,
{
  // `fetch_update` is deprecated for `try_update` (nightly), still unstable — keep it.
  #[allow(deprecated)]
  let elected = transport
    .overflow_gen
    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |g| {
      (g & 1 == 0).then_some(g.wrapping_add(1))
    });
  if let Ok(prev) = elected {
    let ack = OverflowAck {
      generation: Arc::clone(&transport.overflow_gen),
      elected: prev.wrapping_add(1),
    };
    // A refused send drops the message here, whose ack re-arms the dedup.
    let _ = send(SourceMessage::Overflow(ack));
  }
}

/// Enqueues the stream's one terminal `Fatal`, at most once ever.
#[cfg(any(
  all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    not(miri)
  ),
  test
))]
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
