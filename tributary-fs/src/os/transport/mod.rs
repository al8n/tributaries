//! The payload-generic source transport: one ordered queue per source.
//!
//! Every message of a source — `Batch`, `Boundaries`, `Overflow`, `Fatal` —
//! rides ONE unbounded FIFO queue, so per-source ordering between data and the
//! signals covering it holds by construction (there is no second lane to race)
//! and a signal send can never fail for capacity. The queue being unbounded,
//! memory is bounded here instead: a batch may enqueue only under a
//! [`BudgetPermit`], the overflow dedup keeps at most one `Overflow` per
//! ADJACENT run of losses, and the `Fatal` dedup one terminal message ever.
//! `Boundaries` carries no events, so it must not advance the overflow dedup
//! position (see the variant's own docs) — but it does carry memory, and an
//! unbounded queue holding an unbounded number of them is the same hole a
//! permit-less batch would be. It therefore takes a permit against an
//! INDEPENDENT counter ([`BudgetPermit::acquire_boundaries`]): the memory is
//! bounded, and the dedup position is untouched because the boundary counter and
//! the dedup generation are different words. Both properties, neither traded for
//! the other.
//!
//! There are TWO report counters, not one, and both are capped by
//! [`MAX_BOUNDARY_REPORTS_IN_FLIGHT`] rather than by the batch budget. They are
//! separate because their producers are: one claims before an obligation leaves its
//! mailbox, the other before a buffer leaves the kernel, and a backlog on either
//! must not be able to occupy the credit the other paces itself against. Neither
//! exhaustion is a verdict about the CONSUMER — a full counter says eight reports
//! await ingestion at this instant, and permits come back on the driver's thread —
//! so both answer a WAIT, ended by the release itself
//! ([`BoundaryCredit`]).
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

/// The most boundary reports one source may hold on its queue at once, PER
/// PRODUCER CLASS — and deliberately not `os_batch_capacity`.
///
/// # Why it is not the batch budget
///
/// `os_batch_capacity` bounds EVENT-BATCH memory: a batch is up to
/// `os_buffer_bytes` of decoded records, its producer is the kernel's own queue,
/// and its exhaustion degrades to the ordered loss. A boundary report is a
/// different payload with a different producer and a different lifecycle, and it is
/// NOT droppable — the evidence in it is what makes a later mount departure
/// derivable at all — so its exhaustion is back-pressure on the producer instead.
/// The two shared a number for no reason but history, and at the supported floor of
/// `os_batch_capacity = 1` that history cost a healthy source its life: one
/// control-pass recovery report in flight plus one event-path lossy reseed — two
/// ordinary, unrelated events — exhausted the shared count and signalled `Fatal`.
///
/// It is the third instance of the same mistake in this subsystem. The public
/// `max_map_directories` once paid for walk declines
/// (`MAX_WALK_DECLINES` is the split), and the move-in path went on
/// pre-subtracting declines from the map's remaining capacity one round later.
/// A number that bounds one concern may not be read as a verdict about another.
///
/// # Why EIGHT
///
/// It bounds RESIDENCY, so it is sized against the burst each producer legitimately
/// reaches before the driver gets a turn, not against throughput:
///
/// - the control pass emits at most one report per admission within its
///   per-pass quota, plus the one recovery that ends a pass — five. Eight lets a
///   whole pass finish without ever blocking against its OWN output, so the wait it
///   does take is always a statement about the driver.
/// - the event path emits at most one report per buffer read and RESERVES its slot
///   before the read, so eight means eight boundary-bearing buffers may be taken
///   out of the kernel before a ninth waits on the driver. It is headroom for the
///   burst, not a verdict: a full counter is a slow consumer, and the ninth buffer
///   simply stays in the instance's own queue until a slot returns.
///
/// And it stays small because one report is itself capped at `MAX_WALK_DECLINES`
/// (single-digit megabytes at the pathological top, kilobytes at real layouts): a
/// large number here would trade a false terminal for an unbounded queue, which is
/// the hole the permit exists to close.
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
pub(crate) const MAX_BOUNDARY_REPORTS_IN_FLIGHT: usize = 8;

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
  /// Boundary reports the UNDEFERRABLE producer has enqueued (or is processing) —
  /// the event path, whose report is built after the events are already out of the
  /// kernel and the map already rebuilt, so there is nothing left to defer to.
  ///
  /// Its exhaustion is a BOUND and never a verdict, and the distinction is the
  /// finding this counter was split out of. A full counter says
  /// [`MAX_BOUNDARY_REPORTS_IN_FLIGHT`] reports await ingestion AT THIS INSTANT —
  /// a value re-read at a cadence — while permits come back on the driver's own
  /// thread, so reading it as "the driver has stopped consuming" killed sources
  /// that were merely descheduled. The producer WAITS on it instead, before the
  /// buffer that could owe a report ever leaves the kernel
  /// (`fanotify::reader::ReportCredit`), and the wait is ended by the release
  /// itself ([`BoundaryCredit`]). Splitting it off the deferrable counter is what
  /// keeps a control backlog from occupying its headroom; it is not what makes it
  /// a verdict, because nothing here is one. The terminal is reserved for a
  /// liveness proof — a CLOSED receiver, a failed read, an ABI verdict, an
  /// explicit shutdown.
  ///
  /// Separate from the batch count on purpose. Sharing the batch counter would
  /// make a walk's declines cost a batch slot — the back-pressure a boundary
  /// observation must not exert, since it delivers nothing to the consumer — and
  /// pricing a report as a batch would drag the overflow dedup along with it.
  /// A distinct word bounds the memory while leaving both the batch budget and
  /// the dedup generation exactly where they were.
  //
  // Only the fanotify producer walks a tree while live, so every other real
  // backend's build claims no boundary permit — the same gate the
  // `SourceMessage::Boundaries` variant carries.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  reports_in_flight: Arc<AtomicUsize>,
  /// Boundary reports the DEFERRABLE producer has enqueued — the control pass,
  /// which claims its slot before an obligation leaves the mailbox and WAITS when
  /// there is none.
  ///
  /// A third word rather than a share of the second, and for the reason the second
  /// is not a share of the first: the two counters feed OPPOSITE verdicts. An
  /// exhausted undeferrable counter is a dead consumer and the honest answer is the
  /// terminal; an exhausted deferrable one is back-pressure and the honest answer
  /// is to wait. Held on one word, a control backlog running while the driver is
  /// merely slow — a mass unmount is exactly when both happen at once — occupies
  /// the headroom the terminal is read out of, and the event path's next lossy
  /// buffer kills a source with nothing wrong with it. That is the same
  /// two-concerns-one-number defect the batch/boundary split closed, one producer
  /// deeper.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  deferred_reports_in_flight: Arc<AtomicUsize>,
  /// The cap EACH of the two report counters is held to — not `budget`.
  ///
  /// See [`MAX_BOUNDARY_REPORTS_IN_FLIGHT`], which is what every real transport
  /// passes here.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  reports_budget: usize,
  /// Notified after a BOUNDARY slot is returned, so a producer that stopped
  /// short for want of credit is woken by the release rather than by unrelated
  /// traffic.
  ///
  /// A boundary report is NOT droppable — the evidence in it is what makes a
  /// later mount departure derivable — so a producer facing an exhausted counter
  /// waits, whichever counter it is. Waiting is only a move if something ends the
  /// wait, and nothing else does: the reader blocks in `poll`, and the driver
  /// consuming the queue is a different thread that posts no control message for
  /// it. This is that edge.
  ///
  /// `None` for every backend that produces no boundary reports at all, and the
  /// wake is elided anyway when the reader is demonstrably not parked.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  boundary_credit: Option<Arc<dyn BoundaryCredit>>,
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
  /// A fresh transport allowing `budget` BATCHES in flight, and
  /// [`MAX_BOUNDARY_REPORTS_IN_FLIGHT`] boundary reports per producer class.
  ///
  /// `budget` is the caller's `os_batch_capacity`, and it deliberately does not
  /// reach the report counters — see the constant.
  pub(crate) fn new(budget: usize) -> Self {
    Self::with_boundary_credit(budget, None)
  }

  /// The same transport, plus the edge a producer waiting on boundary credit is
  /// woken by. See [`boundary_credit`](Self::boundary_credit).
  pub(crate) fn with_boundary_credit(
    budget: usize,
    boundary_credit: Option<Arc<dyn BoundaryCredit>>,
  ) -> Self {
    Self::with_report_budget(budget, MAX_BOUNDARY_REPORTS_IN_FLIGHT, boundary_credit)
  }

  /// The same transport with the REPORT budget chosen — for the cells that drive
  /// a producer to its credit floor, which is a different floor from
  /// `os_batch_capacity`'s and must be reachable without pretending the two are
  /// one number.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  pub(crate) fn with_report_budget(
    budget: usize,
    reports_budget: usize,
    boundary_credit: Option<Arc<dyn BoundaryCredit>>,
  ) -> Self {
    Self {
      in_flight: Arc::new(AtomicUsize::new(0)),
      budget,
      reports_in_flight: Arc::new(AtomicUsize::new(0)),
      deferred_reports_in_flight: Arc::new(AtomicUsize::new(0)),
      reports_budget,
      boundary_credit,
      overflow_gen: Arc::new(AtomicUsize::new(0)),
      fatal_sent: AtomicBool::new(false),
    }
  }

  /// Batches currently holding a permit (in the queue or being processed).
  #[cfg(test)]
  pub(crate) fn in_flight(&self) -> usize {
    self.in_flight.load(Ordering::Acquire)
  }

  /// Boundary reports currently holding a permit, of EITHER producer class — the
  /// total residency, which is what "the core has ingested everything" reads.
  #[cfg(test)]
  pub(crate) fn boundaries_in_flight(&self) -> usize {
    self.reports_in_flight.load(Ordering::Acquire)
      + self.deferred_reports_in_flight.load(Ordering::Acquire)
  }

  /// Just the DEFERRABLE producer's, for the cells that have to show a control
  /// backlog cannot occupy the headroom the terminal is read out of.
  //
  // Only the fanotify reader has a deferrable report producer, so only its cells
  // read this apart.
  #[cfg(test)]
  #[cfg_attr(not(all(target_os = "linux", not(miri))), allow(dead_code))]
  pub(crate) fn deferred_boundaries_in_flight(&self) -> usize {
    self.deferred_reports_in_flight.load(Ordering::Acquire)
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

/// What a released BOUNDARY slot notifies — the producer-side wake, kept behind a
/// trait so the transport does not reach into any one backend's reader.
///
/// Implemented by the Linux readers' `WakeState`, whose `wake_if_parked` is
/// exactly the right shape: the slot is returned BEFORE the notify (the "enqueue"
/// half of the lost-wakeup handshake), and a reader that is not parked pays no
/// syscall.
pub(crate) trait BoundaryCredit: std::fmt::Debug + Send + Sync {
  /// A boundary slot has just been returned.
  fn boundary_released(&self);
}

/// The RAII budget slot one enqueued batch holds; dropping it — after
/// processing, on a discarded payload, in a shutdown drain, anywhere —
/// returns the slot, so the budget cannot leak on any path.
#[derive(Debug)]
pub(crate) struct BudgetPermit {
  counter: Arc<AtomicUsize>,
  /// Set only for a BOUNDARY slot, and only where a producer can wait for one.
  credit: Option<Arc<dyn BoundaryCredit>>,
}

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
    Self::claim(&transport.in_flight, transport.budget, None)
  }

  /// Claims a BOUNDARY slot — the same RAII permit against the transport's
  /// independent boundary counter, so a queued report is memory-bounded without
  /// spending a batch slot or touching the overflow dedup generation.
  #[cfg(any(all(target_os = "linux", not(miri)), test))]
  pub(crate) fn acquire_boundaries(transport: &TransportState) -> Option<Self> {
    Self::claim(
      &transport.reports_in_flight,
      transport.reports_budget,
      transport.boundary_credit.clone(),
    )
  }

  /// Claims a DEFERRABLE boundary slot — the control pass's, against its own
  /// counter, so a backlog of admission reports can never occupy the headroom the
  /// event path's terminal verdict is read out of.
  //
  // Exactly its callers' cfg: only the fanotify reader has a deferrable report
  // producer, and the only other caller is the tokio-gated driver harness, which
  // prices a recovery reply where production does.
  #[cfg(any(all(target_os = "linux", not(miri)), all(test, feature = "tokio")))]
  pub(crate) fn acquire_deferred_boundaries(transport: &TransportState) -> Option<Self> {
    Self::claim(
      &transport.deferred_reports_in_flight,
      transport.reports_budget,
      transport.boundary_credit.clone(),
    )
  }

  /// The shared claim: bump `counter` while it is below `cap`, and hand back a
  /// permit that releases exactly that counter on drop.
  fn claim(
    counter: &Arc<AtomicUsize>,
    cap: usize,
    credit: Option<Arc<dyn BoundaryCredit>>,
  ) -> Option<Self> {
    // `fetch_update` is deprecated for `try_update` (nightly), still unstable — keep it.
    #[allow(deprecated)]
    counter
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
        (n < cap).then_some(n + 1)
      })
      .ok()?;
    Some(Self {
      counter: Arc::clone(counter),
      credit,
    })
  }
}

impl BudgetPermit {
  /// A permit against a private, standalone counter — for tests that need a
  /// payload without a live [`TransportState`]. Dropping it balances its own
  /// counter and nothing else.
  #[cfg(test)]
  pub(crate) fn detached() -> Self {
    Self {
      counter: Arc::new(AtomicUsize::new(1)),
      credit: None,
    }
  }
}

impl Drop for BudgetPermit {
  fn drop(&mut self) {
    // The slot goes back FIRST and the notify follows: a producer woken by this
    // edge re-reads the counter, and it must find the room this drop just made.
    self.counter.fetch_sub(1, Ordering::AcqRel);
    if let Some(credit) = self.credit.as_deref() {
      credit.boundary_released();
    }
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
  /// SEAM 2, live half: the boundaries a producer's own WALK declined, on their
  /// way to the core's coverage set, plus the permit bounding their residency.
  ///
  /// Not events, and deliberately outside the BATCH machinery: a report stages no
  /// resume position, spends no batch slot, and touches neither the loss dedup nor
  /// the transport's batch budget. A boundary observation delivers nothing to the
  /// consumer — it only tells the core where a walk stopped — so pricing it as a
  /// batch would let a walk's declines advance the dedup position and mute a loss
  /// signal behind them.
  ///
  /// It is NOT outside the memory bound, which is a different property and was
  /// once conflated with that one. The queue is unbounded, so an unpermitted
  /// message is an unbounded one: a reader can drive a walk per buffer, and
  /// nothing in the batch machinery back-pressures a message that takes no batch
  /// slot. The permit is against the transport's INDEPENDENT boundary counter
  /// ([`BudgetPermit::acquire_boundaries`]), so the residency is bounded while the
  /// dedup position is untouched. A producer that cannot claim one WAITS: the
  /// report is not droppable (a positional `Overflow` cannot stand in for evidence
  /// a later departure needs) and a full counter is a slow driver, not a dead one.
  ///
  /// They still ride the source's ONE ordered queue, which is what keeps them
  /// ordered against the events and the loss signals around them: a boundary
  /// recorded ahead of the `Overflow` that covers its location is recorded
  /// before the consumer's covering re-read, never after it.
  ///
  /// The SPAWN walk has no queue to ride — it runs before the stream exists —
  /// and surfaces its declines on `RootMeta::declined` instead.
  //
  // Only the fanotify producer walks a tree while live, so every other real
  // backend's build sees this variant as never constructed while still matching
  // it in the driver's one message body.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  Boundaries(super::WalkBoundaries, BudgetPermit),
  /// One ADMISSION RESEED's answer — the reply half of the round trip an
  /// [`AdmitRequest`](super::AdmitRequest) opened, releasing the cover the core
  /// parked on it.
  ///
  /// Out of band for the same reasons [`Boundaries`](Self::Boundaries) is: it
  /// holds no budget permit, stages no resume position, and delivers nothing to
  /// the consumer, so pricing it as a batch would advance the loss dedup position
  /// and mute an `Overflow` behind it.
  ///
  /// Riding the source's ONE ordered queue is what makes admission-before-cover
  /// true rather than merely intended: the walk mutates the map on the reader
  /// thread and then sends this, so a reply the core acts on is a reply whose
  /// admission has already landed — and every event the reader admitted before it
  /// is already ahead of it on the queue.
  //
  // Only the fanotify producer keeps an admission map, so every other real
  // backend's build sees this variant as never constructed while still matching
  // it in the driver's one message body.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  Admitted(super::AdmitReport),
  /// ONE whole-root recovery, indivisible: the reseed's complete generation, the
  /// loss it implies, and the cutoff that discharges every outstanding admission
  /// at or below it — see [`RootRecovery`](super::RootRecovery).
  ///
  /// It replaces a three-message sequence (a `Boundaries` report, an `Overflow`,
  /// and one `Admitted` per collapsed ticket) whose parts could be dropped
  /// independently of each other. The failure that shape allowed was not a lost
  /// cover but a lost WITNESS: the reply retired the records the departure
  /// verdict had taken while the generation that would have re-recorded the
  /// still-live ones went missing, leaving the source permanently unable to
  /// derive a later departure there — and permanently blind to the ground it
  /// would have revealed.
  ///
  /// It carries a permit like [`Boundaries`](Self::Boundaries), for the same
  /// residency bound — and takes the one its producer claimed BEFORE the
  /// obligation left the mailbox, which is what makes it undroppable without
  /// making the counter a verdict: a pass that cannot claim walks nothing,
  /// consumes nothing, and waits for a released slot.
  //
  // Only the fanotify producer keeps an admission map, so every other real
  // backend's build sees this variant as never constructed while still matching
  // it in the driver's one message body.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  RootRecovered(super::RootRecovery, BudgetPermit),
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
