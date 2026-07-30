use std::{collections::VecDeque, path::PathBuf};

use super::*;
use crate::os::fsevent::{FsEventFlags, RawOsEvent};

/// The suites instantiate the generic transport at the macOS payload — the
/// protocol never reads the events, so one concrete payload exercises it for
/// every backend.
type Msg = SourceMessage<RawOsEvent>;

fn raw(path: &str) -> RawOsEvent {
  RawOsEvent {
    path: PathBuf::from(path),
    flags: FsEventFlags::new(0),
    event_id: 1,
    file_id: None,
  }
}

/// A deterministic queue satisfying exactly the three properties the seam
/// assumes of the production channel — FIFO, unbounded, closed-signal —
/// plus a processing log the invariants read. Driving the REAL transport
/// functions over it makes every schedule below an execution of production
/// code, not of a parallel model.
#[derive(Default)]
struct Model {
  queue: VecDeque<(u64, Msg)>,
  seq: u64,
  closed: bool,
  /// Queue positions of processed batches and overflows, in processing
  /// order, plus the terminal fatal count.
  processed: Vec<(u64, Kind)>,
  fatals: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
  Batch,
  Overflow,
}

impl Model {
  fn send(&mut self, msg: Msg) -> bool {
    if self.closed {
      // The refused message drops here; its permit/ack releases via Drop.
      return false;
    }
    self.seq += 1;
    self.queue.push_back((self.seq, msg));
    true
  }

  /// One driver step: process the head message, exactly as the driver
  /// does — an Overflow's ack drops before anything else happens.
  fn step_driver(&mut self) -> bool {
    let Some((pos, msg)) = self.queue.pop_front() else {
      return false;
    };
    match msg {
      SourceMessage::Batch(payload) => {
        self.processed.push((pos, Kind::Batch));
        drop(payload);
      }
      SourceMessage::Overflow(ack) => {
        drop(ack);
        self.processed.push((pos, Kind::Overflow));
      }
      SourceMessage::Fatal(_) => self.fatals += 1,
    }
    true
  }
}

/// A bit-string schedule: each `take` consumes one interleaving decision.
struct Chooser {
  bits: u32,
  idx: u32,
}

impl Chooser {
  fn take(&mut self) -> bool {
    // Long schedules wrap the bit-string: a repeating interleaving pattern
    // is still a valid schedule, and the exhaustive tier stays complete at
    // its own (sub-32-decision) bound.
    let bit = (self.bits >> (self.idx % u32::BITS)) & 1 == 1;
    self.idx = self.idx.wrapping_add(1);
    bit
  }
}

#[derive(Debug, Clone, Copy)]
enum CbOp {
  /// One callback delivering `events` decoded events, `lossy` when decode
  /// also dropped something.
  Batch { events: usize, lossy: bool },
  /// A callback whose every entry was undecodable.
  LossyEmpty,
  /// A callback panic's terminal signal.
  Fatal,
}

/// Runs one schedule of `ops` against a fresh transport with `budget`,
/// interleaving driver steps per the schedule bits — before each callback
/// op and, through the send hook, between a signal's election and its
/// enqueue (the exact window the deleted latch protocol raced on).
/// Returns the model and the callback-side ground-truth loss count.
fn run_schedule(budget: usize, ops: &[CbOp], bits: u32) -> (Model, TransportState, usize) {
  let transport = TransportState::new(budget);
  let mut model = Model::default();
  let mut chooser = Chooser { bits, idx: 0 };
  let mut losses = 0usize;
  for op in ops {
    if chooser.take() {
      model.step_driver();
    }
    assert_permit_accounting(&model, &transport);
    match *op {
      CbOp::Batch { events, lossy } => {
        if lossy {
          losses += 1;
        }
        if events > 0 && transport.in_flight() >= budget {
          // The budget will refuse: this batch degrades to a loss.
          losses += 1;
        }
        let batch: Vec<RawOsEvent> = (0..events).map(|_| raw("/r/x")).collect();
        let interpose = chooser.take();
        forward_batch(&transport, batch, lossy, |msg| {
          if interpose {
            model.step_driver();
          }
          model.send(msg)
        });
      }
      CbOp::LossyEmpty => {
        losses += 1;
        let interpose = chooser.take();
        forward_batch(&transport, Vec::new(), true, |msg| {
          if interpose {
            model.step_driver();
          }
          model.send(msg)
        });
      }
      CbOp::Fatal => {
        signal_fatal_once(&transport, SourceError::CallbackPanic, |msg| {
          model.send(msg)
        });
      }
    }
  }
  while model.step_driver() {
    assert_permit_accounting(&model, &transport);
  }
  (model, transport, losses)
}

/// The permit-accounting invariant, checked at every quiescent point of a
/// schedule (this model consumes payloads on processing, so live payloads
/// are exactly the queued batches): `in_flight` equals the batches whose
/// permits are still alive — the budget neither leaks nor double-returns.
fn assert_permit_accounting(model: &Model, transport: &TransportState) {
  let queued_batches = model
    .queue
    .iter()
    .filter(|(_, msg)| matches!(msg, SourceMessage::Batch(_)))
    .count();
  assert_eq!(
    transport.in_flight(),
    queued_batches,
    "in_flight tracks live payloads exactly"
  );
}

/// The invariants every schedule must satisfy at quiescence. Together they
/// are the no-silent-loss transport contract: a loss always surfaces as at
/// least one processed Overflow, the dedup never floods, the budget never
/// leaks, and processing observes queue order (the property that makes a
/// signal unable to overtake the data it postdates).
fn assert_quiescent(model: &Model, transport: &TransportState, losses: usize, ctx: &str) {
  let overflows = model
    .processed
    .iter()
    .filter(|(_, k)| *k == Kind::Overflow)
    .count();
  if losses > 0 {
    assert!(overflows >= 1, "{ctx}: a loss must surface as an Overflow");
  }
  assert!(
    overflows <= losses,
    "{ctx}: the dedup admits at most one Overflow per loss"
  );
  assert_eq!(
    transport.in_flight(),
    0,
    "{ctx}: every batch permit is returned"
  );
  assert!(
    !transport.overflow_pending(),
    "{ctx}: a drained queue leaves no pending signal"
  );
  assert!(model.fatals <= 1, "{ctx}: the Fatal is once-ever");
  assert!(
    model.processed.windows(2).all(|w| w[0].0 < w[1].0),
    "{ctx}: processing observes queue order"
  );
}

/// Tier 1: EXHAUSTIVE small-bound interleaving enumeration. Three op
/// scripts cover the loss-signalling failure shapes (an unwoken loss
/// marker, a store racing its own wake, a signal overtaking queued data);
/// all 2^bits driver interleavings of each are executed against the real
/// transitions — each of those bugs is a single-batch counterexample at
/// this bound.
#[test]
fn every_small_interleaving_holds_the_transport_contract() {
  let scripts: &[(usize, &[CbOp])] = &[
    (
      2,
      &[
        CbOp::Batch {
          events: 1,
          lossy: false,
        },
        CbOp::Batch {
          events: 1,
          lossy: true,
        },
        CbOp::LossyEmpty,
      ],
    ),
    (
      1,
      &[
        CbOp::Batch {
          events: 1,
          lossy: false,
        },
        CbOp::Batch {
          events: 1,
          lossy: false,
        },
        CbOp::Batch {
          events: 1,
          lossy: false,
        },
      ],
    ),
    (
      1,
      &[
        CbOp::LossyEmpty,
        CbOp::Batch {
          events: 1,
          lossy: true,
        },
        CbOp::Fatal,
      ],
    ),
  ];
  for (i, (budget, ops)) in scripts.iter().enumerate() {
    for bits in 0..(1u32 << 9) {
      let (model, transport, losses) = run_schedule(*budget, ops, bits);
      assert_quiescent(
        &model,
        &transport,
        losses,
        &format!("script {i} bits {bits:#011b}"),
      );
    }
  }
}

/// Tier 2: a seeded schedule storm past the exhaustive bound — long random
/// op histories (multi-loss, dedup re-arm cycles, fatal-after-loss) under
/// random driver interleavings.
#[test]
fn random_schedules_hold_the_transport_contract() {
  // Seeds are statistical convergence coverage, which is the native runs' job:
  // one seed drives every code path the rest do, while sixty-odd seeds' worth of
  // churn is enough to exhaust a 32-bit target's whole address space under miri.
  // Miri is here to find UB, so it runs the shape once.
  let seeds: u64 = if cfg!(miri) { 1 } else { 64 };
  for seed in 1..=seeds {
    let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(11);
    let mut rng = || {
      s ^= s << 13;
      s ^= s >> 17;
      s ^= s << 5;
      s
    };
    let mut ops = Vec::with_capacity(200);
    for _ in 0..200 {
      ops.push(match rng() % 8 {
        0 => CbOp::LossyEmpty,
        1 => CbOp::Batch {
          events: 1,
          lossy: true,
        },
        7 => CbOp::Fatal,
        _ => CbOp::Batch {
          events: (rng() % 3) as usize,
          lossy: false,
        },
      });
    }
    let (model, transport, losses) = run_schedule(1 + (rng() % 3) as usize, &ops, rng() as u32);
    assert_quiescent(&model, &transport, losses, &format!("seed {seed}"));
  }
}

#[test]
fn closed_queue_signals_nothing_and_unmutes_the_dedup() {
  let transport = TransportState::new(4);
  let mut model = Model {
    closed: true,
    ..Model::default()
  };
  forward_batch(&transport, vec![raw("/r/a")], true, |msg| model.send(msg));
  assert!(model.queue.is_empty());
  assert_eq!(transport.in_flight(), 0, "the refused permit returned");
  assert!(
    !transport.overflow_pending(),
    "the refused Overflow's ack re-armed the dedup, so a future generation is not muted"
  );
}

#[test]
fn ack_drop_rearms_the_dedup() {
  let transport = TransportState::new(4);
  let mut model = Model::default();
  forward_batch(&transport, Vec::new(), true, |msg| model.send(msg));
  assert!(transport.overflow_pending());
  // A second loss while the first is unacknowledged rides that message.
  forward_batch(&transport, Vec::new(), true, |msg| model.send(msg));
  assert_eq!(model.queue.len(), 1, "the pending signal dedups the loss");
  assert!(model.step_driver(), "the driver processes the Overflow");
  assert!(
    !transport.overflow_pending(),
    "processing (dropping the ack) re-arms the dedup"
  );
  forward_batch(&transport, Vec::new(), true, |msg| model.send(msg));
  assert_eq!(model.queue.len(), 1, "the next loss signals afresh");
}

/// The position-aware dedup's core guarantee: a `Batch` enqueued between two
/// losses ends the first loss's `Overflow` run, so the second loss elects a
/// FRESH `Overflow` BEHIND the batch. Without it, the second loss's staleness
/// (it postdates the interposed batch, which an earlier signal's rescan cannot
/// have covered) rides no covering signal at all. Neither ack has dropped, so
/// this exercises the batch-supersede path, not ack re-arming.
#[test]
fn a_batch_between_losses_elects_a_fresh_overflow_behind_it() {
  let transport = TransportState::new(4);
  let mut model = Model::default();
  // loss1 → Overflow1.
  forward_batch(&transport, Vec::new(), true, |msg| model.send(msg));
  assert!(transport.overflow_pending());
  // A clean batch lands BEHIND the pending Overflow: the run ends.
  forward_batch(&transport, vec![raw("/r/x")], false, |msg| model.send(msg));
  assert!(
    !transport.overflow_pending(),
    "a landed batch supersedes the pending Overflow's run"
  );
  // loss2 — no ack has dropped — must elect a SECOND Overflow, not dedup.
  forward_batch(&transport, Vec::new(), true, |msg| model.send(msg));
  assert!(transport.overflow_pending());
  let kinds: Vec<&Msg> = model.queue.iter().map(|(_, m)| m).collect();
  assert!(
    matches!(
      kinds.as_slice(),
      [
        SourceMessage::Overflow(_),
        SourceMessage::Batch(_),
        SourceMessage::Overflow(_)
      ]
    ),
    "the batch is bracketed by two Overflows, so the batch's staleness is covered: {kinds:?}"
  );
  while model.step_driver() {}
  assert!(!transport.overflow_pending(), "the drained queue re-arms");
}

/// The dedup still collapses ADJACENT losses — nothing enqueued between them —
/// onto one message, so a burst does not flood the queue.
#[test]
fn adjacent_losses_still_collapse_onto_one_overflow() {
  let transport = TransportState::new(4);
  let mut model = Model::default();
  for _ in 0..5 {
    forward_batch(&transport, Vec::new(), true, |msg| model.send(msg));
  }
  let overflows = model
    .queue
    .iter()
    .filter(|(_, m)| matches!(m, SourceMessage::Overflow(_)))
    .count();
  assert_eq!(overflows, 1, "five adjacent losses dedup onto one Overflow");
}

/// Acknowledging the FIRST Overflow while a SECOND pends behind an interposed
/// batch must NOT clear the second's pending state: the older ack is pinned to a
/// superseded generation, so its drop is a no-op on the live signal. This is the
/// exact cross-buffer erasure the single-latch protocol suffered.
#[test]
fn acking_the_first_overflow_leaves_the_second_pending() {
  let transport = TransportState::new(4);
  let mut model = Model::default();
  // loss1 → Overflow1 (pos 1); batch (pos 2); loss2 → Overflow2 (pos 3).
  forward_batch(&transport, Vec::new(), true, |msg| model.send(msg));
  forward_batch(&transport, vec![raw("/r/x")], false, |msg| model.send(msg));
  forward_batch(&transport, Vec::new(), true, |msg| model.send(msg));
  assert!(transport.overflow_pending(), "Overflow2 is pending");
  // Process Overflow1: its ack drops (a superseded generation), and the second
  // Overflow must STILL be pending.
  assert!(model.step_driver(), "process Overflow1");
  assert!(
    transport.overflow_pending(),
    "acking the older Overflow does not clear the newer pending one"
  );
  // Drain: processing Overflow2 drops its ack and finally re-arms.
  while model.step_driver() {}
  assert!(
    !transport.overflow_pending(),
    "only the current Overflow's ack re-arms the dedup"
  );
  // A fresh loss now signals afresh.
  forward_batch(&transport, Vec::new(), true, |msg| model.send(msg));
  assert!(transport.overflow_pending());
}

#[test]
fn budget_denial_degrades_to_an_in_order_overflow() {
  let transport = TransportState::new(1);
  let mut model = Model::default();
  forward_batch(&transport, vec![raw("/r/a")], false, |msg| model.send(msg));
  assert_eq!(transport.in_flight(), 1);
  forward_batch(&transport, vec![raw("/r/b")], false, |msg| model.send(msg));
  let kinds: Vec<&Msg> = model.queue.iter().map(|(_, m)| m).collect();
  assert!(
    matches!(
      kinds.as_slice(),
      [SourceMessage::Batch(_), SourceMessage::Overflow(_)]
    ),
    "the over-budget batch became an Overflow BEHIND the accepted batch: {kinds:?}"
  );
  while model.step_driver() {}
  assert_eq!(transport.in_flight(), 0);
}
