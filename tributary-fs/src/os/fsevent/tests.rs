use super::*;

#[test]
fn flag_predicates_match_their_bits() {
  let f = FsEventFlags::new(FsEventFlags::ITEM_CREATED.bits() | FsEventFlags::ITEM_IS_DIR.bits());
  assert!(f.item_created());
  assert!(f.item_is_dir());
  assert!(!f.item_removed());
  assert!(!f.item_renamed());
  assert!(f.contains(FsEventFlags::ITEM_CREATED));
  assert!(!f.contains(FsEventFlags::ITEM_REMOVED));
}

#[test]
fn coalesced_flag_words_report_every_operation() {
  let f = FsEventFlags::new(
    FsEventFlags::ITEM_CREATED.bits()
      | FsEventFlags::ITEM_MODIFIED.bits()
      | FsEventFlags::ITEM_REMOVED.bits()
      | FsEventFlags::ITEM_RENAMED.bits(),
  );
  assert!(f.item_created() && f.item_modified() && f.item_removed() && f.item_renamed());
}

#[test]
fn lost_sync_covers_both_drop_sides() {
  assert!(FsEventFlags::USER_DROPPED.lost_sync());
  assert!(FsEventFlags::KERNEL_DROPPED.lost_sync());
  assert!(!FsEventFlags::MUST_SCAN_SUBDIRS.lost_sync());
  assert!(!FsEventFlags::new(0).lost_sync());
}

#[test]
fn file_id_policy_is_total() {
  assert_eq!(file_id_from_extended(0), None);
  assert_eq!(file_id_from_extended(5).map(|n| n.get()), Some(5));
  assert_eq!(
    file_id_from_extended(-1).map(|n| n.get()),
    Some(u64::MAX),
    "the bit-cast is the lossless inverse of signed journal storage"
  );
}

#[test]
fn path_from_fs_repr_stops_at_the_first_nul() {
  assert_eq!(
    path_from_fs_repr(b"/tmp/a.txt\0slack"),
    Some(PathBuf::from("/tmp/a.txt"))
  );
  assert_eq!(path_from_fs_repr(b"/tmp/x"), Some(PathBuf::from("/tmp/x")));
  assert_eq!(path_from_fs_repr(b""), None);
  assert_eq!(path_from_fs_repr(b"\0"), None);
}

#[cfg(unix)]
#[test]
fn path_from_fs_repr_preserves_non_utf8_bytes() {
  use std::os::unix::ffi::OsStrExt;
  let bytes = b"/tmp/\xC3\x28\0";
  let path = path_from_fs_repr(bytes).expect("non-UTF-8 bytes are still a path");
  assert_eq!(path.as_os_str().as_bytes(), b"/tmp/\xC3\x28");
}

mod transport {
  use std::collections::VecDeque;

  use super::*;

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
    queue: VecDeque<(u64, SourceMessage)>,
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
    fn send(&mut self, msg: SourceMessage) -> bool {
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
    while model.step_driver() {}
    (model, transport, losses)
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
  /// scripts cover the shapes of every historical transport finding; all
  /// 2^bits driver interleavings of each are executed against the real
  /// transitions. The R1/R3/R7 loss-signalling bugs are all single-batch
  /// counterexamples at this bound.
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
    for seed in 1..=64u64 {
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

  #[test]
  fn budget_denial_degrades_to_an_in_order_overflow() {
    let transport = TransportState::new(1);
    let mut model = Model::default();
    forward_batch(&transport, vec![raw("/r/a")], false, |msg| model.send(msg));
    assert_eq!(transport.in_flight(), 1);
    forward_batch(&transport, vec![raw("/r/b")], false, |msg| model.send(msg));
    let kinds: Vec<&SourceMessage> = model.queue.iter().map(|(_, m)| m).collect();
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
}

mod pure_rename {
  use super::*;

  #[test]
  fn type_hints_keep_a_rename_pure() {
    for extra in [
      0,
      FsEventFlags::ITEM_IS_FILE.bits(),
      FsEventFlags::ITEM_IS_DIR.bits(),
      FsEventFlags::ITEM_IS_SYMLINK.bits(),
      FsEventFlags::ITEM_IS_HARDLINK.bits(),
      FsEventFlags::ITEM_IS_LAST_HARDLINK.bits(),
    ] {
      let word = FsEventFlags::new(FsEventFlags::ITEM_RENAMED.bits() | extra);
      assert!(word.is_pure_rename(), "{word:?}");
    }
  }

  #[test]
  fn any_extra_operation_makes_a_rename_impure() {
    for extra in [
      FsEventFlags::ITEM_CREATED.bits(),
      FsEventFlags::ITEM_REMOVED.bits(),
      FsEventFlags::ITEM_MODIFIED.bits(),
      FsEventFlags::ITEM_INODE_META_MOD.bits(),
      FsEventFlags::ITEM_XATTR_MOD.bits(),
      FsEventFlags::ITEM_CHANGE_OWNER.bits(),
      FsEventFlags::ITEM_FINDER_INFO_MOD.bits(),
      FsEventFlags::ITEM_CLONED.bits(),
      FsEventFlags::OWN_EVENT.bits(),
      FsEventFlags::MUST_SCAN_SUBDIRS.bits(),
      FsEventFlags::ROOT_CHANGED.bits(),
    ] {
      let word = FsEventFlags::new(FsEventFlags::ITEM_RENAMED.bits() | extra);
      assert!(!word.is_pure_rename(), "{word:?}");
    }
    assert!(
      !FsEventFlags::ITEM_MODIFIED.is_pure_rename(),
      "a non-rename word is never a pure rename"
    );
  }
}
