/// The pure decode constants restate the kernel ABI; this pins them to libc
/// so they can never drift.
mod libc_cross_assert {
  use crate::os::linux::inotify::decode;

  #[test]
  fn decode_constants_match_libc() {
    assert_eq!(decode::IN_CREATE, libc::IN_CREATE);
    assert_eq!(decode::IN_DELETE, libc::IN_DELETE);
    assert_eq!(decode::IN_DELETE_SELF, libc::IN_DELETE_SELF);
    assert_eq!(decode::IN_MODIFY, libc::IN_MODIFY);
    assert_eq!(decode::IN_ATTRIB, libc::IN_ATTRIB);
    assert_eq!(decode::IN_MOVE_SELF, libc::IN_MOVE_SELF);
    assert_eq!(decode::IN_MOVED_FROM, libc::IN_MOVED_FROM);
    assert_eq!(decode::IN_MOVED_TO, libc::IN_MOVED_TO);
    assert_eq!(decode::IN_UNMOUNT, libc::IN_UNMOUNT);
    assert_eq!(decode::IN_Q_OVERFLOW, libc::IN_Q_OVERFLOW);
    assert_eq!(decode::IN_IGNORED, libc::IN_IGNORED);
    assert_eq!(decode::IN_ISDIR, libc::IN_ISDIR);
    assert_eq!(decode::IN_ONLYDIR, libc::IN_ONLYDIR);
    assert_eq!(decode::IN_DONT_FOLLOW, libc::IN_DONT_FOLLOW);
    assert_eq!(decode::IN_EXCL_UNLINK, libc::IN_EXCL_UNLINK);
    assert_eq!(decode::IN_MASK_CREATE, libc::IN_MASK_CREATE);
  }
}

/// The loss ordering barrier at the reader seam: a lossy buffer forwards ONLY the
/// `Overflow`, never a Batch of the records that trailed the sentinel (whose paths
/// a lost rename could make stale) — the inotify twin of the fanotify barrier.
mod barrier {
  use core::num::NonZeroU64;

  use tributary_proto::WatchId;

  use crate::os::{
    SourceMessage,
    linux::{
      AttributedBatch, attribute_events,
      inotify::{
        decode::{
          DecodeOutcome, IN_CREATE, IN_IGNORED, IN_MOVED_FROM, IN_Q_OVERFLOW, InotifyMask,
          RawInotifyEvent,
        },
        table::{DrainDecision, WdTable},
      },
    },
    transport::TransportState,
  };

  fn watch(n: u64) -> WatchId {
    WatchId::new(NonZeroU64::new(n).unwrap())
  }

  fn event(wd: i32, mask: u32, name: Option<&[u8]>) -> RawInotifyEvent {
    RawInotifyEvent {
      wd,
      mask: InotifyMask(mask),
      cookie: 0,
      name: name.map(<[u8]>::to_vec),
    }
  }

  /// The kind of each message the forward put on the queue, in order.
  #[derive(Debug, PartialEq, Eq)]
  enum Sent {
    Batch(usize),
    Overflow,
  }

  /// Runs the reader's `forward_attributed` over an already-attributed batch,
  /// capturing the kinds of message it forwards, in order.
  fn forward_capture(attributed: AttributedBatch, decode_lossy: bool) -> Vec<Sent> {
    let transport = TransportState::new(8);
    let sent = std::cell::RefCell::new(Vec::new());
    super::super::forward_attributed(&transport, attributed, decode_lossy, |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => unreachable!("no fatal on this path"),
      });
      true
    });
    sent.into_inner()
  }

  /// Attributes `records` against a table holding one live `wd`, then runs the
  /// reader's `forward_attributed` over the result, capturing what it forwards.
  fn run(records: Vec<RawInotifyEvent>, decode_lossy: bool) -> Vec<Sent> {
    let mut table = WdTable::new();
    table.register(3, watch(1));
    let attributed = attribute_events(records, &mut table);
    forward_capture(attributed, decode_lossy)
  }

  /// Runs the reader's real `attribute_and_forward` seam — attribute → reset the
  /// wd-table windows on a decode loss → forward behind the barrier — over `decoded`
  /// against `table`, capturing what it forwards. Unlike `forward_capture`, the
  /// on-decode-loss window reset is EXERCISED here (not stubbed), so this is the seam
  /// the decode-loss stranding regression must go through.
  fn attribute_forward_capture(table: &mut WdTable, decoded: DecodeOutcome) -> Vec<Sent> {
    let transport = TransportState::new(8);
    let sent = std::cell::RefCell::new(Vec::new());
    super::super::attribute_and_forward(&transport, table, decoded, |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => unreachable!("no fatal on this path"),
      });
      true
    });
    sent.into_inner()
  }

  /// An `IN_Q_OVERFLOW` sentinel followed by an attributable record: the reader
  /// drops the trailing record (its path could be stale after a lost rename) and
  /// forwards ONLY the Overflow — no Batch precedes it.
  #[test]
  fn overflow_then_record_forwards_only_the_overflow() {
    let sent = run(
      vec![
        event(-1, IN_Q_OVERFLOW, None),
        // A live rename half whose reported path rides the anchor's recorded
        // path — exactly what a lost rename in the window would make wrong.
        event(3, IN_MOVED_FROM, Some(b"x")),
      ],
      false,
    );
    assert_eq!(
      sent,
      vec![Sent::Overflow],
      "the barrier: the post-sentinel record is dropped, no Batch precedes the Overflow"
    );
  }

  /// A decode-level loss (a truncated tail, `decode_lossy`) applies the same
  /// barrier even with no overflow sentinel in the attributed records.
  #[test]
  fn decode_loss_forwards_only_the_overflow() {
    let sent = run(vec![event(3, IN_CREATE, Some(b"x"))], true);
    assert_eq!(
      sent,
      vec![Sent::Overflow],
      "a decode loss drops the batch too"
    );
  }

  /// A clean buffer forwards its attributed records as one Batch and no Overflow.
  #[test]
  fn clean_buffer_forwards_the_batch() {
    let sent = run(
      vec![
        event(3, IN_CREATE, Some(b"a")),
        event(3, IN_CREATE, Some(b"b")),
      ],
      false,
    );
    assert_eq!(
      sent,
      vec![Sent::Batch(2)],
      "both records ride one Batch, no Overflow"
    );
  }

  /// The post-loss stale-marker sequence at the attribution seam: a live
  /// mapping whose kernel watch died with its markers queued BEHIND a
  /// still-unread overflow, while the replacement binding stands on a FRESH
  /// `wd` — the allocator's next grant, strictly past the stale one (the
  /// no-wrap adoption invariant). The overflow buffer forwards only the
  /// covering `Overflow` (live mappings survive the reap); the late stale
  /// `IN_IGNORED` then erases exactly the stale mapping (fanning its kernel
  /// teardown); the replacement binding is untouchable by it — it lives on a
  /// `wd` the marker does not address — and keeps delivering. Sharing the
  /// stale `wd` (the wrap the instance rebuild forecloses) is the only state
  /// in which this marker could have erased the replacement.
  #[test]
  fn a_post_overflow_stale_marker_erases_only_the_stale_mapping() {
    let mut table = WdTable::new();
    // The stale mapping: watch(1)'s kernel watch is dead, markers queued
    // behind the unread overflow.
    table.register(3, watch(1));
    // The replacement binding: granted past the stale wd (monotone grants).
    table.register(4, watch(2));

    // The overflow sentinel is read first: only the Overflow is forwarded,
    // and both mappings survive (live entries are never reaped).
    let over = attribute_events(vec![event(-1, IN_Q_OVERFLOW, None)], &mut table);
    assert!(over.lost);
    assert_eq!(forward_capture(over, false), vec![Sent::Overflow]);

    // The stale mapping's late IGNORED (queued behind the sentinel) erases
    // it, fanning the kernel teardown to its own anchor — never to watch(2).
    let ignored = attribute_events(vec![event(3, IN_IGNORED, None)], &mut table);
    assert_eq!(
      forward_capture(ignored, false),
      vec![Sent::Batch(1)],
      "the stale mapping's teardown is forwarded to its own anchor"
    );
    assert!(!table.contains(3), "the stale mapping is gone");

    // The replacement binding survives the whole sequence and delivers.
    assert_eq!(table.wd_of(watch(2)), Some(4));
    let live = attribute_events(vec![event(4, IN_CREATE, Some(b"real"))], &mut table);
    assert_eq!(
      forward_capture(live, false),
      vec![Sent::Batch(1)],
      "the replacement binding was never erased by the stale marker"
    );
  }

  /// A decode-level loss reaps a stranded tombstone at the real seam
  /// (`attribute_and_forward`, gated on `decoded.lossy`): the tombstone's
  /// awaited marker may be in the dropped tail, and nothing else reaps one.
  /// If the marker actually survived, its late arrival no-ops on the
  /// unmapped `wd`.
  #[test]
  fn a_decode_loss_reaps_a_stranded_tombstone() {
    let mut table = WdTable::new();
    table.register(3, watch(1));
    assert_eq!(table.begin_drain(watch(1)), DrainDecision::RemoveWd(3));
    assert!(table.contains(3), "the tombstone awaits its marker");

    let decoded = DecodeOutcome {
      events: vec![event(7, IN_CREATE, Some(b"x"))],
      lossy: true,
    };
    assert_eq!(
      attribute_forward_capture(&mut table, decoded),
      vec![Sent::Overflow],
      "the lossy buffer forwards only the covering Overflow"
    );
    assert!(!table.contains(3), "the decode loss reaped the tombstone");

    // The marker the reap presumed dropped arrives after all: a no-op.
    let straggler = attribute_events(vec![event(3, IN_IGNORED, None)], &mut table);
    assert!(straggler.events.is_empty() && !straggler.lost);
    assert!(!table.contains(3));
  }

  /// A clean buffer reaps nothing: absent a decode loss the tombstone stays
  /// until its own marker erases it — the ordinary draining discipline.
  #[test]
  fn a_clean_buffer_leaves_a_tombstone_for_its_own_marker() {
    let mut table = WdTable::new();
    table.register(3, watch(1));
    assert_eq!(table.begin_drain(watch(1)), DrainDecision::RemoveWd(3));

    let decoded = DecodeOutcome {
      events: vec![event(3, IN_CREATE, Some(b"late"))],
      lossy: false,
    };
    assert_eq!(
      attribute_forward_capture(&mut table, decoded),
      Vec::<Sent>::new(),
      "a record on the draining wd is skipped without loss"
    );
    assert!(table.contains(3), "no loss, no reap");

    // Its own marker is the authoritative erase.
    let ignored = attribute_events(vec![event(3, IN_IGNORED, None)], &mut table);
    assert!(ignored.events.is_empty());
    assert!(!table.contains(3));
  }
}

/// Reader-teardown fairness: the drain loop services control BETWEEN reads, so a
/// source that stays readable under sustained traffic can never wedge teardown or
/// starve arm/disarm. `/dev/zero` is the hermetic stand-in for an always-readable
/// source (it never returns `EAGAIN`), so the ONLY way a drain over it can return
/// is by observing the interleaved control — the reader module is already gated to
/// Linux/non-miri, so a real fd is available here.
mod liveness {
  use core::num::NonZeroU64;
  use std::{ffi::OsString, os::fd::OwnedFd, sync::mpsc, time::Duration};

  use tributary_proto::{WatchError, WatchId};

  use super::super::{
    AnchorRequest, BatchReply, Control, ControlOp, DrainExit, Instance, ReaderShared, drain_events,
  };
  use crate::os::{
    SourceMessage,
    linux::{WatchOutcome, wake::WakeState},
    transport::TransportState,
  };

  /// An always-readable fd that never returns `EAGAIN`, standing in for a source
  /// under sustained traffic: `drain_events` reads it forever unless it observes a
  /// control message between reads.
  fn never_eagain_fd() -> OwnedFd {
    std::fs::File::open("/dev/zero")
      .expect("/dev/zero opens on linux")
      .into()
  }

  /// An instance over `fd` whose rebuild threshold can never trip (no arm in
  /// these cells grants a `wd`).
  fn instance(fd: OwnedFd) -> Instance {
    Instance::with_threshold(fd, i32::MAX)
  }

  /// A `ReaderShared` over an unbounded queue; the returned receiver is kept alive
  /// so the queue never closes (the all-zero drain forwards nothing, but a closed
  /// queue would still be a surprise the tests should not carry).
  fn reader_shared() -> (ReaderShared, async_channel::Receiver<SourceMessage>) {
    let (tx, rx) = async_channel::unbounded();
    let shared = ReaderShared {
      queue: tx,
      transport: TransportState::new(8),
      buffer_bytes: 64 * 1024,
    };
    (shared, rx)
  }

  /// A pending `Shutdown` stops the drain at the TOP of the loop, before the next
  /// read — so even against a never-`EAGAIN` fd the reader observes teardown at
  /// once. A watchdog bounds the assertion: a regressed check that never consults
  /// control would spin on `/dev/zero` forever, failing as a timeout.
  #[test]
  fn pending_shutdown_stops_the_drain_before_eagain() {
    let fd = never_eagain_fd();
    let (tx, rx) = mpsc::channel();
    tx.send(Control::Shutdown).expect("enqueue shutdown");
    let (shared, _queue_rx) = reader_shared();
    let wake = WakeState::new().expect("wake state");

    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let mut instance = instance(fd);
      let mut buf = vec![0u8; 64 * 1024];
      let exit = drain_events(&mut instance, &mut buf, &rx, &wake, &shared);
      let _ = done_tx.send(exit);
    });
    let exit = done_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("a pending shutdown must stop the drain, not spin on /dev/zero");
    assert_eq!(exit, DrainExit::Shutdown);
    worker.join().expect("worker joins");
  }

  /// The core liveness proof: a `Shutdown` that arrives WHILE the reader is already
  /// draining a never-`EAGAIN` fd is observed within a bounded time — the reader
  /// interleaves the control check between reads rather than only after `EAGAIN`
  /// (which never comes). No wake is issued: the mid-drain `try_recv` alone catches
  /// a send that lands while draining, exactly the teardown path.
  #[test]
  fn shutdown_arriving_mid_drain_is_observed_promptly() {
    let fd = never_eagain_fd();
    let (tx, rx) = mpsc::channel();
    let (shared, _queue_rx) = reader_shared();
    let wake = WakeState::new().expect("wake state");

    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let mut instance = instance(fd);
      let mut buf = vec![0u8; 64 * 1024];
      let exit = drain_events(&mut instance, &mut buf, &rx, &wake, &shared);
      let _ = done_tx.send(exit);
    });

    // Let the worker get well into draining the infinite fd, then request teardown.
    std::thread::sleep(Duration::from_millis(100));
    tx.send(Control::Shutdown)
      .expect("enqueue shutdown mid-drain");
    let exit = done_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("the reader must observe a mid-drain shutdown, not drain to EAGAIN");
    assert_eq!(exit, DrainExit::Shutdown);
    worker.join().expect("worker joins");
  }

  /// An arm batch that arrives while the reader is draining a never-`EAGAIN` fd is
  /// serviced inline — its reply comes back without the drain ever returning to the
  /// poll loop. Proves point (b): a mid-drain arm/disarm feeds the `wd` table and
  /// answers its reply between reads. The arm targets a nonexistent path so it
  /// fails fast (`NotFound`) without touching the `/dev/zero` fd; the point is that
  /// a reply is produced at all, mid-drain.
  ///
  /// The batch also carries the reader's pre-reply cut, and a fd that never
  /// returns `EAGAIN` is exactly the fd no cut can PROVE it drained: the bound
  /// exhausts and the cut retires the instance behind one covering loss. So the
  /// drain parks on the fresh fd of its own accord — no teardown needed — which
  /// this cell then reads as the retirement's signature. A mid-drain `Shutdown`
  /// is pinned separately, on cut-free staging, by
  /// [`shutdown_arriving_mid_drain_is_observed_promptly`].
  #[test]
  fn arm_batch_is_serviced_mid_drain() {
    let fd = never_eagain_fd();
    let (tx, rx) = mpsc::channel();
    let (shared, queue_rx) = reader_shared();
    let wake = WakeState::new().expect("wake state");

    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let mut instance = instance(fd);
      let mut buf = vec![0u8; 64 * 1024];
      let exit = drain_events(&mut instance, &mut buf, &rx, &wake, &shared);
      let _ = done_tx.send(exit);
    });

    std::thread::sleep(Duration::from_millis(100));
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    tx.send(Control::Batch {
      ops: vec![ControlOp::Arm(AnchorRequest {
        watch: WatchId::new(NonZeroU64::new(1).unwrap()),
        parent: None,
        name: OsString::from("/tributary-fs-nonexistent-arm-target"),
        expected: None,
      })],
      reply: BatchReply::new(1, move |outcome| {
        let _ = reply_tx.send(outcome);
      }),
    })
    .expect("enqueue arm batch mid-drain");
    let replies = reply_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("the arm must be serviced mid-drain, not after EAGAIN")
      .replies;
    assert_eq!(
      replies.len(),
      1,
      "one arm yields one reply, serviced inline"
    );

    let exit = done_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("the retired instance parks the drain instead of spinning on /dev/zero");
    assert_eq!(
      exit,
      DrainExit::Parked,
      "the unprovable cut swapped the never-EAGAIN fd out, so the drain reaches EAGAIN"
    );
    worker.join().expect("worker joins");

    let mut sent = Vec::new();
    while let Ok(msg) = queue_rx.try_recv() {
      sent.push(msg);
    }
    assert!(
      matches!(sent.as_slice(), [SourceMessage::Overflow(_)]),
      "the retirement signals exactly one covering loss, and the all-zero reads it \
       forwarded attribute to no watch: {sent:?}"
    );
  }

  /// Teardown preempts a queued batch at the drain seam: a multi-op `Control::Batch`
  /// (a cold enumerate's many arms) queued AHEAD of teardown. With the shutdown flag
  /// already raised, the reader preempts the batch at its FIRST op — NONE of the arms
  /// run (each would open its nonexistent path and answer `NotFound`; a preempted arm
  /// answers `Io` instead) — fails every arm, and exits promptly. Proves the reader
  /// does not execute the whole batch before observing shutdown.
  #[test]
  fn queued_batch_is_preempted_by_pending_shutdown() {
    let fd = never_eagain_fd();
    let (tx, rx) = mpsc::channel();
    let (shared, _queue_rx) = reader_shared();
    let wake = WakeState::new().expect("wake state");

    // Queue a big batch, then raise the flag + enqueue Shutdown BEFORE the drain runs
    // — exactly the teardown ordering (`request_shutdown` then send `Shutdown`).
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    let ops: Vec<ControlOp> = (0..64)
      .map(|i| {
        ControlOp::Arm(AnchorRequest {
          watch: WatchId::new(NonZeroU64::new(i + 1).unwrap()),
          parent: None,
          name: OsString::from("/tributary-fs-nonexistent-arm-target"),
          expected: None,
        })
      })
      .collect();
    tx.send(Control::Batch {
      ops,
      reply: BatchReply::new(64, move |outcome| {
        let _ = reply_tx.send(outcome);
      }),
    })
    .expect("enqueue batch");
    wake.request_shutdown();
    tx.send(Control::Shutdown).expect("enqueue shutdown");

    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let mut instance = instance(fd);
      let mut buf = vec![0u8; 64 * 1024];
      let exit = drain_events(&mut instance, &mut buf, &rx, &wake, &shared);
      let _ = done_tx.send(exit);
    });

    let replies = reply_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("the preempted batch still answers its reply, never hanging")
      .replies;
    assert_eq!(replies.len(), 64, "every arm gets a reply, index-aligned");
    assert!(
      replies
        .iter()
        .all(|r| matches!(r.outcome, WatchOutcome::Failed(WatchError::Io))),
      "a preempted batch fails every arm with Io — proving none of the 64 arms ran"
    );
    let exit = done_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("the reader exits promptly on the preempted batch");
    assert_eq!(exit, DrainExit::Shutdown);
    worker.join().expect("worker joins");
  }
}

/// The re-add (binding re-proof) semantics of `arm` against a real fd:
/// arm-first-never-drain-first — the kernel reply decides the old binding's
/// fate, so a live shared watch is never removed preemptively and a dead one
/// is superseded with its table binding drained.
mod rebind {
  use core::num::NonZeroU64;
  use std::ffi::OsString;

  use tributary_proto::WatchId;

  use super::super::{AnchorRequest, Instance, arm, create_instance};
  use crate::os::linux::WatchOutcome;

  fn watch(n: u64) -> WatchId {
    WatchId::new(NonZeroU64::new(n).unwrap())
  }

  fn scratch(tag: &str) -> std::path::PathBuf {
    let dir =
      std::env::temp_dir().join(format!("tributary-fs-rebind-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
  }

  fn instance() -> Instance {
    Instance::with_threshold(create_instance().expect("inotify instance"), i32::MAX)
  }

  fn request(watch: WatchId, path: &std::path::Path) -> AnchorRequest {
    AnchorRequest {
      watch,
      parent: None,
      name: OsString::from(path.as_os_str()),
      expected: None,
    }
  }

  /// A re-add of a binding that is still live: `EEXIST` → `Aliased` on the
  /// SAME `wd`, the table dedups the anchor (no duplicate fan-out), and
  /// nothing is drained.
  #[test]
  fn a_readd_of_a_live_binding_aliases_and_dedups() {
    let mut instance = instance();
    let dir = scratch("alive");

    let first = arm(&mut instance, request(watch(1), &dir));
    let WatchOutcome::Installed(wd) = first.outcome else {
      panic!("the first arm installs: {:?}", first.outcome);
    };

    let readd = arm(&mut instance, request(watch(1), &dir));
    assert!(
      matches!(readd.outcome, WatchOutcome::Aliased(w) if w == wd),
      "the live binding aliases on its own wd: {:?}",
      readd.outcome
    );
    assert_eq!(
      instance.table.attribute(wd).to_vec(),
      vec![watch(1)],
      "no duplicate anchor"
    );
    assert_eq!(instance.table.wd_of(watch(1)), Some(wd));

    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A re-add after the watched object died and the path was re-occupied by a
  /// NEW object: the arm installs fresh (a different `wd`) and the anchor's
  /// old table binding drains (the kernel removal is the `EINVAL`-benign race
  /// — the old watch died with its object).
  #[test]
  fn a_readd_of_a_dead_binding_installs_and_drains_the_old() {
    let mut instance = instance();
    let dir = scratch("dead");

    let first = arm(&mut instance, request(watch(1), &dir));
    let WatchOutcome::Installed(old_wd) = first.outcome else {
      panic!("the first arm installs: {:?}", first.outcome);
    };

    // The object dies (its watch with it — the IGNORED queues unread) and a
    // NEW object takes the path: the exact recycled-slot shape a recovery
    // re-add must supersede.
    std::fs::remove_dir_all(&dir).expect("drop the watched dir");
    std::fs::create_dir_all(&dir).expect("recreate the path");

    let readd = arm(&mut instance, request(watch(1), &dir));
    let WatchOutcome::Installed(new_wd) = readd.outcome else {
      panic!("the dead binding re-installs: {:?}", readd.outcome);
    };
    assert_ne!(new_wd, old_wd, "a fresh kernel watch, not the dead one");
    assert!(
      new_wd > old_wd,
      "the fresh watch's wd is granted past the dead one (no-wrap monotonicity)"
    );
    assert_eq!(
      instance.table.wd_of(watch(1)),
      Some(new_wd),
      "the anchor rebinds to the fresh watch"
    );
    assert_eq!(instance.table.attribute(new_wd).to_vec(), vec![watch(1)]);
    // The old entry drained: the arm's O_PATH anchor (held by `first`) pins the
    // watched inode, so the kernel watch outlived the unlink and its removal
    // SUCCEEDED — the marker is genuinely owed, and the tombstone occupies the
    // `wd` until it arrives.
    assert!(
      instance.table.attribute(old_wd).is_empty(),
      "the dead binding attributes to nobody"
    );
    assert!(
      instance.table.contains(old_wd),
      "the tombstone occupies the wd until its owed marker"
    );

    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The tombstone a dead watch would otherwise strand. The watch is killed
  /// for real — the arm's `O_PATH` anchor is dropped first, so nothing pins the
  /// inode and the kernel destroys the mark with it — and the disarm's removal
  /// then answers `EINVAL`: proof the kernel can never owe the `IN_IGNORED`
  /// this tombstone would wait for. Under the retained-binding recovery that
  /// marker is routinely the one a queue loss swallowed (indistinguishable at
  /// this call site), so the entry must go now rather than leak for the fd's
  /// whole life. A straggling marker then no-ops on the unmapped `wd`.
  ///
  /// Mutation witness: ignore the `EINVAL` (the old `let _ =`) and the
  /// tombstone is still mapped here, awaiting a marker that cannot come.
  #[test]
  fn a_disarm_of_a_dead_watch_leaves_no_tombstone() {
    let mut instance = instance();
    let dir = scratch("disarm-dead");

    let armed = arm(&mut instance, request(watch(1), &dir));
    let WatchOutcome::Installed(wd) = armed.outcome else {
      panic!("the arm installs: {:?}", armed.outcome);
    };
    drop(armed); // release the O_PATH anchor: nothing pins the inode
    std::fs::remove_dir_all(&dir).expect("drop the watched dir");

    super::super::disarm(&mut instance, watch(1));
    assert!(
      !instance.table.contains(wd),
      "the disarm of an already-dead watch strands no tombstone"
    );
    assert!(
      instance.table.wd_of(watch(1)).is_none(),
      "the anchor keeps no binding"
    );
    assert!(
      instance.table.on_ignored(wd).is_empty(),
      "a straggling marker no-ops on the freed wd"
    );
  }

  /// The same rule on the superseded-binding path — the disarm site's one
  /// sibling, and the shape the binding re-proof actually takes: a re-add lands
  /// the anchor on a FRESH `wd` while its previous watch is already dead, so
  /// the old binding's removal answers `EINVAL` and its tombstone is erased
  /// with it.
  #[test]
  fn a_readd_past_a_dead_watch_strands_no_tombstone() {
    let mut instance = instance();
    let dir = scratch("readd-dead");

    let first = arm(&mut instance, request(watch(1), &dir));
    let WatchOutcome::Installed(old_wd) = first.outcome else {
      panic!("the first arm installs: {:?}", first.outcome);
    };
    drop(first); // release the O_PATH anchor so the watch dies with its object
    std::fs::remove_dir_all(&dir).expect("drop the watched dir");
    std::fs::create_dir_all(&dir).expect("recreate the path");

    let readd = arm(&mut instance, request(watch(1), &dir));
    let WatchOutcome::Installed(new_wd) = readd.outcome else {
      panic!("the dead binding re-installs: {:?}", readd.outcome);
    };
    assert_ne!(new_wd, old_wd, "a fresh kernel watch, not the dead one");
    assert!(
      !instance.table.contains(old_wd),
      "the superseded binding's dead watch leaves no tombstone behind"
    );
    assert_eq!(
      instance.table.wd_of(watch(1)),
      Some(new_wd),
      "the anchor rebinds to the fresh watch"
    );

    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A disarm of a watch that is still ALIVE takes the ordinary path: the
  /// kernel removes it successfully, so the marker IS owed and the tombstone
  /// stands until it arrives. The `EINVAL` erase must not generalize to a
  /// successful removal — that would drop an entry whose marker is still
  /// coming.
  #[test]
  fn a_disarm_of_a_live_watch_keeps_its_tombstone() {
    let mut instance = instance();
    let dir = scratch("disarm-live");

    let armed = arm(&mut instance, request(watch(1), &dir));
    let WatchOutcome::Installed(wd) = armed.outcome else {
      panic!("the arm installs: {:?}", armed.outcome);
    };

    super::super::disarm(&mut instance, watch(1));
    assert!(
      instance.table.contains(wd),
      "a live watch's removal owes an IN_IGNORED — the tombstone waits for it"
    );
    assert!(
      instance.table.on_ignored(wd).is_empty(),
      "and its own marker is the authoritative erase"
    );
    assert!(!instance.table.contains(wd));

    let _ = std::fs::remove_dir_all(&dir);
  }
}

/// The no-wrap adoption invariant against the real kernel allocator: on one
/// fd, every fresh install's `wd` is strictly greater than every `wd` the fd
/// granted before — across removals, object deaths, and re-arms — so a fresh
/// install can NEVER land on a mapped `wd`, and the arm asserts (rather than
/// handles) the impossibility. A real wrap (~2³¹ grants on one fd) is not
/// stageable; the monotone-grant lemma these cells pin is exactly what makes
/// the wrap the ONLY path to reuse, and the instance rebuild (the `rebuild`
/// module) is what makes that path unreachable.
mod allocation {
  use core::num::NonZeroU64;
  use std::ffi::OsString;

  use tributary_proto::{WatchError, WatchId};

  use super::super::{AnchorRequest, ControlOp, Instance, arm, create_instance, execute_batch};
  use crate::os::linux::{WatchOutcome, attribute_events, inotify::decode};

  fn watch(n: u64) -> WatchId {
    WatchId::new(NonZeroU64::new(n).unwrap())
  }

  fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
      "tributary-fs-allocation-{tag}-{}",
      std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
  }

  fn instance() -> Instance {
    Instance::with_threshold(create_instance().expect("inotify instance"), i32::MAX)
  }

  fn request(watch: WatchId, path: &std::path::Path) -> AnchorRequest {
    AnchorRequest {
      watch,
      parent: None,
      name: OsString::from(path.as_os_str()),
      expected: None,
    }
  }

  fn install(instance: &mut Instance, anchor: WatchId, path: &std::path::Path) -> i32 {
    let reply = arm(instance, request(anchor, path));
    match reply.outcome {
      WatchOutcome::Installed(wd) => wd,
      other => panic!("the arm installs: {other:?}"),
    }
  }

  /// Everything currently queued on the instance's fd, decoded.
  pub(super) fn drain_decoded(instance: &Instance) -> Vec<decode::RawInotifyEvent> {
    let mut buf = vec![0u8; 4096];
    let mut events = Vec::new();
    loop {
      match rustix::io::read(&instance.fd, &mut buf) {
        Ok(0) => break,
        Ok(n) => {
          let decoded = decode::decode_events(&buf[..n]);
          assert!(!decoded.lossy, "the drain reads intact records");
          events.extend(decoded.events);
        }
        Err(rustix::io::Errno::AGAIN) => break,
        Err(err) => panic!("drain read: {err}"),
      }
    }
    events
  }

  /// The lemma itself: grants on one fd are strictly increasing even across
  /// kernel removals — a freed `wd` is never re-granted before the wrap the
  /// rebuild makes unreachable — so no grant can ever equal a mapped (or
  /// previously granted) `wd`.
  #[test]
  fn grants_are_strictly_increasing_and_never_reuse_a_freed_wd() {
    let mut inst = instance();
    let dirs: Vec<_> = (0..6).map(|i| scratch(&format!("mono-{i}"))).collect();
    let mut granted = Vec::new();
    for (i, dir) in dirs.iter().enumerate() {
      granted.push(install(&mut inst, watch(1 + i as u64), dir));
    }
    assert!(
      granted.windows(2).all(|w| w[0] < w[1]),
      "grants are strictly increasing: {granted:?}"
    );

    // Free two of them (a kernel removal via the object's death, and one via
    // disarm), then keep arming: every later grant is still strictly greater
    // than EVERYTHING granted before — the freed wds are not re-granted.
    std::fs::remove_dir_all(&dirs[1]).expect("kill a watched object");
    super::super::disarm(&mut inst, watch(4));
    let top = *granted.last().expect("granted some");
    for i in 0..3 {
      let dir = scratch(&format!("mono-more-{i}"));
      let wd = install(&mut inst, watch(100 + i as u64), &dir);
      assert!(
        wd > top && !granted.contains(&wd),
        "a fresh grant outgrows every prior grant (freed or live): {wd} vs {granted:?}"
      );
      granted.push(wd);
      let _ = std::fs::remove_dir_all(&dir);
    }

    for dir in dirs {
      let _ = std::fs::remove_dir_all(&dir);
    }
  }

  /// The unreachability tripwire: the state the invariant excludes — a
  /// mapped entry standing where the allocator's next grant lands — trips
  /// the arm's assert rather than being silently adopted. (On a fresh fd the
  /// first grant is exactly `wd` 1, so the impossible state is staged by
  /// mapping 1 up front.)
  #[cfg(debug_assertions)]
  #[test]
  #[should_panic(expected = "a fresh install's wd outgrows every mapped one")]
  fn a_mapped_wd_in_the_grant_path_trips_the_invariant_assert() {
    let mut inst = instance();
    inst.table.register(1, watch(7));
    let dir = scratch("tripwire");
    let _ = arm(&mut inst, request(watch(1), &dir));
  }

  /// A failed arm inside a batch answers in its slot while the rest of the
  /// batch proceeds: replies stay index-aligned across mixed outcomes.
  #[test]
  fn a_batch_with_a_failed_arm_answers_every_arm_in_order() {
    let mut inst = instance();
    let dir = scratch("aligned");
    let ops = vec![
      ControlOp::Arm(AnchorRequest {
        watch: watch(1),
        parent: None,
        name: OsString::from("/tributary-fs-nonexistent-arm-target"),
        expected: None,
      }),
      ControlOp::Arm(request(watch(2), &dir)),
    ];
    let (shared, _queue_rx) = super::rebuild::reader_shared();
    let (replies, preempted) = execute_batch(&mut inst, &shared, ops, || false);
    assert!(!preempted);
    let [reply_a, reply_b] = replies.as_slice() else {
      panic!("two arms, two replies: {replies:?}");
    };
    assert_eq!(
      reply_a.outcome,
      WatchOutcome::Failed(WatchError::NotFound),
      "the missing target fails in its own slot"
    );
    let WatchOutcome::Installed(wd_b) = reply_b.outcome else {
      panic!("the clean sibling installs: {:?}", reply_b.outcome);
    };
    assert_eq!(inst.table.wd_of(watch(2)), Some(wd_b));
    assert_eq!(inst.table.wd_of(watch(1)), None);

    let _ = std::fs::remove_dir_all(&dir);
  }

  /// Deterministic fuzz over real-world churn — arms of fresh objects,
  /// object deaths under live mappings (stale-live: markers queued unread),
  /// disarms (draining tombstones), and marker consumption — asserting the
  /// adoption invariant end to end: every install's `wd` is granted past
  /// every `wd` this fd ever granted (never a mapped one), stale mappings
  /// and tombstones are erased only by their own consumed markers, and every
  /// still-live binding keeps attributing. Seeded xorshift keeps it
  /// reproducible.
  #[test]
  fn random_churn_never_regrants_a_mapped_wd() {
    for seed in 1..=16u64 {
      let mut s = seed.wrapping_mul(2_654_435_761).wrapping_add(12_345);
      let mut rng = || {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        s
      };

      let mut inst = instance();
      let mut granted: Vec<i32> = Vec::new();
      // Anchor → (wd, live dir path if the object still exists).
      let mut bound: std::collections::BTreeMap<u64, (i32, Option<std::path::PathBuf>)> =
        std::collections::BTreeMap::new();
      let mut next_anchor = 1u64;

      for _step in 0..12 {
        match rng() % 4 {
          // Arm a fresh object: the grant must outgrow everything granted.
          0 | 3 => {
            let dir = scratch(&format!("churn-{seed}-{next_anchor}"));
            let wd = install(&mut inst, watch(next_anchor), &dir);
            assert!(
              granted.iter().all(|&g| wd > g),
              "seed {seed}: grant {wd} outgrows every prior grant {granted:?}"
            );
            granted.push(wd);
            bound.insert(next_anchor, (wd, Some(dir)));
            next_anchor += 1;
          }
          // Kill a watched object: its mapping goes stale-live, markers
          // queued unread — the exact shape a wrap would have aliased onto.
          1 => {
            let target = bound
              .iter()
              .find(|(_, (_, dir))| dir.is_some())
              .map(|(&anchor, _)| anchor);
            if let Some(anchor) = target {
              let (_, dir) = bound.get_mut(&anchor).expect("just found");
              let path = dir.take().expect("object was live");
              std::fs::remove_dir_all(&path).expect("kill the object");
            }
          }
          // Disarm an anchor: its entry drains into a tombstone (or erases
          // if its marker already landed).
          2 => {
            let target = bound.keys().next().copied();
            if let Some(anchor) = target {
              super::super::disarm(&mut inst, watch(anchor));
              bound.remove(&anchor);
            }
          }
          _ => unreachable!("rng % 4"),
        }
        // Occasionally consume the queue: markers erase exactly the mappings
        // they belong to, never a later binding.
        if rng() % 2 == 0 {
          let events = drain_decoded(&inst);
          let _ = attribute_events(events, &mut inst.table);
        }
      }

      // Every anchor still bound to a live object attributes through its own
      // wd — no churn step ever displaced it.
      let events = drain_decoded(&inst);
      let _ = attribute_events(events, &mut inst.table);
      for (anchor, (wd, dir)) in &bound {
        if dir.is_some() {
          assert_eq!(
            inst.table.wd_of(watch(*anchor)),
            Some(*wd),
            "seed {seed}: a live binding is never displaced by churn"
          );
        }
      }

      for (_, (_, dir)) in bound {
        if let Some(dir) = dir {
          let _ = std::fs::remove_dir_all(&dir);
        }
      }
    }
  }
}

/// The instance rebuild against the real kernel: once the `wd` high-water
/// mark reaches the instance's threshold, the arm executor swaps in a fresh
/// fd + table (allocator cursor back at `wd` 1), drains the dying fd's queue
/// AHEAD of one whole-instance loss signal, and the batch continues on the
/// fresh instance. A real threshold trip (~2³¹ grants) is not stageable, so
/// these cells lower the per-instance threshold; the production path differs
/// only in the constant.
mod rebuild {
  use core::num::NonZeroU64;
  use std::{ffi::OsString, sync::mpsc, time::Duration};

  use tributary_proto::WatchId;

  use super::super::{
    AnchorRequest, BatchReply, Control, ControlOp, DrainExit, Instance, ReaderShared,
    create_instance, drain_events, execute_batch, rebuild_instance_with,
  };
  use crate::os::{
    SourceError, SourceMessage,
    linux::{WatchOutcome, wake::WakeState},
    transport::TransportState,
  };

  fn watch(n: u64) -> WatchId {
    WatchId::new(NonZeroU64::new(n).unwrap())
  }

  fn scratch(tag: &str) -> std::path::PathBuf {
    let dir =
      std::env::temp_dir().join(format!("tributary-fs-rebuild-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
  }

  fn arm_op(watch: WatchId, path: &std::path::Path) -> ControlOp {
    ControlOp::Arm(AnchorRequest {
      watch,
      parent: None,
      name: OsString::from(path.as_os_str()),
      expected: None,
    })
  }

  /// A `ReaderShared` over an unbounded queue; the receiver is returned so
  /// cells can assert exactly what the reader forwarded, in order.
  pub(super) fn reader_shared() -> (ReaderShared, async_channel::Receiver<SourceMessage>) {
    let (tx, rx) = async_channel::unbounded();
    let shared = ReaderShared {
      queue: tx,
      transport: TransportState::new(8),
      buffer_bytes: 64 * 1024,
    };
    (shared, rx)
  }

  /// The kinds of message on the queue, in order.
  #[derive(Debug, PartialEq, Eq)]
  enum Sent {
    Batch(usize),
    Overflow,
  }

  fn drain_queue(rx: &async_channel::Receiver<SourceMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(msg) = rx.try_recv() {
      sent.push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => unreachable!("no fatal on this path"),
      });
    }
    sent
  }

  /// The trip fires BEFORE the arm that would eat into the margin: with a
  /// threshold of 2, arms grant `wd` 1 and 2 on the first fd (never past the
  /// threshold), the third arm swaps the instance and lands on the fresh
  /// fd's `wd` 1, and the batch simply continues — index-aligned replies,
  /// old bindings dropped with the old table, exactly one loss signal on the
  /// queue, and a second trip renews again.
  #[test]
  fn a_threshold_trip_swaps_the_instance_before_the_arm() {
    let dirs: Vec<_> = (0..5).map(|i| scratch(&format!("trip-{i}"))).collect();
    let mut inst = Instance::with_threshold(create_instance().expect("inotify instance"), 2);
    let (shared, queue_rx) = reader_shared();

    let ops: Vec<ControlOp> = (0..4usize)
      .map(|i| arm_op(watch(1 + i as u64), &dirs[i]))
      .collect();
    let (replies, preempted) = execute_batch(&mut inst, &shared, ops, || false);
    assert!(!preempted);
    let wds: Vec<_> = replies
      .iter()
      .map(|r| match r.outcome {
        WatchOutcome::Installed(wd) => wd,
        other => panic!("every arm installs: {other:?}"),
      })
      .collect();
    assert_eq!(
      wds,
      vec![1, 2, 1, 2],
      "grants stop AT the threshold on the old fd and restart at 1 on the fresh one"
    );

    // The old fd's bindings died with its table: only the post-swap arms map.
    assert_eq!(inst.table.wd_of(watch(1)), None);
    assert_eq!(inst.table.wd_of(watch(2)), None);
    assert_eq!(inst.table.wd_of(watch(3)), Some(1));
    assert_eq!(inst.table.wd_of(watch(4)), Some(2));

    // Exactly one whole-instance loss signal, nothing before it (no events
    // were queued on the dying fd).
    assert_eq!(drain_queue(&queue_rx), vec![Sent::Overflow]);

    // The fresh instance trips again at ITS threshold: renewal is per fd,
    // not once.
    let (replies, _) = execute_batch(&mut inst, &shared, vec![arm_op(watch(5), &dirs[4])], || {
      false
    });
    assert!(
      matches!(replies[0].outcome, WatchOutcome::Installed(1)),
      "the second renewal restarts at wd 1 too: {:?}",
      replies[0].outcome
    );
    assert_eq!(drain_queue(&queue_rx), vec![Sent::Overflow]);

    for dir in dirs {
      let _ = std::fs::remove_dir_all(&dir);
    }
  }

  /// Events already queued on the dying fd are drained and forwarded —
  /// honestly attributed through the OLD table — BEFORE the loss signal, so
  /// recorded traffic keeps its delivery density and the loss covers only
  /// what follows it.
  #[test]
  fn queued_events_are_drained_ahead_of_the_loss_signal() {
    let dir = scratch("drain-order");
    let mut inst = Instance::with_threshold(create_instance().expect("inotify instance"), 1);
    let (shared, queue_rx) = reader_shared();

    let (replies, _) = execute_batch(&mut inst, &shared, vec![arm_op(watch(1), &dir)], || false);
    assert!(matches!(replies[0].outcome, WatchOutcome::Installed(1)));

    // Traffic lands on the old fd's queue, unread.
    std::fs::write(dir.join("recorded.txt"), b"x").expect("write into the watched dir");

    // The next arm trips the renewal: the queued create must come through
    // ahead of the loss, attributed to watch(1) via the old table.
    let other = scratch("drain-order-b");
    let (replies, _) = execute_batch(&mut inst, &shared, vec![arm_op(watch(2), &other)], || false);
    assert!(matches!(replies[0].outcome, WatchOutcome::Installed(1)));

    let sent = drain_queue(&queue_rx);
    assert!(
      matches!(sent.first(), Some(Sent::Batch(n)) if *n >= 1),
      "the dying fd's recorded traffic is drained first: {sent:?}"
    );
    assert_eq!(
      sent.last(),
      Some(&Sent::Overflow),
      "the loss signal follows the drained traffic: {sent:?}"
    );
    assert_eq!(
      sent.iter().filter(|s| **s == Sent::Overflow).count(),
      1,
      "exactly one whole-instance loss per renewal: {sent:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other);
  }

  /// A renewal that cannot get a replacement fd leaves the stream UNTOUCHED
  /// and signals no loss: the caller refuses the arm instead (the cursor
  /// stays frozen, so the wrap stays impossible) and the old fd keeps
  /// serving events until a retry succeeds.
  #[test]
  fn a_failed_renewal_leaves_the_instance_intact_and_signals_nothing() {
    let dir = scratch("fail-renew");
    let mut inst = Instance::with_threshold(create_instance().expect("inotify instance"), 1);
    let (shared, queue_rx) = reader_shared();

    let (replies, _) = execute_batch(&mut inst, &shared, vec![arm_op(watch(1), &dir)], || false);
    assert!(matches!(replies[0].outcome, WatchOutcome::Installed(1)));
    drain_queue(&queue_rx);

    let renewed = rebuild_instance_with(&mut inst, &shared, || Err(SourceError::CreateFailed));
    assert!(
      matches!(renewed, Err(SourceError::CreateFailed)),
      "no replacement fd, no renewal — and the typed reason reaches the caller, \
       which is what lets the unprovable-cut degrade escalate it fatally: {renewed:?}"
    );
    assert_eq!(
      inst.table.wd_of(watch(1)),
      Some(1),
      "the live binding is untouched by the failed renewal"
    );
    assert_eq!(inst.alloc_cursor, 1, "the cursor accounting is untouched");
    assert_eq!(
      drain_queue(&queue_rx),
      Vec::<Sent>::new(),
      "no loss is signalled when nothing was renewed"
    );

    // The old fd still serves: traffic keeps attributing through it.
    std::fs::write(dir.join("still-live.txt"), b"x").expect("write into the watched dir");
    let events = super::allocation::drain_decoded(&inst);
    assert!(
      events
        .iter()
        .any(|ev| ev.name.as_deref() == Some(b"still-live.txt".as_slice())),
      "the un-renewed instance keeps recording: {events:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A renewal tripped MID-DRAIN redirects the read loop to the fresh fd:
  /// the swap's own bounded drain caps out against a never-`EAGAIN` fd
  /// (rather than wedging), the arm lands on the fresh instance, and the
  /// outer drain then parks on the fresh fd's `EAGAIN`.
  #[test]
  fn a_mid_drain_renewal_redirects_the_loop_to_the_fresh_fd() {
    let zero: std::os::fd::OwnedFd = std::fs::File::open("/dev/zero")
      .expect("/dev/zero opens on linux")
      .into();
    let mut inst = Instance::with_threshold(zero, 1);
    inst.alloc_cursor = 1; // At the threshold: the next arm must renew first.

    let (tx, rx) = mpsc::channel();
    let (shared, queue_rx) = reader_shared();
    let wake = WakeState::new().expect("wake state");
    let dir = scratch("mid-drain");
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    tx.send(Control::Batch {
      ops: vec![arm_op(watch(1), &dir)],
      reply: BatchReply::new(1, move |outcome| {
        let _ = reply_tx.send(outcome);
      }),
    })
    .expect("enqueue the tripping batch");

    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let mut buf = vec![0u8; 64 * 1024];
      let exit = drain_events(&mut inst, &mut buf, &rx, &wake, &shared);
      let _ = done_tx.send((exit, inst));
    });

    let replies = reply_rx
      .recv_timeout(Duration::from_secs(10))
      .expect("the tripping batch answers despite the never-EAGAIN fd")
      .replies;
    assert!(
      matches!(replies[0].outcome, WatchOutcome::Installed(1)),
      "the arm lands on the fresh instance: {:?}",
      replies[0].outcome
    );
    let (exit, inst) = done_rx
      .recv_timeout(Duration::from_secs(10))
      .expect("the outer drain parks on the fresh fd instead of spinning on /dev/zero");
    assert_eq!(exit, DrainExit::Parked);
    assert_eq!(inst.table.wd_of(watch(1)), Some(1));
    assert_eq!(
      drain_queue(&queue_rx),
      vec![Sent::Overflow],
      "the all-zero swap drain forwards nothing; the loss signal alone crosses"
    );
    worker.join().expect("worker joins");

    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The conservative allocator-cursor bound closes the barrier-honesty hole
  /// that a success-only high-water mark left open: a run of adds that BURN the
  /// kernel's cyclic cursor through POST-ALLOCATION failures (ENOSPC on the
  /// `max_user_watches` gate, ENOMEM installing the mark — the cursor advances,
  /// no `wd` returns) advances the bound just like grants do, so the rebuild
  /// fires BEFORE the cursor can wrap onto a still-mapped `wd`. The failures and
  /// the wrapped grant are injected (a real ~2³¹-add wrap is not stageable); the
  /// bound is what makes the gate trip on the failures the old mark could not
  /// see. Mutation witness: advancing the bound only on a successful grant (the
  /// old semantics) leaves the gate blind to the failure run — the wrapped `Ok`
  /// then lands on the pre-mapped `wd`, tripping the adoption `debug_assert` and
  /// signalling no loss, and this cell fails.
  #[test]
  fn a_cursor_burning_failure_run_rebuilds_before_a_wrapped_grant_collides() {
    let dir = scratch("cursor-burn");
    const THRESHOLD: i32 = 4;
    let mut inst =
      Instance::with_threshold(create_instance().expect("inotify instance"), THRESHOLD);
    // Script: THRESHOLD post-allocation FAILURES (each burns a cursor slot and
    // returns no `wd`), then a SUCCESS returning the wrapped low `wd` 1 — the
    // grant a wrapped cursor would hand back.
    let mut script: std::collections::VecDeque<Result<i32, rustix::io::Errno>> =
      std::iter::repeat_with(|| Err(rustix::io::Errno::NOSPC))
        .take(THRESHOLD as usize)
        .collect();
    script.push_back(Ok(1));
    inst.injected_adds = Some(script);
    // Pre-map `wd` 1 to a live stale binding: the wrapped grant would alias
    // onto it (the collision the rebuild forecloses).
    inst.table.register(1, watch(99));

    let (shared, queue_rx) = reader_shared();
    // THRESHOLD failing arms, then the arm that would land the wrapped grant.
    // Each opens the same real dir (so the arm reaches the injected add) under a
    // distinct watch id — never the pre-mapped 99.
    let ops: Vec<ControlOp> = (0..=THRESHOLD as u64)
      .map(|i| arm_op(watch(100 + i), &dir))
      .collect();
    let (replies, preempted) = execute_batch(&mut inst, &shared, ops, || false);
    assert!(!preempted);

    // The bound tripped the rebuild at the (THRESHOLD+1)-th arm, BEFORE the
    // wrapped grant: exactly one whole-instance loss signal (the mutation
    // witness — a blind gate rebuilds nothing and signals nothing).
    assert_eq!(
      drain_queue(&queue_rx),
      vec![Sent::Overflow],
      "the failure run tripped the rebuild before the wrap (one whole-instance loss)"
    );
    // The final grant landed on the FRESH fd's empty table — no collision.
    assert!(
      matches!(
        replies.last().map(|r| &r.outcome),
        Some(WatchOutcome::Installed(1))
      ),
      "the final grant installed on the fresh fd's wd 1: {:?}",
      replies.last().map(|r| &r.outcome)
    );
    assert_eq!(
      inst.table.wd_of(watch(99)),
      None,
      "the stale pre-mapped binding died with the old table on rebuild — no aliasing"
    );
    assert_eq!(
      inst.table.wd_of(watch(100 + THRESHOLD as u64)),
      Some(1),
      "the final arm owns the fresh wd 1 alone"
    );

    let _ = std::fs::remove_dir_all(&dir);
  }
}

/// The batch executor's preemption point, tested deterministically over an injected
/// shutdown predicate (no real teardown race). Covers the whole class: the whole
/// batch runs when no shutdown pends; none runs when shutdown pends up front; and a
/// mid-batch flip executes the prefix and failed-replies the tail — all index-
/// aligned to the batch's `Arm` entries.
mod batch_preemption {
  use core::num::NonZeroU64;
  use std::{cell::Cell, ffi::OsString};

  use tributary_proto::{WatchError, WatchId};

  use super::super::{AnchorRequest, ControlOp, Instance, create_instance, execute_batch};
  use crate::os::linux::WatchOutcome;

  fn instance() -> Instance {
    Instance::with_threshold(create_instance().expect("inotify instance"), i32::MAX)
  }

  /// One arm targeting a path that never exists, so `arm` fails fast at `open_anchor`
  /// (`NotFound`) WITHOUT touching the inotify fd — the executed-arm outcome, kept
  /// distinct from the preempted-arm `Io`.
  fn arm_op(n: u64) -> ControlOp {
    ControlOp::Arm(AnchorRequest {
      watch: WatchId::new(NonZeroU64::new(n).unwrap()),
      parent: None,
      name: OsString::from("/tributary-fs-nonexistent-arm-target"),
      expected: None,
    })
  }

  /// No shutdown pending: the whole batch executes exactly as before — every arm
  /// gets its real reply (`NotFound` for the nonexistent target), and `preempted`
  /// is false.
  #[test]
  fn whole_batch_runs_when_no_shutdown() {
    let mut inst = instance();
    let (shared, _queue_rx) = super::rebuild::reader_shared();
    let ops = vec![arm_op(1), arm_op(2), arm_op(3)];
    let (replies, preempted) = execute_batch(&mut inst, &shared, ops, || false);
    assert!(!preempted);
    assert_eq!(replies.len(), 3);
    assert!(
      replies
        .iter()
        .all(|r| matches!(r.outcome, WatchOutcome::Failed(WatchError::NotFound))),
      "each arm actually ran (NotFound), not a preemption reply"
    );
  }

  /// Shutdown pending BEFORE the first op: none of the arms run, every one is failed
  /// with `Io` (distinguishable from the executed `NotFound`), and `preempted` is
  /// true — the batch is not executed at all.
  #[test]
  fn no_op_runs_when_shutdown_pending_up_front() {
    let mut inst = instance();
    let (shared, _queue_rx) = super::rebuild::reader_shared();
    let ops = vec![arm_op(1), arm_op(2), arm_op(3)];
    let (replies, preempted) = execute_batch(&mut inst, &shared, ops, || true);
    assert!(preempted);
    assert_eq!(replies.len(), 3, "all three arms answered, index-aligned");
    assert!(
      replies
        .iter()
        .all(|r| matches!(r.outcome, WatchOutcome::Failed(WatchError::Io))),
      "every arm is a preemption reply — none executed"
    );
  }

  /// Shutdown flips mid-batch: the predicate returns false once (op 0 runs) then
  /// true, so op 0 gets its real `NotFound` reply and the tail (ops 1, 2) are failed
  /// with `Io`. The reply vec still covers all three arms in order.
  #[test]
  fn prefix_runs_then_tail_is_failed_on_mid_batch_shutdown() {
    let mut inst = instance();
    let (shared, _queue_rx) = super::rebuild::reader_shared();
    let ops = vec![arm_op(1), arm_op(2), arm_op(3)];
    let calls = Cell::new(0u32);
    let (replies, preempted) = execute_batch(&mut inst, &shared, ops, || {
      let n = calls.get();
      calls.set(n + 1);
      n >= 1
    });
    assert!(preempted);
    assert_eq!(replies.len(), 3);
    assert!(
      matches!(
        replies[0].outcome,
        WatchOutcome::Failed(WatchError::NotFound)
      ),
      "op 0 executed before the flip"
    );
    assert!(
      matches!(replies[1].outcome, WatchOutcome::Failed(WatchError::Io))
        && matches!(replies[2].outcome, WatchOutcome::Failed(WatchError::Io)),
      "the un-executed tail is failed-replied with Io"
    );
  }
}

/// The pre-reply queue cut against the real kernel: every reply the reader can
/// send leaves through `drain_control`, and a non-preempted one leaves only
/// AFTER the fd's queued records have been read, attributed, and forwarded. The
/// three drains that can answer control — the poll loop's control-first
/// dispatch, the inter-read drain inside `drain_events`, and the pre-park guard
/// drain — all reply through that one site, so pinning it pins the class.
///
/// These cells own both sides (no reader thread), so the ordering they assert is
/// program order, not timing: the queue's contents are read after
/// `drain_control` returns, and the reply is in hand at the same instant.
mod queue_cut {
  use core::num::NonZeroU64;
  use std::{ffi::OsString, sync::mpsc, time::Duration};

  use tributary_proto::WatchId;

  use std::os::fd::{AsRawFd, RawFd};

  use super::super::{
    AnchorRequest, BatchReply, Control, ControlOp, DrainExit, Errno, Instance,
    MAX_CUT_FALLBACK_READS, MAX_CUT_INTERRUPTED_READS, MAX_CUT_OWED_READS, ReaderShared,
    create_instance, cut_kernel_queue_with, drain_control, drain_events,
  };
  use crate::os::{
    SourceError, SourceMessage,
    linux::{ArmReply, WatchOutcome, wake::WakeState},
    transport::TransportState,
  };

  fn watch(n: u64) -> WatchId {
    WatchId::new(NonZeroU64::new(n).unwrap())
  }

  fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tributary-fs-cut-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
  }

  fn instance() -> Instance {
    Instance::with_threshold(create_instance().expect("inotify instance"), i32::MAX)
  }

  /// A budget wide enough that no batch degrades to a transport `Overflow`: a
  /// kernel `IN_Q_OVERFLOW` must be the only loss these cells can observe.
  fn reader_shared() -> (ReaderShared, async_channel::Receiver<SourceMessage>) {
    let (tx, rx) = async_channel::unbounded();
    let shared = ReaderShared {
      queue: tx,
      transport: TransportState::new(1024),
      buffer_bytes: 64 * 1024,
    };
    (shared, rx)
  }

  fn arm_batch(
    tx: &mpsc::Sender<Control>,
    anchor: WatchId,
    path: &std::path::Path,
  ) -> mpsc::Receiver<Vec<ArmReply>> {
    let (reply_tx, replies) = mpsc::sync_channel(1);
    tx.send(Control::Batch {
      ops: vec![ControlOp::Arm(AnchorRequest {
        watch: anchor,
        parent: None,
        name: OsString::from(path.as_os_str()),
        expected: None,
      })],
      reply: BatchReply::new(1, move |outcome| {
        let _ = reply_tx.send(outcome.replies);
      }),
    })
    .expect("enqueue the arm batch");
    replies
  }

  /// What the reader forwarded, in order.
  #[derive(Debug, PartialEq, Eq)]
  enum Sent {
    Batch(usize),
    Overflow,
  }

  fn drained(rx: &async_channel::Receiver<SourceMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(msg) = rx.try_recv() {
      sent.push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(err) => panic!("no fatal on this path: {err:?}"),
      });
    }
    sent
  }

  /// The kernel's queue ceiling for this host, or `None` when the value is
  /// missing or too large to flood inside a test's budget (a deliberately loud
  /// skip rather than a silent pass).
  fn max_queued_events() -> Option<usize> {
    let raw = std::fs::read_to_string("/proc/sys/fs/inotify/max_queued_events").ok()?;
    let value: usize = raw.trim().parse().ok()?;
    if value == 0 || value > 200_000 {
      eprintln!("skipping: fs.inotify.max_queued_events = {value} is outside the tested range");
      return None;
    }
    Some(value)
  }

  /// Floods `dir`'s watch past `count` queued records. Consecutive records must
  /// DIFFER or the kernel coalesces them into one, so this alternates two
  /// names: one `chmod` per record, no allocation, no readdir.
  fn flood(dir: &std::path::Path, count: usize) {
    let a = dir.join("a");
    let b = dir.join("b");
    std::fs::write(&a, b"a").expect("stage a");
    std::fs::write(&b, b"b").expect("stage b");
    let mut mode = 0o600;
    for i in 0..count {
      mode = if mode == 0o600 { 0o644 } else { 0o600 };
      let target = if i % 2 == 0 { &a } else { &b };
      std::fs::set_permissions(target, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .expect("chmod to queue one record");
    }
  }

  /// Records the kernel had queued when a batch executed are on the source
  /// queue BEFORE the batch's reply — the cut runs between `execute_batch` and
  /// the reply send, so a caller holding the reply provably holds them too.
  #[test]
  fn a_batch_reply_is_preceded_by_the_queue_cut() {
    let mut instance = instance();
    let (shared, queue_rx) = reader_shared();
    let dir = scratch("order");
    let wake = WakeState::new().expect("wake state");
    let (tx, rx) = mpsc::channel();

    // Arm the scratch dir through the reader itself, then drain what that arm
    // put on the queue (nothing: the arm generates no records).
    let armed = arm_batch(&tx, watch(1), &dir);
    let mut buf = vec![0u8; 64 * 1024];
    assert!(!drain_control(&mut instance, &shared, &rx, &wake, &mut buf));
    let replies = armed.recv_timeout(Duration::from_secs(5)).expect("armed");
    assert!(
      matches!(replies[0].outcome, WatchOutcome::Installed(_)),
      "the scratch dir armed: {:?}",
      replies[0].outcome
    );
    assert!(drained(&queue_rx).is_empty(), "arming forwards nothing");

    // Stage records the reader has NOT read, then answer a second batch: its
    // reply may not leave before they are forwarded.
    flood(&dir, 8);
    let second = arm_batch(&tx, watch(2), &dir);
    assert!(!drain_control(&mut instance, &shared, &rx, &wake, &mut buf));
    let replies = second.recv_timeout(Duration::from_secs(5)).expect("armed");
    assert!(
      matches!(replies[0].outcome, WatchOutcome::Aliased(_)),
      "the second anchor aliases the same watch: {:?}",
      replies[0].outcome
    );
    let sent = drained(&queue_rx);
    assert!(
      !sent.is_empty() && sent.iter().all(|s| matches!(s, Sent::Batch(_))),
      "the staged records rode the cut, ahead of the reply: {sent:?}"
    );
  }

  /// The finding's own shape, with a REAL kernel loss: the fd is flooded past
  /// `fs.inotify.max_queued_events` so an `IN_Q_OVERFLOW` is kernel-resident
  /// and unread, then a settling arm batch is answered. The cut puts the
  /// overflow on the source queue before the reply exists, so the settle
  /// observation the reply arms cannot precede the loss it would certify over.
  /// Mutation witness: without the cut the reply lands with the queue still
  /// holding the overflow and this cell sees no loss at all.
  #[test]
  fn a_kernel_resident_overflow_precedes_the_settling_reply() {
    let Some(ceiling) = max_queued_events() else {
      return;
    };
    let mut instance = instance();
    let (shared, queue_rx) = reader_shared();
    let dir = scratch("overflow");
    let wake = WakeState::new().expect("wake state");
    let (tx, rx) = mpsc::channel();

    let armed = arm_batch(&tx, watch(1), &dir);
    let mut buf = vec![0u8; 64 * 1024];
    assert!(!drain_control(&mut instance, &shared, &rx, &wake, &mut buf));
    armed.recv_timeout(Duration::from_secs(5)).expect("armed");
    let _ = drained(&queue_rx);

    // Past the ceiling: the kernel drops records and queues its sentinel.
    flood(&dir, ceiling + 64);
    let settling = arm_batch(&tx, watch(2), &dir);
    assert!(!drain_control(&mut instance, &shared, &rx, &wake, &mut buf));
    let replies = settling
      .recv_timeout(Duration::from_secs(5))
      .expect("the settling arm is answered");
    assert!(
      matches!(replies[0].outcome, WatchOutcome::Aliased(_)),
      "the settling arm's outcome is intact: {:?}",
      replies[0].outcome
    );
    let sent = drained(&queue_rx);
    assert!(
      sent.contains(&Sent::Overflow),
      "the kernel-resident loss reached the queue before the reply: {sent:?}"
    );
  }

  /// The one documented exception, pinned: a PREEMPTED batch skips the cut.
  /// Its replies are the failure tail of a reader that is exiting — nothing
  /// settles on them, and the scope funnels to a teardown whose fences degrade
  /// — so bounded teardown latency wins over an ordering no verdict needs.
  #[test]
  fn a_preempted_batch_skips_the_cut() {
    let mut instance = instance();
    let (shared, queue_rx) = reader_shared();
    let dir = scratch("preempt");
    let wake = WakeState::new().expect("wake state");
    let (tx, rx) = mpsc::channel();

    let armed = arm_batch(&tx, watch(1), &dir);
    let mut buf = vec![0u8; 64 * 1024];
    assert!(!drain_control(&mut instance, &shared, &rx, &wake, &mut buf));
    armed.recv_timeout(Duration::from_secs(5)).expect("armed");
    let _ = drained(&queue_rx);

    flood(&dir, 8);
    let preempted = arm_batch(&tx, watch(2), &dir);
    wake.request_shutdown();
    assert!(
      drain_control(&mut instance, &shared, &rx, &wake, &mut buf),
      "a preempted batch exits the reader"
    );
    let replies = preempted
      .recv_timeout(Duration::from_secs(5))
      .expect("the preempted batch still answers");
    assert!(
      matches!(
        replies[0].outcome,
        WatchOutcome::Failed(tributary_proto::WatchError::Io)
      ),
      "the un-executed arm is failed-replied: {:?}",
      replies[0].outcome
    );
    assert!(
      drained(&queue_rx).is_empty(),
      "the exiting reader spends no cut on a reply nothing settles over"
    );
  }

  /// An interrupt storm on the cut. `EINTR` consumes no queued bytes and proves
  /// nothing, so retrying it is the cut's one non-progressing step: unbudgeted,
  /// a storm aimed at this thread withholds the batch reply (or the
  /// observation's report) that a driver-side settle waits on — and blocks the
  /// reader's own teardown — indefinitely, which is exactly what the cut's
  /// must-complete bound forbids. Driven through the real body over the
  /// injectable read seam on a descriptor whose `FIONREAD` genuinely owes bytes,
  /// so this is the SUCCESSFUL-ioctl path (a signal storm cannot be aimed at a
  /// test's own thread without hijacking the process's handlers).
  ///
  /// Three legs, ordered so the one that RETIRES the instance runs last (it
  /// closes the fd every earlier leg's staging lives on):
  ///
  /// - a PENDING TEARDOWN degrades at the first interruption instead of
  ///   spending the budget, so teardown proceeds at once (this is the reader's
  ///   teardown-fairness invariant: the cut is must-complete work, but only
  ///   while it is making progress) — and, the remainder being unproven, it
  ///   STOPS the reader rather than minting a replacement it would close a
  ///   moment later;
  /// - an interleaved storm that still reaches the queue's end COMPLETES the
  ///   cut — records forwarded, NO loss signalled, nothing retired — so the
  ///   budget cannot fire spuriously and turn a provable cut into a degrade;
  /// - the budget bounds the attempts exactly, and the exhausted cut takes the
  ///   unprovable-cut exit: the instance is retired, its salvageable traffic
  ///   forwarded first and one `Overflow` closing it, all on the queue before
  ///   the call returns — hence before any reply or proof the caller then sends.
  ///
  /// The injected storm is itself bounded — twice the budget, then an empty read
  /// — on purpose: the regression under test IS an unbounded retry loop, so an
  /// endless injection would HANG the suite inside it. Capped, an unbudgeted
  /// retry instead overshoots the attempt count and ends with no covering loss,
  /// so both mutations fail LOUDLY on an assertion.
  #[test]
  fn an_interrupt_storm_bounds_the_cut_and_degrades_to_a_covering_loss() {
    let mut instance = instance();
    let (shared, queue_rx) = reader_shared();
    let dir = scratch("interrupt");
    let wake = WakeState::new().expect("wake state");
    let (tx, rx) = mpsc::channel();

    let armed = arm_batch(&tx, watch(1), &dir);
    let mut buf = vec![0u8; 64 * 1024];
    assert!(!drain_control(&mut instance, &shared, &rx, &wake, &mut buf));
    armed.recv_timeout(Duration::from_secs(5)).expect("armed");
    let _ = drained(&queue_rx);

    // Records the kernel owes: the interrupted legs below run the
    // `FIONREAD`-succeeded path with a non-zero remainder and read none of it.
    flood(&dir, 8);

    // Twice the budget, then an empty read (which ends any cut, loss-free).
    let storm = MAX_CUT_INTERRUPTED_READS * 2;
    let mut attempts = 0u32;
    let exit = cut_kernel_queue_with(
      &mut instance,
      &shared,
      &mut buf,
      || true,
      |_, _| {
        attempts += 1;
        if attempts > storm {
          Ok(0)
        } else {
          Err(Errno::INTR)
        }
      },
      |fd: &std::os::fd::OwnedFd| rustix::io::ioctl_fionread(fd),
      || unreachable!("a teardown-shortened cut spends no thread minting an instance"),
    );
    assert!(
      exit,
      "a teardown observed mid-cut stops the reader: the remainder it could not prove \
       it read stays resident, so the covering loss is honest only while nothing further \
       is forwarded behind it"
    );
    assert_eq!(
      attempts, 1,
      "a pending teardown degrades at the FIRST interruption rather than spending the budget"
    );
    assert_eq!(
      drained(&queue_rx),
      vec![Sent::Overflow],
      "the shortened cut still degrades honestly rather than under-draining silently"
    );

    let mut calls = 0u32;
    let mut interrupts = 0u32;
    let exit = cut_kernel_queue_with(
      &mut instance,
      &shared,
      &mut buf,
      || false,
      |fd, buf| {
        calls += 1;
        if calls <= 3 {
          interrupts += 1;
          Err(Errno::INTR)
        } else {
          rustix::io::read(fd, buf)
        }
      },
      |fd: &std::os::fd::OwnedFd| rustix::io::ioctl_fionread(fd),
      || unreachable!("a cut that reaches the queue's end retires nothing"),
    );
    assert!(
      !exit,
      "a completed cut neither dies nor retires the instance"
    );
    assert_eq!(interrupts, 3, "the interleaved storm was absorbed");
    let sent = drained(&queue_rx);
    assert!(
      !sent.is_empty() && sent.iter().all(|s| matches!(s, Sent::Batch(_))),
      "a cut that reached the queue's end forwards its records and signals NO loss: {sent:?}"
    );

    // The leg above drained the staged remainder; re-stage it, because what the
    // exhausted budget must now be shown doing is retiring records it never read.
    flood(&dir, 8);
    let fd_before = instance.fd.as_raw_fd();
    let mut attempts = 0u32;
    let exit = cut_kernel_queue_with(
      &mut instance,
      &shared,
      &mut buf,
      || false,
      |_, _| {
        attempts += 1;
        if attempts > storm {
          Ok(0)
        } else {
          Err(Errno::INTR)
        }
      },
      |fd: &std::os::fd::OwnedFd| rustix::io::ioctl_fionread(fd),
      create_instance,
    );
    assert!(
      !exit,
      "a retired instance is not a stream death: the reader continues on the fresh fd"
    );
    assert_eq!(
      attempts, MAX_CUT_INTERRUPTED_READS,
      "the storm is bounded by the interrupted-attempt budget"
    );
    assert_ne!(
      instance.fd.as_raw_fd(),
      fd_before,
      "the unprovable cut RETIRES the instance rather than announcing the loss over a \
       queue it left resident"
    );
    let sent = drained(&queue_rx);
    assert_eq!(
      sent.iter().filter(|s| **s == Sent::Overflow).count(),
      1,
      "exactly one covering loss, ahead of the reply: {sent:?}"
    );
    assert_eq!(
      sent.last(),
      Some(&Sent::Overflow),
      "and it CLOSES what the retirement forwarded — the swap's drain salvages genuine \
       pre-loss traffic ahead of the loss, never behind it: {sent:?}"
    );
  }

  /// A queued-byte count past what the kernel could hold is a WRAP artifact, not
  /// a debt, so the cut refuses to believe it and drains under the unknown-count
  /// bound instead.
  ///
  /// `FIONREAD` reports through a C `int`, and the count reaches this code
  /// widened to `u64` — so a wrapped negative arrives as a value near
  /// `u64::MAX`, not as something negative to reject. Believed, it would be a
  /// debt no read could ever retire, holding the control reply and the teardown
  /// join behind a loop that cannot end.
  ///
  /// Mutation witness: drop the credibility bound and the incredible count is
  /// taken as a real debt, so the drain runs to the far larger owed budget
  /// instead of the fallback's — this cell's read count fails.
  #[test]
  fn an_incredible_queued_count_is_not_believed_as_a_debt() {
    let mut instance = instance();
    let (shared, queue_rx) = reader_shared();
    let mut buf = vec![0u8; 4096];
    let mut reads = 0u32;
    let exit = cut_kernel_queue_with(
      &mut instance,
      &shared,
      &mut buf,
      || false,
      |_, buf| {
        reads += 1;
        buf[0] = 0;
        Ok(1)
      },
      |_| Ok(u64::MAX),
      create_instance,
    );
    assert!(!exit, "an unprovable cut is not a stream death");
    assert_eq!(
      reads, MAX_CUT_FALLBACK_READS,
      "the wrapped count is discarded, so the UNKNOWN-count bound applies"
    );
    assert_eq!(
      drained(&queue_rx),
      vec![Sent::Overflow],
      "a cut that could not prove the queue was cut degrades to one covering loss"
    );
  }

  /// A CREDIBLE debt that will not retire under its own bound degrades like any
  /// other unprovable cut rather than holding the reply forever.
  ///
  /// Reaching the claimed endpoint is deliberately not an exit — a wrapped-small
  /// count would otherwise let the cut reply while records it never read, an
  /// overflow sentinel among them, were still resident. Termination therefore
  /// rests on `EAGAIN` or on this bound, and a queue that keeps yielding bytes
  /// must hit the bound.
  ///
  /// Mutation witness: remove the owed bound and this cell does not fail, it
  /// HANGS — which is precisely the withheld reply and withheld teardown the
  /// bound exists to prevent.
  #[test]
  fn a_credible_debt_that_never_retires_degrades_at_its_bound() {
    let mut instance = instance();
    let (shared, queue_rx) = reader_shared();
    let mut buf = vec![0u8; 4096];
    let mut reads = 0u32;
    let exit = cut_kernel_queue_with(
      &mut instance,
      &shared,
      &mut buf,
      || false,
      |_, buf| {
        reads += 1;
        buf[0] = 0;
        Ok(1)
      },
      |_| Ok(1024),
      create_instance,
    );
    assert!(!exit, "an unprovable cut is not a stream death");
    assert_eq!(
      reads, MAX_CUT_OWED_READS,
      "the credible-debt drain is bounded by its own read budget"
    );
    assert_eq!(
      drained(&queue_rx),
      vec![Sent::Overflow],
      "and exhausting it takes the same honest degrade as every other unprovable cut"
    );
  }

  /// One well-formed kernel record on a `wd` this instance never granted. It
  /// decodes cleanly, so a cut reading it signals no loss of its own, and it
  /// attributes to nothing (the allocator starts at `wd` 1 and the table maps
  /// only granted `wd`s), so it forwards no batch either — which makes EVERY
  /// message the cells below observe the degrade's own doing. Sixteen zero
  /// bytes: `wd` 0, an empty mask, no cookie, a zero-length name.
  const UNMAPPED_RECORD: [u8; 16] = [0; 16];

  /// One armed instance with real kernel records the reader has NOT read — the
  /// staging an unprovable-cut cell needs, since what it must prove concerns
  /// exactly the records the cut never reached.
  struct Resident {
    instance: Instance,
    shared: ReaderShared,
    queue_rx: async_channel::Receiver<SourceMessage>,
    /// The control channel `drain_events` services between reads; kept empty
    /// and un-shut-down so the post-cut drain is a plain read-to-`EAGAIN`.
    control_rx: mpsc::Receiver<Control>,
    /// Held only to keep `control_rx` connected, exactly as a live port does.
    _control_tx: mpsc::Sender<Control>,
    wake: std::sync::Arc<WakeState>,
    dir: std::path::PathBuf,
  }

  impl Drop for Resident {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.dir);
    }
  }

  /// Arms `watch(1)` on a real directory through the reader's own control path,
  /// then floods it: the records are genuinely kernel-committed and genuinely
  /// unread, which is the only staging under which "what the cut could not read"
  /// means anything.
  fn resident(tag: &str) -> Resident {
    let mut instance = instance();
    let (shared, queue_rx) = reader_shared();
    let dir = scratch(tag);
    let wake = WakeState::new().expect("wake state");
    let (control_tx, control_rx) = mpsc::channel();

    let armed = arm_batch(&control_tx, watch(1), &dir);
    let mut buf = vec![0u8; 64 * 1024];
    assert!(!drain_control(
      &mut instance,
      &shared,
      &control_rx,
      &wake,
      &mut buf
    ));
    let replies = armed.recv_timeout(Duration::from_secs(5)).expect("armed");
    assert!(
      matches!(replies[0].outcome, WatchOutcome::Installed(_)),
      "the scratch dir armed: {:?}",
      replies[0].outcome
    );
    drop(replies);

    flood(&dir, 8);
    assert!(
      drained(&queue_rx).is_empty(),
      "staging: the flooded records are UNREAD, so every message a cell sees below \
       is the degrade's own"
    );
    Resident {
      instance,
      shared,
      queue_rx,
      control_rx,
      _control_tx: control_tx,
      wake,
      dir,
    }
  }

  /// The unprovable cut's whole contract, read off one staged instance: the
  /// reader's NEXT drain forwards nothing behind the covering loss, exactly one
  /// covering loss closes what the cut did forward, and the instance was
  /// retired.
  ///
  /// The order is the finding's order. A degrade that only signals the loss
  /// fails the FIRST assertion, with the stale batch that crossed printed in the
  /// message — which is the defect, stated as the cell sees it.
  fn assert_nothing_outlives_the_loss(resident: &mut Resident, fd_before: RawFd, leg: &str) {
    let cut = drained(&resident.queue_rx);
    let mut buf = vec![0u8; 64 * 1024];
    let exit = drain_events(
      &mut resident.instance,
      &mut buf,
      &resident.control_rx,
      &resident.wake,
      &resident.shared,
    );
    assert_eq!(
      exit,
      DrainExit::Parked,
      "{leg}: the post-cut instance drains clean"
    );
    let after = drained(&resident.queue_rx);
    assert_eq!(
      after,
      Vec::<Sent>::new(),
      "{leg}: NOTHING may follow the covering loss — the records the cut could not \
       prove it read are gone with the retired fd, never delivered as ordinary history \
       into the epoch the loss opened (the cut forwarded {cut:?}, then this: {after:?})"
    );
    assert_eq!(
      cut.iter().filter(|s| **s == Sent::Overflow).count(),
      1,
      "{leg}: exactly one covering loss, ahead of the reply: {cut:?}"
    );
    assert_eq!(
      cut.last(),
      Some(&Sent::Overflow),
      "{leg}: and it CLOSES the cut — what the retirement salvaged rides AHEAD of it, \
       never behind: {cut:?}"
    );
    assert_ne!(
      resident.instance.fd.as_raw_fd(),
      fd_before,
      "{leg}: the instance is RETIRED, which is what makes the remainder \
       unconstructible rather than merely covered"
    );
  }

  /// An unprovable cut's unread remainder may not arrive as post-loss history.
  ///
  /// Announcing the loss and replying is honest about the loss and silent about
  /// what follows it: the remainder the cut could not prove it read is still
  /// resident on the SAME instance, so the reader's very next drain forwards
  /// those OLDER records as an ordinary batch BEHIND the covering loss — stamped
  /// in the epoch the loss's `Rescan` opened. A consumer that crawled at the
  /// rescan then replays pre-loss renames and removes over its fresh state, and
  /// an all-aliased binding reproof can close with no rescan of its own, so
  /// nothing downstream re-covers them.
  ///
  /// Each leg stages REAL kernel-resident records and drives one of the three
  /// unprovable exits over the injected read — which never touches that
  /// remainder and never reaches `EAGAIN`, so the exit is forced with the
  /// remainder intact. The verdict is then read from the reader's own
  /// `drain_events`, not from a paraphrase of it.
  ///
  /// MUTATION WITNESS: revert either exit to `signal_covering_loss(shared);
  /// return false;` and every leg FAILS on the first assertion — the same fd is
  /// still installed, `drain_events` reads the flooded remainder off it, and an
  /// ordinary `Batch` lands behind the `Overflow`.
  #[test]
  fn an_unprovable_cut_lets_no_pre_loss_record_cross_into_the_new_epoch() {
    // A credible debt that will not retire under its own read bound.
    let mut owed = resident("resident-owed");
    let fd_before = owed.instance.fd.as_raw_fd();
    let mut buf = vec![0u8; 64 * 1024];
    let mut reads = 0u32;
    let exit = cut_kernel_queue_with(
      &mut owed.instance,
      &owed.shared,
      &mut buf,
      || false,
      |_, out| {
        reads += 1;
        out[..UNMAPPED_RECORD.len()].copy_from_slice(&UNMAPPED_RECORD);
        Ok(UNMAPPED_RECORD.len())
      },
      |_| Ok(1024),
      create_instance,
    );
    assert!(!exit, "a retired instance is not a stream death");
    assert_eq!(
      reads, MAX_CUT_OWED_READS,
      "the owed bound is what exhausted"
    );
    assert_nothing_outlives_the_loss(&mut owed, fd_before, "credible debt");

    // The unknown-count fallback, exhausted before `EAGAIN`.
    let mut fallback = resident("resident-fallback");
    let fd_before = fallback.instance.fd.as_raw_fd();
    let mut reads = 0u32;
    let exit = cut_kernel_queue_with(
      &mut fallback.instance,
      &fallback.shared,
      &mut buf,
      || false,
      |_, out| {
        reads += 1;
        out[..UNMAPPED_RECORD.len()].copy_from_slice(&UNMAPPED_RECORD);
        Ok(UNMAPPED_RECORD.len())
      },
      |_| Err(Errno::NOTTY),
      create_instance,
    );
    assert!(!exit, "a retired instance is not a stream death");
    assert_eq!(
      reads, MAX_CUT_FALLBACK_READS,
      "the unknown-count bound is what exhausted"
    );
    assert_nothing_outlives_the_loss(&mut fallback, fd_before, "unknown count");

    // The interrupted-read budget, exhausted with nothing read at all.
    let mut storm = resident("resident-interrupt");
    let fd_before = storm.instance.fd.as_raw_fd();
    let mut attempts = 0u32;
    let exit = cut_kernel_queue_with(
      &mut storm.instance,
      &storm.shared,
      &mut buf,
      || false,
      |_, _| {
        attempts += 1;
        Err(Errno::INTR)
      },
      |_| Ok(1024),
      create_instance,
    );
    assert!(!exit, "a retired instance is not a stream death");
    assert_eq!(
      attempts, MAX_CUT_INTERRUPTED_READS,
      "the interrupted-attempt budget is what exhausted"
    );
    assert_nothing_outlives_the_loss(&mut storm, fd_before, "interrupt storm");
  }

  /// The unprovable cut's one fatal leg: no replacement instance.
  ///
  /// The arm gate can refuse its arm and keep the old fd — no add, no cursor
  /// advance, the wrap stays impossible — but the cut has no equivalent retreat:
  /// the old fd's unread remainder is exactly what must not survive, so a reader
  /// that cannot retire the instance stops delivering instead of delivering it.
  /// The terminal `Fatal` dominates the loss it could not signal, and the stream
  /// is left UNTOUCHED (no drain, no swap) so nothing half-retired can leak.
  #[test]
  fn an_unprovable_cut_that_cannot_be_retired_is_fatal() {
    let mut unmintable = resident("no-replacement");
    let fd_before = unmintable.instance.fd.as_raw_fd();
    let mut buf = vec![0u8; 64 * 1024];
    let exit = cut_kernel_queue_with(
      &mut unmintable.instance,
      &unmintable.shared,
      &mut buf,
      || false,
      |_, out| {
        out[..UNMAPPED_RECORD.len()].copy_from_slice(&UNMAPPED_RECORD);
        Ok(UNMAPPED_RECORD.len())
      },
      |_| Err(Errno::NOTTY),
      || Err(SourceError::InstanceLimit),
    );
    assert!(
      exit,
      "a cut that cannot retire the instance stops the reader rather than delivering \
       the remainder it could not prove it read"
    );
    assert_eq!(
      unmintable.instance.fd.as_raw_fd(),
      fd_before,
      "the failed mint leaves the stream untouched — no drain, no swap, no loss"
    );
    let mut sent = Vec::new();
    while let Ok(msg) = unmintable.queue_rx.try_recv() {
      sent.push(msg);
    }
    assert!(
      matches!(
        sent.as_slice(),
        [SourceMessage::Fatal(SourceError::InstanceLimit)]
      ),
      "the terminal Fatal carries the real reason and is ALL that crosses: {sent:?}"
    );
  }

  /// The retained-binding recovery's premise, pinned at the reader's own seam
  /// with nothing privileged in play: no sysctl, no loop device, no process
  /// stopped mid-flight.
  ///
  /// Everything that makes the swallowed case what it is lives in the RECORD
  /// STREAM, not in kernel state: the reader learns of a watch's death from an
  /// `IN_IGNORED` (with an `IN_DELETE_SELF` or `IN_UNMOUNT` ahead of it), and a
  /// queue overflow destroys unread records — so a scope can die with its
  /// teardown pair among the destroyed, leaving the reader only the sentinel.
  /// The two cells below stage exactly that stream, byte for byte, over the
  /// cut's injected read: identical staging, one bit of difference — whether the
  /// teardown pair is in the buffer — so the retention the first cell asserts is
  /// the record shape's doing and not the table's inertia. That contrast is what
  /// gives the first cell its meaning.
  ///
  /// The staging is real on every side the reader can see. The `wd` is granted
  /// by the kernel through the reader's own control path, the death is genuine
  /// (the arm's `O_PATH` anchor is released before the directory is removed, so
  /// the kernel destroys the mark for real and really queues the pair the
  /// swallowed buffer then omits), and the bytes travel the production route —
  /// `decode_events`, `attribute_events`, the live `WdTable`, the real transport
  /// — so what these cells exercise is attribution, not a paraphrase of it.
  mod swallowed_teardown {
    use std::{ffi::OsString, sync::mpsc, time::Duration};

    use tributary_proto::WatchId;

    use super::{
      AnchorRequest, Instance, ReaderShared, arm_batch, cut_kernel_queue_with, drain_control,
      instance, reader_shared, scratch, watch,
    };
    use crate::os::{
      SourceEvent, SourceMessage,
      linux::{
        WatchOutcome,
        inotify::{
          decode::{IN_ATTRIB, IN_DELETE_SELF, IN_IGNORED, IN_ISDIR, IN_Q_OVERFLOW, IN_UNMOUNT},
          reader::arm,
        },
        wake::WakeState,
      },
    };

    /// One packed kernel `inotify_event`: the 16-byte header — `wd`, `mask`,
    /// `cookie`, `len` — then the name, NUL-terminated and padded up to a
    /// multiple of the header size, exactly as `copy_event_to_user` lays it out.
    /// Native-endian, because the reader decodes what its own machine wrote. A
    /// nameless record (a self-event, a teardown marker, the overflow sentinel)
    /// carries `len == 0` and no tail at all.
    fn record(wd: i32, mask: u32, name: Option<&[u8]>) -> Vec<u8> {
      const HEADER: usize = 16;
      let mut tail = Vec::new();
      if let Some(name) = name {
        tail.extend_from_slice(name);
        tail.push(0);
        while tail.len() % HEADER != 0 {
          tail.push(0);
        }
      }
      let mut out = Vec::with_capacity(HEADER + tail.len());
      out.extend_from_slice(&wd.to_ne_bytes());
      out.extend_from_slice(&mask.to_ne_bytes());
      out.extend_from_slice(&0u32.to_ne_bytes());
      out.extend_from_slice(&(tail.len() as u32).to_ne_bytes());
      out.extend_from_slice(&tail);
      out
    }

    /// What the reader forwarded onto the source's queue, in order: a `Batch`
    /// laid out as the `(anchors, mask)` of each inotify record it carried — so
    /// a cell can say WHICH anchor a teardown was reported for, not merely that
    /// a batch of some size crossed — or the covering loss.
    #[derive(Debug, PartialEq, Eq)]
    enum Forwarded {
      Batch(Vec<(Vec<WatchId>, u32)>),
      Overflow,
    }

    fn forwarded(rx: &async_channel::Receiver<SourceMessage>) -> Vec<Forwarded> {
      let mut sent = Vec::new();
      while let Ok(msg) = rx.try_recv() {
        sent.push(match msg {
          SourceMessage::Batch(payload) => Forwarded::Batch(
            payload
              .events
              .iter()
              .map(|event| {
                let SourceEvent::Linux(linux) = event else {
                  panic!("the inotify reader forwards linux records only");
                };
                let (anchors, raw) = linux.as_inotify().expect("an inotify record");
                (anchors.to_vec(), raw.mask.0)
              })
              .collect(),
          ),
          SourceMessage::Overflow(_) => Forwarded::Overflow,
          SourceMessage::Fatal(err) => panic!("no fatal on this path: {err:?}"),
        });
      }
      sent
    }

    /// One armed scope whose kernel watch is then genuinely destroyed, with the
    /// teardown records it produced still unread on the fd.
    struct DeadScope {
      instance: Instance,
      shared: ReaderShared,
      queue_rx: async_channel::Receiver<SourceMessage>,
      /// The `wd` the kernel granted the arm — the binding under test.
      wd: i32,
      /// The watched path, freed for a re-add to re-occupy.
      dir: std::path::PathBuf,
    }

    /// Arms `watch(1)` on a real directory through the reader's own control
    /// path, then kills the watched object for real: the arm's `O_PATH` anchor
    /// is released FIRST, so nothing pins the inode, the kernel destroys the
    /// mark, and its teardown pair queues unread. The reader's table still maps
    /// the binding — a dead watch is indistinguishable from a live one until a
    /// record says otherwise, which is the whole reason the swallowed case
    /// exists.
    fn armed_then_dead(tag: &str) -> DeadScope {
      let mut instance = instance();
      let (shared, queue_rx) = reader_shared();
      let dir = scratch(tag);
      let wake = WakeState::new().expect("wake state");
      let (tx, rx) = mpsc::channel();

      let armed = arm_batch(&tx, watch(1), &dir);
      let mut buf = vec![0u8; 64 * 1024];
      assert!(!drain_control(&mut instance, &shared, &rx, &wake, &mut buf));
      let replies = armed.recv_timeout(Duration::from_secs(5)).expect("armed");
      let WatchOutcome::Installed(wd) = replies[0].outcome else {
        panic!("the scratch dir armed: {:?}", replies[0].outcome);
      };
      assert_eq!(
        instance.table.attribute(wd).to_vec(),
        vec![watch(1)],
        "the binding attributes before anything is lost"
      );
      assert!(
        forwarded(&queue_rx).is_empty(),
        "arming forwards nothing of its own"
      );

      drop(replies); // release the O_PATH anchor: nothing pins the inode
      std::fs::remove_dir_all(&dir).expect("kill the watched object");

      DeadScope {
        instance,
        shared,
        queue_rx,
        wd,
        dir,
      }
    }

    /// Runs the reader's real pre-reply cut over a queue whose ENTIRE content is
    /// `queue`: one read hands that buffer back, the next reports the queue
    /// empty. `FIONREAD` answers the byte count the kernel would report for that
    /// queue, so the real body's credible-debt path runs and ends on the empty
    /// read — the cut signals nothing of its own, which is what lets a cell
    /// attribute any loss on the source queue to the RECORDS rather than to a
    /// degrade.
    fn deliver(instance: &mut Instance, shared: &ReaderShared, queue: &[u8]) {
      let mut buf = vec![0u8; 64 * 1024];
      let mut reads = 0u32;
      let exit = cut_kernel_queue_with(
        instance,
        shared,
        &mut buf,
        || false,
        |_, out| {
          reads += 1;
          if reads > 1 {
            return Ok(0);
          }
          out[..queue.len()].copy_from_slice(queue);
          Ok(queue.len())
        },
        |_| Ok(queue.len() as u64),
        // A cut that reaches the queue's end proves the cut and retires
        // nothing; minting an instance here would mean these cells' bindings
        // died with a swapped table rather than surviving the loss, which is
        // the very retention they exist to assert.
        || unreachable!("a proven cut mints no replacement instance"),
      );
      assert!(
        !exit,
        "a delivered queue neither dies nor retires the instance"
      );
      assert_eq!(reads, 2, "the scripted queue was read, then read empty");
    }

    /// The swallowed case. The buffer holds the genuine pre-death traffic and
    /// then the kernel's overflow sentinel; the target's `IN_IGNORED` — and the
    /// `IN_DELETE_SELF`/`IN_UNMOUNT` that would have preceded it — are ABSENT,
    /// destroyed with the rest of an unread queue. Nothing in that stream tells
    /// the attribution layer the watch died, so:
    ///
    /// - the binding stays RETAINED — mapped, live, still the anchor's `wd` (the
    ///   loss reaps draining tombstones, which await a marker that may have been
    ///   among the destroyed, and leaves live bindings alone);
    /// - the covering loss is signalled, and it is ALL that crosses: the lossy
    ///   buffer's own records are dropped behind the barrier, so the driver's
    ///   settle-edge fence sees the loss and degrades instead of certifying over
    ///   a window it cannot describe.
    ///
    /// The closing leg is what the retention is FOR: the recovery's re-add
    /// re-proves the binding on a FRESH `wd`, supersedes the retained one, and
    /// erases its tombstone on the removal's `EINVAL` — the kernel's own proof
    /// that the marker this cut never saw can never come.
    #[test]
    fn a_swallowed_teardown_retains_the_binding_and_signals_a_covering_loss() {
      let mut scope = armed_then_dead("swallowed");
      let wd = scope.wd;

      let queue = [
        // Genuine traffic the binding attributed while it was still believed
        // live — a chmod of a child, the densest record a directory watch sees.
        record(wd, IN_ATTRIB, Some(b"a")),
        // The kernel could not queue what came next and destroyed it, marking
        // the gap with its sentinel. The teardown pair was in that gap.
        record(-1, IN_Q_OVERFLOW, None),
      ]
      .concat();
      deliver(&mut scope.instance, &scope.shared, &queue);

      assert_eq!(
        forwarded(&scope.queue_rx),
        vec![Forwarded::Overflow],
        "the covering loss is signalled, and the lossy buffer's records ride nothing ahead of it"
      );
      assert_eq!(
        scope.instance.table.wd_of(watch(1)),
        Some(wd),
        "the binding is RETAINED: nothing in the stream said its watch died"
      );
      assert_eq!(
        scope.instance.table.attribute(wd).to_vec(),
        vec![watch(1)],
        "and it still attributes — a retained binding, not a stranded entry"
      );
      assert!(
        scope.instance.table.is_live(wd),
        "retained LIVE, so the re-add's kernel reply is what decides its fate"
      );

      std::fs::create_dir_all(&scope.dir).expect("re-occupy the watched path");
      let readd = arm(
        &mut scope.instance,
        AnchorRequest {
          watch: watch(1),
          parent: None,
          name: OsString::from(scope.dir.as_os_str()),
          expected: None,
        },
      );
      let WatchOutcome::Installed(fresh) = readd.outcome else {
        panic!(
          "the retained binding re-proves by a fresh install: {:?}",
          readd.outcome
        );
      };
      assert!(
        fresh > wd,
        "the re-add's grant outgrows the retained wd: {fresh} vs {wd}"
      );
      assert_eq!(
        scope.instance.table.wd_of(watch(1)),
        Some(fresh),
        "the anchor now binds the re-proved watch"
      );
      assert!(
        !scope.instance.table.contains(wd),
        "the superseded binding strands no tombstone: its removal answered EINVAL"
      );

      let _ = std::fs::remove_dir_all(&scope.dir);
    }

    /// The contrast leg. Same staging, same real death, same injected-read seam
    /// — the buffer simply CARRIES the teardown pair the swallowed case lost. So
    /// the attribution layer is told, and the retained-binding case does not
    /// arise at all: the marker erases the mapping, the teardown is reported to
    /// the anchor it belonged to, and no loss is signalled because nothing needs
    /// covering.
    ///
    /// Both real teardown pairs are run — a deleted object (`IN_DELETE_SELF`,
    /// which the kernel flags `IN_ISDIR` for a directory) and an unmounted one
    /// (`IN_UNMOUNT`) — since it is the marker that erases, and either preface
    /// must reach the driver as ordinary attributed traffic.
    #[test]
    fn a_delivered_teardown_drops_the_binding() {
      for (tag, preface) in [
        ("delivered-deleted", IN_DELETE_SELF | IN_ISDIR),
        ("delivered-unmounted", IN_UNMOUNT),
      ] {
        let mut scope = armed_then_dead(tag);
        let wd = scope.wd;

        let queue = [
          record(wd, IN_ATTRIB, Some(b"a")),
          record(wd, preface, None),
          record(wd, IN_IGNORED, None),
        ]
        .concat();
        deliver(&mut scope.instance, &scope.shared, &queue);

        assert_eq!(
          forwarded(&scope.queue_rx),
          vec![Forwarded::Batch(vec![
            (vec![watch(1)], IN_ATTRIB),
            (vec![watch(1)], preface),
            (vec![watch(1)], IN_IGNORED),
          ])],
          "a delivered teardown is REPORTED to its anchor, with no loss to cover"
        );
        assert_eq!(
          scope.instance.table.wd_of(watch(1)),
          None,
          "no retained-binding claim survives a delivered marker"
        );
        assert!(
          scope.instance.table.attribute(wd).is_empty(),
          "the dropped binding attributes to nobody"
        );
        assert!(
          !scope.instance.table.contains(wd),
          "the marker is the authoritative erase: not even a tombstone remains"
        );
      }
    }
  }
}
