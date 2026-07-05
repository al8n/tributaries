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
      attribute_events,
      inotify::{
        decode::{IN_CREATE, IN_MOVED_FROM, IN_Q_OVERFLOW, InotifyMask, RawInotifyEvent},
        table::WdTable,
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

  /// Attributes `records` against a table holding one live `wd`, then runs the
  /// reader's `forward_attributed` over the result, capturing what it forwards.
  fn run(records: Vec<RawInotifyEvent>, decode_lossy: bool) -> Vec<Sent> {
    let mut table = WdTable::new();
    table.register(3, watch(1));
    let attributed = attribute_events(records, &mut table);
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

  use tributary_proto::WatchId;

  use super::super::{AnchorRequest, Control, ControlOp, DrainExit, ReaderShared, drain_events};
  use crate::os::{SourceMessage, linux::inotify::table::WdTable, transport::TransportState};

  /// An always-readable fd that never returns `EAGAIN`, standing in for a source
  /// under sustained traffic: `drain_events` reads it forever unless it observes a
  /// control message between reads.
  fn never_eagain_fd() -> OwnedFd {
    std::fs::File::open("/dev/zero")
      .expect("/dev/zero opens on linux")
      .into()
  }

  /// A `ReaderShared` over an unbounded queue; the returned receiver is kept alive
  /// so the queue never closes (the all-zero drain forwards nothing, but a closed
  /// queue would still be a surprise the tests should not carry).
  fn reader_shared() -> (ReaderShared, async_channel::Receiver<SourceMessage>) {
    let (tx, rx) = async_channel::unbounded();
    let shared = ReaderShared {
      queue: tx,
      transport: TransportState::new(8),
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

    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let mut table = WdTable::new();
      let mut buf = vec![0u8; 64 * 1024];
      let exit = drain_events(&fd, &mut buf, &mut table, &rx, &shared);
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

    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let mut table = WdTable::new();
      let mut buf = vec![0u8; 64 * 1024];
      let exit = drain_events(&fd, &mut buf, &mut table, &rx, &shared);
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
  #[test]
  fn arm_batch_is_serviced_mid_drain() {
    let fd = never_eagain_fd();
    let (tx, rx) = mpsc::channel();
    let (shared, _queue_rx) = reader_shared();

    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let mut table = WdTable::new();
      let mut buf = vec![0u8; 64 * 1024];
      let exit = drain_events(&fd, &mut buf, &mut table, &rx, &shared);
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
      reply: reply_tx,
    })
    .expect("enqueue arm batch mid-drain");
    let replies = reply_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("the arm must be serviced mid-drain, not after EAGAIN");
    assert_eq!(
      replies.len(),
      1,
      "one arm yields one reply, serviced inline"
    );

    tx.send(Control::Shutdown).expect("enqueue shutdown");
    let exit = done_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("shutdown after the arm still stops the drain");
    assert_eq!(exit, DrainExit::Shutdown);
    worker.join().expect("worker joins");
  }
}
