//! The per-root reader thread: owns the inotify fd AND the `wd` table, so
//! decode-attribution and arm/disarm mutations are serialized by
//! construction — control requests travel over a channel and are executed
//! between reads, never concurrently with them.
//!
//! Wakeup: the thread blocks in `poll` over the inotify fd and a per-root
//! [`WakeState`] eventfd. Control senders enqueue first, then wake the eventfd
//! only when the reader is parked (see [`WakeState`]'s lost-wakeup argument),
//! so a busy reader takes no wake syscalls and a batch of N arms costs at most
//! one wake. Arms arrive batched (one [`Control::Batch`] per driver effect-drain
//! per scope) and are processed in a single pass between reads.

use std::{
  os::fd::{AsFd, AsRawFd, OwnedFd},
  panic::{AssertUnwindSafe, catch_unwind},
  sync::{Arc, mpsc},
  thread::JoinHandle,
};

use rustix::{
  event::{PollFd, PollFlags, poll},
  fs::{
    OFlags,
    inotify::{self, WatchFlags},
    openat,
  },
  io::Errno,
};
use tributary_proto::{WatchError, WatchId};

use super::{
  super::{
    super::{SourceError, transport},
    AnchorRequest, ArmReply, WatchOutcome, attribute_events,
    wake::WakeState,
  },
  decode::{self, WATCH_MASK},
  table::{DrainDecision, WdTable},
};

/// What the reader shares with the handle side.
pub(crate) struct ReaderShared {
  /// The source's single ordered queue.
  pub(crate) queue: async_channel::Sender<crate::os::SourceMessage>,
  /// The batch budget and signal dedups.
  pub(crate) transport: transport::TransportState,
}

/// One arm or disarm inside a control batch. Emission order is preserved: a
/// disarm and a later re-arm of the same slot mutate the `wd` table in the same
/// order the core produced them.
pub(crate) enum ControlOp {
  /// Install (or alias) a kernel watch for `request.watch`.
  Arm(AnchorRequest),
  /// Drop `anchor` from attribution (kernel removal when its last alias
  /// drains).
  Disarm(WatchId),
}

/// One control request executed by the reader between reads. Arms/disarms are
/// batched — one message per effect-drain cycle per scope — so N arms cost one
/// enqueue and at most one wake; each arm still gets its own reply slot.
pub(crate) enum Control {
  /// A batch of arms/disarms in emission order, with one reply carrying the
  /// arms' outcomes (index-aligned to the `Arm` entries, in order).
  Batch {
    ops: Vec<ControlOp>,
    reply: mpsc::SyncSender<Vec<ArmReply>>,
  },
  Shutdown,
}

/// Creates the per-root inotify instance.
pub(crate) fn create_instance() -> Result<OwnedFd, SourceError> {
  inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK).map_err(|err| {
    // EMFILE is both the per-process fd ceiling and the per-uid
    // `fs.inotify.max_user_instances` ceiling — the typed spawn error the
    // per-root-instance topology trades for its overflow isolation.
    if err == Errno::MFILE {
      SourceError::InstanceLimit
    } else {
      SourceError::CreateFailed
    }
  })
}

/// Starts the reader thread. The fd, the wake eventfd, and the `wd` table live
/// and die with it.
pub(crate) fn start(
  fd: OwnedFd,
  wake: Arc<WakeState>,
  control: mpsc::Receiver<Control>,
  shared: Arc<ReaderShared>,
) -> JoinHandle<()> {
  std::thread::Builder::new()
    .name("tributary-fs.inotify".into())
    .spawn(move || {
      let outcome = catch_unwind(AssertUnwindSafe(|| {
        run(&fd, &wake, &control, &shared);
      }));
      if outcome.is_err() {
        signal_fatal(&shared, SourceError::CallbackPanic);
      }
    })
    .expect("spawning the reader thread")
}

fn signal_fatal(shared: &ReaderShared, err: SourceError) {
  transport::signal_fatal_once(&shared.transport, err, |msg| {
    shared.queue.try_send(msg).is_ok()
  });
}

fn run(fd: &OwnedFd, wake: &WakeState, control: &mpsc::Receiver<Control>, shared: &ReaderShared) {
  let mut table = WdTable::new();
  // Sized for a dense read: watchman's batch scale (16k events of header
  // size) is far past what one wake needs; 64 KiB covers the deepest names.
  let mut buf = vec![0u8; 64 * 1024];
  loop {
    // Announce the intent to block, then re-drain control BEFORE polling: a
    // sender that enqueued before our fence is guaranteed visible here (the
    // lost-wakeup guard — see `WakeState`). Draining anything means we service
    // it and loop without ever blocking on a non-empty queue.
    wake.arm_park();
    if drain_control(fd, &mut table, control) {
      return; // Shutdown observed in the guard drain.
    }
    // A quiet re-check found nothing pending; commit to the block. Only the
    // eventfd (a sender's wake) or source data returns us.
    let event = wake.event_fd();
    let mut fds = [
      PollFd::new(fd, PollFlags::IN),
      PollFd::new(&event, PollFlags::IN),
    ];
    match poll(&mut fds, None) {
      Ok(_) => {}
      Err(Errno::INTR) => {
        wake.unpark();
        continue;
      }
      Err(err) => {
        wake.unpark();
        signal_fatal(shared, SourceError::ReadFailed { source: err.into() });
        return;
      }
    }
    let source_ready = fds[0].revents().contains(PollFlags::IN);
    let event_ready = fds[1].revents().contains(PollFlags::IN);
    wake.unpark();

    if event_ready {
      wake.drain();
      if drain_control(fd, &mut table, control) {
        return;
      }
    }
    if source_ready && !drain_events(fd, &mut buf, &mut table, shared) {
      return;
    }
  }
}

/// Drains every pending control message, executing each batch in one pass.
/// Returns `true` when a shutdown was observed (the caller then exits).
fn drain_control(fd: &OwnedFd, table: &mut WdTable, control: &mpsc::Receiver<Control>) -> bool {
  loop {
    match control.try_recv() {
      Ok(Control::Batch { ops, reply }) => {
        let mut replies = Vec::new();
        for op in ops {
          match op {
            ControlOp::Arm(request) => replies.push(arm(fd, table, request)),
            ControlOp::Disarm(anchor) => disarm(fd, table, anchor),
          }
        }
        let _ = reply.send(replies);
      }
      Ok(Control::Shutdown) => return true,
      Err(_) => return false,
    }
  }
}

/// Reads the instance until `EAGAIN`, forwarding each buffer as one batch.
/// Returns `false` when the stream died (fatal already signaled).
fn drain_events(fd: &OwnedFd, buf: &mut [u8], table: &mut WdTable, shared: &ReaderShared) -> bool {
  loop {
    let n = match rustix::io::read(fd, &mut *buf) {
      Ok(n) => n,
      // `EAGAIN` and `EWOULDBLOCK` are the same errno on Linux.
      Err(Errno::AGAIN) => return true,
      Err(Errno::INTR) => continue,
      Err(err) => {
        signal_fatal(shared, SourceError::ReadFailed { source: err.into() });
        return false;
      }
    };
    if n == 0 {
      return true;
    }
    let decoded = decode::decode_events(&buf[..n]);
    let attributed = attribute_events(decoded.events, table);
    let events = attributed
      .events
      .into_iter()
      .map(crate::os::SourceEvent::Linux)
      .collect();
    transport::forward_batch(
      &shared.transport,
      events,
      decoded.lossy || attributed.lost,
      |msg| shared.queue.try_send(msg).is_ok(),
    );
  }
}

/// Executes one arm on the reader's own fd: open the target through the
/// parent anchor (object-correct — a parent rename cannot retarget the add),
/// install through `/proc/self/fd/N`, and map `EEXIST` to the aliasing path.
fn arm(fd: &OwnedFd, table: &mut WdTable, request: AnchorRequest) -> ArmReply {
  let anchor = match open_anchor(&request) {
    Ok(anchor) => anchor,
    Err(err) => {
      return ArmReply {
        outcome: WatchOutcome::Failed(errno_to_watch_error(err)),
        anchor: None,
      };
    }
  };

  let proc_path = format!("/proc/self/fd/{}", anchor.as_raw_fd());
  // The /proc entry is itself a symlink to the anchored object, so the add
  // must follow exactly that one link. Symlink safety is already enforced —
  // `open_anchor` opened with `NOFOLLOW|DIRECTORY`, so the object behind the
  // anchor is a real directory, never a link.
  let mask = WatchFlags::from_bits_retain(WATCH_MASK & !decode::IN_DONT_FOLLOW);
  match inotify::add_watch(fd, proc_path.as_str(), mask) {
    Ok(wd) => {
      table.register(wd, request.watch);
      ArmReply {
        outcome: WatchOutcome::Installed(wd),
        anchor: Some(anchor),
      }
    }
    // The inode is already watched. `IN_MASK_CREATE` refuses to say WHICH wd,
    // so re-add without it: the mask is identical, making the update a no-op
    // that returns the existing wd for the alias registration.
    Err(Errno::EXIST) => {
      let mask = WatchFlags::from_bits_retain(mask.bits() & !decode::IN_MASK_CREATE);
      match inotify::add_watch(fd, proc_path.as_str(), mask) {
        Ok(wd) => {
          table.alias(wd, request.watch);
          ArmReply {
            outcome: WatchOutcome::Aliased(wd),
            anchor: Some(anchor),
          }
        }
        Err(err) => ArmReply {
          outcome: WatchOutcome::Failed(errno_to_watch_error(err)),
          anchor: None,
        },
      }
    }
    Err(err) => ArmReply {
      outcome: WatchOutcome::Failed(errno_to_watch_error(err)),
      anchor: None,
    },
  }
}

/// Opens the arm target as a transient `O_PATH` anchor.
fn open_anchor(request: &AnchorRequest) -> Result<OwnedFd, Errno> {
  let dirfd = request.parent.as_ref().map(|fd| fd.as_fd());
  let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC;
  // `openat` with a `None` dirfd is `AT_FDCWD` in rustix; the root arms by its
  // absolute canonical path, a child arms relative to its parent's anchor.
  match dirfd {
    Some(dirfd) => openat(
      dirfd,
      request.name.as_os_str(),
      flags,
      rustix::fs::Mode::empty(),
    ),
    None => openat(
      rustix::fs::CWD,
      request.name.as_os_str(),
      flags,
      rustix::fs::Mode::empty(),
    ),
  }
}

/// Removes `anchor` from attribution, issuing the kernel removal when the
/// last alias drains. `remove_watch` errors are ignored deliberately: the
/// kernel auto-removes a watch whose object was deleted (its `IN_IGNORED` is
/// already queued), making `EINVAL` here a benign race, and the table entry
/// drains through that `IN_IGNORED` either way.
fn disarm(fd: &OwnedFd, table: &mut WdTable, anchor: WatchId) {
  if let DrainDecision::RemoveWd(wd) = table.begin_drain(anchor) {
    let _ = inotify::remove_watch(fd, wd);
  }
}

/// Maps an arm-time [`Errno`] to the Monitor's watch-result taxonomy.
fn errno_to_watch_error(err: Errno) -> WatchError {
  match err {
    Errno::NOENT => WatchError::NotFound,
    // The slot's object stopped being a directory between the caller's
    // enumerate and this arm — the directory the Monitor meant is gone.
    Errno::NOTDIR => WatchError::Gone,
    Errno::ACCESS | Errno::PERM => WatchError::Permission,
    // fs.inotify.max_user_watches exhausted.
    Errno::NOSPC => WatchError::NoSpace,
    _ => WatchError::Io,
  }
}

/// The pure decode constants restate the kernel ABI; this pins them to libc
/// so they can never drift.
#[cfg(test)]
mod libc_cross_assert {
  use super::decode;

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
