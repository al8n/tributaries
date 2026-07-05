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
//!
//! # Teardown-fairness invariant
//!
//! No unbounded or long-running op loop on this reader may defer shutdown
//! indefinitely. Every such loop yields to a pending teardown at a bounded
//! granularity:
//!
//! | Long-op site                     | Verdict                              |
//! |----------------------------------|--------------------------------------|
//! | Event drain (read → `EAGAIN`)    | preemptible BETWEEN reads            |
//! | Inter-message control drain      | preemptible BETWEEN messages         |
//! | Intra-batch arm/disarm ops       | preemptible BETWEEN ops, failed-reply the tail |
//!
//! The last is the sharp edge: one [`Control::Batch`] can be a cold enumerate's
//! thousands of blocking `openat`/`fstat`/`add_watch`, so [`execute_batch`] checks
//! [`WakeState::shutdown_requested`] before each op and, on a pending teardown,
//! stops and answers `Failed(Io)` for every un-executed arm — the caller's pending
//! grants resolve as failures rather than blocking on a truncated reply, and the
//! reader exits at once. A bounded op that CANNOT be safely interrupted is instead
//! documented as must-complete: the fanotify reader's reseed / move-in subtree
//! walks (its sibling module) rebuild the map atomically, so interrupting one would
//! leave a half-built map (silent blindness) — shutdown waits for the walk, which
//! is bounded by the directory count and either completes or escalates blind →
//! fatal. This reader has no such walk; its every long op is preemptible.

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
    AnchorRequest, ArmReply, ExpectedObject, WatchOutcome, attribute_events,
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
/// and die with it. A spawn failure (thread or memory exhaustion) is a typed
/// [`SourceError::StartFailed`] on the never-live path — the instance fd closes
/// as the returned closure drops, and no watch was armed.
pub(crate) fn start(
  fd: OwnedFd,
  wake: Arc<WakeState>,
  control: mpsc::Receiver<Control>,
  shared: Arc<ReaderShared>,
) -> Result<JoinHandle<()>, SourceError> {
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
    .map_err(|_| SourceError::StartFailed)
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
    if drain_control(fd, &mut table, control, wake) {
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
      if drain_control(fd, &mut table, control, wake) {
        return;
      }
    }
    if source_ready {
      match drain_events(fd, &mut buf, &mut table, control, wake, shared) {
        DrainExit::Parked => {}
        DrainExit::Shutdown | DrainExit::Died => return,
      }
    }
  }
}

/// Drains every pending control message, executing each batch in one pass.
/// Returns `true` when a shutdown was observed (the caller then exits). A batch is
/// run through [`execute_batch`], which yields to a pending teardown BETWEEN its
/// ops — so shutdown preempts a long cold-enumerate batch mid-flight rather than
/// only after the whole batch (the teardown-fairness invariant in the module docs).
fn drain_control(
  fd: &OwnedFd,
  table: &mut WdTable,
  control: &mpsc::Receiver<Control>,
  wake: &WakeState,
) -> bool {
  loop {
    match control.try_recv() {
      Ok(Control::Batch { ops, reply }) => {
        let (replies, preempted) = execute_batch(fd, table, ops, || wake.shutdown_requested());
        // Send the (executed + failed-tail) replies either way so the caller's
        // `batch()` never blocks on a truncated reply; then, if teardown preempted
        // mid-batch, exit as if the terminal `Shutdown` had been observed here.
        let _ = reply.send(replies);
        if preempted {
          return true;
        }
      }
      Ok(Control::Shutdown) => return true,
      Err(_) => return false,
    }
  }
}

/// Executes one control batch's ops in emission order, checking `shutdown` BEFORE
/// each op so a teardown mid-batch preempts. With no shutdown pending the whole
/// batch runs exactly as before (every arm gets its real reply, every disarm its
/// kernel removal). On a pending shutdown it stops immediately and fails every
/// UN-executed arm — the current op and the tail — with `Failed(Io)`, so the
/// returned replies stay index-aligned to the batch's `Arm` entries (the caller's
/// `batch()` reply contract) and the driver's pending grants resolve as failures
/// rather than hanging. Returns the replies and whether it was preempted.
///
/// Pure over the `shutdown` predicate — the only teardown-observing part — so the
/// preemption point is deterministically testable without racing a real teardown.
fn execute_batch(
  fd: &OwnedFd,
  table: &mut WdTable,
  ops: Vec<ControlOp>,
  mut shutdown: impl FnMut() -> bool,
) -> (Vec<ArmReply>, bool) {
  let mut replies = Vec::new();
  let mut ops = ops.into_iter();
  let preempted = loop {
    if shutdown() {
      break true;
    }
    let Some(op) = ops.next() else {
      break false;
    };
    match op {
      ControlOp::Arm(request) => replies.push(arm(fd, table, request)),
      ControlOp::Disarm(anchor) => disarm(fd, table, anchor),
    }
  };
  if preempted {
    // The shutdown check broke the loop BEFORE consuming the current op, so `ops`
    // still holds every un-executed op. Fail each remaining arm so the reply vec
    // covers all of the batch's `Arm` entries; disarms need no reply (and the fd is
    // about to close, so their kernel removal is moot).
    for op in ops {
      if matches!(op, ControlOp::Arm(_)) {
        replies.push(shutdown_arm_reply());
      }
    }
  }
  (replies, preempted)
}

/// The reply for an arm preempted (un-executed) by a mid-batch teardown: the same
/// `Failed(Io)` a dead reader answers, so the driver's pending grant resolves as a
/// failure rather than blocking on a truncated batch reply.
fn shutdown_arm_reply() -> ArmReply {
  ArmReply {
    outcome: WatchOutcome::Failed(WatchError::Io),
    anchor: None,
  }
}

/// Why [`drain_events`] returned. The reader re-parks and polls only on
/// [`Parked`](DrainExit::Parked); [`Shutdown`](DrainExit::Shutdown) and
/// [`Died`](DrainExit::Died) both exit the reader thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainExit {
  /// The instance drained to `EAGAIN` (or a zero-length read): re-park and poll.
  Parked,
  /// A `Shutdown` was observed between reads. Teardown takes PRIORITY over
  /// further event draining, so the reader stops now rather than after `EAGAIN`.
  Shutdown,
  /// The stream died; the terminal `Fatal` was already signaled.
  Died,
}

/// Reads the instance until `EAGAIN`, forwarding each buffer as one batch, while
/// servicing control BETWEEN reads so teardown and arm traffic never wait on an
/// `EAGAIN` that a sustained event stream keeps postponing (the reader-teardown
/// fairness contract — the `poll` loop's own control drain is reached only after
/// `EAGAIN`, which never comes under load). The interleaved [`drain_control`] runs
/// each pending batch inline — a mid-drain arm/disarm mutates the `wd` table, which
/// the NEXT decoded buffer then sees — and stops the drain immediately on a
/// `Shutdown`, so shutdown takes priority over further event draining. Control is
/// observed at the top of the loop, between one buffer's forward and the next read,
/// never mid-buffer, so the per-buffer loss barrier and attribution are unchanged.
/// Returns [`DrainExit::Died`] when the stream died (fatal already signaled),
/// [`DrainExit::Shutdown`] on a mid-drain shutdown, and [`DrainExit::Parked`] when
/// the instance drained clean.
fn drain_events(
  fd: &OwnedFd,
  buf: &mut [u8],
  table: &mut WdTable,
  control: &mpsc::Receiver<Control>,
  wake: &WakeState,
  shared: &ReaderShared,
) -> DrainExit {
  loop {
    if drain_control(fd, table, control, wake) {
      return DrainExit::Shutdown;
    }
    let n = match rustix::io::read(fd, &mut *buf) {
      Ok(n) => n,
      // `EAGAIN` and `EWOULDBLOCK` are the same errno on Linux.
      Err(Errno::AGAIN) => return DrainExit::Parked,
      Err(Errno::INTR) => continue,
      Err(err) => {
        signal_fatal(shared, SourceError::ReadFailed { source: err.into() });
        return DrainExit::Died;
      }
    };
    if n == 0 {
      return DrainExit::Parked;
    }
    let decoded = decode::decode_events(&buf[..n]);
    // Attribution still runs on a lossy buffer so the `wd` table stays accurate
    // (an `IN_IGNORED` in it must still consume its entry); its EVENTS are dropped
    // by the barrier inside `forward_attributed`.
    let attributed = attribute_events(decoded.events, table);
    forward_attributed(&shared.transport, attributed, decoded.lossy, |msg| {
      shared.queue.try_send(msg).is_ok()
    });
  }
}

/// Forwards one attributed buffer onto the queue via `send`, holding the loss
/// ordering barrier. Pure over the send closure — the only queue-touching part —
/// so the barrier is testable over a real [`AttributedBatch`] with a capturing
/// sender.
///
/// Loss is an ordering barrier. A lossy buffer (an `IN_Q_OVERFLOW` sentinel or a
/// truncated record) is a mix of records around an UNKNOWN loss window: the
/// sentinel names no position, so the records decoded AFTER it in the same buffer
/// are attributed through the `wd` table as usual — and a `wd` pins its inode
/// (object-stable), so it still names the right OBJECT — but the PATH the Monitor
/// reports comes from the anchor's RECORDED path, which a rename lost in the window
/// (`IN_MOVED_FROM`/`IN_MOVED_TO`) makes STALE. Forwarded in a Batch ahead of the
/// loss signal, that wrong path reaches the consumer BEFORE the covering rescan
/// corrects it — the same stale-attribution hole the fanotify reader closes. So
/// deliver NO events from a lossy buffer: the covering rescan (epoch bump +
/// re-enumerate + re-arm) already owes the consumer the full truth for everything
/// this buffer could have said, so delivering none of it is strictly honest, at the
/// cost of a few droppable pre-loss records the rescan re-covers. Signal ONLY the
/// loss — empty events + lossy makes [`transport::forward_batch`] enqueue the
/// `Overflow` alone, so nothing from the lossy buffer precedes it.
fn forward_attributed<S>(
  transport: &transport::TransportState,
  attributed: super::super::AttributedBatch,
  decode_lossy: bool,
  send: S,
) where
  S: FnMut(crate::os::SourceMessage) -> bool,
{
  let lost = decode_lossy || attributed.lost;
  let events = if lost {
    Vec::new()
  } else {
    attributed
      .events
      .into_iter()
      .map(crate::os::SourceEvent::Linux)
      .collect()
  };
  transport::forward_batch(transport, events, lost, send);
}

/// Executes one arm on the reader's own fd: open the target through the
/// parent anchor (object-correct — a parent rename cannot retarget the add),
/// confirm the opened object is the one the enumerate saw, install through
/// `/proc/self/fd/N`, and map `EEXIST` to the aliasing path.
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

  // Object-correctness: an absolute-path open (the common case, once the cold
  // enumerate consumed the parent anchor) can land on a DIFFERENT object if a
  // rename slipped in after the enumerate. `fstat` the opened `O_PATH` fd and
  // require the `(dev, ino)` the enumerate read — a mismatch means the name now
  // points at another object, so the arm is refused as `Gone` and the Monitor's
  // tested drop+rescan heals. An anchor-chain open is already object-pinned
  // through `/proc/self/fd`, but confirming it too costs one `fstat` and closes
  // the window uniformly.
  if !object_matches(&anchor, request.expected) {
    return ArmReply {
      outcome: WatchOutcome::Failed(WatchError::Gone),
      anchor: None,
    };
  }

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

/// Whether the opened anchor is the object the enumerate saw. An `expected` of
/// `None` is unverified (identity was unavailable at enumerate time) and passes.
/// An `fstat` failure is treated as a mismatch: the object the arm would install
/// on cannot be confirmed, so refusing (→ `Gone` → rescan) is the honest choice.
/// `fstat` on an `O_PATH` fd reads the pinned object's `(dev, ino)` — exactly the
/// object the watch would attach to.
fn object_matches(anchor: &OwnedFd, expected: Option<ExpectedObject>) -> bool {
  let Some(expected) = expected else {
    return true;
  };
  match rustix::fs::fstat(anchor) {
    Ok(stat) => stat.st_dev == expected.dev && stat.st_ino == expected.ino.get(),
    Err(_) => false,
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

#[cfg(test)]
mod tests;
