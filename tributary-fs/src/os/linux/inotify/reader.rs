//! The per-root reader thread: owns the inotify fd AND the `wd` table, so
//! decode-attribution and arm/disarm mutations are serialized by
//! construction — control requests travel over a channel and are executed
//! between reads, never concurrently with them.
//!
//! Wakeup: the thread blocks in `poll` over the inotify fd and the read end
//! of a private pipe; control senders (and shutdown) write one byte to the
//! pipe after queuing, so the reader observes every request promptly without
//! busy-waiting.

use std::{
  io,
  os::fd::{AsRawFd, FromRawFd, OwnedFd},
  panic::{AssertUnwindSafe, catch_unwind},
  sync::{Arc, mpsc},
  thread::JoinHandle,
};

use tributary_proto::{WatchError, WatchId};

use super::{
  super::{
    super::{SourceError, transport},
    AnchorRequest, ArmReply, WatchOutcome, attribute_events,
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

/// One control request, executed by the reader between reads.
pub(crate) enum Control {
  AddWatch {
    request: AnchorRequest,
    reply: mpsc::SyncSender<ArmReply>,
  },
  RemoveWatch {
    anchor: WatchId,
    reply: mpsc::SyncSender<()>,
  },
  Shutdown,
}

/// Creates the per-root inotify instance.
pub(crate) fn create_instance() -> Result<OwnedFd, SourceError> {
  // SAFETY: plain syscall; the returned fd is owned exclusively here.
  let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
  if fd < 0 {
    let err = io::Error::last_os_error();
    return Err(match err.raw_os_error() {
      // EMFILE is both the per-process fd ceiling and the per-uid
      // `fs.inotify.max_user_instances` ceiling — the typed spawn error the
      // per-root-instance topology trades for its overflow isolation.
      Some(libc::EMFILE) => SourceError::InstanceLimit,
      _ => SourceError::CreateFailed,
    });
  }
  // SAFETY: fd is a fresh, owned descriptor.
  Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Creates the wakeup pipe: `(write, read)` ends.
pub(crate) fn wake_pipe() -> Result<(OwnedFd, OwnedFd), SourceError> {
  let mut fds = [0 as libc::c_int; 2];
  // SAFETY: fds is a valid two-slot buffer; pipe2 fills it on success.
  if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
    return Err(SourceError::CreateFailed);
  }
  // SAFETY: both fds are fresh, owned descriptors.
  Ok(unsafe { (OwnedFd::from_raw_fd(fds[1]), OwnedFd::from_raw_fd(fds[0])) })
}

/// Wakes the reader (one byte on the pipe; a full pipe already guarantees a
/// pending wake).
pub(crate) fn wake(pipe_write: &OwnedFd) {
  // SAFETY: writes one byte from a valid buffer to an owned fd.
  let _ = unsafe { libc::write(pipe_write.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
}

/// Starts the reader thread. The fd, the wake pipe's read end, and the `wd`
/// table live and die with it.
pub(crate) fn start(
  fd: OwnedFd,
  wake_rx: OwnedFd,
  control: mpsc::Receiver<Control>,
  shared: Arc<ReaderShared>,
) -> JoinHandle<()> {
  std::thread::Builder::new()
    .name("tributary-fs.inotify".into())
    .spawn(move || {
      let outcome = catch_unwind(AssertUnwindSafe(|| {
        run(&fd, &wake_rx, &control, &shared);
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

fn run(fd: &OwnedFd, wake_rx: &OwnedFd, control: &mpsc::Receiver<Control>, shared: &ReaderShared) {
  let mut table = WdTable::new();
  // Sized for a dense read: watchman's batch scale (16k events of header
  // size) is far past what one wake needs; 64 KiB covers the deepest names.
  let mut buf = vec![0u8; 64 * 1024];
  loop {
    let mut fds = [
      libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
      },
      libc::pollfd {
        fd: wake_rx.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
      },
    ];
    // SAFETY: fds is a valid two-entry pollfd array.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
    if rc < 0 {
      let err = io::Error::last_os_error();
      if err.kind() == io::ErrorKind::Interrupted {
        continue;
      }
      signal_fatal(shared, SourceError::ReadFailed { source: err });
      return;
    }

    if fds[1].revents & libc::POLLIN != 0 {
      drain_pipe(wake_rx);
      loop {
        match control.try_recv() {
          Ok(Control::AddWatch { request, reply }) => {
            let _ = reply.send(arm(fd, &mut table, request));
          }
          Ok(Control::RemoveWatch { anchor, reply }) => {
            disarm(fd, &mut table, anchor);
            let _ = reply.send(());
          }
          Ok(Control::Shutdown) => return,
          Err(_) => break,
        }
      }
    }

    if fds[0].revents & libc::POLLIN != 0 && !drain_events(fd, &mut buf, &mut table, shared) {
      return;
    }
  }
}

/// Reads the instance until `EAGAIN`, forwarding each buffer as one batch.
/// Returns `false` when the stream died (fatal already signaled).
fn drain_events(fd: &OwnedFd, buf: &mut [u8], table: &mut WdTable, shared: &ReaderShared) -> bool {
  loop {
    // SAFETY: reads into an exclusively-borrowed buffer of the given length.
    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
      let err = io::Error::last_os_error();
      return match err.kind() {
        io::ErrorKind::WouldBlock => true,
        io::ErrorKind::Interrupted => continue,
        _ => {
          signal_fatal(shared, SourceError::ReadFailed { source: err });
          false
        }
      };
    }
    if n == 0 {
      return true;
    }
    let decoded = decode::decode_events(&buf[..n as usize]);
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

fn drain_pipe(wake_rx: &OwnedFd) {
  let mut sink = [0u8; 64];
  loop {
    // SAFETY: reads into a local buffer from the owned pipe fd.
    let n = unsafe { libc::read(wake_rx.as_raw_fd(), sink.as_mut_ptr().cast(), sink.len()) };
    if n <= 0 {
      return;
    }
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
        outcome: WatchOutcome::Failed(errno_to_watch_error(&err)),
        anchor: None,
      };
    }
  };

  let proc_path = format!("/proc/self/fd/{}\0", anchor.as_raw_fd());
  // SAFETY: proc_path is NUL-terminated; the fd is the reader's own instance.
  let wd =
    unsafe { libc::inotify_add_watch(fd.as_raw_fd(), proc_path.as_ptr().cast(), WATCH_MASK) };
  if wd >= 0 {
    table.register(wd, request.watch);
    return ArmReply {
      outcome: WatchOutcome::Installed(wd),
      anchor: Some(anchor),
    };
  }

  let err = io::Error::last_os_error();
  if err.raw_os_error() == Some(libc::EEXIST) {
    // The inode is already watched. `IN_MASK_CREATE` refuses to say WHICH wd,
    // so re-add without it: the mask is identical, making the update a no-op
    // that returns the existing wd for the alias registration.
    // SAFETY: same arguments as above minus the create guard.
    let wd = unsafe {
      libc::inotify_add_watch(
        fd.as_raw_fd(),
        proc_path.as_ptr().cast(),
        WATCH_MASK & !decode::IN_MASK_CREATE,
      )
    };
    if wd >= 0 {
      table.alias(wd, request.watch);
      return ArmReply {
        outcome: WatchOutcome::Aliased(wd),
        anchor: Some(anchor),
      };
    }
  }
  ArmReply {
    outcome: WatchOutcome::Failed(errno_to_watch_error(&io::Error::last_os_error())),
    anchor: None,
  }
}

/// Opens the arm target as a transient `O_PATH` anchor.
fn open_anchor(request: &AnchorRequest) -> io::Result<OwnedFd> {
  use std::os::unix::ffi::OsStrExt;
  let name = std::ffi::CString::new(request.name.as_bytes())
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains a NUL byte"))?;
  let dirfd = request
    .parent
    .as_ref()
    .map(|fd| fd.as_raw_fd())
    .unwrap_or(libc::AT_FDCWD);
  let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC;
  // SAFETY: name is NUL-terminated; dirfd is a live anchor (or AT_FDCWD).
  let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags) };
  if fd < 0 {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: fd is a fresh, owned descriptor.
  Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Removes `anchor` from attribution, issuing the kernel removal when the
/// last alias drains. `rm_watch` errors are ignored deliberately: the kernel
/// auto-removes a watch whose object was deleted (its `IN_IGNORED` is already
/// queued), making `EINVAL` here a benign race, and the table entry drains
/// through that `IN_IGNORED` either way.
fn disarm(fd: &OwnedFd, table: &mut WdTable, anchor: WatchId) {
  if let DrainDecision::RemoveWd(wd) = table.begin_drain(anchor) {
    // SAFETY: plain syscall on the reader's own fd.
    let _ = unsafe { libc::inotify_rm_watch(fd.as_raw_fd(), wd) };
  }
}

/// Maps an arm-time errno to the Monitor's watch-result taxonomy.
fn errno_to_watch_error(err: &io::Error) -> WatchError {
  match err.raw_os_error() {
    Some(libc::ENOENT) => WatchError::NotFound,
    // The slot's object stopped being a directory between the caller's
    // enumerate and this arm — the directory the Monitor meant is gone.
    Some(libc::ENOTDIR) => WatchError::Gone,
    Some(libc::EACCES) | Some(libc::EPERM) => WatchError::Permission,
    // fs.inotify.max_user_watches exhausted.
    Some(libc::ENOSPC) => WatchError::NoSpace,
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
