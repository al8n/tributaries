//! The per-root fanotify reader thread: owns the fanotify fd AND the per-root
//! [`FidMap`], so decode, admission, and the map's self-maintenance are
//! serialized by construction — there is no arm traffic (the mark is
//! kernel-recursive), only reads and a shutdown wake.
//!
//! Wakeup mirrors the inotify reader: the thread blocks in `poll` over the
//! fanotify fd and a private pipe; shutdown writes one byte to the pipe. A
//! `FAN_Q_OVERFLOW` marker (or a truncated/malformed record) degrades to the
//! ordered loss signal; a read error or a panic degrades to the terminal
//! `Fatal` exactly once, then the thread exits.

use std::{
  io,
  os::fd::{AsRawFd, FromRawFd, OwnedFd},
  panic::{AssertUnwindSafe, catch_unwind},
  sync::{Arc, mpsc},
  thread::JoinHandle,
};

use super::{
  super::super::{SourceError, transport},
  Admission, admit,
  fid::decode_events,
  map::FidMap,
};

/// What the reader shares with the handle side: the ordered queue and the
/// transport budget/dedups.
pub(crate) struct ReaderShared {
  pub(crate) queue: async_channel::Sender<crate::os::SourceMessage>,
  pub(crate) transport: transport::TransportState,
}

/// One control request. fanotify has no arm traffic, so shutdown is the only
/// message.
pub(crate) enum Control {
  Shutdown,
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

/// Starts the reader thread. The fd, the wake pipe's read end, and the seeded
/// `FidMap` live and die with it.
pub(crate) fn start(
  fd: OwnedFd,
  wake_rx: OwnedFd,
  control: mpsc::Receiver<Control>,
  map: FidMap,
  shared: Arc<ReaderShared>,
) -> JoinHandle<()> {
  std::thread::Builder::new()
    .name("tributary-fs.fanotify".into())
    .spawn(move || {
      let mut map = map;
      let outcome = catch_unwind(AssertUnwindSafe(|| {
        run(&fd, &wake_rx, &control, &mut map, &shared);
      }));
      if outcome.is_err() {
        signal_fatal(&shared, SourceError::CallbackPanic);
      }
    })
    .expect("spawning the fanotify reader thread")
}

fn signal_fatal(shared: &ReaderShared, err: SourceError) {
  transport::signal_fatal_once(&shared.transport, err, |msg| {
    shared.queue.try_send(msg).is_ok()
  });
}

fn run(
  fd: &OwnedFd,
  wake_rx: &OwnedFd,
  control: &mpsc::Receiver<Control>,
  map: &mut FidMap,
  shared: &ReaderShared,
) {
  // fanotify events are large (a metadata header plus variable-length FID
  // records with names); 64 KiB holds a dense read of them.
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
      if matches!(control.try_recv(), Ok(Control::Shutdown)) {
        return;
      }
    }

    if fds[0].revents & libc::POLLIN != 0 && !drain_events(fd, &mut buf, map, shared) {
      return;
    }
  }
}

/// Reads the instance until `EAGAIN`, admitting and forwarding each buffer as
/// one batch. Returns `false` when the stream died (fatal already signaled).
fn drain_events(fd: &OwnedFd, buf: &mut [u8], map: &mut FidMap, shared: &ReaderShared) -> bool {
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
    let decoded = decode_events(&buf[..n as usize]);
    // Admission is the superblock-firehose filter: an event whose directory
    // FID is unknown is provably outside the root and dropped without loss.
    let mut events = Vec::with_capacity(decoded.events.len());
    for event in &decoded.events {
      if let Admission::Admit(admitted) = admit(map, event) {
        events.push(crate::os::SourceEvent::Linux(
          crate::os::linux::RawLinuxEvent::Fanotify(admitted),
        ));
      }
    }
    transport::forward_batch(&shared.transport, events, decoded.lossy, |msg| {
      shared.queue.try_send(msg).is_ok()
    });
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
