//! The per-root fanotify reader thread: owns the fanotify fd AND the per-root
//! [`FidMap`], so decode, admission, and the map's self-maintenance are
//! serialized by construction — there is no arm traffic (the mark is
//! kernel-recursive), only reads and a shutdown wake.
//!
//! Wakeup mirrors the inotify reader: the thread blocks in `poll` over the
//! fanotify fd and a per-root [`WakeState`] eventfd; shutdown increments the
//! eventfd. Because the ONLY sender is shutdown (and it wakes unconditionally),
//! no wake elision applies here, but the park/guard/drain shape is shared with
//! the inotify reader for one wakeup story. A `FAN_Q_OVERFLOW` marker (or a
//! truncated/malformed record) degrades to the ordered loss signal; a read
//! error or a panic degrades to the terminal `Fatal` exactly once, then the
//! thread exits.

use std::{
  os::fd::OwnedFd,
  panic::{AssertUnwindSafe, catch_unwind},
  sync::{Arc, mpsc},
  thread::JoinHandle,
};

use rustix::{
  event::{PollFd, PollFlags, poll},
  io::Errno,
};

use super::{
  super::{
    super::{SourceError, transport},
    wake::WakeState,
  },
  Admission, admit,
  fid::decode_events,
  map::{FidMap, SeedEntry},
  source::ReseedContext,
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

/// Starts the reader thread. The fd, the wake eventfd, the seeded `FidMap`, and
/// the reseed context live and die with it. A spawn failure (thread or memory
/// exhaustion) is a typed [`SourceError::StartFailed`] on the never-live path —
/// no events, the probed fd closed as the returned closure drops.
pub(crate) fn start(
  fd: OwnedFd,
  wake: Arc<WakeState>,
  control: mpsc::Receiver<Control>,
  map: FidMap,
  reseed: ReseedContext,
  shared: Arc<ReaderShared>,
) -> Result<JoinHandle<()>, SourceError> {
  std::thread::Builder::new()
    .name("tributary-fs.fanotify".into())
    .spawn(move || {
      let mut map = map;
      let outcome = catch_unwind(AssertUnwindSafe(|| {
        run(&fd, &wake, &control, &mut map, &reseed, &shared);
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

fn run(
  fd: &OwnedFd,
  wake: &WakeState,
  control: &mpsc::Receiver<Control>,
  map: &mut FidMap,
  reseed: &ReseedContext,
  shared: &ReaderShared,
) {
  // fanotify events are large (a metadata header plus variable-length FID
  // records with names); 64 KiB holds a dense read of them.
  let mut buf = vec![0u8; 64 * 1024];
  loop {
    // Announce the intent to block, then re-check for shutdown before polling
    // (the lost-wakeup guard — see `WakeState`; a shutdown enqueued before the
    // fence is visible here).
    wake.arm_park();
    if matches!(control.try_recv(), Ok(Control::Shutdown)) {
      return;
    }
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
      if matches!(control.try_recv(), Ok(Control::Shutdown)) {
        return;
      }
    }
    if source_ready && !drain_events(fd, &mut buf, map, reseed, shared) {
      return;
    }
  }
}

/// Reads the instance until `EAGAIN`, admitting and forwarding each buffer as
/// one batch. Returns `false` when the stream died (fatal already signaled).
fn drain_events(
  fd: &OwnedFd,
  buf: &mut [u8],
  map: &mut FidMap,
  reseed: &ReseedContext,
  shared: &ReaderShared,
) -> bool {
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
    let decoded = decode_events(&buf[..n]);
    // Admission is the superblock-firehose filter: an event whose directory FID
    // is unknown is provably outside the root and dropped without loss. That
    // silent drop is BY DESIGN — the filter working — and is distinct from the
    // staleness a loss induces, which the reseed below repairs.
    let mut events = Vec::with_capacity(decoded.events.len());
    for event in &decoded.events {
      if let Admission::Admit(admitted) = admit(map, event) {
        events.push(crate::os::SourceEvent::Linux(
          crate::os::linux::RawLinuxEvent::Fanotify(admitted),
        ));
      }
    }
    // A lossy batch (a `FAN_Q_OVERFLOW` marker, or a truncated/one-sided
    // record) means create/rename updates were lost — the map is now blind to
    // directories born in the loss window, and future events under them would
    // drop as outside-root FOREVER. Rebuild the map from a fresh walk BEFORE
    // signaling loss downstream, so the reseeded sight is live by the time the
    // consumer's rescan re-enumerates. The walk is synchronous between reads
    // (overflow is rare, the walk is bounded by the root's directory count).
    //
    // A walk that fails leaves the map permanently blind — a stale-but-running
    // source is the silent-loss shape this whole stack exists to prevent — so
    // the failure is escalated honestly, not swallowed.
    if decoded.lossy && matches!(reseed_map(map, || reseed.walk()), ReseedOutcome::Blind) {
      signal_fatal(
        shared,
        SourceError::ReadFailed {
          source: reseed_blind_error(),
        },
      );
      return false;
    }
    transport::forward_batch(&shared.transport, events, decoded.lossy, |msg| {
      shared.queue.try_send(msg).is_ok()
    });
  }
}

/// Whether a loss-triggered reseed restored the map's sight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReseedOutcome {
  /// The walk succeeded (on the first try or the single retry) and the map was
  /// rebuilt.
  Reseeded,
  /// The walk failed twice: the map is stale and the source is blind. The caller
  /// escalates to the terminal `Fatal` rather than run on permanently.
  Blind,
}

/// Rebuilds `map` from a fresh walk after a loss, retrying ONCE on failure
/// before conceding blindness. Pure over the walk closure so the
/// retry-then-escalate policy is testable without a live fd: a walk that fails
/// twice returns [`ReseedOutcome::Blind`]; any success reseeds and returns
/// [`ReseedOutcome::Reseeded`]. The immediate retry absorbs a transient failure
/// (a directory momentarily unreadable mid-walk) without killing the scope.
fn reseed_map<W>(map: &mut FidMap, mut walk: W) -> ReseedOutcome
where
  W: FnMut() -> std::io::Result<Vec<SeedEntry>>,
{
  for _ in 0..2 {
    if let Ok(entries) = walk() {
      map.reseed(entries);
      return ReseedOutcome::Reseeded;
    }
  }
  ReseedOutcome::Blind
}

/// The error a blinding reseed failure escalates through the terminal `Fatal`.
fn reseed_blind_error() -> std::io::Error {
  std::io::Error::other(
    "the fanotify FID map could not be reseeded after a loss; the source is blind",
  )
}

#[cfg(test)]
mod tests;
