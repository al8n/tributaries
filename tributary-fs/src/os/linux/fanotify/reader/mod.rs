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
      match admit(map, event) {
        Admission::Admit(admitted) => events.push(fanotify_event(admitted)),
        // A directory moved IN from outside the root: walk its pre-existing
        // descendants into the map BEFORE forwarding the move, so any later event
        // in this same batch under those descendants already admits.
        //
        // The walk's starting path is resolved through the map (`seed_moved_in_
        // subtree` → `pending_walk_target`), NOT captured at admission — an
        // in-root rename that this reader has already processed would have
        // re-parented the pending node, and the walk must follow it.
        //
        // Walk-cancellation soundness (the batch-ordering argument): this reader
        // is single-threaded and processes the batch IN ORDER, and the map lookup
        // gates the walk. So at walk time the map reflects EXACTLY the events up to
        // and including this one:
        //  - if a rename-OUT / delete of the moved dir had been processed, it would
        //    have `forget`-ten (and pruned) the node — `pending_walk_target` returns
        //    `None`, the walk is CANCELLED (a departed subtree owes nothing);
        //  - if an in-root rename of it had been processed, the node is re-parented
        //    and STILL pending (the flag is preserved across a re-parent), so the
        //    walk rebases to the new path;
        //  - otherwise the node is present and pending at its move-in destination.
        // Therefore a `NotFound` at the resolved path means NO removal was processed
        // by this reader, yet the directory is gone on disk (a later event in this
        // same batch — the burst — already hit disk but not the reader). That is a
        // genuine coverage hole, so the walk classifies it `Incomplete` and, after
        // the single retry, escalates to the terminal `Fatal` (blind → fatal) —
        // NOT a benign empty walk. Auto's next `watch()` then lands on inotify,
        // which re-enumerates; a silent blind subtree is never left behind.
        Admission::AdmitAndSeed { event, moved_fid } => {
          if matches!(
            seed_moved_in_subtree(map, &moved_fid, |subtree, subtree_fid| {
              reseed.walk_subtree(subtree, subtree_fid)
            }),
            SeedOutcome::Blind
          ) {
            signal_fatal(
              shared,
              SourceError::ReadFailed {
                source: moved_in_blind_error(),
              },
            );
            return false;
          }
          events.push(fanotify_event(event));
        }
        Admission::Drop => {}
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

/// Wraps one admitted event for the driver queue.
fn fanotify_event(admitted: super::AdmittedEvent) -> crate::os::SourceEvent {
  crate::os::SourceEvent::Linux(crate::os::linux::RawLinuxEvent::Fanotify(admitted))
}

/// Whether walking a moved-in subtree into the map succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedOutcome {
  /// The subtree walk succeeded (first try or the single retry, its descendant
  /// directories inserted) — OR the walk was CANCELLED because the moved dir was
  /// forgotten/orphaned before it ran, or an intervening event already cleared its
  /// pending flag (nothing owed). Both leave the map complete.
  Seeded,
  /// The walk failed twice: the moved-in subtree is only partially mapped, so the
  /// source is blind under it. The caller escalates to the terminal `Fatal`.
  Blind,
}

/// Walks a moved-in directory's pre-existing descendants into `map`, resolving
/// the directory's CURRENT path through the map before each attempt (an in-root
/// rename in the same batch may have re-parented it since admission) and mirroring
/// [`reseed_map`]'s retry-then-escalate policy: the walk runs once,
/// retries once on failure, and a second failure concedes [`SeedOutcome::Blind`].
///
/// The map lookup gates the walk:
///
/// - the moved dir is GONE (forgotten/orphaned by an intervening event before the
///   walk ran): the walk is CANCELLED — a departed subtree owes nothing —
///   returning [`SeedOutcome::Seeded`];
/// - its `pending_walk` flag is already CLEAR (an intervening event completed the
///   obligation): likewise cancelled;
/// - otherwise walk from the resolved current path. A `NotFound` there is
///   `Incomplete` (the node is still in-map and pending, so no rename-out was
///   processed — a missing dir is a genuine hole, not a race), which folds to the
///   retry-then-blind policy.
///
/// On a successful walk the entries are ADDED (the moved dir itself is already
/// learned) and its pending flag is cleared, keeping the completeness invariant at
/// the boundary-move site. The `walk` closure is the only fd-touching part, so the
/// resolve/gate/retry policy is testable over a real map with a stub walk.
fn seed_moved_in_subtree<W>(
  map: &mut FidMap,
  moved_fid: &super::fid::Fid,
  mut walk: W,
) -> SeedOutcome
where
  W: FnMut(&std::path::Path, &super::fid::Fid) -> std::io::Result<Vec<SeedEntry>>,
{
  for _ in 0..2 {
    // Resolve the moved dir's CURRENT path and pending state each attempt: an
    // intervening event may have re-parented, cleared, or removed it.
    let Some((subtree, pending)) = map.pending_walk_target(moved_fid) else {
      // Forgotten/orphaned before the walk ran: a departed subtree owes nothing.
      return SeedOutcome::Seeded;
    };
    if !pending {
      // An intervening event already discharged the walk obligation.
      return SeedOutcome::Seeded;
    }
    if let Ok(entries) = walk(&subtree, moved_fid) {
      map.seed(entries);
      map.clear_pending_walk(moved_fid);
      return SeedOutcome::Seeded;
    }
  }
  SeedOutcome::Blind
}

/// The error a blinding moved-in subtree walk escalates through the terminal
/// `Fatal`: a foreign populated directory arrived but its descendants could not
/// be mapped, so events under them would drop as outside-root forever — the
/// silent-loss shape, refused honestly.
fn moved_in_blind_error() -> std::io::Error {
  std::io::Error::other(
    "a directory moved into the watched root could not be walked; its subtree is blind",
  )
}

#[cfg(test)]
mod tests;
