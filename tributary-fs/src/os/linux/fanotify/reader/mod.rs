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
//!
//! # Teardown-fairness invariant
//!
//! Same charter as the inotify reader (no unbounded op loop defers shutdown), but
//! the long-op sites differ — this reader has NO control batch (the mark is
//! kernel-recursive, so shutdown is the only control message):
//!
//! | Long-op site                          | Verdict                             |
//! |---------------------------------------|-------------------------------------|
//! | Event drain (read → `EAGAIN`)         | preemptible BETWEEN reads           |
//! | Reseed walk (`reseed_map`)            | bounded, must complete or blind→fatal |
//! | Move-in subtree walk (`seed_moved_in_subtree`) | bounded, must complete or blind→fatal |
//!
//! The two walks are the bounded-must-complete case: each rebuilds (or extends) the
//! FID map from a fresh directory enumerate, and the map swap is only sound once the
//! walk's full inventory is in hand — interrupting one mid-flight would leave a
//! half-built map, i.e. a silently-blind subtree, the exact class the whole stack
//! prevents. So a shutdown landing mid-walk WAITS for the walk (checked between
//! reads, after the current buffer's walk has finished): the walk is bounded by the
//! root's directory count and either completes or escalates blind → fatal. Unlike
//! the inotify batch, a walk's work cannot be failed-reply'd away — there is no
//! per-op grant to resolve, only a map that is whole or blind. This is why the
//! inotify intra-batch preemption has no analog here.

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
    super::{BackendStatsShared, SourceError, transport},
    wake::WakeState,
  },
  Admission, MemoBatch, classify,
  fid::decode_events,
  map::{FidMap, SeedEntry},
  source::ReseedContext,
};

/// What the reader shares with the handle side: the ordered queue, the
/// transport budget/dedups, and the live stats the operator polls.
pub(crate) struct ReaderShared {
  pub(crate) queue: async_channel::Sender<crate::os::SourceMessage>,
  pub(crate) transport: transport::TransportState,
  /// The atomic stats the reader writes (map size, walk timings, memo tallies)
  /// and [`Watcher::backend_stats`](crate::Watcher::backend_stats) snapshots.
  pub(crate) stats: std::sync::Arc<BackendStatsShared>,
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
  // Publish the seeded map's footprint before the reader blocks, so a poll
  // before the first event still sees the true directory count.
  let seeded = map.stats();
  shared
    .stats
    .set_map(seeded.directories, seeded.memo_generation);
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
    if source_ready {
      match drain_events(fd, &mut buf, map, reseed, control, shared) {
        DrainExit::Parked => {}
        DrainExit::Shutdown | DrainExit::Died => return,
      }
    }
  }
}

/// Why [`drain_events`] returned. The reader re-parks and polls only on
/// [`Parked`](Self::Parked); [`Shutdown`](Self::Shutdown) and
/// [`Died`](Self::Died) both exit the reader thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainExit {
  /// The instance drained to `EAGAIN` (or a zero-length read): re-park and poll.
  Parked,
  /// A `Shutdown` was observed between reads. Teardown takes PRIORITY over
  /// further draining, so the reader stops now rather than after `EAGAIN`.
  Shutdown,
  /// The stream died; the terminal `Fatal` was already signaled.
  Died,
}

/// Reads the instance until `EAGAIN`, admitting and forwarding each buffer as one
/// batch, while observing a pending `Shutdown` BETWEEN reads so teardown never
/// waits on an `EAGAIN` that a sustained event stream keeps postponing (the
/// reader-teardown fairness contract — the `poll` loop's own shutdown check is
/// reached only after `EAGAIN`, which never comes under load). The check sits at
/// the top of the loop, before the next read/decode, so a reseed or subtree walk
/// from the PREVIOUS buffer has fully completed before it runs: a shutdown that
/// lands mid-reseed quiesces cleanly at the next read boundary rather than
/// interrupting the walk. fanotify has no arm traffic, so shutdown is the only
/// control message. Returns [`DrainExit::Died`] when the stream died (fatal
/// already signaled), [`DrainExit::Shutdown`] on a mid-drain shutdown, and
/// [`DrainExit::Parked`] when the instance drained clean.
fn drain_events(
  fd: &OwnedFd,
  buf: &mut [u8],
  map: &mut FidMap,
  reseed: &ReseedContext,
  control: &mpsc::Receiver<Control>,
  shared: &ReaderShared,
) -> DrainExit {
  loop {
    if matches!(control.try_recv(), Ok(Control::Shutdown)) {
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
    let decoded = decode_events(&buf[..n]);
    if !process_decoded(
      decoded,
      map,
      &shared.stats,
      &shared.transport,
      || reseed.walk(),
      |subtree, subtree_fid, budget| reseed.walk_subtree(subtree, subtree_fid, budget),
      |msg| shared.queue.try_send(msg).is_ok(),
    ) {
      return DrainExit::Died;
    }
  }
}

/// Processes one decoded buffer: [`classify`]s each event into its admission
/// action, applies the resulting map self-maintenance, and forwards the admitted
/// events onto the queue via `send` — or routes a loss through the barrier.
/// Returns `false` when the stream died (fatal already signaled), mirroring
/// [`drain_events`]'s contract. Pure over the two walk closures and the send
/// closure — the ONLY fd-touching or queue-touching parts — so the barrier and
/// the classify/reseed/escalate policy are testable over a real [`FidMap`] with
/// stub walks and a capturing sender, exactly as [`reseed_map`] and
/// [`seed_moved_in_subtree`] already are.
///
/// Loss reaches the barrier two ways, both funneling to the SAME per-buffer drop:
/// a WIRE-level loss (`decoded.lossy` — a `FAN_Q_OVERFLOW` marker, a
/// truncated/malformed record, a structurally unpairable `FAN_RENAME`), OR a
/// CLASSIFIED [`Admission::Lossy`] — an event whose selected action lacks a
/// required field (a named dirent with no name; a directory create/delete/rename
/// with no child `target_fid`). Either way the whole buffer is a barrier, so no
/// ordinary event is delivered from it (see the barrier rationale below).
///
/// `reseed_walk` rebuilds the whole map from the root (a loss); `subtree_walk`
/// maps one moved-in directory's descendants (its resolved current path, its FID,
/// and the remaining directory budget). Both mirror `ReseedContext`'s methods.
fn process_decoded<R, S, Q>(
  decoded: super::fid::DecodeOutcome,
  map: &mut FidMap,
  stats: &BackendStatsShared,
  transport: &transport::TransportState,
  reseed_walk: R,
  mut subtree_walk: S,
  mut send: Q,
) -> bool
where
  R: FnMut() -> std::io::Result<Vec<SeedEntry>>,
  S: FnMut(&std::path::Path, &super::fid::Fid, Option<usize>) -> std::io::Result<Vec<SeedEntry>>,
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  // The batch memo (design §4.9) caches admitted directory resolutions FOR THIS
  // buffer only: the reader is single-threaded and the map is queue-ordered, so a
  // cached path is sound until the next map mutation, which bumps the map's
  // generation and thus invalidates the memo. A fresh memo per buffer clears it at
  // batch end by construction.
  let mut memo = MemoBatch::new();
  let mut events = Vec::new();
  // A wire-level loss skips classification entirely (its events are already
  // suspect); a classified `Lossy` sets this mid-loop and breaks. Both take the
  // barrier below.
  let mut lossy = decoded.lossy;
  if !lossy {
    events.reserve(decoded.events.len());
    for event in &decoded.events {
      match classify(map, event, &mut memo) {
        // A forwarded event whose admission mutated no growing node, OR a root
        // self-event routed to the death lifecycle. A `LearnDir` may have grown the
        // map past its cap (design §4.9): a capped map that keeps eventing while
        // silently refusing to learn is the silent-loss shape, so an over-cap map is
        // the terminal `Fatal`, not run on blind. (The check is cheap and harmless
        // on the non-growing arms.)
        Admission::Forward(event)
        | Admission::LearnDir(event)
        | Admission::ForgetDir(event)
        | Admission::RootDeath(event) => {
          if map.over_capacity() {
            signal_fatal_cap(transport, &mut send);
            return false;
          }
          events.push(fanotify_event(event));
        }
        // A `FAN_RENAME`, its map self-maintenance already applied. `seed` is the
        // moved directory's FID when it moved IN from outside the root and its
        // pre-existing descendants must be walked into the map BEFORE forwarding, so
        // any later event in this same batch under those descendants already admits.
        //
        // The walk's starting path is resolved through the map (`seed_moved_in_
        // subtree` → `pending_walk_target`), NOT captured at admission — an in-root
        // rename this reader already processed would have re-parented the pending
        // node, and the walk must follow it.
        //
        // Walk-cancellation soundness (the batch-ordering argument): this reader is
        // single-threaded and processes the batch IN ORDER, and the map lookup gates
        // the walk. So at walk time the map reflects EXACTLY the events up to and
        // including this one:
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
        // the single retry, escalates to the terminal `Fatal` (blind → fatal) — NOT
        // a benign empty walk. Auto's next `watch()` then lands on inotify, which
        // re-enumerates; a silent blind subtree is never left behind.
        Admission::Rename { event, seed } => {
          // The re-parent / move-in learn may have grown the map past its cap; check
          // it FIRST — before any walk — so an over-cap learn cannot even start one.
          if map.over_capacity() {
            signal_fatal_cap(transport, &mut send);
            return false;
          }
          if let Some(moved_fid) = seed {
            // Fence the walk to the REMAINING budget, not the full cap: the map is
            // near-cap (the top just landed), and passing the full cap as the
            // descend budget would let a populated move-in allocate up to a whole
            // extra `cap` of descendants before the additive check below fired. `cap
            // - len` is the room actually left; the walk aborts the moment it would
            // exceed it, so the map never grows past the cap mid-walk. Uncapped
            // stays `None`.
            let budget = map.remaining_capacity();
            let started = std::time::Instant::now();
            let outcome = seed_moved_in_subtree(map, &moved_fid, |subtree, subtree_fid| {
              subtree_walk(subtree, subtree_fid, budget)
            });
            stats.record_walk(walk_micros(started));
            if matches!(outcome, SeedOutcome::Blind) {
              transport::signal_fatal_once(
                transport,
                SourceError::ReadFailed {
                  source: moved_in_blind_error(),
                },
                &mut send,
              );
              return false;
            }
            // The belt: the walk fenced its own production to the remaining budget,
            // so this only fires on the exact cap boundary — the same terminal a
            // live create over the cap hits. A move-in that cannot fit is the cap
            // doing its job; fatal is the honest terminal.
            if map.over_capacity() {
              signal_fatal_cap(transport, &mut send);
              return false;
            }
          }
          events.push(fanotify_event(event));
        }
        // Provably outside the watched root (the firehose filter): a clean drop, BY
        // DESIGN — distinct from the staleness a loss induces, which the reseed
        // below repairs.
        Admission::ForeignDrop => {}
        // A classified loss: the selected action lacks a required field. Take the
        // per-buffer barrier — drop the whole buffer (any events pushed so far
        // included), reseed, and signal only `Overflow`.
        Admission::Lossy => {
          lossy = true;
          break;
        }
      }
    }
  }

  // Loss is an ordering barrier. A lossy buffer is a mix of events around an
  // UNKNOWN loss window: the marker/missing field names no position, so events
  // around it would be admitted against a map the window may have staled. If the
  // window dropped a directory rename/move-out, a co-batched event under that FID
  // resolves through STALE parent links — a WRONG in-root path — and, forwarded in
  // a Batch ahead of the loss signal, the consumer sees it BEFORE the covering
  // rescan corrects it. So deliver NO ordinary events from a lossy buffer: drop the
  // whole decode. The covering rescan already owes the consumer the full truth for
  // everything this buffer could have said, so delivering none of it is strictly
  // honest — no wrong paths — at the cost of a few droppable events the rescan
  // re-covers. Reseed the map (future admissions), then signal ONLY the loss, so
  // nothing from the lossy buffer precedes the `Overflow` on the queue. A partial
  // classify's map mutations are erased by the reseed's `dirs.clear()`.
  if lossy {
    if !reseed_after_loss(map, stats, reseed_walk, transport, &mut send) {
      return false;
    }
    let map_stats = map.stats();
    stats.set_map(map_stats.directories, map_stats.memo_generation);
    // Empty events + lossy: `forward_batch` enqueues the `Overflow` alone (no
    // Batch), the barrier this whole branch exists to hold.
    transport::forward_batch(transport, Vec::new(), true, &mut send);
    return true;
  }

  // Publish this batch's memo tallies and the map's post-batch footprint, so an
  // operator poll reflects the current admission map and memo hit rate.
  stats.add_memo(memo.hits, memo.misses);
  let map_stats = map.stats();
  stats.set_map(map_stats.directories, map_stats.memo_generation);
  // A clean buffer forwards its admitted events with no loss.
  transport::forward_batch(transport, events, false, &mut send);
  true
}

/// Signals the terminal `Fatal` for a map that grew past its directory cap.
fn signal_fatal_cap<Q>(transport: &transport::TransportState, send: Q)
where
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  transport::signal_fatal_once(
    transport,
    SourceError::ReadFailed {
      source: cap_exceeded_error(),
    },
    send,
  );
}

/// Rebuilds the map from a fresh walk after a loss and records the reseed timing,
/// returning `false` (fatal already signaled) when the walk stays blind. Factored
/// out of [`process_decoded`]'s barrier branch so the reseed-and-escalate policy is
/// one place: a `FAN_Q_OVERFLOW`, a truncated/one-sided record — every lossy
/// buffer funnels here BEFORE the loss is signaled, so the reseeded sight is live
/// by the time the consumer's rescan re-enumerates. The walk is synchronous
/// between reads (overflow is rare, the walk is bounded by the root's directory
/// count). A walk that fails twice leaves the map permanently blind — a
/// stale-but-running source is the silent-loss shape this whole stack exists to
/// prevent — so the failure is escalated to the terminal `Fatal`, not swallowed.
fn reseed_after_loss<R, Q>(
  map: &mut FidMap,
  stats: &BackendStatsShared,
  reseed_walk: R,
  transport: &transport::TransportState,
  send: Q,
) -> bool
where
  R: FnMut() -> std::io::Result<Vec<SeedEntry>>,
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  stats.record_reseed();
  let started = std::time::Instant::now();
  let outcome = reseed_map(map, reseed_walk);
  stats.record_walk(walk_micros(started));
  if matches!(outcome, ReseedOutcome::Blind) {
    transport::signal_fatal_once(
      transport,
      SourceError::ReadFailed {
        source: reseed_blind_error(),
      },
      send,
    );
    return false;
  }
  true
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

/// The error a live map growing past its directory cap escalates through the
/// terminal `Fatal` (design §4.9): a capped map that keeps eventing while
/// silently refusing to learn new directories would drop their events as
/// outside-root forever — the silent-loss shape, refused honestly.
fn cap_exceeded_error() -> std::io::Error {
  std::io::Error::other(
    "the fanotify FID map exceeded its directory cap on a live create/move-in; the source cannot keep learning",
  )
}

/// A completed walk's duration in whole microseconds, saturating so a pathological
/// clock can never wrap the counter.
fn walk_micros(started: std::time::Instant) -> u64 {
  started.elapsed().as_micros().try_into().unwrap_or(u64::MAX)
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
