//! The reader-thread wakeup: one `eventfd` per root plus a `parked` flag that
//! elides the wake syscall whenever the reader is demonstrably not blocked.
//!
//! Both Linux readers (inotify and fanotify) block in `poll` over their source
//! fd and this eventfd; a sender that enqueues control traffic wakes the reader
//! by incrementing the eventfd — but only when the reader might actually be
//! asleep. The counter semantics mean one `read` drains any number of pending
//! wakes (no drain loop), and a write on an already-signaled eventfd is
//! harmless (the pending count already guarantees a wake).
//!
//! # The lost-wakeup argument
//!
//! The reader must never sleep in `poll` while a control message sits unserved
//! with no wake in flight. The protocol that guarantees this is a store/load
//! handshake on `parked`, and it is correct ONLY with a `SeqCst` fence on both
//! sides — plain Release/Acquire is NOT enough here.
//!
//! - Reader, immediately before blocking: [`arm_park`] sets `parked = true`,
//!   then executes a `SeqCst` fence. AFTER that fence the reader re-drains its
//!   control queue (the lost-wakeup guard); if anything is pending it clears the
//!   park and services it WITHOUT blocking.
//! - Sender: enqueues the message FIRST, then [`wake_if_parked`] executes a
//!   `SeqCst` fence and loads `parked`, writing the eventfd only if it reads
//!   `true`.
//!
//! The two operations that must not reorder are a store (`parked = true`) then a
//! load (the queue drain) on the reader, and a store (the enqueue) then a load
//! (`parked`) on the sender — the classic StoreLoad hazard. Under Release/
//! Acquire the CPU may sink the reader's park-store past its queue-drain AND
//! sink the sender's enqueue past its parked-load, so the reader drains empty
//! and the sender reads `false`: the reader blocks forever on a pending
//! message. The two `SeqCst` fences impose a single total order S over
//! themselves, which forces at least one thread to observe the other's write:
//!
//! - If the sender's `parked` load reads `false`, that load is ordered after
//!   the reader's park-store in S, so the sender's fence precedes the reader's
//!   fence in S; the enqueue (program-ordered before the sender's fence) then
//!   happens-before the reader's post-fence drain, and the reader SEES the
//!   message and does not block.
//! - Otherwise the sender's load reads `true` and it writes the eventfd, so the
//!   reader's `poll` returns (the eventfd is level/counter-readable) even if it
//!   had already committed to blocking.
//!
//! Either way the message is serviced; no quiet root can deadlock.

use std::{
  os::fd::{AsFd, OwnedFd},
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering, fence},
  },
};

use rustix::event::{EventfdFlags, eventfd};

use super::super::SourceError;

/// The wakeup state shared between a reader thread and its control senders: the
/// eventfd the reader blocks on and the `parked` flag that gates the wake.
#[derive(Debug)]
pub(crate) struct WakeState {
  /// The per-root eventfd; a sender increments it to wake the reader, the
  /// reader drains it with one `read` (counter semantics).
  event: OwnedFd,
  /// `true` while the reader is committed to (or already inside) a blocking
  /// `poll`; senders skip the wake syscall when it reads `false`.
  parked: AtomicBool,
  /// Set once by teardown, BEFORE the terminal `Control::Shutdown` is enqueued, so
  /// a reader executing a long control batch (an inotify cold enumerate's thousands
  /// of arms in ONE [`Control::Batch`](super::inotify::reader::Control)) observes it
  /// BETWEEN ops and preempts, rather than running the whole batch before it sees
  /// the following shutdown message. Advisory: its correctness floor is the terminal
  /// message (channel-synchronized) plus the unconditional [`wake`](Self::wake), so
  /// a maximally-delayed load only falls back to the existing between-message check
  /// — never a missed teardown. Used by the inotify reader (the only one with a
  /// control batch); the fanotify reader has no batch, so it never reads this.
  shutdown: AtomicBool,
}

impl WakeState {
  /// Creates the eventfd (initial counter 0, close-on-exec, non-blocking) and
  /// the shared handle wrapping it.
  pub(crate) fn new() -> Result<Arc<Self>, SourceError> {
    let event = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
      .map_err(|_| SourceError::CreateFailed)?;
    Ok(Arc::new(Self {
      event,
      parked: AtomicBool::new(false),
      shutdown: AtomicBool::new(false),
    }))
  }

  /// The eventfd, for the reader's `poll` set.
  pub(crate) fn event_fd(&self) -> impl AsFd + '_ {
    self.event.as_fd()
  }

  /// Announces that the reader is about to block: sets `parked` and fences so
  /// the post-fence queue re-drain cannot be reordered before the store (see
  /// the module's lost-wakeup argument). The caller MUST re-check its control
  /// queue after this and, if non-empty, [`unpark`] and service it without
  /// blocking.
  pub(crate) fn arm_park(&self) {
    self.parked.store(true, Ordering::Relaxed);
    fence(Ordering::SeqCst);
  }

  /// Clears `parked` — the reader is no longer (or never became) blocked.
  pub(crate) fn unpark(&self) {
    self.parked.store(false, Ordering::Relaxed);
  }

  /// Drains the eventfd counter with one `read` — resets it to 0 regardless of
  /// how many wakes accumulated. `EAGAIN` (counter already 0) is expected and
  /// ignored.
  pub(crate) fn drain(&self) {
    let mut buf = [0u8; 8];
    let _ = rustix::io::read(&self.event, &mut buf);
  }

  /// Wakes the reader IF it may be parked: fences and loads `parked`, writing
  /// the eventfd only when the reader is (or is committing to) a block. Callers
  /// MUST enqueue their control message BEFORE calling this — the fence pairs
  /// the enqueue with the reader's park-store (module lost-wakeup argument).
  pub(crate) fn wake_if_parked(&self) {
    fence(Ordering::SeqCst);
    if self.parked.load(Ordering::Relaxed) {
      self.wake();
    }
  }

  /// Unconditionally increments the eventfd counter — shutdown, and the
  /// fanotify admission reseed, where no wake elision applies. The write result
  /// is ignored: a full counter already guarantees a pending wake.
  pub(crate) fn wake(&self) {
    let _ = rustix::io::write(&self.event, &1u64.to_ne_bytes());
  }

  /// Raises the shutdown flag so a reader mid control-batch preempts between ops.
  /// Teardown calls this BEFORE enqueuing `Control::Shutdown` and BEFORE
  /// [`wake`](Self::wake), so the flag is visible by the time the reader next
  /// checks it. `Relaxed` suffices: the flag carries no data to publish, and its
  /// correctness floor is the terminal message + unconditional wake (see the field
  /// docs), so a delayed observation only defers to the between-message check.
  pub(crate) fn request_shutdown(&self) {
    self.shutdown.store(true, Ordering::Relaxed);
  }

  /// Whether this reader is (or is committing to) a block — the park half of the
  /// lost-wakeup handshake, for the cells that have to show a wait ARMED it before
  /// blocking and cleared it on every exit.
  #[cfg(test)]
  pub(crate) fn is_parked(&self) -> bool {
    self.parked.load(Ordering::Relaxed)
  }

  /// Whether teardown has requested shutdown — the inotify reader's between-ops
  /// preemption check inside a control batch.
  pub(crate) fn shutdown_requested(&self) -> bool {
    self.shutdown.load(Ordering::Relaxed)
  }
}

/// Returned transport credit wakes a reader exactly as a control message does,
/// and through the same handshake: the slot is given back before this runs (the
/// "enqueue" half), so a reader that parked after failing to claim one is woken,
/// and a reader that is demonstrably running pays no syscall.
impl crate::os::transport::BoundaryCredit for WakeState {
  fn boundary_released(&self) {
    self.wake_if_parked();
  }
}
