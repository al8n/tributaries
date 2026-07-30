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
//! | Instance-rebuild swap drain      | bounded must-complete ([`MAX_SWAP_DRAIN_READS`] reads), then the per-op check resumes |
//! | Pre-reply queue cut              | bounded must-complete (the byte count owed at cut start — [`cut_kernel_queue`]), skipped whole on a preempted batch; interrupted retries are separately budgeted and yield to a teardown, which degrades by signalling a covering loss and STOPPING the reader ([`cut_kernel_queue_with`]) |
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
    AnchorRequest, ArmReply, BatchReply, ExpectedObject, WatchOutcome, attribute_events,
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
  /// A batch of arms/disarms in emission order, with one reply sink carrying
  /// the arms' outcomes (index-aligned to the `Arm` entries, in order).
  ///
  /// The sink travels WITH the batch, so the message and the obligation to
  /// answer it are one object: a batch this reader never dequeues is answered
  /// by its own destruction rather than left to a caller's timeout.
  Batch {
    ops: Vec<ControlOp>,
    reply: BatchReply,
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

/// How far below the `wd` allocator's wrap edge an instance retires. The
/// no-wrap proof needs a margin of exactly 1 — the arm gate checks the
/// conservative allocator-cursor bound before every allocating add, and one
/// arm issues at most two adds — but 2¹⁶ grants of slack cost nothing at a
/// 2³¹ scale and keep the invariant safe against any future accounting slip.
/// The bound advances on EVERY allocation-capable add ATTEMPT, not just on the
/// grants that return a `wd`, so a kernel add that fails AFTER `idr_alloc_cyclic`
/// already advanced the cyclic cursor (say ENOSPC/ENOMEM installing the mark —
/// the kernel `idr_remove`s the entry but the cursor stays advanced) is counted
/// exactly like a grant. The bound therefore never under-counts the real
/// cursor: no run of such failures — however long — can carry the cursor past
/// the gate unseen, which the earlier max-granted-`wd` mark could not promise.
const REBUILD_MARGIN: i32 = 1 << 16;

/// The high-water mark at which the arm gate stops issuing adds on an
/// instance and rebuilds it instead (see [`Instance`]).
const REBUILD_THRESHOLD: i32 = i32::MAX - REBUILD_MARGIN;

/// The most reads one instance swap spends draining the dying fd. The kernel
/// queue at swap time holds at most `max_queued_events` records (a few reads'
/// worth); a producer refilling it cannot extend the swap past this cap —
/// whatever stays unread is covered by the loss signal the swap sends.
const MAX_SWAP_DRAIN_READS: u32 = 64;

/// The test-only rebuild-threshold override, read once per created
/// [`Instance`]. Zero means none. A real descriptor-space exhaustion (~2³¹
/// arms on one fd) is not stageable, so the deterministic forced-rebuild
/// suites lower the threshold instead; production builds compile the
/// constant alone.
#[cfg(any(test, feature = "_integration"))]
static THRESHOLD_OVERRIDE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Overrides the rebuild threshold for instances created after the call;
/// `None` restores the production constant. Test-only surface for the
/// real-kernel suites (a low threshold is the only way to force a rebuild
/// deterministically); the suites run single-threaded and restore it.
#[cfg(any(test, feature = "_integration"))]
#[doc(hidden)]
pub fn override_rebuild_threshold_for_tests(threshold: Option<i32>) {
  THRESHOLD_OVERRIDE.store(
    threshold.unwrap_or(0).max(0),
    std::sync::atomic::Ordering::Relaxed,
  );
}

/// The rebuild threshold a fresh [`Instance`] is born with.
fn rebuild_threshold() -> i32 {
  #[cfg(any(test, feature = "_integration"))]
  {
    let over = THRESHOLD_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
    if over > 0 {
      return over;
    }
  }
  REBUILD_THRESHOLD
}

/// The reader's live inotify instance: the fd, the `wd` table in lockstep
/// with it, and the conservative allocator-cursor bound that schedules the
/// instance's rebuild before the kernel's `wd` allocator could wrap.
///
/// # The no-wrap invariant (what keeps `wd` attribution unambiguous)
///
/// The kernel allocates `wd`s per instance with a cyclic cursor
/// (`inotify_new_watch`'s `idr_alloc_cyclic`, start 1): every grant is the
/// cursor's next value — STRICTLY INCREASING — until a grant past `i32::MAX`
/// would wrap the cursor to 1 and start re-granting freed `wd`s. A re-grant
/// of a `wd` the table still maps (a stale binding whose teardown records
/// were swallowed by a queue loss) is the one way a record could ever be
/// attributed to the wrong watch, so the reader never lets the cursor get
/// there: the arm executor checks the [`alloc_cursor`](Self::alloc_cursor)
/// bound before every arm and, once it reaches the threshold, REBUILDS the
/// instance — a fresh fd (cursor back at 1), a fresh table, the old fd drained
/// and closed, and one whole-instance loss signal so the Monitor re-proves
/// every retained binding on the fresh fd by acknowledged re-adds (the same
/// recovery any scope loss runs, holding the barrier down until the fresh ACKs
/// land). Old-fd and new-fd `wd`s can never alias: each instance's attribution
/// lives and dies with its own table.
///
/// Why a CONSERVATIVE bound, not the max granted `wd`: the kernel advances the
/// cyclic cursor on the ALLOCATION, so a post-allocation failure (ENOSPC on the
/// `max_user_watches` gate, ENOMEM installing the mark) leaves the cursor
/// advanced while returning NO `wd`. A mark tracking only granted `wd`s would
/// under-count the real cursor without bound, and a long enough run of such
/// failures could carry the cursor through the wrap while the gate kept
/// permitting adds — the next grant then lands a WRAPPED (low) `wd` onto a live
/// mapping. So the reader instead advances `alloc_cursor` on every add ATTEMPT
/// ([`add_watch`](Self::add_watch)): the bound is then always ≥ the real cursor
/// (every real `idr_alloc_cyclic` advance is preceded by an attempt the bound
/// counted; an `EEXIST`/update that allocated nothing is merely over-counted,
/// tripping the rebuild EARLY, never late), so the gate trips before the cursor
/// can reach the wrap and a wrapped grant — hence a collision — is
/// unconstructible.
///
/// Margin arithmetic: an arm is issued only while `alloc_cursor < threshold`,
/// and one arm advances the bound by at most two (its two adds), so the bound
/// peaks at `threshold + 1` — well short of the wrap edge by [`REBUILD_MARGIN`]
/// (2¹⁶) — and the real cursor, being ≤ the bound, never crosses `threshold`
/// either. The rebuild itself issues no adds on the old fd (the swap precedes
/// the arm that tripped it) and resets the bound to 0 on the fresh fd. If the
/// whole live tree ever exceeded the threshold the renewal would re-trip
/// mid-recovery — liveness would degrade, but no fd would ever grant past the
/// threshold, so the safety invariant is unconditional (and ~2³¹ live watches
/// is beyond `max_user_watches` and kernel memory).
pub(crate) struct Instance {
  fd: OwnedFd,
  table: WdTable,
  /// A conservative UPPER BOUND on the kernel's per-fd `wd` allocator cursor:
  /// advanced by one on every allocation-capable add ATTEMPT (see
  /// [`add_watch`](Self::add_watch)), so it stays ≥ the real cursor even when a
  /// post-allocation failure burns a cursor slot with no `wd` returned. The arm
  /// gate rebuilds on this bound, never on the max granted `wd`, so the cursor
  /// cannot wrap unseen.
  alloc_cursor: i32,
  threshold: i32,
  /// Test-only scripted add outcomes. When set, [`add_watch`](Self::add_watch)
  /// returns the next scripted result instead of calling the kernel — the
  /// conservative-bound advance runs first, exactly as on the kernel path — so
  /// a cursor-burning failure run and the wrapped grant it forecloses are
  /// deterministic (a real ~2³¹-add wrap is not stageable).
  #[cfg(test)]
  injected_adds: Option<std::collections::VecDeque<Result<i32, Errno>>>,
}

impl Instance {
  /// Wraps a freshly created inotify fd with an empty table and the
  /// production (or test-overridden) rebuild threshold.
  fn new(fd: OwnedFd) -> Self {
    Self::with_threshold(fd, rebuild_threshold())
  }

  /// An instance with an explicit rebuild threshold — the deterministic
  /// harness for the forced-rebuild suites.
  fn with_threshold(fd: OwnedFd, threshold: i32) -> Self {
    Self {
      fd,
      table: WdTable::new(),
      alloc_cursor: 0,
      threshold,
      #[cfg(test)]
      injected_adds: None,
    }
  }

  /// Issues one allocation-capable `inotify_add_watch` on this fd, advancing
  /// the conservative allocator-cursor bound FIRST. Every attempt that can
  /// reach the kernel's cyclic allocator (`idr_alloc_cyclic`) burns a cursor
  /// slot whether it returns `Ok`, `EEXIST`, or a post-allocation errno —
  /// counting the ATTEMPT (never merely the grant) is what keeps the bound
  /// ≥ the real cursor. Over-counting an `EEXIST`/update that allocated
  /// nothing is safe: it trips the rebuild slightly EARLY, never late.
  fn add_watch(&mut self, path: &str, mask: WatchFlags) -> Result<i32, Errno> {
    self.alloc_cursor = self.alloc_cursor.saturating_add(1);
    #[cfg(test)]
    if let Some(injected) = self.injected_adds.as_mut() {
      return injected.pop_front().unwrap_or(Err(Errno::NOSPC));
    }
    inotify::add_watch(&self.fd, path, mask)
  }

  /// Whether the next allocating add must be preceded by an instance
  /// rebuild: the conservative cursor bound has reached the threshold, so
  /// issuing another allocating add would eat into the wrap margin.
  fn needs_rebuild(&self) -> bool {
    self.alloc_cursor >= self.threshold
  }
}

/// Rebuilds the instance in place: [`rebuild_instance_with`] over the real
/// [`create_instance`].
fn rebuild_instance(instance: &mut Instance, shared: &ReaderShared) -> Result<(), SourceError> {
  rebuild_instance_with(instance, shared, create_instance)
}

/// Replaces the instance with a fresh one — a new fd (cursor back at `wd` 1)
/// and an empty table — after draining what the old fd still holds, then
/// signals ONE whole-instance loss so the Monitor re-proves every retained
/// binding on the fresh fd. Ordering on the source's single queue is what
/// makes the swap honest: the drained batches precede the loss signal, and
/// the loss signal precedes anything the fresh fd can deliver (the reader is
/// single-threaded), so everything the swap window could lose is covered by
/// the loss's Rescan and the re-prove's closing bridge exactly as a kernel
/// overflow's window is. Closing the old fd frees every kernel watch on it;
/// the old table dies unread with it, so no marker or record can cross
/// instances.
///
/// `create` failing returns its typed error with the stream UNTOUCHED — no
/// drain, no swap, no loss signal — and each caller answers that on its own
/// terms. The ARM gate refuses the arm (no add ⇒ the cursor cannot advance ⇒
/// wrap stays impossible), events keep flowing on the old fd, and the Monitor's
/// heal-kicked retry re-attempts the rebuild once descriptors free up. The
/// unprovable-cut degrade has no such retreat and escalates instead
/// ([`retire_unprovable_cut`]).
fn rebuild_instance_with(
  instance: &mut Instance,
  shared: &ReaderShared,
  create: impl FnOnce() -> Result<OwnedFd, SourceError>,
) -> Result<(), SourceError> {
  let fresh = create()?;
  drain_before_swap(instance, shared);
  instance.fd = fresh;
  instance.table = WdTable::new();
  instance.alloc_cursor = 0;
  transport::signal_loss(&shared.transport, |msg| shared.queue.try_send(msg).is_ok());
  Ok(())
}

/// Drains what the dying fd still holds, forwarding each buffer through the
/// OLD table — genuine pre-swap traffic, honestly attributed — bounded by
/// [`MAX_SWAP_DRAIN_READS`] so a sustained producer cannot wedge the swap
/// (whatever stays unread is covered by the loss signal the swap sends). A
/// read error stops the drain rather than killing the stream: the fd is
/// being replaced, and the loss covers whatever the error hid.
fn drain_before_swap(instance: &mut Instance, shared: &ReaderShared) {
  let mut buf = vec![0u8; 64 * 1024];
  for _ in 0..MAX_SWAP_DRAIN_READS {
    let n = match rustix::io::read(&instance.fd, &mut *buf) {
      Ok(0) | Err(Errno::AGAIN) => break,
      Ok(n) => n,
      Err(Errno::INTR) => continue,
      Err(_) => break,
    };
    let decoded = decode::decode_events(&buf[..n]);
    attribute_and_forward(&shared.transport, &mut instance.table, decoded, |msg| {
      shared.queue.try_send(msg).is_ok()
    });
  }
}

/// The most reads one pre-reply kernel-queue cut spends when `FIONREAD` is
/// unavailable and the byte bound must be replaced by a read-to-`EAGAIN`
/// drain. Sized for the default `fs.inotify.max_queued_events` (16384) at the
/// maximum record size (a 16-byte header plus a NAME_MAX name and its NUL
/// padding, 272 bytes): ⌈16384 × 272 / 65536⌉ = 68 buffer reads, plus slack
/// for a raised buffer's rounding. A queue this cap cannot exhaust (a raised
/// sysctl under a fallback that should be unreachable) is not silently left
/// resident — see [`cut_kernel_queue`]'s unprovable-cut rule.
const MAX_CUT_FALLBACK_READS: u32 = 72;

/// The largest queued-byte count from `FIONREAD` this cut will believe.
///
/// The ioctl reports through a C `int`, so a queue past `i32::MAX` bytes wraps
/// and the value stops describing the queue at all. `i32::MAX` is itself far
/// above any credible inotify queue — the kernel's own ceiling is
/// `max_queued_events` records of at most `16 + NAME_MAX + 1` bytes, so even a
/// sysctl raised a thousandfold stays orders of magnitude below it — which makes
/// any count at or past this bound a wrap artifact rather than a debt.
/// Note the widening: the ioctl's `int` reaches this code as a `u64`, so a
/// negative wrap does not arrive as a negative number to reject — it arrives as
/// a value near `u64::MAX`, which is precisely what this bound catches.
const MAX_CREDIBLE_QUEUE_BYTES: u64 = i32::MAX as u64;

/// The most reads one cut spends retiring a CREDIBLE `FIONREAD` debt before it
/// degrades to a covering loss.
///
/// The debt bounds how much the kernel says is queued, not how many reads it
/// takes to drain: a wrapped-small count under a still-filling queue, or a
/// buffer smaller than the records it must carry, would otherwise loop with the
/// control reply and the teardown join both withheld behind it. Sized well above
/// the fallback's derivation so a genuinely full queue at a raised sysctl retires
/// inside it, and exhausting it means the same thing exhausting any other bound
/// means: the cut is unprovable, so it degrades.
const MAX_CUT_OWED_READS: u32 = 4096;

/// The most INTERRUPTED read attempts one pre-reply cut absorbs before it
/// degrades to a covering loss. An `EINTR` return consumes no queued bytes and
/// proves nothing, so retrying it is the one step of the cut that makes no
/// progress — and an unbudgeted retry is therefore the one way the cut's
/// must-complete bound can be broken from OUTSIDE the queue: a signal storm
/// aimed at this thread would spin here indefinitely, withholding the batch
/// reply a driver-side settle waits on and blocking this reader's own
/// teardown. Set far above any realistic load (the kernel
/// redelivers one pending signal per interrupted syscall, and reads still get
/// through between deliveries) yet low enough to bound the cut to microseconds
/// of retries. Note this is a CEILING, not the tolerance actually available: an
/// interrupted retry also charges the read budget it runs under, so on the
/// unknown-count path the cut retires at whichever of the two exhausts first. The exhausted verdict is the [`MAX_CUT_FALLBACK_READS`] verdict:
/// a cut that cannot prove it drained the queue retires the instance ahead of
/// the reply instead of leaving a possibly-resident record to outlive it.
const MAX_CUT_INTERRUPTED_READS: u32 = 256;

/// Reads everything the kernel had committed to this instance's queue by the
/// time the control message being answered was serviced — the just-executed
/// batch's last op — attributing and forwarding it onto the source's single
/// ordered queue BEFORE
/// the reply is sent. This is the reply edge's ordering guarantee: a loss
/// record (an `IN_Q_OVERFLOW`, a decode break) that was kernel-resident when a
/// settling arm executed is enqueued behind nothing and ahead of the reply,
/// so on the driver's ingest order it precedes the settle observation that
/// reply arms — the settle-edge loss fence's drain-start snapshot provably
/// contains it, the fence turns lossy, and the barrier re-proves instead of
/// certifying over the unread loss. Without this cut the reply can outrun the
/// queue (control is serviced before and between reads by design), and no
/// driver-side ordering can recover what was never read.
///
/// Bounded by construction: `owed` is the queued byte count `FIONREAD`
/// reports at cut start (inotify implements it as exactly that), so records
/// arriving DURING the cut postdate every op of the batch and legitimately
/// ride behind the reply — the cut never chases a refilling queue. The bound
/// is therefore the kernel's own queue ceiling (`max_queued_events` records),
/// the same must-complete budget the instance swap's drain works to, and the
/// common case is one ioctl returning 0 with no read at all. Should the ioctl
/// fail (unreachable on a real inotify fd), the fallback drains to `EAGAIN`
/// under [`MAX_CUT_FALLBACK_READS`]; a fallback that exhausts its cap without
/// reaching `EAGAIN` cannot PROVE the queue was cut, so it takes the
/// unprovable-cut exit below — the barrier then degrades and re-proves, which is
/// the honest verdict, never a silent under-drain.
///
/// One step of the cut makes no progress against either bound: an interrupted
/// read (`EINTR`) consumes no queued bytes and answers nothing, so retrying it
/// is bounded separately by [`MAX_CUT_INTERRUPTED_READS`] — and yields at once
/// to a pending teardown, since a reader on its way out must not spend even
/// that budget. Without that budget a signal storm aimed at this thread would
/// hold the reply indefinitely — the cut sits on the settling-reply path, so
/// the withheld reply is a withheld verdict, and the reader could not tear down
/// either.
///
/// # What an unprovable cut owes, and why a covering loss alone did not pay it
///
/// Every bound above ends in the same verdict — the queue's remainder is
/// UNPROVEN — and the honest answer to that is not merely to announce the loss:
/// the unread remainder is still resident on this same instance, so the reader's
/// very next read forwards those OLDER records as an ORDINARY batch BEHIND the
/// covering loss. The loss's `Rescan` bumps the epoch, and a consumer that
/// crawled at the rescan then replays pre-loss renames and removes over its
/// fresh state — records the loss was supposed to dominate arriving stamped as
/// new history. An all-aliased binding reproof can close with no rescan of its
/// own, so nothing downstream re-covers them either.
///
/// So an unprovable cut RETIRES the instance instead ([`retire_unprovable_cut`]):
/// the swap's drain salvages what it can ahead of the loss, the loss precedes
/// the reply exactly as before, and closing the old fd makes the remainder
/// unconstructible rather than merely covered. A teardown observed mid-cut takes
/// the one other honest exit — signal the covering loss and STOP the reader —
/// because a reader on its way out must not spend the thread on a rebuild, and a
/// reader that stops forwards nothing behind the loss either.
///
/// Pure over the `read`, `shutdown` and `create` seams — the fd-touching,
/// teardown-observing and instance-minting parts — so an interrupt storm, which
/// no test can inject at a real descriptor, drives the real body
/// deterministically.
///
/// Returns `true` when the reader must EXIT after answering the message it was
/// serving: the stream died mid-cut (a read error, or no replacement instance
/// for an unprovable cut — the terminal `Fatal` is already signaled and ordered
/// AFTER everything the cut forwarded), or a teardown was observed mid-cut (the
/// covering loss is already signaled).
fn cut_kernel_queue(
  instance: &mut Instance,
  shared: &ReaderShared,
  buf: &mut [u8],
  wake: &WakeState,
) -> bool {
  cut_kernel_queue_with(
    instance,
    shared,
    buf,
    || wake.shutdown_requested(),
    |fd, buf| rustix::io::read(fd, buf),
    |fd: &OwnedFd| rustix::io::ioctl_fionread(fd),
    create_instance,
  )
}

/// The unprovable cut's degrade: RETIRE the instance, so nothing it still holds
/// can outlive the covering loss the retirement signals.
///
/// This is [`rebuild_instance_with`] verbatim — the same machinery the
/// allocator's no-wrap bound rebuilds on, not a second path — and it inherits
/// that swap's whole ordering argument: the dying fd's drain is forwarded first
/// (genuine pre-loss traffic, honestly attributed through the OLD table),
/// exactly ONE whole-instance loss follows it, and the fresh fd — a fresh table
/// with it — can deliver only after that. Called from inside the cut, the loss
/// therefore still precedes the reply the cut precedes, and the records the cut
/// could not prove it read are gone with the fd rather than queued behind the
/// loss. Arm ACKs the batch already produced on the old fd are superseded by
/// that loss and resolved by the Monitor's binding re-proof, precisely as they
/// are when a mid-batch threshold trip retires the instance.
///
/// A replacement fd that cannot be created is FATAL, and that asymmetry with the
/// arm gate is deliberate. The gate can refuse its arm and keep the old fd (no
/// add ⇒ no cursor advance ⇒ the wrap stays impossible); here the old fd's
/// unread remainder is exactly what must not survive, so there is no retreat
/// that keeps it. A reader that cannot retire the instance stops delivering
/// instead of delivering it — the terminal `Fatal` dominates the loss it could
/// not signal, and the scope funnels to teardown.
///
/// Returns `true` when the reader must exit (the terminal `Fatal` is signaled).
fn retire_unprovable_cut(
  instance: &mut Instance,
  shared: &ReaderShared,
  create: impl FnOnce() -> Result<OwnedFd, SourceError>,
) -> bool {
  match rebuild_instance_with(instance, shared, create) {
    Ok(()) => false,
    Err(err) => {
      signal_fatal(shared, err);
      true
    }
  }
}

/// [`cut_kernel_queue`]'s body, over injectable `read`, `shutdown`, `fionread`
/// and `create` seams.
///
/// The ioctl is injectable for the same reason the read is: a wrapped queued-byte
/// count is unreachable at a real descriptor — it needs gigabytes resident — so
/// the guards against it would otherwise be argued rather than pinned. `create`
/// is injectable so the unprovable cut's fatal leg — no replacement instance —
/// is pinned without exhausting the host's descriptors.
fn cut_kernel_queue_with(
  instance: &mut Instance,
  shared: &ReaderShared,
  buf: &mut [u8],
  mut shutdown: impl FnMut() -> bool,
  mut read: impl FnMut(&OwnedFd, &mut [u8]) -> Result<usize, Errno>,
  mut fionread: impl FnMut(&OwnedFd) -> Result<u64, Errno>,
  mut create: impl FnMut() -> Result<OwnedFd, SourceError>,
) -> bool {
  // The count is a HINT, never a proof. `FIONREAD` yields a C `int`, so a queue
  // holding more than `i32::MAX` bytes reports a WRAPPED value: implausibly huge
  // (a debt no read can retire, holding the reply and the teardown join), or
  // small enough to under-claim a queue that is still resident (a reply ordered
  // ahead of records the cut never read — including an overflow sentinel, which
  // is exactly the ordering this cut exists to establish). So an incredible count
  // is discarded rather than believed, and reaching the claimed endpoint is not
  // by itself an exit: only `EAGAIN`, an empty read, or an exhausted bound ends
  // the cut, and the last of those retires the instance.
  let mut owed = match fionread(&instance.fd) {
    Ok(owed) if owed <= MAX_CREDIBLE_QUEUE_BYTES => Some(owed),
    Ok(_) | Err(_) => None,
  };
  let mut owed_reads = 0u32;
  let mut fallback_reads = 0u32;
  let mut interrupted = 0u32;
  loop {
    match owed {
      Some(_) => {
        if owed_reads >= MAX_CUT_OWED_READS {
          // A credible debt that will not retire under its own bound is no more
          // provable than a failed ioctl: retire the instance rather than spin
          // on the reply.
          return retire_unprovable_cut(instance, shared, &mut create);
        }
        owed_reads += 1;
      }
      None => {
        if fallback_reads >= MAX_CUT_FALLBACK_READS {
          // The cap ran out before `EAGAIN`: the queue's remainder is
          // unknowable here, so the instance is retired rather than left
          // holding records that would arrive behind the covering loss as if
          // they postdated it.
          return retire_unprovable_cut(instance, shared, &mut create);
        }
        fallback_reads += 1;
      }
    }
    let n = match read(&instance.fd, &mut *buf) {
      // Defensive: with this thread as the fd's only reader, a queue owing
      // bytes cannot read empty — but an empty read always ends the cut.
      Ok(0) | Err(Errno::AGAIN) => return false,
      Ok(n) => n,
      Err(Errno::INTR) => {
        // The one step that reads nothing — but NOT one that costs nothing:
        // `continue` re-enters the loop top, so an interrupted retry charges the
        // owed or fallback budget exactly like a real read. The interrupt budget
        // is therefore an upper bound that the read budget can pre-empt: on the
        // unknown-count path the effective interrupt tolerance is the smaller of
        // the two, and the cut retires on whichever is exhausted first. Both
        // outcomes are the same conservative verdict, so the interaction costs
        // honesty nothing — but it does mean this budget is not spent in
        // isolation. Retry, then — but hand a pending
        // teardown the thread immediately rather than spending it, and rather
        // than spending it on a rebuild either. Both exits agree the
        // remainder is unproven; they differ only in how the reader stops it
        // from arriving behind the loss (retire the fd, or stop reading).
        interrupted += 1;
        if shutdown() {
          return abandon_cut_to_teardown(shared);
        }
        if interrupted >= MAX_CUT_INTERRUPTED_READS {
          return retire_unprovable_cut(instance, shared, &mut create);
        }
        continue;
      }
      Err(err) => {
        signal_fatal(shared, SourceError::ReadFailed { source: err.into() });
        return true;
      }
    };
    if let Some(owed) = owed.as_mut() {
      // One read can deliver MORE than the owed remainder (records that
      // arrived after the snapshot fill the same buffer) — saturation ends
      // the cut with the extra genuine traffic forwarded in order.
      *owed = owed.saturating_sub(n as u64);
    }
    let decoded = decode::decode_events(&buf[..n]);
    attribute_and_forward(&shared.transport, &mut instance.table, decoded, |msg| {
      shared.queue.try_send(msg).is_ok()
    });
    // Checked AFTER the read, never before it: a reader on its way out must not
    // spend an unbounded run of iterations, but neither may a pending teardown
    // preempt the attempt — one read often completes the cut outright, and
    // abandoning it unread would degrade a barrier that had no need to. Past that
    // attempt the withheld reply and the teardown join both sit behind this loop,
    // so an abandoned proof is an unprovable cut like any other.
    if shutdown() {
      return abandon_cut_to_teardown(shared);
    }
  }
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
        run(fd, &wake, &control, &shared);
      }));
      if outcome.is_err() {
        signal_fatal(&shared, SourceError::CallbackPanic);
      }
    })
    .map_err(|_| SourceError::StartFailed)
}

/// The teardown's exit from an unprovable cut: a covering loss on the source
///
/// The invariant is that an `Overflow` covering the remainder PRECEDES the reply,
/// not that a new message is always enqueued: the transport's position-aware
/// dedup collapses this signal onto an `Overflow` already pending at the tail,
/// which covers the same remainder from an earlier queue position. Read any
/// message-count assertion in the cells as a property of their own staging.
/// queue — enqueued before the reply the cut precedes, so the driver's barrier
/// degrades and re-proves instead of certifying over a record the cut could not
/// read — and then the READER STOPS.
///
/// Stopping is what makes the loss honest, and it is the whole reason this is
/// not [`retire_unprovable_cut`]. The remainder the cut could not prove it read
/// is still resident, so if the reader kept going it would forward those older
/// records as an ordinary batch behind the loss, in the epoch the loss opened.
/// Retiring the instance would foreclose that, but a teardown-bound reader must
/// not spend its thread minting a replacement it will immediately close (the
/// module's teardown-fairness invariant) — and it does not need to: a reader
/// that stops reading forwards nothing behind the loss at all. Exiting without
/// having dequeued the terminal `Control::Shutdown` is the already-established
/// preempted-batch behaviour: the message is not the exit condition, and a
/// caller whose batch never lands reads the dropped receiver as a dead reader.
///
/// Always returns `true` — the caller answers the message it was serving, then
/// exits.
fn abandon_cut_to_teardown(shared: &ReaderShared) -> bool {
  transport::signal_loss(&shared.transport, |msg| shared.queue.try_send(msg).is_ok());
  true
}

fn signal_fatal(shared: &ReaderShared, err: SourceError) {
  transport::signal_fatal_once(&shared.transport, err, |msg| {
    shared.queue.try_send(msg).is_ok()
  });
}

fn run(fd: OwnedFd, wake: &WakeState, control: &mpsc::Receiver<Control>, shared: &ReaderShared) {
  let mut instance = Instance::new(fd);
  // Sized for a dense read: watchman's batch scale (16k events of header
  // size) is far past what one wake needs; 64 KiB covers the deepest names.
  let mut buf = vec![0u8; 64 * 1024];
  loop {
    // Announce the intent to block, then re-drain control BEFORE polling: a
    // sender that enqueued before our fence is guaranteed visible here (the
    // lost-wakeup guard — see `WakeState`). Draining anything means we service
    // it and loop without ever blocking on a non-empty queue.
    wake.arm_park();
    if drain_control(&mut instance, shared, control, wake, &mut buf) {
      return; // Shutdown observed in the guard drain.
    }
    // A quiet re-check found nothing pending; commit to the block. Only the
    // eventfd (a sender's wake) or source data returns us. The fd is re-read
    // from the instance each lap: a mid-batch rebuild swaps it, and the next
    // poll must watch the fresh one.
    let event = wake.event_fd();
    let mut fds = [
      PollFd::new(&instance.fd, PollFlags::IN),
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
      if drain_control(&mut instance, shared, control, wake, &mut buf) {
        return;
      }
    }
    if source_ready {
      match drain_events(&mut instance, &mut buf, control, wake, shared) {
        DrainExit::Parked => {}
        DrainExit::Shutdown | DrainExit::Died => return,
      }
    }
  }
}

/// Drains every pending control message, executing each batch in one pass.
/// Returns `true` when the reader must exit — a shutdown was observed, a
/// teardown preempted the batch, or the pre-reply cut demanded the exit (a
/// stream death or an un-mintable replacement instance, both with the terminal
/// `Fatal` already signaled; or a teardown observed mid-cut, whose covering loss
/// may not be followed by any further forward — see [`cut_kernel_queue`]). A
/// batch is run through
/// [`execute_batch`], which yields to a pending teardown BETWEEN its ops — so
/// shutdown preempts a long cold-enumerate batch mid-flight rather than only
/// after the whole batch (the teardown-fairness invariant in the module docs).
///
/// Every reply the reader can send leaves through this one site, and every
/// non-preempted reply is preceded by [`cut_kernel_queue`]: whichever drain
/// triggered the batch — the poll loop's control-first dispatch, the
/// inter-read drain inside [`drain_events`], or the pre-park guard drain —
/// the records the kernel had committed by the batch's execution are on the
/// source queue before the caller can observe the reply. A PREEMPTED batch
/// skips the cut: its replies are the failure tail of a reader that is
/// exiting, nothing settles on them, and the scope funnels to teardown whose
/// fences degrade — bounded teardown latency is the invariant there.
fn drain_control(
  instance: &mut Instance,
  shared: &ReaderShared,
  control: &mpsc::Receiver<Control>,
  wake: &WakeState,
  buf: &mut [u8],
) -> bool {
  loop {
    match control.try_recv() {
      Ok(Control::Batch { ops, reply }) => {
        let (replies, preempted) =
          execute_batch(instance, shared, ops, || wake.shutdown_requested());
        let cut_exits = !preempted && cut_kernel_queue(instance, shared, buf, wake);
        // Answer with the (executed + failed-tail) replies either way so no caller
        // is left waiting on a truncated reply; then, if teardown preempted
        // mid-batch (or the cut itself demanded the exit — a stream death, a
        // replacement instance it could not mint, or a teardown observed
        // mid-cut), exit as if the terminal `Shutdown` had been observed here.
        reply.answer(replies);
        if preempted || cut_exits {
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
/// Each arm additionally passes the no-wrap gate: once the instance's `wd`
/// high-water mark reaches its rebuild threshold, the instance is REBUILT —
/// swapped for a fresh fd + table with a whole-instance loss signalled —
/// BEFORE the add is issued, so no allocating add ever eats into the wrap
/// margin ([`Instance`]). Ops before the trip executed on the old fd (their
/// ACKs were true at execution and are superseded by the queued loss, which
/// the Monitor's binding re-proof resolves either way it races the reply);
/// the tripping arm and the rest of the batch execute on the fresh fd. A
/// rebuild that cannot get a replacement fd refuses the arm instead — the
/// cursor stays frozen, wrap stays impossible, and the heal retry
/// re-attempts.
///
/// Pure over the `shutdown` predicate — the only teardown-observing part — so the
/// preemption point is deterministically testable without racing a real teardown.
fn execute_batch(
  instance: &mut Instance,
  shared: &ReaderShared,
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
      ControlOp::Arm(request) => {
        if instance.needs_rebuild() && rebuild_instance(instance, shared).is_err() {
          replies.push(failed_arm_reply());
          continue;
        }
        replies.push(arm(instance, request));
      }
      ControlOp::Disarm(anchor) => disarm(instance, anchor),
    }
  };
  if preempted {
    // The shutdown check broke the loop BEFORE consuming the current op, so `ops`
    // still holds every un-executed op. Fail each remaining arm so the reply vec
    // covers all of the batch's `Arm` entries; disarms need no reply (and the fd is
    // about to close, so their kernel removal is moot).
    for op in ops {
      if matches!(op, ControlOp::Arm(_)) {
        replies.push(failed_arm_reply());
      }
    }
  }
  (replies, preempted)
}

/// The `Failed(Io)` reply for an arm the reader could not execute: one
/// preempted (un-executed) by a mid-batch teardown — the same reply a dead
/// reader answers — or one refused because the instance is at its rebuild
/// threshold and no replacement fd could be created. Both resolve
/// driver-side as ordinary arm failures (a covering `Rescan` and a
/// heal-retried deficit), never a hang on a truncated batch reply.
fn failed_arm_reply() -> ArmReply {
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
/// the NEXT decoded buffer then sees, and a mid-drain instance rebuild swaps the
/// fd, which the next read then reads (the fresh fd; the old one was drained by
/// the swap itself) — and stops the drain immediately on a `Shutdown`, so shutdown
/// takes priority over further event draining. Control is observed at the top of
/// the loop, between one buffer's forward and the next read, never mid-buffer, so
/// the per-buffer loss barrier and attribution are unchanged.
/// Returns [`DrainExit::Died`] when the stream died (fatal already signaled),
/// [`DrainExit::Shutdown`] on a mid-drain shutdown, and [`DrainExit::Parked`] when
/// the instance drained clean.
fn drain_events(
  instance: &mut Instance,
  buf: &mut [u8],
  control: &mpsc::Receiver<Control>,
  wake: &WakeState,
  shared: &ReaderShared,
) -> DrainExit {
  loop {
    if drain_control(instance, shared, control, wake, buf) {
      return DrainExit::Shutdown;
    }
    let n = match rustix::io::read(&instance.fd, &mut *buf) {
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
    attribute_and_forward(&shared.transport, &mut instance.table, decoded, |msg| {
      shared.queue.try_send(msg).is_ok()
    });
  }
}

/// Attributes one decoded buffer against the `wd` table, reaps the table's
/// draining tombstones on a DECODE-level loss, and forwards the result behind the
/// loss ordering barrier. Pure over the `send` closure — the only queue-touching
/// part — so the whole seam is testable over a real table +
/// [`DecodeOutcome`](decode::DecodeOutcome) with a capturing sender.
///
/// Attribution runs even on a lossy buffer so the `wd` table stays accurate (an
/// `IN_IGNORED` in the decoded prefix must still consume its entry); the events are
/// then dropped by the barrier inside [`forward_attributed`].
///
/// # Tombstone reaping: which losses reap, and which do not
///
/// A draining tombstone WAITS for its final `IN_IGNORED`, and only a loss that
/// dropped queued bytes can have taken that marker with it (leaving the tombstone
/// stranded forever — nothing else reaps one). Every loss path is classified
/// accordingly:
///
/// | Loss path                                    | Bytes dropped | Tombstones reaped |
/// |----------------------------------------------|---------------|-------------------|
/// | `IN_Q_OVERFLOW` record (kernel drop)         | yes           | yes — in [`attribute_events`], in-order at the sentinel |
/// | Decode-truncation / absurd-len / malformed   | yes           | yes — HERE, on `decoded.lossy`, after the prefix is attributed |
/// | Budget-refused batch (transport backpressure)| no            | no — the buffer's markers were already consumed by attribution; only its events degrade to a covering `Overflow` |
/// | `Fatal` (stream death)                       | terminal      | no — the table dies with the reader thread |
///
/// Reaping early — the marker actually survived behind the break — is safe: the
/// freed `wd` stays un-adoptable until the kernel's cyclic allocator laps, so the
/// straggling marker no-ops on the unmapped `wd` (the table's adoption invariant).
/// The reap runs AFTER attributing the intact prefix (so any real markers it held
/// are honored) and BEFORE forwarding the loss barrier.
fn attribute_and_forward<S>(
  transport: &transport::TransportState,
  table: &mut WdTable,
  decoded: decode::DecodeOutcome,
  send: S,
) where
  S: FnMut(crate::os::SourceMessage) -> bool,
{
  let attributed = attribute_events(decoded.events, table);
  if decoded.lossy {
    // A decode-level loss dropped the tail after the break: a draining
    // tombstone's awaited final marker may be in that tail and will never
    // arrive. Reap the tombstones (same body as the in-order overflow reap).
    table.on_loss();
  }
  forward_attributed(transport, attributed, decoded.lossy, send);
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
///
/// A RE-add (the anchor already bound in the table) is arm-first, never
/// drain-first: the kernel reply decides the old binding's fate. `Aliased` on
/// the anchor's own `wd` proves the binding was live all along — table dedup
/// only, nothing removed (draining first would have removed a LIVE shared
/// watch, opening a gratuitous dark window and turning every recovery
/// `Installed`). `Installed` on a DIFFERENT `wd` — or an alias landing on one
/// — proves the old binding superseded: it is drained, with the kernel
/// removal when the last alias leaves (`EINVAL`-benign on a dead watch; a
/// REAL removal on a detached-live one, ending its misattributing delivery),
/// before the fresh registration.
///
/// # Why a fresh install can never collide (the table's adoption invariant)
///
/// A fresh, kernel-CREATED watch's `wd` is the allocator cursor's next value,
/// strictly greater than every `wd` this instance ever granted — the arm gate
/// rebuilds the instance before the cursor could wrap ([`Instance`]) — and
/// the table (born empty with the instance) maps only granted `wd`s. So a
/// fresh install's `wd` is never mapped: no stale entry can stand where it
/// lands, no stale marker can ever address it, and everything consumed on a
/// mapped `wd` belongs to that mapping. Asserted, not handled — the branch
/// that once refused a colliding install died with the wrap that produced it.
///
/// The one refusal that remains is the `EEXIST` path's degenerate outcome
/// ([`refuse_disguised_create`]): the probed watch dying between the two adds
/// turns the second add into a fresh create on the doomed object — reachable
/// without any `wd` reuse, and refused onto a provably unmapped `wd`.
fn arm(instance: &mut Instance, request: AnchorRequest) -> ArmReply {
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
  match instance.add_watch(proc_path.as_str(), mask) {
    // `IN_MASK_CREATE` makes this success a kernel-CREATED watch on a fresh
    // `wd` — the cursor's next grant, past every `wd` the table could map
    // (the no-wrap invariant above).
    Ok(wd) => {
      debug_assert!(
        !instance.table.contains(wd),
        "a fresh install's wd outgrows every mapped one: the instance rebuilds before the allocator can wrap"
      );
      drain_superseded_binding(&instance.fd, &mut instance.table, wd, request.watch);
      instance.table.register(wd, request.watch);
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
      match instance.add_watch(proc_path.as_str(), mask) {
        Ok(wd) => {
          // A genuine alias updates the EXISTING watch, whose `wd` is
          // necessarily mapped live (every live watch on this fd was adopted
          // through `register`, and its entry outlives it). Anything else
          // means the target's watch died between the two adds and this add
          // CREATED a fresh watch on the anchor-pinned, now-doomed object —
          // refused, so the retry re-opens the target and reports its true
          // state.
          if !instance.table.is_live(wd) {
            return refuse_disguised_create(instance, wd);
          }
          drain_superseded_binding(&instance.fd, &mut instance.table, wd, request.watch);
          instance.table.alias(wd, request.watch);
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

/// Refuses the `EEXIST` path's one degenerate outcome: the probed watch died
/// between the two adds (its object was unlinked or unmounted in that
/// instant — the only ways a watch dies under a held anchor), so the second,
/// `IN_MASK_CREATE`-less add CREATED a fresh watch on the doomed object
/// instead of updating the live one. The just-created watch is removed again
/// and the arm fails `Failed(Io)` into the Monitor's install-refusal funnel
/// (covering `Rescan`, slot deficit, heal-kicked retry), whose retry
/// re-opens the target and reports its true state (`NotFound`/`Gone`).
///
/// No `wd` reuse is involved: the created `wd` is the cursor's next grant,
/// past every mapped one (the no-wrap invariant), so nothing attributes
/// through it — records its instant of kernel-side existence queued address
/// no mapping and are skipped, and its removal's `IN_IGNORED` no-ops on the
/// unmapped `wd`.
fn refuse_disguised_create(instance: &mut Instance, wd: i32) -> ArmReply {
  debug_assert!(
    !instance.table.contains(wd),
    "a disguised create's fresh wd outgrows every mapped one"
  );
  let _ = inotify::remove_watch(&instance.fd, wd);
  ArmReply {
    outcome: WatchOutcome::Failed(WatchError::Io),
    anchor: None,
  }
}

/// Drains `anchor`'s previous binding when an arm landed it on a DIFFERENT
/// `wd`: the old binding is superseded — the object at the anchor's live path
/// is (or is now watched as) another kernel watch — so the anchor leaves it,
/// and the kernel removal is issued when it was the last alias. On a
/// detached-live binding (a lazy-unmounted tree still delivering) the removal
/// is real and required. A same-`wd` reply never drains: it is always an alias
/// of the live binding (dedup handles it) — a fresh install cannot land on the
/// anchor's own old `wd`, whose grant it strictly outgrows (the no-wrap
/// invariant).
///
/// `EINVAL` means the watch is already gone, so its `IN_IGNORED` is either
/// queued (the benign race) or was swallowed by a queue loss — under the
/// retained-binding recovery the second case is ordinary, and the tombstone
/// left waiting for a marker that will never come would leak for the fd's
/// whole life. Proof the kernel cannot owe the marker erases the tombstone at
/// once ([`WdTable::erase_dead`]); a surviving marker no-ops on the unmapped
/// `wd`. Other errnos stay ignored — `EBADF` is unreachable on the owned fd,
/// and erasing on it would mask an fd-lifecycle bug rather than a dead watch.
fn drain_superseded_binding(fd: &OwnedFd, table: &mut WdTable, wd: i32, anchor: WatchId) {
  if table.wd_of(anchor).is_some_and(|old| old != wd)
    && let DrainDecision::RemoveWd(old) = table.begin_drain(anchor)
  {
    erase_dead_on_invalid(fd, table, old);
  }
}

/// Issues the kernel removal for a just-drained tombstone and erases the
/// tombstone when the kernel answers `EINVAL` — the watch is already gone, so
/// no `IN_IGNORED` can still be owed (see [`WdTable::erase_dead`]). Any other
/// errno leaves the tombstone draining exactly as before.
fn erase_dead_on_invalid(fd: &OwnedFd, table: &mut WdTable, wd: i32) {
  match inotify::remove_watch(fd, wd) {
    Err(Errno::INVAL) => table.erase_dead(wd),
    Err(err) => {
      debug_assert!(
        err != Errno::BADF,
        "the reader owns its inotify fd for the instance's whole life"
      );
    }
    Ok(()) => {}
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
/// last alias drains. The kernel auto-removes a watch whose object was
/// deleted, so `EINVAL` here means the watch is already gone: its
/// `IN_IGNORED` is queued (the benign race) or a queue loss swallowed it, and
/// only the marker would ever reap the tombstone — so the proof erases it
/// immediately, exactly as on the superseded-binding path
/// ([`erase_dead_on_invalid`]).
fn disarm(instance: &mut Instance, anchor: WatchId) {
  if let DrainDecision::RemoveWd(wd) = instance.table.begin_drain(anchor) {
    erase_dead_on_invalid(&instance.fd, &mut instance.table, wd);
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
