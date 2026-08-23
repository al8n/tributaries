//! The per-root fanotify reader thread: owns the fanotify fd AND the per-root
//! [`FidMap`], so decode, admission, and the map's self-maintenance are
//! serialized by construction — there is no ARM traffic (the mark is
//! kernel-recursive), only reads, admission reseeds, and a shutdown wake.
//!
//! Wakeup mirrors the inotify reader: the thread blocks in `poll` over the
//! fanotify fd and a per-root [`WakeState`] eventfd; every control message
//! increments the eventfd. One wait polls the eventfd ALONE — the boundary-report
//! credit reserved before each read ([`ReportCredit`]) — because the instance is
//! readable by definition there and including it would spin.
//! Because each sender wakes unconditionally, no wake
//! elision applies here, but the park/guard/drain shape is shared with the
//! inotify reader for one wakeup story. A `FAN_Q_OVERFLOW` marker (or a
//! truncated/malformed record) degrades to the ordered loss signal; a read
//! error, a foreign event-metadata ABI version, or a panic degrades to the
//! terminal `Fatal` exactly once, then the thread exits.
//!
//! # Control traffic: shutdown, and the admission reseed
//!
//! [`Control`] carries two messages, and the second is what makes the mount
//! design's fanotify half real rather than merely signalled. Admission is
//! directory-handle MEMBERSHIP, and the seed walk declines to descend a mount —
//! so ground a departed mount REVEALS was never seeded and its events drop as
//! provably-outside-root. The core detects that departure from the mount table,
//! parks the cover it owes, and sends an [`crate::os::AdmitRequest`] here; this
//! reader walks the revealed ground into the map and answers, and only then does
//! the cover reach the consumer. Everything about that ordering lives on the two
//! sides of the same one queue — see [`crate::os::AdmitOutcome`].
//!
//! Every control message reaches the reader through [`ControlInbox`], which
//! DRAINS the channel rather than peeking at its head. That is not a style
//! choice: the three places this reader observes control were once spelled
//! `matches!(control.try_recv(), Ok(Control::Shutdown))`, which RECEIVES a
//! message and evaluates to `false` for anything that is not a shutdown — i.e.
//! silently consumes and discards it. With one variant that was merely
//! redundant; with two it would drop admissions on the floor and leave a cover
//! parked in the core forever. The inbox has no shape that can discard: what it
//! takes off the channel it either acts on or holds.
//!
//! # Teardown-fairness invariant
//!
//! Same charter as the inotify reader (no unbounded op loop defers shutdown), but
//! the long-op sites differ — this reader has no control BATCH, and its control
//! work is a walk rather than a set of arms to reply to:
//!
//! | Long-op site                          | Verdict                             |
//! |---------------------------------------|-------------------------------------|
//! | Event drain (read → `EAGAIN`)         | preemptible BETWEEN reads           |
//! | Boundary-credit wait (before a read)  | preemptible; nothing is read yet    |
//! | Reseed walk (`reseed_map`)            | bounded, must complete or blind→fatal |
//! | Move-in subtree walk (`seed_moved_in_subtree`) | bounded, must complete or blind→loss |
//! | Admission reseed (`admit_revealed`)   | bounded, must complete or blind→loss |
//! | Every walk LADDER (its retry, its escalation) | preemptible BETWEEN attempts |
//! | Admission BACKLOG (`service_control`) | preemptible BETWEEN admissions      |
//!
//! The three walks are the bounded-must-complete case: each rebuilds (or extends) the
//! FID map from a fresh directory enumerate, and the map swap is only sound once the
//! walk's full inventory is in hand — interrupting one mid-flight would leave a
//! half-built map, i.e. a silently-blind subtree, the exact class the whole stack
//! prevents. So a shutdown landing mid-walk WAITS for the walk (checked between
//! reads, after the current buffer's walk has finished): the walk is bounded by the
//! root's directory count and either completes or concedes blindness. Unlike
//! the inotify batch, a walk's work cannot be failed-reply'd away — there is no
//! per-op grant to resolve, only a map that is whole or blind.
//!
//! **The must-complete rule binds ONE walk, never a ladder of them.** Each of those
//! three drivers retries once, and the admission driver then escalates a
//! twice-failed located walk into a whole-root reseed that retries once more — up
//! to four whole walks behind one control message, with the shutdown check sitting
//! only in front of the first. So every ladder carries the shutdown predicate and
//! consults it BETWEEN attempts and before the escalation ([`StepExit`]): a retry
//! is a fresh walk with no partial state to protect, and abandoning one costs
//! exactly what the abandoned admission already costs — nothing that outlives the
//! scope being torn down.
//!
//! A RUN of admissions is a different question from one walk, and it is where the
//! inotify reader's intra-batch preemption DOES have an analog. One refresh can
//! condemn every mount under the root at once, so this queue's burst size is the
//! namespace's, and each entry drives up to two revealed walks plus two whole-root
//! reseeds on failure. Servicing that snapshot whole defers both halves of the
//! contract at once — `SourceHandle::shutdown` joins this thread, and not one
//! event is read for the duration, which is a `FAN_Q_OVERFLOW` rather than mere
//! latency. So [`service_control`] bounds every step of it: the outstanding set
//! itself is bounded and coalescing at the point a message is POSTED
//! ([`Mailbox`] — at most [`MAX_QUEUED_ADMITS`] bodies plus ONE recovery cutoff,
//! however long the producer runs), the admissions run to a quota
//! ([`ADMIT_QUOTA_PER_PASS`]), shutdown is re-checked off the mailbox AND off the
//! out-of-band [`WakeState::request_shutdown`] flag between admissions and
//! between the retries of one walk ladder, and a backlog past
//! [`MAX_QUEUED_ADMITS`] collapses into one root-wide recovery answered by ONE
//! message instead of one reply per ticket.
//!
//! The mailbox replaced an unbounded channel, and the two properties it buys are
//! not cosmetic: a queued burst costs ONE recovery rather than one per receive
//! budget, and sustained production while a slow reseed runs stays bounded rather
//! than growing a queue that amplifies into back-to-back whole-tree walks. The
//! argument for why coalescing is a DISCHARGE and not a discard is on [`Mailbox`].
//!
//! A shutdown observed alongside a pending admission WINS, and the admission is
//! abandoned unrun and unanswered: teardown takes priority over every long op
//! here, and the scope whose cover was parked on that request is ending — its
//! coverage obligation ends with its own terminal record, not with a cover for a
//! subtree nobody is subscribed to any more.
//!
//! What a conceded walk COSTS differs by walk, and the difference is the recovery
//! left: a move-in walk and an admission reseed that fail still have a full reseed
//! to fall back on, so they degrade to the loss barrier; the reseed IS that
//! fallback, so its own failure is the terminal.

use std::{
  collections::VecDeque,
  os::fd::OwnedFd,
  panic::{AssertUnwindSafe, catch_unwind},
  sync::Arc,
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
  fid::{AbiMismatch, FANOTIFY_METADATA_VERSION, decode_events},
  map::FidMap,
  source::{AdmitWalk, MAX_WALK_DECLINES, ReseedContext, WalkSeed},
};
use crate::os::{AdmitOutcome, AdmitReport, AdmitRequest};

/// What the reader shares with the handle side: the ordered queue, the
/// transport budget/dedups, and the live stats the operator polls.
pub(crate) struct ReaderShared {
  pub(crate) queue: async_channel::Sender<crate::os::SourceMessage>,
  pub(crate) transport: transport::TransportState,
  /// How many bytes one `read` of the instance may take, from the configured
  /// native buffer size.
  pub(crate) buffer_bytes: usize,
  /// The atomic stats the reader writes (map size, walk timings, memo tallies)
  /// and [`Watcher::backend_stats`](crate::Watcher::backend_stats) snapshots.
  pub(crate) stats: std::sync::Arc<BackendStatsShared>,
}

/// One control request. fanotify has no ARM traffic (the mark is
/// kernel-recursive), but it does have admission traffic: the core cannot touch
/// the [`FidMap`] — the reader owns it — so the operations that must extend or
/// rebuild it from outside an event travel here.
pub(crate) enum Control {
  /// Quiesce and exit. Takes priority over everything else in the inbox.
  Shutdown,
  /// Admit the ground a departed mount revealed, then answer the ticket so the
  /// core may release the cover it parked on this round trip.
  Admit(AdmitRequest),
  /// Reseed the WHOLE map from the root and answer with one
  /// [`RootRecovery`](crate::os::RootRecovery) whose cutoff is this request's
  /// ticket. The root-scope form of [`Admit`](Self::Admit), sent when the core has
  /// decided that no located answer will do — it fails closed, or it collapsed a
  /// departure burst.
  Recover(crate::os::RecoveryRequest),
  /// The core's current [frame epoch](crate::os::AdmitRequest::epoch) — the count
  /// of worlds it has adopted for this scope.
  ///
  /// The one control message that asks for NOTHING and answers nothing: it
  /// carries no ticket, opens no round trip, and the reader discharges it simply
  /// by remembering it ([`Mailbox::frame_epoch`]). It exists so the reader's own
  /// autonomous whole-root reseed — the one no request asked for — can stamp its
  /// generation with a core-owned, non-recyclable counter instead of a mount id
  /// the kernel re-issues (see
  /// [`WalkReach::WholeRoot::epoch`](crate::os::WalkReach)).
  ///
  /// Published on every non-stale mount refresh rather than only on a change, so
  /// a reader spawned into a scope whose epoch has already moved (a world swap,
  /// or simply the birth adoption) is SEEDED by that scope's first refresh rather
  /// than left claiming a world it was never told about.
  Frame(u64),
}

/// The control state the handle and the reader SHARE — bounded and coalescing by
/// construction, so what a sender can hand over is not a queue whose length the
/// reader must chase.
///
/// # Why this is not a channel
///
/// It was an unbounded `mpsc`, and both of the properties below were impossible
/// with one.
///
/// - **A queued burst must cost ONE recovery.** The reader drains before it
///   services, so a drain that stopped at a per-pass budget executed and cleared
///   the accumulated recovery cutoff while the rest of the burst was still
///   unreceived — and then recovered again for the remainder. An N-message burst
///   already sitting in the channel paid `ceil(N / budget)` whole-tree reseeds
///   for what is, by the cutoff rule, one obligation.
/// - **Production must stay bounded under SUSTAINED arrivals.** A scope that
///   fails closed asks for a recovery on every authoritative refresh. With an
///   unbounded channel those accumulated while a slow reseed ran — the queue grew
///   without bound, and each pass turned another budget's worth of them into
///   another whole-tree walk, so the reader could stop reading events
///   indefinitely while the kernel queue filled behind it (`FAN_Q_OVERFLOW`, a
///   real loss).
///
/// So the coalescing happens where the message is POSTED rather than after a
/// bounded slice of it has been received. What this holds is the whole outstanding
/// obligation at any instant: at most [`MAX_QUEUED_ADMITS`] admission bodies, at
/// most ONE recovery cutoff, and one sticky shutdown flag.
///
/// # Coalescing is not discarding
///
/// The rule the inbox has always had — no message is silently discarded — is
/// unchanged, and it is what makes folding legal. A `Control::Recover` carries
/// exactly one thing the reader owes back: a ticket, answered by ONE
/// [`RootRecovery`](crate::os::RootRecovery) whose cutoff discharges every ticket
/// at or below it. Tickets are minted from the core's monotone counter, so a set
/// of them is discharged in full by their MAXIMUM. Folding two into their max
/// therefore answers both — it is the same discharge the backlog collapse and
/// [`take_recovery`](ControlInbox::take_recovery) already performed,
/// moved ahead of the queue instead of behind a slice of it.
///
/// The obligation that must NOT be folded away is a post-snapshot one: a ticket
/// minted after the current reseed's walk began names ground that walk may not
/// have seen. That is why the fold has two homes and not one — the cutoff the
/// reader took OUT (the current recovery, on `run_root_recovery`'s stack) and the
/// slot here that re-accumulates while the walk runs (the follow-up). At most one
/// of each exists, so sustained arrivals cost one extra walk, never one per
/// arrival and never a lost ticket.
struct Mailbox {
  /// Admission bodies posted and not yet run, in arrival order. Capped at
  /// [`MAX_QUEUED_ADMITS`]; past that the request BODY is dropped and its ticket
  /// folds into [`recovery`](Self::recovery).
  admits: VecDeque<AdmitRequest>,
  /// The highest-ticketed request owed the WHOLE-ROOT recovery, if any is owed: a
  /// `Control::Recover` the core sent, the overflow of the backlog cap, a request
  /// the reader's own ladder escalated, or any of them folded together. Never
  /// dropped — a ticket the core parked a cover on is always answered — but never
  /// accumulated either, because one recovery answers the whole prefix at or below
  /// it.
  ///
  /// It holds the whole [`RecoveryRequest`](crate::os::RecoveryRequest) and not
  /// just the ticket: the reply must carry the issuing frame EPOCH back too, and
  /// the epoch that belongs on it is the newest folded obligation's — the one
  /// whose ticket is the cutoff.
  recovery: Option<crate::os::RecoveryRequest>,
  /// A `Shutdown` has been posted. Sticky: teardown is terminal.
  shutdown: bool,
  /// The newest [frame epoch](Control::Frame) the core has published for this
  /// scope, as a MAXIMUM over everything it has ever sent — the `Control::Frame`
  /// publications and the epoch every admission and recovery request carries.
  ///
  /// Monotone by construction and never recycled: every value folded in was the
  /// core's own epoch at some past moment, and that counter only ever advances, so
  /// this can never run AHEAD of the core's current world. That one-sided error is
  /// what makes it usable as a stamp — a report carrying a stale value is refused
  /// and costs one generation, while a report carrying a value the core has not
  /// reached is impossible.
  ///
  /// Starts at zero, which is the epoch a scope is born at; a source spawned into
  /// a scope that has already adopted worlds reads zero until that scope's next
  /// refresh publishes, and its autonomous generations are refused until then.
  frame_epoch: u64,
  /// The reader still holds its [`ControlInbox`]. Cleared by that inbox's `Drop`,
  /// which is the `mpsc` "the receiver is gone" signal in the one shape a shared
  /// mailbox can give it: a sender that posts into a mailbox no reader will ever
  /// read again would strand the core waiting on a reply that cannot come.
  open: bool,
}

impl Mailbox {
  /// Folds one request into the outstanding recovery, keeping the HIGHEST TICKET
  /// and the epoch that came with it. The cutoff must cover every ticket the
  /// recovery discharges, and tickets are monotone, so the maximum is exactly that
  /// bound — and its epoch is the newest statement about the world the walk this
  /// authorizes will run in.
  fn fold_recovery(&mut self, request: crate::os::RecoveryRequest) {
    self.recovery = Some(match self.recovery {
      Some(current) if current.ticket >= request.ticket => current,
      _ => request,
    });
  }

  /// Accepts one control message into the outstanding obligation.
  ///
  /// Every message that carries the core's epoch advances
  /// [`frame_epoch`](Self::frame_epoch) as a MAXIMUM, whatever else it does — a
  /// request is a statement about the world it was issued in just as much as the
  /// bare publication is, and reading it here means a scope with live admission
  /// traffic needs no publication to stay current.
  fn post(&mut self, message: Control) {
    match message {
      Control::Shutdown => self.shutdown = true,
      Control::Frame(epoch) => self.observe_epoch(epoch),
      Control::Recover(request) => {
        self.observe_epoch(request.epoch);
        self.fold_recovery(request);
      }
      Control::Admit(request) => {
        self.observe_epoch(request.epoch);
        if self.admits.len() < MAX_QUEUED_ADMITS {
          self.admits.push_back(request);
        } else {
          self.fold_recovery(recovery_of(&request));
        }
      }
    }
  }

  /// Folds one published epoch in, keeping the maximum. Never a plain store: the
  /// mailbox is posted into from the driver's effect drain in whatever order the
  /// effects were queued, and a stamp that could go BACKWARDS would refuse
  /// generations from the world the core actually holds.
  fn observe_epoch(&mut self, epoch: u64) {
    self.frame_epoch = self.frame_epoch.max(epoch);
  }
}

/// The recovery obligation one admission request collapses into: its ticket is
/// what a cutoff must cover, its epoch is the world the core issued it in.
///
/// Both places an admission folds — the backlog cap here, and the reader's own
/// blind/superseded rung ([`ControlInbox::escalate`]) — read it through this, so
/// the two can never disagree about what a collapsed request still owes.
fn recovery_of(request: &AdmitRequest) -> crate::os::RecoveryRequest {
  crate::os::RecoveryRequest {
    ticket: request.ticket,
    epoch: request.epoch,
  }
}

/// Takes the mailbox lock, recovering from poisoning rather than propagating it.
///
/// Nothing under this lock can panic (a `VecDeque` push/pop, an `Option::max`, a
/// `bool` store), so a poisoned mailbox means some other thread unwound while
/// holding it — and the state is still structurally intact. Killing the driver
/// thread over that would turn a reader-side panic (already reported as the
/// terminal `Fatal`) into a second, unrelated failure.
fn lock(mailbox: &std::sync::Mutex<Mailbox>) -> std::sync::MutexGuard<'_, Mailbox> {
  mailbox
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The handle's end of the control mailbox.
pub(crate) struct ControlPost(Arc<std::sync::Mutex<Mailbox>>);

impl ControlPost {
  /// Posts one control message, answering whether the reader is still there to
  /// act on it.
  ///
  /// `false` is the `mpsc::Sender::send` error in this shape: the reader's inbox
  /// has been dropped, so nothing will ever run this request or answer its
  /// ticket, and the caller must resolve the round trip itself.
  pub(crate) fn send(&self, message: Control) -> bool {
    let mut mailbox = lock(&self.0);
    if !mailbox.open {
      return false;
    }
    mailbox.post(message);
    true
  }

  /// Posts a whole BURST of admissions INDIVISIBLY — one lock, every request, and
  /// the caller's one wake behind it.
  ///
  /// The atomicity is the point, and it is a correctness property rather than a
  /// saving. One mount-table refresh can condemn many boundaries at once, and the
  /// core parks a cover on each; posted one at a time, the reader can wake on the
  /// first, find the rest of the burst not yet posted, and SNAPSHOT only what it
  /// can see ([`ControlInbox::take_recovery`]). The remainder then arrives while
  /// that snapshot's whole-root walk is running and buys a SECOND whole-root walk
  /// and a second report — and at the supported boundary budget of one, the first
  /// report still holds the only permit, so the second kills a source that had
  /// nothing wrong with it.
  ///
  /// Under one lock there is no such half-posted state to snapshot: the burst is
  /// either wholly invisible to the reader or wholly visible, so the fold that
  /// makes a burst cost one walk sees all of it.
  ///
  /// `false` is the same refusal [`send`](Self::send) gives, and it is
  /// all-or-nothing for the same reason: an inbox that is gone will run none of
  /// these, so the caller resolves every one of them itself.
  pub(crate) fn send_all(&self, requests: Vec<AdmitRequest>) -> bool {
    let mut mailbox = lock(&self.0);
    if !mailbox.open {
      return false;
    }
    for request in requests {
      mailbox.post(Control::Admit(request));
    }
    true
  }

  /// The outstanding obligation, for the cells that assert the mailbox stays
  /// bounded under sustained production: `(queued admission bodies, whether a
  /// recovery is owed)`.
  ///
  /// Read from the POSTING end so a cell can observe it from inside a walk the
  /// reader is running — which is the only moment the sustained-arrival bound is
  /// observable at all.
  #[cfg(test)]
  fn outstanding(&self) -> (usize, bool) {
    let mailbox = lock(&self.0);
    (mailbox.admits.len(), mailbox.recovery.is_some())
  }
}

/// The reader's end of the control mailbox.
///
/// # It cannot discard a message, and that is its entire reason to exist
///
/// The three places the reader observes control used to read
/// `matches!(control.try_recv(), Ok(Control::Shutdown))`. That expression
/// RECEIVES — the message leaves the channel — and then evaluates to `false`
/// for any variant that is not `Shutdown`, dropping it on the floor. With one
/// variant it was harmless; the moment a second exists it is a silent-loss hole
/// with no diagnostic at all: the core would sit holding a parked cover for a
/// reply that was consumed and thrown away.
///
/// A shared mailbox has no shape that can discard: there is no receive at all,
/// only reads of an outstanding obligation that is cleared by DISCHARGING it. A
/// shutdown is STICKY (once seen it is terminal; there is nothing to un-see), and
/// admissions queue in arrival order.
///
/// # Everything it holds is O(1) or bounded
///
/// A capped deque plus two words, and that is the bound the reader relies on: one
/// `service_control` pass can never face more than [`MAX_QUEUED_ADMITS`] bodies
/// plus one cutoff, however long the producer has been running, so the work
/// between two reads of the fanotify fd is bounded by construction rather than by
/// a per-pass receive budget that cut obligations in half. The `ADMIT_QUOTA_PER_PASS`
/// slice bounds it further still.
pub(crate) struct ControlInbox(Arc<std::sync::Mutex<Mailbox>>);

impl Drop for ControlInbox {
  fn drop(&mut self) {
    lock(&self.0).open = false;
  }
}

/// Creates one control mailbox: the handle's posting end and the reader's end.
pub(crate) fn control_mailbox() -> (ControlPost, ControlInbox) {
  let mailbox = Arc::new(std::sync::Mutex::new(Mailbox {
    admits: VecDeque::new(),
    recovery: None,
    shutdown: false,
    frame_epoch: 0,
    open: true,
  }));
  (ControlPost(Arc::clone(&mailbox)), ControlInbox(mailbox))
}

impl ControlInbox {
  /// Whether a shutdown has been posted.
  fn shutting_down(&self) -> bool {
    lock(&self.0).shutdown
  }

  /// Whether an admission body is queued — the PEEK the credit claim needs, so a
  /// pass with nothing to run never claims (and therefore never releases, and
  /// therefore never notifies its own reader).
  fn admit_pending(&self) -> bool {
    !lock(&self.0).admits.is_empty()
  }

  /// The next admission to run, in arrival order.
  fn next_admit(&mut self) -> Option<AdmitRequest> {
    lock(&self.0).admits.pop_front()
  }

  /// Whether a whole-root recovery is owed.
  fn recovering(&self) -> bool {
    lock(&self.0).recovery.is_some()
  }

  /// The newest [frame epoch](Control::Frame) the core has published — the stamp
  /// an AUTONOMOUS whole-root generation carries.
  ///
  /// Read once, BEFORE the walk it will stamp: the value may advance while that
  /// walk runs, and a report claiming the newer world would be claiming one its
  /// walk never saw the whole of.
  fn frame_epoch(&self) -> u64 {
    lock(&self.0).frame_epoch
  }

  /// Whether anything at all is still owed a reply.
  fn has_work(&self) -> bool {
    let mailbox = lock(&self.0);
    !mailbox.admits.is_empty() || mailbox.recovery.is_some()
  }

  /// Takes the ONE obligation the whole-root recovery answers — its cutoff ticket
  /// and the epoch to stamp the reply with — discharging every queued request
  /// along with it: a reseed from the root subsumes every located walk they would
  /// have driven, so their bodies go and their tickets fold into the same maximum.
  ///
  /// The cutoff is a SNAPSHOT, taken before the walk it authorizes runs. A ticket
  /// posted while that walk is in flight names ground the walk may not have
  /// reached, so it deliberately does NOT fold into this cutoff: it lands in the
  /// slot this call just emptied and becomes the one follow-up recovery.
  ///
  /// Returns `None` when no recovery is owed, which the caller treats as "nothing
  /// to do" — it is never a reason to send a report with no cutoff.
  fn take_recovery(&mut self) -> Option<crate::os::RecoveryRequest> {
    let mut mailbox = lock(&self.0);
    let mut recovery = mailbox.recovery.take()?;
    for request in mailbox.admits.drain(..) {
      if request.ticket > recovery.ticket {
        recovery = recovery_of(&request);
      }
    }
    Some(recovery)
  }

  /// Folds one admission the reader's own ladder gave up on into the outstanding
  /// recovery — the [`Blind`](AdmitVerdict::Blind)/[`Stale`](AdmitVerdict::Stale)
  /// rung's whole disposal.
  ///
  /// It is the SAME fold the backlog cap performs and answers the ticket the same
  /// way (one recovery discharges every ticket at or below its cutoff), so nothing
  /// is discarded by routing the escalation through the slot instead of walking on
  /// the spot. What it buys is that a BURST of them costs one walk: the slot
  /// coalesces at post time, and [`take_recovery`](Self::take_recovery) then drains
  /// the requests still queued behind this one into the same cutoff — so 64
  /// requests superseded by one root re-mount reseed once and report once, rather
  /// than driving 64 whole-root walks and 64 reports (the second of which cannot
  /// even claim a boundary permit at a budget of one, and kills a healthy source).
  fn escalate(&self, request: &AdmitRequest) {
    lock(&self.0).fold_recovery(recovery_of(request));
  }
}

/// The most admission REQUESTS one mailbox holds before the backlog collapses
/// into a single root-wide recovery.
///
/// A mass unmount is one refresh that condemns every departed record at once, so
/// this queue's natural burst size is "every mount under the root". Each entry
/// carries a `PathBuf` and drives up to two revealed walks plus, on failure, two
/// whole-root reseeds — so an uncapped backlog is an unbounded amount of work the
/// reader must get through while the kernel queue keeps filling behind it.
///
/// Sized so it binds only the burst: a handful of simultaneous departures is
/// ordinary and each deserves its own located walk, while sixty-four at once is a
/// namespace-wide event whose one root-wide reseed is both cheaper and STRONGER
/// than sixty-four located ones (it re-walks everything, and the `Overflow` behind
/// it dominates every located cover it replaces).
///
/// It is also the mailbox's whole memory bound, which the unbounded channel in
/// front of it used to defeat: a request past the cap is folded rather than
/// queued, so a producer that never stops still leaves at most this many bodies
/// resident.
const MAX_QUEUED_ADMITS: usize = 64;

/// The most admissions one [`service_control`] pass runs before returning to the
/// reader's event loop.
///
/// The teardown half of the fairness contract is already covered by the shutdown
/// re-check between admissions; this bounds the EVENT half. A pass that ran the
/// whole backlog would read no events for the duration of every walk in it, and
/// the kernel queue that fills meanwhile is a `FAN_Q_OVERFLOW` — a real loss —
/// rather than mere latency. Four keeps the round trips moving (the core's cover
/// waits on each) while capping the gap between two reads at four walks.
const ADMIT_QUOTA_PER_PASS: usize = 4;

/// How one step that can run a WALK LADDER finished.
///
/// The reader's long ops are ladders — two attempts at a located walk, two at a
/// whole-root reseed — and each ATTEMPT is a fresh walk, not a resumption of the
/// one before it. So the module's must-complete rule ("a half-built map is worse
/// than a slow teardown") binds the walk IN FLIGHT and nothing beyond it: between
/// two attempts there is no partial state to protect, and a teardown that landed
/// while the first one ran must not be made to wait out up to three more
/// potentially million-directory walks. Every ladder therefore carries the
/// shutdown predicate and answers [`Abandoned`](Self::Abandoned) at the first
/// gap after it reads true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepExit {
  /// The step ran to its own verdict; the reader carries on.
  Done,
  /// The stream died; the terminal `Fatal` is already signaled and the reader
  /// exits.
  Died,
  /// A teardown was observed BETWEEN attempts. Whatever the step had left is
  /// abandoned unrun and unanswered, and the reader exits — the same
  /// teardown-priority rule that abandons a queued admission, for the same
  /// reason: the scope whose cover was parked on it is ending, and its coverage
  /// obligation ends with its own terminal record.
  Abandoned,
}

/// Why [`service_control`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlExit {
  /// The inbox is drained and every admission in it has run; carry on.
  Continue,
  /// The pass spent its [`ADMIT_QUOTA_PER_PASS`] with work still queued. Identical
  /// to [`Continue`](Self::Continue) for the caller that is about to read events
  /// anyway; the caller that is about to BLOCK must keep a wake pending instead,
  /// or the remaining admissions wait for unrelated traffic.
  Deferred,
  /// A `Shutdown` was observed. The reader exits; any admission still queued is
  /// abandoned unrun (see the module doc's teardown-priority rule).
  Shutdown,
  /// An admission's recovery ladder ran out: the terminal `Fatal` is already
  /// signaled and the reader exits.
  Died,
  /// The pass stopped short with an obligation still owed because the transport
  /// had no BOUNDARY credit for the report that obligation produces.
  ///
  /// Nothing was taken out of the mailbox and nothing was walked, so nothing is
  /// discarded — the obligation is exactly where it was. Unlike
  /// [`Deferred`](Self::Deferred) the caller must NOT keep a wake pending: the
  /// pass would repeat identically until the driver consumed a report, which is a
  /// spin rather than progress. The edge that ends the wait is the RELEASE of a
  /// boundary slot ([`transport::BoundaryCredit`]), which the transport routes
  /// back to this reader's `WakeState`.
  Blocked,
}

/// Runs a BOUNDED slice of the outstanding control obligation, in one step that
/// no message can escape.
///
/// Shutdown is checked FIRST and wins outright: teardown priority is the
/// reader-fairness contract, and a scope being torn down is owed no cover. It is
/// then re-checked BETWEEN admissions so a shutdown that lands during the first
/// walk of a backlog preempts the rest instead of queueing behind all of them —
/// and, through the predicate the walk ladders now carry, BETWEEN the retries of
/// one admission too. Only the walk in flight is waited on: the bounded
/// must-complete case the module doc's table names.
///
/// The check is the OUT-OF-BAND flag as well as the posted message: a teardown
/// raises [`WakeState::request_shutdown`] before it posts the terminal one, so a
/// shutdown that lands mid-pass preempts at the very next check without reading
/// the mailbox at all.
///
/// Four properties, and the first is why the others are not optional:
///
/// - **no message is discarded.** Every ticket the mailbox accepted is either run
///   and answered, folded into the recovery cutoff that answers it, or abandoned
///   by a shutdown that ends the scope. Folding is a discharge and not a drop —
///   see [`Mailbox`], where the argument lives with the fold.
/// - **the outstanding set is bounded.** [`Mailbox`] coalesces AT POST: at most
///   [`MAX_QUEUED_ADMITS`] bodies plus one recovery cutoff exist at any instant,
///   whatever the producer has been doing, so one pass faces a bounded amount of
///   work by construction rather than by a receive budget that could cut an
///   obligation in half.
/// - **the admission slice is bounded.** [`ADMIT_QUOTA_PER_PASS`] admissions run,
///   then the reader returns to reading events with the rest still queued.
/// - **the backlog is bounded.** Past [`MAX_QUEUED_ADMITS`] the whole outstanding
///   set collapses into ONE root-wide reseed, answered by ONE
///   [`RootRecovery`](crate::os::RootRecovery) whose cutoff discharges every
///   ticket at or below it. That is not a new degrade: it is the rung
///   [`AdmitVerdict::Blind`] already falls to, and the root cover it carries
///   dominates every located cover it stands in for. The reseed's own whole-root
///   declines re-record the boundaries that are still live, so a collapsed
///   `StillCovered` is not lost — it comes back as a fresh observation.
fn service_control(
  inbox: &mut ControlInbox,
  map: &mut FidMap,
  reseed: &ReseedContext,
  shared: &ReaderShared,
  shutdown_requested: &dyn Fn() -> bool,
) -> ControlExit {
  service_control_with(
    inbox,
    map,
    ReportContext {
      stats: &shared.stats,
      transport: &shared.transport,
    },
    |location, frame, budget| reseed.walk_revealed(location, frame, budget),
    || reseed.walk(),
    |msg| shared.queue.try_send(msg).is_ok(),
    shutdown_requested,
  )
}

/// [`service_control`]'s body, pure over the two walk closures and the send
/// closure — the ONLY fd-touching or queue-touching parts — exactly as
/// [`run_admission`] and [`process_decoded`] are. The quota, the between-admission
/// preemption and the backlog collapse are all decided here, so all three are
/// testable over a real [`FidMap`] with stub walks and a capturing sender, and a
/// shutdown can be staged INSIDE a walk rather than raced against one.
///
/// # AT MOST ONE whole-root recovery per pass
///
/// A recovery YIELDS the pass — it returns rather than carrying on into the
/// admission quota — and that is a hard bound, not fairness tuning. The recovery's
/// [`RootRecovery`](crate::os::RootRecovery) is indivisible and therefore NOT
/// droppable, and the boundary budget's supported floor is ONE, so two recovery
/// reports produced back to back inside a single pass would put the second one on
/// a queue with no slot left for it.
///
/// The pass could reach two only by taking a SECOND obligation that arrived while
/// the first one's walk was running (the first snapshot drained everything queued
/// before it). Deferring that one costs a re-entry — the caller re-enters at once,
/// and [`Deferred`](ControlExit::Deferred) is exactly the signal that arranges it
/// — and nothing is discarded by the deferral, because the obligation stays in the
/// mailbox slot that coalesces it.
///
/// It is the reader-side half of the burst rule. The other half is that a
/// core-produced burst arrives INDIVISIBLY ([`ControlPost::send_all`]), so the
/// first snapshot sees all of it and one burst never becomes two obligations in
/// the first place.
///
/// # A pass boundary is not a CREDIT boundary
///
/// One recovery per pass is not on its own a seal, and reading it as one is what
/// killed healthy sources. The permit a report holds is released by the DRIVER, on
/// another thread, whenever it ingests the message — while this caller re-enters
/// immediately (the self-wake on `Deferred` makes the `poll` return at once). Two
/// ordinary bursts arriving a moment apart therefore met an exhausted counter at
/// `os_batch_capacity = 1` and signalled the terminal `Fatal` for nothing worse
/// than consumer scheduling latency.
///
/// So every step here that can produce a boundary report claims its slot BEFORE
/// the obligation leaves the mailbox. A claim that fails walks nothing, consumes
/// nothing, and answers [`Blocked`](ControlExit::Blocked): the caller waits, and
/// the RELEASE of a slot is the edge that ends the wait
/// ([`transport::BoundaryCredit`]). Deferring costs a round trip; dying costs the
/// scope.
fn service_control_with<A, R, Q>(
  inbox: &mut ControlInbox,
  map: &mut FidMap,
  report: ReportContext<'_>,
  mut admit_walk: A,
  mut reseed_walk: R,
  mut send: Q,
  shutdown_requested: &dyn Fn() -> bool,
) -> ControlExit
where
  A: FnMut(&std::path::Path, crate::os::ScopeFrame, Option<usize>) -> std::io::Result<AdmitWalk>,
  R: FnMut() -> std::io::Result<WalkSeed>,
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  if inbox.shutting_down() || shutdown_requested() {
    return ControlExit::Shutdown;
  }
  if inbox.recovering() {
    // CREDIT BEFORE THE OBLIGATION LEAVES THE MAILBOX. The report a recovery
    // produces is indivisible and not droppable, so a walk begun without a slot to
    // deliver its result on has already spent the map reseed and can only end in
    // the terminal. Claiming first turns "no credit" into a wait that costs
    // nothing and discards nothing.
    let Some(permit) = transport::BudgetPermit::acquire_deferred_boundaries(report.transport)
    else {
      return ControlExit::Blocked;
    };
    match run_root_recovery(
      inbox,
      map,
      report,
      permit,
      &mut reseed_walk,
      &mut send,
      shutdown_requested,
    ) {
      StepExit::Done => return pass_end(inbox),
      StepExit::Died => return ControlExit::Died,
      StepExit::Abandoned => return ControlExit::Shutdown,
    }
  }
  for _ in 0..ADMIT_QUOTA_PER_PASS {
    // Peeked rather than popped, because the credit claim below must not happen
    // when there is nothing to spend it on: a claim taken and released on an empty
    // pass would notify this very reader's own wake and turn each park into an
    // immediate return.
    if !inbox.admit_pending() {
      break;
    }
    let Some(permit) = transport::BudgetPermit::acquire_deferred_boundaries(report.transport)
    else {
      return ControlExit::Blocked;
    };
    let Some(request) = inbox.next_admit() else {
      break;
    };
    match run_admission(
      inbox,
      map,
      report,
      request,
      permit,
      &mut admit_walk,
      &mut send,
      shutdown_requested,
    ) {
      StepExit::Done => {}
      StepExit::Died => return ControlExit::Died,
      StepExit::Abandoned => return ControlExit::Shutdown,
    }
    // Between admissions: a shutdown posted while the walk above ran preempts the
    // remainder of the backlog here. Without this the whole snapshot runs first
    // and `SourceHandle::shutdown` — which joins this thread — waits out every
    // walk in it. The mailbox is shared, so the read is live; there is no receive
    // to repeat.
    //
    // It is ALSO the teardown gate on the recovery below: an admission whose
    // ladder ran out escalates by folding into the slot rather than walking, so a
    // teardown observed here preempts the whole-root walk that escalation would
    // otherwise buy — the check the rung used to make for itself, in the one place
    // that now runs the walk.
    if inbox.shutting_down() || shutdown_requested() {
      return ControlExit::Shutdown;
    }
    if inbox.recovering() {
      let Some(permit) = transport::BudgetPermit::acquire_deferred_boundaries(report.transport)
      else {
        return ControlExit::Blocked;
      };
      match run_root_recovery(
        inbox,
        map,
        report,
        permit,
        &mut reseed_walk,
        &mut send,
        shutdown_requested,
      ) {
        StepExit::Done => return pass_end(inbox),
        StepExit::Died => return ControlExit::Died,
        StepExit::Abandoned => return ControlExit::Shutdown,
      }
    }
  }
  pass_end(inbox)
}

/// How a pass that neither died nor was torn down ends: [`Deferred`] while
/// anything is still owed a reply, [`Continue`] once nothing is.
///
/// [`Deferred`]: ControlExit::Deferred
/// [`Continue`]: ControlExit::Continue
fn pass_end(inbox: &ControlInbox) -> ControlExit {
  if inbox.has_work() {
    ControlExit::Deferred
  } else {
    ControlExit::Continue
  }
}

/// Runs ONE whole-root recovery and answers it with ONE message: reseed the whole
/// map from the root, then send the walk's complete generation, the ticket cutoff
/// it discharges and the loss it implies, together, as a single
/// [`RootRecovery`](crate::os::RootRecovery).
///
/// This is both the backlog collapse and the core's explicit
/// [`Control::Recover`], because they want exactly the same work done.
///
/// # Why one message and not three
///
/// It was three — a `Boundaries` report, an `Overflow`, and one `Admitted` per
/// discharged ticket — and each could be dropped independently. When the boundary
/// report lost its permit it was dropped for a bare loss signal, while the replies
/// still told the core to retire every record its departure verdict had taken. The
/// mounts the reseed found STILL THERE were then recorded nowhere: no later
/// departure at those locations was derivable, their revealed ground was never
/// admitted, and events on it were rejected as outside the map with no signal at
/// all. A positional cover cannot stand in for evidence a LATER departure needs.
///
/// So the three facts travel together and the message is NOT droppable — which is
/// why its slot is claimed BEFORE the obligation leaves the mailbox
/// ([`service_control_with`]) rather than at the send: a pass with no credit walks
/// nothing and waits ([`ControlExit::Blocked`]), so an unconsumed queue is never
/// read as a death. [`forward_root_recovery`] therefore takes the caller's permit
/// and cannot fail for credit at all.
///
/// Returns [`StepExit::Died`] when the reseed conceded blindness — the terminal
/// `Fatal` is signaled and the reader exits, exactly as it does on the ladder's
/// blind rung. The cutoff is then left unanswered on purpose: the source is dying,
/// and its terminal record ends every scope obligation with it.
///
/// [`StepExit::Abandoned`] is the same disposal for the same reason, reached when
/// a teardown lands between the reseed's two attempts: the cutoff is already out
/// of the mailbox and is deliberately not put back, because the scope it belongs
/// to is ending.
fn run_root_recovery<R, Q>(
  inbox: &mut ControlInbox,
  map: &mut FidMap,
  report: ReportContext<'_>,
  permit: transport::BudgetPermit,
  reseed_walk: R,
  mut send: Q,
  shutdown_requested: &dyn Fn() -> bool,
) -> StepExit
where
  R: FnMut() -> std::io::Result<WalkSeed>,
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  let ReportContext { stats, .. } = report;
  let Some(recovery) = inbox.take_recovery() else {
    return StepExit::Done;
  };
  let mut generation = ReseedGeneration::default();
  match reseed_after_loss(
    map,
    report,
    reseed_walk,
    &mut generation,
    &mut send,
    shutdown_requested,
  ) {
    StepExit::Done => {}
    exit => return exit,
  }
  let map_stats = map.stats();
  stats.set_map(map_stats.directories, map_stats.memo_generation);
  forward_root_recovery(
    permit,
    crate::os::RootRecovery {
      declined: generation.declined,
      cutoff: recovery.ticket,
      // The core's own stamp, echoed untouched, beside the frame THIS walk read
      // off the fd it reopened. Neither is a value the other side can re-derive:
      // the epoch says which world asked, the mount id says which root answered,
      // and the core installs the generation only when both are still its own.
      epoch: recovery.epoch,
      root_mnt_id: generation.root_mnt_id,
    },
    &mut send,
  );
  StepExit::Done
}

/// Starts the reader thread. The fd, the wake eventfd, the seeded `FidMap`, and
/// the reseed context live and die with it. A spawn failure (thread or memory
/// exhaustion) is a typed [`SourceError::StartFailed`] on the never-live path —
/// no events, the probed fd closed as the returned closure drops.
pub(crate) fn start(
  fd: OwnedFd,
  wake: Arc<WakeState>,
  control: ControlInbox,
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
      let mut inbox = control;
      let outcome = catch_unwind(AssertUnwindSafe(|| {
        run(&fd, &wake, &mut inbox, &mut map, &reseed, &shared);
      }));
      // The payload is retired inside its own boundary. Dropped as this closure
      // returns, one whose own `Drop` panics would unwind the thread body after the
      // terminal below was already sent — and `shutdown` then JOINS this thread, so
      // that payload would land on the teardown worker, which is the executor the
      // whole teardown contract is built to keep unbounded and unguarded work off.
      if let Err(payload) = outcome {
        let _ = tributary_proto::unwind::dispose_panic_payload(payload);
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
  inbox: &mut ControlInbox,
  map: &mut FidMap,
  reseed: &ReseedContext,
  shared: &ReaderShared,
) {
  // fanotify events are large (a metadata header plus variable-length FID
  // records with names); the 64 KiB default holds a dense read of them.
  let mut buf = vec![0u8; shared.buffer_bytes];
  loop {
    // Announce the intent to block, then service control before polling (the
    // lost-wakeup guard — see `WakeState`; a message enqueued before the fence is
    // visible here). An admission runs HERE, on the quiet path: this reader spends
    // nearly all its life blocked in the `poll` below, so a tree with no event
    // traffic reaches its admissions through this site alone. A wake landing while
    // the walk runs is not lost — it leaves the eventfd signalled, so the `poll`
    // returns at once and the `event_ready` service below observes it.
    wake.arm_park();
    match service_control(inbox, map, reseed, shared, &|| wake.shutdown_requested()) {
      ControlExit::Continue => {}
      // The pass stopped on its quota with admissions still queued, and this
      // caller is about to BLOCK. Signal the eventfd so the `poll` below returns
      // at once: the remaining admissions then run on the next pass, interleaved
      // with the event read this iteration still performs, rather than waiting for
      // unrelated traffic to wake a reader that already knows it has work. The
      // wake is armed BEFORE the poll, so it cannot be lost.
      ControlExit::Deferred => wake.wake(),
      // Stopped on transport credit, not on its own quota. Keeping a wake pending
      // here is exactly what must not happen: the pass would re-run, fail the same
      // claim, and self-wake again — a spin that starves the event reads instead of
      // waiting for the driver. Blocking is safe because the RELEASE of a boundary
      // slot wakes this reader (`transport::BoundaryCredit`), and the park was armed
      // before the claim was attempted, so a release that lands in between writes
      // the eventfd and the `poll` below returns at once.
      ControlExit::Blocked => {}
      ControlExit::Shutdown | ControlExit::Died => return,
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
      match service_control(inbox, map, reseed, shared, &|| wake.shutdown_requested()) {
        // `Deferred` needs no wake here: the loop re-parks at the top, where the
        // pre-park pass observes the same backlog and arms one.
        ControlExit::Continue | ControlExit::Deferred | ControlExit::Blocked => {}
        ControlExit::Shutdown | ControlExit::Died => return,
      }
    }
    if source_ready {
      match drain_events(fd, &mut buf, map, reseed, inbox, shared, wake) {
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
/// reader-teardown fairness contract — the `poll` loop's own control check is
/// reached only after `EAGAIN`, which never comes under load). The check sits at
/// the top of the loop, before the next read/decode, so a reseed or subtree walk
/// from the PREVIOUS buffer has fully completed before it runs: a shutdown that
/// lands mid-reseed quiesces cleanly at the next read boundary rather than
/// interrupting the walk. It services ADMISSIONS at the same point and for the
/// mirror-image reason: a sustained event stream never returns to the `poll` loop,
/// so an admission serviced only there would wait — and the core's parked cover
/// with it — for as long as the tree stayed busy.
///
/// It also PACES itself against the boundary-report credit, and does so before
/// each read rather than at the report: a buffer may drive a walk, a walk's report
/// is not droppable, and the only moment this producer still has somewhere to
/// leave its events is while they are in the kernel's queue ([`ReportCredit`]).
/// The wait that follows from that is the reader's, so it observes shutdown and a
/// closed receiver exactly as the rest of the loop does.
///
/// Returns [`DrainExit::Died`] when the stream died (fatal already signaled — a
/// failed read, a foreign event-metadata ABI version, a recovery that could not
/// restore sight, or a queue receiver that is gone), [`DrainExit::Shutdown`] on a
/// mid-drain shutdown — including one that lands while it waits for report credit
/// — and [`DrainExit::Parked`] when the instance drained clean.
fn drain_events(
  fd: &OwnedFd,
  buf: &mut [u8],
  map: &mut FidMap,
  reseed: &ReseedContext,
  inbox: &mut ControlInbox,
  shared: &ReaderShared,
  wake: &WakeState,
) -> DrainExit {
  loop {
    match service_control(inbox, map, reseed, shared, &|| wake.shutdown_requested()) {
      // A deferred backlog needs no wake on this path: the next read is the very
      // next statement, and the loop's own top services the rest between reads.
      // `Blocked` needs no wake on this path either, and for a stronger reason than
      // `Deferred` does: the next statement reads events, and the loop's own top
      // re-attempts the claim between every buffer.
      ControlExit::Continue | ControlExit::Deferred | ControlExit::Blocked => {}
      ControlExit::Shutdown => return DrainExit::Shutdown,
      ControlExit::Died => return DrainExit::Died,
    }
    // THE CREDIT COMES BEFORE THE EVENTS DO. A buffer can drive a walk, and a walk
    // owes a report that is not droppable — so the slot is claimed while the events
    // are still in the KERNEL's queue, which is the one place this producer can
    // leave them. Past the read there is nowhere: the map is reseeded and the
    // events are decoded, which is exactly why the exhausted counter used to be
    // read as a death sentence. See [`ReportCredit`].
    //
    // While this waits, the instance is NOT drained. That is the pressure, and its
    // overrun is `FAN_Q_OVERFLOW` — the ordered loss this reader already handles —
    // rather than a source failure.
    let report_credit = match reserve_report_credit(
      &shared.transport,
      wake,
      &|| shared.queue.is_closed(),
      || {
        // Only the WAKE fd. The instance is readable (that is why this reader is
        // here), so polling it would return at once and turn the wait into a spin;
        // the edge that matters is a released slot, and it comes through the
        // eventfd.
        let event = wake.event_fd();
        let mut fds = [PollFd::new(&event, PollFlags::IN)];
        match poll(&mut fds, None) {
          Ok(_) | Err(Errno::INTR) => Ok(()),
          Err(err) => Err(err.into()),
        }
      },
    ) {
      ReportCredit::Claimed(permit) => permit,
      // Nothing was read and nothing consumed: re-service control (a wake is as
      // likely to be a control post as a released slot) and re-attempt.
      ReportCredit::Woken => continue,
      ReportCredit::Shutdown => return DrainExit::Shutdown,
      ReportCredit::Closed => {
        signal_fatal_receiver_gone(&shared.transport, |msg| shared.queue.try_send(msg).is_ok());
        return DrainExit::Died;
      }
      ReportCredit::Failed(err) => {
        signal_fatal(shared, SourceError::ReadFailed { source: err });
        return DrainExit::Died;
      }
    };
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
    let decoded = match decode_events(&buf[..n]) {
      Ok(decoded) => decoded,
      // Not this buffer's defect but this FD's: the event-metadata ABI is fixed
      // for the descriptor's life, so the loss barrier would reseed, cover, and
      // hand the next read straight back here — forever, and never decoding a
      // notification. The terminal is the only exit that ends it, and the same
      // one a failed read takes.
      Err(mismatch) => {
        signal_fatal(
          shared,
          SourceError::ReadFailed {
            source: abi_mismatch_error(mismatch),
          },
        );
        return DrainExit::Died;
      }
    };
    match process_decoded(
      decoded,
      map,
      &BufferContext {
        report: ReportContext {
          stats: &shared.stats,
          transport: &shared.transport,
        },
        exclusions: reseed.exclusions(),
        // Sampled HERE, before the decode and therefore before any reseed this
        // buffer drives: the stamp on an autonomous generation must name the world
        // the walk started in.
        frame_epoch: inbox.frame_epoch(),
      },
      report_credit,
      || reseed.walk(),
      |subtree, subtree_fid, budget, declines| {
        reseed.walk_subtree(subtree, subtree_fid, budget, declines)
      },
      |msg| shared.queue.try_send(msg).is_ok(),
      &|| wake.shutdown_requested(),
    ) {
      StepExit::Done => {}
      StepExit::Died => return DrainExit::Died,
      // A teardown preempted a walk ladder inside the buffer: quiesce now rather
      // than after the walks it cut short would have finished.
      StepExit::Abandoned => return DrainExit::Shutdown,
    }
  }
}

/// Where one ladder step REPORTS: the counters it records into and the transport
/// its loss/fatal signalling is routed through.
///
/// These two travel together everywhere — the control pass, the root recovery, the
/// admission round trip, the post-loss reseed and every buffer — because they are
/// one concern: the source-wide state a step reports THROUGH, as opposed to the
/// [`FidMap`] it mutates and the effect closures it calls. Naming that concern once
/// keeps each step's argument list about what actually varies per call, and keeps
/// the pair from drifting apart inside a signature (which is how
/// [`reseed_after_loss`] came to take them three parameters apart).
///
/// `Copy` because it is two shared borrows: a step hands it to the steps it drives
/// without threading a reborrow through the ladder.
#[derive(Clone, Copy)]
struct ReportContext<'a> {
  /// Where the counters (memo hits/misses, map size, walk time, reseeds) land.
  stats: &'a BackendStatsShared,
  /// The transport state the loss/fatal signalling is routed through.
  transport: &'a transport::TransportState,
}

/// The source-wide state one buffer is processed against — everything
/// [`process_decoded`] only READS, as opposed to the [`FidMap`] it mutates and the
/// effect closures it calls. Grouped so the borrowed context travels as one value:
/// it is identical for every buffer of a source's life, while the map and the
/// closures are what each call actually varies.
struct BufferContext<'a> {
  /// The counters and the transport this buffer's steps report through.
  report: ReportContext<'a>,
  /// The caller's exclusion fence, consulted by [`classify`] before any map
  /// self-maintenance runs.
  exclusions: &'a [std::path::PathBuf],
  /// The core's [frame epoch](Control::Frame) as this source last heard it,
  /// sampled from the control mailbox BEFORE this buffer was decoded — and
  /// therefore before any reseed this buffer drives.
  ///
  /// It is the only field that varies per buffer, and it varies for a reason the
  /// grouping above does not weaken: it must be a value read before the walk it
  /// stamps, so it is sampled where the buffer is read rather than inside the walk
  /// that would already have started. Sampling early can only make it OLDER, which
  /// costs a refused generation; sampling late could make it claim a world the walk
  /// never saw whole.
  frame_epoch: u64,
}

/// Processes one decoded buffer: [`classify`]s each event into its admission
/// action, applies the resulting map self-maintenance, and forwards the admitted
/// events onto the queue via `send` — or routes a loss through the barrier.
/// Returns [`StepExit::Died`] when the stream died (fatal already signaled),
/// mirroring [`drain_events`]'s contract, and [`StepExit::Abandoned`] when a
/// teardown landed between the retries of a walk this buffer drove. Pure over the
/// two walk closures and the send closure — the ONLY fd-touching or
/// queue-touching parts — so the barrier and
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
/// the map's remaining room, and this buffer's remaining decline allowance —
/// TWO budgets, never one number). Both mirror `ReseedContext`'s methods.
///
/// `cx.exclusions` is handed straight to [`classify`], which decides the fence BEFORE
/// any map self-maintenance runs. Nothing is filtered here afterwards: an excluded
/// event arrives as [`Admission::ExcludedDrop`] having mutated nothing, so this loop
/// never sees a forwarded event the caller asked not to hear about, and — the
/// property that matters — excluded activity never grew the map to get here.
#[allow(clippy::too_many_arguments)]
fn process_decoded<R, S, Q>(
  decoded: super::fid::DecodeOutcome,
  map: &mut FidMap,
  cx: &BufferContext<'_>,
  report_credit: transport::BudgetPermit,
  reseed_walk: R,
  mut subtree_walk: S,
  mut send: Q,
  shutdown_requested: &dyn Fn() -> bool,
) -> StepExit
where
  R: FnMut() -> std::io::Result<WalkSeed>,
  S: FnMut(&std::path::Path, &super::fid::Fid, Option<usize>, usize) -> std::io::Result<WalkSeed>,
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  let &BufferContext {
    report,
    exclusions,
    frame_epoch: _,
  } = cx;
  let ReportContext { stats, transport } = report;
  // SEAM 2, live half: every boundary the walks this buffer drives declined.
  // Accumulated across the buffer and sent ONCE, ahead of whatever the buffer
  // ends with — a batch of events or the loss barrier — so a boundary is always
  // recorded before the cover that re-reads its location, never after it.
  let mut declined: Vec<crate::os::DeclinedBoundary> = Vec::new();
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
      match classify(map, event, &mut memo, exclusions) {
        // A forwarded event whose admission mutated no growing node, OR a root
        // self-event routed to the death lifecycle. A `LearnDir` may have grown the
        // map past its cap (design §4.9): a capped map that keeps eventing while
        // silently refusing to learn is the silent-loss shape, so an over-cap map is
        // the terminal `Fatal`, not run on blind. (The check is cheap and harmless
        // on the non-growing arms.)
        Admission::RootDeath(event) => {
          if map.over_capacity() {
            signal_fatal_cap(transport, &mut send);
            return StepExit::Died;
          }
          // Never suppressed. The root's own death is the scope's lifecycle, not
          // its content: an exclusion covering the root (a caller excluding the
          // very tree it watched) would otherwise silence the one record that says
          // the watch is over.
          events.push(fanotify_event(event));
        }
        Admission::Forward(event) | Admission::LearnDir(event) | Admission::ForgetDir(event) => {
          if map.over_capacity() {
            signal_fatal_cap(transport, &mut send);
            return StepExit::Died;
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
        //
        // A `NotFound` at the resolved path therefore means no removal was processed
        // BY THIS READER, yet the directory is not there. That is the ordinary shape
        // of a same-buffer move burst: move a populated `X` into `/root/a/X`, then to
        // `/root/b/X` before the reader consumes the buffer, and the walk that runs at
        // the FIRST record looks for a directory the SECOND record — still unread, but
        // long since applied to disk — has already moved. The map is behind the disk,
        // not blind to it, and the next record in this very buffer would have
        // re-parented the node.
        //
        // So a failed walk is LOSS, not death. It degrades to the same per-buffer
        // barrier every other loss takes: drop the buffer, reseed the whole map from
        // the root, and signal `Overflow`. The reseed is a fresh enumerate of the live
        // tree, so it finds the moved directory wherever it actually landed, and the
        // covering rescan owes the consumer everything the dropped buffer could have
        // said. `Fatal` is reserved for the failure of that FULL recovery
        // (`reseed_after_loss`), which is the only failure that really does leave the
        // source unable to see.
        Admission::Rename { event, seed } => {
          // The re-parent / move-in learn may have grown the map past its cap; check
          // it FIRST — before any walk — so an over-cap learn cannot even start one.
          if map.over_capacity() {
            signal_fatal_cap(transport, &mut send);
            return StepExit::Died;
          }
          if let Some(moved_fid) = seed {
            // TWO budgets, and they are handed over as two numbers because they
            // bound two different things and neither may ever be spent on the
            // other.
            //
            // The MAP budget is the room the map actually has left, UNMODIFIED.
            // Not the full cap — the map is near-cap (the top just landed), and
            // passing the whole cap as the descend budget would let a populated
            // move-in allocate up to another `cap` of descendants before the
            // additive check below fired — but not less than it either. Deducting
            // this buffer's accumulated declines from it was the defect: a decline
            // seeds no map node, so charging one against `max_map_directories`
            // spends a PUBLIC option (whose documented meaning is the map's size)
            // on a vector the map does not account for, and a move-in burst then
            // fails walks that fit the cap perfectly well, dropping the buffer
            // through the loss/reseed ladder for nothing. Uncapped stays `None`.
            //
            // The WALK-OUTPUT budget is what is LEFT of `MAX_WALK_DECLINES` after
            // what this buffer already accumulated. That is what bounds the shared
            // accumulator: every walk in the buffer appends into `declined`, so
            // without a per-walk share of one allowance the vector would be
            // bounded only by `renames-in-buffer x MAX_WALK_DECLINES`. A walk that
            // would exceed its share aborts `Incomplete`, which is the existing
            // loss ladder — `SeedOutcome::Blind` below, the per-buffer barrier,
            // reseed, `Overflow` — and never the terminal.
            let budget = map.remaining_capacity();
            let decline_budget = MAX_WALK_DECLINES.saturating_sub(declined.len());
            let started = std::time::Instant::now();
            let outcome = seed_moved_in_subtree(
              map,
              &moved_fid,
              &mut declined,
              |subtree, subtree_fid| subtree_walk(subtree, subtree_fid, budget, decline_budget),
              shutdown_requested,
            );
            stats.record_walk(walk_micros(started));
            // A teardown between the move-in walk's two attempts: abandon the
            // buffer whole rather than take the loss barrier, which would run a
            // whole-root reseed on the way out.
            if matches!(outcome, SeedOutcome::Abandoned) {
              return StepExit::Abandoned;
            }
            if matches!(outcome, SeedOutcome::Blind) {
              // The subtree could not be mapped from the path the map resolves it
              // to. Take the loss barrier rather than the terminal: a reseed both
              // repairs whatever the burst staled and covers it with a rescan,
              // where killing the scope would strand every unrelated subscription
              // on it over ordinary churn.
              lossy = true;
              break;
            }
            // The belt: the walk fenced its own production to the remaining budget,
            // so this only fires on the exact cap boundary — the same terminal a
            // live create over the cap hits. A move-in that cannot fit is the cap
            // doing its job; fatal is the honest terminal.
            if map.over_capacity() {
              signal_fatal_cap(transport, &mut send);
              return StepExit::Died;
            }
          }
          events.push(fanotify_event(event));
        }
        // Provably outside the watched root (the firehose filter): a clean drop, BY
        // DESIGN — distinct from the staleness a loss induces, which the reseed
        // below repairs.
        Admission::ForeignDrop => {}
        // Inside the root but outside the REPORTED tree: the exclusion fence refused
        // the event at the TOP of `classify`, so nothing was learned, re-parented,
        // forgotten, or handed here as a subtree to walk. Excluded churn therefore
        // costs this reader one path resolution and nothing else — it cannot grow the
        // admission map toward the cap, and it cannot barrier the buffer, so no
        // subscription outside the exclusion is ever affected by activity under it.
        Admission::ExcludedDrop => {}
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
    // The pre-barrier walks' declines are DISCARDED rather than merged: the
    // whole-root reseed about to run re-declines every boundary that is still
    // there, so keeping them would add nothing — and would actively corrupt the
    // generation, since a stale location among them would be re-recorded right
    // after the sweep that exists to drop it.
    declined.clear();
    let mut reseeded = ReseedGeneration::default();
    // Abandonment propagates: a teardown between the reseed's two attempts ends
    // the buffer here, with no boundary report and no `Overflow`. That is sound
    // because the `Overflow`'s only consumer is a scope that is being torn down —
    // `drain_events` stops reading at the very next check anyway, and the source's
    // terminal record ends the obligation the loss signal would have opened. It is
    // the same disposal a queued admission gets, for the same reason.
    match reseed_after_loss(
      map,
      report,
      reseed_walk,
      &mut reseeded,
      &mut send,
      shutdown_requested,
    ) {
      StepExit::Done => {}
      exit => return exit,
    }
    let map_stats = map.stats();
    stats.set_map(map_stats.directories, map_stats.memo_generation);
    // The reseed's declines go out BEFORE the loss signal, for the same reason
    // the reseed itself runs before it: the covering rescan is about to make the
    // consumer re-read this tree, and the coverage set should already know where
    // that tree ends when it does. This is not an event and does not break the
    // barrier below — it carries no record, so nothing from the lossy buffer
    // precedes the `Overflow`.
    //
    // WHOLE-ROOT: `reseed_after_loss` answering `Done` means one walk from the
    // root ran to completion (a truncated or failed attempt contributes no seed
    // at all), so this is the complete boundary set under the root — the generation
    // the core reconciles its device-only records against. This is the ONLY
    // observation on a kernel-recursive profile that can retire one, which is why
    // it is worth saying explicitly on the message.
    forward_boundaries(
      report_credit,
      crate::os::WalkBoundaries {
        declined: reseeded.declined,
        // BOTH stamps, the same pair a requested recovery echoes back. The root
        // this generation actually describes, straight off the fd the reseed
        // reopened — and beside it the core's own frame epoch as this source last
        // heard it, sampled before the walk began. No request asked for this walk,
        // so neither stamp is an echo; they are what the source honestly holds, and
        // the core installs nothing unless both are still its own. A mount id alone
        // is not enough: ids are allocated lowest-free, so a root that moved and
        // came back is on the id the core still holds while this walk ran against
        // an incarnation that has since died.
        reach: crate::os::WalkReach::WholeRoot {
          root_mnt_id: reseeded.root_mnt_id,
          epoch: cx.frame_epoch,
        },
      },
      &mut send,
    );
    // Empty events + lossy: `forward_batch` enqueues the `Overflow` alone (no
    // Batch), the barrier this whole branch exists to hold.
    transport::forward_batch(transport, Vec::new(), true, &mut send);
    return StepExit::Done;
  }

  // Publish this batch's memo tallies and the map's post-batch footprint, so an
  // operator poll reflects the current admission map and memo hit rate.
  stats.add_memo(memo.hits, memo.misses);
  let map_stats = map.stats();
  stats.set_map(map_stats.directories, map_stats.memo_generation);
  // Ahead of the events, so a boundary a move-in walk declined is in the coverage
  // set before any event under it is delivered. PARTIAL: a moved-in subtree walk
  // saw one subtree and proves nothing about the rest of the root.
  forward_boundaries(
    report_credit,
    crate::os::WalkBoundaries {
      declined,
      reach: crate::os::WalkReach::Partial,
    },
    &mut send,
  );
  // A clean buffer forwards its admitted events with no loss.
  transport::forward_batch(transport, events, false, &mut send);
  StepExit::Done
}

/// The event path's boundary-report CREDIT, reserved before the read that could
/// produce a report — the answer to "what does a producer that cannot defer do
/// when the counter is full?"
///
/// # Why the counter was never a verdict
///
/// This rung used to be a terminal: a report that could not claim a permit killed
/// the source, on the reading that every slot being taken proves the driver has
/// stopped consuming the queue. It proves nothing of the sort. It proves that
/// [`MAX_BOUNDARY_REPORTS_IN_FLIGHT`] reports are awaiting ingestion at this
/// instant — a value re-read at a cadence — while [`drain_events`] reads to
/// `EAGAIN` with no pacing against that credit and can produce one report per
/// buffer, and permits come back only when the driver's task is polled. Nine
/// boundary-bearing buffers while the driver is merely descheduled, or busy with
/// other ready work, therefore killed a source with nothing wrong with it.
/// Splitting the deferrable and undeferrable counters stopped one producer
/// occupying the other's headroom; it did not turn a backlog into evidence of
/// death.
///
/// # Where a producer that cannot defer puts its events
///
/// Back in the kernel. The constraint that made this hard is real — by the time a
/// report is built its events are already out of the kernel and its map is already
/// reseeded, so there is nowhere to put them and nothing to defer TO — but it
/// binds only AFTER the read. Before it, the fanotify instance's own queue is
/// exactly the place, which is why the credit is claimed here rather than at the
/// report: a buffer is never taken out of the kernel without the slot to report
/// its walk on, and a producer with no slot simply does not read yet. That is the
/// same discipline the control pass already keeps — credit before the obligation
/// leaves the mailbox — applied to the one producer that had none.
///
/// The pressure is bounded and its degrade is the one this reader already owns: a
/// wait long enough to overrun the instance's queue yields `FAN_Q_OVERFLOW`, which
/// is the ordinary loss barrier, not a new failure mode.
///
/// # What still ends the wait
///
/// - a RELEASED slot ([`transport::BoundaryCredit`] → this reader's `WakeState`),
///   which is the edge the whole wait rests on. The claim is re-attempted under an
///   ARMED park, so a release landing between the failed claim and the block
///   cannot elide its wake;
/// - a shutdown, checked out of band before the block and again on the caller's
///   next pass — teardown outranks every long op here;
/// - a CLOSED receiver. That is the liveness proof the terminal was reaching for
///   and never had: with no consumer, the permits behind the queued reports may
///   never be released at all, so waiting would be a hang. It is the only report
///   condition that still answers `Fatal`.
///
/// Pure over the `block` closure — the only fd-touching part — exactly as every
/// other step in this reader is, so the wait, the lost-wakeup guard and the
/// terminal are all testable without a live instance.
#[derive(Debug)]
enum ReportCredit {
  /// The slot for the next buffer's report.
  Claimed(transport::BudgetPermit),
  /// The wait ended without a slot in hand (a release, a control wake, a signal).
  /// The caller re-services control and re-attempts the claim; nothing was
  /// consumed and nothing was read.
  Woken,
  /// A teardown was observed instead of a slot.
  Shutdown,
  /// The receiver is gone: no permit will ever come back and no report could be
  /// delivered if one did.
  Closed,
  /// The block itself failed.
  Failed(std::io::Error),
}

/// Claims the [`ReportCredit`] one buffer needs, blocking through `block` when
/// there is none. See the type for why this is the credit's site.
fn reserve_report_credit<B>(
  transport: &transport::TransportState,
  wake: &WakeState,
  receiver_closed: &dyn Fn() -> bool,
  mut block: B,
) -> ReportCredit
where
  B: FnMut() -> std::io::Result<()>,
{
  if let Some(permit) = transport::BudgetPermit::acquire_boundaries(transport) {
    return ReportCredit::Claimed(permit);
  }
  if receiver_closed() {
    return ReportCredit::Closed;
  }
  // ARM THE PARK, THEN RE-CHECK. A slot released after the claim above and before
  // the park-store would find `parked` clear, elide its wake, and leave this reader
  // blocked on an edge that has already passed — the module's lost-wakeup shape,
  // and the reason the second claim is not redundant.
  wake.arm_park();
  if let Some(permit) = transport::BudgetPermit::acquire_boundaries(transport) {
    wake.unpark();
    return ReportCredit::Claimed(permit);
  }
  if wake.shutdown_requested() {
    wake.unpark();
    return ReportCredit::Shutdown;
  }
  let blocked = block();
  wake.unpark();
  match blocked {
    Ok(()) => {
      // The counter is drained here rather than left standing: the caller's next
      // statement services control off the MAILBOX and re-attempts the claim, so a
      // level left signalled would only make the following poll return instantly.
      wake.drain();
      ReportCredit::Woken
    }
    Err(err) => ReportCredit::Failed(err),
  }
}

/// Signals the terminal for a source whose consumer is GONE: the reports it owes
/// can neither be delivered nor ever paid for, so the reader stops instead of
/// waiting on credit nothing will return.
fn signal_fatal_receiver_gone<Q>(transport: &transport::TransportState, send: Q)
where
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  transport::signal_fatal_once(
    transport,
    SourceError::ReadFailed {
      source: std::io::Error::other(
        "the fanotify source has no consumer: its queue receiver is closed, so its boundary \
         evidence can neither be delivered nor paid for",
      ),
    },
    send,
  );
}

/// Puts one walk's declines on the queue under a permit the CALLER already
/// claimed — the only form there is, and it cannot fail for want of credit because
/// no producer here starts work without the slot to report it on: the control pass
/// claims before an obligation leaves the mailbox
/// ([`service_control_with`]), the event path before a buffer leaves the kernel
/// ([`ReportCredit`]).
///
/// A WHOLE-ROOT report is sent even when it is empty, and that is not a nicety: an
/// empty complete walk says "there is no boundary anywhere under this root", which
/// is exactly the generation that retires the last stale device-only record.
/// Suppressing it would make the reconciliation work everywhere except the one
/// state it most needs to reach. An empty PARTIAL report is still nothing to say,
/// and the permit simply goes back.
///
/// Deliberately NOT routed through [`transport::forward_batch`]: a boundary
/// observation stages no resume position and spends no BATCH slot, and pricing it
/// as a batch would advance the loss dedup position — muting an `Overflow` that a
/// walk's declines happened to precede.
fn forward_boundaries<Q>(
  permit: transport::BudgetPermit,
  boundaries: crate::os::WalkBoundaries,
  mut send: Q,
) where
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  if boundaries.declined.is_empty() && boundaries.reach == crate::os::WalkReach::Partial {
    return;
  }
  // A refused send means the driver is gone; there is nothing left to tell.
  let _ = send(crate::os::SourceMessage::Boundaries(boundaries, permit));
}

/// Puts ONE whole-root recovery on the queue — the reseed's complete generation,
/// the ticket cutoff it discharges, and the loss it implies, as a single
/// indivisible message.
///
/// Non-droppable for the reason [`forward_boundaries`] is, and more sharply: this
/// message is the ENTIRE evidence base of a recovery that has already replaced the
/// map and already retired the located walks it stood in for. There is nothing
/// below it on any ladder.
///
/// It takes the permit the CALLER claimed rather than claiming its own, and that
/// is what makes it infallible. The credit is secured before the obligation leaves
/// the mailbox ([`service_control_with`]), so the reseed this reports on never runs
/// without a slot to deliver its result on — and a driver that has not got round to
/// ingesting the previous report is a wait rather than a source death.
fn forward_root_recovery<Q>(
  permit: transport::BudgetPermit,
  recovery: crate::os::RootRecovery,
  mut send: Q,
) where
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  // A refused send means the driver is gone; there is nothing left to tell.
  let _ = send(crate::os::SourceMessage::RootRecovered(recovery, permit));
}

/// Runs one ADMISSION RESEED end to end and answers its ticket, returning
/// [`StepExit::Died`] when the stream died (the terminal `Fatal` already
/// signaled), mirroring [`process_decoded`]'s contract.
///
/// The order of what goes on the queue is the contract, not an implementation
/// detail:
///
/// 1. the walk's own DECLINES, so a boundary inside the revealed ground is in the
///    core's coverage set before anything makes the consumer re-read that ground
///    — the same rule every other walk driver follows;
/// 2. the [`AdmitReport`] LAST, so the core acts on the reply only once every
///    consequence of the walk is already behind it on the one ordered queue.
///
/// Admission-before-cover falls out of (2): the core holds the cover parked until
/// this reply, and the reply cannot overtake the map mutation that precedes it on
/// the reader's own thread.
///
/// The ladder's bottom rung sends NOTHING and walks nothing: a request the located
/// walk could not answer is folded into the mailbox's recovery slot
/// ([`ControlInbox::escalate`]) and discharged by the ONE whole-root recovery
/// [`service_control_with`] runs next. That is what keeps a burst bounded — see
/// the arm itself.
///
/// Pure over the walk closure and the send closure — the ONLY fd-touching or
/// queue-touching parts — exactly as [`process_decoded`] is, so the whole ladder
/// (refuse, retry, escalate) is testable over a real [`FidMap`] with a stub walk
/// and a capturing sender.
#[allow(clippy::too_many_arguments)]
fn run_admission<A, Q>(
  inbox: &ControlInbox,
  map: &mut FidMap,
  report: ReportContext<'_>,
  request: AdmitRequest,
  permit: transport::BudgetPermit,
  admit_walk: A,
  mut send: Q,
  shutdown_requested: &dyn Fn() -> bool,
) -> StepExit
where
  A: FnMut(&std::path::Path, crate::os::ScopeFrame, Option<usize>) -> std::io::Result<AdmitWalk>,
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  let ReportContext { stats, transport } = report;
  let mut declined: Vec<crate::os::DeclinedBoundary> = Vec::new();
  let started = std::time::Instant::now();
  let verdict = admit_revealed(map, &request, &mut declined, admit_walk, shutdown_requested);
  stats.record_walk(walk_micros(started));
  // Abandoned inside the located ladder, BEFORE anything went on the queue: the
  // request is dropped whole, unanswered and with no partial evidence emitted.
  // That is the module doc's teardown rule verbatim — a shutdown observed
  // alongside a pending admission wins, and the scope whose cover was parked on
  // it is ending.
  if matches!(verdict, AdmitVerdict::Abandoned) {
    return StepExit::Abandoned;
  }
  // PARTIAL: the admission walk covers the revealed location's subtree alone. The
  // slot was claimed before this walk ever started, so there is no rung here where
  // an unconsumed queue turns a healthy source into a terminal.
  forward_boundaries(
    permit,
    crate::os::WalkBoundaries {
      declined,
      reach: crate::os::WalkReach::Partial,
    },
    &mut send,
  );
  let outcome = match verdict {
    AdmitVerdict::Admitted => {
      // The belt, identical to the move-in walk's: the walk fenced its own
      // production to the map's REMAINING room, so this trips only at the exact
      // cap boundary — where a map that cannot keep learning is the honest
      // terminal rather than a source that runs on silently blind.
      if map.over_capacity() {
        signal_fatal_cap(transport, &mut send);
        return StepExit::Died;
      }
      AdmitOutcome::Admitted
    }
    AdmitVerdict::StillCovered { dev, mnt_id } => AdmitOutcome::StillCovered { dev, mnt_id },
    // Screened above, before anything reached the queue.
    AdmitVerdict::Abandoned => return StepExit::Abandoned,
    AdmitVerdict::Blind | AdmitVerdict::Stale => {
      // The ladder: the scoped walk failed twice — or was refused outright because
      // the request's frame is superseded — so fall back to the recovery that
      // subsumes it. A whole-map reseed re-walks from the ROOT and reads its fence
      // from the fd it reopens; the revealed ground is on that frame now, so that
      // walk admits it, and the root cover the recovery carries dominates the
      // located cover this round trip held. A reseed that stays blind is the
      // terminal `Fatal`, exactly as it is after a lossy buffer: there is nothing
      // below it on the ladder.
      //
      // THE WALK DOES NOT HAPPEN HERE. This rung folds the request into the
      // mailbox's recovery slot and returns; `service_control_with` sees the slot
      // set and runs ONE `run_root_recovery`, which atomically folds every request
      // still queued behind this one into the same maximum cutoff, walks once, and
      // leaves only the tickets posted DURING that walk for a single follow-up.
      //
      // Running it inline instead is what made one A->B frame change cost a
      // complete root walk and a complete report PER REQUEST: the core permits 64
      // pending admissions before it collapses them, every one of that burst is
      // superseded by the same re-mount, and each answered only its own cutoff
      // while the rest sat queued. Sixty-four whole-tree walks starve the event
      // reads the kernel queue is filling behind (a `FAN_Q_OVERFLOW` — a real
      // loss), and at a boundary budget of one the SECOND report cannot claim a
      // permit at all, which kills an otherwise healthy source.
      //
      // Nothing is discarded by folding: a recovery discharges every ticket at or
      // below its cutoff, so the maximum answers this request exactly as a reply of
      // its own would have — the identical discharge `Mailbox::post`'s backlog cap
      // already performs. Teardown priority is unchanged too: the escalation costs
      // no walk, and the caller re-reads the shutdown flag before the recovery it
      // triggers, so a teardown that landed during the two located attempts still
      // preempts the whole-root walk it would otherwise have bought.
      inbox.escalate(&request);
      return StepExit::Done;
    }
  };
  let map_stats = map.stats();
  stats.set_map(map_stats.directories, map_stats.memo_generation);
  // A refused send means the driver is gone; the round trip dies with it, and
  // there is no core left holding a cover.
  let _ = send(crate::os::SourceMessage::Admitted(AdmitReport {
    ticket: request.ticket,
    outcome,
  }));
  StepExit::Done
}

/// Whether an admission reseed got the revealed ground into the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmitVerdict {
  /// The map now covers the revealed ground — or there was nothing to cover.
  Admitted,
  /// The location is still a boundary; nothing was walked. Carries WHAT the walk
  /// found standing there, which is what lets the core re-record the boundary that
  /// is present rather than the one that departed — see
  /// [`AdmitOutcome::StillCovered`].
  StillCovered {
    /// The device of the object at the location.
    dev: Option<u64>,
    /// That object's mount id, or `None` where the host answers none.
    mnt_id: Option<u64>,
  },
  /// The walk failed twice. The caller falls back to the loss barrier.
  Blind,
  /// The request's captured frame is no longer the root's, so nothing ran and
  /// nothing was walked ([`AdmitWalk::Stale`]). Disposed of exactly as
  /// [`Blind`](Self::Blind) is — a whole-root recovery cut off at this ticket —
  /// and kept a separate verdict because it is a definite answer about the WORLD
  /// rather than an exhausted ladder: it is never retried, and a cell can tell the
  /// two apart.
  Stale,
  /// A teardown landed between the two attempts, so the retry was never run. NOT
  /// [`Blind`](Self::Blind): the ladder was cut short by teardown priority rather
  /// than exhausted, so the caller abandons the request instead of escalating it
  /// to a whole-root reseed.
  Abandoned,
}

/// Admits the ground a departed mount revealed, retrying ONCE on failure before
/// conceding blindness — [`reseed_map`]'s and [`seed_moved_in_subtree`]'s policy,
/// applied to the fourth walk driver. Pure over the walk closure, so the
/// frame-refusal, retry and escalation policy is testable over a real [`FidMap`]
/// with no live fd.
///
/// Three things a naive version gets wrong, all of them decided here rather than
/// in the walk:
///
/// - **A refusal is not a failure.** [`AdmitWalk::StillCovered`] is a definite
///   answer about a live boundary, so it returns immediately: retrying it would
///   just re-open the location and re-read the same frame, and folding it into
///   the failure count would drive a still-mounted location into the loss barrier
///   every time the refresh raced a mount. [`AdmitWalk::Stale`] is definite for
///   the same reason and returns the same way — the request's frame will not
///   become current again on a second attempt.
/// - **The parent must still be REACHABLE.** The walk hands back the FID of the
///   directory the revealed location hangs under; if the map cannot resolve that
///   parent to a path — it is excluded, orphaned, or outside the reported tree —
///   then nothing seeded beneath it could ever admit anyway (`resolve` walks
///   parent links to the anchor), and the inventory would enter as dead nodes
///   counting against the directory cap. Nothing is owed for ground the map does
///   not reach, so this is [`Admitted`](AdmitVerdict::Admitted) with no mutation.
/// - **Only a successful walk contributes declines.** A failed attempt returns no
///   seed at all, so a retry never double-records and a walk that died mid-tree
///   never surfaces a partial fence as though it were the whole one.
fn admit_revealed<W>(
  map: &mut FidMap,
  request: &AdmitRequest,
  declined: &mut Vec<crate::os::DeclinedBoundary>,
  mut walk: W,
  shutdown_requested: &dyn Fn() -> bool,
) -> AdmitVerdict
where
  W: FnMut(&std::path::Path, crate::os::ScopeFrame, Option<usize>) -> std::io::Result<AdmitWalk>,
{
  for attempt in 0..2 {
    // BETWEEN attempts only, like every other ladder here: the walk in flight
    // completes (an interrupted one leaves a half-built map), but the retry is a
    // fresh walk and a teardown outranks it.
    if attempt > 0 && shutdown_requested() {
      return AdmitVerdict::Abandoned;
    }
    // The budget is re-read each attempt: a live `learn` between attempts changes
    // the room actually left.
    match walk(&request.location, request.frame, map.remaining_capacity()) {
      Ok(AdmitWalk::StillCovered { dev, mnt_id }) => {
        return AdmitVerdict::StillCovered { dev, mnt_id };
      }
      // Definite, like the refusal above and for the same reason: a retry would
      // re-open the same root and read the same live frame against the same
      // captured one. The request is superseded, and only a fresh one can help.
      Ok(AdmitWalk::Stale) => return AdmitVerdict::Stale,
      Ok(AdmitWalk::Nothing) => return AdmitVerdict::Admitted,
      Ok(AdmitWalk::Revealed { parent, seed }) => {
        if map.resolve_path(&parent).is_none() {
          return AdmitVerdict::Admitted;
        }
        declined.extend(seed.declined);
        map.seed(seed.entries);
        return AdmitVerdict::Admitted;
      }
      Err(_) => {}
    }
  }
  AdmitVerdict::Blind
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
  report: ReportContext<'_>,
  reseed_walk: R,
  generation: &mut ReseedGeneration,
  send: Q,
  shutdown_requested: &dyn Fn() -> bool,
) -> StepExit
where
  R: FnMut() -> std::io::Result<WalkSeed>,
  Q: FnMut(crate::os::SourceMessage) -> bool,
{
  let ReportContext { stats, transport } = report;
  stats.record_reseed();
  let started = std::time::Instant::now();
  let outcome = reseed_map(map, generation, reseed_walk, shutdown_requested);
  stats.record_walk(walk_micros(started));
  match outcome {
    ReseedOutcome::Reseeded => StepExit::Done,
    // Abandoned BETWEEN the two attempts, so the map is exactly as stale as a
    // failed first attempt left it — and no `Fatal` is signaled, because nothing
    // has been proven blind: the walk was never given its retry. The reader is
    // exiting, so the staleness has no consumer.
    ReseedOutcome::Abandoned => StepExit::Abandoned,
    ReseedOutcome::Blind => {
      transport::signal_fatal_once(
        transport,
        SourceError::ReadFailed {
          source: reseed_blind_error(),
        },
        send,
      );
      StepExit::Died
    }
  }
}

/// What ONE completed whole-root reseed learned BESIDE the map it rebuilt.
///
/// The two facts travel together because they are read from the same walk and
/// mean nothing apart: a generation is a claim about where coverage ends UNDER A
/// PARTICULAR ROOT MOUNT, so the core cannot apply one without knowing which root
/// mount that was ([`RootRecovery::root_mnt_id`](crate::os::RootRecovery)).
///
/// Empty/`None` until a walk succeeds: a failed attempt returns no seed at all, so
/// a retry never double-records and a walk that died mid-tree never surfaces a
/// partial fence — nor a frame — as though it were the whole one.
#[derive(Debug, Default)]
struct ReseedGeneration {
  /// Every boundary the completed walk declined.
  declined: Vec<crate::os::DeclinedBoundary>,
  /// The root mount id that walk fenced its descent against.
  root_mnt_id: Option<u64>,
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
  /// A teardown landed between the two attempts, so the retry was never run. NOT
  /// [`Blind`](Self::Blind): nothing was proven about the source's sight, and the
  /// caller must not escalate a teardown into a terminal `Fatal`.
  Abandoned,
}

/// Rebuilds `map` from a fresh walk after a loss, retrying ONCE on failure
/// before conceding blindness. Pure over the walk closure so the
/// retry-then-escalate policy is testable without a live fd: a walk that fails
/// twice returns [`ReseedOutcome::Blind`]; any success reseeds and returns
/// [`ReseedOutcome::Reseeded`]. The immediate retry absorbs a transient failure
/// (a directory momentarily unreadable mid-walk) without killing the scope.
fn reseed_map<W>(
  map: &mut FidMap,
  generation: &mut ReseedGeneration,
  mut walk: W,
  shutdown_requested: &dyn Fn() -> bool,
) -> ReseedOutcome
where
  W: FnMut() -> std::io::Result<WalkSeed>,
{
  for attempt in 0..2 {
    // BETWEEN attempts only. The walk in flight is never interrupted (a half-built
    // map is the silent-blindness shape this stack exists to prevent), but the
    // RETRY is a fresh walk over the whole root, and making a teardown wait out a
    // second one buys nothing at all.
    if attempt > 0 && shutdown_requested() {
      return ReseedOutcome::Abandoned;
    }
    if let Ok(seed) = walk() {
      // SEAM 2, reseed driver. Only a SUCCESSFUL walk contributes: a failed
      // attempt returns no seed at all, so a retry never double-records and a
      // walk that dies mid-tree never surfaces a partial fence as if it were the
      // whole one. The frame the walk fenced against rides out beside the
      // declines, from the same successful attempt and no other.
      generation.declined.extend(seed.declined);
      generation.root_mnt_id = seed.fence_mnt_id;
      map.reseed(seed.entries);
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

/// The error a foreign `fanotify_event_metadata.vers` escalates through the
/// terminal `Fatal`: the running kernel's event ABI is not the one this build
/// decodes, so no read of this fd can be parsed and fanotify(7)'s own
/// instruction is to abandon it. Carries both versions, which is what separates
/// "the kernel grew a newer event ABI" from "this stream is not fanotify".
fn abi_mismatch_error(mismatch: AbiMismatch) -> std::io::Error {
  std::io::Error::other(format!(
    "the fanotify stream reports event-metadata ABI version {}, not the {FANOTIFY_METADATA_VERSION} this build decodes; the source cannot be parsed",
    mismatch.found
  ))
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
  /// map is stale under it. The caller degrades to the per-buffer LOSS barrier —
  /// drop the buffer, reseed the whole map, signal `Overflow` — never straight to
  /// the terminal, because the commonest cause is an ordinary same-buffer move
  /// burst the reseed repairs.
  Blind,
  /// A teardown landed between the two attempts, so the retry was never run. NOT
  /// [`Blind`](Self::Blind): the caller must abandon the buffer rather than take a
  /// loss barrier whose reseed is a whole-root walk the teardown just preempted.
  Abandoned,
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
///   `Incomplete` — the node is still in-map and pending, so THIS READER processed
///   no removal, but a later record in the same unread buffer may already have
///   moved the directory on disk — which folds to the retry-then-`Blind` policy and
///   from there to the caller's loss barrier.
///
/// On a successful walk the entries are ADDED (the moved dir itself is already
/// learned) and its pending flag is cleared, keeping the completeness invariant at
/// the boundary-move site. The `walk` closure is the only fd-touching part, so the
/// resolve/gate/retry policy is testable over a real map with a stub walk.
fn seed_moved_in_subtree<W>(
  map: &mut FidMap,
  moved_fid: &super::fid::Fid,
  declined: &mut Vec<crate::os::DeclinedBoundary>,
  mut walk: W,
  shutdown_requested: &dyn Fn() -> bool,
) -> SeedOutcome
where
  W: FnMut(&std::path::Path, &super::fid::Fid) -> std::io::Result<WalkSeed>,
{
  for attempt in 0..2 {
    // BETWEEN attempts only, like every other ladder here.
    if attempt > 0 && shutdown_requested() {
      return SeedOutcome::Abandoned;
    }
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
    if let Ok(seed) = walk(&subtree, moved_fid) {
      // SEAM 2, move-in driver. A directory moved in from OUTSIDE the root brings
      // its own submounts with it, and this walk is the only thing that will ever
      // look at them — the mount table sees a vfsmount among them, but a
      // device-only boundary inside a moved-in subtree has no other observer at
      // all. Contributed only on the attempt that actually succeeded, like the
      // reseed's.
      declined.extend(seed.declined);
      map.seed(seed.entries);
      map.clear_pending_walk(moved_fid);
      return SeedOutcome::Seeded;
    }
  }
  SeedOutcome::Blind
}

#[cfg(test)]
mod tests;
