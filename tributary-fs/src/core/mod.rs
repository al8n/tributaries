//! The sans-I/O driver core: every decision between a raw OS batch and the
//! Monitor lives here, with all I/O returned as typed [`Effect`]s.
//!
//! `DriverCore` is the proto's Sans-I/O pattern applied one level up. It owns
//! the [`Monitor`] plus the driver state the Monitor cannot hold — path
//! lowering, flag grounding, rename classification, probe parking, overflow
//! clamping, identity minting, and the consumer-lag protocol — and it never
//! spawns, stats, sends, or reads a clock. The async driver task executes the
//! effects it emits and feeds the results (and the time) back in, so every
//! protocol is unit-testable with a hand clock and zero tasks.
//!
//! FSEvents flags are hints, never a log: one event's flag word can carry
//! several operations OR'd together with ordering unrecoverable, so no record
//! verb is minted from an ambiguous word — truth is established by a
//! [`Probe`](Effect::Probe) and anything un-groundable escalates to a located
//! rescan. Loss is never silent.
//!
//! Device trust is fail-closed: every move cookie derives from contemporaneous
//! probe evidence (a live `dev == root_dev` read, or a same-batch partner's
//! probe binding the fileID to the root device), the mount table only ever
//! VETOES trust — its mutations are monotone within a batch (adds early,
//! removals late) — and any loss signal revokes its authority until a fresh
//! read of the live table is installed.
//!
//! # Mount-refresh publication
//!
//! [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed) publishes on a strict
//! order. The root-LIVENESS verdict is acted on FIRST and unconditionally — a dead
//! root is terminal regardless of snapshot staleness, so its death evidence is never
//! discarded by a stale flag. Everything the snapshot then carries — the mount TABLE
//! and the root's descent FRAME (`root_mnt_id`) — publishes ONLY when the snapshot is
//! not stale: a stale completion (a loss or tick overlapped its read, so the snapshot
//! may predate the lost window, and the table + frame come from that one read)
//! publishes neither and re-arms one fresh read. So `state.root_mnt_id` is only ever
//! the last AUTHORITATIVE frame, never a stale/pre-window one, and the frame
//! [`crosses_mount_boundary`] consumes for enumerate descent is always authoritative.
//! A non-stale frame CHANGE (a same-object re-mount moved the root to a different
//! mount) then reconciles a DESCENDING scope's coverage — a rescan-and-re-arm
//! re-checks the children the last enumerate classified under the old frame, since
//! adopting the frame alone does not re-read them (a kernel-recursive scope never
//! consumes the frame, so it needs no replay).
//!
//! The mount-TABLE half carries an authority invariant of its own: `mounts_authoritative`
//! is true ONLY immediately after a refresh installs an authoritative table, and ANY
//! refresh that cannot install one closes it — a STALE completion (discarded above) OR
//! a live but NON-authoritative read (the live table could not be read). So the
//! device-trust-by-absence check ([`device_trusted`]) consults the table ONLY while
//! authority is open; a closed authority falls back to the conservative born-closed
//! behavior — no absence-based trust until the next authoritative refresh re-opens it —
//! while probe-read device evidence (`dev == root_dev`) still decides independently
//! throughout.
//!
//! # Root-death signals per backend
//!
//! Every backend's root death — unmount, delete, or replace — must reach a
//! trigger that runs [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed)'s
//! death mapping or the Monitor's self-event path; the trigger differs by
//! backend, and one backend's unmount is signal-silent, which the periodic tick
//! ([`root_liveness_interval`](DriverCore::new)) exists to cover:
//!
//! | backend | root unmount trigger | in-tree delete/replace trigger |
//! |---|---|---|
//! | inotify (descending) | `IN_UNMOUNT` + `IN_IGNORED` event | `IN_DELETE_SELF` / `IN_MOVE_SELF` event |
//! | FSEvents (macOS) | `RootChanged` flag → root-alive probe | `RootChanged` flag → root-alive probe |
//! | fanotify (`FAN_MARK_FILESYSTEM`) | **SILENT** — no event, no hangup (the mark holds the sb alive; L4.1) → the **periodic liveness tick** re-stats the root | `FAN_DELETE_SELF` / `FAN_MOVE_SELF` event |
//! | RDCW (Windows) | any terminal read completion → fatal source error → self-event | same signal; RDCW draws no in-band distinction from unmount |
//! | USN journal (Windows) | a failed journal read → fatal source error → self-event | the root's own FRN named in a delete/rename record → `RootDeath` |
//!
//! Only fanotify's unmount emits nothing in-band, so only fanotify arms the
//! tick (gated by [`liveness_ticked`](DriverCore::liveness_ticked)). Its in-tree
//! self-events, and every other backend's death signal, already lower a
//! terminal `Removed`/`Rescan` through the existing paths; the tick's role is
//! solely to make the quiet unmount observable within a bounded latency — a
//! loss-triggered refresh already catches it immediately when one occurs.

use std::{
  collections::{BTreeMap, BTreeSet, VecDeque},
  num::NonZeroU64,
  path::{Path, PathBuf},
  sync::Arc,
  time::Duration,
};

use tributary_proto::{
  ArmAttempt, Capabilities, Change, ChangeKind, DirEntry, EnumerateResult, Evidence, FileKind,
  Identity, Instant, Interest, IoClass, Location, Monitor, MoveCookie, OsRecord, RecordKind, ReqId,
  Scope, ScopeId, Segment, StatEntry, StatResult, SubtreeScope, WatchError, WatchId,
  monitor::{CoverageWorkEpoch, RecordOutcome},
};

use crate::{
  error::WatchRootError,
  os::{
    BackendKind, BatchPayload, FsEventFlags, RawOsEvent, RootIdentity, RootMeta, SourceError,
    SourceEvent,
    linux::{RawLinuxEvent, WatchOutcome},
    transport::BudgetPermit,
    windows::RawWindowsEvent,
  },
  stamped::Stamped,
};

mod compile;

#[cfg(test)]
mod tests;

/// Correlates a [`Effect::Probe`] request with its
/// [`on_probe_result`](DriverCore::on_probe_result).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProbeId(u64);

/// What an executed probe (an `lstat` of one path) found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
  /// The path does not exist.
  Missing,
  /// The path exists.
  Present {
    /// The object's kind.
    kind: FileKind,
    /// The object's inode number, if one could be read.
    file_id: Option<NonZeroU64>,
    /// The device the object lives on; identity is minted only on the
    /// root's own device.
    dev: u64,
  },
  /// The probe failed (permission, I/O); existence is unknowable.
  Failed,
}

/// What the mount refresh's root re-stat found — folded into every refresh so a
/// kernel-recursive backend, which receives no in-tree signal when its root is
/// unmounted or replaced (design §7), still detects the death at the refresh
/// cadence (birth + every loss signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootLiveness {
  /// The root still stats to an object; the core compares its identity against
  /// the barrier's to decide alive-vs-replaced.
  Present(RootIdentity),
  /// The root path no longer exists (lowers to `DeleteSelf`).
  Missing,
  /// The root could not be stat'd (permission, I/O, an unmounted-out mount
  /// point); existence is unknowable, so it lowers to `MoveSelf` exactly like a
  /// `RootChanged` probe that resolves `Failed`.
  Unreadable,
}

/// One mount-table refresh result: the mount prefixes strictly under the root,
/// whether the read was authoritative, and what the root itself re-stat'd to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountRefresh {
  /// Mount points observed strictly under the root.
  pub(crate) mounts: Vec<PathBuf>,
  /// Whether the live mount table could be read (device trust returns only
  /// with an authoritative read).
  pub(crate) authoritative: bool,
  /// The root's liveness at refresh time — the composition-only root-death
  /// check (no new timer, no new effect: the refresh already runs at birth and
  /// on every loss).
  pub(crate) root: RootLiveness,
  /// The root's CURRENT mount id, re-read at the refresh cadence. A same-object
  /// re-mount of the root (unmount + re-bind: identity unchanged, so the death
  /// gate passes) lands the root on a NEW mount, and the descent boundary
  /// [`crosses_mount_boundary`] fences children against the scope's captured
  /// `root_mnt_id` — so without refreshing it, every descendant on the new mount
  /// would read as a boundary and lower non-descendable until the next re-watch.
  /// [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed) adopts a `Some`
  /// value once the root is confirmed alive-and-present AND the refresh is not stale
  /// (a stale snapshot's frame is as suspect as its mount table). `None` (below Linux
  /// 5.8, the mask bit unset, or a non-Linux/fake source that reports no frame)
  /// leaves the captured value intact — a transient read miss never drops a known
  /// frame.
  pub(crate) root_mnt_id: Option<u64>,
}

/// One I/O obligation the driver task must execute for the core.
#[derive(Debug)]
pub(crate) enum Effect {
  /// Start the native source watching `root` for `scope`.
  SpawnStream {
    /// The scope the stream will feed.
    scope: ScopeId,
    /// The root path as the consumer supplied it.
    root: PathBuf,
  },
  /// Quiesce and destroy `scope`'s native source.
  TeardownStream {
    /// The scope whose stream is torn down.
    scope: ScopeId,
  },
  /// `lstat` one path and feed the outcome back under `probe`.
  Probe {
    /// The correlation id the result must echo.
    probe: ProbeId,
    /// The absolute path to stat.
    path: PathBuf,
  },
  /// Deliver one change to the consumer, reporting the delivery outcome back
  /// through [`on_delivery`](DriverCore::on_delivery).
  Emit {
    /// The scope the change belongs to.
    scope: ScopeId,
    /// The canonical root the change's location is relative to. Deliveries
    /// carry their own root so consumer-side assembly never depends on a
    /// registry entry — a dead scope's trailing changes (above all its
    /// terminal `Rescan`) still assemble after the scope is reclaimed.
    root: Arc<PathBuf>,
    /// The change to deliver.
    change: Change,
  },
  /// Install a kernel watch for one directory the Monitor descended into,
  /// reporting the outcome through
  /// [`on_watch_installed`](DriverCore::on_watch_installed).
  AddWatch {
    /// The scope whose live source executes the arm.
    scope: ScopeId,
    /// The Monitor watch being armed.
    watch: WatchId,
    /// The arm ATTEMPT this effect executes, echoed back with its outcome. A
    /// `WatchId` outlives its bindings — a root keeps it across a rebind — so
    /// only the attempt distinguishes this arm's verdict from that of one a
    /// later arm has already superseded.
    attempt: ArmAttempt,
    /// The already-armed parent watch (its anchor roots the open).
    parent: WatchId,
    /// The child's name under the parent.
    name: Segment,
    /// The child's absolute path — the parent's path joined with the name;
    /// executors and fakes address the object by it.
    path: Arc<PathBuf>,
    /// The `(dev, ino)` the enumerate (or the root's barrier) read for this
    /// object, when known. The executor opens the target by path/anchor and must
    /// confirm the opened object matches this before installing the watch — a
    /// rename between the enumerate and the arm would otherwise install the watch
    /// on a different object while the Monitor keeps the stale identity. `None`
    /// leaves the arm unverified (identity was unavailable — a foreign-device or
    /// unrepresentable entry), exactly as the Monitor already reconciles.
    expected: Option<ExpectedObject>,
  },
  /// Remove one per-directory kernel watch the Monitor dropped. Fire-and-
  /// forget: the Monitor's unwatch carries no result contract, and a wd the
  /// removal never reached is reclaimed when the scope's stream closes.
  RemoveWatch {
    /// The scope whose live source executes the disarm.
    scope: ScopeId,
    /// The Monitor watch being disarmed.
    watch: WatchId,
  },
  /// Read one directory (blocking readdir + per-entry stat), reporting the
  /// raw listing through [`on_enumerated`](DriverCore::on_enumerated).
  Enumerate {
    /// The correlation id the result must echo.
    req: ReqId,
    /// The directory's watch.
    watch: WatchId,
    /// The directory's absolute path.
    path: Arc<PathBuf>,
  },
  /// Re-read the live mount table strictly under `root` (blocking) and feed
  /// the result back through
  /// [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed): a loss signal
  /// may have swallowed a mount transition, so the table's authority is
  /// revoked until this fresh read installs.
  RefreshMounts {
    /// The scope whose device-trust table went stale.
    scope: ScopeId,
    /// The canonical root to enumerate mounts under.
    root: Arc<PathBuf>,
  },
}

/// The outcome of one attempted [`Effect::Emit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
  /// The consumer channel accepted the change.
  Accepted,
  /// The consumer channel was full; the change was not delivered.
  Refused,
}

/// Correlates one parked set-cover acknowledgement with its settlement: the
/// driver opens a fence via [`open_cover_fence`](DriverCore::open_cover_fence)
/// when an acked reconcile starts, and
/// [`poll_cover_settlements`](DriverCore::poll_cover_settlements) reports each
/// fence's [`CoverSettle`] once its scope's re-arm work quiesces. Minted from a
/// monotone counter, never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FenceId(u64);

/// How [`on_set_cover`](DriverCore::on_set_cover) disposed of one requested
/// cover reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverReconcile {
  /// The prune/grow walk ran. The scope may now hold re-arm work; a caller
  /// that owes an acknowledgement opens a fence
  /// ([`open_cover_fence`](DriverCore::open_cover_fence)) that resolves when
  /// [`Monitor::rearm_settled`] next holds for the scope.
  Reconciling,
  /// No reconcile ran; the reason tells the driver what to answer immediately.
  Noop(CoverNoop),
}

/// Why [`on_set_cover`](DriverCore::on_set_cover) refused to reconcile — each
/// reason maps to an immediate (never-fenced) driver answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverNoop {
  /// The scope is not registered.
  UnknownScope,
  /// The scope is not publicly live: between its spawn and the root-arm grant
  /// (or root-less before spawn) no caller holds a handle, so there is no
  /// coverage CLAIM to reconcile — the registration's own crawl is still
  /// installing the scope's whole coverage, and a reconcile over it would prune
  /// or re-issue ground the grant has not handed anyone. Refused outright; the
  /// caller's cover is re-issued once the grant commits (the umbrella only ever
  /// covers committed watches, so only the re-publicized API can reach this).
  ///
  /// This clause once carried a second, sharper reason: a pre-grant grow would
  /// mark the root's pending COLD arm as a re-arm and so suppress the initial
  /// inventory's `Created`s. That harm did not go away — it became the DESIGN.
  /// A registration births its root re-arm-flavored deliberately, because the
  /// contract reports no inventory for state that merely pre-existed the grant,
  /// and the window is marked so the suppression is never silent. The refusal
  /// therefore rests on the claim argument alone; the retired reason is recorded
  /// rather than dropped, because the clause reads vestigial without it.
  NotLive,
  /// The scope's backend is kernel-recursive: one whole-subtree stream is the
  /// coverage, which never narrowed, so there is nothing to prune or re-arm.
  /// Explicit rather than a silent walk-of-nothing, so the driver can answer
  /// "coverage was never reduced" instead of "applied".
  KernelRecursive,
  /// The retained cover was refused: empty, or entirely outside the live root
  /// (a caller typo / relative / stale path) — acting on either would prune
  /// the whole scope. Prior coverage and `applied_cover` stay untouched.
  RefusedCover,
}

/// How one settled set-cover fence reports its window.
///
/// # What a clean settle certifies, and what it cannot
///
/// [`Applied`](Self::Applied) is an IRREVERSIBLE claim about remote
/// asynchronous state, so its exact reach is worth stating. Three surfaces ride
/// it and are uncorrectable once it is reported: the acknowledgement itself
/// (its oneshot has one constructor and no retraction), the settle-fenced
/// cookie dispatch's pre-write contract ("a covering `Rescan` rides the queue
/// ahead of this cookie"), and the settle-floor promotion the clean verdict
/// performs (`settle_floor := applied_cover`, the claim a later lossy settle
/// rewinds to). What is NOT at stake is the end-to-end sync verdict: a
/// `Delivered` cannot be falsely certified through a settle, because the
/// cookie's own event travels the scope's single ordered lane behind any loss
/// that preceded its write, and the umbrella's two loss clocks (the per-sub
/// serial and the shared generation snapshotted before the install) resolve
/// every such race `Dominated`.
///
/// Certification over remote state always leaves a final
/// [observation, certify] instant, so the guarantee is stated against the
/// window's PROOFS: a fence settles `Applied` only when every counted proof
/// its window rests on postdates every loss the kernel had committed by that
/// proof's execution. A loss committed after those proofs is observed at its
/// own ingest, which marks pending fences lossy, degrades the claim and the
/// floor, and re-proves the scope before any later settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverSettle {
  /// The reconcile's re-arm work quiesced with no loss signal in the window:
  /// every re-armed watch is live, so writes under the retained cover from
  /// this moment are delivered.
  Applied,
  /// The reconcile settled, but the window was lossy — a covering `Rescan`
  /// passed or a grow kickoff coalesced into an in-flight cold read. Coverage
  /// may be partial; the `Rescan` dominates the gap.
  Degraded,
  /// The scope died under this fence: the teardown fold resolved it and there
  /// is no stream left to report anything on.
  ///
  /// Minted at the single place death is known SYNCHRONOUSLY — the teardown
  /// fold — so the fact travels with the verdict. A consumer that must not act
  /// on a dead scope reads it here instead of re-deriving it from driver maps
  /// that only a later `TeardownStream` execution clears, which is what let a
  /// parked barrier be answered over a scope that was already gone.
  ///
  /// Weaker than [`Degraded`](Self::Degraded) for any caller that only asks
  /// "was coverage complete" — both answer no — so the public
  /// `set_cover` outcome maps it to `Degraded` and is unchanged by its
  /// introduction.
  Dead,
}

/// Which boundary a [`poll_cover_settlements`](DriverCore::poll_cover_settlements)
/// pass speaks for, and therefore which verdicts it is entitled to mint.
///
/// # The residue rule
///
/// A live pass runs behind a source drain bounded by a per-lane snapshot, and
/// that drain can legitimately end with counted items still resident: the
/// merged fan-in may answer `Pending` while a ready item exists. The scopes
/// whose own lane still holds such items ride here, and for each of them this
/// pass mints NOTHING — not a clean verdict and not a lossy one.
///
/// Withholding the LOSSY verdict too is the part worth stating, because a
/// degraded verdict is not falsifiable by more loss. It is falsifiable by
/// DEATH: an unread terminal `Fatal` sitting in exactly those counted items
/// has not yet folded the scope's fence to [`Dead`](CoverSettle::Dead), so a
/// [`Degraded`](CoverSettle::Degraded) minted over it ANSWERS a caller —
/// dispatching its parked cookie write on a stream that is already gone, the
/// successful-but-unsatisfiable barrier `Dead` exists to refuse. So the rule
/// is by scope, not by verdict: while a scope's own lane holds counted-but-
/// unconsumed items, no settlement that answers a caller may resolve for it.
///
/// The residue set is per SCOPE rather than one global flag because the items
/// are per lane: a busy scope's backlog says nothing about another scope's
/// window, and coupling them would defer an unrelated fence for as long as the
/// neighbour keeps producing.
///
/// # Liveness
///
/// The deferral cannot outlive the residue that caused it. The snapshot is
/// retaken every pass, so a scope whose lane drains spends immediately and
/// resolves on the next one; and if the residue IS the terminal `Fatal`,
/// ingesting it folds the fence to `Dead`, which resolves through the already-
/// settled path this gate never touches. Either way the next pass answers.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SettlePass<'a> {
  /// The driver's live loop top: verdicts are minted against streams that are
  /// still running, so a clean window may certify — except for the scopes in
  /// `unspent`, whose settled fences are all held over to a later pass.
  Live {
    /// Scopes whose current delivery lane still holds items this pass's source
    /// snapshot counted but its drain did not ingest.
    unspent: &'a BTreeSet<ScopeId>,
  },
  /// The driver's close drain: every stream has been torn down, so there is
  /// nothing left to certify a clean window against and the boundary withholds
  /// that verdict. Nothing may be DEFERRED here, though — this is the last
  /// pass there will ever be, and a held-over fence would strand its caller's
  /// reply forever — so a lossy window still reports its honest verdict, and
  /// owes no ordering proof to do it (see [`Self::owes_cut_proof`]).
  Closing,
}

impl SettlePass<'_> {
  /// Whether this pass may mint a clean certificate at all.
  const fn certifies_clean(self) -> bool {
    matches!(self, Self::Live { .. })
  }

  /// Whether a verdict minted here is acted on against a LIVE stream, and so
  /// rests on the ordering proof every live verdict owes (see [`CutProof`]).
  ///
  /// Only the loop-top pass does. By the close drain every stream has already
  /// been torn down: no reader is left to cut a kernel queue and answer the
  /// batch that would mint a proof, and no verdict this pass reports can reach
  /// a stream — the close drain dispatches no cookie and answers a parked one
  /// with its pre-physical terminal. So the proof is both unobtainable and
  /// unnecessary here, and demanding it would do the one thing the last pass may
  /// not: park a caller's reply on a round trip that can never complete.
  const fn owes_cut_proof(self) -> bool {
    matches!(self, Self::Live { .. })
  }

  /// Whether `scope`'s settled fences are held over rather than resolved —
  /// true only for a live pass's unspent scopes, never at close.
  fn withholds(self, scope: ScopeId) -> bool {
    match self {
      Self::Live { unspent } => unspent.contains(&scope),
      Self::Closing => false,
    }
  }
}

/// One scope's pending set-cover fence bookkeeping.
///
/// # The lossy-window rule
///
/// `lossy` is the scope's loss memory since its last settle **observation**
/// (the [`poll_cover_settlements`](DriverCore::poll_cover_settlements) call
/// that found the scope settled and cleared this entry). It is set by
///
/// - any public scope `Rescan` passing [`route_event`](DriverCore::route_event)
///   — which ENSURES the entry, creating it when none exists, so the memory is
///   scope-persistent rather than fence-scoped: a loss landing OUT of any
///   reconcile window (after a clean settle, before the next `on_set_cover`)
///   is still remembered until the next settle observation, and the same
///   `Rescan` immediately degrades a narrowed `applied_cover` claim to the
///   empty cover (see [`ScopeState::applied_cover`]); and
/// - any reconcile whose grow observed a [`RearmKickoff::Coalesced`] — the
///   obligation rides an in-flight COLD read the settle counter deliberately
///   does not see, so the scope can read settled while the obligation is
///   latent (lossy **from birth**, per the fence design's F0 amendment).
///
/// A third source is a standing CONDITION rather than an event, so it is read
/// at the settle observation instead of being remembered here: a registration
/// window's unanswered classification stat
/// ([`Monitor::bootstrap_stat_outstanding`], read in
/// [`poll_cover_settlements`](DriverCore::poll_cover_settlements)). An event
/// mark would be spent by the first observation to pass while the slot stayed
/// dark, so the condition is re-read every time a verdict is minted.
///
/// Either event marks every currently-pending fence lossy AND is remembered
/// here until the scope next settles, so a fence opened AFTER the event but
/// BEFORE that settle inherits it — a reply-less reconcile
/// (`request_set_cover`) that coalesced still degrades the fence the driver
/// opens for a later acked reconcile of the same window, and the first
/// reconcile issued after an out-of-window loss degrades honestly (its re-arm
/// work is re-attempted against the degraded claim; a second clean re-issue
/// then applies). The settle observation clears the memory with the fences —
/// a pending-empty entry created by an out-of-window `Rescan` included — so
/// nothing leaks onto a fence opened after it. A corollary: every fence
/// resolving at one settle reports the same verdict — lossiness only accretes
/// between settles, an opening fence inherits the accreted state, and a loss
/// marks all pending — which is the honest shape: covers applied within one
/// unsettled window ride each other's re-arm work, so none of them can claim
/// a cleaner window than the scope's.
///
/// # The tranche rule
///
/// One ordering proof does not necessarily speak for every fence the entry
/// holds: it licenses only those that were already open when it was requested
/// (see [`CutProof`]). Fences therefore carry the ordinal they were opened at,
/// and because they are held in open order the ones a proof licenses are always
/// a PREFIX of the list. A settle observation resolves that prefix and leaves
/// the rest pending, with their accrued lossiness intact, to be offered a
/// successor proof.
///
/// The entry itself — the scope's loss memory, and the applied-cover repair
/// that rides its removal — is spent only when the LAST pending fence goes. A
/// claim is never promoted over a stretch of the window no proof has ordered
/// yet, and the loss memory a straggler may still need is never cleared out
/// from under it.
///
/// [`RearmKickoff::Coalesced`]: tributary_proto::RearmKickoff::Coalesced
#[derive(Debug, Default)]
struct CoverFence {
  /// Pending fences in open (FIFO) order, so their ordinals ascend and the
  /// fences one proof licenses are a prefix.
  pending: Vec<PendingFence>,
  /// The scope's loss memory since the last settle observation (see the
  /// lossy-window rule above).
  lossy: bool,
  /// Open ordinals minted for this entry so far. Per entry, which is the only
  /// scale the tranche rule compares at: a proof's mark lives on this same
  /// entry and dies with it.
  opened: u64,
  /// How far a clean verdict is licensed, and what is out to license the rest —
  /// see [`CutProof`].
  cut: CutProof,
}

/// One fence awaiting its scope's settle.
#[derive(Debug, Clone, Copy)]
struct PendingFence {
  /// The id the driver parked this caller's reply under.
  fence: FenceId,
  /// Whether this fence's window has taken loss — inherited from the entry's
  /// memory at open, then set by every later loss event.
  lossy: bool,
  /// Where this fence sits in its entry's open order, counted from one. An
  /// ordering proof licenses exactly the fences it reaches (see [`CutProof`]).
  opened: u64,
}

impl CoverFence {
  /// Records `fence` as pending: it takes the next open ordinal and inherits
  /// the loss memory the scope has accrued since its last settle observation.
  fn open(&mut self, fence: FenceId) {
    self.opened += 1;
    self.pending.push(PendingFence {
      fence,
      lossy: self.lossy,
      opened: self.opened,
    });
  }

  /// Records one loss event: remembered until the next settle observation and
  /// stamped onto every pending fence.
  fn mark_lossy(&mut self) {
    self.lossy = true;
    for pending in &mut self.pending {
      pending.lossy = true;
    }
  }

  /// The newest pending fence's ordinal — the mark a proof must reach to
  /// license this entry's whole pending set.
  ///
  /// Zero when nothing is pending. Such an entry still owes a proof before its
  /// settle observation may repair the applied-cover claim, but it has no fence
  /// to exclude, so any proof taken under the current epoch reaches it.
  fn high_water(&self) -> u64 {
    self.pending.last().map_or(0, |pending| pending.opened)
  }
}

/// Whether this fence has forced the source to surface what the kernel already
/// holds, which is what a CLEAN verdict rests on.
///
/// The barrier's counted work — arms, re-arms, enumerates — proves the coverage
/// was rebuilt. It does NOT prove the kernel had nothing queued while that
/// happened: an enumerate completes on the blocking pool and never crosses the
/// reader, and a re-issued or pruning cover can settle with no counted work at
/// all. In both cases the settle-edge drain sees only what the reader has
/// ALREADY forwarded, so a record the kernel committed but nobody has read yet
/// sits in no lane and the drain reads trivially spent.
///
/// One empty control batch closes that: the reader cuts its kernel queue onto
/// the lane before answering ANY batch, so the reply is an ordering proof —
/// whatever the kernel held is ingested ahead of it.
///
/// # What one proof licenses
///
/// A proof speaks for the WINDOW AS IT STOOD WHEN THE REQUEST WAS MADE — not
/// for all time and not for the scope at large — so it licenses a clean verdict
/// on one condition, read along both axes that window has:
///
/// **A proof licenses a fence iff the fence was already pending when the proof
/// was requested AND the scope has acquired no coverage work since.**
///
/// The two halves are the same statement about the same instant. The request
/// records the scope's coverage-work epoch ([`Monitor::coverage_work_epoch`])
/// and the open ordinal of the newest fence then pending — one [`CutMark`] —
/// and the reply's proof inherits it whole. Work acquired afterwards moves the
/// epoch and voids the proof outright; a fence opened afterwards takes a higher
/// ordinal and is simply not among those it speaks for — the earlier fences it
/// genuinely ordered keep it. Neither half is a special case of the other: work
/// can be acquired with no fence opening, and a fence can open with no work
/// acquired at all.
///
/// Both are checked against the scope AS IT READS NOW rather than against a
/// list of events that invalidate a proof, which is what makes the rule total:
/// nothing has to hunt down the marks a scope holds when its epoch moves,
/// because a mark stamped under a departed epoch licenses nothing wherever it
/// sits, and an epoch never returns.
///
/// # A request is not a proof
///
/// A request and the proof it will mint are therefore kept apart, and the entry
/// holds both at once: the PROVEN PREFIX — the strongest mark a completed cut
/// has earned, which is the only thing that licenses a verdict — and the
/// SUCCESSOR IN FLIGHT, the request out for the fences that prefix does not
/// reach. Latching a successor records that a request exists and nothing more:
/// authority already earned is not evidence about a window still being ordered,
/// so it can neither be spent by one nor lowered by one. A completed request
/// retires into the prefix and only ever moves it forward — across an epoch its
/// mark replaces the prefix outright, since carrying an older stamp's reach onto
/// a newer one would claim an ordering that cut never took, and within one epoch
/// the further reach wins.
///
/// Holding one slot for both would confuse a claim with an answer, and the
/// driver's loop makes that fatal rather than merely lossy: it latches the
/// successors it is offered ABOVE the settlement it resolves below, so a window
/// taking one new fence per round would have every successor erase the proof
/// that had just landed for its predecessors, and no fence would ever resolve.
///
/// # Why a binding and not a list
///
/// The barrier ([`Monitor::coverage_settled`]) is a conjunction over several
/// kinds of coverage work, each of them "the scope holds none of this". So it
/// can go settled → unsettled → settled again through work the proof knows
/// nothing about: a proven cut forwards a `MovedFrom` whose held-source
/// obligation is created only when the settle-edge drain ingests it, and a
/// paired `MovedTo` then releases the hold. An overflow the kernel committed
/// after the cut can still be sitting unread across that whole round, and a
/// proof kept valid through it would certify exactly the record it existed to
/// surface. Enumerating such edges cannot be made to hold: the enumeration is
/// complete only until the barrier grows another conjunct.
///
/// So the proof carries the scope's coverage-work epoch
/// ([`Monitor::coverage_work_epoch`]) — a counter that advances whenever the
/// scope acquires work ANY conjunct counts — and licenses a clean verdict only
/// while the scope still reads that epoch. Since a conjunct can only turn from
/// settled to unsettled by acquiring work, an unchanged epoch means the window
/// the cut ordered was never re-opened, for every conjunct at once.
///
/// # Convergence
///
/// A scope that keeps acquiring work keeps invalidating proofs, which costs
/// nothing: it is not settled, so it is offered no fence and asked for no
/// proof. The epoch does NOT move on a release, so a scope that settles and
/// then stays settled holds it fixed, and the next proof taken over it survives
/// to certify. Progress therefore needs only quiescence, not quiet.
///
/// The ordinal converges for a reason of its own, and it is why a request
/// already in flight is never displaced by a fence opened behind it: every
/// request licenses every fence pending at the instant it was latched, so each
/// completed proof resolves at least the whole tranche that was waiting when it
/// left, and the fences that joined behind it are offered a successor the
/// moment it lands ([`covers_awaiting_cut`](DriverCore::covers_awaiting_cut)
/// compares the proven prefix's reach against the newest pending ordinal).
/// Arrival rate therefore cannot outrun resolution: a fence waits on the first
/// request latched after it opened, and on no more than one round trip beyond
/// the one already out.
///
/// # What the epoch does not cover
///
/// A reconcile whose prune drops a watch subtree MOVES coverage without
/// acquiring any: a drop only releases work, so no funnel bumps the epoch, yet
/// the window is no longer the one the proof was taken over. That one discards
/// the latch at its own site — proven prefix and request in flight alike, since
/// neither speaks for the window that remains. Without it a proof spent on one
/// cascade would license a second cascade joining the same entry: the whole
/// defect, one level up.
///
/// A reconcile that grows nothing and prunes nothing is NOT one of them, and
/// must not reset. It leaves the window exactly as the standing proof found it,
/// so that proof still orders every record the window can hold. Discarding it
/// there would buy no ordering at all, and would cost far more than a round
/// trip: such re-issues can arrive faster than a cut completes, so every proof
/// that completed would land on a latch some later re-issue had already reset,
/// and the window would never settle clean.
///
/// A newly opened fence is not one of them either, and for a stronger reason: it
/// needs no reset at all. Its ordinal already places it outside every standing
/// request's reach, which is strictly more precise than resetting — the coarser
/// rule threw away a proof that was still perfectly good for the fences it had
/// ordered, so a scope taking acknowledged covers faster than a cut completes
/// lost every proof to the next fence and settled none of them.
///
/// It is deliberately NOT the retired settle-edge observation gate: there is no
/// observation record to hold valid, no serial, no lane generation and no
/// completion flag, and the ordering is bought by a cut the reader already
/// performs rather than by a new mechanism.
///
/// # Why a lossy window owes one too
///
/// The proof is owed for the WINDOW, not for the claim the verdict will make.
/// More loss genuinely cannot falsify a degraded verdict — but the cut is not
/// there to surface loss, it is there to surface whatever the kernel holds
/// unread, and that includes DEATH. A root renamed away while its
/// `IN_MOVE_SELF` sits unread in the kernel queue is a scope that no longer
/// exists, and a `Degraded` is a LIVE verdict: it answers its caller and
/// dispatches the parked cookie write, which then lands in a recreated,
/// unmonitored directory and is reported `Ok` for a record no stream can ever
/// deliver. The scope's death is processed afterwards, and the loss that
/// degraded the window covers nothing that happened after it. The omitted cut is
/// exactly what would have put that record on the lane first, folding the fence
/// to [`CoverSettle::Dead`] and refusing the cookie. So every live fence asks,
/// whatever verdict it is heading for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct CutProof {
  /// The prefix already proven: the strongest mark a completed cut has earned
  /// for this entry, and the only thing here that licenses a verdict. `None`
  /// until one lands.
  proven: Option<CutMark>,
  /// The request out for the fences `proven` does not reach. At most one is ever
  /// out, and what the window does behind it leaves it alone.
  in_flight: Option<CutRequest>,
}

/// The window one cut speaks for, stamped at the instant its request was
/// committed to and inherited unchanged by the proof it mints.
///
/// The stamp is the scope's [`Monitor::coverage_work_epoch`] at that instant, and
/// the value it carries is the open ordinal of the newest fence then pending —
/// the last fence this cut reaches. Keeping the reach [`Stamped`] is what makes
/// the epoch check unskippable rather than merely required: the mark licenses
/// nothing at any other epoch, there is no way to read the reach at all without
/// naming the epoch it is being read under, and the epoch cannot be named
/// without reading it off the Monitor — a [`CoverageWorkEpoch`] is unforgeable
/// here, so no site can satisfy the check with the stamp the mark already
/// carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct CutMark(Stamped<CoverageWorkEpoch, u64>);

/// A cut that has been asked for: the token of the batch carrying the request,
/// and the mark that batch's completion earns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct CutRequest {
  /// Identifies the request, so only the completion of the batch that actually
  /// carried it can close this one.
  token: u64,
  /// What the reply will prove — the window as it stood when the request was
  /// committed to, never as it stands when the reply lands.
  mark: CutMark,
}

impl CutMark {
  /// The mark a cut taken under coverage-work epoch `epoch` earns: it reaches
  /// the fences through open ordinal `covers` and no further.
  const fn new(epoch: CoverageWorkEpoch, covers: u64) -> Self {
    Self(Stamped::new(epoch, covers))
  }

  /// The stronger of two marks: a later epoch wins outright, and within one
  /// epoch the further reach does.
  ///
  /// Reaches never merge across epochs. Only one epoch is ever current, so the
  /// older stamp already licenses nothing, and carrying its reach onto the newer
  /// one would claim an ordering the newer cut never took. The comparison
  /// therefore decides which mark is kept WHOLE and nothing else, and it is made
  /// inside the stamped value so that neither reach has to be read out to make
  /// it: a reach is still only ever read under an epoch the scope currently
  /// holds.
  fn strongest(self, other: Self) -> Self {
    if other.0.supersedes(&self.0) {
      other
    } else {
      self
    }
  }

  /// How far this mark licenses a CLEAN verdict at `epoch` — nothing at all
  /// unless it was stamped under exactly the coverage work the scope still
  /// holds.
  fn reach(self, epoch: CoverageWorkEpoch) -> Option<u64> {
    self.0.current(epoch).copied()
  }
}

impl CutProof {
  /// Whether this latch already speaks for every fence through `high_water` at
  /// `epoch`, and so owes no fresh cut.
  ///
  /// A request stamped under the current epoch does, whatever has opened behind
  /// it: it will license everything that was pending when it left, and asking
  /// again would only orphan it — a scope taking fences steadily would then
  /// cancel every request before its reply could land, and the fences it was
  /// bought for would wait on a reply nothing can close. The proven prefix does
  /// only as far as its reach, so fences opened past it are what provoke a
  /// successor once nothing is out. Anything stamped under an epoch the scope
  /// has since left speaks for nothing, a request included, because its reply
  /// could only ever mint a proof that is stale on arrival.
  fn answers_for(self, epoch: CoverageWorkEpoch, high_water: u64) -> bool {
    match (self.in_flight, self.proven) {
      // A request licenses its whole tranche or nothing, so its reach is not
      // consulted — only whether it still speaks at this epoch at all.
      (Some(request), _) if request.mark.reach(epoch).is_some() => true,
      (_, Some(proven)) => match proven.reach(epoch) {
        Some(covers) => covers >= high_water,
        None => false,
      },
      _ => false,
    }
  }

  /// The open ordinal through which a CLEAN verdict is licensed at `epoch`.
  ///
  /// Only the proven prefix licenses anything, and only as far as the tranche
  /// its request was made behind. A stale prefix and a request still out both
  /// license nothing: the fences beyond withhold, and the window asks again.
  fn licenses_through(self, epoch: CoverageWorkEpoch) -> Option<u64> {
    match self.proven {
      Some(proven) => proven.reach(epoch),
      None => None,
    }
  }

  /// Puts `token`'s request out for `mark`'s window. The proven prefix is left
  /// exactly as it stands: a successor is a claim about a window still being
  /// ordered, never evidence against one already ordered.
  fn latch(&mut self, token: u64, mark: CutMark) {
    self.in_flight = Some(CutRequest { token, mark });
  }

  /// Retires the request in flight into the proven prefix, raising it to that
  /// request's mark — but only for the token actually out, so every other
  /// completion is inert.
  fn prove(&mut self, token: u64) {
    let Some(request) = self.in_flight.take_if(|request| request.token == token) else {
      return;
    };
    self.proven = Some(
      self
        .proven
        .map_or(request.mark, |proven| proven.strongest(request.mark)),
    );
  }

  /// Discards everything the latch holds — proven prefix and request in flight
  /// alike — because the window they were taken over is no longer the one this
  /// entry stands for.
  fn invalidate(&mut self) {
    *self = Self::default();
  }
}

/// A planned Monitor input, compiled from one raw event.
#[derive(Debug)]
enum Planned {
  /// Feed a normalized record.
  Rec(OsRecord),
  /// Feed an overflow for a scope slice.
  Over(Scope),
}

/// One raw event's compilation: its planned inputs, possibly gated on a probe.
#[derive(Debug)]
struct Item {
  planned: Vec<Planned>,
  probe: Option<ProbeId>,
  /// A vanished rename half's cookie candidacy `(fileID, source path)`:
  /// granted at settlement iff a same-batch partner's probe evidenced the
  /// fileID on the root device AND the vanished path itself lies under no
  /// foreign prefix of the still-monotone table.
  cookie_candidate: Option<(NonZeroU64, PathBuf)>,
}

/// A batch whose items are being resolved; fed to the Monitor only once every
/// probe has answered, so per-root input order is preserved. `trailing`
/// inputs (a covering rescan for an ambiguous rename group) apply after every
/// item, so whatever the items degraded to is dominated.
///
/// A profile that answers [`feeds_at_classify`] has no probes to wait on and
/// hands its items over during the fence, so what reaches `settle` here is the
/// `trailing` tail alone; the ordering statement above is unchanged, since the
/// items went first either way.
#[derive(Debug)]
struct PendingBatch {
  items: Vec<Item>,
  awaiting: usize,
  trailing: Vec<Planned>,
  /// The batch's transport budget slot, held for as long as the compiled
  /// items are retained: parked memory then counts against the same budget
  /// that bounds the queue, so a stuck probe back-pressures the callback
  /// instead of growing the park unbudgeted. Dropped when the batch settles
  /// or is discarded (loss flush, scope teardown) — RAII, every path.
  permit: Option<BudgetPermit>,
  /// Unmount trust-removals deferred to the batch's settlement: removing a
  /// foreign prefix only ever INCREASES trust, so it must not happen before
  /// every one of the batch's classification and cookie decisions has run
  /// (the monotone-within-batch rule).
  deferred_unmounts: Vec<PathBuf>,
  /// fileIDs a `Present` rename probe bound to the root device in THIS batch,
  /// each with EVERY partner path that carried the proof — the contemporaneous
  /// evidence a vanished partner's cookie grant requires at settlement.
  /// Evidence exists only under the temporal bind: the partner's EVENT word
  /// carried the same fileID its probe observed (a probe-only fileID proves
  /// what occupies the path NOW, not what the batch's events were about).
  /// All partners are kept, not a representative: a grant demands exactly one
  /// (see [`DriverCore::grant_evidenced_cookies`]), and probe completion
  /// order must not decide which partner a cover points at.
  evidenced: BTreeMap<NonZeroU64, Vec<PathBuf>>,
}

/// Per-root batch parking: while a batch has probes in flight, later batches
/// queue behind it rather than overtaking it. Both the active batch and every
/// queued payload keep holding their transport budget slot (see
/// [`BatchPayload`]), so the park's memory is bounded by the same budget as
/// the queue's.
#[derive(Debug, Default)]
struct Park {
  active: Option<PendingBatch>,
  queued: VecDeque<BatchPayload>,
}

/// Why a probe was issued, and how to plan its resolution.
#[derive(Debug)]
enum ProbePurpose {
  /// A multi-verb flag word needed existence to ground a single record.
  Ambiguous {
    item: usize,
    flags: FsEventFlags,
    target: Option<Location>,
    path: PathBuf,
  },
  /// An unpaired rename half needed existence to pick its direction.
  Rename {
    item: usize,
    file_id: Option<NonZeroU64>,
    target: Option<Location>,
    path: PathBuf,
    /// Whether the half may mint a pairing cookie at all — `false` for a
    /// member of an ambiguous same-fileID group, whose shared id must not
    /// pair anything.
    allow_cookie: bool,
    /// The word also carried content/attrib bits; a surviving object then
    /// owes a grounded `Modified` alongside the move half.
    content_changed: bool,
  },
  /// A `RootChanged` needed the root's existence to pick the death signal.
  RootAlive { item: usize },
  /// An [`Action::Stat`](tributary_proto::Action::Stat) — the kind of a slot a
  /// listing could not classify. It belongs to no batch: the Monitor asked for
  /// it directly, and its answer goes straight back through
  /// [`Monitor::on_stat_result`], so it never parks an item or grounds a
  /// record.
  SlotKind { req: ReqId },
}

#[derive(Debug)]
struct ProbeCtx {
  scope: ScopeId,
  purpose: ProbePurpose,
}

/// How long a refused parked delivery waits before it is offered again. The
/// retry rides the core's own timer: an immediate re-offer would spin the
/// executing loop without yielding (the channel cannot drain meanwhile), so a
/// lagged consumer is polled at this bounded interval instead.
const DELIVERY_RETRY: Duration = Duration::from_millis(25);

/// The consumer-lag state of one scope. Events are only ever dropped while a
/// dominating `Rescan` is parked and undelivered, so the consumer's
/// post-`Rescan` re-enumeration provably covers them.
///
/// INV-PARK: the parked coverage never narrows while the lag stands. Every
/// `Rescan` routed while lagged — including a LOCATED one (a deficit
/// re-signal, an incomplete read, a failed arm) — is folded in by
/// [`DriverCore::covering_merge`]: the location becomes the join of the two
/// subtree coverages (their longest common prefix) and the id + epoch become
/// the newest mint's. So the promised drop set only ever grows, and the one
/// delivered instruction carries an epoch that dominates everything dropped
/// under it.
#[derive(Debug)]
enum LagState {
  /// Deliveries flow.
  Normal,
  /// The consumer channel refused a change: a dominating `Rescan` is parked
  /// (or being minted, while `parked` is `None`) and everything else for the
  /// scope is dropped as dominated.
  Lagged {
    parked: Option<Change>,
    attempt: Attempt,
  },
}

/// The delivery lifecycle of a parked `Rescan`.
#[derive(Debug, Clone, Copy)]
enum Attempt {
  /// Ready to be offered by [`DriverCore::poll_effect`].
  Idle,
  /// Offered and awaiting its [`DriverCore::on_delivery`] outcome; carries
  /// the offered change's epoch so an acceptance of a since-replaced
  /// `Rescan` retries the newer one rather than ending the lag.
  InFlight(tributary_proto::Epoch),
  /// Refused; re-offered once the retry deadline passes.
  Spent {
    /// When the next offer becomes due.
    retry_at: Instant,
  },
}

/// A torn-down scope's terminal `Rescan`, retried until the consumer accepts
/// it. Teardown ends the OS stream immediately, but the one change covering
/// everything the dead scope dropped must survive refusals — a plain queued
/// emit is one-shot, with no scope state left to re-park it on a full channel.
#[derive(Debug)]
struct DyingDelivery {
  change: Change,
  attempt: Attempt,
  /// The dead scope's canonical root, retained so the terminal delivery (and
  /// any straggler routed through the dying entry) still assembles after the
  /// scope state — and the consumer-side registry entry — are gone.
  root: Arc<PathBuf>,
}

/// One watched root's driver-side state.
#[derive(Debug)]
struct ScopeState {
  watch: WatchId,
  /// The [`ArmAttempt`] of the root's BOOTSTRAP arm — the one
  /// `Action::Watch(Root)` a registration ever queues, captured when the
  /// action is consumed because the spawn path answers it out of band (a
  /// kernel-recursive stream inline, a descending root through its own
  /// `AddWatch`). `None` until the action is drained.
  root_attempt: Option<ArmAttempt>,
  /// The backend lowering profile registration intended; the spawned
  /// source's [`RootMeta`] must agree.
  profile: BackendKind,
  requested: PathBuf,
  /// Canonicalized root bytes — known once the stream spawned. Shared so
  /// every delivery can carry it without copying.
  root: Option<Arc<PathBuf>>,
  root_dev: Option<u64>,
  /// The root's MOUNT id — the descent boundary the enumerate lowering fences on.
  /// A child directory on a different mount (even the SAME device, as a
  /// `mount --bind` of a same-superblock directory produces) is lowered
  /// non-descendable, closing the same-device bind breach the `root_dev` check
  /// alone cannot. Captured at the spawn barrier AND re-read on every alive,
  /// NON-STALE mount refresh: a same-object re-mount of the root (unmount + re-bind,
  /// identity unchanged) moves it to a new mount, so a frozen value would fence every
  /// descendant on the new mount as a boundary — the refresh keeps it current
  /// (`on_mounts_refreshed` adopts a fresh `Some`, then reconciles a descending
  /// scope's coverage when the frame changed). Only ever the last AUTHORITATIVE frame
  /// — a stale refresh publishes nothing here (see the module doc's mount-refresh
  /// publication invariant). `None` when neither the barrier nor a refresh could read
  /// it (below Linux 5.8, or a non-Linux/fake source), and then the device check
  /// governs alone — the honest degrade.
  root_mnt_id: Option<u64>,
  /// The root object's identity, captured at the spawn barrier. The mount
  /// refresh re-stats the root and compares against this: a `Missing` or
  /// mismatched read is a root death, lowered through the same self-event path
  /// a `RootChanged` probe uses (kernel-recursive backends have no in-tree
  /// unmount signal, so the refresh cadence is their root-liveness check).
  /// `None` for a scope whose barrier read no identity (off-unix fakes).
  identity: Option<RootIdentity>,
  /// Foreign-device prefixes under the root: seeded from the live mount
  /// table at spawn, then maintained by Mount/Unmount events and probed
  /// devices. Tiny in practice, so a linear scan beats indexing.
  mounts: Vec<PathBuf>,
  /// Whether `mounts` is backed by an authoritative read of the live mount
  /// table (the spawn seed, or a post-loss refresh). Without it, a path not
  /// covered by a known mount prefix proves nothing (the table is blind), so
  /// event-side device trust is refused. Revoked by every loss signal — a
  /// dropped window may have carried a mount transition.
  mounts_authoritative: bool,
  /// An [`Effect::RefreshMounts`] is outstanding; repeated loss signals
  /// coalesce onto it instead of stacking effects.
  refresh_pending: bool,
  /// A loss signal arrived while a refresh was in flight: that snapshot may
  /// predate the newly-lost window, so its result is discarded and one more
  /// refresh re-arms.
  refresh_stale: bool,
  /// A root REPLACE committed while a refresh was in flight: that snapshot
  /// describes the replaced world, so EVERYTHING it carries — the liveness
  /// verdict included — is about an object this scope no longer watches.
  /// Its result is discarded whole and one refresh re-arms against the live
  /// world. Distinct from [`refresh_stale`](Self::refresh_stale), which
  /// gates only the table/frame: same-world death evidence must survive a
  /// loss, but a cross-world verdict must not survive a replace.
  refresh_world_stale: bool,
  lag: LagState,
  park: Park,
  /// The journal id counter wrapped; any minted resume token is invalid.
  resume_poisoned: bool,
  /// Whether public delivery has begun — the never-live fence's real fact. A
  /// scope is publicly live once its CALLER holds a handle: for a kernel-
  /// recursive backend that is the spawn (the live stream is the coverage, the
  /// grant commits inline), but for a descending backend it is the ROOT ARM
  /// SUCCESS, not the spawn — the source starts with no watches, so `root`
  /// being populated at spawn does NOT yet mean anything is delivered. The
  /// [`DeferredGrant`](crate::driver::DeferredGrant) dates the caller's handle
  /// from the same root arm, so a root arm that FAILS answers the caller `Err`
  /// and leaves this `false`: [`route_event`](DriverCore::route_event) then
  /// drops the Monitor's internal failure `Rescan` instead of emitting a public
  /// event for a registration no one owns.
  publicly_live: bool,
  /// When this scope's root is next re-stat'd for liveness, for a
  /// signal-silent-on-unmount backend (fanotify) under a non-zero interval.
  /// `None` for every other backend, before the root goes live, and while the
  /// tick is disabled — the loss-triggered refresh remains its own path. Seeded
  /// once the birth refresh confirms the root alive and re-armed by
  /// [`on_timeout`](DriverCore::on_timeout) after each tick fires.
  liveness_deadline: Option<Instant>,
  /// The retained cover this scope's per-directory coverage was last reconciled to by
  /// [`on_set_cover`](DriverCore::on_set_cover) — `None` is FULL coverage (the initial,
  /// never-pruned state). The broadening delta a later set-cover must re-arm is computed
  /// against THIS previously-applied cover ([`broadening_delta`]), never against which
  /// watches happen to exist: a narrower cover deliberately keeps the connecting ANCESTORS
  /// of its retained prefixes armed while pruning their other descendants, so an exact-path
  /// "is a watch present at this prefix" test would wrongly read a retained ancestor as
  /// fully covered and skip re-arming the descendants the earlier cover pruned — silent loss
  /// after the bridge Rescan's crawl. Set on every successful `on_set_cover`;
  /// initialized `None`. **Optimistic**: recorded before the grow's re-arm
  /// work completes, so a LOSSY settle rewinds it to `settle_floor` (the
  /// applied-cover-lie fix — see `settle_floor`), and a public scope `Rescan`
  /// degrades a `Some` claim IMMEDIATELY to the EMPTY cover (nothing below
  /// the root is claimed): the loss may have hollowed the claim even with no
  /// reconcile in flight, so the next `on_set_cover` computes a full
  /// broadening delta and re-proves the coverage it requests
  /// ([`route_event`](DriverCore::route_event)'s lossy-window handling).
  applied_cover: Option<Vec<PathBuf>>,
  /// The coverage provably live regardless of grow outcomes: the running
  /// antichain MEET ([`cover_meet`]) of every cover applied since the last
  /// CLEAN settle observation — `None` is FULL coverage, the meet identity.
  /// Retained-and-covered survivors are never re-armed by a reconcile, so
  /// meet-coverage never gapped even when every grow arm failed. Updated on
  /// EVERY `on_set_cover` application (acked or reply-less); at each settle
  /// observation ([`poll_cover_settlements`](DriverCore::poll_cover_settlements)):
  /// a CLEAN settle resets it to the now-truthful `applied_cover`, a LOSSY
  /// settle rewinds `applied_cover` to it (it IS the floor, so it stays).
  /// A public scope `Rescan` degrading a narrowed `applied_cover` folds this
  /// floor down with it (the meet with the empty cover is the empty cover),
  /// so the observation-time rewind cannot resurrect the pre-loss claim.
  /// Without the rewind a re-issue after a failed grow would compute an empty
  /// [`broadening_delta`] and settle clean over a hole; under-claiming only
  /// costs redundant re-reads.
  settle_floor: Option<Vec<PathBuf>>,
  /// A same-transport widen's WITNESSED WINDOW (INV-ROOT), open from the
  /// reservation of the widened root's watch id to the commit gate. The
  /// reserved watch is pre-armed on the LIVE lane under a Monitor-unknown id,
  /// so its kernel records would drop silently at the Monitor's unknown-watch
  /// guard; the inotify lowering (`plan_inotify`) intercepts them HERE
  /// instead — before the guard: a death record taints the window, benign
  /// churn is counted and left to the post-commit cold read. Every scope loss signal ([`on_root_overflow`](DriverCore::on_root_overflow))
  /// taints too — a loss may have carried the death records themselves. The
  /// commit ([`on_root_widened`](DriverCore::on_root_widened)) consumes the
  /// window and refuses a tainted one into the stream-replace fallback, so
  /// the barrier never certifies over a binding whose window was not
  /// provably clean — verification by witness, never by an out-of-band
  /// identity sample (which cannot distinguish a live watch from an IGNORED
  /// one over a same-identity rebind).
  pending_widen: Option<PendingWiden>,
}

/// What one record owes the exclusion geometry, decided from the Monitor's own
/// report of what that record did to the watch tree.
///
/// Read entirely on the far side of the record's hand-off to the Monitor
/// ([`reparent_geometry`](DriverCore::reparent_geometry)): nothing about a rename's
/// consequences is knowable before the Monitor has decided them, so there is no
/// pre-feed half and no verdict a pre-feed half could return.
#[derive(Debug)]
enum Geometry {
  /// The record carries no geometry, or its rename left the geometry unchanged,
  /// or the Monitor relocated nothing.
  Nothing,
  /// A repair to queue directly BEHIND the record: the Monitor's own located
  /// loss signal at the rename's destination, so the re-enumeration is lowered
  /// against the path the subtree actually landed at.
  Repair(Planned),
}

/// The witnessed window of one pending same-transport widen (INV-ROOT): the
/// reserved root's binding is provably live at the commit iff the window saw
/// neither a reserved death record nor a scope loss signal. Created by
/// [`begin_widen_watch`](DriverCore::begin_widen_watch) BEFORE the pre-arm
/// dispatch (so no reserved-attributed record can predate it), consumed by the
/// commit gate, cleared by [`abort_widen_watch`](DriverCore::abort_widen_watch)
/// on a failed pre-arm and by [`on_root_replaced`](DriverCore::on_root_replaced)
/// when the fallback replace commits over it.
#[derive(Debug)]
struct PendingWiden {
  /// The reserved root [`WatchId`] the pre-arm bound on the live lane.
  reserved: WatchId,
  /// The witness verdict: `Some` once the window tainted. First cause wins —
  /// the earliest signal is the one that ended the window's cleanliness.
  tainted: Option<TaintCause>,
  /// Benign (non-death) reserved records the latch consumed — the churn the
  /// post-commit cold read converges. Diagnostic surface for the fallback.
  benign: u32,
}

impl PendingWiden {
  fn taint(&mut self, cause: TaintCause) {
    self.tainted.get_or_insert(cause);
  }
}

/// Why a witnessed widen window tainted (INV-ROOT) — the diagnostic the
/// fallback carries, mirroring the transport `Fatal`'s carried class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaintCause {
  /// The reserved root's own death record: `Ignored` (⊇ unmount), `MoveSelf`,
  /// or `DeleteSelf`, attributed to the reserved watch inside the window.
  RootDeath(RecordKind),
  /// A transport loss signal for the scope (overflow, decode loss, budget
  /// refusal) — the window may have lost the death records themselves, so it
  /// can no longer witness their absence.
  Loss,
}

/// A tainted window's diagnostics, carried on the commit refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WidenTaint {
  /// What ended the window's cleanliness.
  pub(crate) cause: TaintCause,
  /// How many benign reserved records the latch consumed before the verdict.
  pub(crate) benign: u32,
}

/// How [`on_root_widened`](DriverCore::on_root_widened) disposed of a
/// same-transport widen commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum WidenCommit {
  /// The splice applied; the widen is live on the same transport. Carries the
  /// [`ArmAttempt`] the pre-armed root's replayed outcome must be reported
  /// under — the splice mints it, so an outcome naming any other attempt is a
  /// superseded arm's and is discarded.
  Committed(ArmAttempt),
  /// The witnessed window tainted (INV-ROOT): a reserved death record or a
  /// scope loss signal landed between the reservation and this commit, so
  /// the binding cannot be proven live. Core and Monitor are untouched
  /// except that the spent window is consumed; the caller disarms the
  /// pre-armed descriptor and falls back to the general stream replace,
  /// whose spawn barrier re-establishes the binding from scratch. A
  /// LEGITIMATE outcome, never a driver bug.
  TaintedWindow(WidenTaint),
  /// A violated precondition on a path the driver's gates make unreachable —
  /// core and Monitor bit-identical (the window entry included), the caller
  /// treats it loudly and falls back to the stream replace, whose commit
  /// clears the leftover window.
  Refused,
}

impl ScopeState {
  /// The root every delivery of this scope carries: the canonical root once
  /// the stream spawned, else the consumer-supplied path (the defensive floor
  /// for a scope that dies before its spawn result lands).
  fn delivery_root(&self) -> Arc<PathBuf> {
    self
      .root
      .clone()
      .unwrap_or_else(|| Arc::new(self.requested.clone()))
  }
}

/// Where a path fell relative to its scope root.
enum Lowered {
  /// The root itself.
  Root,
  /// A descendant, as a root-relative location.
  Target(Location),
  /// Not under the root (above it, unrelated, or unrepresentable) — the
  /// caller escalates, never drops.
  Outside,
}

/// The sans-I/O driver core. See the module docs for the shape.
#[derive(Debug)]
pub(crate) struct DriverCore {
  monitor: Monitor,
  scopes: BTreeMap<ScopeId, ScopeState>,
  watch_scopes: BTreeMap<WatchId, ScopeId>,
  /// Outstanding enumerate requests: the scope whose state mints entry
  /// identities when the raw listing returns, plus the directory the read was
  /// ISSUED against.
  ///
  /// That path is a HISTORICAL fact — where the directory was when this core
  /// asked for its listing — and is deliberately not re-derived on completion.
  /// It is not a second addressing map: nothing arms or opens by it (the
  /// executor lists through the directory's own anchor, which follows the inode
  /// across a rename), and its one live consumer is the cold half of the
  /// exclusion fence. A rename that moves the read directory across an exclusion
  /// boundary is answered by the geometry pass's located repair
  /// ([`reparent_geometry`](Self::reparent_geometry)), whose re-arm issues a
  /// FRESH read against the destination; this in-flight one was compiled against
  /// the pre-move world and is superseded rather than patched.
  enum_reqs: BTreeMap<ReqId, (ScopeId, Arc<PathBuf>)>,
  probes: BTreeMap<ProbeId, ProbeCtx>,
  effects: VecDeque<Effect>,
  /// Terminal `Rescan`s of torn-down scopes, each retried until accepted.
  /// Scope handles are never reused, so a dead scope's key cannot collide
  /// with a live one.
  dying: BTreeMap<ScopeId, DyingDelivery>,
  /// Per-scope set-cover fence bookkeeping (see [`CoverFence`]'s lossy-window
  /// rule). An entry exists exactly while the scope has an unobserved
  /// reconcile OR an unobserved loss signal — created by every `Reconciling`
  /// [`on_set_cover`](Self::on_set_cover) (acked or not, so a reply-less
  /// reconcile's window is still observed and its loss memory still clears)
  /// and by every public scope `Rescan`, whatever the profile (so an
  /// out-of-window loss is remembered, not dropped with the window), removed
  /// by the settle observation or the scope's teardown. No entry may outlive
  /// its scope.
  ///
  /// A kernel-recursive scope takes the mark too: `sync_root` fences any
  /// profile, so exempting it left a real queue overflow invisible to a
  /// pending sync fence.
  cover_fences: BTreeMap<ScopeId, CoverFence>,
  /// Fences a scope teardown resolved (always [`CoverSettle::Dead`] — the
  /// terminal `Rescan` covers the caller, and the verdict carries the death
  /// itself because the `TeardownStream` that clears the driver's liveness
  /// maps is only queued at that point), folded into the next
  /// [`poll_cover_settlements`](Self::poll_cover_settlements) so the driver
  /// consumes every resolution at its one loop-top choke point.
  settled_covers: Vec<(FenceId, CoverSettle)>,
  scope_seq: u64,
  probe_seq: u64,
  fence_seq: u64,
  /// A monotone counter minting move cookies for `FAN_RENAME` pairs. fanotify
  /// reports each rename atomically (both halves in one event), so the cookie
  /// only needs to pair the two records emitted adjacently — a fresh counter
  /// per rename suffices and never clashes across renames.
  cookie_seq: u64,
  /// How often a signal-silent-on-unmount scope (fanotify) re-stats its root:
  /// the composition's one timer (see the per-backend death-signal table in the
  /// module docs). `Duration::ZERO` disables the tick — only the loss-triggered
  /// refresh then detects a quiet unmount. Every non-fanotify scope ignores it.
  root_liveness_interval: Duration,
  /// The caller's exclusion directories, applied to every scope this core owns
  /// (they are a watcher-wide option, not a per-root one). Empty is the common
  /// case and short-circuits both fences below.
  ///
  /// THE COMMON-LAYER EXCLUSION FENCE, in two halves — the enforcement for every
  /// backend that carries none of its own:
  ///
  /// - [`on_enumerated`](Self::on_enumerated) drops an excluded entry from a cold
  ///   or re-arm listing, so an excluded directory is never staged, never armed
  ///   and never descended;
  /// - [`fence_exclusions`](Self::fence_exclusions) drops a compiled record — or a
  ///   located rescan — whose absolute path is at or under an exclusion, so a
  ///   directory created or moved live under one never enters coverage either,
  ///   and no event from inside one is delivered.
  ///
  /// Placing it HERE rather than in the backends is forced, not stylistic. A
  /// descending backend's only way to decline a directory is to refuse its arm,
  /// and the Monitor reads a refused arm as coverage LOSS: it drops the node and
  /// emits a `Rescan` naming exactly that location. Answering "do not tell me
  /// about this path" with a rescan that names the path is worse than ignoring
  /// the option, so the suppression has to happen BEFORE the Monitor ever learns
  /// the directory exists — which is the enumerate listing and the compiled
  /// record, the two places a directory can enter coverage from. Nothing here
  /// refuses an arm, so nothing here can produce that rescan.
  exclusions: Vec<PathBuf>,
}

impl DriverCore {
  /// Builds a core whose Monitor pairs renames within `move_window` and re-stats
  /// each signal-silent scope's root every `root_liveness_interval`
  /// (`Duration::ZERO` disables that tick).
  pub(crate) fn new(move_window: Duration, root_liveness_interval: Duration) -> Self {
    let mut monitor = Monitor::new(caps_for(BackendKind::FsEvents));
    monitor.set_move_window(move_window);
    Self {
      monitor,
      scopes: BTreeMap::new(),
      watch_scopes: BTreeMap::new(),
      enum_reqs: BTreeMap::new(),
      probes: BTreeMap::new(),
      effects: VecDeque::new(),
      dying: BTreeMap::new(),
      cover_fences: BTreeMap::new(),
      settled_covers: Vec::new(),
      scope_seq: 0,
      probe_seq: 0,
      fence_seq: 0,
      cookie_seq: 0,
      root_liveness_interval,
      exclusions: Vec::new(),
    }
  }

  /// Returns this core enforcing `exclusions` on every scope it registers — the
  /// watcher-wide load-shedding set, applied through the two fences documented on
  /// [`exclusions`](Self::exclusions).
  #[must_use]
  pub(crate) fn with_exclusions(mut self, exclusions: Vec<PathBuf>) -> Self {
    self.exclusions = exclusions;
    self
  }

  /// Whether `path` is at or under one of this core's exclusions — the ONE
  /// matching rule, shared with the sync-cookie birth refusal and with the
  /// fanotify backend's own fence.
  fn excluded(&self, path: &Path) -> bool {
    crate::driver::excluded(&self.exclusions, path)
  }

  /// Where one watch of `state`'s scope IS: the scope root's canonical path
  /// joined with the Monitor's own placement of that watch in its node tree.
  ///
  /// # Derived, never mirrored
  ///
  /// This core keeps no map of watch paths. It kept one once, and the map was a
  /// second description of a tree the Monitor already owns: a rename is answered
  /// by rewriting ONE parent link, which relocates a whole subtree in O(1) and
  /// leaves every absolute path a mirror had stored naming ground the subtree has
  /// left. Repairing that costs a subtree walk per rename, has to be invoked from
  /// wherever renames are noticed, and — being an invocation rather than a
  /// property — is exactly the kind of repair that gets missed on a path nobody
  /// tested. It WAS missed: the repair sat behind the exclusion fence, so the
  /// default configuration (no exclusions) never ran it at all, and every arm and
  /// every enumerate the core dispatched under a moved subtree addressed the old
  /// path while the delivery beside it named the new one.
  ///
  /// Deriving makes the question unaskable. There is one description of where a
  /// watch is, the Monitor's, and reading it cannot be stale because there is
  /// nothing to go stale.
  ///
  /// The cost is real and stated plainly: one parent-chain walk (a map lookup per
  /// level) and one fresh `PathBuf`, against a mirror's single lookup and clone.
  /// It is paid only where a path is actually wanted — dispatching an effect, or
  /// answering the exclusion fence, both of which already allocate a path — and a
  /// scope with no exclusions configured never asks per record at all.
  ///
  /// # Why the root is answered without a walk
  ///
  /// A scope root has no location of its own — it IS the origin — and
  /// [`Monitor::location_of_checked`] correctly answers it with the empty
  /// location. Joining an empty location would yield a trailing separator, and
  /// more importantly the root's path is a fact this core holds directly
  /// (`state.root`, installed by the spawn barrier and by every root swap), so
  /// there is nothing to derive. A watched root never moves inside its own tree.
  ///
  /// # Why the state is passed in
  ///
  /// [`on_batch`](Self::on_batch) DETACHES a scope's [`ScopeState`] from `scopes`
  /// for the duration of one read, so a derivation that looked the scope up
  /// itself would answer `None` for every record of every batch — the fence's
  /// fail-open, silently, on the hot path. Callers that hold a scope id instead
  /// go through [`scoped_path`](Self::scoped_path).
  ///
  /// # Do not store the answer
  ///
  /// See [`Monitor::location_of_checked`]'s own warning. A stored copy is the
  /// mirror this derivation exists to have deleted.
  ///
  /// `None` when the scope has no root yet (registered, not spawned) or when the
  /// Monitor cannot place the watch — a dropped node, a severed ancestry. Never a
  /// SHORT path: `location_of_checked` reports those conditions as `None` rather
  /// than as a truncated location, which is what makes an unresolvable watch
  /// distinguishable from one sitting at the root.
  fn path_of(&self, state: &ScopeState, watch: WatchId) -> Option<PathBuf> {
    let root = state.root.as_deref()?;
    if watch == state.watch {
      return Some(root.clone());
    }
    let mut path = root.clone();
    for segment in self.monitor.location_of_checked(watch)?.segments() {
      path.push(segment.as_str());
    }
    Some(path)
  }

  /// [`path_of`](Self::path_of) for a caller holding a scope ID rather than the
  /// state itself — the drain's route, which looks a scope up per action.
  fn scoped_path(&self, scope: ScopeId, watch: WatchId) -> Option<PathBuf> {
    self.path_of(self.scopes.get(&scope)?, watch)
  }

  /// The absolute path a watch-anchored input addresses: the anchor's own path
  /// joined with the record's root-relative descent.
  ///
  /// One resolution for both lowering profiles, which is what lets ONE fence
  /// cover them: a descending record anchors at the affected directory's own
  /// watch and carries a one-segment name, a kernel-recursive record anchors at
  /// the root watch and carries the whole root-relative location.
  ///
  /// `None` when the anchor cannot be placed ([`path_of`](Self::path_of) — a
  /// superseded or already-dropped watch, or a scope not yet spawned). The fence
  /// then FAILS OPEN — it suppresses nothing. That direction is deliberate:
  /// exclusions are documented as an optimization that correctness never depends
  /// on, so the only cost of not suppressing is a delivery the caller did not
  /// want, whereas suppressing on an unresolved path would drop one it may have
  /// needed.
  fn anchored_path(
    &self,
    state: &ScopeState,
    watch: WatchId,
    descent: Option<&Location>,
  ) -> Option<PathBuf> {
    let mut path = self.path_of(state, watch)?;
    for segment in descent.into_iter().flat_map(Location::segments) {
      path.push(segment.as_str());
    }
    Some(path)
  }

  /// Whether `profile` is a backend that emits NO in-band signal when its root
  /// is unmounted — the gate for the periodic root-liveness tick.
  ///
  /// The per-backend death-signal table (design §7; the module docs restate it):
  ///
  /// | backend | root unmount | root delete/replace in-tree | tick needed |
  /// |---|---|---|---|
  /// | inotify (descending) | `IN_UNMOUNT` + `IN_IGNORED` | `IN_DELETE_SELF`/`IN_MOVE_SELF` | no |
  /// | FSEvents (macOS) | `RootChanged` | `RootChanged` | no |
  /// | fanotify (`FAN_MARK_FILESYSTEM`) | **SILENT** (fd goes quiet, mark holds the sb alive — L4.1) | `FAN_DELETE_SELF`/`FAN_MOVE_SELF` | **yes** |
  /// | RDCW (Windows) | fatal source error on any terminal read completion | same signal | no |
  /// | USN journal (Windows) | fatal source error on a failed journal read | `RootDeath` (the root's own FRN in a delete/rename record) | no |
  ///
  /// Only fanotify's unmount is signal-silent, so only fanotify arms the tick;
  /// its in-tree self-events and every other backend's death signal already
  /// reach [`on_mounts_refreshed`](Self::on_mounts_refreshed)'s death mapping
  /// (via a loss-triggered refresh) or the Monitor's self-event path directly.
  const fn liveness_ticked(profile: BackendKind) -> bool {
    matches!(profile, BackendKind::Fanotify)
  }

  /// Mints the next `FAN_RENAME` pairing cookie.
  fn next_cookie(&mut self) -> MoveCookie {
    self.cookie_seq += 1;
    MoveCookie::new(NonZeroU64::new(self.cookie_seq).expect("cookie counter starts at one"))
  }

  /// Registers a new watched root, returning its scope handle. Queues the
  /// [`Effect::SpawnStream`] that starts the native source.
  ///
  /// Fallible only because the Monitor refuses a scope that already has a
  /// registered root. The mint below is monotonic and never reuses a value, so
  /// the branch is dead by construction HERE — it is propagated rather than
  /// `expect`ed because the Monitor's guard exists for out-of-tree drivers, and
  /// an assertion in this crate's only caller would answer their mistake with a
  /// panic instead of the refusal. Nothing is registered on the error path.
  pub(crate) fn on_watch(
    &mut self,
    root: PathBuf,
    interest: Interest,
    profile: BackendKind,
  ) -> Result<ScopeId, WatchRootError> {
    self.scope_seq += 1;
    let scope = ScopeId::new(NonZeroU64::new(self.scope_seq).expect("sequence starts at one"));
    let Some(watch) = self
      .monitor
      .register_root_with_profile(scope, interest, caps_for(profile))
    else {
      return Err(WatchRootError::ScopeInUse);
    };
    self.scopes.insert(
      scope,
      ScopeState {
        watch,
        root_attempt: None,
        profile,
        requested: root,
        root: None,
        root_dev: None,
        root_mnt_id: None,
        identity: None,
        mounts: Vec::new(),
        mounts_authoritative: false,
        refresh_pending: false,
        refresh_stale: false,
        refresh_world_stale: false,
        lag: LagState::Normal,
        park: Park::default(),
        resume_poisoned: false,
        publicly_live: false,
        liveness_deadline: None,
        applied_cover: None,
        settle_floor: None,
        pending_widen: None,
      },
    );
    self.watch_scopes.insert(watch, scope);
    self.drain_monitor();
    Ok(scope)
  }

  /// Unregisters a watched root; its teardown effect follows.
  pub(crate) fn on_unwatch(&mut self, scope: ScopeId) {
    if self.scopes.contains_key(&scope) {
      self.monitor.unregister_root(scope);
      self.drain_monitor();
    }
  }

  /// Reconciles `scope`'s per-directory kernel coverage to the `retained` cover **in place**,
  /// **bidirectionally** (the set-cover reconcile): it BOTH prunes every descended watch
  /// strictly OUTSIDE the cover AND re-arms any retained subtree the scope is not currently
  /// covering — while leaving every retained subtree that is already covered, and the
  /// connecting ancestors from the root down to each, untouched. Neither the retained-and-
  /// covered watches nor the connecting ancestors are ever re-armed, so their events keep
  /// flowing with **no gap and no re-crawl** (the shrink-in-place property); only the
  /// previously-pruned corner is grown back.
  ///
  /// `retained` is the antichain of canonical absolute paths some surviving consumer still
  /// needs. A watch at path `P` is KEPT by the prune iff some retained `R` satisfies
  /// `P.starts_with(R)` (P lies in a retained subtree) OR `R.starts_with(P)` (P is a
  /// connecting ancestor a retained subtree descends from); it is pruned only when strictly
  /// outside **every** retained prefix, so no retained key ever routes through a pruned watch.
  /// A retained prefix with **no live watch at its own path** — one an EARLIER, narrower cover
  /// pruned — is re-armed by re-arming its deepest still-watched ancestor (the root is always
  /// one), whose recursive re-arm re-installs the pruned directory and everything between; the
  /// re-arm emits no `Created` and no `Rescan`, so it silently restores coverage the way the
  /// prune silently reclaims it.
  ///
  /// # Why the grow half exists
  ///
  /// A prune-only set-cover cannot restore coverage: after an applied prune of `/a/c`, a later
  /// consumer watching `/a/c` again (subsumed under the still-armed wide root — `Covered` at
  /// the umbrella, no re-arm) would sit over a hole no per-directory watch backs, silently
  /// missing every deep change. The umbrella now re-issues the FRESH cover (including that
  /// newcomer) on the `Covered` commit, and this grow half is what turns that re-issue into
  /// real coverage again.
  ///
  /// **Best-effort and correctness-neutral.** The caller (the umbrella's set-cover seam)
  /// computes `retained` from the live survivors, so the prune only ever removes coverage no
  /// consumer is subscribed under and the grow only ever re-arms coverage a survivor needs: a
  /// partial or skipped prune merely leaves the root briefly over-broad (self-healing), and a
  /// skipped grow merely leaves the newcomer briefly under-covered until the umbrella's own
  /// bridging `Rescan` and a later re-issue converge — neither loses an event under a retained,
  /// covered key, and neither emits a `Rescan`.
  ///
  /// # Refusals
  ///
  /// A [`Noop`](CoverReconcile::Noop) — no prune, no grow, `applied_cover` and the settle
  /// floor untouched — for:
  ///
  /// - an **unknown scope** ([`UnknownScope`](CoverNoop::UnknownScope));
  /// - a scope that is **not publicly live** ([`NotLive`](CoverNoop::NotLive)) — no caller
  ///   holds a handle between a descending scope's spawn and its root-arm grant, so there is no
  ///   coverage CLAIM to reconcile: the registration's own crawl is installing all of it (see
  ///   [`NotLive`](CoverNoop::NotLive) for the sharper reason this clause used to carry, and
  ///   why it is now the design rather than the harm);
  /// - a **kernel-recursive** scope (fanotify / FSEvents;
  ///   [`KernelRecursive`](CoverNoop::KernelRecursive)): its single whole-subtree stream has no
  ///   per-directory children, so coverage never narrowed and there is nothing to prune or
  ///   re-arm — reported explicitly rather than walked as silence, so the driver can answer
  ///   "recursive" instead of "applied";
  /// - a **refused cover** ([`RefusedCover`](CoverNoop::RefusedCover)): empty `retained`
  ///   (defensive — never prune the whole tree) or a cover ENTIRELY outside the live root (a
  ///   caller error — validated against the scope root and refused before any prune, so a typo /
  ///   relative / stale path can never silently prune the whole scope). A PARTIALLY out-of-root
  ///   cover proceeds with the in-root subset only.
  ///
  /// Otherwise [`Reconciling`](CoverReconcile::Reconciling): the walk ran, and each pruned
  /// watch's [`RemoveWatch`](Effect::RemoveWatch) and each grown watch's
  /// [`AddWatch`](Effect::AddWatch) / [`Enumerate`](Effect::Enumerate) flow through the ordinary
  /// descending paths, keeping the reader's `wd` table and the core's watch-to-scope map
  /// consistent exactly as delete-driven and create-driven transitions do. A `Reconciling` return also
  /// updates the fence bookkeeping: the scope's [`CoverFence`] entry is (re)ensured so the next
  /// settle observation sees this window, any `Coalesced` grow kickoff records the born-lossy
  /// memory (see [`CoverFence`]), and `applied_cover` / `settle_floor` are recorded
  /// (optimistically / as the running meet).
  #[must_use = "the disposition routes the acknowledgement: a Noop is answered immediately, a Reconciling may owe a fence"]
  pub(crate) fn on_set_cover(&mut self, scope: ScopeId, retained: &[PathBuf]) -> CoverReconcile {
    let Some(state) = self.scopes.get(&scope) else {
      return CoverReconcile::Noop(CoverNoop::UnknownScope);
    };
    // The publicly-live gate (see the refusal table above): pre-grant there is no
    // coverage claim to reconcile — the registration's own crawl owns all of it.
    if !state.publicly_live {
      return CoverReconcile::Noop(CoverNoop::NotLive);
    }
    // Kernel-recursive coverage never narrowed: refuse explicitly (the walk below would be
    // a structural no-op, but recording `applied_cover` for it would misstate that the
    // whole-subtree stream was ever reconciled).
    if state.profile.is_kernel_recursive() {
      return CoverReconcile::Noop(CoverNoop::KernelRecursive);
    }
    // An empty cover would mark every node strictly-outside (vacuously) and prune the
    // whole scope; the umbrella never requests it, but never risk collapsing coverage.
    if retained.is_empty() {
      return CoverReconcile::Noop(CoverNoop::RefusedCover);
    }
    // Validate the retained cover against the LIVE scope root before acting on it. A
    // retained path that is not under the root — a caller typo, a relative or stale path — lies
    // strictly OUTSIDE every in-root watch, so an UNVALIDATED cover would mark the whole scope
    // outside and SILENTLY PRUNE ALL coverage. Keep only paths within the root (the root itself
    // allowed). The prefix test is LEXICAL, and `Path::starts_with` does not resolve `..` — so a
    // path like `root/../elsewhere` lexically begins with the root while escaping it (
    // ). A CANONICAL retained path never contains `.`/`..` components (the scope root and
    // every survivor cover the umbrella issues are canonical), so any path carrying one is a
    // caller error: reject it outright rather than guessing what it resolves to. A root not yet
    // known cannot validate anything — unreachable behind the publicly-live gate (a live scope
    // always spawned), kept as the defensive not-live answer.
    let Some(root) = state.root.clone() else {
      return CoverReconcile::Noop(CoverNoop::NotLive);
    };
    let retained: Vec<PathBuf> = retained
      .iter()
      .filter(|path| {
        path.starts_with(root.as_path())
          && !path.components().any(|component| {
            matches!(
              component,
              std::path::Component::ParentDir | std::path::Component::CurDir
            )
          })
      })
      .cloned()
      .collect();
    // An ENTIRELY out-of-root cover is a caller error the core refuses to act on: do NOT prune and
    // do NOT record `applied_cover`, leaving the prior (still-correct) coverage untouched. A
    // PARTIALLY valid cover proceeds with the valid subset ONLY — the invalid prefixes are dropped.
    if retained.is_empty() {
      return CoverReconcile::Noop(CoverNoop::RefusedCover);
    }
    let retained = retained.as_slice();

    let root_watch = state.watch;
    // The cover the previous reconcile settled on: the grow keys its re-arm on the delta
    // against THIS, not on which watches survive.
    let prev_cover = state.applied_cover.clone();

    // --- PRUNE (the shrink half): drop every descended watch strictly OUTSIDE the cover ---
    // This scope's descended (non-root) watches strictly OUTSIDE every retained prefix,
    // shallowest first — so a maximal outside subtree is dropped at its top and its
    // deeper descendants are already gone (skipped by the `is_watched` guard) when
    // reached. The root is never a candidate (it is an ancestor of every retained key).
    let mut outside: Vec<(usize, WatchId)> = self
      .watch_scopes
      .iter()
      .filter(|(watch, watch_scope)| **watch_scope == scope && **watch != root_watch)
      .filter_map(|(watch, _)| {
        let path = self.path_of(state, *watch)?;
        let strictly_outside = retained
          .iter()
          .all(|r| !path.starts_with(r) && !r.starts_with(path.as_path()));
        strictly_outside.then(|| (path.components().count(), *watch))
      })
      .collect();
    outside.sort_unstable_by_key(|(depth, _)| *depth);
    // Whether the shrink half actually dropped coverage — the Monitor's own answer, not an
    // inference from the requested cover, because a cover naming subtrees this scope no longer
    // watches prunes nothing.
    let mut pruned = false;
    for (_, watch) in outside {
      // A node an ancestor's drop already reclaimed is no longer watched — skip it (the
      // shallow-first order guarantees the ancestor was processed first).
      if self.monitor.is_watched(watch) {
        pruned |= self.monitor.drop_watch_subtree(watch);
      }
    }

    // --- GROW (the set-cover dual): re-arm the BROADENING DELTA against the PREVIOUS cover ---
    // A retained prefix is re-armed iff the previously-applied cover did NOT already cover it
    // ([`broadening_delta`]): its subtree was pruned under that cover, so a watch may still sit
    // at its own path merely as a connecting ANCESTOR while its descendants are gone. Keying on
    // the delta rather than on exact-path watch presence is exactly what re-arms those pruned
    // descendants when growing back to a retained ancestor (`/a/b/deep` → `/a/b`) or to the
    // whole root. For each delta prefix, re-arm the DEEPEST still-watched
    // ancestor-OR-SELF: its recursive re-arm re-reads that directory, re-installs every
    // previously-pruned directory beneath it, and cascades down — with no `Created` and no
    // `Rescan`. Dedup by target watch, so sibling delta prefixes sharing one ancestor re-arm
    // it once.
    let mut to_rearm: BTreeSet<WatchId> = BTreeSet::new();
    for r in broadening_delta(prev_cover.as_deref(), retained) {
      // The deepest still-watched ancestor-or-self of `r` in this scope. The root is always an
      // ancestor of every retained prefix, so a prefix under the root always finds one; a `None`
      // (a prefix somehow above/outside the root) simply grows nothing.
      let deepest = self
        .watch_scopes
        .iter()
        .filter(|(_, watch_scope)| **watch_scope == scope)
        .filter_map(|(watch, _)| {
          let path = self.path_of(state, *watch)?;
          r.starts_with(&path)
            .then(|| (path.components().count(), *watch))
        })
        .max_by_key(|(depth, _)| *depth);
      if let Some((_, watch)) = deepest {
        to_rearm.insert(watch);
      }
    }
    // Kick off the ANTICHAIN of the targets only: a target inside another target's
    // subtree is dropped, because the shallower target's recursive re-arm already
    // re-reads it — and kicking both would land the ancestor's cascade on the
    // descendant's own in-flight re-arm read, dirtying it into an escalation
    // `Rescan` (an honest `Degraded`, but for a collision this reconcile itself
    // manufactured). Ancestor+descendant targets arise whenever the delta holds a
    // pruned prefix (re-armed at a shallow surviving ancestor) alongside a
    // still-watched one (re-armed at itself) — the degraded-claim full delta after
    // a loss being the canonical case.
    let targets: Vec<WatchId> = to_rearm
      .iter()
      .filter(|watch| {
        !to_rearm.iter().any(|other| {
          other != *watch
            && matches!(
              (self.path_of(state, **watch), self.path_of(state, *other)),
              (Some(path), Some(ancestor)) if path.starts_with(&ancestor)
            )
        })
      })
      .copied()
      .collect();
    // A `Coalesced` kickoff folded its obligation into an in-flight COLD read the settle
    // counter deliberately does not see: the scope can read settled while the obligation is
    // latent, so the fence window is lossy FROM BIRTH (the F0 amendment).
    let mut coalesced = false;
    // Whether the grow half actually recorded a re-arm obligation — again the Monitor's answer:
    // a `Refused` kickoff (a target the tree no longer holds) grows nothing.
    let mut grew = false;
    for watch in targets {
      let kickoff = self.monitor.rearm_watch_subtree(watch);
      coalesced |= kickoff.is_coalesced();
      grew |= !kickoff.is_refused();
    }

    // Fence bookkeeping BEFORE the drain, so an entry exists when any change this reconcile
    // provokes routes: ensure the scope's entry (the next settle observation must see this
    // window even when the reconcile is reply-less — that observation resets the floor on a
    // clean settle and clears the loss memory), and record the born-lossy memory, which marks
    // every already-pending fence and is inherited by any fence opened before the scope next
    // settles (see [`CoverFence`]).
    let fence = self.cover_fences.entry(scope).or_default();
    // A reconcile that MOVED coverage extended the window past whatever a standing
    // ordering proof was taken over, so that proof licenses nothing about what it
    // now holds. Reset it: the proof is asked for again at the next quiescence, and
    // a reply still in flight for the spent request finds `Unproven` and correctly
    // no-ops. The epoch binding does not subsume this — a prune only RELEASES work,
    // so no funnel bumps the epoch even though the coverage under the proof changed.
    //
    // A reconcile that grew nothing and pruned nothing extended nothing, and its
    // window is exactly the one the standing proof already orders. Invalidating
    // there would be worse than a wasted round trip: reply-less re-issues of a
    // settled cover can arrive faster than a cut completes, so every completed
    // proof would land on a latch a later re-issue had already reset, and the
    // window would never settle clean at all (see [`CutProof`]).
    if pruned || grew {
      fence.cut.invalidate();
    }
    if coalesced {
      fence.mark_lossy();
    }

    // Turn the queued `Action::Unwatch`es (prune) into `RemoveWatch` effects and the queued
    // `Action::Watch`/`Enumerate`s (grow) into `AddWatch`/`Enumerate` effects, and reconcile
    // the watch-to-scope map, exactly as Monitor-driven drops and descents do. A no-op when
    // both halves queued nothing.
    self.drain_monitor();

    // Record the cover just applied: the NEXT set-cover computes its broadening delta against it
    //. Stored verbatim; `broadening_delta` treats the init `None` as full, and a
    // full-root cover (retained = the root's own path) yields an empty delta for any later shrink
    // exactly as `None` would. The record is OPTIMISTIC (the grow's re-arm work has not
    // completed), so the settle floor keeps the running meet the lossy-settle rewind falls back
    // to (see `ScopeState::settle_floor`).
    if let Some(state) = self.scopes.get_mut(&scope) {
      state.settle_floor = Some(cover_meet(state.settle_floor.as_deref(), retained));
      state.applied_cover = Some(retained.to_vec());
    }
    CoverReconcile::Reconciling
  }

  /// Opens one settlement fence for `scope`: the driver parks an acked
  /// `set_cover`'s reply under the returned id and resolves it with the
  /// [`CoverSettle`] the next [`poll_cover_settlements`](Self::poll_cover_settlements)
  /// reports for it. Call it immediately after the
  /// [`Reconciling`](CoverReconcile::Reconciling) `on_set_cover` it acknowledges
  /// (before any other core input), so the fence cannot miss its own
  /// reconcile's window: it inherits the scope's loss memory accrued since the
  /// last settle observation — including a born-lossy `Coalesced` grow — per
  /// [`CoverFence`]'s rule.
  ///
  /// The fence takes the entry's next open ordinal, and that is what keeps it
  /// from inheriting an ordering proof older than itself: a proof licenses only
  /// the fences that were already pending when it was requested, and this one
  /// was not (see [`CutProof`]). Standing proofs and requests in flight are
  /// left untouched — they still order the fences they were bought for, and the
  /// successor this fence needs is asked for once they land.
  pub(crate) fn open_cover_fence(&mut self, scope: ScopeId) -> FenceId {
    self.fence_seq += 1;
    let fence = FenceId(self.fence_seq);
    self.cover_fences.entry(scope).or_default().open(fence);
    fence
  }

  /// How many acknowledged reconciles `scope` currently holds pending on its
  /// coverage fence — the core's half of one admitted `set_cover`, minted by
  /// [`open_cover_fence`](Self::open_cover_fence) together with the driver's
  /// parked reply sender and released together with it. The driver reads this as
  /// the admission bound for awaited reconciles, so neither half can grow past
  /// the cap while a scope's proof round trip is stalled.
  pub(crate) fn pending_cover_fences(&self, scope: ScopeId) -> usize {
    self
      .cover_fences
      .get(&scope)
      .map_or(0, |entry| entry.pending.len())
  }

  /// Whether `scope` still carries a coverage-fence ENTRY at all — the memory a
  /// fence opened right now would inherit.
  ///
  /// [`pending_cover_fences`](Self::pending_cover_fences) cannot answer this: an
  /// entry holding no pending fence reads zero there while still carrying the
  /// scope's accrued `lossy` memory, and that is exactly the state a routed
  /// `Rescan` leaves behind until a settle observation spends it (see
  /// [`CoverFence`]). A registration window's closing `Rescan` therefore stands
  /// across the gap between its routing and the ordering-proof round trip that
  /// lets the observation clear the entry, and a fence opened inside that gap
  /// inherits the loss and settles `Degraded` — honestly for the product, and
  /// fatally for a cell staging a clean baseline. Staging that means "this scope
  /// has nothing accrued" waits on the ENTRY going, not on the pending count.
  ///
  /// Test-only, gated to the driver suite that consumes it.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn holds_cover_fence_entry(&self, scope: ScopeId) -> bool {
    self.cover_fences.contains_key(&scope)
  }

  /// Drops the pending records of `abandoned` fences — callers that cancelled their
  /// `set_cover` await before the settle. Only the per-fence records go: the scope's
  /// loss memory, its settle-floor bookkeeping, and every still-awaited fence stay
  /// untouched, so the settle observation's cover repair is unaffected. Without this,
  /// a caller repeatedly issuing-and-cancelling against a scope whose re-arm work is
  /// stalled would accumulate one pending record per processed request indefinitely —
  /// the bounded command mailbox limits only instantaneous traffic, never the total.
  pub(crate) fn abandon_cover_fences(&mut self, abandoned: &std::collections::BTreeSet<FenceId>) {
    if abandoned.is_empty() {
      return;
    }
    for entry in self.cover_fences.values_mut() {
      entry
        .pending
        .retain(|pending| !abandoned.contains(&pending.fence));
    }
  }

  /// Reports every set-cover fence that has settled since the last poll: each
  /// scope with an unobserved reconcile whose coverage work quiesced
  /// ([`Monitor::coverage_settled`] — the counted re-arm work of
  /// [`Monitor::rearm_settled`], plus the held-move and latent-cold-read
  /// windows a sync cookie must not dispatch inside) resolves ALL its pending
  /// fences at this one settle instant — in FIFO open order, each with its
  /// recorded lossiness ([`Applied`](CoverSettle::Applied) /
  /// [`Degraded`](CoverSettle::Degraded)) — plus every fence a scope teardown
  /// already resolved [`Dead`](CoverSettle::Dead). The driver polls this at
  /// its loop top, after feeding results back.
  ///
  /// A settled scope resolves the fences its ordering proof licenses — the
  /// prefix of its pending list the proof was requested behind (see
  /// [`CutProof`]) — and holds any that opened past it, which are offered a
  /// successor proof and resolve at a later pass. A lossy window owes that proof
  /// exactly as a clean one does: what the cut surfaces is an unread death, and
  /// a `Degraded` dispatches its caller's cookie onto a stream just as an
  /// `Applied` does. Only a scope that can obtain no proof is exempt — a
  /// kernel-recursive one, whose control batches never reach a reader — and it
  /// resolves whole.
  ///
  /// The settle observation is also where the applied-cover lie is repaired:
  /// a LOSSY window rewinds `applied_cover` to the settle floor (the provable
  /// under-claim, so a re-issue recomputes a real broadening delta); a CLEAN
  /// window resets the floor to the now-truthful `applied_cover`. That repair
  /// rides the entry's removal, so it waits for the LAST pending fence: a claim
  /// is never promoted over a stretch of the window no proof has ordered yet.
  /// Once the entry goes, no fence state outlives it — pending fences and loss
  /// memory alike.
  /// The settle-fence gate: exactly the Monitor's barrier predicate
  /// ([`Monitor::coverage_settled`]), with no core-side conjunct. The widen
  /// window needs none: pre-commit, fences certify the OLD world, whose
  /// coverage is genuinely live and unchanged (the zero-gap half); the commit
  /// itself is gated on the witnessed window (INV-ROOT —
  /// [`on_root_widened`](Self::on_root_widened)), so by the time a fence can
  /// consult this gate over the widened world the binding was proven live at
  /// the commit or the widen fell back to a fresh spawn barrier. A scope with
  /// no state resolves through the teardown fold below, never through this
  /// gate.
  fn barrier_settled(&self, scope: ScopeId) -> bool {
    self.monitor.coverage_settled(scope)
  }

  /// Whether the next [`poll_cover_settlements`](Self::poll_cover_settlements)
  /// would OBSERVE at least one scope — some scope with fence bookkeeping
  /// whose coverage barrier currently holds. The driver consults this before
  /// resolving so it can first ingest every source message already queued:
  /// loss signals and arm ACKs travel on two unordered channels, and an
  /// observation taken while a loss for the scope is queued-but-unseen would
  /// certify a clean window the loss already voided (and reset the settle
  /// floor to a cover the loss is about to invalidate). Teardown-folded
  /// settles need no such fence — their verdict is already `Dead`, which more
  /// loss cannot falsify — so they do not arm this probe. They are still
  /// delivered promptly: the driver's loop-top resolve is unconditional.
  pub(crate) fn cover_settlement_due(&self) -> bool {
    self
      .cover_fences
      .keys()
      .any(|scope| self.barrier_settled(*scope))
  }

  /// The scopes whose barrier has quiesced but which have not yet forced the
  /// source to surface what the kernel holds — see [`CutProof`].
  ///
  /// Reporting does NOT latch: the caller may decline a scope — a stream that is
  /// already gone has nothing to ask — and a request spent on a batch nobody
  /// sends could only ever be closed by a reply that never comes, parking the
  /// fence until its scope dies. So the caller latches with
  /// [`mark_cut_inflight`](Self::mark_cut_inflight) once it has committed to
  /// sending, and a declined scope simply reappears here next pass.
  ///
  /// A LOSSY fence is returned like any other, and the offer is the half of that
  /// rule that keeps it live: the settle gate below requires a proof of every
  /// live fence, so a fence that is never OFFERED one would wait for it forever.
  /// The two sides carry the same exemption and no other, which is what makes
  /// "asked for iff required" hold rather than merely be intended.
  ///
  /// A scope whose latch does not speak for its whole pending set IS returned,
  /// for either of the two reasons a latch can fall short: the coverage work it
  /// was stamped against has moved on, so it licenses nothing at all; or a
  /// fence has opened past the tranche the proven prefix reaches, so it licenses
  /// nothing for THAT fence. Either way a fence would otherwise wait on a reply
  /// that cannot certify it. A request still in flight under the current epoch
  /// is not re-asked for — see [`CutProof`]'s convergence rule, which is what
  /// bounds a fence's wait however fast fences arrive.
  ///
  /// Those two cases leave no gap between them, which is the property a fence's
  /// liveness rests on: a settled clean window holding a fence its prefix does
  /// not reach is offered a cut unless one is already out under the current
  /// epoch, and both ways that request can end — its own completion, which
  /// raises the prefix, and the epoch moving out from under it, which retires
  /// it where it stands — put the window straight back here.
  ///
  /// The offer and the latch below share one predicate, so the caller can
  /// always latch what it was offered.
  pub(crate) fn covers_awaiting_cut(&self) -> Vec<ScopeId> {
    self
      .cover_fences
      .iter()
      .filter(|(scope, entry)| {
        self.cut_proof_required(**scope)
          && self.barrier_settled(**scope)
          && !entry
            .cut
            .answers_for(self.coverage_epoch(**scope), entry.high_water())
      })
      .map(|(scope, _)| *scope)
      .collect()
  }

  /// The coverage-work epoch a cut proof for `scope` is stamped with and
  /// checked against — see [`CutProof`].
  fn coverage_epoch(&self, scope: ScopeId) -> CoverageWorkEpoch {
    self.monitor.coverage_work_epoch(scope)
  }

  /// Whether `scope`'s live verdicts need an ordering proof at all.
  ///
  /// Only a per-directory-watch scope can hold an unread kernel queue a fence
  /// would resolve over, and only such a scope has a control port whose batch a
  /// reader answers — so a kernel-recursive scope can neither need the proof nor
  /// obtain one, and asking would strand its settles rather than protect them. A
  /// scope whose state is gone needs nothing: its fences resolve at the teardown
  /// fold.
  fn cut_proof_required(&self, scope: ScopeId) -> bool {
    self
      .scopes
      .get(&scope)
      .is_some_and(|state| !state.profile.is_kernel_recursive())
  }

  /// Latches `scope`'s fence as having the ordering-proof request `token` in
  /// flight, so it is asked for exactly one however many passes the reply takes.
  /// Called only once the caller has committed to sending that batch.
  ///
  /// The request is stamped with the scope's CURRENT coverage-work epoch and
  /// with the newest ordinal currently pending — the tranche this proof will be
  /// able to license — both of which its proof inherits and is checked against
  /// at the settle, so the caller needs no bookkeeping of its own. Latching is
  /// refused only when the latch already speaks for that pair, which is exactly
  /// when [`covers_awaiting_cut`](Self::covers_awaiting_cut) would not have
  /// offered the scope: what it offers, this always latches. Latching displaces
  /// whatever request was out, so the batch that carried it can no longer prove
  /// anything — which is why an in-flight request under the current epoch is
  /// never displaced merely because a fence opened behind it. The proven prefix
  /// is untouched either way: a successor asks about the fences beyond it and
  /// says nothing about the ones it already reaches.
  pub(crate) fn mark_cut_inflight(&mut self, scope: ScopeId, token: u64) {
    let epoch = self.coverage_epoch(scope);
    if let Some(entry) = self.cover_fences.get_mut(&scope) {
      let covers = entry.high_water();
      if !entry.cut.answers_for(epoch, covers) {
        entry.cut.latch(token, CutMark::new(epoch, covers));
      }
    }
  }

  /// Records that `scope`'s source answered a control batch, whose reply the
  /// reader's pre-reply cut precedes — so anything the kernel held is now on
  /// the lane, ahead of this.
  ///
  /// Only the request actually in flight is closed, and only by its OWN token —
  /// which is what makes every stale completion inert. A window extended by a
  /// reconcile discards the latch, so a reply for the request that predated it
  /// matches nothing; and a PREDECESSOR batch of the same scope, whose cut was
  /// taken before this request existed, carries a different token and cannot
  /// close it either. The caller supplies the token only for a batch that ran to
  /// completion, so an unwinding batch proves nothing.
  ///
  /// The proof inherits the REQUEST's epoch and mark, not the scope's now: the
  /// cut ordered the window as it stood when the request was committed to, so
  /// work the scope acquired while the batch was out is outside it and must
  /// leave the proof stale rather than be absorbed into it, and a fence opened
  /// while the batch was out is outside it and must wait for a successor rather
  /// than be swept into this one. It RAISES the proven prefix (see
  /// [`CutProof`]), so a completion can only ever extend what the entry has
  /// earned.
  pub(crate) fn prove_cut(&mut self, scope: ScopeId, token: u64) {
    if let Some(entry) = self.cover_fences.get_mut(&scope) {
      entry.cut.prove(token);
    }
  }

  /// Resolves every settled fence the [`SettlePass`] entitles this boundary to
  /// mint, and holds the rest over WITH THEIR ENTRIES INTACT — a deferred
  /// window is retried, never degraded and never lost.
  ///
  /// Deaths are not gated by any of it: a teardown fold and the seam-bug path
  /// both resolve [`Dead`](CoverSettle::Dead) through the already-settled list
  /// this function drains unconditionally, so a scope held over below still
  /// reports its death at the very pass that reads it.
  ///
  /// - a live pass whose drain SPENT the scope's counted items resolves
  ///   everything, subject to the window's own ordering proof — owed by a lossy
  ///   window as much as by a clean one, since both dispatch a caller's cookie;
  /// - a live pass with counted items still resident on that scope's lane
  ///   resolves NOTHING for it — including a lossy window, whose `Degraded`
  ///   would answer a caller over a death that may be sitting in exactly those
  ///   items (see [`SettlePass`]);
  /// - the close pass refuses the clean verdict — no stream is left to certify
  ///   against — while still reporting a lossy window honestly, because a
  ///   deferral at close would strand its caller's reply forever.
  pub(crate) fn poll_cover_settlements(
    &mut self,
    pass: SettlePass<'_>,
  ) -> Vec<(FenceId, CoverSettle)> {
    let mut settled = std::mem::take(&mut self.settled_covers);
    let scopes: Vec<ScopeId> = self.cover_fences.keys().copied().collect();
    for scope in scopes {
      if !self.barrier_settled(scope) {
        continue;
      }
      // The registration window's unanswered classification stat is a LOSS this
      // settlement must carry, and it is read here — at the observation — rather
      // than at an edge, because it is a STANDING condition and not an event. A
      // scope's loss memory is spent by every settle observation, so a mark laid
      // when the stat was queued would be cleared by the first observation to
      // pass and the next fence would certify the same uncovered window anyway.
      //
      // The slot may be a directory the scope has no watch on: the crawl that
      // listed it as `FileKind::Unknown` reconciled nothing for it, and the stat
      // is uncounted, so the barrier above quiesces with the slot dark. The
      // verdict degrades and the settle floor keeps its under-claim, which sends
      // the consumer back to enumerate — never `Applied` over ground writes go
      // unrecorded beneath.
      //
      // Deliberately NOT a conjunct of the barrier
      // ([`Monitor::bootstrap_stat_outstanding`]): a driver that never answers
      // must cost a degraded verdict, not a wedged scope. Everything below still
      // runs — the residue and certification deferrals, the ordering proof, the
      // resolution — exactly as for any other lossy window.
      if self.monitor.bootstrap_stat_outstanding(scope)
        && let Some(entry) = self.cover_fences.get_mut(&scope)
      {
        entry.mark_lossy();
      }
      // The residue deferral: this scope's lane still holds items the pass
      // counted and did not read, and an unread terminal `Fatal` among them
      // makes a live verdict of EITHER kind a claim about a stream that is
      // already gone. Both deferrals here keep the entry INTACT, so a window
      // they catch is retried rather than decided.
      if pass.withholds(scope) {
        continue;
      }
      // The certification deferral, which IS clean-only: the close pass has no
      // stream left to certify a clean window against, so it holds that verdict
      // over rather than minting it. A lossy window is not withheld here — it
      // has nothing to certify, its floor move is the rewind, and this is the
      // last pass its caller will ever be answered by.
      if !pass.certifies_clean()
        && self
          .cover_fences
          .get(&scope)
          .is_some_and(|entry| !entry.lossy)
      {
        continue;
      }
      // The counted work quiescing proves the coverage was rebuilt; it does not
      // prove the kernel had nothing queued while that happened. Until a fence
      // has an ordering proof, any live verdict would rest on the drain having
      // seen a lane the reader may not have filled yet.
      //
      // How far the proof reaches decides how much of the entry may resolve.
      // Both of its bounds are checked against the scope as it reads NOW: it
      // must have been taken over the coverage work the scope currently holds —
      // a proof stamped before the scope acquired and released more of it
      // ordered an earlier window, and the record it would certify over may
      // still be kernel-resident — and it reaches only the fences that were
      // already pending when it was requested. A stale proof is therefore no
      // proof at all, and an unreached fence withholds; both reappear in
      // `covers_awaiting_cut`.
      //
      // A LOSSY window owes the same proof. More loss cannot falsify its
      // degraded verdict, but the cut does not surface loss — it surfaces
      // whatever the kernel still holds, death included, and a `Degraded` is a
      // live verdict that dispatches its caller's parked cookie exactly as an
      // `Applied` does. A root renamed away and its pathname recreated while
      // `IN_MOVE_SELF` sits unread would otherwise take that write into an
      // unmonitored directory and answer `Ok` for a record no stream can report,
      // with the scope's death processed only afterwards and the earlier loss
      // covering nothing that happened after it.
      //
      // Two cases are exempt, and neither is about the verdict. A
      // KERNEL-RECURSIVE scope can obtain no proof at all: its control batches
      // carry no inotify port, so the source refuses them without ever reaching
      // a reader, and requiring one would defer its settles forever. The
      // consequence is recorded honestly: the kernel-resident leg of this defect
      // stays open on such a backend, where it is currently unreachable because
      // the scope records no coverage claim and takes no `set_cover` fence —
      // only a `sync_root` opens one, and a sync's own ordering rests on the
      // single ordered lane instead. The CLOSE pass is exempt for the mirror
      // reason (see [`SettlePass::owes_cut_proof`]): every stream is already
      // torn down, so no reader can answer and no verdict can dispatch. Both
      // exempt cases reach every fence they hold, so they always resolve whole.
      let Some(entry) = self.cover_fences.get(&scope) else {
        continue;
      };
      let through = if self.cut_proof_required(scope) && pass.owes_cut_proof() {
        let Some(reach) = entry.cut.licenses_through(self.coverage_epoch(scope)) else {
          continue;
        };
        reach
      } else {
        entry.high_water()
      };
      let Some(entry) = self.cover_fences.get_mut(&scope) else {
        continue;
      };
      // Ordinals ascend with open order, so the licensed fences are exactly a
      // prefix; the rest stay pending, keeping the lossiness they have accrued,
      // and are decided by their own successor proof.
      let split = entry
        .pending
        .partition_point(|pending| pending.opened <= through);
      let resolving: Vec<PendingFence> = entry.pending.drain(..split).collect();
      let lossy = entry.lossy;
      let spent = entry.pending.is_empty();
      // Teardown removes the entry with its scope, so a live entry always has scope
      // state; a scope-less entry is a seam bug — resolve its fences `Dead` rather
      // than report `Applied` for coverage nobody backs. Such an entry is exempt
      // above (a scope with no state can obtain no proof), so it always resolves
      // whole and reaches the repair below rather than lingering half-settled.
      let mut dead = false;
      if spent {
        self.cover_fences.remove(&scope);
        if let Some(state) = self.scopes.get_mut(&scope) {
          if lossy {
            state.applied_cover = state.settle_floor.clone();
          } else {
            state.settle_floor = state.applied_cover.clone();
          }
        } else {
          debug_assert!(false, "a fence entry never outlives its scope");
          dead = true;
        }
      }
      for pending in resolving {
        // A scope-less entry means exactly what the teardown fold means — no scope
        // backs this fence — so it mints the same verdict rather than a weaker one
        // that a consumer would have to disambiguate.
        let settle = if dead {
          CoverSettle::Dead
        } else if pending.lossy {
          CoverSettle::Degraded
        } else {
          CoverSettle::Applied
        };
        settled.push((pending.fence, settle));
      }
    }
    settled
  }

  /// The cookie dispatch's deficit seam: re-signals `scope`'s standing
  /// terminal coverage deficits through the Monitor (one fresh epoch-bumped
  /// covering `Rescan` per site plus a bounded heal kick —
  /// [`Monitor::resignal_coverage_deficits`]), then drains, so the `Rescan`
  /// effects are queued BEFORE the caller dispatches the parked cookie write.
  /// Returns whether anything was re-signaled; a no-op for a scope with no
  /// deficit or a kernel-recursive one.
  pub(crate) fn resignal_coverage_deficits(&mut self, scope: ScopeId) -> bool {
    let signaled = self.monitor.resignal_coverage_deficits(scope);
    if signaled {
      self.drain_monitor();
    }
    signaled
  }

  /// Feeds the blocking spawn's outcome for `scope`'s stream.
  pub(crate) fn on_stream_spawned(&mut self, scope: ScopeId, res: Result<RootMeta, SourceError>) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    let watch = state.watch;
    match res {
      Ok(meta) => {
        // `Backend::Auto` decides the backend only once the source has spawned,
        // so the registered profile is provisional: adopt the probed backend's
        // profile before the root's watch-result is fed. The root node is still
        // bootstrapping (no children, no record ingested), so re-profiling only
        // governs decisions still to come — the post-arm enumerate and every
        // later descent gate. A forced backend resolves to the profile it was
        // registered with, so the reprofile is a no-op there.
        let backend = meta.backend;
        if backend != state.profile {
          state.profile = backend;
          self.monitor.reprofile_root(scope, caps_for(backend));
        }
        let root = Arc::new(meta.root);
        state.root = Some(Arc::clone(&root));
        state.root_dev = Some(meta.root_dev);
        state.root_mnt_id = meta.root_mnt_id;
        state.identity = Some(meta.identity);
        state.mounts = meta.mounts;
        // Born closed: the seed was read before the stream started, so a
        // mount appearing in that gap is in neither the seed nor the event
        // stream — the seed can only REDUCE trust. Authority arrives with
        // this birth refresh, whose post-live read the stream orders against
        // every later mount transition; until it installs, event-side
        // identity and cookies fail closed (the non-authoritative default).
        Self::arm_refresh(&mut self.effects, scope, state);
        match backend {
          // Kernel-recursive: the live stream IS the root's coverage, so the
          // spawn doubles as the root's watch-result AND the moment the caller's
          // grant commits inline — public delivery begins here. fanotify's one
          // superblock mark and the Windows primitives' subtree streams cover
          // the whole root exactly like FSEvents.
          BackendKind::FsEvents
          | BackendKind::Fanotify
          | BackendKind::Rdcw
          | BackendKind::UsnJournal => {
            state.publicly_live = true;
            let attempt = state.root_attempt;
            if let Some(attempt) = attempt {
              self.monitor.on_watch_result(
                watch,
                attempt,
                Ok(tributary_proto::WatchAck::Installed),
              );
            } else {
              debug_assert!(false, "a spawned scope drained its root's bootstrap arm");
            }
          }
          // Descending: the source starts with NO watches (nothing may be
          // delivered before the Monitor's own watch flow runs), so the
          // root's kernel watch is armed through the same effect path as
          // every descendant — its watch-result arrives via
          // [`on_watch_installed`](Self::on_watch_installed).
          BackendKind::Inotify => {
            let name = root
              .file_name()
              .and_then(|name| name.to_str())
              .unwrap_or("/");
            // The root's barrier read its identity; the arm confirms the object
            // did not get replaced between that read and the (absolute-path) open.
            // The spawn barrier already brackets identity around start, but the
            // root arm happens after — so the same confirmation applies here.
            let expected = u64::try_from(meta.identity.ino())
              .ok()
              .and_then(NonZeroU64::new)
              .map(|ino| ExpectedObject {
                dev: meta.identity.dev(),
                ino,
              });
            let Some(attempt) = state.root_attempt else {
              debug_assert!(false, "a spawned scope drained its root's bootstrap arm");
              return;
            };
            self.effects.push_back(Effect::AddWatch {
              scope,
              watch,
              attempt,
              parent: watch,
              name: Segment::new(name),
              path: root,
              expected,
            });
          }
        }
      }
      Err(err) => {
        if let Some(attempt) = state.root_attempt {
          self
            .monitor
            .on_watch_result(watch, attempt, Err(watch_error(&err)));
        }
      }
    }
    self.drain_monitor();
  }

  /// The driver refused the spawned stream before it went live: its FINAL
  /// canonical root overlapped a root this watcher already covers (the
  /// backend re-canonicalizes, so a spawn can resolve somewhere the
  /// reservation did not). The scope ends exactly like a failed spawn.
  pub(crate) fn on_spawn_rejected(&mut self, scope: ScopeId) {
    let Some(state) = self.scopes.get(&scope) else {
      return;
    };
    let watch = state.watch;
    if let Some(attempt) = state.root_attempt {
      self
        .monitor
        .on_watch_result(watch, attempt, Err(WatchError::Gone));
    }
    self.drain_monitor();
  }

  /// Feeds one descending arm's outcome. An [`Aliased`](WatchOutcome::Aliased)
  /// anchor maps to a successful watch-result exactly like a fresh install:
  /// the wd table fans the shared kernel watch's events out to every anchor,
  /// so the anchor's coverage is real — the Monitor proceeds to the post-arm
  /// read the node's own flavor selects (a registration's is re-arm-flavored and
  /// announces nothing; a live discovery's is cold) and the coverage it takes is
  /// correct either way.
  /// The scope a watch belongs to, while the watch is tracked. The driver
  /// uses this to route a root arm's outcome to its deferred registration
  /// grant.
  pub(crate) fn scope_of_watch(&self, watch: WatchId) -> Option<ScopeId> {
    self.watch_scopes.get(&watch).copied()
  }

  /// The attempt `watch`'s current arm carries — what the driver captures off
  /// the [`Effect::AddWatch`] it dispatches. Recovered here for tests that are
  /// not about supersession; one that IS captures the token from the effect and
  /// replays it after a later arm has taken over.
  #[cfg(test)]
  pub(crate) fn arm_attempt(&self, watch: WatchId) -> ArmAttempt {
    self
      .monitor
      .arm_attempt(watch)
      .unwrap_or_else(|| ArmAttempt::new(NonZeroU64::MIN))
  }

  pub(crate) fn on_watch_installed(
    &mut self,
    watch: WatchId,
    attempt: ArmAttempt,
    outcome: WatchOutcome,
  ) {
    // The fresh-vs-aliased bit is carried through, not collapsed: a binding
    // re-proof keys its dark-window verdict on it (`Installed` = the old
    // binding was dead or rebound, so the settle edge owes the closing
    // `Rescan`; `Aliased` = live all along, no window).
    let res = match outcome {
      WatchOutcome::Installed(_) => Ok(tributary_proto::WatchAck::Installed),
      WatchOutcome::Aliased(_) => Ok(tributary_proto::WatchAck::Aliased),
      WatchOutcome::Failed(err) => Err(err),
    };
    // A descending scope's ROOT arm succeeding is the moment its coverage — and
    // its caller's handle (the deferred grant commits on this same result) —
    // become real: public delivery begins here, exactly like the KR spawn does
    // inline. `watch == state.watch` is precisely the root's own watch (the root
    // arms with `parent == watch == the scope's root watch`), so a CHILD arm
    // never flips this. A FAILED root arm leaves `publicly_live` false, so the
    // Monitor's ensuing failure `Rescan` is fenced out of the effect queue — the
    // caller got `Err`, never a handle, so there is no public view to cover.
    if res.is_ok()
      && let Some(&scope) = self.watch_scopes.get(&watch)
      && let Some(state) = self.scopes.get_mut(&scope)
      && state.watch == watch
    {
      state.publicly_live = true;
    }
    self.monitor.on_watch_result(watch, attempt, res);
    self.drain_monitor();
  }

  /// Feeds one raw directory listing back for the enumerate that requested
  /// it, minting each entry's identity through the SAME policy the probe path
  /// uses (enumerate-side identity is the authority; a foreign-device entry
  /// mints `None`). A DIRECTORY across the scope's MOUNT boundary — a differing
  /// mount id, or (as a belt, and when the mount id is unavailable) a differing
  /// device — is lowered as [`FileKind::Other`]: the mount boundary is the scope
  /// boundary, so the Monitor must not descend it — the entry still delivers, the
  /// subtree beyond the boundary is deliberately outside coverage. The mount-id
  /// fence catches a `mount --bind` of a same-DEVICE directory the device check
  /// alone would descend across (the same breach the fanotify walk closes with the
  /// same fence); the device belt still governs when either mount id is unknown
  /// (the honest below-5.8 degrade).
  ///
  /// An entry the caller EXCLUDED is dropped from the listing outright — the cold
  /// half of the common-layer fence (see [`exclusions`](Self::exclusions)). An
  /// excluded directory is therefore never staged, so the Monitor never emits its
  /// `Created`, never reconciles a slot for it, never arms it and never descends
  /// it. The drop deliberately does NOT set `lossy`: a `Partial` listing means the
  /// read could not report everything, which forces a covering `Rescan` and a
  /// bounded retry, whereas this omission is exactly what the caller asked for and
  /// has nothing to recover. This fence needs no backend gate — an enumerate only
  /// ever happens on a descending profile, and a descending backend by
  /// construction has no admission-time enforcement of its own.
  pub(crate) fn on_enumerated(&mut self, req: ReqId, raw: RawEnumerate) {
    let Some((scope, dir)) = self.enum_reqs.remove(&req) else {
      return;
    };
    let res = match raw {
      RawEnumerate::Failed(class) => EnumerateResult::Failed(class),
      RawEnumerate::Listed { entries, complete } => {
        let Some(state) = self.scopes.get(&scope) else {
          return;
        };
        let mut listed = Vec::with_capacity(entries.len());
        let mut lossy = false;
        for entry in entries {
          let Ok(name) = core::str::from_utf8(&entry.name) else {
            // A non-UTF-8 name cannot become a `Segment` (the documented v1
            // limitation): degrade the listing to Partial so the Monitor's
            // bounded retry + standing Rescan cover the unrepresentable
            // entry rather than silently omitting it.
            lossy = true;
            continue;
          };
          let path = dir.join(name);
          if self.excluded(&path) {
            continue;
          }
          let node = mint(state, &path, NonZeroU64::new(entry.ino), Some(entry.dev));
          let kind = if entry.kind.is_dir() && crosses_mount_boundary(state, &entry) {
            FileKind::Other
          } else {
            entry.kind
          };
          let mut dir_entry = DirEntry::new(Segment::new(name), kind);
          if let Some(node) = node {
            dir_entry = dir_entry.with_node(node);
          }
          listed.push(dir_entry);
        }
        if complete && !lossy {
          EnumerateResult::Ok(listed)
        } else {
          EnumerateResult::Partial(listed)
        }
      }
    };
    self.monitor.on_enumerate(req, res);
    self.drain_monitor();
  }

  /// Feeds one decoded callback batch for `scope`, taking the whole payload:
  /// the budget slot rides with the events for as long as the core retains
  /// them (parked active or queued), so parked memory stays inside the
  /// transport budget and a stuck probe back-pressures the callback.
  pub(crate) fn on_batch(&mut self, scope: ScopeId, payload: BatchPayload, now: Instant) {
    let Some(mut state) = self.scopes.remove(&scope) else {
      return;
    };
    if state.park.active.is_some() {
      state.park.queued.push_back(payload);
      self.scopes.insert(scope, state);
      return;
    }
    let BatchPayload { events, permit, .. } = payload;
    let mut batch = self.compile(&mut state, scope, events, now);
    batch.permit = Some(permit);
    let fed = Self::settle_if_ready(&mut self.monitor, &mut state, scope, batch, now);
    self.scopes.insert(scope, state);
    if fed {
      self.pump_queued(scope, now);
    }
    self.drain_monitor();
  }

  /// Test entry taking bare FSEvents records under a detached budget slot.
  #[cfg(test)]
  pub(crate) fn on_batch_events(&mut self, scope: ScopeId, events: Vec<RawOsEvent>, now: Instant) {
    let events = events.into_iter().map(SourceEvent::FsEvents).collect();
    self.on_batch(scope, BatchPayload::detached(events), now);
  }

  /// Test entry taking bare attributed inotify records.
  #[cfg(test)]
  pub(crate) fn on_inotify_events(
    &mut self,
    scope: ScopeId,
    events: Vec<crate::os::linux::RawLinuxEvent>,
    now: Instant,
  ) {
    let events = events.into_iter().map(SourceEvent::Linux).collect();
    self.on_batch(scope, BatchPayload::detached(events), now);
  }

  /// Feeds one probe's outcome; a completed batch (and any batches queued
  /// behind it) is then fed to the Monitor in order.
  pub(crate) fn on_probe_result(&mut self, probe: ProbeId, outcome: ProbeOutcome, now: Instant) {
    let Some(ctx) = self.probes.remove(&probe) else {
      return;
    };
    // A slot stat answers the Monitor directly: it grounds no batch item, so it
    // resolves ahead of the park machinery and never touches a scope's park.
    if let ProbePurpose::SlotKind { req } = ctx.purpose {
      self.monitor.on_stat_result(req, stat_result(outcome));
      self.drain_monitor();
      return;
    }
    let Some(mut state) = self.scopes.remove(&ctx.scope) else {
      return;
    };
    let scope = ctx.scope;
    let resolved = Self::resolve(&mut state, ctx.purpose, outcome);
    let mut fed = false;
    if let Some(batch) = state.park.active.as_mut() {
      if let Some((fid, partner)) = resolved.evidences {
        batch.evidenced.entry(fid).or_default().push(partner);
      }
      if let Some(slot) = batch.items.get_mut(resolved.item) {
        slot.planned = resolved.planned;
        slot.probe = None;
        slot.cookie_candidate = resolved.candidate;
        batch.awaiting = batch.awaiting.saturating_sub(1);
      }
      if batch.awaiting == 0 {
        let batch = state.park.active.take().expect("just observed Some");
        Self::settle(&mut self.monitor, &mut state, scope, batch, now);
        fed = true;
      }
    }
    self.scopes.insert(scope, state);
    if fed {
      self.pump_queued(scope, now);
    }
    self.drain_monitor();
  }

  /// Commits a root replacement on a live scope: the new stream's
  /// [`RootMeta`] replaces the scope's world (root bytes, device, mount
  /// frame, identity, mount seed), and everything the OLD world still owed
  /// is resolved by domination — the loss-path cut. Parked work and
  /// in-flight probes were compiled against the old root's bytes, so they
  /// are dropped, not re-addressed; the epoch-bumped full-root `Rescan` the
  /// cut emits instructs the consumer to re-read the (widened) world, which
  /// covers the old subtree's swap window and the newly covered delta alike.
  ///
  /// The scope's LOWERING must be preserved (the driver refuses a
  /// descending↔KR flip as `BackendDiverged` before this input is reached);
  /// a KR→KR backend change (a replace landing on another volume under the
  /// windows Auto ladder) re-profiles exactly like `on_stream_spawned`. On a
  /// descending scope the per-directory book rebinds
  /// ([`Monitor::rebind_root`]): the driver has ALREADY armed the new root
  /// on the new transport and replays that outcome via
  /// [`on_watch_installed`](Self::on_watch_installed) immediately after this
  /// input — the re-arm-flavored rebuild it kicks off restores coverage
  /// without re-announcing content the commit `Rescan` already covers.
  ///
  /// Returns the [`ArmAttempt`] that replay must be reported under (`None` for
  /// a kernel-recursive scope, which replays nothing): the rebind supersedes
  /// every arm the retired transport still owes, so an outcome from one of
  /// those names an older attempt and is discarded rather than judging the
  /// binding that replaced it.
  pub(crate) fn on_root_replaced(
    &mut self,
    scope: ScopeId,
    meta: RootMeta,
    now: Instant,
  ) -> Option<ArmAttempt> {
    let state = self.scopes.get_mut(&scope)?;
    debug_assert_eq!(
      state.profile.is_kernel_recursive(),
      meta.backend.is_kernel_recursive(),
      "replace never crosses lowering profiles; the driver refuses BackendDiverged"
    );
    let backend = meta.backend;
    if backend != state.profile {
      state.profile = backend;
      self.monitor.reprofile_root(scope, caps_for(backend));
    }

    // The world swap — the on_stream_spawned adoption, on a live scope.
    let root = Arc::new(meta.root);
    state.root = Some(root);
    state.root_dev = Some(meta.root_dev);
    state.root_mnt_id = meta.root_mnt_id;
    state.identity = Some(meta.identity);
    state.mounts = meta.mounts;
    // The old world's authority cannot vouch for the new root's mounts:
    // trust fails closed until the refresh this commit arms completes. A
    // refresh already in flight was addressed to the REPLACED root — mark it
    // cross-world so its completion (liveness verdict included) is discarded
    // rather than judging the new identity by the old object.
    state.refresh_world_stale = state.refresh_pending;
    // A replace commit ends any witnessed widen window outright: the fallback
    // route lands here with the tainted (or refused) window still recorded,
    // and the replacement's own spawn barrier re-established the binding from
    // scratch — leaking the dead window would poison a FUTURE widen's
    // reservation (INV-ROOT leg (i)).
    state.pending_widen = None;
    state.mounts_authoritative = false;
    Self::arm_refresh(&mut self.effects, scope, state);

    // The cut: old-world parked work and probes are dominated, and the
    // Monitor turns the swap into the epoch-bumped covering Rescan.
    state.park.active = None;
    state.park.queued.clear();
    // The geometry pass needs no cut of its own here. It holds no state across
    // records: a rename's source end is read from the Monitor's own reparent
    // report at the instant the destination is fed, so the halves the rebind
    // below purges ([`Monitor::rebind_root`]) take every geometry consequence
    // with them. A destination arriving in the NEW world under a wrapped kernel
    // cookie finds no half, is reported as the fresh directory it is, and
    // repairs nothing.
    Self::trust_lost(&mut self.effects, scope, state);
    self.probes.retain(|_, ctx| ctx.scope != scope);
    // Old-world enumerate contexts are dominated too: a descending replace's
    // in-flight reads will never return (their Monitor slots are dropped by
    // `rebind_root` below), and a late result would otherwise lower against
    // the NEW world before the Monitor rejects its now-unknown request.
    // Reclaim them exactly as teardown does; the rebuild's fresh reads are
    // recorded below in `drain_monitor`.
    self.enum_reqs.retain(|_, (s, _)| *s != scope);
    // Descending: the per-directory book was built on the retired
    // transport — rebind it (children dropped, root reset to a counted
    // re-arm) BEFORE the overflow cut, whose re-arm kickoff then folds into
    // the reset root instead of re-reading the old tree.
    let replay = if backend.is_kernel_recursive() {
      None
    } else {
      self.monitor.rebind_root(scope).map(|(_, attempt)| attempt)
    };
    self.monitor.on_overflow(Scope::Root(scope), now);
    self.drain_monitor();
    replay
  }

  /// The root `WatchId` of a live scope — the anchor the driver pre-arms on
  /// the replacement transport before committing a descending replace.
  pub(crate) fn root_watch(&self, scope: ScopeId) -> Option<WatchId> {
    self.scopes.get(&scope).map(|state| state.watch)
  }

  /// A live scope's canonical root — the commit-time authority the driver's
  /// widen predicate (old ⊂ new) compares against.
  pub(crate) fn root_path(&self, scope: ScopeId) -> Option<Arc<PathBuf>> {
    self.scopes.get(&scope).and_then(|state| state.root.clone())
  }

  /// A live scope's mount frame `(root_dev, root_mnt_id)` — the same-frame
  /// conjunct of the widen predicate: the enumerate lowering marks any entry
  /// across the scope's frame [`FileKind::Other`] and the reconcile drops the
  /// watch in such a slot, so widening over a differing frame would actively
  /// tear the adopted coverage down. `None` for a scope with no live stream.
  pub(crate) fn root_frame(&self, scope: ScopeId) -> Option<(u64, Option<u64>)> {
    self
      .scopes
      .get(&scope)
      .and_then(|state| state.root_dev.map(|dev| (dev, state.root_mnt_id)))
  }

  /// Mints the watch id a same-transport widen pre-arms on the LIVE port
  /// before its commit — see [`Monitor::reserve_watch_id`].
  pub(crate) fn reserve_watch_id(&mut self) -> WatchId {
    self.monitor.reserve_watch_id()
  }

  /// Opens the witnessed window for a same-transport widen (INV-ROOT): from
  /// this instant every record the transport attributes to `reserved` is
  /// intercepted by the inotify lowering (a death record taints, benign churn
  /// is counted) and every scope loss signal taints — so the commit gate can
  /// prove, not sample, that the reserved binding is still live. MUST be
  /// called before the pre-arm is dispatched: the reader registers the kernel
  /// wd against `reserved` at arm execution, and no attributed record may
  /// predate the window that witnesses it. Single-flight per scope (the
  /// driver's `replace_states` already serializes replaces).
  pub(crate) fn begin_widen_watch(&mut self, scope: ScopeId, reserved: WatchId) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    debug_assert!(
      state.pending_widen.is_none(),
      "replaces are single-flight per scope; a stale window may not leak into a fresh widen"
    );
    state.pending_widen = Some(PendingWiden {
      reserved,
      tainted: None,
      benign: 0,
    });
  }

  /// Closes a witnessed window whose widen will not commit — a failed or
  /// retired pre-arm, or the loud impossible-path fallback. Idempotent; a
  /// scope torn down meanwhile has no state and nothing to clear (the window
  /// died with it).
  pub(crate) fn abort_widen_watch(&mut self, scope: ScopeId) {
    if let Some(state) = self.scopes.get_mut(&scope) {
      state.pending_widen = None;
    }
  }

  /// Commits a same-transport WIDEN on a live descending scope: the world meta
  /// swaps to the new (containing) root and the Monitor splices the new root
  /// ABOVE the old one ([`Monitor::widen_root`]) — the old subtree's watches,
  /// states, reads, move halves, and deficits all ride across untouched on the
  /// unchanged stream, which is the zero-gap guarantee. Deliberately absent,
  /// each a loss signal the D1 replace commit
  /// ([`on_root_replaced`](Self::on_root_replaced)) must produce and this
  /// commit must NOT: no park/probe/enumerate cut (the inotify lowering parks
  /// nothing and its watch-anchored records are immune to the root flip), no
  /// covering `Rescan`, no epoch bump, no cover-claim reset (`applied_cover`
  /// keeps the old claim — resetting to `None` would claim full coverage over
  /// regions a prior `set_cover` pruned, and the next reconcile's broadening
  /// delta against `None` would grow nothing over the hole; keeping it merely
  /// under-claims the freshly-armed slice, the safe direction).
  ///
  /// The caller (the driver's widen commit) has ALREADY armed `reserved` on
  /// the live transport and replays that outcome via
  /// [`on_watch_installed`](Self::on_watch_installed) immediately after this
  /// input; the replay's cold enumerate discovers the newly covered ground as
  /// `Created`s — a birth-equivalent window, dominated by nothing.
  ///
  /// Returns how the commit was disposed of ([`WidenCommit`]).
  /// [`TaintedWindow`](WidenCommit::TaintedWindow) is the witnessed-window
  /// gate (INV-ROOT): a reserved death record or a scope loss signal landed
  /// between the reservation and this commit, so the reserved binding cannot
  /// be proven live — the splice is refused with the core and Monitor
  /// untouched except for the spent window, and the caller (which owes no
  /// loudness — this is a legitimate outcome) disarms the pre-armed
  /// descriptor and falls back to the general stream replace, re-establishing
  /// the binding through a fresh spawn barrier.
  /// [`Refused`](WidenCommit::Refused) — a violated precondition on a path
  /// the driver's gates make unreachable — leaves the core and the Monitor
  /// bit-identical, the window entry included (every refusal is decided
  /// before the first mutation), and the caller MUST treat it loudly: the
  /// widen falls back to the general stream replace (the driver clears the
  /// leftover window and keeps the registry on the OLD root — the widened
  /// entry publishes only after a `Committed`). A silent `Ok` over a refused
  /// splice would be a registry/core root divergence on the barrier-honesty
  /// path.
  pub(crate) fn on_root_widened(
    &mut self,
    scope: ScopeId,
    meta: RootMeta,
    reserved: WatchId,
    now: Instant,
  ) -> WidenCommit {
    let liveness = self.root_liveness_interval;
    let Some(state) = self.scopes.get_mut(&scope) else {
      return WidenCommit::Refused;
    };
    // The witnessed-window gate (INV-ROOT), FIRST: the window verdict is
    // prior to the splice's shape — a tainted window refuses regardless of
    // how well-formed the commit is, because the thing being committed (the
    // reserved binding) can no longer be proven live. Only the taint verdict
    // consumes the window (its defined semantics: the window is spent, the
    // fallback re-establishes); every later refusal leaves it intact for the
    // fallback commit to clear, preserving the bit-identical contract.
    match &state.pending_widen {
      Some(pending) if pending.reserved != reserved => {
        debug_assert!(false, "the committed reservation is the window's own");
        return WidenCommit::Refused;
      }
      Some(pending) => {
        if pending.tainted.is_some() {
          let spent = state.pending_widen.take().expect("just observed Some");
          return WidenCommit::TaintedWindow(WidenTaint {
            cause: spent.tainted.expect("just observed tainted"),
            benign: spent.benign,
          });
        }
      }
      None => {
        debug_assert!(false, "a widen commit follows its begin_widen_watch");
        return WidenCommit::Refused;
      }
    }
    debug_assert!(
      !state.profile.is_kernel_recursive() && state.profile == meta.backend,
      "a widen never crosses profiles or backends"
    );
    // The inotify lowering settles every batch inline (no probes, no park), so
    // there is no compiled old-root-relative state to cut or re-base. A future
    // probing/parking descending backend must revisit this keep-list.
    debug_assert!(
      state.park.active.is_none() && state.park.queued.is_empty(),
      "the descending profile parks nothing"
    );

    // The adopted chain: the old root's location relative to the new root. The
    // driver validated strict containment and UTF-8 before dispatching the
    // pre-arm; re-derive defensively and refuse untouched on any violation —
    // the driver falls back to the stream replace, whose commit publishes
    // spawn-minted truth (the registry still names the old root: the widened
    // entry publishes only after this commit succeeds).
    let Some(old_root) = state.root.clone() else {
      return WidenCommit::Refused;
    };
    let Ok(rel) = old_root.strip_prefix(meta.root.as_path()) else {
      debug_assert!(false, "the driver routes only strict widens here");
      return WidenCommit::Refused;
    };
    let mut chain = Vec::new();
    for component in rel.components() {
      let std::path::Component::Normal(os) = component else {
        debug_assert!(
          false,
          "a canonical strict suffix has only normal components"
        );
        return WidenCommit::Refused;
      };
      let Some(name) = os.to_str() else {
        debug_assert!(false, "the driver refuses a non-UTF-8 chain");
        return WidenCommit::Refused;
      };
      chain.push(Segment::new(name));
    }
    if chain.is_empty() {
      debug_assert!(false, "the driver refuses an equal-root widen");
      return WidenCommit::Refused;
    }
    // The adopted node's identity, in the enumerate-mint space (the bare inode
    // — see `mint`): the old root sits on the scope's own device by the widen
    // predicate, so the device-trust gate is satisfied by construction.
    let old_identity = state
      .identity
      .and_then(|id| u64::try_from(id.ino()).ok())
      .and_then(NonZeroU64::new)
      .map(Identity::new);
    let Some((_, attempt)) = self
      .monitor
      .widen_root(scope, reserved, chain, old_identity)
    else {
      debug_assert!(false, "a live descending scope accepts its widen splice");
      return WidenCommit::Refused;
    };

    // Watch bookkeeping: the new root joins the scope map, and the old
    // subtree's addressing needs no rewrite — paths are DERIVED, and the splice
    // above already re-rooted the old root under the adopted chain, so every
    // watch beneath it composes the same absolute path off the new origin.
    let root = Arc::new(meta.root);
    self.watch_scopes.insert(reserved, scope);
    state.watch = reserved;

    // The world swap — the same adoption `on_root_replaced` performs, minus
    // every cut: the new root is a different object, so mount trust fails
    // closed until the refresh this arms completes, and an in-flight refresh
    // was addressed to the OLD root and must be discarded on completion.
    state.root = Some(root);
    state.root_dev = Some(meta.root_dev);
    state.root_mnt_id = meta.root_mnt_id;
    state.identity = Some(meta.identity);
    state.mounts = meta.mounts;
    state.refresh_world_stale = state.refresh_pending;
    // The witnessed window is CONSUMED by the commit (INV-ROOT): it was clean
    // through the taint gate above, the splice landed, and from here the
    // reserved id is a KNOWN root — its death records run the ordinary
    // in-band funnel, so the commit is a regime boundary, never a flush (a
    // death record still queued at this instant invalidates the widened root
    // honestly when it drains). The proof the window discharges: the pre-arm
    // bound the right object (open-verify-install + the post-arm bracket), a
    // binding bound right that later dies or moves emits a death record or
    // its loss is signalled, and neither happened — so the binding is live
    // and correctly placed NOW, with no out-of-band sample consulted.
    state.pending_widen = None;
    Self::trust_lost(&mut self.effects, scope, state);
    Self::arm_liveness(state, liveness, now);

    // A lag-parked Rescan crosses the commit as the WIDENED scope's drop
    // license: while the lag stands, route_event keeps dropping scope-wide —
    // from here that includes the added ground and its cold-read discoveries
    // — so the parked instruction is re-parked at the NEW root (empty
    // location, id + epoch kept), never merely re-based under the adopted
    // prefix: a prefix-joined location would cover only the old subtree
    // while licensing widened-scope drops (INV-PARK). An over-wide
    // re-enumeration is the honest direction. (D1 needs neither — its commit
    // parks a fresh dominating ROOT Rescan through the overflow cut.)
    if let LagState::Lagged {
      parked: Some(change),
      ..
    } = &mut state.lag
    {
      debug_assert!(change.kind().is_rescan(), "only Rescans park under lag");
      *change = Change::new(
        change.id(),
        scope,
        Location::new(),
        change.kind().clone(),
        change.epoch(),
      );
    }

    // The chain arms and the replayed root arm's cold read lower through the
    // ordinary drain — the live port is the attached port, so no transport
    // work exists here at all.
    self.drain_monitor();
    WidenCommit::Committed(attempt)
  }

  /// Feeds a transport-level loss signal for `scope` (a dropped batch, the
  /// handle's overflow latch): parked work is dominated and dropped, and the
  /// Monitor turns the loss into an epoch-bumped `Rescan`.
  pub(crate) fn on_root_overflow(&mut self, scope: ScopeId, now: Instant) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    // The witnessed window's loss leg (INV-ROOT): a loss inside the widen
    // window may have carried the reserved root's own death records, so the
    // window can no longer witness their absence — taint it (coarse by
    // design: attribution of a loss is unknowable, so any scope loss taints).
    // The tainted commit falls back to the stream replace, whose covering
    // Rescan + fresh spawn barrier own the lost window anyway.
    if let Some(pending) = state.pending_widen.as_mut() {
      pending.taint(TaintCause::Loss);
    }
    state.park.active = None;
    state.park.queued.clear();
    Self::trust_lost(&mut self.effects, scope, state);
    self.probes.retain(|_, ctx| ctx.scope != scope);
    self.monitor.on_overflow(Scope::Root(scope), now);
    self.drain_monitor();
  }

  /// Fails device trust closed after a loss signal: the dropped window may
  /// have carried a mount transition, so the table can no longer prove a path
  /// is root-device. Authority returns only with a fresh read of the live
  /// mount table; repeated losses coalesce onto one outstanding refresh.
  fn trust_lost(effects: &mut VecDeque<Effect>, scope: ScopeId, state: &mut ScopeState) {
    state.mounts_authoritative = false;
    Self::arm_refresh(effects, scope, state);
  }

  /// Arms one mount-table refresh for `scope`, coalescing onto an outstanding
  /// one: a refresh raced by a newer arming re-runs once (`refresh_stale`)
  /// instead of stacking effects. Serves both the birth refresh (authority is
  /// never presumed at spawn) and every post-loss re-read.
  fn arm_refresh(effects: &mut VecDeque<Effect>, scope: ScopeId, state: &mut ScopeState) {
    if state.refresh_pending {
      state.refresh_stale = true;
      return;
    }
    // No canonical root means no live stream: nothing to read yet, and the
    // spawn arm re-arms once the root installs.
    let Some(root) = state.root.clone() else {
      return;
    };
    state.refresh_pending = true;
    effects.push_back(Effect::RefreshMounts { scope, root });
  }

  /// (Re)arms the periodic root-liveness deadline for a signal-silent scope
  /// whose root is live, or clears it when the tick does not apply (a non-
  /// fanotify backend, `Duration::ZERO`, or a root not yet live). Called on
  /// every alive mount-refresh completion so birth seeds it and each refresh
  /// re-seeds it, and after [`on_timeout`](Self::on_timeout) fires a tick. Takes
  /// `interval` explicitly (like [`arm_refresh`](Self::arm_refresh) takes
  /// `effects`) so it composes with a `&mut ScopeState` borrowed out of
  /// `self.scopes`.
  fn arm_liveness(state: &mut ScopeState, interval: Duration, now: Instant) {
    state.liveness_deadline =
      (Self::liveness_ticked(state.profile) && !interval.is_zero() && state.root.is_some())
        .then(|| now + interval);
  }

  /// Feeds one mount-table refresh result: updates device trust AND checks the
  /// root's liveness (folded into the same refresh — a kernel-recursive backend
  /// gets no in-tree unmount signal, so this cadence is its root-death check).
  ///
  /// Publication is ordered: the root-liveness verdict acts FIRST and
  /// unconditionally (a dead root is terminal regardless of snapshot staleness);
  /// the mount table AND the descent frame (`root_mnt_id`) publish only on a
  /// non-stale snapshot; and a non-stale frame CHANGE reconciles a descending
  /// scope's coverage (see the module doc's publication invariant).
  pub(crate) fn on_mounts_refreshed(
    &mut self,
    scope: ScopeId,
    refresh: MountRefresh,
    now: Instant,
  ) {
    let interval = self.root_liveness_interval;
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    // The cross-world gate precedes even the death gate: this completion was
    // addressed to a root this scope REPLACED, so its liveness verdict is
    // about the old object — evidence for a world that ended at the commit,
    // not death evidence for the new one. Discard it whole and re-read the
    // live world (trust is already closed since the commit).
    if state.refresh_world_stale {
      state.refresh_world_stale = false;
      state.refresh_pending = false;
      state.refresh_stale = false;
      Self::trust_lost(&mut self.effects, scope, state);
      return;
    }
    state.refresh_pending = false;

    // Root-liveness FIRST, unconditionally — BEFORE the stale gate. A dead root
    // is terminal: mount-set staleness is irrelevant to it (a root that vanished
    // at the read's snapshot vanished, full stop), so the death evidence must
    // never be discarded by a stale flag. Under an interval shorter than refresh
    // latency (or a backed-up pool) EVERY completion is stale-marked, so gating
    // the death check on `!stale` would let a quiet unmount stay live forever —
    // the exact hole the tick exists to close. The death lowers through the SAME
    // self-event path a `RootChanged` probe uses (terminal Removed/Rescan, then
    // registry reclamation). Only a barrier-known identity can be compared (an
    // off-unix fake has none).
    let death = state.identity.and_then(|expected| match refresh.root {
      // Present and unchanged: alive, continue to the mount table below.
      RootLiveness::Present(live) if live == expected => None,
      // Present but a different object, or unreadable: the path no longer names
      // the watched object — MoveSelf, exactly as a `RootChanged` probe
      // resolving `Present`/`Failed`.
      RootLiveness::Present(_) | RootLiveness::Unreadable => Some(RecordKind::MoveSelf),
      RootLiveness::Missing => Some(RecordKind::DeleteSelf),
    });
    if let Some(kind) = death {
      let watch = state.watch;
      self.monitor.on_os_record(OsRecord::new(watch, kind), now);
      self.drain_monitor();
      return;
    }
    // Alive past the death gate. Deliberately NOT a barrier release edge: a
    // single-sample identity match proves the PATH still names the same
    // object, never that OUR watch is still its live binding (a same-identity
    // unmount+rebind passes it with the watch IGNORED), so no settle fence
    // may read anything from this positive. The widen's binding is proven at
    // its commit by the witnessed window instead (INV-ROOT); this gate's sole
    // job is the negative verdict above — a mismatch runs the death funnel.
    //
    // The stale gate governs EVERYTHING this
    // snapshot carries — the mount-TABLE install below AND the descent FRAME adopted
    // after it. A newer loss overlapped this read, so its snapshot may predate the
    // lost window; `refresh_mounts` reads the table and re-stats the frame in ONE
    // snapshot, so a stale table means an equally stale frame — publish neither.
    // The table is discarded, one fresh refresh re-arms, and device trust stays
    // closed. Liveness is already settled above (terminal regardless of stale), so a
    // stale-but-alive completion only re-arms: the frame block and the table install
    // below are BOTH the authoritative path.
    if state.refresh_stale {
      state.refresh_stale = false;
      Self::trust_lost(&mut self.effects, scope, state);
      return;
    }

    // Non-stale: adopt the freshly re-read mount frame. A same-object re-mount
    // (unmount + re-bind at the same path) keeps the root's `(dev, ino)`, so the
    // death gate above passed, yet the root now lives on a DIFFERENT mount — and
    // `crosses_mount_boundary` fences enumerate descent against this `root_mnt_id`,
    // so a frozen frame would lower every descendant on the new mount
    // non-descendable. Only a `Some` read is adopted: a transient mnt-id miss
    // (`None`) must not drop a known frame to the device belt. Gated behind the stale
    // check above, so `state.root_mnt_id` is only ever the last AUTHORITATIVE frame —
    // the value `crosses_mount_boundary` consumes is never a stale/pre-window one.
    let frame_changed = if let Some(mnt_id) = refresh.root_mnt_id {
      let changed = state.root_mnt_id != Some(mnt_id);
      state.root_mnt_id = Some(mnt_id);
      changed
    } else {
      false
    };

    // Alive and current: (re)arm the liveness tick — the birth refresh seeds it
    // and every later refresh re-seeds it, regardless of whether the mount table
    // itself could be read below.
    Self::arm_liveness(state, interval, now);

    if refresh.authoritative {
      // UNION, never replacement: an existing entry is either a still-real mount (a
      // later unmount event removes it) or a probed foreign-device prefix the
      // snapshot cannot know about — keeping both only ever reduces trust, the safe
      // direction. Probe-carried device evidence still decides what it can.
      for mount in refresh.mounts {
        if !state.mounts.iter().any(|m| m == &mount) {
          state.mounts.push(mount);
        }
      }
      state.mounts_authoritative = true;
    } else {
      // The live table could not be read, so this refresh installs no table — and a
      // prior authoritative install may have left authority OPEN. Leaving it open
      // would keep proving paths root-device by their ABSENCE from a table we just
      // failed to re-read across the very mount change this refresh was meant to
      // reconcile. Close it: absence from an unreadable table is not evidence of
      // in-root-device. The trust-REDUCING learned prefixes in `state.mounts` are
      // kept (they only ever veto trust, never grant it) for the next authoritative
      // refresh to union onto.
      state.mounts_authoritative = false;
    }

    // A CHANGED frame means a same-object re-mount moved the root to a different
    // mount: every child the last enumerate already classified carries the OLD
    // verdict — those now on the root's mount were fenced as boundaries, those left
    // behind are boundaries now — and adopting the frame does not re-read them. Only
    // a descending scope consumes the frame (a kernel-recursive mark covers the whole
    // subtree, so its frame is inert), so only it needs the replay: rescan and re-arm
    // the root under the now-authoritative frame. The loss that drove this refresh
    // also rescans, but that rescan races AHEAD of this completion and reads the
    // pre-adoption frame; this replay reruns it once the frame is current.
    if frame_changed && !state.profile.is_kernel_recursive() {
      self.monitor.on_overflow(Scope::Root(scope), now);
      self.drain_monitor();
    }
  }

  /// Feeds a dead-stream signal: the scope's coverage ended with no parent
  /// watch left to report it.
  pub(crate) fn on_source_fatal(&mut self, scope: ScopeId, now: Instant) {
    let Some(state) = self.scopes.get(&scope) else {
      return;
    };
    let watch = state.watch;
    self
      .monitor
      .on_os_record(OsRecord::new(watch, RecordKind::Ignored), now);
    self.drain_monitor();
  }

  /// Feeds the outcome of one attempted [`Effect::Emit`].
  pub(crate) fn on_delivery(&mut self, scope: ScopeId, delivery: Delivery, now: Instant) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      // A dead scope: the outcome belongs to its retryable terminal `Rescan`
      // iff that offer is the one in flight — the driver reports each emit
      // synchronously, so an ordinary post-teardown emit and the dying offer
      // are never in flight together. An ordinary emit's refusal is covered
      // by the dying `Rescan` itself and needs no bookkeeping.
      if let Some(entry) = self.dying.get_mut(&scope)
        && matches!(entry.attempt, Attempt::InFlight(_))
      {
        match delivery {
          Delivery::Accepted => {
            self.dying.remove(&scope);
          }
          Delivery::Refused => {
            entry.attempt = Attempt::Spent {
              retry_at: now + DELIVERY_RETRY,
            };
          }
        }
      }
      return;
    };
    match (delivery, &mut state.lag) {
      (Delivery::Accepted, LagState::Lagged { parked, attempt }) => {
        let delivered_current = match (parked.as_ref(), &attempt) {
          (Some(change), Attempt::InFlight(epoch)) => change.epoch() == *epoch,
          _ => false,
        };
        if delivered_current {
          state.lag = LagState::Normal;
        } else {
          // A since-replaced Rescan was accepted: the newer one still owes
          // delivery, so it becomes offerable immediately.
          *attempt = Attempt::Idle;
        }
      }
      (Delivery::Accepted, LagState::Normal) => {}
      (Delivery::Refused, LagState::Normal) => {
        state.lag = LagState::Lagged {
          parked: None,
          attempt: Attempt::Idle,
        };
        // Everything this scope already queued is dominated by the Rescan
        // being minted below; delivering any of it after the refusal would
        // put an ordinary event ahead of the Rescan that covers the drop.
        Self::purge_scope_emits(&mut self.effects, scope);
        self.monitor.on_overflow(Scope::Root(scope), now);
        self.drain_monitor();
      }
      (Delivery::Refused, LagState::Lagged { attempt, .. }) => {
        // Never re-offer synchronously — the refusing channel cannot have
        // drained yet; the retry rides the core's timer.
        *attempt = Attempt::Spent {
          retry_at: now + DELIVERY_RETRY,
        };
      }
    }
  }

  /// Advances time: resolves rename halves whose pairing window elapsed,
  /// re-arms refused parked deliveries whose retry deadline passed, and fires
  /// the periodic root-liveness re-stat for every signal-silent scope whose
  /// tick came due (the ONE timer the fanotify composition adds — a quiet
  /// unmount produces neither a birth nor a loss refresh, so without this the
  /// death would never be observed).
  pub(crate) fn on_timeout(&mut self, now: Instant) {
    self.monitor.handle_timeout(now);
    for state in self.scopes.values_mut() {
      if let LagState::Lagged { attempt, .. } = &mut state.lag
        && let Attempt::Spent { retry_at } = attempt
        && now.reached(*retry_at)
      {
        *attempt = Attempt::Idle;
      }
    }
    for entry in self.dying.values_mut() {
      if let Attempt::Spent { retry_at } = entry.attempt
        && now.reached(retry_at)
      {
        entry.attempt = Attempt::Idle;
      }
    }
    // Fire due liveness ticks: each arms the existing `RefreshMounts` (whose
    // completion runs the root-death mapping) and re-arms the deadline for the
    // next interval. Collected first so `arm_refresh` can take `&mut effects`
    // while each scope is mutated in turn. A refresh already in flight coalesces
    // (arm_refresh sets `refresh_stale`), so a tick never stacks effects.
    let interval = self.root_liveness_interval;
    let due: Vec<ScopeId> = self
      .scopes
      .iter()
      .filter_map(|(scope, state)| {
        state
          .liveness_deadline
          .filter(|deadline| now.reached(*deadline))
          .map(|_| *scope)
      })
      .collect();
    for scope in due {
      if let Some(state) = self.scopes.get_mut(&scope) {
        Self::arm_refresh(&mut self.effects, scope, state);
        Self::arm_liveness(state, interval, now);
      }
    }
    self.drain_monitor();
  }

  /// Dequeues the next I/O obligation, if any. A scope lagging with a parked
  /// `Rescan` — or a torn-down scope whose terminal `Rescan` is still owed —
  /// offers that delivery here once per attempt; a refusal re-arms through
  /// the retry timer, never synchronously.
  pub(crate) fn poll_effect(&mut self) -> Option<Effect> {
    if let Some(effect) = self.effects.pop_front() {
      return Some(effect);
    }
    for (scope, state) in self.scopes.iter_mut() {
      let root = match &state.lag {
        LagState::Lagged {
          parked: Some(_),
          attempt: Attempt::Idle,
        } => state.delivery_root(),
        _ => continue,
      };
      if let LagState::Lagged {
        parked: Some(change),
        attempt: attempt @ Attempt::Idle,
      } = &mut state.lag
      {
        *attempt = Attempt::InFlight(change.epoch());
        return Some(Effect::Emit {
          scope: *scope,
          root,
          change: change.clone(),
        });
      }
    }
    for (scope, entry) in self.dying.iter_mut() {
      if matches!(entry.attempt, Attempt::Idle) {
        entry.attempt = Attempt::InFlight(entry.change.epoch());
        return Some(Effect::Emit {
          scope: *scope,
          root: Arc::clone(&entry.root),
          change: entry.change.clone(),
        });
      }
    }
    None
  }

  /// The earliest instant [`on_timeout`](Self::on_timeout) has work to do: the
  /// Monitor's pairing deadline, a parked delivery's retry, or a scope's next
  /// root-liveness re-stat, whichever comes first.
  ///
  /// # Every table with its own lifetime is represented here
  ///
  /// The rule worth stating as one: a per-scope table whose entries expire on
  /// their own schedule must be REPRESENTED in the scheduler, or swept where it
  /// is consulted, or both. Retiring it as a side effect of some other timer
  /// happening to be armed is not a rule, it is a coincidence, and it survives
  /// only until the mechanism supplying the coincidence changes.
  ///
  /// The corollary is the cheaper defence, and the one the rename geometry now
  /// takes: a derived table with its own lifetime is a lifetime to schedule, so
  /// deriving nothing — reading the fact off the store that already owns it —
  /// removes the obligation rather than discharging it. The geometry's source end
  /// comes from the Monitor's own reparent report, which expires with the
  /// Monitor's own half, so there is no second expiry for this census to carry.
  ///
  /// The rule is checkable because the census is small. Every deadline stored
  /// anywhere under the run loop is one of three, and all three reach the loop's
  /// single `min_instant(core.poll_timeout(), cookies.min_retry_at())`:
  ///
  /// - the Monitor's pending-move deadline, via [`Monitor::poll_timeout`];
  /// - [`Attempt::Spent`]'s retry, for a scope's parked delivery and for a dying
  ///   scope's terminal `Rescan`;
  /// - [`liveness_deadline`](ScopeState::liveness_deadline), the signal-silent
  ///   root re-stat.
  ///
  /// (The driver's own sync-cookie remove-retry is the other term of that
  /// `min_instant`, outside this core.) A fourth stored deadline introduced
  /// anywhere without a leg here reopens the same class of wedge.
  pub(crate) fn poll_timeout(&self) -> Option<Instant> {
    let retry = self
      .scopes
      .values()
      .filter_map(|state| match &state.lag {
        LagState::Lagged {
          attempt: Attempt::Spent { retry_at },
          ..
        } => Some(*retry_at),
        _ => None,
      })
      .chain(self.dying.values().filter_map(|entry| match entry.attempt {
        Attempt::Spent { retry_at } => Some(retry_at),
        _ => None,
      }))
      .chain(
        self
          .scopes
          .values()
          .filter_map(|state| state.liveness_deadline),
      )
      .min();
    match (self.monitor.poll_timeout(), retry) {
      (Some(monitor), Some(retry)) => Some(if monitor.reached(retry) {
        retry
      } else {
        monitor
      }),
      (monitor, retry) => monitor.or(retry),
    }
  }

  /// Whether `scope`'s journal ids wrapped, invalidating any resume token.
  #[cfg(test)]
  pub(crate) fn resume_poisoned(&self, scope: ScopeId) -> bool {
    self
      .scopes
      .get(&scope)
      .is_some_and(|state| state.resume_poisoned)
  }

  /// Whether `scope` has a pending terminal `Rescan` in the dying set — a
  /// never-live scope must never appear here.
  #[cfg(test)]
  pub(crate) fn dying_contains(&self, scope: ScopeId) -> bool {
    self.dying.contains_key(&scope)
  }

  /// Every path this core currently holds — or is trying to hold — a kernel
  /// watch for, sorted: the descending COVERAGE set itself, as opposed to what
  /// happened to be delivered.
  ///
  /// An entry appears the moment the arm is queued and disappears when the node
  /// drops, so a directory that entered coverage shows up here even if its arm
  /// never completed and even if nothing was ever emitted for it. That is the
  /// distinction a delivery-only assertion cannot make, and exclusions are
  /// precisely a coverage question.
  ///
  /// Each entry names where its watch IS, not where it was armed: the set is
  /// derived per call ([`path_of`](Self::path_of)), so a rename the Monitor
  /// answered by re-parenting a subtree is reflected here with no repair pass and
  /// no exclusion configured. A watch the Monitor can no longer place is absent
  /// rather than reported at a stale path — this is a coverage statement, and a
  /// watch nothing can address covers nothing.
  #[cfg(test)]
  pub(crate) fn covered_paths(&self) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = self
      .watch_scopes
      .iter()
      .filter_map(|(watch, scope)| self.scoped_path(*scope, *watch))
      .collect();
    paths.sort();
    paths
  }

  /// Lowers one raw batch per the scope's backend profile. The FSEvents path
  /// probe-grounds ambiguity; the inotify path is direct. A payload variant
  /// that disagrees with the profile is a seam bug — its events degrade to a
  /// root rescan rather than a wrong lowering.
  fn compile(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    events: Vec<SourceEvent>,
    now: Instant,
  ) -> PendingBatch {
    let mut batch = match state.profile {
      BackendKind::FsEvents => {
        let mut fsevents = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::FsEvents(ev) => fsevents.push(ev),
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_fsevents(state, scope, fsevents);
        if mismatched {
          debug_assert!(false, "a foreign event reached an FSEvents scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
      BackendKind::Inotify => {
        let mut linux = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::Linux(RawLinuxEvent::Inotify { anchors, event }) => {
              linux.push(RawLinuxEvent::Inotify { anchors, event });
            }
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_inotify(state, scope, linux);
        if mismatched {
          debug_assert!(false, "a non-inotify event reached an inotify scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
      BackendKind::Fanotify => {
        let mut fanotify = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::Linux(RawLinuxEvent::Fanotify(admitted)) => fanotify.push(admitted),
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_fanotify(state, scope, fanotify);
        if mismatched {
          debug_assert!(false, "a non-fanotify event reached a fanotify scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
      BackendKind::Rdcw => {
        let mut rdcw = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::Windows(RawWindowsEvent::Rdcw(event)) => rdcw.push(event),
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_rdcw(state, scope, rdcw);
        if mismatched {
          debug_assert!(false, "a non-RDCW event reached an RDCW scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
      BackendKind::UsnJournal => {
        let mut usn = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::Windows(RawWindowsEvent::Usn(event)) => usn.push(event),
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_usn(state, scope, usn);
        if mismatched {
          debug_assert!(false, "a non-USN event reached a USN scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
    };
    self.fence_exclusions(state, scope, &mut batch, now);
    batch
  }

  /// Drops every compiled input the caller's exclusions cover — the live half of
  /// the common-layer fence (see [`exclusions`](Self::exclusions)).
  ///
  /// This is where a descending backend's coverage is actually declined: the
  /// Monitor arms a directory it learns about from a `Created`/`MovedTo` record,
  /// so a record the fence removes is a directory the Monitor never learns about,
  /// never arms and never descends. It is also where the two kernel-recursive
  /// Windows backends get their enforcement, off exactly the same rule — one
  /// fence, three backends, and a future descending backend inherits it by
  /// existing.
  ///
  /// Three things are never suppressed, and each is load-bearing:
  ///
  /// - a SELF-EVENT (`Ignored`/`MoveSelf`/`DeleteSelf`). Its watch's own death is
  ///   the one record that says the coverage is over, and a caller who excluded
  ///   the very tree it asked to watch must still be told the watch ended — the
  ///   same carve-out the fanotify fence makes for the root's death;
  /// - a ROOT-scoped or backend-wide overflow. Those cover the reported tree as
  ///   well as the exclusion, so dropping one would be silent loss over ground
  ///   the caller IS watching. The scope-wide cover in located clothing (the root
  ///   watch, no descent) is the same signal and is spared with them;
  /// - anything whose anchor path cannot be resolved ([`anchored_path`] is `None`)
  ///   — the fence fails OPEN, never closed.
  ///
  /// A located rescan strictly INSIDE an exclusion is dropped, and that is not
  /// silent loss: nothing under an exclusion is covered, so there is no coverage
  /// for it to be lost from — while keeping it would hand the caller a rescan
  /// naming the very path it asked never to hear about, which is the failure mode
  /// this whole fence exists to avoid.
  ///
  /// Runs in STREAM ORDER, and each record's classification and its hand-off to
  /// the Monitor are ONE step — the record is judged, then fed, before the NEXT
  /// record is judged. Two passes over the buffer cannot express that, and the
  /// split is not a tidiness question but the hole itself: one read can carry a
  /// directory's rename into an exclusion followed by a record from a descendant
  /// watch that rode across with it. Classify-then-feed judges that suffix against
  /// a Monitor that has not yet performed the re-parent — so the descendant still
  /// resolves outside the exclusion, is kept, and the re-parent then delivers it
  /// under the excluded destination. A record already retained is past recall: the
  /// located repair queued after the pair covers what comes next, it does not
  /// unsay what was kept ahead of it. Feeding first moves the Monitor's tree,
  /// which IS this core's addressing ([`path_of`]), so the suffix resolves where
  /// the rename actually put it and the ordinary fence suppresses it as ordinary
  /// excluded ground.
  ///
  /// `trailing` is fenced after every item for the same reason it is FED after
  /// every item: it is later in the stream, so it must be judged against the
  /// addressing the items left behind.
  ///
  /// # Feeding
  ///
  /// A profile that answers [`feeds_at_classify`] hands each kept record to the
  /// Monitor HERE, as it is judged, rather than leaving the read for
  /// [`settle`](Self::settle) to replay. That closes the phase lag the stream-order
  /// walk above is otherwise blind to: this core derives every watch path from the
  /// Monitor's tree, so a read that judges all of its records before telling the
  /// Monitor about any of them judges the whole read against the world as it stood
  /// before the read began.
  ///
  /// It is also what lets the geometry decision be driven by the Monitor's own
  /// [`RecordOutcome`] rather than by a prediction: the hand-off happens between
  /// this record and the next one to be judged, so the report of what it did to the
  /// tree is available in time. The geometry pass therefore sits wholly on the FAR
  /// side of the hand-off ([`reparent_geometry`](Self::reparent_geometry)) — it
  /// acts on the re-parent that happened, and nothing precedes the feed to predict
  /// one.
  ///
  /// The discipline is chosen by the PROFILE, above both of this function's
  /// early-outs. A scope that configured no exclusions still feeds record by
  /// record, so the suppressing path and the default path are one path — the
  /// alternative is a default configuration whose feeding no exclusion cell ever
  /// covers.
  ///
  /// Order is unchanged either way: items in stream order, then `trailing`, which
  /// under feed-at-classify is simply the part `settle` still has to feed.
  ///
  /// # The geometry pass has no bound of its own, and must not grow one back
  ///
  /// This pass once mirrored each parked rename SOURCE in a per-scope table so a
  /// later destination could look one up. A mirror is retained state, retention
  /// wants a ceiling, and the ceiling was a refusal: at a full table a rename
  /// source was not parked, classification stopped at that record, and its whole
  /// read suffix was dropped behind one scope-wide `Rescan`. Reading the source off
  /// the Monitor's own reparent report retains nothing here, so the ceiling and its
  /// refusal are gone with the table.
  ///
  /// A reader who notices that a burst of unpaired renames is now retained without
  /// any limit visible from here will be tempted to put the ceiling back. It was
  /// never a ceiling on the burst. Every source this pass could park is a source the
  /// Monitor parks too — the same record, one step later in the same walk, keyed by
  /// `(scope, cookie)` against the mirror's `cookie` — so the mirror's population
  /// was a per-scope subset of `Monitor::pending_moves`, retired on the same
  /// deadline. That store is UNCAPPED: `park_pending_move` is its single insert
  /// funnel and inserts unconditionally, and each `PendingMove` carries a
  /// `Location`, an `Evidence` and six further fields against the mirror's one
  /// optional path. So the adversarial stream that filled the mirror already grows
  /// the primary store past any number the mirror would have refused at, and always
  /// did. Capping the shadow moved no memory ceiling; it only bought a dropped read
  /// suffix and a scope-wide re-read per over-cap read.
  ///
  /// A bound on rename retention is therefore a question for `pending_moves`, where
  /// the retention actually is, and it has to be answered there — with the Monitor's
  /// own pairing semantics in hand — rather than re-imposed on a derived table whose
  /// refusal costs coverage and defends nothing.
  ///
  /// [`anchored_path`]: Self::anchored_path
  /// [`path_of`]: Self::path_of
  fn fence_exclusions(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    batch: &mut PendingBatch,
    now: Instant,
  ) {
    // INV-FEED. The feeding discipline is read off the PROFILE, before either
    // early-out, so a scope with no exclusions configured reaches the Monitor by
    // exactly the same route as one with them (see [`feeds_at_classify`]).
    let at_classify = feeds_at_classify(state.profile);
    debug_assert!(
      !runs_rename_geometry(state.profile) || at_classify,
      "INV-FEED: geometry => feed-at-classify — a profile that resolves paths \
       mid-read must not classify its records over the phase lag"
    );
    debug_assert!(
      !at_classify || batch.awaiting == 0,
      "INV-FEED: feed-at-classify => awaiting == 0 — a probe-parked batch's items \
       are placeholders and must not reach the Monitor before their probes answer"
    );
    // The fence itself stands down where the backend decides exclusions at
    // admission, and where the caller configured none.
    let fence = !self.exclusions.is_empty() && !backend_enforces_exclusions(state.profile);
    // The geometry half additionally stands down for a kernel-recursive profile
    // (see [`reparent_geometry`](Self::reparent_geometry)); the fence itself does
    // not.
    let geometry = fence && runs_rename_geometry(state.profile);
    if !fence && !at_classify {
      return;
    }
    for item in &mut batch.items {
      let planned = core::mem::take(&mut item.planned);
      // Nothing is retained under feed-at-classify — each kept record leaves for
      // the Monitor as it is judged — so the buffer that would hold them is not
      // allocated.
      let mut kept = if at_classify {
        Vec::new()
      } else {
        Vec::with_capacity(planned.len())
      };
      for planned in planned {
        if fence && self.fenced(state, &planned) {
          continue;
        }
        // Only a KEPT record carries geometry: a rename half the fence just
        // suppressed has an unreported endpoint, which means no watched subtree
        // to carry across — the destination reconciles a fresh directory and
        // cold-walks it, and that walk is fenced entry by entry.
        //
        // The destination slot a repair would name, taken while the record is
        // still in hand: the feed consumes it, and the verdict that decides
        // whether a repair is owed does not exist until the feed has happened.
        let landing = if geometry {
          Self::landing(&planned)
        } else {
          None
        };
        let outcome = Self::accept(&mut self.monitor, state, &mut kept, planned, now);
        // The repair is by construction anchored at a reported destination, so
        // it needs no fencing of its own. It follows the record it repairs, in
        // this order, on both disciplines.
        if let Some((watch, target)) = landing
          && let Geometry::Repair(repair) =
            self.reparent_geometry(state, scope, watch, target.as_ref(), &outcome)
        {
          Self::accept(&mut self.monitor, state, &mut kept, repair, now);
        }
      }
      item.planned = kept;
    }
    if fence {
      batch
        .trailing
        .retain(|planned| !self.fenced(state, planned));
    }
  }

  /// Takes one record the fence kept: handed to the Monitor AT ONCE under a
  /// feed-at-classify profile, buffered into `kept` for
  /// [`settle`](Self::settle) otherwise.
  ///
  /// The two disciplines differ only in WHEN a record leaves, never in which
  /// records leave or in what order: the fence walks one read in stream order and
  /// `settle` replays the buffer in that same order, so the sequence the Monitor
  /// observes is identical. `trailing` is not accepted here — it is judged and fed
  /// after every item on both disciplines, which under feed-at-classify means it
  /// is simply left for `settle` to feed once the items are already gone.
  ///
  /// Returns what the hand-off did to the watch tree's shape. A BUFFERED record has
  /// not reached the Monitor, so it truthfully reports [`RecordOutcome::Nothing`]:
  /// nothing has been done to the tree yet. That cannot mislead the one caller that
  /// reads the value, because [`runs_rename_geometry`] implies
  /// [`feeds_at_classify`] (INV-FEED's first leg, asserted at compile time) — a
  /// profile whose geometry consumes the outcome never takes the buffering branch
  /// at all.
  fn accept(
    monitor: &mut Monitor,
    state: &ScopeState,
    kept: &mut Vec<Planned>,
    planned: Planned,
    now: Instant,
  ) -> RecordOutcome {
    if !feeds_at_classify(state.profile) {
      kept.push(planned);
      return RecordOutcome::Nothing;
    }
    Self::feed(monitor, planned, now)
  }

  /// Whether an exclusion lies AT OR UNDER `path` — the fence's own containment
  /// predicate run the other way round, with `path` as the exclusion set and each
  /// exclusion as the candidate.
  ///
  /// [`excluded`](Self::excluded) answers "is this path inside an exclusion", which
  /// is what suppression needs. Re-parenting needs the mirror question — "does this
  /// subtree CONTAIN an exclusion" — because that is what decides whether rewriting
  /// the subtree's path changes which of its descendants are reported.
  ///
  /// Deliberately expressed through [`crate::driver::excluded`] rather than a fresh
  /// prefix walk: that is the ONE matching rule the cold fence, the live fence, the
  /// sync-cookie birth refusal and the fanotify backend all share, and a second rule
  /// here could drift out of step with it and re-open the hole from the other side.
  fn exclusion_under(&self, path: &Path) -> bool {
    let containing = [path.to_path_buf()];
    self
      .exclusions
      .iter()
      .any(|exclusion| crate::driver::excluded(&containing, exclusion))
  }

  /// The destination slot a rename's repair would be lowered against, taken from a
  /// record BEFORE it is fed.
  ///
  /// The two inputs of the post-feed decision sit on opposite sides of the hand-off:
  /// the feed consumes the record, and the outcome that decides whether a repair is
  /// owed at all does not exist until the feed has happened. So the record's own
  /// half is captured here, and joined with the Monitor's report afterwards.
  ///
  /// Gated on the KIND alone. Only a `MovedTo` can report a reparent, and gating any
  /// tighter — on a directory flag the destination half is free to omit — would let
  /// a real reparent go unrepaired because its record under-described itself.
  fn landing(planned: &Planned) -> Option<(WatchId, Option<Location>)> {
    match planned {
      Planned::Rec(rec) if matches!(rec.kind(), RecordKind::MovedTo) => {
        Some((rec.watch(), rec.target().cloned()))
      }
      _ => None,
    }
  }

  /// Re-enumerates a moved directory subtree whose RENAME changed the exclusion
  /// geometry over it — the one thing the record-by-record fence structurally
  /// cannot see.
  ///
  /// [`fenced`](Self::fenced) judges each record by its own anchored endpoint, so a
  /// rename whose two endpoints are BOTH reported is preserved whole, as it must be.
  /// But the Monitor answers such a rename by re-parenting the already-known watch
  /// subtree in place — an O(1) carry-over that rewrites the subtree's path while
  /// carrying every descendant across untouched. Exclusions match on path prefixes,
  /// so which descendants are reported is a function of that very path, and a move
  /// whose endpoints sit on different sides of an exclusion leaves the coverage
  /// describing a tree the fence no longer agrees with — in BOTH directions, and
  /// permanently, because nothing else ever re-walks it:
  ///
  /// - **out of an exclusion.** With root `/r` and `/r/a/cache` excluded, the cold
  ///   walk of `/r/a` skipped `cache` and armed nothing there. Renaming `/r/a` to
  ///   `/r/b` makes `cache` reportable, yet the bare re-parent adds nothing: no watch
  ///   exists at `/r/b/cache`, no record can be attributed to it, and a newly visible
  ///   subtree is blind forever. This is silent, permanent loss.
  /// - **into an exclusion.** With `/r/a/cache` excluded, `/r/b/cache` IS covered.
  ///   Renaming `/r/b` to `/r/a` leaves those watches installed, so the scope keeps
  ///   spending kernel watches — and delivering — on ground the caller excluded to
  ///   shed exactly that cost.
  ///
  /// The rule is [`exclusion_under`](Self::exclusion_under) at EITHER endpoint, which
  /// is how the fanotify admission map and the USN journal decide the same question:
  /// one predicate, asked of both ends, never a second matching rule. Deliberately
  /// CONSERVATIVE in the same way — an exclusion sitting under both endpoints at the
  /// same relative offset leaves the geometry genuinely unchanged yet answers `true`,
  /// costing one re-enumeration on a path this rare.
  ///
  /// Where it DIFFERS is the repair, because inotify's coverage is not a private
  /// admission map it can forget and relearn locally: it is the Monitor's node tree
  /// plus real kernel watches. So the repair is stated as the Monitor's own located
  /// loss signal at the destination, queued immediately AFTER the pairing record so
  /// the re-parent has already landed. The Monitor answers that signal by emitting a
  /// covering `Rescan` there and re-arming from the destination's parent — a complete
  /// re-arm read prunes vanished names, arms new ones and cascades into survivors, so
  /// it descends into the just-reparented directory and reconciles it against a fresh
  /// listing. That listing is produced by [`on_enumerated`](Self::on_enumerated),
  /// which applies the SAME exclusion rule: a newly reportable child is listed and
  /// armed, a newly excluded one is absent and pruned. Both directions, one existing
  /// mechanism, no parallel bookkeeping.
  ///
  /// Runs only where the common fence runs AND coverage is per-directory. A backend
  /// that enforces exclusions itself already handles its own geometry, and a
  /// kernel-recursive one has no per-directory watches to re-arm — its single stream
  /// covers the destination the moment the re-parent lands — so escalating there
  /// would be a bare `Rescan` repairing nothing.
  ///
  /// Loss is never silent: when the escalation cannot be placed (the destination
  /// anchor resolves no path) it degrades to the scope-wide cover, whose recovery
  /// re-arms everything. That cover replaces a REPAIR, never an ordering — it
  /// re-reads what comes next and cannot unsay a record the same read already
  /// retained under the pre-move addressing.
  ///
  /// Called per RECORD from the fence's own stream-ordered walk rather than as a
  /// second pass, and the ORDER of the repair is the reason: it must be queued
  /// directly behind the record that provoked it, so the Monitor answers it with
  /// the re-parent already landed and the located `Rescan` names the destination.
  ///
  /// # What this pass is NOT
  ///
  /// It does not re-address anything. Watch paths are DERIVED from the Monitor's
  /// own tree ([`path_of`](Self::path_of)), so the O(1) re-parent that carried the
  /// subtree across has already moved every path under it — for every scope,
  /// whether or not exclusions are configured, and with no walk. This pass owes
  /// only the question derivation cannot answer: a moved subtree's watches are
  /// correctly NAMED at their new home, but which directories under that home
  /// should be watched AT ALL is a function of the exclusion set, and that
  /// membership did not move with them. A subtree carried out of an exclusion has
  /// correct names for the watches it holds and no watches at all for the children
  /// the cold walk skipped; a subtree carried into one keeps watches on ground the
  /// caller excluded. Only a re-enumeration settles membership, and only a scope
  /// with exclusions can have any membership to settle — which is why the pass is
  /// gated on the fence, while addressing is not gated on anything.
  ///
  /// # It acts on the reparent that HAPPENED
  ///
  /// The trigger is the Monitor's own [`RecordOutcome`] for the record just fed,
  /// not a source this pass parked and predicted a pairing for. A prediction and a
  /// performance are two implementations of one rule, and two implementations skew:
  /// the Monitor pairs only inside the window, only over a held subtree, and only
  /// when the O(1) reparent it then attempts actually succeeds. Every case that
  /// fails one of those tests reports [`RecordOutcome::Nothing`] and is answered
  /// here by repairing nothing — which is correct by construction, because a
  /// subtree nothing relocated has crossed no exclusion boundary.
  ///
  /// # Composing the source
  ///
  /// [`RecordOutcome::Reparented`] reports a `(from_parent, from)` SLOT rather than
  /// an absolute path, and `from` is the SCOPE-relative location the Monitor
  /// reconstructed from its live tree at report time — `from_parent`'s own location
  /// already joined with the half's name. So the absolute source is the scope
  /// ROOT's path joined with it, and `from_parent` names the anchor the
  /// reconstruction ran against rather than a second anchor to join onto (joining
  /// against `from_parent`'s own path would count that parent's location twice).
  ///
  /// The root is also the one anchor a post-feed composition cannot get wrong: a
  /// watched root never moves inside its own tree, so it is the fixed point every
  /// other path is derived from. The source is then the Monitor's live description
  /// of where the subtree was, plus that fixed point — which is exactly what an
  /// absolute path pinned at `MovedFrom` could not be, since an ancestor renamed
  /// mid-window moves the ground under it and leaves the pin naming nothing.
  ///
  /// Composed AFTER the record has been fed, which is safe for the same reason: the
  /// reparent this outcome reports rewrote a child edge inside the tree, and the
  /// root path it is joined onto is not something any reparent can touch.
  fn reparent_geometry(
    &self,
    state: &ScopeState,
    scope: ScopeId,
    watch: WatchId,
    target: Option<&Location>,
    outcome: &RecordOutcome,
  ) -> Geometry {
    let Some((_, from)) = outcome.reparented() else {
      return Geometry::Nothing;
    };
    let from = self.anchored_path(state, state.watch, Some(from));
    let to = self.anchored_path(state, watch, target);
    // One predicate, asked of both ends. An endpoint that resolved no
    // path answers "changed" for the same reason the fanotify map does
    // for a moved node whose ancestry no longer reaches the root: with
    // no path to compare, the safe direction is the one that costs a
    // re-enumeration, not the one that costs coverage.
    let changed = |end: Option<&Path>| end.is_none_or(|path| self.exclusion_under(path));
    if !changed(from.as_deref()) && !changed(to.as_deref()) {
      return Geometry::Nothing;
    }
    // The located repair needs a destination to name. Without one the
    // scope-wide cover is the honest degrade — never a quiet drop, and
    // never a `Rescan` naming a path that could not be resolved.
    Geometry::Repair(match (to, target) {
      (Some(_), Some(target)) => Planned::Over(located(watch, Some(target.clone()))),
      _ => Planned::Over(Scope::Root(scope)),
    })
  }

  /// Whether one planned Monitor input addresses only excluded ground.
  fn fenced(&self, state: &ScopeState, planned: &Planned) -> bool {
    match planned {
      Planned::Rec(rec) => {
        !rec.kind().is_self_event()
          && self
            .anchored_path(state, rec.watch(), rec.target())
            .is_some_and(|path| self.excluded(&path))
      }
      Planned::Over(Scope::Subtree(sub)) => {
        let scope_wide = sub.watch() == state.watch && sub.descent().is_empty();
        !scope_wide
          && self
            .anchored_path(state, sub.watch(), Some(sub.descent()))
            .is_some_and(|path| self.excluded(&path))
      }
      Planned::Over(_) => false,
    }
  }

  fn settle_if_ready(
    monitor: &mut Monitor,
    state: &mut ScopeState,
    scope: ScopeId,
    batch: PendingBatch,
    now: Instant,
  ) -> bool {
    if batch.awaiting == 0 {
      Self::settle(monitor, state, scope, batch, now);
      true
    } else {
      state.park.active = Some(batch);
      false
    }
  }

  /// Settles a fully-resolved batch: grants evidenced vanished-half cookies,
  /// feeds the Monitor in item order, then applies the deferred unmount
  /// trust-removals (the monotone rule's late edge).
  ///
  /// A feed-at-classify profile ([`feeds_at_classify`]) arrives here with its
  /// items already emptied by the fence, so what it settles is `trailing` alone —
  /// which is where `trailing` belongs on both disciplines, after every item. The
  /// other two duties are the reason the split is safe to make per profile: a
  /// cookie grant needs a `cookie_candidate` and `evidenced` partners, and a
  /// deferred unmount needs `deferred_unmounts`, and all three are filled only by
  /// the FSEvents path — which does not feed at classify time.
  fn settle(
    monitor: &mut Monitor,
    state: &mut ScopeState,
    scope: ScopeId,
    mut batch: PendingBatch,
    now: Instant,
  ) {
    Self::grant_evidenced_cookies(state, scope, &mut batch);
    let deferred = std::mem::take(&mut batch.deferred_unmounts);
    for item in batch.items {
      for planned in item.planned {
        Self::feed(monitor, planned, now);
      }
    }
    for planned in batch.trailing {
      Self::feed(monitor, planned, now);
    }
    for path in deferred {
      state.mounts.retain(|m| m != &path);
    }
  }

  /// Grants a vanished rename half its pairing cookie at settlement, under
  /// ALL the proofs the fabrication class demands: a same-batch partner's
  /// probe bound the fileID to the root device AND that partner's event word
  /// carried the same fileID (the temporal bind — see
  /// [`PendingBatch::evidenced`]), and the vanished path lies under no
  /// foreign prefix of the still-monotone, still-authoritative table (a
  /// collision from a just-mounted or just-unmounted volume fails here).
  /// Cross-batch vanished sources never cookie — the Monitor degrades them
  /// to a removal, the documented pairing cost.
  ///
  /// The residual is inode reuse INSIDE one batch: FSEvents supplies no
  /// rename token, so an object deleted and an unrelated object recycling
  /// its inode within the same batch can satisfy every proof above and
  /// mis-pair. That cannot be distinguished from a real rename event-side,
  /// so every granted pair also queues one covering located rescan at the
  /// pair's deepest common ancestor — a mis-pair is then recoverable, never
  /// silent.
  fn grant_evidenced_cookies(state: &ScopeState, scope: ScopeId, batch: &mut PendingBatch) {
    let evidenced = std::mem::take(&mut batch.evidenced);
    let mut covers: Vec<Planned> = Vec::new();
    for item in &mut batch.items {
      let Some((fid, path)) = item.cookie_candidate.take() else {
        continue;
      };
      let Some(partners) = evidenced.get(&fid) else {
        continue;
      };
      // The unambiguous-partner rule: a grant demands EXACTLY ONE evidenced
      // partner. With two or more, the Monitor would pair the granted cookie
      // with whichever destination feeds first while a one-partner cover
      // could point at another — the recovery the cover exists to guarantee
      // would miss the real destination. Ambiguity is a degrade, not an
      // error: no cookie (the vanished half resolves as its removal, the
      // present halves as creations) under one cover spanning the source and
      // every evidenced partner.
      if partners.len() != 1 {
        covers.push(Self::covering_rescan(
          state,
          scope,
          core::iter::once(&path).chain(partners.iter()),
        ));
        continue;
      }
      if !device_trusted(state, &path, None) {
        continue;
      }
      let partner = &partners[0];
      let mut granted = false;
      for planned in &mut item.planned {
        if let Planned::Rec(rec) = planned
          && rec.kind().is_moved_from()
          && rec.cookie().is_none()
        {
          *rec = rec.clone().with_cookie(MoveCookie::new(fid));
          granted = true;
        }
      }
      if granted {
        covers.push(Self::covering_rescan(
          state,
          scope,
          [&path, partner].into_iter(),
        ));
      }
    }
    batch.trailing.extend(covers);
  }

  /// Hands one planned input to the Monitor and reports what it did to the watch
  /// tree's SHAPE.
  ///
  /// The [`RecordOutcome`] is the Monitor's own account of the reparent it just
  /// performed — never a prediction re-derived from the same record by a second
  /// implementation of the same rule. That is what the geometry pass decides on
  /// ([`reparent_geometry`](Self::reparent_geometry)).
  ///
  /// An overflow instruction moves no subtree, so it reports nothing.
  fn feed(monitor: &mut Monitor, planned: Planned, now: Instant) -> RecordOutcome {
    match planned {
      Planned::Rec(rec) => monitor.on_os_record(rec, now),
      Planned::Over(scope) => {
        monitor.on_overflow(scope, now);
        RecordOutcome::Nothing
      }
    }
  }

  /// Compiles and feeds queued batches until one parks or the queue drains.
  fn pump_queued(&mut self, scope: ScopeId, now: Instant) {
    loop {
      let Some(mut state) = self.scopes.remove(&scope) else {
        return;
      };
      let Some(BatchPayload { events, permit, .. }) = state.park.queued.pop_front() else {
        self.scopes.insert(scope, state);
        return;
      };
      let mut batch = self.compile(&mut state, scope, events, now);
      batch.permit = Some(permit);
      let fed = Self::settle_if_ready(&mut self.monitor, &mut state, scope, batch, now);
      self.scopes.insert(scope, state);
      if !fed {
        return;
      }
    }
  }

  /// One rescan covering an ambiguous same-fileID rename group: the deepest
  /// common ancestor of the members' parents, clamped to the whole root when
  /// any member falls outside it.
  fn covering_rescan<P: AsRef<Path>>(
    state: &ScopeState,
    scope: ScopeId,
    paths: impl Iterator<Item = P>,
  ) -> Planned {
    let mut prefix: Option<Vec<Segment>> = None;
    for path in paths {
      let parent = match lower(state, path.as_ref()) {
        Lowered::Target(location) => {
          let mut segments = location.segments().to_vec();
          segments.pop();
          segments
        }
        Lowered::Root => Vec::new(),
        Lowered::Outside => return Planned::Over(Scope::Root(scope)),
      };
      prefix = Some(match prefix {
        None => parent,
        Some(acc) => acc
          .iter()
          .zip(parent.iter())
          .take_while(|(a, b)| a == b)
          .map(|(a, _)| a.clone())
          .collect(),
      });
    }
    let descent = prefix.unwrap_or_default();
    let target = if descent.is_empty() {
      None
    } else {
      Some(Location::from_segments(descent))
    };
    Planned::Over(located(state.watch, target))
  }

  /// Resolves one probe's plan.
  fn resolve(state: &mut ScopeState, purpose: ProbePurpose, outcome: ProbeOutcome) -> Resolved {
    match purpose {
      // A slot stat grounds no batch item; `on_probe_result` answers it before
      // this table is ever reached.
      ProbePurpose::SlotKind { .. } => {
        debug_assert!(false, "a slot stat is answered ahead of the batch table");
        Resolved::plain(usize::MAX, Vec::new())
      }
      ProbePurpose::RootAlive { item } => {
        let kind = match outcome {
          ProbeOutcome::Missing => RecordKind::DeleteSelf,
          // Present elsewhere or unknowable both end the scope's coverage:
          // the registered path no longer names the watched object.
          ProbeOutcome::Present { .. } | ProbeOutcome::Failed => RecordKind::MoveSelf,
        };
        Resolved::plain(item, vec![Planned::Rec(OsRecord::new(state.watch, kind))])
      }
      ProbePurpose::Ambiguous {
        item,
        flags,
        target,
        path,
      } => {
        // The word's content and metadata bits are facts existence cannot judge:
        // an lstat says what is THERE, never whether the bytes or the mode moved
        // while it was. They therefore ride through both arms below, and only the
        // STRUCTURAL half is grounded — which is exactly what the probe is for.
        let content = Evidence::new()
          .maybe_modified(flags.item_modified())
          .maybe_attrib(
            flags.item_inode_meta_mod()
              || flags.item_change_owner()
              || flags.item_xattr_mod()
              || flags.item_finder_info_mod(),
          );
        let planned = match outcome {
          ProbeOutcome::Missing => {
            let proven = content.with_removed();
            match record_proved(state, proven, target.clone(), dir_hint(flags), None) {
              Some(rec) => vec![Planned::Rec(rec)],
              None => vec![Planned::Over(located(state.watch, target))],
            }
          }
          ProbeOutcome::Present { kind, file_id, dev } => {
            learn_device(state, &path, dev);
            let proven = content.maybe_created(flags.item_created());
            let node = mint(state, &path, file_id, Some(dev));
            match record_proved(state, proven, target.clone(), Some(kind.is_dir()), node) {
              Some(rec) => vec![Planned::Rec(rec)],
              // The word's ONLY grounded verb was a removal existence just
              // disproved: nothing is left to name, so the located rescan grounds
              // whatever occupies the path now.
              None => vec![Planned::Over(located(state.watch, target))],
            }
          }
          ProbeOutcome::Failed => vec![Planned::Over(located(state.watch, target))],
        };
        Resolved::plain(item, planned)
      }
      ProbePurpose::Rename {
        item,
        file_id,
        target,
        path,
        allow_cookie,
        content_changed,
      } => {
        match outcome {
          // Gone: the source half of a move out of (or within) the tree. A
          // vanished path has NO contemporaneous device evidence — the mount
          // table cannot prove which device it WAS on — so no cookie is
          // minted here. Settlement grants one iff a same-batch partner's
          // probe binds this fileID to the root device; otherwise the
          // Monitor degrades the half to an immediate removal (cross-batch
          // vanished sources never pair — the documented cost).
          ProbeOutcome::Missing => {
            let candidate = allow_cookie
              .then_some(file_id)
              .flatten()
              .map(|fid| (fid, path.clone()));
            let rec = record_with(state, RecordKind::MovedFrom, target, None, None);
            Resolved {
              item,
              planned: vec![Planned::Rec(rec)],
              evidences: None,
              candidate,
            }
          }
          // Exists: the destination half. An appeared DIRECTORY delivers no
          // events for the children it arrived with, so the record is paired
          // with a located rescan — unless the Monitor pairs it with a held
          // source, where the extra rescan is merely redundant, never wrong.
          ProbeOutcome::Present {
            kind,
            file_id: probed,
            dev,
          } => {
            learn_device(state, &path, dev);
            // Identity binding: the cookie and its published evidence derive
            // from the PROBED inode exclusively — the probe is what carries
            // the device proof. An event id that disagrees with the probe
            // means the path was replaced between the callback and the
            // lstat: the batch's view of this path is stale, so no cookie
            // may bridge the two objects, and the located rescan below
            // re-grounds whatever occupies the path now.
            let stale = matches!((file_id, probed), (Some(event), Some(live)) if event != live);
            let cookie = (allow_cookie && !stale)
              .then(|| cookie_for(state, probed, dev))
              .flatten();
            let node = mint(state, &path, probed, Some(dev));
            let mut rec = record_with(
              state,
              RecordKind::MovedTo,
              target.clone(),
              Some(kind.is_dir()),
              node,
            );
            if let Some(cookie) = cookie {
              rec = rec.with_cookie(cookie);
            }
            let mut planned = vec![Planned::Rec(rec)];
            if content_changed {
              // The word coalesced a content/attrib change with the rename;
              // the survivor owes that truth alongside the move (existence
              // subsumes any coalesced create/remove bits, but a content
              // change is invisible to existence).
              let rec = record_with(
                state,
                RecordKind::Modified,
                target.clone(),
                Some(kind.is_dir()),
                node,
              );
              planned.push(Planned::Rec(rec));
            }
            if kind.is_dir() || stale {
              planned.push(Planned::Over(located(state.watch, target)));
            }
            Resolved {
              item,
              planned,
              // Evidence needs the TEMPORAL BIND on top of the cookie's own
              // rules: the event word must have carried the same fileID the
              // probe observed. A probe-only fileID proves what occupies the
              // path now — not which object the batch's events were about —
              // so it may cookie this present half but never vouch for a
              // vanished partner (that pair degrades to Removed + Created).
              evidences: (cookie.is_some() && file_id == probed)
                .then(|| probed.map(|fid| (fid, path.clone())))
                .flatten(),
              candidate: None,
            }
          }
          ProbeOutcome::Failed => {
            Resolved::plain(item, vec![Planned::Over(located(state.watch, target))])
          }
        }
      }
    }
  }

  /// Drops every queued [`Effect::Emit`] belonging to `scope`. Called exactly
  /// when the scope's queued deliveries become dominated (lag entry): the
  /// non-emit effects (spawns, teardowns, probes) are obligations, never
  /// dominated, and always survive.
  fn purge_scope_emits(effects: &mut VecDeque<Effect>, scope: ScopeId) {
    effects.retain(|effect| !matches!(effect, Effect::Emit { scope: s, .. } if *s == scope));
  }

  /// Removes and returns the LAST queued `Rescan` emit for `scope` (with the
  /// root it was queued to deliver under), if any — the terminal covering
  /// change a teardown keeps retryable.
  fn extract_last_rescan(
    effects: &mut VecDeque<Effect>,
    scope: ScopeId,
  ) -> Option<(Arc<PathBuf>, Change)> {
    let idx = effects.iter().rposition(|effect| {
      matches!(effect, Effect::Emit { scope: s, change, .. } if *s == scope && change.kind().is_rescan())
    })?;
    match effects.remove(idx) {
      Some(Effect::Emit { root, change, .. }) => Some((root, change)),
      _ => None,
    }
  }

  /// The covering merge of two same-scope `Rescan`s (INV-PARK): the location
  /// becomes their longest common prefix — the join of the two subtree
  /// coverages, since a shorter location covers MORE — and the id + epoch
  /// become the newer change's, so the merged instruction still licenses
  /// every drop either input licensed while its epoch dominates everything
  /// dropped. Never narrows either input. Callers pass the later-minted
  /// change as `newer`: route order is mint order, and every routed `Rescan`
  /// carries a freshly bumped epoch, so `newer`'s epoch is the greater one.
  fn covering_merge(prev: &Change, newer: Change) -> Change {
    debug_assert!(
      prev.kind().is_rescan() && newer.kind().is_rescan(),
      "only Rescans carry a drop license to merge"
    );
    let shared = prev
      .location()
      .segments()
      .iter()
      .zip(newer.location().segments())
      .take_while(|(a, b)| a == b)
      .count();
    if shared == newer.location().len() {
      // Newer's location is a prefix of prev's (or equal): it already covers
      // everything prev promised.
      return newer;
    }
    let location = Location::from_segments(newer.location().segments()[..shared].iter().cloned());
    Change::new(
      newer.id(),
      newer.scope(),
      location,
      ChangeKind::Rescan,
      newer.epoch(),
    )
  }

  fn mint_probe(&mut self, scope: ScopeId, purpose: ProbePurpose) -> ProbeId {
    self.probe_seq += 1;
    let probe = ProbeId(self.probe_seq);
    self.probes.insert(probe, ProbeCtx { scope, purpose });
    probe
  }

  /// Clamps an overflow path to the scope: strictly-under-root rescans the
  /// located subtree; the root, an ancestor ("/" on drops), or anything
  /// unrepresentable rescans the whole root.
  fn clamp(state: &ScopeState, scope: ScopeId, path: &Path) -> Scope {
    match lower(state, path) {
      Lowered::Target(location) => {
        Scope::Subtree(SubtreeScope::new(state.watch).with_descent(location))
      }
      Lowered::Root | Lowered::Outside => Scope::Root(scope),
    }
  }

  /// Drains the Monitor to a fixpoint: actions become effects, changes route
  /// through the per-scope lag protocol. Events drain first — a root-death
  /// `Rescan` must route while its scope's lag state still exists.
  fn drain_monitor(&mut self) {
    while let Some(change) = self.monitor.poll_event() {
      self.route_event(change);
    }
    while let Some(action) = self.monitor.poll_action() {
      match action {
        tributary_proto::Action::Watch(cmd) => {
          if let Some(scope) = cmd.target().root() {
            // The bootstrap arm is answered out of band — by the spawn itself on a
            // kernel-recursive backend, by the root's own `AddWatch` on a descending
            // one — so its attempt is captured HERE, where the action is consumed,
            // and echoed at whichever of those answers it.
            let root = match self.scopes.get_mut(&scope) {
              Some(state) => {
                state.root_attempt = Some(cmd.attempt());
                state.requested.clone()
              }
              None => PathBuf::new(),
            };
            self.effects.push_back(Effect::SpawnStream { scope, root });
          } else if let Some(scope) = cmd.target().rearm_root() {
            // A root binding re-proof: re-add the EXISTING root's kernel watch
            // on the LIVE source — the self-parented root-arm shape the spawn
            // path uses, never a stream (re)spawn. `expected` is the barrier
            // identity, so a different-object rebind at the same path fails
            // the arm's open-verify as `Gone` into the root-invalidation
            // funnel — the death the identity-sampling liveness gate cannot
            // see.
            let Some(state) = self.scopes.get(&scope) else {
              debug_assert!(false, "a root re-add names a live scope");
              continue;
            };
            debug_assert_eq!(
              state.watch,
              cmd.id(),
              "a root re-add names the current root"
            );
            let Some(root) = state.root.clone() else {
              debug_assert!(false, "a root re-add follows a committed spawn");
              continue;
            };
            let name = root
              .file_name()
              .and_then(|name| name.to_str())
              .unwrap_or("/");
            let expected = state.identity.and_then(|identity| {
              u64::try_from(identity.ino())
                .ok()
                .and_then(NonZeroU64::new)
                .map(|ino| ExpectedObject {
                  dev: identity.dev(),
                  ino,
                })
            });
            self.effects.push_back(Effect::AddWatch {
              scope,
              watch: cmd.id(),
              attempt: cmd.attempt(),
              parent: cmd.id(),
              name: Segment::new(name),
              path: root,
              expected,
            });
          } else if let Some(child) = cmd.target().as_child() {
            let parent = child.parent();
            let Some(&scope) = self.watch_scopes.get(&parent) else {
              debug_assert!(false, "a child watch descends from a known parent");
              continue;
            };
            // Addressed off the parent's CURRENT placement, so a child armed
            // under a subtree an earlier record in this same read relocated
            // opens at the path the delivery beside it names.
            let Some(parent_path) = self.scoped_path(scope, parent) else {
              debug_assert!(false, "a child watch descends from a placeable parent");
              continue;
            };
            let name = child.name().clone();
            let path = Arc::new(parent_path.join(name.as_str()));
            self.watch_scopes.insert(cmd.id(), scope);
            // The object the enumerate discovered, so the arm can confirm the
            // open lands on it: the Monitor node carries the entry's identity
            // (its inode), and single-device descent means a descended child is
            // always on the scope's root device — a foreign-device entry mints no
            // identity and is never descended. An identity-less node leaves the
            // arm unverified, exactly as the Monitor already reconciles.
            let expected = self.monitor.node_identity(cmd.id()).and_then(|id| {
              self
                .scopes
                .get(&scope)
                .and_then(|state| state.root_dev)
                .map(|dev| ExpectedObject { dev, ino: id.get() })
            });
            self.effects.push_back(Effect::AddWatch {
              scope,
              watch: cmd.id(),
              attempt: cmd.attempt(),
              parent,
              name,
              path,
              expected,
            });
          }
        }
        tributary_proto::Action::Unwatch(watch) => {
          let is_root = self
            .watch_scopes
            .get(&watch)
            .and_then(|scope| self.scopes.get(scope))
            .is_some_and(|state| state.watch == watch);
          if !is_root {
            // A per-directory child watch the Monitor dropped: disarm it and
            // forget which scope owned it. Fire-and-forget — the unwatch carries
            // no result contract, and an unreached wd dies with the stream.
            let scope = self.watch_scopes.remove(&watch);
            if let Some(scope) = scope {
              self.effects.push_back(Effect::RemoveWatch { scope, watch });
            }
            continue;
          }
          if let Some(scope) = self.watch_scopes.remove(&watch) {
            // The scope's terminal `Rescan` — parked by lag, or still queued
            // as a plain effect — is the only signal covering whatever the
            // dead scope dropped, and it must survive refusals: a queued
            // emit is one-shot (a refusal finds no scope state to re-park
            // it), so the newest terminal `Rescan` moves into the dying set
            // and retries until the consumer accepts it. Ordinary queued
            // emits stay best-effort — each is dominated by that `Rescan`.
            //
            // A NEVER-LIVE scope promotes nothing: its caller got Err, not a
            // handle, so there is no consumer view to cover (the route_event
            // fence already kept its changes out of the effect queue). The fact
            // is `publicly_live` — a descending scope whose root arm failed
            // populated `root` at spawn yet is not publicly live, so it must not
            // promote a terminal `Rescan` for a registration no one owns.
            let removed = self.scopes.remove(&scope);
            let live = removed.as_ref().is_some_and(|state| state.publicly_live);
            let parked = removed.and_then(|state| {
              let root = state.delivery_root();
              match state.lag {
                LagState::Lagged { parked, .. } => parked.map(|change| (root, change)),
                LagState::Normal => None,
              }
            });
            let queued = Self::extract_last_rescan(&mut self.effects, scope);
            debug_assert!(
              live || (parked.is_none() && queued.is_none()),
              "a never-live scope emits nothing to promote"
            );
            // Both present is structurally dead today — a Lagged scope
            // queues no emits and a Normal one parks nothing — but if both
            // ever exist the terminal promise must not narrow to whichever
            // carries the newer epoch: the coverages merge (INV-PARK) and
            // the promotion rides the newer mint's root.
            let terminal = match (parked, queued) {
              (Some(a), Some(b)) => {
                let ((_, older), (root, newer)) = if b.1.epoch() > a.1.epoch() {
                  (a, b)
                } else {
                  (b, a)
                };
                Some((root, Self::covering_merge(&older, newer)))
              }
              (a, b) => a.or(b),
            };
            if live && let Some((root, change)) = terminal {
              self.dying.insert(
                scope,
                DyingDelivery {
                  change,
                  attempt: Attempt::Idle,
                  root,
                },
              );
            }
            // Scope teardown mid-fence (unwatch, root death — every teardown funnels
            // through this arm): the reconcile's work dies with the scope, so every
            // pending fence resolves `Dead` — the terminal `Rescan` above covers the
            // caller — folded into the next settlement poll so the driver keeps its
            // one choke point. The entry is removed with the scope: no fence state
            // outlives it.
            //
            // `Dead` rather than `Degraded` because this is the one place the death
            // is known synchronously, while the `TeardownStream` that clears the
            // driver's liveness maps is merely QUEUED. A consumer polling this
            // settlement therefore cannot re-derive the fact from those maps — they
            // still read live — so it has to travel in the verdict.
            if let Some(entry) = self.cover_fences.remove(&scope) {
              for pending in entry.pending {
                self.settled_covers.push((pending.fence, CoverSettle::Dead));
              }
            }
            self.probes.retain(|_, ctx| ctx.scope != scope);
            let dead: Vec<WatchId> = self
              .watch_scopes
              .iter()
              .filter(|(_, s)| **s == scope)
              .map(|(w, _)| *w)
              .collect();
            for watch in dead {
              self.watch_scopes.remove(&watch);
            }
            self.enum_reqs.retain(|_, (s, _)| *s != scope);
            self.effects.push_back(Effect::TeardownStream { scope });
          }
        }
        tributary_proto::Action::Enumerate(cmd) => {
          let watch = cmd.dir();
          let Some(&scope) = self.watch_scopes.get(&watch) else {
            debug_assert!(false, "an enumerate reads a known directory");
            continue;
          };
          let Some(path) = self.scoped_path(scope, watch) else {
            debug_assert!(false, "an enumerate reads a placeable directory");
            continue;
          };
          let path = Arc::new(path);
          self.enum_reqs.insert(cmd.req(), (scope, Arc::clone(&path)));
          self.effects.push_back(Effect::Enumerate {
            req: cmd.req(),
            watch,
            path,
          });
        }
        tributary_proto::Action::Stat(cmd) => {
          // The Monitor asks only for a slot a listing left unclassifiable. This
          // driver's own listing lowers every `FileType` it can name and falls back
          // to `Other`, so the request is unreachable through it — but a stat is a
          // protocol obligation, and dropping one would leave the Monitor's slot
          // dark forever rather than merely until the answer lands. It is served on
          // the blocking pool by the same `lstat` the FSEvents grounding uses.
          let Some(child) = cmd.of().as_child() else {
            debug_assert!(false, "the Monitor stats a named child slot");
            continue;
          };
          let Some(&scope) = self.watch_scopes.get(&child.parent()) else {
            debug_assert!(false, "a stat names a slot under a known directory");
            continue;
          };
          let Some(parent_path) = self.scoped_path(scope, child.parent()) else {
            debug_assert!(false, "a stat names a slot under a placeable directory");
            continue;
          };
          let path = parent_path.join(child.name().as_str());
          let probe = self.mint_probe(scope, ProbePurpose::SlotKind { req: cmd.req() });
          self.effects.push_back(Effect::Probe { probe, path });
        }
        other => {
          debug_assert!(false, "the Monitor requests no other work: {other:?}");
        }
      }
    }
  }

  fn route_event(&mut self, change: Change) {
    let scope = change.scope();
    let Some(state) = self.scopes.get_mut(&scope) else {
      // A change for a scope torn down in the same drain still delivers when
      // its root is still nameable (the dying entry keeps it) — over-delivery
      // is the safe direction. Without a dying entry the dead scope owes no
      // coverage, and a straggler with no assignable root is dropped rather
      // than misattributed.
      if let Some(entry) = self.dying.get(&scope) {
        self.effects.push_back(Effect::Emit {
          scope,
          root: Arc::clone(&entry.root),
          change,
        });
      }
      return;
    };
    // NEVER-LIVE FENCE: a scope whose public delivery never began owes the
    // consumer nothing — its watch() resolved Err (a spawn failure, a final-root
    // rejection, or a descending ROOT-ARM failure) and the caller never received
    // the handle these changes would carry. The Monitor's own failure Rescan for
    // such a root is internal bookkeeping, not public coverage; delivering it
    // would tell a consumer to rescan a root that was never watched. The fact is
    // `publicly_live`, NOT `root.is_some()`: a descending scope populates `root`
    // at spawn but is not publicly live until its root arm succeeds, so a failed
    // root arm (whose `Err` the deferred grant already delivered) is fenced here.
    if !state.publicly_live {
      return;
    }
    // THE LOSSY WINDOW: a public scope `Rescan` signals the scope may have lost
    // coverage work (a failed grow arm, an unreadable re-arm read, an overflow) —
    // whether or not a reconcile is currently unobserved. For a descending scope:
    //
    // - The `Rescan` ENSURES the scope's loss-memory entry (creating it when none
    //   exists) and marks it: every pending fence degrades, and a fence opened later
    //   — before the next settle observation clears the memory — inherits the loss
    //   (see [`CoverFence`]). Without the entry creation an out-of-window loss (after
    //   a clean settle, before the next reconcile) would be dropped with the window.
    //   The entry-creating mark cannot leak: the next settle observation removes a
    //   pending-empty entry exactly like any other.
    // - A NARROWED claim (`applied_cover` is `Some`) degrades IMMEDIATELY to the
    //   empty cover — the standing `Rescan` means the claim may span a hole, and the
    //   empty cover claims nothing below the root. The settle floor folds with it
    //   (the meet with the empty cover IS the empty cover), so an observation-time
    //   rewind cannot resurrect the stale claim. The next `on_set_cover` then
    //   computes its broadening delta against the degraded claim — a full re-arm of
    //   the requested retained set, genuinely re-proving coverage. Redundant
    //   re-reads on surviving watches are the bounded cost (a re-arm never MOVES a
    //   survivor). A never-narrowed scope (`applied_cover == None`) has no stale
    //   claim to degrade; its coverage self-heals through the Monitor's own re-arm.
    //
    // A kernel-recursive scope's whole-subtree stream never narrows
    // (`on_set_cover` refuses it before recording anything, so its `applied_cover`
    // is never `Some`), but that buys it no exemption here: `sync_root` opens a
    // cover fence for ANY scope without consulting the profile, so a KR scope can
    // hold a pending fence, and skipping its loss memory let a real
    // `FAN_Q_OVERFLOW` resolve that fence `Applied` over a window the kernel had
    // already dropped events from. The cost is at most ONE entry per scope,
    // cleared at the next settle observation — and a kernel-recursive scope's
    // `Rescan` sources are all genuine loss windows rather than churn: a real
    // queue overflow, a root death, and a root replace's cut. Conservative by
    // design for descending scopes: an unrelated churn `Rescan` degrades too (the
    // caller self-heals by re-issuing). Both routes below deliver the `Rescan`
    // (emitted, or parked as the lag's dominating change), so a marked window is
    // never a signal the consumer didn't also get.
    if change.kind().is_rescan() {
      self.cover_fences.entry(scope).or_default().mark_lossy();
      if state.applied_cover.is_some() {
        state.applied_cover = Some(Vec::new());
        state.settle_floor = Some(Vec::new());
      }
    }
    match &mut state.lag {
      LagState::Normal => {
        let root = state.delivery_root();
        self.effects.push_back(Effect::Emit {
          scope,
          root,
          change,
        });
      }
      LagState::Lagged { parked, .. } => {
        if change.kind().is_rescan() {
          // Fold the new Rescan into the parked one (INV-PARK): a located
          // mint (a deficit re-signal, an incomplete read, a failed arm)
          // must not shrink the drop set the parked instruction promised, so
          // the coverages join while the id + epoch advance to the newest
          // mint. Everything non-Rescan the scope produces while lagged
          // stays covered by the never-narrowing parked instruction and is
          // dropped.
          *parked = Some(match parked.take() {
            None => change,
            Some(prev) => Self::covering_merge(&prev, change),
          });
        }
      }
    }
  }
}

/// The plan for one compiled event.
enum ItemPlan {
  Immediate(Vec<Planned>),
  Await { probe: ProbeId, path: PathBuf },
}

/// One probe's resolution: the item it grounds, its planned inputs, and its
/// contribution to the batch's cookie-evidence exchange.
struct Resolved {
  item: usize,
  planned: Vec<Planned>,
  /// A fileID this probe bound to the root device (a cookied `Present`
  /// rename half whose EVENT word carried the same fileID the probe
  /// observed), with the partner path that carried the proof — settlement
  /// evidence for a vanished partner.
  evidences: Option<(NonZeroU64, PathBuf)>,
  /// A vanished half's grant candidacy (see [`Item::cookie_candidate`]).
  candidate: Option<(NonZeroU64, PathBuf)>,
}

impl Resolved {
  fn plain(item: usize, planned: Vec<Planned>) -> Self {
    Self {
      item,
      planned,
      evidences: None,
      candidate: None,
    }
  }
}

/// Lowers one executed `lstat` into the Monitor's stat vocabulary. A vanished
/// path is the benign race the Monitor settles as an empty slot; an unreadable
/// one settles nothing and leaves the slot's deficit standing.
fn stat_result(outcome: ProbeOutcome) -> StatResult {
  match outcome {
    // Identity is minted as the enumerate mints it — the bare inode, for an object
    // the probe could name. The probed DEVICE is deliberately not consulted: this
    // answer settles a kind, and the mount/device descent gate the enumerate applies
    // still governs whether the Monitor may go below the slot at all.
    ProbeOutcome::Present { kind, file_id, .. } => {
      let entry = StatEntry::new(kind);
      StatResult::Ok(match file_id.map(Identity::new) {
        Some(node) => entry.with_node(node),
        None => entry,
      })
    }
    ProbeOutcome::Missing => StatResult::Failed(IoClass::NotFound),
    ProbeOutcome::Failed => StatResult::Failed(IoClass::Io),
  }
}

/// Builds a record with identity minted from the event-side fileID.
fn record_from_event(
  state: &ScopeState,
  kind: RecordKind,
  target: Option<Location>,
  is_dir: Option<bool>,
  file_id: Option<NonZeroU64>,
  path: &Path,
) -> OsRecord {
  let node = mint(state, path, file_id, None);
  record_with(state, kind, target, is_dir, node)
}

/// Builds a record addressing `target` under the scope's root watch.
fn record_with(
  state: &ScopeState,
  kind: RecordKind,
  target: Option<Location>,
  is_dir: Option<bool>,
  node: Option<Identity>,
) -> OsRecord {
  let mut rec = OsRecord::new(state.watch, kind);
  if let Some(target) = target {
    rec = rec.with_target(target);
  }
  if let Some(is_dir) = is_dir {
    rec = rec.with_is_dir(is_dir);
  }
  if let Some(node) = node {
    rec = rec.with_node(node);
  }
  rec
}

/// Builds a record for the whole fact set `proven`, addressing `target` under the
/// scope's root watch. `None` when the set names no dirent verb — the caller then
/// owes a located rescan rather than a fabricated record.
fn record_proved(
  state: &ScopeState,
  proven: Evidence,
  target: Option<Location>,
  is_dir: Option<bool>,
  node: Option<Identity>,
) -> Option<OsRecord> {
  let mut rec = OsRecord::proved(state.watch, proven)?;
  if let Some(target) = target {
    rec = rec.with_target(target);
  }
  if let Some(is_dir) = is_dir {
    rec = rec.with_is_dir(is_dir);
  }
  if let Some(node) = node {
    rec = rec.with_node(node);
  }
  Some(rec)
}

/// A located subtree overflow at `target` under `watch` (the watch itself
/// when `target` is `None`).
fn located(watch: WatchId, target: Option<Location>) -> Scope {
  let sub = SubtreeScope::new(watch);
  Scope::Subtree(match target {
    Some(location) => sub.with_descent(location),
    None => sub,
  })
}

/// The directory-ness hint a flag word carries, if any.
fn dir_hint(flags: FsEventFlags) -> Option<bool> {
  if flags.item_is_dir() {
    Some(true)
  } else if flags.item_is_file() || flags.item_is_symlink() {
    Some(false)
  } else {
    None
  }
}

/// Mints the record identity for an object at `path`.
///
/// One function serves the event path (no device known — trusted iff no
/// foreign-mount prefix covers the path) and the probe path (`dev` known —
/// authoritative). Two minting schemes would make the Monitor's identity
/// comparisons fire on the same object forever.
fn mint(
  state: &ScopeState,
  path: &Path,
  file_id: Option<NonZeroU64>,
  dev: Option<u64>,
) -> Option<Identity> {
  let fid = file_id?;
  device_trusted(state, path, dev).then(|| Identity::new(fid))
}

/// Whether an enumerated directory `entry` sits across the scope's MOUNT
/// boundary and so must not be descended (lowered to [`FileKind::Other`]).
///
/// Two independent fences, either one a boundary:
///
/// - **the device belt** — `entry.dev != root_dev`. A different device is a
///   different superblock, always a boundary, and needs no mount id. Kept even
///   when mount ids are known (a different device cannot share the root's mount, so
///   this only ever agrees with the mount fence, but it costs nothing and is the
///   sole fence when a mount id is unavailable).
/// - **the mount fence** — the child's mount id differs from the root's, when BOTH
///   are known. This is the fence the device belt CANNOT provide: a `mount --bind`
///   of a same-superblock directory shares the root's device, so only a differing
///   mount id marks it a boundary.
///
/// When either mount id is unknown (the executor could not read one — below Linux
/// 5.8, the `stx_mask` bit unset, or a non-Linux/fake source), the device belt
/// alone governs — the honest degrade to the settled single-device policy, never
/// over-fencing a genuine in-root directory on a mount-id read miss. An unknown
/// ROOT device (`None`, an off-unix fake) leaves the belt inert; with no mount id
/// either, nothing crosses — the fake tree is one scope.
///
/// A `None` mount id reaching this belt is ALWAYS a legitimate mask-absent read (a
/// SUCCESSFUL statx below 5.8, or a fake), NEVER a swallowed statx failure: on Linux
/// the spawn barrier fails closed on any statx error (`os::linux::require_statx`) and
/// the mount-id captures turn a statx syscall failure into a spawn/walk failure, so a
/// statx-denied environment never goes live to feed a `None` frame here. The belt is
/// thus only ever the honest pre-5.8 degrade, not a silently disabled fence.
fn crosses_mount_boundary(state: &ScopeState, entry: &RawDirEntry) -> bool {
  let device_boundary = matches!(state.root_dev, Some(root_dev) if entry.dev != root_dev);
  let mount_boundary = matches!(
    (state.root_mnt_id, entry.mnt_id),
    (Some(root_mnt), Some(entry_mnt)) if root_mnt != entry_mnt
  );
  device_boundary || mount_boundary
}

/// The retained prefixes in `new` the PREVIOUS applied cover `prev` did not already cover —
/// the broadening delta a set-cover must re-arm. `prev == None` is the FULL
/// (never-pruned) cover: it covers everything, so nothing is broadening and the delta is empty.
/// Otherwise a retained prefix `r` is broadening iff NO member of `prev` is a prefix of it: its
/// subtree was pruned under `prev` (only its connecting ancestors were kept armed), so it must
/// be re-armed regardless of whether a watch survives at its own path. A prefix INSIDE some
/// previously-retained subtree (`r.starts_with(p)`) was never pruned and is skipped.
///
/// A pure function of the two covers — the coverage-restore decision in isolation, unit-tested
/// cross-platform. The caller resolves each broadening prefix to the deepest still-watched
/// ancestor-or-self and re-arms it.
fn broadening_delta<'a>(prev: Option<&[PathBuf]>, new: &'a [PathBuf]) -> Vec<&'a Path> {
  let Some(prev) = prev else {
    return Vec::new();
  };
  new
    .iter()
    .filter(|r| !prev.iter().any(|p| r.starts_with(p)))
    .map(PathBuf::as_path)
    .collect()
}

/// The antichain MEET of two retained covers — the coverage guaranteed by BOTH.
///
/// A cover retains everything under its prefixes, so the meet is their
/// intersection: a path is covered by the meet iff it is covered by `prev` AND
/// by `applied`. For antichain covers that is the pairwise rule — for each
/// nested pair, keep the DEEPER prefix (`meet({/x}, {/x/y}) = {/x/y}`); prefixes
/// nested in no member of the other cover contribute nothing
/// (`meet({/x}, {/z}) = {}` — an EMPTY meet is meaningful: nothing is
/// guaranteed by both). `prev == None` is FULL coverage, the meet identity
/// (`meet(FULL, A) = A`), mirroring `applied_cover`'s never-pruned initial
/// state. The pairwise result is deduped and normalized to cover form (a
/// member inside another member's subtree is redundant — with antichain
/// inputs the pairwise set already is one, so the pruning is defensive).
///
/// The settle floor is folded with this on every applied cover; a pure
/// function of the two covers, unit-tested cross-platform like
/// [`broadening_delta`].
fn cover_meet(prev: Option<&[PathBuf]>, applied: &[PathBuf]) -> Vec<PathBuf> {
  let Some(prev) = prev else {
    return applied.to_vec();
  };
  let mut deeper: Vec<&Path> = Vec::new();
  for p in prev {
    for a in applied {
      let kept = if a.starts_with(p) {
        a.as_path()
      } else if p.starts_with(a) {
        p.as_path()
      } else {
        continue;
      };
      if !deeper.contains(&kept) {
        deeper.push(kept);
      }
    }
  }
  let mut meet: Vec<PathBuf> = Vec::new();
  for kept in &deeper {
    // Cover normal form: a member strictly inside another member's subtree is
    // redundant — the shallower member already covers it. (`deeper` is deduped,
    // so value inequality means a different member.)
    let redundant = deeper
      .iter()
      .any(|other| *kept != *other && kept.starts_with(other));
    if !redundant {
      meet.push(kept.to_path_buf());
    }
  }
  meet
}

/// The move cookie for a rename half, minted ONLY from contemporaneous probe
/// evidence: `dev` is the device a probe just read for the object. fileIDs
/// are device-scoped, so any cookie without live root-device proof could pair
/// two different objects into a fabricated move — corruption with no covering
/// rescan. The mount table never grants a cookie; it can only veto one (the
/// vanished-half grant in [`DriverCore::grant_evidenced_cookies`] requires a
/// partner's probe evidence AND a clean table).
fn cookie_for(state: &ScopeState, file_id: Option<NonZeroU64>, dev: u64) -> Option<MoveCookie> {
  let fid = file_id?;
  (state.root_dev == Some(dev)).then(|| MoveCookie::new(fid))
}

/// Whether `path`'s objects provably live on the scope's root device.
///
/// A probe-side caller passes the stat-read device — direct evidence that
/// decides alone. An event-side caller passes `dev: None`, and unknown is
/// UNTRUSTED by default: absence from the mount table only proves anything
/// when the table was seeded authoritatively at spawn (an unseeded table is
/// merely blind to already-mounted volumes, which is exactly how a foreign
/// fileID gets promoted into a fabricated move).
///
/// The prefix comparison here is byte-based, and on a case-insensitive volume
/// a spelling-aliased path could MISS a stored mount prefix — the trust-
/// increasing direction. That miss is contained by what the table's answer
/// may still reach: cookies never come from the table (`cookie_for` requires
/// probe-read device evidence, and every probe carries the real device
/// regardless of spelling); the vanished-half grant uses the table only as a
/// VETO on top of partner probe evidence, and every grant that fires queues a
/// covering located `Rescan`, so an evaded veto degrades to a covered
/// mis-pair, never a silent one; event-side `mint` identity is consumed by
/// the Monitor only through descent machinery, which a kernel-recursive
/// backend never engages. The spellings themselves also share one origin —
/// mount prefixes (`getfsstat`) and event paths both carry the kernel's VFS
/// form through the same filesystem-representation transform — so an aliased
/// miss requires the kernel reporting two spellings for one mount point.
fn device_trusted(state: &ScopeState, path: &Path, dev: Option<u64>) -> bool {
  match (dev, state.root_dev) {
    (Some(dev), Some(root_dev)) => return dev == root_dev,
    (Some(_), None) => return false,
    (None, _) => {}
  }
  state.mounts_authoritative && !state.mounts.iter().any(|m| path.starts_with(m))
}

/// Applies one MOUNT event's trust-reducing prefix add. Runs in `compile`'s
/// pre-scan — strictly before any of the batch's items are classified — so a
/// same-batch rename under the just-mounted volume already sees the foreign
/// prefix. The trust-increasing dual (an unmount's removal) is deferred to
/// settlement instead: see the monotone-within-batch rule in `compile`.
fn apply_mount_add(state: &mut ScopeState, ev: &RawOsEvent) {
  if !matches!(lower(state, &ev.path), Lowered::Target(_)) {
    return;
  }
  if !state.mounts.iter().any(|m| m == &ev.path) {
    state.mounts.push(ev.path.clone());
  }
}

/// Records a probed foreign-device path as a mount prefix, so later
/// event-side identities under it degrade to `None` instead of colliding.
fn learn_device(state: &mut ScopeState, path: &Path, dev: u64) {
  if let Some(root_dev) = state.root_dev
    && dev != root_dev
    && !state.mounts.iter().any(|m| path.starts_with(m))
  {
    state.mounts.push(path.to_path_buf());
  }
}

/// Lowers an absolute event path to its place under the scope root.
///
/// Canonical roots never carry a trailing separator except the filesystem
/// root `/` itself (both `fs::canonicalize` and the spawn-side transform
/// guarantee it), so `/` is the one root whose descendants strip to a bare
/// remainder.
fn lower(state: &ScopeState, path: &Path) -> Lowered {
  let Some(root) = state.root.as_deref() else {
    return Lowered::Outside;
  };
  let root_bytes = path_bytes(root);
  let bytes = path_bytes(path);
  let Some(rest) = bytes.strip_prefix(root_bytes) else {
    return Lowered::Outside;
  };
  let rest = match rest {
    [] => return Lowered::Root,
    [b'/', tail @ ..] => tail,
    // The root "/" already ends with the separator, so its descendants
    // arrive without a leading one ("/tmp/a" strips to "tmp/a").
    tail if root_bytes == b"/" => tail,
    // The prefix matched mid-component (root "/a/b" vs path "/a/bc").
    _ => return Lowered::Outside,
  };
  let mut segments = Vec::new();
  for part in rest.split(|&b| b == b'/') {
    if part.is_empty() {
      continue;
    }
    // macOS filenames are valid Unicode by filesystem contract; anything
    // else is unaddressable and escalates at the caller.
    let Ok(part) = std::str::from_utf8(part) else {
      return Lowered::Outside;
    };
    segments.push(Segment::new(part));
  }
  if segments.is_empty() {
    Lowered::Root
  } else {
    Lowered::Target(Location::from_segments(segments))
  }
}

fn path_bytes(path: &Path) -> &[u8] {
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes()
  }
  #[cfg(not(unix))]
  {
    path.as_os_str().to_str().map_or(&[][..], str::as_bytes)
  }
}

/// The Monitor capability profile a backend registers with.
const fn caps_for(backend: BackendKind) -> Capabilities {
  let caps = Capabilities::new().with_supports_push().with_native_move();
  match backend {
    // Every kernel-recursive backend registers the KR profile: one native
    // stream covers the whole root, so the Monitor never descends.
    BackendKind::FsEvents | BackendKind::Fanotify | BackendKind::Rdcw | BackendKind::UsnJournal => {
      caps.with_kernel_recursive()
    }
    // inotify's per-watch teardown records (`IN_IGNORED`, unmount included)
    // ride the same queue an `IN_Q_OVERFLOW` empties, so a loss can leave
    // retained watches kernel-dead with no record of it: a scope-level loss
    // must re-prove every retained binding by an acknowledged re-add.
    BackendKind::Inotify => caps.with_lossy_watch_teardown(),
  }
}

/// Whether `backend` decides exclusions ITSELF, at admission, before an event
/// ever reaches the common layer — the composition gate for the live half of the
/// common-layer fence ([`DriverCore::fence_exclusions`]).
///
/// The fence supplies enforcement exactly where a backend has none. Where a
/// backend already has one, re-deciding here could only DIFFER from it, because
/// the backend decides with strictly more context:
///
/// - **FSEvents** hands the set to the OS, which drops the events before the
///   process sees them (a rejected set fails the spawn outright, so enforcement
///   is proven, never partial). Its records are also minted at probe resolution,
///   AFTER compile, so a fence here would cover only some of them — partial
///   suppression is worse than none.
/// - **fanotify** fences at admission, where it holds the atomic rename pair. It
///   deliberately forwards a rename that CROSSES the boundary — the crossing is
///   what tells the consumer the object left the reported tree — and suppresses
///   only a rename with NO end in the reported tree (an end fails to be
///   reported either because it is excluded or because it lies outside the
///   watched root — the two are not the same test). A second, half-by-half
///   decision here would silently rewrite that pair into a bare removal.
///
/// Every other backend answers `false` and is enforced by the fence, INCLUDING a
/// future descending one: a descending backend cannot enforce at admission (its
/// only refusal is an arm, which the Monitor reads as loss), so the default is
/// the correct answer for the whole class rather than a per-backend opinion.
const fn backend_enforces_exclusions(backend: BackendKind) -> bool {
  matches!(backend, BackendKind::FsEvents | BackendKind::Fanotify)
}

/// Whether `backend` runs the GEOMETRY half of the common-layer fence — the half
/// that re-enumerates a moved subtree whose rename crossed an exclusion boundary
/// ([`DriverCore::reparent_geometry`]), read off the Monitor's own report on the
/// far side of each record's hand-off.
///
/// A pure function of the profile, deliberately: the caller's exclusion set
/// decides whether the geometry pass has anything to do on a given read, but not
/// whether the profile is one that resolves per-directory paths mid-read at all.
/// That distinction is what [`feeds_at_classify`] is coupled to — a discipline
/// that flipped with the configuration would make the exclusion path a different
/// code path from the default one.
const fn runs_rename_geometry(backend: BackendKind) -> bool {
  !backend_enforces_exclusions(backend) && !caps_for(backend).kernel_recursive()
}

/// Whether `backend` hands each kept record to the Monitor AS THE FENCE
/// CLASSIFIES IT, instead of buffering the whole read for
/// [`settle`](DriverCore::settle).
///
/// # Why the discipline exists
///
/// Batch-then-settle puts a PHASE LAG between the two halves of one read: the
/// fence classifies every record before the Monitor is told about any of them.
/// This core derives every watch path from the Monitor's own tree
/// ([`DriverCore::path_of`]), so under the lag a descending profile's addressing
/// question — "where does this record's watch live NOW" — is answered by a
/// Monitor that has not yet heard a single record of the read it is being asked
/// about, and one rename early in the read makes every later answer wrong. The
/// geometry decision has the same shape: it reads the Monitor's report of a
/// reparent that, under the lag, has not happened. Feeding at classify time
/// closes both: by the time a record is judged, every record ahead of it in the
/// same read has already landed, and the report of what each one did to the tree
/// exists.
///
/// # Why it is per-PROFILE and not per-configuration
///
/// The answer is read off the backend alone, so a scope with no exclusions
/// configured feeds exactly the way a scope with them does. The fence's
/// early-outs (no exclusions, or a backend that enforces its own) decide whether
/// there is anything to SUPPRESS; they must not decide how records reach the
/// Monitor, or the default configuration would exercise a feeding path the
/// exclusion tests never cover.
///
/// # Why only inotify
///
/// [`settle`](DriverCore::settle) has three duties, and inotify is the profile
/// for which the other two are vacuous:
///
/// - **granting evidenced cookies.** A `cookie_candidate` is minted only at probe
///   resolution and `evidenced` is filled only there, so both are empty for every
///   lowering that mints no probe — which is every lowering but FSEvents.
/// - **applying deferred unmount trust-removals.** `deferred_unmounts` is filled
///   only by the FSEvents lowering; every other lowering builds it empty.
///
/// What remains is feeding, and feeding early is safe only where the batch is
/// complete when the fence runs: FSEvents is the one profile that compiles a
/// batch with `awaiting > 0`, parking it until its probes answer, and a parked
/// batch's items are still placeholders. It also stands the fence down entirely
/// ([`backend_enforces_exclusions`]), so it neither needs nor may have this.
/// fanotify likewise stands the fence down. RDCW and USN are fence-active but
/// kernel-recursive, so they run no geometry, and every record of theirs anchors
/// at the scope ROOT — the one watch no rename inside the tree can move — so
/// their addressing is a fixed point and batch-then-settle costs them nothing.
///
/// The batch's transport permit is unaffected: a feed-at-classify profile never
/// parks, so its permit is attached and dropped inside the same call either way.
///
/// Written as an exhaustive match so a new backend cannot be added without
/// answering this question, and checked against [`runs_rename_geometry`] below.
const fn feeds_at_classify(backend: BackendKind) -> bool {
  match backend {
    // Descending and fence-active: the only profile whose fence resolves
    // per-directory paths mid-read, and the only one that compiles no
    // probe-parked batch AND runs the geometry pass.
    BackendKind::Inotify => true,
    // Parks for probes (`awaiting > 0`), so a batch is not complete when the
    // fence runs — and stands the fence down anyway.
    BackendKind::FsEvents => false,
    // Enforces exclusions at admission; the fence stands down.
    BackendKind::Fanotify => false,
    // Fence-active but kernel-recursive: no per-directory watches, so no
    // geometry and no mid-read addressing dependency.
    BackendKind::Rdcw | BackendKind::UsnJournal => false,
  }
}

/// INV-FEED, first leg: geometry ⇒ feed-at-classify.
///
/// Both sides are pure functions of the profile, so the implication is settled at
/// COMPILE time rather than left to agree by coincidence — a future descending
/// backend that answered [`feeds_at_classify`] with `false` would run the
/// geometry pass over the phase lag, classifying each record against addressing
/// its own read is still rewriting, and would fail to build here instead.
///
/// The second leg (feed-at-classify ⇒ `awaiting == 0`) is a property of the
/// compiled batch rather than of the profile, so it is asserted where the batch
/// exists, in [`DriverCore::fence_exclusions`]. That assertion is stated over the
/// profile in hand rather than variant by variant, so it reaches every backend
/// including one added after this list.
const _: () = {
  assert!(!runs_rename_geometry(BackendKind::Inotify) || feeds_at_classify(BackendKind::Inotify));
  assert!(!runs_rename_geometry(BackendKind::FsEvents) || feeds_at_classify(BackendKind::FsEvents));
  assert!(!runs_rename_geometry(BackendKind::Fanotify) || feeds_at_classify(BackendKind::Fanotify));
  assert!(!runs_rename_geometry(BackendKind::Rdcw) || feeds_at_classify(BackendKind::Rdcw));
  assert!(
    !runs_rename_geometry(BackendKind::UsnJournal) || feeds_at_classify(BackendKind::UsnJournal)
  );
};

/// The `(dev, ino)` an arm must confirm the opened object still has before
/// installing its kernel watch — the object-correctness check that closes the
/// enumerate→arm rename window (a descended child, or the root itself). Carried
/// on [`Effect::AddWatch`] and plumbed to the executor's open+fstat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpectedObject {
  /// The device the object was read on.
  pub(crate) dev: u64,
  /// The object's inode.
  pub(crate) ino: NonZeroU64,
}

/// One raw directory entry as the executor read it — name bytes and stat
/// facts only; the CORE mints the proto `DirEntry` (identity policy needs the
/// scope's device-trust state, which an executor never holds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawDirEntry {
  /// The entry's name, as raw bytes (non-UTF-8 degrades the listing).
  pub(crate) name: Vec<u8>,
  /// The entry's kind.
  pub(crate) kind: FileKind,
  /// The device the entry lives on.
  pub(crate) dev: u64,
  /// The entry's inode number (0 = unknown).
  pub(crate) ino: u64,
  /// The entry's MOUNT id (from `statx(STATX_MNT_ID)`), or `None` when the
  /// executor could not read it (a pre-5.8 kernel, the mask bit unset, or a
  /// non-Linux/fake executor). The core fences descent on a differing mount id —
  /// a `mount --bind` of a same-device directory shares [`dev`](Self::dev), so
  /// the device alone cannot mark it a boundary. `None` falls back to the device
  /// check (the honest below-5.8 degrade).
  pub(crate) mnt_id: Option<u64>,
}

/// One raw enumerate outcome from the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RawEnumerate {
  /// The directory was read; `complete` is false when the read was cut short.
  Listed {
    /// The entries read.
    entries: Vec<RawDirEntry>,
    /// Whether the listing covered the whole directory.
    complete: bool,
  },
  /// The directory could not be read.
  Failed(IoClass),
}

/// Maps a spawn failure to the Monitor's watch-error vocabulary.
fn watch_error(err: &SourceError) -> WatchError {
  match err {
    SourceError::RootUnavailable { source, .. } => match source.kind() {
      std::io::ErrorKind::NotFound => WatchError::NotFound,
      std::io::ErrorKind::PermissionDenied => WatchError::Permission,
      _ => WatchError::Io,
    },
    _ => WatchError::Io,
  }
}
