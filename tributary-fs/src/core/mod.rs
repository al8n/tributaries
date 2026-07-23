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
  Capabilities, Change, ChangeKind, DirEntry, EnumerateResult, FileKind, Identity, Instant,
  Interest, IoClass, Location, Monitor, MoveCookie, OsRecord, RecordKind, ReqId, Scope, ScopeId,
  Segment, SubtreeScope, WatchError, WatchId,
};

use crate::os::{
  BackendKind, BatchPayload, FsEventFlags, RawOsEvent, RootIdentity, RootMeta, SourceError,
  SourceEvent,
  linux::{RawLinuxEvent, WatchOutcome},
  transport::BudgetPermit,
  windows::RawWindowsEvent,
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
  /// (or root-less before spawn) no caller holds a handle, and a reconcile in
  /// that window would mark the root's pending COLD arm as a re-arm —
  /// converting the initial cold discovery into a `Created`-suppressing
  /// re-arm read. Refused outright; the caller's cover is re-issued once the
  /// grant commits (the umbrella only ever covers committed watches, so only
  /// the re-publicized API can reach this).
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverSettle {
  /// The reconcile's re-arm work quiesced with no loss signal in the window:
  /// every re-armed watch is live, so writes under the retained cover from
  /// this moment are delivered.
  Applied,
  /// The reconcile settled, but the window was lossy — a covering `Rescan`
  /// passed, a grow kickoff coalesced into an in-flight cold read, or the
  /// scope tore down mid-fence. Coverage may be partial; the `Rescan`
  /// (terminal, for teardown) dominates the gap.
  Degraded,
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
/// [`RearmKickoff::Coalesced`]: tributary_proto::RearmKickoff::Coalesced
#[derive(Debug, Default)]
struct CoverFence {
  /// Pending fences in open (FIFO) order, each carrying its own lossy flag —
  /// inherited from `lossy` at open, then marked by later loss events.
  pending: Vec<(FenceId, bool)>,
  /// The scope's loss memory since the last settle observation (see the
  /// lossy-window rule above).
  lossy: bool,
}

impl CoverFence {
  /// Records one loss event: remembered until the next settle observation and
  /// stamped onto every pending fence.
  fn mark_lossy(&mut self) {
    self.lossy = true;
    for (_, lossy) in &mut self.pending {
      *lossy = true;
    }
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
  /// The splice applied; the widen is live on the same transport.
  Committed,
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
  /// Every live watch's absolute path (the root's canonical path; a child's
  /// = its parent's joined with its name) — how descending effects address
  /// objects. Same order of growth as the Monitor's own tree.
  watch_paths: BTreeMap<WatchId, Arc<PathBuf>>,
  /// Outstanding enumerate requests: the scope whose state mints entry
  /// identities when the raw listing returns, plus the read directory.
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
  /// and by every public scope `Rescan` of a descending scope (so an
  /// out-of-window loss is remembered, not dropped with the window), removed
  /// by the settle observation or the scope's teardown. No entry may outlive
  /// its scope.
  cover_fences: BTreeMap<ScopeId, CoverFence>,
  /// Fences a scope teardown resolved (always [`CoverSettle::Degraded`] — the
  /// terminal `Rescan` covers the caller), folded into the next
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
      watch_paths: BTreeMap::new(),
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
    }
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
  pub(crate) fn on_watch(
    &mut self,
    root: PathBuf,
    interest: Interest,
    profile: BackendKind,
  ) -> ScopeId {
    self.scope_seq += 1;
    let scope = ScopeId::new(NonZeroU64::new(self.scope_seq).expect("sequence starts at one"));
    let watch = self
      .monitor
      .register_root_with_profile(scope, interest, caps_for(profile));
    self.scopes.insert(
      scope,
      ScopeState {
        watch,
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
    scope
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
  /// - a scope that is **not publicly live** ([`NotLive`](CoverNoop::NotLive)) — between a
  ///   descending scope's spawn and its root-arm grant the root's arm is still COLD, and a
  ///   reconcile's grow would mark it re-arm-flavored, suppressing the initial inventory's
  ///   `Created`s (re-arms deliberately emit none); no caller holds a handle yet, so there is
  ///   no coverage to reconcile;
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
  /// descending paths, keeping the reader's `wd` table and the core's addressing maps consistent
  /// exactly as delete-driven and create-driven transitions do. A `Reconciling` return also
  /// updates the fence bookkeeping: the scope's [`CoverFence`] entry is (re)ensured so the next
  /// settle observation sees this window, any `Coalesced` grow kickoff records the born-lossy
  /// memory (see [`CoverFence`]), and `applied_cover` / `settle_floor` are recorded
  /// (optimistically / as the running meet).
  #[must_use = "the disposition routes the acknowledgement: a Noop is answered immediately, a Reconciling may owe a fence"]
  pub(crate) fn on_set_cover(&mut self, scope: ScopeId, retained: &[PathBuf]) -> CoverReconcile {
    let Some(state) = self.scopes.get(&scope) else {
      return CoverReconcile::Noop(CoverNoop::UnknownScope);
    };
    // The publicly-live gate (see the refusal table above): a pre-grant reconcile would
    // convert the root's cold discovery into a `Created`-suppressing re-arm.
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
        let path = self.watch_paths.get(watch)?;
        let strictly_outside = retained
          .iter()
          .all(|r| !path.starts_with(r) && !r.starts_with(path.as_path()));
        strictly_outside.then(|| (path.components().count(), *watch))
      })
      .collect();
    outside.sort_unstable_by_key(|(depth, _)| *depth);
    for (_, watch) in outside {
      // A node an ancestor's drop already reclaimed is no longer watched — skip it (the
      // shallow-first order guarantees the ancestor was processed first).
      if self.monitor.is_watched(watch) {
        self.monitor.drop_watch_subtree(watch);
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
          let path = self.watch_paths.get(watch)?;
          r.starts_with(path.as_path())
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
              (self.watch_paths.get(watch), self.watch_paths.get(other)),
              (Some(path), Some(ancestor)) if path.starts_with(ancestor.as_path())
            )
        })
      })
      .copied()
      .collect();
    // A `Coalesced` kickoff folded its obligation into an in-flight COLD read the settle
    // counter deliberately does not see: the scope can read settled while the obligation is
    // latent, so the fence window is lossy FROM BIRTH (the F0 amendment).
    let mut coalesced = false;
    for watch in targets {
      if self.monitor.rearm_watch_subtree(watch).is_coalesced() {
        coalesced = true;
      }
    }

    // Fence bookkeeping BEFORE the drain, so an entry exists when any change this reconcile
    // provokes routes: ensure the scope's entry (the next settle observation must see this
    // window even when the reconcile is reply-less — that observation resets the floor on a
    // clean settle and clears the loss memory), and record the born-lossy memory, which marks
    // every already-pending fence and is inherited by any fence opened before the scope next
    // settles (see [`CoverFence`]).
    let fence = self.cover_fences.entry(scope).or_default();
    if coalesced {
      fence.mark_lossy();
    }

    // Turn the queued `Action::Unwatch`es (prune) into `RemoveWatch` effects and the queued
    // `Action::Watch`/`Enumerate`s (grow) into `AddWatch`/`Enumerate` effects, and reconcile
    // the addressing maps, exactly as Monitor-driven drops and descents do. A no-op when both
    // halves queued nothing.
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
  pub(crate) fn open_cover_fence(&mut self, scope: ScopeId) -> FenceId {
    self.fence_seq += 1;
    let fence = FenceId(self.fence_seq);
    let entry = self.cover_fences.entry(scope).or_default();
    entry.pending.push((fence, entry.lossy));
    fence
  }

  /// Drops the pending tuples of `abandoned` fences — callers that cancelled their
  /// `set_cover` await before the settle. Only the per-fence tuples go: the scope's
  /// loss memory, its settle-floor bookkeeping, and every still-awaited fence stay
  /// untouched, so the settle observation's cover repair is unaffected. Without this,
  /// a caller repeatedly issuing-and-cancelling against a scope whose re-arm work is
  /// stalled would accumulate one pending tuple per processed request indefinitely —
  /// the bounded command mailbox limits only instantaneous traffic, never the total.
  pub(crate) fn abandon_cover_fences(&mut self, abandoned: &std::collections::BTreeSet<FenceId>) {
    if abandoned.is_empty() {
      return;
    }
    for entry in self.cover_fences.values_mut() {
      entry
        .pending
        .retain(|(fence, _)| !abandoned.contains(fence));
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
  /// already resolved `Degraded`. The driver polls this at its loop top,
  /// after feeding results back.
  ///
  /// The settle observation is also where the applied-cover lie is repaired:
  /// a LOSSY window rewinds `applied_cover` to the settle floor (the provable
  /// under-claim, so a re-issue recomputes a real broadening delta); a CLEAN
  /// window resets the floor to the now-truthful `applied_cover`. Either way
  /// the scope's fence entry — pending fences and loss memory — is cleared:
  /// no fence state outlives its settle.
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

  pub(crate) fn poll_cover_settlements(&mut self) -> Vec<(FenceId, CoverSettle)> {
    let mut settled = std::mem::take(&mut self.settled_covers);
    let scopes: Vec<ScopeId> = self.cover_fences.keys().copied().collect();
    for scope in scopes {
      if !self.barrier_settled(scope) {
        continue;
      }
      let Some(entry) = self.cover_fences.remove(&scope) else {
        continue;
      };
      // Teardown removes the entry with its scope, so a live entry always has scope
      // state; a scope-less entry is a seam bug — degrade its fences rather than
      // report `Applied` for coverage nobody backs.
      let mut dead = false;
      if let Some(state) = self.scopes.get_mut(&scope) {
        if entry.lossy {
          state.applied_cover = state.settle_floor.clone();
        } else {
          state.settle_floor = state.applied_cover.clone();
        }
      } else {
        debug_assert!(false, "a fence entry never outlives its scope");
        dead = true;
      }
      for (fence, lossy) in entry.pending {
        let settle = if lossy || dead {
          CoverSettle::Degraded
        } else {
          CoverSettle::Applied
        };
        settled.push((fence, settle));
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
        self.watch_paths.insert(watch, Arc::clone(&root));
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
            self.monitor.on_watch_result(watch, Ok(()));
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
            self.effects.push_back(Effect::AddWatch {
              scope,
              watch,
              parent: watch,
              name: Segment::new(name),
              path: root,
              expected,
            });
          }
        }
      }
      Err(err) => {
        self.monitor.on_watch_result(watch, Err(watch_error(&err)));
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
    self.monitor.on_watch_result(watch, Err(WatchError::Gone));
    self.drain_monitor();
  }

  /// Feeds one descending arm's outcome. An [`Aliased`](WatchOutcome::Aliased)
  /// anchor maps to a successful watch-result exactly like a fresh install:
  /// the wd table fans the shared kernel watch's events out to every anchor,
  /// so the anchor's coverage is real — the Monitor proceeds to its cold
  /// enumerate and the inventory is correct.
  /// The scope a watch belongs to, while the watch is tracked. The driver
  /// uses this to route a root arm's outcome to its deferred registration
  /// grant.
  pub(crate) fn scope_of_watch(&self, watch: WatchId) -> Option<ScopeId> {
    self.watch_scopes.get(&watch).copied()
  }

  pub(crate) fn on_watch_installed(&mut self, watch: WatchId, outcome: WatchOutcome) {
    let res = match outcome {
      WatchOutcome::Installed(_) | WatchOutcome::Aliased(_) => Ok(()),
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
    self.monitor.on_watch_result(watch, res);
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
    let BatchPayload { events, permit } = payload;
    let mut batch = self.compile(&mut state, scope, events);
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
  pub(crate) fn on_root_replaced(&mut self, scope: ScopeId, meta: RootMeta, now: Instant) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    debug_assert_eq!(
      state.profile.is_kernel_recursive(),
      meta.backend.is_kernel_recursive(),
      "replace never crosses lowering profiles; the driver refuses BackendDiverged"
    );
    let watch = state.watch;
    let backend = meta.backend;
    if backend != state.profile {
      state.profile = backend;
      self.monitor.reprofile_root(scope, caps_for(backend));
    }

    // The world swap — the on_stream_spawned adoption, on a live scope.
    let root = Arc::new(meta.root);
    self.watch_paths.insert(watch, Arc::clone(&root));
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
    if !backend.is_kernel_recursive() {
      self.monitor.rebind_root(scope);
    }
    self.monitor.on_overflow(Scope::Root(scope), now);
    self.drain_monitor();
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
    if self
      .monitor
      .widen_root(scope, reserved, chain, old_identity)
      .is_none()
    {
      debug_assert!(false, "a live descending scope accepts its widen splice");
      return WidenCommit::Refused;
    }

    // Watch bookkeeping: the new root joins the maps, the old subtree's
    // entries stay — `watch_paths` are absolute, so nothing is rewritten.
    let root = Arc::new(meta.root);
    self.watch_scopes.insert(reserved, scope);
    self.watch_paths.insert(reserved, Arc::clone(&root));
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
    WidenCommit::Committed
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

  /// Settles a fully-resolved batch: grants evidenced vanished-half cookies,
  /// feeds the Monitor in item order, then applies the deferred unmount
  /// trust-removals (the monotone rule's late edge). Parks instead when
  /// probes are still outstanding.
  /// Lowers one raw batch per the scope's backend profile. The FSEvents path
  /// probe-grounds ambiguity; the inotify path is direct. A payload variant
  /// that disagrees with the profile is a seam bug — its events degrade to a
  /// root rescan rather than a wrong lowering.
  fn compile(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    events: Vec<SourceEvent>,
  ) -> PendingBatch {
    match state.profile {
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

  fn feed(monitor: &mut Monitor, planned: Planned, now: Instant) {
    match planned {
      Planned::Rec(rec) => monitor.on_os_record(rec, now),
      Planned::Over(scope) => monitor.on_overflow(scope, now),
    }
  }

  /// Compiles and feeds queued batches until one parks or the queue drains.
  fn pump_queued(&mut self, scope: ScopeId, now: Instant) {
    loop {
      let Some(mut state) = self.scopes.remove(&scope) else {
        return;
      };
      let Some(BatchPayload { events, permit }) = state.park.queued.pop_front() else {
        self.scopes.insert(scope, state);
        return;
      };
      let mut batch = self.compile(&mut state, scope, events);
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
        let planned = match outcome {
          ProbeOutcome::Missing => {
            let rec = record_with(state, RecordKind::Removed, target, dir_hint(flags), None);
            vec![Planned::Rec(rec)]
          }
          ProbeOutcome::Present { kind, file_id, dev } => {
            learn_device(state, &path, dev);
            let verb = if flags.item_created() {
              RecordKind::Created
            } else if flags.item_modified() {
              RecordKind::Modified
            } else {
              RecordKind::Attrib
            };
            let node = mint(state, &path, file_id, Some(dev));
            let rec = record_with(state, verb, target, Some(kind.is_dir()), node);
            vec![Planned::Rec(rec)]
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
            let root = self
              .scopes
              .get(&scope)
              .map(|state| state.requested.clone())
              .unwrap_or_default();
            self.effects.push_back(Effect::SpawnStream { scope, root });
          } else if let Some(child) = cmd.target().as_child() {
            let parent = child.parent();
            let (Some(&scope), Some(parent_path)) = (
              self.watch_scopes.get(&parent),
              self.watch_paths.get(&parent),
            ) else {
              debug_assert!(false, "a child watch descends from a known parent");
              continue;
            };
            let name = child.name().clone();
            let path = Arc::new(parent_path.join(name.as_str()));
            self.watch_scopes.insert(cmd.id(), scope);
            self.watch_paths.insert(cmd.id(), Arc::clone(&path));
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
            // forget its addressing. Fire-and-forget — the unwatch carries no
            // result contract, and an unreached wd dies with the stream.
            let scope = self.watch_scopes.remove(&watch);
            self.watch_paths.remove(&watch);
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
            // pending fence resolves `Degraded` — the terminal `Rescan` above covers
            // the caller — folded into the next settlement poll so the driver keeps
            // its one choke point. The entry is removed with the scope: no fence
            // state outlives it.
            if let Some(entry) = self.cover_fences.remove(&scope) {
              for (fence, _) in entry.pending {
                self.settled_covers.push((fence, CoverSettle::Degraded));
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
              self.watch_paths.remove(&watch);
            }
            self.watch_paths.remove(&watch);
            self.enum_reqs.retain(|_, (s, _)| *s != scope);
            self.effects.push_back(Effect::TeardownStream { scope });
          }
        }
        tributary_proto::Action::Enumerate(cmd) => {
          let watch = cmd.dir();
          let (Some(&scope), Some(path)) =
            (self.watch_scopes.get(&watch), self.watch_paths.get(&watch))
          else {
            debug_assert!(false, "an enumerate reads a known directory");
            continue;
          };
          self.enum_reqs.insert(cmd.req(), (scope, Arc::clone(path)));
          self.effects.push_back(Effect::Enumerate {
            req: cmd.req(),
            watch,
            path: Arc::clone(path),
          });
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
    // A kernel-recursive scope needs neither: its whole-subtree stream never narrows
    // (`on_set_cover` refuses it before recording anything, so its `applied_cover`
    // is never `Some`) and no fence ever opens for it, so creating loss memory for
    // its churn `Rescan`s would only cycle map entries. Conservative by design for
    // descending scopes: an unrelated churn `Rescan` degrades too (the caller
    // self-heals by re-issuing). Both routes below deliver the `Rescan` (emitted, or
    // parked as the lag's dominating change), so a marked window is never a signal
    // the consumer didn't also get.
    if change.kind().is_rescan() && !state.profile.is_kernel_recursive() {
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
fn caps_for(backend: BackendKind) -> Capabilities {
  let caps = Capabilities::new().with_supports_push().with_native_move();
  match backend {
    // Every kernel-recursive backend registers the KR profile: one native
    // stream covers the whole root, so the Monitor never descends.
    BackendKind::FsEvents | BackendKind::Fanotify | BackendKind::Rdcw | BackendKind::UsnJournal => {
      caps.with_kernel_recursive()
    }
    BackendKind::Inotify => caps,
  }
}

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
