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
//! not stale: a stale completion (an INVALIDATING arming — a loss, or a world swap —
//! overlapped its read, so the snapshot may predate the lost window, and the table +
//! frame come from that one read) publishes neither and re-arms one fresh read. The
//! periodic tick is NOT such an arming: it coalesces onto an in-flight read and lets
//! it publish, because a cadence witnesses no transition (see [`RefreshCause`]).
//! So `state.root_mnt_id` is only ever
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
//! The veto itself is TWO components, and the split is what lets the table half be
//! replaced rather than unioned. [`ScopeState::mount_table`] holds one authoritative
//! snapshot's rows and the next one replaces it whole ([`install_mount_table`]): the
//! reads are serialized and a stale one publishes nothing, so a location an
//! authoritative read does not list is a mount the host says is gone. Everything a
//! snapshot cannot speak for — an in-band `Mount` word for a mount that arrived after
//! the read in flight was taken, or a probe's foreign device at a path arbitrarily deep
//! inside a volume — lives in [`ScopeState::learned_mounts`], which no read may empty
//! and which only the in-band unmount word (or a world swap) retires.
//!
//! # Root-death signals per backend
//!
//! Every backend's root death — unmount, delete, or replace — must reach a
//! trigger that runs [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed)'s
//! death mapping or the Monitor's self-event path; the trigger differs by
//! backend, and two of them cannot be left to their own signal alone, which is
//! what the periodic tick ([`root_liveness_interval`](DriverCore::new)) covers:
//!
//! | backend | root unmount trigger | in-tree delete/replace trigger |
//! |---|---|---|
//! | inotify (descending) | `IN_UNMOUNT` + `IN_IGNORED` event | `IN_DELETE_SELF` / `IN_MOVE_SELF` event — but the delete half is queued only once the LAST reference to the root drops, so the **periodic liveness tick** re-stats the root beside it |
//! | FSEvents (macOS) | `RootChanged` flag → root-alive probe | `RootChanged` flag → root-alive probe |
//! | fanotify (`FAN_MARK_FILESYSTEM`) | **SILENT** — no event, no hangup (the mark holds the sb alive; L4.1) → the **periodic liveness tick** re-stats the root | `FAN_DELETE_SELF` / `FAN_MOVE_SELF` event |
//! | RDCW (Windows) | any terminal read completion → fatal source error → self-event | same signal; RDCW draws no in-band distinction from unmount |
//! | USN journal (Windows) | a failed journal read → fatal source error → self-event | the root's own FRN named in a delete/rename record → `RootDeath` |
//!
//! So both Linux profiles arm the tick (gated by
//! [`liveness_ticked`](DriverCore::liveness_ticked)), for two different
//! reasons: fanotify's unmount emits nothing in band at all, and inotify's
//! in-tree death notice is postponed by every descriptor this driver holds on
//! the root — a sync's admission pins above all, which a stalled write keeps
//! for as long as the stall lasts. The three remaining backends' death signals
//! already lower a terminal `Removed`/`Rescan` through the existing paths with
//! nothing of ours able to hold them back; the tick's role is to bound the
//! latency of the two that cannot say so themselves — a loss-triggered refresh
//! still catches either immediately when one occurs.
//!
//! The same cadence carries a THIRD obligation on both of those profiles, and it
//! is the one below: the sample that re-stats the root reads the mount table
//! under it too (#74).
//!
//! # A mount change UNDER the root (#74)
//!
//! A mount that departs below a watched root emits no kernel signal, on any
//! backend, because there is no such signal to emit: a lazy unmount (`umount -l`)
//! detaches the tree and the per-directory watches inside it simply stop meaning
//! anything — no `IN_UNMOUNT`, no `IN_IGNORED`, nothing. The mirror case is as
//! silent and as consequential: a mount that ARRIVES hides ground this scope
//! already enumerated and armed, and one that is REPLACED at an unchanged path
//! does both at once. In every case the coverage the scope believes it holds
//! stops describing the tree that is there.
//!
//! The only witness is the table itself, so the periodic sample is the mechanism
//! and the rule over it is deliberately COARSE:
//!
//! > On ANY difference between two authoritative samples of the rows strictly
//! > under the root, cover the WHOLE root once.
//!
//! The fingerprint is the sorted multiset of
//! [`MountRow`](crate::os::MountRow)s — `(location, dev, mnt_id, parent_id,
//! mnt_id_unique)` — and the cover fires when the rows differ, when the root's own
//! incarnation moved (the frame-adoption legs above), or, on a kernel whose rows
//! carry no never-recycled id, when the mount-namespace transition count moved
//! since the last sample. That last clause is the conservative one: a legacy mount
//! id is allocated lowest-free, so a departure and an arrival at one location
//! inside a single interval can leave two samples comparing EQUAL, and a
//! transition the host counted is the only fact left that can contradict them. It
//! over-fires on unrelated namespace churn, and that is the accepted price of
//! never being silent.
//!
//! What a cover IS depends only on how the profile SEES the tree.
//! [`cover_whole_root`](DriverCore::cover_whole_root) is `on_overflow(Scope::Root)`
//! on every profile but one — the Monitor re-enumerates and re-arms, the consumer
//! gets one `Rescan` at the root. Fanotify is the exception, because its sight is
//! a FID map seeded by a walk that stops at every mount boundary: ground a
//! departed mount revealed was never walked, so the map holds no handle there and
//! events under it decode as outside-root. That scope reseeds FIRST
//! ([`Effect::RecoverRoot`], one walk in flight per scope, epoch-stamped so a
//! reply from a world that ended is dropped) and covers on the reseed's
//! completion — telling the consumer to re-read a subtree the source is still
//! blind to would buy it one listing and then permanent silence.
//!
//! # Why it is coarse
//!
//! There is no census of the boundaries under a root and no ledger keyed on them.
//! A located cover — "the mount at `sub/vol` went away" — needs both: a record of
//! every boundary the crawl declined at, kept correct across renames of the
//! directories above it, bounded against a namespace that can hold thousands of
//! rows, and reconciled with every arrival that lands between two samples. All of
//! that machinery exists to compute a LOCATION, and a `Rescan` is a coverage
//! statement rather than a delivery: the consumer answers a located one by
//! re-reading that subtree and answers this one by re-reading the root, which it
//! was going to do anyway for anything that moved near the top.
//!
//! So the proof is one paragraph, and it is the reason for the shape. Every mount
//! transition under the root changes the table. Every table change fires the
//! cover. There is no third case to reason about, no state to keep consistent,
//! and nothing that can drift out of agreement with the kernel — the price being
//! one whole-root re-read per interval in which the table moved.

use std::{
  collections::{BTreeMap, BTreeSet, VecDeque},
  num::NonZeroU64,
  path::{Path, PathBuf},
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};

#[cfg(feature = "sync")]
use tributary_proto::ChangeId;
use tributary_proto::{
  ArmAttempt, Capabilities, Change, ChangeKind, DirEntry, EnumerateResult, Evidence, FileKind,
  Identity, Instant, IoClass, Location, Monitor, MoveCookie, OsRecord, RecordKind, ReqId, Scope,
  ScopeId, Segment, StatEntry, StatResult, SubtreeScope, WatchError, WatchId,
  glob::Globs,
  monitor::{CoverageWorkEpoch, RecordOutcome},
};

// Named only by the test-only interest shorthand below (and, through
// `use super::*`, by the cells themselves); the production entry takes a whole
// `RootOptions`.
#[cfg(test)]
use tributary_proto::Interest;

use crate::{
  error::WatchRootError,
  options::RootOptions,
  os::{
    BackendKind, BatchPayload, FsEventFlags, RawOsEvent, RootIdentity, RootMeta, RootRecovery,
    ScopeFrame, SourceError, SourceEvent,
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
  /// The mount rows observed strictly under the root.
  ///
  /// Identity-bearing where the host can answer it
  /// ([`MountRow`](crate::os::MountRow)), which is what lets two successive
  /// readings be compared for a mount REPLACED at an unchanged path — a change
  /// in `(mnt_id, parent_id, dev, mnt_id_unique)` and in nothing else, which a
  /// paths-only read cannot express at all.
  pub(crate) mounts: Vec<crate::os::MountRow>,
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
  /// (a stale snapshot's frame is as suspect as its mount table). `None` (a
  /// non-Linux/fake source, or a kernel below every id oracle, that reports no
  /// frame) leaves the captured value intact — a transient read miss never drops a
  /// known frame.
  pub(crate) root_mnt_id: Option<u64>,
  /// WHICH INCARNATION of a mount the root was on when this refresh read it, where
  /// the host can answer that at all ([`RootIncarnation`](crate::os::RootIncarnation)).
  ///
  /// [`root_mnt_id`](Self::root_mnt_id) is a value observed at one instant, and an
  /// unmount plus a remount between two refreshes hands the new mount the id the
  /// old one freed — so an id that MATCHES across the gap is not evidence the root
  /// stayed put. This is the fact that is, and the scope's frame moves on it.
  ///
  /// `None` where nothing could answer: a host with no unique mount id and no
  /// namespace generation, or a window this refresh could not prove quiet (a
  /// token built out of two reads that straddle a transition would read as
  /// continuity on the very next refresh). A `None` compares against nothing and
  /// leaves the scope's last PROVEN token standing — the frame then moves on the
  /// mount-id comparison alone, exactly as it did before this existed.
  pub(crate) root_incarnation: Option<crate::os::RootIncarnation>,
  /// The mount-namespace TRANSITION COUNT this refresh observed, where the host
  /// keeps one (`ns->event`, read through the same held fd the table came from);
  /// `None` off Linux and on every fake.
  ///
  /// [`root_incarnation`](Self::root_incarnation) already carries this number on
  /// a host with no unique mount id, but it carries it INSTEAD of the unique id,
  /// and the coarse cover needs both at once: on a kernel that answers unique ids
  /// the root's token is `Unique`, and the transition count is then the only
  /// thing left that can speak for a sample whose rows carry no unique id of
  /// their own (an empty table, or a per-row `statx` that failed). Kept as its
  /// own field rather than derived, so the rule reads what it means.
  pub(crate) namespace_transitions: Option<u64>,
}

/// Why one mount refresh is being armed.
///
/// The two causes agree completely when nothing is in flight — both arm one
/// read. They differ ONLY in what they say about a refresh that IS in flight,
/// because they carry opposite evidence about its snapshot:
///
/// - an **invalidating** arming happened BECAUSE the world moved (a loss window,
///   a root replace or widen, a birth), so the in-flight read may have sampled
///   the far side of that transition — it is suspect, and
///   [`refresh_stale`](ScopeState::refresh_stale) condemns it.
/// - a **periodic** arming is pure cadence: nothing happened. The in-flight
///   snapshot is exactly as good as the one this tick would take, so the tick
///   coalesces onto it and lets it PUBLISH.
///
/// Conflating the two starves everything that publishes past
/// [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed)'s stale gate — the
/// mount-table install and the frame adoption. With refresh latency at or past
/// the interval (a backed-up blocking pool, or simply a short interval — any
/// nonzero duration is configurable), a tick that stale-marked would condemn
/// EVERY completion in turn: each is discarded and re-armed, and the next tick
/// condemns the next read. The root-death check survives that only because it is
/// evaluated BEFORE the gate; everything else sits behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshCause {
  /// The world moved under the in-flight read: a loss signal, a root replace or
  /// widen, or the birth arming. Condemns an outstanding snapshot.
  Invalidating,
  /// The periodic tick came due. Coalesces onto an outstanding read without
  /// condemning it — and without ever CLEARING a condemnation an invalidating
  /// arming already made.
  Periodic,
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
    /// The scope whose ground this path names.
    scope: ScopeId,
    /// The root incarnation this stat belongs to
    /// ([`incarnation`](ScopeState::incarnation)).
    incarnation: u64,
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
    /// The root incarnation this arm belongs to
    /// ([`incarnation`](ScopeState::incarnation)).
    incarnation: u64,
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
    /// The scope's descent frame at the moment the arm was issued. The executor
    /// stats the object it opened and REFUSES the arm when the landing sits
    /// across this frame ([`ScopeFrame::crossed_by`]) — the prevention half of
    /// the mount-boundary design, and the only one that runs on an arm the
    /// enumerate fence never saw.
    ///
    /// Not the same guard as [`expected`](Self::AddWatch::expected), and it must
    /// not be folded into it: `expected` is `None` for exactly the arms that
    /// need this most (inotify's `Created` carries no identity), so a frame
    /// check gated on a known object would be gated off precisely where the
    /// boundary gets crossed.
    frame: ScopeFrame,
  },
  /// Remove one per-directory kernel watch the Monitor dropped. Fire-and-
  /// forget: the Monitor's unwatch carries no result contract, and a wd the
  /// removal never reached is reclaimed when the scope's stream closes.
  RemoveWatch {
    /// The scope whose live source executes the disarm.
    scope: ScopeId,
    /// The root incarnation this disarm belongs to
    /// ([`incarnation`](ScopeState::incarnation)).
    incarnation: u64,
    /// The Monitor watch being disarmed.
    watch: WatchId,
  },
  /// Read one directory (blocking readdir + per-entry stat), reporting the
  /// raw listing through [`on_enumerated`](DriverCore::on_enumerated).
  Enumerate {
    /// The scope whose ground this directory belongs to.
    scope: ScopeId,
    /// The root incarnation this listing belongs to
    /// ([`incarnation`](ScopeState::incarnation)).
    incarnation: u64,
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
    /// The root incarnation this refresh belongs to
    /// ([`incarnation`](ScopeState::incarnation)). A refresh armed against a
    /// world a commit has since retired is dropped at the poll site; path
    /// equality is never the test, because a same-path replacement leaves the
    /// root bytes equal ([`effect_is_current`](DriverCore::effect_is_current)).
    incarnation: u64,
    /// The canonical root to enumerate mounts under.
    root: Arc<PathBuf>,
  },
  /// Re-seed a kernel-recursive fanotify scope's FID map over the WHOLE root,
  /// then feed the outcome back through
  /// [`on_root_recovered`](DriverCore::on_root_recovered).
  ///
  /// The one asynchronous round trip in the mount-change cover (#74), and it
  /// exists because a fanotify source's sight is a MAP rather than a mark. The
  /// seed walk stops at every mount boundary, so ground a departed mount had
  /// been covering was never walked: the map holds no handle for any directory
  /// there, and every later event under it decodes as outside-root. Telling the
  /// consumer to re-read first would hand it a listing the source is still blind
  /// to — it would re-enumerate the revealed subtree, see it, and then hear
  /// nothing more about it. So the reseed runs FIRST and the `Rescan` is emitted
  /// on its completion.
  ///
  /// `epoch` is what makes the reply judgeable. The walk runs on the blocking
  /// pool while the world can move under it (a root replace, a widen), so the
  /// core stamps each request and drops a reply whose stamp is no longer the
  /// scope's current one. One recovery is in flight per scope at a time; a fire
  /// during one is coalesced onto a single follow-up
  /// ([`ScopeState::recovery_dirty`]).
  RecoverRoot {
    /// The scope whose whole-root sight is being rebuilt.
    scope: ScopeId,
    /// The stamp the reply must still carry to be acted on.
    epoch: u64,
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

/// One scope's BARRIER EPOCH: a monotone count of the coverage transitions that
/// have passed one of the barrier funnels since the scope was born.
///
/// A sync barrier is dispatched under one of these and certifies delivery only
/// within it. A coverage transition that touches the ground the barrier depends
/// on, while the barrier is live, retires the barrier — dominated by the located
/// `Rescan` that transition stands — never as a certificate.
///
/// Advanced from every funnel ([`barrier_moved`](DriverCore::barrier_moved)) and
/// nowhere else. Anything that comes to move a scope's coverage owes its funnel a
/// call there, or a barrier stamped with this epoch would certify over exactly
/// the window the new transition opened.
///
/// NOTHING in production compares one. It is the stamp a dispatched obligation
/// records and the witness a cell reads — a cell proves a funnel bumped by
/// watching the stamp move — while the decision "this barrier is dominated" is
/// carried by the [`BarrierMove`] the same funnel records, so there is one
/// representation of that fact rather than two.
///
/// Opaque for the reason [`CoverageWorkEpoch`](tributary_proto::monitor::CoverageWorkEpoch)
/// is: only [`barrier_epoch`](DriverCore::barrier_epoch) mints one and the count
/// itself is never handed out, so the only way to name the epoch a scope reads
/// NOW is to ask the core that owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BarrierEpoch(u64);

impl BarrierEpoch {
  /// The never-bumped floor a scope is born at.
  const BIRTH: Self = Self(0);

  /// Counts one coverage transition through a funnel.
  fn advance(&mut self) {
    self.0 += 1;
  }
}

/// The ground one [`BarrierMove`] touched — what decides which obligations it
/// retires.
///
/// Retirement is LOCATION-SCOPED: an obligation retires when its cookie
/// directory INTERSECTS the move's ground (either is a prefix of the other), so
/// a `mkdir` deep in the tree retires only barriers standing on that ground and
/// a busy tree with a stable watch set retires none. A whole-scope move is the
/// wide answer the root transitions carry, and the honest fallback wherever a
/// funnel cannot place its ground.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BarrierLocation {
  /// The whole scope: every obligation of it is on this move's ground.
  Scope,
  /// One located ground, absolute.
  Path(Arc<PathBuf>),
}

impl BarrierLocation {
  /// The ground `path` names within `state`'s scope.
  ///
  /// A path that IS the scope root answers [`Scope`](Self::Scope): a root-located
  /// transition already touches every obligation of the scope, and giving it one
  /// spelling rather than two is what lets two funnels reporting the same root
  /// ground coalesce instead of retiring the same barrier twice.
  fn at(state: &ScopeState, path: Arc<PathBuf>) -> Self {
    match state.root.as_deref() {
      Some(root) if root == path.as_ref() => Self::Scope,
      _ => Self::Path(path),
    }
  }

  /// Whether an obligation whose marker lands in `cover_dir` stands on this
  /// move's ground.
  ///
  /// Intersection in EITHER direction, not containment in one: a move at
  /// `/r/a` touches a barrier at `/r/a/b` (the ground beneath it moved) and a
  /// move at `/r/a/b` touches a barrier at `/r/a` (the ground beneath IT moved,
  /// and the marker's create has to come off a watch on the descent). Testing
  /// one direction only would spare exactly the half whose watch actually
  /// changed. A whole-scope move is on every obligation's ground by
  /// construction.
  #[cfg(feature = "sync")]
  pub(crate) fn intersects(&self, cover_dir: &Path) -> bool {
    match self {
      Self::Scope => true,
      Self::Path(ground) => {
        cover_dir.starts_with(ground.as_path()) || ground.starts_with(cover_dir)
      }
    }
  }
}

/// One entry of the barrier queue: a coverage transition a funnel raised, or a
/// paired DIRECTORY RENAME, which dominates every barrier under its source.
///
/// The two ride ONE queue because they are drained in order at one seam, ahead
/// of every effect. A rename is not a [`Move`](Self::Move) because it carries
/// what no move carries: the DESTINATION, which is where the markers of the
/// obligations it retires now stand and therefore where their covering
/// instruction has to be aimed — a retirement's ordinary `Rescan` stands at the
/// obligation's own recorded ground, which after a rename names a path nothing
/// stands on.
///
/// Recorded in the core (sans-I/O) and drained by the driver with
/// [`take_barrier_events`](DriverCore::take_barrier_events) BEFORE it executes
/// the effect queue — not as an [`Effect`], because an effect cannot purge an
/// emit that precedes it in the same queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BarrierEvent {
  /// A coverage transition; which barriers it retires is the ledger's business.
  Move(BarrierMove),
  /// A DIRECTORY RENAME the Monitor paired inside the scope: every in-pool,
  /// owned and removing obligation standing under `from` is retired
  /// `Dominated` at the drain, and each retirement's domination `Rescan` stands
  /// at the DESTINATION'S PARENT — the ground its marker now stands in.
  ///
  /// Whether a barrier stood under `from` at all is the LEDGER's answer, which
  /// is why this carries the coordinates rather than a verdict: a rename with no
  /// barrier under it retires nothing, stands nothing and advances nothing, so
  /// the rename stays the deliberate non-bump §2.1 makes it.
  Renamed {
    /// The scope whose subtree moved.
    scope: ScopeId,
    /// Where the subtree WAS, absolute: the source slot the Monitor
    /// reconstructed from its live tree at the pairing, joined onto the scope
    /// ROOT — the one anchor no reparent inside the tree can move.
    from: PathBuf,
    /// Where it now is, absolute.
    to: PathBuf,
  },
}

/// One coverage transition a funnel raised while barriers may be live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BarrierMove {
  /// The scope whose coverage moved.
  pub(crate) scope: ScopeId,
  /// The ground it moved on.
  pub(crate) location: BarrierLocation,
  /// Whether the funnel ALREADY stood a located `Rescan` covering that ground.
  ///
  /// A barrier is never retired silently: `SyncOutcome::Dominated` promises the
  /// caller a re-enumeration instruction on its stream, so a retirement under a
  /// move that stood none has to stand one itself. Only the funnels that mint a
  /// `Rescan` of their own report `true` — a child arm, a child drop and the
  /// settle rewind stand nothing by construction.
  pub(crate) rescan_stands: bool,
}

/// How many LOCATED moves one scope may queue between two drains before they
/// fold into a single whole-scope move.
///
/// The queue is drained after every core input, so the ordinary occupancy is one
/// batch's worth; this is the ceiling a burst cannot pass. Folding rather than
/// dropping is what keeps the bound honest — a whole-scope move retires a
/// superset of what the folded ones would have, and owes its own covering
/// `Rescan` — so the queue is bounded by (live scopes × this) entries and never
/// by forgetting a transition.
const MAX_BARRIER_MOVES_PER_SCOPE: usize = 16;

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

/// Why the driver did NOT dispatch a mount refresh the core had armed
/// ([`on_refresh_declined`](DriverCore::on_refresh_declined)).
///
/// The two are not the same fact, and the core answers them differently. One is
/// a coalescing skip over a probe that IS running; the other is a probe that was
/// never sent, so nothing is going to prove this root's liveness — and a scope
/// whose liveness cannot be proven has to say so rather than keep a coverage
/// claim nobody is checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeclineReason {
  /// This scope already has a probe outstanding. A second thread on a root that
  /// has not answered proves nothing, and the running probe's own completion is
  /// the answer that clears the mark — so the tick costs one interval and
  /// nothing else.
  ScopeBusy,
  /// The watcher is at its liveness-probe budget
  /// ([`MAX_LIVENESS_PROBES`](crate::driver::MAX_LIVENESS_PROBES)): every slot is
  /// held by a probe inside a call that may never return, so THIS scope's root is
  /// being watched for death by nothing at all.
  BudgetFull,
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
  /// passed, a grow kickoff coalesced into an in-flight cold read, or an
  /// unanswered classification stat stands the scope's settlement loss.
  /// Coverage may be partial; a covering `Rescan` dominating the gap has been
  /// EMITTED.
  ///
  /// Emitted, and no more than that: this verdict is not a delivery receipt, and
  /// the caller RE-ENUMERATES the retained cover rather than waiting for the
  /// instruction to arrive. A full consumer channel refuses the offer and parks
  /// it (INV-PARK) to be retried behind this answer. A verdict minted on the
  /// CLOSING pass is weaker again — the core is dropped with its effects still
  /// queued, and the one loss source whose cover only a settlement can stand
  /// gets none there at all — which is exactly why the caller re-enumerates
  /// instead. Making the answer wait for the delivery would put a caller's own
  /// reply behind that caller draining its event stream.
  ///
  /// All three sources carry a cover into the verdict. The first IS the
  /// `Rescan`. The second holds the barrier down
  /// ([`Monitor::coverage_settled`](tributary_proto::Monitor::coverage_settled))
  /// until the coalesced read completes, and that completion escalates into one.
  /// The third is the only loss that stands none of its own — the read that
  /// queued the stat reconciled nothing for the slot, and a pure grow stands no
  /// `Rescan` at all — so a LIVE settle observation stands a scope-level one and
  /// holds the tranche for the single flush that offers it, which is the same
  /// best-effort ordering the other two already have (see
  /// [`poll_cover_settlements`](DriverCore::poll_cover_settlements)). The close
  /// pass stands none: no flush follows it.
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

  /// Whether this pass may stand the cover a standing stat loss owes and hold a
  /// licensed tranche for the ONE flush that offers it, so the instruction is
  /// offered before the verdict it covers answers a caller.
  ///
  /// Only the live loop may, and the hold it takes is bounded by the DRIVER: the
  /// driver re-tops on it ([`take_cover_flush_due`](DriverCore::take_cover_flush_due)),
  /// the loop-top flush offers the cover, and the very next observation resolves —
  /// whether that offer was accepted or refused. Nothing here waits on consumer
  /// progress, which a `Degraded` verdict does not promise.
  ///
  /// The close drain neither stands a cover nor holds. It is the last pass there
  /// will ever be, so a held fence would strand its caller's reply forever, and
  /// there is no flush left to carry an instruction anywhere — the drained items'
  /// effects die with the core. It reports the lossy verdict where it stands, and
  /// the caller re-enumerates on it exactly as the contract says.
  const fn orders_stat_cover(self) -> bool {
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

/// Whether the covering `Rescan` a standing stat loss owes one tranche has been
/// stood yet.
///
/// A [`Degraded`](CoverSettle::Degraded) verdict reports that such a `Rescan` was
/// EMITTED, never that the consumer has taken it: the loop-top `try_send` refuses
/// it whenever the channel is full, which parks it as the scope's dominating
/// instruction (INV-PARK), and the caller re-enumerates rather than waiting for
/// it. So the latch records the one fact the verdict rests on — the cover was
/// stood — and nothing about the delivery it does not promise.
///
/// What it still buys is ORDERING, best-effort and bounded by the driver alone:
/// the tranche is held for exactly the ONE re-top whose flush offers the cover
/// ([`take_cover_flush_due`](DriverCore::take_cover_flush_due)), so a consumer
/// with room is instructed before the verdict — exactly as it is for every other
/// `Degraded` producer, whose covers are queued by an earlier pass and flushed at
/// this pass's loop top. A consumer without room is not waited for: the cover is
/// parked (or folded into the instruction already parked) and rides the lane's
/// own delivery retry, behind the verdict.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum StatCover {
  /// No cover has been stood for this tranche.
  #[default]
  Unstood,
  /// Stood: the tranche is held for the single flush that follows and resolves
  /// at the next observation, whatever that flush did with it — accepted,
  /// refused and parked, or (where the lane was ALREADY lagging) folded into the
  /// scope's parked dominating `Rescan` and never separately offered at all.
  ///
  /// Preserved across a PROOF INVALIDATION, which defers the tranche with its
  /// entry — and so this state — intact, so a deferred tranche re-instructs
  /// nobody.
  Stood,
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
/// at the settle observation instead of being remembered here: an unanswered
/// classification stat that stands the scope's settlement loss
/// ([`Monitor::stat_loss_outstanding`], read in
/// [`poll_cover_settlements`](DriverCore::poll_cover_settlements)). An event
/// mark would be spent by the first observation to pass while the slot stayed
/// dark, so the condition is re-read every time a verdict is minted.
///
/// It is also the one source that arrives with NO cover of its own — the two
/// events above are (or produce) the `Rescan` that marks them — so the
/// observation that reads it stands one, and holds the tranche for the single
/// flush that offers it ([`stat_cover`](CoverFence::stat_cover)).
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
  /// Whether the covering `Rescan` a standing stat loss owes has been stood for
  /// the tranche this entry is about to resolve
  /// ([`Monitor::cover_stat_loss`](tributary_proto::Monitor::cover_stat_loss)).
  ///
  /// The latch is what makes the one-flush ordering stand exactly ONE cover per
  /// tranche: it leaves [`Unstood`](StatCover::Unstood) when the cover is stood,
  /// is reset when the tranche is drained, and goes with the entry when the last
  /// pending fence does. Without it a scope whose stat never answers would stand
  /// a fresh cover on every pass and never report the degraded verdict the
  /// standing loss exists to produce; with it a later tranche — resolving under
  /// its own successor proof, over a stretch of the window the earlier cover does
  /// not reach — still stands one of its own.
  stat_cover: StatCover,
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

/// The ordering proof one scope's STAGED adoption markers wait on — the same
/// reader-queue cut [`CutProof`] buys, consumed for the one certifying verdict
/// that used to resolve on the op lane instead.
///
/// # What it is bought for
///
/// A widen's adoption marker is discharged by the chain parent's first complete
/// listing, and the confirming direction of that listing is a claim about an
/// INTERVAL — the splice-to-listing window — read off the interval's end state.
/// That is admissible only if every record which could refute it has already
/// been fed to the Monitor, and the listing's own completion does not establish
/// it: the listing runs on the blocking pool, its completion is reported on the
/// op channel, and the driver polls that channel ahead of the source lane. So
/// the record which refutes the window — the adopted object's own `MoveSelf` —
/// can be committed by the kernel BEFORE the listing and still unread when the
/// listing's verdict runs.
///
/// The reader's pre-reply cut is exactly the missing edge. A control batch
/// requested after the listing is answered only behind a drain of everything the
/// kernel had committed to the instance's queue, forwarded onto the source lane
/// AHEAD of the reply. One scope is one instance is one FIFO queue, so a
/// refuting record committed before the listing is on the lane before that
/// reply, and the choke point's drain feeds it before the seal takes any
/// verdict.
///
/// The interval the claim is about is the ADOPTED OBJECT's occupancy of its
/// slot. A cut orders records, and every reading behind the verdict — the
/// marker's survival, the listing's identity match, the occupancy check — is
/// about an inode, its parent link, and its filesystem. A mount stacked over the
/// slot and unmounted again before the listing disturbs none of those and emits
/// no record for a cut to order, so it leaves the end state reading exactly as
/// the widen left it (see [`Monitor::seal_staged_adoptions`]).
///
/// # Why it is not [`CutProof`]
///
/// Same primitive, different window, and two differences that matter.
///
/// A cover fence's proof is stamped with the scope's coverage-work epoch,
/// because what it must not outlive is the barrier re-opening. A seal's window
/// is pinned by the markers themselves — a staged marker holds
/// [`Monitor::coverage_settled`] down, so the fence's own arming predicate
/// (`barrier_settled`) is false for exactly as long as a seal is owed, and the
/// two can never be offered a cut in the same pass. What a seal must not
/// outlive is the TRANSPORT: a cut taken on a queue the scope no longer reads
/// orders nothing about the one it does. So the latch is stamped with the
/// delivery lane instead, and a lane it does not name answers for nothing.
///
/// And a cover fence's in-flight request licenses its whole tranche including
/// fences opened behind it, because a fence is a question about the window the
/// cut already ordered. A staging is not: a marker staged after the request was
/// committed to had its listing ingested after the cut was requested, so the cut
/// says nothing about it. The reach is therefore compared at the VERDICT
/// ([`licenses_through`](AdoptionSeal::licenses_through)), and a later staging
/// waits for its own successor rather than being swept into a proof that never
/// covered it.
///
/// # Why it cannot strand a scope
///
/// A token stops being provable in exactly four ways, and each of them clears
/// this latch by a different edge:
///
/// - the batch carrying it never proves — it unwound, or its reader died under
///   the current generation. Both fail closed to `on_source_fatal`, whose
///   teardown releases every marker of the scope, so the staged set empties and
///   [`resolve_adoption_seals`](DriverCore::resolve_adoption_seals) drops the
///   entry;
/// - the completion arrives under a generation the scope has swapped away from,
///   so the driver's in-flight mark no longer names it and the proof is dropped
///   silently. The lane stamp catches that with no help from anyone: the latch
///   stops answering the moment the scope's lane moves, and the scope is offered
///   a fresh cut. (The swap also rebinds the root, which releases the markers —
///   so the entry is dropped as well. Two independent escapes, deliberately, for
///   the same reason [`CutProof`] has two.)
/// - the scope is torn down. Its markers die with its tree and the entry is
///   dropped with them;
/// - the batch is still QUEUED when a later request for the same scope discards
///   it ([`queue_cut_proof`](crate::driver::queue_cut_proof)'s coalesce rule).
///   Only two things mint a later request here: this latch itself, which does so
///   only after rebuilding on a moved lane and so no longer names the discarded
///   token, and a cover fence, which is offered a cut only once every marker of
///   the scope has been released — the very condition that drops this entry.
///
/// What it CAN do is defer: a scope whose source lane never finishes draining
/// holds its seal over pass after pass. That is the deferral a cover fence
/// already carries, bounded per pass by the drain's own per-lane budget, and the
/// marker keeps every one of its other exits — the spend, the retry cap, the
/// walk, the rebind — throughout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct AdoptionSeal {
  /// The delivery lane everything below was taken on. A latch read under any
  /// other lane answers for nothing and is rebuilt.
  lane: u64,
  /// The staging generation an answered cut has proven through: every marker
  /// staged at or before it may be sealed. `None` until one lands. Kept as a
  /// PREFIX rather than consumed, so a seal the drain defers costs no second
  /// round trip.
  proven: Option<u64>,
  /// The request out, and the newest staging it will license. At most one is
  /// ever out: a staging that opens behind it waits for a successor rather than
  /// displacing it, so a scope widening steadily cannot cancel every request
  /// before its reply lands.
  in_flight: Option<SealRequest>,
}

/// A seal cut that has been asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SealRequest {
  /// Identifies the request, so only the completion of the batch that actually
  /// carried it can close this one.
  token: u64,
  /// The staging generation this request's answer earns — the newest staging at
  /// the instant it was committed to, never the newest when the reply lands.
  reach: u64,
}

impl AdoptionSeal {
  /// A latch on `lane` with nothing proven and nothing out.
  const fn new(lane: u64) -> Self {
    Self {
      lane,
      proven: None,
      in_flight: None,
    }
  }

  /// Whether this latch already owes no fresh cut for a scope on `lane` whose
  /// newest staging is `high_water`.
  ///
  /// A request still out answers whatever has staged behind it — asking again
  /// would only orphan it, and the successor the later staging needs is offered
  /// the moment this one lands. A proven prefix answers only as far as it
  /// reaches. Anything stamped on another lane answers for nothing at all,
  /// request included: its reply can only ever prove an ordering of a queue the
  /// scope has stopped reading.
  const fn answers_for(self, lane: u64, high_water: u64) -> bool {
    if self.lane != lane {
      return false;
    }
    if self.in_flight.is_some() {
      return true;
    }
    match self.proven {
      Some(proven) => proven >= high_water,
      None => false,
    }
  }

  /// The staging generation a CONFIRM is licensed through on `lane`, which the
  /// caller must read off the scope's CURRENT transport rather than off this
  /// latch — a stamp compared against itself proves nothing.
  ///
  /// Only the proven prefix licenses anything: a request still out has ordered
  /// nothing yet, and a prefix earned on another lane orders nothing here.
  const fn licenses_through(self, lane: u64) -> Option<u64> {
    match self.proven {
      Some(proven) if self.lane == lane => Some(proven),
      _ => None,
    }
  }

  /// Puts `token`'s request out for the stagings through `reach`. The proven
  /// prefix is left as it stands — a successor is a claim about stagings this
  /// latch has not ordered yet, never evidence against the ones it has.
  const fn latch(&mut self, token: u64, reach: u64) {
    self.in_flight = Some(SealRequest { token, reach });
  }

  /// Retires the request in flight into the proven prefix — but only for the
  /// token actually out, so every other completion is inert.
  fn prove(&mut self, token: u64) {
    let Some(request) = self.in_flight.take_if(|request| request.token == token) else {
      return;
    };
    self.proven = Some(match self.proven {
      Some(proven) => proven.max(request.reach),
      None => request.reach,
    });
  }
}

/// A planned Monitor input, compiled from one raw event.
#[derive(Debug)]
enum Planned {
  /// Feed a normalized record.
  Rec(OsRecord),
  /// Feed an overflow for a scope slice.
  Over(Scope),
  /// Stand the located `Rescan` a DOMINATED sync barrier is retired with — the
  /// same instruction [`Over`](Self::Over) produces, minted as a DOMINATION and
  /// not as a loss.
  ///
  /// The distinction exists because the two say different things about the
  /// scope's COVERAGE. An overflow says the watched world may have moved
  /// unobserved: the cover fence's window is lossy, the scope's optimistic
  /// coverage claim may span a hole and is degraded to the empty cover with the
  /// settle floor folded down beside it, and the Monitor recovers the watch set
  /// for the slice. A domination says only that one barrier's caller must
  /// re-read: the retirement's `Rescan` is "re-read, your barrier is
  /// dominated", never a claim about the scope's coverage — so unlike an
  /// overflow it must NOT mark the fence lossy and must NOT rewind the settle
  /// floor. Marking that fence lossy made a shrink DEGRADE and rewind its own
  /// claim, and the recovery re-armed the very ground the shrink had just
  /// pruned — the cover a caller asked for undone by the instruction telling
  /// another caller its barrier had moved.
  ///
  /// This holds UNCONDITIONALLY, on every funnel that retires this way
  /// (`rescan_stands: false`) — including the two that are themselves
  /// loss-originated: funnel 5a's refresh-world-stale path and funnel 8's
  /// lossy settle rewind. A retirement stood there is still only "re-read",
  /// never "nothing about the window was in doubt" — the window's own loss IS
  /// in doubt, and it is signalled by that path's own machinery, not by this
  /// `Rescan`: 5a's loss surfaces at the refresh's later verdict, 8's at the
  /// settle it already made lossy before this retirement ever ran. Exempting
  /// the retirement's own instruction from a SECOND, redundant lossy mark
  /// removes nothing either of them established.
  ///
  /// Only the RETIREMENT's own `Rescan` is stood this way
  /// ([`stand_covering_rescan`](DriverCore::stand_covering_rescan), the funnels
  /// that stand none of their own). Every other funnel stands its `Rescan`
  /// through [`Over`](Self::Over) and stays lossy — those ARE losses.
  #[cfg(feature = "sync")]
  Dominated(Scope),
}

#[cfg(feature = "sync")]
impl Planned {
  /// Re-flavours a planned covering `Rescan` as a DOMINATION rather than a loss
  /// ([`Dominated`](Self::Dominated)).
  ///
  /// [`covering_rescan`](DriverCore::covering_rescan) — the one producer a
  /// retirement stands its instruction through — plans nothing but an
  /// [`Over`](Self::Over), so there is no other flavour to carry here.
  fn into_domination(self) -> Self {
    match self {
      Self::Over(target) => Self::Dominated(target),
      other => other,
    }
  }
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
  /// The move cookies whose consumption RIDES THIS BATCH: a rename whose
  /// destination the prune seat covers, judged by the fence on a profile that
  /// classifies the whole read before feeding any of it, so the source half the
  /// consumption names is not parked yet and cannot be taken at the fence. They
  /// are consumed in [`settle`](DriverCore::settle), immediately after this
  /// batch's records have been fed — the settlement that parks the half — and
  /// nowhere later. A profile that answers [`feeds_at_classify`] takes its halves
  /// at the fence and leaves this empty.
  ///
  /// Bounded by the batch's own item count: at most one entry per widened
  /// cookie-carrying `MovedTo`, and each compiled item plans at most one of those
  /// (a rename item's lowering plans the `MovedFrom`/`MovedTo` pair together).
  /// `trailing` and the late-born repairs are located instructions, which carry no
  /// cookie at all. So the batch's transport permit bounds this exactly as it
  /// bounds the items.
  deferred_consumptions: Vec<MoveCookie>,
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
    /// The content and metadata facts the word carried alongside the rename.
    /// A surviving object owes them as ONE grounded record beside the move
    /// half, carrying every fact so either subscription admits it; an empty
    /// set owes nothing.
    content: Evidence,
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
  /// The scope's RETIREMENT interlock: the flag every dispatched cookie write of
  /// this scope re-reads as it hands its file over, minted by the driver when the
  /// scope goes live and cloned in here
  /// ([`bind_retiring`](DriverCore::bind_retiring)).
  ///
  /// The core stores `true` into it BEFORE it removes the scope's root-watch
  /// mapping or its state, so the store is the irrevocable transition point:
  /// a claim on another OS thread cannot observe a live flag for a scope that
  /// is gone. The removal happens on the driver thread and a write claims on
  /// another, and no yield separates the two. An atomic store is not I/O, so
  /// holding it here leaves the core sans-I/O.
  ///
  /// `None` for a scope that never went live — it has no dispatchable write to
  /// revoke, and its stream teardown publishes for it anyway.
  retiring: Option<Arc<AtomicBool>>,
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
  /// Which WORLD this scope watches now: a monotone count of the commits that
  /// have replaced or widened its root.
  ///
  /// Every queued effect of a scope belongs to one incarnation. A commit that
  /// retires the root leaves the queue holding obligations armed against ground
  /// the scope no longer watches, and a syscall that blocks on a retired mount
  /// wedges the replacement's reader — so each scope-bound effect that touches
  /// the ground is stamped with this when it is queued, and the driver drops a
  /// stale-stamped one at the poll site before any syscall, without touching the
  /// scope's pending flags ([`effect_is_current`](DriverCore::effect_is_current)).
  ///
  /// The stamp is the INVARIANT at that single reader, not the load-bearing
  /// belt: `on_root_replaced` purges the scope's queued ground-touching effects
  /// before it queues the live world's own, and every producer that can run after
  /// a commit is lane-, tag- or attempt-fenced, so no stale effect should reach
  /// the poll site at all. The purge is a discipline every future world-swapping
  /// site has to remember; this holds for a site nobody remembered, and its reach
  /// does not end at the queue.
  incarnation: u64,
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
  /// it (a non-Linux/fake source, or a kernel below every id oracle), and then the
  /// device check governs alone — the honest degrade.
  root_mnt_id: Option<u64>,
  /// The last PROVEN incarnation token for the mount
  /// [`root_mnt_id`](Self::root_mnt_id) names — what makes a frame move
  /// observable when the id did not change.
  ///
  /// Overwritten only by a refresh that answered one, so an unprovable window
  /// leaves the last proven token to be compared against, rather than a token
  /// that would silently agree with whatever comes next. `None` until the first
  /// refresh that can answer, and forever on a host that answers none.
  root_incarnation: Option<crate::os::RootIncarnation>,
  /// The root object's identity, captured at the spawn barrier. The mount
  /// refresh re-stats the root and compares against this: a `Missing` or
  /// mismatched read is a root death, lowered through the same self-event path
  /// a `RootChanged` probe uses (kernel-recursive backends have no in-tree
  /// unmount signal, so the refresh cadence is their root-liveness check).
  /// `None` for a scope whose barrier read no identity (off-unix fakes).
  identity: Option<RootIdentity>,
  /// The AUTHORITATIVE mount table's locations under the root, as of the last
  /// read that could take one — the REPLACEABLE half of the device-trust veto.
  ///
  /// Every row here came from one snapshot, and the next authoritative snapshot
  /// replaces the whole vector rather than unioning onto it
  /// ([`install_mount_table`]). It used to union, on the argument that absence
  /// from a table must never GRANT trust — but the two components below were
  /// conflated then, and the union was what actually leaked: every mountpoint a
  /// host ever presented stayed here for the life of the scope, so a long-lived
  /// scope on a container host retained one `PathBuf` per HISTORICAL mount and
  /// paid a linear scan against that history on every refresh. Unbounded
  /// residency is not a safe direction, it is a leak wearing one.
  ///
  /// Replacement is sound because the reads are SERIALIZED — [`arm_refresh`] lets
  /// at most one be outstanding, so snapshot N+1 is read after N landed — and a
  /// stale one publishes no table at all. A row absent from an authoritative read
  /// is therefore a mount the host says is gone, which is exactly the fact that
  /// makes the path root-device again. What replacement must NOT touch is a
  /// prefix learned somewhere OTHER than a table snapshot, and that is why those
  /// live in [`learned_mounts`](Self::learned_mounts) instead.
  ///
  /// Tiny in practice, so a linear scan beats indexing.
  mount_table: Vec<PathBuf>,
  /// Foreign-device prefixes this scope learned from something OTHER than a mount
  /// table read — the INDEPENDENT half of the veto, and the one no snapshot may
  /// remove.
  ///
  /// Two writers: [`apply_mount_add`] (an in-band `Mount` flag word) and
  /// [`learn_device`] (a probe that read a foreign device at a path). Neither is a
  /// mount-table row: the first can describe a mount that arrived AFTER the
  /// snapshot in flight was read, and the second is a path that may sit
  /// arbitrarily deep inside one. A table install that dropped either would
  /// re-trust a subtree this scope has direct evidence is foreign.
  ///
  /// So the lifecycle is evidence-backed in both directions, and only in both
  /// directions: an entry enters on an observation and leaves ONLY on the in-band
  /// unmount word that proves its mount is gone (`deferred_unmounts`, applied at
  /// [`settle`](DriverCore::settle)) or on a world swap, which retires the whole
  /// world the prefix described. A cadence never removes one.
  learned_mounts: Vec<PathBuf>,
  /// Whether [`mount_table`](Self::mount_table) is backed by an authoritative
  /// read of the live mount table (the spawn seed, or a post-loss refresh).
  /// Without it, a path not covered by a known mount prefix proves nothing (the
  /// table is blind), so event-side device trust is refused. Revoked by every
  /// loss signal — a dropped window may have carried a mount transition.
  mounts_authoritative: bool,
  /// The last AUTHORITATIVE sample's rows strictly under the root, SORTED — the
  /// fingerprint the coarse mount-change cover compares each new sample against
  /// (#74; see the module doc's "A mount change under the root" section).
  ///
  /// Whole [`MountRow`](crate::os::MountRow)s rather than locations, because the
  /// change this exists to see is often only an identity: a `mount --move` and a
  /// same-path replacement both leave the LOCATION set untouched. Sorted on
  /// install so the comparison is order-insensitive — mountinfo's row order is
  /// the kernel's list order, which a mount elsewhere can permute without
  /// anything under this root having changed.
  ///
  /// `None` until the first authoritative sample of this world, which therefore
  /// only INSTALLS: registration's own crawl already covered the tree, so the
  /// birth refresh has nothing to cover. A world swap resets it to `None` for the
  /// same reason.
  table_fingerprint: Option<Vec<crate::os::MountRow>>,
  /// The mount-namespace transition count the last authoritative sample carried
  /// ([`MountRefresh::namespace_transitions`]), or `None` where the host answers
  /// none.
  ///
  /// Read ONLY where the sample carries no per-row unique mount ids, and then it
  /// is the conservative rule that keeps the cover honest on a kernel whose ids
  /// recycle: a mount that departs and one that arrives at the same location
  /// inside one refresh interval can hand the newcomer the freed id, leaving two
  /// samples that compare EQUAL across a replacement. A transition the host
  /// counted is the fact the rows could not carry.
  namespace_transitions_seen: Option<u64>,
  /// The stamp on this scope's current whole-root recovery
  /// ([`Effect::RecoverRoot`]) — bumped per request and by every world swap, so
  /// a reply from a world that ended is dropped rather than acted on.
  recovery_epoch: u64,
  /// A [`Effect::RecoverRoot`] is outstanding: further fires coalesce onto
  /// [`recovery_dirty`](Self::recovery_dirty) instead of stacking reseed walks.
  recovery_in_flight: bool,
  /// A fire landed while a recovery was in flight. The in-flight walk may have
  /// been mid-descent when the table moved again, so its map cannot be trusted to
  /// cover the newer change: exactly one more recovery runs when this one lands,
  /// however many fires arrived meanwhile.
  recovery_dirty: bool,
  /// An [`Effect::RefreshMounts`] is outstanding; repeated loss signals
  /// coalesce onto it instead of stacking effects.
  refresh_pending: bool,
  /// An INVALIDATING arming ([`RefreshCause::Invalidating`] — a loss signal, or
  /// a world swap's own re-arm) landed while a refresh was in flight: that
  /// snapshot may predate the newly-lost window, so its result is discarded and
  /// one more refresh re-arms.
  ///
  /// The periodic tick pointedly does NOT set it. A tick carries no evidence
  /// against the in-flight snapshot — it is a cadence, not a transition — and a
  /// tick that condemned it would starve every publication behind
  /// [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed)'s stale gate for
  /// as long as refresh latency stayed at or past the interval.
  refresh_stale: bool,
  /// The ONE watch-set recovery a probe-BUDGET episode owes, already made: a
  /// refresh this scope armed was declined because every liveness-probe slot in
  /// the watcher was held ([`DeclineReason::BudgetFull`]), and the covering
  /// `Rescan` for that decline was minted through the Monitor's overflow path,
  /// which reconciles the watch set along with it.
  ///
  /// Once per EPISODE, because the reconcile is the expensive half and a decline
  /// is not what makes it necessary. On a binding-re-proving profile it bumps
  /// the loss generation, reinstalls the root and re-proves every retained
  /// descendant under it; a second one per liveness interval invalidates the
  /// generation the first is still arming under, so a large tree restarts its
  /// reproof for as long as the saturation lasts and never settles. A declined
  /// probe read nothing and dropped nothing: what it failed to establish is the
  /// ROOT's liveness, which no re-add establishes either.
  ///
  /// Cleared by a refresh of this scope that actually completes — the moment a
  /// probe answers, the episode is over and a later decline opens a new one.
  budget_recovered: bool,
  /// A probe-BUDGET report this scope has not yet handed the consumer: the
  /// covering `Rescan` for a [`BudgetFull`](DeclineReason::BudgetFull) decline
  /// was queued and is still owed.
  ///
  /// It bounds the RATE of the report, never the number of reports. An EVENT IS
  /// NOT A STATE: a `Rescan` is a point-in-time instruction to re-enumerate,
  /// which a subscriber discharges by re-enumerating, and nothing on this
  /// crate's surface lets one stand for "and keep re-checking". So a root that
  /// dies quietly after the first `Rescan` must still be reported — and under a
  /// saturated budget it is a root whose scope can never dispatch the probe that
  /// would prove it alive. Every later tick refused `BudgetFull` therefore
  /// reports again, and the liveness interval — which the consumer chose — is
  /// what bounds the rate.
  ///
  /// Cleared at this scope's next accepted delivery
  /// ([`on_delivery`](DriverCore::on_delivery)), which is that covering `Rescan`
  /// itself: the decline purges everything this scope had queued before minting
  /// the instruction, so nothing of this scope's stands ahead of it. A `Rescan`
  /// still queued is not doubled — the tick that finds this latch set stands no
  /// second instruction, and records only the window it could not prove.
  budget_report_owed: bool,
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
  /// When this scope's root is next re-stat'd for liveness, for a tick-armed
  /// backend (fanotify, inotify — see [`liveness_ticked`](DriverCore::liveness_ticked))
  /// under a non-zero interval.
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
  /// The [`ChangeId`]s of the DOMINATION `Rescan`s this scope's barrier
  /// retirements stood ([`Planned::Dominated`]) and the routing seat has not
  /// reached yet — each read once by [`route_event`](DriverCore::route_event)
  /// to exempt exactly that change from the lossy-window handling (the fence
  /// mark, the coverage degrade and the settle-floor fold) and removed as it is
  /// read.
  ///
  /// Keyed on the change's own id rather than on a "a domination is in flight"
  /// flag, because ids are unique and never reused: an entry no routing pass
  /// ever matches is inert, and every `Rescan` the scope produces for any other
  /// reason is a loss the seat handles as one.
  ///
  /// A SET and not one slot, so the exemption does not depend on WHEN the
  /// instruction is routed. [`stand_covering_rescan`](DriverCore::stand_covering_rescan)
  /// drains the Monitor on its way out, so today each retirement's `Rescan` is
  /// routed before the next retirement of the same drain stands one — but a
  /// drain stands one retirement per obligation the move retired, and a
  /// whole-scope move retires every obligation of the scope. One slot is
  /// correct only for as long as that immediate drain holds: the moment two of
  /// them are in flight at once, it keeps the last and lets every earlier
  /// domination route as the loss it is not, marking the fence lossy and
  /// re-arming the very settle rewind that stood the retirement. Bounded by the
  /// obligations a scope can hold: an entry is removed by the routing pass of
  /// the change it names, and every route consumes it — including
  /// [`route_event`](DriverCore::route_event)'s never-live return, which would
  /// otherwise skip the read and strand the entry.
  ///
  /// A mint that COALESCED into an identical still-queued instruction reports
  /// [`None`] and adds nothing — that queued change is the earlier mint's and
  /// already carries the earlier mint's entry, so it keeps the flavour the
  /// earlier mint gave it instead of having it taken away.
  #[cfg(feature = "sync")]
  dominating_rescans: BTreeSet<ChangeId>,
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
  /// The root's PRUNED subtrees, compiled once when the root is registered.
  ///
  /// The per-root, glob-shaped half of the common-layer fence: a DIRECTORY whose
  /// root-relative path — or that of any ancestor below the root — matches is
  /// never staged by a listing, never armed, never descended, and nothing at or
  /// under it is delivered. Empty is the common case and short-circuits every
  /// test.
  ///
  /// It speaks for directories ONLY. A pattern is matched against the directory
  /// prefixes of a path, so a plain file whose own name matches stays visible —
  /// narrowing which FILES are delivered is [`include`](Self::include)'s seat,
  /// and conflating the two turns a `**/.*` written to skip dot-directories into
  /// a silent ban on every dotfile in the tree. This driver's own sync cookie is
  /// exempt outright ([`crate::driver::prune_prefixes`]).
  ///
  /// Unlike the watcher-wide [`exclusions`](DriverCore::exclusions) it NEVER
  /// stands down for a backend that enforces exclusions itself: no OS API takes
  /// a glob, so a backend cannot have decided this question at admission (see
  /// [`fence_exclusions`](DriverCore::fence_exclusions)).
  prune: Globs,
  /// The root's INCLUDE seat: `None` — the default — delivers every file, and
  /// `Some` narrows delivery to files whose last location segment (the object's
  /// NAME) matches.
  ///
  /// Purely a DELIVERY gate, applied in [`route_event`](DriverCore::route_event):
  /// it changes no coverage, arms nothing differently and consumes no lag
  /// accounting, so widening it later needs no re-arm. Directories, `Rescan`s and
  /// changes whose object class no source proved always pass — the seat fails
  /// OPEN, because a folder the consumer never hears about is a hole in its view
  /// while an extra event is one it can drop.
  include: Option<Globs>,
  /// The LEAF names of this scope's sync markers that are still pending, each
  /// mapped to the cookie obligation that OWNS it — armed when a `sync` is
  /// admitted ([`DriverCore::arm_sync_marker`]) and released when that
  /// obligation reaches its typed terminal
  /// ([`DriverCore::release_sync_markers`]).
  ///
  /// The owner is what makes a release safe against name REUSE. A name frees at
  /// its holder's terminal, so a successor sync may be admitted under the very
  /// leaf a retired predecessor is still queueing a release for; keyed by name
  /// alone, that queued release would disarm the successor's live exemption and
  /// hand the seat the one file its barrier waits on. Keyed by the obligation,
  /// the successor's admission takes ownership on insertion and the predecessor's
  /// release finds an owner that is not its own and removes nothing.
  ///
  /// The map is what makes the marker exemption an IDENTITY rather than a claim
  /// about its parent's spelling. Both seats exempt this driver's own cookie
  /// artifact POSITIONALLY ([`crate::driver::is_sync_cookie_artifact_segment`]:
  /// the reserved directory, and the marker standing directly in it), and that
  /// reading is only as stable as the names above the marker. A peer that renames
  /// the cookie directory — or any directory on the way to it — between the
  /// descriptor walk and the create leaves the marker exactly where the walk put
  /// it, wearing a parent the classifier no longer recognizes; a peer that renames
  /// one into pruned ground does the same to the prune half. The seat then takes
  /// the one file a barrier waits on, and the sync waits out its caller's deadline
  /// over a source that did everything right.
  ///
  /// The leaf cannot be mistaken for anybody else's: the name carries the sync's
  /// unpredictable nonce, so a member of this set names THIS watcher's own
  /// in-flight artifact under this root and nothing else. Bounded by the cookie
  /// ledger's own admission caps — one entry per live obligation of this scope —
  /// and EMPTY for every scope that never syncs, which short-circuits both seats.
  markers: BTreeMap<Arc<str>, crate::driver::CookieId>,
  /// This scope's [`BarrierEpoch`] — the stamp a sync barrier is dispatched
  /// under, advanced by every barrier funnel and by nothing else.
  barrier_epoch: BarrierEpoch,
}

/// What the common-layer fence makes of one planned Monitor input
/// ([`fenced`](DriverCore::fenced)).
///
/// Three answers rather than two, because a located over-signal is a RECOVERY
/// instruction and the fence may not take one away without leaving something in
/// its place: a signal whose own leaf a `prune` word covers is re-aimed at the
/// nearest parent the caller still hears about, and only a signal under ground
/// the caller closed is dropped outright.
#[derive(Debug)]
enum Fenced {
  /// Nothing either seat speaks for: the input reaches the Monitor as planned.
  Stands,
  /// Excluded ground, or ground under a pruned ancestor: the input is dropped
  /// and nothing is owed in its place.
  Dropped,
  /// A located over-signal re-aimed above the pruned leaf it named. Fed in the
  /// dropped signal's place, in its position.
  Widened(Planned),
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

/// Why a widen's witnessed window was spent without committing (INV-ROOT) —
/// the diagnostic the fallback carries, mirroring the transport `Fatal`'s
/// carried class. The first two causes are WITNESS verdicts: the window saw
/// something that costs it the proof its own binding is live. The last two are
/// not witnessed at all — they are the commit gate finding the splice
/// unprovable on its face, one because the adopted OBJECT cannot be named and
/// one because the adopted PATH is too deep to prove — but each spends the
/// window and takes the same fallback, so they travel the same channel rather
/// than inventing a parallel one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaintCause {
  /// The reserved root's own death record: `Ignored` (⊇ unmount), `MoveSelf`,
  /// or `DeleteSelf`, attributed to the reserved watch inside the window.
  RootDeath(RecordKind),
  /// A transport loss signal for the scope (overflow, decode loss, budget
  /// refusal) — the window may have lost the death records themselves, so it
  /// can no longer witness their absence.
  Loss,
  /// The OLD root's identity does not fit the Monitor's enumerate-mint space
  /// (a synthesized or unreadable `ino == 0`, or a 128-bit file id past
  /// `u64` — ReFS), so the splice could install no expected object at the
  /// adopted edge and its dark-window tripwire would have nothing to re-prove
  /// against. Not a witness verdict: nothing went wrong in the window, the
  /// commit is simply not provable, and the fallback's fresh spawn barrier
  /// rebuilds the binding without needing the identity at all.
  UnmintableIdentity,
  /// The old root sits more than one segment below the new one, so the splice
  /// would have to mint INTERMEDIATE connectors — unidentified cold nodes whose
  /// own edges no adoption marker names and no read re-proves. A connector could
  /// move out of its slot and back inside the dark window unrecorded, movement
  /// deeper down the chain could go unobserved entirely, and a rename of an
  /// ANCESTOR of the old root emits no `MoveSelf` for the already-watched old
  /// root, so the invalidation that spends a moved adoption's proof never fires;
  /// the single tail marker would confirm regardless.
  /// [`Monitor::widen_root`] therefore serves depth one only. Like
  /// [`UnmintableIdentity`](Self::UnmintableIdentity) this is not a witness
  /// verdict and not a driver bug — the widen was well-formed and the window was
  /// clean, the shape is simply one no proof covers — and the fallback replace
  /// re-establishes the binding over an arbitrarily deep widen without needing a
  /// window proof at all.
  UnprovableChain,
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
  /// The commit is not provable, for one of the [`TaintCause`]s: the
  /// witnessed window tainted (a reserved death record or a scope loss signal
  /// landed between the reservation and this commit, so the binding cannot be
  /// proven live), the old root carried no mintable identity for the
  /// adopted edge's re-proof, or it sat more than one segment down so the
  /// splice's intermediate connector edges would have no proof at all. Core
  /// and Monitor are untouched except that the
  /// spent window is consumed; the caller disarms the pre-armed descriptor
  /// and falls back to the general stream replace, whose spawn barrier
  /// re-establishes the binding from scratch. A LEGITIMATE outcome, never a
  /// driver bug — and because the window is consumed HERE, the caller must
  /// not close it again.
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

  /// This scope's descent frame, as every arm carries it.
  ///
  /// Read LIVE at each emission, never captured once: a same-object re-mount
  /// moves `root_mnt_id` and a replace/widen swaps both halves, and an arm must
  /// be judged against the frame of the world that issued it. Both halves are
  /// `None` before the stream spawns, which is the honest degrade — an arm with
  /// nothing to fence against installs, exactly as [`crosses_mount_boundary`]
  /// declines nothing under an unknown frame.
  const fn frame(&self) -> ScopeFrame {
    ScopeFrame {
      root_dev: self.root_dev,
      root_mnt_id: self.root_mnt_id,
    }
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
  /// Per-scope adoption-seal latch — the ordering proof a STAGED adoption
  /// marker waits on (see [`AdoptionSeal`]). An entry is minted when the scope
  /// is first offered a cut for a staged marker and dropped by
  /// [`resolve_adoption_seals`](Self::resolve_adoption_seals) as soon as the
  /// scope has no staged marker left, so it never outlives the obligation and
  /// never outlives its scope.
  adoption_seals: BTreeMap<ScopeId, AdoptionSeal>,
  /// Fences a scope teardown resolved (always [`CoverSettle::Dead`] — the
  /// terminal `Rescan` covers the caller, and the verdict carries the death
  /// itself because the `TeardownStream` that clears the driver's liveness
  /// maps is only queued at that point), folded into the next
  /// [`poll_cover_settlements`](Self::poll_cover_settlements) so the driver
  /// consumes every resolution at its one loop-top choke point.
  settled_covers: Vec<(FenceId, CoverSettle)>,
  /// Whether a settlement stood a covering `Rescan` and held its tranche for it
  /// (see [`CoverFence::stat_cover`]), so the driver must flush its effects and
  /// resolve again rather than park — the one place a
  /// [`poll_cover_settlements`](Self::poll_cover_settlements) pass leaves work
  /// that no external input will bring it back for. Read and cleared by
  /// [`take_cover_flush_due`](Self::take_cover_flush_due).
  cover_flush_due: bool,
  /// The coverage transitions the barrier funnels have raised, and the paired
  /// directory renames the scopes have learned, since the driver last drained
  /// them ([`take_barrier_events`](Self::take_barrier_events)) — in ONE queue,
  /// because one seam spends both: the retirement each drives has to purge the
  /// retired obligation's already-queued marker emit.
  ///
  /// NOT an [`Effect`], and that placement is the whole of the drain-order fix:
  /// [`drain_monitor`](Self::drain_monitor) routes every change before it
  /// processes any action, so a funnel raised from an action sits BEHIND a
  /// marker emit produced by the same drain. An effect queued behind that emit
  /// could never purge it; a queue the driver drains BEFORE it executes the
  /// effects can.
  ///
  /// The MOVES are bounded by [`MAX_BARRIER_MOVES_PER_SCOPE`] per scope, and
  /// moves naming the same `(scope, location)` between two drains coalesce
  /// rather than stack. A RENAME is never folded and never coalesced away: at
  /// most one is recorded per record the Monitor pairs a directory rename for,
  /// so a scope's renames between two drains are bounded by one batch's records
  /// — the transport's own budget — and dropping one would leave the barriers
  /// its subtree carried away standing on a path nothing stands on.
  barrier_moves: VecDeque<BarrierEvent>,
  /// Every scope this core has ENDED since the driver last drained them
  /// ([`take_ended_scopes`](Self::take_ended_scopes)).
  ///
  /// A terminal transition publishes its interlock at its linearization point,
  /// and a scope ends HERE — at the one site that queues its `TeardownStream` —
  /// not when that effect is later polled. The list rides beside
  /// `barrier_moves` and is taken by the same drain, which runs at every loop
  /// top and before every effect, so the retirement is published in the same
  /// synchronous pass as the input that ended the scope, before any effect and
  /// before the next flush.
  ///
  /// The scope is removed from `scopes` in the same step that records it here,
  /// so it can never be recorded twice.
  ended_scopes: Vec<ScopeId>,
  scope_seq: u64,
  probe_seq: u64,
  fence_seq: u64,
  /// A monotone counter minting move cookies for `FAN_RENAME` pairs. fanotify
  /// reports each rename atomically (both halves in one event), so the cookie
  /// only needs to pair the two records emitted adjacently — a fresh counter
  /// per rename suffices and never clashes across renames.
  cookie_seq: u64,
  /// How often a tick-armed scope (fanotify, inotify) re-stats its root: the
  /// composition's one timer (see the per-backend death-signal table in the
  /// module docs). `Duration::ZERO` disables the tick — only the loss-triggered
  /// refresh then detects a quiet unmount, or a death notice a held descriptor
  /// is postponing. Every other profile ignores it.
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
  /// The EXACT directory leaf this process reserves for its sync cookies — the
  /// one name [`on_set_cover`](Self::on_set_cover) exempts from the shrink.
  ///
  /// It is the exact leaf rather than the classifier
  /// ([`is_sync_cookie_dir_name`](crate::is_sync_cookie_dir_name)) because the
  /// classifier recognizes a whole NAME SPACE — the bare stem and every canonical
  /// `u32` qualifier — and any peer that can create directories under the watched
  /// tree can fill it. Exempting the space would let a covered directory
  /// populated with `…-0`, `…-1`, `…-2` keep one watch descriptor per forged
  /// sibling across every shrink, so the set-cover could be defeated as a
  /// reclamation mechanism until the watch table ran out. Exempting the one leaf
  /// this process would actually write into keeps the bound the exemption claims:
  /// at most ONE extra watch per covered directory, by construction.
  ///
  /// `None` where the platform reserves no stable leaf — Windows mints a fresh
  /// directory name per obligation and never looks one up, so there is no name to
  /// exempt (and its backend is kernel-recursive, which `on_set_cover` refuses
  /// before the rule is ever reached).
  reserved_cookie_dir: Option<Arc<str>>,
  /// Test-only seam for the removal-order cell: invoked with the
  /// scope id, whether `scopes` still holds that scope, and whether
  /// `watch_scopes` still holds its mapping, at the point between the
  /// retirement store and the two removals. No production code installs one.
  #[cfg(test)]
  removal_hook: Option<RemovalHook>,
}

/// A test-only callback slot on [`DriverCore`], run between the retirement
/// store and the two removals it precedes so a cell can observe the
/// transition order directly rather than inferring it from state after the
/// fact. Wrapped so `DriverCore`'s derived `Debug` has something to print.
/// `Send` because `DriverCore` itself must stay `Send`.
#[cfg(test)]
struct RemovalHook(Box<dyn FnMut(ScopeId, bool, bool) + Send>);

#[cfg(test)]
impl std::fmt::Debug for RemovalHook {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("RemovalHook(..)")
  }
}

impl DriverCore {
  /// Builds a core whose Monitor pairs renames within `move_window`, re-stats
  /// each tick-armed scope's root every `root_liveness_interval`
  /// (`Duration::ZERO` disables that tick), and exempts exactly
  /// `reserved_cookie_dir` from a set-cover shrink (see that field for why it is
  /// one leaf and not the reserved name space).
  pub(crate) fn new(
    move_window: Duration,
    root_liveness_interval: Duration,
    reserved_cookie_dir: Option<Arc<str>>,
  ) -> Self {
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
      adoption_seals: BTreeMap::new(),
      settled_covers: Vec::new(),
      cover_flush_due: false,
      barrier_moves: VecDeque::new(),
      ended_scopes: Vec::new(),
      scope_seq: 0,
      probe_seq: 0,
      fence_seq: 0,
      cookie_seq: 0,
      root_liveness_interval,
      exclusions: Vec::new(),
      reserved_cookie_dir,
      #[cfg(test)]
      removal_hook: None,
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

  /// Whether the [`prune`](ScopeState::prune) seat covers `path` — some directory
  /// prefix of it matches.
  ///
  /// The seat's whole definition, the cookie-directory exemption included, lives
  /// in the ONE shared predicate ([`crate::driver::pruned`]), so the core's fence
  /// and the kernel-recursive sources that enforce the seat at their own boundary
  /// cannot drift apart. Here it is only bound to a scope: an unbound root (one
  /// not resolved yet) fails OPEN, exactly as a path outside the root does.
  ///
  /// `directory` is the caller's PROOF that `path`'s own last segment is a
  /// directory, never its suspicion: an unproven class is judged on the
  /// ancestors alone, so nothing this layer cannot classify is silenced by its
  /// own name (see [`crate::driver::prune_prefixes`] for the price of each
  /// direction).
  fn is_pruned(state: &ScopeState, directory: bool, path: &Path) -> bool {
    state
      .root
      .as_deref()
      .is_some_and(|root| crate::driver::pruned(root, &state.prune, directory, path))
  }

  /// Whether `path` lies inside EITHER half of the common-layer fence — the ONE
  /// containment predicate the fence is asked through.
  ///
  /// Two seats, one question: the watcher-wide exclusion covering `path` (an
  /// absolute-path subtree test), or a pruned directory prefix of it (a
  /// root-relative glob test, [`is_pruned`](Self::is_pruned)).
  ///
  /// `exclusions` is whether the EXCLUSION half is live for this scope: it stands
  /// down where the backend decides exclusions at admission
  /// ([`backend_enforces_exclusions`]). The PRUNE half never stands down — no OS
  /// API takes a glob, so no backend can have decided that question already.
  ///
  /// `directory` is the prune half's own question and the exclusion half ignores
  /// it: an exclusion is a literal subtree, so it covers a file inside it exactly
  /// as it covers the directory holding it.
  fn is_fenced(&self, state: &ScopeState, exclusions: bool, directory: bool, path: &Path) -> bool {
    self.excludes(exclusions, path) || Self::is_pruned(state, directory, path)
  }

  /// The EXCLUSION half of [`is_fenced`](Self::is_fenced) alone, for the one
  /// caller that must answer the two halves separately: the record arm of
  /// [`fenced`](Self::fenced), whose marker exemption and rename cover belong to
  /// the prune half and must not reach inside a subtree the caller took out of
  /// the reported world.
  fn excludes(&self, exclusions: bool, path: &Path) -> bool {
    exclusions
      && !self.exclusions.is_empty()
      && crate::driver::cookie_dir_excluded(&self.exclusions, path).is_some()
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
    watch_path(&self.monitor, state, watch)
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
    Self::anchored_at(&self.monitor, state, watch, descent)
  }

  /// [`anchored_path`](Self::anchored_path) for a caller holding the Monitor
  /// rather than the core — the funnel's route, which resolves a paired
  /// rename's two ends from inside the hand-off that reported it. One
  /// resolution, asked from both seats.
  fn anchored_at(
    monitor: &Monitor,
    state: &ScopeState,
    watch: WatchId,
    descent: Option<&Location>,
  ) -> Option<PathBuf> {
    let mut path = watch_path(monitor, state, watch)?;
    for segment in descent.into_iter().flat_map(Location::segments) {
      path.push(segment.as_str());
    }
    Some(path)
  }

  /// Whether `profile` is a backend whose root death cannot be left to its own
  /// signal alone — the gate for the periodic root-liveness tick.
  ///
  /// The per-backend death-signal table (design §7; the module docs restate it):
  ///
  /// | backend | root unmount | root delete/replace in-tree | tick needed |
  /// |---|---|---|---|
  /// | inotify (descending) | `IN_UNMOUNT` + `IN_IGNORED` | `IN_DELETE_SELF`/`IN_MOVE_SELF`, but the delete half is queued only when the LAST reference to the root drops | **yes** |
  /// | FSEvents (macOS) | `RootChanged` | `RootChanged` | no |
  /// | fanotify (`FAN_MARK_FILESYSTEM`) | **SILENT** (fd goes quiet, mark holds the sb alive — L4.1) | `FAN_DELETE_SELF`/`FAN_MOVE_SELF` | **yes** |
  /// | RDCW (Windows) | fatal source error on any terminal read completion | same signal | no |
  /// | USN journal (Windows) | fatal source error on a failed journal read | `RootDeath` (the root's own FRN in a delete/rename record) | no |
  ///
  /// Two backends arm it, for two different reasons.
  ///
  /// fanotify, because its unmount emits NOTHING in band: the mark holds the
  /// superblock alive and the fd simply goes quiet, so a re-stat is the only
  /// observation there is.
  ///
  /// inotify, because its in-tree death notice is not INDEPENDENT of this
  /// process. Linux queues a watched root's `IN_DELETE_SELF` only once the last
  /// reference to the removed directory drops, so every descriptor this driver
  /// holds on the root postpones it — and a sync's admission pins are held for
  /// as long as the write that owns them takes, which on a stalled filesystem
  /// is unbounded. Waiting on that signal would let a removed root stay
  /// falsely live for the length of a hung syscall: no terminal `Rescan`,
  /// syncs refused as in-flight, close reporting non-quiescence. The tick is
  /// the observation that does not depend on it, and it bounds the delay to
  /// one interval whatever any pin is doing.
  ///
  /// The other three keep their in-band signals and stay off the tick: each
  /// reaches [`on_mounts_refreshed`](Self::on_mounts_refreshed)'s death mapping
  /// (via a loss-triggered refresh) or the Monitor's self-event path directly,
  /// with no reference of this driver's able to hold it back.
  ///
  /// # The tick is also the mount SAMPLER
  ///
  /// A mount that departs BELOW the root is silent on every backend — there is no
  /// such thing as an unmount signal for a subtree you are not the mount of — so
  /// the only way any scope learns of one is by re-reading the table (#74). That
  /// is a THIRD obligation on the same cadence, and both ticking profiles owe it
  /// whatever their root's own death signal does:
  ///
  /// - **inotify**: per-directory watches under a departed mount go quiet with no
  ///   `IN_UNMOUNT` and no `IN_IGNORED`, and a mount that ARRIVES hides a subtree
  ///   whose watches now describe nothing reachable. Both need the sample.
  /// - **fanotify**: the FID map holds no handle under revealed ground, so the
  ///   sample drives the reseed as well as the cover.
  /// - **FSEvents / RDCW / USN**: kept off the tick, exactly as they were. Their
  ///   streams follow nested volumes themselves, so a table sample would buy the
  ///   consumer nothing and cost every macOS and Windows root a periodic read.
  const fn liveness_ticked(profile: BackendKind) -> bool {
    matches!(profile, BackendKind::Fanotify | BackendKind::Inotify)
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
  ///
  /// Test entry: the production path always carries a whole
  /// [`RootOptions`] (it rides the watcher's `Command::Watch`), so this
  /// interest-only shorthand exists for the cells that are about anything else.
  #[cfg(test)]
  pub(crate) fn on_watch(
    &mut self,
    root: PathBuf,
    interest: Interest,
    profile: BackendKind,
  ) -> Result<ScopeId, WatchRootError> {
    self.on_watch_with(root, &RootOptions::new().with_interest(interest), profile)
  }

  /// [`on_watch`](Self::on_watch) taking the whole per-root household: the
  /// interest AND the two glob seats, compiled once here and stored on the
  /// scope ([`prune`](ScopeState::prune), [`include`](ScopeState::include)).
  ///
  /// # Errors
  ///
  /// [`WatchRootError::ScopeInUse`] when the Monitor already holds a root for
  /// the minted scope — see [`on_watch`](Self::on_watch).
  pub(crate) fn on_watch_with(
    &mut self,
    root: PathBuf,
    options: &RootOptions,
    profile: BackendKind,
  ) -> Result<ScopeId, WatchRootError> {
    let interest = options.interest();
    let (prune, include) = options.compile()?;
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
        retiring: None,
        root_attempt: None,
        profile,
        requested: root,
        incarnation: 0,
        root: None,
        root_dev: None,
        root_mnt_id: None,
        root_incarnation: None,
        identity: None,
        mount_table: Vec::new(),
        learned_mounts: Vec::new(),
        mounts_authoritative: false,
        table_fingerprint: None,
        namespace_transitions_seen: None,
        recovery_epoch: 0,
        recovery_in_flight: false,
        recovery_dirty: false,
        refresh_pending: false,
        refresh_stale: false,
        budget_recovered: false,
        budget_report_owed: false,
        lag: LagState::Normal,
        park: Park::default(),
        resume_poisoned: false,
        publicly_live: false,
        liveness_deadline: None,
        applied_cover: None,
        settle_floor: None,
        #[cfg(feature = "sync")]
        dominating_rescans: BTreeSet::new(),
        pending_widen: None,
        prune,
        include,
        markers: BTreeMap::new(),
        barrier_epoch: BarrierEpoch::BIRTH,
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
    // The one exempt leaf, taken out of `self` before the walk borrows it.
    let reserved = self.reserved_cookie_dir.clone();

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
        // The reserved cookie directory of a COVERED directory is not dropped, however far
        // outside the cover its own name lies. It is a sibling of whatever the cover
        // retained, so a cover naming a file subscription marks it strictly outside and
        // takes it — and the next sync into that directory reuses the reserved directory
        // already standing (the EEXIST arm), so no directory create ever reaches the
        // parent's watch to re-arm it. On a descending backend the marker is then born in
        // unarmed ground, no source event exists at all, and the barrier can only time out.
        //
        // The exemption is the NAME's and the PARENT's together: the marker's landing
        // directory is coverage the sync barrier depends on and the cover — which speaks
        // for the caller's subscriptions — cannot know to name. It keeps at most one watch
        // per covered directory that already carries a reserved directory, so it is bounded
        // by what was already armed. A reserved directory under ground the cover genuinely
        // narrowed away goes with that ground: a sync of an uncovered directory is refused
        // before birth, so nothing will ever land there. The root needs no case of its own —
        // it is an ancestor of every retained prefix, so it is never strictly outside.
        //
        // This is the set-cover's half of the rule the prune seat already states for
        // patterns: the marker exemption keeps the record reportable, this keeps it
        // observable.
        //
        // The name is matched for EQUALITY against the one leaf this process
        // reserves, never against the classifier's whole name space
        // ([`reserved_cookie_dir`](Self::reserved_cookie_dir)): the space is
        // predictable and unowned, so any peer could fill a covered directory with
        // reserved-shaped siblings and keep a watch descriptor per forged name
        // across every shrink. Equality is what makes "one extra watch per covered
        // directory" a construction rather than a hope.
        let reserved_cookie_dir = path
          .file_name()
          .and_then(std::ffi::OsStr::to_str)
          .is_some_and(|leaf| reserved.as_deref() == Some(leaf))
          && path
            .parent()
            .is_some_and(|parent| !strictly_outside(retained, parent));
        let outside = strictly_outside(retained, &path) && !reserved_cookie_dir;
        outside.then(|| (path.components().count(), *watch))
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

  /// `scope`'s current [`BarrierEpoch`], or `None` for a scope this core does not
  /// hold — the dispatch stamp a sync barrier records, read at the instant it is
  /// handed to the pool.
  ///
  /// The stamp's reader is the cookie ledger's dispatch; the cells read it as the
  /// witness that a funnel bumped.
  #[cfg(any(test, feature = "sync"))]
  pub(crate) fn barrier_epoch(&self, scope: ScopeId) -> Option<BarrierEpoch> {
    self.scopes.get(&scope).map(|state| state.barrier_epoch)
  }

  /// Drains the coverage transitions the funnels have raised, and the paired
  /// directory renames the scope learned, since the last drain — IN ORDER.
  ///
  /// The driver calls this after every core input and BEFORE it executes the
  /// effect queue: the retirement a move drives has to purge the retired
  /// obligation's already-queued marker emit, and an effect drained in queue
  /// order can only ever arrive behind one.
  pub(crate) fn take_barrier_events(&mut self) -> Vec<BarrierEvent> {
    self.barrier_moves.drain(..).collect()
  }

  /// The coverage transitions alone, for the cells that read the funnels through
  /// their moves rather than through the renames a scope records beside them.
  #[cfg(test)]
  pub(crate) fn take_barrier_moves(&mut self) -> Vec<BarrierMove> {
    self
      .barrier_moves
      .drain(..)
      .filter_map(|event| match event {
        BarrierEvent::Move(moved) => Some(moved),
        BarrierEvent::Renamed { .. } => None,
      })
      .collect()
  }

  /// Drains the scopes this core has ended since the last drain.
  ///
  /// Taken by the same drain as [`take_barrier_events`](Self::take_barrier_events),
  /// which the driver runs at every loop top and before every effect: the
  /// retirement of each scope named here is published in the same synchronous
  /// pass as the input that ended it, before the teardown effect takes the
  /// delivery lane away and before the next flush.
  pub(crate) fn take_ended_scopes(&mut self) -> Vec<ScopeId> {
    std::mem::take(&mut self.ended_scopes)
  }

  /// Whether a scope this core has ended is still awaiting its publication or
  /// its teardown — the driver's gate for giving an ended scope UNCONDITIONAL
  /// priority over a ready command or op result.
  ///
  /// An ended scope's teardown must run before anything else is serviced: a due
  /// fence's settlement can consume a fatal and remove the scope with its
  /// teardown still queued, and a ready replacement completion would otherwise
  /// be taken first and install a successor for a scope this core no longer
  /// holds — a successful replacement the old death's teardown then dismantles.
  ///
  /// BOTH terms are needed. `ended_scopes` alone goes blind whenever the drain
  /// inside the settlement resolution takes the list in the very pass that ended
  /// the scope; the queued `TeardownStream` is what remains true until the
  /// loop-top flush executes it. Ended scopes are finite per input and the loop
  /// top clears both, so re-topping on this cannot spin.
  pub(crate) fn has_ended_scopes(&self) -> bool {
    !self.ended_scopes.is_empty()
      || (!self.effects.is_empty()
        && self
          .effects
          .iter()
          .any(|effect| matches!(effect, Effect::TeardownStream { .. })))
  }

  /// Whether anything is waiting in the effect queue.
  ///
  /// The driver consults this immediately before it builds its timer and enters
  /// `select`, so that it re-tops whenever a producer that ran AFTER the pass's
  /// flush left work behind — the dispatch re-judge of a parked obligation is the
  /// proven case, and any future post-flush producer is the class. Every such
  /// producer is thereby flushed before the driver sleeps.
  ///
  /// The queue alone is the whole question at that point.
  /// [`poll_effect`](Self::poll_effect) has two further offer sources — a lagging
  /// scope's parked `Rescan` and a dying scope's terminal one — and both are
  /// offered only under [`Attempt::Idle`], which the driver's own effect pass has
  /// already taken every one of; a post-flush producer parks a change without ever
  /// returning an attempt to `Idle`, and a REFUSED offer becomes
  /// [`Attempt::Spent`], whose retry [`poll_timeout`](Self::poll_timeout) names
  /// and the deadline arm serves.
  pub(crate) fn has_queued_effects(&self) -> bool {
    !self.effects.is_empty()
  }

  /// Whether a coverage transition is waiting to be drained — the other half of
  /// the same question [`has_queued_effects`](Self::has_queued_effects) asks, for
  /// the queue the driver drains ahead of every effect.
  pub(crate) fn has_barrier_moves(&self) -> bool {
    !self.barrier_moves.is_empty()
  }

  /// THE BARRIER FUNNEL: advances `scope`'s [`BarrierEpoch`] and records the
  /// coverage transition that moved it.
  ///
  /// Called from the ten sites through which every coverage transition of a
  /// scope passes — a child watch armed or dropped, a located `Rescan` fed to the
  /// Monitor, a root replace, a real mount-refresh loss, a root overflow, a
  /// routed `Rescan`'s cover degrade, the settle observation's lossy rewind, a
  /// probe-budget loss, and a delivery the consumer refused — and from nowhere
  /// else. Each new funnel is appended rather than inserted, so the ones that
  /// precede it keep the numbers every seat in this crate already cites: the
  /// probe-budget loss is the NINTH and the lag entry the TENTH. A site that
  /// synthesizes a root overflow of its own is its own funnel rather than a
  /// caller of the root-overflow one, which is why the last two both have the
  /// shape `on_root_overflow` has. The list is short and auditable because it names
  /// FUNNELS rather than their callers: a caller list is exactly the enumeration
  /// discipline that the pairwise-check rounds kept defeating.
  ///
  /// The funnels are unconditional but for the deliberate non-bumps listed at the
  /// funnels themselves, each with a negative cell of its own:
  ///
  /// - the arm funnel — the arming of this process's reserved cookie directory
  ///   (the exact leaf [`reserved_cookie_dir`](DriverCore::reserved_cookie_dir)
  ///   holds) is the barrier's own ground coming into coverage, created by the
  ///   write itself, so it records no move;
  /// - the cover degrade — a scope that never narrowed has no recorded claim, so
  ///   there is no wholesale change of what "covered" means for that funnel to
  ///   report;
  /// - the settle observation — an observation that resolves no fence (a bare
  ///   loss-memory entry) instructed nobody and closed nobody's fence, so it owes
  ///   nobody a covering `Rescan`.
  ///
  /// Everything else outside this list is a site that never reaches a funnel at
  /// all — data events, a directory rename within the scope, a widen commit, a
  /// no-op cover re-issue, a scope teardown, a scope birth — and each carries a
  /// negative cell of its own too. Such a rename records a
  /// [`BarrierEvent::Renamed`] instead
  /// ([`barrier_renamed`](Self::barrier_renamed)): the destination's coverage is
  /// unchanged, so the rename passes no funnel of its own — but the ground every
  /// barrier under its source stands on has moved, and the drain retires them
  /// under the domination `Rescan` it stands at the destination's parent. A
  /// rename with no barrier under it retires nothing and stays the non-bump.
  ///
  /// Two foldings keep the queue bounded without ever forgetting a transition:
  ///
  /// - a move naming ground a queued move of the same scope already names folds
  ///   into it. `rescan_stands` folds by AND — a fold may only claim a standing
  ///   `Rescan` when EVERY move it absorbed stood one, since an extra covering
  ///   `Rescan` costs a redundant re-read while a missing one is silent loss;
  /// - a whole-scope move subsumes every located move of its scope, and past
  ///   [`MAX_BARRIER_MOVES_PER_SCOPE`] located moves the scope's entries fold
  ///   into one. Folding UP is the honest degrade: the whole-scope move retires a
  ///   superset of what the folded ones would have.
  fn barrier_moved(
    moves: &mut VecDeque<BarrierEvent>,
    state: &mut ScopeState,
    scope: ScopeId,
    location: BarrierLocation,
    rescan_stands: bool,
  ) {
    state.barrier_epoch.advance();
    if matches!(location, BarrierLocation::Scope) {
      Self::fold_barrier_moves(moves, scope, rescan_stands);
      return;
    }
    // The merge reaches the whole queue: no entry rewrites the ground another is
    // judged against, so a move applied out of order intersects exactly what it
    // would have intersected in order. A rename entry beside them retires on its
    // own ground and is idempotent with every move that overlaps it.
    let mut located = 0usize;
    for event in moves.iter_mut() {
      let BarrierEvent::Move(queued) = event else {
        continue;
      };
      if queued.scope != scope {
        continue;
      }
      if queued.location == location || matches!(queued.location, BarrierLocation::Scope) {
        queued.rescan_stands &= rescan_stands;
        return;
      }
      located += 1;
    }
    if located >= MAX_BARRIER_MOVES_PER_SCOPE {
      // The incoming move is LOCATED, so a `true` here means "a Rescan
      // covering THIS ground stands" — a claim that is location-specific by
      // construction (`barrier_ground` derives the location from that
      // Rescan's own anchor and descent). Widening it to `Scope` must not
      // carry that claim forward: no Rescan covers the whole scope, only
      // the `MAX_BARRIER_MOVES_PER_SCOPE` grounds that were actually
      // stood, so the fold unconditionally sets `rescan_stands = false` and
      // the retirement stands its own covering Rescan instead of trusting
      // one that was never scope-wide.
      Self::fold_barrier_moves(moves, scope, false);
      return;
    }
    moves.push_back(BarrierEvent::Move(BarrierMove {
      scope,
      location,
      rescan_stands,
    }));
  }

  /// A DIRECTORY RENAME DOMINATES EVERY BARRIER UNDER ITS SOURCE: records the
  /// paired rename inside `scope` so the drain retires every obligation
  /// standing under `from` and stands each retirement's domination `Rescan` at
  /// the destination's parent.
  ///
  /// Every located judgement of a barrier is by PATH, and a rename changes paths
  /// on four different routes — the Monitor's re-key, the pairing on a profile
  /// that keeps no child watches, the reserved cookie directory moved as a
  /// subtree of its own, and the prune fence's widened destination. One rule
  /// answers all of them: the ground a barrier stands on has moved, so the
  /// barrier is retired and re-read rather than followed.
  ///
  /// The rename advances no epoch here. A rename with no barrier under it
  /// retires nothing and stands nothing, which keeps it the deliberate non-bump
  /// §2.1 makes it; a rename WITH one passes the funnel through the domination
  /// `Rescan` the drain stands for each retirement.
  ///
  /// An endpoint the Monitor can no longer place records a whole-scope move
  /// instead — an unnamed source cannot select the obligations the rename moved,
  /// and an unnamed destination cannot aim their instruction. That is the
  /// fail-WIDE direction [`barrier_ground`](Self::barrier_ground) takes for the
  /// same question, and the whole-scope move claims nothing: every obligation it
  /// retires stands its own covering `Rescan` at its own recorded ground.
  fn barrier_renamed(
    moves: &mut VecDeque<BarrierEvent>,
    monitor: &Monitor,
    state: &mut ScopeState,
    scope: ScopeId,
    from: &Location,
    to: Option<(WatchId, Option<Location>)>,
  ) {
    // The SOURCE is joined onto the scope root rather than onto the slot's own
    // parent: `from` is the location the Monitor reconstructed from its live
    // tree at the pairing, already carrying that parent's own descent, and the
    // root is the one anchor no reparent inside the tree can move.
    let from = Self::anchored_at(monitor, state, state.watch, Some(from));
    let to =
      to.and_then(|(watch, target)| Self::anchored_at(monitor, state, watch, target.as_ref()));
    match (from, to) {
      (Some(from), Some(to)) => moves.push_back(BarrierEvent::Renamed { scope, from, to }),
      _ => Self::barrier_moved(moves, state, scope, BarrierLocation::Scope, false),
    }
  }

  /// Replaces every queued move of `scope` with the one whole-scope move that
  /// subsumes them, keeping the AND of what they and the incoming move stood.
  ///
  /// The scope's queued RENAMES survive the fold, in place. A whole-scope move
  /// retires a superset of every located move it absorbs, but it stands no
  /// instruction at any destination — and a rename's whole business is to aim
  /// one at the ground the markers it carried away now stand in, which the
  /// obligation's own recorded ground no longer names.
  fn fold_barrier_moves(moves: &mut VecDeque<BarrierEvent>, scope: ScopeId, rescan_stands: bool) {
    let folded = |event: &BarrierEvent| match event {
      BarrierEvent::Move(queued) => queued.scope == scope,
      BarrierEvent::Renamed { .. } => false,
    };
    let stands = rescan_stands
      && moves
        .iter()
        .filter(|event| folded(event))
        .all(|event| matches!(event, BarrierEvent::Move(queued) if queued.rescan_stands));
    moves.retain(|event| !folded(event));
    moves.push_back(BarrierEvent::Move(BarrierMove {
      scope,
      location: BarrierLocation::Scope,
      rescan_stands: stands,
    }));
  }

  /// The ground one [`Planned::Over`] or [`Planned::Dominated`] names, as the
  /// funnel records it: the whole scope for a root (or backend-wide) slice, the
  /// located directory for a subtree one.
  ///
  /// An anchor the Monitor can no longer place answers the whole scope. That is
  /// the fail-WIDE direction every barrier question takes: retiring more
  /// obligations than the transition strictly touched costs a re-enumeration,
  /// retiring fewer certifies over ground that moved.
  fn barrier_ground(monitor: &Monitor, state: &ScopeState, target: &Scope) -> BarrierLocation {
    let Scope::Subtree(sub) = target else {
      return BarrierLocation::Scope;
    };
    let Some(mut path) = watch_path(monitor, state, sub.watch()) else {
      return BarrierLocation::Scope;
    };
    for segment in sub.descent().segments() {
      path.push(segment.as_str());
    }
    BarrierLocation::at(state, Arc::new(path))
  }

  /// Arms `name` as an ACTIVE sync marker of `scope`, OWNED by the cookie
  /// obligation `owner`: from here until that obligation releases it, no seat of
  /// that scope may take a change whose object wears the leaf
  /// ([`markers`](ScopeState::markers)).
  ///
  /// Called at the sync's ADMISSION — the same step that births its cookie
  /// obligation, whose id is the owner recorded here — so the exemption is
  /// standing before any write can be dispatched, let alone land. A name armed
  /// for a scope that is not registered is dropped: there is no state to exempt
  /// anything on, and the sync's own admission refuses a scope with no live
  /// stream.
  ///
  /// An arm under a leaf some earlier obligation still holds TAKES ownership: a
  /// name is only reusable once its previous holder retired, so the newcomer is
  /// the live owner by construction and the predecessor's pending release is the
  /// stale one.
  #[cfg(feature = "sync")]
  pub(crate) fn arm_sync_marker(
    &mut self,
    scope: ScopeId,
    name: Arc<str>,
    owner: crate::driver::CookieId,
  ) {
    if let Some(state) = self.scopes.get_mut(&scope) {
      state.markers.insert(name, owner);
    }
  }

  /// Releases marker leaves whose obligations have retired — the ledger's typed
  /// terminals, drained into the core by the driver loop — each removed only
  /// while the RELEASED obligation still owns it.
  ///
  /// The release runs on the far side of the barrier it protects: an obligation
  /// retires when its cookie is confirmed gone (the umbrella reaps it only after
  /// the delivery it was waiting for) or when nothing was ever created, so a
  /// marker leaves this set only once no change can still be owed for it.
  ///
  /// The ownership condition is what keeps that true across a name REUSE. A
  /// retirement queues its release under the ledger lock and the drain applies it
  /// a loop pass later; in between, the freed name may already have been admitted
  /// again, and a name-keyed removal would then disarm a LIVE successor whose
  /// marker has not been written yet. Comparing the owner makes the stale release
  /// a no-op instead.
  #[cfg(feature = "sync")]
  pub(crate) fn release_sync_markers(
    &mut self,
    released: impl IntoIterator<Item = (ScopeId, Arc<str>, crate::driver::CookieId)>,
  ) {
    for (scope, name, owner) in released {
      if let Some(state) = self.scopes.get_mut(&scope)
        && state.markers.get(&name) == Some(&owner)
      {
        state.markers.remove(&name);
      }
    }
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

  /// The scopes whose staged adoption markers have not yet forced the source to
  /// surface what the kernel holds — see [`AdoptionSeal`].
  ///
  /// `lane_of` reports a scope's CURRENT delivery lane, which the latch is
  /// stamped with: a latch naming any other lane speaks for a queue the scope
  /// has stopped reading, and is re-offered rather than waited on. The driver
  /// owns that number, so it is asked for it here rather than mirroring it.
  ///
  /// Reporting does NOT latch, for the same reason
  /// [`covers_awaiting_cut`](Self::covers_awaiting_cut) does not: the caller may
  /// decline a scope whose stream is already gone, and a request spent on a
  /// batch nobody sends could only ever be closed by a reply that never comes.
  /// A declined scope simply reappears next pass.
  ///
  /// The offer and [`mark_adoption_cut_inflight`](Self::mark_adoption_cut_inflight)
  /// share one predicate, so the caller can always latch what it was offered.
  pub(crate) fn adoptions_awaiting_cut(&self, lane_of: &impl Fn(ScopeId) -> u64) -> Vec<ScopeId> {
    self
      .monitor
      .staged_adoption_scopes()
      .into_iter()
      .filter(|(scope, high_water)| {
        self.cut_proof_required(*scope)
          && !self
            .adoption_seals
            .get(scope)
            .is_some_and(|seal| seal.answers_for(lane_of(*scope), *high_water))
      })
      .map(|(scope, _)| scope)
      .collect()
  }

  /// Latches `scope`'s seal as having the ordering-proof request `token` in
  /// flight on `lane`, so it is asked for exactly one however many passes the
  /// reply takes. Called only once the caller has committed to sending that
  /// batch.
  ///
  /// The request is stamped with the newest staging the scope currently holds —
  /// the stagings this proof will be able to license — which its proof inherits
  /// and the seal is checked against, so the caller needs no bookkeeping of its
  /// own. A latch on a lane the scope has left is rebuilt from nothing rather
  /// than extended: neither its prefix nor its request orders the queue the
  /// scope now reads.
  pub(crate) fn mark_adoption_cut_inflight(&mut self, scope: ScopeId, lane: u64, token: u64) {
    let Some(high_water) = self.monitor.adoption_staging_high_water(scope) else {
      return;
    };
    let seal = self
      .adoption_seals
      .entry(scope)
      .or_insert_with(|| AdoptionSeal::new(lane));
    if seal.lane != lane {
      *seal = AdoptionSeal::new(lane);
    }
    if !seal.answers_for(lane, high_water) {
      seal.latch(token, high_water);
    }
  }

  /// Records that `scope`'s source answered, on `lane`, a control batch carrying
  /// the seal request `token` — whose reply the reader's pre-reply cut precedes,
  /// so anything the kernel held is now on the lane, ahead of this.
  ///
  /// Only the request actually in flight is closed, and only by its OWN token
  /// and its OWN lane, which is what makes every stale completion inert: a
  /// predecessor batch's cut was taken before this request existed, and a batch
  /// answered on a retired transport cut a queue this scope no longer reads.
  pub(crate) fn prove_adoption_cut(&mut self, scope: ScopeId, lane: u64, token: u64) {
    if let Some(seal) = self.adoption_seals.get_mut(&scope)
      && seal.lane == lane
    {
      seal.prove(token);
    }
  }

  /// Whether the next [`resolve_adoption_seals`](Self::resolve_adoption_seals)
  /// would release at least one staged marker — some scope holding a proven
  /// prefix that reaches a marker still staged.
  ///
  /// The driver consults this to arm the same source drain a cover settlement
  /// arms, and for the same reason: the verdict may only be taken over a lane
  /// nobody is still reading. Free for a scope that owes no seal — the latch map
  /// is empty outside a widen's confirm window.
  pub(crate) fn adoption_seal_due(&self, lane_of: &impl Fn(ScopeId) -> u64) -> bool {
    self.adoption_seals.iter().any(|(scope, seal)| {
      seal
        .licenses_through(lane_of(*scope))
        .is_some_and(|through| self.monitor.adoption_staged_through(*scope, through))
    })
  }

  /// Releases every staged adoption marker an answered cut has ordered, at the
  /// driver's one choke point — after the drain that fed the lane to spent, and
  /// never for a scope the drain did not finish.
  ///
  /// The withholding is the same rule a cover settlement takes and it is owed
  /// for a stronger reason: the whole point of the cut is to put a refuting
  /// record on the lane, so a verdict taken while that lane still holds unread
  /// items would resolve over exactly the record the round trip was bought to
  /// surface.
  ///
  /// Sweeping first is the seal latch's clear-on-empty edge: a scope with no
  /// staged marker owes no seal, so its latch — proven prefix and request in
  /// flight alike — is dropped where it stands rather than left to answer for an
  /// obligation that no longer exists. That is what keeps a request whose reply
  /// can never arrive from being mistaken for one that still might.
  pub(crate) fn resolve_adoption_seals(
    &mut self,
    lane_of: &impl Fn(ScopeId) -> u64,
    unspent: &std::collections::BTreeSet<ScopeId>,
  ) {
    let monitor = &self.monitor;
    self
      .adoption_seals
      .retain(|scope, _| monitor.adoption_staging_high_water(*scope).is_some());
    let due: Vec<(ScopeId, u64)> = self
      .adoption_seals
      .iter()
      .filter(|(scope, _)| !unspent.contains(*scope))
      .filter_map(|(scope, seal)| {
        seal
          .licenses_through(lane_of(*scope))
          .filter(|through| monitor.adoption_staged_through(*scope, *through))
          .map(|through| (*scope, through))
      })
      .collect();
    if due.is_empty() {
      return;
    }
    for (scope, through) in due {
      self.monitor.seal_staged_adoptions(scope, through);
    }
    self.drain_monitor();
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
      // An unanswered classification stat over a slot this scope covers with
      // nothing is a LOSS this settlement must carry, and it is read here — at
      // the observation — rather than at an edge, because it is a STANDING
      // condition and not an event. A scope's loss memory is spent by every
      // settle observation, so a mark laid when the stat was queued would be
      // cleared by the first observation to pass and the next fence would
      // certify the same uncovered window anyway.
      //
      // The slot may be a directory the scope has no watch on: the read that
      // listed it as `FileKind::Unknown` reconciled nothing for it, and the stat
      // is uncounted, so the barrier above quiesces with the slot dark. Nor need
      // that read have stood a `Rescan` — a pure grow and a record-driven cold
      // read stand none — so this is the only thing between the fence and a
      // certified window. The verdict degrades and the settle floor keeps its
      // under-claim, which sends the consumer back to enumerate — never
      // `Applied` over ground writes go unrecorded beneath.
      //
      // Deliberately NOT a conjunct of the barrier
      // ([`Monitor::stat_loss_outstanding`]): a driver that never answers must
      // cost a degraded verdict, not a wedged scope. Everything below still runs
      // — the residue and certification deferrals, the ordering proof, the
      // resolution — as for any other lossy window, plus the ONE further pass
      // this loss owes on its own account: it is the only one that arrives with
      // no `Rescan`, so the verdict's cover is stood and ordered below.
      let stat_loss = self.monitor.stat_loss_outstanding(scope);
      if stat_loss && let Some(entry) = self.cover_fences.get_mut(&scope) {
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
      // THE COVER THE STANDING STAT LOSS OWES. The mark above degrades this
      // tranche's verdict; a degraded verdict reports a covering `Rescan`
      // EMITTED for the gap, and this condition is the one loss source that
      // stands none of its own — the read that queued the stat reconciled
      // nothing for the slot, and a pure grow or a record-driven cold read
      // stands no `Rescan` at all. So it is stood HERE, scope-level, where the
      // verdict is minted: the darkness cannot be covered at the slot (that is
      // what the outstanding request means), and the root-covering `Rescan` is
      // the re-enumerate instruction the degraded verdict names.
      //
      // The tranche is then held for exactly ONE pass — entry intact, exactly
      // like the deferrals above — so the driver's re-top
      // ([`take_cover_flush_due`](Self::take_cover_flush_due)) flushes the
      // instruction to the consumer's channel before the next observation
      // answers the caller. That is the same ordering every OTHER `Degraded`
      // producer gets for free: its cover is queued by an earlier pass and
      // offered by this pass's loop-top flush.
      //
      // The hold ends there and is never extended by the offer's OUTCOME. A
      // refused cover is parked as the scope's dominating instruction and rides
      // the lane's own delivery retry, BEHIND the verdict — because `Degraded`
      // promises emission, not delivery, and a hold that waited for an
      // acceptance would make a caller's own `set_cover` reply depend on that
      // caller reading its event stream. Nothing here reads the lane, the
      // channel, or the consumer.
      //
      // Only where a verdict is actually minted (`split > 0`): an observation
      // that resolves no fence — a bare loss-memory entry, or a tranche no proof
      // has reached — instructs nobody and so owes nobody a cover.
      //
      // Asked as a VALUE the match produces, so a state added to [`StatCover`]
      // does not compile until it has said whether a tranche may resolve over it.
      let stood = entry.stat_cover;
      let (stat_cover, held) = if pass.orders_stat_cover() {
        match stood {
          // Nothing stood yet, and this pass mints a verdict over the standing
          // loss: stand the cover and hold the tranche for the flush that offers
          // it.
          StatCover::Unstood if stat_loss && split > 0 => match self.stand_stat_cover(scope) {
            StatCover::Stood => (StatCover::Stood, true),
            // Nothing was stood, so nothing is owed and nothing is ordered: a
            // kernel-recursive scope stats no slot, and a torn-down one has no
            // consumer left to instruct.
            StatCover::Unstood => (StatCover::Unstood, false),
          },
          // No verdict over a standing loss here: nobody is instructed, so nobody
          // is owed a cover.
          StatCover::Unstood => (StatCover::Unstood, false),
          // Stood on an earlier pass, so its flush has already run — or a proof
          // invalidation deferred this tranche past it, which is a longer wait
          // still. Either way the instruction is out and the verdict may follow;
          // the latch is preserved so no second cover is stood.
          StatCover::Stood => (StatCover::Stood, false),
        }
      } else {
        (stood, false)
      };
      // Re-taken because standing the cover routes its own `Rescan` through the
      // loss-memory entry (which is where a `Rescan` degrades the scope's
      // recorded claim, exactly as any other loss does).
      let Some(entry) = self.cover_fences.get_mut(&scope) else {
        continue;
      };
      entry.stat_cover = stat_cover;
      if held {
        continue;
      }
      let resolving: Vec<PendingFence> = entry.pending.drain(..split).collect();
      // The hold is spent with the tranche it ordered: a successor tranche
      // covers its own stretch of the window.
      entry.stat_cover = StatCover::Unstood;
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
            // The rewind below is unconditional while the funnel that
            // follows is conditional on `!resolving.is_empty()`; the pairing
            // is safe because a bare loss-memory entry (no fence resolving)
            // was created by `route_event`'s lossy branch, which writes
            // `applied_cover` and `settle_floor` to the same value in one
            // step — so this rewind is a no-op for it. Only a resolving
            // fence can have moved the two apart.
            state.applied_cover = state.settle_floor.clone();
            // BARRIER FUNNEL: the settle observation narrows the scope's claim
            // to the provable under-claim, so an obligation admitted under the
            // optimistic one can find itself outside the rewound one. It fires
            // from the loop top on the fence entry's ACCRUED lossy memory, many
            // passes after whatever set it, and the `Rescan` that made the
            // window lossy need not cover this obligation's ground — so this
            // funnel always owes its own covering `Rescan`.
            //
            // NO claim condition gates it, and none may be added. The
            // Monitor-minted LOCATED losses that pass neither `feed` nor
            // funnel 7 — a root invalidation, an arm-failure or stat-deficit
            // re-signal ([`route_event`](Self::route_event)'s own list),
            // since funnel 7 is itself gated on `applied_cover.is_some()` —
            // are the losses for which this funnel is the ONLY one that
            // fires. Every other loss reaching this seat has already bumped
            // through its own funnel, so this funnel doubling up on it is
            // harmless (`fold_barrier_moves`' rule).
            //
            // What it does NOT fire for is an observation that resolves no
            // fence. The loop walks every `cover_fences` key, and a BARE
            // LOSS-MEMORY ENTRY is one of them: `route_event` creates it
            // (`entry(scope).or_default().mark_lossy()`) for a `Rescan` that
            // arrives with no fence open at all. Such an entry has nothing
            // pending, so `split` is 0, `resolving` is empty and `spent` is
            // true on the first observation to pass — a window in which
            // nothing was instructed and nobody's fence closed. It is the same
            // shape the stat cover refuses above: an observation that resolves
            // no fence instructs nobody and so owes nobody a cover.
            //
            // That over-fire was not idempotently inert. A whole-scope move
            // raised for a bare entry cannot be consumed where a resolved
            // fence's move is: the per-cookie drain in
            // `resolve_cover_settlements` sits under
            // `parked_cookies.remove(&fence)`, and a bare entry yields no
            // `(FenceId, CoverSettle)` pair at all, so its move survives to a
            // loop-top `drain_barrier_moves` one pass later. By then the sync
            // that was `Parked` at its own settle — and so could not be
            // retired by it — has dispatched and is `InPool`, and
            // `invalidate_barriers` DOES retire it: a caller handed a covering
            // `Rescan` nothing owes it, on a scope that has since healed.
            if !resolving.is_empty() {
              Self::barrier_moved(
                &mut self.barrier_moves,
                state,
                scope,
                BarrierLocation::Scope,
                false,
              );
            }
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

  /// Whether the last [`poll_cover_settlements`](Self::poll_cover_settlements)
  /// stood a covering `Rescan` and held its tranche for the flush that offers
  /// it, clearing the flag as it reports.
  ///
  /// The driver re-tops on `true`: the loop-top effect flush OFFERS that
  /// `Rescan` to the consumer's stream, and the next pass — the one that answers
  /// the caller with the degraded verdict naming it — runs behind that offer. It
  /// is the ONE settlement outcome no external input would bring the loop back
  /// for.
  ///
  /// Raised by the pass that STANDS a cover and by no other — one re-top per
  /// held tranche, so the re-top run stays a single pass and the driver's
  /// bounded-service invariant is untouched. What the flush then makes of the
  /// cover changes nothing here: a refused one is parked, and a lane already
  /// lagging absorbed it into its parked instruction before the flush ran. Both
  /// ride the scope's delivery retry, behind a verdict that has already
  /// answered.
  pub(crate) fn take_cover_flush_due(&mut self) -> bool {
    std::mem::take(&mut self.cover_flush_due)
  }

  /// Stands the covering `Rescan` a standing stat loss owes the tranche about to
  /// resolve, and reports whether one was stood.
  ///
  /// [`StatCover::Stood`] asks the driver for the single re-top whose flush
  /// offers it. [`StatCover::Unstood`] where nothing was stood: a
  /// kernel-recursive scope stats no slot, and a torn-down one has no consumer
  /// left to instruct — so nothing is ordered and the tranche resolves where it
  /// stands.
  fn stand_stat_cover(&mut self, scope: ScopeId) -> StatCover {
    if !self.monitor.cover_stat_loss(scope) {
      return StatCover::Unstood;
    }
    self.drain_monitor();
    self.cover_flush_due = true;
    StatCover::Stood
  }

  /// The cookie dispatch's deficit seam: re-signals `scope`'s standing
  /// terminal coverage deficits through the Monitor (one fresh epoch-bumped
  /// covering `Rescan` per site plus a bounded heal kick —
  /// [`Monitor::resignal_coverage_deficits`]), then drains, so the `Rescan`
  /// effects are queued BEFORE the caller dispatches the parked cookie write.
  /// Returns whether anything was re-signaled; a no-op for a scope with no
  /// deficit or a kernel-recursive one.
  #[cfg(any(test, feature = "sync"))]
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
        // A token belongs to the mount it was proven against, so a new world
        // starts with none: comparing this world's first reading against the
        // previous root's token would read every fresh scope as a frame move.
        state.root_incarnation = None;
        retire_root_recovery(state);
        state.identity = Some(meta.identity);
        install_mount_table(state, meta.mounts.into_iter().map(|row| row.location));
        // A brand-new world: nothing learned about the previous one survives, and
        // nothing else may empty this set (see [`ScopeState::learned_mounts`]).
        state.learned_mounts.clear();
        // Born closed: the seed was read before the stream started, so a
        // mount appearing in that gap is in neither the seed nor the event
        // stream — the seed can only REDUCE trust. Authority arrives with
        // this birth refresh, whose post-live read the stream orders against
        // every later mount transition; until it installs, event-side
        // identity and cookies fail closed (the non-authoritative default).
        Self::arm_refresh(&mut self.effects, scope, state, RefreshCause::Invalidating);
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
            let incarnation = state.incarnation;
            self.effects.push_back(Effect::AddWatch {
              scope,
              incarnation,
              watch,
              attempt,
              parent: watch,
              name: Segment::new(name),
              path: root,
              expected,
              // The ROOT is where the frame comes FROM, so it can never be
              // across it: the check compares the landing to the meta this same
              // spawn just installed. Carried anyway rather than special-cased,
              // so exactly one rule governs every arm.
              frame: state.frame(),
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
      // The TRANSITION, not every root arm that answers `Ok`: a binding reproof
      // re-adds this same root, and clearing the latch on one of those would
      // discharge a report the consumer has not been handed and let the next
      // refused tick stand a second instruction for it. On the transition the
      // latch is already clear — nothing is owed before a scope is public
      // ([`on_refresh_declined`](Self::on_refresh_declined)) — so this makes
      // that bound structural rather than argued.
      if !std::mem::replace(&mut state.publicly_live, true) {
        state.budget_report_owed = false;
      }
    }
    self.monitor.on_watch_result(watch, attempt, res);
    self.drain_monitor();
  }

  /// Feeds one raw directory listing back for the enumerate that requested
  /// it, minting each entry's identity through the SAME policy the probe path
  /// uses (enumerate-side identity is the authority; a foreign-device entry
  /// mints `None`). A DIRECTORY across the scope's MOUNT boundary — a differing
  /// mount id, or (as a belt, and when the mount id is unavailable) a differing
  /// device — is marked a DESCENT BOUNDARY ([`DirEntry::with_boundary`]): the
  /// mount boundary is the scope boundary, so the Monitor must not descend it —
  /// the entry still delivers, as the directory it is, and the subtree beyond the
  /// boundary is deliberately outside coverage. The mount-id fence catches a
  /// `mount --bind` of a same-DEVICE directory the device check alone would
  /// descend across (the same breach the fanotify walk closes with the same
  /// fence); the device belt still governs when either mount id is unknown (the
  /// honest below-5.8 degrade).
  ///
  /// The boundary is stated ALONGSIDE the kind rather than by rewriting it. A
  /// kind rewritten to a non-directory would travel out to the consumer as
  /// `is_dir: Some(false)` and let a file-shaped delivery seat — the root's
  /// [`include`](ScopeState::include) — silently drop a real directory's
  /// `Created`; the Monitor's own arm, descent and coverage decisions read
  /// [`DirEntry::descends`] and are unchanged by the split.
  ///
  /// # What the listing drops
  ///
  /// An entry the caller EXCLUDED is dropped outright — the cold half of the
  /// common-layer fence (see [`exclusions`](Self::exclusions)) — and so is one the
  /// root's [`prune`](ScopeState::prune) seat covers. The prune half is asked as
  /// the seat is defined: an entry LISTED as a directory (a boundary directory
  /// included) is judged on its own root-relative path as well as its ancestors',
  /// while every other entry — a proven non-directory, and one whose kind the
  /// read could not classify at all — is judged on its ancestors alone. So a FILE
  /// whose name happens to match a pattern stays in the listing, an entry of
  /// unknown kind stays with it, and only an already-pruned prefix above either
  /// can take it out (see [`is_pruned`](Self::is_pruned)).
  ///
  /// Either drop means the Monitor never emits the entry's `Created`, never
  /// reconciles a slot for it, never arms it and never descends it. Neither
  /// deliberately sets `lossy`: a `Partial` listing means the read could not
  /// report everything, which forces a covering `Rescan` and a bounded retry,
  /// whereas this omission is exactly what the caller asked for and has nothing to
  /// recover — and a `Rescan` naming a pruned or excluded path is the one thing
  /// both seats must never produce. The exclusion half needs no backend gate — an
  /// enumerate only ever happens on a descending profile, and a descending backend
  /// by construction has no admission-time enforcement of its own — and the prune
  /// half never stands down for a backend at all.
  ///
  /// [`DirEntry::with_boundary`]: tributary_proto::DirEntry::with_boundary
  /// [`DirEntry::descends`]: tributary_proto::DirEntry::descends
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
          // Only a LISTED directory is judged on its own name. `readdir` answers
          // `DT_UNKNOWN` on whole filesystems, and reading that as a directory
          // would silence every regular FILE on such a filesystem whose name
          // happens to match a `**/.*` seat — a drop with no `Rescan` behind it,
          // which is the one thing this fence may not do. An unknown-kind entry
          // is therefore staged: a directory among them costs one watch and its
          // own dirents, and its descendants prune at the next level down,
          // because its name is a proper ancestor prefix of every one of them.
          let directory = entry.kind.is_dir();
          if self.excluded(&path) || Self::is_pruned(state, directory, &path) {
            continue;
          }
          let node = mint(state, &path, NonZeroU64::new(entry.ino), Some(entry.dev));
          let mut dir_entry = DirEntry::new(Segment::new(name), entry.kind);
          if entry.kind.is_dir() && crosses_mount_boundary(state, &entry) {
            dir_entry = dir_entry.with_boundary();
          }
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
    let fed = Self::settle_if_ready(
      &mut self.monitor,
      &mut self.barrier_moves,
      &mut state,
      scope,
      batch,
      now,
    );
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
    // The fence has no batch in hand here — the park owns it — so a consumption it
    // defers is collected and handed to that batch below, on the far side of the
    // call and before the batch can settle. A resolution whose batch is already
    // gone (a loss flush, a teardown) drops its records and its deferrals together.
    let mut deferred = Vec::new();
    let resolved = self.fence_resolved(&mut state, scope, resolved, &mut deferred);
    let mut fed = false;
    if let Some(batch) = state.park.active.as_mut() {
      batch.deferred_consumptions.append(&mut deferred);
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
        Self::settle(
          &mut self.monitor,
          &mut self.barrier_moves,
          &mut state,
          scope,
          batch,
          now,
        );
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
    // Every queued effect of this scope belongs to the world it was armed
    // against, so the incarnation moves with the root.
    state.incarnation += 1;
    let root = Arc::new(meta.root);
    state.root = Some(root);
    state.root_dev = Some(meta.root_dev);
    state.root_mnt_id = meta.root_mnt_id;
    // A token belongs to the mount it was proven against, so a new world starts
    // with none: comparing this world's first reading against the previous root's
    // token would read the swap as a frame move on top of the swap itself.
    state.root_incarnation = None;
    retire_root_recovery(state);
    state.identity = Some(meta.identity);
    install_mount_table(state, meta.mounts.into_iter().map(|row| row.location));
    // A brand-new world: nothing learned about the previous one survives, and
    // nothing else may empty this set (see [`ScopeState::learned_mounts`]).
    state.learned_mounts.clear();
    // The old world's authority cannot vouch for the new root's mounts: trust
    // fails closed until the refresh this commit arms completes. A refresh
    // already in flight is DISOWNED. Coalescing onto an outstanding refresh is
    // right within one world and wrong across a commit: the old root's probe may
    // be inside a `stat` on a wedged mount and never come back, and the
    // replacement would then wait for it — no refresh of its own, so no mount
    // authority and, worse, no root-liveness check at all, leaving an unmounted
    // replacement reading live forever. `trust_lost` below therefore issues a
    // REAL refresh rather than setting the stale bit, and the driver retires the
    // scope's probe tag at the same commit — the ONE owner of the cross-world
    // fence — so the old root's late answer is dropped before it reaches the
    // core, and the fresh-tag completion this arms is applied on arrival.
    state.refresh_pending = false;
    state.refresh_stale = false;
    // A replace commit ends any witnessed widen window outright: the fallback
    // route lands here with the tainted (or refused) window still recorded,
    // and the replacement's own spawn barrier re-established the binding from
    // scratch — leaking the dead window would poison a FUTURE widen's
    // reservation (INV-ROOT leg (i)).
    state.pending_widen = None;
    state.mounts_authoritative = false;

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
    //
    // BARRIER FUNNEL: the root this scope watches is a different object, so
    // every obligation of the scope stands on ground that moved. The cut below
    // turns the swap into the epoch-bumped covering `Rescan`, which is the
    // instruction a retirement under this move owes.
    Self::barrier_moved(
      &mut self.barrier_moves,
      state,
      scope,
      BarrierLocation::Scope,
      true,
    );
    // Every queued effect of this scope names the root this commit retired. The
    // driver's generation fences probes already DISPATCHED and the transport
    // generation fences control batches already EMITTED; an effect still QUEUED is
    // neither yet, so at the next flush it is relabelled onto the replacement's
    // lane and its syscall runs against the retired root ahead of the corrective
    // work queued below — and one that blocks on a retired mount wedges the
    // replacement's reader. Purge before re-arming, so the queue holds exactly the
    // live world's obligations.
    Self::purge_scope_effects(&mut self.effects, scope);
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

  /// Binds `scope`'s RETIREMENT interlock — the flag the driver mints when the
  /// scope goes live and clones into every write it dispatches for it.
  ///
  /// The core stores `true` into this flag BEFORE it removes the scope's
  /// root-watch mapping or its state — the store is the irrevocable
  /// transition point, not a publication a later drain makes: the removal
  /// runs on the driver thread while a write claims on another, and no yield
  /// separates the two. Without the store landing first, a writer released in
  /// that gap reads `retiring = false`, publishes `Owned` and answers `Ok`
  /// for a marker no stream will ever deliver — a claim on another OS thread
  /// cannot observe a live flag for a scope that is gone.
  ///
  /// Taken on the same transitions the cookie floor is (birth, and a commit that
  /// re-records the root under a surviving scope), and idempotent: the flag a
  /// live scope already carries is the one handed back, so a write already in
  /// the pool keeps reading the flag this store will raise. A scope this core no
  /// longer holds binds nothing — it has already been retired.
  // The flag is the scope's OWN terminal bookkeeping and is stored at the core's
  // removal site, which is not about syncs; with the barrier gated out the ledger
  // that binds one is gone, so nothing calls this and nothing reads the field.
  // The removal site deliberately stays ungated, so the two are
  // allowed to stand unread rather than gated with their one caller.
  #[cfg_attr(not(feature = "sync"), allow(dead_code))]
  pub(crate) fn bind_retiring(&mut self, scope: ScopeId, flag: Arc<AtomicBool>) {
    if let Some(state) = self.scopes.get_mut(&scope) {
      state.retiring = Some(flag);
    }
  }

  /// A live scope's canonical root — the commit-time authority the driver's
  /// widen predicate (old ⊂ new) compares against.
  pub(crate) fn root_path(&self, scope: ScopeId) -> Option<Arc<PathBuf>> {
    self.scopes.get(&scope).and_then(|state| state.root.clone())
  }

  /// Whether `incarnation` is the world `scope` watches NOW — the test the driver
  /// applies to a queued scope-bound effect before it performs any syscall for it.
  ///
  /// A stale answer means the effect was armed against ground a commit has since
  /// retired: running it would arm, list or stat the old root on the
  /// replacement's transport, ahead of the corrective work the commit queued.
  /// Path equality is never the test — a same-path replacement leaves the root
  /// bytes equal across a world the effect did not survive.
  ///
  /// `false` for a scope this core does not hold — an obligation of a torn-down
  /// scope describes no world at all.
  pub(crate) fn effect_is_current(&self, scope: ScopeId, incarnation: u64) -> bool {
    self
      .scopes
      .get(&scope)
      .is_some_and(|state| state.incarnation == incarnation)
  }

  /// The incarnation a scope-bound effect queued NOW belongs to — the ONE place
  /// a stamp is read off the scope, so every push site stamps the same way.
  ///
  /// An unknown scope answers the birth value: it queues no effect anyone will
  /// poll, and the poll site refuses it on the scope's absence in any case.
  fn incarnation_of(&self, scope: ScopeId) -> u64 {
    self.scopes.get(&scope).map_or(0, |state| state.incarnation)
  }

  /// A live scope's compiled `prune` seat.
  ///
  /// The seat is the SCOPE's, so the core owns it — but two things outside the
  /// core have to enforce it and cannot reach the core to ask: the blocking
  /// cookie write (which alone knows the canonical directory it is about to
  /// create in) and the kernel-recursive sources (which enforce the seat at their
  /// own admission boundary, so a pruned subtree is never walked, never mapped
  /// and never granted transport). Both are handed this clone — cheap, the
  /// compiled set is shared — rather than a second compilation of the same words.
  ///
  /// An unknown scope answers the unengaged seat: it fences nothing, which is the
  /// fail-open direction every prune site takes.
  pub(crate) fn scope_prune(&self, scope: ScopeId) -> Globs {
    self
      .scopes
      .get(&scope)
      .map_or_else(Globs::default, |state| state.prune.clone())
  }

  /// Whether `dir` is inside the coverage this scope's applied set-cover still claims —
  /// the sync admission's membership test, answered lexically because the cover is a
  /// lexical statement about paths.
  ///
  /// `true` whenever there is nothing to be outside of, which is every case but a
  /// descending scope a caller narrowed:
  ///
  /// - an **unknown scope** — the admission's own live-root gate speaks for that, and
  ///   fail-open is the direction every coverage test here takes;
  /// - a scope with **no applied cover** (`None`) — never narrowed, so the root's whole
  ///   subtree is covered. A kernel-recursive scope is permanently here: `on_set_cover`
  ///   refuses it before recording anything, because a whole-subtree stream has no
  ///   per-directory coverage to narrow;
  /// - a scope whose applied cover is **empty** — the degraded claim a standing `Rescan`
  ///   leaves behind (see [`ScopeState::applied_cover`]). It claims no narrowing at all
  ///   and is being re-armed from the root, so it fences nothing; reading it as the
  ///   literal cover would mark every path outside, vacuously.
  ///
  /// Otherwise `dir` must be an ancestor or a descendant of some retained prefix. A
  /// directory strictly outside is ground the caller's own cover asked this scope to stop
  /// watching, so a marker written there could never be observed — the admission refuses
  /// it before birth ([`DirUncovered`](crate::error::SyncRootError::DirUncovered)).
  #[cfg(feature = "sync")]
  pub(crate) fn covers(&self, scope: ScopeId, dir: &Path) -> bool {
    let Some(cover) = self
      .scopes
      .get(&scope)
      .and_then(|state| state.applied_cover.as_deref())
      .filter(|cover| !cover.is_empty())
    else {
      return true;
    };
    !strictly_outside(cover, dir)
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
  /// [`TaintedWindow`](WidenCommit::TaintedWindow) collects the three
  /// unprovable-commit gates. The witnessed-window one (INV-ROOT): a reserved
  /// death record or a scope loss signal landed between the reservation and
  /// this commit, so the reserved binding cannot be proven live. The
  /// adopted-object one: the OLD root's identity does not fit the Monitor's
  /// enumerate-mint space, so the widen's dark-window tripwire would have no
  /// expected object to re-prove the adopted edge against. The adopted-path
  /// one: the old root sits more than one segment down, so the splice's
  /// intermediate connectors would carry edges no marker proves and no
  /// `MoveSelf` invalidates. `Monitor::widen_root` refuses both of the latter
  /// two shapes outright — screened HERE so neither refusal reaches the
  /// driver-bug channel below. Any of the three refuses the
  /// splice with the core and Monitor untouched except for the
  /// spent window, and the caller (which owes no loudness — this is a
  /// legitimate outcome, and it must NOT close the window again) disarms the
  /// pre-armed descriptor and falls back to the general stream replace,
  /// re-establishing the binding through a fresh spawn barrier. Only the widen's
  /// zero-gap SHORTCUT is depth-capped: the stream replace re-roots to an
  /// arbitrarily distant ancestor, so no reachable root becomes unwatchable.
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
    // DEPTH ONE only. Past one segment the splice would mint intermediate
    // connectors whose edges nothing proves and nothing invalidates
    // ([`TaintCause::UnprovableChain`]), and `Monitor::widen_root` refuses that
    // shape outright — screened HERE, in the Monitor's own order (chain shape
    // before identity), so that refusal never reaches the driver-bug channel
    // below, exactly as the unmintable-identity screen does. A well-formed,
    // clean-window widen of a deep root is a LEGITIMATE fallback: the stream
    // replace re-roots to an arbitrary ancestor through a fresh spawn barrier,
    // paying a covering `Rescan` and a re-crawl instead of a window proof, so
    // the capability survives the refusal and only its zero-gap shortcut does
    // not. Spending the window is part of the disposal — the caller's
    // `TaintedWindow` arm deliberately does not close it, and a leaked entry
    // would poison a future widen's reservation on this scope if the fallback's
    // spawn then failed.
    if chain.len() > 1 {
      let spent = state
        .pending_widen
        .take()
        .expect("the taint gate above proved the window live");
      return WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::UnprovableChain,
        benign: spent.benign,
      });
    }
    // The adopted node's identity, in the enumerate-mint space (the bare inode
    // — see `mint`): the old root sits on the scope's own device by the widen
    // predicate, so the device-trust gate is satisfied by construction.
    let old_identity = state
      .identity
      .and_then(|id| u64::try_from(id.ino()).ok())
      .and_then(NonZeroU64::new)
      .map(Identity::new);
    // No mintable identity, no adoption. `widen_root` requires one — it is the
    // only thing the tail's first read can re-prove the adopted edge against,
    // and confirming that edge on ignorance would certify a dark-window swap.
    // Screen it here so the Monitor's refusal stays what the assert below says
    // it is (a driver bug), and dispose it as the window's own legitimate
    // spend: the fallback replace rebuilds the binding from a fresh spawn
    // barrier, which needs no identity to be correct. Consuming the window is
    // part of that disposal — the caller's `TaintedWindow` arm deliberately
    // does not close it, and a leaked entry would poison a future widen's
    // reservation on this scope if the fallback's spawn then failed.
    let Some(old_identity) = old_identity else {
      let spent = state
        .pending_widen
        .take()
        .expect("the taint gate above proved the window live");
      return WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::UnmintableIdentity,
        benign: spent.benign,
      });
    };
    let Some((_, attempt)) = self
      .monitor
      .widen_root(scope, reserved, chain, Some(old_identity))
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
    // closed until the refresh this arms completes.
    state.incarnation += 1;
    state.root = Some(root);
    state.root_dev = Some(meta.root_dev);
    state.root_mnt_id = meta.root_mnt_id;
    // A token belongs to the mount it was proven against, so a new world starts
    // with none: comparing this world's first reading against the previous root's
    // token would read the swap as a frame move on top of the swap itself.
    state.root_incarnation = None;
    retire_root_recovery(state);
    state.identity = Some(meta.identity);
    install_mount_table(state, meta.mounts.iter().map(|row| row.location.clone()));
    // The ONE world entry that seeds its own mount-change baseline (#74) instead
    // of leaving the first authoritative refresh to install one.
    //
    // A registration and a replace both hand the consumer a covering statement
    // for the whole new root — the crawl's closing `Rescan`, the commit's
    // epoch-bumped one — so nothing is owed for the window between the barrier's
    // table read and the first refresh, and the refresh may simply install. A
    // widen deliberately splices WITHOUT domination: it mints no covering
    // `Rescan` at all, and the ADDED ground is read by the chain arm's cold
    // enumerate, which declines beneath every mount it finds. So a mount that is
    // listed by this barrier and gone by the first refresh leaves ground that was
    // declined by the crawl and never re-read by anything — invisible forever, if
    // that first refresh were the baseline rather than the first comparison.
    //
    // The two readings are comparable by construction: the seed reader enriches
    // its rows with the same per-row unique ids the refresh sampler reads, for
    // exactly this reason (see `os::linux::mounts_under`). A seed row that
    // degrades where the refresh's does not costs one whole-root cover on this
    // scope's first refresh — bounded, once per widen, and in the covering
    // direction.
    let mut seeded = meta.mounts;
    seeded.sort_unstable();
    state.table_fingerprint = Some(seeded);
    // A brand-new world: nothing learned about the previous one survives, and
    // nothing else may empty this set (see [`ScopeState::learned_mounts`]).
    state.learned_mounts.clear();
    // An in-flight refresh is disowned for the reason the stream replace disowns
    // it: a widened root is a different object, and its first refresh must not be
    // one the OLD root's possibly-wedged probe still owes. The driver retires the
    // scope's probe tag at this commit too, so the old root's answer is dropped
    // before the core sees it and the refresh armed below is applied on arrival
    // (see [`Self::on_root_replaced`]).
    state.refresh_pending = false;
    state.refresh_stale = false;
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
    // The refresh alone is superseded, and the widen purges it for the reason the
    // stream replace does: it was armed against a different object, and the
    // driver's generation reaches only probes already dispatched (see
    // [`Self::on_root_replaced`]). The rest of the queue is CARRIED into the new
    // incarnation rather than taken: a widen adopts the old root as a child of
    // the new one, keeps the transport and every watch id, and re-queues nothing
    // for the subtree, so its queued arms, disarms, listings and stats name ground
    // that is still live and still owed — dropping one would leave its Monitor
    // node arming with no arm outstanding and nothing to re-issue it.
    let incarnation = state.incarnation;
    Self::purge_scope_refreshes(&mut self.effects, scope);
    Self::rebase_scope_effects(&mut self.effects, scope, incarnation);
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
        change.is_dir(),
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
    // BARRIER FUNNEL: a transport-level loss may have swallowed any coverage
    // transition at all, so it is one about the whole scope. The overflow cut
    // below stands the covering `Rescan`.
    Self::barrier_moved(
      &mut self.barrier_moves,
      state,
      scope,
      BarrierLocation::Scope,
      true,
    );
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
    Self::arm_refresh(effects, scope, state, RefreshCause::Invalidating);
  }

  /// Arms one mount-table refresh for `scope`, coalescing onto an outstanding
  /// one instead of stacking effects. Serves the birth refresh (authority is
  /// never presumed at spawn), every post-loss re-read, and the periodic tick.
  ///
  /// What the coalescing DOES to the outstanding read is `cause`'s business (see
  /// [`RefreshCause`]): an invalidating arming condemns it (`refresh_stale`, so
  /// its completion is discarded and one fresh read re-runs), a periodic one
  /// merely rides on it. Only the invalidating branch ever writes the flag, so a
  /// tick can neither condemn a sound snapshot nor absolve a condemned one.
  fn arm_refresh(
    effects: &mut VecDeque<Effect>,
    scope: ScopeId,
    state: &mut ScopeState,
    cause: RefreshCause,
  ) {
    if state.refresh_pending {
      if matches!(cause, RefreshCause::Invalidating) {
        state.refresh_stale = true;
      }
      return;
    }
    // No canonical root means no live stream: nothing to read yet, and the
    // spawn arm re-arms once the root installs.
    let Some(root) = state.root.clone() else {
      return;
    };
    state.refresh_pending = true;
    effects.push_back(Effect::RefreshMounts {
      scope,
      incarnation: state.incarnation,
      root,
    });
  }

  /// Withdraws the refresh `scope` has pending because the driver DECLINED to
  /// dispatch it, and — where the decline means nothing is proving this root's
  /// liveness — says so on the scope's own stream.
  ///
  /// Coalescing is right only onto a probe that is actually running. A pending
  /// mark standing for a probe nobody sent would swallow every later arming for
  /// this scope — `arm_refresh` would set the stale bit and return — and nothing
  /// would ever clear it, because the completion that clears it is the one that
  /// was never dispatched. Dropping the mark costs one interval and lets the next
  /// tick try again, which is exactly what a saturated budget should degrade to.
  ///
  /// The liveness deadline is re-armed here too, and that is not decoration: the
  /// deadline is seeded by a completing refresh, so a scope whose BIRTH refresh is
  /// the one declined has no deadline yet and would never tick again — the
  /// silently permanent hole a budget must not open.
  ///
  /// # A declined probe is a lost PROOF, and [`BudgetFull`](DeclineReason::BudgetFull)
  /// says so
  ///
  /// Dropping the mark and re-arming the deadline is the whole answer for
  /// [`ScopeBusy`](DeclineReason::ScopeBusy): a probe of this scope is running,
  /// and its completion is the proof. At the BUDGET there is no such probe. Every
  /// slot is held by a call that may never return, so this root's death — which
  /// on a descending backend can be postponed indefinitely by a descriptor a
  /// stalled write is holding — has nothing left to detect it, and the next tick
  /// will be declined for the same reason. Withdrawing the mark alone would leave
  /// the scope FALSELY LIVE and silent: the subscriber keeps a coverage claim
  /// nobody is checking and is never told.
  ///
  /// So the scope goes through the loss funnel the rest of the core already uses
  /// — a whole-scope [`barrier_moved`](Self::barrier_moved) and the covering
  /// `Rescan` the Monitor mints for it — and the subscriber learns that its
  /// coverage is UNPROVEN and must re-enumerate, rather than being told a root is
  /// alive on no evidence. The retry deadline is kept: this is a degradation, not
  /// a terminal.
  ///
  /// TWO LATCHES, because the report and the watch-set recovery are owed on
  /// different schedules.
  ///
  /// The RECOVERY ([`budget_recovered`](ScopeState::budget_recovered)) is the
  /// reconcile the Monitor's overflow path performs along with its mint, and it
  /// is made once per EPISODE: a declined probe read nothing and dropped
  /// nothing, so re-proving every binding under the root answers a question
  /// nobody asked, and repeating it every interval invalidates the generation
  /// the previous one is still arming under. It clears at a refresh that
  /// completes, so an episode a probe ends is over and a later one is new.
  ///
  /// The REPORT ([`budget_report_owed`](ScopeState::budget_report_owed)) is
  /// RENEWABLE: once per covering `Rescan` DELIVERED. An EVENT IS NOT A STATE —
  /// the instruction says "re-enumerate now", and a subscriber that does so has
  /// discharged it — so a root that dies quietly after the first one would stay
  /// falsely live for as long as the saturation lasts, and a scope the budget
  /// starves can never dispatch the probe that would end the episode. The
  /// liveness interval bounds the rate, and the consumer chose it.
  ///
  /// So every refused tick raises the whole-scope move, and then:
  ///
  /// - the recovery not yet made — the Monitor's overflow path, which mints the
  ///   covering `Rescan` and reconciles the watch set;
  /// - the recovery made and no report owed —
  ///   [`Monitor::report_loss`](tributary_proto::Monitor::report_loss), the same
  ///   root-located loss instruction without the reconcile;
  /// - a report still owed — nothing but the move. The queued `Rescan` speaks
  ///   for this window too, and it stands ahead of everything else this scope
  ///   has queued (its own mint purged what preceded it), so there is nothing
  ///   left to purge and nothing to stand.
  ///
  /// The first two purge before they mint: the instruction is appended at the
  /// TAIL of the effect queue, which is polled front-first, so anything of this
  /// scope queued since the last delivered instruction would otherwise reach the
  /// consumer ahead of it.
  ///
  /// NOTHING IS REPORTED before the scope is
  /// [`publicly_live`](ScopeState::publicly_live). A spawn queues the birth
  /// refresh before a descending root arms, so a decline at a saturated budget
  /// can land while no caller holds a handle: the never-live fence drops the
  /// instruction, nothing can ever deliver it, and a latch set there would
  /// silence every later public tick. So a pre-public decline makes the recovery
  /// exactly as a public one does — its `Rescan` is fenced, which costs nothing
  /// — and owes no report, and a pre-public tick after that recovery raises the
  /// move and nothing else. The move is itself inert before public: admission
  /// needs a live root, so there is no obligation in flight to retire.
  ///
  /// Deliberately NOT the full [`on_root_overflow`](Self::on_root_overflow)
  /// treatment: device trust is left alone, because closing it arms another
  /// refresh — the very effect the budget cannot dispatch — and parked work is
  /// left alone, because nothing here says a window was dropped. What IS taken
  /// from it is the barrier funnel, because what this arm establishes is exactly
  /// what an overflow establishes for a live barrier: a window this scope cannot
  /// account for.
  pub(crate) fn on_refresh_declined(
    &mut self,
    scope: ScopeId,
    now: Instant,
    reason: DeclineReason,
  ) {
    let interval = self.root_liveness_interval;
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    state.refresh_pending = false;
    Self::arm_liveness(state, interval, now);
    let recover = match reason {
      // A probe of this scope is RUNNING, and its completion is the proof: no
      // window goes unaccounted for, so no funnel fires and neither latch moves.
      DeclineReason::ScopeBusy => return,
      DeclineReason::BudgetFull => !std::mem::replace(&mut state.budget_recovered, true),
    };
    let report = !recover && state.publicly_live && !state.budget_report_owed;
    if state.publicly_live && (recover || report) {
      // An instruction is about to be minted, and it is owed until the consumer
      // has it.
      state.budget_report_owed = true;
    }
    if recover || report {
      // Everything this scope already queued is dominated by the Rescan being
      // minted below (the same sentence `on_delivery`'s `Refused` arm writes):
      // this call runs INSIDE `execute_effects` (fed back from
      // `on_refresh_declined`'s caller), so without this purge a marker
      // `Effect::Emit` queued behind the `RefreshMounts` effect that provoked
      // this decline would be delivered in the SAME `poll_effect` pass, ahead
      // of both the covering `Rescan` appended below and the next loop-top
      // drain. Purging first closes that escape the same way `on_delivery`'s
      // `Refused` arm closes it one screen away.
      Self::purge_scope_emits(&mut self.effects, scope);
    }
    // BARRIER FUNNEL: this root's liveness is UNPROVEN, and a window nothing
    // is proving may have carried any coverage transition at all — so it is a
    // move about the whole scope, the same shape `on_root_overflow` has. The
    // routed cover degrade cannot stand in for it: that funnel is gated on a
    // recorded claim, so a never-narrowed scope — and every kernel-recursive
    // scope, which never records one — would get no move, and an in-pool write
    // would claim after the `Rescan` and certify across the unproven window.
    // Raised on EVERY refused tick, because each interval it turns away is a
    // fresh window this root cannot account for. The covering `Rescan` is the
    // instruction this retirement owes — the one minted below, or the one still
    // queued from the tick that owed it — so the retirement stands none of its
    // own.
    Self::barrier_moved(
      &mut self.barrier_moves,
      state,
      scope,
      BarrierLocation::Scope,
      true,
    );
    if recover {
      self.monitor.on_overflow(Scope::Root(scope), now);
      self.drain_monitor();
    } else if report {
      let _ = self.monitor.report_loss(scope);
      self.drain_monitor();
    }
  }

  /// (Re)arms the periodic root-liveness deadline for a tick-armed scope whose
  /// root is live, or clears it when the tick does not apply (a backend
  /// [`liveness_ticked`](Self::liveness_ticked) refuses, `Duration::ZERO`, or a
  /// root not yet live). Called on
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

  /// Test-only: forces `scope`'s liveness deadline to be immediately due —
  /// [`Instant::ORIGIN`], which every later `now` has already reached — so the
  /// next [`on_timeout`](Self::on_timeout) fires its tick regardless of the
  /// configured interval or how much wall-clock time has actually elapsed.
  ///
  /// Unconditional: it bypasses the `liveness_ticked` / non-zero-interval /
  /// live-root gating [`arm_liveness`] applies, the same way a caller-forced
  /// deadline should — a scope with no root yet simply finds `arm_refresh` a
  /// no-op on the next timeout, exactly as an organically-armed deadline
  /// would. The two seams this backs exist so a suite can drive one scope's
  /// periodic re-stat deterministically instead of waiting on a real interval
  /// to elapse against dozens of parked OS threads — see their docs for why
  /// that wait is the wrong shape on a slow runner.
  /// [`DebugTickLiveness`](crate::driver::Command::DebugTickLiveness) runs the
  /// tick inside its own command arm and drains what it raised before
  /// replying; [`DebugArmLivenessDue`](crate::driver::Command::DebugArmLivenessDue)
  /// replies first and leaves the tick to the driver's own timer, which is the
  /// only staging under which a cell can observe what the production path
  /// orders between a funnel's `Rescan` and the retirement it covers.
  #[cfg(all(test, feature = "tokio", not(miri)))]
  pub(crate) fn force_liveness_due(&mut self, scope: ScopeId) {
    if let Some(state) = self.scopes.get_mut(&scope) {
      state.liveness_deadline = Some(Instant::ORIGIN);
    }
  }

  /// Feeds one mount-table refresh result: updates device trust AND checks the
  /// root's liveness (folded into the same refresh — a kernel-recursive backend
  /// gets no in-tree unmount signal, so this cadence is its root-death check).
  ///
  /// Every completion that arrives here describes the world this scope watches
  /// NOW. The driver's probe generation is the one owner of the cross-world
  /// fence: it retires the scope's tag at the replace commit and at the
  /// same-transport widen commit, and forwards only a current-generation answer,
  /// so a refresh addressed to a root this scope has left is dropped before the
  /// core sees it. The first refresh of a replaced or widened root therefore
  /// carries the new generation and is applied on arrival — its alive verdict is
  /// not re-probed, and its missing verdict is death evidence the gate below
  /// acts on.
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
    // A probe of this scope answered, whatever it answered: the budget episode
    // that left its liveness unproven is over, so a LATER one is a fresh episode
    // and recovers the watch set again ([`on_refresh_declined`]). Cleared ahead
    // of every gate below, since each of them is a completion too. The report
    // latch is NOT cleared here: an instruction the consumer has not been handed
    // is still owed, whatever a probe has since proven.
    state.budget_recovered = false;
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
      // BARRIER FUNNEL: the registered path no longer names the watched object,
      // which ends the coverage of every obligation this scope holds. The
      // self-event below lowers it through the terminal `Rescan` path, so the
      // covering instruction stands.
      Self::barrier_moved(
        &mut self.barrier_moves,
        state,
        scope,
        BarrierLocation::Scope,
        true,
      );
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
    //
    // TWO legs, and the second is what makes the first honest. An id comparison
    // observes a VALUE, and mount ids are allocated lowest-free: a root that went
    // A -> B -> new-A between two refreshes is back on the id this scope still
    // holds, so the comparison passes and the coverage this scope re-established
    // under the FIRST A is never re-checked against the mount actually standing
    // there. So the frame also moves on the INCARNATION token, which is a
    // transition the host observed rather than a value this scope re-read (see
    // [`RootIncarnation`](crate::os::RootIncarnation)).
    //
    // The token only ever ADDS a move. A refresh that answers none, or a host that
    // has none, compares nothing and leaves this exactly the id check it has always
    // been — which is what keeps every host without a mount namespace (and every
    // fake) on the behaviour it had.
    let incarnation_moved = matches!(
      (state.root_incarnation, refresh.root_incarnation),
      (Some(held), Some(read)) if held != read
    );
    if refresh.root_incarnation.is_some() {
      state.root_incarnation = refresh.root_incarnation;
    }
    let frame_changed = if let Some(mnt_id) = refresh.root_mnt_id {
      let changed = state.root_mnt_id != Some(mnt_id);
      state.root_mnt_id = Some(mnt_id);
      changed || incarnation_moved
    } else {
      incarnation_moved
    };

    // Alive and current: (re)arm the liveness tick — the birth refresh seeds it
    // and every later refresh re-seeds it, regardless of whether the mount table
    // itself could be read below.
    Self::arm_liveness(state, interval, now);

    // The COARSE COVER (#74) begins here, and the frame move above is one of its
    // three legs: a root that moved to a different mount is a table change like
    // any other, and folding it in is what keeps a scope from being told twice
    // about one transition.
    let mut fire = frame_changed;

    if refresh.authoritative {
      // The FINGERPRINT, taken before the table half is installed off the same
      // rows. Sorted, because mountinfo's row order is the kernel's own list
      // order: a mount created ELSEWHERE on the host can permute it with nothing
      // under this root having changed, and an order-sensitive comparison would
      // read that as a departure and cover for it every time.
      let mut rows = refresh.mounts;
      rows.sort_unstable();

      // Whether this sample's rows can speak for themselves about a REPLACEMENT.
      // A row's `mnt_id_unique` is never recycled, so two samples that differ by
      // a same-location replacement differ in the rows; a sample carrying none
      // (a kernel below 6.8, a table with no rows at all, or per-row reads that
      // all failed) has only the LEGACY id, which the kernel hands to the next
      // mount as soon as the old one frees it — so a departure and an arrival
      // inside one interval can compare EQUAL.
      //
      // Read off the sample rather than off the per-process tier memo on
      // purpose: the memo answers what the KERNEL can do, and the question here
      // is what THIS reading actually carries. A reading whose per-row reads
      // failed is exactly as blind to a recycled id as a 6.7 kernel is, and it
      // is the reading that gets compared.
      let per_row_unique = rows.iter().any(|row| row.mnt_id_unique.is_some());

      // The conservative leg, and the only one that can over-fire: a namespace
      // transition is SOMETHING mounting or unmounting anywhere on the host, not
      // necessarily under this root. Consumed as a whole-root cover only where
      // the rows cannot answer for themselves, and the alternative there is to
      // keep reading a recycled id as proof of continuity — a silence, which is
      // the one outcome this design refuses. On a busy pre-6.8 host it costs one
      // whole-root `Rescan` per refresh interval; that cost is the ruling.
      let namespace_moved = matches!(
        (state.namespace_transitions_seen, refresh.namespace_transitions),
        (Some(held), Some(read)) if held != read
      );
      if refresh.namespace_transitions.is_some() {
        state.namespace_transitions_seen = refresh.namespace_transitions;
      }

      // A held fingerprint is what makes a comparison possible at all. Its
      // absence is the FIRST authoritative sample of this world — registration's
      // crawl (or the swap's own `Rescan`) already covered the tree, so this one
      // installs and says nothing.
      if let Some(held) = state.table_fingerprint.as_ref()
        && (*held != rows || (!per_row_unique && namespace_moved))
      {
        fire = true;
      }

      // REPLACEMENT, never union: the reads are serialized and this one is not
      // stale, so a location it does not list is a mount the host says is gone —
      // and unioning retained one `PathBuf` per HISTORICAL mountpoint for the life
      // of the scope. What a snapshot may not reach lives in
      // [`ScopeState::learned_mounts`]: an in-band mount word can describe a mount
      // that arrived after this read was taken, and a probe's foreign device is a
      // path no mountinfo row will ever name. Probe-carried device evidence still
      // decides what it can.
      install_mount_table(state, rows.iter().map(|row| row.location.clone()));
      state.table_fingerprint = Some(rows);
      state.mounts_authoritative = true;
    } else {
      // The live table could not be read, so this refresh installs no table — and a
      // prior authoritative install may have left authority OPEN. Leaving it open
      // would keep proving paths root-device by their ABSENCE from a table we just
      // failed to re-read across the very mount change this refresh was meant to
      // reconcile. Close it: absence from an unreadable table is not evidence of
      // in-root-device. Both veto components are kept as they stand (they only ever
      // reduce trust, never grant it) for the next authoritative read to replace
      // the table half of.
      state.mounts_authoritative = false;
    }

    // One difference, one whole-root cover — and the frame move above is one of
    // its three legs. A CHANGED frame means a same-object re-mount moved the root
    // to a different mount: every child the last enumerate already classified
    // carries the OLD verdict — those now on the root's mount were fenced as
    // boundaries, those left behind are boundaries now — and adopting the frame
    // does not re-read them. That is a table change like any other, so it is
    // folded in here rather than covered separately, which is what keeps a scope
    // from being told twice about one transition.
    //
    // Folding it in also stops gating it on the profile. A descending scope
    // consumes the frame directly, so main covered only it; a kernel-recursive
    // scope's mark makes the frame inert, but its FID map was seeded under the
    // OLD mount, and `cover_whole_root` is what rebuilds that — so the fanotify
    // leg is served by the reseed rather than skipped.
    //
    // Nothing here asks WHICH row moved or WHERE it was: a located cover would
    // need a census of the boundaries under the root and a ledger to keep it
    // honest across renames, and neither buys the consumer anything it cannot get
    // from re-reading the tree it was told to re-read. The whole proof is one line
    // — every mount transition under the root changes the table, and every table
    // change covers the root.
    if fire {
      self.cover_whole_root(scope, now);
    }
  }

  /// Covers this scope's WHOLE root once: the consumer is told to re-read from
  /// the root, and a descending scope's per-directory coverage is re-established
  /// under it.
  ///
  /// `on_overflow(Scope::Root(..))` is the primitive on every profile but one —
  /// the Monitor re-enumerates and re-arms, synchronously, and the consumer gets
  /// its `Rescan`. It is the same call a root overflow and a frame change already
  /// made; nothing about it is new here except what asks for it.
  ///
  /// Fanotify is the exception, and the reason is that its sight is a FID map
  /// rather than a kernel-recursive mark on the tree. A mount that departs
  /// reveals ground the seed walk stopped short of, so the map holds no handle
  /// there and events under it decode as outside-root — a `Rescan` alone would
  /// have the consumer read a subtree the source will then never speak about
  /// again. The reseed goes first ([`Effect::RecoverRoot`]) and the cover follows
  /// its completion.
  ///
  /// # The funnel, and why the two branches claim differently
  ///
  /// A cover is a coverage transition over the whole scope, so it passes the
  /// barrier funnel like every other one — a live barrier whose ground a mount
  /// change moved must retire rather than certify. What differs is the claim.
  ///
  /// The synchronous branch stands its covering `Rescan` in the same call, so it
  /// claims one (`rescan_stands = true`) exactly as the frame replay always did.
  /// The fanotify branch does NOT: its `Rescan` is owed by
  /// [`on_root_recovered`](Self::on_root_recovered), a reply that a world swap
  /// mid-walk drops whole, so a retirement here must stand its own. An extra
  /// covering `Rescan` costs a redundant re-read; a missing one is silent loss.
  fn cover_whole_root(&mut self, scope: ScopeId, now: Instant) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    if !matches!(state.profile, BackendKind::Fanotify) {
      // BARRIER FUNNEL: the mount table under the root moved (or the root's own
      // frame did), so every child the last enumerate classified carries a
      // verdict taken against a tree that is no longer there — a coverage
      // transition over the whole scope, whose overflow below stands the
      // covering `Rescan`.
      Self::barrier_moved(
        &mut self.barrier_moves,
        state,
        scope,
        BarrierLocation::Scope,
        true,
      );
      self.monitor.on_overflow(Scope::Root(scope), now);
      self.drain_monitor();
      return;
    }
    // No canonical root means no live stream to reseed; the spawn's own seed walk
    // covers that case.
    if state.root.is_none() {
      return;
    }
    // BARRIER FUNNEL: raised HERE, at the transition, and not at the reply — the
    // ground moved now, and a barrier certified while the reseed walks would be
    // certified over a tree the source cannot yet see. It stands no `Rescan` of
    // its own (the reseed's completion owes that, and a stale epoch drops it), so
    // the retirement stands one itself. Raised before the in-flight check, so a
    // fire that only sets `recovery_dirty` still bumps: it is a transition too.
    Self::barrier_moved(
      &mut self.barrier_moves,
      state,
      scope,
      BarrierLocation::Scope,
      false,
    );
    // Exactly one walk at a time, and exactly one follow-up however many fires
    // arrive during it: a reseed is a full descent of the root, and stacking them
    // would let a churning table hold the blocking pool indefinitely.
    if state.recovery_in_flight {
      state.recovery_dirty = true;
      return;
    }
    state.recovery_epoch = state.recovery_epoch.wrapping_add(1);
    state.recovery_in_flight = true;
    let epoch = state.recovery_epoch;
    self.effects.push_back(Effect::RecoverRoot { scope, epoch });
  }

  /// Feeds the outcome of one [`Effect::RecoverRoot`]: the fanotify source's FID
  /// map has been rebuilt over the whole root, so the consumer may now be told to
  /// re-read it.
  ///
  /// The ORDER is the whole point. The `Rescan` is emitted here, on the reseed's
  /// completion, and never beside the request — a consumer that re-enumerated
  /// while the source was still blind to the revealed ground would see the
  /// subtree once and hear nothing about it afterwards.
  ///
  /// A reply whose `epoch` is no longer the scope's is dropped whole: the world
  /// moved (the root was replaced or widened) while the walk ran, so the map it
  /// rebuilt describes a root this scope no longer watches, and the swap has
  /// already covered the new one.
  pub(crate) fn on_root_recovered(
    &mut self,
    scope: ScopeId,
    epoch: u64,
    outcome: RootRecovery,
    now: Instant,
  ) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    if state.recovery_epoch != epoch {
      return;
    }
    state.recovery_in_flight = false;
    if matches!(outcome, RootRecovery::Unreachable) {
      // The walk could not reach the root at all. That is a root death and takes
      // the SAME funnel a refresh's death gate takes — terminal `Removed`/`Rescan`
      // and registry reclamation — rather than a cover for a tree that is gone.
      // Nothing is owed after it, so the dirty flag dies with the scope.
      let watch = state.watch;
      state.recovery_dirty = false;
      // BARRIER FUNNEL: the root no longer names a tree this source can reach,
      // which ends the coverage of every obligation this scope holds — the
      // refresh death gate's own funnel, raised here because this is the same
      // verdict reached by the other observation. The self-event below lowers it
      // through the terminal `Rescan` path, so the covering instruction stands.
      Self::barrier_moved(
        &mut self.barrier_moves,
        state,
        scope,
        BarrierLocation::Scope,
        true,
      );
      self
        .monitor
        .on_os_record(OsRecord::new(watch, RecordKind::DeleteSelf), now);
      self.drain_monitor();
      return;
    }
    // BARRIER FUNNEL: the cover the request could not stand. `cover_whole_root`
    // bumped for the transition itself and claimed no `Rescan`; this one stands
    // the `Rescan` right below it, and retires anything dispatched into the
    // window the reseed was walking — ground the source could not yet see.
    Self::barrier_moved(
      &mut self.barrier_moves,
      state,
      scope,
      BarrierLocation::Scope,
      true,
    );
    self.monitor.on_overflow(Scope::Root(scope), now);
    self.drain_monitor();
    // A fire during the walk: the table moved again, possibly under ground this
    // walk had already descended, so its map cannot be trusted to have seen it.
    // One more round, and only one.
    if self
      .scopes
      .get_mut(&scope)
      .is_some_and(|state| std::mem::take(&mut state.recovery_dirty))
    {
      self.cover_whole_root(scope, now);
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
    if matches!(delivery, Delivery::Accepted) {
      // The consumer's channel holds a change of this scope, so whatever
      // covering `Rescan` a probe-budget decline left owed has been handed over
      // and the next tick refused at the budget reports again
      // ([`on_refresh_declined`](Self::on_refresh_declined)). The SCOPE names
      // that instruction precisely enough: the decline purges everything this
      // scope had queued before minting it, and it runs inside `execute_effects`
      // where no emit of this scope can be in flight, so the first delivery of
      // this scope after a decline is the instruction itself. A REFUSAL leaves
      // it owed — the arm below stands the replacement — so the latch survives
      // one; and a consumer that dropped its stream is reported no delivery at
      // all, which is the one case nothing is owed to.
      state.budget_report_owed = false;
    }
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
        // BARRIER FUNNEL: the lag entry synthesizes a root overflow, and it is
        // one about the whole scope for the same reason `on_root_overflow` is —
        // everything this scope drops from here until the lag exits is a window
        // it cannot account for. The routed cover degrade cannot stand in for
        // it: that funnel is gated on a recorded claim, so a never-narrowed
        // scope — and every kernel-recursive scope, which never records one —
        // would get no move, no child-watch funnel would fire either, and an
        // in-pool write would claim `Ok` after the covering `Rescan` was
        // queued, its marker then dropped while lagged or delivered behind the
        // instruction. Raised in the order the probe-budget decline uses —
        // purge the queued emits, raise the move, then synthesize the overflow
        // — so the retirement withdraws the in-pool marker and answers
        // `Dominated` before the write can claim. The instruction this
        // retirement owes is the overflow's own `Rescan`, parked below as the
        // lag's dominating change: while the lag stands every other change of
        // this scope is dropped, so the parked one precedes every later delta
        // the consumer will see, and the retirement stands none of its own.
        Self::barrier_moved(
          &mut self.barrier_moves,
          state,
          scope,
          BarrierLocation::Scope,
          true,
        );
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
  /// the periodic root-liveness re-stat for every tick-armed scope whose tick
  /// came due (the ONE timer the Linux composition adds — a quiet unmount
  /// produces neither a birth nor a loss refresh, and a death notice a held
  /// descriptor is postponing produces neither either, so without this the
  /// death would go unobserved for as long as that lasts).
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
    // while each scope is mutated in turn.
    //
    // A refresh already in flight coalesces — `RefreshCause::Periodic`, so the
    // tick rides that read rather than condemning it. The deadline still
    // advances here, so a coalesced tick loses no obligation: the read it rode
    // publishes (installing the table and adopting the frame) and re-seeds the
    // deadline itself on its alive completion, so the cadence simply re-bases
    // off whichever of the two lands later. Condemning it instead is what
    // starves the whole publication path once refresh latency reaches the
    // interval (see [`RefreshCause`]).
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
        Self::arm_refresh(&mut self.effects, scope, state, RefreshCause::Periodic);
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
  /// - [`liveness_deadline`](ScopeState::liveness_deadline), the periodic
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
    // The EXCLUSION half stands down where the backend decides exclusions at
    // admission, and where the caller configured none. The PRUNE half never
    // stands down for a backend — no OS API takes a glob, so no backend can have
    // decided that question already — only for a root that configured no
    // patterns.
    let exclusions = !self.exclusions.is_empty() && !backend_enforces_exclusions(state.profile);
    let fence = exclusions || !state.prune.is_empty();
    // The geometry half additionally stands down for a kernel-recursive profile
    // (see [`reparent_geometry`](Self::reparent_geometry)); the fence itself does
    // not. What the profiles WITHOUT geometry owe a prune seat instead is the
    // blunt destination cover ([`reveals_ground`](Self::reveals_ground)).
    let geometry = fence && runs_rename_geometry(state.profile);
    let reveals = Self::reveals_ground(state);
    if !fence && !at_classify {
      return;
    }
    // The paired SOURCES this batch carries, taken before the walk for the same
    // reason the consumptions are collected beside it: the walk holds
    // `batch.items` mutably and empties each item's planned inputs as it judges
    // them. Empty on the discipline that feeds as it classifies, where the half
    // is already parked in the Monitor by the time its destination is judged.
    let paired = if at_classify {
      Vec::new()
    } else {
      self.batch_paired_sources(state, batch)
    };
    // The consumptions this pass cannot take itself, collected beside the batch
    // rather than into it: the walk below holds `batch.items` mutably. They are
    // appended to the batch at the end of the pass, still ahead of every feed a
    // batch-classifying profile makes.
    let mut deferred: Vec<MoveCookie> = Vec::new();
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
        let planned = if fence {
          match self.fenced(state, exclusions, scope, &planned, &paired, &mut deferred) {
            Fenced::Stands => planned,
            Fenced::Dropped => continue,
            // The widened signal takes the dropped one's PLACE, so everything
            // below reads the input that is actually going to the Monitor.
            Fenced::Widened(widened) => widened,
          }
        } else {
          planned
        };
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
        // The same question the geometry pass answers from the Monitor's report,
        // asked of the record alone because on these profiles there is no report
        // to read (see [`revealed`](Self::revealed)).
        let revealed = if reveals {
          Self::revealed(&planned)
        } else {
          None
        };
        let outcome = Self::accept(
          &mut self.monitor,
          &mut self.barrier_moves,
          state,
          scope,
          &mut kept,
          planned,
          now,
        );
        // The repair is by construction anchored at a reported destination, so
        // it needs no fencing of its own. It follows the record it repairs, in
        // this order, on both disciplines.
        if let Some((watch, target)) = landing
          && let Geometry::Repair(repair) =
            self.reparent_geometry(state, exclusions, scope, watch, target.as_ref(), &outcome)
        {
          Self::accept(
            &mut self.monitor,
            &mut self.barrier_moves,
            state,
            scope,
            &mut kept,
            repair,
            now,
          );
        }
        // The destination cover goes through the FENCE like anything else bound
        // for the Monitor. It is born after the record's own verdict was taken,
        // and it names a path that verdict never judged: a directory rename into
        // pruned ground keeps both halves (neither is a PROVEN directory, so
        // neither is judged on its own last segment) and then reveals a
        // destination the seat does cover. Accepting it unjudged emitted a
        // `Rescan` naming exactly the subtree the caller pruned — an instruction
        // to enumerate ground whose every later change stays silent.
        if let Some(repair) = revealed
          && let Some(repair) =
            self.fenced_repair(state, exclusions, scope, repair, &paired, &mut deferred)
        {
          Self::accept(
            &mut self.monitor,
            &mut self.barrier_moves,
            state,
            scope,
            &mut kept,
            repair,
            now,
          );
        }
      }
      item.planned = kept;
    }
    if fence {
      let trailing = core::mem::take(&mut batch.trailing)
        .into_iter()
        .filter_map(|planned| {
          match self.fenced(state, exclusions, scope, &planned, &paired, &mut deferred) {
            Fenced::Stands => Some(planned),
            Fenced::Dropped => None,
            Fenced::Widened(widened) => Some(widened),
          }
        })
        .collect();
      batch.trailing = trailing;
    }
    batch.deferred_consumptions.append(&mut deferred);
  }

  /// Re-runs the live fence over one probe's resolution — the second, and last,
  /// place a planned input can be born.
  ///
  /// [`fence_exclusions`](Self::fence_exclusions) judges a batch as it is
  /// compiled, and an item still AWAITING a probe is a placeholder there: its
  /// planned inputs do not exist yet, and
  /// [`on_probe_result`](Self::on_probe_result) installs them wholesale
  /// afterwards. Without this pass those inputs would reach the Monitor unjudged.
  ///
  /// It costs nothing for the exclusion half, which stands down on the ONE
  /// profile that parks for probes (FSEvents enforces its own exclusions), and it
  /// exists for the prune half, which stands down for no backend at all.
  ///
  /// A record the fence takes contributes NOTHING further: its cookie candidacy
  /// goes with it, so a vanished half inside pruned ground can neither be granted
  /// a pairing cookie nor provoke the ambiguity cover that grant would otherwise
  /// stand — which is what keeps a `Rescan` from naming a path the caller pruned.
  /// Its EVIDENCE for someone else's grant survives: a pair straddling the fence
  /// is a real crossing, and the half that lies inside the reported tree is owed
  /// its report. That surviving evidence is also how a vanished SOURCE whose only
  /// destination this fence replaced is still granted its pairing cookie at
  /// settlement — which is why the widening arm's consumption has to RIDE THE
  /// BATCH from here rather than be taken here: the half it names is fed after
  /// this pass, not before it. `deferred` is the carrier, and its caller hands it
  /// to the batch this resolution belongs to.
  ///
  /// Classifying a whole batch ahead of feeding it leaks on a profile whose
  /// records are addressed through per-directory anchors (a reparent mid-read
  /// moves the ground under the records behind it), which is exactly why
  /// [`feeds_at_classify`] is true for the descending profile. This pass is safe
  /// for the same reason it is needed: only FSEvents parks, and every FSEvents
  /// record is anchored at the ROOT watch with a whole root-relative location, so
  /// no reparent can change how a later one resolves.
  fn fence_resolved(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    mut resolved: Resolved,
    deferred: &mut Vec<MoveCookie>,
  ) -> Resolved {
    let exclusions = !self.exclusions.is_empty() && !backend_enforces_exclusions(state.profile);
    if !exclusions && state.prune.is_empty() {
      return resolved;
    }
    let reveals = Self::reveals_ground(state);
    let before = resolved.planned.len();
    let mut kept = Vec::with_capacity(before);
    for planned in core::mem::take(&mut resolved.planned) {
      // The probe-parked profile grants its rename sources their pairing cookies
      // at SETTLEMENT, on evidence this pass does not hold, so no pairing of this
      // batch is established here and the fence has no source to place.
      let planned = match self.fenced(state, exclusions, scope, &planned, &[], deferred) {
        Fenced::Stands => planned,
        Fenced::Dropped => continue,
        Fenced::Widened(widened) => widened,
      };
      // The destination cover the geometry-less profiles owe, queued directly
      // behind the record that provoked it exactly as the batch-time fence
      // queues it. This is the second and last place a planned input is born, so
      // a rename resolved through a probe owes the same repair one judged at
      // compile time does.
      let revealed = if reveals {
        Self::revealed(&planned)
      } else {
        None
      };
      kept.push(planned);
      // Fenced for the reason the batch-time twin is: this cover is born after
      // its record's verdict and names ground that verdict never judged, so it
      // is the one input that could carry a `Rescan` into a pruned subtree.
      kept.extend(
        revealed
          .and_then(|repair| self.fenced_repair(state, exclusions, scope, repair, &[], deferred)),
      );
    }
    resolved.planned = kept;
    if before > 0 && resolved.planned.is_empty() {
      resolved.candidate = None;
    }
    resolved
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
    moves: &mut VecDeque<BarrierEvent>,
    state: &mut ScopeState,
    scope: ScopeId,
    kept: &mut Vec<Planned>,
    planned: Planned,
    now: Instant,
  ) -> RecordOutcome {
    if !feeds_at_classify(state.profile) {
      kept.push(planned);
      return RecordOutcome::Nothing;
    }
    Self::feed(monitor, moves, state, scope, planned, now)
  }

  /// Whether the fence's MEMBERSHIP over the subtree rooted at `path` depends on
  /// where that subtree sits — the mirror of [`is_fenced`](Self::is_fenced),
  /// asked the other way round.
  ///
  /// [`is_fenced`](Self::is_fenced) answers "is this path inside a fence", which
  /// is what suppression needs. Re-parenting needs "does this subtree CONTAIN
  /// fenced ground", because that is what decides whether rewriting the subtree's
  /// path changes which of its descendants are reported.
  ///
  /// The two seats answer it differently, and the difference is forced by what a
  /// pattern IS:
  ///
  /// - **exclusions** are literal paths, so the question is decidable exactly:
  ///   does some exclusion lie at or under `path`? Deliberately expressed through
  ///   [`crate::driver::excluded`] rather than a fresh prefix walk — that is the
  ///   ONE matching rule the cold fence, the live fence, the sync-cookie birth
  ///   refusal and the fanotify backend all share, and a second rule here could
  ///   drift out of step with it and re-open the hole from the other side.
  /// - **prune** is a glob over root-relative paths, whose language cannot be
  ///   enumerated: whether some unseen descendant's verdict flips when the subtree
  ///   is relocated is not a question the matcher can be asked. So a scope with any
  ///   prune pattern answers `true` — CONSERVATIVE in the direction the exclusion
  ///   half already is, and for the same reason: with no answer available, the safe
  ///   direction is the one that costs a re-enumeration, not the one that costs
  ///   coverage.
  ///
  /// The cost of that conservatism is bounded and paid only where the Monitor
  /// actually re-parented a watched subtree
  /// ([`reparent_geometry`](Self::reparent_geometry) consults this only after a
  /// [`RecordOutcome::Reparented`]): one located `Rescan` and one re-arm read of
  /// the destination per directory rename inside a pruned root.
  fn fence_under(&self, state: &ScopeState, exclusions: bool, path: &Path) -> bool {
    if exclusions {
      let containing = [path.to_path_buf()];
      if self
        .exclusions
        .iter()
        .any(|exclusion| crate::driver::excluded(&containing, exclusion))
      {
        return true;
      }
    }
    !state.prune.is_empty()
  }

  /// The destination slot a rename's repair would be lowered against, taken from a
  /// record BEFORE it is fed.
  ///
  /// The two inputs of the post-feed decision sit on opposite sides of the hand-off:
  /// the feed consumes the record, and the outcome that decides whether a repair is
  /// owed at all does not exist until the feed has happened. So the record's own
  /// half is captured here, and joined with the Monitor's report afterwards.
  ///
  /// Gated on the KIND alone. Only a `MovedTo` can report a relocation, and gating
  /// any tighter — on a directory flag the destination half is free to omit — would
  /// let a real one go unrepaired because its record under-described itself.
  fn landing(planned: &Planned) -> Option<(WatchId, Option<Location>)> {
    match planned {
      Planned::Rec(rec) => Self::landing_of(rec),
      _ => None,
    }
  }

  /// [`landing`](Self::landing) for a caller holding the record itself — the
  /// funnel's route, which takes it out of the record it is about to feed so the
  /// rename's destination can be named on the far side of the hand-off. One
  /// rule, asked from both seats.
  fn landing_of(rec: &OsRecord) -> Option<(WatchId, Option<Location>)> {
    matches!(rec.kind(), RecordKind::MovedTo).then(|| (rec.watch(), rec.target().cloned()))
  }

  /// Whether this scope owes a DESTINATION COVER on every directory rename it
  /// keeps: a live prune seat on a profile that runs no rename geometry.
  ///
  /// The defect it answers is [`reparent_geometry`](Self::reparent_geometry)'s,
  /// in the one shape that pass cannot reach. A prune pattern can be
  /// position-sensitive (`a/cache` names one place, not a name at any depth), so
  /// a rename that relocates a subtree changes which of its descendants are
  /// pruned — and BOTH endpoints of such a rename are reported, so the
  /// record-by-record fence preserves the pair and suppresses nothing. On a
  /// descending profile the Monitor answers that rename by re-parenting a watch
  /// subtree and SAYS SO, and the geometry pass re-enumerates from its report.
  /// The other profiles have no such report to read: FSEvents and fanotify decide
  /// exclusions at admission and RDCW and USN are kernel-recursive, so none of
  /// them keeps per-directory watches to re-parent. Their consumer is left
  /// holding a `Moved(a → b)` and no way to learn that `b/cache/x`, silent until
  /// now, has become reportable — silent, permanent, and invisible in exactly the
  /// direction the caller cannot audit.
  ///
  /// So they pay the same conservatism the geometry pass pays, without the
  /// report: every kept directory rename gets one located `Rescan` at its
  /// destination, and the consumer re-enumerates. It repairs no coverage — a
  /// kernel-recursive stream already covers the destination the moment the
  /// re-parent lands — and it does not need to: what was lost is the consumer's
  /// VIEW, and a `Rescan` is exactly the instruction to rebuild it.
  ///
  /// Costed honestly: one extra `Rescan` per directory rename, on a root that
  /// configured a prune seat, on four of the five backends. A scope with no
  /// pattern pays nothing.
  fn reveals_ground(state: &ScopeState) -> bool {
    !state.prune.is_empty() && !runs_rename_geometry(state.profile)
  }

  /// The destination cover one record owes under
  /// [`reveals_ground`](Self::reveals_ground), or `None`.
  ///
  /// Owed by a rename's DESTINATION half whose object is not a proven
  /// non-directory: a proven file move relocates no subtree and can reveal
  /// nothing, while an unproven class is judged as a directory for the same
  /// reason the fence judges it as one — a backend that reported no class has not
  /// reported a file.
  ///
  /// Fenced by its caller before acceptance, and the reason is the very case this
  /// cover exists for: a kept record's endpoint is NOT by construction unpruned.
  /// The record fence judges a leaf only when the backend PROVED it a directory,
  /// and the profiles that owe this cover are exactly the ones whose records
  /// often prove nothing — so a directory rename into pruned ground keeps both
  /// halves and reveals a destination the seat covers. See
  /// [`fenced_repair`](Self::fenced_repair).
  /// One LATE-born repair, run through the same fence every planned input goes
  /// through: `None` where the fence drops it, and the widened signal where the
  /// fence re-aims it above a pruned leaf.
  ///
  /// It exists as its own step because a repair is born on the far side of its
  /// record's verdict — after the feed at batch time, after the resolution at
  /// probe time — and so is the one input the record-by-record pass structurally
  /// cannot have judged. Widening rather than dropping is what keeps the
  /// recovery instruction alive: a `Rescan` one level above the pruned leaf still
  /// covers what was revealed while naming only ground the caller hears about,
  /// which is the same trade [`fenced`](Self::fenced) already makes for every
  /// other located over-signal.
  fn fenced_repair(
    &mut self,
    state: &mut ScopeState,
    exclusions: bool,
    scope: ScopeId,
    repair: Planned,
    paired: &[(MoveCookie, PathBuf)],
    deferred: &mut Vec<MoveCookie>,
  ) -> Option<Planned> {
    match self.fenced(state, exclusions, scope, &repair, paired, deferred) {
      Fenced::Stands => Some(repair),
      Fenced::Dropped => None,
      Fenced::Widened(widened) => Some(widened),
    }
  }

  fn revealed(planned: &Planned) -> Option<Planned> {
    match planned {
      Planned::Rec(rec)
        if matches!(rec.kind(), RecordKind::MovedTo) && rec.is_dir() != Some(false) =>
      {
        Some(Planned::Over(located(rec.watch(), rec.target().cloned())))
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
  /// The rule is [`fence_under`](Self::fence_under) at EITHER endpoint, which
  /// is how the fanotify admission map and the USN journal decide the same question:
  /// one predicate, asked of both ends, never a second matching rule. Its prune half
  /// is the constant `true` — a glob's language cannot be enumerated, so whether some
  /// unseen descendant's verdict flips is not a question the matcher can be asked, and
  /// a scope with any pattern answers "changed" at both ends. Deliberately
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
  /// fails one of those tests reports something OTHER than
  /// [`RecordOutcome::Reparented`] and is answered here by repairing nothing —
  /// which is correct by construction, because watches that did not travel hold
  /// no membership that could have crossed an exclusion boundary with them.
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
    exclusions: bool,
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
    let changed =
      |end: Option<&Path>| end.is_none_or(|path| self.fence_under(state, exclusions, path));
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

  /// The paired SOURCE of every rename this batch carries a cookie for, by
  /// cookie, resolved absolutely.
  ///
  /// It exists for the ONE seat that has to name a rename's source after taking
  /// its destination away: the prune fence's widening arm replaces a `MovedTo`
  /// whose destination the seat covers, so that record never reaches the Monitor,
  /// no pairing is resolved there, and the ground the pairing dominates has to be
  /// named from what the batch itself holds.
  ///
  /// The lowerings that mint a cookie mint it for a pair the backend reported as
  /// ONE rename and emit both halves into the batch, so a cookie found here is a
  /// pairing the events proved rather than one this core predicted. A destination
  /// whose cookie names no half of this batch is answered by the fence's
  /// fail-wide, not by a guess.
  ///
  /// Taken only where the fence classifies a whole batch ahead of feeding it. The
  /// descending discipline parks the source in the Monitor before it judges the
  /// destination, so its source is read there
  /// ([`Monitor::pending_move_from`]) and this pass would allocate for nothing.
  fn batch_paired_sources(
    &self,
    state: &ScopeState,
    batch: &PendingBatch,
  ) -> Vec<(MoveCookie, PathBuf)> {
    let mut sources = Vec::new();
    let planned = batch
      .items
      .iter()
      .flat_map(|item| item.planned.iter())
      .chain(batch.trailing.iter());
    for planned in planned {
      let Planned::Rec(rec) = planned else {
        continue;
      };
      if !matches!(rec.kind(), RecordKind::MovedFrom) {
        continue;
      }
      if let Some(cookie) = rec.cookie()
        && let Some(path) = self.anchored_path(state, rec.watch(), rec.target())
      {
        sources.push((cookie, path));
      }
    }
    sources
  }

  /// Where the half paired with `cookie` came from, absolutely — the ground the
  /// rename dominates, asked of whichever seat holds it on this scope's feeding
  /// discipline.
  ///
  /// A profile that FEEDS AS IT CLASSIFIES ([`feeds_at_classify`]) has already
  /// fed — and parked — the source by the time its destination is judged, so the
  /// Monitor's own store is the seat, and the coordinate it answers with is the
  /// one a paired record's outcome reports through
  /// ([`Monitor::pending_move_from`]). A profile that classifies a whole batch
  /// ahead of feeding it has parked nothing yet, and its pair is in the batch
  /// ([`batch_paired_sources`](Self::batch_paired_sources)).
  ///
  /// `None` where the source cannot be placed at all — a half whose anchor has
  /// died, or a cookie no half of this batch carries. The fence answers that by
  /// failing wide.
  fn paired_source(
    &self,
    state: &ScopeState,
    scope: ScopeId,
    cookie: MoveCookie,
    paired: &[(MoveCookie, PathBuf)],
  ) -> Option<PathBuf> {
    if feeds_at_classify(state.profile) {
      let from = self.monitor.pending_move_from(scope, cookie)?;
      // Joined onto the scope ROOT, the one anchor no reparent inside the tree
      // can move, exactly as the funnel's own rename joins it.
      return Self::anchored_at(&self.monitor, state, state.watch, Some(&from));
    }
    paired
      .iter()
      .find(|(queued, _)| *queued == cookie)
      .map(|(_, path)| path.clone())
  }

  /// What the fence makes of one planned Monitor input — excluded, pruned, or
  /// neither ([`is_fenced`](Self::is_fenced)).
  ///
  /// The prune half needs the object's CLASS as well as its path, and each arm
  /// supplies it from what it holds:
  ///
  /// - a RECORD carries the backend's own verdict, and only a PROVEN directory
  ///   is judged on its own last segment. A class no backend stamped is not a
  ///   proof of a directory either, and reading it as one silences a real file:
  ///   RDCW's basic records carry no class at all, so every create, write and
  ///   delete of a regular `cache` under `prune = ["cache"]` would vanish with
  ///   no `Rescan` behind it. An unproven directory instead costs one watch and
  ///   prunes at its children (see [`crate::driver::prune_prefixes`]);
  /// - a located OVER-signal names a subtree, but not every producer of one has
  ///   proven a directory: a USN `HARD_LINK_CHANGE` on a regular file lowers to
  ///   an exact-file `Rescan`, and a boundary-crossing rename covers the in-root
  ///   END whatever its class. So prune is asked of its PROPER ancestors alone,
  ///   and a leaf the seat covers WIDENS the signal to the nearest unpruned
  ///   parent rather than dropping it. The parent is unpruned by construction —
  ///   every prefix above the leaf was just asked and answered no — and one
  ///   segment is the whole climb.
  ///
  /// Widening is what keeps a recovery instruction from being taken by the very
  /// word it was owed under. Dropping it delivers neither a trustworthy delta
  /// nor the `Rescan` that would repair one, which is the silent loss the fence
  /// exists to prevent; a `Rescan` one level wider covers the pruned leaf's
  /// recovery while naming only ground the caller still hears about.
  ///
  /// The EXCLUSION half never widens. An exclusion is a literal subtree the
  /// caller took out of the reported world, so an over-signal inside one is
  /// dropped exactly as it was.
  ///
  /// # A record has two more ways out of the prune half
  ///
  /// - an ACTIVE sync marker ([`markers`](ScopeState::markers)) STANDS wherever
  ///   it is. The marker is this watcher's own artifact, minted with the sync's
  ///   own nonce, and the barrier waiting on it cannot be resolved by anything
  ///   else; a word that took it would turn a peer's rename of some directory on
  ///   the way to the cookie — which the anchored create correctly follows — into
  ///   the caller's timeout. Its ancestors' words are beside the point for the
  ///   same reason the reserved directory's own exemption is;
  /// - a directory rename INTO pruned ground is COVERED rather than dropped
  ///   ([`unpruned_cover`](Self::unpruned_cover)). The pair's source half lies in
  ///   the reported tree and is kept, so the consumer is told the subtree left —
  ///   but the destination is where anything that lands next will be, and every
  ///   later change there is silent by the seat's own rule. One `Rescan` at the
  ///   destination's nearest unpruned parent is the instruction that covers it,
  ///   and it dominates any barrier still waiting under the moved subtree, which
  ///   a bare drop left waiting for its deadline.
  ///
  ///   That domination is the RENAME'S OWN MOVE, recorded here and AHEAD of the
  ///   widened cover. The destination this arm replaces never reaches the
  ///   Monitor, so no pairing is resolved there and the funnel that records a
  ///   rename off a record's own outcome is never asked; the obligations of the
  ///   scope stay recorded at the path their ground has already left, and the
  ///   widened cover intersects none of them. The move is LOCATED at the rename's
  ///   source and claims the widened cover as its standing `Rescan` — a cover at
  ///   the destination's nearest unpruned ancestor is a prefix of the ground the
  ///   markers moved into, and no `Rescan` this seat stands may name pruned
  ///   ground. A source that cannot be placed
  ///   ([`paired_source`](Self::paired_source)) fails WIDE.
  ///
  ///   The half the Monitor parked for that rename is CONSUMED
  ///   ([`Monitor::consume_pending_move`]). The destination this arm replaces
  ///   never reaches the Monitor, so nothing is left to pair with — and an
  ///   unpaired half holds its detached subtree, and the scope's move settle with
  ///   it, until the pairing window elapses. Shedding it at once is what the prune
  ///   seat asked for; waiting a day for a pairing that cannot happen is the
  ///   opposite. Where the half cannot be parked yet — the batch-classifying
  ///   profiles, whose fences all run ahead of their feeds — the cookie rides
  ///   `deferred` onto the batch instead, to be consumed the moment that batch's
  ///   records are fed.
  fn fenced(
    &mut self,
    state: &mut ScopeState,
    exclusions: bool,
    scope: ScopeId,
    planned: &Planned,
    paired: &[(MoveCookie, PathBuf)],
    deferred: &mut Vec<MoveCookie>,
  ) -> Fenced {
    match planned {
      Planned::Rec(rec) => {
        if rec.kind().is_self_event() {
          return Fenced::Stands;
        }
        let Some(path) = self.anchored_path(state, rec.watch(), rec.target()) else {
          return Fenced::Stands;
        };
        // The EXCLUSION half, asked first and answering alone: a sync whose
        // cookie directory lies inside an exclusion is refused at BIRTH, so no
        // marker of this scope can stand in one, and a subtree the caller took
        // out of the reported world is owed no covering `Rescan` either.
        if self.excludes(exclusions, &path) {
          return Fenced::Dropped;
        }
        if Self::names_active_marker(state, rec.target()) {
          return Fenced::Stands;
        }
        let directory = rec.is_dir() == Some(true);
        if !Self::is_pruned(state, directory, &path) {
          return Fenced::Stands;
        }
        // A rename whose destination the seat covers. Judged on the same
        // class rule [`revealed`](Self::revealed) uses — a PROVEN file
        // relocates no subtree and reveals nothing, while an unproven class is
        // read as a directory, because the profiles that report the fewest
        // classes are exactly the ones that move whole subtrees silently.
        if matches!(rec.kind(), RecordKind::MovedTo) && rec.is_dir() != Some(false) {
          let widened = self.unpruned_cover(state, scope, directory, &path);
          // The destination never reaches the Monitor, so the SOURCE half parked
          // under this cookie would never be paired: it would hold its detached
          // subtree — and the scope's move settle with it — until the pairing
          // window elapsed, which the option bounds at a day. Nothing is waiting
          // for it any more, so it is consumed here and torn down exactly as that
          // window's expiry would tear it down: the same emissions, the
          // source-side departure included. The widened `Rescan` stands unchanged
          // beside it, and the prune's resource-shedding contract holds without a
          // wait.
          //
          // It reaches the half directly on the discipline that FEEDS AS IT
          // CLASSIFIES ([`feeds_at_classify`]): there the source was fed — and
          // parked — before this destination was judged, so the consumption either
          // finds it or owes nothing, the source lying outside the scope.
          //
          // On a batch-classifying profile every fence runs ahead of every feed, so
          // the half arrives only when the batch's kept records are fed, and the
          // cookie is CARRIED ON THE BATCH to be consumed immediately after that
          // feed. The Monitor keeps no memory of a consumption: the cookie space a
          // source draws from is finite, so a value reused inside the move window
          // would otherwise catch an unrelated later rename and resolve it as a
          // departure plus a creation. Those scopes hold no per-directory watches
          // and so shed no subtree — what an unpaired half of theirs holds is the
          // scope's move settle, and with it every cover fence and every new sync,
          // for the whole window.
          if let Some(cookie) = rec.cookie() {
            // THE PAIRING'S OWN DOMINATION, AHEAD OF THE WIDENED COVER. This
            // destination never reaches the Monitor, so no pairing is resolved
            // there and the funnel that records a rename off a record's own
            // outcome is never asked. The obligations of the scope would go on
            // being judged at the path their ground has already left, and the
            // widened cover — which names the destination's nearest unpruned
            // ancestor — intersects none of them.
            //
            // The source is placed from whichever seat holds it on this
            // discipline ([`paired_source`](Self::paired_source)).
            let from = self.paired_source(state, scope, cookie, paired);
            let scope_wide = matches!(
              &widened,
              Planned::Over(target)
                if matches!(
                  Self::barrier_ground(&self.monitor, state, target),
                  BarrierLocation::Scope
                )
            );
            // THE RENAME'S OWN MOVE, AHEAD OF THE WIDENED COVER — and a LOCATED
            // move rather than this seat's destination, because no `Rescan` may
            // name pruned ground and the destination's parent may lie inside it.
            // The widened cover standing at the destination's nearest unpruned
            // ancestor is a prefix of the ground the retired markers moved into,
            // so it IS their covering instruction and the move claims it.
            let located = from.map(|from| BarrierLocation::at(state, Arc::new(from)));
            match located {
              Some(location) => {
                Self::barrier_moved(&mut self.barrier_moves, state, scope, location, true);
              }
              // A source nobody can place cannot select the obligations the
              // rename moved, so the whole scope is retired — claiming the
              // widened cover only where that cover is itself scope-wide.
              None => Self::barrier_moved(
                &mut self.barrier_moves,
                state,
                scope,
                BarrierLocation::Scope,
                scope_wide,
              ),
            }
            if feeds_at_classify(state.profile) {
              self.monitor.consume_pending_move(scope, cookie);
            } else {
              deferred.push(cookie);
            }
          }
          return Fenced::Widened(widened);
        }
        Fenced::Dropped
      }
      Planned::Over(Scope::Subtree(sub)) => {
        let scope_wide = sub.watch() == state.watch && sub.descent().is_empty();
        if scope_wide {
          return Fenced::Stands;
        }
        let Some(path) = self.anchored_path(state, sub.watch(), Some(sub.descent())) else {
          return Fenced::Stands;
        };
        // The proper ancestors, asked first: a signal under pruned ground has no
        // unpruned parent to climb to inside the subtree the caller closed, and
        // the exclusion half answers here too.
        if self.is_fenced(state, exclusions, false, &path) {
          return Fenced::Dropped;
        }
        if !Self::is_pruned(state, true, &path) {
          return Fenced::Stands;
        }
        let descent = sub.descent();
        Fenced::Widened(match descent.len().checked_sub(1) {
          Some(parent) => Planned::Over(located(
            sub.watch(),
            Some(Location::from_segments(
              descent.segments()[..parent].iter().cloned(),
            )),
          )),
          // A signal at a watch's OWN directory has no descent segment to drop,
          // so the climb would have to leave for a watch this layer cannot name.
          // The scope-wide cover is the honest degrade — never a quiet drop, and
          // never a `Rescan` naming the pruned path.
          None => Planned::Over(Scope::Root(scope)),
        })
      }
      Planned::Over(_) => Fenced::Stands,
      // A retirement's own instruction never reaches this seat: it is stood
      // straight at the funnel ([`stand_covering_rescan`](Self::stand_covering_rescan))
      // rather than compiled from a raw event, and the barrier it retires was
      // refused at birth had its ground lain under a prune seat or an exclusion.
      #[cfg(feature = "sync")]
      Planned::Dominated(_) => Fenced::Stands,
    }
  }

  /// The covering signal a record dropped into pruned ground stands in place of:
  /// ONE located `Rescan` at `path`'s nearest UNPRUNED ancestor, or the scope
  /// cover when that ancestor is the root itself.
  ///
  /// The ancestor is derived rather than climbed one step at a time: the seat's
  /// walk asks the root-relative directory prefixes shallowest-first
  /// ([`crate::driver::prune_prefixes`]), so the FIRST prefix it matches is the
  /// shallowest pruned one and its own parent is unpruned by construction —
  /// every prefix above it was just asked and answered no. That is what makes
  /// one derivation enough for both shapes the seat can take: a destination the
  /// caller pruned by its own name, and one pruned by an ancestor several levels
  /// up.
  ///
  /// Anchored at the SCOPE ROOT watch with a root-relative descent, which is what
  /// lets one derivation serve both lowering profiles: a descending record
  /// anchors at its parent's own watch and a kernel-recursive one at the root, and
  /// only the root is an anchor every profile can name. A watched root never
  /// moves inside its own tree, so the composition cannot go stale.
  ///
  /// Degrades to the scope cover whenever the derivation cannot be made — an
  /// unbound root, an unrepresentable segment, a path outside the root: never a
  /// quiet drop, and never a `Rescan` naming pruned ground.
  fn unpruned_cover(
    &self,
    state: &ScopeState,
    scope: ScopeId,
    directory: bool,
    path: &Path,
  ) -> Planned {
    let located_cover = || {
      let root = state.root.as_deref()?;
      let depth = crate::driver::pruned_ancestor_depth(root, &state.prune, directory, path)?;
      let keep = depth.checked_sub(1).filter(|keep| *keep > 0)?;
      let relative = path.strip_prefix(root).ok()?;
      let mut segments = Vec::with_capacity(keep);
      for segment in relative.iter().take(keep) {
        segments.push(Segment::new(segment.to_str()?));
      }
      Some(Planned::Over(located(
        state.watch,
        Some(Location::from_segments(segments)),
      )))
    };
    located_cover().unwrap_or(Planned::Over(Scope::Root(scope)))
  }

  fn settle_if_ready(
    monitor: &mut Monitor,
    moves: &mut VecDeque<BarrierEvent>,
    state: &mut ScopeState,
    scope: ScopeId,
    batch: PendingBatch,
    now: Instant,
  ) -> bool {
    if batch.awaiting == 0 {
      Self::settle(monitor, moves, state, scope, batch, now);
      true
    } else {
      state.park.active = Some(batch);
      false
    }
  }

  /// Settles a fully-resolved batch: grants evidenced vanished-half cookies,
  /// feeds the Monitor in item order, takes the move consumptions the fence
  /// deferred onto this batch, then applies the deferred unmount trust-removals
  /// (the monotone rule's late edge).
  ///
  /// A feed-at-classify profile ([`feeds_at_classify`]) arrives here with its
  /// items already emptied by the fence, so what it settles is `trailing` alone —
  /// which is where `trailing` belongs on both disciplines, after every item. The
  /// other duties are the reason the split is safe to make per profile: a cookie
  /// grant needs a `cookie_candidate` and `evidenced` partners, a deferred unmount
  /// needs `deferred_unmounts`, and a deferred consumption exists only where the
  /// fence ran ahead of the feeds — and all of them are filled only by the
  /// profiles that do not feed at classify time.
  ///
  /// The consumptions come IMMEDIATELY AFTER the feeds and nowhere later: this is
  /// the settlement that grants a vanished source its pairing cookie and parks its
  /// half, so it is the first instant at which the half the fence's widened
  /// destination orphaned exists to be taken — and the Monitor remembers nothing,
  /// so a call that misses its half owes nothing and takes nothing.
  fn settle(
    monitor: &mut Monitor,
    moves: &mut VecDeque<BarrierEvent>,
    state: &mut ScopeState,
    scope: ScopeId,
    mut batch: PendingBatch,
    now: Instant,
  ) {
    Self::grant_evidenced_cookies(state, scope, &mut batch);
    let unmounts = std::mem::take(&mut batch.deferred_unmounts);
    for item in batch.items {
      for planned in item.planned {
        Self::feed(monitor, moves, state, scope, planned, now);
      }
    }
    for planned in batch.trailing {
      Self::feed(monitor, moves, state, scope, planned, now);
    }
    for cookie in batch.deferred_consumptions {
      monitor.consume_pending_move(scope, cookie);
    }
    for path in unmounts {
      // The LEARNED half only: this word is the one piece of evidence that retires
      // a prefix no snapshot may remove. A table row that named the same mount is
      // dropped by the next authoritative read instead.
      state.learned_mounts.retain(|m| m != &path);
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

  /// Hands one planned input to the Monitor and reports what it RELOCATED.
  ///
  /// The [`RecordOutcome`] is the Monitor's own account of the rename it just
  /// resolved — never a prediction re-derived from the same record by a second
  /// implementation of the same rule. The re-key half of it is what the geometry
  /// pass decides on ([`reparent_geometry`](Self::reparent_geometry)); the
  /// domination below reads the whole of it.
  ///
  /// An overflow instruction relocates nothing, so it reports nothing.
  ///
  /// It is also the BARRIER FUNNEL every located `Rescan` this core mints passes
  /// through — the twenty-odd [`Planned::Over`] construction sites and the one
  /// [`Planned::Dominated`] site all drain here — so the bump for one is raised
  /// here and at none of them. The two arms raise the SAME bump over the same
  /// ground; what separates them is what the Monitor is then asked to do with
  /// the slice, and what the routing seat makes of the `Rescan` that comes back
  /// (see [`Planned::Dominated`]).
  fn feed(
    monitor: &mut Monitor,
    moves: &mut VecDeque<BarrierEvent>,
    state: &mut ScopeState,
    scope: ScopeId,
    planned: Planned,
    now: Instant,
  ) -> RecordOutcome {
    match planned {
      Planned::Rec(rec) => {
        // The destination slot the domination would be aimed at, taken while
        // the record is still in hand: the feed consumes it, and the report that
        // says whether anything relocated at all does not exist until the feed
        // has happened.
        let landing = Self::landing_of(&rec);
        let outcome = monitor.on_os_record(rec, now);
        // EVERY PAIRED DIRECTORY RENAME DOMINATES THE BARRIERS UNDER ITS
        // SOURCE. This is the one seat the Monitor's own report of a relocation
        // is produced at, and it is reached by every profile and every
        // configuration — the geometry pass beside it is gated on the fence, and
        // a scope with neither exclusions nor prune patterns renames just the
        // same.
        //
        // Read through the report that answers for BOTH shapes of relocation, so
        // one line covers the profiles that keep per-directory child watches and
        // the ones that keep none. A kernel-recursive stream covers the
        // destination the moment the rename lands and so re-keys nothing — but
        // its located moves still name the POST-rename path, and a ground
        // recorded at the pre-rename one intersects none of them.
        if let Some(from) = outcome.paired_from() {
          Self::barrier_renamed(moves, monitor, state, scope, from, landing);
        }
        outcome
      }
      Planned::Over(target) => {
        // The ground is read BEFORE the overflow reshapes the watch tree the
        // anchor is placed against. The `Rescan` the Monitor stands IS the
        // covering instruction a retirement would otherwise owe — but only where
        // it actually stands one, and a slice naming ground the Monitor does not
        // cover stands nothing (and owes nothing). A slice naming a held move
        // source stands its instruction at the scope's ROOT, at this item: the
        // located path is the stale pre-move one, and an instruction deferred to
        // whichever move resolves the hold would be overtaken by the delta a
        // pairing fed later in the same batch queues. The Monitor REPORTS which
        // it did, and the funnel records that rather than assuming.
        let ground = Self::barrier_ground(monitor, state, &target);
        let rescan_stands = monitor.on_overflow(target, now);
        Self::barrier_moved(moves, state, scope, ground, rescan_stands);
        RecordOutcome::Nothing
      }
      #[cfg(feature = "sync")]
      Planned::Dominated(target) => {
        // The same funnel bump the overflow arm raises, for the same reason and
        // with the same claim: the `Rescan` this stands IS the covering
        // instruction every obligation it retires is owed. The ground is read
        // first here too, so the two arms record one ground the same way.
        //
        // The claim needs no report from the Monitor, because a retirement's
        // instruction is never deferred: `Monitor::cover_domination` answers at
        // the scope's ROOT where the slice lies inside a held move source, so
        // this seat always stands one. A mint that coalesced stands one too —
        // the twin it folded into is undelivered and covers this ground.
        let ground = Self::barrier_ground(monitor, state, &target);
        Self::barrier_moved(moves, state, scope, ground, true);
        // Latched so the routing seat can tell this instruction from a loss —
        // see [`ScopeState::dominating_rescans`] and [`Planned::Dominated`].
        // ADDED to the standing latches, never made the only one: one drain
        // stands a retirement per obligation the move retired. A mint that
        // coalesced reports nothing and takes nothing away — the instruction it
        // folded into is an earlier mint's, already latched by that mint.
        if let Some(stood) = monitor.cover_domination(target) {
          state.dominating_rescans.insert(stood);
        }
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
      let fed = Self::settle_if_ready(
        &mut self.monitor,
        &mut self.barrier_moves,
        &mut state,
        scope,
        batch,
        now,
      );
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
        content,
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
            // The word coalesced content/metadata changes with the rename: a
            // change existence cannot judge, so it rides the probe and is owed
            // alongside the move. ONE record carries the WHOLE set, so a
            // metadata-only subscription admits a chmod-with-rename that a
            // `Modified` verb alone would have hidden from it. The set holds
            // those two facts and no others: existence subsumes any coalesced
            // create/remove bits at this probed site, and the `moved` fact
            // already rides the `MovedTo` above.
            //
            // `None` is the empty set — most pure renames — and pushes
            // NOTHING, exactly as the bool guard this replaced did. It must
            // NOT fall back to the sibling arms' covering rescan, which would
            // staple one onto every rename.
            if let Some(rec) =
              record_proved(state, content, target.clone(), Some(kind.is_dir()), node)
            {
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

  /// Drops every queued [`Effect::RefreshMounts`] belonging to `scope`. Called by
  /// the widen commit before it re-arms, so the queue holds exactly the live
  /// world's refresh.
  ///
  /// A refresh is armed against ONE root incarnation, and a commit replaces the
  /// world it was armed against. Unlike the emits above it is not dominated work
  /// — the live world still owes a refresh of its own, which the re-arm queues
  /// behind this purge.
  fn purge_scope_refreshes(effects: &mut VecDeque<Effect>, scope: ScopeId) {
    effects
      .retain(|effect| !matches!(effect, Effect::RefreshMounts { scope: s, .. } if *s == scope));
  }

  /// Drops every queued effect of `scope` that would touch the ground the
  /// replace commit just retired. Called by [`on_root_replaced`](Self::on_root_replaced)
  /// before it queues the live world's own, so the queue holds exactly the live
  /// world's obligations.
  ///
  /// The generalisation of [`purge_scope_refreshes`](Self::purge_scope_refreshes):
  /// a queued arm, disarm, listing or stat names the OLD root as surely as a
  /// queued refresh does, and none of them is a probe or a control batch yet — at
  /// the next flush the arm is relabelled onto the replacement's lane, passes its
  /// generation check and runs against the retired root ahead of the corrective
  /// reproof, and a syscall that blocks on a retired mount wedges the
  /// replacement's reader. The replace hook rebuilds every binding the scope owns
  /// (the per-directory book is rebound, the overflow cut re-arms from the root)
  /// and drops the probe and enumerate contexts, so what is taken here is dead
  /// work the live world re-queues for itself.
  ///
  /// The two lifecycle effects and the deliveries are deliberately left standing.
  /// A spawn and a teardown are obligations, never dominated — a dropped teardown
  /// would leak the stream, its lane, its control state and its registry entry. A
  /// delivery carries its own root and is self-describing, so an old world's
  /// change still assembles; the covering `Rescan` this commit stands is queued
  /// behind them, and the emits a commit really must take are the marker emits of
  /// the barriers its whole-scope move retires, which the drain purges before any
  /// effect leaves the queue.
  ///
  /// The WIDEN commit calls this on nothing. It adopts the old root as a child of
  /// the new one, keeps the transport and every watch id, and re-queues nothing
  /// for the subtree — so its queued arms, disarms, listings and stats name ground
  /// that is still live and still owed, and taking them would leave their Monitor
  /// nodes arming with no arm outstanding and no cascade to re-issue one. The
  /// widen carries them into its new incarnation instead
  /// ([`rebase_scope_effects`](Self::rebase_scope_effects)).
  fn purge_scope_effects(effects: &mut VecDeque<Effect>, scope: ScopeId) {
    effects.retain(|effect| match effect {
      Effect::AddWatch { scope: s, .. }
      | Effect::RemoveWatch { scope: s, .. }
      | Effect::Enumerate { scope: s, .. }
      | Effect::Probe { scope: s, .. }
      | Effect::RefreshMounts { scope: s, .. }
      // A reseed of the retired root's sight (#74). The commit bumped the
      // recovery epoch ([`retire_root_recovery`]), so its reply would be dropped
      // on arrival anyway — running it would spend a pool thread walking a tree
      // the replacement no longer watches, and the commit's own covering
      // `Rescan` already speaks for the new one.
      | Effect::RecoverRoot { scope: s, .. } => *s != scope,
      Effect::SpawnStream { .. } | Effect::TeardownStream { .. } | Effect::Emit { .. } => true,
    });
  }

  /// Carries `scope`'s surviving queued effects into `incarnation`. Called by
  /// [`on_root_widened`](Self::on_root_widened) after its own refresh purge.
  ///
  /// A widen adopts the ground its queued obligations name rather than retiring
  /// it, so those obligations belong to the widened world too. Re-stamping them is
  /// what lets the incarnation name the world the scope watches NOW without the
  /// poll site dropping an arm whose directory the widen kept.
  fn rebase_scope_effects(effects: &mut VecDeque<Effect>, scope: ScopeId, incarnation: u64) {
    for effect in effects.iter_mut() {
      match effect {
        Effect::AddWatch {
          scope: s,
          incarnation: stamp,
          ..
        }
        | Effect::RemoveWatch {
          scope: s,
          incarnation: stamp,
          ..
        }
        | Effect::Enumerate {
          scope: s,
          incarnation: stamp,
          ..
        }
        | Effect::Probe {
          scope: s,
          incarnation: stamp,
          ..
        }
        | Effect::RefreshMounts {
          scope: s,
          incarnation: stamp,
          ..
        } => {
          if *s == scope {
            *stamp = incarnation;
          }
        }
        // A recovery carries no incarnation to rebase: its own epoch is the
        // stamp that decides whether its reply still means anything, and the
        // widen bumped that ([`retire_root_recovery`]). The walk it asks for is
        // "re-read the root you are live on", which the widen does not change.
        Effect::RecoverRoot { .. }
        | Effect::SpawnStream { .. }
        | Effect::TeardownStream { .. }
        | Effect::Emit { .. } => {}
      }
    }
  }

  /// Drops every queued [`Effect::Emit`] of `scope` whose change names the
  /// marker leaf `name`, reporting how many went.
  ///
  /// The narrow half of [`purge_scope_emits`](Self::purge_scope_emits), and the
  /// close of the drain-order hole. [`drain_monitor`](Self::drain_monitor) routes
  /// every change BEFORE it processes any action, so a marker's `Created` is
  /// queued as an emit while the coverage transition that retires its barrier is
  /// still an unprocessed action: the consumer would match the marker first and
  /// read a certificate over a window whose ground moved. A retirement therefore
  /// PURGES the marker's queued emit and stands the covering `Rescan` in its
  /// place, both before the effect queue is executed.
  ///
  /// Keyed on the marker's LEAF and on the scope, never on the scope alone: a
  /// scope-wide purge would take the emit of an obligation the location test
  /// spared and time that barrier out. The leaf carries the sync's unpredictable
  /// nonce, so it names this watcher's own in-flight artifact and nothing else,
  /// and a `Moved` is matched on its source leaf too — a marker moved aside is
  /// still the barrier's own object.
  ///
  /// A `Rescan` is never taken. It is the no-silent-loss escape and names a
  /// subtree to re-read rather than an object, so no marker leaf may speak for
  /// one.
  #[cfg(feature = "sync")]
  pub(crate) fn purge_marker_emits(&mut self, scope: ScopeId, name: &str) -> usize {
    let before = self.effects.len();
    self.effects.retain(|effect| {
      !matches!(
        effect,
        Effect::Emit {
          scope: emitted,
          change,
          ..
        } if *emitted == scope && !change.kind().is_rescan() && names_leaf(change, name)
      )
    });
    before - self.effects.len()
  }

  /// Queues the located `Rescan` covering `at` on `scope`'s stream.
  ///
  /// The other half of the substitution: a retiring bump MUST leave a located
  /// `Rescan` covering the retired obligation's ground, because
  /// `SyncOutcome::Dominated`'s public contract promises exactly that — a
  /// re-enumeration instruction is on the caller's stream, so its obligation is
  /// to re-read rather than to worry. Three of the funnels stand none of their
  /// own, and a fourth stands none whenever the Monitor deferred its mint to a
  /// held move source's pairing; this is what those retirements call.
  ///
  /// It goes through [`covering_rescan`](Self::covering_rescan) and
  /// [`feed`](Self::feed) rather than reaching for the Monitor directly, so the
  /// instruction carries everything a `Rescan` this core mints carries — the same
  /// clamp to the scope, the same attribution, the same epoch bump and the same
  /// ordering ahead of every later delta. `covering_rescan` covers the PARENT
  /// of what it is given, which subsumes `at` itself. Its own funnel bump is
  /// idempotent: it names ground already dominated, and it stands a `Rescan`.
  ///
  /// It needs no widening to the root when the obligation's ground lies inside a
  /// held move source. `covering_rescan` lowers `at` TEXTUALLY against the
  /// scope's root and anchors the slice at the scope's ROOT WATCH, which is
  /// never a held source, so the Monitor reconstructs the location from the root
  /// rather than through a hold's stale pre-move parent link: the instruction is
  /// minted synchronously and lands exactly at the ground the obligation named.
  ///
  /// It is stood as a DOMINATION ([`Planned::Dominated`]) and not as a loss: a
  /// domination `Rescan` is not a coverage loss of the applied cover — it tells
  /// the dominated barrier's caller to re-read, it does not say the new cover has
  /// a hole — so it must NOT mark the scope's cover fence lossy and must NOT
  /// rewind the settle floor, and the Monitor recovers no watch set for it. The
  /// funnels that stand their OWN `Rescan` (3 through 7, and 9) go through the
  /// ordinary loss path, which stays lossy: those are losses.
  ///
  /// The drain that follows is what puts the instruction into the effect queue
  /// ahead of the flush the driver is about to run — the whole point of standing
  /// it here rather than one loop pass later.
  #[cfg(feature = "sync")]
  pub(crate) fn stand_covering_rescan(&mut self, scope: ScopeId, at: &Path, now: Instant) {
    let Some(mut state) = self.scopes.remove(&scope) else {
      return;
    };
    let planned = Self::covering_rescan(&state, scope, core::iter::once(at)).into_domination();
    Self::feed(
      &mut self.monitor,
      &mut self.barrier_moves,
      &mut state,
      scope,
      planned,
      now,
    );
    self.scopes.insert(scope, state);
    self.drain_monitor();
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
      newer.is_dir(),
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
            let incarnation = state.incarnation;
            self.effects.push_back(Effect::AddWatch {
              scope,
              incarnation,
              watch: cmd.id(),
              attempt: cmd.attempt(),
              parent: cmd.id(),
              name: Segment::new(name),
              path: root,
              expected,
              frame: state.frame(),
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
            // BARRIER FUNNEL: a child watch armed for the scope, whatever queued
            // it — a crawl, a cascade, a cold enumeration, a `set_cover` grow, the
            // slot reconcile's move-in arm. The arm is the funnel every one of
            // them passes through, so the bump is raised HERE and at none of them.
            // It stands no `Rescan` of its own (an arm emits none), so a
            // retirement under it owes the covering one itself.
            //
            // ONE arm is a deliberate NON-bump: the arming of THIS PROCESS's
            // RESERVED COOKIE DIRECTORY
            // ([`reserved_cookie_dir`](Self::reserved_cookie_dir) — the exact leaf
            // the core holds). The first sync of a directory MINTS that directory
            // and the cascade arms it: it is the barrier's own ground coming into
            // coverage, created by the write itself, and it can only ever hold
            // markers. A foreign directory standing at that name is the EEXIST
            // arm's business — identity against the admission's reading, the
            // sole-entry proof, the exact-leaf exemption — never the epoch's.
            // Without this exemption every barrier dominates ITSELF on its first
            // sync: the arm lands AT the reserved directory, which intersects the
            // obligation's `cover_dir` (its parent, `starts_with` in either
            // direction), so the retirement refuses the claim or purges the emit
            // of the very write that created the ground.
            //
            // The name is matched for EQUALITY against the one leaf this process
            // reserves, never against the classifier's whole name space — the
            // rule `on_set_cover`'s shrink exemption already states, and for the
            // same reason: the space is predictable and unowned, so exempting it
            // would let any peer fill covered ground with reserved-SHAPED
            // siblings whose arms move no stamp. Keep every other arm a bump.
            //
            // This predicate is NAME-ONLY — unlike `on_set_cover`'s twin it does
            // not also require the parent to be inside the retained cover — and
            // that widening is safe only because of a fact this crate does not
            // itself enforce: the CONSUMER classifier (`is_reserved`, two-level
            // ground — parent-is-a-cookie-dir-name OR leaf-is-one) suppresses a
            // foreign directory at this name and everything directly inside it
            // from every stream regardless, so no un-bumped arm here can bring
            // unreported old contents into observable coverage. Everything
            // deeper than depth one is NOT suppressed and still arms under its
            // OWN name, which passes this funnel normally and bumps. A future
            // narrowing of that suppression to one level, or a widening of it to
            // the whole subtree, would silently open this exemption into a real
            // hole — the two are one invariant split across two crates.

            let reserved_cookie_dir = self.reserved_cookie_dir.as_deref() == Some(name.as_str());
            if !reserved_cookie_dir && let Some(state) = self.scopes.get_mut(&scope) {
              let ground = BarrierLocation::at(state, Arc::clone(&path));
              Self::barrier_moved(&mut self.barrier_moves, state, scope, ground, false);
            }
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
            let incarnation = self.incarnation_of(scope);
            // THE arm this fence exists to refuse. A child learned from a
            // `Created` record was never enumerated, so `crosses_mount_boundary`
            // never judged it and `expected` above is `None` (inotify's
            // `Created` carries no identity) — leaving the executor's own object
            // guard vacuous. The frame is what the executor judges it on.
            let frame = self
              .scopes
              .get(&scope)
              .map(ScopeState::frame)
              .unwrap_or_default();
            self.effects.push_back(Effect::AddWatch {
              scope,
              incarnation,
              watch: cmd.id(),
              attempt: cmd.attempt(),
              parent,
              name,
              path,
              expected,
              frame,
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
              // BARRIER FUNNEL: a child watch dropped — a prune, the reconcile's
              // drop-before-arm, a subtree drop. Like the arm above it is the one
              // funnel all of them pass, and it stands no `Rescan` of its own (a
              // shrink-in-place prune emits none by construction).
              //
              // The ground is what the Monitor can still place the watch at.
              // [`Monitor::drop_subtree`] ERASES a node before it queues the
              // node's `Unwatch` (the erase and the push are in the same DFS
              // pop, and `Action::Unwatch` has exactly one producer in the
              // whole workspace), so a dropped watch is UNCONDITIONALLY no
              // longer placeable today and the funnel always records the
              // whole scope: retiring more obligations than the drop touched
              // costs a re-enumeration, while guessing a narrower ground from
              // a remembered path would spare a barrier standing on ground
              // that really did stop being watched. Carrying the dropped
              // node's path on the unwatch action, together with
              // ancestor-coalescing in `barrier_moved`, is tracked as a
              // follow-up: #137.
              let ground = self.scoped_path(scope, watch);
              if let Some(state) = self.scopes.get_mut(&scope) {
                let ground = ground.map_or(BarrierLocation::Scope, |path| {
                  BarrierLocation::at(state, Arc::new(path))
                });
                Self::barrier_moved(&mut self.barrier_moves, state, scope, ground, false);
              }
              let incarnation = self.incarnation_of(scope);
              self.effects.push_back(Effect::RemoveWatch {
                scope,
                incarnation,
                watch,
              });
            }
            continue;
          }
          if let Some(scope) = self.watch_scopes.get(&watch).copied() {
            // THE STORE IS THE IRREVOCABLE TRANSITION POINT, and it comes
            // before anything else moves: before the root-watch mapping is
            // removed, before the scope state is removed, before the fences
            // resolve, before the scope is reported ended and before the
            // teardown is queued. A claim on another OS thread cannot observe
            // a live flag for a scope that is gone — reading the flag through
            // the still-live `scopes` entry and storing `true` first closes
            // the gap a store made AFTER either removal would leave open: a
            // writer claiming in that gap would read `retiring = false`,
            // publish `Owned` and answer `Ok` for a marker no stream will
            // ever deliver. An atomic store is not I/O, so the core stays
            // sans-I/O.
            //
            // The two removals below are not equally load-bearing.
            // `CookieGuard::precedence` reads only this flag — it never
            // consults `watch_scopes` — so the store landing ahead of
            // `self.scopes.remove(&scope)` is what actually closes the claim
            // window; ahead of `self.watch_scopes.remove(&watch)` is
            // defense-in-depth, keeping the whole transition on one side of
            // the store rather than splitting it across a mixed order.
            if let Some(flag) = self
              .scopes
              .get(&scope)
              .and_then(|state| state.retiring.as_ref())
            {
              flag.store(true, Ordering::SeqCst);
            }
            // Test-only seam for the removal-order cell: invoked between the
            // store above and the removals below, so a test can observe the
            // flag already raised while both the scope state and the
            // root-watch mapping are still present. Not part of the
            // production transition; the facts are read only when a hook is
            // installed, so an uninstalled hook costs nothing.
            #[cfg(test)]
            if let Some(hook) = self.removal_hook.as_mut() {
              let scope_present = self.scopes.contains_key(&scope);
              let watch_mapping_present = self.watch_scopes.contains_key(&watch);
              (hook.0)(scope, scope_present, watch_mapping_present);
            }
            self.watch_scopes.remove(&watch);
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
            // THE SCOPE ENDS HERE. Every way a scope dies by an input — a root
            // death by event, a source fatal, an unregistered root — funnels
            // through this one arm, and this is the instant the scope stops
            // existing: it is out of `scopes`, its fences are resolved `Dead`
            // and its teardown is merely QUEUED. Reporting it beside the barrier
            // moves is what lets the driver's drain publish the writes'
            // retirement in this same synchronous pass, ahead of the effect that
            // takes the delivery lane away.
            self.ended_scopes.push(scope);
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
          let incarnation = self.incarnation_of(scope);
          self.effects.push_back(Effect::Enumerate {
            scope,
            incarnation,
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
          let incarnation = self.incarnation_of(scope);
          self.effects.push_back(Effect::Probe {
            scope,
            incarnation,
            probe,
            path,
          });
        }
        other => {
          debug_assert!(false, "the Monitor requests no other work: {other:?}");
        }
      }
    }
  }

  /// Whether `state`'s [`include`](ScopeState::include) seat admits `change`.
  ///
  /// The seat matches one thing: the object's NAME — the LAST segment of its
  /// location. A pattern containing a `/` therefore never admits anything, and
  /// `*.mp4` and `**/*.mp4` are the same seat.
  ///
  /// Six admitting clauses, and every one of them widens rather than narrows:
  ///
  /// - **(a)** a [`Rescan`](ChangeKind::Rescan). It is the no-silent-loss escape
  ///   and names a subtree to re-read rather than an object, so no file pattern
  ///   can speak for it;
  /// - **(b)** an unengaged seat (`None`) — the default, which delivers
  ///   everything and is byte-for-byte the pre-seat path;
  /// - **(c)** an object that is not a PROVEN non-directory
  ///   ([`Change::is_dir`] `!= Some(false)`). Directories always pass, so a moved
  ///   or removed folder is never silent, and an unproven class fails OPEN — a
  ///   backend that reported no class has not reported a file;
  /// - **(d)** this driver's OWN sync cookie: a change whose location IS the
  ///   reserved cookie directory or its DIRECT marker child
  ///   ([`prune_prefixes`](crate::driver::prune_prefixes) exempts exactly the
  ///   same two). The marker is a file, and it is the file a `sync` barrier waits
  ///   on — a caller's pattern about the caller's own media has no business
  ///   deciding whether the watcher can observe its own artifact, and a seat that
  ///   dropped it would turn every restricted-include sync into a timeout. Read
  ///   over every segment because a sync is placed under the SUBSCRIPTION's
  ///   directory, which need not be the root, and read POSITIONALLY because a
  ///   deeper descendant of a cookie-named directory is nothing this driver ever
  ///   wrote: a stray file under one is the caller's own ground and is filtered
  ///   like any other. The layer that owns the namespace keeps these off the
  ///   consumer's stream regardless, so admitting here widens the barrier's view
  ///   and not the caller's;
  /// - **(e)** an ACTIVE sync marker of this scope, by its LEAF
  ///   ([`markers`](ScopeState::markers)) — whatever its parent is called. Clause
  ///   (d) reads the marker's POSITION, and a position is a statement about the
  ///   names above it: rename the reserved directory to an ordinary one between
  ///   the write's descriptor walk and its create (a peer may, and the anchored
  ///   create correctly follows the descriptor) and the marker arrives under a
  ///   parent no classifier recognizes, whereupon a seat naming the caller's own
  ///   media takes the one file the barrier waits on. The leaf is minted with the
  ///   sync's unpredictable nonce, so it identifies this watcher's own artifact
  ///   with no help from its ancestry;
  /// - **(f)** a last location segment that matches;
  /// - **(g)** a [`Moved`](ChangeKind::Moved) whose SOURCE's last segment
  ///   matches — the seat's own pattern, or an active marker leaf. A media file
  ///   renamed to a non-media name is still reported, so the consumer can drop
  ///   what it was holding rather than keep a name that no longer exists; a
  ///   marker moved aside is still the barrier's own object.
  ///
  /// [`Interest::ondir`](tributary_proto::Interest::ondir) keeps governing directory changes
  /// exactly as it did: this seat only ever admits ON TOP of it, never instead of
  /// it.
  fn admits(state: &ScopeState, change: &Change) -> bool {
    let Some(include) = state.include.as_ref() else {
      return true;
    };
    if change.kind().is_rescan() || change.is_dir() != Some(false) {
      return true;
    }
    let segments = change.location().segments();
    if segments.iter().enumerate().any(|(index, segment)| {
      crate::driver::is_sync_cookie_artifact_segment(segment.as_str(), index, segments.len())
    }) {
      return true;
    }
    let matches = |location: &Location| {
      location.segments().last().is_some_and(|segment| {
        include.is_match(segment.as_str()) || state.markers.contains_key(segment.as_str())
      })
    };
    matches(change.location()) || change.kind().moved_from().is_some_and(matches)
  }

  /// Whether `location`'s last segment is an ACTIVE sync marker leaf of `state`
  /// — the identity half of the marker exemption, asked by the prune fence.
  ///
  /// A location with no last segment names no object and can name no marker.
  fn names_active_marker(state: &ScopeState, location: Option<&Location>) -> bool {
    !state.markers.is_empty()
      && location
        .and_then(|location| location.segments().last())
        .is_some_and(|segment| state.markers.contains_key(segment.as_str()))
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
      // The domination latch is consumed HERE too, and not only at the seat
      // below. It is minted per retirement standing and read once by the
      // routing of the change it names; a return that skips that read would
      // strand the entry for the life of the scope, and since the set holds one
      // entry per retirement rather than one slot, a never-public scope would
      // accrue them without bound. Unreachable today — an obligation exists
      // only for an admitted sync, which requires a publicly live scope — which
      // is exactly why the bound is made structural rather than argued.
      #[cfg(feature = "sync")]
      if change.kind().is_rescan() {
        state.dominating_rescans.remove(&change.id());
      }
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
    //
    // A DOMINATION `Rescan` is the ONE exemption, and it is exempt from all of
    // it: the retirement's own instruction tells a dominated barrier's caller to
    // re-read, it does not say the applied cover has a hole. Treating it as a
    // loss made a shrink that dominated a live barrier degrade its own verdict
    // and rewind the claim it had just applied. It is recognized by the id the
    // funnel latched ([`ScopeState::dominating_rescans`]) — by ITS OWN id, one
    // entry per retirement standing, so a drain that retires several
    // obligations exempts every instruction it stood rather than only the last
    // — so every other `Rescan`, including the ones funnels 3 through 7 stand
    // for real losses, reaches the handling below unchanged.
    // With the barrier gated out no retirement ever stands a domination, so the
    // latch has nothing in it and every `Rescan` is the loss it looks like.
    #[cfg(feature = "sync")]
    let dominating = state.dominating_rescans.remove(&change.id());
    #[cfg(not(feature = "sync"))]
    let dominating = false;
    if change.kind().is_rescan() && !dominating {
      self.cover_fences.entry(scope).or_default().mark_lossy();
      if state.applied_cover.is_some() {
        state.applied_cover = Some(Vec::new());
        state.settle_floor = Some(Vec::new());
        // BARRIER FUNNEL: the scope's recorded coverage claim just changed
        // wholesale — what "covered" means for every admission after this is a
        // different statement. It OVERLAPS `feed`'s funnel for a `Rescan` that
        // passed through it (idempotently: both name the same ground, and the
        // second bump retires nothing the first did not), and it is not subsumed
        // by it, because a Monitor-minted `Rescan` — a root invalidation, an
        // arm-failure or stat-deficit re-signal — reaches here without passing
        // `feed` at all. The `Rescan` being routed IS the covering instruction.
        // Built from `state.root`, the same root `BarrierLocation::at`
        // compares against — never `delivery_root()`, whose fallback to
        // `state.requested` for a rootless scope would let the two
        // canonicalizations diverge and record a root-located degrade as a
        // located `Path` instead of `Scope`.
        let ground = match state.root.as_deref() {
          Some(root) => {
            let mut ground = root.clone();
            for segment in change.location().segments() {
              ground.push(segment.as_str());
            }
            BarrierLocation::at(state, Arc::new(ground))
          }
          None => BarrierLocation::Scope,
        };
        Self::barrier_moved(&mut self.barrier_moves, state, scope, ground, true);
      }
    }
    // THE INCLUDE SEAT: the root's file-delivery narrowing, applied here and
    // nowhere else. A change it does not admit is dropped SILENTLY — no effect,
    // no lag accounting, no coverage consequence — because the seat is a
    // statement about what the consumer wants to hear, not about what the core
    // knows. It sits behind the lossy-window handling above deliberately: a
    // `Rescan` is admitted by rule (a) anyway, and the cover bookkeeping it
    // drives is coverage state the seat has no business touching.
    if !Self::admits(state, &change) {
      return;
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

/// Whether `path` lies STRICTLY OUTSIDE `retained` — neither a descendant of a retained
/// prefix (its coverage was asked for) nor an ancestor of one (it connects the root to
/// coverage that was). The set-cover's prune predicate, and the membership test the sync
/// admission asks the applied cover; lexical, exactly as the cover itself is.
///
/// An EMPTY `retained` marks every path outside, vacuously — which is why the empty cover
/// is never applied as a narrowing (`on_set_cover` refuses it) and never read as one (see
/// [`DriverCore::covers`]).
fn strictly_outside(retained: &[PathBuf], path: &Path) -> bool {
  retained
    .iter()
    .all(|r| !path.starts_with(r) && !r.starts_with(path))
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
  state.mounts_authoritative
    && !state.mount_table.iter().any(|m| path.starts_with(m))
    && !state.learned_mounts.iter().any(|m| path.starts_with(m))
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
  // Into the LEARNED half, and deduped only against that half. A word describes a
  // mount that may have arrived after the snapshot currently in flight was read,
  // so pairing it with a table row would let that install drop it; kept
  // independent, it is removed by exactly one thing — the unmount word for the
  // same path, deferred to settlement — which is what bounds this set to the
  // mounts that are actually live.
  if !state.learned_mounts.iter().any(|m| m == &ev.path) {
    state.learned_mounts.push(ev.path.clone());
  }
}

/// Records a probed foreign-device path as a mount prefix, so later
/// event-side identities under it degrade to `None` instead of colliding.
///
/// Into the LEARNED half: this is a path the probe read a device at, not a
/// mountpoint, so no table row need ever name it and an install that replaced it
/// away would re-trust a subtree a stat proved foreign. Deduped against BOTH
/// halves — a path already covered by a live table row or an existing learned
/// prefix adds no veto — which is also what bounds the set: the first prefix
/// learned under a volume absorbs every deeper path on it.
fn learn_device(state: &mut ScopeState, path: &Path, dev: u64) {
  if let Some(root_dev) = state.root_dev
    && dev != root_dev
    && !state.mount_table.iter().any(|m| path.starts_with(m))
    && !state.learned_mounts.iter().any(|m| path.starts_with(m))
  {
    state.learned_mounts.push(path.to_path_buf());
  }
}

/// Installs one authoritative mount table's locations, REPLACING the last one.
///
/// The single write path for [`mount_table`](ScopeState::mount_table) — the spawn
/// barrier's seed, both world swaps' and the authoritative refresh's — so the
/// replacement discipline is stated once and cannot drift between the four.
fn install_mount_table(state: &mut ScopeState, rows: impl IntoIterator<Item = PathBuf>) {
  state.mount_table.clear();
  state.mount_table.extend(rows);
}

/// Retires everything the coarse mount-change cover (#74) holds about the world
/// that just ended — at a spawn, and at both world swaps.
///
/// The fingerprint goes first: it describes the table under a DIFFERENT root, so
/// comparing the new world's first sample against it would read the swap itself
/// as a mount change and cover a tree the swap's own `Rescan` already covered.
/// `None` makes that first sample an install, exactly as it is at birth.
///
/// The epoch BUMPS rather than resets, and that is what makes an in-flight reseed
/// safe to abandon: its reply carries the old stamp, so it is dropped instead of
/// covering the new world off a walk of the old one. Nothing is cancelled — the
/// walk finishes on the blocking pool and its answer is discarded.
fn retire_root_recovery(state: &mut ScopeState) {
  state.table_fingerprint = None;
  state.namespace_transitions_seen = None;
  state.recovery_epoch = state.recovery_epoch.wrapping_add(1);
  state.recovery_in_flight = false;
  state.recovery_dirty = false;
}

/// Whether `change` names the leaf `name` — the object's own last location
/// segment, or a `Moved`'s SOURCE last segment.
///
/// The same two readings [`DriverCore::admits`]' marker clauses take, asked of an
/// explicit name rather than of the scope's active set.
#[cfg(feature = "sync")]
fn names_leaf(change: &Change, name: &str) -> bool {
  let names = |location: &Location| {
    location
      .segments()
      .last()
      .is_some_and(|segment| segment.as_str() == name)
  };
  names(change.location()) || change.kind().moved_from().is_some_and(names)
}

/// [`DriverCore::path_of`]'s derivation, reached without the core: the scope's
/// root joined with whatever the Monitor places `watch` at.
///
/// Split out for the funnels that hold `monitor` and `state` as separate borrows
/// rather than the whole core — one derivation for both, since a second
/// implementation of it is the stored mirror `path_of` exists to have deleted.
fn watch_path(monitor: &Monitor, state: &ScopeState, watch: WatchId) -> Option<PathBuf> {
  let root = state.root.as_deref()?;
  if watch == state.watch {
    return Some(root.clone());
  }
  let mut path = root.clone();
  for segment in monitor.location_of_checked(watch)?.segments() {
    path.push(segment.as_str());
  }
  Some(path)
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
