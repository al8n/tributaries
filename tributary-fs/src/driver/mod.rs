//! The async driver task: a thin executor around [`DriverCore`].
//!
//! Every decision lives in the sans-I/O core; this loop only moves bytes —
//! it selects over the command channel, the core's one timer, the blocking
//! pool's results, and every root's OS batches, executes the core's
//! [`Effect`]s (stream spawn/teardown and probes on the blocking pool, event
//! delivery by `try_send`), and feeds each outcome straight back in.
//!
//! # The one-sample rule
//!
//! Every fact this executor reports about a filesystem OBJECT — kind, device,
//! inode, mount frame — comes from ONE sample of that object: a single `statx`
//! (or `symlink_metadata`) of one path, or one `fstat` of one pinned fd. Never
//! two path syscalls whose results are then paired, because a rename or bind
//! toggling between them would pair one object's identity with another's frame,
//! and the identity checks downstream (a per-directory arm confirms only
//! `(dev, ino)`) would then admit a foreign object. The Linux enumerate, the
//! root-liveness refresh, and the spawn barriers all obey it — see
//! [`stat_sample`], [`root_liveness_and_frame`], and the pinned-fd reads in
//! `os::linux`.
//!
//! The Linux backends REQUIRE `statx` (Linux 4.11+): the spawn barrier probes it
//! once up front and refuses a kernel below the floor (see `os::linux`), so this
//! executor's live-path sample ([`stat_sample`]) is always a `statx` and never
//! needs a sub-`statx` fallback. A `statx` mask miss (no `STATX_MNT_ID` below 5.8)
//! still drops just the mount frame (absent, never mixed in from a second lookup)
//! and the core fences that object on the device belt — so the rule holds either
//! way: one object, one sample.

use std::{
  collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
  io::Write as _,
  num::NonZeroUsize,
  path::{Path, PathBuf},
  sync::{
    Arc, Mutex, MutexGuard, PoisonError,
    atomic::{AtomicBool, AtomicU64, Ordering},
  },
  time::Duration,
};

use agnostic_lite::{RuntimeLite, time::Instant as _};
use futures_util::{FutureExt, StreamExt, stream::SelectAll};
use tributary_proto::{
  ArmAttempt, Change, Instant, Interest, IoClass, ReqId, ScopeId, Segment, WatchError, WatchId,
};

use crate::{
  core::{
    CoverNoop, CoverReconcile, CoverSettle, Delivery, DriverCore, Effect, ExpectedObject, FenceId,
    MountRefresh, ProbeId, ProbeOutcome, RawDirEntry, RawEnumerate, RootLiveness, SettlePass,
    WidenCommit, WidenTaint,
  },
  error::WatchRootError,
  os::{
    Backend, BackendKind, EventReceiver, RootIdentity, RootMeta, ScopePort, SourceConfig,
    SourceError, SourceHandle, SourceMessage, SpawnFailed, linux::WatchOutcome,
  },
  watcher::{CoverOutcome, SkipReason, SyncTicket},
};

#[cfg(all(test, feature = "tokio"))]
pub(crate) mod testing;
#[cfg(all(test, feature = "tokio"))]
mod tests;

/// The driver-side knobs a watcher hands its task.
#[derive(Debug, Clone)]
pub(crate) struct DriverConfig {
  /// The OS event-coalescing latency.
  pub(crate) latency: Duration,
  /// The requested rename-pairing window; the effective window never falls
  /// below what the latency makes physically necessary.
  pub(crate) move_window: Duration,
  /// Per-root capacity of the callback→driver channel, in batches.
  pub(crate) os_batch_capacity: NonZeroUsize,
  /// The native read buffer each source reads kernel records into, in bytes —
  /// independent of the batch count above.
  pub(crate) os_buffer_bytes: std::num::NonZeroU32,
  /// Load-shedding exclusion directories applied to every root.
  pub(crate) exclusions: Vec<PathBuf>,
  /// The backend lowering profile every root registers with — the PROVISIONAL
  /// Monitor profile (the platform's descending default on Linux). Under
  /// [`Backend::Auto`] the spawn barrier probes and the core adopts the
  /// resolved backend's profile at [`on_stream_spawned`]; a forced backend
  /// makes this the final profile.
  ///
  /// [`on_stream_spawned`]: DriverCore::on_stream_spawned
  pub(crate) profile: BackendKind,
  /// The per-root backend SELECTION the spawn barrier honors: [`Backend::Auto`]
  /// probes and falls back, the explicit variants pin the choice (a forced
  /// [`Backend::Fanotify`] surfaces a typed error instead of falling back).
  /// Ignored on macOS. The Monitor profile above is provisional until this
  /// resolves.
  pub(crate) backend: Backend,
  /// The periodic root-liveness deadline for the one signal-silent-on-unmount
  /// backend (fanotify): the driver re-stats such a root on this cadence so a
  /// quiet unmount — which emits no kernel signal and no loss — is still
  /// detected. Every other backend, including both Windows ones, surfaces an
  /// unmount as its own fatal source error instead of going quiet, so none of
  /// them arm this tick. [`Duration::ZERO`] disables it.
  pub(crate) root_liveness_interval: Duration,
  /// The admission-map directory cap (design §4.9); `None` = uncapped.
  /// Threaded into each fanotify and USN journal spawn's `SourceConfig`;
  /// ignored by inotify, RDCW, and macOS.
  pub(crate) max_map_directories: Option<usize>,
  /// First-retry delay for a failed cookie unlink; the backoff doubles per
  /// attempt up to [`cookie_retry_cap`](Self::cookie_retry_cap).
  pub(crate) cookie_retry_base: Duration,
  /// The cookie-unlink backoff ceiling.
  pub(crate) cookie_retry_cap: Duration,
  /// Max unlink attempts per arming; then an UNMARKED record PARKS
  /// (`RemoveFailed`, unscheduled) until an explicit re-arm (a fresh reap/cancel,
  /// a retire sweep, or the close sweep). A record still carrying a reap mark is
  /// serviced into one fresh arming at that exhaustion instead (see
  /// [`CookieRegistry::schedule_retry`]). Never a spin — the fresh arming
  /// consumes the mark.
  pub(crate) cookie_retry_budget: u8,
  /// Per-scope unremoved-cookie cap: at or above it, a new `SyncRoot` command
  /// is refused [`CleanupBacklog`](crate::error::SyncRootError::CleanupBacklog)
  /// — the per-scope memory bound on the ledger.
  pub(crate) cookie_backlog_cap: usize,
  /// GLOBAL unremoved-cookie cap across every scope, live or retired: at or
  /// above it a new `SyncRoot` is refused `CleanupBacklog` whatever scope owns
  /// the residue. The per-scope cap resets for each fresh scope, so without this
  /// a sync→failing-cleanup→unwatch→rewatch churn would grow `owned` without
  /// bound across RETIRED scopes; this ceiling makes total ledger memory bounded
  /// regardless of churn, and self-heals as the cleanup retries drain.
  pub(crate) cookie_global_cap: usize,
}

impl DriverConfig {
  /// First-retry delay for a failed cookie unlink (§1.9 default).
  pub(crate) const DEFAULT_COOKIE_RETRY_BASE: Duration = Duration::from_millis(100);
  /// Cookie-unlink backoff ceiling (§1.9 default).
  pub(crate) const DEFAULT_COOKIE_RETRY_CAP: Duration = Duration::from_secs(5);
  /// Cookie-unlink attempt budget per arming (§1.9 default).
  pub(crate) const DEFAULT_COOKIE_RETRY_BUDGET: u8 = 8;
  /// Per-scope unremoved-cookie cap (§1.9 default).
  pub(crate) const DEFAULT_COOKIE_BACKLOG_CAP: usize = 8;
  /// Global unremoved-cookie cap across all scopes — several scopes' worth of
  /// per-scope headroom, so ordinary multi-root use never trips it while a
  /// permafailing-unlink churn stays bounded.
  pub(crate) const DEFAULT_COOKIE_GLOBAL_CAP: usize = 128;

  /// The platform's native backend profile — PROVISIONAL under
  /// `Backend::Auto` (the resolved `RootMeta.backend` supersedes it at
  /// spawn); on Windows the provisional and resolved profiles are both
  /// kernel-recursive, so the reconcile is always profile-stable there.
  pub(crate) fn platform_profile() -> BackendKind {
    if cfg!(target_os = "linux") {
      BackendKind::Inotify
    } else if cfg!(target_os = "windows") {
      BackendKind::Rdcw
    } else {
      BackendKind::FsEvents
    }
  }
}

impl DriverConfig {
  /// The rename window actually armed — the same total derivation the public
  /// options expose (see [`WatcherOptions::effective_move_window`]).
  ///
  /// [`WatcherOptions::effective_move_window`]: crate::WatcherOptions::effective_move_window
  pub(crate) fn effective_move_window(&self) -> Duration {
    crate::options::derive_move_window(self.move_window, self.latency)
  }
}

/// The reply channel of one `Command::Watch`, carrying a [`WatchGrant`] on
/// success.
pub(crate) type WatchReply = futures_channel::oneshot::Sender<Result<WatchGrant, WatchRootError>>;

/// The dispatch plumbing of one sync-cookie write parked on its scope's
/// coverage-settle fence: where the cookie is to be written, and the reply that
/// carries its path back to the caller at write-complete.
///
/// ROUTING ONLY — this map answers "which caller does this fence belong to",
/// nothing else. The parked write's TRUTH is its ledger obligation
/// ([`Phase::Parked`]), born at admission: which syncs are parked, which scope
/// each belongs to, its name, and whether a cancel has marked it are all read
/// from the ledger, so no gauge, cancel, or sweep depends on this local. The
/// driver is the only mutator of both sides and moves them in lockstep — an
/// entry here exists exactly while its obligation is `Parked`.
struct ParkedCookie {
  dir: PathBuf,
  reply: futures_channel::oneshot::Sender<Result<PathBuf, crate::error::SyncRootError>>,
}

/// The immutable identity of ONE cookie-record incarnation, minted under the
/// ledger lock when the record is born (the sync's admission). A path can be
/// REUSED across incarnations (a direct fs-API caller reusing a cookie name
/// recreates the same path after the old file is unlinked); the id cannot. Every
/// internal completion carries the id of the record it was spawned for, and every
/// record mutation it performs is conditioned on the id still matching — the
/// record-level mirror of the per-scope root generation (R6-5): stale actors
/// become no-ops instead of acting on the wrong incarnation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct CookieId(u64);

/// A test-only tally of every obligation BIRTH and every typed terminal, kept
/// under the ledger mutex so it cannot race the transitions it counts. It exists
/// to assert the census equation — `births = ConfirmedGone + NeverCreated +
/// AbnormalResidual + live` — which is the structural proof that no obligation
/// ever leaves the ledger untyped: the equation can only hold if every removal
/// went through [`LedgerInner::retire`] naming its evidence.
#[cfg(all(test, feature = "tokio"))]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct Census {
  births: u64,
  confirmed_gone: u64,
  never_created: u64,
  abnormal_residual: u64,
}

#[cfg(all(test, feature = "tokio"))]
impl Census {
  fn count(&mut self, reaped: Reaped) {
    let counter = match reaped {
      Reaped::ConfirmedGone => &mut self.confirmed_gone,
      Reaped::NeverCreated => &mut self.never_created,
      Reaped::AbnormalResidual => &mut self.abnormal_residual,
    };
    *counter += 1;
  }

  /// Every birth is accounted for exactly once: as one of the three typed
  /// terminals, or as a record still live in the ledger.
  fn balances(&self, live: usize) -> bool {
    self.births == self.confirmed_gone + self.never_created + self.abnormal_residual + live as u64
  }
}

/// Everything the pool and the driver must observe atomically about cookies:
/// one mutex, so a claim, a reap-request mark, and a record transition can never
/// interleave (see [`CookieGuard::claim`] and [`CookieIngress::mark`]). Shared
/// with the watcher handle as the cleanup ingress ([`cookie_ingress`]), so a
/// public reap or cancel is a transition on this same state. Replaces the bare
/// `HashMap<PathBuf, ScopeId>` the ledger was before the lifecycle state machine.
struct LedgerInner {
  /// Every cookie obligation the driver has admitted and not yet retired, keyed
  /// by its immutable incarnation id. The ONE insert site is the sync's ADMISSION
  /// ([`CookieRegistry::admit_parked`]), always with a freshly minted, unique
  /// id, so an insert can never displace an existing obligation: a same-path
  /// successor gets its own key and both records coexist until each earns its own
  /// terminal. The value carries the landing path and the lifecycle phase.
  ///
  /// Because birth is admission — not the later dispatch — this map is the WHOLE
  /// gauge: `len()` is the global cap's Φ in one term, with a parked sync and a
  /// dispatched write each counted exactly once, from one store, with nothing to
  /// dedup against a second one.
  ///
  /// Shared with the blocking pool: a dispatched write publishes the path it
  /// ACTUALLY landed at (see [`CookieGuard::claim`]), because only the write
  /// knows it — a cookie for a covered FILE subscription lands in the file's
  /// PARENT. Publishing under the lock the sweeps and cancels take is what makes
  /// the unorderable operations safe: no interleaving can leave a created file
  /// that nobody owns.
  obligations: HashMap<CookieId, Obligation>,
  /// Landing path -> incarnation id: the index a public path-addressed removal
  /// resolves through, filled when the write learns where its cookie landed (only
  /// the write does — a covered FILE subscription lands in the PARENT).
  /// Newest-claim-wins on a hostile same-path reuse: a claim overwrites the
  /// entry, never the displaced record, which keeps its own key and reaches its
  /// terminal through the id-addressed sweeps. Removed with its record, only
  /// while it still points BACK to that id (a successor's entry is never
  /// clobbered).
  by_path: HashMap<PathBuf, CookieId>,
  /// Rendered cookie file NAME -> incarnation id, for cancel-by-name lookup. The
  /// name (not the path) is what the canceller knows: the umbrella lost the path
  /// (only the write learns where the cookie landed) but can re-render the name
  /// from the token it minted. Inserted at BIRTH, so a cancel-by-name always has
  /// a target whatever the obligation's phase — including a write still in the
  /// pool, which is what lets the reap mark ride the record instead of a
  /// free-standing tombstone. Public admission REFUSES a second live obligation
  /// under a name this map already holds (`NameInUse`), so at most one live record
  /// carries any name: this map is an injection from names to live records, and
  /// cancel-by-name resolves to the unique holder rather than a
  /// most-recently-born guess. One entry per record; the point-back check at
  /// retire (removed only while it still names that id) is retained as the
  /// defensive rule for state minted below the public surface (tests, future
  /// internal callers).
  by_name: HashMap<String, CookieId>,
  /// Ticket sequence -> incarnation id, for the incarnation-precise cancel/reap a
  /// [`request_cancel_sync`] addresses. Unlike `by_name`, a ticket sequence is
  /// minted once by the watcher and NEVER re-minted, so this map carries temporal
  /// identity the name axis cannot: a delayed cancel through a ticket resolves that
  /// ticket's own incarnation whatever its phase, or nothing once it has retired —
  /// it can never resolve a same-name successor. Inserted at BIRTH (the same single
  /// critical section as `by_name`) and removed at that record's retire. Public
  /// admission REFUSES a second live obligation under a sequence this map already
  /// holds (`TicketInUse`), so it is an injection from live sequences to live
  /// records. A projection of counted records — one entry per live obligation, +8
  /// bytes each, bounded by the global cap — never a gauge.
  ///
  /// [`request_cancel_sync`]: crate::Watcher::request_cancel_sync
  by_ticket: HashMap<u64, CookieId>,
  /// The id mint (§1.1). Bumped under this mutex ONCE per admitted sync, at
  /// ADMISSION ([`CookieRegistry::admit_parked`]) — the ONE site that inserts a
  /// record, so mint and birth are one step and an id can never be minted for a
  /// record that is never born. The id then rides the guard the dispatch hands
  /// its write, through the [`CookieGuard::claim`] that adopts it and any
  /// `self_reap`, so one sync carries one id across its whole lifecycle. `u64`
  /// monotone, driver-lifetime only (no persistence, no wraparound concern), so
  /// no two incarnations ever share an id.
  next_cookie_id: u64,
  /// The LRU clock for recovery re-arm ordering (R11-1). Bumped under this
  /// mutex at every transition INTO `RemoveFailed`, stamping the failing
  /// record's `last_failure_seq` — so a record that keeps failing keeps moving
  /// to the BACK of the recovery selection order (`rearm_parked_batch`).
  failure_clock: u64,
  #[cfg(all(test, feature = "tokio"))]
  census: Census,
}

impl LedgerInner {
  fn new() -> Self {
    Self {
      obligations: HashMap::new(),
      by_path: HashMap::new(),
      by_name: HashMap::new(),
      by_ticket: HashMap::new(),
      next_cookie_id: 0,
      failure_clock: 0,
      #[cfg(all(test, feature = "tokio"))]
      census: Census::default(),
    }
  }

  /// Removes incarnation `id` and its three index entries — the ONLY way a record
  /// leaves the ledger. Because the record is keyed by its id, the removal is
  /// structural: a confirm for incarnation N can never delete a successor M that
  /// reclaimed the same path (M has a different key). Returns the removed record
  /// (`None` if it was already retired — a racing confirm, or the abnormal-path
  /// take).
  ///
  /// Each index entry is dropped only while it still points BACK to this id: the
  /// umbrella mints per-sync-unique names (owner-global seq + nonce), so this is
  /// always true for it, but a direct fs-API caller that reused one name across
  /// two live incarnations must not have the survivor's index clobbered by the
  /// other's retire. The `by_ticket` point-back is uniform with the others though
  /// a displacement is unmintable through the public API: a watcher-minted ticket
  /// sequence is issued once, never repeats, and the move-only admission makes
  /// presenting it to two syncs a compile error — so through the public surface
  /// `by_ticket[seq]` can only ever have named THIS record (the driver-test harness
  /// forges wire tickets below that surface, where a displacement is representable).
  fn retire(&mut self, id: CookieId, reaped: Reaped) -> Option<Obligation> {
    let ob = self.obligations.remove(&id)?;
    #[cfg(all(test, feature = "tokio"))]
    self.census.count(reaped);
    #[cfg(not(all(test, feature = "tokio")))]
    let _ = reaped;
    if let Some(file) = ob.file.as_ref()
      && self.by_path.get(file.path()) == Some(&id)
    {
      self.by_path.remove(file.path());
    }
    if self.by_name.get(&ob.name) == Some(&id) {
      self.by_name.remove(&ob.name);
    }
    if self.by_ticket.get(&ob.ticket) == Some(&id) {
      self.by_ticket.remove(&ob.ticket);
    }
    Some(ob)
  }

  /// A transient unlink failure landed for incarnation `id`: bump the record's
  /// attempt count, PARK it as `RemoveFailed` (no deadline — only the driver
  /// owns the clock, so only the driver schedules), and refresh its LRU re-arm
  /// key. Returns the new attempt count, or `None` if the record has since been
  /// retired (the abnormal-path take), so this failure is stale and touches
  /// nothing — not even the clock: only a real failure of a live incarnation
  /// advances the LRU order.
  ///
  /// Called by the job that performed the failing unlink, under this mutex,
  /// BEFORE it reports the verdict: physical truth is written by the job that
  /// learned it, so a lost completion message can cost promptness (the record
  /// parks awaiting a re-arm) but never ownership truth (a `Removing` record
  /// nothing re-arms). Reads the count as it stands — never assuming `Removing`
  /// — the tolerance rule that makes every rare interleaving converge.
  fn record_remove_failed(&mut self, id: CookieId) -> Option<u8> {
    if !self.obligations.contains_key(&id) {
      return None;
    }
    // Stamp the LRU clock under this same lock the failure transition rides, so
    // a stale failure can never refresh a successor's key.
    self.failure_clock += 1;
    let seq = self.failure_clock;
    let ob = self
      .obligations
      .get_mut(&id)
      .expect("the record was present under this held lock");
    let attempts = match ob.phase {
      Phase::Removing { attempts } | Phase::RemoveFailed { attempts, .. } => attempts,
      Phase::Parked { .. } | Phase::InPool | Phase::Owned => 0,
    }
    .saturating_add(1);
    ob.phase = Phase::RemoveFailed {
      attempts,
      retry_at: None,
    };
    ob.last_failure_seq = seq;
    Some(attempts)
  }
}

/// The reserved-namespace stem of the cookie directory. A consumer of this crate
/// suppresses the directory's own create and the cookies inside it, since both are
/// this driver's artifacts and not user changes; [`is_sync_cookie_dir_name`] is the
/// classifier that decides which leaves those are.
const COOKIE_DIR_PREFIX: &str = ".tributaries-sync-cookies";

/// Whether `name` is the leaf of a cookie directory **this crate creates** —
/// `.tributaries-sync-cookies`, optionally suffixed with the creating user's effective
/// uid.
///
/// The uid suffix is matched for ANY uid, not just the caller's: two users may
/// legitimately watch one tree, and neither one's cookie directory is a user change on
/// the other's stream. It is matched only in the shape this crate can actually render —
/// canonical decimal, inside the uid space — so a user directory that merely begins with
/// the stem stays a user directory, together with everything a consumer reports inside
/// it.
///
/// Exported because the layer that decides what reaches a consumer sits above this one,
/// while the name is minted here — a caller-side prefix test would suppress every
/// user leaf sharing the stem, and would drift the moment this crate changes the shape.
#[must_use]
pub fn is_sync_cookie_dir_name(name: &str) -> bool {
  match name.strip_prefix(COOKIE_DIR_PREFIX) {
    // The bare stem: the name on a platform with no uid to qualify it.
    Some("") => true,
    // `-<euid>`, exactly as `format!` renders a `uid_t`.
    Some(suffix) => suffix.strip_prefix('-').is_some_and(is_minted_uid),
    None => false,
  }
}

/// Whether `field` is exactly what `format!("{euid}")` renders for some `libc::uid_t` a
/// [`cookie_dir_name`] minter could hold: decimal digits, no sign, no redundant leading zero
/// (`0` itself is the one-digit case), and inside the 32-bit uid space every platform that
/// opens a cookie directory uses — less its one unownable value, `(uid_t)-1`.
///
/// A suffix outside that is one [`cookie_dir_name`] could never have produced, so the
/// directory wearing it was created by somebody else. Admitting it would classify a user
/// directory — and, for a consumer that suppresses what lands inside the cookie
/// directory, everything reported within it — as this driver's artifact, and silently.
///
/// The bound is the MINTER's range, never the watching platform's: the suffix is matched for
/// any uid (see [`is_sync_cookie_dir_name`]), and on a shared filesystem the minter may run
/// on another platform entirely, so narrowing to this one's own uid ceiling would stop
/// recognizing a genuine foreign cookie directory — the leak this classifier exists to close.
fn is_minted_uid(field: &str) -> bool {
  field.bytes().all(|b| b.is_ascii_digit())
    && (field.len() == 1 || !field.starts_with('0'))
    // `parse` is what rejects the empty suffix and the overflowing one; the digit test
    // above is what rejects the leading sign `from_str` would otherwise accept.
    //
    // `u32::MAX` is refused because it is `(uid_t)-1` — POSIX's invalid-uid sentinel, the
    // value `chown`/`chgrp` read as "leave this id alone" and the one `setreuid` takes as
    // "no change". No account is allocated it and no `geteuid()` returns it, so
    // `cookie_dir_name` can never render this suffix. Do NOT simplify this back to a bare
    // `parse::<u32>()`: a consumer suppresses every change reported inside a directory this
    // admits, so admitting `.tributaries-sync-cookies-4294967295` erases a user directory's
    // whole contents from every stream, with no `Rescan` and no diagnostic.
    && field.parse::<u32>().is_ok_and(|uid| uid != u32::MAX)
}

/// The directory a cookie is created inside, held OPEN for as long as any cookie
/// created through it is outstanding.
///
/// # What it is for
///
/// The cookie must land inside the watched root, because the whole mechanism is
/// the ordered kernel event its creation mints. That put every past cookie in a
/// directory belonging to the WATCHED TREE, where anyone permitted to write may
/// unlink a name and rebind it — and where, in consequence, no removal addressed
/// by pathname could ever be safe.
///
/// This type takes that permission away. The directory is created by this driver,
/// `0o700`, owned by the effective user: binding a name in it requires write
/// permission on it, which the mode grants to nobody else. A cookie's name can
/// therefore not be rebound between the removal's proof and its unlink, and both
/// operations go through this descriptor rather than through the name — so not
/// even an intermediate component of the path participates.
///
/// # Where it lives, and why not directly under the root
///
/// It is created inside the directory the sync named (see [`cookie_dir`]), not at
/// the root. Under a DESCENDING backend a directory outside the scope's retained
/// cover carries no kernel watch, and a cookie there would mint no event at all.
/// A child of the sync's own directory is covered exactly when that directory is,
/// so nesting adds no coverage requirement the caller did not already have; a
/// directory at the root would add one the caller cannot satisfy.
///
/// # What a pre-existing directory must prove
///
/// A directory already standing at the name is VERIFIED, never adopted on faith:
/// it must be a real directory (not a symlink — the open refuses to follow one),
/// owned by this effective user, and carry no group or other permission bits. A
/// directory failing any of those is refused and the sync reports a typed write
/// failure. Adopting one instead would hand the whole argument above to whoever
/// created it.
///
/// The name carries the effective uid so two users watching one shared tree get
/// one directory EACH rather than one refusing the other forever; the ownership
/// check then only ever fires on a directory somebody planted.
///
/// # What this does not give, and the trust boundary that follows
///
/// The mode distinguishes USERS, so it cannot separate this process from another
/// process running as the same user — including the watched tree's own owner. Such
/// a peer can rebind a name inside the directory, or destroy the directory itself.
/// Destroying it is harmless: this descriptor keeps referring to the directory it
/// opened, and a cookie removal through a directory that is no longer linked finds
/// the name absent and settles as already-gone, unlinking nothing.
///
/// REBINDING is not closed at all, and the contract states that rather than
/// implying otherwise. A removal proves what stands at the name and then unlinks
/// the name, two calls that no Unix offers a way to fuse (see
/// [`remove_anchored`]), so a same-uid peer that rebinds between them makes the
/// unlink land on its own object. That peer is trusted here — it can already
/// delete the cookie, replace this directory or attach to this process, so no
/// removal-side check holds a boundary the kernel does not draw. What the
/// comparison in [`CookieProof::Object`] buys is the honest verdict for the
/// ORDINARY races, not a defence against that peer.
#[derive(Debug)]
pub(crate) struct CookieDir {
  path: PathBuf,
  /// Every `openat`/`unlinkat` runs against this, never against `path`.
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fd: std::os::fd::OwnedFd,
}

impl CookieDir {
  /// The directory's own path, for reporting a cookie's landing.
  pub(crate) fn path(&self) -> &Path {
    &self.path
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl CookieDir {
  /// Creates (or re-opens) the cookie directory inside `parent` and verifies what
  /// it opened. Every check reads the OPENED DESCRIPTOR, never a second lookup of
  /// the name: a check against a path would describe whatever the name denotes at
  /// that instant rather than the directory the cookies are about to go into.
  fn open_or_create(parent: &Path) -> Result<Self, std::io::Error> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

    let path = parent.join(cookie_dir_name());
    // `0o700` is the mode the whole argument rests on. A umask can only clear
    // bits, so the created directory is never more permissive than asked; the
    // verification below re-reads what was actually made either way.
    match std::fs::DirBuilder::new().mode(0o700).create(&path) {
      Ok(()) => {}
      // Already there — from an earlier sync, or from a previous run of this
      // process. Verified below like any other pre-existing directory.
      Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
      Err(err) => return Err(err),
    }
    // `O_DIRECTORY` refuses anything that is not a directory and `O_NOFOLLOW`
    // refuses a symlink standing at the name, so what this descriptor refers to
    // cannot have been redirected elsewhere.
    let opened = std::fs::OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
      .open(&path)?;
    let meta = opened.metadata()?;
    // SAFETY: `geteuid` reads no memory, takes no arguments, and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
      return Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "the cookie directory is owned by another user",
      ));
    }
    if meta.mode() & 0o077 != 0 {
      return Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "the cookie directory grants access beyond its owner",
      ));
    }
    Ok(Self {
      path,
      fd: std::os::fd::OwnedFd::from(opened),
    })
  }

  /// Creates `name` inside this directory and returns the descriptor the create
  /// itself produced. `O_EXCL` refuses an existing name (a cookie name is minted
  /// unique, so anything already there is foreign), `O_NOFOLLOW` states the same
  /// refusal for a symlink explicitly, and `0o600` keeps the cookie as private as
  /// the directory holding it.
  fn create(&self, name: &str) -> Result<std::fs::File, std::io::Error> {
    self.open_at(
      name,
      libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
      0o600,
    )
  }

  /// Opens whatever stands at `name` just far enough to read its identity.
  ///
  /// `O_NONBLOCK` is what makes this bounded: a plain `O_RDONLY` of a FIFO waits
  /// for a writer FOREVER, which would wedge a blocking-pool thread on a removal
  /// that should have settled in microseconds. With it, every object kind opens
  /// (or fails) at once and reaches the identity comparison, where a FIFO — not
  /// being the cookie — settles as displaced.
  ///
  /// `O_PATH` would be tighter still on Linux, but it does not exist on macOS and
  /// `fstat` of an `O_PATH` descriptor is not answerable on every kernel, so one
  /// portable form that is known to work everywhere is preferred to two.
  fn open_for_classification(&self, name: &str) -> Result<std::fs::File, std::io::Error> {
    self.open_at(
      name,
      libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
      0,
    )
  }

  /// Unlinks `name` from THIS directory. No component of any path is resolved, so
  /// the entry removed is an entry of the directory this descriptor refers to and
  /// of no other.
  fn unlink(&self, name: &str) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd;

    let name = cookie_c_name(name)?;
    // SAFETY: `fd` is an open directory descriptor owned by `self`, `name` is a
    // live NUL-terminated C string for the call, and `0` is a valid flag word for
    // `unlinkat` (remove a non-directory entry).
    let rc = unsafe { libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), 0) };
    if rc == 0 {
      return Ok(());
    }
    Err(std::io::Error::last_os_error())
  }

  /// Destroys the cookie a create just made, for the caller still holding the
  /// descriptor that create returned.
  ///
  /// The destroy is the anchored unlink: it addresses an entry of the directory
  /// this descriptor refers to, resolving no path component. The create's own
  /// descriptor cannot aim it — this platform has no unlink conditioned on the
  /// object — so what vouches for the name is the `O_EXCL` create that bound it a
  /// moment ago, under the same same-uid-trusted contract every removal here runs
  /// under ([`remove_anchored`]). It is borrowed rather than consumed so the
  /// caller can keep it OPEN across the unlink — the entry goes away, the object
  /// does not, and its identity slot stays out of the allocator's reach for as
  /// long as the caller holds it, which is what lets a FAILED destroy come back as
  /// a residue whose identity can still be promoted later.
  fn destroy_created(&self, name: &str, _created: &std::fs::File) -> Result<(), std::io::Error> {
    self.unlink(name)
  }

  fn open_at(
    &self,
    name: &str,
    flags: libc::c_int,
    mode: libc::c_uint,
  ) -> Result<std::fs::File, std::io::Error> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = cookie_c_name(name)?;
    // SAFETY: `fd` is an open directory descriptor owned by `self`, `name` is a
    // live NUL-terminated C string for the call, and `mode` is only consulted when
    // `flags` carries `O_CREAT`.
    let raw = unsafe { libc::openat(self.fd.as_raw_fd(), name.as_ptr(), flags, mode) };
    if raw < 0 {
      return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a fresh descriptor owned by nobody else, so the
    // `File` takes sole ownership of it.
    Ok(unsafe { std::fs::File::from_raw_fd(raw) })
  }
}

#[cfg(all(target_os = "windows", not(miri)))]
impl CookieDir {
  /// Creates (or re-opens) the cookie directory inside `parent`.
  ///
  /// Windows has no `openat`, and nothing here establishes the exclusive-write
  /// argument the Unix implementation rests on: on this platform the directory is
  /// a grouping and a reserved-namespace convenience, NOT the source of removal
  /// safety. Safety here comes from the disposition being set on an already-open
  /// handle whose identity is RE-verified first — see [`remove_anchored`].
  fn open_or_create(parent: &Path) -> Result<Self, std::io::Error> {
    let path = parent.join(cookie_dir_name());
    match std::fs::create_dir(&path) {
      Ok(()) => {}
      Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
      Err(err) => return Err(err),
    }
    // A reparse point standing at the name would redirect every cookie out of the
    // watched root, where its event could never reach the stream.
    let meta = std::fs::symlink_metadata(&path)?;
    if !meta.is_dir() {
      return Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "the cookie directory's name is held by something that is not a directory",
      ));
    }
    Ok(Self { path })
  }

  /// Creates `name` inside this directory. `create_new` refuses an existing name,
  /// and the reparse-point flag refuses to follow a link planted at it.
  fn create(&self, name: &str) -> Result<std::fs::File, std::io::Error> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
      DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // DELETE travels with the descriptor so the create's own handle can destroy
    // what it made without resolving a name — the residue path's only object-exact
    // removal on this platform. `access_mode` replaces the read/write bits, so
    // `write` stays set for `create_new`'s sake (a create disposition without it is
    // rejected) while the effective rights are exactly these two.
    options.access_mode(FILE_GENERIC_WRITE | DELETE);
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(self.path.join(name))
  }

  /// Opens whatever stands at `name` with the LOWEST rights that still answer an
  /// identity. Asking for DELETE here instead would let a sharing violation hide a
  /// displacement behind a retry that can never converge; the DELETE-capable handle
  /// is taken separately, and re-verified, only once the object has been proven.
  ///
  /// `FILE_FLAG_BACKUP_SEMANTICS` is required for a handle on a DIRECTORY, and a
  /// directory is one of the things that can be standing at the name.
  fn open_for_classification(&self, name: &str) -> Result<std::fs::File, std::io::Error> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
      FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };

    let mut options = std::fs::OpenOptions::new();
    options.access_mode(FILE_READ_ATTRIBUTES);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(self.path.join(name))
  }

  /// Opens `name` with DELETE rights, for the caller that has already classified
  /// the object and will RE-verify this handle's identity before destroying it.
  fn open_for_delete(&self, name: &str) -> Result<std::fs::File, std::io::Error> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
      DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };

    let mut options = std::fs::OpenOptions::new();
    options.access_mode(FILE_READ_ATTRIBUTES | DELETE);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(self.path.join(name))
  }

  /// Destroys the cookie a create just made, for the caller still holding the
  /// descriptor that create returned.
  ///
  /// This platform has no anchored unlink, so the destroy is addressed to the
  /// HANDLE rather than to a name: a disposition set on the create's own handle
  /// destroys the object that handle refers to with no path resolved at all, which
  /// is why [`create`](Self::create) asks for `DELETE` alongside write access. The
  /// directory descriptor plays no part — on this platform it is a grouping, not
  /// the source of removal safety.
  fn destroy_created(&self, _name: &str, created: &std::fs::File) -> Result<(), std::io::Error> {
    use std::os::windows::io::AsHandle;

    crate::os::windows::ffi::delete_by_handle(created.as_handle())
  }
}

/// A platform with NEITHER anchor primitive: no `openat`/`unlinkat`, and no
/// handle-bound disposition. Every removal there would have to resolve a pathname,
/// which is the deletion this whole design refuses to perform — so no cookie is
/// created in the first place, and the sync reports an honest `Unsupported`
/// instead of a barrier whose cleanup could destroy a stranger's file. Such a
/// target has no working watch backend either (see `os::unsupported`), so nothing
/// that worked before stops working.
#[cfg(not(any(
  target_os = "linux",
  target_os = "macos",
  all(target_os = "windows", not(miri))
)))]
impl CookieDir {
  fn open_or_create(_parent: &Path) -> Result<Self, std::io::Error> {
    Err(std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "this platform has no way to bind a cookie's removal to the object created",
    ))
  }

  fn create(&self, _name: &str) -> Result<std::fs::File, std::io::Error> {
    Err(std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "this platform has no way to bind a cookie's removal to the object created",
    ))
  }

  /// Unreachable by construction — [`open_or_create`](Self::open_or_create) never
  /// yields a directory here, so no cookie is ever created and none can ever need
  /// destroying. The answer if one somehow did is still the refusal: destroying an
  /// object without an anchor would mean resolving its pathname, which is the
  /// deletion this design forbids. Refusing is also the fail-closed half of the
  /// caller's contract, which reads a failed destroy as a file that SURVIVED and
  /// reports it as residue rather than claiming the write left nothing behind.
  fn destroy_created(&self, _name: &str, _created: &std::fs::File) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "this platform has no way to bind a cookie's removal to the object created",
    ))
  }
}

/// The cookie directory's name: the reserved stem, plus the effective uid where
/// there is one (see [`CookieDir`] for why it is part of the name).
///
/// Called only by the two [`CookieDir::open_or_create`] bodies that can actually
/// open a directory; the no-anchor platform refuses before it needs a name, so
/// this is inert there rather than unused.
#[cfg_attr(
  not(any(
    target_os = "linux",
    target_os = "macos",
    all(target_os = "windows", not(miri))
  )),
  allow(dead_code)
)]
fn cookie_dir_name() -> String {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    // SAFETY: `geteuid` reads no memory, takes no arguments, and cannot fail.
    let euid = unsafe { libc::geteuid() };
    format!("{COOKIE_DIR_PREFIX}-{euid}")
  }
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    COOKIE_DIR_PREFIX.to_owned()
  }
}

/// A cookie name as a C string, for the `*at` calls. An interior NUL is refused
/// rather than silently truncating the name a removal would then address.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cookie_c_name(name: &str) -> Result<std::ffi::CString, std::io::Error> {
  std::ffi::CString::new(name).map_err(|_| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "a cookie name may not contain a NUL",
    )
  })
}

/// What authorizes a removal to destroy the object standing at a cookie's name.
///
/// Both variants are read together with the [`CookieDir`] the cookie was created
/// through: the directory is what makes the name unbindable by anyone else, and
/// this is what the removal additionally proves — or declines to prove — about
/// the object it finds there.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CookieProof {
  /// The create read this identity off its OWN descriptor. Every removal
  /// re-reads the identity of whatever stands at the name and refuses unless it
  /// matches, so a name that has come to hold a different object is settled as
  /// displaced instead of unlinked.
  ///
  /// On Unix the comparison and the unlink are separate calls, so this DETECTS a
  /// displacement rather than excluding one; the removal's contract says which
  /// actors that covers and which it names trusted (see [`remove_anchored`]).
  /// On Windows the disposition is set on a handle that has itself been proven,
  /// so there the removal genuinely destroys the object it compared.
  ///
  /// The identity is READ only by a removal that has an anchor to remove through;
  /// where none exists the removal refuses before comparing anything, so the field
  /// is inert there and the lint is turned off exactly there.
  Object(
    #[cfg_attr(
      not(any(
        target_os = "linux",
        target_os = "macos",
        all(target_os = "windows", not(miri))
      )),
      allow(dead_code)
    )]
    RootIdentity,
  ),
  /// The create could NOT read an identity, and the immediate destroy that
  /// follows such a create also failed — so a file is on disk that nothing can
  /// name an identity for. Minted at exactly one site (see [`FsOps::write_cookie`]).
  ///
  /// This proof authorizes NO removal by name. It used to: the retry went straight
  /// to the anchored unlink on the argument that the anchor alone was enough, and
  /// that is the one shape with no evidence behind it at all — not even the
  /// displacement comparison an [`Object`](Self::Object) record gets — which makes
  /// it `remove_file(path)` minus only the path resolution.
  ///
  /// What each platform does instead: Windows destroys the object through the
  /// create's own retained handle, with no name resolved (genuinely object-exact).
  /// Unix promotes the record to an `Object` proof by reading the identity off
  /// that same retained handle — a lookup of nothing, so it names this write's own
  /// object — and refuses the removal outright when it cannot.
  Anchor,
}

/// One sync cookie as a physical OBJECT: the directory it was created through,
/// its name inside that directory, what authorizes its removal, and — for a
/// cookie a real write minted — the descriptor that create returned, held OPEN
/// until the obligation retires.
///
/// # Why the anchor, and not a pathname
///
/// A path is a handle on nothing. `remove_file(path)` performs a FRESH pathname
/// resolution, so between proving what stands at a name and unlinking it the
/// name can be rebound and the unlink destroys the successor — a stranger's data,
/// irreversibly, on behalf of a sync that has nothing to do with it. That window
/// is not sub-microsecond either: a preempted thread can sit in it indefinitely.
/// No amount of extra verification closes it, because the verification and the
/// unlink resolve the name twice.
///
/// So the removal does not address a pathname at all. Every operation on a cookie
/// is anchored to the [`CookieDir`] descriptor the create was made through
/// (`openat`/`unlinkat` on Unix, a handle-bound disposition on Windows), and that
/// directory is one this driver created for itself with `0o700`. Rebinding a name
/// inside it requires WRITE permission on it, and the permission model denies
/// that to every user but the one this process runs as.
///
/// What that closes is the race against ANOTHER USER, which is the one the
/// path-based shape above loses catastrophically. It does not close the race
/// against another process of the SAME user, because Unix offers no unlink
/// conditioned on the object and the proof therefore cannot be fused to the
/// removal; that peer is named trusted by the removal's own contract rather than
/// guarded against — see [`remove_anchored`].
///
/// [`path`](Self::path) is retained for REPORTING only — it is what the caller is
/// told and what a path-addressed cleanup request resolves through. No removal
/// ever resolves it.
///
/// # The pin, and why an identity alone proves nothing
///
/// Inode numbers and Windows file ids are ALLOCATOR slots, not names: each is
/// handed back out once the object holding it is freed, and Windows states
/// outright that file ids are not unique over time. An identity captured at
/// create therefore proves nothing by itself — let the cookie be deleted, and the
/// next create in that directory may be handed the very same slot under the very
/// same name, and compare EQUAL to the cookie that is already gone.
///
/// Holding the create's own descriptor open is what makes the slot unfreeable:
/// while any descriptor references the object the kernel cannot reissue its
/// identity, so a successor at the name necessarily reads back a DIFFERENT one
/// and the comparison correctly refuses.
///
/// The pin is an `Arc`, not an owned `File`: this value is cloned onto every
/// removal job, and a `File` clone would `dup` a second descriptor per clone —
/// multiplying the very cost the obligation cap is meant to bound. Every clone
/// shares the one descriptor, which closes when the last of them dies. Since the
/// ledger record holds one clone and each in-flight removal holds its own, the
/// pin necessarily outlives the removal syscall that reads against it, which is
/// what makes the comparison sound at removal time and not merely at create.
///
/// `dir` and `pin` are `None` only for a cookie minted BELOW the real write — the
/// fake [`FsOps`] and hand-built ledger records — where no descriptor exists to
/// hold. A real removal handed such a record refuses rather than falling back to a
/// pathname.
#[derive(Clone, Debug)]
pub(crate) struct CookieFile {
  path: PathBuf,
  /// The directory descriptor every operation on this cookie is anchored to,
  /// shared by every clone so one open directory serves the whole obligation.
  dir: Option<Arc<CookieDir>>,
  /// The cookie's name INSIDE `dir` — the only thing `openat`/`unlinkat` resolve,
  /// and always a single normal component.
  name: String,
  proof: CookieProof,
  /// Never read, and that is the point: its whole contribution is its `Drop`,
  /// which is the instant the kernel becomes free to hand this object's identity
  /// to someone else. On Windows it is read once more — it is the only object-exact
  /// destroy that platform's [`CookieProof::Anchor`] residue has.
  pin: Option<Arc<std::fs::File>>,
}

impl CookieFile {
  /// Pairs a landed cookie's path with the identity of the object the create
  /// returned, anchoring NOTHING: for a cookie with no real descriptor behind it.
  /// The identity must still come from that create, never from a second lookup
  /// of the path, which is the very race the pairing exists to close.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn new(path: PathBuf, identity: RootIdentity) -> Self {
    let name = path
      .file_name()
      .map(|name| name.to_string_lossy().into_owned())
      .unwrap_or_default();
    Self {
      path,
      dir: None,
      name,
      proof: CookieProof::Object(identity),
      pin: None,
    }
  }

  /// The form a real create mints: the anchor it was created through, its name
  /// inside that anchor, what authorizes its removal, and the create's own
  /// descriptor — retained so the identity cannot be reissued to anyone else for
  /// as long as this value (or any clone of it) lives.
  fn anchored(dir: Arc<CookieDir>, name: &str, proof: CookieProof, handle: std::fs::File) -> Self {
    Self {
      path: dir.path().join(name),
      dir: Some(dir),
      name: name.to_owned(),
      proof,
      pin: Some(Arc::new(handle)),
    }
  }

  /// Where the cookie landed — the authority on its location, since only the
  /// write learns it (see [`FsOps::write_cookie`]). Reported to the caller; never
  /// resolved by a removal.
  pub(crate) fn path(&self) -> &Path {
    &self.path
  }

  /// Which object the cookie IS, when its create could say. `None` is an
  /// [`Anchor`](CookieProof::Anchor) residue, which no comparison can settle.
  ///
  /// The real removals read the proof directly and never go through here; this is
  /// the fake's mirror of the same comparison.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) const fn identity(&self) -> Option<RootIdentity> {
    match self.proof {
      CookieProof::Object(identity) => Some(identity),
      CookieProof::Anchor => None,
    }
  }

  /// The retained descriptor, for the cell that has to prove the object outlives
  /// the loss of its name — the property the whole proof rests on and the one
  /// thing no filesystem-level observation can show from outside. Gated exactly
  /// as that cell is: it runs against real inodes, so nowhere else.
  #[cfg(all(test, feature = "tokio", unix, not(miri)))]
  pub(crate) fn pinned_handle(&self) -> Option<&std::fs::File> {
    self.pin.as_deref()
  }
}

/// What one cookie removal PROVED about the name it was handed. Every variant is
/// a success — the obligation retires on all three — but they are not the same
/// fact, and collapsing them would hide the only one that means a foreign object
/// is sitting where this driver's cookie used to be.
///
/// A platform with no anchor primitive constructs none of them: its removal
/// refuses rather than settling a verdict it has no primitive to reach (see
/// [`CookieDir`]). The variants are inert there, not unused, and the driver still
/// matches on all three — so the lint is turned off exactly on that platform and
/// keeps its bite everywhere a variant could genuinely fall out of use.
#[cfg_attr(
  not(any(
    target_os = "linux",
    target_os = "macos",
    all(target_os = "windows", not(miri))
  )),
  allow(dead_code)
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CookieRemoval {
  /// The name still denoted this cookie, and it is now unlinked.
  Unlinked,
  /// Nothing is at the name: a cookie already reaped (a crash leftover someone
  /// else swept, a racing sync). The idempotence contract.
  AlreadyGone,
  /// The name denotes a DIFFERENT object. This sync's cookie is gone from it and
  /// a stranger holds it now, so nothing is unlinked — deleting it would destroy
  /// data this driver never created and cannot restore.
  Displaced,
}

/// Why a cookie write produced no usable cookie, and — the part that decides the
/// obligation's fate — whether it left a FILE behind.
///
/// A write that fails before anything lands is a clean pre-physical failure, and
/// its obligation retires having created nothing. A write that creates a file it
/// then cannot identify tries to destroy that file at once; if THAT fails too, a
/// cookie is on disk that no caller will ever ask about. Reporting such a write
/// as though nothing had been created is what makes those files untracked and
/// uncounted, so repeated attempts grow the tree without ever reaching the
/// obligation cap that is supposed to bound them. The residue is therefore
/// returned, and the caller admits it as an ordinary owned cookie whose removal
/// is retried — counted the whole time.
#[derive(Debug)]
pub(crate) struct CookieWriteError {
  /// The failure the sync reports, verbatim.
  pub(crate) source: std::io::Error,
  /// A file this write created, could not identify, and could not destroy. It is
  /// still on disk, and whoever receives it OWNS it. Boxed so the failure path
  /// costs a pointer rather than a whole cookie record on every `Result` the
  /// write returns.
  pub(crate) residue: Option<Box<CookieFile>>,
}

impl CookieWriteError {
  /// The pre-physical failure: nothing of this write is on disk.
  pub(crate) const fn clean(source: std::io::Error) -> Self {
    Self {
      source,
      residue: None,
    }
  }
}

/// The typed terminal of a cookie obligation — the reason a [`retire`] removes a
/// record, stated at every removal site so a removal can never be an untyped
/// inference.
///
/// [`retire`]: LedgerInner::retire
#[derive(Clone, Copy, Debug)]
enum Reaped {
  /// The cookie is confirmed absent from its name: the unlink returned `Ok`, or
  /// the name was already empty, or it now holds a DIFFERENT object
  /// ([`CookieRemoval::Displaced`]) — under all three this incarnation's file is
  /// gone from the only place this driver could ever address it.
  ConfirmedGone,
  /// Nothing physical was ever created for this incarnation: a write that
  /// failed before it landed a file.
  NeverCreated,
  /// The abnormal-path [`Drop`] backstop swept the record best-effort, outside
  /// any orderly close grace.
  AbnormalResidual,
}

/// One cookie obligation's ledger record: the scope it belongs to, its rendered
/// name (kept so retiring the record can also drop its `by_name` index without
/// recomputation), the ticket sequence keying it (kept for the same reason on the
/// `by_ticket` index), its immutable incarnation identity, the path it landed at,
/// the reap mark, its LRU re-arm key, and its lifecycle phase.
struct Obligation {
  scope: ScopeId,
  name: String,
  /// The [`SyncTicket`] sequence this admission was keyed by (kept so retiring the
  /// record can also drop its `by_ticket` index without recomputation). Minted once
  /// by the watcher and never re-minted, so it names this incarnation alone.
  ticket: u64,
  /// Immutable incarnation identity — also this record's ledger key. Never
  /// changes for the life of the record; a same-path successor gets a fresh one.
  id: CookieId,
  /// The cookie the write landed — its path AND the identity of the object that
  /// create made — learned only once the write reports it. `None` while the sync
  /// is parked on its fence or its write is still in the pool; `Some(F)` from the
  /// claim (or the refused claim's self-reap) onward — the sweeps and the
  /// abnormal-path backstop unlink through it, and `by_path` maps its path back
  /// to this id. A fileless record is exactly one for which no file can exist
  /// yet, so every sweep leaves it to its own write (or, parked, to its
  /// pre-physical terminal) rather than unlinking.
  ///
  /// The identity rides the record rather than being re-derived at removal time
  /// because a removal can run arbitrarily long after the write — a retry
  /// minutes later, a close-time sweep — and a second lookup of the path would
  /// only ever describe whatever holds the name NOW, which proves nothing about
  /// what this sync created.
  ///
  /// This field is also where the create's descriptor is PINNED (see
  /// [`CookieFile`]): the record is the thing whose lifetime the pin must match,
  /// because the identity has to stay unreissuable for exactly as long as some
  /// removal may still compare against it. It is released when [`retire`] drops
  /// this record — and, for a removal in flight at that instant, when that job's
  /// own clone dies just after. One descriptor per landed cookie, so the live
  /// descriptor count is the count of records with a landing, which
  /// `cookie_global_cap` bounds along with the rest of the ledger.
  ///
  /// [`retire`]: LedgerInner::retire
  file: Option<CookieFile>,
  /// This obligation must not survive: set by a cancel that names it, whatever
  /// its phase. It rides the record rather than a free-standing tombstone set,
  /// so it cannot be set for an obligation that does not exist, cannot be left
  /// behind by any other refusal, and dies with the record it marks — the
  /// boundedness rule holds by construction instead of by a sweep protocol.
  /// [`CookieGuard::claim`] reads its OWN record's mark inside the same critical
  /// section as the shutdown/retiring/generation refusals, so a cancel either
  /// finds the cookie owned (and reaps it through the phase machine) or refuses
  /// the claim before ownership ever lands — no third interleaving.
  reap_requested: bool,
  /// The R11-1 LRU re-arm key — the `failure_clock` value stamped at the
  /// record's most recent transition into `RemoveFailed` (0 = never failed;
  /// unreachable for a parked record, which required ≥ 1 failure). Refreshed
  /// on EVERY failure, so a permafailing record that was just re-armed and
  /// failed again moves BEHIND every record that failed before it: recovery
  /// selection (`rearm_parked_batch`) becomes least-recently-failed-first,
  /// which is what makes it starvation-free.
  last_failure_seq: u64,
  phase: Phase,
}

/// The per-record lifecycle phase. `attempts` counts unlink attempts MADE for
/// the current arming; it rides the record (not a driver-local map) so the close
/// drain and the live loop share one truth.
///
/// Every phase is an honest obligation: each is counted by the global gauge and
/// by the close reply, so no phase transition can make a physical cookie — or a
/// write that may be about to create one — vanish from the accounting.
enum Phase {
  /// Admitted and parked on its coverage-settle fence: no write has been
  /// dispatched, so this obligation is PRE-PHYSICAL — no file can exist for it
  /// and its `path` is `None`, which is why no sweep can ever try to unlink it.
  /// It is nonetheless a full obligation: the global cap counts it, the close
  /// reply counts it, and a cancel naming it has a record to mark — the reason
  /// the cancel of a not-yet-dispatched sync needs no free-standing lookaside.
  /// Its `fence` is the settle it waits on; `parked_cookies` routes that fence
  /// back to the caller's reply.
  Parked { fence: FenceId },
  /// A write job for this obligation is in the pool: no file exists yet, or one
  /// may at any instant. Its scope's single-flight write gate is exactly "this
  /// scope has an obligation in this phase".
  InPool,
  /// The write claimed: the file at `path` (which is `Some` from the claim on)
  /// is owned. No removal in flight or requested-and-armed.
  Owned,
  /// Exactly one unlink job is in the pool FOR THIS OBLIGATION (single-flight):
  /// the record leaves this phase only once that job's syscall has returned.
  Removing { attempts: u8 },
  /// The last unlink failed. `Some(retry_at)` = SCHEDULED (the driver, which
  /// owns the clock, stamped the deadline); `None` = PARKED — budget exhausted
  /// for an UNMARKED record (one still carrying a reap mark is serviced into one
  /// fresh arming at that exhaustion instead of parking, see
  /// [`CookieRegistry::schedule_retry`]), or the failure has not been scheduled
  /// yet — awaiting an explicit re-arm (a fresh reap/cancel request, a retire
  /// sweep, the close sweep, or the recovery re-arm batch). Never CPU-spinning.
  /// The deadline rides the record it belongs to, so no schedule can outlive,
  /// mismatch, or clobber its incarnation.
  RemoveFailed {
    attempts: u8,
    retry_at: Option<Instant>,
  },
}

type CookieLedger = Arc<Mutex<LedgerInner>>;

/// Mints the cookie-cleanup ingress: ONE ledger, shared between the watcher
/// HANDLE and its driver task, plus the **capacity-1** coalescing wake the handle
/// rings after marking an obligation. The two halves are created together — at
/// the watcher's spawn, alongside the command channel — because the handle side
/// must address the very records the driver admits.
///
/// This pair REPLACES the dedicated cleanup queue the public reap and cancel used
/// to feed. That queue had to be unbounded (a bounded one once refused a removal
/// and orphaned the file it named), while every dedup and ownership resolution
/// happened only after dequeue — so nothing bounded the QUEUE, and a flood of
/// duplicate or unknown requests allocated one caller-sized message apiece. The
/// tension is not resolved by sizing a channel; it is dissolved by moving the
/// request onto the obligation it names. Because a record now exists from
/// admission to its typed terminal ([`CookieRegistry::admit_parked`]), a cleanup
/// request has somewhere to LIVE: it is one bool on already-counted state, so
/// there is no queue to bound and no admission to refuse.
pub(crate) fn cookie_ingress() -> (CookieIngress, CookieWake) {
  let ledger: CookieLedger = Arc::new(Mutex::new(LedgerInner::new()));
  // Capacity 1, and the token is a bare `()`: it carries no request — it only says
  // "some bit changed, sweep". A second wake against a full channel is therefore
  // not a dropped request but a COALESCED one: the pending token's sweep has not
  // run yet, so it will see every bit set before it takes the lock (§3.4).
  let (wake_tx, wake_rx) = async_channel::bounded(1);
  (
    CookieIngress {
      ledger: Arc::clone(&ledger),
      wake: wake_tx,
    },
    CookieWake {
      ledger,
      wake: wake_rx,
    },
  )
}

/// The HANDLE side of the cookie-cleanup ingress: the shared ledger, and the wake.
///
/// Every public cleanup request — [`request_remove_cookie`] and
/// [`request_cancel_sync`] — is exactly this: resolve the caller's address to an
/// obligation through a projection, set that obligation's reap mark, ring the
/// wake. It creates nothing, decides nothing, dispatches nothing, and retains
/// nothing; the driver owns every reaction, on records it already owns.
///
/// [`request_remove_cookie`]: crate::Watcher::request_remove_cookie
/// [`request_cancel_sync`]: crate::Watcher::request_cancel_sync
///
/// # A hostile flood retains NOTHING — structurally, not by draining
///
/// Per call: one mutex critical section (an O(1) projection lookup and, at most,
/// one bool store on a PRE-EXISTING record) and one `try_send` into a capacity-1
/// channel. No queue exists to grow, no entry is created, and an unaddressable
/// target touches nothing at all — it does not even wake. The retained-memory
/// delta of `loop { request_remove_cookie(random) }` is therefore ZERO, and the
/// whole ingress-reachable state is `obligations` (≤ the global cap, enforced at
/// admission, where a refusal creates nothing) plus one wake slot. Crucially this
/// holds even when the driver is NEVER SCHEDULED — a current-thread runtime whose
/// caller never yields — because the bound is a property of the SHAPE, not of a
/// drain keeping up with a producer.
///
/// # A genuine request can never be refused — by TYPE
///
/// A genuine request names an obligation this watcher admitted, and every public
/// address becomes valid strictly before a caller can legitimately hold it:
/// `by_path` is filled by the claim, whose mutex section precedes the `sync_root`
/// reply that is the ONLY place a caller learns the path (claim-before-reply);
/// `by_ticket` is filled at admission, before `sync_root` can even be answered, so
/// a cancel through the ticket the caller passed always resolves while the sync is
/// live. The ingress locks the same mutex those writes took, so it observes them.
///
/// There is then no refusal edge on the genuine path: a mutex lock cannot fail
/// (poisoning is absorbed — [`lock_ledger`]), a bool store cannot fail, and the
/// wake is not load-bearing for admission (only for promptness — see
/// [`CookieWake`]). There is NO CAPACITY ANYWHERE on the genuine path: the
/// obligation IS the storage, so "never refuse a genuine unlink" and "bound the
/// ingress" stop competing. The old lane could guarantee only one of them —
/// unbounded bought admission at the cost of the bound; bounded would have traded
/// it back.
///
/// # The door's trade-off, stated
///
/// An UNADDRESSABLE target — a path or ticket matching no live obligation — is
/// dropped right here rather than queued to be discovered a no-op later. This is
/// exact rather than heuristic, because the ledger is birth-to-terminal complete:
/// an unknown address provably names no obligation of this watcher. The one
/// caller-visible nuance: a caller that PREDICTS a cookie path before its
/// `sync_root` reply arrives (possible only by re-deriving `dir.join(name)`
/// out-of-contract) is dropped at the door where it would once have been queued
/// and then found to be a no-op — the same net effect, now by construction.
///
/// The rule this generalizes to, for any lane added later: **every queue's
/// occupancy must derive from a counted obligation or a driver-minted grant;
/// anything else needs a door.**
///
/// Cloneable: it is a handle over shared state, and every clone addresses the one
/// ledger. Nothing about the mechanism is per-holder.
#[derive(Clone)]
pub(crate) struct CookieIngress {
  ledger: CookieLedger,
  /// The capacity-1 wake. `Sender`, so the driver's `recv` observes the close
  /// when the watcher drops — the same shape the command channel uses.
  wake: async_channel::Sender<()>,
}

/// The DRIVER side of the cookie-cleanup ingress: the same ledger its registry is
/// built around, and the wake it parks on.
///
/// # No request can be lost
///
/// The ingress orders **set the bit (under the mutex) → `try_send`**; the driver
/// orders **`recv` → lock and sweep**. Given a bit set at instant *t*:
///
/// - the `try_send` SUCCEEDS ⇒ a token exists ⇒ some later `recv` consumes it, and
///   the sweep that follows acquires the lock after our release ⇒ it sees our bit;
/// - the `try_send` finds the channel FULL ⇒ a token was already enqueued and not
///   yet consumed at *t* ⇒ the `recv` that consumes it happens no earlier than
///   *t*, so the sweep following it locks after our release ⇒ it sees our bit.
///   This is why a full wake is coalescing rather than lossy;
/// - the channel is CLOSED ⇒ the driver is gone ⇒ its terminal sweep (the orderly
///   close's, or the registry's `Drop` backstop) already owns every record
///   regardless of any bit.
///
/// A bit a sweep SEES but cannot act on immediately — a `Removing`/scheduled
/// record it can only coalesce onto — is not lost either: it rides the record,
/// and the arming that owns the record services it (retire, or a consume into one
/// fresh arming at budget exhaustion — see [`CookieRegistry::schedule_retry`]).
/// A seen bit is therefore a serviced bit, not merely a seen one.
///
/// The retire and close sweeps remain the promptness backstop for every residual
/// scheduling gap, exactly as before.
pub(crate) struct CookieWake {
  ledger: CookieLedger,
  wake: async_channel::Receiver<()>,
}

impl CookieIngress {
  /// Marks the obligation `resolve` names — the whole ingress. The lookup and the
  /// store are ONE critical section, so no claim can interleave between them: a
  /// cancel either finds the record already claimed (and the wake sweep reaps the
  /// cookie through the phase machine) or marks it in time for
  /// [`CookieGuard::claim`] to read the mark and refuse. There is no third
  /// interleaving, and no second decision point that could disagree with the
  /// driver — because this makes no decision at all.
  ///
  /// The mark is idempotent and monotone within a request cycle: set here, cleared
  /// only by the driver, in the same critical section in which it ACTS on it.
  fn mark(&self, resolve: impl FnOnce(&LedgerInner) -> Option<CookieId>) {
    {
      let mut inner = lock_ledger(&self.ledger);
      let Some(id) = resolve(&inner) else {
        // Unaddressable: not an obligation of this watcher. Nothing to store it
        // on, and nothing to tell the driver about — drop it at the door.
        return;
      };
      let Some(ob) = inner.obligations.get_mut(&id) else {
        return;
      };
      ob.reap_requested = true;
    }
    // Ring the wake with the lock RELEASED: the critical section above must stay
    // pure memory (no allocation, no I/O, no waker work), and the release is what
    // the no-lost-request argument orders the send against (see [`CookieWake`]).
    // A full channel means a wake is already pending, which is precisely the wake
    // that will observe the bit just set — so ignoring the result is correct, not
    // lossy. A closed channel means the driver is gone and its terminal sweep owns
    // every record.
    let _ = self.wake.try_send(());
  }

  /// Reaps the cookie at `path` — the public completed-cookie request, resolved
  /// through the projection the claim filled. `by_path` names the path's CURRENT
  /// holder, so a remove delayed across one incarnation's retire and a same-path
  /// successor's claim (two syncs reusing one name in one dir) reaps the successor;
  /// [`request_cancel`](Self::request_cancel) is the incarnation-precise form.
  pub(crate) fn request_remove(&self, path: &Path) {
    self.mark(|inner| inner.by_path.get(path).copied());
  }

  /// Cancels the sync `ticket` keys — the public incarnation-precise cancel/reap.
  /// `by_ticket` is populated at ADMISSION, so this always has a target whatever
  /// the obligation's phase: a sync still parked on its fence, a write still in the
  /// pool, or a cookie already owned. Because a ticket sequence is minted once and
  /// never re-minted, it resolves that one incarnation or — once it has retired —
  /// nothing, never a same-name successor. The watcher already dropped a
  /// foreign-brand ticket at its door, so a sequence reaching here belongs to this
  /// ledger's numbering.
  pub(crate) fn request_cancel(&self, ticket: SyncTicket) {
    self.mark(|inner| inner.by_ticket.get(&ticket.seq()).copied());
  }

  /// The live obligation count as the HANDLE sees it — the flood cell's oracle: it
  /// reads the very ledger a public request transitions, so "the flood retained
  /// nothing" is asserted on the structure itself rather than inferred from
  /// process memory.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn ledger_len(&self) -> usize {
    lock_ledger(&self.ledger).obligations.len()
  }

  /// How many wake tokens are outstanding — never more than 1 by construction.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn wake_len(&self) -> usize {
    self.wake.len()
  }
}

/// A detached-blocking-job spawner, captured from the driver's runtime so the
/// registry's [`Drop`] can dispatch its best-effort abnormal-path unlinks
/// off-reactor without an `R` type parameter in scope. `Send + Sync` (the
/// captured closure is zero-capture, so it is both) keeps [`CookieRegistry`]
/// itself `Sync`, so `&cookies` can be read inside the `Send` close-drain future
/// where the LIVE ledger is the drain's quiescence condition (§5.2).
type DetachedSpawner = Box<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>;

/// Locks the ledger, ignoring poisoning: every critical section is a small,
/// invariant-preserving mutation that cannot leave the maps half-written, and
/// the terminal sweep runs from a [`Drop`] — where unwrapping a poisoned lock
/// would abort the process mid-unwind instead of reaping the cookies.
fn lock_ledger(ledger: &CookieLedger) -> MutexGuard<'_, LedgerInner> {
  ledger.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `backoff(k) = min(base · 2^(k-1), cap)` — the cookie-unlink retry delay for
/// the `k`-th attempt of the current arming (`k` ≥ 1). Saturating so a large
/// attempt count can never overflow the shift.
fn cookie_backoff(base: Duration, cap: Duration, attempt: u8) -> Duration {
  let shift = attempt.saturating_sub(1).min(31);
  base.saturating_mul(1u32 << shift).min(cap)
}

/// The ownership half one dispatched cookie write carries into the blocking
/// pool: the ledger holding the record born for it, and the two flags that can
/// refuse the handover.
struct CookieGuard {
  /// This write's incarnation id (§1.1), minted at DISPATCH under the ledger lock
  /// together with the record it keys — the SINGLE birth site — and carried from
  /// here: the [`claim`](Self::claim) and any `self_reap` transition THAT record.
  /// One physical write, one id, one record, for the whole lifecycle: the global
  /// cap has nothing to dedup, and a reused name cannot mask a distinct write
  /// (R12-F3).
  id: CookieId,
  ledger: CookieLedger,
  /// The registry is gone (driver returned, panicked, or was cancelled).
  shutdown: Arc<AtomicBool>,
  /// This write's scope is retiring (its stream is being torn down).
  retiring: Arc<AtomicBool>,
  /// The scope's live root generation, shared with the registry. A replace
  /// commit bumps it under the SURVIVING scope, so a write dispatched under the
  /// pre-replace root carries a now-stale [`dispatched_generation`].
  ///
  /// [`dispatched_generation`]: Self::dispatched_generation
  generation: Arc<AtomicU64>,
  /// The generation current when this write was dispatched. A claim finding the
  /// live generation moved past this one is refused: the root the cookie was to
  /// be reported on is gone, and its create event could never reach the current
  /// stream.
  dispatched_generation: u64,
}

impl CookieGuard {
  /// Hands a just-created cookie to the registry, which then owns it. `None`
  /// means the handover was REFUSED — a cancel named this obligation, the
  /// registry is gone, the scope is retiring, or the scope's root generation has
  /// moved past the one this write was dispatched under — so a sweep has already
  /// passed this path by, or the root the cookie belongs to is gone; either way
  /// the caller must unlink the file itself.
  ///
  /// The refusal check and the transition are ONE critical section against the
  /// sweeps, and every sweep raises its flag BEFORE taking the ledger. So a
  /// claim that lands after a sweep took the map necessarily observes the raised
  /// flag and refuses (the write reaps itself), and one that lands before it is
  /// in the map that sweep takes. There is no third interleaving: a created file
  /// is always owned by exactly one of the two. The generation is one more
  /// refusal reason inside this SAME section, never a new race: a replace commit
  /// bumps it, so a write whose captured generation is stale reaps itself
  /// exactly as a retired one does. The record's own REAP MARK is one more, read
  /// in this same section: a cancel that named this obligation while its write
  /// was still in the pool forces the claim to refuse and self-reap, closing the
  /// "delivered-but-unread cookie orphaned by a raced cancel" window. The mark
  /// rides the record it refuses: usually the self-reap that follows retires the
  /// record and the mark dies with it, but if that unlink fails the record
  /// survives carrying the mark, which the failing arming's budget-exhaustion
  /// completion then services (see [`CookieRegistry::schedule_retry`]).
  ///
  /// An ABSENT record means the abnormal-path [`Drop`] already took the ledger;
  /// its flag is raised before that take, so this refuses on either observation
  /// and the write reaps its own file.
  fn claim(&self, file: &CookieFile) -> Option<CookieId> {
    let mut inner = lock_ledger(&self.ledger);
    let ob = inner.obligations.get_mut(&self.id)?;
    if ob.reap_requested
      || self.shutdown.load(Ordering::SeqCst)
      || self.retiring.load(Ordering::SeqCst)
      || self.generation.load(Ordering::SeqCst) != self.dispatched_generation
    {
      return None;
    }
    // Transition THIS write's own record — born at its dispatch under this same
    // lock — rather than inserting one: there is no insert-by-path anywhere, so
    // a claim can never displace another obligation. A same-path successor and
    // predecessor coexist under distinct keys, each retired by its own syscall
    // verdict. The claim publishes the landing only the write knows (a covered
    // FILE subscription's cookie lands in the PARENT) — path AND identity, so
    // every later removal inherits the write's proof of which object it made.
    // That is what the sweeps and a public path-addressed removal resolve
    // through.
    //
    // `by_path` MAY overwrite an entry left by an older incarnation at this path.
    // Two live records at one path require two live same-name obligations (the
    // path is `dir.join(name)`), which public admission now refuses before birth
    // (`NameInUse`): this overwrite is therefore unreachable through the public
    // surface and retained defensively for state minted below it. Newest-claim-wins
    // if it does occur: the displaced id's record is left untouched (we cannot know
    // which file-at-P history is live), and it reaches its terminal through the
    // id-addressed sweeps, which unlink P on its behalf and earn its confirm.
    ob.file = Some(file.clone());
    ob.phase = Phase::Owned;
    inner.by_path.insert(file.path().to_path_buf(), self.id);
    Some(self.id)
  }
}

/// Owns every cookie this driver has written and not yet removed. Ownership is
/// the registry's, never the reply oneshot's: a caller that abandons its sync
/// cannot strand a file, and neither can a scope that dies under an in-flight
/// write.
///
/// Every physical unlink that ends a cookie's life is a TRACKED, counted job:
/// its ledger record is dropped only once the unlink CONFIRMS (success, or a
/// file already gone), so a transient failure retains the record for a later
/// sweep rather than silently orphaning the file. The reaps that end a cookie
/// — a completed-cookie reap and a scope's stream teardown
/// ([`retire_scope`](Self::retire_scope)), and the orderly close's
/// [`sweep_owned`](Self::sweep_owned) — each raise their flag before taking the
/// paths, so a write still in the blocking pool can never slip a file past the
/// sweep that was supposed to reap it. This type's [`Drop`] is the
/// ABNORMAL-path backstop only (a panic or a task cancellation, where no close
/// grace exists): it dispatches its remaining unlinks DETACHED so it can never
/// block the very unwind it runs under.
struct CookieRegistry<F: FsOps> {
  ops: F,
  /// Raised before the registry stops accepting handovers — at the orderly
  /// close's sweep and, as the abnormal-path backstop, in [`Drop`]. A write in
  /// the pool re-checks it while claiming its file, so a write can never outlive
  /// the registry that dispatched it.
  shutdown: Arc<AtomicBool>,
  ledger: CookieLedger,
  /// Per-scope retirement flags, cloned into each dispatched write. Raised
  /// BEFORE a retiring scope's cookies are unlinked, so a write that lands
  /// afterwards reaps itself instead of surviving. The entry is dropped with the
  /// scope (the write holds its own clone), so this never accrues dead scopes.
  retiring: HashMap<ScopeId, Arc<AtomicBool>>,
  /// Each live scope's canonical root — the FLOOR its cookies may never be
  /// written above (see [`cookie_dir`]). Dropped with the scope, like the flags.
  roots: HashMap<ScopeId, PathBuf>,
  /// Each live scope's root GENERATION, cloned into each dispatched write and
  /// bumped at every replace commit's lane swap (see
  /// [`advance_generation_locked`](Self::advance_generation_locked)), under the
  /// ledger lock so the bump is atomic with a claim. A write claims only while
  /// the generation still matches the one it captured, so a barrier dispatched
  /// under a superseded root reaps itself rather than landing a cookie the
  /// current stream could never observe. Dropped with the scope, like the flags
  /// and the root.
  generations: HashMap<ScopeId, Arc<AtomicU64>>,
  /// Spawns a detached blocking job. Captured from the driver's runtime at
  /// construction so [`Drop`] — which has no `R` in scope — can dispatch its
  /// best-effort abnormal-path unlinks OFF-reactor. Unlinking synchronously in
  /// Drop would, on a hung mount, wedge the very unwind (a panic or a task
  /// cancellation) the Drop is running under; a detached job cannot.
  spawn_detached: DetachedSpawner,
}

impl<F: FsOps> CookieRegistry<F> {
  /// Takes the ledger rather than minting one: it is created at the watcher's
  /// spawn ([`cookie_ingress`]) and shared with the handle, whose public cleanup
  /// requests are transitions on the records this registry admits.
  fn new<R>(ops: F, ledger: CookieLedger) -> Self
  where
    R: RuntimeLite,
  {
    Self {
      ops,
      shutdown: Arc::new(AtomicBool::new(false)),
      ledger,
      retiring: HashMap::new(),
      roots: HashMap::new(),
      generations: HashMap::new(),
      spawn_detached: Box::new(|job| R::spawn_blocking_detach(job)),
    }
  }

  /// `scope`'s stream is live under `root` — recorded on the SAME transitions
  /// the scope registry learns them on (birth, and a replace's commit, which
  /// overwrites the root under a surviving scope). Birth establishes generation
  /// 0; a replace's commit RE-records the root here but no longer bumps the
  /// generation — the bump moved to the lane swap itself
  /// ([`advance_generation_locked`](Self::advance_generation_locked), taken
  /// under the ledger lock), so it is atomic with a concurrent claim and lands
  /// at the swap's linearization point rather than in this post-commit call.
  fn scope_live(&mut self, scope: ScopeId, root: PathBuf) {
    self.roots.insert(scope, root);
    self
      .generations
      .entry(scope)
      .or_insert_with(|| Arc::new(AtomicU64::new(0)));
  }

  /// Bumps `scope`'s root generation under the LEDGER LOCK — the same lock
  /// [`CookieGuard::claim`] takes to read it — so a bump and a claim cannot
  /// interleave: a claim either completes before the bump (sees the OLD
  /// generation, and the stream that generation names is still the current one)
  /// or after it (sees the new generation and refuses). Called at the replace
  /// commit's lane swap, so the generation transition IS the swap's
  /// linearization point: a write dispatched under the retiring root can never
  /// claim once the new stream is live, and one that already claimed belongs to
  /// the still-current old stream. A scope with no generation entry has no
  /// dispatched writes to revoke, so a missing entry is a no-op.
  fn advance_generation_locked(&self, scope: ScopeId) {
    let _ledger = lock_ledger(&self.ledger);
    if let Some(generation) = self.generations.get(&scope) {
      generation.fetch_add(1, Ordering::SeqCst);
    }
  }

  /// The root a cookie for `scope` must stay inside. `None` for a scope with no
  /// live stream — nothing to write a barrier on.
  fn root_of(&self, scope: ScopeId) -> Option<&Path> {
    self.roots.get(&scope).map(PathBuf::as_path)
  }

  /// BIRTHS one cookie obligation, PARKED on the settle fence its sync was
  /// admitted under, and returns its incarnation id. The id, the record, and its
  /// `by_name` and `by_ticket` entries are all created HERE — the SINGLE birth
  /// site, and the single id mint — under the ledger lock, so:
  ///
  /// - every admitted sync is a COUNTED obligation from the instant its caller
  ///   can address it, so the global cap sees a parked sync and a dispatched
  ///   write alike, in one term, with no second gauge to keep in step;
  /// - a cancel through the sync's ticket always has a target, whatever the phase
  ///   — which is why the reap mark can ride the record instead of a free-standing
  ///   tombstone, and why cancelling a sync whose write has not been dispatched
  ///   needs no lookaside scan of the driver's parked-routing local;
  /// - an insert can never displace a live obligation, since the id is minted
  ///   with it and is unique by construction.
  ///
  /// `ticket` is the caller's [`SyncTicket`] sequence — the `by_ticket` key an
  /// incarnation-precise cancel resolves through.
  ///
  /// Called only AFTER every admission refusal has passed: a refused sync must
  /// create nothing at all.
  fn admit_parked(
    &mut self,
    scope: ScopeId,
    name: String,
    ticket: u64,
    fence: FenceId,
  ) -> CookieId {
    let mut inner = lock_ledger(&self.ledger);
    inner.next_cookie_id += 1;
    let id = CookieId(inner.next_cookie_id);
    inner.obligations.insert(
      id,
      Obligation {
        scope,
        name: name.clone(),
        ticket,
        id,
        file: None,
        reap_requested: false,
        last_failure_seq: 0,
        phase: Phase::Parked { fence },
      },
    );
    // Public admission refuses a second live obligation under a name already
    // held (the command handler's `name_in_use` probe → `NameInUse`), so this
    // insert can no longer displace a live same-name record through the public
    // surface. The unconditional insert is retained for state minted BELOW that
    // surface (tests, future internal callers); there, the point-back discipline
    // at retire keeps the id-keyed machinery correct even under a hand-built
    // same-name pair.
    inner.by_name.insert(name, id);
    // The ticket sequence, likewise inserted here in the same critical section.
    // Public admission refuses a second live obligation under a sequence already
    // held (`ticket_in_use` → `TicketInUse`), and a sequence is never re-minted,
    // so this map is an injection from live sequences to live records — a cancel
    // through a ticket resolves that one incarnation for all time.
    inner.by_ticket.insert(ticket, id);
    #[cfg(all(test, feature = "tokio"))]
    {
      inner.census.births += 1;
    }
    id
  }

  /// The parked obligation on `fence` — its id, scope, and rendered name. The
  /// LEDGER is what knows a sync is parked; `parked_cookies` only routes the
  /// fence to its caller's reply, so this reads the truth rather than the local.
  /// O(ledger), which the global cap bounds.
  fn parked_on(&self, fence: FenceId) -> Option<(CookieId, ScopeId, String)> {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .find(|ob| matches!(ob.phase, Phase::Parked { fence: on } if on == fence))
      .map(|ob| (ob.id, ob.scope, ob.name.clone()))
  }

  /// The DISPATCH decision for the obligation parked on a settled fence: either
  /// the write goes to the pool under the returned handle (`Parked → InPool`), or
  /// the obligation reaches its terminal here, having created nothing.
  ///
  /// `None` means DO NOT WRITE — a cancel marked this obligation before its write
  /// was ever dispatched, so it is retired `NeverCreated` right here (nothing
  /// physical can exist for a parked record) and the caller must answer the
  /// barrier `Retired` and abandon the fence. Folding the mark into the dispatch
  /// is what makes "cancel a sync that has not been written yet" one transition of
  /// the machine rather than a lookaside protocol.
  ///
  /// `Some(guard)` transitions the record `InPool` and hands the write its
  /// ownership handle, minting the scope's retirement flag on demand. The flags
  /// are taken here, at dispatch, so they cover the whole in-flight window:
  /// everything that retires the cookie between here and the write's landing is
  /// visible to the write itself.
  fn dispatch_guard(&mut self, scope: ScopeId, id: CookieId) -> Option<CookieGuard> {
    let generation = Arc::clone(
      self
        .generations
        .entry(scope)
        .or_insert_with(|| Arc::new(AtomicU64::new(0))),
    );
    let dispatched_generation = generation.load(Ordering::SeqCst);
    let retiring = Arc::clone(self.retiring.entry(scope).or_default());
    {
      let mut inner = lock_ledger(&self.ledger);
      let ob = inner.obligations.get_mut(&id)?;
      if ob.reap_requested {
        inner.retire(id, Reaped::NeverCreated);
        return None;
      }
      ob.phase = Phase::InPool;
    }
    Some(CookieGuard {
      id,
      ledger: Arc::clone(&self.ledger),
      shutdown: Arc::clone(&self.shutdown),
      retiring,
      generation,
      dispatched_generation,
    })
  }

  /// The count of outstanding cookie obligations: one ledger snapshot, ONE term.
  /// Every lifecycle stage from the sync's admission to its typed terminal is ONE
  /// record in this map — a sync parked on its fence, an in-pool write, an owned
  /// cookie, an unlink in flight, a failed unlink — so there is nothing to dedup
  /// and no second gauge that could drift out of step with it.
  ///
  /// Serves BOTH the close reply (a `NotQuiesced` count) AND `SyncRoot`
  /// admission (the whole-lifecycle global cap Φ, §4.1). ONE method, so the two
  /// callers can never diverge (divergence is exactly how the earlier close bug
  /// happened); do not fork it.
  ///
  /// A false `Ok(0)` is foreclosed structurally: the record is born before any
  /// caller can address the obligation — and long before a file can exist — and
  /// is removed only by a typed [`retire`], which every path takes only once it
  /// holds evidence: a syscall verdict, or the fact that nothing was ever
  /// created. There is no window in which an obligation exists and this count
  /// omits it.
  ///
  /// [`retire`]: LedgerInner::retire
  fn unremoved(&self) -> usize {
    lock_ledger(&self.ledger).obligations.len()
  }

  /// How many cookies `scope` still owns — the backlog cap's probe. O(ledger),
  /// which the cap keeps bounded (`cookie_backlog_cap × live scopes`).
  fn unremoved_for(&self, scope: ScopeId) -> usize {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter(|ob| ob.scope == scope)
      .count()
  }

  /// Whether `scope` has a sync anywhere in the write pipeline — parked on its
  /// settle fence, or dispatched into the pool. This is the single-flight write
  /// gate: ONE phase probe over the one ledger, rather than two structures (a
  /// gauge and a parked local) to keep in step with each other.
  ///
  /// The gate opens the moment that sync leaves `Parked`/`InPool` — at its CLAIM,
  /// or at the typed terminal of a write that created nothing — rather than at the
  /// tail of its `CookieWriteDone`. A scope can therefore transiently hold one
  /// write JOB plus one COMPLETING TAIL (a claimed write whose completion message
  /// is still in flight), which is the bound that matters: at most one
  /// `write_cookie` syscall per scope is ever outstanding, so a caller that times
  /// out and retries still cannot pile blocking writes against a hung mount.
  fn has_pending_write(&self, scope: ScopeId) -> bool {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .any(|ob| ob.scope == scope && matches!(ob.phase, Phase::Parked { .. } | Phase::InPool))
  }

  /// Whether a LIVE obligation already holds this rendered cookie name — the
  /// PHYSICAL-identity gate. With cancel addressed by ticket rather than by name,
  /// this gate's load-bearing role is no longer cancel disambiguation but the
  /// physical file: one live obligation per name ⇒ per path ⇒ no two live syncs
  /// contend one cookie file (the claim's `by_path` displacement and the
  /// create_new/unlink collisions stay unmintable through the public surface).
  /// `by_name` membership IS liveness: entries are inserted only at admission
  /// (which now requires absence) and removed exactly at that record's retire, so
  /// every phase from `Parked` through `RemoveFailed` holds its name, and a name is
  /// freed only at the holder's typed terminal. A name with no live holder —
  /// including one whose holder just retired — admits, so SEQUENTIAL reuse of a
  /// name is unrefused; only a second CONCURRENT live holder is. One hash lookup,
  /// no fs I/O.
  fn name_in_use(&self, name: &str) -> bool {
    lock_ledger(&self.ledger).by_name.contains_key(name)
  }

  /// Whether a LIVE obligation already holds this ticket sequence — the ticket
  /// single-use gate. Mirrors [`name_in_use`](Self::name_in_use): `by_ticket`
  /// membership is liveness, inserted at admission and removed at retire, so this
  /// refuses only a second CONCURRENTLY-live obligation under one sequence (a
  /// caller passing one ticket to two live syncs). A sequence whose holder has
  /// retired admits — but since the watcher never re-mints a sequence, that never
  /// arises for a conforming caller. One hash lookup, no fs I/O.
  fn ticket_in_use(&self, ticket: u64) -> bool {
    lock_ledger(&self.ledger).by_ticket.contains_key(&ticket)
  }

  /// Re-arms PARKED removal records at a cap refusal — refusing-scope-FIRST,
  /// then least-recently-FAILED-first across every other scope — so a caller
  /// being refused always makes progress on its own backlog, and a recovered
  /// mount's records can never be starved by a permafailing one (R11-1):
  /// `last_failure_seq` is refreshed on every failure, so records that keep
  /// failing keep moving to the BACK of the selection order, and a record that
  /// has not failed since the fs recovered ratchets monotonically to the front.
  ///
  /// The backlog-recovery driver: a parked record on a RETIRED scope has no live
  /// scope to sweep it and no timer to retry it, so without this a
  /// since-recovered filesystem would never drain those records and the global
  /// cap could lock out every future sync permanently. Bounded: ≤ `limit`
  /// re-arms for the refusing scope PLUS ≤ `limit` across the rest, per refusal
  /// (the two budgets are separate, so a scope whose own cap-sized backlog
  /// re-parks between refusals can never consume the whole batch and starve the
  /// rotation). Single-flight and the scheduled/`Removing` filters coalesce
  /// everything already owned by a timer or an in-flight job. Returns how many
  /// were re-armed. No fs I/O, no allocation growth beyond the snapshot; runs
  /// only on the refusal path.
  fn rearm_parked_batch<R>(
    &self,
    op_tx: &async_channel::Sender<OpResult<F::Handle>>,
    refusing: ScopeId,
    limit: usize,
  ) -> usize
  where
    R: RuntimeLite,
  {
    // ONE lock: snapshot every PARKED record — `RemoveFailed` carrying no
    // deadline of its own. The deadline rides the record, so "scheduled" is one
    // field of the record being tested, not a cross-structure conjunction.
    let parked: Vec<(CookieId, ScopeId, u64)> = {
      let inner = lock_ledger(&self.ledger);
      inner
        .obligations
        .values()
        .filter(|ob| matches!(ob.phase, Phase::RemoveFailed { retry_at: None, .. }))
        .map(|ob| (ob.id, ob.scope, ob.last_failure_seq))
        .collect()
    };
    let (mut mine, mut others): (Vec<_>, Vec<_>) = parked
      .into_iter()
      .partition(|(_, scope, _)| *scope == refusing);
    mine.truncate(limit); // order immaterial: ≤ cap + 1 records
    others.sort_by_key(|(_, _, seq)| *seq); // LRU: least-recently-failed first
    others.truncate(limit);
    let rearmed = mine.len() + others.len();
    for (id, _, _) in mine.into_iter().chain(others) {
      self.request_removal::<R>(op_tx, RemovalRequest::Targeted(id));
    }
    rearmed
  }

  /// Spawns the ONE blocking unlink of `file` for incarnation `id` (the record
  /// was already transitioned to `Removing` under the ledger lock by the
  /// decision that called this, which read `id` from the record inside that
  /// same section). The job writes the PHYSICAL VERDICT itself, under the ledger
  /// mutex, before reporting anything: a confirmed removal (unlinked, already
  /// gone, or the name displaced by a foreign object) retires incarnation `id` —
  /// a racing successor keeps its own key and is left intact — and a transient
  /// failure parks the record as `RemoveFailed` so the file is never orphaned.
  /// The `CookieRemoveDone` that follows carries the id and drives SCHEDULING
  /// only: the driver owns the clock, so it alone stamps the retry deadline.
  /// Truth therefore rides the job that learned it, and a lost completion costs
  /// promptness (a parked record awaits a re-arm), never ownership.
  ///
  /// The job carries the write's own identity for the cookie — and, through its
  /// clone of the record's [`CookieFile`], the create's descriptor, so that
  /// identity is still the cookie's alone while this syscall runs. A successor
  /// that reclaimed the name is therefore REFUSED rather than unlinked
  /// ([`CookieRemoval::Displaced`]): the successor's file survives, its own
  /// record still owns it, and this incarnation retires having proved its file is
  /// no longer at the name. What remains unclosed is a Linux/macOS-only window
  /// stated at `remove_verified`; Windows closes it by removing through the
  /// verified handle.
  fn spawn_unlink<R>(
    &self,
    op_tx: &async_channel::Sender<OpResult<F::Handle>>,
    file: CookieFile,
    id: CookieId,
  ) where
    R: RuntimeLite,
  {
    let ops = self.ops.clone();
    let ledger = Arc::clone(&self.ledger);
    let tx = op_tx.clone();
    R::spawn_blocking_detach(move || {
      let confirmed = ops.remove_cookie(&file).is_ok();
      {
        let mut inner = lock_ledger(&ledger);
        if confirmed {
          // Retire incarnation `id`: keyed by the id, this can never remove a
          // successor that reclaimed the same path between the unlink syscall and
          // this lock.
          inner.retire(id, Reaped::ConfirmedGone);
        } else {
          // The syscall has already returned, so leaving `Removing` here cannot
          // overlap a second unlink for this record: the file is retained as
          // failed, PARKED until the driver schedules its retry.
          inner.record_remove_failed(id);
        }
      }
      let _ = tx.try_send(OpResult::CookieRemoveDone { id, confirmed });
    });
  }

  /// The under-the-lock removal decision: returns `Some((file, id))` iff the
  /// caller must now spawn an unlink, having transitioned that record to
  /// `Removing` here. Single-flight-per-record follows because only a state that
  /// is not already `Removing` can dispatch, and the transition happens before
  /// the job exists. The wake sweep calls this inside its OWN critical
  /// section (so one whole pass is one lock acquisition); every other
  /// producer routes through [`request_removal`](Self::request_removal).
  ///
  /// EVERY request is id-addressed: no path-addressed removal decision exists in
  /// the driver at all, because the one PUBLIC path-addressed request resolves
  /// `by_path` at the door — under this same mutex, in the same critical section
  /// that marks the record it found ([`CookieIngress::request_remove`]). So a
  /// record displaced from `by_path` by a same-path successor stays reachable, and
  /// a retired one is a no-op: a stale actor never touches a successor
  /// incarnation.
  fn removal_decision_locked(
    inner: &mut LedgerInner,
    req: &RemovalRequest,
  ) -> Option<(CookieFile, CookieId)> {
    // A record that is missing — already retired — is idempotently nothing.
    let id = match req {
      RemovalRequest::Targeted(id) | RemovalRequest::RetryDue(id) => *id,
    };
    let ob = inner.obligations.get_mut(&id)?;
    // A record with no landing has no file to unlink: its sync is still parked (no
    // write has been dispatched, so nothing physical can exist), or its write is
    // in the pool and only that write can learn where its cookie landed. This one
    // line is what makes every sweep, retry and public removal structurally
    // incapable of unlinking for a pre-physical record: a parked record is left to
    // its pre-physical terminal, and an in-pool one reaps itself against the flags.
    let file = ob.file.clone()?;
    let attempts = match (&ob.phase, req) {
      // Owned: a marked record or a targeted sweep dispatches a fresh removal;
      // a retry for a not-yet-failed record is a no-op.
      (Phase::Owned, RemovalRequest::Targeted(_)) => Some(0),
      (Phase::Owned, RemovalRequest::RetryDue(_)) => None,
      // RemoveFailed, SCHEDULED (its own retry owns it): coalesce for a marked
      // record or a targeted sweep; the due retry itself dispatches.
      (
        Phase::RemoveFailed {
          retry_at: Some(_), ..
        },
        RemovalRequest::Targeted(_),
      ) => None,
      // RemoveFailed, PARKED: a marked record or a targeted sweep RE-ARMS with a
      // fresh budget.
      (Phase::RemoveFailed { retry_at: None, .. }, RemovalRequest::Targeted(_)) => Some(0),
      // The retry dispatcher fired for a due record: dispatch it preserving the
      // attempt count toward the budget.
      (Phase::RemoveFailed { attempts, .. }, RemovalRequest::RetryDue(_)) => Some(*attempts),
      // A `Removing` record (an unlink already owns this record's fate) → coalesce.
      (Phase::Removing { .. }, _) => None,
      // A parked sync and an in-pool write are pre-physical, so neither is
      // addressable for removal: see `path` above.
      (Phase::Parked { .. } | Phase::InPool, _) => None,
    };
    let attempts = attempts?;
    // Any deadline this record carried is superseded by the dispatch: it lives
    // inside the phase, so the transition retires it with no second structure to
    // keep in step and no chance of a schedule outliving its arming.
    ob.phase = Phase::Removing { attempts };
    Some((file, id))
  }

  /// The ONE unlink dispatch point routed to by `retire_scope`, `sweep_owned`,
  /// the recovery re-arm, and the retry dispatcher (the wake sweep uses the
  /// `_locked` core directly, so one pass is one lock acquisition). Decides under
  /// the ledger lock, spawns after unlock.
  fn request_removal<R>(
    &self,
    op_tx: &async_channel::Sender<OpResult<F::Handle>>,
    req: RemovalRequest,
  ) where
    R: RuntimeLite,
  {
    let decision = {
      let mut inner = lock_ledger(&self.ledger);
      Self::removal_decision_locked(&mut inner, &req)
    };
    if let Some((file, id)) = decision {
      self.spawn_unlink::<R>(op_tx, file, id);
    }
  }

  /// The PHYSICAL half of the wake sweep: ONE O(ledger) pass that routes every
  /// MARKED obligation through the same phase machine every other producer routes
  /// through, deciding under the lock and spawning after it is released — the
  /// invariable rule, since an unlink on a hung mount under this mutex would
  /// serialize every other critical section behind it, the caller-facing ingress
  /// included.
  ///
  /// The mark is cleared EXACTLY when the sweep acts on it — i.e. iff the decision
  /// transitioned the record to `Removing` and this call will spawn its unlink.
  /// That equivalence is what each surviving mark then means:
  ///
  /// - `Parked` — pre-physical, so nothing is dispatched (no path, no file). Its
  ///   terminal is the caller-answering one [`retire_parked_cookies`] runs.
  /// - `InPool` — only the write knows where its cookie will land, so nothing is
  ///   dispatched. The mark is what its claim reads, refuses on, and self-reaps
  ///   against; it usually dies with the record, but if that self-reap's unlink
  ///   fails the record survives carrying the mark, which the failing arming's
  ///   budget-exhaustion completion then services (see
  ///   [`CookieRegistry::schedule_retry`]).
  /// - `Removing` / SCHEDULED `RemoveFailed` — an unlink or a deadline already
  ///   owns this record's fate, so the request COALESCES onto it. The mark stays,
  ///   and the arming that owns the record services it: on retire the mark dies
  ///   with the record, and on budget exhaustion the failing completion consumes
  ///   the mark into one fresh arming ([`CookieRegistry::schedule_retry`]) — not
  ///   dependent on a subsequent wake.
  /// - PARKED `RemoveFailed` — budget-spent and unscheduled: the request re-arms it
  ///   with a fresh budget, which is the demand edge that makes a fresh reap or
  ///   cancel accelerate a stalled backlog.
  fn sweep_reap_marks<R>(&self, op_tx: &async_channel::Sender<OpResult<F::Handle>>)
  where
    R: RuntimeLite,
  {
    let dispatch: Vec<(CookieFile, CookieId)> = {
      let mut inner = lock_ledger(&self.ledger);
      let marked: Vec<CookieId> = inner
        .obligations
        .values()
        .filter(|ob| ob.reap_requested)
        .map(|ob| ob.id)
        .collect();
      marked
        .into_iter()
        .filter_map(|id| {
          let decided = Self::removal_decision_locked(&mut inner, &RemovalRequest::Targeted(id))?;
          if let Some(ob) = inner.obligations.get_mut(&id) {
            ob.reap_requested = false;
          }
          Some(decided)
        })
        .collect()
    };
    for (file, id) in dispatch {
      self.spawn_unlink::<R>(op_tx, file, id);
    }
  }

  /// The earliest scheduled cookie-unlink retry, or `None` if every failed record
  /// is parked — the driver's deadline arm. O(ledger), which the global cap
  /// bounds.
  fn min_retry_at(&self) -> Option<Instant> {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter_map(|ob| match ob.phase {
        Phase::RemoveFailed { retry_at, .. } => retry_at,
        Phase::Parked { .. } | Phase::InPool | Phase::Owned | Phase::Removing { .. } => None,
      })
      .min()
  }

  /// Pulls every scheduled retry no later than `floor` — the close sweep's
  /// flat-base rule, so a record sitting on a far exponential deadline is still
  /// retried inside the grace instead of making close report a spurious
  /// `NotQuiesced`.
  fn pull_retries_forward(&self, floor: Instant) {
    let mut inner = lock_ledger(&self.ledger);
    for ob in inner.obligations.values_mut() {
      if let Phase::RemoveFailed {
        retry_at: Some(at), ..
      } = &mut ob.phase
        && *at > floor
      {
        *at = floor;
      }
    }
  }

  /// Schedules incarnation `id`'s retry after a failed unlink — the driver is the
  /// only writer of deadlines, because it is the only holder of the clock. A
  /// record PARKED within its budget takes `now + backoff(attempts)`. Past the
  /// budget an UNMARKED record stays parked (no schedule, zero CPU) awaiting an
  /// explicit re-arm; a record that still carries a STANDING reap mark is
  /// serviced here instead — the mark is consumed into exactly one fresh arming,
  /// scheduled due-now, because the wake that carried it may already have been
  /// spent by a coalescing sweep while an earlier arming owned the record. Any
  /// other phase — retired by a racing confirm, or already re-armed into
  /// `Removing` by a sweep — is a stale report and touches nothing. `flat` uses
  /// the flat base delay during the close drain (the ~1 s grace bounds attempts
  /// there).
  fn schedule_retry(&self, config: &DriverConfig, id: CookieId, now: Instant, flat: bool) {
    let mut inner = lock_ledger(&self.ledger);
    let Some(ob) = inner.obligations.get_mut(&id) else {
      return;
    };
    let Phase::RemoveFailed {
      attempts,
      retry_at: retry_at @ None,
    } = &mut ob.phase
    else {
      return;
    };
    if *attempts > config.cookie_retry_budget {
      // Budget exhausted: the record would park. A standing reap mark is serviced
      // in this same critical section — consumed into exactly one fresh arming
      // (attempts 0, `Targeted` re-arm semantics), scheduled due-now for the
      // existing retry machinery to dispatch. Set-then-consume can never lose a
      // request; consume-then-park can never spin. An unmarked record parks.
      if ob.reap_requested {
        ob.reap_requested = false;
        ob.phase = Phase::RemoveFailed {
          attempts: 0,
          retry_at: Some(now),
        };
      }
      return;
    }
    let delay = if flat {
      config.cookie_retry_base
    } else {
      cookie_backoff(config.cookie_retry_base, config.cookie_retry_cap, *attempts)
    };
    *retry_at = Some(now + delay);
  }

  /// Retires `scope`: raise its flag FIRST — a write still in the pool then
  /// finds its claim refused and reaps itself, rather than landing a file into a
  /// scope nothing will sweep again — then route every cookie the scope still
  /// owns through the phase machine (§2.7): `Owned` and PARKED `RemoveFailed`
  /// dispatch with a fresh budget, a scheduled `RemoveFailed` keeps its retry, a
  /// `Removing` coalesces, and an `InPool` record is left to the flag it just
  /// raised (only its own write knows where its file landed). The records are
  /// KEPT until each unlink confirms, so a transient failure cannot orphan the
  /// file.
  ///
  /// A sync still PARKED on its fence is pre-physical, so there is nothing here to
  /// unlink and nothing to revoke by flag. Its fence was resolved `Dead` by the
  /// same teardown, and the next settle observation reads that VERDICT — not the
  /// maps this function clears — to retire the record `NeverCreated` and answer its
  /// barrier `Retired`, the ONE site that resolves a parked sync, caller reply and
  /// ledger record in the same step. Which is why the ordering between this
  /// function and that observation no longer matters: when a death is ingested
  /// inside the settle-edge drain, the observation runs while `roots` and `handles`
  /// still read live, and only the verdict carries the truth.
  fn retire_scope<R>(&mut self, scope: ScopeId, op_tx: &async_channel::Sender<OpResult<F::Handle>>)
  where
    R: RuntimeLite,
  {
    if let Some(flag) = self.retiring.remove(&scope) {
      flag.store(true, Ordering::SeqCst);
    }
    self.roots.remove(&scope);
    // The generation is per-scope and dies with it — a retired scope's writes
    // are already revoked by the flag above, so the generation has no work left.
    self.generations.remove(&scope);
    // Snapshot each of the scope's incarnation ids under the lock, then dispatch
    // each as a `Targeted(id)`, which addresses the incarnation directly.
    let reap: Vec<CookieId> = lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter(|ob| ob.scope == scope)
      .map(|ob| ob.id)
      .collect();
    for id in reap {
      self.request_removal::<R>(op_tx, RemovalRequest::Targeted(id));
    }
    // A record whose unlink PERMANENTLY fails (a genuinely undeletable file —
    // rare: we created it, so we hold its directory) parks here after its budget
    // with no live scope left to re-arm it, lingering in the ledger until the
    // driver closes or the fs recovers. That is the honest floor for "never
    // orphan a file we cannot confirm gone" (the alternative is to FORGET it,
    // i.e. leak the disk file). The dead-scope tail no longer grows without bound
    // under watch/unwatch churn: the GLOBAL cookie cap (checked at `SyncRoot`
    // admission) ceilings the whole ledger across live AND retired scopes.
  }

  /// Raises the shutdown flag WITHOUT sweeping — the orderly close's first step,
  /// so a write landing during the close drain finds its claim refused and reaps
  /// itself (inside its own tracked job) rather than landing a cookie owned but
  /// unswept behind the sweep below.
  fn begin_shutdown(&self) {
    self.shutdown.store(true, Ordering::SeqCst);
  }

  /// Routes every cookie the registry still owns through the phase machine — the
  /// orderly close's sweep, run BEFORE the registry is dropped so the close grace
  /// COVERS the unlinks: a hung mount then makes close report `NotQuiesced`
  /// honestly rather than wedging, and each record is dropped as its unlink
  /// confirms. Run after [`begin_shutdown`](Self::begin_shutdown), so nothing new
  /// can land unswept behind it. Per-phase rules as
  /// [`retire_scope`](Self::retire_scope) (§2.8).
  ///
  /// PARKED syncs are not this sweep's to resolve — they are pre-physical, and
  /// their callers' replies live in the driver's routing local; close retires them
  /// through [`retire_parked_cookies`] alongside this call.
  fn sweep_owned<R>(&self, op_tx: &async_channel::Sender<OpResult<F::Handle>>)
  where
    R: RuntimeLite,
  {
    // Snapshot each incarnation id, then dispatch each `Targeted(id)`,
    // addressing the incarnation directly.
    let owned: Vec<CookieId> = lock_ledger(&self.ledger)
      .obligations
      .keys()
      .copied()
      .collect();
    for id in owned {
      self.request_removal::<R>(op_tx, RemovalRequest::Targeted(id));
    }
  }

  /// How many cookies the registry currently owns — the leak oracle: a failed
  /// write, an abandoned reply, a retired scope, and a completed-cookie reap must
  /// all leave it exactly as they found it.
  #[cfg(all(test, feature = "tokio"))]
  fn len(&self) -> usize {
    lock_ledger(&self.ledger).obligations.len()
  }

  /// How many obligations carry a reap mark — a test hook proving the
  /// boundedness rule (a mark exists only on a live obligation, and never
  /// survives it).
  #[cfg(all(test, feature = "tokio"))]
  fn reap_marks(&self) -> usize {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter(|ob| ob.reap_requested)
      .count()
  }

  /// How many of `scope`'s records are PARKED — `RemoveFailed` carrying no
  /// deadline (the same predicate `rearm_parked_batch` selects on). The
  /// recovery-fairness suites' oracle for which scope's backlog a cap refusal
  /// re-armed vs. left parked.
  #[cfg(all(test, feature = "tokio"))]
  fn parked_for(&self, scope: ScopeId) -> usize {
    lock_ledger(&self.ledger)
      .obligations
      .values()
      .filter(|ob| {
        ob.scope == scope && matches!(ob.phase, Phase::RemoveFailed { retry_at: None, .. })
      })
      .count()
  }

  /// The birth/terminal census paired with the live record count — the census
  /// equation's oracle.
  #[cfg(all(test, feature = "tokio"))]
  fn census(&self) -> (Census, usize) {
    let inner = lock_ledger(&self.ledger);
    (inner.census, inner.obligations.len())
  }
}

/// Which producer is asking [`CookieRegistry::removal_decision_locked`] to
/// remove a cookie — the two callers with different addressing/re-arm
/// semantics. Both address ONE incarnation by id: with the cleanup queue gone,
/// the public path-addressed request resolves its path to an id at the door, so
/// no path-addressed removal decision survives here.
#[derive(Clone)]
enum RemovalRequest {
  /// A targeted request — a marked record on the wake sweep, a retire sweep, the
  /// close sweep, a recovery re-arm: addresses one incarnation by id, and a no-op
  /// if that incarnation has been retired (a sweep never touches a successor
  /// incarnation it did not select — it may belong to a different, live scope).
  /// `Owned` dispatches; a PARKED `RemoveFailed` re-arms with a fresh budget; a
  /// scheduled `RemoveFailed` or a `Removing` coalesces; a sync still parked and a
  /// write still in the pool are pre-physical, so neither is addressable for
  /// removal — the pool write reaps itself against the flags and the mark.
  Targeted(CookieId),
  /// The retry dispatcher, firing a due deadline: dispatches only a
  /// `RemoveFailed` record, PRESERVING its attempt count toward the budget; a
  /// retired incarnation or any other phase is a no-op.
  RetryDue(CookieId),
}

impl<F: FsOps> Drop for CookieRegistry<F> {
  fn drop(&mut self) {
    // The ABNORMAL-path backstop — a panic or a task cancellation, where no
    // orderly close ran its tracked sweep. On the NORMAL path the close already
    // swept every owned cookie as a grace-covered job, so this finds the ledger
    // empty (or only records whose unlink transiently failed) and merely raises
    // the flag one more, idempotent, time.
    //
    // The flag is raised BEFORE the map is taken, and a write claims its file
    // under the same lock: a claim that beat the take is in the map this sweep
    // unlinks; one that lost it sees the flag and reaps itself. Neither order
    // leaks. The unlinks are DETACHED, never synchronous: a synchronous unlink
    // on a hung mount would wedge the very unwind this Drop runs under. A
    // detached job may not run on a cancelled runtime — the accepted best-effort
    // for the abnormal path, which by construction cannot block.
    self.shutdown.store(true, Ordering::SeqCst);
    // Retire every remaining record under ONE lock (removing its two index
    // entries with it), each counted as the abnormal residual it is. Keep the
    // landing path of each record that has NO unlink already in flight, for a
    // detached best-effort unlink.
    //
    // A record with NO path is pre-physical, so it has no file to reap: a sync
    // still PARKED on its fence had no write dispatched at all (its caller's reply
    // drops with the driver's locals, and its record is counted here as the
    // abnormal residual it is), while a write still IN THE POOL knows where its
    // file landed and nobody else does — the flag raised above is what makes it
    // refuse its claim and reap the file itself, the same protocol that covers a
    // write racing an orderly close.
    //
    // A `Removing` record already has a job — the orderly-close drain's (which
    // may be hung past the grace), or one spawned just before an abnormal cancel
    // — and a second unlink for the same path is exactly the duplicate the
    // single-flight choke point forbids. A `Removing` record whose job never
    // lands on a cancelled runtime is the accepted abnormal-path residual, no
    // worse than any other detached job there.
    //
    // ACCEPTED RESIDUAL (orderly close): a `Removing` record whose unlink hangs
    // PAST the ~1 s grace and only THEN fails is skipped here and gets no retry —
    // its file persists. This is bounded and honestly reported: close already
    // returned `NotQuiesced` counting that cookie (`unremoved` tallies every
    // record), and the residue is an inert, reserved-namespace
    // (`is_sync_artifact`) file that never surfaces as a user event. Removing it
    // after the fact would require a cleanup owner that outlives the driver task
    // and awaits the hung unlink — disproportionate machinery for an inert file
    // left by a pathological mount during shutdown. On a healthy fs the drain
    // confirms every unlink within the grace and this branch reaps nothing.
    let reap: Vec<CookieFile> = {
      let mut inner = lock_ledger(&self.ledger);
      let ids: Vec<CookieId> = inner.obligations.keys().copied().collect();
      ids
        .into_iter()
        .filter_map(|id| inner.retire(id, Reaped::AbnormalResidual))
        .filter(|ob| !matches!(ob.phase, Phase::Removing { .. }))
        .filter_map(|ob| ob.file)
        .collect()
    };
    if reap.is_empty() {
      return;
    }
    let ops = self.ops.clone();
    (self.spawn_detached)(Box::new(move || {
      // Best-effort, but never blind: each record carries the identity its own
      // write captured, so even this last sweep unlinks only what it can prove
      // is its own — the abnormal path is exactly where a stale path is most
      // likely to have been reclaimed by someone else.
      for file in reap {
        let _ = ops.remove_cookie(&file);
      }
    }));
  }
}

/// One in-flight root replacement: the reservation the commit releases, the
/// caller's reply, and which of the two replace shapes is running (`mode`).
struct ReplaceState<H> {
  reservation: crate::watcher::ReservationGuard,
  reply: futures_channel::oneshot::Sender<Result<(), crate::error::ReplaceRootError>>,
  mode: ReplaceMode<H>,
}

/// The two replace shapes.
enum ReplaceMode<H> {
  /// The general replace: a fresh stream spawns and the commit swaps lanes. A
  /// descending replace parks its spawned-but-uncommitted replacement in
  /// `arming` while the new root's pre-arm runs on the blocking pool
  /// ([`FsOps::preflight_arm`]); a kernel-recursive replace commits straight
  /// off its spawn and never populates it.
  NewFd { arming: Option<SpawnedSource<H>> },
  /// The same-transport WIDEN (descending only, old root strictly inside the
  /// new): no stream is ever spawned — the live fd gains the new root's watch
  /// and the Monitor adopts the old tree in place, so the commit swaps no
  /// lane, bumps no generation, and retires nothing. Holding no native
  /// handle, this mode needs no close-sweep teardown; an armed-but-refused
  /// reservation's watch descriptor dies with the scope's own stream.
  SameFd { phase: SameFdPhase },
}

/// A widen commit's applied shape: committed, or fallen back — an unprovable
/// commit (INV-ROOT's tainted witnessed window, an old root with no mintable
/// identity for the adopted edge's re-proof, or an old root more than one
/// segment down, whose connector edges no proof covers: the legitimate refusals)
/// or the core's pre-mutation guards (the impossible path made visible instead
/// of a silent `Ok`). Either fallback leaves the core, the Monitor, AND the
/// registry untouched — the widened entry publishes only at a commit
/// (Golden-2), so the OLD entry keeps naming the live truth through the whole
/// fallback and through a fallback failure. The caller converts the obligation
/// to the general stream replace: its commit overwrites the entry with
/// spawn-minted truth and its failure taxonomy answers the caller.
enum WidenOutcome {
  /// The core and Monitor spliced; the widen is live on the same transport.
  Committed,
  /// Fall back to the new-stream replace under the caller's original
  /// reservation. `Some` carries an unprovable commit's diagnostics (the
  /// cause plus the benign reserved records the latch consumed) — read
  /// only by the env-gated widen diagnostic today, mirroring the transport
  /// `Fatal`'s carried class; `None` is the impossible-path core refusal.
  FallBack(Option<WidenTaint>),
}

/// Where a same-transport widen stands.
enum SameFdPhase {
  /// The no-spawn [`RootMeta`] resolve ([`FsOps::resolve_root_meta`]) is on
  /// the blocking pool.
  MetaPending,
  ///`reserved` is pre-arming the widened root on the LIVE port; `meta` is the
  /// resolved, re-validated world the commit will adopt.
  Arming { reserved: WatchId, meta: RootMeta },
  /// The pre-arm succeeded and the commit is CATCHING UP to the lane: the
  /// NORMAL source arm processes the scope's queued messages one per loop
  /// iteration — benign records deliver at the (still current) old root,
  /// death records and losses taint through the two INV-ROOT funnels — and
  /// `remaining` counts down the queued-length snapshot taken at
  /// [`OpResult::WidenArmed`]. The commit fires at the first loop top AFTER
  /// the effect flush with `remaining == 0` and the lane not dead-pending
  /// ([`resolve_widen_catchups`]); a scope death en route resolves the widen
  /// `Retired` through the same liveness gate every path uses. This is the
  /// by-construction shape that retired the synchronous drain: ordering
  /// (Golden-1), lane death (G2-1), boundedness (G2-2), and delivery
  /// coordinates (G3-1) are all properties of the arm's own frame — one
  /// message per iteration, effects flushed between, death only via the end
  /// marker — so none of them exists as a separate obligation here.
  CatchUp {
    reserved: WatchId,
    meta: RootMeta,
    /// The pre-arm outcome the commit replays (`Installed`/`Aliased`).
    replay: WatchOutcome,
    /// Prefix messages still to be processed by the arm before the commit
    /// may read the witnessed window. Strictly decreasing; post-snapshot
    /// arrivals are NOT counted — they are transport-concurrent with the
    /// commit and ride the post-commit known-root regime.
    remaining: usize,
  },
}

/// One watch awaiting its spawn result: the reply channel plus the root the
/// watcher reserved, so the final-root revalidation can exclude this watch's
/// own reservation from the conflict check.
struct PendingWatch {
  requested: PathBuf,
  reply: WatchReply,
}

/// A registration grant held between a descending spawn's success and its
/// ROOT watch-result: the stream is live but covers nothing until the root's
/// kernel watch arms, and the public contract dates delivery from the grant.
///
/// The birth is still IN FLIGHT here, which is why the driver's map of these
/// counts against [`MAX_TEARDOWN_BACKLOG`]: the caller has not been handed the
/// grant and so cannot unwatch, while both remaining outcomes are fallible — a
/// failed root arm refuses the registration and a cancelled `watch()` unwinds it,
/// each retiring the running stream into the counted teardown path.
struct DeferredGrant {
  pending: PendingWatch,
  /// The final canonical root (what the grant hands the caller).
  root: PathBuf,
}

/// Commits one successful registration: hands the caller the armed-to-unwind
/// grant. `false` means the watch() future was already gone — the caller
/// unwinds the scope.
fn commit_grant(
  pending: PendingWatch,
  scope: ScopeId,
  root: PathBuf,
  unwind_tx: &async_channel::Sender<ScopeId>,
) -> bool {
  let grant = WatchGrant::new(scope, root, unwind_tx.clone());
  match pending.reply.send(Ok(grant)) {
    Ok(()) => true,
    Err(payload) => {
      // The receiver is already gone; unwind synchronously rather than
      // through the grant's Drop.
      if let Ok(grant) = payload {
        grant.defuse();
      }
      false
    }
  }
}

/// Lowers a failed ROOT arm to the registration vocabulary: the caller asked
/// to watch a directory that was validated at spawn, so an arm failure is a
/// race (the object vanished) or an environment limit.
///
/// The io error carries BOTH halves of what the caller needs: the situation in
/// its message, and the cause in its [`kind`](std::io::Error::kind) — from
/// [`arm_error_kind`], the same mapping [`arm_failure`] answers the
/// `replace_root`/widen pre-arm refusals with, so a watch-limit `ENOSPC` is
/// dispatchable as [`std::io::ErrorKind::StorageFull`] here too instead of
/// collapsing into an untyped `Other`.
fn arm_grant_error(err: WatchError, requested: PathBuf, root: PathBuf) -> WatchRootError {
  match err {
    WatchError::NotFound | WatchError::Gone => WatchRootError::NotFound { path: requested },
    err => WatchRootError::Source(SourceError::RootUnavailable {
      root,
      source: std::io::Error::new(
        arm_error_kind(err),
        format!("the root watch could not be armed ({})", err.as_str()),
      ),
    }),
  }
}

/// The successful payload of a watch reply: ownership of the just-spawned
/// stream, armed to unwind.
///
/// A oneshot send succeeding only proves the receiver was alive — not that
/// the `watch()` future will ever poll the value out. Until
/// [`defuse`](Self::defuse) — called only after the watcher has inserted the
/// registry entry — dropping the grant (a cancelled future, a dropped
/// receiver) asks the driver to unwatch the scope, so no live stream is ever
/// left without an owner. This is the commit half of a two-phase handoff;
/// the unwind funnels into the driver's normal unwatch path (teardown,
/// `on_scope_dead`, registry reconciliation).
pub(crate) struct WatchGrant {
  scope: ScopeId,
  root: PathBuf,
  unwind: async_channel::Sender<ScopeId>,
  armed: bool,
}

impl WatchGrant {
  /// Mints an armed grant. The driver is the only production caller; tests
  /// mint grants to pin the unwind contract.
  pub(crate) const fn new(
    scope: ScopeId,
    root: PathBuf,
    unwind: async_channel::Sender<ScopeId>,
  ) -> Self {
    Self {
      scope,
      root,
      unwind,
      armed: true,
    }
  }

  /// The granted scope.
  pub(crate) const fn scope(&self) -> ScopeId {
    self.scope
  }

  /// Commits the grant: the caller now owns the stream through its registry,
  /// and dropping the grant no longer unwinds it.
  pub(crate) fn defuse(mut self) {
    self.armed = false;
  }
}

impl Drop for WatchGrant {
  fn drop(&mut self) {
    if self.armed {
      // Unbounded and driver-held: this send only fails when the driver is
      // gone, whose own exit path already reclaimed every stream.
      let _ = self.unwind.try_send(self.scope);
    }
  }
}

impl core::fmt::Debug for WatchGrant {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("WatchGrant")
      .field("scope", &self.scope)
      .field("root", &self.root)
      .field("armed", &self.armed)
      .finish_non_exhaustive()
  }
}

/// How an awaited [`Watcher::unwatch`](crate::Watcher::unwatch) resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnwatchAck {
  /// The scope was live and has now reached quiescence across every native
  /// obligation — every one of them PROVEN, so the caller may treat the stream,
  /// its reader and its callbacks as gone.
  Torn,
  /// The handle did not name a live root of this watcher — never watched,
  /// already unwatched, or torn down by a root-death event.
  Unknown,
  /// One of this scope's teardowns UNWOUND: its `shutdown` panicked part-way,
  /// so nothing ever observed the native stream stop. The obligation is
  /// discharged — no reaper thread is still working on it — but quiescence was
  /// never PROVEN, and this scope can never prove it later: whatever the panic
  /// left behind (a reader thread mid-loop, a registered callback, an open
  /// descriptor) is unreachable from here.
  ///
  /// Distinguished from [`Torn`](Self::Torn) because the two answers license
  /// different caller behaviour, and only one of them is safe: `Torn` is the
  /// signal to release everything the stream could still touch. Reporting this
  /// state as `Torn` — which the driver did while the terminal existed only for
  /// close's arithmetic — hands that licence out over a stream nobody proved
  /// stopped.
  ///
  /// Latched per scope for the driver's life. An unproven teardown is never
  /// later proven, so every waiter the scope resolves from here on carries this
  /// verdict, including one parked (or arriving) after the unwind and one whose
  /// own stream is a healthy replacement: the SCOPE is what the caller releases
  /// against, and part of it was never accounted for.
  Unproven,
  /// Refused before anything was parked: this scope already holds
  /// [`MAX_PARKED_SETTLEMENTS`] awaited unwatches whose teardown has not
  /// quiesced. Retryable.
  Backlogged,
}

// Gated exactly like the `tests` module below, which is these predicates' only
// consumer: a plain `cfg(test)` leaves them defined but unreachable in every
// build that has no `tokio` (the featureless and Smol-only test builds, and
// Miri's default-feature one), where they are dead code.
#[cfg(all(test, feature = "tokio"))]
impl UnwatchAck {
  /// Whether this is [`Torn`](Self::Torn).
  pub(crate) const fn is_torn(self) -> bool {
    matches!(self, Self::Torn)
  }

  /// Whether this is [`Unknown`](Self::Unknown).
  pub(crate) const fn is_unknown(self) -> bool {
    matches!(self, Self::Unknown)
  }

  /// Whether this is [`Unproven`](Self::Unproven).
  pub(crate) const fn is_unproven(self) -> bool {
    matches!(self, Self::Unproven)
  }
}

/// One command from the watcher facade to its driver task.
pub(crate) enum Command {
  /// Watch a new root; resolves once the native stream is live.
  Watch {
    /// The root to watch.
    root: PathBuf,
    /// The delivery interest for the new scope.
    interest: Interest,
    /// Resolved once the stream is live, with the scope handle and the
    /// canonical root path event paths will arrive under.
    reply: WatchReply,
  },
  /// Stop watching a root; the awaited form resolves once its stream is torn down.
  Unwatch {
    /// The scope to stop.
    scope: ScopeId,
    /// `Some` for the awaited [`Watcher::unwatch`](crate::Watcher::unwatch) (resolved with
    /// how the scope settled); `None` for the non-blocking, reply-less
    /// [`Watcher::request_unwatch`](crate::Watcher::request_unwatch) — the SAME teardown and
    /// registry reclamation, simply unacknowledged. The driver applies both
    /// identically and skips the ack when there is no reply.
    reply: Option<futures_channel::oneshot::Sender<UnwatchAck>>,
  },
  /// Reconcile a live scope's per-directory coverage to the `retained` cover IN PLACE,
  /// BIDIRECTIONALLY — prune every descended watch strictly outside the cover AND re-arm
  /// any retained subtree an earlier, narrower cover pruned — keeping every already-covered
  /// retained subtree and its connecting ancestors armed (no re-arm, so no gap). The core
  /// answers every refusal as a typed no-op (unknown scope, not publicly live,
  /// kernel-recursive profile, refused cover), acknowledged immediately; a reconcile that
  /// RAN parks its acknowledgement under a settlement fence, resolved only once the scope's
  /// re-arm work has quiesced — the effect-completion fence, so the ack means "the retained
  /// cover is live", never "the effects were queued".
  SetCover {
    /// The scope to reconcile.
    scope: ScopeId,
    /// The canonical absolute paths whose coverage MUST be retained (the survivor
    /// antichain). Every watch neither under one of these nor an ancestor of one is
    /// pruned; every retained prefix not currently covered is re-armed.
    retained: Vec<PathBuf>,
    /// `Some` for the awaited [`Watcher::set_cover`](crate::Watcher::set_cover) — resolved
    /// with the reconcile's [`CoverOutcome`]: immediately for a no-op, at the settlement
    /// fence otherwise; `None` for the non-blocking, reply-less
    /// [`Watcher::request_set_cover`](crate::Watcher::request_set_cover) — the PROMPT path
    /// that applies a queued reconcile without waiting for a later arm. The driver applies
    /// both identically; a reply-less reconcile opens no fence, though its window still
    /// feeds the settlement bookkeeping (loss memory, floor rewind).
    reply: Option<futures_channel::oneshot::Sender<CoverOutcome>>,
  },
  /// Replace a live root's coverage with `root` (make-before-break): the
  /// new stream goes live before the old one is retired, the `RootHandle`,
  /// scope, and epoch stream survive, and the commit's epoch-bumped
  /// full-root `Rescan` instructs the consumer to re-read the widened
  /// world. The reservation travels WITH the command: the driver releases
  /// it at commit or failure, so cancelling the caller's future abandons
  /// only the notification, never the reservation or the swap.
  Replace {
    /// The live scope whose root is being replaced.
    scope: ScopeId,
    /// The canonicalized replacement root.
    root: PathBuf,
    /// The reservation covering `root` (exempting `scope`).
    reservation: crate::watcher::ReservationGuard,
    /// Resolved at commit, or with the typed failure.
    reply: futures_channel::oneshot::Sender<Result<(), crate::error::ReplaceRootError>>,
  },
  /// Place a sync cookie under `dir` for `scope`, resolving with the path it
  /// landed at. The write PARKS on the scope's coverage-settle fence: under a
  /// descending backend a pre-sync write inside a subtree whose per-directory
  /// watch is mid-re-arm was never kernel-reported, and no queue ordering
  /// covers it — settling first means every re-arm terminal is armed-live or
  /// dropped-with-a-standing-`Rescan`. A kernel-recursive scope is trivially
  /// settled, so the write dispatches at once. A `Degraded` settle still
  /// writes: the covering `Rescan` the loss already emitted rides the queue
  /// ahead of the cookie, so the barrier is met by domination.
  SyncRoot {
    /// The root the cookie must be reported on.
    scope: ScopeId,
    /// The directory to place it in (validated inside the root by the watcher).
    dir: PathBuf,
    /// The minted cookie name (the caller owns the reserved namespace).
    name: String,
    /// The watcher-minted ticket keying this admission — the `by_ticket` address a
    /// later cancel resolves through. Its foreign-brand refusal is the watcher's
    /// synchronous door, so a ticket reaching here is always this watcher's.
    ticket: SyncTicket,
    /// Resolved with the cookie's path at WRITE-complete — never at observe
    /// (the observation arrives on the caller's own event stream).
    reply: futures_channel::oneshot::Sender<Result<PathBuf, crate::error::SyncRootError>>,
  },
  /// Orderly shutdown; resolves when every stream is torn down.
  Close {
    /// Resolved with the number of teardowns still wedged past the close
    /// grace — 0 means native-stream quiescence was proven.
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only snapshot of per-scope bookkeeping the suites assert is
  /// reclaimed on teardown (the live delivery-lane count), so a leak of that
  /// state under watch/unwatch churn is provable rather than inferred.
  #[cfg(all(test, feature = "tokio"))]
  DebugLaneCount {
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only count of the awaited-unwatch waiters parked for `scope`, so a
  /// suite can prove an issue-and-cancel storm leaves the waiter vector
  /// bounded rather than growing without limit.
  #[cfg(all(test, feature = "tokio"))]
  DebugUnwatchWaiters {
    scope: ScopeId,
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only count of the coverage fences `scope` still holds pending — the
  /// core's half of every admitted awaited `set_cover`, minted and released in
  /// lockstep with the driver's parked reply sender — so a suite can prove the
  /// admitted population stays inside its bound while the scope cannot settle.
  #[cfg(all(test, feature = "tokio"))]
  DebugPendingCoverFences {
    scope: ScopeId,
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only reading of whether `scope` still carries a coverage-fence
  /// ENTRY — the loss memory a fence opened right now would inherit, which
  /// [`DebugPendingCoverFences`](Command::DebugPendingCoverFences) cannot see
  /// (an entry holding no pending fence reads zero there). A staging helper
  /// waits on this to hand its cells a scope whose registration window is not
  /// merely closed but SPENT.
  #[cfg(all(test, feature = "tokio"))]
  DebugCoverFenceEntry {
    scope: ScopeId,
    reply: futures_channel::oneshot::Sender<bool>,
  },
  /// A test-only count of the cookies the driver still OWNS, so a suite can
  /// prove that a failed write, an abandoned reply, a retired scope, and a
  /// completed-cookie reap each leave the registry exactly as they found it — a
  /// leak (or unbounded growth under repeated failure) is then provable rather
  /// than inferred from the unlinks.
  #[cfg(all(test, feature = "tokio"))]
  DebugCookieCount {
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only count of the obligations carrying a reap mark, so a suite can
  /// prove a mark never survives the obligation it names (the boundedness rule).
  #[cfg(all(test, feature = "tokio"))]
  DebugCookieReapMarks {
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only count of `scope`'s PARKED removal records (`RemoveFailed`
  /// carrying no deadline), so the recovery-fairness suites can assert which
  /// scope's backlog a cap refusal re-armed and which stayed parked.
  #[cfg(all(test, feature = "tokio"))]
  DebugCookieParkedFor {
    scope: ScopeId,
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only read of the birth/terminal census plus the live record count, so
  /// a suite can assert the census equation over a whole scenario: every
  /// obligation ever born is either still live or accounted for by exactly one
  /// typed terminal.
  #[cfg(all(test, feature = "tokio"))]
  DebugCookieCensus {
    reply: futures_channel::oneshot::Sender<(Census, usize)>,
  },
  /// A test-only count of the teardowns whose `shutdown` UNWOUND — the fact the
  /// close reply reports as non-quiescence.
  ///
  /// A suite staging on an unwind cannot watch the panicking thread: a
  /// `shutdown` that unwinds touches no completion counter (that is what makes
  /// it unproven), and the panic runtime's own reporting sits between the last
  /// observable it does touch and the terminal it sends. This reads the fact the
  /// DRIVER holds, so an edge staged on it is genuinely ordered after ingestion.
  #[cfg(all(test, feature = "tokio"))]
  DebugUnprovenTeardowns {
    reply: futures_channel::oneshot::Sender<usize>,
  },
  /// A test-only read of [`teardown_pressure`] — the gauge admission itself
  /// compares against [`MAX_TEARDOWN_BACKLOG`], reservations included.
  ///
  /// Answered on the command arm, so its reply also serves as a BARRIER: the
  /// mailbox is FIFO and the loop takes one command per iteration, so a suite
  /// that queues a burst of admissions ahead of this one knows, when the reply
  /// lands, that every one of them has been judged.
  #[cfg(all(test, feature = "tokio"))]
  DebugTeardownPressure {
    reply: futures_channel::oneshot::Sender<usize>,
  },
}

/// Lowers a refused cover reconcile to the public outcome — answered at
/// command time, the never-fenced half of the set-cover ack.
const fn noop_outcome(reason: CoverNoop) -> CoverOutcome {
  match reason {
    CoverNoop::KernelRecursive => CoverOutcome::Recursive,
    CoverNoop::UnknownScope => CoverOutcome::Skipped(SkipReason::UnknownRoot),
    CoverNoop::NotLive => CoverOutcome::Skipped(SkipReason::NotLive),
    CoverNoop::RefusedCover => CoverOutcome::Skipped(SkipReason::RefusedCover),
  }
}

/// Lowers a settled fence's verdict to the public outcome. This is the ONLY
/// constructor of an [`Applied`](CoverOutcome::Applied) /
/// [`Degraded`](CoverOutcome::Degraded) for a parked reply — reached solely
/// through [`resolve_cover_settlements`] — which is what makes a queue-time
/// acknowledgement unrepresentable: nothing else can answer a fenced reply.
const fn settle_outcome(settle: CoverSettle) -> CoverOutcome {
  match settle {
    CoverSettle::Applied => CoverOutcome::Applied,
    // A caller awaiting `set_cover` asked whether coverage is complete, and a
    // dead scope's answer to that is the one it already had before `Dead`
    // existed: the retained cover is not proven, and the terminal `Rescan`
    // dominates the gap. The distinction `Dead` carries is only actionable for
    // the parked-cookie barrier, which reads the settle directly.
    CoverSettle::Degraded | CoverSettle::Dead => CoverOutcome::Degraded,
  }
}

/// Retires every PARKED obligation `doomed` selects, BEFORE any write is
/// dispatched for it — the ONE pre-physical terminal, shared by the cancel
/// sweep, the replace-commit's uncovered-parked revoke, and the close sweep.
///
/// Each selected obligation earns `NeverCreated`: a parked record is
/// pre-physical by construction (no write was dispatched, so no file can exist),
/// which is exactly the evidence that terminal names. Its caller is answered
/// `Retired` through the fence's routing entry, and its settle fence is abandoned
/// in the core — the same prune the cancelled-ack path runs, and equally
/// untouching of the scope's loss memory and settle floor.
///
/// The ledger is walked ONCE, and `doomed` sees each parked obligation together
/// with its routing entry, so a selection can read the record's truth (scope,
/// mark) and the plumbing (the target dir) in one place. Record, reply and fence
/// move together here, so the routing local and the ledger can never disagree
/// about which syncs are parked.
fn retire_parked_cookies<F: FsOps>(
  core: &mut DriverCore,
  parked_cookies: &mut BTreeMap<FenceId, ParkedCookie>,
  cookies: &CookieRegistry<F>,
  doomed: &dyn Fn(&Obligation, &ParkedCookie) -> bool,
) {
  // Decide AND retire under the one ledger lock; the replies and the core's fence
  // bookkeeping are touched only after it is released. No FS I/O is reachable
  // from here at all — a parked obligation has no file — but the lock still holds
  // nothing but memory, as every ledger critical section must.
  let abandoned: std::collections::BTreeSet<FenceId> = {
    let mut inner = lock_ledger(&cookies.ledger);
    let selected: Vec<(FenceId, CookieId)> = inner
      .obligations
      .values()
      .filter_map(|ob| match ob.phase {
        Phase::Parked { fence } => parked_cookies
          .get(&fence)
          .filter(|parked| doomed(ob, parked))
          .map(|_| (fence, ob.id)),
        Phase::InPool | Phase::Owned | Phase::Removing { .. } | Phase::RemoveFailed { .. } => None,
      })
      .collect();
    for (_, id) in &selected {
      inner.retire(*id, Reaped::NeverCreated);
    }
    selected.into_iter().map(|(fence, _)| fence).collect()
  };
  for fence in &abandoned {
    if let Some(parked) = parked_cookies.remove(fence) {
      // The umbrella's canceller has usually dropped this receiver already (so the
      // send is a no-op there), but a direct-API caller learns its parked sync was
      // retired rather than reading a bare `Closed`.
      let _ = parked.reply.send(Err(crate::error::SyncRootError::Retired));
    }
  }
  core.abandon_cover_fences(&abandoned);
}

/// Resolves every parked set-cover acknowledgement whose fence has settled —
/// the loop-top (and close-drain) choke point. It first prunes CANCELLED
/// callers (the reply receiver is gone) on BOTH sides of the seam: the parked
/// sender here, and the fence's pending tuple in the core
/// ([`DriverCore::abandon_cover_fences`]) — the scope's loss memory and
/// settle-floor bookkeeping stay untouched, so the settle observation's cover
/// repair is unaffected. Pruning only the sender would let an issue-and-cancel
/// storm against a stalled scope grow the core's pending list without bound
/// (the bounded mailbox limits instantaneous traffic, never the total). The
/// prune is O(parked) per pass, and it means a reported settlement may
/// legitimately find no sender (a caller dropped at close).
///
/// Reports whether a settlement stood a covering `Rescan` and held its tranche
/// over for it ([`DriverCore::take_cover_flush_due`]): the caller must flush its
/// effects and resolve again rather than park, so that cover reaches the
/// consumer before the verdict it covers answers anybody.
#[allow(clippy::too_many_arguments)]
fn resolve_cover_settlements<R, F>(
  core: &mut DriverCore,
  ops: &F,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  cover_replies: &mut BTreeMap<FenceId, futures_channel::oneshot::Sender<CoverOutcome>>,
  parked_cookies: &mut BTreeMap<FenceId, ParkedCookie>,
  cookies: &mut CookieRegistry<F>,
  live: &dyn Fn(ScopeId) -> bool,
  pass: SettlePass<'_>,
) -> bool
where
  R: RuntimeLite,
  F: FsOps,
{
  let mut abandoned = std::collections::BTreeSet::new();
  cover_replies.retain(|fence, reply| {
    let alive = !reply.is_canceled();
    if !alive {
      abandoned.insert(*fence);
    }
    alive
  });
  core.abandon_cover_fences(&abandoned);
  // A cancelled sync (the caller dropped its future) abandons its fence the same
  // way — and, since the cookie is simply never written, its obligation reaches
  // the pre-physical terminal with it rather than lingering in the ledger for a
  // write that will never be dispatched.
  retire_parked_cookies(core, parked_cookies, cookies, &|_, parked| {
    parked.reply.is_canceled()
  });
  for (fence, settle) in core.poll_cover_settlements(pass) {
    // A missing sender is a caller dropped at close; settlement already
    // updated the core's bookkeeping either way.
    if let Some(reply) = cover_replies.remove(&fence) {
      let _ = reply.send(settle_outcome(settle));
      continue;
    }
    // The settle-fenced cookie write. Both LIVE verdicts write: a `Degraded`
    // settle means a WINDOW loss already stood a covering `Rescan` that
    // rides the queue ahead of this cookie, and any LEVEL-PERSISTENT
    // deficit (an arm-refused slot, an exhausted-read interior — darkness
    // that outlives its edge `Rescan`) is re-signaled below before the
    // write dispatches — so a covering `Rescan` rides the queue ahead of
    // this cookie in EVERY case, and the barrier is met by domination
    // rather than by delivery. Only a scope that DIED loses its write, and
    // it says so in the verdict itself (`Dead`): there is no stream left to
    // report the cookie on.
    //
    // Which is why both live verdicts are minted only behind the scope's
    // ordering proof: the cut puts whatever the kernel held — a root's own
    // death among it — on the lane ahead of the verdict, so a scope that reads
    // live to the dispatch below was live at the cut rather than merely unread.
    if let Some(cookie) = parked_cookies.remove(&fence) {
      // The obligation this fence carries: born at its sync's admission, so it is
      // always here — the routing entry above and the record move in lockstep,
      // which is why nothing below has to tolerate a missing record. Should that
      // lockstep ever be broken by a later change, the caller is still ANSWERED
      // rather than left to read a bare `Closed` off a dropped reply: no routing
      // entry may be discarded without resolving the barrier it carries.
      let Some((id, scope, name)) = cookies.parked_on(fence) else {
        let _ = cookie.reply.send(Err(crate::error::SyncRootError::Retired));
        continue;
      };
      // The scope died under this fence. Take the verdict's word for it rather
      // than the liveness maps below: the teardown that produced `Dead` only
      // QUEUED its `TeardownStream`, and `resolve_cover_settlements` runs with no
      // `execute_effects` between, so `handles`, `root_of` and `retiring` all
      // still read live for a scope that is already gone. Consulting them here
      // dispatched a write and answered the caller `Ok` for a cookie no live
      // stream could ever report — a successful but unsatisfiable barrier.
      //
      // Nothing physical was created for a parked cookie, so the obligation earns
      // the same pre-physical terminal the scope-died branch below gives it, in
      // the same step that answers the barrier. The fence needs no abandoning: it
      // already settled to reach this line.
      if matches!(settle, CoverSettle::Dead) {
        lock_ledger(&cookies.ledger).retire(id, Reaped::NeverCreated);
        let _ = cookie.reply.send(Err(crate::error::SyncRootError::Retired));
        continue;
      }
      // The root the cookie must stay inside — and, being recorded on the same
      // transitions the stream is, a second proof the scope is live.
      let Some(root) = cookies
        .root_of(scope)
        .filter(|_| live(scope))
        .map(Path::to_path_buf)
      else {
        // Defence in depth for a death that reaches here WITHOUT folding into the
        // settle: the `Dead` verdict above intercepts every teardown ordering
        // currently constructible, because the verdict travels with the fence and
        // so does not depend on when `TeardownStream` runs. Kept for any future
        // death path that clears these maps without minting a verdict.
        //
        // Nothing physical was ever created for the sync — no write was dispatched
        // — so the obligation earns the pre-physical terminal here, in the same
        // step that answers its barrier. The fence needs no abandoning: it already
        // settled to reach this line.
        lock_ledger(&cookies.ledger).retire(id, Reaped::NeverCreated);
        let _ = cookie.reply.send(Err(crate::error::SyncRootError::Retired));
        continue;
      };
      // F2: a standing terminal deficit means this scope has dark coverage
      // no past `Rescan` covers going forward. Re-signal it NOW — the fresh
      // epoch-bumped `Rescan`s enter the effect queue ahead of anything the
      // cookie write can cause (its own record arrives only via a later
      // batch input), and the loop-top `execute_effects` flushes them to the
      // consumer before that record can be routed.
      let _ = core.resignal_coverage_deficits(scope);
      // The dispatched write is a TRACKED, single-flighted job: from here its
      // obligation is an `InPool` record rather than a `Parked` one — still the
      // scope's single-flight gate (a second sync is refused while it stands),
      // still one unit of the global cap, and now an outstanding obligation that
      // holds close in `NotQuiesced` rather than letting it wedge on a hung mount.
      // The guard is taken HERE FIRST, at dispatch, so the flags it carries cover
      // the whole in-flight window: a teardown, a cancel, or a driver exit between
      // this line and the write's landing is visible to the write itself.
      //
      // A cancel that named this sync while it was parked refuses the dispatch
      // instead: the obligation is retired pre-physically and no write is ever
      // made, which is the same refusal the claim would make on the same mark, one
      // phase earlier and without creating the file first.
      let Some(guard) = cookies.dispatch_guard(scope, id) else {
        let _ = cookie.reply.send(Err(crate::error::SyncRootError::Retired));
        continue;
      };
      let ops = ops.clone();
      let tx = op_tx.clone();
      R::spawn_blocking_detach(move || {
        let ParkedCookie { dir, reply } = cookie;
        match ops.write_cookie(&root, &dir, &name) {
          Ok(file) => {
            // Hand the cookie to the registry — the path the write ACTUALLY
            // landed at (which only the write knows: a covered FILE
            // subscription's cookie lands in the parent) together with the
            // identity of the object the create returned, so every later removal
            // can prove the name is still that object before unlinking it.
            match guard.claim(&file) {
              None => {
                // A refused claim means a cancel named this obligation, the
                // registry is gone, the scope is retiring, or the generation
                // moved: its cookie must not survive, so the write self-reaps
                // (never discarding ownership before the unlink confirms).
                self_reap(&ops, &guard, file, None);
                let _ = reply.send(Err(crate::error::SyncRootError::Retired));
              }
              Some(id) => {
                // The caller names cookies by path, so only the path crosses the
                // reply; the identity stays with the record, which is the only
                // thing that ever unlinks.
                if reply.send(Ok(file.path().to_path_buf())).is_err() {
                  // A caller that abandoned the sync (timed out, dropped the
                  // future) has dropped this reply receiver and will never ask
                  // for this cookie's removal. The write completing late must
                  // not outlive the barrier that asked for it: reap the file,
                  // but keep ownership (of incarnation `id`) until the unlink
                  // confirms.
                  self_reap(&ops, &guard, file, Some(id));
                }
              }
            }
          }
          Err(CookieWriteError {
            source,
            residue: None,
          }) => {
            // Nothing was created, so this incarnation reaches its terminal
            // having produced no file: retire it as never-created, IN THE JOB
            // that learned the fact. This is what keeps repeated failed syncs on
            // a long-lived scope from growing the ledger — and, because the
            // record leaves only once nothing physical can exist, it can never
            // uncount a live obligation.
            lock_ledger(&guard.ledger).retire(guard.id, Reaped::NeverCreated);
            let _ = reply.send(Err(crate::error::SyncRootError::Write {
              path: dir.join(&name),
              source,
            }));
          }
          Err(CookieWriteError {
            source,
            residue: Some(residue),
          }) => {
            // The write FAILED but left a file behind (it could not identify what
            // it made, and could not destroy it either). Retiring `NeverCreated`
            // here would be a lie with teeth: the file would stop counting against
            // the obligation cap that bounds exactly this, and nothing would ever
            // reap it. So the residue is admitted like any other owned cookie and
            // then immediately self-reaped — the caller is being told the write
            // failed and will never ask for this path, so nobody else ever will.
            // A retry that fails again leaves the record `RemoveFailed`: counted,
            // owned, and swept at the scope's teardown.
            let residue = *residue;
            let claimed = guard.claim(&residue);
            self_reap(&ops, &guard, residue, claimed);
            let _ = reply.send(Err(crate::error::SyncRootError::Write {
              path: dir.join(&name),
              source,
            }));
          }
        }
        // Done, whatever the verdict. Every physical fact this write learned is
        // already written to its record, under the ledger lock, by the code that
        // learned it; this message only tells the driver — the sole owner of the
        // clock — to schedule a retry if the record parked failed.
        let _ = tx.try_send(OpResult::CookieWriteDone { id: guard.id });
      });
    }
  }
  core.take_cover_flush_due()
}

/// The write job's self-reap: unlink a cookie its own write must not leave
/// behind, NEVER discarding ownership before the unlink CONFIRMS, and NEVER
/// acting on a record that is not the one this write was born for. Every verdict
/// is written to that record here, in the job, under the ledger lock; the
/// `CookieWriteDone` that follows carries only the id, and the driver — the sole
/// owner of the clock — schedules the retry of a record left `RemoveFailed`.
///
/// `claimed = None` — the claim was REFUSED. The record is still `InPool`: it is
/// RE-ASSERTED here (its landing published, so every sweep can find the file and
/// prove which object it is, and its phase moved to `Removing`) BEFORE the
/// unlink, and that ordering is what keeps the accounting honest — the
/// obligation is never momentarily invisible while its file is on disk, and a
/// `Drop` landing mid-unlink skips it as it skips any `Removing` record. The
/// re-assert deliberately ignores the shutdown/retiring flags that caused the
/// refusal: it is what keeps a failing unlink from orphaning the file.
///
/// `claimed = Some(id)` — the reply send FAILED, so OUR claim left record `id`
/// `Owned`, and a racing token-cancel may already have moved it to `Removing`
/// and dispatched its own unlink (the caller-gone event that fails `reply.send`
/// is the same event that makes the umbrella send `Cancel`); we first CLAIM the
/// removal under the lock, addressing our own id, so the two claimants cannot
/// overlap and we can never act on a SUCCESSOR that reclaimed the path.
///
/// An ABSENT record (only the abnormal-path `Drop`'s take) leaves the refusal
/// case a bare best-effort unlink of the file this write itself created, and the
/// reply-fail case yielding: the record's fate is no longer ours to write.
fn self_reap<F: FsOps>(ops: &F, guard: &CookieGuard, file: CookieFile, claimed: Option<CookieId>) {
  // The incarnation whose fate this reap writes. Both cases name this write's own
  // record — a claim returns the guard's id — but the reply-fail case addresses
  // the id the claim ACTUALLY returned, so a stale claimant can never transition
  // a record that is not the one it claimed.
  let id = claimed.unwrap_or(guard.id);
  // Decide under the lock; every unlink runs after it is released. No FS I/O may
  // happen under the ledger mutex: on a hung mount it would serialize every other
  // pool job behind this one.
  let tracked = {
    let mut inner = lock_ledger(&guard.ledger);
    match inner.obligations.get_mut(&id) {
      // Refusal case: the record never left `InPool` — only this write can learn
      // where its cookie landed, so no other actor could have moved it. Re-assert
      // it, publishing the landing so every sweep and the backstop can find the
      // file and prove it is ours. `by_path` follows the same newest-claim-wins
      // rule a claim does.
      Some(ob) if matches!(ob.phase, Phase::InPool) => {
        ob.file = Some(file.clone());
        ob.phase = Phase::Removing { attempts: 0 };
        inner.by_path.insert(file.path().to_path_buf(), id);
        true
      }
      // Reply-fail case: take the removal, or yield to whoever beat us.
      Some(ob) if matches!(ob.phase, Phase::Owned) => {
        ob.phase = Phase::Removing { attempts: 0 };
        true
      }
      // Removing/RemoveFailed: a cancel-dispatched unlink already owns this
      // record's fate — unlinking from here would race a file that is no longer
      // ours to remove.
      Some(_) => return,
      // The abnormal-path take already retired the record (it raises its flag
      // first, which is why we were refused).
      None => {
        // A reply-failed claim yields: a racing confirm may already have removed
        // our file, and a successor could own the path now.
        if claimed.is_some() {
          return;
        }
        false
      }
    }
  };
  if !tracked {
    // A refused claim still unlinks the file it created — best-effort, and no
    // record's fate rides on it (the take already retired the record).
    let _ = ops.remove_cookie(&file);
    return;
  }
  if ops.remove_cookie(&file).is_ok() {
    lock_ledger(&guard.ledger).retire(id, Reaped::ConfirmedGone);
  } else {
    // Retain as failed: the file is still on disk and this record still owns it.
    lock_ledger(&guard.ledger).record_remove_failed(id);
  }
}

/// Revokes every barrier still PARKED for `scope` whose directory the just-
/// committed replacement root no longer covers. A replace overwrites the root
/// under a surviving scope; a parked write whose directory now sits outside that
/// coverage would place a cookie the current stream could never observe, so its
/// obligation is retired `NeverCreated` (no write was dispatched, so nothing
/// physical was ever created) and its caller answered `Retired`, rather than left
/// to strand. A parked write STILL inside the (widened) root is kept: it
/// dispatches normally under the bumped generation. The DISPATCHED counterpart —
/// a write already in the pool — is revoked instead by the generation the same
/// commit bumped, checked when it claims.
fn revoke_uncovered_parked_cookies<F: FsOps>(
  core: &mut DriverCore,
  parked_cookies: &mut BTreeMap<FenceId, ParkedCookie>,
  cookies: &CookieRegistry<F>,
  scope: ScopeId,
  new_root: &Path,
) {
  retire_parked_cookies(core, parked_cookies, cookies, &|ob, parked| {
    ob.scope == scope && !cookie_dir_within_root(new_root, &parked.dir)
  });
}

/// Drops CANCELLED awaited-unwatch waiters (the caller dropped its future, so
/// the reply receiver is gone) from every scope's parked vector, removing
/// now-empty scope entries — the loop-top (and close-drain) choke point,
/// analogous to [`resolve_cover_settlements`]'s cancel prune. A `RootHandle`
/// is `Copy`, so a caller can issue-and-cancel `unwatch` repeatedly against a
/// scope whose teardown or replacement is stalled; without this prune each
/// canceled sender would accrue until quiescence (the bounded command mailbox
/// caps instantaneous traffic, never the total). A surviving (still-awaited)
/// waiter keeps its verdict and resolves at quiescence. O(parked) per pass.
fn prune_canceled_unwatch_waiters(
  unwatch_replies: &mut BTreeMap<
    ScopeId,
    Vec<(futures_channel::oneshot::Sender<UnwatchAck>, UnwatchAck)>,
  >,
) {
  unwatch_replies.retain(|_, waiters| {
    waiters.retain(|(reply, _)| !reply.is_canceled());
    !waiters.is_empty()
  });
}

/// A spawned native source, as the blocking pool hands it back.
pub(crate) struct SpawnedSource<H> {
  /// The live stream handle.
  pub(crate) handle: H,
  /// The stream's single ordered message queue.
  pub(crate) receiver: EventReceiver,
  /// What the spawn learned about the root.
  pub(crate) meta: RootMeta,
}

/// The watcher-side registry of live scopes, written EXCLUSIVELY by the
/// driver task: it records a scope live (before the watch reply is sent) and
/// dead (at every teardown), in program order on one task — so an
/// insert-after-remove interleaving between the two transitions cannot exist.
/// The watcher only reads.
pub(crate) trait ScopeRegistry: Send + Sync + 'static {
  /// `scope`'s stream is live; its event paths arrive under `root`, whose
  /// object identity and ancestor identities the registry retains for the
  /// disjointness checks of later watches. `backend` is the primitive the
  /// spawn barrier selected — the capability report a later `backend_of` query
  /// reads back.
  fn scope_live(
    &self,
    scope: ScopeId,
    root: &Path,
    identity: RootIdentity,
    ancestors: &[RootIdentity],
    backend: BackendKind,
    stats: Option<crate::os::BackendStatsHandle>,
  );

  /// `scope` ended (unwatch, root death, stream fatal, close); its entry is
  /// reclaimed.
  fn scope_dead(&self, scope: ScopeId);

  /// The live or reserved root that overlaps `final_root`, ignoring the one
  /// reservation at `reserved` (the checking watch's own). The backend
  /// re-canonicalizes during spawn, so disjointness must hold for the FINAL
  /// root — the reservation only ever vouched for the form the watcher knew —
  /// and the driver, as the registry's single writer, checks it immediately
  /// before the scope goes live.
  ///
  /// Overlap is decided by byte containment AND by object identity — equality
  /// with a live root, the new root's ancestor chain containing a live root
  /// (new-inside-existing), or a live root's ancestor chain containing the new
  /// identity (existing-inside-new) — so spelling aliases on case- or
  /// normalization-insensitive volumes cannot admit two watches over one
  /// subtree.
  fn final_root_conflict(
    &self,
    final_root: &Path,
    identity: RootIdentity,
    ancestors: &[RootIdentity],
    reserved: Option<&Path>,
    exempt: Option<ScopeId>,
  ) -> Option<PathBuf>;
}

/// One arm or disarm collected from a single effect-drain cycle. The driver
/// groups these per scope and dispatches each scope's run as ONE batch — one
/// control message, one potential reader wake for N arms — while keeping each
/// arm's individual reply (an [`Arm`](Self::Arm) still yields one
/// [`WatchInstalled`](OpResult::WatchInstalled)). Emission order is preserved
/// inside the batch so a disarm and a later re-arm of the same slot apply in
/// the order the core produced them.
pub(crate) enum ControlRequest {
  /// Install a per-directory watch for `watch` (arming `parent`'s child
  /// `name`, addressed by absolute `path`). `expected` is the `(dev, ino)` the
  /// opened object must still have before the watch installs (the enumerate→arm
  /// rename guard); `None` leaves the arm unverified.
  Arm {
    watch: WatchId,
    /// The arm ATTEMPT this request executes, echoed back in its
    /// [`ArmResolution`]. The core's fence is per attempt, not per handle: a
    /// root keeps its `WatchId` across a rebind, so only the attempt tells this
    /// arm's verdict from that of one a later arm superseded.
    ///
    /// `None` for a PRE-arm ([`FsOps::preflight_arm`]), which precedes the
    /// accounting entirely: its outcome is returned synchronously and replayed
    /// under the attempt the commit mints, so it never travels the fenced reply
    /// path at all.
    attempt: Option<ArmAttempt>,
    parent: WatchId,
    name: Segment,
    path: Arc<PathBuf>,
    expected: Option<ExpectedObject>,
  },
  /// Remove `watch`'s per-directory watch (fire-and-forget; no reply).
  Disarm { watch: WatchId },
}

/// One arm's resolution out of a control batch.
pub(crate) struct ArmResolution {
  pub(crate) watch: WatchId,
  pub(crate) attempt: Option<ArmAttempt>,
  pub(crate) outcome: WatchOutcome,
}

/// What one control batch came back with: its arms' resolutions, and — told
/// apart from them — whether the executor ANSWERED it.
///
/// The resolutions alone cannot carry the second fact. A batch with no arms
/// resolves nothing, so one the executor served and one whose reader died both
/// come back empty — and the empty batch is exactly the ordering-proof round
/// trip, whose entire meaning is that the reader reached it and cut its kernel
/// queue onto the lane first. An empty vector must not mean both "the cut
/// happened" and "nobody was left to cut", so
/// [`answered`](Self::answered) travels beside the payload and picks the
/// returning batch's [`ControlBatchEnd`] at [`submit_control_batch`].
pub(crate) struct ControlBatchOutcome {
  /// One entry per `Arm` in the batch, in emission order. Filled on EVERY path,
  /// answered or not: a refused arm still returns the outcome its Monitor node
  /// is parked on, so no registration is stranded by a batch nobody served.
  pub(crate) resolutions: Vec<ArmResolution>,
  /// Whether the executor answered this batch. False means the reader was gone
  /// or died before replying, so the batch's ops are not known to have run and
  /// nothing about the stream's ordering may be inferred from its return. A
  /// deliberate refusal IS an answer — a batch the source declines at its
  /// generation front-check ran nothing, and says so in every resolution.
  pub(crate) answered: bool,
}

/// The sink one dispatched control batch reports its [`ControlBatchOutcome`]
/// through, exactly once, from whoever ends up producing it: each arm's
/// `WatchInstalled` and then the batch's `ControlBatchDone`, straight onto the
/// driver's result channel.
///
/// It REPORTS rather than rendezvous-ing back to the thread that dispatched the
/// batch, and that is the whole point. An executor whose reader answers batches
/// can leave one outstanding for as long as the filesystem under it stays wedged,
/// and a driver can hold arbitrarily many at once — one per transport a replace
/// retired out from under a stuck reader. Anything that WAITS for such an outcome
/// is a resource spent per stuck batch: a parked pool worker starves the live
/// generation's arms and its ordering proof of any fixed-width pool, and a parked
/// task competes for scheduling with the driver's own loop, whose completions
/// must outrank command pressure. Reporting spends neither: the sink travels WITH
/// the batch, and the thread that finally produces the outcome hands it to the
/// driver in one non-blocking send.
///
/// DESTROYING the sink without a report is itself a report. The completion is
/// emitted by the drop, so an executor that stops part-way through a batch still
/// advances the scope's queue rather than wedging it — and what it advances the
/// queue with is [`ControlBatchEnd::Unwound`], because how far such a batch got,
/// and what its callers are still owed, is exactly what is unknown.
///
/// The two messages ride the same FIFO channel in that order, so the driver has
/// ingested every arm result before the completion releases the scope's successor.
pub(crate) struct ControlAnswer<H> {
  op_tx: async_channel::Sender<OpResult<H>>,
  scope: ScopeId,
  /// The transport generation this batch was emitted for, echoed back so the
  /// driver can tell this completion from one whose generation it has since
  /// retired.
  generation: u64,
  /// The ordering-proof request this batch carries, echoed back so the driver can
  /// tell this completion from a predecessor's.
  cut_token: Option<u64>,
  /// Overwritten only once an outcome has arrived and said which end it was. The
  /// drop fires on an unwind too, so what this carries until then must be the end
  /// that assumes least — and that is exactly [`ControlBatchEnd`]'s default.
  end: ControlBatchEnd,
}

impl<H> ControlAnswer<H> {
  /// Reports `outcome`: every arm's resolution, then — as this sink drops — the
  /// batch's end.
  pub(crate) fn resolve(mut self, outcome: ControlBatchOutcome) {
    for resolution in outcome.resolutions {
      // Only a DISPATCHED batch reports here, and every arm the core dispatches
      // carries its attempt; a pre-arm's attempt-less request is answered
      // synchronously and never reaches a sink.
      let Some(attempt) = resolution.attempt else {
        debug_assert!(false, "a dispatched arm carries the attempt it executes");
        continue;
      };
      let _ = self.op_tx.try_send(OpResult::WatchInstalled {
        watch: resolution.watch,
        attempt,
        outcome: resolution.outcome,
        scope: self.scope,
        generation: self.generation,
      });
    }
    // An outcome ARRIVING is not enough on its own to say the batch ran: a reader
    // that dies between dequeuing a batch and replying to it produces an outcome
    // with nothing to show for it, and for the ordering-proof round trip — which
    // carries no arms, so it resolves nothing either way — that outcome is
    // indistinguishable from a served batch's. `answered` is what separates them,
    // so it decides between the two ends an ARRIVAL can report: a batch nobody
    // answered never licenses a cut that did not happen.
    //
    // Neither collapses into the destroyed-sink case. A batch that reports at all
    // has fed every arm it carried back, refused or not, where a destroyed sink
    // reaches that loop never — and the driver owes the two different terminals.
    self.end = if outcome.answered {
      ControlBatchEnd::Answered
    } else {
      ControlBatchEnd::Unanswered
    };
  }
}

impl<H> Drop for ControlAnswer<H> {
  fn drop(&mut self) {
    let _ = self.op_tx.try_send(OpResult::ControlBatchDone {
      scope: self.scope,
      generation: self.generation,
      cut_token: self.cut_token,
      end: self.end,
    });
  }
}

/// The blocking-pool side of the platform: spawn, teardown, and stat. A
/// test implementation runs the whole driver loop against a fake filesystem.
pub(crate) trait FsOps: Clone + Send + Sync + 'static {
  /// The live-stream handle type.
  type Handle: SourceControl;

  /// The transient directory handle one enumerate reads THROUGH: the arm's
  /// `O_PATH` anchor on the descending Linux backend, and nothing at all on a
  /// platform that lists by path. It travels to the blocking pool, so it must
  /// be owned outright.
  type Anchor: Send + 'static;

  /// Starts the native source (blocking).
  ///
  /// A failure answers [`SpawnFailed`], which carries the LIVE stream whenever
  /// the barrier got far enough to start one. A backend must never tear that
  /// stream down itself: its `shutdown` may answer
  /// [`Quiesce::Unproven`](crate::os::Quiesce::Unproven) and retain native
  /// state, and only the driver's counted submission can turn that answer into
  /// a terminal anything accounts for.
  fn spawn_source(
    &self,
    config: SourceConfig,
  ) -> Result<SpawnedSource<Self::Handle>, SpawnFailed<Self::Handle>>;

  /// `lstat`s one path (blocking).
  fn probe(&self, path: &Path) -> ProbeOutcome;

  /// Creates the sync cookie `name` for `dir`, inside `root` (blocking),
  /// returning WHERE it landed and what authorizes its later removal. The
  /// cookie's whole purpose is the kernel event its creation mints: it rides the
  /// root's ordered queue behind every change the backend reported before it, so
  /// observing it proves those changes have already exited the pipeline. A
  /// read-only tree fails here with `PermissionDenied` — the honest refusal.
  ///
  /// `dir` is the SUBSCRIPTION's key, which a covered FILE subscription makes a
  /// file: the cookie then lands beside it instead, and never above `root` (see
  /// [`cookie_dir`]). A real implementation then nests one more level, into the
  /// private [`CookieDir`] it owns. So the RETURNED [`CookieFile`] is the only
  /// authority on where the cookie went — `dir.join(name)` is not, and nothing
  /// may record ownership of a cookie by predicting its path.
  ///
  /// The identity it carries MUST be read from the descriptor this create
  /// returned, never from a second lookup of the path: a second lookup would
  /// describe whatever holds the name at that later instant, which is precisely
  /// the object the identity exists to distinguish the cookie FROM. A real
  /// implementation also RETAINS that descriptor in the returned
  /// [`CookieFile`], because an identity whose slot the allocator may reissue is
  /// no proof at all — see there.
  ///
  /// FAIL-CLOSED on an object it cannot identify: an implementation that creates
  /// a file but cannot read an identity off it must destroy that file and report
  /// the error, never return a normally-proven [`CookieFile`]. If the destroy
  /// ALSO fails, the file it left is handed back as
  /// [`CookieWriteError::residue`] — never dropped on the floor, because a file
  /// nobody records is a file nothing ever reaps and nothing ever counts.
  fn write_cookie(
    &self,
    root: &Path,
    dir: &Path,
    name: &str,
  ) -> Result<CookieFile, CookieWriteError>;

  /// Removes a sync cookie (blocking) through the anchor it was created with,
  /// first PROVING — where a proof exists — that the name still denotes the object
  /// `cookie` records. The three successful verdicts are [`CookieRemoval`]'s:
  /// unlinked, already gone, or displaced — and all three retire the obligation,
  /// because under each one this driver's file is no longer at the name and no
  /// later retry could change that.
  ///
  /// No implementation may remove a cookie by resolving a pathname. The anchor —
  /// a directory descriptor on Unix, an already-open handle on Windows — is what
  /// confines the removal to the directory the create was made through; a name
  /// resolved a second time is a fresh lookup that could land anywhere, including
  /// outside the tree entirely.
  ///
  /// Anchored is not the same as object-exact, and only Windows is both: its
  /// disposition is set on a handle whose identity was verified first, so the
  /// object destroyed IS the object proven. Unix has no unlink conditioned on file
  /// identity, so its proof and its removal are two calls and the guarantee is
  /// narrower — the entry removed is an entry of the private, uid-owned `0o700`
  /// directory, and a process of THIS USER is trusted not to rebind names inside
  /// it. [`remove_anchored`] states that boundary in full; no caller of this trait
  /// may claim more than it does.
  ///
  /// What no implementation may do under any contract is remove a name it holds no
  /// evidence about: an [`Anchor`](CookieProof::Anchor) record is either promoted
  /// to an identity from the create's own retained handle, or destroyed through
  /// that handle, or refused.
  ///
  /// Idempotent: a cookie already gone (a crash leftover reaped by someone else,
  /// a racing sync) maps to `AlreadyGone`. Every OTHER failure is RETURNED so the
  /// caller can retain the cookie's ledger record and let a later sweep retry the
  /// removal, rather than silently orphaning the file. That includes a failure to
  /// READ the identity of whatever stands at the name: unprovable is not
  /// displaced, and reporting it as a settled verdict would retire a record whose
  /// file may still be on disk. The removal's own event is suppressed by the
  /// reserved namespace, never by any pending-cookie bookkeeping.
  fn remove_cookie(&self, cookie: &CookieFile) -> Result<CookieRemoval, std::io::Error>;

  /// Re-reads the live mount table strictly under `root` AND re-stats the root
  /// itself (blocking): the mount prefixes, whether the read was authoritative,
  /// and the root's liveness. The root re-stat rides the mount refresh so a
  /// kernel-recursive backend's root death (unmount/replace — no in-tree signal)
  /// is caught at the refresh cadence without any new timer or effect.
  fn refresh_mounts(&self, root: &Path) -> MountRefresh;

  /// Attaches the arm/disarm port of `scope`'s freshly spawned source under
  /// its transport `generation` (the delivery lane), so the descending
  /// executors can route to its reader AND recognize a control batch left
  /// over from a prior transport. A no-op for executors (fakes) that answer
  /// arms themselves.
  fn attach_scope(&self, scope: ScopeId, port: ScopePort, generation: u64) {
    let _ = (scope, port, generation);
  }

  /// Detaches `scope`'s port (and any transient state keyed under it) at
  /// stream teardown.
  fn detach_scope(&self, scope: ScopeId) {
    let _ = scope;
  }

  /// Installs a per-directory kernel watch for `watch` at `path` (blocking).
  /// Reached only under a descending profile. `expected` is the object the arm
  /// must confirm the open lands on (the enumerate→arm rename guard).
  fn add_watch(
    &self,
    scope: ScopeId,
    watch: WatchId,
    parent: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome;

  /// Removes a per-directory kernel watch (blocking, fire-and-forget).
  fn remove_watch(&self, scope: ScopeId, watch: WatchId);

  /// Executes one scope's batch of arms/disarms (blocking) and returns each
  /// arm's outcome, in order, together with whether the batch was ANSWERED at
  /// all.
  ///
  /// This is the entry for a caller whose thread is its own to spend on the
  /// executor's reply. The driver's per-scope batches take
  /// [`dispatch_control`](Self::dispatch_control) instead, and that distinction
  /// is a liveness one — see there.
  ///
  /// The default runs them one-by-one through
  /// [`add_watch`](Self::add_watch)/[`remove_watch`](Self::remove_watch) — the
  /// right shape for a fake with no transport; the real inotify source
  /// overrides it to ship the whole batch as ONE control message so N arms cost
  /// at most one reader wake. `generation` is the transport generation the
  /// batch was emitted for; the real source refuses a batch whose generation
  /// no longer matches the attached port (a leftover of a replaced
  /// transport). The default ignores it — a fake answers arms itself and has
  /// no transport to leak, so it always answers.
  fn batch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> ControlBatchOutcome {
    let _ = generation;
    let mut outcomes = Vec::new();
    for request in requests {
      match request {
        ControlRequest::Arm {
          watch,
          attempt,
          parent,
          name,
          path,
          expected,
        } => outcomes.push(ArmResolution {
          watch,
          attempt,
          outcome: self.add_watch(scope, watch, parent, &path, &name, expected),
        }),
        ControlRequest::Disarm { watch } => self.remove_watch(scope, watch),
      }
    }
    ControlBatchOutcome {
      resolutions: outcomes,
      answered: true,
    }
  }

  /// Hands one scope's control batch to the executor, arranging for `answer` to
  /// carry the batch's outcome once it is known.
  ///
  /// MUST NOT WAIT FOR AN EXECUTOR'S REPLY. The caller is a worker of the shared
  /// blocking pool, whose width [`RuntimeLite`] promises nothing about — a single
  /// worker is a legal pool — and a backend whose READER answers batches can leave
  /// one outstanding indefinitely: a reader already inside a syscall against a
  /// wedged filesystem observes neither the batch nor its own shutdown until the
  /// kernel returns. Waiting here would spend one worker per such batch, and a
  /// driver can hold arbitrarily many at once, one for every transport a replace
  /// retired out from under a stuck reader. Retiring a generation releases the
  /// scope's serialization slot, so the replacement's arms and its ordering proof
  /// are free to be submitted the instant the swap commits — but a pool those
  /// dead waits have filled leaves them nothing to run on, and the new root stays
  /// partially armed with every clean fence latched on a proof that never
  /// executes. So hand the batch over, resolve `answer` from wherever the outcome
  /// is actually produced, and return.
  ///
  /// The default RUNS the batch here and resolves the answer with it, which is
  /// exactly right for an executor that answers arms itself — a fake, or any
  /// platform with no control transport. Such a batch waits on no reader at all,
  /// so its work is bounded by the batch and the worker is released with it.
  fn dispatch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
    answer: ControlAnswer<Self::Handle>,
  ) {
    answer.resolve(self.batch_control(scope, generation, requests));
  }

  /// Arms `watch` at `path` on an EXPLICIT port — the not-yet-attached
  /// replacement transport of an in-flight descending replace (blocking).
  /// The scope's port table still routes to the OLD stream at this point, so
  /// the pre-arm cannot go through [`batch_control`](Self::batch_control);
  /// commit-or-unwind is decided by the returned outcome. The default routes
  /// through [`add_watch`](Self::add_watch) — the right shape for executors
  /// (fakes) that answer arms themselves and carry `Inert` ports.
  fn preflight_arm(
    &self,
    port: &ScopePort,
    scope: ScopeId,
    watch: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    let _ = port;
    self.add_watch(scope, watch, watch, path, name, expected)
  }

  /// Takes `watch`'s transient directory anchor, TRANSFERRING ownership to the
  /// caller. The driver calls this at the instant it dispatches the watch's
  /// enumerate and moves the result into that one blocking job, so an anchor
  /// belongs to exactly one read and is released by it — never left in a shared
  /// table where a later read could find it gone.
  ///
  /// A `WatchId` is NOT a sufficient key for the release. An id outlives the
  /// binding it names: loss recovery re-adds the very same id, so a read that
  /// recovery superseded — whose blocking job cannot be cancelled — would
  /// otherwise reach into the table on its way out and claim the anchor a LATER
  /// arm published for a LATER read. That read then lists the absolute path
  /// instead, which a rename can point at a different directory, and the
  /// identities it derives bind foreign children to the original node. The
  /// transport generation cannot separate the two: a loss re-proof re-arms on
  /// the SAME transport, so both sides carry the identical generation.
  ///
  /// `None` — the default, and every executor that lists by path — means the
  /// read falls back to the absolute path.
  fn take_enumerate_anchor(&self, watch: WatchId) -> Option<Self::Anchor> {
    let _ = watch;
    None
  }

  /// Reads one directory — entries with their stat facts (blocking). Reached
  /// only under a descending profile. `watch` names the node the listing
  /// answers for; `anchor` is the transient handle
  /// [taken](Self::take_enumerate_anchor) for THIS read, and the listing goes
  /// through it whenever there is one.
  fn enumerate(&self, watch: WatchId, anchor: Option<Self::Anchor>, path: &Path) -> RawEnumerate;

  /// Resolves the [`RootMeta`] a same-transport widen commits with — the spawn
  /// barrier's metadata half with NO stream creation: canonicalize, pin,
  /// locality gate, identity and mount frame from the pin, mount seed, and
  /// ancestor identities (blocking). Reached only for a widening replace on a
  /// live DESCENDING scope, whose stream the commit keeps; the default refuses
  /// — a platform with no descending backend never routes here.
  fn resolve_root_meta(&self, path: &Path) -> Result<RootMeta, SourceError> {
    let _ = path;
    Err(SourceError::Unsupported)
  }
}

/// The control surface of a live stream handle.
pub(crate) trait SourceControl: Send + 'static {
  /// Quiesces and destroys the stream: signals the reader and WAITS for it to
  /// finish, so a caller that returns from here may assume nothing of this
  /// stream is still running.
  ///
  /// The wait has no bound. A backend with a reader thread observes its
  /// shutdown only between operations, so one already inside a blocking syscall
  /// against a wedged filesystem returns when the kernel says so. That is why
  /// the driver runs every call to this on the [`TeardownReaper`] and never on
  /// the blocking pool the live generation's work shares.
  ///
  /// # The answer is what makes the return trustworthy
  ///
  /// Returning is NOT the same as having proven anything, and a backend that
  /// conflates them makes the driver certify over state nobody observed stop.
  /// The Windows pumps are the case: a panicked pump, or a cancellation drain
  /// that never dequeued its read's completion, deliberately RETAINS pinned
  /// buffers, `OVERLAPPED`s and handles rather than freeing memory the kernel
  /// may still write — and then its thread returns normally. Answering
  /// [`Quiesce::Unproven`](crate::os::Quiesce::Unproven) is how that retention
  /// reaches [`OpResult::TeardownFailed`] instead of being counted as a clean
  /// teardown.
  ///
  /// So the contract is: answer
  /// [`Quiesce::Proven`](crate::os::Quiesce::Proven) only when this call
  /// OBSERVED the stream's end — a reader joined, a serial queue drained to
  /// completion, a completion dequeued. Anything else, including any path that
  /// leaks in order to stay memory-safe, answers `Unproven`.
  fn shutdown(self) -> crate::os::Quiesce;

  /// The clonable arm/disarm port of this source, `Inert` when the backend
  /// carries no arm traffic (kernel-recursive sources, fakes).
  fn scope_port(&self) -> ScopePort {
    ScopePort::Inert
  }

  /// The source's live stats handle, `Some` only for a fanotify source (every
  /// other backend has no pollable internals — design §4.9). The driver threads
  /// it into the registry so [`Watcher::backend_stats`](crate::Watcher::backend_stats)
  /// can snapshot it per root.
  fn backend_stats(&self) -> Option<crate::os::BackendStatsHandle> {
    None
  }

  /// Where a successor stream could resume this one's journal from, when the
  /// backend keeps one and its ids are still valid. A root replacement takes
  /// this from the RETIRING stream and hands it to the replacement's spawn,
  /// so the swap window is replayed from the journal rather than left to the
  /// commit `Rescan` alone. `None` — the default, and every backend without a
  /// journal — simply means live-only: the `Rescan` still covers the window.
  fn resume_token(&self) -> Option<crate::os::ResumeToken> {
    None
  }
}

impl SourceControl for SourceHandle {
  fn shutdown(self) -> crate::os::Quiesce {
    SourceHandle::shutdown(self)
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn scope_port(&self) -> ScopePort {
    SourceHandle::scope_port(self)
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn backend_stats(&self) -> Option<crate::os::BackendStatsHandle> {
    SourceHandle::backend_stats(self)
  }

  // Every source but the Linux ones mints a resume point (inotify and
  // fanotify have no journal to resume from, so they keep the `None`
  // default). FSEvents is the one backend that actually replays from it.
  #[cfg(not(all(target_os = "linux", not(miri))))]
  fn resume_token(&self) -> Option<crate::os::ResumeToken> {
    SourceHandle::resume_token(self)
  }
}

/// Maps an enumerate open failure to the Monitor's `IoClass` vocabulary.
fn io_class(err: &std::io::Error) -> IoClass {
  match err.kind() {
    std::io::ErrorKind::NotFound => IoClass::NotFound,
    std::io::ErrorKind::PermissionDenied => IoClass::Permission,
    _ => IoClass::Io,
  }
}

/// The proto file kind of a stat file type (symlinks are never followed). Feeds
/// the metadata-based enumerate/liveness sample; the Linux path derives the kind
/// from its one sample's raw mode instead ([`kind_of_mode`], via [`stat_sample`]).
#[cfg(not(all(target_os = "linux", not(miri))))]
fn kind_of(kind: &std::fs::FileType) -> tributary_proto::FileKind {
  if kind.is_dir() {
    tributary_proto::FileKind::Dir
  } else if kind.is_symlink() {
    tributary_proto::FileKind::Symlink
  } else if kind.is_file() {
    tributary_proto::FileKind::File
  } else {
    tributary_proto::FileKind::Other
  }
}

// The metadata-based `(dev, ino)` extractors feed the non-Linux enumerate and
// liveness samples; the Linux path reads both from its one `statx` result, so it
// never calls these.
#[cfg(all(unix, not(all(target_os = "linux", not(miri)))))]
fn dev_of(meta: &std::fs::Metadata) -> u64 {
  use std::os::unix::fs::MetadataExt;
  meta.dev()
}

#[cfg(all(not(unix), not(all(target_os = "linux", not(miri)))))]
fn dev_of(_meta: &std::fs::Metadata) -> u64 {
  0
}

#[cfg(all(unix, not(all(target_os = "linux", not(miri)))))]
fn ino_of(meta: &std::fs::Metadata) -> u64 {
  use std::os::unix::fs::MetadataExt;
  meta.ino()
}

#[cfg(all(not(unix), not(all(target_os = "linux", not(miri)))))]
fn ino_of(_meta: &std::fs::Metadata) -> u64 {
  0
}

/// Every fact one caller reads about a filesystem object, from ONE sample of that
/// object (symlink not followed): its kind, device, inode, and mount frame. The
/// four are always one object's — the one-sample rule (see the driver module doc)
/// made concrete, so a rename/bind slipping between two syscalls can never pair
/// one object's identity with another's frame.
#[cfg(all(target_os = "linux", not(miri)))]
#[derive(Debug)]
struct StatSample {
  kind: tributary_proto::FileKind,
  dev: u64,
  ino: u64,
  /// The mount frame, `Some` only when the sample reported the mount id, `None`
  /// on a `statx` mask miss (`STATX_MNT_ID` is 5.8; below it the bit stays unset)
  /// — the core then fences on the device belt.
  frame: Option<u64>,
}

/// ONE sample of the object at `path` (symlink not followed): the sole path-syscall
/// behind every fact a caller reads about that object.
///
/// `statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS | STATX_MNT_ID)` —
/// kind, device, inode, AND mount frame all from THAT one result. The Linux backends
/// require `statx` (Linux 4.11+, gated once at spawn — see `os::linux`), so there is
/// no sub-`statx` fallback: the sample is always this single syscall. A mask miss
/// (`STATX_MNT_ID` is 5.8) declines only the frame (`None`), and the core then fences
/// that object on the device belt.
///
/// The path is resolved the same way `symlink_metadata` was, so an anchor
/// (`/proc/self/fd/N`) enumerate reads every fact THROUGH the pinned fd too.
///
/// An interrupted syscall (`EINTR`) is RETRIED in place — a signal cutting the
/// `statx` short is not a raced-away entry, and letting it surface as an error
/// would let `dir_entry_stat`/`list_dir` mint a spurious `Partial` enumerate (a
/// raced-away `None`) whose honest dirty cold-read escalates to a root-`[]`
/// `Rescan` on freshly-covered ground. Signal-storm runners (sanitizer
/// stop-the-world, slow CI) inject exactly this. Every OTHER errno propagates
/// unchanged (notably `NOENT`), keeping the callers' `Missing`/raced-away
/// meanings — a genuine vanished entry is still Partial, an interrupted read
/// never is.
#[cfg(all(target_os = "linux", not(miri)))]
fn stat_sample(path: &Path) -> Result<StatSample, rustix::io::Errno> {
  use rustix::fs::{AtFlags, StatxFlags, makedev, statx};
  let stx = loop {
    match statx(
      rustix::fs::CWD,
      path,
      AtFlags::SYMLINK_NOFOLLOW,
      StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID),
    ) {
      Ok(stx) => break stx,
      Err(rustix::io::Errno::INTR) => continue,
      Err(err) => return Err(err),
    }
  };
  Ok(StatSample {
    kind: kind_of_mode(u32::from(stx.stx_mode)),
    dev: makedev(stx.stx_dev_major, stx.stx_dev_minor),
    ino: stx.stx_ino,
    frame: (stx.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(stx.stx_mnt_id),
  })
}

/// The proto file kind of a raw `st_mode`/`stx_mode` (symlinks are never followed).
#[cfg(all(target_os = "linux", not(miri)))]
fn kind_of_mode(mode: u32) -> tributary_proto::FileKind {
  use rustix::fs::FileType;
  match FileType::from_raw_mode(mode) {
    FileType::Directory => tributary_proto::FileKind::Dir,
    FileType::Symlink => tributary_proto::FileKind::Symlink,
    FileType::RegularFile => tributary_proto::FileKind::File,
    _ => tributary_proto::FileKind::Other,
  }
}

/// The root's liveness verdict AND its current mount frame from ONE
/// [`stat_sample`] — so the refresh pairs the identity it decides
/// alive-vs-replaced on with the frame it adopts from the SAME object, never two
/// separate path lookups a replace/remount could split. The single sample yields
/// `(dev, ino)` for the liveness identity and `stx_mnt_id` for the frame in one
/// atomic read: were these two reads (an `lstat` then a `statx`), a swap between
/// them would let the OLD identity's "alive-and-matching" verdict adopt a DIFFERENT
/// object's mount frame, over-/under-fencing genuine children until the next refresh
/// healed it.
///
/// A mask miss yields the identity from the SAME result with a `None` frame, so a
/// transient miss never mispairs, it just declines the frame (the core keeps its
/// captured one). The sample maps to the [`RootLiveness`] taxonomy exactly as the
/// prior `symlink_metadata` did: `ENOENT` is `Missing` (DeleteSelf), any other error
/// is `Unreadable` (MoveSelf), success is `Present`.
#[cfg(all(target_os = "linux", not(miri)))]
fn root_liveness_and_frame(root: &Path) -> (RootLiveness, Option<u64>) {
  match stat_sample(root) {
    Ok(sample) => (
      RootLiveness::Present(RootIdentity::new(sample.dev, sample.ino.into())),
      sample.frame,
    ),
    Err(rustix::io::Errno::NOENT) => (RootLiveness::Missing, None),
    Err(_) => (RootLiveness::Unreadable, None),
  }
}

/// The non-Linux / miri sample: `symlink_metadata` for the liveness verdict, no
/// mount frame (no mount-id notion off Linux — the macOS refresh executor inherits
/// this, and its core descent fences on device alone). Kept a single stat so the
/// identity is still one object's, matching the Linux helper's atomicity.
#[cfg(all(
  not(all(target_os = "linux", not(miri))),
  not(all(target_os = "windows", not(miri)))
))]
fn root_liveness_and_frame(root: &Path) -> (RootLiveness, Option<u64>) {
  let liveness = match std::fs::symlink_metadata(root) {
    Ok(meta) => RootLiveness::Present(RootIdentity::new(dev_of(&meta), ino_of(&meta).into())),
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => RootLiveness::Missing,
    Err(_) => RootLiveness::Unreadable,
  };
  (liveness, None)
}

/// The Windows sample: the identity must be the SAME `(volume serial,
/// 128-bit file id)` the spawn barrier minted into `RootMeta` — a stat-based
/// `(0, 0)` here would make the birth refresh classify every healthy root
/// as replaced. Read through the same pinned-handle helper the barrier
/// uses; the open itself is the liveness verdict.
#[cfg(all(target_os = "windows", not(miri)))]
fn root_liveness_and_frame(root: &Path) -> (RootLiveness, Option<u64>) {
  let liveness = match crate::os::windows::ffi::open_directory(root) {
    Ok(handle) => {
      use std::os::windows::io::AsHandle;
      match crate::os::windows::ffi::identity_of(handle.as_handle()) {
        Ok(identity) => {
          RootLiveness::Present(RootIdentity::new(identity.volume_serial, identity.file_id))
        }
        Err(_) => RootLiveness::Unreadable,
      }
    }
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => RootLiveness::Missing,
    Err(_) => RootLiveness::Unreadable,
  };
  (liveness, None)
}

/// Every live arm's transient `O_PATH` anchor, keyed by its watch: the owning
/// scope (teardown reclamation) and the transport generation that published it,
/// beside the fd.
#[cfg(all(target_os = "linux", not(miri)))]
type AnchorTable = BTreeMap<WatchId, (ScopeId, u64, std::os::fd::OwnedFd)>;

/// The real platform: `Source::spawn` + `lstat`.
#[derive(Debug, Clone, Default)]
pub(crate) struct RealFs {
  /// Per-scope arm/disarm ports of live descending sources, attached at
  /// spawn success and detached at stream teardown. Kernel-recursive scopes
  /// attach `Inert` and never route arm traffic. Each port carries the
  /// TRANSPORT GENERATION it was attached under (the scope's delivery lane):
  /// a control batch is dispatched with the generation current at emission,
  /// and a batch whose generation no longer matches the attached port is
  /// stale — a leftover of the pre-replace transport — and must not arm the
  /// replacement's fd nor publish an anchor into the swapped scope.
  #[cfg(all(target_os = "linux", not(miri)))]
  ports: std::sync::Arc<std::sync::RwLock<BTreeMap<ScopeId, (u64, ScopePort)>>>,
  /// Transient `O_PATH` anchors returned by arms, held only until the watch's
  /// cold enumerate is dispatched and takes ownership of one (anchor-relative
  /// readdir), so fd usage stays O(in-flight operations) — never O(tree).
  ///
  /// The recorded generation is what makes a removal safe to apply out of order.
  /// A watch id is unique for the driver's life, but not to one WORLD: a
  /// replace's rebind keeps the root's id and re-arms it on the new transport,
  /// so a batch of the retired generation can name an id whose anchor now
  /// belongs to the replacement. Stamping the publisher lets a removal tell
  /// those apart.
  #[cfg(all(target_os = "linux", not(miri)))]
  anchors: std::sync::Arc<std::sync::Mutex<AnchorTable>>,
}

impl RealFs {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// The transport generation currently attached for `scope`, or a sentinel
  /// (`u64::MAX`) when no descending port is attached — a value no real lane
  /// generation reaches, so a control op resolving it fails the front-check
  /// and refuses rather than arming a nonexistent transport.
  #[cfg(all(target_os = "linux", not(miri)))]
  fn current_generation(&self, scope: ScopeId) -> u64 {
    self
      .ports
      .read()
      .unwrap()
      .get(&scope)
      .map(|(generation, _)| *generation)
      .unwrap_or(u64::MAX)
  }

  /// Builds one arm request, resolving the parent's still-held transient anchor
  /// so the open is object-correct even across a parent rename. A consumed (or
  /// never-held) anchor falls back to the absolute path with ENOENT honesty —
  /// the Monitor's NotFound path re-arms. The root is its own parent, and
  /// `openat(anchor, name)` cannot re-open the anchor itself, so the root
  /// always arms by absolute path.
  ///
  /// The path fallback is exactly why `expected` matters: an absolute-path open
  /// can land on a DIFFERENT object if a rename slipped in after the enumerate,
  /// so the reader confirms the opened fd's `(dev, ino)` against `expected`
  /// before installing the watch (the anchor-chain open is already object-pinned
  /// through `/proc/self/fd`, but the fallback is not — and it is the common case
  /// once the cold enumerate has consumed the parent anchor).
  #[cfg(all(target_os = "linux", not(miri)))]
  fn build_arm_request(
    &self,
    watch: WatchId,
    parent: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> crate::os::linux::AnchorRequest {
    let expected = expected.map(|e| crate::os::linux::ExpectedObject {
      dev: e.dev,
      ino: e.ino,
    });
    let parent_anchor = if parent == watch {
      None
    } else {
      self
        .anchors
        .lock()
        .unwrap()
        .get(&parent)
        .and_then(|(_, _, fd)| fd.try_clone().ok())
    };
    match parent_anchor {
      Some(fd) => crate::os::linux::AnchorRequest {
        watch,
        parent: Some(fd),
        name: std::ffi::OsString::from(name.as_str()),
        expected,
      },
      None => crate::os::linux::AnchorRequest {
        watch,
        parent: None,
        name: path.as_os_str().to_os_string(),
        expected,
      },
    }
  }

  /// Resolves `scope`'s control port and translates one batch's requests into
  /// the reader's ops plus the anchor-map plan the answer will be replayed
  /// through — everything a batch can do BEFORE it reaches the reader. `Err`
  /// carries the finished outcome of a batch that never gets that far.
  ///
  /// GENERATION FRONT-CHECK: a batch whose generation no longer matches the
  /// attached port is a leftover of a transport a replace has since retired. Its
  /// arms must NOT install on the replacement's fd (they name old-world paths),
  /// and its disarms are moot (their kernel watches died with the old fd). The
  /// one live case that also lands here is a kernel-recursive or teardown-racing
  /// scope with no descending port — both refuse identically.
  ///
  /// The refusal is itself an ANSWER, and reports as one: it is this executor's
  /// own decision, taken in full knowledge, and it leaves every arm resolved and
  /// the kernel untouched. Only a reader that never spoke is unanswered.
  #[cfg(all(target_os = "linux", not(miri)))]
  #[allow(clippy::type_complexity)]
  fn translate_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> Result<
    (
      crate::os::linux::ControlPort,
      Vec<crate::os::linux::ControlOp>,
      Vec<Publication>,
    ),
    ControlBatchOutcome,
  > {
    use crate::os::linux::ControlOp;

    let port = match self.ports.read().unwrap().get(&scope) {
      Some((attached, ScopePort::Inotify(port))) if *attached == generation => port.clone(),
      _ => {
        return Err(ControlBatchOutcome {
          resolutions: requests
            .iter()
            .filter_map(|request| match request {
              ControlRequest::Arm { watch, attempt, .. } => Some(ArmResolution {
                watch: *watch,
                attempt: *attempt,
                outcome: WatchOutcome::Failed(WatchError::Gone),
              }),
              ControlRequest::Disarm { .. } => None,
            })
            .collect(),
          answered: true,
        });
      }
    };

    // Deferring the removal leaves a disarmed watch's anchor readable as a
    // PARENT for the remainder of this translation, so a later arm under it
    // resolves through the pinned object rather than the absolute path. That
    // direction is the safe one: the anchor is object-pinned, and a doomed
    // parent answers ENOENT — the same honest refusal the path fallback gives,
    // which the Monitor's NotFound re-arm heals.
    let mut ops = Vec::with_capacity(requests.len());
    let mut plan = Vec::with_capacity(requests.len());
    for request in requests {
      match request {
        ControlRequest::Arm {
          watch,
          attempt,
          parent,
          name,
          path,
          expected,
        } => {
          ops.push(ControlOp::Arm(
            self.build_arm_request(watch, parent, &path, &name, expected),
          ));
          plan.push(Publication::Arm(watch, attempt));
        }
        ControlRequest::Disarm { watch } => {
          ops.push(ControlOp::Disarm(watch));
          plan.push(Publication::Disarm(watch));
        }
      }
    }
    Ok((port, ops, plan))
  }

  /// Replays `plan` against the batch's answer IN THE BATCH'S OWN ORDER under the
  /// anchors lock: each arm publishes its transient anchor (held until its cold
  /// enumerate consumes it), each disarm applies its removal where the core placed
  /// it. Returns the arms' resolutions in that same order, carrying the answer's
  /// own `answered` through untouched — that is the reader's report, and the
  /// anchor bookkeeping here neither establishes it nor can stand in for it.
  ///
  /// Runs wherever the outcome was produced: on the caller's thread for a
  /// blocking batch, on the reader's for a dispatched one, and on whichever
  /// thread destroys a batch no reader served. It takes two short locks and
  /// touches no filesystem, so no caller of it can be delayed by anything but
  /// another replay. Three properties it preserves, and why each still holds:
  ///
  /// REPLY ALIGNMENT. The replies are index-aligned to the `Arm` entries in
  /// order, and to nothing else: the reader pushes exactly one reply per `Arm` —
  /// including a failed one for every arm a mid-batch teardown left un-executed —
  /// and none for a `Disarm`, and a dead reader answers one per arm as well. The
  /// plan lists the arms in that identical order, so consuming ONE reply at each
  /// `Arm` position and none at a `Disarm` position IS that index alignment —
  /// walked rather than zipped.
  ///
  /// THE GENERATION RE-CHECK. The insert is gated on the port carrying
  /// `generation`, re-read WHILE the anchors lock is held. A replace committing
  /// while the batch was with the reader swaps the port under a NEW generation and
  /// `detach_scope` purges this scope's anchors under this SAME lock, so holding it
  /// across the check and every insert is precisely what stops a late insert from
  /// resurrecting an anchor that purge just removed (lock order is
  /// anchors-then-ports, as everywhere). One read covers the whole replay because
  /// nothing releases the lock inside it. The REMOVALS are gated on the PUBLISHER
  /// instead: a batch reclaims what its own generation (or an older one) put there,
  /// and refuses an anchor a newer generation published. Nothing leaks either way —
  /// the anchor a removal declines is owned by the live world, which consumes it at
  /// its cold enumerate or purges it at `detach_scope` — while an ungated removal
  /// would let a batch stalled across a replace close the replacement's anchor for
  /// the one id a rebind carries between worlds, the root's.
  ///
  /// `ArmResolution` ORDER. Outcomes are pushed at arm positions only, and the plan
  /// preserves the arms' relative order. Its consumers are position-sensitive —
  /// `add_watch` takes the FIRST resolution of its single-arm batch, and
  /// `submit_control_batch` feeds each `WatchInstalled` back in this order.
  #[cfg(all(target_os = "linux", not(miri)))]
  fn publish_arm_anchors(
    &self,
    scope: ScopeId,
    generation: u64,
    plan: Vec<Publication>,
    outcome: crate::os::linux::BatchOutcome,
  ) -> ControlBatchOutcome {
    let crate::os::linux::BatchOutcome { replies, answered } = outcome;
    let mut outcomes = Vec::with_capacity(replies.len());
    let mut anchors = self.anchors.lock().unwrap();
    let still_current = self
      .ports
      .read()
      .unwrap()
      .get(&scope)
      .is_some_and(|(attached, _)| *attached == generation);
    let mut replies = replies.into_iter();
    for entry in plan {
      match entry {
        Publication::Arm(watch, attempt) => {
          // The reply count matches the arm count on every path above, so this
          // never runs dry; if it somehow did, the remaining REMOVALS must still
          // apply rather than be abandoned with their fds.
          let Some(reply) = replies.next() else {
            continue;
          };
          if let Some(anchor) = reply.anchor
            && still_current
          {
            anchors.insert(watch, (scope, generation, anchor));
          }
          outcomes.push(ArmResolution {
            watch,
            attempt,
            outcome: reply.outcome,
          });
        }
        Publication::Disarm(watch) => {
          // An ORDERING comparison, and deliberately not the equality a stamped
          // read would impose: a batch reclaims what its own generation or an
          // OLDER one published and refuses only a NEWER publication. Narrowed
          // to equality it would decline removals the batch is obliged to make,
          // holding their `O_PATH` anchors open until the scope is detached.
          if anchors
            .get(&watch)
            .is_some_and(|(_, published, _)| *published <= generation)
          {
            anchors.remove(&watch);
          }
        }
      }
    }
    ControlBatchOutcome {
      resolutions: outcomes,
      answered,
    }
  }
}

/// One control request's anchor-map mutation, recorded at translation and
/// applied when the batch's answer comes back.
///
/// A disarm must NOT drop its anchor during translation. The batch has not run
/// yet, so the anchor its own arm publishes does not exist to be dropped — and
/// publishing every arm AFTER the batch put that insert on the far side of the
/// removal. An `Arm(w), Disarm(w)` pair in one batch (rapid create/delete/create
/// churn on one slot mints exactly that) therefore ended with `w`'s anchor
/// RESURRECTED: `w`'s id is retired, so no cold enumerate ever consumes it, and
/// its `O_PATH` fd was held for the life of the scope. Repetition walked the
/// process to `RLIMIT_NOFILE`, where real arms and binding re-proofs start
/// failing. Recording the order and replaying it is what makes the map end in
/// the state the batch's own order dictates, in both directions.
#[cfg(all(target_os = "linux", not(miri)))]
enum Publication {
  /// Publish `watch`'s anchor from the reply occupying this arm's position among
  /// the batch's `Arm` entries, resolving the arm ATTEMPT it answers.
  Arm(WatchId, Option<ArmAttempt>),
  /// Drop `watch`'s transient anchor.
  Disarm(WatchId),
}

/// The directory a sync cookie for `dir` actually lands in: `dir` itself when it
/// IS one, its containing directory otherwise — never above `root`.
///
/// The cookie key a sync carries is the subscription's own, and a FILE
/// subscription is validly covered (it commits under an armed ancestor) — so
/// `dir` can name a file, and creating `file/.tributaries-sync-…` inside it would
/// fail ENOTDIR instead of establishing a barrier. The cookie goes BESIDE such a
/// subscription instead, and the caller learns the real location from the
/// returned path.
///
/// `root` is the FLOOR, and it is load-bearing rather than defensive. The
/// watcher proved `dir` is INSIDE the root, so the parent of a `dir` strictly
/// under the root is inside it too — but the parent of the ROOT is not, and a
/// root that has just died (deleted, or replaced by a file) is exactly a `dir`
/// that fails the directory test. Without the floor, a sync racing a root death
/// would place a cookie in the root's PARENT: outside the watched tree, where no
/// event can be reported and nothing else would have any business writing. With
/// it, such a write answers the typed failure instead — the honest outcome for a
/// barrier on a root that is gone.
///
/// One sample, symlink NOT followed: a symlinked directory is not a directory
/// here, and deliberately so — a cookie written through it would be created
/// under the link's TARGET and its event reported outside this root, never
/// meeting the barrier.
fn cookie_dir<'a>(root: &Path, dir: &'a Path) -> &'a Path {
  match std::fs::symlink_metadata(dir) {
    Ok(meta) if meta.is_dir() => dir,
    _ => match dir.parent() {
      Some(parent) if parent.starts_with(root) => parent,
      // No containing directory inside the root: `dir` IS the root (or has no
      // parent at all). Keep `dir` — the create then fails honestly.
      _ => dir,
    },
  }
}

/// Whether a minted cookie NAME is exactly one normal filename component — no
/// separators, no `.`/`..`, not absolute, not empty. The umbrella mints
/// `.tributaries-sync-…`, always normal; anything else is a contract violation
/// that must be refused BEFORE it reaches a path join, where an absolute or
/// `..` name would escape the directory the barrier was validated for.
pub(crate) fn is_normal_cookie_name(name: &str) -> bool {
  let mut components = Path::new(name).components();
  matches!(
    (components.next(), components.next()),
    (Some(std::path::Component::Normal(_)), None)
  )
}

/// `path` with its `.`/`..` components folded lexically (no filesystem access),
/// or `None` if a `..` would climb above the path's anchor. Purely lexical, so
/// it is safe to run inline on the owner's thread — the containment decision it
/// feeds never touches a possibly-hung mount.
fn lexically_normalized(path: &Path) -> Option<PathBuf> {
  let mut out = PathBuf::new();
  for component in path.components() {
    match component {
      std::path::Component::ParentDir => {
        if !out.pop() {
          return None;
        }
      }
      std::path::Component::CurDir => {}
      other => out.push(other.as_os_str()),
    }
  }
  Some(out)
}

/// Whether a cookie directory lies within `root` once `.`/`..` are folded
/// lexically. This REPLACES a plain `starts_with`, which accepts `/r/../outside`
/// (component-wise, `/r/../outside` does start with `/r`) and would place a
/// barrier outside the watched tree. `root` is canonical (no `.`/`..`), so a
/// lexical prefix test on the folded `dir` is exact.
pub(crate) fn cookie_dir_within_root(root: &Path, dir: &Path) -> bool {
  lexically_normalized(dir).is_some_and(|dir| dir.starts_with(root))
}

/// The exclusion covering a cookie directory, if any.
///
/// Containment within the root is necessary but not sufficient for a barrier:
/// the cookie's own event has to be reportable, and an exclusion is precisely an
/// instruction to the source NOT to report a subtree. Writing there succeeds and
/// then nothing ever arrives, so the caller's observation waits for an event
/// that cannot exist — a hang where a typed refusal belongs. The exclusion set
/// is documented as applying to every root, so the refusal is the same on every
/// backend, whether or not that backend can currently enforce the exclusion
/// itself.
///
/// Matched on the paths AS SUPPLIED (lexically folded, like the containment
/// test): a source hands the OS these same bytes to match against absolute
/// event paths, so an exclusion that could not match an event path here could
/// not suppress one there either.
pub(crate) fn cookie_dir_excluded<'a>(exclusions: &'a [PathBuf], dir: &Path) -> Option<&'a Path> {
  let dir = lexically_normalized(dir)?;
  exclusions.iter().find_map(|exclusion| {
    let folded = lexically_normalized(exclusion)?;
    dir.starts_with(&folded).then_some(exclusion.as_path())
  })
}

/// Whether `path` lies at or under one of the caller's exclusion directories —
/// THE enforcement predicate, for every enforcement site on every backend.
///
/// It does not re-derive the matching rule: it is the SAME
/// [`cookie_dir_excluded`] the sync-cookie birth refusal uses, so "a directory
/// `sync_root` refuses to write a cookie into", "a directory a backend refuses
/// to report from" and "a directory the common layer refuses to cover" are one
/// set by construction rather than three that agree today. The rule is a lexical
/// prefix test on the paths AS SUPPLIED, which is what a source that hands an
/// exclusion list to the OS gets too — and it is a SUBTREE test, not a name-prefix
/// one: `/r/cached` survives an exclusion of `/r/cache`.
///
/// It lives here, beside the rule, precisely because it is no longer one
/// platform's helper: the fanotify admission fence, the fanotify seed walk and
/// the cross-platform core's own suppression all consult this one function.
///
/// The empty-set fast path matters: exclusions are rare, and this is called per
/// walked directory, per decoded event and per compiled record.
pub(crate) fn excluded(exclusions: &[PathBuf], path: &Path) -> bool {
  !exclusions.is_empty() && cookie_dir_excluded(exclusions, path).is_some()
}

impl FsOps for RealFs {
  type Handle = SourceHandle;

  /// The `O_PATH` fd an arm published. Off the descending backend no anchor is
  /// ever minted, and an uninhabited type says so in the type system: every
  /// `Option<Self::Anchor>` there is provably `None`.
  #[cfg(all(target_os = "linux", not(miri)))]
  type Anchor = std::os::fd::OwnedFd;
  #[cfg(not(all(target_os = "linux", not(miri))))]
  type Anchor = std::convert::Infallible;

  fn spawn_source(
    &self,
    config: SourceConfig,
  ) -> Result<SpawnedSource<Self::Handle>, SpawnFailed<Self::Handle>> {
    if !config.backend.native_to_host() {
      return Err(
        SourceError::ForeignBackend {
          requested: config.backend,
        }
        .into(),
      );
    }
    // The spawn itself mints the RootMeta — canonical root, device, and the
    // mount seed are all finalized BEFORE the stream starts delivering, so
    // the metadata is a safe authority for every event on the queue; deriving
    // any of it here, after start, could postdate events already enqueued.
    let (handle, receiver, meta) = crate::os::spawn_source(config)?;
    Ok(SpawnedSource {
      handle,
      receiver,
      meta,
    })
  }

  fn probe(&self, path: &Path) -> ProbeOutcome {
    match std::fs::symlink_metadata(path) {
      Ok(meta) => {
        let file_type = meta.file_type();
        let kind = if file_type.is_dir() {
          tributary_proto::FileKind::Dir
        } else if file_type.is_file() {
          tributary_proto::FileKind::File
        } else if file_type.is_symlink() {
          tributary_proto::FileKind::Symlink
        } else {
          tributary_proto::FileKind::Other
        };
        let (file_id, dev) = inode_of(&meta);
        ProbeOutcome::Present { kind, file_id, dev }
      }
      Err(err) if err.kind() == std::io::ErrorKind::NotFound => ProbeOutcome::Missing,
      Err(_) => ProbeOutcome::Failed,
    }
  }

  fn write_cookie(
    &self,
    root: &Path,
    dir: &Path,
    name: &str,
  ) -> Result<CookieFile, CookieWriteError> {
    // Resolve the directory the sync named — which is where the private cookie
    // directory goes — then CANONICALIZE it: `canonicalize` follows every symlink
    // in the path, so an ALREADY-EXISTING intermediate symlink (`<root>/link/sub`
    // where `link` targets outside) is resolved to where the cookie would truly
    // land — the lexical containment check upstream never sees that, because
    // component-wise the spelling still sits under the root.
    // Canonicalizing the root too makes the beneath test compare two paths from
    // the SAME resolver (identical prefix form on every platform). Both blocking
    // calls run on the driver's blocking pool, never the owner loop, so a hung
    // mount cannot wedge it. `canonicalize` requires the target to exist; a cookie
    // directory that is gone is already a typed write failure, so the valid case
    // is unchanged.
    let canonical_dir =
      std::fs::canonicalize(cookie_dir(root, dir)).map_err(CookieWriteError::clean)?;
    let canonical_root = std::fs::canonicalize(root).map_err(CookieWriteError::clean)?;
    if !canonical_dir.starts_with(&canonical_root) {
      // The real directory escapes the watched root — its cookie's create event
      // could never reach this root's stream. Refuse before creating anything.
      return Err(CookieWriteError::clean(std::io::Error::other(
        "the cookie directory resolves outside the watched root",
      )));
    }
    // This is the last path this write resolves. The private directory is opened
    // once, and every operation on the cookie — this create, and every removal the
    // obligation ever attempts — goes through its descriptor, which is what makes
    // the cookie's name unbindable by anyone else (see [`CookieDir`]).
    //
    // A residual the canonicalize above does not close: a symlink swapped INTO an
    // intermediate directory between `canonicalize` and this open is still
    // followed, because a path-based open is not beneath-anchored. Bounded to what
    // it can actually cause — the cookie could be placed under a directory other
    // than the one the caller named, whose events the root's stream may never
    // report, so the sync's barrier does not resolve. It cannot cause a deletion:
    // whatever directory is opened is verified to be this user's before anything is
    // created in it, and every removal is confined to that same descriptor.
    let cookies =
      Arc::new(CookieDir::open_or_create(&canonical_dir).map_err(CookieWriteError::clean)?);
    let created = cookies.create(name).map_err(CookieWriteError::clean)?;
    // The identity comes off the descriptor the create just returned — one
    // `fstat` of the object we made, in obedience to the one-sample rule (see the
    // module doc). Re-opening the name to read it would defeat the purpose: it
    // could only ever describe whatever holds the name at that instant, which is
    // exactly the thing the removal must be able to tell this cookie apart from.
    match identity_of_handle(&created) {
      // The descriptor travels INTO the record: for the whole life of the
      // obligation it holds this object's identity slot out of the allocator's
      // reach, which is what makes a later comparison against it mean anything
      // (see `CookieFile`).
      Ok(Some(identity)) => Ok(CookieFile::anchored(
        cookies,
        name,
        CookieProof::Object(identity),
        created,
      )),
      // A file exists and nothing can say WHICH file it is — either the platform
      // has no identity to give or the read failed. Both are fail-closed the same
      // way: destroy what we just made and report the write as failed, rather than
      // admit a cookie no removal could ever tell apart from a successor. The
      // sync's caller sees a typed, retryable write failure either way; whether a
      // FILE survives is what the returned residue answers.
      Ok(None) => Err(destroy_unidentified(
        cookies,
        name,
        created,
        std::io::Error::new(
          std::io::ErrorKind::Unsupported,
          "the cookie's filesystem answers no identity for an open descriptor",
        ),
      )),
      Err(err) => Err(destroy_unidentified(cookies, name, created, err)),
    }
  }

  fn remove_cookie(&self, cookie: &CookieFile) -> Result<CookieRemoval, std::io::Error> {
    let Some(dir) = cookie.dir.as_deref() else {
      // A record minted below the real write carries no anchor, so there is no
      // removal this implementation may perform for it. Falling back to the
      // pathname is exactly the deletion the anchor exists to forbid, and a
      // returned failure keeps the record — the safe half of both.
      return Err(std::io::Error::other(
        "a cookie with no anchoring directory cannot be removed",
      ));
    };
    remove_anchored(dir, &cookie.name, cookie.proof, cookie.pin.as_deref())
  }

  fn refresh_mounts(&self, root: &Path) -> MountRefresh {
    let (mounts, authoritative) = match crate::os::mounts_under(root) {
      Some(mounts) => (mounts, true),
      None => (Vec::new(), false),
    };
    // ONE sample proves liveness AND reads the mount frame: `root_liveness_and_frame`
    // is a single `statx` (symlink not followed, so a root retargeted to a symlink is
    // a replacement, not a follow), yielding the `(dev, ino)` the death gate decides
    // alive-vs-replaced on AND the frame the core adopts — from the SAME object. A
    // same-object re-mount keeps `(dev, ino)` (the death gate passes) but moves the
    // root to a new mount; adopting the frame from the identical sample keeps the
    // enumerate descent fence relative to that new mount without ever pairing the
    // identity verdict with a different object's frame (a replace/remount between two
    // separate lookups would). A `Missing` root is DeleteSelf, any other stat failure
    // is Unreadable (MoveSelf) — the exact `RootChanged`-probe mapping; the mount id
    // is inotify's best-effort belt (`None` below 5.8), taken from the same result's
    // mask.
    let (root_liveness, root_mnt_id) = root_liveness_and_frame(root);
    MountRefresh {
      mounts,
      authoritative,
      root: root_liveness,
      root_mnt_id,
    }
  }
  #[cfg(all(target_os = "linux", not(miri)))]
  fn attach_scope(&self, scope: ScopeId, port: ScopePort, generation: u64) {
    self
      .ports
      .write()
      .unwrap()
      .insert(scope, (generation, port));
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn detach_scope(&self, scope: ScopeId) {
    // Purge the port AND this scope's anchors under the anchors lock held
    // across both: a concurrent `batch_control` publishes an anchor only
    // while holding this same lock and only after re-confirming the port's
    // generation, so it cannot slip a fresh anchor in AFTER this purge (it
    // would find the generation already gone). Lock order everywhere is
    // anchors-then-ports.
    let mut anchors = self.anchors.lock().unwrap();
    self.ports.write().unwrap().remove(&scope);
    anchors.retain(|_, (anchor_scope, _, _)| *anchor_scope != scope);
  }

  // Arm/disarm route through the live source's control path (the reader owns
  // the fd and the wd table). A scope with no attached port — a
  // kernel-recursive source, or an arm racing its own stream teardown —
  // answers the honest typed refusal, never a silent success.
  #[cfg(all(target_os = "linux", not(miri)))]
  fn add_watch(
    &self,
    scope: ScopeId,
    watch: WatchId,
    parent: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    // A direct single arm runs against the CURRENT transport (the caller is
    // synchronous, not a leftover batch), so it adopts the attached
    // generation rather than one captured earlier. It is only ever a PRE-arm,
    // whose outcome is returned here and replayed under the attempt the commit
    // mints — so the request carries none.
    let generation = self.current_generation(scope);
    self
      .batch_control(
        scope,
        generation,
        vec![ControlRequest::Arm {
          watch,
          attempt: None,
          parent,
          name: name.clone(),
          path: Arc::new(path.to_path_buf()),
          expected,
        }],
      )
      .resolutions
      .into_iter()
      .next()
      .map(|resolution| resolution.outcome)
      .unwrap_or(WatchOutcome::Failed(WatchError::Gone))
  }

  #[cfg(not(all(target_os = "linux", not(miri))))]
  fn add_watch(
    &self,
    _scope: ScopeId,
    _watch: WatchId,
    _parent: WatchId,
    _path: &Path,
    _name: &Segment,
    _expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    WatchOutcome::Failed(WatchError::Io)
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn remove_watch(&self, scope: ScopeId, watch: WatchId) {
    let generation = self.current_generation(scope);
    self.batch_control(scope, generation, vec![ControlRequest::Disarm { watch }]);
  }

  #[cfg(not(all(target_os = "linux", not(miri))))]
  fn remove_watch(&self, _scope: ScopeId, _watch: WatchId) {}

  // The batched arm path IS the real inotify arm path: even a single arm goes
  // through it, so anchor bookkeeping and the control envelope live in exactly
  // one place. The whole batch becomes ONE `Control::Batch` message, so a drain
  // cycle that produces N arms wakes the reader at most once.
  //
  // This is the blocking entry, for the direct single-op callers that own their
  // thread outright. The driver's own per-scope batches take `dispatch_control`
  // instead: same translation, same publication, but the reader's answer is
  // awaited by nobody's thread.
  #[cfg(all(target_os = "linux", not(miri)))]
  fn batch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> ControlBatchOutcome {
    match self.translate_control(scope, generation, requests) {
      Err(refused) => refused,
      Ok((port, ops, plan)) => self.publish_arm_anchors(scope, generation, plan, port.batch(ops)),
    }
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn dispatch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
    answer: ControlAnswer<Self::Handle>,
  ) {
    match self.translate_control(scope, generation, requests) {
      Err(refused) => answer.resolve(refused),
      Ok((port, ops, plan)) => {
        // The reader owns the answer from here. It replies when it has run the
        // batch, and a batch no reader survives to serve is answered by the
        // message's own destruction — so the publication below runs wherever the
        // outcome is actually produced, and this call returns to the pool with
        // nothing of the batch still owed to the thread it was made on.
        let ops_handle = self.clone();
        port.dispatch(ops, move |outcome| {
          answer.resolve(ops_handle.publish_arm_anchors(scope, generation, plan, outcome));
        });
      }
    }
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn preflight_arm(
    &self,
    port: &ScopePort,
    _scope: ScopeId,
    watch: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    use crate::os::linux::ControlOp;

    let ScopePort::Inotify(port) = port else {
      return WatchOutcome::Failed(WatchError::Gone);
    };
    let ops = vec![ControlOp::Arm(
      self.build_arm_request(watch, watch, path, name, expected),
    )];
    // A pre-arm needs no `answered`: a reader that never served it answers its one
    // arm `Failed(Io)`, and the commit is decided by that outcome alone — it
    // refuses into the stream-replace fallback either way.
    let Some(reply) = port.batch(ops).replies.pop() else {
      return WatchOutcome::Failed(WatchError::Gone);
    };
    // The anchor is deliberately DROPPED, not stored: the commit's
    // detach_scope purges this scope's anchors wholesale, and a refused
    // commit would leave a stale anchor pointing into a torn-down transport.
    // The post-commit root enumerate falls back to path-based listing — a
    // new root renamed inside that window reads as the root dying right
    // after the swap, healed loudly by the refresh-cadence liveness check.
    //
    // A WIDEN pre-arm runs on the LIVE fd, where the reader's no-wrap gate
    // applies as everywhere: an instance at its rebuild threshold is swapped
    // for a fresh fd first, and the swap's whole-instance loss signal taints
    // the (already-open) widen window — the commit then refuses into the
    // stream-replace fallback, the old coverage untouched. A replace pre-arm
    // runs on a freshly spawned fd far from the threshold.
    reply.outcome
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn resolve_root_meta(&self, path: &Path) -> Result<RootMeta, SourceError> {
    // Spelled out rather than imported: the seam's spawn now goes through
    // [`crate::os::spawn_source`], so a plain `Source` import would be unused on
    // every host but this one.
    crate::os::Source::resolve_root_meta(path)
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn take_enumerate_anchor(&self, watch: WatchId) -> Option<Self::Anchor> {
    self
      .anchors
      .lock()
      .unwrap()
      .remove(&watch)
      .map(|(_, _, anchor)| anchor)
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn enumerate(&self, _watch: WatchId, anchor: Option<Self::Anchor>, path: &Path) -> RawEnumerate {
    use std::os::fd::AsRawFd;

    // With an anchor in hand the listing reads THROUGH the armed object
    // (`/proc` re-opens an `O_PATH` fd), immune to a rename between the arm and
    // this read; the path fallback is the honest best effort when the arm
    // published none. Either way the fd is released when this read returns —
    // and with the job if it is dropped unrun — so usage stays O(in-flight).
    let Some(anchor) = anchor else {
      return list_dir(path);
    };
    let via = PathBuf::from(format!("/proc/self/fd/{}", anchor.as_raw_fd()));
    let listed = list_dir(&via);
    drop(anchor);
    listed
  }

  #[cfg(not(all(target_os = "linux", not(miri))))]
  fn enumerate(&self, _watch: WatchId, _anchor: Option<Self::Anchor>, path: &Path) -> RawEnumerate {
    list_dir(path)
  }
}

/// All of one directory entry's stat facts — kind, device, inode, mount frame —
/// from a SINGLE path sample, symlink not followed. `None` is a raced-away entry
/// (the listing no longer reflects that name).
///
/// On Linux this is ONE [`stat_sample`]: every fact comes from that one result,
/// so a rename/bind toggling between two syscalls can never pair one object's
/// `(kind, dev, ino)` with another object's mount frame — the arm downstream
/// verifies `(dev, ino)` only, so a raced foreign bind that split the sample
/// could otherwise be classified descendable and armed. A `statx` mask miss (no
/// `STATX_MNT_ID` below 5.8) drops just the frame (`None`) and descent runs on the
/// device belt. Off Linux, one `symlink_metadata` (no mount-id notion; the core
/// fences on device alone) — still a single object's facts.
#[cfg(all(target_os = "linux", not(miri)))]
fn dir_entry_stat(entry_path: &Path) -> Option<(tributary_proto::FileKind, u64, u64, Option<u64>)> {
  let sample = stat_sample(entry_path).ok()?;
  Some((sample.kind, sample.dev, sample.ino, sample.frame))
}

#[cfg(not(all(target_os = "linux", not(miri))))]
fn dir_entry_stat(entry_path: &Path) -> Option<(tributary_proto::FileKind, u64, u64, Option<u64>)> {
  let meta = std::fs::symlink_metadata(entry_path).ok()?;
  Some((
    kind_of(&meta.file_type()),
    dev_of(&meta),
    ino_of(&meta),
    None,
  ))
}

/// The most entries ONE directory read may retain before it declares itself
/// incomplete.
///
/// An enumerate is a bounded REQUEST — one job, one directory — whose retained
/// size is chosen by the filesystem rather than by this driver. Uncapped, a
/// single directory decides how much memory the process holds: the listing's own
/// vector, plus the `DirEntry` vector [`DriverCore::on_enumerated`] builds from
/// it while the first is still alive, plus the Monitor's node state for every
/// name. A tree whose directories are written by someone else — a shared upload
/// area, a tenant's cache, a maildir — therefore turns one legal watch into an
/// unbounded allocation, and the driver has no way to refuse it after the fact.
///
/// The cap is applied as LOSS, not as silence, and that is what makes it safe:
/// a truncated read reports `complete: false`, which is the same incomplete
/// listing a readdir cut short mid-directory produces. The Monitor already owns
/// that case — it reconciles and arms every name it DID see, cascades the re-arm
/// into every child it already knows, retries a bounded number of times, and then
/// lets a covering `Rescan` stand for the rest. So the consumer is told to
/// re-enumerate rather than being quietly told nothing.
///
/// Sized so the bound binds only pathological directories: 65_536 names is far
/// above any tree a watcher is expected to descend, and a component is at most
/// 255 bytes on the filesystems this targets, so the entry cap bounds the
/// listing's bytes too.
const MAX_ENUMERATE_ENTRIES: usize = 65_536;

#[cfg(test)]
thread_local! {
  /// Test seam: the entry bound [`list_dir`] reads, so a cell can prove the
  /// truncation without materializing [`MAX_ENUMERATE_ENTRIES`] real directory
  /// entries. `list_dir` is a plain synchronous function, so a cell calling it
  /// directly runs it on the very thread that set this.
  static ENUMERATE_ENTRY_CAP: std::cell::Cell<usize> =
    const { std::cell::Cell::new(MAX_ENUMERATE_ENTRIES) };
}

#[cfg(test)]
fn enumerate_entry_cap() -> usize {
  ENUMERATE_ENTRY_CAP.with(std::cell::Cell::get)
}

#[cfg(not(test))]
const fn enumerate_entry_cap() -> usize {
  MAX_ENUMERATE_ENTRIES
}

/// One blocking readdir + a single per-entry stat sample, lowered to raw stat
/// facts (see [`dir_entry_stat`] for the one-sample discipline), truncating at
/// [`MAX_ENUMERATE_ENTRIES`].
fn list_dir(path: &Path) -> RawEnumerate {
  let dir = match std::fs::read_dir(path) {
    Ok(dir) => dir,
    Err(err) => return RawEnumerate::Failed(io_class(&err)),
  };
  let mut entries = Vec::new();
  let mut complete = true;
  for entry in dir {
    if entries.len() >= enumerate_entry_cap() {
      // The retention bound, reported as the incomplete read it is: the Monitor
      // arms what was seen and covers the remainder with a `Rescan`, exactly as
      // for a readdir cut short by the kernel (see [`MAX_ENUMERATE_ENTRIES`]).
      if std::env::var("TRIBUTARY_FS_WIDEN_DEBUG").is_ok() {
        let _ = writeln!(
          std::io::stderr().lock(),
          "[tributary-fs widen-debug] enumerate PARTIAL at {} (directory exceeds the \
           {}-entry retention bound) — the Monitor escalates this dirty cold-read to a Rescan",
          path.display(),
          enumerate_entry_cap(),
        );
      }
      complete = false;
      break;
    }
    let Ok(entry) = entry else {
      // The read was cut short mid-directory; what was seen still
      // reconciles, and the incomplete flag drives the Monitor's retry.
      if std::env::var("TRIBUTARY_FS_WIDEN_DEBUG").is_ok() {
        // Best-effort: a diagnostic must never unwind the driver (a closed log
        // pipe would otherwise abort a widen mid-recovery), so discard write errors.
        let _ = writeln!(
          std::io::stderr().lock(),
          "[tributary-fs widen-debug] enumerate PARTIAL at {} (readdir cut short mid-directory) \
           — the Monitor escalates this dirty cold-read to a Rescan",
          path.display()
        );
      }
      complete = false;
      break;
    };
    let entry_path = entry.path();
    let Some((kind, dev, ino, mnt_id)) = dir_entry_stat(&entry_path) else {
      // A raced-away entry: the listing no longer reflects one name.
      if std::env::var("TRIBUTARY_FS_WIDEN_DEBUG").is_ok() {
        let _ = writeln!(
          std::io::stderr().lock(),
          "[tributary-fs widen-debug] enumerate PARTIAL at {} (entry {} stat gave None — a \
           genuine raced-away entry post-EINTR-retry) — the Monitor escalates this dirty \
           cold-read to a Rescan",
          path.display(),
          entry_path.display()
        );
      }
      complete = false;
      continue;
    };
    entries.push(RawDirEntry {
      name: entry.file_name().as_encoded_bytes().to_vec(),
      kind,
      dev,
      ino,
      mnt_id,
    });
  }
  RawEnumerate::Listed { entries, complete }
}

fn inode_of(meta: &std::fs::Metadata) -> (Option<std::num::NonZeroU64>, u64) {
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    (std::num::NonZeroU64::new(meta.ino()), meta.dev())
  }
  #[cfg(not(unix))]
  {
    let _ = meta;
    (None, 0)
  }
}

/// The identity of an OPEN object, read from the descriptor itself — one `fstat`
/// (or its Windows equivalent on the handle), never a lookup of a path, so the
/// answer can only ever name the object the caller already holds.
///
/// Three outcomes, kept apart because they demand opposite responses:
///
/// - `Err` — the read itself failed. Which object this is stays UNKNOWN, so no
///   caller may settle anything on it; it propagates, and a removal retries.
/// - `Ok(None)` — the platform or volume has no identity to give (a file id is
///   not universal). A definite answer, and a definite absence of proof.
/// - `Ok(Some(id))` — the object's identity.
///
/// Collapsing the first two into one is what makes an identity read fail OPEN:
/// an `fstat` that errored would read as "this platform has none", and every
/// consumer of that answer would then take the by-name branch it exists to
/// avoid. A synthesized stand-in would be worse still — it compares EQUAL
/// between two unrelated objects, licensing exactly the deletion the proof
/// refuses.
fn identity_of_handle(file: &std::fs::File) -> Result<Option<RootIdentity>, std::io::Error> {
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok(Some(RootIdentity::new(meta.dev(), meta.ino().into())))
  }
  // The crate's one Windows identity read, shared with the source brackets:
  // `(volume serial, 128-bit file id)`, wide enough for ReFS ids that a folded
  // 64-bit index would collide.
  #[cfg(all(target_os = "windows", not(miri)))]
  {
    use std::os::windows::io::AsHandle;
    let identity = crate::os::windows::ffi::identity_of(file.as_handle())?;
    // Zero and all-ones are Windows' two spellings of "this object has no file
    // id", not ids. Admitting either would make every object that answers the
    // same sentinel compare EQUAL to every other — one identity shared by
    // unrelated files, which is the precise shape of the licence-to-delete this
    // whole mechanism exists to withhold.
    if identity.file_id == 0 || identity.file_id == u128::MAX {
      return Ok(None);
    }
    Ok(Some(RootIdentity::new(
      identity.volume_serial,
      identity.file_id,
    )))
  }
  #[cfg(not(any(unix, all(target_os = "windows", not(miri)))))]
  {
    let _ = file;
    Ok(None)
  }
}

/// Destroys the cookie `handle` refers to after its identity could not be read,
/// and reports the write's failure — together with the FILE, if the destroy could
/// not be completed.
///
/// A file that exists and cannot be identified must not survive if it can be
/// helped: no later removal could tell it apart from a successor at its name. So
/// it is destroyed HERE, while its own create is still on the stack, through the
/// same anchor the create used — `unlinkat` against the private cookie directory
/// on Unix, the create's own handle on Windows. Neither resolves a pathname, so
/// neither can leave the directory the create was made in; on Windows the destroy
/// is object-exact besides, and on Unix it rests on the `O_EXCL` create that
/// bound this name a moment ago plus the same-uid trust the removal contract
/// states ([`remove_anchored`]).
///
/// A destroy that FAILS leaves the file on disk, and reporting the write as
/// though nothing had been created is what makes such files untracked and
/// uncounted forever. It comes back as a residue instead, marked
/// [`Anchor`](CookieProof::Anchor) and carrying the create's descriptor — which
/// keeps the object's identity slot reserved AND is what a later removal reads to
/// promote the record to a real identity rather than retry a bare name.
fn destroy_unidentified(
  dir: Arc<CookieDir>,
  name: &str,
  handle: std::fs::File,
  err: std::io::Error,
) -> CookieWriteError {
  // Which primitive performs the destroy is the cookie directory's own business,
  // and asking it here is what keeps this site from naming a platform set that can
  // drift from the one actually implementing the primitive: a target with no
  // anchor at all answers the refusal below instead of failing to compile against
  // a method it never had.
  //
  // The handle is deliberately still held across the destroy: the entry goes away,
  // the OBJECT does not, so its identity slot stays out of the allocator's reach
  // for as long as the residue below (if any) lives.
  let destroyed = dir.destroy_created(name, &handle);
  match destroyed {
    Ok(()) => CookieWriteError::clean(err),
    // Already gone: nothing survives this write either way.
    Err(gone) if gone.kind() == std::io::ErrorKind::NotFound => CookieWriteError::clean(err),
    Err(_) => CookieWriteError {
      source: err,
      residue: Some(Box::new(CookieFile::anchored(
        dir,
        name,
        CookieProof::Anchor,
        handle,
      ))),
    },
  }
}

/// Removes `name` from the directory `dir` refers to, having first compared the
/// object standing at the name against the one the cookie records.
///
/// # What this removal is, and what it is NOT
///
/// It is ANCHORED: `openat` and `unlinkat` both address an entry OF THE DIRECTORY
/// THIS DESCRIPTOR REFERS TO, so no component of any path is resolved and the
/// entry unlinked is an entry of the same directory the identity was read
/// through. A directory renamed, replaced or destroyed under this driver's feet
/// changes nothing about where the removal lands. That is the property [`Path`]
/// based removal does not have and the reason none is performed anywhere.
///
/// It is NOT object-exact. Neither Linux nor macOS has an unlink conditioned on
/// file identity — no `unlinkat` flag, no `funlinkat`, nothing — so the proof and
/// the removal are necessarily TWO calls, and no amount of proximity closes the
/// gap between them: a preempted thread can sit there indefinitely. Whoever can
/// bind a name in this directory can therefore make this call unlink an object it
/// did not create, and the identity comparison cannot prevent it.
///
/// # Who that leaves, and why the contract names them trusted
///
/// The directory is created `0o700` with the effective uid in its name and
/// verified on open (owner and mode), so binding a name in it requires being this
/// USER. Every other user — the case the whole anchoring design exists for — is
/// excluded by the kernel, not by this comparison.
///
/// What remains is another process running AS THIS USER. That peer is trusted
/// here, and the contract says so rather than pretending otherwise: it can
/// already unlink the cookie outright, replace the private directory, write
/// anywhere this process can write, and attach to this process. There is no
/// boundary at the removal for a check to hold that the operating system does not
/// draw one for.
///
/// So the comparison is a DISPLACEMENT DETECTOR, not a proof: it is what turns
/// the ordinary races — a crash leftover swept by a later run, a name freed and
/// reused, an object nothing can classify — into the [`Displaced`] and
/// unprovable-failure verdicts the ledger needs, and it is deliberately kept for
/// exactly that. It is not a defence against a hostile same-uid peer, and nothing
/// in this crate should be written as though it were.
///
/// # The one thing the narrowed contract still refuses
///
/// Trusting the peer licenses unlinking a name this driver has EVIDENCE about. It
/// does not license unlinking a name it knows nothing about, which is what an
/// [`Anchor`](CookieProof::Anchor) record used to do: created by this write,
/// never identifiable, and retried later by name with no comparison at all —
/// `remove_file(path)` minus only the path resolution. The identity is therefore
/// promoted first, off the create's OWN retained descriptor: an `fstat` of a
/// handle this process holds is not a lookup of anything and cannot be
/// redirected, so it names the object this write made and nothing else. Where it
/// cannot be promoted the removal FAILS CLOSED — the record survives, close
/// reports the residue, and no name is touched.
///
/// [`Displaced`]: CookieRemoval::Displaced
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_anchored(
  dir: &CookieDir,
  name: &str,
  proof: CookieProof,
  pin: Option<&std::fs::File>,
) -> Result<CookieRemoval, std::io::Error> {
  let identity = match proof {
    CookieProof::Object(identity) => identity,
    CookieProof::Anchor => {
      let Some(created) = pin else {
        return Err(std::io::Error::other(
          "an unidentified cookie with no retained handle cannot be removed",
        ));
      };
      // A propagated read failure is transient and keeps the record for a later
      // sweep; a platform that answers no identity at all leaves this removal
      // with nothing to compare, and a by-name unlink under that is the deletion
      // this design refuses to perform.
      match identity_of_handle(created)? {
        Some(identity) => identity,
        None => {
          return Err(std::io::Error::other(
            "an unidentifiable cookie cannot be removed: this platform has no unlink \
             conditioned on the object, and its name alone vouches for nothing",
          ));
        }
      }
    }
  };
  let standing = match dir.open_for_classification(name) {
    Ok(file) => file,
    // Idempotent by contract: an already-gone cookie is success.
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
      return Ok(CookieRemoval::AlreadyGone);
    }
    // A symlink standing at the name: `O_NOFOLLOW` refuses it, and a cookie is
    // never a symlink (its own create refused one too), so this is a
    // displacement and not a transient failure. Reporting it as a failure
    // instead would arm a retry that can never converge.
    Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
      return Ok(CookieRemoval::Displaced);
    }
    // Anything else leaves WHICH object stands at the name unknown — a socket's
    // `ENXIO`, a resource limit, an I/O error. Unknown is not displaced, and
    // settling a verdict on it would retire a record whose file is still there.
    Err(err) => return Err(err),
  };
  // A FAILED read is returned for the same reason. `Ok(None)` — an object that
  // answers no identity — IS a mismatch, since the pinned cookie has one and
  // this thing does not.
  if identity_of_handle(&standing)? != Some(identity) {
    return Ok(CookieRemoval::Displaced);
  }
  match dir.unlink(name) {
    Ok(()) => Ok(CookieRemoval::Unlinked),
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(CookieRemoval::AlreadyGone),
    // A transient failure (a hung mount, a flipped permission) is reported, not
    // swallowed, so the record survives for a later sweep to retry.
    Err(err) => Err(err),
  }
}

/// Removes `name` from `dir` on the platform that HAS the primitive the two
/// Unixes lack: a disposition set on an already-open handle destroys the object
/// that handle refers to, with no name resolved at all.
///
/// Two opens, because one cannot do both jobs. The first asks for the LOWEST
/// rights that answer an identity, so an object this process may not delete still
/// reaches the comparison and settles as displaced instead of failing forever.
/// The second asks for DELETE — and its identity is RE-READ before the
/// disposition, because it is a second lookup of the name and a second lookup can
/// land on a different object. Only a handle that has itself been proven is ever
/// deleted through.
///
/// An [`Anchor`](CookieProof::Anchor) residue has no identity to prove and takes
/// neither open: it is destroyed through the create's OWN retained handle, which
/// is object-exact by construction. Without that handle there is nothing safe left
/// to do, and the failure is returned so the record survives.
#[cfg(all(target_os = "windows", not(miri)))]
fn remove_anchored(
  dir: &CookieDir,
  name: &str,
  proof: CookieProof,
  pin: Option<&std::fs::File>,
) -> Result<CookieRemoval, std::io::Error> {
  use std::os::windows::io::AsHandle;

  let CookieProof::Object(identity) = proof else {
    let Some(created) = pin else {
      return Err(std::io::Error::other(
        "an unidentified cookie with no retained handle cannot be removed",
      ));
    };
    return match crate::os::windows::ffi::delete_by_handle(created.as_handle()) {
      Ok(()) => Ok(CookieRemoval::Unlinked),
      Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(CookieRemoval::AlreadyGone),
      Err(err) => Err(err),
    };
  };
  let standing = match dir.open_for_classification(name) {
    Ok(file) => file,
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
      return Ok(CookieRemoval::AlreadyGone);
    }
    Err(err) => return Err(err),
  };
  if identity_of_handle(&standing)? != Some(identity) {
    return Ok(CookieRemoval::Displaced);
  }
  drop(standing);
  let deletable = match dir.open_for_delete(name) {
    Ok(file) => file,
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
      return Ok(CookieRemoval::AlreadyGone);
    }
    // A sharing violation on the DELETE open is transient by the caller's
    // contract: the record survives for a later sweep.
    Err(err) => return Err(err),
  };
  // The re-proof. Everything below this line destroys the object `deletable`
  // refers to, so it is this handle's identity — not the first one's — that has to
  // match.
  if identity_of_handle(&deletable)? != Some(identity) {
    return Ok(CookieRemoval::Displaced);
  }
  match crate::os::windows::ffi::delete_by_handle(deletable.as_handle()) {
    Ok(()) => Ok(CookieRemoval::Unlinked),
    // The object went away under us between the proof and the disposition: still
    // the idempotent success, since this driver's file is gone from the only place
    // it could ever address it.
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(CookieRemoval::AlreadyGone),
    // Anything else (a sharing violation, a read-only volume) is transient by the
    // caller's contract: the record survives for a later sweep.
    Err(err) => Err(err),
  }
}

/// The platform with no anchor primitive at all. No cookie is ever created there
/// (see [`CookieDir`]), so no removal is ever asked for; a request that reaches
/// here anyway refuses rather than falling back to a pathname.
#[cfg(not(any(
  target_os = "linux",
  target_os = "macos",
  all(target_os = "windows", not(miri))
)))]
fn remove_anchored(
  _dir: &CookieDir,
  _name: &str,
  _proof: CookieProof,
  _pin: Option<&std::fs::File>,
) -> Result<CookieRemoval, std::io::Error> {
  Err(std::io::Error::new(
    std::io::ErrorKind::Unsupported,
    "this platform has no way to bind a cookie's removal to the object created",
  ))
}

/// How a dispatched control batch ENDED. The completion's fail-closed policy is
/// judged on this, so the two ways of NOT running are kept apart: they differ in
/// how much they leave unknown, which is the whole input to that judgement.
///
/// [`Unwound`](Self::Unwound) is the DEFAULT because the completion is emitted by
/// a guard that fires on drop. Until an outcome has arrived to record an end
/// from, the only honest thing to say about the batch is that nothing is known
/// about it, so the value carried in the meantime must be the one that assumes
/// least.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum ControlBatchEnd {
  /// No outcome ever arrived: the executor stopped part-way through the batch,
  /// destroying the answer sink instead of resolving it. Neither how far it got
  /// nor which of its callers were answered survives that — the arm results ride
  /// the outcome — and no later fact bounds either.
  #[default]
  Unwound,
  /// The outcome ARRIVED, reporting that no reader served the batch: the control
  /// channel was already closed, or the reader unwound before replying. Every arm
  /// it carried still came back refused, so no caller is left waiting on it, and
  /// whatever a dying reader may have half-run is confined to the one transport
  /// the batch was addressed to.
  Unanswered,
  /// The executor served the batch, so its reader cut the kernel queue onto the
  /// lane before replying — the only end that can carry an ordering proof.
  Answered,
}

/// One blocking operation's result, shipped back to the select loop.
enum OpResult<H> {
  /// One spawn finished. BOTH outcomes can carry a live native stream: a
  /// success carries the committed one, and a failure carries the rollback of a
  /// barrier that got past its stream's start (see
  /// [`SpawnFailed`](crate::os::SpawnFailed)) — so every guard that drains this
  /// queue has to look at both.
  Spawned {
    scope: ScopeId,
    result: Result<SpawnedSource<H>, SpawnFailed<H>>,
  },
  Probed {
    probe: ProbeId,
    outcome: ProbeOutcome,
  },
  MountsRefreshed {
    scope: ScopeId,
    refresh: MountRefresh,
  },
  TornDown {
    scope: ScopeId,
  },
  /// A teardown that did not PROVE its stream gone — its `shutdown` unwound, or
  /// it returned [`Quiesce::Unproven`](crate::os::Quiesce). The obligation is
  /// retired exactly as a [`TornDown`](Self::TornDown) retires one — the reaper
  /// thread is free and nothing is still running — but the stream's quiescence
  /// was never proven, so close records it and refuses to report `Ok` over it.
  /// Without this terminal a failed teardown leaves the scope's count owed
  /// forever and every later close reports a phantom obligation for work that
  /// stopped long ago.
  ///
  /// The returned-unproven half is not hypothetical: a Windows pump that cannot
  /// prove its overlapped read's pin ended must RETAIN the kernel-owned buffer
  /// rather than free it, and it then returns normally. That leak reaches this
  /// terminal, and so is counted, latched against the scope, and refused over
  /// by close — exactly as an unwind is.
  TeardownFailed {
    scope: ScopeId,
  },
  /// One arm's outcome from a dispatched control batch. `scope` and
  /// `generation` name the transport lane the batch was emitted for: a reply
  /// whose generation no longer matches the scope's current lane is a
  /// leftover of a replaced transport and is dropped whole — with root
  /// re-adds occurring mid-life, a stale synthesized `Failed` reaching the
  /// core against the REBOUND root (which keeps its `WatchId` across a
  /// rebind) would spuriously invalidate the fresh world.
  WatchInstalled {
    watch: WatchId,
    attempt: ArmAttempt,
    outcome: WatchOutcome,
    scope: ScopeId,
    generation: u64,
  },
  /// A descending replace's pre-arm resolved: the new root's kernel watch on
  /// the REPLACEMENT transport installed (or refused) while the old stream
  /// still owns the scope. Routed to the replace commit, never to the core's
  /// ordinary watch-result path.
  RebindArmed {
    scope: ScopeId,
    outcome: WatchOutcome,
  },
  /// A same-transport widen's no-spawn [`RootMeta`] resolve finished. It owns
  /// no native stream, so a straggler after the close sweep is dropped whole.
  ReplaceMeta {
    scope: ScopeId,
    result: Result<RootMeta, SourceError>,
  },
  /// A same-transport widen's pre-arm of the widened root on the LIVE port
  /// resolved: commit, or unwind with the old coverage untouched.
  WidenArmed {
    scope: ScopeId,
    outcome: WatchOutcome,
  },
  Enumerated {
    req: ReqId,
    raw: RawEnumerate,
  },
  /// A dispatched physical cookie WRITE finished — success, refusal, or error.
  /// Sent exactly once per dispatched write, carrying only the incarnation it was
  /// dispatched for: every physical fact is already on that record, written by the
  /// job under the ledger lock. The driver's one job here is SCHEDULING — if the
  /// write's self-reap left the record parked as failed, stamp its retry deadline
  /// (the driver owns the clock).
  CookieWriteDone {
    id: CookieId,
  },
  /// A dispatched physical cookie UNLINK finished for incarnation `id`, which the
  /// job has already resolved on the record: `confirmed` = Ok / already gone (the
  /// record and its indexes are retired); `!confirmed` = transient failure (the
  /// record is parked `RemoveFailed`). As above, the driver only schedules — and a
  /// report whose incarnation has since been retired or re-armed touches nothing.
  CookieRemoveDone {
    id: CookieId,
    confirmed: bool,
  },
  /// A dispatched control batch reached an end — answered, unanswered, or never
  /// answered at all: the driver clears the scope's in-flight mark and submits its
  /// next queued batch, so a generation's batches run strictly one-at-a-time in
  /// emission order WITHOUT a pool worker ever blocking on another batch — the
  /// wait lives here, in the async loop, not on a parked blocking-pool thread.
  /// Emitted AFTER the batch's [`WatchInstalled`](OpResult::WatchInstalled)
  /// replies (same FIFO `op_tx`), so the driver has ingested every reply before it
  /// releases the successor; fs-driver-local, so `tributary-proto` is untouched.
  ControlBatchDone {
    scope: ScopeId,
    /// The transport generation this batch was emitted for, echoed back so the
    /// completion can be told from one belonging to a generation a replace has
    /// since retired.
    ///
    /// Scope alone cannot say that. A batch of a retired generation publishes
    /// nothing into the swapped scope, but it still completes eventually — and
    /// a completion read as the CURRENT batch's would clear a mark it does not
    /// own, release a successor twice over, and certify an ordering proof with
    /// a cut taken on a transport that no longer exists.
    generation: u64,
    /// The ordering-proof request this batch was carrying, if any.
    ///
    /// A completion keyed only by scope cannot say WHICH request it answers, and
    /// the scope's batches are a queue: a predecessor still recorded as running
    /// can complete after a proof request has already been queued and latched,
    /// and its cut — taken before that request existed — would license it. The
    /// token makes the completion self-identifying, so only the batch that
    /// actually carried the request can close it.
    cut_token: Option<u64>,
    /// How the batch ended: served, returned unserved, or never returned at all.
    ///
    /// The guard fires whether the call returns or unwinds, and a return says
    /// nothing by itself, so neither a panic on the pool nor a reader that died
    /// before replying can be read as a cut. The two of them are still not one
    /// fact — an unwind leaves the kernel state it may have half-written
    /// unknown, where an unserved return leaves nothing unknown at all — and the
    /// completion's terminal turns on that difference.
    end: ControlBatchEnd,
  },
}

/// The earlier of two optional deadlines (the core's timer and the earliest due
/// cookie retry), in proto-`Instant` space.
fn min_instant(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
  match (a, b) {
    (Some(a), Some(b)) => Some(a.min(b)),
    (a, b) => a.or(b),
  }
}

/// Dispatches every cookie-unlink retry whose deadline is at or before `now`
/// (T8): one O(ledger) scan under the lock, then each due incarnation routed
/// through the phase machine, which preserves the record's attempt count toward
/// the budget and drops the deadline with the transition out of `RemoveFailed`.
/// A record retired between the scan and its dispatch is a no-op — the deadline
/// rides the record, so it can never fire against another incarnation.
fn dispatch_due_cookie_retries<R, F>(
  cookies: &CookieRegistry<F>,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  now: Instant,
) where
  R: RuntimeLite,
  F: FsOps,
{
  let due: Vec<CookieId> = {
    let inner = lock_ledger(&cookies.ledger);
    inner
      .obligations
      .values()
      .filter(|ob| matches!(ob.phase, Phase::RemoveFailed { retry_at: Some(at), .. } if at <= now))
      .map(|ob| ob.id)
      .collect()
  };
  for id in due {
    cookies.request_removal::<R>(op_tx, RemovalRequest::RetryDue(id));
  }
}

/// The driver's WHOLE reaction to the public cleanup ingress: one pass over the
/// reap marks, servicing every request that has landed since the last pass.
///
/// The wake that triggers this carries no request — it only says "some bit
/// changed" — so the sweep re-reads the marks rather than a queue, and requests
/// against one record naturally coalesce into one action. It costs one O(ledger)
/// pass, which the global cap bounds, and it is self-limiting (each action clears
/// the mark that caused it), so the biased select's arm order stays a valid
/// starvation fence.
///
/// Both halves take the marks as their whole selection, so neither needs to be
/// told which request arrived:
///
/// - the PHYSICAL half dispatches an unlink for every marked record that has a
///   file and no removal already in flight;
/// - the PRE-PHYSICAL half retires every marked record still PARKED on its settle
///   fence, answering its barrier `Retired` and abandoning the fence — so a sync
///   cancelled before its write was ever dispatched creates no file at all, which
///   is the same refusal its claim would have made, one phase earlier.
fn sweep_reap_requests<R, F>(
  cookies: &CookieRegistry<F>,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  parked_cookies: &mut BTreeMap<FenceId, ParkedCookie>,
  core: &mut DriverCore,
) where
  R: RuntimeLite,
  F: FsOps,
{
  cookies.sweep_reap_marks::<R>(op_tx);
  retire_parked_cookies(core, parked_cookies, cookies, &|ob, _| ob.reap_requested);
}

/// Handles a `CookieRemoveDone` (§2.3), identical in the live arm and the close
/// drain. The unlink's verdict already landed on the record, in the job that
/// performed it, so this only SCHEDULES: a transient failure left the record
/// parked `RemoveFailed`, and the driver — the sole owner of the clock — stamps
/// its backed-off retry deadline, or leaves it parked past the budget (no
/// schedule, zero CPU). A confirm has nothing left to do. `flat` uses the flat
/// base delay during the close drain (the 1 s grace bounds attempts there).
fn on_cookie_remove_done<F: FsOps>(
  cookies: &CookieRegistry<F>,
  config: &DriverConfig,
  id: CookieId,
  confirmed: bool,
  now: Instant,
  flat: bool,
) {
  if confirmed {
    return;
  }
  cookies.schedule_retry(config, id, now, flat);
}

/// Runs one watcher's driver loop until `commands` closes or a `Close`
/// command arrives. Consumes the command receiver and the event sender; the
/// sender dropping is the consumer's end-of-stream.
///
/// `cleanup` is this driver's half of the cookie-cleanup ingress
/// ([`cookie_ingress`]): the ledger it shares with the watcher handle, and the
/// coalescing wake the handle rings after marking one of this driver's own
/// obligations. There is no cleanup QUEUE — a public reap or cancel is a
/// transition on an already-counted record, so it can neither be refused nor
/// accrue, whatever the command traffic or the runtime's scheduling.
pub(crate) async fn run<R, F>(
  config: DriverConfig,
  ops: F,
  commands: async_channel::Receiver<Command>,
  cleanup: CookieWake,
  events: async_channel::Sender<(ScopeId, Arc<PathBuf>, Change)>,
  registry: impl ScopeRegistry,
) where
  R: RuntimeLite,
  F: FsOps,
{
  // Secured BEFORE anything that could produce a stream. Retiring one JOINS its
  // reader — an unbounded wait that must never run on this task — and the reaper
  // is the only executor that can absorb it; see [`TeardownReaper`] for why
  // counting on the blocking pool being wide is not an option. A driver that
  // cannot get one has no honest way to retire what it would admit, so it admits
  // nothing: it returns here, before a single source exists, and the watcher
  // reads the closed command channel and ended event stream exactly as it reads
  // any dead driver.
  let Ok(reaper) = TeardownReaper::new() else {
    return;
  };
  let CookieWake {
    ledger,
    wake: reap_wake,
  } = cleanup;
  let mut core = DriverCore::new(
    config.effective_move_window(),
    config.root_liveness_interval,
  )
  .with_exclusions(config.exclusions.clone());
  let origin = R::now();
  let now = move || Instant::from_origin(R::now().duration_since(origin));
  // Unbounded so the blocking pool reports results with a plain `try_send`
  // (`send_blocking` does not exist on wasm builds, where async-channel has no
  // blocking API); the op volume is already bounded by outstanding operations
  // — one spawn/teardown per root plus one probe per parked batch item.
  //
  // The RECEIVER is guarded: a `Spawned` result carries a live stream, so a
  // queue that is dropped rather than read joins native readers wherever the
  // drop happens — see [`OpQueue`]. Everything below reads it through `op_rx`
  // exactly as before.
  let (op_tx, op_rx) = async_channel::unbounded::<OpResult<F::Handle>>();
  let op_queue = OpQueue {
    rx: op_rx,
    sink: reaper.sink(),
  };
  let op_rx = &op_queue.rx;
  // One lane per source: its single ordered queue, chased by a `None` end
  // marker — the receiver-disconnect fact itself, which a dropped sender
  // would otherwise erase silently.
  let mut os: SelectAll<
    futures_util::stream::BoxStream<'static, (ScopeId, u64, Option<SourceMessage>)>,
  > = SelectAll::new();
  // The guard keeps the SelectAll from ever emptying: an empty SelectAll
  // reports termination, which would spin the loop's stream arm.
  os.push(futures_util::stream::pending().boxed());
  // Both maps that can OWN a native stream live behind one guard, so an exit
  // that never reaches the orderly sweep below — a cancelled task, a runtime
  // shutting down, an unwind — still hands every stream to the reaper instead of
  // joining its reader on the runtime's own thread. See [`StreamReservoir`];
  // `handles` and `replace_states` below are its two fields, used exactly as the
  // plain locals they replace.
  let mut streams = StreamReservoir::<F::Handle>::new(reaper.sink());
  // Per-scope clones of the CURRENT lane's message channel, kept as PURE
  // OBSERVERS — never received from. A widen's catch-up commit
  // ([`SameFdPhase::CatchUp`]) reads `len()` once at `WidenArmed` for its
  // finite-prefix snapshot and `is_closed()` at the commit check for the
  // dead-lane wait; the messages themselves are consumed only by the source
  // arm, one per iteration, in its own frame. Re-bound at every lane swap
  // (`commit_replace`), removed with the stream at teardown.
  let mut source_taps: BTreeMap<ScopeId, EventReceiver> = BTreeMap::new();
  // Each spawned stream is one delivery LANE, tagged by a per-driver
  // generation: a scope's current lane is the one whose messages reach the
  // core. Today exactly one lane exists per scope for its whole life;
  // replace_root retires a lane and installs a successor under the SAME
  // scope, and a retired lane's stragglers are dropped here (dominated by
  // the replace commit's covering Rescan) — its end marker is not a death.
  let mut lanes: BTreeMap<ScopeId, u64> = BTreeMap::new();
  let mut next_lane: u64 = 0;
  // Off-loop work that owns — or is about to own — a native stream: spawns
  // dispatched to the blocking pool but not yet returned, teardowns handed to
  // `reaper` but not yet confirmed. Close quiesces BOTH alongside the live
  // handles: a spawn still in flight can otherwise start a native source after
  // the close reply, and an unconfirmed teardown is a stream still winding down.
  // Teardowns COUNT rather than flag: a replace can have the retired lane's
  // teardown in flight while the scope is live on its successor, so one scope may
  // owe several confirmations.
  let mut pending_spawns: BTreeSet<ScopeId> = BTreeSet::new();
  let mut pending_teardowns: BTreeMap<ScopeId, usize> = BTreeMap::new();
  // Teardowns whose `shutdown` UNWOUND. Their obligations are discharged — the
  // reaper is free, nothing is running — but no one proved the stream gone, so
  // close counts them and never reports `Ok` over one. Monotone for the driver's
  // life: an unproven teardown is never later proven.
  let mut unproven_teardowns: usize = 0;
  // WHICH scopes those teardowns belonged to. Close's count says only how MANY
  // streams were left unproven; an awaited unwatch has to answer per scope, and
  // must never report the proven-quiescent verdict for one of these — see
  // [`UnwatchAck::Unproven`]. Monotone alongside the count above.
  let mut unproven_scopes: BTreeSet<ScopeId> = BTreeSet::new();
  // Each live scope's committed backend — the commit-time profile gate: a
  // replacement whose spawn resolved to a different LOWERING PROFILE
  // (descending↔KR) is refused as BackendDiverged, because a live scope
  // never swaps lowering profiles.
  let mut scope_backends: BTreeMap<ScopeId, BackendKind> = BTreeMap::new();
  let mut watch_replies: BTreeMap<ScopeId, PendingWatch> = BTreeMap::new();
  // Descending-profile grants held between spawn success and the ROOT's
  // watch-result: the spawned source starts with no watches, so "live" — the
  // moment the public contract starts promising delivery — is the root arm,
  // not the fd. A grant here resolves at `WatchInstalled`, at stream
  // teardown (the scope died first), or by dropping at close (`Closed`).
  //
  // Membership is also the birth's BACKLOG RESERVATION for this phase — the
  // stream is running and the caller holds nothing yet, so a failed arm or a
  // cancelled `watch()` retires it into the counted teardown path (see
  // [`teardown_pressure`]).
  let mut deferred_grants: BTreeMap<ScopeId, DeferredGrant> = BTreeMap::new();
  // Each scope's CONTROL QUEUE: arm/disarm batches WAITING to dispatch behind
  // the scope's in-flight one, in emission (FIFO) order, each carrying the
  // transport generation it was emitted for. The batch currently RUNNING is
  // owned by its pool closure — not held here — so this queue holds only its
  // successors; `control_inflight` maps a scope to the GENERATION of its
  // running batch. The driver submits a scope's next batch only when the
  // running one's `ControlBatchDone` lands, so a generation's batches execute
  // strictly one-at-a-time in emission order (a disarm emitted after a re-add
  // can never run — and orphan the re-add's kernel watch + O_PATH anchor —
  // ahead of it) WITHOUT any blocking-pool worker ever parking to wait on
  // another batch: the wait is this driver-held queue, in the async loop, so
  // ordering is immune to the pool's start order and worker bound (a
  // worker-parked chain deadlocks a bounded, non-FIFO pool). Cross-scope
  // batches stay concurrent, and so do batches separated by a transport swap —
  // see [`kick_control_queue`] for why serializing across one would buy no
  // ordering and cost liveness. That release is only part of the liveness: it
  // frees the replacement's batches to be submitted, and what leaves the pool
  // with a worker for them to run on is that a retired transport occupies none —
  // nothing waits for its stuck batch (`ControlAnswer`) and its teardown joins on
  // `reaper` below. Both reclaimed at teardown
  // (scope ids are never reused); a completion for a torn-down scope finds
  // neither and is inert.
  // Mints one identity per ordering-proof request, so a completion can say which
  // request it answers. Monotone for the driver's life: a token is never reused,
  // so a stale completion can only ever fail to match.
  let mut cut_token_seq: u64 = 0;
  let mut pending_control: PendingControl = BTreeMap::new();
  let mut control_inflight: ControlInflight = BTreeMap::new();
  // Awaited unwatch replies parked until the scope is fully quiescent, each
  // paired with the verdict to send then: `true` for a live scope this
  // unwatch tears down, `false` (UnknownRoot) for a scope whose root already
  // died while a replacement was still resolving — the reply still waits for
  // that replacement's teardown, but reports the scope gone. A `RootHandle`
  // is `Copy`, so ONE scope can accrue several awaited unwatches (a second
  // arriving before the first quiesces); every waiter is kept and resolved
  // together — dropping one would surface to its caller as `Closed`, which
  // the watcher reads as driver death and would wrongly clear the registry.
  let mut unwatch_replies: BTreeMap<
    ScopeId,
    Vec<(futures_channel::oneshot::Sender<UnwatchAck>, UnwatchAck)>,
  > = BTreeMap::new();
  // Awaited set-cover acknowledgements parked under their settlement fences
  // (see `Command::SetCover`): resolved by `resolve_cover_settlements` at the
  // loop top once the scope's re-arm work quiesces, dropped at close (the
  // caller sees `Closed` through the dropped-reply mapping).
  let mut cover_replies: BTreeMap<FenceId, futures_channel::oneshot::Sender<CoverOutcome>> =
    BTreeMap::new();
  // Sync-cookie writes parked under the SAME settlement fences (see
  // `Command::SyncRoot`): the write dispatches to the blocking pool once the
  // scope's re-arm work quiesces, whatever the settle's verdict.
  let mut parked_cookies: BTreeMap<FenceId, ParkedCookie> = BTreeMap::new();
  // The OWNER of every cookie this driver writes, from its sync's ADMISSION —
  // before any file can exist — until that obligation earns a typed terminal, its
  // scope's stream tears down, or this local drops. Every gauge the cookie
  // lifecycle needs is a probe of this one ledger: the single-flight write gate,
  // the per-scope backlog, the global cap, the retry schedule, and the close
  // count. Ownership never rides the reply oneshot, so a caller that abandons its
  // sync cannot strand a file and no source-side removal queue is needed; the
  // orderly close sweeps owned cookies as tracked jobs, and the registry's `Drop`
  // reaps any remainder best-effort so a panicking or CANCELLED driver task still
  // cleans up.
  //
  // The ledger is the SHARED half of the cleanup ingress rather than this task's
  // private state: the watcher handle marks the records this registry admits, so
  // both are views on one store under one mutex — the same sharing shape the root
  // set has. It outlives this task inside the handle's `Arc`, which is inert: with
  // the driver gone, a mark lands on an empty ledger (the terminal sweep already
  // retired everything) and the wake `try_send` finds a closed channel.
  let mut cookies = CookieRegistry::new::<R>(ops.clone(), ledger);
  // Uncommitted watch grants unwind through here (see `WatchGrant`); the
  // driver keeps a sender so grants can always be minted, which is fine —
  // exit is driven by the COMMAND channel, and this receiver merely pends.
  let (unwind_tx, unwind_rx) = async_channel::unbounded::<ScopeId>();

  let close_reply = loop {
    execute_effects::<R, F>(
      &mut core,
      &ops,
      &config,
      &op_tx,
      &reaper,
      &mut streams.handles,
      &mut pending_spawns,
      &mut pending_teardowns,
      &mut scope_backends,
      &mut lanes,
      &mut source_taps,
      &events,
      &mut unwatch_replies,
      &mut deferred_grants,
      &mut pending_control,
      &mut control_inflight,
      &mut cookies,
      &registry,
      &now,
    );

    // Widen catch-up commits resolve HERE — strictly after the effect flush
    // above, which is load-bearing: the prefix's deliveries have already
    // reached the consumer at their pre-commit (old-root) coordinates, so
    // the root flip below can never precede a delivery it re-frames (G3-1
    // by construction; see `resolve_widen_catchups`).
    if resolve_widen_catchups::<R, F>(
      &mut core,
      &ops,
      &config,
      &op_tx,
      &reaper,
      &streams.handles,
      &mut pending_spawns,
      &pending_teardowns,
      &scope_backends,
      &source_taps,
      &mut streams.replace_states,
      &mut unwatch_replies,
      &mut parked_cookies,
      &mut cookies,
      &registry,
      &now,
    ) {
      // A commit just enqueued its own post-splice effects (the widened
      // root's cold-read enumerate above all) AFTER the flush above ran —
      // flush once more so a quiescent widen cannot park with the newly
      // covered ground stranded unread behind an already-resolved `Ok`.
      // Nothing between the first flush and the commit can enqueue an emit,
      // so this second flush carries only post-commit (new-world) effects —
      // the G3-1 pre/post ordering is untouched. Conditional: one extra
      // flush per RESOLVED widen, never a steady-state cost.
      execute_effects::<R, F>(
        &mut core,
        &ops,
        &config,
        &op_tx,
        &reaper,
        &mut streams.handles,
        &mut pending_spawns,
        &mut pending_teardowns,
        &mut scope_backends,
        &mut lanes,
        &mut source_taps,
        &events,
        &mut unwatch_replies,
        &mut deferred_grants,
        &mut pending_control,
        &mut control_inflight,
        &mut cookies,
        &registry,
        &now,
      );
    }

    // Service any cookie-unlink retries now due, opportunistically at the loop
    // top so a busy loop that never parks still drives them promptly (T8) — the
    // belt-and-suspenders the timer arm below shares.
    dispatch_due_cookie_retries::<R, F>(&cookies, &op_tx, now());

    // Fairness for the cleanup ingress: the select below is command-biased (it
    // polls `commands` before the wake), so a caller that keeps the bounded
    // command mailbox continuously ready would otherwise STARVE cleanup and leave
    // cookies lingering owned. Consuming a PENDING wake here, every iteration,
    // guarantees cleanup makes steady progress whatever the command load, while
    // preserving the command/close priority the biased select gives. Cheap by
    // construction: no wake pending means no request has landed since the last
    // sweep, so this is one non-blocking probe.
    if reap_wake.try_recv().is_ok() {
      sweep_reap_requests::<R, F>(&cookies, &op_tx, &mut parked_cookies, &mut core);
    }

    // The settle observation's loss fence. Loss signals ride the source
    // queue while the arm ACKs that quiesce a barrier ride `op_rx`, and the
    // two are UNORDERED: a source that elects a loss and then answers an arm
    // batch (an inotify instance rebuild enqueues its whole-instance
    // `Overflow`, swaps the fd, and only then replies to the very batch that
    // tripped it) has its ACKs ingested by the op-first select while the
    // loss is still queued — the stamp rule cannot refuse them (it compares
    // against the INGESTED generation), so without this fence the
    // observation below would certify `Applied` over bindings that loss
    // voided, an uncorrectable oneshot. The fence: when — and only when — an
    // observation is due, ingest everything the source had ALREADY queued at
    // drain start, so any such loss lands first (the fence turns lossy, the
    // reprove re-holds the barrier) and only arrivals genuinely after that
    // instant can trail the verdict. The bound is the [`SourceSnapshot`]
    // taken here — per-lane drain-start content, the catch-up commit's own
    // snapshot discipline — so a producer re-enqueuing between every poll
    // pair stretches a pass by the fair-interleave factor at most, never
    // into an unbounded run deferring the resolve and the select below; a
    // genuinely backlogged queue is instead worked down across re-topped
    // passes with the resolution, effect flushes, and commands interleaved.
    // The queued loss is inside the snapshot BY the fence's own ordering —
    // it was enqueued before the settling ACK, which was ingested before
    // this observation came due — so the cap can only ever exclude
    // post-settle arrivals, and a single `Pending` poll when nothing is
    // queued keeps the fence inert; the select's starvation fences (ops over
    // commands over the stream) are untouched everywhere else.
    // What the drain LEFT is what gates the resolve below, and it is deliberately
    // not the same fact as `drained`. A `Pending` poll is NOT proof the counted
    // items are gone: the merged stream is a `FuturesUnordered` fan-in, which may
    // legally answer `Pending` while a ready item exists — a concurrent wake that
    // lands mid-poll is enqueued for a LATER poll, and `poll!` takes only one. So
    // an item counted in this snapshot can still be resident when the loop breaks,
    // and no live verdict for its scope may rest on a lane nobody finished
    // reading: a clean one would mint a false certificate over a loss the fence's
    // own ordering placed INSIDE the snapshot, omitting its `Rescan`, and a lossy
    // one would answer its caller — dispatching a parked cookie write — over a
    // terminal `Fatal` that may be sitting in exactly those unread items.
    //
    // Per SCOPE, because the residue is per lane: `SourceSnapshot` budgets every
    // live scope's lane separately, so one busy scope's backlog defers only its
    // own windows and never a neighbour's. Deaths are unaffected either way — a
    // teardown fold resolves through the core's already-settled list, which no
    // deferral touches. The snapshot is retaken every pass, so the deferral cannot
    // outlive the residue that caused it.
    let mut source_unspent = BTreeSet::new();
    // The adoption seal arms the same fence for a stronger reason than the
    // settle observation does. A cover settlement guards against resolving over
    // a queued loss; the seal's entire purpose is to take its verdict AFTER a
    // record the cut has just forwarded onto this lane, so a seal resolved over
    // an undrained lane would resolve over exactly the evidence its round trip
    // was bought to surface.
    let lane_of = |scope: ScopeId| lanes.get(&scope).copied().unwrap_or(u64::MAX);
    let observed_over_drained_source =
      (core.cover_settlement_due() || core.adoption_seal_due(&lane_of)) && {
        let mut snapshot = SourceSnapshot::taken(&lanes, &source_taps);
        let mut drained = false;
        while !snapshot.spent() {
          let core::task::Poll::Ready(Some(item)) = futures_util::poll!(os.next()) else {
            break;
          };
          snapshot.consume(item.0, item.1);
          ingest_source_item::<F>(
            &mut core,
            &lanes,
            &mut streams.replace_states,
            &streams.handles,
            item,
            &now,
          );
          drained = true;
        }
        source_unspent = snapshot.unspent_scopes();
        drained
      };

    // The adoption seal resolves ABOVE both demand loops, because it is the one
    // thing in this pass that can RELEASE the coverage barrier. Every other
    // release happens at an ingest, whose own select arm re-tops the loop and
    // brings the demand below back around; this one happens here, so a fence
    // offered before it would be judged against a barrier the very next line was
    // about to settle — and with nothing left to ingest, the loop would then park
    // with the fence owing a cut nobody had asked for.
    //
    // Resolving first costs the settlement below nothing: a seal can only fire
    // when `adoption_seal_due` armed the drain above, so the per-lane withholding
    // the settlement reads was computed under exactly the fence a release-in-this-
    // pass needs.
    core.resolve_adoption_seals(&lane_of, &source_unspent);

    // Set-cover settlements resolve at this one choke point — after the
    // previous arm's results fed the core and their effects drained, BEFORE
    // any new command is processed — so a lossy settle's `applied_cover`
    // rewind always lands before the next reconcile computes its broadening
    // delta, and a teardown-folded `Dead` is delivered promptly. The
    // barrier predicate and the loss memory this resolution reads are fed
    // synchronously by the drain above, so resolving ahead of the drained
    // items' effect flush stays honest — but only for the scopes the drain
    // actually finished, which is what `source_unspent` withholds.
    // A quiesced barrier has proven its coverage was rebuilt, not that the
    // kernel had nothing queued while it was: the terminal proof is routinely an
    // enumerate, which completes on the blocking pool and never crosses the
    // reader, and a re-issued or pruning cover can quiesce with no counted work
    // at all. Either way a record the kernel has committed but nobody has read
    // yet sits in NO lane, so the drain above reads spent and would resolve over
    // it.
    //
    // One empty batch per such fence closes it, using the cut the reader
    // already performs before answering any batch — so the ordering is bought
    // by the round trip, not by anything the batch carries, and no new reader
    // mechanism appears. It rides `pending_control`, so it keeps per-scope
    // emission order behind whatever arms are already queued; the reply flips
    // the fence at `ControlBatchDone` and the next pass certifies honestly.
    // Asked once per WINDOW, not per fence: a reconcile extending the window and
    // a fence joining it both reset the latch, and the scope's coverage-work
    // epoch moving retires whatever it holds, so a proof never outlives the work
    // it ordered. Asked for a LOSSY window too — the cut surfaces an unread
    // death, which a degraded verdict is as vulnerable to as a clean one, and
    // which its cookie dispatch would otherwise be answered over. Never asked
    // for a scope whose stream is gone. Those invalidations are also what makes
    // the enqueue below COALESCE rather than append — see [`queue_cut_proof`].
    for scope in core.covers_awaiting_cut() {
      // A stream that is already gone has nothing to ask, and latching a request
      // no batch carries would park the fence on a reply that never comes. Skip
      // it unlatched — it reappears next pass, and if the scope stays gone its
      // teardown folds the fence rather than leaving it waiting.
      if !streams.handles.contains_key(&scope) {
        continue;
      }
      let lane = lanes.get(&scope).copied().unwrap_or(u64::MAX);
      cut_token_seq += 1;
      let token = cut_token_seq;
      queue_cut_proof(&mut pending_control, scope, lane, token);
      core.mark_cut_inflight(scope, token);
      kick_control_queue::<R, F>(
        &ops,
        &op_tx,
        &mut pending_control,
        &mut control_inflight,
        &lanes,
        scope,
      );
    }
    // The adoption seal's own demand, on the same primitive and the same empty
    // batch. It never collides with the fence's demand above: a staged marker
    // holds `Monitor::coverage_settled` down, and `covers_awaiting_cut` offers
    // only a scope whose barrier has settled — so no scope can be offered both
    // in one pass, and the two latches never contend for one token. Nor can this
    // enqueue discard a cover fence's still-live queued proof: a marker can only
    // have been recorded since that proof was queued (a standing marker would
    // have kept the fence from being offered), and recording one ACQUIRES
    // coverage work, whose epoch bump has already retired the fence's latch —
    // which is precisely the condition under which `queue_cut_proof` calls a
    // queued entry obsolete.
    for scope in core.adoptions_awaiting_cut(&lane_of) {
      // A stream that is already gone has nothing to ask, exactly as above.
      if !streams.handles.contains_key(&scope) {
        continue;
      }
      let lane = lane_of(scope);
      cut_token_seq += 1;
      let token = cut_token_seq;
      queue_cut_proof(&mut pending_control, scope, lane, token);
      core.mark_adoption_cut_inflight(scope, lane, token);
      kick_control_queue::<R, F>(
        &ops,
        &op_tx,
        &mut pending_control,
        &mut control_inflight,
        &lanes,
        scope,
      );
    }
    let cover_flush_due = resolve_cover_settlements::<R, F>(
      &mut core,
      &ops,
      &op_tx,
      &mut cover_replies,
      &mut parked_cookies,
      &mut cookies,
      &|scope| streams.handles.contains_key(&scope),
      SettlePass::Live {
        unspent: &source_unspent,
      },
    );
    // Reclaim canceled awaited-unwatch waiters at the same choke point, so an
    // issue-and-cancel storm against a stalled scope cannot grow its waiter
    // vector without bound.
    prune_canceled_unwatch_waiters(&mut unwatch_replies);

    // A settlement stood the covering `Rescan` a standing classification stat
    // owes and held its tranche for it: RE-TOP, so the loop-top flush OFFERS
    // that `Rescan` to the consumer's stream before any pass answers the caller
    // with the degraded verdict it covers. Nothing external would bring the loop
    // back for it — the tranche is licensed and its barrier is settled, so no
    // arm, no read and no reply is outstanding on its behalf.
    //
    // The bounded-service invariant below is discharged by the per-tranche latch
    // this flag reports: only the pass that STANDS a cover raises it, so the
    // re-top run is ONE pass — commands (`Close` above all), op completions,
    // grant unwinds and the deadline each wait at most that. A cover the flush
    // then finds the channel too full to take does NOT raise it again: that
    // tranche waits on the scope's delivery retry, which the deadline below
    // already carries, and defers through the passes in between.
    if cover_flush_due {
      continue;
    }

    // The deadline is computed HERE, above both source-drain re-tops, because
    // the bounded-service gate below has to see a DUE one. Nothing between
    // this point and the `sleep_until` that consumes it feeds the core: the
    // catch-up poll re-tops instead of falling through, so a pass that reaches
    // the timer has ingested nothing since this read. Both arms live in proto-
    // `Instant` space; the runtime conversion happens once, at the arm.
    let due_at = min_instant(core.poll_timeout(), cookies.min_retry_at());

    // THE BOUNDED-SERVICE INVARIANT, which both source-drain phases below owe:
    // internal completions (`op_rx`), grant unwinds, commands, and the deadline
    // are serviced within a BOUNDED number of source-drain passes — no
    // `continue` re-top may loop indefinitely while one of them is pending. The
    // select is the ONLY consumer of all four, so every re-top defers them; a
    // pass of either phase is finite, but a SEQUENCE of passes is not, and an
    // unconditional re-top under a producer that keeps any lane ready defers
    // them forever. The two phases discharge the invariant differently, each
    // the way its own resolution works:
    //
    // - the loss fence's drain (immediately below) re-tops only while NOTHING
    //   is ready here, so its bound is ONE further pass. Its resolution is an
    //   internal completion, so a readiness gate is exactly right: the phase
    //   cannot progress by re-topping past the very input it waits for.
    // - the widen catch-up's forced poll (further below) is bounded instead by
    //   its own finite work — a prefix snapshot and a closed lane's finite tail
    //   — and is armed on MEMBERSHIP in the phase, so no wait sub-state can be
    //   missed. It must NOT yield to a ready command: it exists because a
    //   saturated command mailbox keeps the select off the source arm (G4-1).
    //
    // Every disjunct below makes a select arm ready by construction — this loop
    // is the sole consumer of all three channels, a closed command channel
    // makes `recv` return `Err` (the orderly-exit edge, which an emptiness test
    // alone would miss), and an elapsed `sleep_until` completes on its first
    // poll — so the select cannot park in this state: it services the
    // highest-priority ready arm and the loop re-tops with the drained items'
    // effects flushed. The arm order (ops over commands over the stream) is
    // untouched. The cleanup wake needs no disjunct: the loop top probes and
    // sweeps it every pass already, re-top or not.
    //
    // Barrier honesty is NOT weakened by bounding the re-tops, because this
    // gate is consulted strictly AFTER the drain and the resolve it protects.
    // Every pass in which a settlement is due still (a) takes a fresh per-lane
    // snapshot and drains it to exhaustion, then (b) resolves — in that order,
    // unconditionally. A loss enqueued before the ACK that made the settlement
    // due is therefore queued at every such pass's drain start, inside its
    // snapshot, and ingested ahead of the verdict. What this gate changes is
    // only what happens after the resolve: whether the pass re-tops or lets
    // the select run first. No clean resolve can move earlier than the drain
    // that covers it.
    let service_ready = !op_rx.is_empty()
      || !unwind_rx.is_empty()
      || !commands.is_empty()
      || commands.is_closed()
      || due_at.is_some_and(|at| at <= now());

    // Anything the loss fence drained left its effects queued and may have
    // consumed a widen's awaited prefix tail: RE-TOP — exactly the catch-up
    // poll's flush discipline — so `execute_effects` and the commit check run
    // before the loop can park on them. Bounded by the invariant above: each
    // pass consumes real queued input, and the re-top yields to the select the
    // moment anything is ready there — so the arm ACKs and re-arm reads this
    // fence's own clean settle waits for, the `SetCover` / `SyncRoot` reply it
    // gates, `Close`, and the deadline are each serviced within one further
    // pass, whatever the lane traffic.
    //
    // ARGUED, NOT PINNED — no cell proves the following; it is a reading of the
    // code, recorded so a future reader can attack it rather than inherit it as
    // fact. With the settle-edge observation gate retired, the re-top appears to
    // be defence-in-depth rather than a liveness necessity: `cover_settlement_due`
    // is `cover_fences.keys().any(|scope| barrier_settled(*scope))`, so arming
    // requires a fence whose barrier is ALREADY settled; and every path that
    // opens a NEW fence (`SetCover`, `SyncRoot`, the cookie claim) arrives
    // through the select this re-top skips, so nothing inside a re-top run can
    // arm it afresh.
    //
    // What the resolve does with an armed fence is now two-valued, and only one
    // branch clears it: a fence still awaiting its ordering proof is DEFERRED
    // with its entry intact, so `cover_settlement_due` stays armed across the
    // passes that proof takes. That does not restore the necessity — a deferred
    // fence arms the drain but the drain re-tops only on freshly DRAINED input,
    // and a deferral drains nothing — but it does mean the re-top is no longer
    // one-pass-bounded by the resolve alone. The gate is kept because it is
    // correct and cheap, and because it states the accepted property directly —
    // not because the argument above is proven.
    if observed_over_drained_source && !service_ready {
      continue;
    }

    // Catch-up fairness (G4-1, predicate exactness G5-1): a catching-up
    // widen resolves only through source-arm progress, but the select below
    // polls COMMANDS before the source stream — a caller keeping the
    // bounded command mailbox continuously ready (the documented,
    // test-pinned capability: `command_flood_does_not_starve_op_completions`)
    // would then starve it forever: the widen never resolves, its reply
    // never fires, and the stuck ReplaceState pins the single-flight gate
    // and the root reservation. The guarantee: while any scope is STILL IN
    // CatchUp after the resolver above ran, ONE ready source item is
    // ingested here per iteration — through the same `ingest_source_item`
    // frame the arm uses (latch, ledger, end marker) — and the loop RE-TOPS
    // instead of selecting, so the item's effects flush and the commit
    // check runs before anything can park (without the re-top, consuming
    // the LAST awaited item here would park the loop under quiescence with
    // the resolution forever pending).
    //
    // The arming predicate is membership in CatchUp itself — never a
    // refinement of it. The resolver just removed every scope whose
    // resolution needs NO further source progress (`remaining == 0` on an
    // open lane commits; a dead scope retires), so a scope still in the
    // phase is, exhaustively, either draining its prefix
    // (`remaining > 0`) or awaiting a closed lane's end marker
    // (`remaining == 0`, tap closed — the marker routes `on_source_fatal`
    // and the NEXT resolver pass retires it): both need exactly this poll.
    // Arming on membership rather than on `remaining > 0` closes the
    // closed-tail wedge (a flood starving the end marker) BY CONSTRUCTION:
    // any wait sub-state the phase could ever grow is in the phase, so it
    // is armed — there is no refinement left to miss. One message per
    // fully-flushed iteration — never a synchronous drain (G2-2) — and
    // every message still crosses the taint latch before `remaining` can
    // reach zero (INV-ROOT's prefix-before-commit ordering). The explicit
    // bound: the poll runs a bounded number of flushed iterations — on the
    // order of N × ready lanes for a prefix of N (the merged stream
    // interleaves lanes fairly), plus a closed lane's FINITE tail (no
    // sender exists, so it cannot be re-fed) — because post-snapshot
    // arrivals never extend `remaining` and the poll self-disarms the
    // moment the resolver removes the phase. Commands — Close above all —
    // therefore wait at most that same bounded run, and the normal
    // command-over-source bias resumes at the resolution.
    //
    // This is that invariant's phase-2 discharge: the bound is the finite
    // prefix plus a closed lane's finite tail, and the predicate is
    // deliberately un-refined so no wait sub-state can be missed.
    let catching_up = streams.replace_states.values().any(|state| {
      matches!(
        &state.mode,
        ReplaceMode::SameFd {
          phase: SameFdPhase::CatchUp { .. }
        }
      )
    });
    if catching_up && let core::task::Poll::Ready(Some(item)) = futures_util::poll!(os.next()) {
      ingest_source_item::<F>(
        &mut core,
        &lanes,
        &mut streams.replace_states,
        &streams.handles,
        item,
        &now,
      );
      continue;
    }

    // The one deadline arm serves BOTH the core's timer and the earliest due
    // cookie-unlink retry: an IDLE driver with one `RemoveFailed` cookie would
    // otherwise park forever and never retry (finding 3). Their min was taken
    // above the re-top gate (which needs to see a DUE deadline) in proto-
    // `Instant` space; convert it once, here, for `sleep_until`.
    let deadline = due_at.map(|d| origin + d.elapsed_since_origin());
    let timer = async {
      match deadline {
        Some(at) => {
          R::sleep_until(at).await;
        }
        None => futures_util::future::pending::<()>().await,
      }
    }
    .fuse();
    futures_util::pin_mut!(timer);

    // Arm order is the starvation fence: INTERNAL, self-limiting inputs drain
    // before externally replenishable ones. Op results and grant unwinds are
    // completions of work this loop itself dispatched (bounded by what is
    // outstanding), and the core deadline only fires at instants the core armed
    // and re-arms strictly later — none can stay ready forever, so polling them
    // first cannot starve the later arms. The COMMAND channel can: a saturated,
    // continuously-refilled mailbox keeps a command-first order permanently
    // ready, so arm/enumerate completions are never consumed, scopes never
    // settle, and every reconciled SetCover appends fence + reply state without
    // bound. Commands still outrank the source-event stream (the one order that
    // is load-bearing the other way): events are budget-backpressured but
    // effectively endless, and Close arrives on the command channel.
    futures_util::select_biased! {
      res = op_rx.recv().fuse() => {
        match res.expect("the driver holds a sender") {
          OpResult::Spawned { scope, result } => {
            pending_spawns.remove(&scope);
            if streams.replace_states.contains_key(&scope) {
              // Escrowed at the dequeue, exactly as the birth arm below does:
              // every refusal check, the commit and the pre-arm handoff run with
              // the stream inside a guard rather than beside one.
              let spawned = match result {
                Ok(spawned) => EscrowedSpawn::new(spawned, reaper.sink()),
                Err(failure) => {
                  // A barrier that failed AFTER starting its stream hands the
                  // running stream back rather than tearing it down where no
                  // accounting could hear the verdict. Retiring it here is what
                  // makes an unproven rollback reach `TeardownFailed`, count
                  // against the backlog, and hold `close` honest.
                  let (err, rollback) = escrow_failure(failure, reaper.sink());
                  if let Some(stream) = rollback {
                    stream.retire(&reaper, &op_tx, &mut pending_teardowns, scope);
                  }
                  let replace = streams.replace_states.remove(&scope).expect("just checked");
                  drop(replace.reservation);
                  let _ = replace
                    .reply
                    .send(Err(crate::error::ReplaceRootError::Source(err)));
                  // A failed replacement spawn that started NOTHING is the one
                  // resolution that enqueues no teardown, so a concurrent
                  // unwatch waiting on this scope would never be re-checked by a
                  // TornDown — resolve it here if the failed spawn was the last
                  // obligation. Every other resolution, including a failure that
                  // just retired its rollback above, ends in a counted teardown
                  // whose terminal re-checks (the fence sees that entry and
                  // waits).
                  if scope_quiesced(
                    scope,
                    &streams.handles,
                    &pending_spawns,
                    &pending_teardowns,
                    &streams.replace_states,
                  ) {
                    resolve_unwatch_waiters(&mut unwatch_replies, scope);
                  }
                  continue;
                }
              };
              // Death wins, and a live scope never swaps lowering profiles —
              // both refusals land BEFORE any commit or pre-arm.
              let backend = spawned.meta.backend;
              let old_kr = scope_backends
                .get(&scope)
                .is_some_and(BackendKind::is_kernel_recursive);
              let refusal = if !streams.handles.contains_key(&scope) {
                Some(crate::error::ReplaceRootError::Retired)
              } else if old_kr != backend.is_kernel_recursive() {
                Some(crate::error::ReplaceRootError::BackendDiverged)
              } else {
                None
              };
              if let Some(err) = refusal {
                let replace = streams.replace_states.remove(&scope).expect("just checked");
                retire_refused::<F>(&op_tx, &reaper, &mut pending_teardowns, scope, spawned);
                drop(replace.reservation);
                let _ = replace.reply.send(Err(err));
                continue;
              }
              if backend.is_kernel_recursive() {
                let replace = streams.replace_states.remove(&scope).expect("just checked");
                let widened = spawned.meta.root.clone();
                let outcome = commit_replace::<F>(
                  &mut core,
                  &ops,
                  &op_tx,
                  &reaper,
                  &mut streams.handles,
                  &mut lanes,
                  &mut next_lane,
                  &mut pending_teardowns,
                  &mut os,
                  &mut source_taps,
                  &registry,
                  &cookies,
                  scope,
                  spawned,
                  replace.reservation.path(),
                  None,
                  &now,
                );
                if let Ok(backend) = &outcome {
                  scope_backends.insert(scope, *backend);
                  // Any barrier still parked under coverage the new root has
                  // moved out from under is revoked BEFORE the commit records the
                  // new root; the generation that revokes writes already in the
                  // pool under the old root was bumped inside `commit_replace`, at
                  // the lane swap. This only RE-records the cookie floor for the
                  // widened root.
                  revoke_uncovered_parked_cookies(&mut core, &mut parked_cookies, &cookies, scope, &widened);
                  cookies.scope_live(scope, widened);
                }
                // The reservation releases HERE — commit or failure alike —
                // after the registry overwrite (commit) has already made the
                // new coverage visible, so the path is covered continuously.
                drop(replace.reservation);
                let _ = replace.reply.send(outcome.map(|_| ()));
                continue;
              }
              // Descending: arm the new root on the NEW transport first; the
              // commit (or unwind) rides the outcome. The scope's port table
              // still routes to the OLD stream, so the arm goes through the
              // explicit-port seam.
              let Some(watch) = core.root_watch(scope) else {
                // The handle map says live but the core disagrees — refuse
                // without committing anything.
                let replace = streams.replace_states.remove(&scope).expect("just checked");
                retire_refused::<F>(&op_tx, &reaper, &mut pending_teardowns, scope, spawned);
                drop(replace.reservation);
                let _ = replace
                  .reply
                  .send(Err(crate::error::ReplaceRootError::Retired));
                continue;
              };
              let port = spawned.handle().scope_port();
              let path = spawned.meta.root.clone();
              // The same object confirmation the birth root arm carries: the
              // spawn barrier read the identity; the arm confirms the opened
              // object still is it.
              let name = Segment::new(
                path
                  .file_name()
                  .and_then(|name| name.to_str())
                  .unwrap_or("/"),
              );
              let expected = u64::try_from(spawned.meta.identity.ino())
                .ok()
                .and_then(core::num::NonZeroU64::new)
                .map(|ino| ExpectedObject {
                  dev: spawned.meta.identity.dev(),
                  ino,
                });
              match &mut streams.replace_states.get_mut(&scope).expect("just checked").mode {
                // The slot is borrowed BEFORE the escrow is consumed, so the
                // lookup and its `expect` are still on the guarded side.
                ReplaceMode::NewFd { arming } => spawned.park(arming),
                ReplaceMode::SameFd { .. } => {
                  // Unreachable: the widen route never dispatches a spawn.
                  // Retire the stray stream defensively rather than leak it.
                  debug_assert!(false, "a same-transport widen spawns nothing");
                  retire_refused::<F>(&op_tx, &reaper, &mut pending_teardowns, scope, spawned);
                  continue;
                }
              }
              let ops_for_arm = ops.clone();
              let tx = op_tx.clone();
              R::spawn_blocking_detach(move || {
                let outcome =
                  ops_for_arm.preflight_arm(&port, scope, watch, &path, &name, expected);
                let _ = tx.try_send(OpResult::RebindArmed { scope, outcome });
              });
              continue;
            }
            match result {
            Ok(spawned) => {
              // Escrowed the instant it leaves the result, and disarmed only by
              // the commit into `streams.handles` or the retirement below: the
              // conflict check and the port attach between them are caller code
              // and a lock the backend can leave poisoned, either of which can
              // unwind past a plain local (see [`StreamEscrow`]).
              let EscrowedSpawn { stream, receiver, meta } =
                EscrowedSpawn::new(spawned, reaper.sink());
              let canonical_root = meta.root.clone();
              let identity = meta.identity;
              let ancestors = meta.ancestors.clone();
              let backend = meta.backend;
              let pending = watch_replies.remove(&scope);
              // FINAL-ROOT REVALIDATION: the backend re-canonicalizes during
              // spawn, so the root the stream actually watches can differ
              // from the path the watcher reserved (a symlink retargeted, a
              // directory replaced mid-flight). The reservation vouched only
              // for the form it held; this check — on the registry's single
              // writer, immediately before the scope would go live — is the
              // authority on the final root's disjointness, and it compares
              // object identities so a spelling alias cannot slip past it.
              if let Some(existing) = registry.final_root_conflict(
                &canonical_root,
                identity,
                &ancestors,
                pending.as_ref().map(|p| p.requested.as_path()),
                None,
              ) {
                // Never goes live: tear the fresh stream down inside the
                // pending accounting and end the scope like a failed spawn.
                stream.retire(&reaper, &op_tx, &mut pending_teardowns, scope);
                core.on_spawn_rejected(scope);
                if let Some(pending) = pending {
                  let _ = pending.reply.send(Err(WatchRootError::Overlaps {
                    path: canonical_root,
                    existing,
                  }));
                }
              } else {
                core.on_stream_spawned(scope, Ok(meta));
                // Mint the transport generation (the delivery lane) FIRST so
                // the port attaches under it: the descending root's first
                // AddWatch is dispatched carrying this same generation.
                let lane = next_lane;
                next_lane += 1;
                lanes.insert(scope, lane);
                // The arm/disarm port attaches before any effect of this
                // spawn can execute, so a descending root's first AddWatch
                // always finds its scope routed under the current generation.
                // It runs against the ESCROWED stream: the ordering is
                // load-bearing and the call can unwind, so the handle is read
                // through the guard rather than parked beside it.
                ops.attach_scope(scope, stream.get().scope_port(), lane);
                // The live stats handle (fanotify only) is captured before the
                // handle is stored, so the registry can hand a `backend_stats`
                // query the same counters the reader writes.
                let stats = stream.get().backend_stats();
                stream.commit(&mut streams.handles, scope);
                source_taps.insert(scope, receiver.clone());
                os.push(
                  receiver
                    .map(move |msg| (scope, lane, Some(msg)))
                    .chain(futures_util::stream::once(async move {
                      (scope, lane, None)
                    }))
                    .boxed(),
                );
                // The registry learns the scope is live BEFORE the grant can
                // reach the watcher: both registry transitions then execute on
                // this task in program order, so a death signal processed
                // later can never be overtaken by this insert — the
                // insert-after-remove race has no actors left to run it. A
                // scope dying before the caller polls its grant simply yields
                // a dead-on-arrival handle.
                registry.scope_live(scope, &canonical_root, identity, &ancestors, backend, stats);
                scope_backends.insert(scope, backend);
                // The cookie floor travels with the stream: a sync for this
                // scope may write inside this root, never above it.
                cookies.scope_live(scope, canonical_root.clone());
                match backend {
                  // Descending: the stream is live but covers NOTHING until
                  // the root's kernel watch arms; the grant defers to the
                  // root's watch-result so the public "from resolve, every
                  // change is delivered" bracket holds.
                  BackendKind::Inotify => {
                    if let Some(pending) = pending {
                      deferred_grants.insert(scope, DeferredGrant {
                        pending,
                        root: canonical_root,
                      });
                    } else {
                      // The watch() future was already cancelled: immediate
                      // unwatch, exactly like a refused inline grant.
                      core.on_unwatch(scope);
                    }
                  }
                  // Kernel-recursive: the live stream IS the coverage, so the
                  // grant commits inline. fanotify's superblock mark and the
                  // Windows primitives' subtree streams cover the whole root
                  // exactly like FSEvents.
                  BackendKind::FsEvents
                  | BackendKind::Fanotify
                  | BackendKind::Rdcw
                  | BackendKind::UsnJournal => {
                    let owned = match pending {
                      Some(pending) => {
                        commit_grant(pending, scope, canonical_root, &unwind_tx)
                      }
                      None => false,
                    };
                    if !owned {
                      // The watch() future was cancelled before the reply
                      // could hand ownership over: tear the just-spawned
                      // stream down as an immediate unwatch. (Cancellation
                      // AFTER a successful send is the grant's unwind.)
                      core.on_unwatch(scope);
                    }
                  }
                }
              }
            }
            Err(failure) => {
              // The rollback of a barrier that failed post-live is retired
              // BEFORE the scope is resolved, and inside the same counted
              // accounting a committed stream uses. The earlier shape let the
              // barrier shut its own stream down and threw the verdict away, on
              // the reasoning that a failing spawn owns no scope and owes no
              // obligation — but a rollback that could not prove its pinned I/O
              // ended retains a buffer and a handle, and the scope not existing
              // never made that state stop existing. Routed here it becomes a
              // `TeardownFailed` like any other: counted against
              // [`MAX_TEARDOWN_BACKLOG`], latched against the scope, and refused
              // over by `close`.
              let (err, rollback) = escrow_failure(failure, reaper.sink());
              if let Some(stream) = rollback {
                stream.retire(&reaper, &op_tx, &mut pending_teardowns, scope);
              }
              core.on_stream_spawned(scope, Err(clone_error(&err)));
              if let Some(pending) = watch_replies.remove(&scope) {
                // A spawn-side kind rejection keeps the public contract's
                // vocabulary: the caller asked to watch a directory and the
                // final root is not one.
                let reply = match err {
                  SourceError::NotADirectory { root } => {
                    WatchRootError::NotADirectory { path: root }
                  }
                  err => WatchRootError::Source(err),
                };
                let _ = pending.reply.send(Err(reply));
              }
            }
          }},
          OpResult::Probed { probe, outcome } => core.on_probe_result(probe, outcome, now()),
          OpResult::MountsRefreshed { scope, refresh } => {
            core.on_mounts_refreshed(scope, refresh, now())
          }
          OpResult::WatchInstalled {
            watch,
            attempt,
            outcome,
            scope,
            generation,
          } => {
          // A deferred registration grant riding on this arm resolves FIRST —
          // before the stale-transport fence below: grant ownership is
          // scope-keyed, not lane-keyed, and the caller's registration future
          // has exactly this reply to wait on — fencing it would strand the
          // future forever, while answering it with a superseded arm's outcome
          // is honest (an `Err` is a retryable refusal; an `Ok` commits a
          // handle whose world the swap already re-arms). A failed root arm
          // answering here also precedes the core's teardown effects, which
          // would otherwise answer the caller again. A deferred scope has no
          // children yet (nothing enumerates before the root is live), so any
          // arm landing on it IS the root's.
          let deferred_scope = core
            .scope_of_watch(watch)
            .filter(|scope| deferred_grants.contains_key(scope));
          if let Some(scope) = deferred_scope {
            let DeferredGrant { pending, root } =
              deferred_grants.remove(&scope).expect("scope found above");
            match outcome {
              WatchOutcome::Installed(_) | WatchOutcome::Aliased(_) => {
                if !commit_grant(pending, scope, root, &unwind_tx) {
                  core.on_unwatch(scope);
                }
              }
              WatchOutcome::Failed(err) => {
                let _ = pending.reply.send(Err(arm_grant_error(err, pending.requested, root)));
              }
            }
          }
          // STALE-TRANSPORT FENCE, reply side (the dispatch-side twin lives in
          // `batch_control`'s front-check): a reply whose generation no longer
          // matches the scope's current lane answered against a transport a
          // replace has since retired. Everything it says is old-world — above
          // all a synthesized `Failed` for the ROOT, whose `WatchId` survives
          // the rebind, which would invalidate the fresh world it never
          // touched. A same-transport widen swaps no lane, so its in-flight
          // re-adds pass untouched.
          if lanes.get(&scope).copied() != Some(generation) {
            continue;
          }
          core.on_watch_installed(watch, attempt, outcome);
        }
        OpResult::RebindArmed { scope, outcome } => {
          let Some(replace) = streams.replace_states.remove(&scope) else {
            // Swept by close (its stream already retired) or never ours.
            continue;
          };
          let ReplaceMode::NewFd {
            arming: Some(spawned),
          } = replace.mode
          else {
            drop(replace.reservation);
            continue;
          };
          // Straight from the reservoir into an escrow: the liveness check and
          // the commit below are both on the far side of the handoff.
          let spawned = EscrowedSpawn::new(spawned, reaper.sink());
          let widened = spawned.meta.root.clone();
          let outcome = if !streams.handles.contains_key(&scope) {
            // Death wins: the scope ended while the pre-arm was in flight.
            retire_refused::<F>(&op_tx, &reaper, &mut pending_teardowns, scope, spawned);
            Err(crate::error::ReplaceRootError::Retired)
          } else if let WatchOutcome::Failed(err) = outcome {
            // The new transport could not cover the new root: unwind, the
            // old coverage untouched.
            let root = spawned.meta.root.clone();
            retire_refused::<F>(&op_tx, &reaper, &mut pending_teardowns, scope, spawned);
            Err(crate::error::ReplaceRootError::Source(
              SourceError::RootUnavailable {
                root,
                source: arm_failure(err),
              },
            ))
          } else {
            commit_replace::<F>(
              &mut core,
              &ops,
              &op_tx,
              &reaper,
              &mut streams.handles,
              &mut lanes,
              &mut next_lane,
              &mut pending_teardowns,
              &mut os,
              &mut source_taps,
              &registry,
              &cookies,
              scope,
              spawned,
              replace.reservation.path(),
              Some(outcome),
              &now,
            )
          };
          if let Ok(backend) = &outcome {
            scope_backends.insert(scope, *backend);
            // The cookie floor follows the committed root (see the kernel-
            // recursive commit above); the generation that revokes in-flight
            // writes under the old root was already bumped inside `commit_replace`
            // at the lane swap. Parked barriers the new root no longer covers are
            // revoked first.
            revoke_uncovered_parked_cookies(&mut core, &mut parked_cookies, &cookies, scope, &widened);
            cookies.scope_live(scope, widened);
          }
          drop(replace.reservation);
          let _ = replace.reply.send(outcome.map(|_| ()));
        }
        OpResult::ReplaceMeta { scope, result } => {
          if !streams.replace_states.contains_key(&scope) {
            // Swept by close; the resolve owned nothing.
            continue;
          }
          let meta = match result {
            Ok(meta) => meta,
            Err(err) => {
              let replace = streams.replace_states.remove(&scope).expect("just checked");
              drop(replace.reservation);
              let _ = replace
                .reply
                .send(Err(crate::error::ReplaceRootError::Source(err)));
              // Like a failed replacement spawn: no teardown was enqueued, so
              // a parked unwatch must be re-checked here.
              if scope_quiesced(
                scope,
                &streams.handles,
                &pending_spawns,
                &pending_teardowns,
                &streams.replace_states,
              ) {
                resolve_unwatch_waiters(&mut unwatch_replies, scope);
              }
              continue;
            }
          };
          if !streams.handles.contains_key(&scope) {
            // Death wins while the meta resolved.
            let replace = streams.replace_states.remove(&scope).expect("just checked");
            drop(replace.reservation);
            let _ = replace
              .reply
              .send(Err(crate::error::ReplaceRootError::Retired));
            if scope_quiesced(
              scope,
              &streams.handles,
              &pending_spawns,
              &pending_teardowns,
              &streams.replace_states,
            ) {
              resolve_unwatch_waiters(&mut unwatch_replies, scope);
            }
            continue;
          }
          // Re-validate against the CANONICAL meta: still a strict,
          // representable widen, on the live scope's own mount frame, AND with
          // no resolved mount prefix covering the old root — the enumerate
          // lowering marks a cross-frame entry `Other` and the reconcile drops
          // the watch in such a slot, so a boundary at the root OR anywhere on
          // the CONNECTING CHAIN would make the crawl actively tear the
          // adopted coverage down. The frame equality of the endpoints covers
          // the chain only when both mount ids are known (a mount instance is
          // a connected subtree); the seed check closes the unknown-id degrade
          // and the seed's own read is fresher than the spawn-time frames.
          let still_widen = core.root_path(scope).is_some_and(|old| {
            widen_predicate(&old, &meta.root)
              && !meta.mounts.iter().any(|m| old.starts_with(m))
          }) && core.root_frame(scope).is_some_and(|(dev, mnt)| {
              meta.root_dev == dev
                && match (meta.root_mnt_id, mnt) {
                  (Some(new_mnt), Some(old_mnt)) => new_mnt == old_mnt,
                  // Either frame unknown: the device belt governs alone — the
                  // codebase's existing pre-5.8 degrade, inherited unchanged.
                  _ => true,
                }
            });
          if !still_widen {
            // Fall back to the general new-stream replace: dispatch the spawn
            // the admission would have, under the same accounting.
            streams.replace_states.get_mut(&scope).expect("just checked").mode =
              ReplaceMode::NewFd { arming: None };
            dispatch_replace_spawn::<R, F>(
              &ops,
              &op_tx,
              &reaper,
              &config,
              &streams.handles,
              &mut pending_spawns,
              scope,
              meta.root,
            );
            continue;
          }
          // Reserve the widened root's watch id, OPEN ITS WITNESSED WINDOW
          // (INV-ROOT), and pre-arm it on the LIVE port. The id is unknown to
          // the Monitor until the commit, so the arm cannot ride the ordinary
          // effect path — but its records are NOT dropped: the window is
          // opened before the pre-arm can register the kernel wd, so every
          // record the transport attributes to the reserved id is intercepted
          // at the core's compile stage (a death record taints the window;
          // benign slice churn is consumed and converges through the
          // post-commit cold read), and every scope loss signal taints too.
          // The commit then gates on the clean window: the arm confirmed the
          // meta's object (plus the stale-Installed bracket below), and a
          // binding bound right that later dies or moves emits a death record
          // or a loss — so a clean window PROVES the binding live at the
          // commit, and a tainted one falls back to the stream replace whose
          // spawn barrier re-establishes it from scratch.
          let reserved = core.reserve_watch_id();
          core.begin_widen_watch(scope, reserved);
          let port = streams.handles
            .get(&scope)
            .expect("checked live above")
            .scope_port();
          let path = meta.root.clone();
          let name = Segment::new(
            path
              .file_name()
              .and_then(|name| name.to_str())
              .unwrap_or("/"),
          );
          let expected = u64::try_from(meta.identity.ino())
            .ok()
            .and_then(core::num::NonZeroU64::new)
            .map(|ino| ExpectedObject {
              dev: meta.identity.dev(),
              ino,
            });
          streams.replace_states.get_mut(&scope).expect("just checked").mode = ReplaceMode::SameFd {
            phase: SameFdPhase::Arming { reserved, meta },
          };
          let ops_for_arm = ops.clone();
          let tx = op_tx.clone();
          R::spawn_blocking_detach(move || {
            let mut outcome =
              ops_for_arm.preflight_arm(&port, scope, reserved, &path, &name, expected);
            // The stale-Installed bracket: the arm's own open-then-verify ran
            // at ARM time, and the commit must never accept that outcome
            // alone — re-stat the path NOW, so an object swapped in right
            // after the arm is refused here (the descriptor disarmed, the
            // caller typed) instead of committed with the root watch bound to
            // the DEPARTED object. This is the cheap EARLY refusal and one
            // half of INV-ROOT's live-at-commit proof (the arm bound the
            // right object); the window this probe cannot close (probe →
            // commit) is closed by the witnessed window itself — a swap in it
            // emits a death record on the reserved wd (or its loss is
            // signalled), which taints the window and refuses the commit.
            if let (WatchOutcome::Installed(_) | WatchOutcome::Aliased(_), Some(want)) =
              (&outcome, expected)
            {
              let matches = matches!(
                ops_for_arm.probe(&path),
                ProbeOutcome::Present { kind, file_id: Some(id), dev }
                  if kind.is_dir() && dev == want.dev && id == want.ino
              );
              if !matches {
                ops_for_arm.remove_watch(scope, reserved);
                outcome = WatchOutcome::Failed(WatchError::Gone);
              }
            }
            let _ = tx.try_send(OpResult::WidenArmed { scope, outcome });
          });
        }
        OpResult::WidenArmed { scope, outcome } => {
          let Some(replace) = streams.replace_states.remove(&scope) else {
            // Swept by close: the armed descriptor died with the scope's
            // stream in the sweep.
            continue;
          };
          let ReplaceMode::SameFd {
            phase: SameFdPhase::Arming { reserved, meta },
          } = replace.mode
          else {
            debug_assert!(false, "WidenArmed only follows a widen pre-arm");
            core.abort_widen_watch(scope);
            drop(replace.reservation);
            continue;
          };
          let resolution = if !streams.handles.contains_key(&scope) || core.root_watch(scope).is_none() {
            // Death wins: the stream died with the fd (or the old world
            // already ended core-side). Nothing to tear down that the death
            // funnel does not already own; the witnessed window closes with
            // the widen it belonged to.
            core.abort_widen_watch(scope);
            Err(crate::error::ReplaceRootError::Retired)
          } else if let WatchOutcome::Failed(err) = outcome {
            // The live transport could not cover the widened root: unwind
            // with nothing installed, the old coverage untouched, and the
            // witnessed window closed (nothing will commit over it).
            core.abort_widen_watch(scope);
            Err(crate::error::ReplaceRootError::Source(
              SourceError::RootUnavailable {
                root: meta.root.clone(),
                source: arm_failure(err),
              },
            ))
          } else {
            // The pre-arm holds: the commit now CATCHES UP to the lane
            // instead of jumping it. The queued-length snapshot is the
            // finite prefix the NORMAL source arm must process first —
            // benign records deliver at the still-current old root (their
            // truthful pre-commit coordinates), death records and losses
            // taint through the INV-ROOT funnels — and the commit fires at
            // a loop top once the prefix is consumed
            // ([`resolve_widen_catchups`]). Nothing resolves here.
            let remaining = source_taps.get(&scope).map_or(0, EventReceiver::len);
            streams.replace_states.insert(
              scope,
              ReplaceState {
                reservation: replace.reservation,
                reply: replace.reply,
                mode: ReplaceMode::SameFd {
                  phase: SameFdPhase::CatchUp {
                    reserved,
                    meta,
                    replay: outcome,
                    remaining,
                  },
                },
              },
            );
            continue;
          };
          // A failed or retired pre-arm resolves immediately: no teardown is
          // enqueued, so a parked unwatch is re-checked exactly as after a
          // failed replacement spawn.
          if scope_quiesced(
            scope,
            &streams.handles,
            &pending_spawns,
            &pending_teardowns,
            &streams.replace_states,
          ) {
            resolve_unwatch_waiters(&mut unwatch_replies, scope);
          }
          drop(replace.reservation);
          let _ = replace.reply.send(resolution);
        }
        OpResult::Enumerated { req, raw } => {
          core.on_enumerated(req, raw);
        }
        OpResult::TeardownFailed { scope } => {
            // The stream's quiescence was never PROVEN, so close must not report
            // `Ok` over it — but the obligation itself IS discharged (nothing is
            // still running), and leaving it owed would make every later close
            // report a phantom obligation for work that stopped long ago.
            //
            // The same fact reaches the scope's awaited unwatches, which resolve
            // on the quiescence fence below and would otherwise answer the
            // proven-teardown verdict over exactly the stream nobody proved.
            unproven_teardowns += 1;
            taint_unproven_scope(&mut unproven_scopes, &mut unwatch_replies, scope);
            retire_teardown(&mut pending_teardowns, scope);
            if scope_quiesced(
              scope,
              &streams.handles,
              &pending_spawns,
              &pending_teardowns,
              &streams.replace_states,
            ) {
              resolve_unwatch_waiters(&mut unwatch_replies, scope);
            }
          }
        OpResult::TornDown { scope } => {
            retire_teardown(&mut pending_teardowns, scope);
            // The unwatch fence is per-scope QUIESCENCE across EVERY native
            // obligation — a straggler teardown, a replacement still
            // spawning or pre-arming, or a committed handle — not merely the
            // one stream this TornDown retired.
            if scope_quiesced(
              scope,
              &streams.handles,
              &pending_spawns,
              &pending_teardowns,
              &streams.replace_states,
            ) {
              resolve_unwatch_waiters(&mut unwatch_replies, scope);
            }
          }
        OpResult::CookieWriteDone { id } => {
          // The write already wrote its own verdict to its record: nothing to
          // reopen (the gate is the phase) and nothing to sweep (a reap mark dies
          // with the record it marks). If a self-reap's unlink FAILED, the record
          // is parked `RemoveFailed` — schedule its retry.
          cookies.schedule_retry(&config, id, now(), false);
        }
        OpResult::CookieRemoveDone { id, confirmed } => {
          on_cookie_remove_done(&cookies, &config, id, confirmed, now(), false);
        }
        OpResult::ControlBatchDone {
          scope,
          generation,
          cut_token,
          end,
        } => {
          // The batch has reached an end — its outcome arrived, or its answer sink
          // was destroyed unresolved — and whatever `WatchInstalled` replies it
          // produced are already ingested, ahead of this on the FIFO channel: clear the mark
          // and release the next queued batch, in emission order. A torn-down
          // scope holds no queue and no mark, so this re-creates NO state and
          // submits nothing — the completion is inert. This — not a parked pool
          // worker — IS the serialization wait, so the mechanism never deadlocks a
          // bounded, non-FIFO pool.
          //
          // Only the batch the mark NAMES may act on it. A batch whose generation
          // a replace has retired can still be inside its syscall while the
          // replacement's own batches run, so its completion must not clear a mark
          // it does not own nor release a successor a second time — the mark is
          // the newer batch's wait, and honouring it twice would put two
          // current-generation batches on the pool at once and lose their emission
          // order.
          let holds_mark = control_inflight.get(&scope) == Some(&generation);
          if holds_mark {
            control_inflight.remove(&scope);
          }
          match end {
            ControlBatchEnd::Unwound => {
              // The batch stopped somewhere inside itself, so its native
              // operations may have run in part and its kernel state is unknown —
              // a later batch would be submitted over it blind. The arm results
              // this scope's nodes are waiting on are lost with it: they are fed
              // back on the return path, which this batch never reached.
              //
              // Withholding the proof is not enough on its own: a fence latched on
              // a request whose batch died can never reach `Proven`, is no longer
              // offered by `covers_awaiting_cut`, and would hold a live `set_cover`
              // or sync forever. So this fails CLOSED to the one terminal that
              // resolves everything the scope is owed: the teardown fold answers
              // its fences `Dead`, its pending grants resolve as failures, and its
              // queued batches are dropped rather than run over unknown state.
              //
              // Judged WITHOUT regard to generation, unlike everything else here.
              // An unwind reports only that the batch stopped, so how far it got —
              // and what its callers are still owed — is exactly what is unknown,
              // and no generation comparison bounds that: whatever it half-wrote,
              // it wrote through a port, and a swap since then retracts none of it.
              pending_control.remove(&scope);
              core.on_source_fatal(scope, now());
            }
            ControlBatchEnd::Unanswered if !generation_retired(&lanes, scope, generation) => {
              // The batch belongs to the scope's CURRENT transport, and the reader
              // that was to serve it is gone. Its own callers are answered — every
              // arm came back refused — but the scope cannot go on: its next batch
              // is addressed to the same absent reader, no fence of its can ever be
              // proven, and whatever parks on one would wait forever. So the
              // terminal is the same one an unwind takes, reached for a different
              // reason: it is what resolves everything the scope is owed.
              pending_control.remove(&scope);
              core.on_source_fatal(scope, now());
            }
            ControlBatchEnd::Unanswered => {
              // The reader that went missing served a transport the scope has
              // ALREADY swapped away from, so its absence is the ordinary end of a
              // retired world rather than a live one's failure. Whatever it may
              // have half-run before it died, it ran against that transport's own
              // fd, whose kernel watches die with it and whose anchors the swap
              // purged — none of it reaches the replacement's reader, fd or queue.
              // Failing closed here would kill a live lane on its predecessor's
              // word, after `replace_root` has already reported success to its
              // caller.
              //
              // It certifies nothing either. No reader cut a queue for it, so the
              // mark it may have owned is released above with no proof attached and
              // the live lane's fences still wait on a round trip of their own.
              if holds_mark {
                kick_control_queue::<R, F>(
                  &ops,
                  &op_tx,
                  &mut pending_control,
                  &mut control_inflight,
                  &lanes,
                  scope,
                );
              }
            }
            ControlBatchEnd::Answered => {
              if holds_mark {
                // The reader cuts its kernel queue onto the lane before answering
                // ANY batch, so a batch that RAN and carried this scope's
                // outstanding proof request is an ordering proof: whatever the
                // kernel held when it was served is already ingested ahead of this
                // completion.
                //
                // All three conjuncts are load-bearing. Without the token a
                // PREDECESSOR still recorded as running could complete after a
                // later request was queued and latched, and its cut — taken before
                // that request existed — would license it. Without the ANSWER a
                // batch that unwound, or whose reader died before replying, would
                // do the same: the guard fires on the unwind, and on the very batch
                // that carries no arms a dead reader's return carries no
                // resolutions to give it away. And without the mark a RETIRED
                // generation's completion would license the proof with a cut taken
                // on a transport the scope no longer reads, which orders nothing
                // about the one it does.
                if let Some(token) = cut_token {
                  core.prove_cut(scope, token);
                  // The same round trip proves the same thing for a staged
                  // adoption, and the two latches take it by token: only one of
                  // them ever has a request out for a scope at a time, so the
                  // other's `prove` is inert.
                  core.prove_adoption_cut(scope, generation, token);
                }
                kick_control_queue::<R, F>(
                  &ops,
                  &op_tx,
                  &mut pending_control,
                  &mut control_inflight,
                  &lanes,
                  scope,
                );
              }
            }
          }
        }
        }
      },
      unwound = unwind_rx.recv().fuse() => {
        // An uncommitted grant dropped (a watch() future cancelled after its
        // reply was sent but before it was polled): unwind through the
        // normal unwatch path so the stream, the registry, and the core all
        // reconcile.
        if let Ok(scope) = unwound {
          core.on_unwatch(scope);
        }
      },
      _ = timer => {
        core.on_timeout(now());
        // The one wake also services due cookie retries (T8); firing both is
        // harmless — `on_timeout` before its deadline just re-arms, and a retry
        // pass with nothing due is a no-op.
        dispatch_due_cookie_retries::<R, F>(&cookies, &op_tx, now());
      },
      cmd = commands.recv().fuse() => match cmd {
        Ok(Command::Watch { root, interest, reply }) => {
          // A new root is a new native stream, and every stream this driver ever
          // admits is a teardown it will one day owe. Refuse while the retired
          // ones cannot be reclaimed: watch + reply-less `request_unwatch` is one
          // of the two ways ordinary sequential control traffic outruns the
          // reaper (see [`MAX_TEARDOWN_BACKLOG`]).
          //
          // Judged against the pressure gauge, which counts this driver's
          // in-flight stream work as well as its landed teardowns. Reading the
          // landed ones alone bounded sequential churn only: a spawn owes nothing
          // until it returns, and one that fails POST-LIVE surrenders a running
          // stream into the counted path, so a burst of watches racing one
          // in-flight window all passed the same below-limit state and every one
          // of them converted afterwards. A DESCENDING birth stays in flight past
          // its spawn — live, ungranted and fallible until its root arm resolves
          // — so its reservation runs through that phase too, or a cohort parked
          // on held root arms would free its spawn reservations one by one and
          // let this admission run past the bound.
          if teardown_pressure(
            &pending_teardowns,
            unproven_teardowns,
            &pending_spawns,
            &streams.replace_states,
            &deferred_grants,
          ) >= MAX_TEARDOWN_BACKLOG
          {
            let _ = reply.send(Err(WatchRootError::CleanupBacklog));
          } else {
            let requested = root.clone();
            // The scope mint is monotonic, so the refusal arm is dead here; it
            // is answered rather than asserted so an out-of-tree driver reusing
            // this core learns of the collision instead of taking a panic.
            // Nothing was registered, so there is no teardown to owe.
            match core.on_watch(root, interest, config.profile) {
              Ok(scope) => {
                watch_replies.insert(scope, PendingWatch { requested, reply });
              }
              Err(err) => {
                let _ = reply.send(Err(err));
              }
            }
          }
        }
        Ok(Command::Replace {
          scope,
          root,
          reservation,
          reply,
        }) => {
          if !streams.handles.contains_key(&scope) {
            let _ = reply.send(Err(crate::error::ReplaceRootError::UnknownRoot));
          } else if teardown_pressure(
            &pending_teardowns,
            unproven_teardowns,
            &pending_spawns,
            &streams.replace_states,
            &deferred_grants,
          ) >= MAX_TEARDOWN_BACKLOG
          {
            // A make-before-break replacement RETIRES the live stream and reports
            // success without waiting for it, so admitting one while the backlog
            // is full is precisely how a supervisor retargeting a watch against a
            // dead mount piles up handles nothing can reclaim. Refuse before the
            // successor spawn: the old coverage is untouched
            // (see [`MAX_TEARDOWN_BACKLOG`]).
            //
            // Replacements already in flight are counted here as well, and a
            // WIDEN is why that is not redundant with the spawn term: it resolves
            // over the live transport with no spawn to reserve against, and its
            // fallback dispatches one only later — so a burst of widens would
            // otherwise pass a gauge that saw none of them and convert together.
            drop(reservation);
            let _ = reply.send(Err(crate::error::ReplaceRootError::CleanupBacklog));
          } else {
            match streams.replace_states.entry(scope) {
              std::collections::btree_map::Entry::Occupied(_) => {
                let _ = reply.send(Err(crate::error::ReplaceRootError::ReplaceInFlight));
              }
              std::collections::btree_map::Entry::Vacant(slot) => {
                // The route fork: a WIDEN (old root strictly inside the new,
                // representable chain) on a live DESCENDING scope keeps its
                // stream — no spawn, the same-transport commit. Everything
                // else (KR, narrowing, disjoint, equal, non-UTF-8 chain — and,
                // at the meta re-validation, a differing mount frame) takes
                // the general new-stream path below.
                let descending = !scope_backends
                  .get(&scope)
                  .is_some_and(BackendKind::is_kernel_recursive);
                let widen = descending
                  && core
                    .root_path(scope)
                    .is_some_and(|old| widen_predicate(&old, &root));
                if widen {
                  // The no-spawn meta resolve. NOT counted in
                  // `pending_spawns`: it owns no native stream, so a
                  // post-close straggler is droppable whole.
                  let ops_for_meta = ops.clone();
                  let tx = op_tx.clone();
                  let path = root;
                  R::spawn_blocking_detach(move || {
                    let result = ops_for_meta.resolve_root_meta(&path);
                    let _ = tx.try_send(OpResult::ReplaceMeta { scope, result });
                  });
                  slot.insert(ReplaceState {
                    reservation,
                    reply,
                    mode: ReplaceMode::SameFd {
                      phase: SameFdPhase::MetaPending,
                    },
                  });
                  continue;
                }
                // Dispatch the replacement spawn through the SAME blocking-pool
                // accounting a birth spawn uses (resume point included — see
                // `dispatch_replace_spawn`); the Spawned router diverts the
                // result to the commit tail by the replace_states key.
                dispatch_replace_spawn::<R, F>(
                  &ops,
                  &op_tx,
                  &reaper,
                  &config,
                  &streams.handles,
                  &mut pending_spawns,
                  scope,
                  root,
                );
                slot.insert(ReplaceState {
                  reservation,
                  reply,
                  mode: ReplaceMode::NewFd { arming: None },
                });
              }
            }
          }
        }
        Ok(Command::Unwatch { scope, mut reply }) => {
          // The parked-settlement bound, read before ANY state is touched: an
          // awaited unwatch of a scope whose teardown cannot quiesce is retained
          // until it does, and duplicates of the same handle each add a waiter
          // (see [`MAX_PARKED_SETTLEMENTS`]). The teardown itself is NOT gated —
          // one is already owed for this scope, and refusing to trigger it would
          // trade bounded memory for a leaked stream.
          let backlogged = reply.is_some()
            && unwatch_replies.get(&scope).map_or(0, Vec::len) >= MAX_PARKED_SETTLEMENTS;
          if let Some(reply) = reply.take_if(|_| backlogged) {
            let _ = reply.send(UnwatchAck::Backlogged);
          } else if streams.handles.contains_key(&scope) || watch_replies.contains_key(&scope) {
            // A live scope: the awaited form records its waiter (answered at
            // quiescence with `Torn`); the reply-less `request_unwatch` tears
            // down identically but registers none. Waiters ACCUMULATE up to the
            // parked-settlement bound — a duplicate unwatch of the same handle
            // joins the queue, never evicts an earlier waiter.
            //
            // Live is not the same as provable. A replace retires the old lane
            // make-before-break, so a scope can be live on a healthy successor
            // while the RETIRED stream's teardown unwound — and the caller
            // releases against the scope, not against one lane. The latch
            // therefore overrides the verdict here too.
            if let Some(reply) = reply {
              unwatch_replies.entry(scope).or_default().push((
                reply,
                admitted_verdict(&unproven_scopes, scope, UnwatchAck::Torn),
              ));
            }
            core.on_unwatch(scope);
          } else if pending_spawns.contains(&scope)
            || pending_teardowns.contains_key(&scope)
            || streams.replace_states.contains_key(&scope)
          {
            // The live handle already died (root death / fatal) but the scope
            // is NOT yet quiescent — a replacement is still spawning or
            // pre-arming, or a teardown is still draining. The death path
            // already tore the original stream down and a replacement resolves
            // to `Retired` and is torn down; there is nothing more to trigger.
            // Park the reply for quiescence rather than reporting the scope
            // gone while a native stream is still coming up, and answer
            // `Unknown` — the root died. Waiters accumulate here too (a
            // duplicate must not evict an earlier one).
            if let Some(reply) = reply {
              unwatch_replies.entry(scope).or_default().push((
                reply,
                admitted_verdict(&unproven_scopes, scope, UnwatchAck::Unknown),
              ));
            }
          } else if let Some(reply) = reply {
            // Genuinely unknown: never watched, or already fully quiesced — with
            // one exception the latch names. A scope whose teardown unwound holds
            // no state here either, so it reaches this arm once its last
            // obligation retires; answering `Unknown` would say "no such live
            // root", which is true, while silently dropping the one fact the
            // caller asked for.
            let _ = reply.send(admitted_verdict(&unproven_scopes, scope, UnwatchAck::Unknown));
          }
        }
        Ok(Command::SetCover { scope, retained, mut reply }) => {
          // In-place bidirectional coverage reconcile. The core is the authority on whether
          // a reconcile ran: every refusal — unknown scope, not yet publicly live,
          // kernel-recursive profile, refused cover — comes back as a typed `Noop` and is
          // acknowledged IMMEDIATELY, never fenced. A reconcile that RAN parks its reply
          // under a fence opened right here, before any other core input, so the fence
          // inherits exactly this reconcile's window (a born-lossy coalesced grow
          // included); the loop-top `resolve_cover_settlements` answers it once the
          // scope's re-arm work quiesces. A reply-less reconcile (`request_set_cover`)
          // opens no fence — its window still feeds the settlement bookkeeping,
          // unacknowledged.
          //
          // The parked-settlement bound is read BEFORE the reconcile, never
          // after: an acknowledged reconcile that ran and then found no room for
          // its fence would have applied coverage whose verdict its caller can
          // never learn, so the refusal has to precede the mutation (see
          // [`MAX_PARKED_SETTLEMENTS`]). Both halves of one admitted call — the
          // driver's parked reply sender and the core's pending fence record —
          // are created together and refused together, so bounding the core's
          // side bounds both. A reply-less reconcile parks nothing and is never
          // gated.
          let backlogged =
            reply.is_some() && core.pending_cover_fences(scope) >= MAX_PARKED_SETTLEMENTS;
          if let Some(reply) = reply.take_if(|_| backlogged) {
            let _ = reply.send(CoverOutcome::Skipped(SkipReason::Backlogged));
            continue;
          }
          match core.on_set_cover(scope, &retained) {
            CoverReconcile::Reconciling => {
              if let Some(reply) = reply {
                let fence = core.open_cover_fence(scope);
                cover_replies.insert(fence, reply);
              }
            }
            CoverReconcile::Noop(reason) => {
              if let Some(reply) = reply {
                let _ = reply.send(noop_outcome(reason));
              }
            }
          }
        }
        Ok(Command::SyncRoot {
          scope,
          dir,
          name,
          ticket,
          reply,
        }) => {
          // The scope's canonical root, only for a live scope — the FLOOR the
          // cookie directory must stay within and a proof the scope exists.
          let live_root = streams.handles
            .contains_key(&scope)
            .then(|| cookies.root_of(scope).map(Path::to_path_buf))
            .flatten();
          match live_root {
            None => {
              let _ = reply.send(Err(crate::error::SyncRootError::UnknownRoot));
            }
            Some(root) => {
              // The cookie NAME is one normal component (the umbrella mints
              // `.tributaries-sync-…`); a separator, `..`, or absolute name is a
              // contract violation refused before it can escape on a join. The
              // DIRECTORY must lie within the root once `.`/`..` are folded — the
              // containment a plain `starts_with` misses for `<root>/../out`.
              if !is_normal_cookie_name(&name) {
                let _ = reply.send(Err(crate::error::SyncRootError::BadCookieName { name }));
              } else if !cookie_dir_within_root(&root, &dir) {
                let _ = reply.send(Err(crate::error::SyncRootError::DirOutsideRoot { dir, root }));
              } else if let Some(exclusion) = cookie_dir_excluded(&config.exclusions, &dir) {
                // Inside the root but inside an EXCLUSION: the write would
                // succeed and its event would then be suppressed by the very
                // option that asked for the suppression, leaving the caller's
                // observation waiting on an event that cannot exist. Refuse
                // before birth — a barrier no source can report is not a
                // barrier.
                let exclusion = exclusion.to_path_buf();
                let _ = reply.send(Err(crate::error::SyncRootError::DirExcluded {
                  dir,
                  exclusion,
                }));
              } else if cookies.has_pending_write(scope) {
                // Single-flight per scope: refuse a second sync while one for
                // this scope is anywhere in the pipeline — still PARKED on its
                // settle fence, or its write DISPATCHED (an `InPool` obligation).
                // At most one physical write per scope can then be outstanding, so
                // a caller that times out and retries cannot pile unbounded
                // blocking writes against a hung mount. ONE O(cap) probe over the
                // one ledger, because both stages are one record there.
                let _ = reply.send(Err(crate::error::SyncRootError::WriteInFlight));
              } else if cookies.name_in_use(&name) {
                // A LIVE obligation of this watcher already holds this rendered
                // name. `by_name` maps a name to ONE incarnation ⇒ ONE path, so
                // admitting a second same-name obligation would put two live syncs
                // on one cookie file — the `create_new`/unlink collisions and the
                // `by_path` displacement the physical machinery must never face.
                // Refuse before birth: with no two live same-name obligations, one
                // cookie file has one live owner. The name frees at the holder's
                // typed terminal, so sequential reuse admits; concurrent syncs need
                // distinct names (the umbrella mints per-sync-unique names, so it
                // never trips this).
                //
                // Ordered AFTER `WriteInFlight` so a same-scope retry while the
                // predecessor is still `Parked`/`InPool` keeps reading the transient
                // single-flight signal (renaming is not its remedy), and BEFORE both
                // `TicketInUse` and the caps so a permanently name-blocked request is
                // neither mis-reported as transient capacity pressure nor allowed to
                // spuriously re-arm the recovery batch — and so a name+ticket
                // collision reads `NameInUse` first, keeping every earlier pinned
                // outcome verbatim. A refused admission creates nothing.
                let _ = reply.send(Err(crate::error::SyncRootError::NameInUse { name }));
              } else if cookies.ticket_in_use(ticket.seq()) {
                // A LIVE obligation of this watcher already holds this ticket
                // sequence — the caller passed one ticket to two concurrently-live
                // syncs. `by_ticket` maps a sequence to ONE incarnation, so admitting
                // a second under it would make the sequence's cancel ambiguous.
                // Refuse before birth (both are permanent-shaped caller errors, name
                // first so the name-gate outcomes stay verbatim), and BEFORE the caps
                // so it is not mis-reported as transient pressure nor allowed to
                // re-arm the recovery batch. A refusal creates nothing, so the SAME
                // ticket stays valid for a retry (refusal is not admission).
                let _ = reply.send(Err(crate::error::SyncRootError::TicketInUse {}));
              } else if cookies.unremoved_for(scope) >= config.cookie_backlog_cap
                || cookies.unremoved() >= config.cookie_global_cap
              {
                // The memory bound (§4.3), per-scope AND WHOLE-LIFECYCLE global:
                // too many unremoved cookies for this scope, OR too many total
                // admitted-but-unconfirmed cookie obligations watcher-wide. The
                // global gauge Φ = `unremoved()` is ONE term over ONE store: every
                // lifecycle stage from admission on is exactly one ledger record —
                // a sync parked on its fence, a write in the pool, an owned cookie,
                // an unconfirmed removal — so there is nothing to dedup and no
                // second gauge that could drift. Admission increments Φ by exactly
                // one only under Φ < cap, and no other event increases it, so
                // Φ ≤ cap at every point (§4.3): the ledger is bounded by a FLAT
                // cap, blocking cookie-write jobs in flight ≤ Φ ≤ cap (the
                // pool-exhaustion attack is capped watcher-wide), and a
                // sync→fail→unwatch→rewatch churn cannot grow the ledger past it.
                // Refuse retryably — the cleanup owner keeps retrying, and on a
                // recovered fs the backlog drains and syncs resume with no operator
                // action.
                //
                // Kick recovery before refusing: re-arm a bounded batch of PARKED
                // (budget-spent, unscheduled) records. A parked record on a
                // RETIRED scope has no live scope to sweep it and no timer to
                // retry it, so without this a since-recovered fs would never drain
                // the backlog and the cap could refuse every future sync forever.
                // The re-armed records confirm on a recovered fs (freeing the cap
                // for a later sync) or re-park on a still-failing one — bounded work.
                cookies.rearm_parked_batch::<R>(&op_tx, scope, config.cookie_backlog_cap);
                let _ = reply.send(Err(crate::error::SyncRootError::CleanupBacklog));
              } else {
                // ADMITTED — and admission is BIRTH. Every refusal above has
                // passed, so this sync becomes an obligation right here, before its
                // caller can hold any address for it: from this line the global cap
                // counts it, the single-flight gate stands on it, a cancel through
                // its ticket has a record to mark, and the close reply cannot miss
                // it. A REFUSED admission creates nothing at all — the reason a
                // hostile flood of refused syncs cannot mint state.
                //
                // The write parks on a settle fence opened right here — the same
                // fence a reconcile's ack rides, so it inherits this moment's
                // window. A kernel-recursive scope has no re-arm work, so the
                // fence settles at the very next loop-top poll and the write
                // dispatches immediately; a descending scope waits for its
                // in-flight re-arms to quiesce, which is precisely the ordering
                // the barrier needs.
                let fence = core.open_cover_fence(scope);
                cookies.admit_parked(scope, name, ticket.seq(), fence);
                // The routing half: which caller this fence answers, and where its
                // cookie is to be written. Inserted in the same step as the record
                // it belongs to, and removed in the same step it leaves `Parked` —
                // the lockstep that keeps this local from ever being a second
                // opinion about which syncs are parked.
                parked_cookies.insert(fence, ParkedCookie { dir, reply });
              }
            }
          }
        }
        Ok(Command::Close { reply }) => break Some(reply),
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugLaneCount { reply }) => {
          let _ = reply.send(lanes.len());
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugCookieCount { reply }) => {
          let _ = reply.send(cookies.len());
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugUnwatchWaiters { scope, reply }) => {
          let _ = reply.send(unwatch_replies.get(&scope).map_or(0, Vec::len));
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugPendingCoverFences { scope, reply }) => {
          let _ = reply.send(core.pending_cover_fences(scope));
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugCoverFenceEntry { scope, reply }) => {
          let _ = reply.send(core.holds_cover_fence_entry(scope));
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugCookieReapMarks { reply }) => {
          let _ = reply.send(cookies.reap_marks());
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugCookieParkedFor { scope, reply }) => {
          let _ = reply.send(cookies.parked_for(scope));
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugCookieCensus { reply }) => {
          let _ = reply.send(cookies.census());
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugUnprovenTeardowns { reply }) => {
          let _ = reply.send(unproven_teardowns);
        }
        #[cfg(all(test, feature = "tokio"))]
        Ok(Command::DebugTeardownPressure { reply }) => {
          let _ = reply.send(teardown_pressure(
            &pending_teardowns,
            unproven_teardowns,
            &pending_spawns,
            &streams.replace_states,
            &deferred_grants,
          ));
        }
        // The watcher facade dropped: same orderly teardown, nobody to tell.
        Err(_) => break None,
      },
      // The cookie-cleanup wake, ranked below `commands` so it can never starve a
      // Close, and above the source stream. It cannot drop a request whatever the
      // command load: the request is already ON its record before this fires, and
      // this only says one has landed. A closed wake leaves this inert: the
      // watcher drops the wake and the command sender together, so `commands`
      // (higher-priority) fires its `break None` first — this arm is never
      // selected on the way out, and the terminal sweep below owns every record
      // regardless of any mark.
      wake = reap_wake.recv().fuse() => {
        if wake.is_ok() {
          sweep_reap_requests::<R, F>(&cookies, &op_tx, &mut parked_cookies, &mut core);
        }
      },
      msg = os.next() => {
        if let Some(item) = msg {
          ingest_source_item::<F>(&mut core, &lanes, &mut streams.replace_states, &streams.handles, item, &now);
        }
      },
    }
  };

  // Orderly shutdown: quiesce every stream — the live handles AND the
  // blocking-pool work still capable of producing one (`pending_spawns`,
  // `pending_teardowns`) — then drain what already arrived and deliver what
  // fits. The final event drain is documented best-effort (loss and death
  // signals are in-band messages, so anything undrained here is part of that
  // same best-effort remainder). Uncommitted grants racing this close need no
  // unwind processing: their scopes were either swept here (live handle) or
  // settle below as late spawns; the unread unwind message dies with its
  // channel.
  //
  // Drained ONE AT A TIME out of the reservoir and into an escrow, never taken
  // whole: the reclaims and the detach below are calls that can unwind, and a
  // sweep that emptied the map first would leave every stream it had not reached
  // yet with no guard at all (see [`StreamReservoir::take_live`]).
  while let Some((scope, stream)) = streams.take_live() {
    registry.scope_dead(scope);
    // The same detachment normal `TeardownStream` performs, at the same point
    // relative to the registry reclaim: `attach_scope` runs only where a handle
    // is stored, so this sweep covers every attached scope. Without it the arm
    // port and the scope's retained anchors stay in the executor's maps until
    // the LAST detached job holding an `ops` clone finishes — and enumerate,
    // probe and refresh jobs are deliberately not in the close tally, so a
    // stalled one could keep them alive long past an `Ok(0)` reply. A late
    // control batch for the gone scope now answers the same typed refusal it
    // answers after an ordinary teardown, which is the right answer for a
    // transport this sweep is closing. Nothing here is counted, so the reply's
    // arithmetic below is untouched.
    ops.detach_scope(scope);
    stream.retire(&reaper, &op_tx, &mut pending_teardowns, scope);
  }
  // A descending replace's pre-arm holds a spawned-but-uncommitted stream
  // the maps above no longer cover: retire it inside the same accounting.
  // Drain `replace_states` entirely so the scope-quiescence fence below no
  // longer counts these as outstanding replace obligations; each entry's
  // reservation and reply drop here — the caller sees `Closed`.
  //
  // A same-transport widen holds no native stream and yields `None`: its
  // pre-armed watch descriptor (if any) dies with the scope's own stream in the
  // sweep above.
  while let Some((scope, stream)) = streams.take_replacement() {
    if let Some(stream) = stream {
      stream.retire(&reaper, &op_tx, &mut pending_teardowns, scope);
    }
  }
  // Route every cookie the registry owns through the removal state machine
  // BEFORE the grace, so a hung unlink makes close report `NotQuiesced` honestly
  // rather than wedging — never a synchronous unlink in the registry's `Drop`.
  // Raise the shutdown flag first: a write still in the pool then finds its
  // claim refused and self-reaps rather than landing a cookie owned but unswept
  // behind this sweep. A straggler write's FAILED self-reap landing mid-drain
  // re-inserts a `RemoveFailed` record — the live-ledger drain condition below
  // cannot miss it (finding 4, closed structurally rather than by counting).
  cookies.begin_shutdown();
  cookies.sweep_owned::<R>(&op_tx);
  // A sync still PARKED at close never had a write dispatched, so there is nothing
  // to sweep for it and nothing to wait on: it reaches the pre-physical terminal
  // here, its caller answered `Retired` rather than left to read a bare `Closed`.
  // Retiring them BEFORE the drain is what keeps the drain's ledger-quiescence
  // condition honest — a pre-physical obligation nothing will ever complete must
  // not hold close open for the grace, nor be reported as a non-quiesced cookie.
  retire_parked_cookies(&mut core, &mut parked_cookies, &cookies, &|_, _| true);
  // The sweep re-armed every `Owned`/parked record (dispatched now); a record
  // still mid-backoff was coalesced and keeps its far retry deadline, which the
  // ~1 s grace could outrun — close would then report `NotQuiesced` where a
  // prompt retry inside the grace would have confirmed. Pull every remaining
  // deadline forward to one base delay so the drain's retry arm services it in
  // time (the design's flat-base-during-close intent); a still-failing unlink
  // still ends `NotQuiesced`, only never spuriously.
  cookies.pull_retries_forward(now() + config.cookie_retry_base);
  // The grace is ONE budget, and the drain below spends it in two places, so it
  // is anchored once here on the clock the blocking work it is waiting for
  // actually runs against. `R::timeout` bounds the wait for everything that
  // reports over `op_rx`; this deadline bounds the wait for the reaper, whose
  // threads no runtime timer governs.
  let grace = Duration::from_secs(1);
  let grace_ends = std::time::Instant::now() + grace;
  let drain = async {
    loop {
      // The LIVE-ledger quiescence condition: every cookie obligation — a write
      // still in the pool, an owned cookie, an unconfirmed removal — is one record
      // in the one ledger, so the drain cannot exit while any stands. A post-sweep
      // straggler is impossible to miss: its record was born before its write
      // could create anything, and only a typed terminal removes it.
      if pending_teardowns.is_empty() && pending_spawns.is_empty() && cookies.unremoved() == 0 {
        break;
      }
      // Teardown completions arrive over `op_rx` like every other result, but
      // they are PRODUCED by reaper threads, which no runtime timer governs.
      // Parking on the channel alone would therefore let a runtime whose timer is
      // virtual retire the whole grace before those threads had any real time at
      // all, and close would report a teardown outstanding that was microseconds
      // from done. So the drain buys them time on their own clock — but one SHORT
      // SLICE per round, never the rest of the grace. That wait is synchronous:
      // spending the grace inside it would let a single wedged teardown stop close
      // from consuming the completions that already landed and from servicing a
      // due cookie retry, and on a current-thread runtime it would hold the
      // executor outright for a second. Every slice is clipped to the shared
      // deadline, so all of them together still spend one grace; the round arm
      // below returns the drain here for the next one; and the loop's own exit
      // condition is unchanged, so close still observes every teardown before it
      // reports quiesced. Every teardown a slice returns on has already sent its
      // `TornDown`, so the arms below pick those completions up without waiting.
      let awaiting_reaper = !pending_teardowns.is_empty();
      // A result already queued is progress the drain can make without spending
      // any real time at all, so it takes that first.
      if awaiting_reaper && op_rx.is_empty() {
        reaper.settle(
          REAPER_GRACE_SLICE.min(grace_ends.saturating_duration_since(std::time::Instant::now())),
        );
      }
      futures_util::select_biased! {
        res = op_rx.recv().fuse() => match res {
          Ok(OpResult::TeardownFailed { scope }) => {
            // Same discharge as `TornDown` — the reaper is free and nothing is
            // running — but the quiescence was never proven, so the close reply
            // below counts it and refuses `Ok`, and the scope's parked unwatches
            // are re-verdicted exactly as in the live arm.
            unproven_teardowns += 1;
            taint_unproven_scope(&mut unproven_scopes, &mut unwatch_replies, scope);
            retire_teardown(&mut pending_teardowns, scope);
            if !pending_spawns.contains(&scope) && !pending_teardowns.contains_key(&scope) {
              resolve_unwatch_waiters(&mut unwatch_replies, scope);
            }
          }
          Ok(OpResult::TornDown { scope }) => {
            retire_teardown(&mut pending_teardowns, scope);
            // The same per-scope quiescence fence as the live arm. Close has
            // already drained `handles` and `replace_states` (both provably
            // empty here), and referencing the non-`Sync` handle map inside
            // this future would poison its `Send`ness — so the fence reduces to
            // the two obligations that can still be outstanding in the drain.
            if !pending_spawns.contains(&scope) && !pending_teardowns.contains_key(&scope) {
              resolve_unwatch_waiters(&mut unwatch_replies, scope);
            }
          }
          Ok(OpResult::Probed { probe, outcome }) => core.on_probe_result(probe, outcome, now()),
          Ok(OpResult::WatchInstalled {
            watch,
            attempt,
            outcome,
            ..
          }) => {
            // Every scope is ending here, so a stale reply can only
            // accelerate a teardown already owed — no lane fence needed.
            core.on_watch_installed(watch, attempt, outcome);
          }
          Ok(OpResult::Enumerated { req, raw }) => core.on_enumerated(req, raw),
          Ok(OpResult::MountsRefreshed { scope, refresh }) => {
            core.on_mounts_refreshed(scope, refresh, now())
          }
          // A spawn that raced the close: the stream is live but has no owner —
          // tear it down INSIDE the close accounting (the handle's Drop is only
          // the backstop past the grace) and hold the close reply for its
          // confirmation. Its scope never went registry-live, so there is no
          // entry to reclaim; a failed spawn just settles its slot.
          Ok(OpResult::Spawned { scope, result }) => {
            pending_spawns.remove(&scope);
            match result {
              Ok(spawned) => EscrowedSpawn::new(spawned, reaper.sink()).retire(
                &reaper,
                &op_tx,
                &mut pending_teardowns,
                scope,
              ),
              // A post-live failure racing the close owns a stream exactly like
              // a success does; retiring it inside the close accounting is what
              // holds the reply until its verdict lands.
              Err(failure) => {
                if let Some(stream) = escrow_failure(failure, reaper.sink()).1 {
                  stream.retire(&reaper, &op_tx, &mut pending_teardowns, scope);
                }
              }
            }
            // A spawn that failed with NO stream enqueues no teardown, so —
            // exactly as the live loop's spawn-failed arm does — a parked
            // unwatch waiting on this scope would otherwise never be re-checked
            // and would drop as `Closed` at return. Resolve it here if the
            // failed spawn was the scope's last obligation.
            if !pending_spawns.contains(&scope) && !pending_teardowns.contains_key(&scope) {
              resolve_unwatch_waiters(&mut unwatch_replies, scope);
            }
          }
          // A pre-arm outcome for a replace the close sweep already retired:
          // nothing left to commit or unwind.
          Ok(OpResult::RebindArmed { .. }) => {}
          // A widen's meta resolve or live-port pre-arm straggling past the
          // sweep: neither owns a stream — the armed descriptor (if any) died
          // with the scope's own teardown.
          Ok(OpResult::ReplaceMeta { .. }) | Ok(OpResult::WidenArmed { .. }) => {}
          // A dispatched write finished during the drain: its own verdict is
          // already on its record, so if a FAILED self-reap parked it
          // `RemoveFailed`, schedule its retry at the flat base so the drain's own
          // retry arm drives it to confirmation inside the grace (T3 caught by the
          // live ledger).
          Ok(OpResult::CookieWriteDone { id }) => {
            cookies.schedule_retry(&config, id, now(), true);
          }
          // An unlink finished: a confirm already dropped the record (the pool did
          // it, id-keyed); a transient failure parked it, and this re-schedules at
          // the flat base (the 1 s grace bounds attempts here — §5.2) or leaves it
          // parked past the budget.
          Ok(OpResult::CookieRemoveDone { id, confirmed }) => {
            on_cookie_remove_done(&cookies, &config, id, confirmed, now(), true);
          }
          // A control batch finished during the grace: every scope is ending,
          // so the queue does not advance — its remaining batches are the
          // documented best-effort remainder that dies with the core (arms leave
          // a dead node Arming; disarms are moot once the fd closes). Inert.
          Ok(OpResult::ControlBatchDone { .. }) => {}
          Err(_) => break,
        },
        // Service due cookie-unlink retries inside the grace. No arm fires when
        // the schedule is empty (a `pending()` future), so this can never spin.
        () = async {
          match cookies.min_retry_at() {
            Some(at) => {
              R::sleep_until(origin + at.elapsed_since_origin()).await;
            }
            None => futures_util::future::pending::<()>().await,
          }
        }
        .fuse() => {
          dispatch_due_cookie_retries::<R, F>(&cookies, &op_tx, now());
        },
        // Ends the round while a teardown is outstanding, so the drain goes back
        // for another slice above instead of parking on arms that no executor
        // this runtime schedules is feeding. Inert once the teardowns are done —
        // everything left then reports over a clock the runtime does govern — and
        // bounded by the close timeout either way, so it can neither spin nor
        // stretch the grace.
        () = async {
          if awaiting_reaper {
            R::sleep(REAPER_GRACE_SLICE).await;
          } else {
            futures_util::future::pending::<()>().await;
          }
        }
        .fuse() => {},
      }
    }
  };
  // Grace expiry with work still pending means a wedged blocking pool: the
  // close reply goes out anyway (a wedged pool must not hang close forever),
  // and it reports EVERY pending set — quiescence cannot be claimed while any
  // is non-empty. A still-pending TEARDOWN already moved its handle INTO the
  // wedged shutdown call, so nothing can reclaim that stream until the call
  // returns. A still-pending SPAWN may ALREADY OWN A LIVE STREAM — the backend
  // starts it and then performs post-live metadata reads inside the same call —
  // and only self-reclaims once the wedge clears (its undeliverable result
  // drops and the handle's Drop runs the teardown), so it is just as
  // non-quiescent at reply time. A still-owned COOKIE is a physical write or
  // unlink the sweep dispatched whose file a hung mount will not release until
  // it unwedges (the registry's best-effort Drop retries it), so it too is
  // non-quiescent. One shared grace for all: a wedged FFI or FS call rarely
  // unwedges with more time, so a longer window would only delay the honest
  // signal.
  let _ = R::timeout(grace, drain).await;
  execute_effects::<R, F>(
    &mut core,
    &ops,
    &config,
    &op_tx,
    &reaper,
    &mut streams.handles,
    &mut pending_spawns,
    &mut pending_teardowns,
    &mut scope_backends,
    &mut lanes,
    &mut source_taps,
    &events,
    &mut unwatch_replies,
    &mut deferred_grants,
    &mut pending_control,
    &mut control_inflight,
    &mut cookies,
    &registry,
    &now,
  );
  // One final settlement poll: a DEGRADED fence whose re-arm work quiesced
  // during the drain resolves with its honest verdict instead of spuriously
  // reading as `Closed`. Whatever is still pending drops with `cover_replies`
  // — the ratified close-mid-fence semantics: the caller sees `Closed`, never
  // an outcome fabricated over a torn-down driver. A CLEAN fence is `Closed`
  // here too, by the same rule: this poll runs as [`SettlePass::Closing`], and
  // the sweep above tore every stream down — there is no stream left to
  // certify against, so the boundary withholds the verdict rather than
  // certifying over a scope it is tearing down. `Closed` is the
  // honest no-verdict; the degraded resolutions (the common close-mid-recovery
  // shape) are untouched — and unlike the live loop's pass, this one defers
  // NOTHING for a lane it did not finish reading, because it is the last pass
  // there will ever be and a held-over fence would strand its caller here.
  // No cookie can be dispatched here (no scope is live to this
  // poll, and shutdown already refuses claims), so the registry may retire
  // next. The drain above serviced only `op_rx`, so the same loss fence the
  // live loop's settle observation holds applies here: an ACK that landed during
  // the grace can postdate a loss still on the source queue, and an honest
  // verdict must ingest that loss first — bounded by the same
  // [`SourceSnapshot`], which holds every such loss (it was queued before
  // its ACK, so before this drain starts) while keeping a producer still
  // feeding a lane from wedging close past its grace. The drained items'
  // effects die with the core — the documented best-effort remainder — but
  // their loss memory and barrier state feed this poll.
  if core.cover_settlement_due() {
    let mut snapshot = SourceSnapshot::taken(&lanes, &source_taps);
    while !snapshot.spent() {
      let core::task::Poll::Ready(Some(item)) = futures_util::poll!(os.next()) else {
        break;
      };
      snapshot.consume(item.0, item.1);
      ingest_source_item::<F>(
        &mut core,
        &lanes,
        &mut streams.replace_states,
        &streams.handles,
        item,
        &now,
      );
    }
  }
  // The close pass never holds a tranche over (see
  // [`SettlePass::orders_stat_cover`]), so it reports no flush to owe.
  let _ = resolve_cover_settlements::<R, F>(
    &mut core,
    &ops,
    &op_tx,
    &mut cover_replies,
    &mut parked_cookies,
    &mut cookies,
    &|_| false,
    SettlePass::Closing,
  );
  // The close reply counts every distinct outstanding obligation exactly once:
  // a straggler teardown/spawn, and every cookie obligation the ledger still
  // holds — a write in the pool, an owned cookie, an unconfirmed removal — each
  // ONE record, so one physical obligation can never be tallied twice nor omitted.
  // `Ok(0)` now proves every stream torn down AND every cookie this driver ever
  // wrote is CONFIRMED removed — the strengthened close guarantee.
  //
  // A teardown that UNWOUND is counted here for its whole remaining life. Its
  // obligation was discharged the moment its terminal landed — nothing is still
  // running, so nothing to wait for — but nobody ever proved the stream gone, and
  // reporting `Ok(0)` over an unproven teardown would be exactly the false
  // quiescence this count exists to refuse. Counting it (rather than leaving the
  // obligation owed) also keeps the drain BOUNDED: the loop's exit condition is
  // an empty `pending_teardowns`, which a permanently-owed entry would never
  // satisfy.
  let outstanding = pending_teardowns.values().sum::<usize>()
    + pending_spawns.len()
    + cookies.unremoved()
    + unproven_teardowns;
  // Drop the registry LAST. The orderly sweep above already dispatched an unlink
  // for every owned cookie under the grace, so on a healthy fs this finds the
  // ledger empty; whatever a hung mount would not let go was already counted in
  // the `NotQuiesced` reply above, and this `Drop` fires its best-effort DETACHED
  // retry without blocking. The `Drop` is the guarantee's backstop: a panicking
  // or cancelled driver — one that never reaches this line — still runs it,
  // detached, on exit.
  drop(cookies);
  if let Some(reply) = close_reply {
    let _ = reply.send(outstanding);
  }
}

/// Discharges one counted teardown obligation for `scope`.
///
/// Both teardown terminals retire an obligation identically — the reaper thread
/// is free and nothing is still running either way. What differs is only what
/// close may CLAIM about the stream, which is the caller's business.
fn retire_teardown(pending_teardowns: &mut BTreeMap<ScopeId, usize>, scope: ScopeId) {
  if let Some(owed) = pending_teardowns.get_mut(&scope) {
    *owed -= 1;
    if *owed == 0 {
      pending_teardowns.remove(&scope);
    }
  }
}

/// Latches `scope` as never-proven-quiescent and re-verdicts every unwatch
/// already parked for it.
///
/// A parked waiter carries the verdict chosen when it was ADMITTED, and the
/// unwind that voids that verdict happens later — so the answer has to be
/// rewritten in place rather than chosen at resolution time. Both halves are
/// needed and neither is redundant: the rewrite covers waiters admitted BEFORE
/// the unwind, and the latch covers every unwatch admitted after it (which
/// reads the latch at admission and is parked, or answered, as
/// [`UnwatchAck::Unproven`] from the start).
///
/// The latch is monotone for the driver's life, mirroring the unproven count
/// close reports: nothing later can prove a stream whose `shutdown` stopped
/// half-way.
fn taint_unproven_scope(
  unproven_scopes: &mut BTreeSet<ScopeId>,
  unwatch_replies: &mut BTreeMap<
    ScopeId,
    Vec<(futures_channel::oneshot::Sender<UnwatchAck>, UnwatchAck)>,
  >,
  scope: ScopeId,
) {
  unproven_scopes.insert(scope);
  if let Some(waiters) = unwatch_replies.get_mut(&scope) {
    for (_, verdict) in waiters {
      *verdict = UnwatchAck::Unproven;
    }
  }
}

/// The verdict an unwatch admitted NOW must carry for `scope`: whatever the
/// admission path would answer, unless the scope has already been latched
/// unproven ([`taint_unproven_scope`]) — in which case no later teardown can
/// restore a quiescence claim over it.
fn admitted_verdict(
  unproven_scopes: &BTreeSet<ScopeId>,
  scope: ScopeId,
  verdict: UnwatchAck,
) -> UnwatchAck {
  if unproven_scopes.contains(&scope) {
    UnwatchAck::Unproven
  } else {
    verdict
  }
}

/// Resolves and drops EVERY awaited unwatch parked for `scope`, each with
/// the verdict it is carrying — chosen at admission and rewritten in place by
/// [`taint_unproven_scope`] if the scope stopped being provable meanwhile.
/// Called only once the scope is quiescent; a `RootHandle` is `Copy`
/// so more than one waiter can be queued, and all must be answered — a
/// dropped sender reads to its caller as driver death.
fn resolve_unwatch_waiters(
  unwatch_replies: &mut BTreeMap<
    ScopeId,
    Vec<(futures_channel::oneshot::Sender<UnwatchAck>, UnwatchAck)>,
  >,
  scope: ScopeId,
) {
  if let Some(waiters) = unwatch_replies.remove(&scope) {
    for (reply, verdict) in waiters {
      let _ = reply.send(verdict);
    }
  }
}

/// Whether `scope` holds NO outstanding native obligation — no live handle,
/// no spawn in flight, no counted teardown, and no replace mid-commit. This
/// is the unwatch fence: a replace can leave the current handle down while a
/// replacement is still spawning or pre-arming (and will itself end in a
/// counted teardown), so the unwatch reply must wait for the whole scope to
/// go quiet, not merely for the one stream the unwatch retired.
fn scope_quiesced<H>(
  scope: ScopeId,
  handles: &BTreeMap<ScopeId, H>,
  pending_spawns: &BTreeSet<ScopeId>,
  pending_teardowns: &BTreeMap<ScopeId, usize>,
  replace_states: &BTreeMap<ScopeId, ReplaceState<H>>,
) -> bool {
  !handles.contains_key(&scope)
    && !pending_spawns.contains(&scope)
    && !pending_teardowns.contains_key(&scope)
    && !replace_states.contains_key(&scope)
}

/// The most reaper threads one driver may hold at once, the baseline thread
/// included. A teardown is short on a healthy filesystem and a driver usually
/// retires one stream at a time, so this cap binds only when several transports
/// are wedged simultaneously; what it is here for is root churn, which can
/// retire streams faster than they finish quiescing and would otherwise grow
/// threads without bound. Past the cap teardowns queue and start as reapers free
/// up.
const MAX_TEARDOWN_REAPERS: usize = 4;

/// The most native streams one driver may have RETIRED-BUT-UNRECLAIMED at once:
/// queued for a reaper thread, running inside one, or unwound without proof.
///
/// [`MAX_TEARDOWN_REAPERS`] bounds THREADS, which is not a resource bound at all.
/// Past that cap teardowns queue, and every queued closure still owns its
/// `SourceHandle` — the transport, its reader thread's state, its OS handles and
/// its buffers — none of which is reclaimed until a reaper can enter `shutdown`.
/// A wedged filesystem is exactly the state the reaper exists to survive, and it
/// is also the state in which the queue never drains, so a bound on threads
/// converts unbounded thread growth into unbounded retained-handle growth and
/// calls it a fix.
///
/// The gap is that admitting a stream and reclaiming one are different events.
/// `watch` + the reply-less `request_unwatch`, and awaited `replace_root` (which
/// retires the old stream make-before-break and reports success without waiting
/// for it), both admit a NEW stream while the retired one is still owed — so
/// ordinary sequential control traffic from ONE caller grows the backlog with
/// total churn rather than with live coverage. Neither is limited by the command
/// mailbox: that bounds requests waiting to be RECEIVED, and the driver stays
/// perfectly responsive while it accumulates.
///
/// So the bound is over the retained obligation. Both stream-admitting commands
/// refuse with a typed, retryable `CleanupBacklog` once this many teardowns are
/// outstanding, which leaves the caller's current coverage untouched and clears
/// itself as the wedge does. Dropping queued closures is NOT an alternative: a
/// dropped closure drops its handle, whose own `Drop` performs the same unbounded
/// join, wherever that drop happens and with no terminal to show for it.
///
/// What is counted against it is [`teardown_pressure`], not the landed teardowns
/// alone: a stream-creating operation reserves its unit for as long as it is in
/// flight, or the bound would hold only against sequential traffic and be
/// exceeded by the size of any concurrent burst.
const MAX_TEARDOWN_BACKLOG: usize = 64;

/// The most awaited public control operations one SCOPE may have PARKED in the
/// driver waiting on a settlement the driver does not control.
///
/// The command mailbox is fixed at 16 entries, and that number bounds exactly one
/// thing: requests waiting to be RECEIVED. The driver releases the slot the moment
/// it takes a command, and an awaited `unwatch` or `set_cover` is not finished
/// there — it is parked until the scope's teardown quiesces or its coverage fence
/// settles, both of which depend on a native transport that may never answer. So
/// while a scope is wedged the driver stays perfectly responsive, keeps draining
/// its mailbox, and moves every admitted caller into a per-scope structure with no
/// bound at all: memory grows with TOTAL admitted requests precisely in the failure
/// state the mailbox bound exists to survive. Cancellation pruning does not help —
/// these callers are still waiting, so nothing is cancelled — and the pruning scan
/// itself is linear in the parked population on a hot driver path.
///
/// The bound is therefore over the RETAINED obligation, at admission, per scope:
/// past it the request is refused with a typed, retryable terminal before anything
/// is parked, opened, or reconciled. A refusal costs the caller a retry and leaves
/// the scope exactly as it was; the alternative costs the process its memory.
///
/// Per SCOPE rather than globally on purpose: one wedged root must not deny the
/// control plane to every healthy one, and the number of live scopes is already
/// bounded by the teardown backlog and by coverage itself.
///
/// Sized well above the deepest legitimate in-flight cohort — a caller reissuing
/// covers across a churning tree while one proof round trip is outstanding — and
/// deliberately NOT tied to the 16-slot mailbox, because the two bound different
/// things: the mailbox bounds requests waiting to be RECEIVED, this bounds
/// requests already admitted and not yet settled. The point is to turn unbounded
/// into constant, not to make the constant tight.
const MAX_PARKED_SETTLEMENTS: usize = 64;

/// The gauge [`MAX_TEARDOWN_BACKLOG`] is read against: every native stream this
/// driver has retired but not reclaimed, PLUS one reserved unit for every
/// stream-creating operation still in flight.
///
/// # Why the landed terms alone were not a bound
///
/// `pending_teardowns` and `unproven` count only obligations that have already
/// ARRIVED. An operation that will produce one is invisible to them for its whole
/// in-flight window — a spawn runs on the blocking pool, and a post-live failure
/// surrenders its running stream to the counted teardown path when it returns —
/// so N admissions racing one window all read the same below-limit state, all
/// pass, and all convert afterwards. The bound then held only against SEQUENTIAL
/// traffic, where each operation's obligation lands before the next is judged,
/// and was exceeded by the size of any concurrent burst. A sequential regression
/// cell cannot see that: it never has two operations in flight at once.
///
/// # The reservation, and what releases it
///
/// The reservation is not a new counter with a new decrement path — that is how a
/// bound on ingress becomes an unbounded retention of its own. It is exactly
/// MEMBERSHIP in the three structures the driver already keeps for in-flight
/// stream work, each of which already has exactly one insertion and exactly one
/// removal per operation:
///
/// - `pending_spawns` — a scope with a spawn on the blocking pool. Entered by the
///   birth effect and by [`dispatch_replace_spawn`]; left, on EVERY outcome, at
///   the one `OpResult::Spawned` dequeue (the live loop's and the close drain's).
///   Success releases it as the stream becomes the scope's lane; an ordinary
///   failure releases it with nothing created; a post-live failure releases it in
///   the same step that CONVERTS it, retiring the surrendered stream into
///   `pending_teardowns` — so the gauge never dips between the two.
/// - `replace_states` — a replacement mid-commit. A widen resolves with no spawn
///   at all and would otherwise reserve nothing, yet its fallback dispatches a
///   spawn later; reserving for the whole replace covers that window too. Left
///   when the replace resolves, whichever arm resolves it.
/// - `deferred_grants` — a DESCENDING birth between its spawn's success and its
///   ROOT arm. Its stream is running, but the caller has not been handed the
///   grant and cannot unwatch what it does not hold: the operation is still the
///   driver's own in-flight work, and it is still fallible on both sides — a
///   failed root arm refuses it, a cancelled `watch()` future unwinds it, and
///   either ends in a counted teardown. Entered at the birth commit's descending
///   arm; left at the one `WatchInstalled` resolution, at `TeardownStream` (the
///   scope died first), or by dropping with the frame at close.
///
/// Without the third term the bound held only until a spawn RETURNED. Success
/// released the spawn reservation while the stream stayed ungranted and fallible,
/// so a cohort parked on held root arms freed its reservations one by one and let
/// admission run past the bound by the size of the cohort; when the arms then
/// failed, every staged stream retired at once and landed the whole overshoot in
/// `pending_teardowns` — the retained handles and readers the bound exists to
/// refuse. A burst racing ONE spawn window cannot see that: `pending_spawns`
/// already covers it, and the gap opens only once the spawns resolve.
///
/// A driver that never resolves an operation therefore never releases its
/// reservation — and that is the correct reading, not a leak. For the two spawn
/// terms `close` counts the very same membership as an outstanding obligation, so
/// a reservation is exactly as durable as the obligation it stands for. A
/// deferred grant holds no handle of its own — its stream is `handles`' — so
/// `close` counts it one step removed: the close sweep drains `handles` into
/// `submit_teardown`, and the resulting `pending_teardowns` entry is what the
/// close reply reports. Everything that discards the driver discards all of them
/// together: cancellation, runtime shutdown and an unwind drop these maps with
/// the driver's frame, after which an undeliverable spawn result routes its
/// stream to the reaper sink ([`deliver_spawned`]) with no gauge left to release
/// into.
///
/// # Deduplication
///
/// The reserved term is the CARDINALITY OF THE UNION of the three key sets, not
/// their sum: `|A| + |B \ A| + |C \ (A ∪ B)|`. A general replace is BOTH
/// mid-commit and mid-spawn for most of its life, and a scope can only ever owe
/// the one obligation — the retired stream on a commit, the refused replacement
/// on a failure — so counting a scope twice would refuse healthy traffic without
/// bounding anything further.
///
/// # Ordering
///
/// A reservation is visible to the NEXT admission because the loop dequeues at
/// most one command per iteration and begins every iteration with an effect
/// flush: a `Watch` admitted in one iteration has its `SpawnStream` — and so its
/// `pending_spawns` entry — installed before any later command is judged. A
/// `Replace` needs no such argument; it enters `replace_states` in its own arm.
///
/// The `pending_spawns` → `deferred_grants` HAND-OFF has no gap for the same
/// reason, and the reason is structural rather than a bet on a short window: the
/// release and the acquire are both inside the ONE `OpResult::Spawned` arm body,
/// straight-line and non-awaiting, and this gauge is read only from the command
/// arm of the same biased select — so no admission can be judged between them.
/// The release is atomic with the acquire; the terms need not overlap. The
/// descending arm that finds no pending reply (a `watch()` already cancelled)
/// enters nothing and instead unwatches, and its teardown effect executes at the
/// NEXT iteration's flush — again before any command is judged.
///
/// # What else can hold a live stream, and why nothing else needs a term
///
/// The gauge has to cover every place a native stream can sit between birth and
/// commitment, so the places are enumerated rather than sampled:
///
/// - the blocking-pool spawn closure, which starts the stream and then reads
///   metadata post-live — `pending_spawns`, entered before the dispatch;
/// - an `OpResult::Spawned` in transit on [`OpQueue`] — still `pending_spawns`,
///   which is left only at the dequeue;
/// - a replacement's parked pre-arm, the stream held in [`ReplaceMode::NewFd`]'s
///   `arming` — `replace_states`;
/// - a descending birth's live-but-ungranted stream, which physically sits in
///   `handles` under a scope the caller has no grant for — keyed in
///   `deferred_grants`, which is why the term is that map rather than a second
///   view of `handles`;
/// - an [`EscrowedSpawn`]/[`StreamEscrow`] local: a reservoir of exactly one,
///   whose whole life is inside one arm body that judges no command, so no read
///   of this gauge can observe it;
/// - the reaper's queue — already counted, because [`submit_teardown`] records
///   the obligation before it hands the stream over (the uncounted sink paths run
///   only once the driver frame is gone);
/// - `watch_replies` — holds no stream at all: nothing has been spawned yet, and
///   the scope enters `pending_spawns` at the flush that precedes the next
///   command.
///
/// The REST of `handles` — every scope whose grant has been delivered — is the
/// one live-stream population deliberately left out. A granted stream is not
/// between birth and commitment: it is coverage the caller owns and can retire
/// whenever it likes, and retiring it is the ungated path precisely because a
/// teardown is already owed. Counting it would turn this into a bound on live
/// coverage, which is not what it is for.
///
/// # Arithmetic
///
/// Every addition SATURATES. A saturated sum lands at `usize::MAX`, which is on
/// the refusing side of the comparison, so overflow degrades to the same typed,
/// retryable refusal the bound exists to produce rather than to a debug panic or
/// a release-mode wrap that would read as "plenty of room". A checked form would
/// have to map its `None` to that identical refusal.
fn teardown_pressure<H>(
  pending_teardowns: &BTreeMap<ScopeId, usize>,
  unproven: usize,
  pending_spawns: &BTreeSet<ScopeId>,
  replace_states: &BTreeMap<ScopeId, ReplaceState<H>>,
  deferred_grants: &BTreeMap<ScopeId, DeferredGrant>,
) -> usize {
  let landed = pending_teardowns
    .values()
    .fold(0usize, |acc, owed| acc.saturating_add(*owed))
    .saturating_add(unproven);
  let reserved = pending_spawns
    .len()
    .saturating_add(
      replace_states
        .keys()
        .filter(|scope| !pending_spawns.contains(scope))
        .count(),
    )
    .saturating_add(
      deferred_grants
        .keys()
        .filter(|scope| !pending_spawns.contains(scope) && !replace_states.contains_key(scope))
        .count(),
    );
  landed.saturating_add(reserved)
}

/// How much REAL time one close-drain round hands to the teardown reaper before
/// returning to the drain's own arms.
///
/// Short enough that a wedged teardown delays a landed completion or a due
/// cookie retry by no more than a round, long enough that a healthy one — an OS
/// thread's scheduling plus a `close(2)` — usually finishes inside the first,
/// and either way it divides the close grace into a bounded number of rounds.
const REAPER_GRACE_SLICE: Duration = Duration::from_millis(5);

#[cfg(test)]
thread_local! {
  /// Test seam: while set, a [`TeardownReaper`] built on this thread refuses
  /// every thread creation, standing in for an OS that will not give the driver
  /// one.
  ///
  /// A driver's reaper is built in the driver's own prologue, on the first poll
  /// of its task, so arming this on the thread a current-thread runtime drives
  /// that task from reaches exactly that driver — and no other, since the flag
  /// never leaves the thread it was set on.
  static REFUSE_REAPER_THREADS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The executor stream teardowns run on — deliberately NOT the runtime's
/// blocking pool.
///
/// Tearing a stream down JOINS its reader thread, and that wait has no bound:
/// the reader observes its shutdown only BETWEEN operations, so one already
/// admitted into a blocking syscall against a wedged filesystem (a hung mount, a
/// dead NFS server) returns when the kernel says so and not before. The blocking
/// pool is where the LIVE generation's control batches, spawns and enumerates
/// run, and [`RuntimeLite`] promises nothing about its width — a handful of
/// workers is a legal pool, and the control queue's ordering argument already
/// assumes exactly that.
///
/// Sharing the two would let a scope's DEAD transports hold the workers its LIVE
/// one needs. A join parked on a wedged reader occupies a worker for as long as
/// the filesystem stays wedged, and root churn retires transports faster than
/// they quiesce, so enough of them occupy any bounded pool — and then a committed
/// replacement's arms and its ordering proof, work nothing is serializing any
/// more, simply never start: the new root stays partially armed and every fence
/// waits on a proof that has no worker to run on. Releasing the serialization
/// slot across a transport swap frees that work LOGICALLY; running the joins off
/// the pool is one of the two things that leave capacity for it to actually run.
/// The other is that a control batch's own wait for its reader costs no worker
/// either — see [`FsOps::dispatch_control`].
///
/// The FIRST thread is secured when the reaper is built, before the driver has
/// admitted a single source, and lives until the reaper drops. That ordering is
/// what makes submission TOTAL: a teardown can never be handed to a reaper with
/// no thread to run it on, so submission never has to choose between running an
/// unbounded join on its caller — the driver's own task, and on a current-thread
/// runtime the whole executor with it — and abandoning a live stream. A driver
/// that cannot secure the baseline can uphold none of this and admits nothing.
///
/// Beyond the baseline, threads are created on demand up to
/// [`MAX_TEARDOWN_REAPERS`] and then reused, so a driver retiring one stream at a
/// time holds exactly one. They outlive the driver loop: this drop only SIGNALS,
/// and the threads then wait for the last [`TeardownSink`] to go as well (see
/// [`ReaperState::producers`]) — a sink is a live producer, and a reaper with no
/// thread is a reaper a submission has to CREATE one on, which is the one step
/// that can fail. Joining them here would import the very unbounded wait this
/// type exists to keep off the driver's executors, at the moment the driver is
/// leaving.
///
/// Moving the joins off the pool must not change WHETHER close observes them, so
/// the reaper also tracks how many teardowns are still unfinished and lets close
/// park on that count for short slices of its grace — see [`Self::settle`].
struct TeardownReaper {
  inner: Arc<ReaperInner>,
}

struct ReaperInner {
  state: Mutex<ReaperState>,
  ready: std::sync::Condvar,
  settled: std::sync::Condvar,
  /// Every thread creation against this reaper fails. Test-only: see
  /// [`REFUSE_REAPER_THREADS`] and [`TeardownSink::refuse_further_threads`].
  #[cfg(test)]
  refuse_threads: std::sync::atomic::AtomicBool,
  /// Test seam: this many further workers unwind — OUTSIDE every containment
  /// boundary — right after retiring a claimed teardown.
  ///
  /// [`reap_loop`]'s own boundaries make an escaping unwind unreachable through
  /// the closures it runs, which is exactly why the WORKER-lifetime guard needs
  /// an injected one: what [`LiveReaper`] promises is that ANY abnormal exit
  /// leaves `threads` exact and the queue with a claimant, and a promise about
  /// paths no test can reach is a promise nothing holds to.
  #[cfg(test)]
  unwind_after_claim: std::sync::atomic::AtomicUsize,
}

struct ReaperState {
  /// Teardowns submitted but not yet claimed by a reaper, oldest first.
  queue: VecDeque<Box<dyn FnOnce() + Send>>,
  /// Reapers alive: running a teardown or on their way to the queue for one.
  threads: usize,
  /// Reapers INSIDE a teardown. Every other live reaper is headed for the queue,
  /// so `threads - busy` is exactly how many of the queued teardowns already have
  /// a claimant — a growth signal that holds a steady driver at its baseline
  /// thread without depending on a just-created thread having reached its wait.
  busy: usize,
  /// Teardowns submitted whose closure has not yet returned — queued ones
  /// included, so a teardown waiting behind the thread cap counts exactly like
  /// one already inside its join.
  outstanding: usize,
  /// The driver's own [`TeardownReaper`] has dropped. Necessary for a reaper
  /// thread to exit, but on its own NOT sufficient — see [`Self::producers`].
  owner_gone: bool,
  /// Live [`TeardownSink`]s: every handle that can still submit a teardown here.
  ///
  /// # Why threads are held against this and not against the owner alone
  ///
  /// The exit rule used to be "the driver's reaper dropped and the queue is
  /// empty", and sinks OUTLIVE that reaper by design: a spawn job detached onto
  /// the shared blocking pool carries one so that a stream it cannot deliver
  /// still reaches a reaper thread rather than being joined on that pool. So a
  /// late submission could arrive at a reaper whose threads had all exited. It
  /// then depended on the submission's own growth rule to create one, and thread
  /// creation is exactly the thing that can fail: the growth handed its
  /// reservation back and left the teardown QUEUED with no live claimant, at
  /// which point nothing would ever run it. Dropping the last sink then dropped
  /// `ReaperInner`, its queue, the queued closure and the native handle inside
  /// it — whose own `Drop` performs the unbounded join, on the blocking worker
  /// that happened to be releasing the sink. That is the precise executor the
  /// reaper exists to keep this join off, reached by the very mechanism meant to
  /// protect it.
  ///
  /// Counting producers closes it at the lifetime rather than at the failure: a
  /// thread exits only once NO producer remains, so for as long as anything can
  /// submit, a claimant provably exists and no submission ever depends on
  /// creating one. Every queued closure is therefore RUN by a reaper thread, and
  /// `ReaperInner` cannot be dropped with work still in it — the last thread
  /// holds an `Arc` of its own and drains before it lets go.
  ///
  /// The cost is a parked thread for as long as a detached job holds a sink,
  /// which is exactly as long as that job could still produce a handle to hand
  /// over. One idle thread is the correct price for never joining a native
  /// reader on a runtime executor.
  producers: usize,
}

impl TeardownReaper {
  /// Builds a reaper holding its baseline thread.
  ///
  /// # Errors
  ///
  /// The OS refused the thread. The caller has no executor that can absorb a
  /// stream teardown and so must not start one.
  fn new() -> std::io::Result<Self> {
    let inner = Arc::new(ReaperInner {
      // The baseline counts as alive from here, before it exists, so the growth
      // rule below never mistakes a thread that has not reached its wait yet for
      // one the driver still owes.
      state: Mutex::new(ReaperState {
        queue: VecDeque::new(),
        threads: 1,
        busy: 0,
        outstanding: 0,
        owner_gone: false,
        producers: 0,
      }),
      ready: std::sync::Condvar::new(),
      settled: std::sync::Condvar::new(),
      #[cfg(test)]
      refuse_threads: std::sync::atomic::AtomicBool::new(
        REFUSE_REAPER_THREADS.with(std::cell::Cell::get),
      ),
      #[cfg(test)]
      unwind_after_claim: std::sync::atomic::AtomicUsize::new(0),
    });
    spawn_reaper(&inner)?;
    Ok(Self { inner })
  }

  /// A reaper holding NO thread and refusing to create one — the state
  /// [`Self::new`] refuses to return, built directly so a cell can pin what
  /// submission does when the OS will not give the driver a thread.
  ///
  /// Gated exactly as the suite that calls it: the driver's cells need a
  /// runtime, so on a build carrying a different one this has no caller and
  /// would read as dead code.
  #[cfg(all(test, feature = "tokio"))]
  fn without_threads() -> Self {
    Self {
      inner: Arc::new(ReaperInner {
        state: Mutex::new(ReaperState {
          queue: VecDeque::new(),
          threads: 0,
          busy: 0,
          outstanding: 0,
          owner_gone: false,
          producers: 0,
        }),
        ready: std::sync::Condvar::new(),
        settled: std::sync::Condvar::new(),
        refuse_threads: std::sync::atomic::AtomicBool::new(true),
        unwind_after_claim: std::sync::atomic::AtomicUsize::new(0),
      }),
    }
  }

  /// Queues `teardown` for a reaper thread.
  ///
  /// Never runs it here, on any path. The caller is the driver's own task, and
  /// the join a teardown performs has no bound, so executing one on this side of
  /// the handoff is precisely the freeze this type exists to prevent.
  ///
  /// The teardown is never abandoned either. Dropping the closure would drop the
  /// stream handle it carries, and that handle's own `Drop` performs the SAME
  /// join — wherever the drop happened, and with no `TornDown` to show for it —
  /// so there is no such thing as cheaply discarding one. It is queued, counted
  /// among the outstanding teardowns from here, and claimed by a reaper: the
  /// baseline thread guarantees one exists to claim it.
  fn reap(&self, teardown: impl FnOnce() + Send + 'static) {
    submit_to_reaper(&self.inner, Box::new(teardown));
  }

  /// A submission-only view of this reaper that OUTLIVES the driver's loop.
  ///
  /// A detached job that ends up holding a native handle it cannot deliver — a
  /// spawn whose result channel closed while close was expiring its grace — must
  /// not simply drop it. `Drop` performs the same unbounded join `shutdown` does,
  /// on whatever thread happens to be running, and spawn jobs run on the
  /// runtime's SHARED blocking pool: the one executor the teardown contract
  /// forbids this join on, because parking a worker there starves every later
  /// spawn, enumerate, control and cookie operation, and on a legal one-worker
  /// pool starves them permanently.
  ///
  /// The sink keeps the reaper's state alive on its own AND holds a reaper
  /// thread against its own lifetime, so a submission arriving after the driver's
  /// `TeardownReaper` has dropped finds a queue with a live claimant on it rather
  /// than one whose threads have all exited (see [`ReaperState::producers`]).
  fn sink(&self) -> TeardownSink {
    TeardownSink::held(Arc::clone(&self.inner))
  }

  /// Gives the reaper threads up to `budget` of REAL time, returning as soon as
  /// one of the outstanding teardowns completes — or at once when none is
  /// outstanding. Reports whether every teardown submitted so far has RUN TO
  /// COMPLETION: its join returned and its `TornDown` already handed to the
  /// driver's result channel.
  ///
  /// Close needs this because the two waits it can perform are on different
  /// clocks. Every completion reaches the driver over its result channel, but
  /// the teardown ones are produced by reaper threads, whose progress the
  /// runtime's timer does not track: a runtime whose timer is virtual may retire
  /// the entire close grace while those threads have had no real time at all,
  /// and close would then report a teardown outstanding that was microseconds
  /// from done. So the drain buys them time on the clock they actually run
  /// against.
  ///
  /// This parks the CALLER, which is the driver's own task, so whatever budget a
  /// caller passes is time the driver spends servicing nothing else — hence a
  /// SLICE, spent repeatedly, rather than one whole grace at once. It touches no
  /// blocking-pool worker, so it cannot recreate the contention this type exists
  /// to prevent.
  fn settle(&self, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    let mut state = self.lock();
    // Any completion is progress the caller can act on — its `TornDown` is
    // already queued — so the wait ends there rather than holding out for the
    // wedged remainder.
    let entered = state.outstanding;
    while state.outstanding > 0 && state.outstanding == entered {
      let now = std::time::Instant::now();
      if now >= deadline {
        return false;
      }
      (state, _) = self
        .inner
        .settled
        .wait_timeout(state, deadline - now)
        .unwrap_or_else(PoisonError::into_inner);
    }
    state.outstanding == 0
  }

  fn lock(&self) -> MutexGuard<'_, ReaperState> {
    self
      .inner
      .state
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
  }
}

/// A clonable submission handle for a [`TeardownReaper`] — see
/// [`TeardownReaper::sink`].
///
/// Its existence is what keeps a reaper thread alive past the driver's own
/// reaper: `Clone` and `Drop` are hand-written rather than derived precisely
/// because each one has to move [`ReaperState::producers`], and a derived `Clone`
/// would mint a submission handle no thread was held for.
struct TeardownSink {
  inner: Arc<ReaperInner>,
}

impl TeardownSink {
  /// Registers one more producer against `inner` and returns the handle that
  /// owns that registration.
  ///
  /// TOTAL, and it has to stay that way. Every escrow is built as
  /// `StreamEscrow::new(handle, some_sink())`, so the handle is a temporary while
  /// this runs — armed by nothing yet. An `Arc` clone cannot fail and the lock is
  /// taken poison-tolerantly, so there is no unwind here to catch that temporary;
  /// anything added to this body that CAN unwind would reopen the very window
  /// [`StreamEscrow`] exists to close, at every construction site at once.
  fn held(inner: Arc<ReaperInner>) -> Self {
    inner
      .state
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .producers += 1;
    Self { inner }
  }

  /// Queues `teardown` exactly as [`TeardownReaper::reap`] does, from a detached
  /// job with no access to the driver's own reaper.
  fn reap(&self, teardown: impl FnOnce() + Send + 'static) {
    submit_to_reaper(&self.inner, Box::new(teardown));
  }

  /// Test seam: every FURTHER thread creation against this reaper fails.
  ///
  /// Distinct from [`REFUSE_REAPER_THREADS`], which is read once at construction
  /// and so can only model a reaper that never got a thread at all. A cell
  /// pinning what a LATE submission does needs the other shape: a reaper that
  /// secured its baseline and cannot secure another.
  #[cfg(all(test, feature = "tokio"))]
  fn refuse_further_threads(&self) {
    self
      .inner
      .refuse_threads
      .store(true, std::sync::atomic::Ordering::SeqCst);
  }

  /// Test seam: how many reaper threads are alive. The invariant a cell reads
  /// through it is [`ReaperState::producers`]' — while this handle exists, a
  /// claimant exists, so no submission through it ever depends on creating one.
  #[cfg(all(test, feature = "tokio"))]
  fn reaper_threads(&self) -> usize {
    self
      .inner
      .state
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .threads
  }
}

impl Clone for TeardownSink {
  fn clone(&self) -> Self {
    Self::held(Arc::clone(&self.inner))
  }
}

impl Drop for TeardownSink {
  fn drop(&mut self) {
    let mut state = self
      .inner
      .state
      .lock()
      .unwrap_or_else(PoisonError::into_inner);
    state.producers -= 1;
    let releasable = state.producers == 0 && state.owner_gone;
    drop(state);
    // Only the LAST producer can free a thread, and only once the owner is gone
    // too — waking them at any other point would find the exit predicate false
    // and cost a spurious round of the wait.
    if releasable {
      self.inner.ready.notify_all();
    }
  }
}

/// The driver frame's LIVE-STREAM reservoirs, guarded so an abnormal exit hands
/// what it still holds to the reaper.
///
/// # Why the orderly sweep is not enough
///
/// [`run`]'s close sweep drains both maps into [`submit_teardown`], and that is
/// the only path that can pair a teardown with a counted obligation and a
/// terminal. But a driver task can stop WITHOUT ever reaching it, in three ways
/// the sweep cannot observe: its future is dropped (a cancelled task, an
/// abandoned `select!` branch), the runtime is shut down and drops every task it
/// holds, or the loop unwinds. On all three the frame's locals simply drop where
/// they stand.
///
/// A live `SourceHandle`'s own `Drop` is the BACKSTOP for a handle nobody
/// retired, and it performs the same unbounded join `shutdown` does — the join
/// [`TeardownReaper`] exists to keep off every executor the runtime owns. So
/// dropping these maps in place runs that join on whatever thread was executing
/// the drop: a runtime worker, or on a current-thread runtime the whole
/// executor, parked for as long as the filesystem stays wedged. That is the
/// exact freeze the reaper is for, reintroduced on the paths the sweep never
/// sees.
///
/// # What the guard does
///
/// `Drop` runs on EVERY exit and hands each stream it still finds to a
/// [`TeardownSink`], which keeps the reaper's state alive on its own and so
/// works even once the driver's own [`TeardownReaper`] has been dropped. After
/// an orderly close it finds both maps empty — the sweep already drained them —
/// so it costs nothing on the healthy path and cannot double-submit.
///
/// Nothing is counted and no terminal is produced, and the `Quiesce` these
/// shutdowns answer is discarded. That stays right HERE and only here: every one
/// of these paths runs because the driver frame itself is ending, so the backlog
/// counter, the unproven latch and the close reply the verdict would feed no
/// longer exist. A verdict discarded here has no reader; a verdict discarded
/// while the driver is still running — a spawn rollback, most of all — denies one
/// (see [`SpawnFailed`](crate::os::SpawnFailed)). The whole point of these guards
/// is only that the JOIN happens on a reaper thread rather than on the runtime's.
///
/// # Handles in flight between reservoirs
///
/// A stream is not always inside one of these maps. It arrives from the blocking
/// pool in an [`OpResult::Spawned`], it is read for its port and its stats before
/// the birth commit stores it, and it is taken back out on its way to
/// [`submit_teardown`]. Binding it to a plain local for those stretches is what
/// left an unwind — a poisoned lock inside `attach_scope`, a panicking registry —
/// dropping a live handle where it stood, and a handle's `Drop` backstop is the
/// unbounded join again.
///
/// Nothing here relies on those stretches being short. Every one of them is
/// covered by a [`StreamEscrow`], which is a reservoir of exactly one: the handle
/// is moved into an escrow the instant it leaves a map or a channel, and the
/// escrow is disarmed only BY the operation that places it somewhere else. So the
/// rule is total and stated once — a native stream is inside a reservoir, inside
/// an escrow, or already submitted to the reaper — and no site has to argue that
/// its own window is too narrow to matter.
struct StreamReservoir<H: SourceControl + Send + 'static> {
  /// Each live scope's committed stream.
  handles: BTreeMap<ScopeId, H>,
  /// In-flight root replacements, keyed by the (live) scope being widened: the
  /// reservation parks here until the commit or failure releases it, and the
  /// `OpResult::Spawned` router diverts a replace-spawn's result away from the
  /// birth path.
  ///
  /// A stream reservoir too, not merely bookkeeping: a descending replace parks
  /// its spawned-but-uncommitted replacement in [`ReplaceMode::NewFd`]'s
  /// `arming` while the new root pre-arms on the blocking pool, and that handle
  /// owns a live transport the `handles` map above does not cover.
  replace_states: BTreeMap<ScopeId, ReplaceState<H>>,
  sink: TeardownSink,
}

impl<H: SourceControl + Send + 'static> StreamReservoir<H> {
  fn new(sink: TeardownSink) -> Self {
    Self {
      handles: BTreeMap::new(),
      replace_states: BTreeMap::new(),
      sink,
    }
  }

  /// Removes one live stream and hands it STRAIGHT to an escrow.
  ///
  /// The close sweep used to take both maps whole (`std::mem::take`) and iterate
  /// the result, which emptied the reservoir before a single entry had been
  /// retired: from that instant the guard covered nothing, and an unwind
  /// anywhere in the sweep — `scope_dead`, `detach_scope`, the submission itself
  /// — dropped every remaining handle in place. Draining one at a time keeps
  /// everything not yet swept inside the reservoir and the one in flight inside
  /// an escrow, so the two together cover the whole sweep.
  fn take_live(&mut self) -> Option<(ScopeId, StreamEscrow<H>)> {
    let scope = *self.handles.keys().next()?;
    let handle = self.handles.remove(&scope).expect("just listed");
    Some((scope, StreamEscrow::new(handle, self.sink.clone())))
  }

  /// Removes one in-flight replacement, escrowing the stream it may be parking.
  ///
  /// Its reservation and reply drop here — the caller of a swept `replace_root`
  /// sees `Closed` — and a same-transport widen yields `None`: it owns no stream
  /// of its own, only a pre-armed descriptor that dies with the scope's own
  /// stream.
  fn take_replacement(&mut self) -> Option<(ScopeId, Option<StreamEscrow<H>>)> {
    let scope = *self.replace_states.keys().next()?;
    let replace = self.replace_states.remove(&scope).expect("just listed");
    let stream = match replace.mode {
      ReplaceMode::NewFd {
        arming: Some(spawned),
      } => Some(StreamEscrow::new(spawned.handle, self.sink.clone())),
      ReplaceMode::NewFd { arming: None } | ReplaceMode::SameFd { .. } => None,
    };
    Some((scope, stream))
  }
}

impl<H: SourceControl + Send + 'static> Drop for StreamReservoir<H> {
  fn drop(&mut self) {
    for handle in std::mem::take(&mut self.handles).into_values() {
      self.sink.reap(move || {
        let _ = handle.shutdown();
      });
    }
    for replace in std::mem::take(&mut self.replace_states).into_values() {
      // The only replace shape that owns a stream. A same-transport widen never
      // spawns one — its pre-armed descriptor dies with the scope's own stream,
      // whose handle the map above already carried.
      if let ReplaceMode::NewFd {
        arming: Some(spawned),
      } = replace.mode
      {
        self.sink.reap(move || {
          let _ = spawned.handle.shutdown();
        });
      }
    }
  }
}

/// One native stream in transit, owned by a guard that reaps it — a reservoir of
/// exactly one, for the stretches where no map holds the handle.
///
/// # Why the maps alone were never enough
///
/// [`StreamReservoir`] and [`OpQueue`] cover a handle that is INSIDE a map or a
/// channel. Every handle also spends time outside both: it is destructured out of
/// an `OpResult`, read for its `scope_port` and its `backend_stats`, carried
/// through a refusal check, moved out of a map on its way to a teardown. Those
/// stretches were left to plain locals on the argument that they span only
/// straight-line, non-awaiting code — true, and beside the point. A cancellation
/// cannot land there, but an UNWIND raised by one of those very calls can:
/// `attach_scope` takes a lock the Linux backend can leave poisoned, a registry
/// is caller code, and a `Drop` reached by an unwind runs the same unbounded
/// reader join on whatever executor was running the task.
///
/// The class recurred because the boundary was drawn around the containers rather
/// than around the handle. This draws it around the handle: it moves into an
/// escrow the moment it leaves a container, and only an operation that PLACES it
/// somewhere else disarms the escrow. There is no method that hands the bare
/// handle back to a caller, so no site can reintroduce the gap by accident.
///
/// Nothing here is counted, no terminal is produced and the shutdown's `Quiesce`
/// is discarded on the unwind path, for the same reason [`StreamReservoir`]
/// counts nothing: the frame that owns the backlog counter and the close reply is
/// itself unwinding, so the verdict has no reader rather than a reader being
/// denied one. What matters there is only that the JOIN happens on a reaper
/// thread. The orderly disarms ([`Self::retire`]) go through [`submit_teardown`]
/// and are counted exactly as before.
struct StreamEscrow<H: SourceControl + Send + 'static> {
  /// `None` only after a disarm, which is always the last thing its method does.
  held: Option<H>,
  sink: TeardownSink,
}

impl<H: SourceControl + Send + 'static> StreamEscrow<H> {
  fn new(handle: H, sink: TeardownSink) -> Self {
    Self {
      held: Some(handle),
      sink,
    }
  }

  /// The stream, for the reads a caller must make BEFORE it is placed — its
  /// arm/disarm port and its stats handle. A borrow, so the escrow keeps
  /// ownership across whatever the caller does with the answer.
  fn get(&self) -> &H {
    self
      .held
      .as_ref()
      .expect("armed until a disarm consumes it")
  }

  /// Another producer handle on the same reaper, for a second escrow minted while
  /// this one is armed.
  fn sink(&self) -> TeardownSink {
    self.sink.clone()
  }

  /// Commits the stream as `scope`'s live lane. The move into the reservoir IS
  /// the disarm, so there is no instant at which the handle belongs to neither.
  fn commit(mut self, handles: &mut BTreeMap<ScopeId, H>, scope: ScopeId) {
    handles.insert(scope, self.disarm());
  }

  /// Hands the stream to the counted teardown accounting — the ordinary
  /// retirement, with its obligation and its terminal.
  fn retire(
    mut self,
    reaper: &TeardownReaper,
    op_tx: &async_channel::Sender<OpResult<H>>,
    pending_teardowns: &mut BTreeMap<ScopeId, usize>,
    scope: ScopeId,
  ) {
    submit_teardown(reaper, op_tx, pending_teardowns, scope, self.disarm());
  }

  /// The one way the handle leaves, for a caller that stores it in the same
  /// expression. Private on purpose: every public disarm above is itself the
  /// placement.
  fn disarm(&mut self) -> H {
    self.held.take().expect("armed until a disarm consumes it")
  }
}

impl<H: SourceControl + Send + 'static> Drop for StreamEscrow<H> {
  fn drop(&mut self) {
    if let Some(handle) = self.held.take() {
      self.sink.reap(move || {
        let _ = handle.shutdown();
      });
    }
  }
}

/// Splits a failed spawn into its error and its rollback stream UNDER ESCROW.
///
/// [`SpawnFailed::into_parts`] is the only way the handle comes out, and this is
/// the only caller of it: the stream moves from the failure into a guard in one
/// expression, so a rollback is covered by exactly the rule every other
/// in-transit stream follows (see [`StreamEscrow`]) from the instant it leaves
/// the channel. Callers then either [`retire`](StreamEscrow::retire) it into the
/// counted teardown accounting — the live driver's route — or simply drop the
/// escrow, which reaps it, on the exits where no driver is left to report to.
fn escrow_failure<H>(
  failure: SpawnFailed<H>,
  sink: TeardownSink,
) -> (SourceError, Option<StreamEscrow<H>>)
where
  H: SourceControl + Send + 'static,
{
  let (error, rollback) = failure.into_parts();
  (
    error,
    rollback.map(|handle| StreamEscrow::new(handle, sink)),
  )
}

/// A [`SpawnedSource`] whose native handle is held in a [`StreamEscrow`] while
/// the rest of it — the root metadata and the message receiver, neither of which
/// owns anything the OS has to be told about — travels as ordinary values.
///
/// This is what a spawn result becomes the instant the driver dequeues it, and it
/// is what the replace commit takes, so no site between the channel and a
/// reservoir ever holds a bare `SpawnedSource`.
struct EscrowedSpawn<H: SourceControl + Send + 'static> {
  stream: StreamEscrow<H>,
  receiver: EventReceiver,
  meta: RootMeta,
}

impl<H: SourceControl + Send + 'static> EscrowedSpawn<H> {
  fn new(spawned: SpawnedSource<H>, sink: TeardownSink) -> Self {
    Self {
      stream: StreamEscrow::new(spawned.handle, sink),
      receiver: spawned.receiver,
      meta: spawned.meta,
    }
  }

  fn handle(&self) -> &H {
    self.stream.get()
  }

  /// Parks the whole spawn in a reservoir slot the caller has ALREADY borrowed —
  /// [`ReplaceMode::NewFd`]'s `arming`, which [`StreamReservoir`] covers. Taking
  /// the borrow first is what keeps the lookup that produces it (and its
  /// `expect`) on the armed side of the handoff.
  fn park(self, slot: &mut Option<SpawnedSource<H>>) {
    let Self {
      mut stream,
      receiver,
      meta,
    } = self;
    *slot = Some(SpawnedSource {
      handle: stream.disarm(),
      receiver,
      meta,
    });
  }

  /// Hands the stream to the counted teardown accounting; the inert parts drop.
  fn retire(
    self,
    reaper: &TeardownReaper,
    op_tx: &async_channel::Sender<OpResult<H>>,
    pending_teardowns: &mut BTreeMap<ScopeId, usize>,
    scope: ScopeId,
  ) {
    self.stream.retire(reaper, op_tx, pending_teardowns, scope);
  }
}

/// The driver's result queue, guarded so the streams sitting in UNDELIVERED
/// spawn results reach the reaper rather than dropping with the channel.
///
/// [`OpResult::Spawned`] is the one variant that carries a live stream: the
/// backend starts the transport and its reader thread, and only then hands the
/// handle back — on the failure side too, when the barrier failed after its
/// stream was already running. Every other variant is a plain report that costs
/// nothing to drop. A running driver consumes them promptly, so this queue is
/// normally empty — and it is not empty on exactly the exits that matter.
///
/// [`deliver_spawned`] already covers the case where the receiver is GONE: its
/// `try_send` fails and the handle goes to the sink. What it cannot cover is a
/// result that was ACCEPTED and never read. An abnormal exit drops the receiver
/// with results still queued, and even an orderly close has a window: the grace
/// expires with a spawn wedged, the driver runs its tail, and the pool job
/// clears in the meantime and lands a live stream in a queue nobody will read
/// again. Either way the channel's own drop runs the handle's join — on the
/// driver task's thread on the way out, or on the runtime's on a cancel.
///
/// `Drop` therefore CLOSES the receiver before draining it. Closing makes
/// [`deliver_spawned`]'s `try_send` fail from that instant, so a job still on
/// the pool takes the sink route it already has; without that ordering a result
/// landing between the drain and the receiver's own drop would be lost exactly
/// as before.
struct OpQueue<H: SourceControl + Send + 'static> {
  rx: async_channel::Receiver<OpResult<H>>,
  sink: TeardownSink,
}

impl<H: SourceControl + Send + 'static> Drop for OpQueue<H> {
  fn drop(&mut self) {
    self.rx.close();
    while let Ok(op) = self.rx.try_recv() {
      let OpResult::Spawned { result, .. } = op else {
        continue;
      };
      match result {
        Ok(spawned) => self.sink.reap(move || {
          let _ = spawned.handle.shutdown();
        }),
        // A rollback stream in an undelivered failure is as live as a committed
        // one, and reaching it needs the same drain. Escrowing it and letting
        // the escrow drop IS the reap.
        Err(failure) => drop(escrow_failure(failure, self.sink.clone()).1),
      }
    }
  }
}

/// Queues one teardown on `inner` — the ONE body [`TeardownReaper::reap`] and
/// [`TeardownSink::reap`] share, so a submission from a detached job is counted,
/// claimed and grown against exactly like one from the driver's own task.
fn submit_to_reaper(inner: &Arc<ReaperInner>, teardown: Box<dyn FnOnce() + Send>) {
  let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
  state.queue.push_back(teardown);
  state.outstanding += 1;
  // One reaper per teardown that has no claimant yet, up to the cap: every live
  // reaper not inside a teardown is already headed for the queue, so a steady
  // driver stays at its baseline thread and a burst grows only as far as the
  // cap.
  //
  // Growth is a THROUGHPUT decision here and never a correctness one. Whoever is
  // calling holds either the reaper or one of its sinks, and a thread exits only
  // once neither exists (see [`ReaperState::producers`]) — so at least one
  // claimant is alive at this instant, and a refused thread costs latency rather
  // than stranding the submission.
  let grow = state.queue.len() > state.threads - state.busy && state.threads < MAX_TEARDOWN_REAPERS;
  if grow {
    state.threads += 1;
  }
  drop(state);
  inner.ready.notify_one();
  if !grow {
    return;
  }
  if spawn_reaper(inner).is_err() {
    // The OS refused a thread. Hand the reservation back and leave the teardown
    // queued: the baseline reaper — or any other still alive — inherits it on
    // finishing its own, and until then it stays counted, so close reports it
    // rather than losing it.
    inner
      .state
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .threads -= 1;
  }
}

/// Starts one reaper thread against `inner`, which must already be counted in
/// [`ReaperState::threads`].
fn spawn_reaper(inner: &Arc<ReaperInner>) -> std::io::Result<()> {
  #[cfg(test)]
  {
    if inner
      .refuse_threads
      .load(std::sync::atomic::Ordering::SeqCst)
    {
      return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
    }
  }
  let inner = Arc::clone(inner);
  std::thread::Builder::new()
    .name("tributary-teardown".to_owned())
    .spawn(move || reap_loop(&inner))
    .map(drop)
}

/// One reaper worker's registration in [`ReaperState::threads`], released — and, when the
/// queue would be left without a claimant, replaced — however that worker leaves.
///
/// `threads` used to be decremented by the single `return` in [`reap_loop`]'s exit predicate,
/// which is correct for exactly one of the ways a worker can end. Every other way skipped it,
/// and a skipped decrement is not a leak of a counter but a leak of the driver's whole
/// teardown capacity: `threads` is read as EXACT by [`submit_to_reaper`]'s growth rule
/// (`threads - busy` is how many queued teardowns already have a claimant), so a phantom
/// worker suppresses the growth that would give real queued work a real thread. Enough of
/// them and `threads == MAX_TEARDOWN_REAPERS` with no worker alive at all: every later
/// submission is queued, unclaimed, forever — and a queued closure owns a live
/// `SourceHandle`, so the stream it names is never reclaimed and its eventual drop performs
/// the unbounded join on whatever thread releases the last sink.
///
/// The escape that motivated this is a caught panic payload whose own `Drop` panics: the
/// second unwind ran past [`reap_loop`]'s containment while [`ClaimedTeardown`] repaired
/// `busy`/`outstanding` on the way out, so the accounting looked healthy and the worker was
/// simply gone. That specific unwind is now retired inside
/// [`dispose_panic_payload`](tributary_proto::unwind::dispose_panic_payload), but the guard is
/// deliberately not a patch for it: it covers the exit, not the cause, so a future early
/// return, a poisoned-lock unwind, or any other abnormal end costs the same nothing.
///
/// # Why replacing, and not just decrementing
///
/// A worker that leaves abnormally may have been the only claimant of a non-empty queue.
/// Decrementing alone makes the state HONEST — and the next submission's growth rule would
/// then create a thread — but nothing guarantees a next submission, and the queued teardowns
/// are already-counted obligations `close` parks on. So the guard re-runs the growth rule
/// itself: if the queue holds more than the survivors can claim it reserves and starts a
/// replacement, handing the reservation back if the OS refuses. It also wakes every survivor,
/// which costs one predicate re-read and removes any question of a wakeup consumed by the
/// worker that died.
struct LiveReaper<'a> {
  inner: &'a Arc<ReaperInner>,
}

impl Drop for LiveReaper<'_> {
  fn drop(&mut self) {
    let mut state = self
      .inner
      .state
      .lock()
      .unwrap_or_else(PoisonError::into_inner);
    state.threads -= 1;
    // `busy` never counts this worker here: `ClaimedTeardown` is scoped INSIDE the loop
    // body, so it has already released — on the normal path by its explicit drop, on an
    // unwinding one by unwinding first. The subtraction is therefore the same
    // claimant count the growth rule reads, and cannot underflow.
    let grow =
      state.queue.len() > state.threads - state.busy && state.threads < MAX_TEARDOWN_REAPERS;
    if grow {
      state.threads += 1;
    }
    drop(state);
    self.inner.ready.notify_all();
    if grow && spawn_reaper(self.inner).is_err() {
      self
        .inner
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .threads -= 1;
    }
  }
}

/// Retires one teardown from the outstanding count and frees the reaper that ran
/// it, waking [`TeardownReaper::settle`].
///
/// This is an RAII guard rather than a call at the end of the worker body, and
/// that is the whole point: the teardown it retires is an arbitrary closure over
/// a backend's `shutdown`, and an unwind out of one used to skip the retirement
/// entirely — leaving `busy` and `outstanding` counting an operation that had
/// stopped and a worker that was gone. The counters are read as EXACT by two
/// decisions that then reason from false state: [`TeardownReaper::reap`]'s growth
/// rule (`threads - busy` is how many queued teardowns already have a claimant,
/// so a phantom busy worker suppresses the growth that would give real queued
/// work a thread) and [`TeardownReaper::settle`]'s outstanding count (which close
/// parks on, so a phantom operation is an obligation close can never see
/// discharged). Enough unwinds and `threads == busy == MAX_TEARDOWN_REAPERS`
/// while no worker exists at all, and every later submission is stranded.
///
/// Held from the moment a closure is CLAIMED, so every exit path — return,
/// unwind, or any future early return — repairs both counters exactly once.
struct ClaimedTeardown<'a> {
  inner: &'a ReaperInner,
}

impl Drop for ClaimedTeardown<'_> {
  fn drop(&mut self) {
    let mut state = self
      .inner
      .state
      .lock()
      .unwrap_or_else(PoisonError::into_inner);
    state.busy -= 1;
    state.outstanding -= 1;
    drop(state);
    self.inner.settled.notify_all();
  }
}

impl Drop for TeardownReaper {
  fn drop(&mut self) {
    let mut state = self.lock();
    state.owner_gone = true;
    drop(state);
    self.inner.ready.notify_all();
  }
}

fn reap_loop(inner: &Arc<ReaperInner>) {
  // Held for the whole worker: the ONE place `threads` is given back, on every exit
  // (see [`LiveReaper`]).
  let _live = LiveReaper { inner };
  loop {
    let teardown = {
      let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
      loop {
        if let Some(teardown) = state.queue.pop_front() {
          state.busy += 1;
          break teardown;
        }
        // The exit predicate, read under the same lock every push and every
        // producer change takes: no further teardown can be submitted, and the
        // queue is already drained. While ANY producer lives this thread stays,
        // which is what makes a late submission's claimant exist by construction
        // instead of by a thread creation that might fail
        // (see [`ReaperState::producers`]).
        //
        // `threads` is NOT decremented here: the worker's registration is released by
        // [`LiveReaper`], the single path that covers this exit and every abnormal one
        // alike.
        if state.owner_gone && state.producers == 0 {
          return;
        }
        state = inner
          .ready
          .wait(state)
          .unwrap_or_else(PoisonError::into_inner);
      }
    };
    // The claim and its accounting are now inseparable: the guard is created the
    // instant the closure leaves the queue and repairs both counters however this
    // iteration ends.
    let claimed = ClaimedTeardown { inner };
    // Run outside the lock: this call is the unbounded join the reaper exists to
    // absorb, and holding the lock across it would park every submission — the
    // driver's own task included — behind the wedged filesystem.
    //
    // Contained rather than propagated. A worker that unwound would take its
    // thread with it while `threads` still counted it, and the driver's whole
    // teardown capacity is these threads — so one panicking backend `shutdown`
    // would permanently shrink the pool and, repeated, strand every later handle
    // in a queue with no live claimant. The closure ITSELF reports the failure
    // (see [`submit_teardown`]); this boundary exists so the WORKER survives to
    // claim the next one.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(teardown));
    drop(claimed);
    // The caught PAYLOAD is not the worker's data either. Dropping it here would run
    // the panicking code's own destructor in ordinary control flow, one line past the
    // boundary that just contained it, and a payload whose `Drop` panics would then
    // unwind straight out of this loop — taking the worker with it, silently, in the
    // one shape the containment above exists to prevent. It is retired inside its own
    // boundary instead.
    if let Err(payload) = unwound {
      let _ = tributary_proto::unwind::dispose_panic_payload(payload);
    }
    #[cfg(test)]
    if inner
      .unwind_after_claim
      .load(std::sync::atomic::Ordering::SeqCst)
      > 0
    {
      inner
        .unwind_after_claim
        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
      panic!("an injected worker unwind, outside every containment boundary");
    }
  }
}

/// Queues `handle`'s native teardown on the reaper under `scope`'s pending
/// accounting — the ONE submission path, so the counted obligation, the
/// unwind containment and the terminal that retires it can never diverge
/// between the birth, death, refusal, replacement and close-sweep sites that
/// all retire a stream.
///
/// The terminal is chosen by the shutdown's OUTCOME, and there are TWO ways to
/// fail it. A shutdown that returns [`Quiesce::Proven`](crate::os::Quiesce) sends
/// `TornDown` — the stream is proven gone. One that UNWINDS, and equally one
/// that RETURNS [`Quiesce::Unproven`](crate::os::Quiesce), sends
/// [`OpResult::TeardownFailed`]: the obligation is retired (nothing is still
/// running, and leaving it owed would make every later close report an
/// obligation that had already stopped) while close is told the quiescence was
/// never proven, so it reports honestly instead of returning `Ok` over an
/// unproven teardown.
///
/// Reading the unwind ALONE was the gap. A backend that must leak to stay
/// memory-safe — the Windows pumps, whose kernel-owned read buffers cannot be
/// freed on a panicked or undrained pump's word — catches its own panic,
/// retains the state, and returns normally. Its join then SUCCEEDED, so every
/// such failure was classified `TornDown`: handles and memory accumulated with
/// nothing incremented anywhere, while `unwatch` and `close` went on claiming
/// quiescence over them.
fn submit_teardown<H>(
  reaper: &TeardownReaper,
  op_tx: &async_channel::Sender<OpResult<H>>,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  scope: ScopeId,
  handle: H,
) where
  H: SourceControl + Send + 'static,
{
  *pending_teardowns.entry(scope).or_insert(0) += 1;
  let tx = op_tx.clone();
  reaper.reap(move || {
    // The shutdown's payload is retired inside its own boundary, never dropped here:
    // `handle.shutdown()` joins a reader thread, so the payload it carries can be that
    // thread's, and a payload whose `Drop` panics would otherwise unwind out of this
    // closure BEFORE the terminal below is sent — leaving the scope's obligation
    // retired by the worker's accounting with no verdict on the stream at all.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || handle.shutdown()));
    let terminal = match outcome {
      Err(payload) => {
        let _ = tributary_proto::unwind::dispose_panic_payload(payload);
        OpResult::TeardownFailed { scope }
      }
      Ok(crate::os::Quiesce::Unproven) => OpResult::TeardownFailed { scope },
      Ok(crate::os::Quiesce::Proven) => OpResult::TornDown { scope },
    };
    let _ = tx.try_send(terminal);
  });
}

/// Hands one finished spawn to the driver — and, when the driver is no longer
/// there to take it, hands the stream it created to the teardown reaper instead.
///
/// The result queue is UNBOUNDED, so a refused send is never backpressure from a
/// live driver: it means the receiver is gone, or [`OpQueue`]'s own `Drop` closed
/// it on the way out. That is what puts the sink route below in the same class as
/// the reservoir and escrow guards — the verdict is discarded because no frame is
/// left to read it, not because anyone chose not to look.
///
/// This runs on the runtime's SHARED blocking pool. Ignoring the send failure
/// would drop the returned message right here, and a successful message owns a
/// live `SourceHandle` whose `Drop` joins the reader it just started: exactly the
/// unbounded join the teardown contract forbids on this executor. One abnormal
/// close — the grace expires while a spawn is stalled in a post-live metadata
/// read, the driver returns and drops its receiver, then the stall clears — would
/// otherwise park a shared worker for as long as the filesystem stays wedged, and
/// on a legal one-worker pool starve every later spawn, enumerate, control and
/// cookie operation of every watcher sharing that runtime.
///
/// So the handle is EXTRACTED from the undeliverable message and enqueued on the
/// reaper sink, which outlives the driver's result receiver. A FAILED spawn takes
/// the same route whenever it carries a rollback stream: a barrier that failed
/// after its stream started hands the running stream back, and that stream's own
/// `Drop` performs the identical unbounded join. Only a failure with no stream at
/// all simply drops.
fn deliver_spawned<H>(
  op_tx: &async_channel::Sender<OpResult<H>>,
  sink: &TeardownSink,
  scope: ScopeId,
  result: Result<SpawnedSource<H>, SpawnFailed<H>>,
) where
  H: SourceControl + Send + 'static,
{
  let Err(undelivered) = op_tx.try_send(OpResult::Spawned { scope, result }) else {
    return;
  };
  let OpResult::Spawned { result, .. } = undelivered.into_inner() else {
    return;
  };
  match result {
    Ok(spawned) => sink.reap(move || {
      let _ = spawned.handle.shutdown();
    }),
    // Escrowed and immediately dropped: the escrow's own `Drop` is the reap, so
    // this path cannot diverge from every other one that hands a stream over
    // when no driver is left to count it.
    Err(failure) => drop(escrow_failure(failure, sink.clone()).1),
  }
}

/// Retires a spawned-but-refused replacement stream inside the counted
/// teardown accounting: it never becomes the scope's lane.
fn retire_refused<F>(
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  reaper: &TeardownReaper,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  scope: ScopeId,
  spawned: EscrowedSpawn<F::Handle>,
) where
  F: FsOps,
{
  spawned.retire(reaper, op_tx, pending_teardowns, scope);
}

/// Dispatches a general replace's replacement spawn under the birth
/// accounting — the shared tail of the admission's new-stream route and both
/// same-transport fallbacks (a re-validation miss at the meta, a refused core
/// commit). The swap window rides the journal, not just the covering Rescan:
/// the RETIRING stream's resume point is taken here — while the handle is
/// provably still live — and handed to the replacement's spawn, which replays
/// from it. Taking it EARLY only widens the replay, and duplicates are always
/// legal; a backend with no journal, a wrapped id space, or a foreign device
/// simply mints/honors nothing and the `Rescan` covers the window as before.
#[allow(clippy::too_many_arguments)]
fn dispatch_replace_spawn<R, F>(
  ops: &F,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  reaper: &TeardownReaper,
  config: &DriverConfig,
  handles: &BTreeMap<ScopeId, F::Handle>,
  pending_spawns: &mut BTreeSet<ScopeId>,
  scope: ScopeId,
  root: PathBuf,
) where
  R: RuntimeLite,
  F: FsOps,
{
  pending_spawns.insert(scope);
  let mut source_config = SourceConfig::new(vec![root]);
  source_config.since = handles.get(&scope).and_then(SourceControl::resume_token);
  source_config.exclusions = config.exclusions.clone();
  source_config.latency = config.latency;
  source_config.channel_capacity = config.os_batch_capacity;
  source_config.os_buffer_bytes = config.os_buffer_bytes;
  source_config.backend = config.backend;
  source_config.max_map_directories = config.max_map_directories;
  let ops = ops.clone();
  let tx = op_tx.clone();
  let sink = reaper.sink();
  R::spawn_blocking_detach(move || {
    let result = ops.spawn_source(source_config);
    deliver_spawned(&tx, &sink, scope, result);
  });
}

/// Whether replacing `old` with `new` is a same-transport WIDEN candidate:
/// the old root lies STRICTLY inside the new one and the connecting chain is
/// representable (every relative component is normal UTF-8 — the proto's
/// `Segment` vocabulary). Both paths are canonical at every call site, so the
/// lexical prefix test is object-true. A non-candidate silently takes the
/// general new-stream replace, whose semantics need no chain.
fn widen_predicate(old: &Path, new: &Path) -> bool {
  if old == new {
    return false;
  }
  old.strip_prefix(new).is_ok_and(|rel| {
    let mut any = false;
    for component in rel.components() {
      let std::path::Component::Normal(os) = component else {
        return false;
      };
      if os.to_str().is_none() {
        return false;
      }
      any = true;
    }
    any
  })
}

/// The io flavor an arm refusal lowers to — the ONE mapping every arm-failure
/// reply uses, so a consumer dispatches on the cause identically whichever
/// path answered it: [`arm_failure`] (the `replace_root`/widen pre-arm
/// replies) and [`arm_grant_error`] (`watch()`'s deferred root grant). These
/// two must not diverge again: lowering either through
/// `std::io::Error::other` stamps [`std::io::ErrorKind::Other`]
/// unconditionally, which erases the difference between a watch-limit
/// `ENOSPC`, a permission refusal and a plain I/O failure on that path alone,
/// leaving the cause readable only as a substring of the message.
const fn arm_error_kind(err: WatchError) -> std::io::ErrorKind {
  match err {
    WatchError::NotFound | WatchError::Gone => std::io::ErrorKind::NotFound,
    WatchError::Permission => std::io::ErrorKind::PermissionDenied,
    WatchError::NoSpace => std::io::ErrorKind::StorageFull,
    _ => std::io::ErrorKind::Other,
  }
}

/// Lowers a pre-arm refusal into the io flavor
/// [`SourceError::RootUnavailable`] carries.
fn arm_failure(err: WatchError) -> std::io::Error {
  std::io::Error::new(arm_error_kind(err), err.as_str())
}

/// Applies one source-lane message to the core — the ONE body both the run
/// loop's source arm and the widen commit's lane drain use, so the two can
/// never diverge. (The lane's `None` end marker is a stream artifact, not a
/// channel message, so only the arm can see it and it stays there.)
fn apply_source_message(
  core: &mut DriverCore,
  scope: ScopeId,
  msg: SourceMessage,
  now: &impl Fn() -> Instant,
) {
  match msg {
    // The payload travels whole: its budget slot is released by the
    // core exactly when the batch settles or is discarded, so parked
    // events stay inside the transport budget.
    SourceMessage::Batch(mut payload) => {
      // The ONE ingest boundary, and therefore the one place a journal
      // position may be published: everything past here is the core's, and
      // covered by the core's own loss machinery. A batch that never got here
      // leaves the source's resume point behind it, so a successor stream
      // re-reads that span instead of skipping it.
      payload.acknowledge_resume();
      core.on_batch(scope, payload, now());
    }
    // The queue is the source's ONE ordered lane, so everything the
    // signal postdates was already handled above it — no drain, no
    // barrier, nothing to reason about. Dropping the ack BEFORE
    // acting re-arms the dedup: a loss racing it either rides a
    // fresh message or is covered by the rescan this becomes.
    SourceMessage::Overflow(ack) => {
      drop(ack);
      core.on_root_overflow(scope, now());
    }
    SourceMessage::Fatal(_) => core.on_source_fatal(scope, now()),
  }
}

/// Routes one item yielded by the merged source stream — the ONE body the
/// select's source arm and the catch-up fairness poll share, so the two
/// ingestion sites can never diverge: the retired-lane gate, the message
/// application (with the catch-up ledger decrement), and the end-marker
/// death path.
fn ingest_source_item<F: FsOps>(
  core: &mut DriverCore,
  lanes: &BTreeMap<ScopeId, u64>,
  replace_states: &mut BTreeMap<ScopeId, ReplaceState<F::Handle>>,
  handles: &BTreeMap<ScopeId, F::Handle>,
  item: (ScopeId, u64, Option<SourceMessage>),
  now: &impl Fn() -> Instant,
) {
  let (scope, lane, msg) = item;
  // A retired lane's stragglers are dropped whole: the replace commit's
  // covering Rescan dominates them, and the retired end marker is a
  // teardown artifact, never a death. (Today every scope has exactly one
  // lane for its whole life, so this gate never fires — pinned by the
  // existing suites.)
  if lanes.get(&scope) != Some(&lane) {
    return;
  }
  match msg {
    Some(msg) => {
      apply_source_message(core, scope, msg, now);
      // The catch-up ledger: one prefix message consumed in the arm's own
      // frame — delivered, tainted, or funneled exactly as any other.
      // Saturating: post-snapshot arrivals are transport-concurrent with
      // the pending commit and must not extend its wait (they ride the
      // post-commit regime).
      if let Some(ReplaceState {
        mode:
          ReplaceMode::SameFd {
            phase: SameFdPhase::CatchUp { remaining, .. },
          },
        ..
      }) = replace_states.get_mut(&scope)
      {
        *remaining = remaining.saturating_sub(1);
      }
    }
    // The receiver disconnected while the stream should still be live: the
    // source died without managing to say so (its sender dropped) — a dead
    // stream, not a teardown of ours (that path removes the handle before
    // the disconnect can arrive). The end marker fires only after the queue
    // yielded everything it held.
    None => {
      if handles.contains_key(&scope) {
        core.on_source_fatal(scope, now());
      }
    }
  }
}

/// The settle-edge loss fence's drain bound: how much each CURRENT delivery
/// lane held when a drain pass began — the same drain-start snapshot
/// discipline the widen catch-up commit uses ([`SameFdPhase::CatchUp`]'s
/// `remaining`), so a producer re-enqueuing between consecutive driver polls
/// extends a pass only by the merged stream's fair-interleave factor, never
/// indefinitely.
///
/// The bound is per lane, not one global count, and that is load-bearing:
/// [`SelectAll`] interleaves READY lanes fairly rather than globally FIFO, so
/// under a total-count cap a burst arriving on one lane after the snapshot
/// could spend the whole cap while an item queued BEFORE the snapshot on
/// another lane — the loss the fence exists to ingest — was still waiting its
/// rotation. Per-lane budgets make the pass end (short of the queue going
/// momentarily empty, the strictly stronger exit) only once every lane has
/// yielded everything it held at the snapshot, whatever the interleaving.
///
/// Soundness (the fence's happens-before): a loss enqueued before the ACK
/// that armed the settle observation is still queued — on its live scope's
/// current lane, whose tap counts it — when the snapshot is taken, so it is
/// inside the budget and the pass cannot end before ingesting it. What the
/// budget excludes is exactly the arrivals AFTER drain start, which postdate
/// that ACK and legitimately trail the verdict. Items outside every budget
/// (a retired lane's finite, sender-less stragglers; post-snapshot arrivals)
/// are still ingested when yielded — they just don't extend the pass.
///
/// Termination: every budget unit is backed by an item the merged stream
/// will yield — `len()` counts queued messages whose sole consumer is this
/// task, and the `is_closed` unit counts the lane's `None` end marker, which
/// fires once the queue empties (a tap whose marker was already consumed is
/// removed with its lane by the teardown flush before the next pass, so no
/// unit is ever phantom). A backed lane stays ready until it yields, and the
/// fair interleave yields it within one rotation, so a pass polls at most
/// (outstanding × lanes)-ish items before every budget is spent.
struct SourceSnapshot {
  /// Items still owed per `(scope, current lane)` — absent means spent, or
  /// never counted (a retired lane, a lane that was empty at the snapshot).
  budgets: BTreeMap<(ScopeId, u64), usize>,
  /// The sum of `budgets` — the pass ends when it reaches zero.
  outstanding: usize,
}

impl SourceSnapshot {
  /// Counts what every live scope's current lane holds RIGHT NOW: the tap's
  /// queued length, plus one for a closed lane's still-queued end marker.
  fn taken(lanes: &BTreeMap<ScopeId, u64>, source_taps: &BTreeMap<ScopeId, EventReceiver>) -> Self {
    let mut budgets = BTreeMap::new();
    let mut outstanding = 0;
    for (scope, tap) in source_taps {
      let Some(lane) = lanes.get(scope) else {
        continue;
      };
      let queued = tap.len() + usize::from(tap.is_closed());
      if queued > 0 {
        budgets.insert((*scope, *lane), queued);
        outstanding += queued;
      }
    }
    Self {
      budgets,
      outstanding,
    }
  }

  /// Spends one budget unit for a yielded item; an untracked or already-spent
  /// lane's item costs nothing (it is post-snapshot or a retired straggler).
  fn consume(&mut self, scope: ScopeId, lane: u64) {
    if let Some(budget) = self.budgets.get_mut(&(scope, lane)) {
      *budget -= 1;
      self.outstanding -= 1;
      if *budget == 0 {
        self.budgets.remove(&(scope, lane));
      }
    }
  }

  /// Whether every counted item has been drained — the pass's bound.
  fn spent(&self) -> bool {
    self.outstanding == 0
  }

  /// The scopes whose lane still owes items — a spent budget is removed by
  /// [`consume`](Self::consume), so a scope drops out the instant its counted
  /// items are all ingested. This is the settlement pass's withholding set:
  /// per scope, because a lane's residue says nothing about any other scope's
  /// window.
  fn unspent_scopes(&self) -> BTreeSet<ScopeId> {
    self.budgets.keys().map(|(scope, _)| *scope).collect()
  }
}

/// Resolves every widen whose commit is CATCHING UP to its lane
/// ([`SameFdPhase::CatchUp`]) — called at the loop top strictly AFTER
/// [`execute_effects`] has flushed, which is load-bearing: the prefix's
/// deliveries (queued by the source arm at the still-current OLD root) have
/// then already reached the consumer, so no emit ever straddles the root
/// flip (G3-1 by construction). Per scope, in order:
///
/// - a DEAD scope — the stream gone, or the core state torn down by a death
///   the arm processed en route — resolves the widen `Retired` through the
///   same liveness gate every widen path uses; the witnessed window closes
///   with it and nothing was ever published (Golden-2's deferred publish);
/// - a scope whose prefix is consumed (`remaining == 0`) and whose lane is
///   not DEAD-PENDING commits: a closed tap means the source died with its
///   end marker still queued behind the prefix — committing now would jump
///   that death, so the check WAITS one iteration for the arm's marker path
///   to route the fatal (G2-1's single death funnel), after which the
///   liveness gate above answers `Retired`;
/// - anything else keeps waiting: the arm is still consuming the prefix,
///   one message per iteration with full effect flushes between (G2-2's
///   boundedness is the snapshot: `remaining` strictly decreases, so the
///   commit's delay is exactly the pre-commit backlog).
///
/// The commit itself is [`commit_widen`], unchanged: conflict check →
/// witnessed-window gate → splice → deferred registry publish → replay.
///
/// Returns whether any catch-up RESOLVED (committed, fell back, retired, or
/// errored) in this call: a committed widen enqueues its own post-splice
/// effects — the widened root's cold-read enumerate above all — AFTER the
/// loop's flush already ran, so the caller must flush once more before the
/// loop parks, or a quiescent widen would strand the newly covered ground
/// unread behind an already-resolved `Ok`. (The non-commit resolutions
/// enqueue no core effects today; reporting them too costs one no-op flush
/// per widen and keeps the contract robust if they ever do.)
#[allow(clippy::too_many_arguments)]
fn resolve_widen_catchups<R, F>(
  core: &mut DriverCore,
  ops: &F,
  config: &DriverConfig,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  reaper: &TeardownReaper,
  handles: &BTreeMap<ScopeId, F::Handle>,
  pending_spawns: &mut BTreeSet<ScopeId>,
  pending_teardowns: &BTreeMap<ScopeId, usize>,
  scope_backends: &BTreeMap<ScopeId, BackendKind>,
  source_taps: &BTreeMap<ScopeId, EventReceiver>,
  replace_states: &mut BTreeMap<ScopeId, ReplaceState<F::Handle>>,
  unwatch_replies: &mut BTreeMap<
    ScopeId,
    Vec<(futures_channel::oneshot::Sender<UnwatchAck>, UnwatchAck)>,
  >,
  parked_cookies: &mut BTreeMap<FenceId, ParkedCookie>,
  cookies: &mut CookieRegistry<F>,
  registry: &impl ScopeRegistry,
  now: &impl Fn() -> Instant,
) -> bool
where
  R: RuntimeLite,
  F: FsOps,
{
  let mut resolved_any = false;
  let catching_up: Vec<ScopeId> = replace_states
    .iter()
    .filter(|(_, state)| {
      matches!(
        state.mode,
        ReplaceMode::SameFd {
          phase: SameFdPhase::CatchUp { .. }
        }
      )
    })
    .map(|(scope, _)| *scope)
    .collect();
  for scope in catching_up {
    let dead = !handles.contains_key(&scope) || core.root_watch(scope).is_none();
    if !dead {
      let (ready, lane_dying) = match replace_states.get(&scope) {
        Some(ReplaceState {
          mode:
            ReplaceMode::SameFd {
              phase: SameFdPhase::CatchUp { remaining, .. },
            },
          ..
        }) => {
          // A live catching-up scope always has its lane tap — tap and
          // handle are inserted and removed together. A future refactor
          // breaking that pairing would otherwise wedge this widen silently
          // in the conservative wait below.
          debug_assert!(
            source_taps.contains_key(&scope),
            "a live catching-up scope keeps its lane tap"
          );
          (
            *remaining == 0,
            // A closed tap with the scope still alive: the end marker is
            // queued behind the prefix — wait for the arm to route it.
            source_taps.get(&scope).is_none_or(EventReceiver::is_closed),
          )
        }
        _ => continue,
      };
      if !ready || lane_dying {
        continue;
      }
    }
    let Some(replace) = replace_states.remove(&scope) else {
      continue;
    };
    let ReplaceMode::SameFd {
      phase:
        SameFdPhase::CatchUp {
          reserved,
          meta,
          replay,
          ..
        },
    } = replace.mode
    else {
      debug_assert!(false, "just matched CatchUp above");
      continue;
    };
    resolved_any = true;
    let widened = meta.root.clone();
    let outcome = if dead {
      // Death won during the catch-up: the arm's one end-marker/death path
      // already ran the funnel; the witnessed window closes with the widen.
      core.abort_widen_watch(scope);
      Err(crate::error::ReplaceRootError::Retired)
    } else {
      let backend = *scope_backends
        .get(&scope)
        .expect("a live scope has a committed backend");
      let stats = handles
        .get(&scope)
        .expect("checked live above")
        .backend_stats();
      commit_widen::<R, F>(
        core,
        ops,
        registry,
        scope,
        meta,
        reserved,
        replace.reservation.path(),
        replay,
        backend,
        stats,
        now,
      )
    };
    let resolution = match outcome {
      Ok(WidenOutcome::Committed) => {
        // The cookie floor follows the committed root. The widen uncovers
        // nothing (old ⊂ new), so the parked-barrier revoke is a provable
        // no-op — kept for uniformity with the stream-replace commits.
        // Deliberately absent: the generation bump and the lane swap — the
        // stream did not retire, and an in-flight cookie write under the
        // old root must still claim on it.
        revoke_uncovered_parked_cookies(core, parked_cookies, cookies, scope, &widened);
        cookies.scope_live(scope, widened);
        Ok(())
      }
      Ok(WidenOutcome::FallBack(taint)) => {
        // Diagnostic (env-gated, off by default): name WHY the same-fd widen
        // fell back to the general stream replace so a CI re-flake attributes
        // the escalation to this producer. A tainted window carries its
        // INV-ROOT cause; `None` is the core's impossible-path refusal.
        if std::env::var("TRIBUTARY_FS_WIDEN_DEBUG").is_ok() {
          // Best-effort: a diagnostic must never unwind the driver mid-fallback.
          let mut err = std::io::stderr().lock();
          match &taint {
            Some(t) => {
              let _ = writeln!(
                err,
                "[tributary-fs widen-debug] same-fd widen FELL BACK to stream-replace: \
                 tainted window (cause={:?}, benign={})",
                t.cause, t.benign
              );
            }
            None => {
              let _ = writeln!(
                err,
                "[tributary-fs widen-debug] same-fd widen FELL BACK to stream-replace: \
                 core impossible-path refusal"
              );
            }
          }
        }
        // The splice did not land — a TAINTED witnessed window (INV-ROOT's
        // legitimate refusal, `taint` carrying the witness diagnostics) or
        // the core's impossible-path refusal (already loud inside
        // `commit_widen`). The registry still names the OLD root — the live
        // truth — through the whole fallback (Golden-2: the widened entry
        // publishes only at a commit), so a fallback whose spawn FAILS
        // leaves admission consistent. The caller's obligation converts to
        // the general stream replace: its commit overwrites the entry with
        // spawn-minted truth (clearing any leftover window), its failure
        // taxonomy answers the caller, and its fresh spawn barrier
        // re-establishes the root binding the window could not prove. The
        // reservation and reply ride along on the re-parked state; nothing
        // resolves here.
        dispatch_replace_spawn::<R, F>(
          ops,
          op_tx,
          reaper,
          config,
          handles,
          pending_spawns,
          scope,
          widened,
        );
        replace_states.insert(
          scope,
          ReplaceState {
            reservation: replace.reservation,
            reply: replace.reply,
            mode: ReplaceMode::NewFd { arming: None },
          },
        );
        continue;
      }
      Err(err) => Err(err),
    };
    // No resolution here enqueues a teardown, so a parked unwatch is
    // re-checked exactly as after a failed replacement spawn.
    if scope_quiesced(
      scope,
      handles,
      pending_spawns,
      pending_teardowns,
      replace_states,
    ) {
      resolve_unwatch_waiters(unwatch_replies, scope);
    }
    drop(replace.reservation);
    let _ = replace.reply.send(resolution);
  }
  resolved_any
}

/// Commits (or refuses) one root replacement that already passed the
/// router's death-wins and lowering gates (they also guard the descending
/// pre-arm, which runs before this point). Every failure path tears the NEW
/// stream down inside the counted accounting and leaves the old root
/// untouched — atomic-on-failure. Success retires the old stream (counted),
/// installs the new lane, and feeds the core's
/// [`on_root_replaced`](DriverCore::on_root_replaced) cut; a descending
/// commit then replays the pre-armed root outcome (`replay`) so the rebound
/// root's re-arm-flavored rebuild starts on the new transport.
#[allow(clippy::too_many_arguments)]
fn commit_replace<F>(
  core: &mut DriverCore,
  ops: &F,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  reaper: &TeardownReaper,
  handles: &mut BTreeMap<ScopeId, F::Handle>,
  lanes: &mut BTreeMap<ScopeId, u64>,
  next_lane: &mut u64,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  os: &mut SelectAll<
    futures_util::stream::BoxStream<'static, (ScopeId, u64, Option<SourceMessage>)>,
  >,
  source_taps: &mut BTreeMap<ScopeId, EventReceiver>,
  registry: &impl ScopeRegistry,
  cookies: &CookieRegistry<F>,
  scope: ScopeId,
  spawned: EscrowedSpawn<F::Handle>,
  reserved: &Path,
  replay: Option<WatchOutcome>,
  now: &impl Fn() -> Instant,
) -> Result<BackendKind, crate::error::ReplaceRootError>
where
  F: FsOps,
{
  use crate::error::ReplaceRootError;

  // The single-writer final check: the spawn re-canonicalized, so the
  // FINAL root's disjointness (exempting this scope AND the command's own
  // reservation) is settled here, immediately before commit.
  if let Some(existing) = registry.final_root_conflict(
    &spawned.meta.root,
    spawned.meta.identity,
    &spawned.meta.ancestors,
    Some(reserved),
    Some(scope),
  ) {
    let err = ReplaceRootError::Overlaps {
      path: spawned.meta.root.clone(),
      existing,
    };
    // Refused: the new stream never becomes the scope's lane.
    retire_refused::<F>(op_tx, reaper, pending_teardowns, scope, spawned);
    return Err(err);
  }

  // Make-before-break: the new stream is live; retire the old one now,
  // inside the counted accounting. The retirement goes to the reaper rather
  // than the blocking pool because the old reader is exactly the thread the
  // replacement is being spawned to escape: joining it there would let a
  // stuck-on-a-dead-filesystem transport consume the workers the replacement's
  // own arms and ordering proof need (see [`TeardownReaper`]).
  //
  // Escrowed on the way out of the map, like every other handle in transit: the
  // retiring stream is under a guard from the removal to the submission.
  if let Some(old) = handles.remove(&scope) {
    StreamEscrow::new(old, spawned.stream.sink()).retire(reaper, op_tx, pending_teardowns, scope);
  }
  let EscrowedSpawn {
    stream,
    receiver,
    meta,
  } = spawned;
  // Bump the cookie root generation AT the lane swap, under the ledger lock: a
  // write dispatched under the retiring root can no longer claim once the new
  // stream is live (it sees the newer generation and self-reaps), while one
  // that already claimed belongs to the still-current old stream. This IS the
  // swap's linearization point — the transport generation mint below is its
  // control-plane twin.
  cookies.advance_generation_locked(scope);
  // Mint the replacement's transport generation FIRST, then detach the old
  // port and attach the new one under it: any old-generation control batch
  // still in flight now fails the front-check against this newer generation.
  let lane = *next_lane;
  *next_lane += 1;
  lanes.insert(scope, lane);
  ops.detach_scope(scope);
  ops.attach_scope(scope, stream.get().scope_port(), lane);
  let backend = meta.backend;
  let stats = stream.get().backend_stats();
  stream.commit(handles, scope);
  // The lane's drain tap re-binds with the lane: a widen commit on the NEW
  // stream drains this queue, and the retired lane's old clone drops here.
  source_taps.insert(scope, receiver.clone());
  os.push(
    receiver
      .map(move |msg| (scope, lane, Some(msg)))
      .chain(futures_util::stream::once(
        async move { (scope, lane, None) },
      ))
      .boxed(),
  );
  // Registry overwrite BEFORE the core commit — the same program order
  // birth uses, on the same single-writer task.
  registry.scope_live(
    scope,
    &meta.root,
    meta.identity,
    &meta.ancestors,
    backend,
    stats,
  );
  let watch = core.root_watch(scope);
  // The rebind supersedes every arm the retired transport still owes, and hands
  // back the attempt the replay must name — so a straggler from the dead world
  // answers an attempt the core no longer holds and is discarded, rather than
  // invalidating the binding it never touched.
  let rebound = core.on_root_replaced(scope, meta, now());
  // Descending: replay the pre-armed root outcome the commit adopted; the
  // rebound root is a pending re-arm, and this is the arm it awaits.
  if let (Some(outcome), Some(watch), Some(attempt)) = (replay, watch, rebound) {
    core.on_watch_installed(watch, attempt, outcome);
  }
  Ok(backend)
}

/// Commits (or refuses) one same-transport WIDEN whose pre-arm succeeded on
/// the live port. The commit is the D1 shape minus everything stream-shaped —
/// no lane swap, no generation bump, no handle retirement, no covering
/// `Rescan` — because nothing retires: the core splices the new root above
/// the old one and only then the registry publishes the widened root
/// (atomic-on-failure: every non-committed path leaves the OLD entry — the
/// live truth — in place for the fallback or the caller's error)
/// ([`on_root_widened`](DriverCore::on_root_widened)), and the pre-armed
/// outcome replays so the widened root's COLD read discovers the new ground.
/// The one refusal with something to unwind is the final-root conflict: the
/// pre-armed watch descriptor sits on a stream that KEEPS living, so it is
/// disarmed rather than left to attribute noise for the scope's lifetime.
#[allow(clippy::too_many_arguments)]
fn commit_widen<R, F>(
  core: &mut DriverCore,
  ops: &F,
  registry: &impl ScopeRegistry,
  scope: ScopeId,
  meta: RootMeta,
  reserved: WatchId,
  reserved_path: &Path,
  replay: WatchOutcome,
  backend: BackendKind,
  stats: Option<crate::os::BackendStatsHandle>,
  now: &impl Fn() -> Instant,
) -> Result<WidenOutcome, crate::error::ReplaceRootError>
where
  R: RuntimeLite,
  F: FsOps,
{
  // The single-writer final check, exempting this scope and the command's own
  // reservation — the same authority order the stream-replace commit uses.
  if let Some(existing) = registry.final_root_conflict(
    &meta.root,
    meta.identity,
    &meta.ancestors,
    Some(reserved_path),
    Some(scope),
  ) {
    let err = crate::error::ReplaceRootError::Overlaps {
      path: meta.root.clone(),
      existing,
    };
    // The widen ends here with the OLD world live: close its witnessed
    // window with it, or the leaked entry would poison a future widen's
    // reservation on this scope.
    core.abort_widen_watch(scope);
    let ops = ops.clone();
    R::spawn_blocking_detach(move || ops.remove_watch(scope, reserved));
    return Err(err);
  }
  // The registry publish is DEFERRED to the Committed arm (Golden-2:
  // atomic-on-failure): publishing the widened root before the gate decided
  // left the entry naming a root nobody covers on every non-committed path —
  // and a tainted fallback whose D1 spawn then FAILED would return the error
  // with the corrupt entry in place, poisoning root_path and every later
  // overlap admission. The whole check→commit→publish sequence runs
  // synchronously on the single-writer task, so no reader can observe a gap;
  // the fields the publish needs are captured here because the core commit
  // consumes `meta`.
  let published_root = meta.root.clone();
  let published_identity = meta.identity;
  let published_ancestors = meta.ancestors.clone();
  match core.on_root_widened(scope, meta, reserved, now()) {
    WidenCommit::Committed(attempt) => {
      // The splice landed: NOW the registry names the widened root — the
      // same single-writer program order as birth and the stream replace
      // (decision complete, then publish, then the caller can observe).
      registry.scope_live(
        scope,
        &published_root,
        published_identity,
        &published_ancestors,
        backend,
        stats,
      );
      // Replay the pre-armed outcome: the widened root leaves its pending arm
      // and its cold enumerate begins on the unchanged transport.
      core.on_watch_installed(reserved, attempt, replay);
      Ok(WidenOutcome::Committed)
    }
    WidenCommit::TaintedWindow(taint) => {
      // The commit is not provable — the witnessed window tainted (INV-ROOT:
      // a reserved death record or a scope loss landed between the
      // reservation and this commit, so the pre-armed binding cannot be
      // proven live), the old root had no mintable identity for the
      // adopted edge's re-proof, or it sat more than one segment down, where
      // the splice's connector edges carry no proof at all. Each is a
      // LEGITIMATE refusal, never a bug.
      // The core CONSUMED the window on this path (unlike `Refused` below,
      // which leaves it bit-identical), so there is nothing left for
      // `abort_widen_watch` to close. Disarm the descriptor (mirroring the
      // conflict path above: the live stream keeps running until the fallback
      // retires it) and hand the obligation to the general stream replace,
      // whose fresh spawn barrier re-establishes the binding the commit could
      // not prove.
      let ops = ops.clone();
      R::spawn_blocking_detach(move || ops.remove_watch(scope, reserved));
      Ok(WidenOutcome::FallBack(Some(taint)))
    }
    WidenCommit::Refused => {
      // The impossible path, loud: a violated precondition refused the splice
      // with the core, Monitor, and registry all untouched (the publish is
      // deferred to Committed, so the OLD entry — the live truth — stands).
      // Close the window (the fallback spawn may FAIL, and a leaked entry
      // would poison a later widen), disarm the pre-armed descriptor, and
      // hand the obligation to the general stream replace (see
      // [`WidenOutcome`]).
      debug_assert!(false, "a live descending scope accepts its widen commit");
      core.abort_widen_watch(scope);
      let ops = ops.clone();
      R::spawn_blocking_detach(move || ops.remove_watch(scope, reserved));
      Ok(WidenOutcome::FallBack(None))
    }
  }
}

/// One scope's queued control batches: the lane generation each was emitted
/// under, its ops, and the ordering-proof request it carries (`None` for an
/// ordinary arm or disarm batch, which owes no proof).
///
/// The deque carries ONE invariant, which both enqueue paths
/// ([`queue_control_batch`] and [`queue_cut_proof`]) restore before they return:
/// no two ADJACENT ordinary entries share a generation. Proofs are themselves
/// coalesced to at most one per scope, so that caps the queue at one ordinary
/// entry per generation it carries plus that single proof — and only a transport
/// swap mints a generation, so no volume of directory churn can add an entry at
/// all.
///
/// The cap is what keeps a barrier reachable. Enqueue rate is set by that churn;
/// drain rate is one batch per scope at a time, each paying for the reader's
/// pre-reply kernel-queue cut. Uncapped, a local producer minting create/delete
/// traffic faster than batches complete grows the queue without bound, and the
/// ordering proof a set-cover or sync waits on sits BEHIND all of it — a barrier
/// starved for as long as the churn lasts, with every completed arm's `O_PATH`
/// anchor held open until its disarm, stuck behind the same backlog, finally
/// runs. Capped, the proof is always reached after at most one finite batch.
///
/// The invariant is restored by MERGING. The one thing ever dropped is an
/// obsolete proof, which carries no requests and is owed to nobody (see
/// [`queue_cut_proof`]); dropping an ordinary entry would strand every
/// registration waiting on an arm it carried, because even a refused arm returns
/// the outcome its Monitor node is parked on. So what is capped is the NUMBER of
/// queued batches, not the work inside them: a coalesced batch's own request
/// vector still grows under sustained churn, unchanged from dispatching every
/// batch straight to the blocking pool, where the same payloads accumulated in
/// the pool's own queue instead.
///
/// That remaining growth is a KNOWN, DELIBERATE exception to the retention rule
/// the rest of this driver now follows ([`MAX_TEARDOWN_BACKLOG`],
/// [`MAX_PARKED_SETTLEMENTS`], [`MAX_ENUMERATE_ENTRIES`]): every one of those
/// bounds is enforced by REFUSING an admission, and there is nothing here to
/// refuse. These requests are not caller requests at all — they are the Monitor's
/// own derived coverage work, each one OWED to a node parked on its outcome, so
/// the only ways to bound them are to shed the exact history or to stop producing
/// it, and both were rejected on their costs rather than overlooked:
///
/// - **Shed to a scope-wide loss.** Discarding the queue and letting the
///   overflow cut re-derive coverage from a cold read would bound it, and the
///   covering `Rescan` would keep the CONSUMER whole. But a discarded
///   `RemoveWatch` leaves a kernel watch on an object the Monitor no longer
///   models, and a discarded `AddWatch` leaves a directory unarmed until some
///   later read happens to re-visit it — trading bounded memory for stranded
///   kernel coverage, which is silent loss of exactly the kind this crate refuses
///   to trade for anything.
/// - **Backpressure the producer.** Refusing to drain a scope's source lane while
///   its backlog is over a cap would bound it through the transport, whose own
///   overflow already lowers to a covering `Rescan`. But the lanes are merged into
///   one `SelectAll`, so declining to poll is watcher-wide: one wedged scope would
///   stop DELIVERY for every healthy one, converting bounded memory growth into an
///   unbounded, watcher-wide delivery stall. That is a worse availability posture
///   than the growth it fixes.
///
/// What does bound it, and why the growth is survivable rather than merely
/// admitted: the queue is per-scope and dies whole with its scope; the payload is
/// arms and disarms for directories, so it is bounded at any instant by the
/// scope's live directory count plus the churn a stalled control batch spans, not
/// by the watcher's lifetime; and the cap above guarantees an ordering proof is
/// always reached after at most one finite batch, so a barrier's latency is a
/// function of that payload rather than unbounded in the number of batches. A
/// real fix belongs with the core: an explicit rebuild mode that INVALIDATES the
/// queued attempts and re-derives coverage from current truth, which is a change
/// to the recovery algebra, not to this queue.
type PendingControl = BTreeMap<ScopeId, VecDeque<(u64, Vec<ControlRequest>, Option<u64>)>>;

/// Each scope with a control batch dispatched and not yet completed, mapped to
/// the transport GENERATION that batch was emitted for — the wait
/// [`kick_control_queue`] holds its queue on.
///
/// The generation is half the key, not bookkeeping. Serialization exists to keep
/// emission order among batches that can reach the same transport, and only
/// same-generation batches can: a batch whose generation a replace has retired
/// fails the source's front-check and publishes nothing into the swapped scope,
/// so it can neither reorder against a newer batch nor orphan anything one of
/// them arms. Holding a scope's queue on it would therefore buy no ordering while
/// costing all of the scope's control liveness — an arm blocked inside a syscall
/// on a hung or retired filesystem is observed only BETWEEN operations, so a
/// scope-keyed wait would leave the replacement root partially armed and every
/// clean fence latched for as long as that syscall takes to return, which on a
/// dead mount is indefinitely.
///
/// The generation is held bare rather than inside a
/// [`Stamped`](crate::stamped::Stamped), which would guard nothing here: the
/// mark's whole content IS its generation, so such a wrapper has no value to
/// withhold and every read of it would go through the stamp regardless. Nor is
/// there one incarnation for it to be read against — the two questions asked of
/// the mark compare it to different things, the scope's CURRENT lane in
/// [`kick_control_queue`] (is a batch this queue must wait for still running?)
/// and a COMPLETING batch's own generation at its `ControlBatchDone` (is this the
/// batch the mark names?).
type ControlInflight = BTreeMap<ScopeId, u64>;

/// Whether `generation` names a transport `scope` has already swapped away from,
/// judged against the scope's CURRENT delivery lane.
///
/// A scope with no lane resolves the `u64::MAX` sentinel — a value no real lane
/// reaches — so a batch emitted for a live lane reads retired the moment its
/// stream is torn down, and a batch emitted with the sentinel itself (no stream)
/// reads current, which is harmless: such a scope holds no queue to release.
fn generation_retired(lanes: &BTreeMap<ScopeId, u64>, scope: ScopeId, generation: u64) -> bool {
  lanes.get(&scope).copied().unwrap_or(u64::MAX) != generation
}

/// Appends `entry` to `queue`, MERGING it into the tail instead when both are
/// ordinary batches of one generation — the single rule that maintains
/// [`PendingControl`]'s adjacency invariant, shared by both enqueue paths.
///
/// Appending onto the tail's request vector places the entry's ops exactly where
/// a separate trailing entry would have run them, so emission order is untouched:
/// a disarm emitted after a re-add still cannot run ahead of it and orphan its
/// kernel watch. Nor can a merge ever reach a RUNNING batch, because this queue
/// holds only UN-SUBMITTED work — [`kick_control_queue`] pops the front out of the
/// deque before handing it to the pool, so anything still in the deque is by
/// construction not executing.
///
/// Only the SAME generation may merge. A transport swap bumps the generation, and
/// a batch carries the generation captured at ITS emission so a stale batch fails
/// the source's front-check and publishes nothing into the swapped scope; merging
/// across that boundary would hand the older generation's requests to a newer one,
/// arming the replacement's fd with watches that were refused by construction.
///
/// A proof neither absorbs a merge nor rides into one. An EMPTY batch IS the pure
/// ordering proof: giving it requests, or moving its requests elsewhere, changes
/// what the reader is being asked to prove.
fn push_coalesced(
  queue: &mut VecDeque<(u64, Vec<ControlRequest>, Option<u64>)>,
  entry: (u64, Vec<ControlRequest>, Option<u64>),
) {
  let (generation, requests, cut_token) = entry;
  if cut_token.is_none()
    && let Some((queued_generation, queued, None)) = queue.back_mut()
    && *queued_generation == generation
  {
    queued.extend(requests);
    return;
  }
  queue.push_back((generation, requests, cut_token));
}

/// Queues `scope`'s ordering-proof request, COALESCING it with any proof
/// successor already waiting, so the scope holds at most one in flight plus one
/// queued however hard the latch churns.
///
/// The proof latch is invalidated three ways: a reconcile putting new work into
/// the window and a newly opened fence whose window starts later than the proof
/// each reset it to `Unproven`, and the scope's coverage-work epoch moving
/// retires whatever it holds where it stands. A scope whose in-flight proof is
/// slow therefore re-enters `covers_awaiting_cut` on EVERY such invalidation, and
/// appending a batch per one grows the scope's queue with the REQUEST count:
/// the bounded command mailbox limits only instantaneous input, the abandoned-
/// fence prune never touches these, and when traffic stops every obsolete token
/// still has to cross the reader serially before the newest one can prove —
/// unbounded memory and an O(N) barrier delay.
///
/// A queued proof entry is provably obsolete the moment a new request is minted
/// for the same scope. Minting requires a latch that does not already answer for
/// the scope's current epoch, and it OVERWRITES the latch with the fresh token —
/// so the queued entry's own token, stamped when it was queued, is no longer the
/// one the latch names and can no longer close anything
/// ([`DriverCore::prove_cut`] matches the live request's token, under the epoch
/// it was stamped with). Dropping it loses no work and no reply either: a proof
/// batch carries no requests — an empty batch mutates nothing — and only a
/// SUBMITTED batch owes a `ControlBatchDone`, so an entry that never left this
/// queue is owed to nobody.
///
/// Dropping those obsolete proofs is also what can leave two ordinary entries
/// NEWLY adjacent — they were separated by a proof that no longer exists — so the
/// survivors are re-laid through [`push_coalesced`] before the fresh request goes
/// on. Without that compaction each proof/churn alternation would strand one more
/// unmergeable entry in the queue permanently, and the barrier the proof serves
/// would drift back behind an unbounded run of them: exactly the accumulation
/// [`PendingControl`]'s invariant exists to forbid.
///
/// Merging across a removed proof is safe for the same reason merging at the back
/// is. Two ordinary entries were emitted in queue order, so appending the later
/// one's requests onto the earlier one's vector preserves that order exactly, and
/// the proof that used to sit between them has already been established as
/// obsolete — nothing that had to run between them remains. Same-generation-only
/// still applies, unchanged.
///
/// The fresh request is then appended at the BACK, exactly where an
/// un-coalesced one would land, so emission order behind the scope's queued arms
/// and disarms is untouched: coalescing removes obsolete entries and fuses
/// same-generation neighbours, it never moves a live request forward past one
/// that must precede it.
fn queue_cut_proof(pending_control: &mut PendingControl, scope: ScopeId, lane: u64, token: u64) {
  let queue = pending_control.entry(scope).or_default();
  queue.retain(|(_, _, carried)| carried.is_none());
  let mut compacted = VecDeque::with_capacity(queue.len());
  for entry in queue.drain(..) {
    push_coalesced(&mut compacted, entry);
  }
  *queue = compacted;
  queue.push_back((lane, Vec::new(), Some(token)));
}

/// Queues one drain's arms and disarms for `scope`, COALESCING them into the
/// batch already waiting at the BACK of its queue whenever that batch shares
/// their generation and carries no ordering proof.
///
/// This is [`PendingControl`]'s invariant seen from the churn side: `execute_effects`
/// groups a whole drain into one batch per scope, so an un-coalesced enqueue adds
/// an entry per drain and a producer churning directories faster than batches
/// complete pushes the barrier's ordering proof behind an unbounded run of them.
/// Merging at the tail is what makes the queue's depth independent of how hard the
/// tree is churned; [`push_coalesced`] carries the rule and the reasoning that
/// keeps the merge order-preserving and generation-safe.
fn queue_control_batch(
  pending_control: &mut PendingControl,
  scope: ScopeId,
  generation: u64,
  requests: Vec<ControlRequest>,
) {
  push_coalesced(
    pending_control.entry(scope).or_default(),
    (generation, requests, None),
  );
}

/// Dispatches ONE control batch: hands it to the executor on the blocking pool,
/// carrying the [`ControlAnswer`] that will report its outcome and release the
/// scope's NEXT queued batch.
///
/// The handoff takes a pool worker and gives it back. [`FsOps::dispatch_control`]
/// is contracted never to wait for a reader, so its cost is the batch's own
/// translation — or, for an executor that answers arms itself, the batch itself —
/// and the sink then travels on to whoever produces the outcome. Nothing here, on
/// the pool or anywhere else, waits for that: an executor that never answers costs
/// this driver a live `ControlAnswer` and not one unit of any executor, which is
/// what lets a scope carry arbitrarily many batches stranded on transports it has
/// already retired without denying its LIVE generation the pool.
///
/// The ordering the serialization needs is unaffected, because it never depended
/// on where the outcome was awaited: the predecessor's completion is consumed by
/// the DRIVER — which submits the successor on its `ControlBatchDone` — never by a
/// parked worker, so emission ordering holds on ANY `RuntimeLite` pool, FIFO or
/// not, bounded or not, with no risk of the bounded/non-FIFO deadlock a
/// worker-parked chain invites (W successors could occupy every worker while each
/// waits on a still-queued predecessor).
fn submit_control_batch<R, F>(
  ops: &F,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  scope: ScopeId,
  generation: u64,
  requests: Vec<ControlRequest>,
  cut_token: Option<u64>,
) where
  R: RuntimeLite,
  F: FsOps,
{
  let ops = ops.clone();
  let answer = ControlAnswer {
    op_tx: op_tx.clone(),
    scope,
    generation,
    cut_token,
    end: ControlBatchEnd::default(),
  };
  R::spawn_blocking_detach(move || ops.dispatch_control(scope, generation, requests, answer));
}

/// The single point a control batch moves from a scope's driver-held queue onto
/// the blocking pool: submits the front batch when nothing the queue must wait
/// for is running, otherwise leaves it queued for the running batch's
/// `ControlBatchDone` to release. Draining an emptied queue drops its entry so a
/// live scope keeps no residual control state (scope ids are never reused). A
/// no-op when the queue is empty (a torn-down or never-seen scope holds no queue
/// and no mark, so a late completion kicks nothing) — completion-drives-next,
/// never worker-blocks-on-next.
///
/// The queue waits on the running batch only while that batch's generation is
/// still the scope's CURRENT transport. Serializing across a swap would buy no
/// ordering: a batch of a retired generation fails the source's front-check and
/// publishes nothing into the swapped scope, so it can neither reorder against a
/// newer batch nor orphan a watch one of them arms. What it would cost is the
/// scope's entire control liveness, because a batch is not preemptible — an arm
/// blocked in a syscall on a hung or retired filesystem returns when the kernel
/// says so, and reader shutdown is observed only BETWEEN operations. Holding on
/// it would leave the replacement root partially armed and every clean fence
/// latched for that whole time. So a retired running batch releases the queue,
/// and the batch that goes out claims the mark under ITS OWN generation, which
/// is what keeps the completions unambiguous.
///
/// Releasing the queue frees the replacement's work LOGICALLY; the work still has
/// to find an executor to run on, and on a narrow pool it may find none. Two
/// things stop that, and both are about a retired transport costing the pool
/// nothing: NOTHING waits for the stalled batch's reader — its outcome is reported
/// by whoever produces it (see [`FsOps::dispatch_control`]) — and the swap's
/// teardown, a join on the very reader that batch is stuck inside, runs off the
/// pool entirely (see [`TeardownReaper`]). A pool those two could between them
/// occupy would have nothing left for the work this release just freed, and the
/// liveness would be handed straight back.
///
/// At most one CURRENT-generation batch is therefore in flight per scope, which
/// is the ordering guarantee stated exactly: the mark is claimed by every
/// submission and cleared only by the completion that matches it, so a second
/// current-generation batch can be submitted only after the first has completed.
/// Retired batches may overlap each other and a current one, and that is the
/// point — every one of them refuses at the front-check before it touches the
/// transport.
fn kick_control_queue<R, F>(
  ops: &F,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  pending_control: &mut PendingControl,
  control_inflight: &mut ControlInflight,
  lanes: &BTreeMap<ScopeId, u64>,
  scope: ScopeId,
) where
  R: RuntimeLite,
  F: FsOps,
{
  if control_inflight
    .get(&scope)
    .is_some_and(|running| !generation_retired(lanes, scope, *running))
  {
    // A batch of the live transport is running; its ControlBatchDone releases
    // the next.
    return;
  }
  let Some((generation, requests, cut_token)) = pending_control
    .get_mut(&scope)
    .and_then(VecDeque::pop_front)
  else {
    // Nothing queued (idle scope, or its queue was just torn down).
    return;
  };
  if pending_control.get(&scope).is_some_and(VecDeque::is_empty) {
    pending_control.remove(&scope);
  }
  control_inflight.insert(scope, generation);
  submit_control_batch::<R, F>(ops, op_tx, scope, generation, requests, cut_token);
}

/// Executes the core's queued effects, feeding each outcome straight back.
#[allow(clippy::too_many_arguments)]
fn execute_effects<R, F>(
  core: &mut DriverCore,
  ops: &F,
  config: &DriverConfig,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  reaper: &TeardownReaper,
  handles: &mut BTreeMap<ScopeId, F::Handle>,
  pending_spawns: &mut BTreeSet<ScopeId>,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  scope_backends: &mut BTreeMap<ScopeId, BackendKind>,
  lanes: &mut BTreeMap<ScopeId, u64>,
  source_taps: &mut BTreeMap<ScopeId, EventReceiver>,
  events: &async_channel::Sender<(ScopeId, Arc<PathBuf>, Change)>,
  unwatch_replies: &mut BTreeMap<
    ScopeId,
    Vec<(futures_channel::oneshot::Sender<UnwatchAck>, UnwatchAck)>,
  >,
  deferred_grants: &mut BTreeMap<ScopeId, DeferredGrant>,
  pending_control: &mut PendingControl,
  control_inflight: &mut ControlInflight,
  cookies: &mut CookieRegistry<F>,
  registry: &impl ScopeRegistry,
  now: &impl Fn() -> Instant,
) where
  R: RuntimeLite,
  F: FsOps,
{
  // Arms/disarms from this whole drain, grouped by scope: dispatched as one
  // batch per scope AFTER the drain, so a cycle that arms N directories sends
  // one control message (one potential reader wake) instead of N. Non-control
  // effects still dispatch inline in emission order.
  let mut control_batches: BTreeMap<ScopeId, Vec<ControlRequest>> = BTreeMap::new();
  // Scopes torn down during THIS drain. The post-drain control dispatch
  // consults it so a scope that died mid-drain is never handed a fresh batch:
  // teardown already reclaimed its lane and dropped its control queue + in-flight
  // mark, scope ids are never reused, and nothing would ever remove state
  // re-inserted for it — so an entry left here would grow `pending_control` /
  // `control_inflight` unbounded under root churn. A control op collected for the
  // scope EARLIER in this same drain (a child re-add or disarm ahead of the
  // root's DELETE_SELF) must not resurrect its queue; the dead scope's batch is
  // dropped rather than dispatched.
  let mut torn_down: BTreeSet<ScopeId> = BTreeSet::new();
  while let Some(effect) = core.poll_effect() {
    match effect {
      Effect::SpawnStream { scope, root } => {
        pending_spawns.insert(scope);
        let mut source_config = SourceConfig::new(vec![root]);
        source_config.exclusions = config.exclusions.clone();
        source_config.latency = config.latency;
        source_config.channel_capacity = config.os_batch_capacity;
        source_config.os_buffer_bytes = config.os_buffer_bytes;
        // The spawn selector carries the consumer's backend choice straight to
        // the barrier: `Backend::Auto` probes and falls back, a forced backend
        // pins it (and surfaces a typed error rather than falling back).
        // (macOS ignores the selector — FSEvents is its one backend.)
        source_config.backend = config.backend;
        source_config.max_map_directories = config.max_map_directories;
        let ops = ops.clone();
        let tx = op_tx.clone();
        let sink = reaper.sink();
        R::spawn_blocking_detach(move || {
          let result = ops.spawn_source(source_config);
          deliver_spawned(&tx, &sink, scope, result);
        });
      }
      Effect::TeardownStream { scope } => {
        scope_backends.remove(&scope);
        // The delivery lane (the transport generation) is reclaimed with the
        // scope — scope ids are never reused, so leaving it would grow `lanes`
        // unbounded under ordinary watch/unwatch churn. A late control batch
        // for the gone scope then resolves no lane and refuses (the `u64::MAX`
        // sentinel), exactly the right answer for a torn-down transport.
        lanes.remove(&scope);
        // The control queue and in-flight mark die with the lane for the same
        // reason: a torn-down scope dispatches no further batches, so a residual
        // entry would only grow these maps unbounded under watch/unwatch churn.
        // Any batch already ON the pool keeps running and completes; its
        // ControlBatchDone then finds no queue and no mark and is inert (it
        // re-creates NO state). Dropping the queue here is not enough on its own:
        // a control op for this scope collected EARLIER in the same drain still
        // sits in `control_batches`, and the post-drain dispatch would submit it
        // (re-marking the dead scope in-flight). Recording the teardown makes
        // that dispatch skip the scope, so after a drain that tore a scope down
        // NO per-scope control state remains for it — within the tearing drain,
        // not only across later ones.
        pending_control.remove(&scope);
        control_inflight.remove(&scope);
        torn_down.insert(scope);
        // The lane's drain tap dies with the lane — a clone kept past this
        // point would grow the map unbounded under watch/unwatch churn.
        source_taps.remove(&scope);
        // Every scope end — explicit unwatch, root death, stream fatal —
        // funnels through this effect: reclaim the registry entry, so a dead
        // root stops participating in liveness checks immediately. The arm
        // port detaches with it (late arms answer the typed refusal), and a
        // registration still waiting on its root arm resolves as a failure
        // (the scope died before coverage ever started).
        registry.scope_dead(scope);
        ops.detach_scope(scope);
        // The scope's cookies retire with its stream: no cleanup reap will
        // arrive for a write whose reply was abandoned, and there will be no
        // stream left to report one on. The registry raises the scope's flag
        // before it dispatches its tracked unlinks, so a write still in the pool
        // reaps itself rather than landing a file behind this sweep.
        cookies.retire_scope::<R>(scope, op_tx);
        if let Some(DeferredGrant { pending, root }) = deferred_grants.remove(&scope) {
          let _ = pending
            .reply
            .send(Err(WatchRootError::Source(SourceError::RootUnavailable {
              root,
              source: std::io::Error::other("the source died before the root watch armed"),
            })));
        }
        if let Some(handle) = handles.remove(&scope) {
          // Escrowed on the way out of the map: the same rule every other
          // in-transit handle follows (see [`StreamEscrow`]).
          StreamEscrow::new(handle, reaper.sink()).retire(reaper, op_tx, pending_teardowns, scope);
        } else {
          // No stream ever existed (a failed spawn); every awaited unwatch is
          // complete now.
          resolve_unwatch_waiters(unwatch_replies, scope);
        }
      }
      Effect::AddWatch {
        scope,
        watch,
        attempt,
        parent,
        name,
        path,
        expected,
      } => {
        // Droppable at close, unlike spawns and teardowns: a result that
        // never lands leaves the Monitor node Arming, and the node dies with
        // its scope. The kernel watch (if the arm did install one) is not
        // leaked either — every wd on the source's fd is reclaimed when the
        // scope's stream teardown closes that fd. No pending-set entry.
        // Collected here and dispatched as part of the scope's batch below.
        control_batches
          .entry(scope)
          .or_default()
          .push(ControlRequest::Arm {
            watch,
            attempt: Some(attempt),
            parent,
            name,
            path,
            expected,
          });
      }
      Effect::RemoveWatch { scope, watch } => {
        // Fire-and-forget by contract; droppable at close for the same
        // fd-reclamation reason as AddWatch. Batched with this scope's arms.
        control_batches
          .entry(scope)
          .or_default()
          .push(ControlRequest::Disarm { watch });
      }
      Effect::Enumerate { req, watch, path } => {
        // Droppable at close: a listing that never lands leaves the Monitor
        // node Enumerating; the scope teardown clears its pending request.
        // No OS resource is held by a readdir.
        //
        // The watch's transient anchor is TAKEN here — synchronously, in the
        // same step that turns the core's decision into a job — and MOVED into
        // that job, which is what binds it to this one read (see
        // [`FsOps::take_enumerate_anchor`]). Superseding this read cannot
        // cancel its already-detached job, so leaving the anchor in a shared
        // table for the job to claim later would let it take a successor's.
        // Ownership travelling with the job also means a job dropped unrun
        // closes what it holds.
        let anchor = ops.take_enumerate_anchor(watch);
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let raw = ops.enumerate(watch, anchor, &path);
          let _ = tx.try_send(OpResult::Enumerated { req, raw });
        });
      }
      Effect::Probe { probe, path } => {
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let outcome = ops.probe(&path);
          let _ = tx.try_send(OpResult::Probed { probe, outcome });
        });
      }
      Effect::RefreshMounts { scope, root } => {
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let refresh = ops.refresh_mounts(&root);
          let _ = tx.try_send(OpResult::MountsRefreshed { scope, refresh });
        });
      }
      Effect::Emit {
        scope,
        root,
        change,
      } => {
        // Read BEFORE the send, which moves the change into the channel on
        // success: an acceptance reports the generation it accepted, and that is
        // the only thing that raises the scope's delivery watermark.
        let epoch = change.epoch();
        match events.try_send((scope, root, change)) {
          Ok(()) => core.on_delivery(scope, Delivery::Accepted(epoch), now()),
          Err(async_channel::TrySendError::Full(_)) => {
            core.on_delivery(scope, Delivery::Refused, now());
          }
          // The consumer dropped its stream; shutdown arrives via the command
          // channel closing, so undeliverable changes are simply gone. RECORDED,
          // though, because this arm reports no `Delivery` at all: a lagged lane's
          // in-flight mark is never released and its parked change never re-offered,
          // so an ordering hold waiting on delivery must learn here that no offer
          // can ever land and discharge terminally instead.
          Err(async_channel::TrySendError::Closed(_)) => core.on_consumer_gone(),
        }
      }
    }
  }

  // Dispatch each scope's collected arms/disarms as ONE batch on the blocking
  // pool: the source ships it as a single control message (one potential reader
  // wake for the whole batch), and each arm still feeds back its own
  // `WatchInstalled`. Disarms are fire-and-forget (no reply). The scope's
  // CURRENT transport generation is captured here, at emission, and carried
  // into the batch: if a replace swaps the transport before this batch runs,
  // it fails the generation check and neither arms the replacement's fd nor
  // publishes a stale anchor into the swapped scope.
  for (scope, requests) in control_batches {
    // A scope torn down earlier in THIS drain dispatches no further batches:
    // its queue and in-flight mark are already reclaimed, its Monitor node is
    // gone (a dropped arm result just leaves that dead node Arming), and every
    // wd on its closed fd is reclaimed by the stream teardown. Skipping keeps
    // the no-residual invariant — after a drain that tore a scope down, NO
    // per-scope control state remains for it — which queuing-then-submitting
    // below would break by re-marking a dead scope in-flight. The generation
    // fence stays intact for LIVE scopes (a transport swap bumps the lane, not
    // tears it down); only the torn-down scope's stale batch is dropped, which
    // the fence would refuse anyway once the lane resolved to the `u64::MAX`
    // sentinel.
    if torn_down.contains(&scope) {
      continue;
    }
    // The scope's CURRENT transport generation is captured here, at emission,
    // and carried into the batch: if a replace swaps the transport before this
    // batch runs, it fails the generation check and neither arms the
    // replacement's fd nor publishes a stale anchor into the swapped scope.
    let generation = lanes.get(&scope).copied().unwrap_or(u64::MAX);
    // Enqueue this batch in EMISSION order behind the scope's earlier ones, then
    // submit the queue's front unless a batch of the scope's CURRENT transport
    // is still running. A batch only executes once its same-generation
    // predecessor has reached an end (both the reader execution AND the anchor
    // publication done) — the driver submits the successor on that
    // completion signal, so the two never reorder (a disarm emitted after a
    // re-add can never run ahead of it and orphan its kernel watch + O_PATH
    // anchor) — yet NO blocking-pool worker ever parks waiting for another
    // batch: the wait is this driver-held queue, not a pool thread, so the
    // serialization is immune to the pool's start order and worker bound (a
    // worker-parked chain deadlocks a bounded, non-FIFO pool). A batch stranded
    // on a retired transport holds nothing back — see [`kick_control_queue`].
    // The enqueue COALESCES into the queue's trailing same-generation batch
    // rather than appending unconditionally, so churn arriving faster than
    // batches complete cannot push the ordering proof behind an unbounded run of
    // them — see [`queue_control_batch`].
    queue_control_batch(pending_control, scope, generation, requests);
    kick_control_queue::<R, F>(ops, op_tx, pending_control, control_inflight, lanes, scope);
  }
}

/// Clones the driver-relevant shape of a spawn error: the core needs the
/// class, the caller keeps the original (io::Error is not Clone).
fn clone_error(err: &SourceError) -> SourceError {
  match err {
    SourceError::RootUnavailable { root, source } => SourceError::RootUnavailable {
      root: root.clone(),
      source: std::io::Error::new(source.kind(), source.kind().to_string()),
    },
    SourceError::Unsupported => SourceError::Unsupported,
    SourceError::NoRoots => SourceError::NoRoots,
    SourceError::NotADirectory { root } => SourceError::NotADirectory { root: root.clone() },
    SourceError::RootReplaced { root } => SourceError::RootReplaced { root: root.clone() },
    SourceError::TooManyExclusions { supplied } => SourceError::TooManyExclusions {
      supplied: *supplied,
    },
    SourceError::ExclusionRejected => SourceError::ExclusionRejected,
    SourceError::CreateFailed => SourceError::CreateFailed,
    SourceError::InstanceLimit => SourceError::InstanceLimit,
    SourceError::ReadFailed { source } => SourceError::ReadFailed {
      source: std::io::Error::new(source.kind(), source.kind().to_string()),
    },
    SourceError::StartFailed => SourceError::StartFailed,
    SourceError::BackendProbeFailed { stage } => SourceError::BackendProbeFailed { stage: *stage },
    SourceError::ForeignBackend { requested } => SourceError::ForeignBackend {
      requested: *requested,
    },
    SourceError::CallbackPanic => SourceError::CallbackPanic,
  }
}
