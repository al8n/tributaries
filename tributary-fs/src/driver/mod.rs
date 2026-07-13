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
  collections::{BTreeMap, BTreeSet},
  num::NonZeroUsize,
  path::{Path, PathBuf},
  sync::Arc,
  time::Duration,
};

use agnostic_lite::{RuntimeLite, time::Instant as _};
use futures_util::{FutureExt, StreamExt, stream::SelectAll};
use tributary_proto::{
  Change, Instant, Interest, IoClass, ReqId, ScopeId, Segment, WatchError, WatchId,
};

use crate::{
  core::{
    CoverNoop, CoverReconcile, CoverSettle, Delivery, DriverCore, Effect, ExpectedObject, FenceId,
    MountRefresh, ProbeId, ProbeOutcome, RawDirEntry, RawEnumerate, RootLiveness,
  },
  error::WatchRootError,
  os::{
    Backend, BackendKind, EventReceiver, RootIdentity, RootMeta, ScopePort, Source, SourceConfig,
    SourceError, SourceHandle, SourceMessage, linux::WatchOutcome,
  },
  watcher::{CoverOutcome, SkipReason},
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
  /// The periodic root-liveness deadline for signal-silent-on-unmount backends
  /// (fanotify): the driver re-stats such a root on this cadence so a quiet
  /// unmount — which emits no kernel signal and no loss — is still detected.
  /// [`Duration::ZERO`] disables the tick.
  pub(crate) root_liveness_interval: Duration,
  /// The fanotify admission-map directory cap (design §4.9); `None` = uncapped.
  /// Threaded into each fanotify spawn's `SourceConfig`; ignored by inotify and
  /// macOS.
  pub(crate) max_map_directories: Option<usize>,
}

impl DriverConfig {
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

/// One in-flight root replacement: the reservation the commit releases and
/// the caller's reply. A descending replace parks its spawned-but-uncommitted
/// replacement in `arming` while the new root's pre-arm runs on the blocking
/// pool ([`FsOps::preflight_arm`]); a kernel-recursive replace commits
/// straight off its spawn and never populates it.
struct ReplaceState<H> {
  reservation: crate::watcher::ReservationGuard,
  reply: futures_channel::oneshot::Sender<Result<(), crate::error::ReplaceRootError>>,
  arming: Option<SpawnedSource<H>>,
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
fn arm_grant_error(err: WatchError, requested: PathBuf, root: PathBuf) -> WatchRootError {
  match err {
    WatchError::NotFound | WatchError::Gone => WatchRootError::NotFound { path: requested },
    err => WatchRootError::Source(SourceError::RootUnavailable {
      root,
      source: std::io::Error::other(format!(
        "the root watch could not be armed ({})",
        err.as_str()
      )),
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
    /// whether the scope existed); `None` for the non-blocking, reply-less
    /// [`Watcher::request_unwatch`](crate::Watcher::request_unwatch) — the SAME teardown and
    /// registry reclamation, simply unacknowledged. The driver applies both
    /// identically and skips the ack when there is no reply.
    reply: Option<futures_channel::oneshot::Sender<bool>>,
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
  /// Orderly shutdown; resolves when every stream is torn down.
  Close {
    /// Resolved with the number of teardowns still wedged past the close
    /// grace — 0 means native-stream quiescence was proven.
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
    CoverSettle::Degraded => CoverOutcome::Degraded,
  }
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
fn resolve_cover_settlements(
  core: &mut DriverCore,
  cover_replies: &mut BTreeMap<FenceId, futures_channel::oneshot::Sender<CoverOutcome>>,
) {
  let mut abandoned = std::collections::BTreeSet::new();
  cover_replies.retain(|fence, reply| {
    let live = !reply.is_canceled();
    if !live {
      abandoned.insert(*fence);
    }
    live
  });
  core.abandon_cover_fences(&abandoned);
  for (fence, settle) in core.poll_cover_settlements() {
    // A missing sender is a caller dropped at close; settlement already
    // updated the core's bookkeeping either way.
    if let Some(reply) = cover_replies.remove(&fence) {
      let _ = reply.send(settle_outcome(settle));
    }
  }
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
    parent: WatchId,
    name: Segment,
    path: Arc<PathBuf>,
    expected: Option<ExpectedObject>,
  },
  /// Remove `watch`'s per-directory watch (fire-and-forget; no reply).
  Disarm { watch: WatchId },
}

/// The blocking-pool side of the platform: spawn, teardown, and stat. A
/// test implementation runs the whole driver loop against a fake filesystem.
pub(crate) trait FsOps: Clone + Send + Sync + 'static {
  /// The live-stream handle type.
  type Handle: SourceControl;

  /// Starts the native source (blocking).
  fn spawn_source(&self, config: SourceConfig) -> Result<SpawnedSource<Self::Handle>, SourceError>;

  /// `lstat`s one path (blocking).
  fn probe(&self, path: &Path) -> ProbeOutcome;

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
  /// arm's outcome, in order. The default runs them one-by-one through
  /// [`add_watch`](Self::add_watch)/[`remove_watch`](Self::remove_watch) — the
  /// right shape for a fake with no transport; the real inotify source
  /// overrides it to ship the whole batch as ONE control message so N arms cost
  /// at most one reader wake. `generation` is the transport generation the
  /// batch was emitted for; the real source refuses a batch whose generation
  /// no longer matches the attached port (a leftover of a replaced
  /// transport). The default ignores it — a fake answers arms itself and has
  /// no transport to leak.
  fn batch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> Vec<(WatchId, WatchOutcome)> {
    let _ = generation;
    let mut outcomes = Vec::new();
    for request in requests {
      match request {
        ControlRequest::Arm {
          watch,
          parent,
          name,
          path,
          expected,
        } => outcomes.push((
          watch,
          self.add_watch(scope, watch, parent, &path, &name, expected),
        )),
        ControlRequest::Disarm { watch } => self.remove_watch(scope, watch),
      }
    }
    outcomes
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

  /// Reads one directory — entries with their stat facts (blocking). Reached
  /// only under a descending profile; `watch` addresses the directory object
  /// for executors that resolve anchors rather than paths.
  fn enumerate(&self, watch: WatchId, path: &Path) -> RawEnumerate;
}

/// The control surface of a live stream handle.
pub(crate) trait SourceControl: Send + 'static {
  /// Quiesces and destroys the stream (blocking, bounded).
  fn shutdown(self);

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
}

impl SourceControl for SourceHandle {
  fn shutdown(self) {
    SourceHandle::shutdown(self);
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn scope_port(&self) -> ScopePort {
    SourceHandle::scope_port(self)
  }

  #[cfg(all(target_os = "linux", not(miri)))]
  fn backend_stats(&self) -> Option<crate::os::BackendStatsHandle> {
    SourceHandle::backend_stats(self)
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
/// (`/proc/self/fd/N`) enumerate reads every fact THROUGH the pinned fd too. Any
/// errno propagates unchanged (notably `NOENT`), keeping the callers'
/// `Missing`/raced-away meanings.
#[cfg(all(target_os = "linux", not(miri)))]
fn stat_sample(path: &Path) -> Result<StatSample, rustix::io::Errno> {
  use rustix::fs::{AtFlags, StatxFlags, makedev, statx};
  let stx = statx(
    rustix::fs::CWD,
    path,
    AtFlags::SYMLINK_NOFOLLOW,
    StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID),
  )?;
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
  /// Transient `O_PATH` anchors returned by arms (keyed by the globally
  /// unique watch, valued with the owning scope for teardown reclamation),
  /// held only until the watch's cold enumerate consumes them
  /// (anchor-relative readdir), so fd usage stays O(in-flight operations) —
  /// never O(tree).
  #[cfg(all(target_os = "linux", not(miri)))]
  anchors: std::sync::Arc<std::sync::Mutex<BTreeMap<WatchId, (ScopeId, std::os::fd::OwnedFd)>>>,
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
        .and_then(|(_, fd)| fd.try_clone().ok())
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
}

impl FsOps for RealFs {
  type Handle = SourceHandle;

  fn spawn_source(&self, config: SourceConfig) -> Result<SpawnedSource<Self::Handle>, SourceError> {
    if !config.backend.native_to_host() {
      return Err(SourceError::ForeignBackend {
        requested: config.backend,
      });
    }
    // The spawn itself mints the RootMeta — canonical root, device, and the
    // mount seed are all finalized BEFORE the stream starts delivering, so
    // the metadata is a safe authority for every event on the queue; deriving
    // any of it here, after start, could postdate events already enqueued.
    let (handle, receiver, meta) = Source::spawn(config)?;
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
    anchors.retain(|_, (anchor_scope, _)| *anchor_scope != scope);
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
    // generation rather than one captured earlier.
    let generation = self.current_generation(scope);
    self
      .batch_control(
        scope,
        generation,
        vec![ControlRequest::Arm {
          watch,
          parent,
          name: name.clone(),
          path: Arc::new(path.to_path_buf()),
          expected,
        }],
      )
      .into_iter()
      .next()
      .map(|(_, outcome)| outcome)
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
  #[cfg(all(target_os = "linux", not(miri)))]
  fn batch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> Vec<(WatchId, WatchOutcome)> {
    use crate::os::linux::ControlOp;

    // GENERATION FRONT-CHECK: a batch whose generation no longer matches the
    // attached port is a leftover of a transport a replace has since
    // retired. Its arms must NOT install on the replacement's fd (they name
    // old-world paths), and its disarms are moot (their kernel watches died
    // with the old fd). The one live case that also lands here is a
    // kernel-recursive or teardown-racing scope with no descending port —
    // both refuse identically.
    let port = match self.ports.read().unwrap().get(&scope) {
      Some((attached, ScopePort::Inotify(port))) if *attached == generation => port.clone(),
      _ => {
        return requests
          .iter()
          .filter_map(|request| match request {
            ControlRequest::Arm { watch, .. } => {
              Some((*watch, WatchOutcome::Failed(WatchError::Gone)))
            }
            ControlRequest::Disarm { .. } => None,
          })
          .collect();
      }
    };

    // Build the control ops in emission order, remembering each arm's watch so
    // the reader's index-aligned replies map back to their outcomes. Disarms
    // drop the watch's transient anchor here (the reader issues the kernel
    // removal).
    let mut ops = Vec::with_capacity(requests.len());
    let mut arm_watches = Vec::new();
    for request in requests {
      match request {
        ControlRequest::Arm {
          watch,
          parent,
          name,
          path,
          expected,
        } => {
          ops.push(ControlOp::Arm(
            self.build_arm_request(watch, parent, &path, &name, expected),
          ));
          arm_watches.push(watch);
        }
        ControlRequest::Disarm { watch } => {
          self.anchors.lock().unwrap().remove(&watch);
          ops.push(ControlOp::Disarm(watch));
        }
      }
    }

    let replies = port.batch(ops);
    // Publish each arm's transient anchor (held until its cold enumerate
    // consumes it) under the anchors lock, re-confirming the generation still
    // matches WHILE holding it. A replace committing during `port.batch`
    // above swaps the port under a NEW generation; without this re-check a
    // late insert would resurrect an anchor `detach_scope` just purged. The
    // lock is held across the ports read so the check and the insert are
    // atomic against `detach_scope` (which purges under the same lock).
    let mut outcomes = Vec::with_capacity(arm_watches.len());
    let mut anchors = self.anchors.lock().unwrap();
    let still_current = self
      .ports
      .read()
      .unwrap()
      .get(&scope)
      .is_some_and(|(attached, _)| *attached == generation);
    for (watch, reply) in arm_watches.into_iter().zip(replies) {
      if let Some(anchor) = reply.anchor
        && still_current
      {
        anchors.insert(watch, (scope, anchor));
      }
      outcomes.push((watch, reply.outcome));
    }
    outcomes
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
    let Some(reply) = port.batch(ops).pop() else {
      return WatchOutcome::Failed(WatchError::Gone);
    };
    // The anchor is deliberately DROPPED, not stored: the commit's
    // detach_scope purges this scope's anchors wholesale, and a refused
    // commit would leave a stale anchor pointing into a torn-down transport.
    // The post-commit root enumerate falls back to path-based listing — a
    // new root renamed inside that window reads as the root dying right
    // after the swap, healed loudly by the refresh-cadence liveness check.
    reply.outcome
  }

  fn enumerate(&self, watch: WatchId, path: &Path) -> RawEnumerate {
    // Consume the watch's transient anchor when one is still held: the
    // listing then reads THROUGH the armed object (/proc re-opens an O_PATH
    // fd), immune to a rename between the arm and this read. The anchor
    // closes on scope exit either way — fd usage stays O(in-flight).
    #[cfg(all(target_os = "linux", not(miri)))]
    {
      use std::os::fd::AsRawFd;
      let anchor = self.anchors.lock().unwrap().remove(&watch);
      if let Some((_, anchor)) = anchor {
        let via = PathBuf::from(format!("/proc/self/fd/{}", anchor.as_raw_fd()));
        let listed = list_dir(&via);
        drop(anchor);
        return listed;
      }
    }
    let _ = watch;
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

/// One blocking readdir + a single per-entry stat sample, lowered to raw stat
/// facts (see [`dir_entry_stat`] for the one-sample discipline).
fn list_dir(path: &Path) -> RawEnumerate {
  let dir = match std::fs::read_dir(path) {
    Ok(dir) => dir,
    Err(err) => return RawEnumerate::Failed(io_class(&err)),
  };
  let mut entries = Vec::new();
  let mut complete = true;
  for entry in dir {
    let Ok(entry) = entry else {
      // The read was cut short mid-directory; what was seen still
      // reconciles, and the incomplete flag drives the Monitor's retry.
      complete = false;
      break;
    };
    let entry_path = entry.path();
    let Some((kind, dev, ino, mnt_id)) = dir_entry_stat(&entry_path) else {
      // A raced-away entry: the listing no longer reflects one name.
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

/// One blocking operation's result, shipped back to the select loop.
enum OpResult<H> {
  Spawned {
    scope: ScopeId,
    result: Result<SpawnedSource<H>, SourceError>,
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
  WatchInstalled {
    watch: WatchId,
    outcome: WatchOutcome,
  },
  /// A descending replace's pre-arm resolved: the new root's kernel watch on
  /// the REPLACEMENT transport installed (or refused) while the old stream
  /// still owns the scope. Routed to the replace commit, never to the core's
  /// ordinary watch-result path.
  RebindArmed {
    scope: ScopeId,
    outcome: WatchOutcome,
  },
  Enumerated {
    req: ReqId,
    raw: RawEnumerate,
  },
}

/// Runs one watcher's driver loop until `commands` closes or a `Close`
/// command arrives. Consumes the command receiver and the event sender; the
/// sender dropping is the consumer's end-of-stream.
pub(crate) async fn run<R, F>(
  config: DriverConfig,
  ops: F,
  commands: async_channel::Receiver<Command>,
  events: async_channel::Sender<(ScopeId, Arc<PathBuf>, Change)>,
  registry: impl ScopeRegistry,
) where
  R: RuntimeLite,
  F: FsOps,
{
  let mut core = DriverCore::new(
    config.effective_move_window(),
    config.root_liveness_interval,
  );
  let origin = R::now();
  let now = move || Instant::from_origin(R::now().duration_since(origin));
  // Unbounded so the blocking pool reports results with a plain `try_send`
  // (`send_blocking` does not exist on wasm builds, where async-channel has no
  // blocking API); the op volume is already bounded by outstanding operations
  // — one spawn/teardown per root plus one probe per parked batch item.
  let (op_tx, op_rx) = async_channel::unbounded::<OpResult<F::Handle>>();
  // One lane per source: its single ordered queue, chased by a `None` end
  // marker — the receiver-disconnect fact itself, which a dropped sender
  // would otherwise erase silently.
  let mut os: SelectAll<
    futures_util::stream::BoxStream<'static, (ScopeId, u64, Option<SourceMessage>)>,
  > = SelectAll::new();
  // The guard keeps the SelectAll from ever emptying: an empty SelectAll
  // reports termination, which would spin the loop's stream arm.
  os.push(futures_util::stream::pending().boxed());
  let mut handles: BTreeMap<ScopeId, F::Handle> = BTreeMap::new();
  // Each spawned stream is one delivery LANE, tagged by a per-driver
  // generation: a scope's current lane is the one whose messages reach the
  // core. Today exactly one lane exists per scope for its whole life;
  // replace_root retires a lane and installs a successor under the SAME
  // scope, and a retired lane's stragglers are dropped here (dominated by
  // the replace commit's covering Rescan) — its end marker is not a death.
  let mut lanes: BTreeMap<ScopeId, u64> = BTreeMap::new();
  let mut next_lane: u64 = 0;
  // Blocking-pool work that owns — or is about to own — a native stream:
  // spawns dispatched but not yet returned, teardowns dispatched but not yet
  // confirmed. Close quiesces BOTH alongside the live handles: a spawn still
  // in flight can otherwise start a native source after the close reply, and
  // an unconfirmed teardown is a stream still winding down. Teardowns COUNT
  // rather than flag: a replace can have the retired lane's teardown in
  // flight while the scope is live on its successor, so one scope may owe
  // several confirmations.
  let mut pending_spawns: BTreeSet<ScopeId> = BTreeSet::new();
  let mut pending_teardowns: BTreeMap<ScopeId, usize> = BTreeMap::new();
  // In-flight root replacements, keyed by the (live) scope being widened:
  // the reservation parks here until the commit or failure releases it, and
  // the OpResult::Spawned router below diverts a replace-spawn's result away
  // from the birth path.
  let mut replace_states: BTreeMap<ScopeId, ReplaceState<F::Handle>> = BTreeMap::new();
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
  let mut deferred_grants: BTreeMap<ScopeId, DeferredGrant> = BTreeMap::new();
  let mut unwatch_replies: BTreeMap<ScopeId, futures_channel::oneshot::Sender<bool>> =
    BTreeMap::new();
  // Awaited set-cover acknowledgements parked under their settlement fences
  // (see `Command::SetCover`): resolved by `resolve_cover_settlements` at the
  // loop top once the scope's re-arm work quiesces, dropped at close (the
  // caller sees `Closed` through the dropped-reply mapping).
  let mut cover_replies: BTreeMap<FenceId, futures_channel::oneshot::Sender<CoverOutcome>> =
    BTreeMap::new();
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
      &mut handles,
      &mut pending_spawns,
      &mut pending_teardowns,
      &mut scope_backends,
      &lanes,
      &events,
      &mut unwatch_replies,
      &mut deferred_grants,
      &registry,
      &now,
    );

    // Set-cover settlements resolve at this one choke point — after the
    // previous arm's results fed the core and their effects drained, BEFORE
    // any new command is processed — so a lossy settle's `applied_cover`
    // rewind always lands before the next reconcile computes its broadening
    // delta, and a teardown-folded `Degraded` is delivered promptly.
    resolve_cover_settlements(&mut core, &mut cover_replies);

    let deadline = core
      .poll_timeout()
      .map(|d| origin + d.elapsed_since_origin());
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
            if replace_states.contains_key(&scope) {
              let spawned = match result {
                Ok(spawned) => spawned,
                Err(err) => {
                  let replace = replace_states.remove(&scope).expect("just checked");
                  drop(replace.reservation);
                  let _ = replace
                    .reply
                    .send(Err(crate::error::ReplaceRootError::Source(err)));
                  // A failed replacement spawn is the one resolution that
                  // enqueues NO teardown (there is nothing to retire), so a
                  // concurrent unwatch waiting on this scope would never be
                  // re-checked by a TornDown — resolve it here if the failed
                  // spawn was the last obligation. Every other resolution
                  // ends in a counted teardown whose TornDown re-checks.
                  if scope_quiesced(
                    scope,
                    &handles,
                    &pending_spawns,
                    &pending_teardowns,
                    &replace_states,
                  ) && let Some(reply) = unwatch_replies.remove(&scope)
                  {
                    let _ = reply.send(true);
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
              let refusal = if !handles.contains_key(&scope) {
                Some(crate::error::ReplaceRootError::Retired)
              } else if old_kr != backend.is_kernel_recursive() {
                Some(crate::error::ReplaceRootError::BackendDiverged)
              } else {
                None
              };
              if let Some(err) = refusal {
                let replace = replace_states.remove(&scope).expect("just checked");
                retire_refused::<R, F>(&op_tx, &mut pending_teardowns, scope, spawned);
                drop(replace.reservation);
                let _ = replace.reply.send(Err(err));
                continue;
              }
              if backend.is_kernel_recursive() {
                let replace = replace_states.remove(&scope).expect("just checked");
                let outcome = commit_replace::<R, F>(
                  &mut core,
                  &ops,
                  &op_tx,
                  &mut handles,
                  &mut lanes,
                  &mut next_lane,
                  &mut pending_teardowns,
                  &mut os,
                  &registry,
                  scope,
                  spawned,
                  replace.reservation.path(),
                  None,
                  &now,
                );
                if let Ok(backend) = &outcome {
                  scope_backends.insert(scope, *backend);
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
                let replace = replace_states.remove(&scope).expect("just checked");
                retire_refused::<R, F>(&op_tx, &mut pending_teardowns, scope, spawned);
                drop(replace.reservation);
                let _ = replace
                  .reply
                  .send(Err(crate::error::ReplaceRootError::Retired));
                continue;
              };
              let port = spawned.handle.scope_port();
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
              replace_states
                .get_mut(&scope)
                .expect("just checked")
                .arming = Some(spawned);
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
              let canonical_root = spawned.meta.root.clone();
              let identity = spawned.meta.identity;
              let ancestors = spawned.meta.ancestors.clone();
              let backend = spawned.meta.backend;
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
                *pending_teardowns.entry(scope).or_insert(0) += 1;
                let tx = op_tx.clone();
                let handle = spawned.handle;
                R::spawn_blocking_detach(move || {
                  handle.shutdown();
                  let _ = tx.try_send(OpResult::TornDown { scope });
                });
                core.on_spawn_rejected(scope);
                if let Some(pending) = pending {
                  let _ = pending.reply.send(Err(WatchRootError::Overlaps {
                    path: canonical_root,
                    existing,
                  }));
                }
              } else {
                core.on_stream_spawned(scope, Ok(spawned.meta));
                // Mint the transport generation (the delivery lane) FIRST so
                // the port attaches under it: the descending root's first
                // AddWatch is dispatched carrying this same generation.
                let lane = next_lane;
                next_lane += 1;
                lanes.insert(scope, lane);
                // The arm/disarm port attaches before any effect of this
                // spawn can execute, so a descending root's first AddWatch
                // always finds its scope routed under the current generation.
                ops.attach_scope(scope, spawned.handle.scope_port(), lane);
                // The live stats handle (fanotify only) is captured before the
                // handle is stored, so the registry can hand a `backend_stats`
                // query the same counters the reader writes.
                let stats = spawned.handle.backend_stats();
                handles.insert(scope, spawned.handle);
                os.push(
                  spawned
                    .receiver
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
            Err(err) => {
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
          OpResult::WatchInstalled { watch, outcome } => {
          // A deferred registration grant riding on this arm resolves FIRST,
          // so a failed root arm answers the caller before the core's
          // teardown effects run (which would otherwise answer it again). A
          // deferred scope has no children yet (nothing enumerates before
          // the root is live), so any arm landing on it IS the root's.
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
          core.on_watch_installed(watch, outcome);
        }
        OpResult::RebindArmed { scope, outcome } => {
          let Some(mut replace) = replace_states.remove(&scope) else {
            // Swept by close (its stream already retired) or never ours.
            continue;
          };
          let Some(spawned) = replace.arming.take() else {
            drop(replace.reservation);
            continue;
          };
          let outcome = if !handles.contains_key(&scope) {
            // Death wins: the scope ended while the pre-arm was in flight.
            retire_refused::<R, F>(&op_tx, &mut pending_teardowns, scope, spawned);
            Err(crate::error::ReplaceRootError::Retired)
          } else if let WatchOutcome::Failed(err) = outcome {
            // The new transport could not cover the new root: unwind, the
            // old coverage untouched.
            let root = spawned.meta.root.clone();
            retire_refused::<R, F>(&op_tx, &mut pending_teardowns, scope, spawned);
            Err(crate::error::ReplaceRootError::Source(
              SourceError::RootUnavailable {
                root,
                source: arm_failure(err),
              },
            ))
          } else {
            commit_replace::<R, F>(
              &mut core,
              &ops,
              &op_tx,
              &mut handles,
              &mut lanes,
              &mut next_lane,
              &mut pending_teardowns,
              &mut os,
              &registry,
              scope,
              spawned,
              replace.reservation.path(),
              Some(outcome),
              &now,
            )
          };
          if let Ok(backend) = &outcome {
            scope_backends.insert(scope, *backend);
          }
          drop(replace.reservation);
          let _ = replace.reply.send(outcome.map(|_| ()));
        }
        OpResult::Enumerated { req, raw } => {
          core.on_enumerated(req, raw);
        }
        OpResult::TornDown { scope } => {
            if let Some(owed) = pending_teardowns.get_mut(&scope) {
              *owed -= 1;
              if *owed == 0 {
                pending_teardowns.remove(&scope);
              }
            }
            // The unwatch fence is per-scope QUIESCENCE across EVERY native
            // obligation — a straggler teardown, a replacement still
            // spawning or pre-arming, or a committed handle — not merely the
            // one stream this TornDown retired.
            if scope_quiesced(
              scope,
              &handles,
              &pending_spawns,
              &pending_teardowns,
              &replace_states,
            ) && let Some(reply) = unwatch_replies.remove(&scope)
            {
              let _ = reply.send(true);
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
      _ = timer => core.on_timeout(now()),
      cmd = commands.recv().fuse() => match cmd {
        Ok(Command::Watch { root, interest, reply }) => {
          let requested = root.clone();
          let scope = core.on_watch(root, interest, config.profile);
          watch_replies.insert(scope, PendingWatch { requested, reply });
        }
        Ok(Command::Replace {
          scope,
          root,
          reservation,
          reply,
        }) => {
          if !handles.contains_key(&scope) {
            let _ = reply.send(Err(crate::error::ReplaceRootError::UnknownRoot));
          } else if replace_states.contains_key(&scope) {
            let _ = reply.send(Err(crate::error::ReplaceRootError::ReplaceInFlight));
          } else {
            // Dispatch the replacement spawn through the SAME blocking-pool
            // accounting a birth spawn uses; the Spawned router diverts the
            // result to the commit tail by the replace_states key.
            pending_spawns.insert(scope);
            let mut source_config = SourceConfig::new(vec![root]);
            source_config.exclusions = config.exclusions.clone();
            source_config.latency = config.latency;
            source_config.channel_capacity = config.os_batch_capacity;
            source_config.backend = config.backend;
            source_config.max_map_directories = config.max_map_directories;
            let ops_for_spawn = ops.clone();
            let tx = op_tx.clone();
            R::spawn_blocking_detach(move || {
              let result = ops_for_spawn.spawn_source(source_config);
              let _ = tx.try_send(OpResult::Spawned { scope, result });
            });
            replace_states.insert(
              scope,
              ReplaceState {
                reservation,
                reply,
                arming: None,
              },
            );
          }
        }
        Ok(Command::Unwatch { scope, reply }) => {
          if handles.contains_key(&scope) || watch_replies.contains_key(&scope) {
            // The awaited form records its waiter (answered at scope-dead); the reply-less
            // `request_unwatch` tears down identically but registers none.
            if let Some(reply) = reply {
              unwatch_replies.insert(scope, reply);
            }
            core.on_unwatch(scope);
          } else if let Some(reply) = reply {
            // Unknown scope: only the awaited form is answered — the reply-less request is
            // fire-and-forget, so a no-op teardown is silently complete.
            let _ = reply.send(false);
          }
        }
        Ok(Command::SetCover { scope, retained, reply }) => {
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
        Ok(Command::Close { reply }) => break Some(reply),
        // The watcher facade dropped: same orderly teardown, nobody to tell.
        Err(_) => break None,
      },
      msg = os.next() => {
        if let Some((scope, lane, msg)) = msg {
          // A retired lane's stragglers are dropped whole: the replace
          // commit's covering Rescan dominates them, and the retired end
          // marker is a teardown artifact, never a death. (Today every
          // scope has exactly one lane for its whole life, so this gate
          // never fires — pinned by the existing suites.)
          if lanes.get(&scope) != Some(&lane) {
            continue;
          }
          match msg {
            // The payload travels whole: its budget slot is released by the
            // core exactly when the batch settles or is discarded, so parked
            // events stay inside the transport budget.
            Some(SourceMessage::Batch(payload)) => core.on_batch(scope, payload, now()),
            // The queue is the source's ONE ordered lane, so everything the
            // signal postdates was already handled above it — no drain, no
            // barrier, nothing to reason about. Dropping the ack BEFORE
            // acting re-arms the dedup: a loss racing it either rides a
            // fresh message or is covered by the rescan this becomes.
            Some(SourceMessage::Overflow(ack)) => {
              drop(ack);
              core.on_root_overflow(scope, now());
            }
            Some(SourceMessage::Fatal(_)) => core.on_source_fatal(scope, now()),
            // The receiver disconnected while the stream should still be
            // live: the source died without managing to say so (its sender
            // dropped) — a dead stream, not a teardown of ours (that path
            // removes the handle before the disconnect can arrive). The end
            // marker fires only after the queue yielded everything it held.
            None => {
              if handles.contains_key(&scope) {
                core.on_source_fatal(scope, now());
              }
            }
          }
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
  for (scope, handle) in std::mem::take(&mut handles) {
    registry.scope_dead(scope);
    *pending_teardowns.entry(scope).or_insert(0) += 1;
    let tx = op_tx.clone();
    R::spawn_blocking_detach(move || {
      handle.shutdown();
      let _ = tx.try_send(OpResult::TornDown { scope });
    });
  }
  // A descending replace's pre-arm holds a spawned-but-uncommitted stream
  // the maps above no longer cover: retire it inside the same accounting.
  // Drain `replace_states` whole so the scope-quiescence fence below no
  // longer counts these as outstanding replace obligations; each entry's
  // reservation and reply drop here — the caller sees `Closed`.
  for (scope, mut replace) in std::mem::take(&mut replace_states) {
    if let Some(spawned) = replace.arming.take() {
      *pending_teardowns.entry(scope).or_insert(0) += 1;
      let tx = op_tx.clone();
      R::spawn_blocking_detach(move || {
        spawned.handle.shutdown();
        let _ = tx.try_send(OpResult::TornDown { scope });
      });
    }
  }
  let drain = async {
    while !(pending_teardowns.is_empty() && pending_spawns.is_empty()) {
      match op_rx.recv().await {
        Ok(OpResult::TornDown { scope }) => {
          if let Some(owed) = pending_teardowns.get_mut(&scope) {
            *owed -= 1;
            if *owed == 0 {
              pending_teardowns.remove(&scope);
            }
          }
          // The same per-scope quiescence fence as the live arm. Close has
          // already drained `handles` and `replace_states` (both provably
          // empty here), and referencing the non-`Sync` handle map inside
          // this future would poison its `Send`ness — so the fence reduces to
          // the two obligations that can still be outstanding in the drain.
          if !pending_spawns.contains(&scope)
            && !pending_teardowns.contains_key(&scope)
            && let Some(reply) = unwatch_replies.remove(&scope)
          {
            let _ = reply.send(true);
          }
        }
        Ok(OpResult::Probed { probe, outcome }) => core.on_probe_result(probe, outcome, now()),
        Ok(OpResult::WatchInstalled { watch, outcome }) => {
          core.on_watch_installed(watch, outcome);
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
          if let Ok(spawned) = result {
            *pending_teardowns.entry(scope).or_insert(0) += 1;
            let tx = op_tx.clone();
            R::spawn_blocking_detach(move || {
              spawned.handle.shutdown();
              let _ = tx.try_send(OpResult::TornDown { scope });
            });
          }
        }
        // A pre-arm outcome for a replace the close sweep already retired:
        // nothing left to commit or unwind.
        Ok(OpResult::RebindArmed { .. }) => {}
        Err(_) => break,
      }
    }
  };
  // Grace expiry with work still pending means a wedged blocking pool: the
  // close reply goes out anyway (a wedged pool must not hang close forever),
  // and it reports EVERY pending set — quiescence cannot be claimed while
  // either is non-empty. A still-pending TEARDOWN already moved its handle
  // INTO the wedged shutdown call, so nothing can reclaim that stream until
  // the call returns. A still-pending SPAWN may ALREADY OWN A LIVE STREAM —
  // the backend starts it and then performs post-live metadata reads inside
  // the same call — and only self-reclaims once the wedge clears (its
  // undeliverable result drops and the handle's Drop runs the teardown), so
  // it is just as non-quiescent at reply time. One shared grace for both: a
  // wedged FFI call rarely unwedges with more time, so a longer window would
  // only delay the honest signal.
  let _ = R::timeout(Duration::from_secs(1), drain).await;
  execute_effects::<R, F>(
    &mut core,
    &ops,
    &config,
    &op_tx,
    &mut handles,
    &mut pending_spawns,
    &mut pending_teardowns,
    &mut scope_backends,
    &lanes,
    &events,
    &mut unwatch_replies,
    &mut deferred_grants,
    &registry,
    &now,
  );
  // One final settlement poll: a fence whose re-arm work quiesced during the
  // drain resolves with its honest verdict instead of spuriously reading as
  // `Closed`. Whatever is still pending drops with `cover_replies` — the
  // ratified close-mid-fence semantics: the caller sees `Closed`, never an
  // outcome fabricated over a torn-down driver.
  resolve_cover_settlements(&mut core, &mut cover_replies);
  if let Some(reply) = close_reply {
    let _ = reply.send(pending_teardowns.values().sum::<usize>() + pending_spawns.len());
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

/// Retires a spawned-but-refused replacement stream inside the counted
/// teardown accounting: it never becomes the scope's lane.
fn retire_refused<R, F>(
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  scope: ScopeId,
  spawned: SpawnedSource<F::Handle>,
) where
  R: RuntimeLite,
  F: FsOps,
{
  *pending_teardowns.entry(scope).or_insert(0) += 1;
  let tx = op_tx.clone();
  R::spawn_blocking_detach(move || {
    spawned.handle.shutdown();
    let _ = tx.try_send(OpResult::TornDown { scope });
  });
}

/// Lowers a pre-arm refusal into the io flavor
/// [`SourceError::RootUnavailable`] carries.
fn arm_failure(err: WatchError) -> std::io::Error {
  let kind = match err {
    WatchError::NotFound | WatchError::Gone => std::io::ErrorKind::NotFound,
    WatchError::Permission => std::io::ErrorKind::PermissionDenied,
    WatchError::NoSpace => std::io::ErrorKind::StorageFull,
    _ => std::io::ErrorKind::Other,
  };
  std::io::Error::new(kind, err.as_str())
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
fn commit_replace<R, F>(
  core: &mut DriverCore,
  ops: &F,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  handles: &mut BTreeMap<ScopeId, F::Handle>,
  lanes: &mut BTreeMap<ScopeId, u64>,
  next_lane: &mut u64,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  os: &mut SelectAll<
    futures_util::stream::BoxStream<'static, (ScopeId, u64, Option<SourceMessage>)>,
  >,
  registry: &impl ScopeRegistry,
  scope: ScopeId,
  spawned: SpawnedSource<F::Handle>,
  reserved: &Path,
  replay: Option<WatchOutcome>,
  now: &impl Fn() -> Instant,
) -> Result<BackendKind, crate::error::ReplaceRootError>
where
  R: RuntimeLite,
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
    retire_refused::<R, F>(op_tx, pending_teardowns, scope, spawned);
    return Err(err);
  }

  // Make-before-break: the new stream is live; retire the old one now,
  // inside the counted accounting.
  if let Some(old) = handles.remove(&scope) {
    *pending_teardowns.entry(scope).or_insert(0) += 1;
    let tx = op_tx.clone();
    R::spawn_blocking_detach(move || {
      old.shutdown();
      let _ = tx.try_send(OpResult::TornDown { scope });
    });
  }
  // Mint the replacement's transport generation FIRST, then detach the old
  // port and attach the new one under it: any old-generation control batch
  // still in flight now fails the front-check against this newer generation.
  let lane = *next_lane;
  *next_lane += 1;
  lanes.insert(scope, lane);
  ops.detach_scope(scope);
  ops.attach_scope(scope, spawned.handle.scope_port(), lane);
  let backend = spawned.meta.backend;
  let stats = spawned.handle.backend_stats();
  handles.insert(scope, spawned.handle);
  os.push(
    spawned
      .receiver
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
    &spawned.meta.root,
    spawned.meta.identity,
    &spawned.meta.ancestors,
    backend,
    stats,
  );
  let watch = core.root_watch(scope);
  core.on_root_replaced(scope, spawned.meta, now());
  // Descending: replay the pre-armed root outcome the commit adopted; the
  // rebound root is a pending re-arm, and this is the arm it awaits.
  if let (Some(outcome), Some(watch)) = (replay, watch) {
    core.on_watch_installed(watch, outcome);
  }
  Ok(backend)
}

/// Executes the core's queued effects, feeding each outcome straight back.
#[allow(clippy::too_many_arguments)]
fn execute_effects<R, F>(
  core: &mut DriverCore,
  ops: &F,
  config: &DriverConfig,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  handles: &mut BTreeMap<ScopeId, F::Handle>,
  pending_spawns: &mut BTreeSet<ScopeId>,
  pending_teardowns: &mut BTreeMap<ScopeId, usize>,
  scope_backends: &mut BTreeMap<ScopeId, BackendKind>,
  lanes: &BTreeMap<ScopeId, u64>,
  events: &async_channel::Sender<(ScopeId, Arc<PathBuf>, Change)>,
  unwatch_replies: &mut BTreeMap<ScopeId, futures_channel::oneshot::Sender<bool>>,
  deferred_grants: &mut BTreeMap<ScopeId, DeferredGrant>,
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
  while let Some(effect) = core.poll_effect() {
    match effect {
      Effect::SpawnStream { scope, root } => {
        pending_spawns.insert(scope);
        let mut source_config = SourceConfig::new(vec![root]);
        source_config.exclusions = config.exclusions.clone();
        source_config.latency = config.latency;
        source_config.channel_capacity = config.os_batch_capacity;
        // The spawn selector carries the consumer's backend choice straight to
        // the barrier: `Backend::Auto` probes and falls back, a forced backend
        // pins it (and surfaces a typed error rather than falling back).
        // (macOS ignores the selector — FSEvents is its one backend.)
        source_config.backend = config.backend;
        source_config.max_map_directories = config.max_map_directories;
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let result = ops.spawn_source(source_config);
          let _ = tx.try_send(OpResult::Spawned { scope, result });
        });
      }
      Effect::TeardownStream { scope } => {
        scope_backends.remove(&scope);
        // Every scope end — explicit unwatch, root death, stream fatal —
        // funnels through this effect: reclaim the registry entry, so a dead
        // root stops participating in liveness checks immediately. The arm
        // port detaches with it (late arms answer the typed refusal), and a
        // registration still waiting on its root arm resolves as a failure
        // (the scope died before coverage ever started).
        registry.scope_dead(scope);
        ops.detach_scope(scope);
        if let Some(DeferredGrant { pending, root }) = deferred_grants.remove(&scope) {
          let _ = pending
            .reply
            .send(Err(WatchRootError::Source(SourceError::RootUnavailable {
              root,
              source: std::io::Error::other("the source died before the root watch armed"),
            })));
        }
        if let Some(handle) = handles.remove(&scope) {
          *pending_teardowns.entry(scope).or_insert(0) += 1;
          let tx = op_tx.clone();
          R::spawn_blocking_detach(move || {
            handle.shutdown();
            let _ = tx.try_send(OpResult::TornDown { scope });
          });
        } else if let Some(reply) = unwatch_replies.remove(&scope) {
          // No stream ever existed (a failed spawn); the unwatch is complete.
          let _ = reply.send(true);
        }
      }
      Effect::AddWatch {
        scope,
        watch,
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
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let raw = ops.enumerate(watch, &path);
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
      } => match events.try_send((scope, root, change)) {
        Ok(()) => core.on_delivery(scope, Delivery::Accepted, now()),
        Err(async_channel::TrySendError::Full(_)) => {
          core.on_delivery(scope, Delivery::Refused, now());
        }
        // The consumer dropped its stream; shutdown arrives via the command
        // channel closing, so undeliverable changes are simply gone.
        Err(async_channel::TrySendError::Closed(_)) => {}
      },
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
    let ops = ops.clone();
    let tx = op_tx.clone();
    let generation = lanes.get(&scope).copied().unwrap_or(u64::MAX);
    R::spawn_blocking_detach(move || {
      for (watch, outcome) in ops.batch_control(scope, generation, requests) {
        let _ = tx.try_send(OpResult::WatchInstalled { watch, outcome });
      }
    });
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
