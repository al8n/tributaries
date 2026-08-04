//! The hermetic fake platform the driver and watcher test suites share: fake
//! sources are real transport queues driven through the REAL forwarding
//! protocol, probes consult an in-memory tree — the production loop runs
//! unmodified.

use std::{
  collections::{BTreeMap, BTreeSet, HashMap},
  future::Future,
  num::NonZeroU64,
  path::{Path, PathBuf},
  sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
  },
  time::Duration,
};

use agnostic_lite::{
  AsyncBlockingSpawner, LocalRuntimeLite, RuntimeLite, Yielder, tokio::TokioRuntime,
};
use tributary_proto::{FileKind, IoClass, ScopeId, Segment, WatchId};

use super::{
  CookieFile, CookieRemoval, CookieWriteError, FsOps, ScopeRegistry, SourceControl, SpawnedSource,
};
use crate::{
  core::{ExpectedObject, MountRefresh, ProbeOutcome, RawDirEntry, RawEnumerate, RootLiveness},
  driver::ControlRequest,
  os::{
    BackendKind, RawOsEvent, RootIdentity, RootMeta, SourceConfig, SourceError, SourceEvent,
    SourceMessage, SpawnFailed,
    linux::{RawLinuxEvent, WatchOutcome},
  },
};

/// A parked-work gate: the held flag, its wakeup, and a monotonic count of
/// jobs that have CAPTURED (cloned and committed to) this exact gate — the
/// proof a test needs before it may install a superseding gate without
/// racing a job that is still choosing which gate slot to park on.
type HoldGate = Arc<(Mutex<bool>, Condvar, AtomicUsize)>;

/// One fake filesystem object.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FakeNode {
  pub(crate) kind: FileKind,
  pub(crate) ino: u64,
  pub(crate) dev: u64,
  /// The object's MOUNT id, mirroring the real `statx(STATX_MNT_ID)` the core
  /// fences descent on. Defaults to the fake's `root_mnt_id` (one mount), so a
  /// plain `put` never crosses the boundary; [`FakeFs::put_on_mount`] sets a
  /// differing one to model a bind/submount whose device still equals the root's.
  pub(crate) mnt_id: Option<u64>,
}

/// One spawned fake source: its queue's send end plus the REAL transport
/// state, so test injections run the production forwarding protocol.
struct FakeSource {
  sender: async_channel::Sender<SourceMessage>,
  transport: Arc<crate::os::transport::TransportState>,
  /// A loss the KERNEL has committed that no reader has forwarded yet — staged
  /// by [`FakeFs::stage_kernel_loss`]. It sits in NO queue, so no
  /// `SourceSnapshot` counts it and no drain can ingest it; the next control
  /// batch this source answers flushes it onto the queue, mirroring the real
  /// reader's cut of its kernel queue onto the lane before any batch reply.
  /// [`FakeFs::send_lossy`] models the other side of that cut — a loss already
  /// forwarded, and so already countable.
  pending_kernel_loss: AtomicBool,
}

/// Elects one whole-batch decode loss on `transport` and forwards it down
/// `sender` — the real protocol's in-order `Overflow`, shared by the
/// already-forwarded injection ([`FakeFs::send_lossy`]) and the staged
/// kernel-resident one, so both losses reach the queue by the same path and
/// differ only in WHEN.
fn forward_lossy(
  transport: &crate::os::transport::TransportState,
  sender: &async_channel::Sender<SourceMessage>,
) {
  crate::os::transport::forward_batch(transport, Vec::new(), true, |msg| {
    sender.try_send(msg).is_ok()
  });
}

struct FakeState {
  nodes: Mutex<HashMap<PathBuf, FakeNode>>,
  /// Every source spawned for a root, oldest first. A Vec, not a slot: two
  /// concurrent spawns of one root must not clobber each other — dropping the
  /// earlier sender would fabricate a source death (a spurious end marker)
  /// for a scope whose stream the driver still owns.
  sources: Mutex<HashMap<PathBuf, Vec<FakeSource>>>,
  shutdowns: AtomicUsize,
  spawns: AtomicUsize,
  /// Mount-table refreshes served, plus the configured answer (`None` = an
  /// authoritative empty table).
  refreshes: AtomicUsize,
  refresh_answer: Mutex<Option<(Vec<PathBuf>, bool)>>,
  /// Overrides the root-liveness a refresh reports, so the hermetic suites can
  /// drive the root-death-via-refresh path (`None` = derive from the tree: the
  /// root's live identity, or `Missing` when it is gone).
  root_liveness: Mutex<Option<RootLiveness>>,
  /// Mount prefixes the next spawn seeds its `RootMeta` with.
  spawn_mounts: Mutex<Vec<PathBuf>>,
  /// Requested-root → final-root remaps, mirroring the backend's own
  /// re-canonicalization (a symlink retargeted between reservation and
  /// spawn): the spawned `RootMeta` carries the FINAL root.
  spawn_remaps: Mutex<HashMap<PathBuf, PathBuf>>,
  /// A node written the instant the next fake stream goes live — the
  /// deterministic form of an object swapped inside the real backend's
  /// metadata-capture→start gap. The post-live revalidation must catch it.
  replace_at_live: Mutex<Option<(PathBuf, FakeNode)>>,
  /// The spawn contract's observable order: `meta_sealed` must strictly
  /// precede `stream_live`, mirroring the real backend's pre-start barrier —
  /// a fake that seeded metadata after its stream went live would let the
  /// hermetic suites pass against an ordering the platform forbids.
  spawn_order: Mutex<Vec<&'static str>>,
  /// When set, `spawn_source` parks on the blocking pool until the gate
  /// releases — the close-versus-in-flight-spawn cells need a spawn that is
  /// dispatched but not yet returned.
  spawn_hold: Mutex<Option<HoldGate>>,
  /// When set, `spawn_source` parks AFTER its fake stream went live but
  /// before it returns — the real backend's post-live metadata phase, where a
  /// wedged spawn already owns a live native stream that close must count.
  post_live_hold: Mutex<Option<HoldGate>>,
  /// When set, `SourceControl::shutdown` parks until the gate releases — the
  /// close-versus-wedged-teardown cell needs a teardown whose handle has
  /// already moved into the call, where no Drop backstop can exist.
  teardown_hold: Mutex<Option<HoldGate>>,
  /// How many further `SourceControl::shutdown` calls must UNWIND instead of
  /// returning — the injected teardown panic the reaper's accounting is proven
  /// against. Decremented by each panicking call.
  panic_teardowns: AtomicUsize,
  /// How many further `SourceControl::shutdown` calls must RETURN
  /// [`Quiesce::Unproven`] — a backend that completed its teardown but could
  /// not observe the stream's end, and retained native state rather than free
  /// what the OS may still own. Distinct from `panic_teardowns` on the only
  /// axis that matters: the call returns normally, so nothing but the answer
  /// itself distinguishes it from a clean teardown. Decremented by each such
  /// call.
  unproven_teardowns: AtomicUsize,
  /// The name of the thread that reclaimed the most recently retired stream,
  /// whether through `shutdown` or the `Drop` backstop. The teardown contract is
  /// about WHERE the unbounded join runs, so a cell proving a handle reached the
  /// reaper — rather than being destroyed on the shared blocking pool — has to
  /// read the executor, not merely the count.
  reclaim_thread: Mutex<Option<String>>,
  /// The backend the next spawn's `RootMeta` claims (and thus the lowering
  /// profile the core confirms).
  spawn_backend: Mutex<BackendKind>,
  /// Per-directory arms executed, in call order.
  arms: Mutex<Vec<(WatchId, PathBuf)>>,
  /// The transport generation attached per scope (the delivery lane): a
  /// control batch carrying a different generation is a leftover of a
  /// replaced transport and is refused, modeling the real source's fence.
  scope_generation: Mutex<BTreeMap<ScopeId, u64>>,
  /// Cookies written and removed, in call order — the observable that a sync
  /// placed (and reaped) its marker.
  cookie_writes: Mutex<Vec<PathBuf>>,
  cookie_removes: Mutex<Vec<PathBuf>>,
  /// When set, every cookie write fails with this error kind (the read-only
  /// tree, modeled).
  cookie_write_failure: Mutex<Option<std::io::ErrorKind>>,
  /// When set, every cookie write CREATES its file and then fails with this
  /// error kind, handing the file back as the residue: the write that could not
  /// identify what it made and could not destroy it either. Distinct from
  /// [`cookie_write_failure`](Self::cookie_write_failure), which models a write
  /// that left nothing on disk — the whole difference being whether the caller
  /// may retire the obligation pre-physically.
  cookie_write_strand: Mutex<Option<std::io::ErrorKind>>,
  /// Cookie writes that reached the blocking pool, counted before any hold — the
  /// observable that a write is IN FLIGHT, which is what a cell racing a
  /// retirement or an abandoned reply against it must wait for.
  cookie_dispatches: AtomicUsize,
  /// When set, `write_cookie` parks until the gate releases: the window in which
  /// a test retires the scope, drops the reply, or tears the driver down while
  /// the write is still in the pool.
  cookie_write_hold: Mutex<Option<HoldGate>>,
  /// The next N cookie REMOVES fail with a transient error (a hung/faulty
  /// unlink), so a cell can prove the record is RETAINED and the path retried
  /// rather than orphaned. Decremented per failed remove.
  cookie_remove_failures: AtomicUsize,
  /// Cookie removes that reached the blocking pool, counted before any hold —
  /// the observable that an unlink is IN FLIGHT, which a cell racing a close (or
  /// a Drop) against a hung terminal unlink must wait for.
  cookie_remove_dispatches: AtomicUsize,
  /// When set, `remove_cookie` parks until the gate releases: the window a
  /// close (or a cancelled driver's Drop) races against a hung terminal unlink.
  cookie_remove_hold: Mutex<Option<HoldGate>>,
  /// When set, `remove_cookie` parks AFTER the node is unlinked (so `files_under`
  /// already reflects the removal) but BEFORE it records the remove and returns —
  /// "the unlink syscall completed; the pool job has not yet taken the ledger
  /// lock to confirm". The R11-3 preemption window: a successor can reclaim the
  /// path here, and the parked job's later confirm must be refused by id.
  cookie_remove_confirm_hold: Mutex<Option<HoldGate>>,
  /// Path prefixes whose cookie removes fail PERSISTENTLY (without unlinking the
  /// node), modeling a still-failing mount for one subtree while another has
  /// recovered — the per-scope-recovery re-arm fairness cells. Checked after the
  /// hold and before the global countdown knob and the unlink.
  cookie_remove_failure_prefixes: Mutex<Vec<PathBuf>>,
  /// Cookie directories that CANONICALIZE elsewhere — the fake's model of an
  /// intermediate symlink. A spelled directory maps to the real path it resolves
  /// to, so `write_cookie` can mirror the production canonicalize-and-verify: a
  /// directory that resolves outside the root is refused even though its spelling
  /// sits under it. An unmapped directory canonicalizes to itself.
  canonical_dirs: Mutex<HashMap<PathBuf, PathBuf>>,
  /// The resume point every live fake handle mints — the journal-bearing
  /// backends' `SourceControl::resume_token`, modeled.
  resume_token: Mutex<Option<crate::os::ResumeToken>>,
  /// The `since` each spawn was configured with, in spawn order: the
  /// observable that a replacement inherited the retiring stream's point.
  spawn_resume_points: Mutex<Vec<Option<crate::os::ResumeToken>>>,
  /// Arms refused because their batch carried a stale (replaced) transport
  /// generation — the observable of the fence, in call order.
  stale_arms: Mutex<Vec<(WatchId, PathBuf)>>,
  /// `preflight_arm` ENTRIES (bumped before any hold parks the call) — the
  /// observable that a widen's witnessed window is already OPEN
  /// (`begin_widen_watch` runs in the same handler that dispatches the
  /// pre-arm), so a cell can inject a loss provably inside the window.
  prearm_entries: AtomicUsize,
  /// `probe` calls executed — the widen cells' observable that the pre-arm's
  /// post-arm bracket ran, i.e. the `WidenArmed` completion is about to land
  /// on the op channel (only the `try_send` remains after the probe).
  probes: AtomicUsize,
  /// Every [`batch_control`](FsOps::batch_control) ENTRY, in call order: the
  /// scope it named and how many requests it carried. Recorded at the very top,
  /// before any hold parks the call, so it counts batches SUBMITTED rather than
  /// batches that got as far as executing — which is what a cell proving a dead
  /// scope submits nothing further has to read. The request count discriminates
  /// the shapes: a batch carrying ZERO requests is by construction the
  /// ordering-proof round trip (no arm, no disarm — nothing but the reply), so a
  /// cell can prove the batch it froze is that one and not an arm or disarm batch.
  control_batches: Mutex<Vec<(ScopeId, usize)>>,
  /// When set, the next [`batch_control`](FsOps::batch_control) for this scope
  /// UNWINDS instead of returning — see
  /// [`panic_next_control_batch`](FakeFs::panic_next_control_batch). One-shot:
  /// taken (and cleared) when it fires.
  batch_panic_arm: Mutex<Option<ScopeId>>,
  /// When set, the next [`batch_control`](FsOps::batch_control) for this scope
  /// RETURNS UNANSWERED, having executed nothing — see
  /// [`kill_next_control_reader`](FakeFs::kill_next_control_reader). One-shot,
  /// like the panic arm.
  reader_death_arm: Mutex<Option<ScopeId>>,
  /// When set, the next [`dispatch_control`](FsOps::dispatch_control) for this
  /// scope is TAKEN and never answered — see
  /// [`strand_next_control_reader`](FakeFs::strand_next_control_reader).
  /// One-shot, like the arms above it.
  reader_strand_arm: Mutex<Option<ScopeId>>,
  /// Batches a stranded reader took: `(scope, request count)` and the answer
  /// sink nobody will ever resolve. Holding the sink here is what keeps the
  /// batch outstanding — dropping it would answer the batch as an unwind — so
  /// these live for the fake's whole life.
  stranded_batches: Mutex<Vec<(ScopeId, usize, super::ControlAnswer<FakeHandle>)>>,
  /// Per-directory disarms executed.
  disarms: Mutex<Vec<WatchId>>,
  /// The set of watches whose kernel watch is currently INSTALLED in the fake's
  /// model: an arm success inserts, a disarm removes. Unlike the append-only
  /// `arms`/`disarms` logs, this reflects the live watch table, so a watch left
  /// armed with no matching disarm (a re-add/disarm reorder orphan) shows up
  /// here as a residual entry.
  live_watches: Mutex<BTreeSet<WatchId>>,
  /// When set, an arm EXECUTION whose path matches parks until the gate
  /// releases — distinct from `arm_hold` (which freezes the whole batch,
  /// disarms included) so a cell can freeze ONE watch's re-add while a
  /// same-scope disarm batch races it.
  arm_exec_hold: Mutex<Option<(PathBuf, HoldGate)>>,
  /// Enumerates executed, in call order.
  enumerates: Mutex<Vec<(WatchId, PathBuf)>>,
  /// The transient anchor each armed watch currently has PUBLISHED, mirroring
  /// the real executor's `O_PATH` anchor table: an arm that installs publishes
  /// a fresh id, a disarm drops it, and an enumerate's dispatch takes it. The
  /// ids are unique across the fake's life, so two publications for one watch
  /// are distinguishable — which is the whole point, since a `WatchId` is
  /// re-added under its own name after a loss.
  anchors: Mutex<BTreeMap<WatchId, u64>>,
  /// The publication id sequence feeding `anchors`.
  anchor_seq: AtomicUsize,
  /// Each executed enumerate's `(watch, anchor it was handed)`, in call order —
  /// so a cell can prove WHICH publication a listing read through, and that a
  /// listing entitled to one was not left listing the path.
  enumerate_anchors: Mutex<Vec<(WatchId, Option<u64>)>>,
  /// Paths whose next arm fails with the given error (persistent).
  watch_failures: Mutex<HashMap<PathBuf, tributary_proto::WatchError>>,
  /// Paths whose arms resolve `Aliased` (the EEXIST fan-out outcome).
  watch_aliases: Mutex<HashMap<PathBuf, i32>>,
  /// Injected listings served before the default readdir, per path.
  enumerate_answers: Mutex<HashMap<PathBuf, std::collections::VecDeque<RawEnumerate>>>,
  /// When set, `enumerate` parks until the gate releases (the
  /// close-versus-in-flight-enumerate cell).
  enumerate_hold: Mutex<Option<HoldGate>>,
  /// When set, an enumerate whose path matches parks until the gate releases —
  /// distinct from `enumerate_hold` (which freezes every listing) so a cell can
  /// strand ONE directory's read while the recovery re-reads that drive its
  /// re-add still run.
  enumerate_exec_hold: Mutex<Option<(PathBuf, HoldGate)>>,
  /// When set, `add_watch` and a discovery/re-arm `batch_control` park until
  /// the gate releases (the close-versus-in-flight-arm and
  /// stale-batch-across-replace cells).
  arm_hold: Mutex<Option<HoldGate>>,
  /// When set, `preflight_arm` (a descending replace's pre-arm on the new
  /// transport) parks until the gate releases — distinct from `arm_hold` so a
  /// test can freeze in-flight discovery batches while letting the commit's
  /// pre-arm proceed.
  prearm_hold: Mutex<Option<HoldGate>>,
  /// When set, `refresh_mounts` parks until the gate releases — the
  /// root-binding verification cells hold the widen's commit-armed refresh so
  /// the barrier's unverified window is observable.
  refresh_hold: Mutex<Option<HoldGate>>,
  /// A node swapped in AFTER a `preflight_arm` executes but BEFORE its
  /// post-arm re-stat — the deterministic model of a root replaced between
  /// the kernel arm and the stale-Installed bracket's probe.
  prearm_swap: Mutex<Option<(PathBuf, FakeNode)>>,
  /// The synthetic kernel-watch-descriptor sequence.
  wd_seq: AtomicUsize,
}

impl FakeState {
  /// Records the thread reclaiming a stream — see [`FakeState::reclaim_thread`].
  fn note_reclaim_thread(&self) {
    *self.reclaim_thread.lock().unwrap() = std::thread::current().name().map(str::to_owned);
  }
}

impl Default for FakeState {
  fn default() -> Self {
    Self {
      nodes: Mutex::default(),
      sources: Mutex::default(),
      shutdowns: AtomicUsize::new(0),
      spawns: AtomicUsize::new(0),
      refreshes: AtomicUsize::new(0),
      refresh_answer: Mutex::default(),
      root_liveness: Mutex::default(),
      spawn_mounts: Mutex::default(),
      spawn_remaps: Mutex::default(),
      replace_at_live: Mutex::default(),
      spawn_order: Mutex::default(),
      spawn_hold: Mutex::default(),
      post_live_hold: Mutex::default(),
      teardown_hold: Mutex::default(),
      panic_teardowns: AtomicUsize::new(0),
      unproven_teardowns: AtomicUsize::new(0),
      reclaim_thread: Mutex::default(),
      spawn_backend: Mutex::new(BackendKind::FsEvents),
      arms: Mutex::default(),
      scope_generation: Mutex::default(),
      cookie_writes: Mutex::default(),
      cookie_removes: Mutex::default(),
      cookie_write_failure: Mutex::default(),
      cookie_write_strand: Mutex::default(),
      cookie_dispatches: AtomicUsize::new(0),
      cookie_write_hold: Mutex::default(),
      cookie_remove_failures: AtomicUsize::new(0),
      cookie_remove_dispatches: AtomicUsize::new(0),
      cookie_remove_hold: Mutex::default(),
      cookie_remove_confirm_hold: Mutex::default(),
      cookie_remove_failure_prefixes: Mutex::default(),
      canonical_dirs: Mutex::default(),
      resume_token: Mutex::default(),
      spawn_resume_points: Mutex::default(),
      stale_arms: Mutex::default(),
      prearm_entries: AtomicUsize::new(0),
      probes: AtomicUsize::new(0),
      control_batches: Mutex::default(),
      batch_panic_arm: Mutex::default(),
      reader_death_arm: Mutex::default(),
      reader_strand_arm: Mutex::default(),
      stranded_batches: Mutex::default(),
      disarms: Mutex::default(),
      live_watches: Mutex::default(),
      arm_exec_hold: Mutex::default(),
      enumerates: Mutex::default(),
      anchors: Mutex::default(),
      anchor_seq: AtomicUsize::new(0),
      enumerate_anchors: Mutex::default(),
      watch_failures: Mutex::default(),
      watch_aliases: Mutex::default(),
      enumerate_answers: Mutex::default(),
      enumerate_hold: Mutex::default(),
      enumerate_exec_hold: Mutex::default(),
      arm_hold: Mutex::default(),
      prearm_hold: Mutex::default(),
      refresh_hold: Mutex::default(),
      prearm_swap: Mutex::default(),
      wd_seq: AtomicUsize::new(0),
    }
  }
}

/// A fake platform: sources are channels the test injects into through the
/// real transport protocol, probes consult an in-memory map.
#[derive(Clone, Default)]
pub(crate) struct FakeFs {
  state: Arc<FakeState>,
  root_dev: u64,
  /// The scope root's MOUNT id, carried on `RootMeta` and defaulted onto every
  /// `put` node. `None` (the `Default`) models a source that reports no mount id
  /// (a pre-5.8 kernel / non-Linux backend), where the core's descent fence falls
  /// back to the device check; a `Some` value models a mount-id-reporting source.
  root_mnt_id: Option<u64>,
}

impl FakeFs {
  pub(crate) fn new(root_dev: u64) -> Self {
    Self {
      state: Arc::new(FakeState::default()),
      root_dev,
      root_mnt_id: None,
    }
  }

  /// A fake reporting a root MOUNT id — the mount-id-aware source. Nodes placed by
  /// `put` inherit this id (one mount); [`put_on_mount`](Self::put_on_mount) places
  /// a node on a DIFFERENT mount (a bind/submount) whose device still equals the
  /// root's, exercising the core's mount-id descent fence the device check misses.
  pub(crate) fn with_root_mnt_id(root_dev: u64, root_mnt_id: u64) -> Self {
    Self {
      state: Arc::new(FakeState::default()),
      root_dev,
      root_mnt_id: Some(root_mnt_id),
    }
  }

  pub(crate) fn put(&self, path: impl AsRef<Path>, kind: FileKind, ino: u64) {
    self.state.nodes.lock().unwrap().insert(
      path.as_ref().to_path_buf(),
      FakeNode {
        kind,
        ino,
        dev: self.root_dev,
        mnt_id: self.root_mnt_id,
      },
    );
  }

  /// Places a node on the root's DEVICE but a DIFFERENT mount (`mnt_id`) — a
  /// `mount --bind` of a same-superblock directory, the boundary the device check
  /// alone cannot see. The core lowers such a directory to `FileKind::Other` (not
  /// descended) via the mount-id fence.
  pub(crate) fn put_on_mount(&self, path: impl AsRef<Path>, kind: FileKind, ino: u64, mnt_id: u64) {
    self.state.nodes.lock().unwrap().insert(
      path.as_ref().to_path_buf(),
      FakeNode {
        kind,
        ino,
        dev: self.root_dev,
        mnt_id: Some(mnt_id),
      },
    );
  }

  pub(crate) fn remove(&self, path: impl AsRef<Path>) {
    self.state.nodes.lock().unwrap().remove(path.as_ref());
  }

  /// The landing a `write_cookie` would have reported for the node standing at
  /// `path` right now — for a cell that stages a cookie with [`put`](Self::put)
  /// and hands it to a registry directly, below the write that normally mints
  /// one. Identity is read from the node, so a cell that later replaces it gets
  /// the replacement's, exactly as a real `fstat` would.
  ///
  /// An ABSENT node yields inode 0, which no cell and no fake write ever mints:
  /// staging a cookie for a path with nothing at it is meant to match nothing.
  pub(crate) fn cookie_at(&self, path: impl AsRef<Path>) -> CookieFile {
    let path = path.as_ref().to_path_buf();
    let identity = self.state.nodes.lock().unwrap().get(&path).map_or_else(
      || RootIdentity::new(self.root_dev, 0),
      |node| RootIdentity::new(node.dev, node.ino.into()),
    );
    CookieFile::new(path, identity)
  }

  /// Every regular file at or under `prefix`, for tree-equality oracles.
  pub(crate) fn files_under(
    &self,
    prefix: impl AsRef<Path>,
  ) -> std::collections::BTreeSet<PathBuf> {
    let prefix = prefix.as_ref();
    self
      .state
      .nodes
      .lock()
      .unwrap()
      .iter()
      .filter(|(path, node)| node.kind == FileKind::File && path.starts_with(prefix))
      .map(|(path, _)| path.clone())
      .collect()
  }

  fn source_of(
    &self,
    root: impl AsRef<Path>,
  ) -> (
    async_channel::Sender<SourceMessage>,
    Arc<crate::os::transport::TransportState>,
  ) {
    let sources = self.state.sources.lock().unwrap();
    let source = sources
      .get(root.as_ref())
      .and_then(|spawned| spawned.last())
      .expect("a source was spawned for the root");
    (source.sender.clone(), Arc::clone(&source.transport))
  }

  /// Injects one decoded batch through the REAL forwarding protocol (budget
  /// permit, in-order loss degrade and all).
  ///
  /// Event paths are the backend's wire form: '/'-separated on every host
  /// (build them from literals, never `PathBuf::join`, whose host separator
  /// breaks the byte-level root-prefix lowering on Windows).
  pub(crate) fn send_batch(&self, root: impl AsRef<Path>, events: Vec<RawOsEvent>) {
    let events = events.into_iter().map(SourceEvent::FsEvents).collect();
    self.send_source_batch(root, events);
  }

  /// Injects one decoded, anchor-attributed inotify batch through the same
  /// forwarding protocol.
  pub(crate) fn send_inotify_batch(&self, root: impl AsRef<Path>, events: Vec<RawLinuxEvent>) {
    let events = events.into_iter().map(SourceEvent::Linux).collect();
    self.send_source_batch(root, events);
  }

  fn send_source_batch(&self, root: impl AsRef<Path>, events: Vec<SourceEvent>) {
    let (sender, transport) = self.source_of(root);
    crate::os::transport::forward_batch(&transport, events, false, |msg| {
      sender.try_send(msg).is_ok()
    });
  }

  /// Injects a decode-loss callback (every entry undecodable): the loss rides
  /// the queue as an in-order `Overflow` — i.e. ALREADY FORWARDED, so the
  /// driver's settle-edge drain counts and ingests it with no control round
  /// trip. [`stage_kernel_loss`](Self::stage_kernel_loss) is the other side.
  pub(crate) fn send_lossy(&self, root: impl AsRef<Path>) {
    let (sender, transport) = self.source_of(root);
    forward_lossy(&transport, &sender);
  }

  /// Stages a KERNEL-RESIDENT loss on `root`'s source: the kernel has committed
  /// an overflow and nothing has read it out. It enters no queue, so it is in no
  /// lane, no `SourceSnapshot` counts it, and no drain — however many passes it
  /// takes — can ingest it. Only a control batch this source answers flushes it,
  /// strictly before that batch's reply, exactly where the real reader cuts its
  /// kernel queue onto the lane. One-shot: the flush clears the flag.
  pub(crate) fn stage_kernel_loss(&self, root: impl AsRef<Path>) {
    let sources = self.state.sources.lock().unwrap();
    let source = sources
      .get(root.as_ref())
      .and_then(|spawned| spawned.last())
      .expect("a source was spawned for the root");
    source.pending_kernel_loss.store(true, Ordering::SeqCst);
  }

  /// Forwards every source's staged kernel-resident loss, if any, onto its
  /// queue. Called from the fake's [`batch_control`](FsOps::batch_control) at
  /// the real reader's cut point — after the batch's own work, before its reply
  /// — so a staged loss is on the lane strictly ahead of the completion the
  /// driver reads as its ordering proof. A no-op when nothing is staged, which
  /// is every other cell in the suite.
  ///
  /// Deliberately scope-agnostic: a proof batch carries NO requests, so nothing
  /// in it names a root, and the fake keeps no scope→root map (a widen keeps its
  /// source under the OLD root, so one built from root arms would drift). Any
  /// batch reply therefore flushes every staged loss — stage one per cell, on
  /// the root whose window is under test.
  fn flush_staged_kernel_losses(&self) {
    let staged: Vec<(
      async_channel::Sender<SourceMessage>,
      Arc<crate::os::transport::TransportState>,
    )> = {
      let sources = self.state.sources.lock().unwrap();
      sources
        .values()
        .flatten()
        .filter(|source| source.pending_kernel_loss.swap(false, Ordering::SeqCst))
        .map(|source| (source.sender.clone(), Arc::clone(&source.transport)))
        .collect()
    };
    // Forwarded OUTSIDE the map lock: the protocol's own permit accounting and
    // the queue send must not run under a lock a concurrent spawn also takes.
    for (sender, transport) in staged {
      forward_lossy(&transport, &sender);
    }
  }

  /// Injects the stream's terminal `Fatal`.
  pub(crate) fn send_fatal(&self, root: impl AsRef<Path>) {
    let (sender, transport) = self.source_of(root);
    crate::os::transport::signal_fatal_once(&transport, SourceError::CallbackPanic, |msg| {
      sender.try_send(msg).is_ok()
    });
  }

  /// Whether `root`'s source has an unacknowledged `Overflow` in flight —
  /// false again once the driver processed it (dropping its ack).
  pub(crate) fn overflow_pending(&self, root: impl AsRef<Path>) -> bool {
    self.source_of(root).1.overflow_pending()
  }

  /// Drops `root`'s send end, disconnecting the source without a `Fatal`.
  pub(crate) fn disconnect(&self, root: impl AsRef<Path>) {
    self.state.sources.lock().unwrap().remove(root.as_ref());
  }

  pub(crate) fn shutdowns(&self) -> usize {
    self.state.shutdowns.load(Ordering::SeqCst)
  }

  pub(crate) fn spawns(&self) -> usize {
    self.state.spawns.load(Ordering::SeqCst)
  }

  pub(crate) fn refreshes(&self) -> usize {
    self.state.refreshes.load(Ordering::SeqCst)
  }

  /// Configures the mount prefixes the next spawn seeds its `RootMeta` with.
  pub(crate) fn seed_mounts(&self, mounts: Vec<PathBuf>) {
    *self.state.spawn_mounts.lock().unwrap() = mounts;
  }

  /// Forces every subsequent refresh to report `liveness` as the root's state,
  /// driving the root-death-via-refresh path for the verdicts a present node cannot
  /// express: `RootLiveness::Missing` (vanished) or `Unreadable`. An override forces
  /// the mount frame to `None` too (the real `statx` reports no frame on a failed
  /// stat), so it can never pair a fabricated identity with a node's frame. A
  /// REPLACED-but-present root is driven by replacing the node instead
  /// ([`replace_root_node`](Self::replace_root_node) / `put`), so the refresh's
  /// single node read reports the replacement's identity AND its frame together.
  pub(crate) fn set_root_liveness(&self, liveness: RootLiveness) {
    *self.state.root_liveness.lock().unwrap() = Some(liveness);
  }

  /// Replaces the node at `root` with a new object carrying `(ino, mnt_id)` on the
  /// root's device — the deterministic form of a replace/remount at the root path.
  /// Because the refresh samples identity AND frame from this ONE node, a subsequent
  /// refresh reports the REPLACED identity WITH its frame as a matched pair, never a
  /// mix of the old identity and a new frame (the hazard the atomic `statx` sample
  /// closes). A `mnt_id` of `None` models a source that reports no frame.
  pub(crate) fn replace_root_node(&self, root: impl AsRef<Path>, ino: u64, mnt_id: Option<u64>) {
    self.state.nodes.lock().unwrap().insert(
      root.as_ref().to_path_buf(),
      FakeNode {
        kind: FileKind::Dir,
        ino,
        dev: self.root_dev,
        mnt_id,
      },
    );
  }

  /// The recorded spawn-contract order (`meta_sealed` / `stream_live` per
  /// spawn, in call order).
  pub(crate) fn spawn_order(&self) -> Vec<&'static str> {
    self.state.spawn_order.lock().unwrap().clone()
  }

  /// Arms a node replacement applied the instant the next spawn's stream
  /// goes live, racing the sealed metadata exactly like a real object swap in
  /// the capture→start gap.
  pub(crate) fn replace_at_live(&self, path: impl AsRef<Path>, kind: FileKind, ino: u64) {
    *self.state.replace_at_live.lock().unwrap() = Some((
      path.as_ref().to_path_buf(),
      FakeNode {
        kind,
        ino,
        dev: self.root_dev,
        mnt_id: self.root_mnt_id,
      },
    ));
  }

  /// Remaps a requested root to a different final root at spawn, mirroring
  /// the backend's re-canonicalization.
  pub(crate) fn remap_spawn_root(&self, requested: impl AsRef<Path>, actual: impl AsRef<Path>) {
    self.state.spawn_remaps.lock().unwrap().insert(
      requested.as_ref().to_path_buf(),
      actual.as_ref().to_path_buf(),
    );
  }

  /// Holds every subsequent spawn on the blocking pool until the returned
  /// gate is released.
  pub(crate) fn hold_spawns(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.spawn_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Holds every subsequent `shutdown` on the blocking pool until the
  /// returned gate is released.
  pub(crate) fn hold_teardowns(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.teardown_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Makes the next `count` teardowns UNWIND inside `shutdown`, before the
  /// completion is counted — a backend whose quiescence call panics (an
  /// invariant `expect`, a poisoned lock), which the reaper must contain
  /// without corrupting its own accounting.
  pub(crate) fn panic_teardowns(&self, count: usize) {
    self.state.panic_teardowns.store(count, Ordering::SeqCst);
  }

  /// Makes the next `count` teardowns RETURN [`Quiesce::Unproven`] — a backend
  /// whose `shutdown` ran to completion and still could not prove the stream
  /// gone (the Windows pumps' panic-forget and undrained-cancellation paths,
  /// which retain kernel-owned buffers and handles on purpose). They complete
  /// like any other teardown, so a driver that reads the RETURN rather than the
  /// answer cannot tell them apart from success.
  pub(crate) fn unproven_teardowns(&self, count: usize) {
    self.state.unproven_teardowns.store(count, Ordering::SeqCst);
  }

  /// The name of the thread that reclaimed the most recently retired stream.
  pub(crate) fn reclaim_thread(&self) -> Option<String> {
    self.state.reclaim_thread.lock().unwrap().clone()
  }

  /// Holds every subsequent spawn AFTER its stream goes live but before the
  /// spawn returns — the post-live metadata phase of the real backend.
  pub(crate) fn hold_spawns_post_live(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.post_live_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }
}

impl FakeFs {
  /// The backend the next spawns claim (and thus the profile the core runs).
  pub(crate) fn spawn_backend(&self, backend: BackendKind) {
    *self.state.spawn_backend.lock().unwrap() = backend;
  }

  /// Fails every arm of `path` with `err` (persistent until replaced, or
  /// cleared by [`heal_watch_at`](Self::heal_watch_at)).
  pub(crate) fn fail_watch_at(&self, path: impl AsRef<Path>, err: tributary_proto::WatchError) {
    self
      .state
      .watch_failures
      .lock()
      .unwrap()
      .insert(path.as_ref().to_path_buf(), err);
  }

  /// Clears a [`fail_watch_at`](Self::fail_watch_at) injection: later arms of
  /// `path` resolve normally again — the heal half of a lossy-then-re-issued
  /// grow.
  pub(crate) fn heal_watch_at(&self, path: impl AsRef<Path>) {
    self
      .state
      .watch_failures
      .lock()
      .unwrap()
      .remove(path.as_ref());
  }

  /// Resolves every arm of `path` as `Aliased` — the EEXIST fan-out outcome.
  pub(crate) fn alias_watch_at(&self, path: impl AsRef<Path>) {
    let wd = self.state.wd_seq.fetch_add(1, Ordering::SeqCst) as i32 + 1;
    self
      .state
      .watch_aliases
      .lock()
      .unwrap()
      .insert(path.as_ref().to_path_buf(), wd);
  }

  /// Serves `answer` for the next enumerate of `path`, before the default
  /// readdir of the fake tree.
  pub(crate) fn enumerate_answer(&self, path: impl AsRef<Path>, answer: RawEnumerate) {
    self
      .state
      .enumerate_answers
      .lock()
      .unwrap()
      .entry(path.as_ref().to_path_buf())
      .or_default()
      .push_back(answer);
  }

  /// Holds every subsequent enumerate until released (the close-versus-
  /// in-flight-enumerate cell).
  pub(crate) fn hold_enumerates(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.enumerate_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Holds every subsequent enumerate OF `path` until released, leaving other
  /// directories' listings free — so a cell can strand one watch's read on the
  /// pool while the recovery that re-adds that same watch runs to completion.
  pub(crate) fn hold_enumerates_at(&self, path: impl AsRef<Path>) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.enumerate_exec_hold.lock().unwrap() =
      Some((path.as_ref().to_path_buf(), Arc::clone(&gate)));
    HoldRelease { gate }
  }

  /// Holds every subsequent arm (`add_watch` and discovery/re-arm
  /// `batch_control`) until released — the close-versus-in-flight-arm and
  /// stale-batch-across-replace cells.
  pub(crate) fn hold_arms(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.arm_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Holds every subsequent `refresh_mounts` until released, so a cell can
  /// observe the widen's barrier across the unverified root-binding window
  /// (the commit-armed refresh is the verification edge).
  pub(crate) fn hold_refreshes(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.refresh_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Swaps the node at `path` right after the NEXT `preflight_arm` executes —
  /// between the kernel arm and the stale-Installed bracket's re-stat, the
  /// race the bracket exists to refuse.
  pub(crate) fn swap_after_prearm(&self, path: impl AsRef<Path>, kind: FileKind, ino: u64) {
    *self.state.prearm_swap.lock().unwrap() = Some((
      path.as_ref().to_path_buf(),
      FakeNode {
        kind,
        ino,
        dev: self.root_dev,
        mnt_id: self.root_mnt_id,
      },
    ));
  }

  /// Holds every subsequent `preflight_arm` (a descending replace's pre-arm
  /// on the new transport) until released — distinct from
  /// [`hold_arms`](Self::hold_arms) so a test can freeze in-flight discovery
  /// batches while the commit's pre-arm still proceeds.
  pub(crate) fn hold_prearms(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.prearm_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Per-directory arms executed so far.
  pub(crate) fn arms(&self) -> Vec<(WatchId, PathBuf)> {
    self.state.arms.lock().unwrap().clone()
  }

  /// Arms refused so far because their batch carried a stale (replaced)
  /// transport generation — the observable that the generation fence held.
  pub(crate) fn stale_arms(&self) -> Vec<(WatchId, PathBuf)> {
    self.state.stale_arms.lock().unwrap().clone()
  }

  /// `preflight_arm` entries so far (a HELD pre-arm counts on entry): once
  /// non-zero, the widen's witnessed window is provably open — the pre-arm
  /// dispatch and `begin_widen_watch` share one handler.
  pub(crate) fn prearm_entries(&self) -> usize {
    self.state.prearm_entries.load(Ordering::SeqCst)
  }

  /// `probe` calls executed so far (the widen pre-arm's post-arm bracket is
  /// one) — see the field doc.
  pub(crate) fn probes(&self) -> usize {
    self.state.probes.load(Ordering::SeqCst)
  }

  /// Cookies written so far, in call order.
  pub(crate) fn cookie_writes(&self) -> Vec<PathBuf> {
    self.state.cookie_writes.lock().unwrap().clone()
  }

  /// Cookies unlinked so far, in call order.
  pub(crate) fn cookie_removes(&self) -> Vec<PathBuf> {
    self.state.cookie_removes.lock().unwrap().clone()
  }

  /// Fails every subsequent cookie write with `kind` — the read-only tree.
  pub(crate) fn fail_cookie_writes(&self, kind: std::io::ErrorKind) {
    *self.state.cookie_write_failure.lock().unwrap() = Some(kind);
  }

  /// Makes every subsequent cookie write CREATE its file and then fail with
  /// `kind`, handing the file back as the residue — the created-but-unresolved
  /// write. What a cell built on this proves is an accounting property: the file
  /// exists, so the obligation may not be retired as though nothing had been made.
  pub(crate) fn strand_cookie_writes(&self, kind: std::io::ErrorKind) {
    *self.state.cookie_write_strand.lock().unwrap() = Some(kind);
  }

  /// Fails the next `n` cookie REMOVES with a transient error, then lets removes
  /// succeed again — a flaky/hung unlink, so a cell can prove the record is
  /// retained and the path retried until it clears.
  pub(crate) fn fail_next_cookie_removes(&self, n: usize) {
    self.state.cookie_remove_failures.store(n, Ordering::SeqCst);
  }

  /// Models an intermediate symlink: a cookie write whose resolved directory is
  /// `spelled` canonicalizes to `canonical`, so the fake's beneath check runs
  /// against the real target — a `canonical` outside the root is refused, matching
  /// production's `std::fs::canonicalize` before the containment test.
  pub(crate) fn resolve_cookie_dir_to(
    &self,
    spelled: impl AsRef<Path>,
    canonical: impl AsRef<Path>,
  ) {
    self.state.canonical_dirs.lock().unwrap().insert(
      spelled.as_ref().to_path_buf(),
      canonical.as_ref().to_path_buf(),
    );
  }

  /// Cookie writes dispatched to the pool so far (counted before any hold), so a
  /// cell can prove a write is IN FLIGHT before racing something against it.
  pub(crate) fn cookie_dispatches(&self) -> usize {
    self.state.cookie_dispatches.load(Ordering::SeqCst)
  }

  /// Cookie removes dispatched to the pool so far (counted before any hold), so
  /// a cell can prove a terminal unlink is IN FLIGHT before racing a close (or a
  /// Drop) against it.
  pub(crate) fn cookie_remove_dispatches(&self) -> usize {
    self.state.cookie_remove_dispatches.load(Ordering::SeqCst)
  }

  /// Holds every subsequent cookie write in the blocking pool until the returned
  /// gate is released — the window a retirement, an abandoned reply, or a driver
  /// teardown races the write in.
  pub(crate) fn hold_cookie_writes(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.cookie_write_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Holds every subsequent cookie REMOVE in the blocking pool until the
  /// returned gate is released — a hung terminal unlink, so a cell can prove a
  /// close reports `NotQuiesced` within its grace rather than wedging, and that
  /// a cancelled driver's `Drop` does not block on it.
  pub(crate) fn hold_cookie_removes(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.cookie_remove_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Holds every subsequent cookie remove AFTER the node is unlinked but BEFORE
  /// the pool job takes the ledger lock to confirm — the R11-3 preemption
  /// window, where a successor sync can reclaim the freed path before the stale
  /// confirm lands. `files_under` flips at the gate; `cookie_removes()` records
  /// only after release, so the two bracket the ABA window cleanly.
  pub(crate) fn hold_cookie_remove_confirms(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.cookie_remove_confirm_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Fails every cookie remove whose path lies under `prefix`, PERSISTENTLY and
  /// without unlinking the node — a still-failing mount subtree, so a cell can
  /// hold one scope's backlog failing while another recovers.
  pub(crate) fn fail_cookie_removes_under(&self, prefix: impl AsRef<Path>) {
    self
      .state
      .cookie_remove_failure_prefixes
      .lock()
      .unwrap()
      .push(prefix.as_ref().to_path_buf());
  }

  /// Clears a prefix armed by [`fail_cookie_removes_under`](Self::fail_cookie_removes_under)
  /// — that subtree's mount recovered, so its removes succeed from here on.
  pub(crate) fn clear_cookie_remove_failures_under(&self, prefix: impl AsRef<Path>) {
    let prefix = prefix.as_ref();
    self
      .state
      .cookie_remove_failure_prefixes
      .lock()
      .unwrap()
      .retain(|armed| armed != prefix);
  }

  /// Makes every live fake handle mint `token` as its resume point — a
  /// journal-bearing backend, modeled.
  pub(crate) fn mint_resume_token(&self, token: crate::os::ResumeToken) {
    *self.state.resume_token.lock().unwrap() = Some(token);
  }

  /// The `since` each spawn was configured with, in spawn order.
  pub(crate) fn spawn_resume_points(&self) -> Vec<Option<crate::os::ResumeToken>> {
    self.state.spawn_resume_points.lock().unwrap().clone()
  }

  /// The non-parking core of one arm: record it, then model object
  /// correctness (identity mismatch and alias) and mint a watch descriptor,
  /// exactly as [`add_watch`](FsOps::add_watch) does once past the hold.
  fn arm_one(
    &self,
    _scope: ScopeId,
    watch: WatchId,
    _parent: WatchId,
    path: &Path,
    _name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    self
      .state
      .arms
      .lock()
      .unwrap()
      .push((watch, path.to_path_buf()));
    // Freeze THIS arm's execution if a path-targeted hold matches: a cell can
    // stall one watch's re-add mid-batch (its batch's completion signal pending)
    // while a same-scope disarm batch races it.
    self.park_arm_exec(path);
    if let Some(err) = self.state.watch_failures.lock().unwrap().get(path) {
      return WatchOutcome::Failed(*err);
    }
    if let Some(expected) = expected {
      let current = self.state.nodes.lock().unwrap().get(path).copied();
      let matches =
        current.is_some_and(|node| node.dev == expected.dev && node.ino == expected.ino.get());
      if !matches {
        return WatchOutcome::Failed(tributary_proto::WatchError::Gone);
      }
    }
    // The arm installs (or aliases) a kernel watch: record it live, so a reorder
    // that installs it AFTER its disarm already ran shows as a residual entry.
    self.state.live_watches.lock().unwrap().insert(watch);
    // The arm also publishes its transient anchor, as the real executor does
    // from the arm's reply. The id is fresh every time: re-arming a watch the
    // core re-added supersedes the previous publication rather than renewing it,
    // so a listing can be told apart by WHICH publication it read through.
    let anchor = self.state.anchor_seq.fetch_add(1, Ordering::SeqCst) as u64 + 1;
    self.state.anchors.lock().unwrap().insert(watch, anchor);
    if let Some(wd) = self.state.watch_aliases.lock().unwrap().get(path) {
      return WatchOutcome::Aliased(*wd);
    }
    let wd = self.state.wd_seq.fetch_add(1, Ordering::SeqCst) as i32 + 1;
    WatchOutcome::Installed(wd)
  }

  /// Parks an arm's execution on the path-targeted [`FakeFs::hold_arm_exec_at`]
  /// gate — a no-op unless a gate is installed for exactly this `path`.
  fn park_arm_exec(&self, path: &Path) {
    self.park_on_path(&self.state.arm_exec_hold, path);
  }

  /// Parks on a PATH-TARGETED gate — a no-op unless the installed gate names
  /// exactly this `path`. The capture is committed after the clone binds the
  /// job to that gate instance, on the same reasoning as [`FakeFs::park_on`].
  fn park_on_path(&self, hold: &Mutex<Option<(PathBuf, HoldGate)>>, path: &Path) {
    let gate = hold
      .lock()
      .unwrap()
      .as_ref()
      .filter(|(held, _)| held == path)
      .map(|(_, gate)| Arc::clone(gate));
    if let Some(gate) = gate {
      gate.2.fetch_add(1, Ordering::SeqCst);
      let (held, cvar, _) = &*gate;
      let mut parked = held.lock().unwrap();
      while *parked {
        parked = cvar.wait(parked).unwrap();
      }
    }
  }

  /// The watches the fake currently models as INSTALLED (armed, not yet
  /// disarmed) — a residual entry is a reorder orphan.
  pub(crate) fn live_watches(&self) -> BTreeSet<WatchId> {
    self.state.live_watches.lock().unwrap().clone()
  }

  /// Holds every subsequent arm EXECUTION at `path` until released, leaving
  /// same-scope disarm batches free — the re-add-versus-prune reorder cell.
  pub(crate) fn hold_arm_exec_at(&self, path: impl AsRef<Path>) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.arm_exec_hold.lock().unwrap() =
      Some((path.as_ref().to_path_buf(), Arc::clone(&gate)));
    HoldRelease { gate }
  }

  /// Per-directory disarms executed so far.
  pub(crate) fn disarms(&self) -> Vec<WatchId> {
    self.state.disarms.lock().unwrap().clone()
  }

  /// Every control batch SUBMITTED so far, in call order, as
  /// `(scope, request count)`. Counted at the entry to
  /// [`batch_control`](FsOps::batch_control) — before any hold — so a batch frozen
  /// on a gate, or one that unwinds, is already here. A zero-request entry is the
  /// ordering-proof round trip.
  pub(crate) fn control_batches(&self) -> Vec<(ScopeId, usize)> {
    self.state.control_batches.lock().unwrap().clone()
  }

  /// Arms the next [`batch_control`](FsOps::batch_control) for `scope` to UNWIND
  /// instead of returning — the pool worker itself dying part-way through a batch.
  /// [`kill_next_control_reader`](Self::kill_next_control_reader) is the other way
  /// a batch goes unanswered, and the two are not interchangeable.
  ///
  /// ONE-SHOT, and scope-keyed: the arm is taken when it fires, so exactly one
  /// batch dies and every later batch (this scope's or another's) behaves
  /// normally. The arm lives in this fake's own state, which no other rig shares,
  /// so it cannot reach another cell either.
  ///
  /// The panic is taken with NO [`FakeState`] lock held. That is load-bearing
  /// rather than tidy: a `panic!` under one of these mutexes would POISON it, and
  /// every later `lock().unwrap()` in the fake — including the one
  /// [`HoldRelease::release`] needs to free a parked pool job — would panic in
  /// turn, replacing the cell's report with an unrelated cascade.
  pub(crate) fn panic_next_control_batch(&self, scope: ScopeId) {
    *self.state.batch_panic_arm.lock().unwrap() = Some(scope);
  }

  /// Arms the next [`batch_control`](FsOps::batch_control) for `scope` to RETURN
  /// having never been answered — the reader dying between dequeuing the batch and
  /// replying to it, which the pool worker cannot see as anything but a normal
  /// return.
  ///
  /// Distinct from [`panic_next_control_batch`](Self::panic_next_control_batch),
  /// and not reachable through it: a panic unwinds the worker, which the completion
  /// guard reports by itself. Here the worker returns, so the ONLY thing separating
  /// this from a batch the reader served is the outcome's `answered` — and on the
  /// ordering-proof round trip, which carries no arms, the two returns resolve an
  /// identically empty vector.
  ///
  /// The batch executes NOTHING: no arm, no disarm, and no staged-loss flush,
  /// because a reader that died before replying never cut its kernel queue onto the
  /// lane. Its arms are still answered `Failed(Io)`, exactly as the real port
  /// answers a batch its reader never ran, so no registration is stranded.
  ///
  /// ONE-SHOT and scope-keyed, like the panic arm.
  pub(crate) fn kill_next_control_reader(&self, scope: ScopeId) {
    *self.state.reader_death_arm.lock().unwrap() = Some(scope);
  }

  /// Takes the one-shot
  /// [`kill_next_control_reader`](Self::kill_next_control_reader) arm if it names
  /// `scope`.
  fn take_reader_death(&self, scope: ScopeId) -> bool {
    Self::take_scope_arm(&self.state.reader_death_arm, scope)
  }

  /// Arms the next DISPATCHED control batch for `scope` to be taken by a reader
  /// that never answers it: neither its ops nor its reply ever happen, and the
  /// batch stays outstanding for the rest of the fake's life.
  ///
  /// This is the reader wedged inside a syscall against a hung filesystem — the
  /// one that observes nothing, not the batch and not its own shutdown, until the
  /// kernel returns. It is distinct from every other way a batch fails to run,
  /// and the distinction is the point: a
  /// [`panic`](Self::panic_next_control_batch) unwinds the dispatching worker and
  /// a [`reader death`](Self::kill_next_control_reader) answers it refused, so
  /// both give the worker back and both reach a terminal. This one gives the
  /// worker back and reaches NO terminal, which is precisely what a fixed-width
  /// pool must survive arbitrarily many of.
  ///
  /// ONE-SHOT and scope-keyed, like the arms beside it.
  pub(crate) fn strand_next_control_reader(&self, scope: ScopeId) {
    *self.state.reader_strand_arm.lock().unwrap() = Some(scope);
  }

  /// Every batch a stranded reader took and never answered, as
  /// `(scope, request count)`.
  pub(crate) fn stranded_control_batches(&self) -> Vec<(ScopeId, usize)> {
    self
      .state
      .stranded_batches
      .lock()
      .unwrap()
      .iter()
      .map(|(scope, requests, _)| (*scope, *requests))
      .collect()
  }

  /// Records one SUBMITTED batch, at the top of whichever entry received it and
  /// before any hold, gate or arm can divert it — so a batch frozen on a gate,
  /// one that unwinds, and one a stranded reader keeps are all already counted.
  fn record_control_batch(&self, scope: ScopeId, requests: usize) {
    self
      .state
      .control_batches
      .lock()
      .unwrap()
      .push((scope, requests));
  }

  /// Runs one control batch to its outcome, carrying the transport GENERATION it
  /// was emitted for. The parking happens ONCE here (the hold point a test uses
  /// to freeze a batch across a replace), then the generation is re-read: a batch
  /// whose generation no longer matches the attached transport is a leftover of a
  /// replaced stream and refuses every arm, exactly as the real source does —
  /// landing nothing on the new transport.
  fn run_control_batch(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> super::ControlBatchOutcome {
    self.park_on(&self.state.arm_hold);
    // The pool worker dying part-way through a batch, modeled at the one place it
    // is observable: this call UNWINDS instead of returning, so the completion
    // guard fires with its default end and no arm result is fed back. Taken
    // BELOW the hold, so a cell can freeze one batch on a gate, arm the death
    // while it is parked, and have the death land on the NEXT batch — the frozen
    // one is already past this line.
    if self.take_batch_panic(scope) {
      panic!("the fake's control reader dies inside batch_control for {scope:?}");
    }
    // The READER dying between dequeuing the batch and replying to it — the other
    // way a batch goes unanswered, and the one the worker cannot see. It returns
    // normally with every arm refused and nothing executed: no arm, no disarm, and
    // NO staged-loss flush, since the cut belongs to the reply this reader never
    // sent. Only `answered` tells this apart from a served batch, and on the
    // ordering-proof round trip it is the only thing that could.
    if self.take_reader_death(scope) {
      return super::ControlBatchOutcome {
        resolutions: requests
          .iter()
          .filter_map(|request| match request {
            ControlRequest::Arm { watch, attempt, .. } => Some(super::ArmResolution {
              watch: *watch,
              attempt: *attempt,
              outcome: WatchOutcome::Failed(tributary_proto::WatchError::Io),
            }),
            ControlRequest::Disarm { .. } => None,
          })
          .collect(),
        answered: false,
      };
    }
    let attached = self
      .state
      .scope_generation
      .lock()
      .unwrap()
      .get(&scope)
      .copied();
    if attached != Some(generation) {
      // A deliberate refusal, so it ANSWERS: nothing ran, every arm says so, and
      // the fake is the one that decided it — exactly as the real source reports
      // its own generation front-check.
      return super::ControlBatchOutcome {
        resolutions: requests
          .into_iter()
          .filter_map(|request| match request {
            ControlRequest::Arm {
              watch,
              attempt,
              path,
              ..
            } => {
              self
                .state
                .stale_arms
                .lock()
                .unwrap()
                .push((watch, path.to_path_buf()));
              Some(super::ArmResolution {
                watch,
                attempt,
                outcome: WatchOutcome::Failed(tributary_proto::WatchError::Gone),
              })
            }
            ControlRequest::Disarm { .. } => None,
          })
          .collect(),
        answered: true,
      };
    }
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
        } => outcomes.push(super::ArmResolution {
          watch,
          attempt,
          outcome: self.arm_one(scope, watch, parent, path.as_path(), &name, expected),
        }),
        ControlRequest::Disarm { watch } => {
          self.state.disarms.lock().unwrap().push(watch);
          self.state.live_watches.lock().unwrap().remove(&watch);
          self.state.anchors.lock().unwrap().remove(&watch);
        }
      }
    }
    // The reader's pre-reply cut, modeled at its real position: a loss the
    // kernel had already committed reaches the queue HERE — past this batch's
    // work, before the completion the driver sees — so the reply is an ordering
    // proof rather than an unrelated round trip. A batch REFUSED for a stale
    // generation, or one whose reader died, returned above without reaching this
    // line, exactly as a real batch no reader served crosses nothing and so cuts
    // nothing.
    self.flush_staged_kernel_losses();
    super::ControlBatchOutcome {
      resolutions: outcomes,
      answered: true,
    }
  }

  /// Takes the one-shot [`panic_next_control_batch`](Self::panic_next_control_batch)
  /// arm if it names `scope`. Separate from the `panic!` itself so the lock guard is
  /// released before the unwind starts.
  fn take_batch_panic(&self, scope: ScopeId) -> bool {
    Self::take_scope_arm(&self.state.batch_panic_arm, scope)
  }

  /// Takes a one-shot scope-keyed arm if it names `scope`, leaving it disarmed.
  fn take_scope_arm(arm: &Mutex<Option<ScopeId>>, scope: ScopeId) -> bool {
    let mut armed = arm.lock().unwrap();
    if *armed == Some(scope) {
      *armed = None;
      true
    } else {
      false
    }
  }

  /// Enumerates executed so far.
  pub(crate) fn enumerates(&self) -> Vec<(WatchId, PathBuf)> {
    self.state.enumerates.lock().unwrap().clone()
  }

  /// Each executed enumerate's `(watch, anchor publication it read through)`,
  /// in execution order. A `None` is a listing that fell back to the absolute
  /// path, and two entries sharing an id would be two listings over one
  /// publication.
  pub(crate) fn enumerate_anchors(&self) -> Vec<(WatchId, Option<u64>)> {
    self.state.enumerate_anchors.lock().unwrap().clone()
  }

  fn park_on(&self, hold: &Mutex<Option<HoldGate>>) {
    let gate = hold.lock().unwrap().clone();
    if let Some(gate) = gate {
      // The parked-on-THIS-gate ack, committed right after the clone binds
      // the job to this exact gate instance: a caller observing the count
      // through the same `Arc` knows a later-installed gate can never
      // retroactively steal this job.
      gate.2.fetch_add(1, Ordering::SeqCst);
      let (held, cvar, _) = &*gate;
      let mut parked = held.lock().unwrap();
      while *parked {
        parked = cvar.wait(parked).unwrap();
      }
    }
  }
}

/// Releases work parked by [`FakeFs::hold_spawns`] / [`FakeFs::hold_teardowns`].
///
/// # The gate opens on drop, and that is load-bearing
///
/// A held gate parks a blocking-pool job on a condition variable. If a cell
/// panics — which is exactly what a cell does when it FINDS the defect it exists
/// to catch — an explicit `release()` placed after the assertions never runs, the
/// parked job never wakes, and the runtime's shutdown waits on it forever. The
/// intended fail-fast report becomes a hung test binary instead, and the defect
/// is reported as a timeout with no assertion text at all.
///
/// Releasing on `Drop` makes every unwind path open the gate, so a cell cannot
/// wedge the binary by holding one. `release()` stays available for the cells that
/// open a gate mid-test and keep testing afterwards, and it is idempotent: it
/// stores `false` and notifies, so an explicit call followed by the drop is
/// harmless.
pub(crate) struct HoldRelease {
  gate: HoldGate,
}

impl Drop for HoldRelease {
  fn drop(&mut self) {
    self.release();
  }
}

impl HoldRelease {
  pub(crate) fn release(&self) {
    let (held, cvar, _) = &*self.gate;
    *held.lock().unwrap() = false;
    cvar.notify_all();
  }

  /// Jobs that have captured this gate via [`FakeFs::park_on`] — cloned it
  /// and committed to parking on (or passing through) THIS instance. Proves
  /// a dispatch has bound to this gate, not merely that a dispatch happened;
  /// a test settles on this before installing a superseding hold, closing
  /// the window where the new gate could otherwise capture an attempt that
  /// was still choosing which gate to park on.
  pub(crate) fn captured(&self) -> usize {
    self.gate.2.load(Ordering::SeqCst)
  }
}

pub(crate) struct FakeHandle {
  state: Arc<FakeState>,
  shut: bool,
}

impl SourceControl for FakeHandle {
  fn resume_token(&self) -> Option<crate::os::ResumeToken> {
    *self.state.resume_token.lock().unwrap()
  }

  fn shutdown(mut self) -> crate::os::Quiesce {
    // The wedge gate parks INSIDE the call, after the handle moved in —
    // exactly the phase where no Drop backstop can exist. Drop itself never
    // waits, or a failing test would hang its own teardown. The bind is
    // acknowledged exactly as `park_on` does, so a cell can settle on the
    // shutdown having parked (the observable that a close broke the loop).
    let gate = self.state.teardown_hold.lock().unwrap().clone();
    if let Some(gate) = gate {
      gate.2.fetch_add(1, Ordering::SeqCst);
      let (held, cvar, _) = &*gate;
      let mut parked = held.lock().unwrap();
      while *parked {
        parked = cvar.wait(parked).unwrap();
      }
    }
    if self
      .state
      .panic_teardowns
      .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
        left.checked_sub(1)
      })
      .is_ok()
    {
      self.shut = true;
      panic!("injected teardown panic");
    }
    self.shut = true;
    self.state.note_reclaim_thread();
    self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
    // The counters above are the healthy path's, and this arm takes them too:
    // an unproven teardown RAN. Only the answer differs, which is exactly the
    // shape the driver has to key on.
    if self
      .state
      .unproven_teardowns
      .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
        left.checked_sub(1)
      })
      .is_ok()
    {
      return crate::os::Quiesce::Unproven;
    }
    crate::os::Quiesce::Proven
  }
}

impl Drop for FakeHandle {
  fn drop(&mut self) {
    // The real handle's Drop backstop, mirrored: an owner that never called
    // shutdown still reclaims the stream.
    if !self.shut {
      self.state.note_reclaim_thread();
      self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
  }
}

impl FsOps for FakeFs {
  type Handle = FakeHandle;
  /// The fake's stand-in for an `O_PATH` fd: the publication id its arm minted.
  type Anchor = u64;

  fn spawn_source(
    &self,
    config: SourceConfig,
  ) -> Result<SpawnedSource<Self::Handle>, SpawnFailed<Self::Handle>> {
    // Record the resume point this spawn was configured with, BEFORE any hold
    // or outcome: a replacement inheriting the retiring stream's point is the
    // observable, and it exists whether or not the spawn goes on to succeed.
    self
      .state
      .spawn_resume_points
      .lock()
      .unwrap()
      .push(config.since);
    // The hold gate parks the whole spawn — before any outcome is decided —
    // so a test can race close() against a spawn that is dispatched but not
    // yet returned.
    let hold = self.state.spawn_hold.lock().unwrap().clone();
    if let Some(gate) = hold {
      let (held, cvar, _) = &*gate;
      let mut parked = held.lock().unwrap();
      while *parked {
        parked = cvar.wait(parked).unwrap();
      }
    }
    let requested = config.roots.first().cloned().ok_or(SourceError::NoRoots)?;
    // A root vanished before start is a clean spawn failure — the pre-start
    // half of the lifecycle contract (post-start deaths travel in-band).
    if !self.state.nodes.lock().unwrap().contains_key(&requested) {
      return Err(
        SourceError::RootUnavailable {
          root: requested,
          source: std::io::Error::from(std::io::ErrorKind::NotFound),
        }
        .into(),
      );
    }
    // The backend re-canonicalizes at spawn; a configured remap mirrors a
    // root retargeted between the watcher's reservation and this point.
    let root = self
      .state
      .spawn_remaps
      .lock()
      .unwrap()
      .get(&requested)
      .cloned()
      .unwrap_or(requested);
    // The kind recheck of the pre-start barrier: the FINAL root must be a
    // directory, exactly as the real backend asserts after its own
    // re-canonicalization.
    if let Some(node) = self.state.nodes.lock().unwrap().get(&root)
      && !node.kind.is_dir()
    {
      return Err(SourceError::NotADirectory { root }.into());
    }
    // The pre-start barrier, mirrored from the real backend: the metadata is
    // sealed strictly before the source becomes injectable (`stream_live`),
    // and the mount seed claims no authority (the driver's birth refresh
    // installs it). Identity aliasing is driven through `put`: two paths
    // sharing one `(dev, ino)` ARE one object, exactly like case-aliased
    // spellings on a real insensitive volume; an ancestor put with a live
    // root's identity exercises the containment cells. A final root the test
    // never put gets a synthetic identity that can collide with nothing.
    let sealed = {
      let nodes = self.state.nodes.lock().unwrap();
      nodes
        .get(&root)
        .map(|node| RootIdentity::new(node.dev, node.ino.into()))
    };
    let identity = sealed.unwrap_or_else(|| {
      RootIdentity::new(
        u64::MAX,
        self.state.spawns.load(Ordering::SeqCst) as u128 + 1,
      )
    });
    self.state.spawn_order.lock().unwrap().push("meta_sealed");
    let (sender, receiver) = async_channel::unbounded();
    let transport = Arc::new(crate::os::transport::TransportState::new(
      config.channel_capacity.get(),
    ));
    self
      .state
      .sources
      .lock()
      .unwrap()
      .entry(root.clone())
      .or_default()
      .push(FakeSource {
        sender,
        transport,
        pending_kernel_loss: AtomicBool::new(false),
      });
    self.state.spawn_order.lock().unwrap().push("stream_live");
    self.state.spawns.fetch_add(1, Ordering::SeqCst);
    // The post-live wedge parks HERE — the stream is live and injectable, the
    // spawn has not returned, and no handle exists yet for any backstop:
    // exactly the phase the close accounting must count as non-quiescent.
    let post_live = self.state.post_live_hold.lock().unwrap().clone();
    if let Some(gate) = post_live {
      let (held, cvar, _) = &*gate;
      let mut parked = held.lock().unwrap();
      while *parked {
        parked = cvar.wait(parked).unwrap();
      }
    }
    // An armed replacement lands now — after the stream went live, before the
    // revalidation — the deterministic capture→start race.
    if let Some((path, node)) = self.state.replace_at_live.lock().unwrap().take() {
      self.state.nodes.lock().unwrap().insert(path, node);
    }
    // The post-live half of the identity bracket, mirrored from the real
    // backend: the root must still be the sealed object (and a directory);
    // otherwise the just-live fake stream is torn down before spawn returns.
    self
      .state
      .spawn_order
      .lock()
      .unwrap()
      .push("root_revalidated");
    let live = {
      let nodes = self.state.nodes.lock().unwrap();
      nodes.get(&root).map(|node| (node.kind, node.ino, node.dev))
    };
    let reject = match (sealed, live) {
      // The synthetic-identity convention: a root the test never put stays
      // absent — unchanged absence is a consistent bracket, not a vanish.
      (None, None) => None,
      (Some(_), None) => Some(SourceError::RootUnavailable {
        root: root.clone(),
        source: std::io::Error::new(
          std::io::ErrorKind::NotFound,
          "the root vanished before the stream went live",
        ),
      }),
      (_, Some((kind, _, _))) if !kind.is_dir() => {
        Some(SourceError::NotADirectory { root: root.clone() })
      }
      (_, Some((_, ino, dev))) if RootIdentity::new(dev, ino.into()) != identity => {
        Some(SourceError::RootReplaced { root: root.clone() })
      }
      (_, Some(_)) => None,
    };
    if let Some(err) = reject {
      if let Some(spawned) = self.state.sources.lock().unwrap().get_mut(&root) {
        spawned.pop();
      }
      // The rollback is HANDED BACK live, never shut down here — the real
      // barriers' shape. A backend that tore its own post-live stream down
      // discarded the `Quiesce` its teardown answered, so a rollback that
      // retained kernel-owned state reached no terminal, no backlog and no close
      // reply. Returning the handle puts the retirement (and therefore the
      // verdict) inside the driver's one counted submission. The `shutdowns`
      // counter is deliberately NOT bumped here: it moves when the handle is
      // actually torn down, on the reaper.
      return Err(SpawnFailed::rolled_back(
        err,
        FakeHandle {
          state: Arc::clone(&self.state),
          shut: false,
        },
      ));
    }
    // Ancestor identities read after the stream is live, like the backend.
    let ancestors = {
      let nodes = self.state.nodes.lock().unwrap();
      root
        .ancestors()
        .skip(1)
        .filter_map(|ancestor| nodes.get(ancestor))
        .map(|node| RootIdentity::new(node.dev, node.ino.into()))
        .collect()
    };
    let meta = RootMeta {
      root: root.clone(),
      root_dev: self.root_dev,
      root_mnt_id: self.root_mnt_id,
      mounts: self.state.spawn_mounts.lock().unwrap().clone(),
      identity,
      ancestors,
      backend: *self.state.spawn_backend.lock().unwrap(),
    };
    Ok(SpawnedSource {
      handle: FakeHandle {
        state: Arc::clone(&self.state),
        shut: false,
      },
      receiver,
      meta,
    })
  }

  fn probe(&self, path: &Path) -> ProbeOutcome {
    self.state.probes.fetch_add(1, Ordering::SeqCst);
    match self.state.nodes.lock().unwrap().get(path) {
      Some(node) => ProbeOutcome::Present {
        kind: node.kind,
        file_id: NonZeroU64::new(node.ino),
        dev: node.dev,
      },
      None => ProbeOutcome::Missing,
    }
  }

  fn refresh_mounts(&self, root: &Path) -> MountRefresh {
    self.park_on(&self.state.refresh_hold);
    self.state.refreshes.fetch_add(1, Ordering::SeqCst);
    let (mounts, authoritative) = self
      .state
      .refresh_answer
      .lock()
      .unwrap()
      .clone()
      .unwrap_or((Vec::new(), true));
    // ONE node read yields BOTH the liveness identity and the mount frame, so the
    // fake CANNOT pair a present-and-matching verdict with a different object's
    // frame — the mixed sample the real `statx` restructure makes impossible is
    // impossible here too. A replaced root is modeled by REPLACING the node (`put` /
    // [`replace_root_node`]), and this single read then reports the REPLACED identity
    // WITH its frame, never a mix. The `root_liveness` override remains only for the
    // verdicts a present node cannot express — `Missing` / `Unreadable` (a vanished /
    // unreadable root) — which carry no frame (the real `statx` returns none on a
    // failed stat), so an override forces the frame to `None` too; it never
    // fabricates a `Present` identity divorced from the node it would pair against.
    let sampled = self
      .state
      .nodes
      .lock()
      .unwrap()
      .get(root)
      .map(|node| (RootIdentity::new(node.dev, node.ino.into()), node.mnt_id));
    let (root_liveness, root_mnt_id) = match self.state.root_liveness.lock().unwrap().as_ref() {
      Some(override_liveness) => (*override_liveness, None),
      None => match sampled {
        Some((identity, mnt_id)) => (RootLiveness::Present(identity), mnt_id),
        None => (RootLiveness::Missing, None),
      },
    };
    MountRefresh {
      mounts,
      authoritative,
      root: root_liveness,
      root_mnt_id,
    }
  }

  fn attach_scope(&self, scope: ScopeId, _port: crate::os::ScopePort, generation: u64) {
    self
      .state
      .scope_generation
      .lock()
      .unwrap()
      .insert(scope, generation);
  }

  fn detach_scope(&self, scope: ScopeId) {
    self.state.scope_generation.lock().unwrap().remove(&scope);
  }

  fn add_watch(
    &self,
    scope: ScopeId,
    watch: WatchId,
    parent: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    self.park_on(&self.state.arm_hold);
    self.arm_one(scope, watch, parent, path, name, expected)
  }

  // The blocking batch entry: the fake answers its own arms, so it needs no
  // reader and the whole batch runs here.
  fn batch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> super::ControlBatchOutcome {
    self.record_control_batch(scope, requests.len());
    self.run_control_batch(scope, generation, requests)
  }

  // The entry the DRIVER calls. Answering inline is what an executor with no
  // reader does, and the fake is one — so unless a reader has been stranded on
  // this batch, this is `batch_control` with the outcome handed to the sink.
  fn dispatch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
    answer: super::ControlAnswer<FakeHandle>,
  ) {
    self.record_control_batch(scope, requests.len());
    // A reader that took the batch and will not answer: park the sink, unexecuted,
    // and RETURN. Returning is the whole model — a wedged reader holds the batch,
    // not the thread that handed it over — so the caller's worker is free while the
    // batch stays outstanding forever. Taken above the generation front-check
    // because a reader stuck in a syscall stops reading long before it could form
    // an opinion about which transport the batch names.
    if Self::take_scope_arm(&self.state.reader_strand_arm, scope) {
      self
        .state
        .stranded_batches
        .lock()
        .unwrap()
        .push((scope, requests.len(), answer));
      return;
    }
    answer.resolve(self.run_control_batch(scope, generation, requests));
  }

  fn remove_watch(&self, _scope: ScopeId, watch: WatchId) {
    self.state.disarms.lock().unwrap().push(watch);
    self.state.live_watches.lock().unwrap().remove(&watch);
    self.state.anchors.lock().unwrap().remove(&watch);
  }

  // A descending replace's pre-arm of the new root on its fresh transport,
  // BEFORE the port is attached under the scope. It parks on its OWN gate
  // (not `arm_hold`) so a test can freeze concurrent discovery batches while
  // this pre-arm still commits. The generation fence does not apply — this
  // arms the explicit new-stream port, which no other batch can reach.
  fn preflight_arm(
    &self,
    _port: &crate::os::ScopePort,
    scope: ScopeId,
    watch: WatchId,
    path: &Path,
    name: &Segment,
    expected: Option<ExpectedObject>,
  ) -> WatchOutcome {
    // Entry counts BEFORE the hold parks: reaching here proves the witnessed
    // window is open (see `prearm_entries`).
    self.state.prearm_entries.fetch_add(1, Ordering::SeqCst);
    self.park_on(&self.state.prearm_hold);
    let outcome = self.arm_one(scope, watch, watch, path, name, expected);
    // The arm→re-stat race, modeled deterministically: the swap lands after
    // the kernel arm bound its object, before the bracket's probe.
    if let Some((path, node)) = self.state.prearm_swap.lock().unwrap().take() {
      self.state.nodes.lock().unwrap().insert(path, node);
    }
    outcome
  }

  // The no-spawn meta half of the barrier, mirrored: canonicalize (the remap
  // table), require the object, refuse a non-directory, and seal identity,
  // frame, ancestors, and the mount seed from the node map. The FRAME comes
  // from the node itself (unlike a spawn's fake-global default), so a
  // `put_on_mount` old world exercises the driver's same-frame re-validation.
  fn resolve_root_meta(&self, path: &Path) -> Result<RootMeta, SourceError> {
    let nodes = self.state.nodes.lock().unwrap();
    if !nodes.contains_key(path) {
      return Err(SourceError::RootUnavailable {
        root: path.to_path_buf(),
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
      });
    }
    let root = self
      .state
      .spawn_remaps
      .lock()
      .unwrap()
      .get(path)
      .cloned()
      .unwrap_or_else(|| path.to_path_buf());
    let Some(node) = nodes.get(&root) else {
      return Err(SourceError::RootUnavailable {
        root,
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
      });
    };
    if !node.kind.is_dir() {
      return Err(SourceError::NotADirectory { root });
    }
    let identity = RootIdentity::new(node.dev, node.ino.into());
    let root_dev = node.dev;
    let root_mnt_id = node.mnt_id;
    let ancestors = root
      .ancestors()
      .skip(1)
      .filter_map(|ancestor| nodes.get(ancestor))
      .map(|node| RootIdentity::new(node.dev, node.ino.into()))
      .collect();
    Ok(RootMeta {
      root,
      root_dev,
      root_mnt_id,
      mounts: self.state.spawn_mounts.lock().unwrap().clone(),
      identity,
      ancestors,
      backend: *self.state.spawn_backend.lock().unwrap(),
    })
  }

  fn write_cookie(
    &self,
    root: &Path,
    dir: &Path,
    name: &str,
  ) -> Result<CookieFile, CookieWriteError> {
    // The dispatch is counted BEFORE the hold: a cell that must race a scope
    // retirement (or an abandoned reply) against a write in flight needs to know
    // the write is parked in the pool, not still queued behind its settle fence.
    self.state.cookie_dispatches.fetch_add(1, Ordering::SeqCst);
    self.park_on(&self.state.cookie_write_hold);
    if let Some(kind) = *self.state.cookie_write_failure.lock().unwrap() {
      return Err(CookieWriteError::clean(std::io::Error::new(
        kind,
        "cookie write refused",
      )));
    }
    // The real `cookie_dir` resolution, mirrored: a covered FILE subscription's
    // key names a file, so the cookie lands BESIDE it rather than failing ENOTDIR
    // inside it — and never above the root, whose own parent is outside the tree.
    // The lock is released before the `put` below re-takes it.
    let path = {
      let nodes = self.state.nodes.lock().unwrap();
      let target = match nodes.get(dir) {
        Some(node) if node.kind.is_dir() => dir,
        _ => match dir.parent() {
          Some(parent) if parent.starts_with(root) => parent,
          _ => dir,
        },
      };
      // A real `create_new` fails when the containing directory is not there (or
      // is not one): ENOENT/ENOTDIR. The fake refuses too, or a cell could
      // "place a barrier" into thin air — a root that died under an in-flight
      // sync is exactly that case.
      if !nodes.get(target).is_some_and(|node| node.kind.is_dir()) {
        return Err(CookieWriteError::clean(std::io::Error::new(
          std::io::ErrorKind::NotFound,
          "the cookie directory is gone",
        )));
      }
      // Canonicalize the resolved directory (resolving any modeled intermediate
      // symlink) and verify it is BENEATH the root — the production
      // canonicalize-and-verify, mirrored. A directory whose real target escapes
      // the root is refused even though its spelling sits under it. The cookie
      // lands at the CANONICAL path, so the record names where it truly went.
      let canonical_dir = self
        .state
        .canonical_dirs
        .lock()
        .unwrap()
        .get(target)
        .cloned()
        .unwrap_or_else(|| target.to_path_buf());
      if !canonical_dir.starts_with(root) {
        return Err(CookieWriteError::clean(std::io::Error::other(
          "the cookie directory resolves outside the watched root",
        )));
      }
      let path = canonical_dir.join(name);
      // O_NOFOLLOW on the real create, mirrored: a symlink swapped in where the
      // cookie is to land is refused rather than followed to a target that could
      // sit outside the root. The fake models the refusal (it holds no symlink
      // targets, so "not followed" is intrinsic) so the contract is exercised.
      if matches!(
        nodes.get(&path).map(|node| node.kind),
        Some(FileKind::Symlink)
      ) {
        return Err(CookieWriteError::clean(std::io::Error::new(
          std::io::ErrorKind::AlreadyExists,
          "refusing to follow a symlink at the cookie path",
        )));
      }
      path
    };
    // The cookie is a real object in the fake tree, exactly as a real create
    // is: a test can then inject its kernel event like any other file's.
    let ino = self.state.wd_seq.fetch_add(1, Ordering::SeqCst) as u64 + 9000;
    // `create_new` fidelity (production parity): a create over an EXISTING node
    // (any kind) fails `AlreadyExists`. This is what makes the R11-3 same-path
    // reuse honest — a second write can only succeed once the old file's unlink
    // physically ran, which is exactly when a claim may overwrite the fileless
    // predecessor record. (The symlink refusal above already covers that kind;
    // this is the general case.)
    if self.state.nodes.lock().unwrap().contains_key(&path) {
      return Err(CookieWriteError::clean(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "a cookie already exists at the path (create_new)",
      )));
    }
    self.put(&path, FileKind::File, ino);
    self.state.cookie_writes.lock().unwrap().push(path.clone());
    // The identity of the node the create just made, mirroring the real `fstat`
    // on the descriptor the create returned — a node the fake later replaces at
    // this path gets a different `ino`, so the removal's proof is exercised
    // against the same distinction production faces.
    let identity = RootIdentity::new(self.root_dev, ino.into());
    let file = CookieFile::new(path, identity);
    if let Some(kind) = *self.state.cookie_write_strand.lock().unwrap() {
      return Err(CookieWriteError {
        source: std::io::Error::new(kind, "cookie write left an unresolved file"),
        residue: Some(Box::new(file)),
      });
    }
    Ok(file)
  }

  fn remove_cookie(&self, cookie: &CookieFile) -> Result<CookieRemoval, std::io::Error> {
    let path = cookie.path();
    // Counted BEFORE the hold: a cell racing a close (or a cancelled driver's
    // Drop) against a hung terminal unlink needs to know the unlink is parked in
    // the pool, not still queued.
    self
      .state
      .cookie_remove_dispatches
      .fetch_add(1, Ordering::SeqCst);
    self.park_on(&self.state.cookie_remove_hold);
    // A PERSISTENT per-subtree failure: this mount is still failing, so the node
    // is KEPT (no `remove` below) and the record retained. Checked before the
    // global countdown knob, so a subtree armed here fails whatever the budget.
    if self
      .state
      .cookie_remove_failure_prefixes
      .lock()
      .unwrap()
      .iter()
      .any(|prefix| path.starts_with(prefix))
    {
      return Err(std::io::Error::other(
        "cookie remove refused (failing subtree)",
      ));
    }
    // A transient unlink failure: the tree KEEPS the node (no `remove` below), so
    // the record is retained and a retry can still find and unlink it — never a
    // silently orphaned file. Decrement-if-positive, atomic against concurrent
    // remove jobs on the pool.
    let mut budget = self.state.cookie_remove_failures.load(Ordering::SeqCst);
    loop {
      if budget == 0 {
        break;
      }
      match self.state.cookie_remove_failures.compare_exchange(
        budget,
        budget - 1,
        Ordering::SeqCst,
        Ordering::SeqCst,
      ) {
        Ok(_) => return Err(std::io::Error::other("cookie remove refused")),
        Err(actual) => budget = actual,
      }
    }
    // The production identity proof, mirrored: a node standing at the path that is
    // NOT the one the write created is left alone, whatever the cell put there.
    // The knobs above are checked first because they model a failing unlink, which
    // in production fails before any object is inspected.
    let present = self
      .state
      .nodes
      .lock()
      .unwrap()
      .get(path)
      .map(|node| RootIdentity::new(node.dev, node.ino.into()));
    if present.is_some_and(|found| Some(found) != cookie.identity()) {
      return Ok(CookieRemoval::Displaced);
    }
    // An absent node still runs the removal below (a no-op on the tree): the
    // already-gone case is idempotent success, and taking it through the same
    // confirm hold and log keeps every cell's bracketing of that window intact.
    let gone = present.is_none();
    self.remove(path);
    // The unlink syscall has completed (the node is gone; `files_under` reflects
    // it), but the pool job has NOT yet taken the ledger lock to confirm: park
    // here so a cell can slip a successor sync into the freed path and prove the
    // stale confirm is refused by id (R11-3). `cookie_removes` records only
    // after release, so it and `files_under` bracket the ABA window.
    self.park_on(&self.state.cookie_remove_confirm_hold);
    self
      .state
      .cookie_removes
      .lock()
      .unwrap()
      .push(path.to_path_buf());
    Ok(if gone {
      CookieRemoval::AlreadyGone
    } else {
      CookieRemoval::Unlinked
    })
  }

  fn take_enumerate_anchor(&self, watch: WatchId) -> Option<Self::Anchor> {
    self.state.anchors.lock().unwrap().remove(&watch)
  }

  fn enumerate(&self, watch: WatchId, anchor: Option<Self::Anchor>, path: &Path) -> RawEnumerate {
    self.park_on(&self.state.enumerate_hold);
    self.park_on_path(&self.state.enumerate_exec_hold, path);
    self
      .state
      .enumerates
      .lock()
      .unwrap()
      .push((watch, path.to_path_buf()));
    // Recorded past both holds, so the log runs in EXECUTION order while the
    // anchor each entry carries was decided back at dispatch — the pairing a
    // cell needs to race a stranded listing against a re-add.
    self
      .state
      .enumerate_anchors
      .lock()
      .unwrap()
      .push((watch, anchor));
    if let Some(answer) = self
      .state
      .enumerate_answers
      .lock()
      .unwrap()
      .get_mut(path)
      .and_then(|queue| queue.pop_front())
    {
      return answer;
    }
    // The default honest readdir of the fake tree: direct children of `path`.
    let nodes = self.state.nodes.lock().unwrap();
    if !nodes.get(path).is_some_and(|node| node.kind.is_dir()) {
      return RawEnumerate::Failed(IoClass::NotFound);
    }
    let mut entries = Vec::new();
    for (candidate, node) in nodes.iter() {
      if candidate.parent() == Some(path) {
        let Some(name) = candidate.file_name() else {
          continue;
        };
        entries.push(RawDirEntry {
          name: name.as_encoded_bytes().to_vec(),
          kind: node.kind,
          dev: node.dev,
          ino: node.ino,
          mnt_id: node.mnt_id,
        });
      }
    }
    RawEnumerate::Listed {
      entries,
      complete: true,
    }
  }
}

/// A registry that records nothing — for tests that don't observe lifecycle.
pub(crate) struct NullRegistry;

impl ScopeRegistry for NullRegistry {
  fn scope_live(
    &self,
    _scope: ScopeId,
    _root: &Path,
    _identity: RootIdentity,
    _ancestors: &[RootIdentity],
    _backend: BackendKind,
    _stats: Option<crate::os::BackendStatsHandle>,
  ) {
  }

  fn scope_dead(&self, _scope: ScopeId) {}

  fn final_root_conflict(
    &self,
    _final_root: &Path,
    _identity: RootIdentity,
    _ancestors: &[RootIdentity],
    _reserved: Option<&Path>,
    _exempt: Option<ScopeId>,
  ) -> Option<PathBuf> {
    None
  }
}

/// The recorded transitions: scopes gone live (with their roots and selected
/// backend) and dead.
type Transitions = (Vec<(ScopeId, PathBuf, BackendKind)>, Vec<ScopeId>);

/// A registry that records every transition, for lifecycle assertions.
#[derive(Clone, Default)]
pub(crate) struct RecordingRegistry {
  state: Arc<Mutex<Transitions>>,
}

impl RecordingRegistry {
  pub(crate) fn live(&self) -> Vec<(ScopeId, PathBuf, BackendKind)> {
    self.state.lock().unwrap().0.clone()
  }

  pub(crate) fn dead(&self) -> Vec<ScopeId> {
    self.state.lock().unwrap().1.clone()
  }
}

impl ScopeRegistry for RecordingRegistry {
  fn scope_live(
    &self,
    scope: ScopeId,
    root: &Path,
    _identity: RootIdentity,
    _ancestors: &[RootIdentity],
    backend: BackendKind,
    _stats: Option<crate::os::BackendStatsHandle>,
  ) {
    self
      .state
      .lock()
      .unwrap()
      .0
      .push((scope, root.to_path_buf(), backend));
  }

  fn scope_dead(&self, scope: ScopeId) {
    self.state.lock().unwrap().1.push(scope);
  }

  fn final_root_conflict(
    &self,
    _final_root: &Path,
    _identity: RootIdentity,
    _ancestors: &[RootIdentity],
    _reserved: Option<&Path>,
    _exempt: Option<ScopeId>,
  ) -> Option<PathBuf> {
    None
  }
}

/// A registry that can FREEZE the owner loop inside a `scope_live` call — the
/// commit's registry overwrite, which `commit_replace` runs AFTER the lane swap.
/// A test arms the gate once birth is past, so only the replace's commit parks,
/// letting a test act in the exact window between the swap and the run loop's
/// post-commit cookie call. The gate blocks the owner-loop thread, so the test
/// must run on a multi-worker runtime.
#[derive(Clone, Default)]
pub(crate) struct GatedRegistry {
  hold: Arc<Mutex<Option<HoldGate>>>,
  entered: Arc<AtomicBool>,
}

impl GatedRegistry {
  /// Freezes the NEXT `scope_live` (the replace commit's, called after the lane
  /// swap) until the returned gate is released.
  pub(crate) fn hold_scope_live(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Whether a gated `scope_live` has entered its park — the owner loop is frozen
  /// mid-commit, past the swap.
  pub(crate) fn scope_live_frozen(&self) -> bool {
    self.entered.load(Ordering::SeqCst)
  }
}

impl ScopeRegistry for GatedRegistry {
  fn scope_live(
    &self,
    _scope: ScopeId,
    _root: &Path,
    _identity: RootIdentity,
    _ancestors: &[RootIdentity],
    _backend: BackendKind,
    _stats: Option<crate::os::BackendStatsHandle>,
  ) {
    let gate = self.hold.lock().unwrap().clone();
    if let Some(gate) = gate {
      self.entered.store(true, Ordering::SeqCst);
      let (held, cvar, _) = &*gate;
      let mut parked = held.lock().unwrap();
      while *parked {
        parked = cvar.wait(parked).unwrap();
      }
    }
  }

  fn scope_dead(&self, _scope: ScopeId) {}

  fn final_root_conflict(
    &self,
    _final_root: &Path,
    _identity: RootIdentity,
    _ancestors: &[RootIdentity],
    _reserved: Option<&Path>,
    _exempt: Option<ScopeId>,
  ) -> Option<PathBuf> {
    None
  }
}

// ---------------------------------------------------------------------------
// A bounded, NON-FIFO blocking-pool runtime — the adversarial scheduler the
// per-scope control dispatch must survive.
//
// `tributary-fs` is generic over an arbitrary `RuntimeLite`, whose
// `spawn_blocking_detach` promises NO start-order for detached blocking work
// and may be bounded to a handful of workers. `TokioRuntime`'s pool is large
// and roughly FIFO, so it can never exercise the failure a bounded LIFO pool
// invites: a chain that parks a pool worker to wait on another batch deadlocks
// once every worker parks on a predecessor still queued behind it. This runtime
// delegates EVERYTHING to `TokioRuntime` except detached blocking work, which
// it routes through a process-global pool of a FIXED, small worker count that
// dispatches submissions newest-first (LIFO) and behind a start gate a test
// opens once its batches have accumulated.
// ---------------------------------------------------------------------------

/// The bounded LIFO pool behind [`NonFifoRuntime`]. Workers pull the
/// most-recently submitted job first, and only once the gate is open — so a
/// test can freeze the pool, let a run of same-scope control batches pile up,
/// then release them into the worst-case (successors-before-predecessor) start
/// order.
struct NonFifoPool {
  inner: Mutex<NonFifoInner>,
  cv: Condvar,
}

struct NonFifoInner {
  /// Workers idle until this is set — the accumulate-then-release gate.
  open: bool,
  /// Submitted jobs, popped newest-first (LIFO).
  stack: Vec<Box<dyn FnOnce() + Send>>,
}

impl NonFifoPool {
  fn run_worker(&self) {
    loop {
      let job = {
        let mut inner = self.inner.lock().unwrap();
        loop {
          if inner.open
            && let Some(job) = inner.stack.pop()
          {
            break job;
          }
          inner = self.cv.wait(inner).unwrap();
        }
      };
      // Run OUTSIDE the lock: the job may block (the old in-pool chain parks
      // here in a predecessor's receiver), and it must not hold the pool lock.
      job();
    }
  }
}

/// The one installed pool. `spawn_blocking_detach` is a static method with no
/// receiver, so the pool it feeds lives here; a test installs one before the
/// driver it drives dispatches any blocking work.
static NON_FIFO_POOL: Mutex<Option<Arc<NonFifoPool>>> = Mutex::new(None);

fn submit_to_non_fifo_pool(job: Box<dyn FnOnce() + Send>) {
  let pool = NON_FIFO_POOL
    .lock()
    .unwrap()
    .clone()
    .expect("install_non_fifo_pool before the NonFifoRuntime driver dispatches blocking work");
  pool.inner.lock().unwrap().stack.push(job);
  pool.cv.notify_one();
}

/// A test's handle to the installed [`NonFifoPool`]'s start gate.
pub(crate) struct NonFifoPoolHandle {
  pool: Arc<NonFifoPool>,
}

impl NonFifoPoolHandle {
  /// Freezes the pool: every subsequent submission accumulates undispatched
  /// until [`open_gate`](Self::open_gate).
  pub(crate) fn close_gate(&self) {
    self.pool.inner.lock().unwrap().open = false;
  }

  /// Releases the accumulated jobs into the pool's bounded, newest-first
  /// workers.
  pub(crate) fn open_gate(&self) {
    self.pool.inner.lock().unwrap().open = true;
    self.pool.cv.notify_all();
  }
}

/// Installs a fresh bounded LIFO pool with `workers` worker threads (open), and
/// returns a handle to its gate. The worker threads are detached and outlive
/// the call; the process reaps them at exit (one install per test binary).
pub(crate) fn install_non_fifo_pool(workers: usize) -> NonFifoPoolHandle {
  let pool = Arc::new(NonFifoPool {
    inner: Mutex::new(NonFifoInner {
      open: true,
      stack: Vec::new(),
    }),
    cv: Condvar::new(),
  });
  for _ in 0..workers {
    let pool = Arc::clone(&pool);
    std::thread::spawn(move || pool.run_worker());
  }
  *NON_FIFO_POOL.lock().unwrap() = Some(Arc::clone(&pool));
  NonFifoPoolHandle { pool }
}

/// `TokioRuntime`'s blocking spawner — the source for every associated type and
/// non-blocking method this runtime reuses.
type TokioBlocking = <TokioRuntime as LocalRuntimeLite>::BlockingSpawner;

/// A blocking spawner whose DETACHED path feeds the bounded LIFO
/// [`NonFifoPool`]; everything else mirrors Tokio's (the driver only ever
/// dispatches control/spawn/enumerate work through `spawn_blocking_detach`).
#[derive(Clone, Copy)]
pub(crate) struct NonFifoBlockingSpawner;

impl Yielder for NonFifoBlockingSpawner {
  fn yield_now() -> impl Future<Output = ()> + Send {
    <TokioBlocking as Yielder>::yield_now()
  }
  fn yield_now_local() -> impl Future<Output = ()> {
    <TokioBlocking as Yielder>::yield_now_local()
  }
}

impl AsyncBlockingSpawner for NonFifoBlockingSpawner {
  type JoinHandle<R>
    = <TokioBlocking as AsyncBlockingSpawner>::JoinHandle<R>
  where
    R: Send + 'static;

  fn spawn_blocking<F, R>(f: F) -> Self::JoinHandle<R>
  where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
  {
    <TokioBlocking as AsyncBlockingSpawner>::spawn_blocking(f)
  }

  fn spawn_blocking_detach<F, R>(f: F)
  where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
  {
    submit_to_non_fifo_pool(Box::new(move || {
      let _ = f();
    }));
  }
}

/// A `RuntimeLite` identical to [`TokioRuntime`] except that detached blocking
/// work runs on the bounded, LIFO [`NonFifoPool`]. Used to drive the real
/// driver loop under a pool that gives no FIFO start-order guarantee.
#[derive(Clone, Copy)]
pub(crate) struct NonFifoRuntime;

impl LocalRuntimeLite for NonFifoRuntime {
  type LocalSpawner = <TokioRuntime as LocalRuntimeLite>::LocalSpawner;
  type BlockingSpawner = NonFifoBlockingSpawner;
  type Instant = <TokioRuntime as LocalRuntimeLite>::Instant;
  type LocalInterval = <TokioRuntime as LocalRuntimeLite>::LocalInterval;
  type LocalSleep = <TokioRuntime as LocalRuntimeLite>::LocalSleep;
  type LocalDelay<F>
    = <TokioRuntime as LocalRuntimeLite>::LocalDelay<F>
  where
    F: Future;
  type LocalTimeout<F>
    = <TokioRuntime as LocalRuntimeLite>::LocalTimeout<F>
  where
    F: Future;

  fn new() -> Self {
    Self
  }
  fn name() -> &'static str {
    "non-fifo"
  }
  fn fqname() -> &'static str {
    "tributary_fs::driver::testing::NonFifoRuntime"
  }
  fn block_on<F: Future>(f: F) -> F::Output {
    TokioRuntime::block_on(f)
  }
  fn interval_local(period: Duration) -> Self::LocalInterval {
    TokioRuntime::interval_local(period)
  }
  fn interval_local_at(start: Self::Instant, period: Duration) -> Self::LocalInterval {
    TokioRuntime::interval_local_at(start, period)
  }
  fn sleep_local(duration: Duration) -> Self::LocalSleep {
    TokioRuntime::sleep_local(duration)
  }
  fn sleep_local_until(instant: Self::Instant) -> Self::LocalSleep {
    TokioRuntime::sleep_local_until(instant)
  }
  fn delay_local<F>(duration: Duration, fut: F) -> Self::LocalDelay<F>
  where
    F: Future,
  {
    TokioRuntime::delay_local(duration, fut)
  }
  fn delay_local_at<F>(deadline: Self::Instant, fut: F) -> Self::LocalDelay<F>
  where
    F: Future,
  {
    TokioRuntime::delay_local_at(deadline, fut)
  }
  fn timeout_local<F>(duration: Duration, fut: F) -> Self::LocalTimeout<F>
  where
    F: Future,
  {
    TokioRuntime::timeout_local(duration, fut)
  }
  fn timeout_local_at<F>(deadline: Self::Instant, fut: F) -> Self::LocalTimeout<F>
  where
    F: Future,
  {
    TokioRuntime::timeout_local_at(deadline, fut)
  }
}

impl RuntimeLite for NonFifoRuntime {
  type Spawner = <TokioRuntime as RuntimeLite>::Spawner;
  type AfterSpawner = <TokioRuntime as RuntimeLite>::AfterSpawner;
  type Interval = <TokioRuntime as RuntimeLite>::Interval;
  type Sleep = <TokioRuntime as RuntimeLite>::Sleep;
  type Delay<F>
    = <TokioRuntime as RuntimeLite>::Delay<F>
  where
    F: Future + Send;
  type Timeout<F>
    = <TokioRuntime as RuntimeLite>::Timeout<F>
  where
    F: Future + Send;

  fn yield_now() -> impl Future<Output = ()> + Send {
    TokioRuntime::yield_now()
  }
  fn interval(period: Duration) -> Self::Interval {
    TokioRuntime::interval(period)
  }
  fn interval_at(start: Self::Instant, period: Duration) -> Self::Interval {
    TokioRuntime::interval_at(start, period)
  }
  fn sleep(duration: Duration) -> Self::Sleep {
    TokioRuntime::sleep(duration)
  }
  fn sleep_until(instant: Self::Instant) -> Self::Sleep {
    TokioRuntime::sleep_until(instant)
  }
  fn delay<F>(duration: Duration, fut: F) -> Self::Delay<F>
  where
    F: Future + Send,
  {
    TokioRuntime::delay(duration, fut)
  }
  fn delay_at<F>(deadline: Self::Instant, fut: F) -> Self::Delay<F>
  where
    F: Future + Send,
  {
    TokioRuntime::delay_at(deadline, fut)
  }
  fn timeout<F>(duration: Duration, fut: F) -> Self::Timeout<F>
  where
    F: Future + Send,
  {
    TokioRuntime::timeout(duration, fut)
  }
  fn timeout_at<F>(deadline: Self::Instant, fut: F) -> Self::Timeout<F>
  where
    F: Future + Send,
  {
    TokioRuntime::timeout_at(deadline, fut)
  }
}
