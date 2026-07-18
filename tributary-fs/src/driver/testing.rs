//! The hermetic fake platform the driver and watcher test suites share: fake
//! sources are real transport queues driven through the REAL forwarding
//! protocol, probes consult an in-memory tree — the production loop runs
//! unmodified.

use std::{
  collections::{BTreeMap, HashMap},
  num::NonZeroU64,
  path::{Path, PathBuf},
  sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
  },
};

use tributary_proto::{FileKind, IoClass, ScopeId, Segment, WatchId};

use super::{FsOps, ScopeRegistry, SourceControl, SpawnedSource};
use crate::{
  core::{ExpectedObject, MountRefresh, ProbeOutcome, RawDirEntry, RawEnumerate, RootLiveness},
  driver::ControlRequest,
  os::{
    BackendKind, RawOsEvent, RootIdentity, RootMeta, SourceConfig, SourceError, SourceEvent,
    SourceMessage,
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
  /// Per-directory disarms executed.
  disarms: Mutex<Vec<WatchId>>,
  /// Enumerates executed, in call order.
  enumerates: Mutex<Vec<(WatchId, PathBuf)>>,
  /// Paths whose next arm fails with the given error (persistent).
  watch_failures: Mutex<HashMap<PathBuf, tributary_proto::WatchError>>,
  /// Paths whose arms resolve `Aliased` (the EEXIST fan-out outcome).
  watch_aliases: Mutex<HashMap<PathBuf, i32>>,
  /// Injected listings served before the default readdir, per path.
  enumerate_answers: Mutex<HashMap<PathBuf, std::collections::VecDeque<RawEnumerate>>>,
  /// When set, `enumerate` parks until the gate releases (the
  /// close-versus-in-flight-enumerate cell).
  enumerate_hold: Mutex<Option<HoldGate>>,
  /// When set, `add_watch` and a discovery/re-arm `batch_control` park until
  /// the gate releases (the close-versus-in-flight-arm and
  /// stale-batch-across-replace cells).
  arm_hold: Mutex<Option<HoldGate>>,
  /// When set, `preflight_arm` (a descending replace's pre-arm on the new
  /// transport) parks until the gate releases — distinct from `arm_hold` so a
  /// test can freeze in-flight discovery batches while letting the commit's
  /// pre-arm proceed.
  prearm_hold: Mutex<Option<HoldGate>>,
  /// The synthetic kernel-watch-descriptor sequence.
  wd_seq: AtomicUsize,
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
      spawn_backend: Mutex::new(BackendKind::FsEvents),
      arms: Mutex::default(),
      scope_generation: Mutex::default(),
      cookie_writes: Mutex::default(),
      cookie_removes: Mutex::default(),
      cookie_write_failure: Mutex::default(),
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
      disarms: Mutex::default(),
      enumerates: Mutex::default(),
      watch_failures: Mutex::default(),
      watch_aliases: Mutex::default(),
      enumerate_answers: Mutex::default(),
      enumerate_hold: Mutex::default(),
      arm_hold: Mutex::default(),
      prearm_hold: Mutex::default(),
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
  /// the queue as an in-order `Overflow`.
  pub(crate) fn send_lossy(&self, root: impl AsRef<Path>) {
    let (sender, transport) = self.source_of(root);
    crate::os::transport::forward_batch(&transport, Vec::new(), true, |msg| {
      sender.try_send(msg).is_ok()
    });
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

  /// Holds every subsequent arm (`add_watch` and discovery/re-arm
  /// `batch_control`) until released — the close-versus-in-flight-arm and
  /// stale-batch-across-replace cells.
  pub(crate) fn hold_arms(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new(), AtomicUsize::new(0)));
    *self.state.arm_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
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
    if let Some(wd) = self.state.watch_aliases.lock().unwrap().get(path) {
      return WatchOutcome::Aliased(*wd);
    }
    let wd = self.state.wd_seq.fetch_add(1, Ordering::SeqCst) as i32 + 1;
    WatchOutcome::Installed(wd)
  }

  /// Per-directory disarms executed so far.
  pub(crate) fn disarms(&self) -> Vec<WatchId> {
    self.state.disarms.lock().unwrap().clone()
  }

  /// Enumerates executed so far.
  pub(crate) fn enumerates(&self) -> Vec<(WatchId, PathBuf)> {
    self.state.enumerates.lock().unwrap().clone()
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
pub(crate) struct HoldRelease {
  gate: HoldGate,
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

  fn shutdown(mut self) {
    // The wedge gate parks INSIDE the call, after the handle moved in —
    // exactly the phase where no Drop backstop can exist. Drop itself never
    // waits, or a failing test would hang its own teardown.
    let gate = self.state.teardown_hold.lock().unwrap().clone();
    if let Some(gate) = gate {
      let (held, cvar, _) = &*gate;
      let mut parked = held.lock().unwrap();
      while *parked {
        parked = cvar.wait(parked).unwrap();
      }
    }
    self.shut = true;
    self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
  }
}

impl Drop for FakeHandle {
  fn drop(&mut self) {
    // The real handle's Drop backstop, mirrored: an owner that never called
    // shutdown still reclaims the stream.
    if !self.shut {
      self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
  }
}

impl FsOps for FakeFs {
  type Handle = FakeHandle;

  fn spawn_source(&self, config: SourceConfig) -> Result<SpawnedSource<Self::Handle>, SourceError> {
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
      return Err(SourceError::RootUnavailable {
        root: requested,
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
      });
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
      return Err(SourceError::NotADirectory { root });
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
      .push(FakeSource { sender, transport });
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
      self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
      return Err(err);
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

  // The batch entry the driver calls, carrying the transport GENERATION the
  // batch was emitted for. The parking happens ONCE here (the hold point a
  // test uses to freeze a batch across a replace), then the generation is
  // re-read: a batch whose generation no longer matches the attached
  // transport is a leftover of a replaced stream and refuses every arm,
  // exactly as the real source does — landing nothing on the new transport.
  fn batch_control(
    &self,
    scope: ScopeId,
    generation: u64,
    requests: Vec<ControlRequest>,
  ) -> Vec<(WatchId, WatchOutcome)> {
    self.park_on(&self.state.arm_hold);
    let attached = self
      .state
      .scope_generation
      .lock()
      .unwrap()
      .get(&scope)
      .copied();
    if attached != Some(generation) {
      return requests
        .into_iter()
        .filter_map(|request| match request {
          ControlRequest::Arm { watch, path, .. } => {
            self
              .state
              .stale_arms
              .lock()
              .unwrap()
              .push((watch, path.to_path_buf()));
            Some((
              watch,
              WatchOutcome::Failed(tributary_proto::WatchError::Gone),
            ))
          }
          ControlRequest::Disarm { .. } => None,
        })
        .collect();
    }
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
          self.arm_one(scope, watch, parent, path.as_path(), &name, expected),
        )),
        ControlRequest::Disarm { watch } => self.state.disarms.lock().unwrap().push(watch),
      }
    }
    outcomes
  }

  fn remove_watch(&self, _scope: ScopeId, watch: WatchId) {
    self.state.disarms.lock().unwrap().push(watch);
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
    self.park_on(&self.state.prearm_hold);
    self.arm_one(scope, watch, watch, path, name, expected)
  }

  fn write_cookie(&self, root: &Path, dir: &Path, name: &str) -> Result<PathBuf, std::io::Error> {
    // The dispatch is counted BEFORE the hold: a cell that must race a scope
    // retirement (or an abandoned reply) against a write in flight needs to know
    // the write is parked in the pool, not still queued behind its settle fence.
    self.state.cookie_dispatches.fetch_add(1, Ordering::SeqCst);
    self.park_on(&self.state.cookie_write_hold);
    if let Some(kind) = *self.state.cookie_write_failure.lock().unwrap() {
      return Err(std::io::Error::new(kind, "cookie write refused"));
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
        return Err(std::io::Error::new(
          std::io::ErrorKind::NotFound,
          "the cookie directory is gone",
        ));
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
        return Err(std::io::Error::other(
          "the cookie directory resolves outside the watched root",
        ));
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
        return Err(std::io::Error::new(
          std::io::ErrorKind::AlreadyExists,
          "refusing to follow a symlink at the cookie path",
        ));
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
      return Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "a cookie already exists at the path (create_new)",
      ));
    }
    self.put(&path, FileKind::File, ino);
    self.state.cookie_writes.lock().unwrap().push(path.clone());
    Ok(path)
  }

  fn remove_cookie(&self, path: &Path) -> Result<(), std::io::Error> {
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
    Ok(())
  }

  fn enumerate(&self, watch: WatchId, path: &Path) -> RawEnumerate {
    self.park_on(&self.state.enumerate_hold);
    self
      .state
      .enumerates
      .lock()
      .unwrap()
      .push((watch, path.to_path_buf()));
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
