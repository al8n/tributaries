//! The hermetic fake platform the driver and watcher test suites share: fake
//! sources are real transport queues driven through the REAL forwarding
//! protocol, probes consult an in-memory tree — the production loop runs
//! unmodified.

use std::{
  collections::HashMap,
  num::NonZeroU64,
  path::{Path, PathBuf},
  sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
};

use tributary_proto::{FileKind, ScopeId};

use super::{FsOps, ScopeRegistry, SourceControl, SpawnedSource};
use crate::{
  core::ProbeOutcome,
  os::{RawOsEvent, RootIdentity, RootMeta, SourceConfig, SourceError, SourceMessage},
};

/// A parked-work gate: the held flag plus its wakeup.
type HoldGate = Arc<(Mutex<bool>, Condvar)>;

/// One fake filesystem object.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FakeNode {
  pub(crate) kind: FileKind,
  pub(crate) ino: u64,
  pub(crate) dev: u64,
}

/// One spawned fake source: its queue's send end plus the REAL transport
/// state, so test injections run the production forwarding protocol.
struct FakeSource {
  sender: async_channel::Sender<SourceMessage>,
  transport: Arc<crate::os::fsevent::TransportState>,
}

#[derive(Default)]
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
  /// Mount prefixes the next spawn seeds its `RootMeta` with.
  spawn_mounts: Mutex<Vec<PathBuf>>,
  /// Requested-root → final-root remaps, mirroring the backend's own
  /// re-canonicalization (a symlink retargeted between reservation and
  /// spawn): the spawned `RootMeta` carries the FINAL root.
  spawn_remaps: Mutex<HashMap<PathBuf, PathBuf>>,
  /// The spawn contract's observable order: `meta_sealed` must strictly
  /// precede `stream_live`, mirroring the real backend's pre-start barrier —
  /// a fake that seeded metadata after its stream went live would let the
  /// hermetic suites pass against an ordering the platform forbids.
  spawn_order: Mutex<Vec<&'static str>>,
  /// When set, `spawn_source` parks on the blocking pool until the gate
  /// releases — the close-versus-in-flight-spawn cells need a spawn that is
  /// dispatched but not yet returned.
  spawn_hold: Mutex<Option<HoldGate>>,
  /// When set, `SourceControl::shutdown` parks until the gate releases — the
  /// close-versus-wedged-teardown cell needs a teardown whose handle has
  /// already moved into the call, where no Drop backstop can exist.
  teardown_hold: Mutex<Option<HoldGate>>,
}

/// A fake platform: sources are channels the test injects into through the
/// real transport protocol, probes consult an in-memory map.
#[derive(Clone, Default)]
pub(crate) struct FakeFs {
  state: Arc<FakeState>,
  root_dev: u64,
}

impl FakeFs {
  pub(crate) fn new(root_dev: u64) -> Self {
    Self {
      state: Arc::new(FakeState::default()),
      root_dev,
    }
  }

  pub(crate) fn put(&self, path: impl AsRef<Path>, kind: FileKind, ino: u64) {
    self.state.nodes.lock().unwrap().insert(
      path.as_ref().to_path_buf(),
      FakeNode {
        kind,
        ino,
        dev: self.root_dev,
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
    Arc<crate::os::fsevent::TransportState>,
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
  pub(crate) fn send_batch(&self, root: impl AsRef<Path>, events: Vec<RawOsEvent>) {
    let (sender, transport) = self.source_of(root);
    crate::os::fsevent::forward_batch(&transport, events, false, |msg| {
      sender.try_send(msg).is_ok()
    });
  }

  /// Injects a decode-loss callback (every entry undecodable): the loss rides
  /// the queue as an in-order `Overflow`.
  pub(crate) fn send_lossy(&self, root: impl AsRef<Path>) {
    let (sender, transport) = self.source_of(root);
    crate::os::fsevent::forward_batch(&transport, Vec::new(), true, |msg| {
      sender.try_send(msg).is_ok()
    });
  }

  /// Injects the stream's terminal `Fatal`.
  pub(crate) fn send_fatal(&self, root: impl AsRef<Path>) {
    let (sender, transport) = self.source_of(root);
    crate::os::fsevent::signal_fatal_once(&transport, SourceError::CallbackPanic, |msg| {
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

  /// The recorded spawn-contract order (`meta_sealed` / `stream_live` per
  /// spawn, in call order).
  pub(crate) fn spawn_order(&self) -> Vec<&'static str> {
    self.state.spawn_order.lock().unwrap().clone()
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
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new()));
    *self.state.spawn_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }

  /// Holds every subsequent `shutdown` on the blocking pool until the
  /// returned gate is released.
  pub(crate) fn hold_teardowns(&self) -> HoldRelease {
    let gate: HoldGate = Arc::new((Mutex::new(true), Condvar::new()));
    *self.state.teardown_hold.lock().unwrap() = Some(Arc::clone(&gate));
    HoldRelease { gate }
  }
}

/// Releases work parked by [`FakeFs::hold_spawns`] / [`FakeFs::hold_teardowns`].
pub(crate) struct HoldRelease {
  gate: HoldGate,
}

impl HoldRelease {
  pub(crate) fn release(&self) {
    let (held, cvar) = &*self.gate;
    *held.lock().unwrap() = false;
    cvar.notify_all();
  }
}

pub(crate) struct FakeHandle {
  state: Arc<FakeState>,
  shut: bool,
}

impl SourceControl for FakeHandle {
  fn shutdown(mut self) {
    // The wedge gate parks INSIDE the call, after the handle moved in —
    // exactly the phase where no Drop backstop can exist. Drop itself never
    // waits, or a failing test would hang its own teardown.
    let gate = self.state.teardown_hold.lock().unwrap().clone();
    if let Some(gate) = gate {
      let (held, cvar) = &*gate;
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
    // The hold gate parks the whole spawn — before any outcome is decided —
    // so a test can race close() against a spawn that is dispatched but not
    // yet returned.
    let hold = self.state.spawn_hold.lock().unwrap().clone();
    if let Some(gate) = hold {
      let (held, cvar) = &*gate;
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
    let identity = {
      let nodes = self.state.nodes.lock().unwrap();
      nodes
        .get(&root)
        .map(|node| RootIdentity::new(node.dev, node.ino))
        .unwrap_or_else(|| {
          RootIdentity::new(
            u64::MAX,
            self.state.spawns.load(Ordering::SeqCst) as u64 + 1,
          )
        })
    };
    let ancestors = {
      let nodes = self.state.nodes.lock().unwrap();
      root
        .ancestors()
        .skip(1)
        .filter_map(|ancestor| nodes.get(ancestor))
        .map(|node| RootIdentity::new(node.dev, node.ino))
        .collect()
    };
    let meta = RootMeta {
      root: root.clone(),
      root_dev: self.root_dev,
      mounts: self.state.spawn_mounts.lock().unwrap().clone(),
      identity,
      ancestors,
    };
    self.state.spawn_order.lock().unwrap().push("meta_sealed");
    let (sender, receiver) = async_channel::unbounded();
    let transport = Arc::new(crate::os::fsevent::TransportState::new(
      config.channel_capacity.get(),
    ));
    self
      .state
      .sources
      .lock()
      .unwrap()
      .entry(root)
      .or_default()
      .push(FakeSource { sender, transport });
    self.state.spawn_order.lock().unwrap().push("stream_live");
    self.state.spawns.fetch_add(1, Ordering::SeqCst);
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

  fn refresh_mounts(&self, _root: &Path) -> (Vec<PathBuf>, bool) {
    self.state.refreshes.fetch_add(1, Ordering::SeqCst);
    self
      .state
      .refresh_answer
      .lock()
      .unwrap()
      .clone()
      .unwrap_or((Vec::new(), true))
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
  ) {
  }

  fn scope_dead(&self, _scope: ScopeId) {}

  fn final_root_conflict(
    &self,
    _final_root: &Path,
    _identity: RootIdentity,
    _ancestors: &[RootIdentity],
    _reserved: Option<&Path>,
  ) -> Option<PathBuf> {
    None
  }
}

/// The recorded transitions: scopes gone live (with their roots) and dead.
type Transitions = (Vec<(ScopeId, PathBuf)>, Vec<ScopeId>);

/// A registry that records every transition, for lifecycle assertions.
#[derive(Clone, Default)]
pub(crate) struct RecordingRegistry {
  state: Arc<Mutex<Transitions>>,
}

impl RecordingRegistry {
  pub(crate) fn live(&self) -> Vec<(ScopeId, PathBuf)> {
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
  ) {
    self
      .state
      .lock()
      .unwrap()
      .0
      .push((scope, root.to_path_buf()));
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
  ) -> Option<PathBuf> {
    None
  }
}
