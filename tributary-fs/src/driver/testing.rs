//! The hermetic fake platform the driver and watcher test suites share: fake
//! sources are real transport queues driven through the REAL forwarding
//! protocol, probes consult an in-memory tree — the production loop runs
//! unmodified.

use std::{
  collections::HashMap,
  num::NonZeroU64,
  path::{Path, PathBuf},
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
};

use tributary_proto::{FileKind, ScopeId};

use super::{FsOps, ScopeRegistry, SourceControl, SpawnedSource};
use crate::{
  core::{ProbeOutcome, RootMeta},
  os::{RawOsEvent, SourceConfig, SourceError, SourceMessage},
};

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
  sources: Mutex<HashMap<PathBuf, FakeSource>>,
  shutdowns: AtomicUsize,
  spawns: AtomicUsize,
  /// Mount-table refreshes served, plus the configured answer (`None` = an
  /// authoritative empty table).
  refreshes: AtomicUsize,
  refresh_answer: Mutex<Option<(Vec<PathBuf>, bool)>>,
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
}

pub(crate) struct FakeHandle {
  state: Arc<FakeState>,
}

impl SourceControl for FakeHandle {
  fn shutdown(self) {
    self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
  }
}

impl FsOps for FakeFs {
  type Handle = FakeHandle;

  fn spawn_source(&self, config: SourceConfig) -> Result<SpawnedSource<Self::Handle>, SourceError> {
    let root = config.roots.first().cloned().ok_or(SourceError::NoRoots)?;
    if !self.state.nodes.lock().unwrap().contains_key(&root) {
      return Err(SourceError::RootUnavailable {
        root,
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
      });
    }
    let (sender, receiver) = async_channel::unbounded();
    let transport = Arc::new(crate::os::fsevent::TransportState::new(
      config.channel_capacity.get(),
    ));
    self
      .state
      .sources
      .lock()
      .unwrap()
      .insert(root.clone(), FakeSource { sender, transport });
    self.state.spawns.fetch_add(1, Ordering::SeqCst);
    Ok(SpawnedSource {
      handle: FakeHandle {
        state: Arc::clone(&self.state),
      },
      receiver,
      meta: RootMeta {
        root,
        root_dev: self.root_dev,
        mounts: Vec::new(),
        mounts_authoritative: true,
      },
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
  fn scope_live(&self, _scope: ScopeId, _root: &Path) {}

  fn scope_dead(&self, _scope: ScopeId) {}
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
  fn scope_live(&self, scope: ScopeId, root: &Path) {
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
}
