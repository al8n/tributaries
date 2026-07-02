use super::*;
use std::{
  num::{NonZeroU64, NonZeroUsize},
  sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
  },
  time::Duration,
};

use agnostic_lite::tokio::TokioRuntime;
use tributary_proto::{FileKind, Location, Segment};

use crate::os::{FsEventFlags, RawOsEvent};

/// One fake filesystem object.
#[derive(Debug, Clone, Copy)]
struct FakeNode {
  kind: FileKind,
  ino: u64,
  dev: u64,
}

#[derive(Default)]
struct FakeState {
  nodes: Mutex<std::collections::HashMap<PathBuf, FakeNode>>,
  /// Injection ends for spawned sources, keyed by root.
  taps: Mutex<std::collections::HashMap<PathBuf, async_channel::Sender<SourceMessage>>>,
  shutdowns: AtomicUsize,
}

/// A fake platform: sources are channel pairs the test injects into, probes
/// consult an in-memory map — the driver loop runs unmodified.
#[derive(Clone, Default)]
struct FakeFs {
  state: Arc<FakeState>,
  root_dev: u64,
}

impl FakeFs {
  fn new(root_dev: u64) -> Self {
    Self {
      state: Arc::new(FakeState::default()),
      root_dev,
    }
  }

  fn put(&self, path: &str, kind: FileKind, ino: u64) {
    self.state.nodes.lock().unwrap().insert(
      PathBuf::from(path),
      FakeNode {
        kind,
        ino,
        dev: self.root_dev,
      },
    );
  }

  fn remove(&self, path: &str) {
    self
      .state
      .nodes
      .lock()
      .unwrap()
      .remove(&PathBuf::from(path));
  }

  fn tap(&self, root: &str) -> async_channel::Sender<SourceMessage> {
    self
      .state
      .taps
      .lock()
      .unwrap()
      .get(&PathBuf::from(root))
      .expect("a source was spawned for the root")
      .clone()
  }

  fn shutdowns(&self) -> usize {
    self.state.shutdowns.load(Ordering::SeqCst)
  }
}

struct FakeHandle {
  overflow: Arc<AtomicBool>,
  shutdowns: Arc<FakeState>,
}

impl SourceControl for FakeHandle {
  fn take_overflow(&self) -> bool {
    self.overflow.swap(false, Ordering::AcqRel)
  }

  fn shutdown(self) {
    self.shutdowns.shutdowns.fetch_add(1, Ordering::SeqCst);
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
    let (tx, rx) = async_channel::bounded(config.channel_capacity.get());
    self.state.taps.lock().unwrap().insert(root.clone(), tx);
    Ok(SpawnedSource {
      handle: FakeHandle {
        overflow: Arc::new(AtomicBool::new(false)),
        shutdowns: Arc::clone(&self.state),
      },
      receiver: rx,
      meta: RootMeta {
        root,
        root_dev: self.root_dev,
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
}

struct Rig {
  fs: FakeFs,
  commands: async_channel::Sender<Command>,
  events: async_channel::Receiver<(ScopeId, Change)>,
}

fn config() -> DriverConfig {
  DriverConfig {
    latency: Duration::from_millis(10),
    move_window: Duration::from_millis(100),
    os_batch_capacity: NonZeroUsize::new(8).unwrap(),
    exclusions: Vec::new(),
  }
}

fn rig_with_capacity(event_capacity: usize) -> Rig {
  let fs = FakeFs::new(1);
  fs.put("/r", FileKind::Dir, 1);
  let (cmd_tx, cmd_rx) = async_channel::bounded(16);
  let (ev_tx, ev_rx) = async_channel::bounded(event_capacity);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config(),
    fs.clone(),
    cmd_rx,
    ev_tx,
  ));
  Rig {
    fs,
    commands: cmd_tx,
    events: ev_rx,
  }
}

async fn watch(rig: &Rig, root: &str) -> ScopeId {
  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from(root),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  on_reply.await.unwrap().expect("watch succeeds")
}

fn ev(path: &str, flags: FsEventFlags, event_id: u64, file_id: u64) -> RawOsEvent {
  RawOsEvent {
    path: PathBuf::from(path),
    flags,
    event_id,
    file_id: NonZeroU64::new(file_id),
  }
}

fn renamed() -> FsEventFlags {
  FsEventFlags::new(FsEventFlags::ITEM_RENAMED.bits() | FsEventFlags::ITEM_IS_FILE.bits())
}

async fn next_event(rig: &Rig) -> (ScopeId, Change) {
  tokio::time::timeout(Duration::from_secs(5), rig.events.recv())
    .await
    .expect("an event arrives")
    .expect("the stream is open")
}

fn loc(parts: &[&str]) -> Location {
  Location::from_segments(parts.iter().map(|p| Segment::new(*p)))
}

#[tokio::test(start_paused = true)]
async fn watch_spawns_a_stream_and_events_flow() {
  let rig = rig_with_capacity(64);
  let scope = watch(&rig, "/r").await;

  rig
    .fs
    .tap("/r")
    .send(SourceMessage::Batch(vec![ev(
      "/r/a/new.txt",
      FsEventFlags::new(FsEventFlags::ITEM_CREATED.bits() | FsEventFlags::ITEM_IS_FILE.bits()),
      1,
      10,
    )]))
    .await
    .unwrap();

  let (got_scope, change) = next_event(&rig).await;
  assert_eq!(got_scope, scope);
  assert!(change.kind().is_created());
  assert_eq!(change.location(), &loc(&["a", "new.txt"]));
}

#[tokio::test(start_paused = true)]
async fn cross_batch_rename_pairs_through_probes() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  let tap = rig.fs.tap("/r");

  // Source half: the path is already gone.
  rig.fs.remove("/r/a/old");
  tap
    .send(SourceMessage::Batch(vec![ev(
      "/r/a/old",
      renamed(),
      10,
      42,
    )]))
    .await
    .unwrap();
  // Destination half in a later batch: the path exists.
  rig.fs.put("/r/b/new", FileKind::File, 42);
  tap
    .send(SourceMessage::Batch(vec![ev(
      "/r/b/new",
      renamed(),
      11,
      42,
    )]))
    .await
    .unwrap();

  let (_, change) = next_event(&rig).await;
  assert_eq!(change.kind().moved_from(), Some(&loc(&["a", "old"])));
  assert_eq!(change.location(), &loc(&["b", "new"]));
}

#[tokio::test(start_paused = true)]
async fn unpaired_source_half_expires_to_removed() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  rig.fs.remove("/r/a/left");
  rig
    .fs
    .tap("/r")
    .send(SourceMessage::Batch(vec![ev(
      "/r/a/left",
      renamed(),
      10,
      7,
    )]))
    .await
    .unwrap();

  // Paused time auto-advances through the pairing window to the timer.
  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_removed());
  assert_eq!(change.location(), &loc(&["a", "left"]));
}

#[tokio::test(start_paused = true)]
async fn overflow_message_becomes_one_epoch_bumped_rescan() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  let tap = rig.fs.tap("/r");

  tap
    .send(SourceMessage::Batch(vec![ev(
      "/r/x",
      FsEventFlags::ITEM_CREATED,
      1,
      3,
    )]))
    .await
    .unwrap();
  let (_, first) = next_event(&rig).await;

  tap.send(SourceMessage::Overflow).await.unwrap();
  let (_, rescan) = next_event(&rig).await;
  assert!(rescan.kind().is_rescan());
  assert!(rescan.epoch() > first.epoch());
}

#[tokio::test(start_paused = true)]
async fn lagged_consumer_gets_the_dominating_rescan() {
  let rig = rig_with_capacity(1);
  let _scope = watch(&rig, "/r").await;
  let tap = rig.fs.tap("/r");

  for (id, name) in [(1u64, "/r/a"), (2, "/r/b"), (3, "/r/c")] {
    tap
      .send(SourceMessage::Batch(vec![ev(
        name,
        FsEventFlags::ITEM_CREATED,
        id,
        id,
      )]))
      .await
      .unwrap();
  }
  // Let the driver churn: the first change fills the capacity-1 channel, the
  // rest refuse and park a dominating Rescan.
  tokio::time::sleep(Duration::from_millis(500)).await;

  let (_, first) = next_event(&rig).await;
  assert!(first.kind().is_created());
  let (_, second) = next_event(&rig).await;
  assert!(
    second.kind().is_rescan(),
    "everything dropped while lagged is covered by the parked Rescan"
  );
  assert!(second.epoch() > first.epoch());
}

#[tokio::test(start_paused = true)]
async fn fatal_source_rescans_and_tears_down() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  rig
    .fs
    .tap("/r")
    .send(SourceMessage::Fatal(SourceError::CallbackPanic))
    .await
    .unwrap();

  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_rescan());
  tokio::time::sleep(Duration::from_millis(100)).await;
  assert_eq!(rig.fs.shutdowns(), 1, "the dead stream is torn down");
}

#[tokio::test(start_paused = true)]
async fn close_tears_down_every_stream_and_ends_the_event_stream() {
  let rig = rig_with_capacity(64);
  let fs = rig.fs.clone();
  fs.put("/s", FileKind::Dir, 2);
  let _one = watch(&rig, "/r").await;
  let _two = watch(&rig, "/s").await;

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig.commands.send(Command::Close { reply }).await.unwrap();
  on_reply.await.unwrap();
  assert_eq!(fs.shutdowns(), 2, "every stream quiesced");
  assert!(
    rig.events.recv().await.is_err(),
    "the event stream ends after close"
  );
}

#[tokio::test(start_paused = true)]
async fn unwatch_stops_one_root_and_replies() {
  let rig = rig_with_capacity(64);
  let scope = watch(&rig, "/r").await;

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Unwatch { scope, reply })
    .await
    .unwrap();
  assert!(on_reply.await.unwrap(), "the scope existed");
  assert_eq!(rig.fs.shutdowns(), 1);
}

#[tokio::test(start_paused = true)]
async fn watch_of_a_missing_root_fails_typed() {
  let rig = rig_with_capacity(64);
  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/absent"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  let err = on_reply.await.unwrap().unwrap_err();
  assert!(matches!(err, SourceError::RootUnavailable { .. }));
}
