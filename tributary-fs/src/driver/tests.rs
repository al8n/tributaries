use super::*;
use std::{
  num::{NonZeroU64, NonZeroUsize},
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
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
  /// Data injection ends for spawned sources, keyed by root.
  taps: Mutex<std::collections::HashMap<PathBuf, async_channel::Sender<SourceMessage>>>,
  /// Control (Overflow/Fatal) injection ends, keyed by root.
  controls: Mutex<std::collections::HashMap<PathBuf, async_channel::Sender<SourceMessage>>>,
  /// Overflow acknowledgements per root, so tests can assert the dedup
  /// re-arm protocol runs.
  acks: Mutex<std::collections::HashMap<PathBuf, Arc<AtomicUsize>>>,
  shutdowns: AtomicUsize,
  /// Mount-table refreshes served, plus the configured answer (`None` = an
  /// authoritative empty table).
  refreshes: AtomicUsize,
  refresh_answer: Mutex<Option<(Vec<PathBuf>, bool)>>,
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

  fn refreshes(&self) -> usize {
    self.state.refreshes.load(Ordering::SeqCst)
  }

  /// The control-channel injection end of `root`'s source.
  fn control_tap(&self, root: &str) -> async_channel::Sender<SourceMessage> {
    self
      .state
      .controls
      .lock()
      .unwrap()
      .get(&PathBuf::from(root))
      .expect("a source was spawned for the root")
      .clone()
  }

  /// How many processed Overflows the driver acknowledged for `root`.
  fn overflow_acks(&self, root: &str) -> usize {
    self
      .state
      .acks
      .lock()
      .unwrap()
      .get(&PathBuf::from(root))
      .expect("a source was spawned for the root")
      .load(Ordering::SeqCst)
  }

  /// Drops both injection ends of `root`'s source, disconnecting it.
  fn disconnect(&self, root: &str) {
    self.state.taps.lock().unwrap().remove(&PathBuf::from(root));
    self
      .state
      .controls
      .lock()
      .unwrap()
      .remove(&PathBuf::from(root));
  }
}

struct FakeHandle {
  acks: Arc<AtomicUsize>,
  shutdowns: Arc<FakeState>,
}

impl SourceControl for FakeHandle {
  fn overflow_processed(&self) {
    self.acks.fetch_add(1, Ordering::SeqCst);
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
    let (control_tx, control_rx) = async_channel::unbounded();
    self
      .state
      .controls
      .lock()
      .unwrap()
      .insert(root.clone(), control_tx);
    let acks = Arc::new(AtomicUsize::new(0));
    self
      .state
      .acks
      .lock()
      .unwrap()
      .insert(root.clone(), Arc::clone(&acks));
    Ok(SpawnedSource {
      handle: FakeHandle {
        acks,
        shutdowns: Arc::clone(&self.state),
      },
      channels: SourceChannels {
        data: rx,
        control: control_rx,
      },
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

struct Rig {
  fs: FakeFs,
  commands: async_channel::Sender<Command>,
  events: async_channel::Receiver<(ScopeId, Arc<PathBuf>, Change)>,
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
    |_| {},
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
  let grant = on_reply.await.unwrap().expect("watch succeeds");
  let scope = grant.scope();
  grant.defuse();
  scope
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
  let (scope, _root, change) = tokio::time::timeout(Duration::from_secs(5), rig.events.recv())
    .await
    .expect("an event arrives")
    .expect("the stream is open");
  (scope, change)
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
async fn cross_batch_rename_degrades_to_remove_plus_create() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  let tap = rig.fs.tap("/r");

  // Source half: the path is already gone. A vanished path has no
  // contemporaneous device evidence and no same-batch partner, so it never
  // mints a cookie — the documented cross-batch pairing cost.
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
  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_removed());
  assert_eq!(change.location(), &loc(&["a", "old"]));

  // Destination half in a later batch: the path exists, finds no pending
  // source, and arrives as a fresh object.
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
  assert!(change.kind().is_created());
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

  // No cookie, no pairing window: the vanished half resolves immediately.
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

  rig
    .fs
    .control_tap("/r")
    .send(SourceMessage::Overflow)
    .await
    .unwrap();
  let (_, rescan) = next_event(&rig).await;
  assert!(rescan.kind().is_rescan());
  assert!(rescan.epoch() > first.epoch());
  // The driver acknowledged the signal, re-arming the source's dedup.
  for _ in 0..100 {
    if rig.fs.overflow_acks("/r") == 1 {
      break;
    }
    tokio::task::yield_now().await;
  }
  assert_eq!(rig.fs.overflow_acks("/r"), 1);
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
  // The dropped ordinary events are covered, never replayed: nothing may
  // arrive after the Rescan that was produced before it.
  let third = tokio::time::timeout(Duration::from_millis(200), rig.events.recv()).await;
  assert!(
    third.is_err(),
    "an ordinary event escaped past its dominating Rescan: {third:?}"
  );
}

#[tokio::test(start_paused = true)]
async fn fatal_source_rescans_and_tears_down() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  rig
    .fs
    .control_tap("/r")
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

#[tokio::test(start_paused = true)]
async fn control_fatal_wakes_the_driver_with_no_data_traffic() {
  let rig = rig_with_capacity(1);
  let _scope = watch(&rig, "/r").await;
  let tap = rig.fs.tap("/r");

  // Fill the DATA channel completely (capacity-1 event channel plus the
  // capacity-8 os channel behind it can hold traffic, but the point is the
  // control channel is independent): the Fatal rides control and wakes the
  // driver even though nothing further arrives on data.
  tap
    .send(SourceMessage::Batch(vec![ev(
      "/r/x",
      FsEventFlags::ITEM_CREATED,
      1,
      3,
    )]))
    .await
    .unwrap();
  rig
    .fs
    .control_tap("/r")
    .send(SourceMessage::Fatal(SourceError::CallbackPanic))
    .await
    .unwrap();

  let (_, first) = next_event(&rig).await;
  assert!(first.kind().is_created());
  let (_, second) = next_event(&rig).await;
  assert!(
    second.kind().is_rescan(),
    "the in-band death surfaces as the terminal Rescan"
  );
  for _ in 0..100 {
    if rig.fs.shutdowns() == 1 {
      break;
    }
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(rig.fs.shutdowns(), 1, "the dead stream is torn down");
}

#[tokio::test(start_paused = true)]
async fn orphaned_watch_reply_tears_the_stream_down() {
  let rig = rig_with_capacity(64);

  // The watch() future was cancelled: its reply receiver is gone before the
  // spawn completes. The driver must not leave the fresh stream unowned.
  let (reply, on_reply) = futures_channel::oneshot::channel();
  drop(on_reply);
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/r"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();

  for _ in 0..100 {
    if rig.fs.shutdowns() == 1 {
      break;
    }
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "an unowned stream is torn down immediately"
  );
}

#[tokio::test(start_paused = true)]
async fn disconnected_source_is_a_dead_stream() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  // The source's sender vanishes without a Fatal — the receiver disconnect
  // itself must be treated as the death signal.
  rig.fs.disconnect("/r");

  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_rescan());
  tokio::time::sleep(Duration::from_millis(100)).await;
  assert_eq!(rig.fs.shutdowns(), 1);
}

#[tokio::test(start_paused = true)]
async fn lagged_root_death_delivers_the_terminal_rescan() {
  let rig = rig_with_capacity(1);
  let _scope = watch(&rig, "/r").await;
  let tap = rig.fs.tap("/r");

  // The first change fills the capacity-1 channel; the second refusal parks
  // a dominating Rescan while the channel is still full.
  for (id, name) in [(1u64, "/r/a"), (2, "/r/b")] {
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
  tokio::time::sleep(Duration::from_millis(100)).await;

  // The root dies while the scope is lagged and the channel is full: the
  // terminal Rescan must survive every refusal and land once the consumer
  // finally drains. Every sender must drop for the receiver to disconnect —
  // including this test's own tap clone.
  drop(tap);
  rig.fs.disconnect("/r");
  tokio::time::sleep(Duration::from_millis(500)).await;

  let (_, first) = next_event(&rig).await;
  assert!(first.kind().is_created());
  let (_, second) = next_event(&rig).await;
  assert!(
    second.kind().is_rescan(),
    "the terminal Rescan is never lost: {second:?}"
  );
  assert!(second.epoch() > first.epoch());
  // The teardown runs on the blocking pool in real time; give its thread
  // scheduler slices instead of trusting one paused-time sleep.
  for _ in 0..100 {
    if rig.fs.shutdowns() == 1 {
      break;
    }
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(rig.fs.shutdowns(), 1, "the dead stream is torn down");
}

#[tokio::test(start_paused = true)]
async fn uncommitted_watch_grant_unwinds_the_stream() {
  let rig = rig_with_capacity(64);

  // The reply receiver stays ALIVE while the driver spawns the stream and
  // sends the grant — then drops without ever being polled, the shape of a
  // watch() future cancelled after the reply landed. The unread grant must
  // unwind the stream it owns.
  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/r"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  for _ in 0..50 {
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  drop(on_reply);

  for _ in 0..100 {
    if rig.fs.shutdowns() == 1 {
      break;
    }
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "a delivered-but-never-polled grant unwinds its stream"
  );
}

#[tokio::test(start_paused = true)]
async fn control_overflow_discards_queued_data() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  let tap = rig.fs.tap("/r");

  // Batches queue on data, then the loss signal lands on control. The driver
  // may legally process a batch that wins the select BEFORE it observes the
  // control message — but once the covering Rescan is minted, nothing from
  // these pre-loss batches may follow it.
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
  rig
    .fs
    .control_tap("/r")
    .send(SourceMessage::Overflow)
    .await
    .unwrap();

  let mut seen = Vec::new();
  while let Ok(Ok((_, _, change))) =
    tokio::time::timeout(Duration::from_millis(300), rig.events.recv()).await
  {
    seen.push(change);
  }
  let rescan_at = seen
    .iter()
    .position(|c| c.kind().is_rescan())
    .expect("the loss surfaced as a Rescan");
  assert!(
    seen[rescan_at + 1..].iter().all(|c| c.kind().is_rescan()),
    "no pre-loss batch event may follow the covering Rescan: {seen:?}"
  );
}

#[tokio::test(start_paused = true)]
async fn fatal_discards_queued_data() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  let tap = rig.fs.tap("/r");

  for (id, name) in [(1u64, "/r/a"), (2, "/r/b")] {
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
  rig
    .fs
    .control_tap("/r")
    .send(SourceMessage::Fatal(SourceError::CallbackPanic))
    .await
    .unwrap();

  let mut seen = Vec::new();
  while let Ok(Ok((_, _, change))) =
    tokio::time::timeout(Duration::from_millis(300), rig.events.recv()).await
  {
    seen.push(change);
  }
  let rescan_at = seen
    .iter()
    .position(|c| c.kind().is_rescan())
    .expect("death surfaced as the terminal Rescan");
  assert!(
    seen[rescan_at + 1..].iter().all(|c| c.kind().is_rescan()),
    "no pre-death batch event may follow the terminal Rescan: {seen:?}"
  );
  for _ in 0..100 {
    if rig.fs.shutdowns() == 1 {
      break;
    }
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(rig.fs.shutdowns(), 1, "the dead stream is torn down");
}

#[tokio::test(start_paused = true)]
async fn overflow_refreshes_mount_trust_and_pairing_resumes() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  let tap = rig.fs.tap("/r");

  rig
    .fs
    .control_tap("/r")
    .send(SourceMessage::Overflow)
    .await
    .unwrap();
  let (_, rescan) = next_event(&rig).await;
  assert!(rescan.kind().is_rescan());

  // The loss revoked device trust and requested a mount-table refresh from
  // the blocking pool. That pool runs on REAL threads outside the paused
  // runtime, so the wait must be bounded by the real clock — a fixed yield
  // count loses the race whenever the machine is loaded.
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.refreshes() < 1 && std::time::Instant::now() < deadline {
    tokio::task::yield_now().await;
  }
  assert_eq!(rig.fs.refreshes(), 1, "one refresh per loss, coalesced");

  // With the refreshed table installed, a same-batch rename pair grounds
  // into a single Moved again — trust round-tripped end to end.
  rig.fs.remove("/r/a/old");
  rig.fs.put("/r/b/new", FileKind::File, 42);
  tap
    .send(SourceMessage::Batch(vec![
      ev("/r/a/old", renamed(), 10, 42),
      ev("/r/b/new", renamed(), 11, 42),
    ]))
    .await
    .unwrap();
  let (_, change) = next_event(&rig).await;
  assert_eq!(change.kind().moved_from(), Some(&loc(&["a", "old"])));
  assert_eq!(change.location(), &loc(&["b", "new"]));
}

/// Every delivery carries the canonical root it assembles under, so the
/// consumer never needs a registry entry — a reclaimed scope's trailing
/// changes still name their absolute paths.
#[tokio::test(start_paused = true)]
async fn deliveries_carry_the_canonical_root() {
  let rig = rig_with_capacity(64);
  let scope = watch(&rig, "/r").await;

  rig
    .fs
    .tap("/r")
    .send(SourceMessage::Batch(vec![ev(
      "/r/carried.txt",
      FsEventFlags::new(FsEventFlags::ITEM_CREATED.bits() | FsEventFlags::ITEM_IS_FILE.bits()),
      1,
      10,
    )]))
    .await
    .unwrap();

  let (got_scope, root, change) = tokio::time::timeout(Duration::from_secs(5), rig.events.recv())
    .await
    .expect("an event arrives")
    .expect("the stream is open");
  assert_eq!(got_scope, scope);
  assert_eq!(root.as_path(), Path::new("/r"));
  assert!(change.kind().is_created());
}

/// The scope-dead signal fires exactly once per stream teardown, naming the
/// dead scope — the reclamation contract the watcher registry builds on.
#[tokio::test(start_paused = true)]
async fn scope_dead_signal_fires_once_per_teardown() {
  let fs = FakeFs::new(1);
  fs.put("/r", FileKind::Dir, 1);
  let (cmd_tx, cmd_rx) = async_channel::bounded(16);
  let (ev_tx, _ev_rx) = async_channel::bounded(64);
  let dead: Arc<Mutex<Vec<ScopeId>>> = Arc::new(Mutex::new(Vec::new()));
  let recorder = Arc::clone(&dead);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config(),
    fs.clone(),
    cmd_rx,
    ev_tx,
    move |scope| recorder.lock().unwrap().push(scope),
  ));
  let rig = Rig {
    fs,
    commands: cmd_tx,
    events: async_channel::bounded(1).1,
  };

  let scope = watch(&rig, "/r").await;
  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Unwatch { scope, reply })
    .await
    .unwrap();
  assert!(on_reply.await.unwrap(), "the unwatch resolves");
  assert_eq!(
    dead.lock().unwrap().as_slice(),
    &[scope],
    "exactly one scope-dead signal, naming the dead scope"
  );
}
