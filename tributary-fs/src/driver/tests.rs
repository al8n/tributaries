use super::{testing::*, *};
use std::{
  collections::{BTreeMap, BTreeSet},
  num::{NonZeroU64, NonZeroUsize},
  sync::Arc,
  time::Duration,
};

use agnostic_lite::tokio::TokioRuntime;
use tributary_proto::{Epoch, FileKind, Location, Segment};

use crate::os::{FsEventFlags, RawOsEvent};

struct Rig {
  fs: FakeFs,
  commands: async_channel::Sender<Command>,
  cookie_removes: async_channel::Sender<CookieReap>,
  events: async_channel::Receiver<(ScopeId, Arc<PathBuf>, Change)>,
}

fn config() -> DriverConfig {
  DriverConfig {
    latency: Duration::from_millis(10),
    move_window: Duration::from_millis(100),
    os_batch_capacity: NonZeroUsize::new(8).unwrap(),
    exclusions: Vec::new(),
    profile: BackendKind::FsEvents,
    backend: Backend::Auto,
    // Inert for the FSEvents/inotify driver suites (only fanotify arms the
    // tick, and the fake spawns never resolve fanotify); a fanotify-specific
    // driver test overrides it.
    root_liveness_interval: Duration::from_secs(30),
    // Inert for the fake spawns (no fanotify admission map); a real fanotify
    // spawn threads this into its SourceConfig.
    max_map_directories: None,
    cookie_retry_base: Duration::from_millis(100),
    cookie_retry_cap: Duration::from_secs(5),
    cookie_retry_budget: 8,
    cookie_backlog_cap: 8,
    cookie_global_cap: 128,
  }
}

/// The cookie-retry cells' config: a fast backoff, a small attempt budget, and a low
/// per-scope backlog cap, so the driver-owned retry, budget-park, and backlog-refusal
/// paths run in real (multi-thread) time within a `settle` window.
fn tuned_config() -> DriverConfig {
  DriverConfig {
    cookie_retry_base: Duration::from_millis(5),
    cookie_retry_cap: Duration::from_millis(20),
    cookie_retry_budget: 3,
    cookie_backlog_cap: 3,
    cookie_global_cap: 64,
    ..config()
  }
}

fn rig_with_capacity(event_capacity: usize) -> Rig {
  rig_with(event_capacity, NullRegistry)
}

/// A rig whose driver runs with an explicit [`DriverConfig`] — the cookie-retry cells override
/// the backoff/budget/backlog knobs so their timings are fast and deterministic.
fn rig_with_config(event_capacity: usize, config: DriverConfig) -> Rig {
  let fs = FakeFs::new(1);
  fs.put("/r", FileKind::Dir, 1);
  let (cmd_tx, cmd_rx) = async_channel::bounded(16);
  let (reap_tx, reap_rx) = async_channel::unbounded();
  let (ev_tx, ev_rx) = async_channel::bounded(event_capacity);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config,
    fs.clone(),
    cmd_rx,
    reap_rx,
    ev_tx,
    NullRegistry,
  ));
  Rig {
    fs,
    commands: cmd_tx,
    cookie_removes: reap_tx,
    events: ev_rx,
  }
}

fn rig_with(event_capacity: usize, registry: impl ScopeRegistry) -> Rig {
  let fs = FakeFs::new(1);
  fs.put("/r", FileKind::Dir, 1);
  let (cmd_tx, cmd_rx) = async_channel::bounded(16);
  let (reap_tx, reap_rx) = async_channel::unbounded();
  let (ev_tx, ev_rx) = async_channel::bounded(event_capacity);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config(),
    fs.clone(),
    cmd_rx,
    reap_rx,
    ev_tx,
    registry,
  ));
  Rig {
    fs,
    commands: cmd_tx,
    cookie_removes: reap_tx,
    events: ev_rx,
  }
}

async fn watch(rig: &Rig, root: &str) -> ScopeId {
  let before = rig.fs.refreshes();
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
  // A scope is born trust-closed; its birth refresh runs on the real-thread
  // blocking pool. Wait it out so every test starts from installed trust —
  // once the result is queued, the biased select consumes it before any
  // batch a test injects afterwards. Real-clock bound: the pool runs outside
  // the paused runtime.
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.refreshes() <= before && std::time::Instant::now() < deadline {
    tokio::task::yield_now().await;
  }
  assert!(rig.fs.refreshes() > before, "the birth refresh ran");
  // The counter increments inside the pool thread an instant before its
  // result is queued; a few yields let that send land.
  for _ in 0..8 {
    tokio::task::yield_now().await;
  }
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

fn created() -> FsEventFlags {
  FsEventFlags::new(FsEventFlags::ITEM_CREATED.bits() | FsEventFlags::ITEM_IS_FILE.bits())
}

fn removed() -> FsEventFlags {
  FsEventFlags::new(FsEventFlags::ITEM_REMOVED.bits() | FsEventFlags::ITEM_IS_FILE.bits())
}

fn renamed() -> FsEventFlags {
  FsEventFlags::new(FsEventFlags::ITEM_RENAMED.bits() | FsEventFlags::ITEM_IS_FILE.bits())
}

/// `next_event` plus the delivery's canonical root.
async fn next_rooted(rig: &Rig) -> (ScopeId, Arc<PathBuf>, Change) {
  tokio::time::timeout(Duration::from_secs(5), rig.events.recv())
    .await
    .expect("an event arrives")
    .expect("the stream is open")
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

/// Gives the blocking pool real-clock scheduler slices under paused time.
async fn settle(mut done: impl FnMut() -> bool) {
  for _ in 0..200 {
    if done() {
      return;
    }
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
}

#[tokio::test(start_paused = true)]
async fn watch_spawns_a_stream_and_events_flow() {
  let rig = rig_with_capacity(64);
  let scope = watch(&rig, "/r").await;

  rig
    .fs
    .send_batch("/r", vec![ev("/r/a/new.txt", created(), 1, 10)]);

  let (got_scope, change) = next_event(&rig).await;
  assert_eq!(got_scope, scope);
  assert!(change.kind().is_created());
  assert_eq!(change.location(), &loc(&["a", "new.txt"]));
}

#[tokio::test(start_paused = true)]
async fn cross_batch_rename_degrades_to_remove_plus_create() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  // Source half: the path is already gone. A vanished path has no
  // contemporaneous device evidence and no same-batch partner, so it never
  // mints a cookie — the documented cross-batch pairing cost.
  rig.fs.remove("/r/a/old");
  rig
    .fs
    .send_batch("/r", vec![ev("/r/a/old", renamed(), 10, 42)]);
  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_removed());
  assert_eq!(change.location(), &loc(&["a", "old"]));

  // Destination half in a later batch: the path exists, finds no pending
  // source, and arrives as a fresh object.
  rig.fs.put("/r/b/new", FileKind::File, 42);
  rig
    .fs
    .send_batch("/r", vec![ev("/r/b/new", renamed(), 11, 42)]);
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
    .send_batch("/r", vec![ev("/r/a/left", renamed(), 10, 7)]);

  // No cookie, no pairing window: the vanished half resolves immediately.
  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_removed());
  assert_eq!(change.location(), &loc(&["a", "left"]));
}

#[tokio::test(start_paused = true)]
async fn overflow_message_becomes_one_epoch_bumped_rescan() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  rig.fs.send_batch("/r", vec![ev("/r/x", created(), 1, 3)]);
  let (_, first) = next_event(&rig).await;

  rig.fs.send_lossy("/r");
  let (_, rescan) = next_event(&rig).await;
  assert!(rescan.kind().is_rescan());
  assert!(rescan.epoch() > first.epoch());
  // The driver dropped the message's ack, re-arming the source's dedup.
  settle(|| !rig.fs.overflow_pending("/r")).await;
  assert!(!rig.fs.overflow_pending("/r"));
}

#[tokio::test(start_paused = true)]
async fn lagged_consumer_gets_the_dominating_rescan() {
  let rig = rig_with_capacity(1);
  let _scope = watch(&rig, "/r").await;

  for (id, name) in [(1u64, "/r/a"), (2, "/r/b"), (3, "/r/c")] {
    rig.fs.send_batch("/r", vec![ev(name, created(), id, id)]);
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
  rig.fs.send_fatal("/r");

  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_rescan());
  settle(|| rig.fs.shutdowns() == 1).await;
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
    .send(Command::Unwatch {
      scope,
      reply: Some(reply),
    })
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
  assert!(matches!(
    err,
    WatchRootError::Source(SourceError::RootUnavailable { .. })
  ));
}

/// The queue is the source's one ordered lane: batches enqueued BEFORE a loss
/// signal deliver before the Rescan it becomes, and nothing from them may
/// follow it — ordering by construction, no drain, no barrier.
#[tokio::test(start_paused = true)]
async fn queued_data_delivers_before_a_later_loss_signal() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  for (id, name) in [(1u64, "/r/a"), (2, "/r/b"), (3, "/r/c")] {
    rig.fs.send_batch("/r", vec![ev(name, created(), id, id)]);
  }
  rig.fs.send_lossy("/r");

  let mut seen = Vec::new();
  while let Ok(Ok((_, _, change))) =
    tokio::time::timeout(Duration::from_millis(300), rig.events.recv()).await
  {
    seen.push(change);
  }
  let names: Vec<String> = seen
    .iter()
    .map(|c| {
      if c.kind().is_rescan() {
        "rescan".to_string()
      } else {
        c.location()
          .name()
          .map(|s| s.as_str().to_string())
          .unwrap_or_default()
      }
    })
    .collect();
  assert_eq!(
    names,
    ["a", "b", "c", "rescan"],
    "queued data precedes the loss signal, in source order"
  );
}

/// Same ordering pin for the terminal signal: batches before the Fatal
/// deliver, then the terminal Rescan, then teardown.
#[tokio::test(start_paused = true)]
async fn fatal_follows_queued_data_in_order() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  for (id, name) in [(1u64, "/r/a"), (2, "/r/b")] {
    rig.fs.send_batch("/r", vec![ev(name, created(), id, id)]);
  }
  rig.fs.send_fatal("/r");

  let mut seen = Vec::new();
  while let Ok(Ok((_, _, change))) =
    tokio::time::timeout(Duration::from_millis(300), rig.events.recv()).await
  {
    seen.push(change);
  }
  assert!(
    seen.len() >= 3 && seen[0].kind().is_created() && seen[1].kind().is_created(),
    "data queued before the death delivers first: {seen:?}"
  );
  assert!(
    seen[2..].iter().all(|c| c.kind().is_rescan()),
    "the terminal Rescan follows in order: {seen:?}"
  );
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1, "the dead stream is torn down");
}

/// The in-band Fatal needs no data traffic to wake the driver: the queue IS
/// the wake.
#[tokio::test(start_paused = true)]
async fn fatal_wakes_the_driver_with_no_data_traffic() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  rig.fs.send_fatal("/r");

  let (_, change) = next_event(&rig).await;
  assert!(
    change.kind().is_rescan(),
    "the in-band death surfaces as the terminal Rescan"
  );
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1);
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

  settle(|| rig.fs.shutdowns() == 1).await;
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
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1);
}

#[tokio::test(start_paused = true)]
async fn lagged_root_death_delivers_the_terminal_rescan() {
  let rig = rig_with_capacity(1);
  let _scope = watch(&rig, "/r").await;

  // The first change fills the capacity-1 channel; the second refusal parks
  // a dominating Rescan while the channel is still full.
  for (id, name) in [(1u64, "/r/a"), (2, "/r/b")] {
    rig.fs.send_batch("/r", vec![ev(name, created(), id, id)]);
  }
  tokio::time::sleep(Duration::from_millis(100)).await;

  // The root dies while the scope is lagged and the channel is full: the
  // terminal Rescan must survive every refusal and land once the consumer
  // finally drains.
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
  settle(|| rig.fs.shutdowns() == 1).await;
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
  settle(|| rig.fs.spawns() == 1).await;
  for _ in 0..50 {
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  drop(on_reply);

  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "a delivered-but-never-polled grant unwinds its stream"
  );
}

#[tokio::test(start_paused = true)]
async fn overflow_refreshes_mount_trust_and_pairing_resumes() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  assert_eq!(rig.fs.refreshes(), 1, "the birth refresh already ran");
  rig.fs.send_lossy("/r");
  let (_, rescan) = next_event(&rig).await;
  assert!(rescan.kind().is_rescan());

  // The loss revoked device trust and requested a mount-table refresh from
  // the blocking pool. That pool runs on REAL threads outside the paused
  // runtime, so the wait must be bounded by the real clock.
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.refreshes() < 2 && std::time::Instant::now() < deadline {
    tokio::task::yield_now().await;
  }
  assert_eq!(
    rig.fs.refreshes(),
    2,
    "one refresh per loss, coalesced, on top of the birth refresh"
  );

  // With the refreshed table installed, a same-batch rename pair grounds
  // into a single Moved again — trust round-tripped end to end.
  rig.fs.remove("/r/a/old");
  rig.fs.put("/r/b/new", FileKind::File, 42);
  rig.fs.send_batch(
    "/r",
    vec![
      ev("/r/a/old", renamed(), 10, 42),
      ev("/r/b/new", renamed(), 11, 42),
    ],
  );
  let (_, change) = next_event(&rig).await;
  assert_eq!(change.kind().moved_from(), Some(&loc(&["a", "old"])));
  assert_eq!(change.location(), &loc(&["b", "new"]));
}

/// Root-death via the refresh path (design §7 gap, closed by L4.2): a refresh
/// whose folded-in root re-stat finds the root GONE lowers the death lifecycle
/// end to end — the terminal `Rescan` is delivered and the driver reclaims the
/// registry entry — with no new timer or effect (the loss-armed refresh is the
/// same one mount trust rides). The kernel-recursive backends' only unmount
/// detection.
#[tokio::test(start_paused = true)]
async fn refresh_finding_root_gone_dies_end_to_end() {
  let registry = RecordingRegistry::default();
  let rig = rig_with(64, registry.clone());
  let scope = watch(&rig, "/r").await;
  assert_eq!(rig.fs.refreshes(), 1, "the birth refresh already ran");

  // Arm the next refresh to report the root GONE, then induce the loss path
  // that runs it (the loss revokes trust and arms one refresh).
  rig.fs.set_root_liveness(RootLiveness::Missing);
  rig.fs.send_lossy("/r");

  // The loss itself yields the standing Rescan; the refresh-detected death then
  // ends the scope with its terminal Rescan and reclaims the entry.
  settle(|| registry.dead() == [scope]).await;
  assert_eq!(
    registry.dead(),
    [scope],
    "the refresh-detected death reclaimed the registry entry"
  );
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the dead root's stream was torn down"
  );
}

/// The refresh samples the root's identity AND its mount frame from ONE object, so
/// a replaced/re-mounted root can never pair the OLD identity's verdict with a NEW
/// object's frame (the mixed sample the atomic `statx` restructure closes). The fake
/// now reads both from one node, making the mix unrepresentable: after
/// `replace_root_node` swaps the object at the root path, the refresh reports the
/// REPLACED identity together with the replacement's frame — a matched pair, never a
/// mix.
#[tokio::test]
async fn refresh_pairs_the_replaced_identity_with_its_own_frame() {
  let fs = FakeFs::with_root_mnt_id(1, 42);
  fs.put("/r", FileKind::Dir, 1);

  // Baseline: the original root (ino 1) on mount 42 — identity and frame paired.
  let before = fs.refresh_mounts(Path::new("/r"));
  assert_eq!(
    before.root,
    RootLiveness::Present(RootIdentity::new(1, 1)),
    "the original root samples its own identity"
  );
  assert_eq!(
    before.root_mnt_id,
    Some(42),
    "the original root samples its own frame (42) from the same node"
  );

  // A replace/remount at the path: a DIFFERENT object (ino 2) on a DIFFERENT mount
  // (77). The single-node read pairs THIS identity with THIS frame — the fake cannot
  // emit ino-1's "matching" verdict beside mount-77's frame.
  fs.replace_root_node("/r", 2, Some(77));
  let after = fs.refresh_mounts(Path::new("/r"));
  assert_eq!(
    after.root,
    RootLiveness::Present(RootIdentity::new(1, 2)),
    "the replaced root reports the REPLACED identity (ino 2), not the old one"
  );
  assert_eq!(
    after.root_mnt_id,
    Some(77),
    "the replaced root's frame (77) is paired with its OWN identity — never a mix with \
     the old identity's verdict"
  );
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
    .send_batch("/r", vec![ev("/r/carried.txt", created(), 1, 10)]);

  let (got_scope, root, change) = tokio::time::timeout(Duration::from_secs(5), rig.events.recv())
    .await
    .expect("an event arrives")
    .expect("the stream is open");
  assert_eq!(got_scope, scope);
  assert_eq!(root.as_path(), Path::new("/r"));
  assert!(change.kind().is_created());
}

/// The single-writer lifecycle contract: the driver records a scope live
/// (before its grant can reach the watcher) and dead (once per teardown), in
/// program order on one task.
#[tokio::test(start_paused = true)]
async fn registry_sees_live_then_dead_in_order() {
  let registry = RecordingRegistry::default();
  let rig = rig_with(64, registry.clone());

  let scope = watch(&rig, "/r").await;
  assert_eq!(
    registry.live(),
    [(scope, PathBuf::from("/r"), BackendKind::FsEvents)],
    "the entry was live before the grant resolved"
  );

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Unwatch {
      scope,
      reply: Some(reply),
    })
    .await
    .unwrap();
  assert!(on_reply.await.unwrap(), "the unwatch resolves");
  assert_eq!(
    registry.dead(),
    [scope],
    "exactly one scope-dead signal, naming the dead scope"
  );
}

/// Driver-level: the source dies AFTER the grant was sent but BEFORE the
/// caller polls it. Both registry transitions ran on the driver in order
/// (live, then dead); the late commit just yields a dead-on-arrival handle,
/// and the path is immediately re-watchable.
#[tokio::test(start_paused = true)]
async fn death_between_grant_send_and_poll_leaves_a_consistent_registry() {
  let registry = RecordingRegistry::default();
  let rig = rig_with(64, registry.clone());

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
  // The grant resolves — the registry entry is already live.
  let grant = on_reply.await.unwrap().expect("watch succeeds");
  let scope = grant.scope();
  assert_eq!(
    registry.live(),
    [(scope, PathBuf::from("/r"), BackendKind::FsEvents)]
  );

  // The source dies before the caller "polls" (commits) the grant.
  rig.fs.disconnect("/r");
  settle(|| registry.dead() == [scope]).await;
  assert_eq!(registry.dead(), [scope], "the driver reclaimed the entry");
  assert_eq!(rig.fs.shutdowns(), 1);

  // The late commit is a dead-on-arrival handle; nothing unwinds twice.
  grant.defuse();
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1, "no double teardown");

  // The path is free: a fresh watch succeeds.
  let scope2 = watch(&rig, "/r").await;
  assert_ne!(scope2, scope, "a fresh scope for the re-watch");
}

fn xorshift(s: &mut u64) -> u64 {
  *s ^= *s << 13;
  *s ^= *s >> 17;
  *s ^= *s << 5;
  *s
}

/// The standing end-to-end no-silent-loss storm — the one property every
/// historical finding violated: under random mutations, decode losses, budget
/// pressure, and a lagging consumer, the view reconstructed from delivered
/// events (honoring Rescans as re-reads) converges to the tree, with
/// per-scope epochs monotone. `TRIBUTARY_FS_STORM_SEEDS` scales the seed
/// count (64 in CI; run 1024 nightly).
///
/// Under miri the default drops to ONE seed: miri never reuses an address, so
/// 64 seeds' worth of path and tree churn exhausts a 32-bit target's whole
/// address space (i686 dies with "no more free addresses"). Miri is here to
/// find UB, and one seed drives every code path the others do — the
/// statistical convergence coverage is the native runs' job, where the full
/// seed count still runs.
#[tokio::test(start_paused = true)]
async fn storm_no_silent_loss_converges() {
  let default_seeds: u64 = if cfg!(miri) { 1 } else { 64 };
  let seeds: u64 = std::env::var("TRIBUTARY_FS_STORM_SEEDS")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(default_seeds);
  for seed in 1..=seeds {
    storm_seed(seed).await;
  }
}

async fn storm_seed(seed: u64) {
  let rig = rig_with_capacity(4);
  rig.fs.put("/r/w", FileKind::Dir, 2);
  let scope = watch(&rig, "/r/w").await;
  let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(1);
  let mut next_ino = 100u64;
  let mut next_id = 1u64;
  let mut live: Vec<(PathBuf, u64)> = Vec::new();
  let mut view: BTreeSet<PathBuf> = BTreeSet::new();
  let mut last_epoch: Option<Epoch> = None;
  let mut last_root: Option<PathBuf> = None;
  let mut current_root = PathBuf::from("/r/w");

  for _ in 0..30 {
    // The replace perturbation: ~1/8 of iterations swap the root between
    // /r/w and /r (widen, then occasionally back). Convergence and epoch
    // order must survive the swap; the commit Rescan re-reads the world.
    if xorshift(&mut s).is_multiple_of(8) {
      let target = if current_root == Path::new("/r/w") {
        PathBuf::from("/r")
      } else {
        PathBuf::from("/r/w")
      };
      let (reply, mut on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: target.clone(),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(target.clone()),
          reply,
        })
        .await
        .unwrap();
      // Keep the pipe draining while the swap settles: the commit Rescan
      // must never deadlock against a full consumer channel.
      let outcome = loop {
        match tokio::time::timeout(Duration::from_millis(50), &mut on_reply).await {
          Ok(res) => break res.expect("driver replies"),
          Err(_) => {
            if let Ok(Ok((_, root, change))) =
              tokio::time::timeout(Duration::from_millis(10), rig.events.recv()).await
            {
              apply(
                &rig,
                &mut view,
                &mut last_epoch,
                &mut last_root,
                &root,
                &change,
              );
            }
          }
        }
      };
      assert!(
        outcome.is_ok(),
        "seed {seed}: the storm swap commits: {outcome:?}"
      );
      current_root = target;
      // The storm's own mutation pool narrows with the coverage; the VIEW
      // re-bases only when the consumer OBSERVES the flip (in `apply`).
      live.retain(|(p, _)| p.starts_with(&current_root));
      continue;
    }
    let mut events = Vec::new();
    match xorshift(&mut s) % 4 {
      0 | 1 => {
        next_ino += 1;
        let path = current_root.join(format!("f{next_ino}"));
        rig.fs.put(&path, FileKind::File, next_ino);
        next_id += 1;
        events.push(ev(path.to_str().unwrap(), created(), next_id, next_ino));
        live.push((path, next_ino));
      }
      2 if !live.is_empty() => {
        let i = (xorshift(&mut s) as usize) % live.len();
        let (path, ino) = live.swap_remove(i);
        rig.fs.remove(&path);
        next_id += 1;
        events.push(ev(path.to_str().unwrap(), removed(), next_id, ino));
      }
      3 if !live.is_empty() => {
        let i = (xorshift(&mut s) as usize) % live.len();
        let (old, ino) = live.swap_remove(i);
        next_ino += 1;
        let new = current_root.join(format!("g{next_ino}"));
        rig.fs.remove(&old);
        rig.fs.put(&new, FileKind::File, ino);
        next_id += 1;
        events.push(ev(old.to_str().unwrap(), renamed(), next_id, ino));
        next_id += 1;
        events.push(ev(new.to_str().unwrap(), renamed(), next_id, ino));
        live.push((new, ino));
      }
      _ => continue,
    }
    // Perturb: one in six batches is lost at decode — the mutation happened,
    // only its report vanished, and the in-order loss signal must cover it.
    if xorshift(&mut s).is_multiple_of(6) {
      rig.fs.send_lossy(&current_root);
    } else {
      rig.fs.send_batch(&current_root, events);
    }
    // A sometimes-lagging consumer: drain a few events only occasionally.
    if xorshift(&mut s).is_multiple_of(3) {
      for _ in 0..(xorshift(&mut s) % 4) {
        match tokio::time::timeout(Duration::from_millis(100), rig.events.recv()).await {
          Ok(Ok((_, root, change))) => {
            apply(
              &rig,
              &mut view,
              &mut last_epoch,
              &mut last_root,
              &root,
              &change,
            );
          }
          _ => break,
        }
      }
    }
  }

  // Mutations stop; give pairing windows and probes time, then drain to
  // quiescence.
  for _ in 0..50 {
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
  while let Ok(Ok((_, root, change))) =
    tokio::time::timeout(Duration::from_millis(300), rig.events.recv()).await
  {
    apply(
      &rig,
      &mut view,
      &mut last_epoch,
      &mut last_root,
      &root,
      &change,
    );
  }

  let tree = rig.fs.files_under(&current_root);
  assert_eq!(
    view, tree,
    "seed {seed}: the reconstructed view converges to the tree under {current_root:?}"
  );
}

fn apply(
  rig: &Rig,
  view: &mut BTreeSet<PathBuf>,
  last_epoch: &mut Option<Epoch>,
  last_root: &mut Option<PathBuf>,
  root: &Path,
  change: &Change,
) {
  // A delivery-root flip IS the observable root replacement: re-base the
  // view to the new coverage. In-order delivery makes this exact — the
  // lane gate guarantees no old-world delivery can follow the commit
  // Rescan, so the flip happens at the world boundary.
  if last_root.as_deref() != Some(root) {
    if last_root.is_some() {
      view.retain(|p| p.starts_with(root));
    }
    *last_root = Some(root.to_path_buf());
  }
  if let Some(prev) = *last_epoch {
    assert!(
      change.epoch() >= prev,
      "per-scope epochs are monotone: {prev:?} then {:?}",
      change.epoch()
    );
  }
  *last_epoch = Some(change.epoch());
  let abs = |l: &Location| {
    let mut p = root.to_path_buf();
    for seg in l.segments() {
      p.push(seg.as_str());
    }
    p
  };
  match change.kind() {
    tributary_proto::ChangeKind::Created => {
      view.insert(abs(change.location()));
    }
    tributary_proto::ChangeKind::Removed => {
      view.remove(&abs(change.location()));
    }
    tributary_proto::ChangeKind::Moved(from) => {
      view.remove(&abs(from));
      view.insert(abs(change.location()));
    }
    tributary_proto::ChangeKind::Modified => {}
    tributary_proto::ChangeKind::Rescan => {
      // A delivered Rescan is a re-read of current state under its location.
      let at = abs(change.location());
      view.retain(|p| !p.starts_with(&at));
      view.extend(rig.fs.files_under(&at));
    }
    _ => {}
  }
}

/// The spawn contract's full observable order: a source's `RootMeta` is
/// sealed strictly BEFORE its stream can enqueue an event (trust-bearing
/// metadata can never postdate a message on the queue), and the root is
/// revalidated strictly AFTER the stream is live — the identity bracket's
/// post-live half — before the spawn returns. A regression that seeds after
/// liveness, or commits without revalidating, fails here.
#[tokio::test(start_paused = true)]
async fn spawn_seals_root_meta_before_the_stream_goes_live() {
  let rig = rig_with_capacity(64);
  watch(&rig, "/r").await;
  assert_eq!(
    rig.fs.spawn_order(),
    vec!["meta_sealed", "stream_live", "root_revalidated"],
    "the metadata barrier precedes liveness; the identity bracket follows it"
  );
}

/// A submount present at spawn lands in the pre-start seed and vetoes trust
/// for its whole prefix from the first event on — even if the volume vanishes
/// immediately after (its unmount travels in-band and is applied late, per
/// the monotone rule); nothing can event before the seed exists.
#[tokio::test(start_paused = true)]
async fn spawn_seed_carries_a_preexisting_submount() {
  let fs = FakeFs::new(1);
  fs.put("/r", FileKind::Dir, 1);
  fs.seed_mounts(vec![PathBuf::from("/r/vol")]);
  let (cmd_tx, cmd_rx) = async_channel::bounded(16);
  let (reap_tx, reap_rx) = async_channel::unbounded();
  let (ev_tx, ev_rx) = async_channel::bounded(64);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config(),
    fs.clone(),
    cmd_rx,
    reap_rx,
    ev_tx,
    NullRegistry,
  ));
  let rig = Rig {
    fs,
    commands: cmd_tx,
    cookie_removes: reap_tx,
    events: ev_rx,
  };
  watch(&rig, "/r").await;

  // A colliding same-fileID rename pair spanning the seeded submount: the
  // foreign half's prefix is vetoed by the seed, so no Moved can fabricate.
  rig.fs.put("/r/dst", FileKind::File, 7);
  rig.fs.send_batch(
    "/r",
    vec![
      ev("/r/vol/src", renamed(), 10, 7),
      ev("/r/dst", renamed(), 11, 7),
    ],
  );
  let (_, change) = next_event(&rig).await;
  assert!(
    !change.kind().is_moved(),
    "a seeded foreign prefix never pairs: {change:?}"
  );
}

/// A spawn already dispatched to the blocking pool is invisible to `handles`;
/// close must hold its reply until the late stream is torn down inside the
/// close accounting. Real time: the ~1 s grace must not fire before the
/// pending-spawn check is exercised.
#[tokio::test]
async fn close_waits_for_an_in_flight_spawn_and_tears_it_down() {
  let rig = rig_with_capacity(64);
  let gate = rig.fs.hold_spawns();

  // A watch whose future is cancelled right after the command is sent: the
  // spawn is in flight with nobody left to take ownership.
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
  drop(on_reply);

  let (close_reply, mut on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  tokio::time::sleep(Duration::from_millis(50)).await;
  assert!(
    (&mut on_close).now_or_never().is_none(),
    "close must wait for the in-flight spawn"
  );

  gate.release();
  tokio::time::timeout(Duration::from_secs(5), on_close)
    .await
    .expect("close resolves once the late spawn settles")
    .expect("the driver confirms the close");
  assert_eq!(rig.fs.spawns(), 1, "the late spawn completed");
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the late stream was torn down inside the close accounting"
  );
}

/// The failed twin: a spawn racing close that returns an error just settles
/// its accounting slot — close resolves with no stream ever live.
#[tokio::test]
async fn close_settles_an_in_flight_spawn_failure() {
  let rig = rig_with_capacity(64);
  let gate = rig.fs.hold_spawns();

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
  drop(on_reply);

  let (close_reply, mut on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  tokio::time::sleep(Duration::from_millis(50)).await;
  assert!(
    (&mut on_close).now_or_never().is_none(),
    "close must wait for the in-flight spawn"
  );

  // The root vanishes while the spawn is parked: releasing the gate fails it.
  rig.fs.remove("/r");
  gate.release();
  tokio::time::timeout(Duration::from_secs(5), on_close)
    .await
    .expect("close resolves once the failed spawn settles")
    .expect("the driver confirms the close");
  assert_eq!(rig.fs.spawns(), 0, "the spawn failed");
  assert_eq!(rig.fs.shutdowns(), 0, "no stream ever existed");
}

/// A blocking pool wedged past the grace must not hang close forever: the
/// reply reports the spawn still pending — a wedged spawn is never treated as
/// quiescent — and the orphan handle's Drop remains the reclamation backstop
/// once the wedge clears.
#[tokio::test]
async fn close_grace_bounds_a_wedged_spawn_and_drop_reclaims_it() {
  let rig = rig_with_capacity(64);
  let gate = rig.fs.hold_spawns();

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
  drop(on_reply);

  let (close_reply, on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
    .await
    .expect("close resolves at the grace boundary")
    .expect("the driver replied");
  assert_eq!(
    pending, 1,
    "a wedged spawn is reported — the driver cannot see which phase it \
     wedged in, so it never claims quiescence over one"
  );
  assert_eq!(
    rig.fs.shutdowns(),
    0,
    "the wedged spawn has not produced a stream yet"
  );
  assert_eq!(
    rig.fs.spawns(),
    0,
    "the wedge parked before the stream went live"
  );

  // The wedge clears after close: the orphan completes, its op message finds
  // the channel closed, and the handle's Drop reclaims the stream.
  gate.release();
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.shutdowns() == 0 && std::time::Instant::now() < deadline {
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the Drop backstop reclaimed the orphan"
  );
}

/// A spawn wedged AFTER its stream went live — the backend's post-live
/// metadata phase — already owns a live native stream, so close must count it
/// as non-quiescent; once the wedge clears, the undeliverable result's handle
/// Drop reclaims the stream.
#[tokio::test]
async fn close_counts_a_post_live_wedged_spawn_as_non_quiescent() {
  let rig = rig_with_capacity(64);
  rig.fs.put("/r", FileKind::Dir, 1);
  let gate = rig.fs.hold_spawns_post_live();

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
  drop(on_reply);

  // Wait until the fake stream is genuinely live inside the parked spawn.
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.spawns() == 0 && std::time::Instant::now() < deadline {
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(rig.fs.spawns(), 1, "the stream went live inside the spawn");

  let (close_reply, on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
    .await
    .expect("close resolves at the grace boundary")
    .expect("the driver replied");
  assert_eq!(pending, 1, "the live-but-unreturned spawn is counted");
  assert_eq!(
    rig.fs.shutdowns(),
    0,
    "the live stream is genuinely unreclaimed at reply time"
  );

  // The wedge clears: the result finds the op channel closed and the handle's
  // Drop reclaims the live stream.
  gate.release();
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.shutdowns() == 0 && std::time::Instant::now() < deadline {
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the Drop backstop reclaimed the stream"
  );
}

/// A teardown wedged past the grace is the residual close must NOT paper
/// over: the handle already moved into the wedged shutdown call, so no Drop
/// backstop exists until it returns — the reply carries the pending count
/// instead of claiming quiescence.
#[tokio::test]
async fn close_reports_a_wedged_teardown_instead_of_quiescence() {
  let rig = rig_with_capacity(64);
  rig.fs.put("/r", FileKind::Dir, 1);
  let _scope = watch(&rig, "/r").await;
  let gate = rig.fs.hold_teardowns();

  let (close_reply, on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
    .await
    .expect("close resolves at the grace boundary")
    .expect("the driver replied");
  assert_eq!(
    pending, 1,
    "the wedged teardown is reported, not papered over"
  );
  assert_eq!(rig.fs.shutdowns(), 0, "the stream is genuinely still live");

  gate.release();
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.shutdowns() == 0 && std::time::Instant::now() < deadline {
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the wedged call completes once released"
  );
}

mod descending {
  //! The descending (inotify-profile) loop, end to end on the fake platform.

  use super::*;
  use crate::os::linux::{RawInotifyEvent, RawLinuxEvent, inotify::decode::InotifyMask};

  fn inotify_config() -> DriverConfig {
    DriverConfig {
      profile: BackendKind::Inotify,
      ..config()
    }
  }

  fn inotify_rig() -> Rig {
    inotify_rig_fs(FakeFs::new(1))
  }

  /// A descending rig whose fake source reports a root MOUNT id, so the core
  /// fences a same-device child on a different mount (a bind) end to end.
  fn inotify_rig_mnt(root_mnt_id: u64) -> Rig {
    inotify_rig_fs(FakeFs::with_root_mnt_id(1, root_mnt_id))
  }

  fn inotify_rig_fs(fs: FakeFs) -> Rig {
    fs.put("/r", FileKind::Dir, 1);
    fs.spawn_backend(BackendKind::Inotify);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (reap_tx, reap_rx) = async_channel::unbounded();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    tokio::spawn(run::<TokioRuntime, FakeFs>(
      inotify_config(),
      fs.clone(),
      cmd_rx,
      reap_rx,
      ev_tx,
      NullRegistry,
    ));
    Rig {
      fs,
      commands: cmd_tx,
      cookie_removes: reap_tx,
      events: ev_rx,
    }
  }

  fn attributed(anchors: &[tributary_proto::WatchId], mask: u32, name: &[u8]) -> RawLinuxEvent {
    RawLinuxEvent::Inotify {
      anchors: anchors.to_vec(),
      event: RawInotifyEvent {
        wd: 1,
        mask: InotifyMask(mask),
        cookie: 0,
        name: Some(name.to_vec()),
      },
    }
  }

  const IN_CREATE: u32 = 0x0000_0100;

  /// Registration → root arm at spawn → cold enumerate against the fake tree
  /// → discovered directory armed → its own enumerate → the inventory reaches
  /// the consumer. The whole dormant vocabulary, driven by the real loop.
  #[tokio::test(flavor = "multi_thread")]
  async fn descending_watch_inventories_and_descends() {
    let rig = inotify_rig();
    rig.fs.put("/r/a.txt", FileKind::File, 10);
    rig.fs.put("/r/sub", FileKind::Dir, 11);
    rig.fs.put("/r/sub/inner.txt", FileKind::File, 12);
    let _scope = watch(&rig, "/r").await;

    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..3 {
      let (_scope, change) = next_event(&rig).await;
      if change.kind().is_created() {
        seen.insert(change.location().clone());
      }
    }
    assert!(seen.contains(&loc(&["a.txt"])), "{seen:?}");
    assert!(seen.contains(&loc(&["sub"])), "{seen:?}");
    assert!(seen.contains(&loc(&["sub", "inner.txt"])), "{seen:?}");
    settle(|| {
      rig
        .fs
        .enumerates()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/sub"))
    })
    .await;
    let arms = rig.fs.arms();
    assert!(
      arms
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/sub")),
      "the discovered directory was armed: {arms:?}"
    );
  }

  /// End to end: a same-DEVICE child on a different MOUNT (a `mount --bind` of a
  /// same-superblock directory) is lowered `Other` and never armed/descended,
  /// while a same-mount sibling is. The device check alone would descend into the
  /// bind (its device equals the root's) and cover an out-of-root subtree — the
  /// mount-id fence is what closes it. Drives the whole path: the fake source
  /// reports the root mount id, the core carries it, the enumerate lowers by it.
  #[tokio::test(flavor = "multi_thread")]
  async fn descending_does_not_descend_a_same_device_bind_mount() {
    let rig = inotify_rig_mnt(42);
    // `bound` shares the device (1) but sits on mount 77 (a bind); `here` is on the
    // root mount (42). Both are directories with children the walk would descend if
    // it entered them.
    rig.fs.put_on_mount("/r/bound", FileKind::Dir, 20, 77);
    rig.fs.put("/r/bound/hidden.txt", FileKind::File, 21);
    rig.fs.put("/r/here", FileKind::Dir, 22);
    rig.fs.put("/r/here/seen.txt", FileKind::File, 23);
    let _scope = watch(&rig, "/r").await;

    // The in-root child directory `here` is enumerated (descended); the bind `bound`
    // never is.
    settle(|| {
      rig
        .fs
        .enumerates()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/here"))
    })
    .await;
    let enumerates = rig.fs.enumerates();
    assert!(
      !enumerates
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/bound")),
      "a same-device bind on a different mount is never descended: {enumerates:?}"
    );
    let arms = rig.fs.arms();
    assert!(
      arms
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/here")),
      "the same-mount child directory is armed: {arms:?}"
    );
    assert!(
      !arms
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/bound")),
      "the bind-mount directory is delivered but never armed: {arms:?}"
    );
  }

  /// A live inotify record injected through the real transport reaches the
  /// consumer as a depth-one change on the right anchor.
  #[tokio::test(flavor = "multi_thread")]
  async fn live_inotify_records_flow() {
    let rig = inotify_rig();
    let _scope = watch(&rig, "/r").await;
    // The root's Monitor watch is the first minted id under this scope; the
    // arm recording carries it.
    settle(|| !rig.fs.enumerates().is_empty()).await;
    let root_watch = rig
      .fs
      .enumerates()
      .first()
      .map(|(watch, _)| *watch)
      .expect("the root enumerated");
    rig.fs.put("/r/new.txt", FileKind::File, 20);
    rig
      .fs
      .send_inotify_batch("/r", vec![attributed(&[root_watch], IN_CREATE, b"new.txt")]);
    loop {
      let (_scope, change) = next_event(&rig).await;
      if change.kind().is_created() && change.location() == &loc(&["new.txt"]) {
        break;
      }
    }
  }

  /// A kernel IN_IGNORED for a child anchor resolves it end to end: the
  /// Monitor drops the node and the executor is told to disarm it.
  #[tokio::test(flavor = "multi_thread")]
  async fn kernel_teardown_disarms_the_child() {
    let rig = inotify_rig();
    rig.fs.put("/r/sub", FileKind::Dir, 11);
    let _scope = watch(&rig, "/r").await;
    settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/sub"))
    })
    .await;
    let child = rig
      .fs
      .arms()
      .iter()
      .find(|(_, p)| p == std::path::Path::new("/r/sub"))
      .map(|(watch, _)| *watch)
      .expect("child armed");
    const IN_IGNORED: u32 = 0x0000_8000;
    rig.fs.send_inotify_batch(
      "/r",
      vec![RawLinuxEvent::Inotify {
        anchors: vec![child],
        event: RawInotifyEvent {
          wd: 2,
          mask: InotifyMask(IN_IGNORED),
          cookie: 0,
          name: None,
        },
      }],
    );
    settle(|| rig.fs.disarms().contains(&child)).await;
  }

  /// Object-correct arming, end to end on the fake platform: an object replaced
  /// between the enumerate that discovered it and its arm is refused as `Gone`,
  /// and the Monitor's drop+rescan heals. The enumerate reports the child at its
  /// ORIGINAL inode (so the Monitor node carries that identity), while the object
  /// currently at the path has a DIFFERENT inode — modeling a rename/replace that
  /// slipped into the enumerate→arm window. The arm's identity check catches it,
  /// so the watch never installs on the wrong object.
  #[tokio::test(flavor = "multi_thread")]
  async fn arm_identity_mismatch_is_gone_and_rescans() {
    let rig = inotify_rig();
    // The object at /r/sub is inode 99, but the cold enumerate reports it as
    // inode 11 (the identity the Monitor descends with).
    rig.fs.put("/r/sub", FileKind::Dir, 99);
    rig.fs.enumerate_answer(
      "/r",
      crate::core::RawEnumerate::Listed {
        entries: vec![crate::core::RawDirEntry {
          name: b"sub".to_vec(),
          kind: FileKind::Dir,
          dev: 1,
          ino: 11,
          mnt_id: None,
        }],
        complete: true,
      },
    );
    let _scope = watch(&rig, "/r").await;

    // The /r/sub arm is attempted with the stale identity (11) against the live
    // object (99): a mismatch, refused as Gone.
    settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/sub"))
    })
    .await;

    // The Monitor heals through a rescan (the dropped subtree's coverage is
    // restored by the standing terminal reconciliation).
    let mut saw_rescan = false;
    for _ in 0..8 {
      let (_scope, change) = next_event(&rig).await;
      if change.kind().is_rescan() {
        saw_rescan = true;
        break;
      }
    }
    assert!(
      saw_rescan,
      "a mismatched arm drops the subtree and rescans to heal"
    );
  }

  /// Close with an enumerate parked on the blocking pool: the listing is
  /// droppable (no OS resource — the Monitor node dies with its scope), so
  /// close resolves quiescent without waiting for it.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_with_in_flight_enumerate_is_quiescent() {
    let rig = inotify_rig();
    let hold = rig.fs.hold_enumerates();
    let _scope = watch(&rig, "/r").await;
    settle(|| !rig.fs.enumerates().is_empty() || rig.fs.spawns() > 0).await;
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let quiesced = on_reply.await.expect("close replies");
    assert_eq!(quiesced, 0, "an in-flight enumerate never blocks close");
    hold.release();
  }

  /// Close with an arm parked on the blocking pool: equally droppable — the
  /// wd (if the arm did install one) is reclaimed when the scope's stream
  /// teardown closes the source fd.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_with_in_flight_arm_is_quiescent() {
    let rig = inotify_rig();
    rig.fs.put("/r/sub", FileKind::Dir, 11);
    // The ROOT arm must complete — registration resolves on it — so gate the
    // cold listing instead, and only then gate arms: the child arm the
    // released listing queues is the one that parks.
    let enum_hold = rig.fs.hold_enumerates();
    let _scope = watch(&rig, "/r").await;
    let hold = rig.fs.hold_arms();
    enum_hold.release();
    // Wait until the cold listing landed (the child arm it queued is parked).
    settle(|| !rig.fs.enumerates().is_empty()).await;
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let quiesced = on_reply.await.expect("close replies");
    assert_eq!(quiesced, 0, "an in-flight arm never blocks close");
    hold.release();
  }

  /// The tree-equality storm under the descending profile: the fake driver
  /// services enumerates against the fake tree, arms fail sporadically, and
  /// listings degrade — the consumer's reconstructed view still converges.
  ///
  /// One seed under miri, for the address-space reason `storm_no_silent_loss_
  /// converges` documents.
  #[tokio::test(flavor = "multi_thread")]
  async fn descending_storm_converges() {
    let default_seeds: u64 = if cfg!(miri) { 1 } else { 8 };
    let seeds: u64 = std::env::var("TRIBUTARY_FS_STORM_SEEDS")
      .ok()
      .and_then(|v| v.parse().ok())
      .unwrap_or(default_seeds);
    for seed in 1..=seeds {
      descending_storm_seed(seed).await;
    }
  }

  async fn descending_storm_seed(seed: u64) {
    let rig = inotify_rig();
    let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(7);
    let mut next_ino = 100u64;
    for i in 0..(1 + xorshift(&mut s) % 3) {
      rig.fs.put(format!("/r/d{i}"), FileKind::Dir, 50 + i);
    }
    let _scope = watch(&rig, "/r").await;
    let mut view: BTreeSet<PathBuf> = BTreeSet::new();
    let mut last_epoch: Option<Epoch> = None;
    let mut last_root: Option<PathBuf> = None;
    let mut live: Vec<PathBuf> = Vec::new();

    for _ in 0..24 {
      match xorshift(&mut s) % 6 {
        0 | 1 => {
          next_ino += 1;
          let dir = if xorshift(&mut s).is_multiple_of(2) {
            "/r"
          } else {
            "/r/d0"
          };
          let path = PathBuf::from(format!("{dir}/f{next_ino}"));
          rig.fs.put(&path, FileKind::File, next_ino);
          live.push(path);
          // The mutation's report is a loss: the in-order signal must cover
          // it (the descending re-arm enumerates the tree back into view).
          rig.fs.send_lossy("/r");
        }
        2 if !live.is_empty() => {
          let i = (xorshift(&mut s) as usize) % live.len();
          let path = live.swap_remove(i);
          rig.fs.remove(&path);
          rig.fs.send_lossy("/r");
        }
        3 => {
          // A degraded (Partial) listing races the next re-arm; the bounded
          // retry re-reads the honest tree.
          rig.fs.enumerate_answer(
            "/r",
            crate::core::RawEnumerate::Listed {
              entries: Vec::new(),
              complete: false,
            },
          );
          rig.fs.send_lossy("/r");
        }
        4 => {
          // A sporadic arm failure: the Monitor drops the subtree and
          // rescans; the next re-arm (fresh default outcome) recovers it.
          rig
            .fs
            .fail_watch_at("/r/d0", tributary_proto::WatchError::NoSpace);
          rig.fs.send_lossy("/r");
        }
        _ => {
          rig.fs.send_lossy("/r");
        }
      }
      // Sometimes-lagging consumer.
      if xorshift(&mut s).is_multiple_of(3) {
        for _ in 0..(xorshift(&mut s) % 4) {
          match tokio::time::timeout(Duration::from_millis(100), rig.events.recv()).await {
            Ok(Ok((_, root, change))) => {
              apply_descending(
                &rig,
                &mut view,
                &mut last_epoch,
                &mut last_root,
                &root,
                &change,
              );
            }
            _ => break,
          }
        }
      }
      tokio::task::yield_now().await;
    }
    // Heal the sporadic arm failure and settle.
    rig.fs.alias_watch_at("/r/d0");
    rig.fs.send_lossy("/r");
    for _ in 0..25 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    while let Ok(Ok((_, root, change))) =
      tokio::time::timeout(Duration::from_millis(200), rig.events.recv()).await
    {
      apply_descending(
        &rig,
        &mut view,
        &mut last_epoch,
        &mut last_root,
        &root,
        &change,
      );
    }
    let tree = rig.fs.files_under("/r");
    assert_eq!(
      view, tree,
      "seed {seed}: the reconstructed view converges to the tree"
    );
  }

  /// The KR storm's reconstruction, with one descending addition: a `Rescan`
  /// re-reads the fake tree under its location (cold inventories then
  /// re-deliver what the re-read missed — extra `Created`s are idempotent).
  fn apply_descending(
    rig: &Rig,
    view: &mut BTreeSet<PathBuf>,
    last_epoch: &mut Option<Epoch>,
    last_root: &mut Option<PathBuf>,
    root: &Path,
    change: &Change,
  ) {
    apply(rig, view, last_epoch, last_root, root, change);
  }

  /// An inotify rig writing transitions into `registry`, for the deferred-grant
  /// never-live assertions.
  fn inotify_rig_with(registry: RecordingRegistry) -> Rig {
    let fs = FakeFs::new(1);
    fs.put("/r", FileKind::Dir, 1);
    fs.spawn_backend(BackendKind::Inotify);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (reap_tx, reap_rx) = async_channel::unbounded();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    tokio::spawn(run::<TokioRuntime, FakeFs>(
      inotify_config(),
      fs.clone(),
      cmd_rx,
      reap_rx,
      ev_tx,
      registry,
    ));
    Rig {
      fs,
      commands: cmd_tx,
      cookie_removes: reap_tx,
      events: ev_rx,
    }
  }

  /// A descending scope is publicly live only once its ROOT ARM SUCCEEDS — the
  /// deferred grant commits there, so a FAILED root arm answers the caller `Err`
  /// and emits NOTHING. Without the deferred-aware fence the Monitor's root-watch
  /// failure would promote a terminal `Rescan` and DELIVER it (the scope's `root`
  /// is populated at spawn), a public event for a registration whose caller never
  /// got a handle. Draining well past every timer deadline still yields zero
  /// events — a never-live scope arms no dying-retry either.
  #[tokio::test(flavor = "multi_thread")]
  async fn failed_root_arm_answers_err_and_emits_nothing() {
    let registry = RecordingRegistry::default();
    let rig = inotify_rig_with(registry.clone());
    // The ROOT arm fails: the object vanished between the validated spawn and
    // the (absolute-path) open.
    rig
      .fs
      .fail_watch_at("/r", tributary_proto::WatchError::NotFound);

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
    let err = on_reply
      .await
      .expect("the watch replies")
      .expect_err("a failed root arm resolves the caller Err");
    assert!(
      matches!(err, WatchRootError::NotFound { .. }),
      "the arm failure lowers to the registration vocabulary: {err:?}"
    );

    // The scope went registry-live at spawn (before the arm), then dead when the
    // failed arm tore it down — reclaimed, never lingering.
    settle(|| !registry.dead().is_empty()).await;
    let scope = registry
      .live()
      .first()
      .map(|(scope, _, _)| *scope)
      .expect("the scope was recorded live at spawn");
    assert_eq!(
      registry.dead(),
      [scope],
      "a failed-root-arm scope is reclaimed via scope_dead"
    );

    // ZERO public events: the never-live fence dropped the Monitor's internal
    // failure Rescan, so nothing was ever queued. A never-live scope promotes no
    // terminal Rescan either, so there is no dying-retry timer to leak through —
    // draining under real-clock timeouts stays empty.
    for _ in 0..10 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
      tokio::time::timeout(Duration::from_millis(200), rig.events.recv())
        .await
        .is_err(),
      "a never-publicly-live scope emits no event, ever"
    );
  }

  /// Closing while a root arm is still PENDING keeps the scope silent: the arm
  /// never resolves, so the scope never became publicly live — the deferred grant
  /// resolves `Err` at teardown and the fence drops any Monitor bookkeeping.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_during_pending_root_arm_stays_silent() {
    let registry = RecordingRegistry::default();
    let rig = inotify_rig_with(registry.clone());
    // Hold every arm on the blocking pool: the ROOT arm parks, so the scope is
    // spawned-and-registry-live but not yet publicly live.
    let hold = rig.fs.hold_arms();

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
    // Wait until the scope is spawned (registry-live) with its root arm parked.
    settle(|| !registry.live().is_empty()).await;

    let (creply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: creply })
      .await
      .unwrap();
    let _ = on_close.await.expect("close replies");
    hold.release();

    // The caller never receives a handle — the pending grant resolves to a
    // failure (a sent `Err`, or the reply sender dropped at close, which is
    // `Canceled`); either way it is NOT an `Ok(grant)`, so nothing went publicly
    // live. And no public event was ever emitted.
    let resolved = on_reply.await;
    assert!(
      !matches!(resolved, Ok(Ok(_))),
      "a scope closed before its root armed never hands back a live grant: {resolved:?}"
    );
    assert!(
      matches!(
        tokio::time::timeout(Duration::from_millis(200), rig.events.recv()).await,
        Err(_) | Ok(Err(_))
      ),
      "a scope closed before going publicly live emits nothing"
    );
  }

  /// A SUCCESSFUL root arm still delivers normally — the fence opens exactly at
  /// the arm, so the cold-inventory `Created`s (and later live records) flow.
  /// The regression guard that the deferred-aware fence did not over-tighten.
  #[tokio::test(flavor = "multi_thread")]
  async fn successful_root_arm_delivers_normally() {
    let rig = inotify_rig();
    rig.fs.put("/r/present.txt", FileKind::File, 10);
    let _scope = watch(&rig, "/r").await;
    // The cold inventory after the successful root arm reaches the consumer.
    loop {
      let (_scope, change) = next_event(&rig).await;
      if change.kind().is_created() && change.location() == &loc(&["present.txt"]) {
        break;
      }
    }
  }

  mod cover_fence {
    //! The set-cover effect-completion fence through the REAL loop: an acked
    //! reconcile's reply parks under its fence and resolves at SETTLE — when
    //! the grow's re-arm work has quiesced — never at effect-queue time. The
    //! core's fence table is unit-covered in `core/tests.rs`; these cells pin
    //! the driver wiring around it (parking, loop-top resolution, close).

    use super::*;
    use crate::watcher::{CoverOutcome, SkipReason};

    /// Sends an awaited `SetCover`, handing back its parked acknowledgement.
    async fn send_set_cover(
      rig: &Rig,
      scope: ScopeId,
      retained: &[&str],
    ) -> futures_channel::oneshot::Receiver<CoverOutcome> {
      let (reply, ack) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SetCover {
          scope,
          retained: retained.iter().map(PathBuf::from).collect(),
          reply: Some(reply),
        })
        .await
        .unwrap();
      ack
    }

    /// Awaits a parked acknowledgement (pinned or not), bounded.
    async fn resolved(
      ack: impl std::future::Future<Output = Result<CoverOutcome, futures_channel::oneshot::Canceled>>,
    ) -> CoverOutcome {
      tokio::time::timeout(Duration::from_secs(10), ack)
        .await
        .expect("the fence settles within the deadline")
        .expect("the driver answers the parked reply")
    }

    /// How many arms have been executed at `path`.
    fn arms_at(rig: &Rig, path: &str) -> usize {
      rig
        .fs
        .arms()
        .iter()
        .filter(|(_, p)| p == std::path::Path::new(path))
        .count()
    }

    /// A live descending rig over `/r` with the given child directories,
    /// whose cold discovery has FULLY quiesced (every child's cold read
    /// landed) — so a later grow can never coalesce into an in-flight cold
    /// read and degrade a window these cells expect clean.
    async fn covered_rig(children: &[(&str, u64)]) -> (Rig, ScopeId) {
      let fs = FakeFs::new(1);
      for (path, ino) in children {
        fs.put(path, FileKind::Dir, *ino);
      }
      let rig = inotify_rig_fs(fs);
      let scope = watch(&rig, "/r").await;
      settle(|| {
        let enumerates = rig.fs.enumerates();
        children.iter().all(|(path, _)| {
          enumerates
            .iter()
            .any(|(_, p)| p == std::path::Path::new(path))
        })
      })
      .await;
      (rig, scope)
    }

    /// The sync cookie's write is parked on the SAME settle fence a cover ack
    /// rides: under a descending backend with re-arm work in flight, the
    /// cookie must not land until the coverage quiesces — otherwise a
    /// pre-sync change inside a mid-re-arm subtree was never kernel-reported
    /// and no queue ordering covers it. Once the re-arm settles, the write
    /// lands and the caller gets the cookie's path.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_cookie_write_parks_on_the_settle_fence() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      // Stall the grow: /r/drop's re-install parks on the blocking pool, so
      // the scope is NOT settled.
      let hold = rig.fs.hold_arms();
      let _ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;

      let (reply, mut on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: ".tributaries-sync-1-2-3".to_owned(),
          reply,
        })
        .await
        .unwrap();
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(&mut on_reply).is_pending(),
        "the cookie write waits for the coverage to settle"
      );
      assert!(
        rig.fs.cookie_writes().is_empty(),
        "nothing was written while the re-arm was in flight"
      );

      hold.release();
      let path = on_reply
        .await
        .expect("the driver replies")
        .expect("the write lands once settled");
      assert_eq!(path, PathBuf::from("/r/.tributaries-sync-1-2-3"));
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// Shrinks the live rig to `{/r/keep}` and awaits the ack: a prune grows
    /// nothing, so the fence settles at the next loop top, clean.
    async fn shrunk_to_keep(rig: &Rig, scope: ScopeId) {
      let ack = send_set_cover(rig, scope, &["/r/keep"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "a prune-only reconcile settles clean"
      );
    }

    /// The fence's core promise at the driver level: the ack PENDS while the
    /// grow's re-arm work is in flight — here an arm parked on the blocking
    /// pool — and resolves `Applied` only once that work lands. Under the old
    /// queue-time ack this future resolved before the arm even dispatched.
    #[tokio::test(flavor = "multi_thread")]
    async fn ack_pends_until_the_grow_settles_then_applies() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      // Hold the grow's arms: the root's re-arm read runs (enumerates are not
      // held), but re-installing /r/drop parks — the fence must pend with it.
      let hold = rig.fs.hold_arms();
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      let mut ack = Box::pin(ack);
      // Generous scheduler slices: the reconcile applies, its re-arm read
      // completes, the /r/drop arm parks — and the ack still pends.
      for _ in 0..50 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(ack.as_mut()).is_pending(),
        "the ack pends while the grow's arm is parked — settle-time, not queue-time"
      );
      hold.release();
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the released arm lands, the cascade quiesces, the clean window applies"
      );
    }

    /// A cancel storm against a STALLED grow stays bounded and healthy: each
    /// issued-then-dropped `set_cover` ack's fence is abandoned on both sides
    /// of the driver/core seam at the next loop-top prune (the sender AND the
    /// core's pending tuple), the loss memory is untouched, and a live caller
    /// issued after the storm still resolves `Applied` once the stall lifts.
    /// Fail-on-old: only the sender was pruned — one core pending tuple
    /// accumulated per processed request for the whole stall.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_acks_under_a_stalled_grow_stay_bounded_and_resolve_the_live_caller() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      // Stall the grow: /r/drop's re-install parks on the blocking pool.
      let hold = rig.fs.hold_arms();
      // The storm: issue-and-cancel many acked reconciles against the stall.
      for _ in 0..64 {
        let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
        drop(ack);
        tokio::task::yield_now().await;
      }
      // The live caller arrives after the storm and pends on the same stall.
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      let mut ack = Box::pin(ack);
      for _ in 0..50 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(ack.as_mut()).is_pending(),
        "the live ack pends on the stalled grow"
      );
      hold.release();
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the storm's abandoned fences never poison the live caller's clean settle"
      );
    }

    /// A failed grow arm is loss inside the window: the fence settles
    /// `Degraded`, and the covering `Rescan` that dominates the gap reaches
    /// the consumer in-band.
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_grow_arm_settles_degraded() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      rig
        .fs
        .fail_watch_at("/r/drop", tributary_proto::WatchError::NoSpace);

      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Degraded,
        "a failed re-arm is signaled loss, not a clean apply"
      );
      let mut saw_rescan = false;
      for _ in 0..8 {
        let (_scope, change) = next_event(&rig).await;
        if change.kind().is_rescan() {
          saw_rescan = true;
          break;
        }
      }
      assert!(
        saw_rescan,
        "the degraded window's covering Rescan is delivered"
      );
    }

    /// The applied-cover-lie regression at the driver level: after a lossy
    /// settle the cover is rewound, so RE-ISSUING the same cover computes a
    /// non-empty broadening delta and the grow re-attempts its arms — here
    /// healed, so the re-issue settles `Applied` over real coverage.
    #[tokio::test(flavor = "multi_thread")]
    async fn reissue_after_lossy_settle_re_attempts_the_arms() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      rig
        .fs
        .fail_watch_at("/r/drop", tributary_proto::WatchError::NoSpace);
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(resolved(ack).await, CoverOutcome::Degraded);

      // Re-issue the SAME cover after healing the arm: without the settle
      // rewind the delta would be empty — no arm attempted, an instant clean
      // settle over the hole the failed arm left.
      rig.fs.heal_watch_at("/r/drop");
      let attempts = arms_at(&rig, "/r/drop");
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      // The re-attempted grow HEALS the standing arm-refused hole, and a heal
      // window owes the hole's dark interval a closing Rescan — so this
      // window is honestly Degraded (the caller's contract: re-issue once
      // more), never a clean claim over darkness the failed arm left.
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Degraded,
        "the grow that heals the hole degrades — its closing Rescan is owed"
      );
      assert!(
        arms_at(&rig, "/r/drop") > attempts,
        "the rewound cover made the delta non-empty — the arm was re-attempted"
      );

      // The NEXT re-issue finds no hole and no fresh installs — survivors
      // only — and settles clean: the degrade is self-resolving.
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the hole-free re-issue settles clean over re-attempted coverage"
      );
    }

    /// Supersession: two acked covers of one root queued back to back — the
    /// second while the first's re-arm work is still parked — both pend, both
    /// resolve at the shared settle, and the latest cover's subtree holds a
    /// live watch again. (FIFO application and latest-wins bookkeeping are
    /// core-pinned; this cell pins the driver's one-fence-one-reply routing.)
    #[tokio::test(flavor = "multi_thread")]
    async fn superseding_acks_resolve_at_the_shared_settle() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12), ("/r/other", 13)]).await;
      shrunk_to_keep(&rig, scope).await;
      let other_arms = arms_at(&rig, "/r/other");

      let hold = rig.fs.hold_arms();
      let first = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      // The first grow's re-arm READ of the root must land before the second
      // cover applies: a cover racing an in-flight re-arm read dirties it,
      // and the dirtied read's completion stands a Rescan that would
      // (honestly) degrade both windows — this cell wants the clean shape.
      // The read having FED the core is observable as the survivor cascade's
      // own read (its second /r/keep enumerate), which that feeding queues.
      settle(|| {
        rig
          .fs
          .enumerates()
          .iter()
          .filter(|(_, p)| p == std::path::Path::new("/r/keep"))
          .count()
          >= 2
      })
      .await;
      let second = send_set_cover(&rig, scope, &["/r/keep", "/r/drop", "/r/other"]).await;
      let mut first = Box::pin(first);
      let mut second = Box::pin(second);
      for _ in 0..50 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(first.as_mut()).is_pending(),
        "the first ack pends on the held grow"
      );
      assert!(
        futures_util::poll!(second.as_mut()).is_pending(),
        "the superseding ack pends on the same scope settle"
      );
      hold.release();
      assert_eq!(resolved(first).await, CoverOutcome::Applied);
      assert_eq!(resolved(second).await, CoverOutcome::Applied);
      assert!(
        arms_at(&rig, "/r/other") > other_arms,
        "the latest cover's /r/other was re-armed"
      );
    }

    /// Close mid-fence DROPS the parked reply (the ratified semantics): the
    /// caller's ack resolves as a cancellation — `UnwatchError::Closed` at the
    /// watcher surface — never as a fabricated outcome over a torn-down
    /// driver.
    #[tokio::test(flavor = "multi_thread")]
    async fn close_mid_fence_drops_the_parked_reply() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      let hold = rig.fs.hold_arms();
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      // The reconcile has been applied once its re-arm read of the root is
      // re-executed; the /r/drop arm it queued is parked on the hold.
      settle(|| {
        rig
          .fs
          .enumerates()
          .iter()
          .filter(|(_, p)| p == std::path::Path::new("/r"))
          .count()
          >= 2
      })
      .await;

      let (creply, on_close) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Close { reply: creply })
        .await
        .unwrap();
      let _ = on_close.await.expect("close replies");
      assert!(
        ack.await.is_err(),
        "a fence still pending at close drops its reply — the watcher maps it to Closed"
      );
      hold.release();
    }

    /// A kernel-recursive scope answers `Recursive` IMMEDIATELY — its
    /// whole-subtree stream never narrowed, so there is no reconcile to fence
    /// — and no per-directory arm or disarm is ever attempted.
    #[tokio::test(flavor = "multi_thread")]
    async fn kernel_recursive_scope_answers_recursive_immediately() {
      // The plain rig IS the kernel-recursive shape: an FsEvents profile with
      // FsEvents-claiming spawns (the hermetic default).
      let rig = rig_with_capacity(64);
      let scope = watch(&rig, "/r").await;
      let ack = send_set_cover(&rig, scope, &["/r/keep"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Recursive,
        "kernel-recursive coverage never narrowed — reported, not fenced"
      );
      assert!(
        rig.fs.arms().is_empty() && rig.fs.disarms().is_empty(),
        "a kernel-recursive scope holds no per-directory watches to reconcile"
      );

      // An unknown scope is the immediate driver-side skip.
      let ghost = ScopeId::new(core::num::NonZeroU64::new(999).unwrap());
      let ack = send_set_cover(&rig, ghost, &["/r/keep"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Skipped(SkipReason::UnknownRoot),
        "an unknown scope is skipped at command time"
      );
    }

    /// How many enumerates have been executed at `path`.
    fn enumerates_at(rig: &Rig, path: &str) -> usize {
      rig
        .fs
        .enumerates()
        .iter()
        .filter(|(_, p)| p == std::path::Path::new(path))
        .count()
    }

    /// Out-of-window coverage loss through the public API: an overflow lands
    /// AFTER a clean settle with NO reconcile pending, then the SAME cover is
    /// re-issued. The loss must degrade the recorded claim, so the re-issue
    /// re-attempts real arm work and its ack inherits the still-unobserved
    /// loss (`Degraded`); a second re-issue then settles `Applied`. Fail-on-old
    /// twice over: without the out-of-window handling the first re-issue
    /// computes an EMPTY broadening delta (no work) and settles `Applied` over
    /// whatever the overflow cost, and the second re-issue re-arms nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn out_of_window_overflow_degrades_then_reissue_applies() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      // Grow back to the full pair and settle clean: the recorded claim is
      // truthful and no fence entry remains.
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(resolved(ack).await, CoverOutcome::Applied);

      // Hold enumerates so the overflow's recovery re-arm cannot quiesce: the
      // loss memory stays unobserved until the re-issued cover's fence opens
      // into it (the deterministic stand-in for a reconcile racing the loss).
      let hold = rig.fs.hold_enumerates();
      rig.fs.send_lossy("/r");
      // The overflow's covering Rescan reaching the consumer proves the loss
      // was routed (and, with the fix, the claim degraded).
      loop {
        let (_scope, change) = next_event(&rig).await;
        if change.kind().is_rescan() {
          break;
        }
      }

      // Re-issue the IDENTICAL cover: the degraded claim yields a full
      // broadening delta, so the reconcile re-arms the retained set; its fence
      // shares the loss's still-unobserved window.
      let first = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      let mut first = Box::pin(first);
      for _ in 0..25 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(first.as_mut()).is_pending(),
        "the re-issue pends on the held recovery — never an instant clean settle over the loss"
      );
      hold.release();
      assert_eq!(
        resolved(first).await,
        CoverOutcome::Degraded,
        "the first re-issue inherits the unobserved out-of-window loss"
      );

      // The second re-issue starts a fresh window against the (still degraded)
      // claim: real re-arm work again, settling clean this time.
      let keep_reads = enumerates_at(&rig, "/r/keep");
      let drop_reads = enumerates_at(&rig, "/r/drop");
      let second = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(second).await,
        CoverOutcome::Applied,
        "the clean re-issue re-proves the claim"
      );
      assert!(
        enumerates_at(&rig, "/r/keep") > keep_reads && enumerates_at(&rig, "/r/drop") > drop_reads,
        "the re-issue re-arms the FULL retained set against the degraded claim"
      );
    }

    /// A saturated, continuously-refilled command channel must not starve op
    /// completions: op results are polled before commands, so a held grow's
    /// arm still lands, its scope still settles, and the awaited ack still
    /// resolves while the spam continues. Under the old command-first arm
    /// order this ack hangs until the `resolved` deadline trips: each spam
    /// command is a reply-less SetCover whose reconcile walks the scope's
    /// whole watch table (the cover here spans dozens of watches), so
    /// consuming one costs far more than producing one and the slot-filling
    /// spammers keep the command branch ready at every loop-top poll — the
    /// starvation is a cost ratio, which is why cheap spam (a ghost unwatch)
    /// cannot reproduce it: the tight consume loop out-races production and
    /// the branch reads not-ready often enough for op results to slip in.
    #[tokio::test(flavor = "multi_thread")]
    async fn command_flood_does_not_starve_op_completions() {
      use std::sync::atomic::{AtomicBool, Ordering};

      // A scope wide enough that every spam reconcile's watch-table walk has
      // real cost: keep + drop + 30 filler directories. The cold inventory
      // (32 `Created`s) stays under the rig's 64-slot event channel, so no
      // lag Rescan can pollute the fence verdict.
      let filler: Vec<String> = (0..30).map(|i| format!("/r/d{i:02}")).collect();
      let mut children: Vec<(&str, u64)> = vec![("/r/keep", 11), ("/r/drop", 12)];
      children.extend(
        filler
          .iter()
          .enumerate()
          .map(|(i, p)| (p.as_str(), 100 + i as u64)),
      );
      let (rig, scope) = covered_rig(&children).await;
      let full_cover: Vec<&str> = children.iter().map(|(p, _)| *p).collect();
      let without_drop: Vec<&str> = full_cover
        .iter()
        .copied()
        .filter(|p| *p != "/r/drop")
        .collect();

      // Prune /r/drop only (instant clean settle), then grow it back with the
      // arms held: the ack now waits on op completions — the root's re-arm
      // cascade and the parked /r/drop arm — that the flood will try to starve.
      let ack = send_set_cover(&rig, scope, &without_drop).await;
      assert_eq!(resolved(ack).await, CoverOutcome::Applied);
      let hold = rig.fs.hold_arms();
      let ack = send_set_cover(&rig, scope, &full_cover).await;
      // The reconcile has been applied once its re-arm read of the root
      // re-executed (its second /r enumerate); the /r/drop arm it queued is
      // parked on the hold.
      settle(|| enumerates_at(&rig, "/r") >= 2).await;

      // Saturate the 16-slot command channel with reply-less SetCovers of the
      // scope's own full cover — each reconcile re-walks every watch against
      // every retained prefix and changes nothing (the delta against the
      // recorded cover is empty, nothing is outside it, no fence is opened) —
      // continuously refilled from tasks that fill EVERY free slot per wakeup.
      let stop = std::sync::Arc::new(AtomicBool::new(false));
      let spam_cover: Vec<PathBuf> = full_cover.iter().map(PathBuf::from).collect();
      let mut spammers = Vec::new();
      for _ in 0..4 {
        let commands = rig.commands.clone();
        let stop = std::sync::Arc::clone(&stop);
        let spam_cover = spam_cover.clone();
        spammers.push(tokio::spawn(async move {
          while !stop.load(Ordering::Relaxed) {
            loop {
              match commands.try_send(Command::SetCover {
                scope,
                retained: spam_cover.clone(),
                reply: None,
              }) {
                Ok(()) => {}
                Err(async_channel::TrySendError::Full(_)) => break,
                Err(async_channel::TrySendError::Closed(_)) => return,
              }
            }
            tokio::task::yield_now().await;
          }
        }));
      }
      // Let the flood establish before the held op completes.
      tokio::time::sleep(Duration::from_millis(100)).await;
      hold.release();

      // The op results and the settlement make progress under sustained
      // command pressure: the ack resolves within the bounded await.
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "op completions and fence settlements outrank the command flood"
      );
      stop.store(true, Ordering::Relaxed);
      for spammer in spammers {
        let _ = spammer.await;
      }
    }
  }

  /// The descending replace end to end: the new root pre-arms on the NEW
  /// transport (the arms ledger shows it), the commit delivers exactly one
  /// covering Rescan, the rebuild re-arms the new tree, and post-swap
  /// records deliver under the new root on the surviving scope.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_descending_replace_rebinds_on_a_fresh_transport() {
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 20);
    rig.fs.put("/r2/sub", FileKind::Dir, 21);
    let scope = watch(&rig, "/r").await;
    let root_arm = rig.fs.arms().first().cloned().expect("the birth root arm");

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(on_reply.await.expect("driver replies").is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;

    // The pre-arm rode the SAME surviving WatchId to the new root.
    let arms = rig.fs.arms();
    assert!(
      arms
        .iter()
        .any(|(w, p)| *w == root_arm.0 && p == std::path::Path::new("/r2")),
      "the new root pre-armed on the surviving watch id: {arms:?}"
    );

    // The commit's covering Rescan, re-rooted.
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), std::path::Path::new("/r2"));
    assert!(change.kind().is_rescan(), "{change:?}");
    let commit_epoch = change.epoch();

    // The rebuild walked the new tree and re-armed it — announcing nothing.
    settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r2/sub"))
    })
    .await;
    assert!(
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r2/sub")),
      "the rebuild re-arms the new tree: {:?}",
      rig.fs.arms()
    );

    // The rebuild's settle closes the bridge window: a change landing after
    // the commit but before a rebuilt watch armed is recorded by nothing and
    // suppressed by the re-arm read, so the window owes a SECOND root Rescan
    // whose epoch strictly dominates the commit's (replace = commit + close).
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), std::path::Path::new("/r2"));
    assert!(change.kind().is_rescan(), "{change:?}");
    assert!(
      change.epoch() > commit_epoch,
      "the closing Rescan strictly dominates the commit: {change:?}"
    );

    // Post-swap records deliver under the new root.
    rig.fs.send_inotify_batch(
      "/r2",
      vec![attributed(&[root_arm.0], IN_CREATE, b"post.txt")],
    );
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), std::path::Path::new("/r2"));
    assert!(change.kind().is_created());
    assert_eq!(change.location(), &loc(&["post.txt"]));
  }

  /// A refused pre-arm unwinds atomically: the caller gets the typed source
  /// failure, the replacement is torn down inside the accounting, and the
  /// old tree keeps delivering.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_failed_pre_arm_unwinds_and_the_old_tree_survives() {
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 20);
    rig
      .fs
      .fail_watch_at("/r2", tributary_proto::WatchError::NoSpace);
    let scope = watch(&rig, "/r").await;
    let root_arm = rig.fs.arms().first().cloned().expect("the birth root arm");

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    let outcome = on_reply.await.expect("driver replies");
    assert!(
      matches!(outcome, Err(crate::error::ReplaceRootError::Source(_))),
      "{outcome:?}"
    );
    settle(|| rig.fs.shutdowns() == 1).await;
    assert_eq!(rig.fs.shutdowns(), 1, "only the refused replacement died");

    rig.fs.send_inotify_batch(
      "/r",
      vec![attributed(&[root_arm.0], IN_CREATE, b"still.txt")],
    );
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), std::path::Path::new("/r"));
    assert!(change.kind().is_created());
  }

  /// Close lands while the pre-arm is parked on the blocking pool: the sweep
  /// retires the spawned-but-uncommitted replacement inside the counted
  /// accounting — both streams torn down, the replace answered Closed.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_during_the_pre_arm_counts_both_streams() {
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 20);
    let scope = watch(&rig, "/r").await;

    let gate = rig.fs.hold_prearms();
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    // The replacement spawned and its pre-arm is parked.
    settle(|| rig.fs.spawns() == 2).await;

    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    // Close settles while the pre-arm is STILL PARKED: the sweep alone must
    // account for the held replacement (releasing first would race the
    // commit against the close and sometimes swap successfully — a
    // different, also-legal ordering this cell is not about).
    assert!(on_close.await.is_ok(), "close settles");
    settle(|| rig.fs.shutdowns() == 2).await;
    assert_eq!(rig.fs.shutdowns(), 2, "old stream AND held replacement");
    assert!(matches!(
      on_reply.await,
      Ok(Err(crate::error::ReplaceRootError::Closed)) | Err(_)
    ));
    gate.release();
  }

  /// The lowering gate, both diagonals: a replacement resolving to a
  /// different recursiveness than the live scope refuses as
  /// BackendDiverged, the old coverage untouched, the fresh stream retired.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_lowering_flip_is_refused_both_ways() {
    // Descending → kernel-recursive.
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 20);
    let scope = watch(&rig, "/r").await;
    rig.fs.spawn_backend(BackendKind::Fanotify);
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(matches!(
      on_reply.await.expect("driver replies"),
      Err(crate::error::ReplaceRootError::BackendDiverged)
    ));
    settle(|| rig.fs.shutdowns() == 1).await;

    // Kernel-recursive → descending.
    let rig = rig_with_capacity(64);
    rig.fs.put("/r2", FileKind::Dir, 20);
    let scope = watch(&rig, "/r").await;
    rig.fs.spawn_backend(BackendKind::Inotify);
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(matches!(
      on_reply.await.expect("driver replies"),
      Err(crate::error::ReplaceRootError::BackendDiverged)
    ));
    settle(|| rig.fs.shutdowns() == 1).await;
  }

  /// The transport-generation fence: an old-world discovery arm dispatched
  /// before a descending replace, but completing AFTER the swap, must NOT
  /// install on the replacement's fd — it names an old-world path and belongs
  /// to a transport the swap retired. Held on `arm_hold` across the commit
  /// (whose pre-arm rides its own gate), the batch runs against the new
  /// generation and is refused, landing nothing on the new transport.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_stale_discovery_arm_across_a_replace_lands_nothing() {
    const IN_ISDIR: u32 = 0x4000_0000;
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 40);
    rig.fs.put("/r2/child", FileKind::Dir, 41);
    let scope = watch(&rig, "/r").await;
    settle(|| !rig.fs.enumerates().is_empty()).await;
    let root_watch = rig
      .fs
      .enumerates()
      .first()
      .map(|(watch, _)| *watch)
      .expect("the root enumerated");

    // Freeze discovery arms, then discover a new OLD-world directory: its arm
    // batch is dispatched carrying the current (pre-replace) generation and
    // parks here.
    let hold = rig.fs.hold_arms();
    rig.fs.put("/r/newdir", FileKind::Dir, 30);
    rig.fs.send_inotify_batch(
      "/r",
      vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"newdir")],
    );
    for _ in 0..30 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
      !rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/newdir")),
      "the discovery arm is parked, not yet landed"
    );

    // Commit the replace: its pre-arm rides `prearm_hold` (not held), so the
    // swap completes and bumps the transport generation while the discovery
    // batch is still parked on `arm_hold`.
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(on_reply.await.expect("driver replies").is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;

    // Release: the parked old-world batch runs against the NEW generation and
    // is refused, while the rebuild arms the new tree.
    hold.release();
    settle(|| {
      rig
        .fs
        .stale_arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/newdir"))
    })
    .await;
    assert!(
      rig
        .fs
        .stale_arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/newdir")),
      "the stale discovery arm was refused: {:?}",
      rig.fs.stale_arms()
    );
    assert!(
      !rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/newdir")),
      "and it never installed on any transport"
    );
    settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r2/child"))
    })
    .await;
    assert!(
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r2/child")),
      "the rebuild armed the new tree on the new transport"
    );
  }

  /// The barrier-honesty acceptance cells: on the descending backend, a sync
  /// cookie must never dispatch ahead of the covering `Rescan` a
  /// level-persistent deficit owes — a replace-rebuild bridge (C1), a standing
  /// arm-refused or exhausted-read hole (C2/C3, bounded per C4), a held move
  /// source (C5), or a latent coalesced cold read (C6). The umbrella turns any
  /// delivered scope `Rescan` ordered ahead of the cookie's event into
  /// `SyncOutcome::Dominated` through its two proven choke points
  /// (`dominate_pending_syncs`, the `loss_gen` install snapshot), so the
  /// queue-order facts pinned here are exactly the inputs barrier honesty
  /// needs.
  mod barrier_honesty {
    use super::*;
    use crate::os::linux::{RawInotifyEvent, RawLinuxEvent, inotify::decode::InotifyMask};

    const IN_CREATE: u32 = 0x0000_0100;
    const IN_MOVED_FROM: u32 = 0x0000_0040;
    const IN_MOVED_TO: u32 = 0x0000_0080;
    const IN_ISDIR: u32 = 0x4000_0000;

    /// Dispatches a sync without awaiting it, returning the pending reply.
    async fn sync_pending(
      rig: &Rig,
      scope: ScopeId,
      dir: &str,
      name: &str,
    ) -> futures_channel::oneshot::Receiver<Result<PathBuf, crate::error::SyncRootError>> {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from(dir),
          name: name.to_owned(),
          reply,
        })
        .await
        .unwrap();
      on_reply
    }

    /// Dispatches a sync and awaits its cookie path, retrying the retryable
    /// single-flight refusal (the previous write's `CookieWriteDone` is
    /// asynchronous relative to its reply) and bounding the whole await so a
    /// wedged fence fails the cell instead of hanging the suite.
    async fn sync_ok(rig: &Rig, scope: ScopeId, dir: &str, name: &str) -> PathBuf {
      for _ in 0..400 {
        let pending = sync_pending(rig, scope, dir, name).await;
        let outcome = tokio::time::timeout(Duration::from_secs(10), pending)
          .await
          .expect("the sync resolves in bounded time — never parked forever")
          .expect("the driver replies");
        match outcome {
          Ok(path) => return path,
          Err(crate::error::SyncRootError::WriteInFlight) => {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
          }
          Err(other) => panic!("unexpected sync error: {other:?}"),
        }
      }
      panic!("the single-flight gate never admitted the sync");
    }

    /// Asserts the parked sync stays pending across generous scheduler slices
    /// with `written` cookie writes on disk — the fence gate observable.
    async fn assert_parked(
      rig: &Rig,
      pending: &mut futures_channel::oneshot::Receiver<
        Result<PathBuf, crate::error::SyncRootError>,
      >,
      written: usize,
    ) {
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(&mut *pending).is_pending(),
        "the sync is parked on the coverage gate"
      );
      assert_eq!(
        rig.fs.cookie_writes().len(),
        written,
        "no cookie is written while the gate holds"
      );
    }

    /// Reads events until a `Rescan` with an epoch strictly above `floor`
    /// arrives, returning its epoch — the "a fresh covering Rescan precedes
    /// the cookie" observable (the event was queued before the write
    /// dispatched; `next_event`'s deadline fails the cell when it never comes).
    async fn next_rescan_above(rig: &Rig, floor: Epoch) -> Epoch {
      loop {
        let (_scope, change) = next_event(rig).await;
        if change.kind().is_rescan() && change.epoch() > floor {
          return change.epoch();
        }
      }
    }

    /// Drains the event channel until it stays quiet across a settle window,
    /// returning the highest `Rescan` epoch seen (or `floor`).
    async fn drain_to_quiet(rig: &Rig, floor: Epoch) -> Epoch {
      let mut top = floor;
      let mut quiet = 0u32;
      while quiet < 20 {
        match rig.events.try_recv() {
          Ok((_scope, _root, change)) => {
            quiet = 0;
            if change.kind().is_rescan() && change.epoch() > top {
              top = change.epoch();
            }
          }
          Err(_) => {
            quiet += 1;
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
          }
        }
      }
      top
    }

    /// C1 (F1, flagship): a sync issued while the replace rebuild is held
    /// parks; a change landing in the held window (`put` with NO batch — dark:
    /// its directory's watch is not armed yet, and the re-arm read suppresses
    /// it) is covered by the closing `Rescan` the rebuild's settle emits, with
    /// an epoch strictly above the commit's, QUEUED before the cookie write
    /// dispatches. Fails on old: only the commit `Rescan` ever arrives and the
    /// cookie precedes any later `Rescan` — the umbrella would read
    /// `Delivered` over the dark change.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_across_a_replace_rebuild_is_covered_by_the_closing_rescan() {
      let rig = inotify_rig();
      rig.fs.put("/r2", FileKind::Dir, 20);
      rig.fs.put("/r2/a", FileKind::Dir, 21);
      let scope = watch(&rig, "/r").await;
      settle(|| {
        rig
          .fs
          .enumerates()
          .iter()
          .any(|(_, p)| p == std::path::Path::new("/r"))
      })
      .await;

      // Hold the rebuild's reads, then commit the replace.
      let hold = rig.fs.hold_enumerates();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r2"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
          reply,
        })
        .await
        .unwrap();
      assert!(on_reply.await.expect("driver replies").is_ok());
      let (_s, change) = next_event(&rig).await;
      assert!(change.kind().is_rescan(), "the commit Rescan: {change:?}");
      let commit_epoch = change.epoch();

      // The barrier over the held rebuild parks; the dark change lands.
      let mut pending = sync_pending(&rig, scope, "/r2", ".tributaries-sync-c1").await;
      assert_parked(&rig, &mut pending, 0).await;
      rig.fs.put("/r2/a/f", FileKind::File, 30);

      // Release: the rebuild settles, the closing Rescan is queued, and only
      // then does the write dispatch.
      hold.release();
      let path = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .expect("the sync resolves once the rebuild settles")
        .expect("the driver replies")
        .expect("the write lands");
      let closing = next_rescan_above(&rig, commit_epoch).await;
      assert!(closing > commit_epoch);
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// C2 (F2a, flagship): a sync over a standing arm-refused hole completes
    /// (never parked forever) with a FRESH covering `Rescan` — epoch strictly
    /// above the failure's — queued ahead of its cookie write, plus a bounded
    /// heal re-attempt of the refused arm; after the hole heals, the healing
    /// window closes with the closing `Rescan`, and a deficit-free sync adds
    /// no `Rescan` at all. Fails on old: after the failure's one edge
    /// `Rescan`, NOTHING precedes any later sync's cookie — the umbrella would
    /// read `Delivered` over changes in the permanently-dark subtree.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_over_an_arm_refused_hole_resignals_then_heals() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/a", FileKind::Dir, 11);
      fs.fail_watch_at("/r/a", tributary_proto::WatchError::NoSpace);
      let rig = inotify_rig_fs(fs);
      let scope = watch(&rig, "/r").await;

      // Boot: the refused arm's edge Rescan.
      let edge = next_rescan_above(&rig, Epoch::START).await;
      let arms_before = arms_at(&rig, "/r/a");

      // Sync #1 over the standing hole: the refreshing Rescan precedes the
      // cookie, and the heal kick re-attempts the arm (which fails again).
      let path1 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c2-1").await;
      let refreshed = next_rescan_above(&rig, edge).await;
      assert_eq!(
        rig.fs.cookie_writes(),
        vec![path1],
        "the write landed behind the refreshing Rescan"
      );
      settle(|| arms_at(&rig, "/r/a") > arms_before).await;
      assert!(
        arms_at(&rig, "/r/a") > arms_before,
        "the heal kick re-attempted the refused arm"
      );
      let top = drain_to_quiet(&rig, refreshed).await;

      // Heal, then sync #2: its re-signal + heal kick succeed, and the healing
      // window closes with the closing Rescan.
      rig.fs.heal_watch_at("/r/a");
      let _path2 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c2-2").await;
      let after_heal = next_rescan_above(&rig, top).await;
      let quiet = drain_to_quiet(&rig, after_heal).await;

      // Sync #3 over the healed scope: no deficit, no new Rescan.
      let _path3 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c2-3").await;
      let end = drain_to_quiet(&rig, quiet).await;
      assert_eq!(end, quiet, "a deficit-free sync adds no Rescan");
    }

    /// C3 (F2b): a sync over an exhausted-read interior re-signals a fresh
    /// covering `Rescan` and kicks a fresh read per degraded sync; once the
    /// directory reads cleanly, a later sync adds nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_over_an_exhausted_read_interior_resignals_then_heals() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/a", FileKind::Dir, 11);
      // The boot read and its bounded retries all fail: exhaustion.
      for _ in 0..3 {
        fs.enumerate_answer(
          "/r/a",
          crate::core::RawEnumerate::Failed(IoClass::Permission),
        );
      }
      let rig = inotify_rig_fs(fs);
      let scope = watch(&rig, "/r").await;
      settle(|| enumerates_at(&rig, "/r/a") == 3).await;
      assert_eq!(enumerates_at(&rig, "/r/a"), 3, "the read exhausted");
      let floor = drain_to_quiet(&rig, Epoch::START).await;

      // Sync #1: the still-failing interior re-signals and re-reads (the kick
      // burns another failure ladder), staying degraded.
      for _ in 0..3 {
        rig.fs.enumerate_answer(
          "/r/a",
          crate::core::RawEnumerate::Failed(IoClass::Permission),
        );
      }
      let reads = enumerates_at(&rig, "/r/a");
      let _path1 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c3-1").await;
      let refreshed = next_rescan_above(&rig, floor).await;
      settle(|| enumerates_at(&rig, "/r/a") > reads).await;
      assert!(
        enumerates_at(&rig, "/r/a") > reads,
        "the heal kick re-read the interior"
      );
      let top = drain_to_quiet(&rig, refreshed).await;

      // Sync #2: the queued failures are burned — the kicked read now serves
      // the real (clean) directory and the interior heals.
      let _path2 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c3-2").await;
      let after_heal = next_rescan_above(&rig, top).await;
      let quiet = drain_to_quiet(&rig, after_heal).await;

      // Sync #3: healed — no new Rescan.
      let _path3 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c3-3").await;
      let end = drain_to_quiet(&rig, quiet).await;
      assert_eq!(end, quiet, "a healed interior owes later syncs nothing");
    }

    /// C4 (no-loop): a PERMANENTLY broken hole never parks a sync forever —
    /// each of two sequential syncs completes in bounded time, each preceded
    /// by its own fresh covering `Rescan` (strictly increasing epochs): an
    /// unbounded sequence of honest `Dominated` barriers, never a wedged one.
    #[tokio::test(flavor = "multi_thread")]
    async fn syncs_over_a_permanently_broken_hole_stay_bounded() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/a", FileKind::Dir, 11);
      fs.fail_watch_at("/r/a", tributary_proto::WatchError::NoSpace);
      let rig = inotify_rig_fs(fs);
      let scope = watch(&rig, "/r").await;
      let edge = next_rescan_above(&rig, Epoch::START).await;

      let _path1 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c4-1").await;
      let first = next_rescan_above(&rig, edge).await;
      let top = drain_to_quiet(&rig, first).await;
      let _path2 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c4-2").await;
      let second = next_rescan_above(&rig, top).await;
      assert!(second > first, "each sync re-signals its own fresh Rescan");
      assert_eq!(rig.fs.cookie_writes().len(), 2, "both writes landed");
    }

    /// C5 (P3, hold gate): a sync issued mid-rename-hold parks — the
    /// suppressed under-hold record's covering `Rescan` is emitted only at the
    /// pairing — and dispatches only after the pairing's `Rescan` is queued.
    /// The rig's move window is stretched far past the parked-assertion's
    /// real-time slices, so it is the PAIRING that releases the gate, never
    /// the timeout racing the assertion. Fails on old: `rearm_settled` never
    /// counted the hold, the cookie was written mid-window, and the pairing
    /// `Rescan` arrived AFTER it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_mid_hold_parks_until_the_pairing_rescan() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/d", FileKind::Dir, 11);
      fs.spawn_backend(BackendKind::Inotify);
      let (cmd_tx, cmd_rx) = async_channel::bounded(16);
      let (reap_tx, reap_rx) = async_channel::unbounded();
      let (ev_tx, ev_rx) = async_channel::bounded(64);
      tokio::spawn(run::<TokioRuntime, FakeFs>(
        DriverConfig {
          move_window: Duration::from_secs(60),
          ..inotify_config()
        },
        fs.clone(),
        cmd_rx,
        reap_rx,
        ev_tx,
        NullRegistry,
      ));
      let rig = Rig {
        fs,
        commands: cmd_tx,
        cookie_removes: reap_tx,
        events: ev_rx,
      };
      let scope = watch(&rig, "/r").await;
      settle(|| {
        rig
          .fs
          .arms()
          .iter()
          .any(|(_, p)| p == std::path::Path::new("/r/d"))
      })
      .await;
      let root_watch = rig.fs.arms().first().cloned().expect("the root arm").0;
      let d_watch = rig
        .fs
        .arms()
        .iter()
        .find(|(_, p)| p == std::path::Path::new("/r/d"))
        .expect("the child arm")
        .0;
      let floor = drain_to_quiet(&rig, Epoch::START).await;

      // The on-disk rename happens first, then its source half arrives: the
      // watched directory detaches-and-holds for the pairing window.
      rig.fs.remove("/r/d");
      rig.fs.put("/r/e", FileKind::Dir, 11);
      rig.fs.send_inotify_batch(
        "/r",
        vec![RawLinuxEvent::Inotify {
          anchors: vec![root_watch],
          event: RawInotifyEvent {
            wd: 1,
            mask: InotifyMask(IN_MOVED_FROM | IN_ISDIR),
            cookie: 7,
            name: Some(b"d".to_vec()),
          },
        }],
      );
      // A record under the held source: suppressed (stale pre-move path), so
      // its covering Rescan is owed at the pairing.
      rig.fs.send_inotify_batch(
        "/r",
        vec![RawLinuxEvent::Inotify {
          anchors: vec![d_watch],
          event: RawInotifyEvent {
            wd: 2,
            mask: InotifyMask(IN_CREATE),
            cookie: 0,
            name: Some(b"x".to_vec()),
          },
        }],
      );
      // A delivered sentinel behind the hold on the same FIFO stream: seeing
      // it proves the MovedFrom was ingested — the command channel is polled
      // ahead of source batches, so without it the sync below could be
      // admitted (and its fence settle) before the hold even exists.
      rig.fs.send_inotify_batch(
        "/r",
        vec![RawLinuxEvent::Inotify {
          anchors: vec![root_watch],
          event: RawInotifyEvent {
            wd: 1,
            mask: InotifyMask(IN_CREATE),
            cookie: 0,
            name: Some(b"z".to_vec()),
          },
        }],
      );
      loop {
        let (_s, change) = next_event(&rig).await;
        if change.kind().is_created() && change.location() == &loc(&["z"]) {
          break;
        }
      }

      // The barrier mid-hold: parked, nothing written.
      let mut pending = sync_pending(&rig, scope, "/r", ".tributaries-sync-c5").await;
      assert_parked(&rig, &mut pending, 0).await;

      // The pairing resolves the hold: its Rescan (the dirtied-hold cover at
      // the destination) is queued, the re-arm settles, the write dispatches.
      rig.fs.send_inotify_batch(
        "/r",
        vec![RawLinuxEvent::Inotify {
          anchors: vec![root_watch],
          event: RawInotifyEvent {
            wd: 1,
            mask: InotifyMask(IN_MOVED_TO | IN_ISDIR),
            cookie: 7,
            name: Some(b"e".to_vec()),
          },
        }],
      );
      let path = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .expect("the sync resolves once the hold pairs")
        .expect("the driver replies")
        .expect("the write lands");
      let _pairing = next_rescan_above(&rig, floor).await;
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// C6 (P4, latent gate): a loss re-arm folded into an in-flight COLD read
    /// leaves `rearm_settled` true while the re-walk obligation is latent — a
    /// sync issued in that window parks, and dispatches only after the
    /// completion's escalation (and the window's closing `Rescan`) are queued.
    /// Fails on old: the fence settled during the latency and the cookie beat
    /// the escalation.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_during_a_coalesced_latent_rearm_parks_until_escalation() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/sub", FileKind::Dir, 11);
      fs.spawn_backend(BackendKind::Inotify);
      // Hold the boot cold read in flight before the loss arrives.
      let hold = fs.hold_enumerates();
      let rig = inotify_rig_fs(fs);
      let scope = watch(&rig, "/r").await;

      // The loss folds its re-arm into the held cold read (Coalesced).
      rig.fs.send_lossy("/r");
      let (_s, change) = next_event(&rig).await;
      assert!(change.kind().is_rescan(), "the overflow Rescan: {change:?}");
      let overflow_epoch = change.epoch();

      // The barrier inside the latent window: parked, nothing written.
      let mut pending = sync_pending(&rig, scope, "/r", ".tributaries-sync-c6").await;
      assert_parked(&rig, &mut pending, 0).await;

      // Release: the dirtied completion escalates (covering Rescan + counted
      // retry), the suppressed re-walk closes with the closing Rescan, and
      // only then does the write dispatch.
      hold.release();
      let path = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .expect("the sync resolves once the escalation drains")
        .expect("the driver replies")
        .expect("the write lands");
      let escalation = next_rescan_above(&rig, overflow_epoch).await;
      assert!(escalation > overflow_epoch);
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// Arms executed at `path` so far.
    fn arms_at(rig: &Rig, path: &str) -> usize {
      rig
        .fs
        .arms()
        .iter()
        .filter(|(_, p)| p == std::path::Path::new(path))
        .count()
    }

    /// Enumerates executed at `path` so far.
    fn enumerates_at(rig: &Rig, path: &str) -> usize {
      rig
        .fs
        .enumerates()
        .iter()
        .filter(|(_, p)| p == std::path::Path::new(path))
        .count()
    }
  }
}

/// The Linux one-sample enumerate: `list_dir`/`dir_entry_stat` build each
/// `RawDirEntry` from ONE `statx` of the entry, so its `(kind, dev, ino)` and
/// its mount frame are always one object's — never a `(dev, ino)` from one
/// syscall paired with a mount id from another that a rename/bind could split.
/// Real syscalls, so Linux-only (the container `unit` suite).
#[cfg(all(target_os = "linux", not(miri)))]
mod enumerate_one_sample {
  use std::os::unix::fs::MetadataExt;

  use tributary_proto::FileKind;

  use super::super::{dir_entry_stat, list_dir};
  use crate::core::{RawDirEntry, RawEnumerate};

  fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir()
      .canonicalize()
      .expect("canonicalize temp dir")
      .join(format!(
        "tributary-fs-enum-{}-{}-{}",
        tag,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
      ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
  }

  /// A directory and a file classify correctly, and every entry's `(dev, ino)`
  /// equals a path stat of that same object — the one `statx` reports the true
  /// object, not a stale or mispaired identity.
  #[test]
  fn entries_carry_the_true_objects_facts() {
    let dir = scratch("facts");
    std::fs::create_dir(dir.join("sub")).expect("create subdir");
    std::fs::write(dir.join("file"), b"x").expect("create file");

    let RawEnumerate::Listed { entries, complete } = list_dir(&dir) else {
      panic!("a readable directory lists");
    };
    assert!(complete, "the whole directory was read");
    assert_eq!(entries.len(), 2, "both entries were sampled: {entries:?}");

    for entry in &entries {
      let name = std::str::from_utf8(&entry.name).expect("ascii entry name");
      let meta = std::fs::symlink_metadata(dir.join(name)).expect("stat the entry path");
      assert_eq!(entry.dev, meta.dev(), "{name}: device is the object's");
      assert_eq!(entry.ino, meta.ino(), "{name}: inode is the object's");
      let expected_kind = if name == "sub" {
        FileKind::Dir
      } else {
        FileKind::File
      };
      assert_eq!(entry.kind, expected_kind, "{name}: kind from the sample");
    }
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A symlink entry is classified `Symlink` — `AT_SYMLINK_NOFOLLOW` on the one
  /// `statx` reports the link itself, so the enumerate never follows it to a
  /// target that a swap could redirect.
  #[test]
  fn a_symlink_entry_is_not_followed() {
    let dir = scratch("symlink");
    std::fs::create_dir(dir.join("real")).expect("create the target dir");
    std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).expect("create a symlink");

    let RawEnumerate::Listed { entries, .. } = list_dir(&dir) else {
      panic!("a readable directory lists");
    };
    let link = entries
      .iter()
      .find(|e| e.name == b"link")
      .expect("the symlink entry is listed");
    assert_eq!(
      link.kind,
      FileKind::Symlink,
      "the symlink is reported as itself, not its target directory"
    );
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The mount frame is read from the SAME sample as the identity: when a fresh
  /// `statx` reports a mount id for the object, `dir_entry_stat` reports the
  /// identical one (both from the one call's result); when the kernel withholds
  /// it (pre-5.8), both decline it. Either way the frame and the identity are one
  /// object's — the split this fix closes.
  #[test]
  fn the_mount_frame_comes_from_the_identity_sample() {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let dir = scratch("frame");
    std::fs::create_dir(dir.join("sub")).expect("create subdir");
    let sub = dir.join("sub");

    let (kind, _dev, _ino, mnt_id) =
      dir_entry_stat(&sub).expect("the freshly created subdir samples");
    assert_eq!(kind, FileKind::Dir);

    // An independent statx of the same object: its mount-id presence and value
    // must match what the enumerate sample reported — proof the enumerate read
    // the frame from the identity's own result, not a second lookup.
    let stx = statx(
      rustix::fs::CWD,
      &sub,
      AtFlags::SYMLINK_NOFOLLOW,
      StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID),
    )
    .expect("statx the subdir");
    let reference = (stx.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(stx.stx_mnt_id);
    assert_eq!(
      mnt_id, reference,
      "the enumerate's mount frame is the identity sample's own mount id"
    );
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A raced-away entry (nothing at the path) yields `None` — the incomplete
  /// flag drives the retry, and no half-built entry with a bogus identity is
  /// pushed.
  #[test]
  fn a_vanished_entry_samples_to_none() {
    let dir = scratch("vanished");
    let gone = dir.join("gone");
    assert!(
      dir_entry_stat(&gone).is_none(),
      "an absent path produces no entry facts"
    );
    // A directly-built entry list stays a well-formed RawEnumerate.
    let entry = RawDirEntry {
      name: b"present".to_vec(),
      kind: FileKind::File,
      dev: 1,
      ino: 2,
      mnt_id: None,
    };
    assert_eq!(entry.name, b"present");
    let _ = std::fs::remove_dir_all(&dir);
  }
}

/// The replace orchestration end to end over the fake platform: the swap
/// commits make-before-break, the handle/scope survive, the covering Rescan
/// arrives, and post-swap events deliver under the new root.
mod replace {
  use super::*;

  async fn replace(
    rig: &Rig,
    scope: ScopeId,
    new_root: &str,
  ) -> Result<(), crate::error::ReplaceRootError> {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from(new_root),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from(new_root)),
        reply,
      })
      .await
      .unwrap();
    on_reply.await.expect("driver replies")
  }

  #[tokio::test(start_paused = true)]
  async fn the_swap_commits_and_the_scope_survives() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Live pre-swap delivery under the old root.
    rig
      .fs
      .send_batch("/r/sub", vec![ev("/r/sub/pre.txt", created(), 1, 11)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r/sub"));
    assert!(change.kind().is_created());
    let pre_epoch = change.epoch();

    // The swap: /r/sub widens to /r; the commit's covering Rescan arrives
    // on the SAME scope, rooted at the NEW path, on a LATER epoch.
    assert!(replace(&rig, scope, "/r").await.is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope, "the scope survives the swap");
    assert_eq!(root.as_path(), Path::new("/r"), "deliveries re-root");
    assert!(change.kind().is_rescan(), "the covering Rescan: {change:?}");
    assert!(
      change.epoch() > pre_epoch,
      "the epoch is monotone across the swap"
    );

    // Post-swap events flow from the NEW stream under the new root.
    rig
      .fs
      .send_batch("/r", vec![ev("/r/post.txt", created(), 2, 12)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r"));
    assert!(change.kind().is_created());
    assert_eq!(change.location(), &loc(&["post.txt"]));

    // Unwatch after the replace tears exactly the surviving (new) stream.
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(on_reply.await.unwrap(), "the swapped scope is unwatchable");
    settle(|| rig.fs.shutdowns() == 2).await;
    assert_eq!(rig.fs.shutdowns(), 2);
  }

  #[tokio::test(start_paused = true)]
  async fn a_narrowing_replace_commits() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r").await;

    // /r narrows to /r/sub: the exemption clears the self-overlap and the
    // commit re-roots the scope downward.
    assert!(replace(&rig, scope, "/r/sub").await.is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r/sub"));
    assert!(change.kind().is_rescan());

    rig
      .fs
      .send_batch("/r/sub", vec![ev("/r/sub/in.txt", created(), 5, 15)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r/sub"));
    assert_eq!(change.location(), &loc(&["in.txt"]));
  }

  #[tokio::test(start_paused = true)]
  async fn a_late_old_stream_batch_after_the_commit_is_dropped_by_its_lane() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Hold teardowns: the commit retires the old handle but its stream stays
    // alive (its shutdown is parked), so a post-commit batch on the OLD
    // stream is consumable — and must be dropped by the lane gate.
    let gate = rig.fs.hold_teardowns();
    assert!(replace(&rig, scope, "/r").await.is_ok());
    let (s, _root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert!(change.kind().is_rescan(), "the commit Rescan first");

    rig
      .fs
      .send_batch("/r/sub", vec![ev("/r/sub/stale.txt", created(), 7, 17)]);
    // An ordering probe on the NEW lane: if the stale batch were going to
    // deliver, it would arrive before this later send.
    rig
      .fs
      .send_batch("/r", vec![ev("/r/probe.txt", created(), 8, 18)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(
      root.as_path(),
      Path::new("/r"),
      "only the new lane delivers"
    );
    assert_eq!(change.location(), &loc(&["probe.txt"]));

    gate.release();
    settle(|| rig.fs.shutdowns() == 1).await;
  }

  #[tokio::test(start_paused = true)]
  async fn close_mid_swap_counts_both_streams() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // The replacement spawn is parked when close arrives: the drain must
    // account for the old stream AND the orphaned replacement.
    let gate = rig.fs.hold_spawns();
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply,
      })
      .await
      .unwrap();
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    gate.release();
    assert!(on_close.await.is_ok(), "close settles");
    settle(|| rig.fs.shutdowns() == 2).await;
    assert_eq!(rig.fs.shutdowns(), 2, "both streams are torn down");
    // The abandoned replace resolves Closed, not silence.
    assert!(matches!(
      on_reply.await,
      Ok(Err(crate::error::ReplaceRootError::Closed)) | Err(_)
    ));
  }

  #[tokio::test(start_paused = true)]
  async fn a_failed_spawn_leaves_the_old_root_untouched() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // "/missing" is not in the fake tree: the replacement spawn fails and
    // the swap is atomic-on-failure.
    let outcome = replace(&rig, scope, "/missing").await;
    assert!(
      matches!(outcome, Err(crate::error::ReplaceRootError::Source(_))),
      "{outcome:?}"
    );

    // The old stream still delivers — coverage untouched.
    rig
      .fs
      .send_batch("/r/sub", vec![ev("/r/sub/still.txt", created(), 3, 13)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r/sub"));
    assert!(change.kind().is_created());
    assert_eq!(rig.fs.shutdowns(), 0, "no stream was torn down");
  }

  // Real-clock (not start_paused): the replacement spawn is HELD on a blocking
  // thread across a `settle`, and tokio will not auto-advance paused time while
  // a blocking task is outstanding — so this cell runs on the multi-thread
  // runtime where the held thread and the driver make real concurrent progress.
  #[tokio::test(flavor = "multi_thread")]
  async fn death_wins_a_mid_swap_unwatch() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Hold the replacement spawn so the unwatch lands first.
    let gate = rig.fs.hold_spawns();
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply,
      })
      .await
      .unwrap();
    let (unwatch_reply, mut on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(unwatch_reply),
      })
      .await
      .unwrap();
    settle(|| rig.fs.shutdowns() == 1).await;
    assert!(
      futures_util::poll!(&mut on_unwatch).is_pending(),
      "unwatch waits for the held replacement, not just the retired stream"
    );

    gate.release();
    let outcome = on_reply.await.expect("driver replies");
    assert!(
      matches!(outcome, Err(crate::error::ReplaceRootError::Retired)),
      "death wins: {outcome:?}"
    );
    // Both the old stream (unwatch) and the orphaned replacement are torn
    // down inside the counted accounting; the unwatch resolves only now, at
    // full scope quiescence.
    assert!(
      on_unwatch.await.unwrap(),
      "the unwatch resolves once the scope is quiescent"
    );
    settle(|| rig.fs.shutdowns() == 2).await;
  }

  #[tokio::test(start_paused = true)]
  async fn a_second_replace_in_flight_is_refused() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    let gate = rig.fs.hold_spawns();
    let (reply1, on_reply1) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply: reply1,
      })
      .await
      .unwrap();
    let (reply2, on_reply2) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply: reply2,
      })
      .await
      .unwrap();
    assert!(
      matches!(
        on_reply2.await.expect("driver replies"),
        Err(crate::error::ReplaceRootError::ReplaceInFlight)
      ),
      "the second replace refuses"
    );
    gate.release();
    assert!(on_reply1.await.expect("driver replies").is_ok());
  }

  /// The unwatch fence is per-scope QUIESCENCE: a replace's retired old
  /// stream is still shutting down when the unwatch starts, and its earlier
  /// completion must NOT resolve the unwatch — only the last teardown of the
  /// scope does.
  #[tokio::test(flavor = "multi_thread")]
  async fn unwatch_resolves_only_at_scope_teardown_quiescence() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // The swap commits while its old-stream teardown parks on gate1.
    let gate1 = rig.fs.hold_teardowns();
    assert!(replace(&rig, scope, "/r").await.is_ok());
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The unwatch's own teardown parks on gate2 (a fresh gate: the parked
    // old-stream thread keeps waiting on the one it cloned at park time).
    let gate2 = rig.fs.hold_teardowns();
    let (reply, mut on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The old-stream straggler completes FIRST; the unwatch must keep
    // pending until the CURRENT stream is down too.
    gate1.release();
    settle(|| rig.fs.shutdowns() == 1).await;
    assert_eq!(rig.fs.shutdowns(), 1, "only the straggler completed");
    assert!(
      futures_util::poll!(&mut on_reply).is_pending(),
      "a straggler's completion must not resolve the unwatch"
    );

    gate2.release();
    assert!(on_reply.await.unwrap(), "resolved at quiescence");
    settle(|| rig.fs.shutdowns() == 2).await;
  }

  /// The commit linearization contract, pinned: a death still QUEUED on the
  /// old lane when the commit lands is dominated whole — the swap reports
  /// success and the covering Rescan re-reads the (new) world; the old
  /// world's fate concerns nothing the scope still covers. The race is
  /// irreducible (a death can always sit in the kernel buffer, not yet in
  /// any queue), so the driver's serialization decides — and BOTH orders
  /// are safe: a death processed first wins (`death_wins_a_mid_swap_
  /// unwatch`), a death queued behind the commit is moot, and a death of
  /// the LIVE world always arrives on the new lane, which is never
  /// suppressed (the tail of this cell).
  #[tokio::test(start_paused = true)]
  async fn a_queued_old_lane_death_is_dominated_by_the_commit() {
    let registry = RecordingRegistry::default();
    let rig = rig_with(64, registry.clone());
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Park the replacement spawn; queue the old stream's death while the
    // driver cannot run (paused current-thread runtime — it advances only
    // at our awaits); then let the spawn finish on the REAL-clock pool
    // while the driver is still frozen. At the next await both queues are
    // ready and the biased select commits BEFORE consuming the death.
    let gate = rig.fs.hold_spawns();
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply,
      })
      .await
      .unwrap();
    // Let the driver process the command and PARK the spawn on the gate
    // (the send resolves on channel capacity alone, before the driver ran).
    for _ in 0..8 {
      tokio::task::yield_now().await;
    }
    rig.fs.send_fatal("/r/sub");
    gate.release();
    std::thread::sleep(Duration::from_millis(200));

    assert!(
      on_reply.await.expect("driver replies").is_ok(),
      "the commit wins the serialization"
    );
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r"));
    assert!(change.kind().is_rescan(), "the covering Rescan: {change:?}");
    assert_eq!(registry.dead(), [], "the old world's death is moot");

    // The scope is genuinely alive on the new lane...
    rig
      .fs
      .send_batch("/r", vec![ev("/r/live.txt", created(), 9, 19)]);
    let (s, _root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert!(change.kind().is_created());

    // ...and a death of the LIVE world is never suppressed: deaths are only
    // ever reordered around the commit, never lost.
    rig.fs.disconnect("/r");
    settle(|| registry.dead() == [scope]).await;
    assert_eq!(registry.dead(), [scope], "the new lane's death lands");
  }

  #[tokio::test(start_paused = true)]
  async fn an_unknown_scope_is_refused() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let _scope = watch(&rig, "/r/sub").await;
    let ghost = ScopeId::new(core::num::NonZeroU64::new(999).unwrap());
    let outcome = replace(&rig, ghost, "/r").await;
    assert!(
      matches!(outcome, Err(crate::error::ReplaceRootError::UnknownRoot)),
      "{outcome:?}"
    );
  }

  /// The unwatch quiescence fence holds under the OTHER ordering: the old
  /// root DIES (removing the handle) while a replacement is still spawning,
  /// and only THEN does unwatch arrive. It must not answer immediately while
  /// the replacement stream is coming up — it parks until the replacement is
  /// torn down, then reports the scope gone (UnknownRoot).
  #[tokio::test(flavor = "multi_thread")]
  async fn unwatch_after_root_death_waits_for_the_replacement() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // A replace is in flight, its spawn held on the blocking pool.
    let gate = rig.fs.hold_spawns();
    let (reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply,
      })
      .await
      .unwrap();
    // The command is processed (replace_states populated) before the death,
    // since the biased select drains the command channel ahead of the source
    // stream.
    for _ in 0..8 {
      tokio::task::yield_now().await;
    }

    // The OLD root dies while the replacement is still spawning: the death
    // path tears the original handle down.
    rig.fs.send_fatal("/r/sub");
    settle(|| rig.fs.shutdowns() == 1).await;

    // Unwatch arrives AFTER the handle is gone: the scope is NOT quiescent (a
    // replacement is still coming up), so the reply must park, not answer.
    let (ureply, mut on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(ureply),
      })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
      futures_util::poll!(&mut on_unwatch).is_pending(),
      "unwatch must wait for the still-spawning replacement, not answer at once"
    );

    // Release: the replacement resolves Retired and is torn down; only then
    // does the unwatch resolve, reporting the dead scope as UnknownRoot.
    gate.release();
    assert!(matches!(
      on_replace.await.expect("driver replies"),
      Err(crate::error::ReplaceRootError::Retired)
    ));
    assert!(
      !on_unwatch.await.unwrap(),
      "the dead scope resolves UnknownRoot, only at quiescence"
    );
    settle(|| rig.fs.shutdowns() == 2).await;
    assert_eq!(rig.fs.shutdowns(), 2, "old stream AND the replacement");
  }

  /// A `RootHandle` is `Copy`, so one scope can accrue several awaited
  /// unwatches. Every parked waiter must be kept and resolved — dropping one
  /// would surface to its caller as `Closed`, which the watcher reads as
  /// driver death. Two unwatches of the same scope, the teardown held: both
  /// pend, then resolve with their OWN verdicts (the first tore it down =
  /// `true`, the duplicate found it already dying = `false`), neither closed.
  #[tokio::test(flavor = "multi_thread")]
  async fn duplicate_awaited_unwatches_all_resolve_none_dropped() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Hold the teardown so the scope stays non-quiescent between the two
    // unwatches (the first removes the handle; the second then lands in the
    // outstanding-obligation branch that used to OVERWRITE the first waiter).
    let gate = rig.fs.hold_teardowns();
    let (r1, mut on1) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(r1),
      })
      .await
      .unwrap();
    // Let the handle be removed and the held teardown dispatched.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (r2, mut on2) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(r2),
      })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Both waiters pend while the teardown is held, and NEITHER is dropped
    // (a dropped sender would resolve as an error, not `Pending`).
    assert!(
      futures_util::poll!(&mut on1).is_pending(),
      "the first waiter is still parked, not dropped"
    );
    assert!(
      futures_util::poll!(&mut on2).is_pending(),
      "the second waiter is queued beside the first, not overwriting it"
    );

    gate.release();
    assert!(
      on1
        .await
        .expect("the first waiter is answered, never Closed"),
      "the first unwatch tore the scope down"
    );
    assert!(
      !on2
        .await
        .expect("the second waiter is answered, never Closed"),
      "the duplicate resolves UnknownRoot"
    );
    settle(|| rig.fs.shutdowns() == 1).await;
  }

  /// The waiter vector is reclaimed, not merely accrued: an issue-and-cancel
  /// storm of duplicate unwatches against a scope whose teardown is STALLED
  /// leaves the parked-waiter vector bounded (the loop-top prune drops
  /// canceled senders), while a genuinely-awaited waiter still resolves.
  #[tokio::test(flavor = "multi_thread")]
  async fn canceled_duplicate_unwatches_stay_bounded() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Hold the teardown so the scope never quiesces during the storm.
    let gate = rig.fs.hold_teardowns();

    // One genuinely-awaited unwatch whose receiver is kept alive.
    let (survivor, on_survivor) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(survivor),
      })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The storm: each duplicate command is accepted, then its receiver
    // dropped (canceled). Without the prune these would accrue without bound
    // while the teardown stays held.
    for _ in 0..200 {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      drop(on_reply);
      tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (q, on_q) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugUnwatchWaiters { scope, reply: q })
      .await
      .unwrap();
    let parked = on_q.await.unwrap();
    assert!(
      parked <= 3,
      "canceled waiters are reclaimed each loop-top, not accrued: {parked}"
    );

    // The genuinely-awaited waiter still resolves with its verdict.
    gate.release();
    assert!(
      on_survivor.await.expect("the survivor is answered"),
      "the live waiter resolves true at quiescence"
    );
    settle(|| rig.fs.shutdowns() == 1).await;
  }

  /// Close must resolve a parked unwatch even when the last obligation is a
  /// FAILED replacement spawn — which enqueues no teardown. The drain's
  /// spawn arm re-checks quiescence (like the live loop's), so the waiter
  /// gets its recorded verdict instead of dropping as `Closed` (a false
  /// driver-death report despite a clean teardown).
  #[tokio::test(flavor = "multi_thread")]
  async fn close_resolves_a_parked_unwatch_when_the_replacement_spawn_fails() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // A replacement spawn that WILL fail (/missing is not in the fake tree),
    // held so Close begins while it is still in flight.
    let gate = rig.fs.hold_spawns();
    let (rep_reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/missing"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from(
          "/missing",
        )),
        reply: rep_reply,
      })
      .await
      .unwrap();
    for _ in 0..8 {
      tokio::task::yield_now().await;
    }

    // An awaited unwatch parks its waiter (handle still present → verdict
    // `true`); its own teardown completes but the waiter stays held on the
    // in-flight spawn.
    let (uw_reply, on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(uw_reply),
      })
      .await
      .unwrap();
    settle(|| rig.fs.shutdowns() == 1).await;

    // Close begins while the failing spawn is still held.
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Release: the spawn fails, the drain reaches quiescence, and the parked
    // unwatch resolves with its VERDICT, never a channel closure.
    gate.release();
    assert!(on_close.await.is_ok(), "close settles");
    assert!(
      on_unwatch
        .await
        .expect("the waiter is answered, not dropped as Closed"),
      "the unwatch resolves its recorded verdict"
    );
    // The abandoned replace caller is resolved (its reservation and reply
    // dropped at the close sweep), never left hanging.
    let replace_outcome = on_replace.await;
    assert!(
      replace_outcome.is_err() || matches!(replace_outcome, Ok(Err(_))),
      "{replace_outcome:?}"
    );
  }

  /// The swap window rides the journal: the replacement spawn inherits the
  /// RETIRING stream's resume point, so a journal-bearing backend replays the
  /// window instead of leaning on the covering `Rescan` alone. A birth spawn
  /// carries none (there is nothing to resume from).
  #[tokio::test(start_paused = true)]
  async fn a_replacement_spawn_inherits_the_retiring_resume_point() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    // The live stream mints a journal point, as FSEvents does.
    let token = crate::os::ResumeToken::new(4242, Some([7u8; 16]));
    rig.fs.mint_resume_token(token);

    let scope = watch(&rig, "/r/sub").await;
    assert_eq!(
      rig.fs.spawn_resume_points(),
      vec![None],
      "a birth spawn has nothing to resume from"
    );

    assert!(replace(&rig, scope, "/r").await.is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;
    assert_eq!(
      rig.fs.spawn_resume_points(),
      vec![None, Some(token)],
      "the replacement resumes the retiring stream's journal point"
    );
  }

  /// Whole-scope teardown reclaims the delivery lane: repeated watch/unwatch
  /// churn leaves no lane entry behind, so `lanes` stays bounded for the
  /// driver's lifetime (scope ids never recycle).
  #[tokio::test(flavor = "multi_thread")]
  async fn watch_unwatch_churn_leaves_no_lane_entry() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    for _ in 0..16 {
      let scope = watch(&rig, "/r/sub").await;
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      assert!(on_reply.await.unwrap(), "each cycle tears down cleanly");
    }
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugLaneCount { reply })
      .await
      .unwrap();
    assert_eq!(
      on_reply.await.unwrap(),
      0,
      "every retired scope reclaimed its lane — no unbounded growth"
    );
  }
}

/// The sync-cookie substrate on a kernel-recursive root: no re-arm work means
/// the settle fence is trivially met, so the write lands at once; the unlink
/// is a reply-less fire-and-forget; and a read-only tree refuses typed.
///
/// The registry OWNS every cookie the driver writes — never the reply oneshot —
/// so no interleaving strands a file: an abandoned reply, a scope retiring under
/// an in-flight write, a failed write, and the driver's own death (close OR
/// cancellation) each leave zero cookies on disk and zero records behind.
mod sync_cookie {
  use super::*;

  async fn sync_root(
    rig: &Rig,
    scope: ScopeId,
    dir: &str,
    name: &str,
  ) -> Result<PathBuf, crate::error::SyncRootError> {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::SyncRoot {
        scope,
        dir: PathBuf::from(dir),
        name: name.to_owned(),
        reply,
      })
      .await
      .unwrap();
    on_reply.await.expect("the driver replies")
  }

  /// Dispatches a sync without awaiting it, holding on to the reply receiver —
  /// the caller can then abandon it, or retire the scope, while the write is
  /// still in the pool.
  async fn sync_root_pending(
    rig: &Rig,
    scope: ScopeId,
    dir: &str,
    name: &str,
  ) -> futures_channel::oneshot::Receiver<Result<PathBuf, crate::error::SyncRootError>> {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::SyncRoot {
        scope,
        dir: PathBuf::from(dir),
        name: name.to_owned(),
        reply,
      })
      .await
      .unwrap();
    on_reply
  }

  /// How many cookies the driver still OWNS. The leak oracle: every path that
  /// ends a cookie's life must leave this back where it found it — an unlinked
  /// file with a live record is a slow leak, and a record per failed attempt is
  /// unbounded growth.
  async fn cookie_count(rig: &Rig) -> usize {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugCookieCount { reply })
      .await
      .unwrap();
    on_reply.await.expect("the driver replies")
  }

  /// How many cancel tombstones the driver currently holds. The boundedness oracle: a tombstone
  /// exists only for a write provably in the pool, and its own completion (or its claim) sweeps
  /// it — so this returns to zero after every cancel ordering.
  async fn cancel_tombstones(rig: &Rig) -> usize {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugCookieCancelTombstones { reply })
      .await
      .unwrap();
    on_reply.await.expect("the driver replies")
  }

  /// Settles until the OWNED-cookie count reaches `target` — the async analogue of [`settle`],
  /// for the ledger count that only a `Command` round-trip can read. Gives the real-clock
  /// blocking pool scheduler slices under paused time.
  async fn settle_cookie_count(rig: &Rig, target: usize) {
    for _ in 0..200 {
      if cookie_count(rig).await == target {
        return;
      }
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  }

  /// Settles until the cancel-tombstone count reaches `target`.
  async fn settle_tombstones(rig: &Rig, target: usize) {
    for _ in 0..200 {
      if cancel_tombstones(rig).await == target {
        return;
      }
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  }

  /// Dispatches a sync, retrying the retryable `WriteInFlight` refusal until the single-flight
  /// gate admits it (a completed write clears the gate on its own `CookieWriteDone`, which is
  /// asynchronous relative to the reply). Panics on any other error.
  async fn admit_sync(rig: &Rig, scope: ScopeId, dir: &str, name: &str) -> PathBuf {
    for _ in 0..400 {
      match sync_root(rig, scope, dir, name).await {
        Ok(path) => return path,
        Err(crate::error::SyncRootError::WriteInFlight) => {
          tokio::task::yield_now().await;
          tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Err(other) => panic!("unexpected sync error: {other:?}"),
      }
    }
    panic!("the single-flight gate never admitted the sync");
  }

  /// The finding-2 retain cells' config: a retry delay LONG enough to observe the retained
  /// `RemoveFailed` record before the driver's OWN retry fires, yet finite so that retry still
  /// confirms within a [`settle`] window. (The `tuned_config`'s 5 ms retry would race the
  /// retain observation.)
  fn retain_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(200),
      cookie_retry_cap: Duration::from_millis(200),
      cookie_retry_budget: 3,
      cookie_backlog_cap: 8,
      cookie_global_cap: 128,
      ..config()
    }
  }

  /// A live rig whose DRIVER TASK the caller keeps, so a cell can drop the
  /// driver future outright — the cancellation path, which no orderly close
  /// tail ever reaches.
  fn cancellable_rig() -> (Rig, tokio::task::JoinHandle<()>) {
    let fs = FakeFs::new(1);
    fs.put("/r", FileKind::Dir, 1);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (reap_tx, reap_rx) = async_channel::unbounded();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    let driver = tokio::spawn(run::<TokioRuntime, FakeFs>(
      config(),
      fs.clone(),
      cmd_rx,
      reap_rx,
      ev_tx,
      NullRegistry,
    ));
    (
      Rig {
        fs,
        commands: cmd_tx,
        cookie_removes: reap_tx,
        events: ev_rx,
      },
      driver,
    )
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn a_kernel_recursive_root_writes_the_cookie_at_once() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-1-7-1")
      .await
      .expect("the write lands");
    assert_eq!(path, PathBuf::from("/r/.tributaries-sync-1-7-1"));
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // The cookie is a real object now: its create event flows like any file's,
    // which is exactly what makes it a barrier marker.
    rig
      .fs
      .send_batch("/r", vec![ev(path.to_str().unwrap(), created(), 1, 9001)]);
    let (s, change) = next_event(&rig).await;
    assert_eq!(s, scope);
    assert!(change.kind().is_created());
    assert_eq!(
      change.location(),
      &loc(&[".tributaries-sync-1-7-1"]),
      "the cookie's own event rides the root's ordered queue"
    );

    // And it reaps, idempotently — on the dedicated cleanup lane.
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(rig.fs.cookie_removes(), vec![path]);
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn a_read_only_tree_refuses_the_cookie_typed() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    rig
      .fs
      .fail_cookie_writes(std::io::ErrorKind::PermissionDenied);

    let outcome = sync_root(&rig, scope, "/r", ".tributaries-sync-1-7-2").await;
    match outcome {
      Err(crate::error::SyncRootError::Write { path, source }) => {
        assert_eq!(path, PathBuf::from("/r/.tributaries-sync-1-7-2"));
        assert_eq!(
          source.kind(),
          std::io::ErrorKind::PermissionDenied,
          "a read-only tree is the honest refusal, not a silent half-barrier"
        );
      }
      other => panic!("expected a typed write refusal, got {other:?}"),
    }
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn a_dead_root_refuses_the_cookie() {
    let rig = rig_with_capacity(64);
    let ghost = ScopeId::new(core::num::NonZeroU64::new(404).unwrap());
    assert!(matches!(
      sync_root(&rig, ghost, "/r", ".tributaries-sync-1-7-3").await,
      Err(crate::error::SyncRootError::UnknownRoot)
    ));
  }

  // The driver owns every cookie it writes: even with NO removal request — the
  // abandoned-after-send case where the caller loses the path — the cookie is
  // unlinked when the driver tears down. This is the guarantee that lets the
  // umbrella source drop its own cookie-removes queue entirely.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_written_cookie_is_reaped_when_the_driver_tears_down() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-1-7-4")
      .await
      .expect("the write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the registry owns the landed cookie"
    );
    assert!(
      rig.fs.cookie_removes().is_empty(),
      "no removal was requested — the cookie is still the driver's to reap"
    );

    // Close WITHOUT ever removing the cookie: the driver's terminal reap must
    // unlink it before the close reply lands.
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let _ = on_reply.await;

    assert_eq!(
      rig.fs.cookie_removes(),
      vec![path],
      "the driver reaped its written cookie at teardown"
    );
  }

  // A cookie whose scope is retired mid-life (unwatch, not close) is reaped by
  // that scope's stream teardown — the same ownership, one scope at a time.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_written_cookie_is_reaped_when_its_scope_is_retired() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-1-7-5")
      .await
      .expect("the write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // Retire the scope with no removal request: the stream teardown reaps the
    // cookie the scope still owns (a reply-less, off-reactor unlink).
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(on_reply.await.unwrap(), "the live scope was unwatched");

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      vec![path],
      "the retiring scope's stream teardown reaped its written cookie"
    );
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "and it took the record with it — a retired scope leaves nothing behind"
    );
  }

  // A write that FAILS creates no file, so it claims nothing. This is what keeps
  // a long-lived scope's registry bounded: the old ledger recorded the path
  // BEFORE dispatching the write and never took it back on failure, so a
  // read-only tree grew it by one path per attempt, forever.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_failed_cookie_write_records_nothing() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    rig
      .fs
      .fail_cookie_writes(std::io::ErrorKind::PermissionDenied);

    for attempt in 0..8 {
      let outcome = sync_root(
        &rig,
        scope,
        "/r",
        &format!(".tributaries-sync-1-8-1-{attempt}"),
      )
      .await;
      assert!(
        matches!(outcome, Err(crate::error::SyncRootError::Write { .. })),
        "the read-only tree refuses every attempt"
      );
      assert_eq!(
        cookie_count(&rig).await,
        0,
        "a failed write records nothing — repeated failures cannot grow the registry (attempt {attempt})"
      );
    }
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "no file was ever created"
    );
    assert!(
      rig.fs.cookie_removes().is_empty(),
      "and none had to be reaped"
    );
  }

  // The caller abandons its sync (a timeout, a dropped future) AFTER the write
  // was dispatched: the file lands into a reply nobody holds. The write reaps it
  // and hands the record back — an unlinked file left recorded would be a leak
  // of a different kind (a sweep chasing a path that no longer exists, forever).
  #[tokio::test(flavor = "multi_thread")]
  async fn an_abandoned_cookie_reply_reaps_and_forgets() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Hold the write in the pool: abandoning the reply EARLIER would be the
    // parked-fence prune (no write is ever dispatched), which reaps nothing
    // because nothing was written.
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-8-2").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write reached the pool before the caller walked away"
    );

    drop(on_reply);
    hold.release();

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    let written = rig.fs.cookie_writes();
    assert_eq!(written.len(), 1, "the write really did land");
    assert_eq!(
      rig.fs.cookie_removes(),
      written,
      "the abandoned cookie was reaped by the write itself"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no file survives a sync nobody is listening for"
    );
    assert_eq!(cookie_count(&rig).await, 0, "and the record went with it");
  }

  // The scope retires while its write is still in the blocking pool: the
  // teardown's sweep runs BEFORE the file exists, so the sweep alone cannot
  // reap it. The retirement flag is what closes the window — raised before the
  // sweep, checked by the write as it hands the file over, so the write reaps
  // itself instead of landing a cookie behind a sweep that already ran.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_written_for_a_retiring_scope_reaps_itself() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-8-3").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write is in the pool, its file not yet created"
    );

    // Retire the scope UNDER the in-flight write.
    let (reply, on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(on_unwatch.await.unwrap(), "the live scope was unwatched");
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "the retirement got there first — the sweep found nothing to unlink"
    );

    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the driver replies"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "a cookie the dead scope could never report is refused, not silently placed"
    );

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      rig.fs.cookie_writes(),
      "the late write reaped the file it had just created"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie outlives the scope it was written for"
    );
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "and nothing was recorded for a scope that will never be swept again"
    );
  }

  // A FILE subscription is validly covered (it commits under an armed
  // ancestor), so the cookie key a sync carries can name a file. Writing inside
  // it would fail ENOTDIR and leave the caller with no barrier at all; the
  // cookie lands beside it instead — still under the root, so its create event
  // is still reported on this root's stream.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_covered_file_subscription_writes_its_cookie_in_the_parent_directory() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    rig.fs.put("/r/sub/notes.txt", FileKind::File, 3);

    let path = sync_root(&rig, scope, "/r/sub/notes.txt", ".tributaries-sync-1-8-4")
      .await
      .expect("a covered file subscription can still place its barrier");
    assert_eq!(
      path,
      PathBuf::from("/r/sub/.tributaries-sync-1-8-4"),
      "the cookie lands in the file's containing directory"
    );
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // The barrier still works: the cookie's own create rides this root's queue.
    rig.fs.send_batch(
      "/r",
      vec![ev("/r/sub/.tributaries-sync-1-8-4", created(), 1, 9001)],
    );
    let (got, change) = next_event(&rig).await;
    assert_eq!(got, scope);
    assert!(change.kind().is_created());
    assert_eq!(change.location(), &loc(&["sub", ".tributaries-sync-1-8-4"]));

    // And the registry owns the path the write ACTUALLY landed at — the
    // caller's remove (keyed off that same returned path) finds it.
    assert_eq!(cookie_count(&rig).await, 1);
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(rig.fs.cookie_removes(), vec![path]);
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the remove dropped the record it named"
    );
  }

  // The terminal sweep is a `Drop`, so it is not a step of the orderly close
  // that a cancelled (or panicking) driver task can skip: dropping the driver
  // future where it stands still reaps every cookie it owns — now DETACHED (a
  // best-effort off-reactor unlink), never a synchronous unlink that could
  // wedge the unwind. The runtime outlives the aborted task, so the detached
  // reap still runs.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancelled_driver_task_still_sweeps_its_cookies() {
    let (rig, driver) = cancellable_rig();
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-1-8-5")
      .await
      .expect("the write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);
    assert!(rig.fs.cookie_removes().is_empty());

    // No Close, no orderly tail — the driver future is dropped mid-flight.
    driver.abort();
    assert!(
      driver.await.unwrap_err().is_cancelled(),
      "the driver was cancelled, not run to completion"
    );

    // The abnormal-path Drop DISPATCHED its sweep detached (never blocking the
    // unwind); the still-live runtime runs it, reaping the cookie shortly after.
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      vec![path],
      "a cancelled driver still sweeps the cookies it owns, best-effort off-reactor"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie outlives the driver that wrote it"
    );
  }

  // The write-versus-sweep race, from the far side: the driver is ALREADY GONE
  // when the write creates its file, so the sweep it should have been caught by
  // ran before the file existed — and there is no driver left to tell about it.
  // The shutdown flag is the whole handshake: raised before the sweep takes the
  // paths, checked by the write as it hands its file over, so the write reaps
  // itself. Nothing else can: this file would otherwise outlive the process's
  // watcher with no channel left to ask for its removal.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_write_landing_after_the_driver_is_gone_reaps_itself() {
    let (rig, driver) = cancellable_rig();
    let scope = watch(&rig, "/r").await;

    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-8-6").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write is in the pool, its file not yet created"
    );

    // The driver dies UNDER the in-flight write: its sweep finds an empty
    // registry (nothing is recorded until a write lands), and it is not around
    // to be told about what happens next.
    driver.abort();
    assert!(driver.await.unwrap_err().is_cancelled());
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "the sweep ran before the file existed — it had nothing to unlink"
    );

    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the write still answers its caller"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "a barrier no live driver could report is refused"
    );

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      rig.fs.cookie_writes(),
      "the write reaped the file it created after its driver was gone"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no dispatched write can outlive the registry that dispatched it"
    );
  }

  // The containing-directory fallback may never climb ABOVE the root. The
  // watcher proves `dir` is inside the root, so the parent of a `dir` strictly
  // under it is inside it too — but the ROOT's parent is not, and a root that
  // died under an in-flight sync is exactly a `dir` that is no longer a
  // directory. Unclamped, that sync would drop a cookie in the root's parent:
  // outside the watched tree, unreportable, and litter in someone else's
  // directory. The typed failure is the honest answer instead.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_never_climbs_above_the_root() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    // The root's parent is a perfectly good directory — which is exactly the
    // hazard: nothing but the floor stops the fallback from writing into it.
    rig.fs.put("/", FileKind::Dir, 99);

    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-8-7").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;

    // The root dies under the parked write, before the driver has processed its
    // death — the window in which the write still believes the scope is live.
    rig.fs.remove("/r");
    hold.release();

    match on_reply.await.expect("the driver replies") {
      Err(crate::error::SyncRootError::Write { path, source }) => {
        assert_eq!(
          path,
          PathBuf::from("/r/.tributaries-sync-1-8-7"),
          "the refusal names the location the caller asked for"
        );
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
      }
      other => panic!("expected a typed write refusal, got {other:?}"),
    }
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "no cookie was created for a root that is gone"
    );
    assert!(
      rig.fs.files_under("/").is_empty(),
      "and nothing landed ABOVE the root, where no event could ever report it"
    );
  }

  // A cookie NAME that is not a single normal component would escape the
  // directory the barrier was validated for once joined — refused before any
  // write, never a silent placement outside coverage.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_name_with_a_separator_is_refused() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    assert!(
      matches!(
        sync_root(&rig, scope, "/r", "sub/evil").await,
        Err(crate::error::SyncRootError::BadCookieName { .. })
      ),
      "a name with a separator is a contract violation, not a barrier"
    );
    assert_eq!(
      rig.fs.cookie_dispatches(),
      0,
      "the write was refused before it could reach the pool"
    );
    assert_eq!(cookie_count(&rig).await, 0);
  }

  // A directory that only appears inside the root through `..` traversal —
  // `/r/../outside` starts_with `/r` component-wise, yet escapes the tree once
  // folded — is refused, closing the lexical escape a plain `starts_with` misses.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_dir_escaping_via_dotdot_is_refused() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    assert!(
      matches!(
        sync_root(&rig, scope, "/r/../outside", ".tributaries-sync-1-9-8").await,
        Err(crate::error::SyncRootError::DirOutsideRoot { .. })
      ),
      "a `..`-escaping directory is outside the root, however it lexes"
    );
    assert_eq!(
      rig.fs.cookie_dispatches(),
      0,
      "the write was refused before it could reach the pool"
    );
    assert_eq!(cookie_count(&rig).await, 0);
  }

  // O_NOFOLLOW on the create: a symlink swapped in where the cookie is to land
  // is refused rather than followed to a target that could sit outside the root,
  // where its create event would never meet the barrier.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_final_component_symlink_is_not_followed() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    // An adversary places a symlink at the exact path the cookie would take.
    rig
      .fs
      .put("/r/.tributaries-sync-1-9-6", FileKind::Symlink, 77);

    match sync_root(&rig, scope, "/r", ".tributaries-sync-1-9-6").await {
      Err(crate::error::SyncRootError::Write { source, .. }) => {
        assert_eq!(
          source.kind(),
          std::io::ErrorKind::AlreadyExists,
          "the create refuses the symlink instead of following it"
        );
      }
      other => panic!("expected a refused create, got {other:?}"),
    }
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "nothing was claimed for a barrier that could not be written"
    );
  }

  // Containment is not merely lexical. A cookie directory whose SPELLING sits
  // under the root but whose real path escapes it — an ALREADY-EXISTING
  // intermediate symlink `<root>/link` pointing outside, needing no swap — passes
  // the lexical check yet must be refused. The write canonicalizes the directory
  // (resolving the link) and verifies the result is beneath the canonical root
  // before creating anything, so no cookie lands outside the watched tree, where
  // its create event could never be reported on this root's stream.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_preexisting_intermediate_symlink_dir_is_refused() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    // `/r/link` is an existing symlink to `/outside`, so `/r/link/sub` really is
    // `/outside/sub`: it exists as a directory and its spelling passes the lexical
    // containment check, but it canonicalizes OUTSIDE the root.
    rig.fs.put("/r/link/sub", FileKind::Dir, 2);
    rig.fs.resolve_cookie_dir_to("/r/link/sub", "/outside/sub");

    match sync_root(&rig, scope, "/r/link/sub", ".tributaries-sync-1-9-7").await {
      Err(crate::error::SyncRootError::Write { source, .. }) => {
        assert_eq!(
          source.kind(),
          std::io::ErrorKind::Other,
          "the write refuses a directory that resolves outside the root"
        );
      }
      other => panic!("expected a refused write, got {other:?}"),
    }
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "no cookie was created for a directory outside the root"
    );
    assert!(
      rig.fs.files_under("/outside").is_empty(),
      "and nothing landed outside the watched tree"
    );
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "nothing was claimed for a barrier that could not be written"
    );
  }

  // A write dispatched under the pre-replace root carries the generation current
  // at DISPATCH; a replace commit bumps it, so the write's claim is refused and
  // its file reaped — never a cookie the new stream could not report. Without the
  // generation check the stale write would claim, strand its barrier, and leave a
  // file outside coverage.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_write_dispatched_under_the_old_root_is_revoked_after_replace() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r2", FileKind::Dir, 2);
    let scope = watch(&rig, "/r").await;

    // The write is dispatched — its guard captures generation 0 — and parks in
    // the pool on the hold gate.
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-9-5").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;

    // Replace the root BEFORE the write lands: the commit bumps the generation.
    let (reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    on_replace
      .await
      .expect("driver replies")
      .expect("the swap commits");

    // Release the held write: it completes under the SUPERSEDED generation and
    // must not claim.
    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the driver replies"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "a write under the old root is revoked, not silently committed"
    );
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      rig.fs.cookie_writes(),
      "the revoked write reaped the file it had created"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie survives under the superseded root"
    );
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "and nothing was recorded for a barrier that never claimed"
    );
  }

  // The generation bump that revokes a stale cookie write must land AT the lane
  // swap, not at the run loop's post-commit call. A write RELEASED in the window
  // after the swap — the new stream is live, the old lane retired — but before
  // that later call would otherwise claim under the still-old generation and
  // strand its barrier on the retired lane. The bump moved INTO `commit_replace`,
  // before the swap and under the ledger lock, so a claim in this window reads the
  // new generation and is refused. The gated registry freezes the owner loop at
  // the commit's registry overwrite — after the swap, before the post-commit
  // cookie call — which is exactly the window; the write is released there.
  //
  // MUST FAIL (the write wrongly commits, replying `Ok`) if the bump sits at the
  // old post-commit site: frozen here, that site has not run, so the generation
  // still matches the one the write captured.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_write_released_after_the_stream_swap_but_before_the_old_bump_site_is_revoked() {
    let registry = GatedRegistry::default();
    let rig = rig_with(64, registry.clone());
    rig.fs.put("/r2", FileKind::Dir, 2);
    let scope = watch(&rig, "/r").await;

    // The write is dispatched under the current root — its guard captures
    // generation 0 — and parks in the pool, its file not yet created.
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-9-9").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;

    // Freeze the owner loop at the replace commit's registry overwrite — PAST the
    // lane swap (and, with the fix, past the generation bump), BEFORE the run
    // loop's post-commit cookie call.
    let commit = registry.hold_scope_live();
    let (reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    settle(|| registry.scope_live_frozen()).await;
    assert!(
      registry.scope_live_frozen(),
      "the owner loop is frozen in the commit, past the swap"
    );

    // Release the held write INTO that window: with the bump at the swap, the
    // live generation has already moved past the one the write captured, so the
    // claim is refused — never a barrier committed to the retired lane.
    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the write answers its caller"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "a write released after the swap is revoked, not committed under the stale generation"
    );

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      rig.fs.cookie_writes(),
      "the revoked write reaped the file it had created"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie survives on the superseded root"
    );

    // Let the frozen commit finish; the barrier count is back to zero.
    commit.release();
    on_replace
      .await
      .expect("driver replies")
      .expect("the swap commits");
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "nothing was recorded for a barrier that never claimed"
    );
  }

  // The completed-cookie reap rides a DEDICATED lane, so a saturated command
  // channel can never drop it. With the 16-slot command channel provably full,
  // every reap still lands and the registry returns to zero while the scope stays
  // live. A single-threaded runtime makes the saturation deterministic: the fill
  // burst yields nowhere, so the driver cannot drain a slot until the next await.
  // MUST hang (or leak) if the removal rode the command channel.
  #[tokio::test(flavor = "current_thread")]
  async fn saturated_command_channel_still_reaps_completed_cookies() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Complete several syncs; the registry now owns their cookies.
    let mut cookies = Vec::new();
    for seq in 0..4 {
      let name = format!(".tributaries-sync-1-9-9-{seq}");
      cookies.push(
        sync_root(&rig, scope, "/r", &name)
          .await
          .expect("the write lands"),
      );
    }
    assert_eq!(cookie_count(&rig).await, cookies.len());

    // Saturate the 16-slot command channel: this burst never awaits, so on a
    // single-threaded runtime the driver cannot drain a slot mid-fill.
    for _ in 0..16 {
      let (reply, _rx) = futures_channel::oneshot::channel::<usize>();
      rig
        .commands
        .try_send(Command::DebugCookieCount { reply })
        .expect("a command slot is free");
    }
    let (reply, _rx) = futures_channel::oneshot::channel::<usize>();
    assert!(
      rig
        .commands
        .try_send(Command::DebugCookieCount { reply })
        .is_err(),
      "the command channel is saturated"
    );

    // Every completed cookie reaps through the DEDICATED lane — admitted despite
    // the jammed command channel.
    for path in &cookies {
      rig
        .cookie_removes
        .try_send(CookieReap::Remove(path.clone()))
        .expect("the cleanup lane always admits");
    }

    // Draining the fillers frees the command channel; the reaps land, the
    // registry empties, and the scope is still live.
    settle(|| rig.fs.cookie_removes().len() == cookies.len()).await;
    let mut reaped = rig.fs.cookie_removes();
    reaped.sort();
    let mut expected = cookies.clone();
    expected.sort();
    assert_eq!(reaped, expected, "every completed cookie was unlinked");
    assert_eq!(cookie_count(&rig).await, 0, "the registry returned to zero");
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie file lingers"
    );
    // The scope never died — a fresh barrier still lands.
    sync_root(&rig, scope, "/r", ".tributaries-sync-1-9-9-live")
      .await
      .expect("the scope is still live after the reaps");
  }

  // A transient unlink failure must not orphan the cookie: the record is
  // RETAINED (dropped only when the unlink confirms) so the path stays eligible
  // for a later sweep, and the DRIVER'S OWN backed-off retry — not a second
  // request from the caller — eventually removes it (finding 3). The old
  // fire-and-forget unlink ignored every error, silently stranding the file.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_transient_unlink_failure_retains_the_cookie_until_it_succeeds() {
    // The retain config's 200ms base gives a comfortable window to observe the
    // RETAINED record before the driver's own retry fires (the default 100ms
    // base would race that observation).
    let rig = rig_with_config(64, retain_config());
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-4-1-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1, "the registry owns the cookie");

    // The next unlink fails once; the reap dispatches it and it is refused.
    rig.fs.fail_next_cookie_removes(1);
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();
    settle(|| rig.fs.cookie_remove_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the unlink reached the pool and was refused"
    );
    assert!(
      rig.fs.cookie_removes().is_empty(),
      "a failed unlink records no removal"
    );
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the record is RETAINED across the transient failure — never orphaned"
    );
    assert!(
      !rig.fs.files_under("/r").is_empty(),
      "the file is still on disk, still eligible for a retry"
    );

    // No second request is needed: the DRIVER OWNS the retry (finding 3). It re-dispatches the
    // unlink on its own backed-off schedule, which now succeeds and drops the record — the
    // requester never asks twice (the old design's requester-driven re-reap is gone).
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    assert!(
      rig.fs.cookie_removes().contains(&path),
      "the driver's own retry removed the cookie with no second request"
    );
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      2,
      "exactly two dispatches: the failed attempt and the driver's own retry"
    );
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the record dropped only once the unlink confirmed"
    );
  }

  // Single-flight per scope: while one physical write is outstanding, a second
  // sync is refused `WriteInFlight` rather than dispatching another — so a caller
  // that times out and retries cannot pile unbounded blocking writes against a
  // hung mount. Once the first write resolves the gate reopens.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_second_sync_while_a_write_is_in_flight_is_refused() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Hold the first write in the pool: the scope is now IN FLIGHT.
    let hold = rig.fs.hold_cookie_writes();
    let first = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-2-1-1").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the first write is dispatched and outstanding"
    );

    // A second sync for the SAME scope is refused, never dispatched.
    assert!(
      matches!(
        sync_root(&rig, scope, "/r", ".tributaries-sync-2-1-2").await,
        Err(crate::error::SyncRootError::WriteInFlight)
      ),
      "a second sync while a write is in flight is refused single-flight"
    );
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the refusal never reached the pool — still exactly one write dispatched"
    );

    // Release the first write: it lands.
    hold.release();
    let path = first
      .await
      .expect("the driver replies")
      .expect("the first write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // The gate reopens once the write fully resolves; a caller retries the
    // (retryable) refusal until admitted.
    let mut again = None;
    for _ in 0..200 {
      match sync_root(&rig, scope, "/r", ".tributaries-sync-2-1-3").await {
        Ok(fresh) => {
          again = Some(fresh);
          break;
        }
        Err(crate::error::SyncRootError::WriteInFlight) => {
          tokio::task::yield_now().await;
          tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Err(other) => panic!("unexpected sync error: {other:?}"),
      }
    }
    let again = again.expect("the single-flight gate reopened after the first write");
    assert_ne!(again, path, "the second barrier is its own cookie");
  }

  // A physical write still outstanding at close makes close report `NotQuiesced`
  // with the write counted — honest, never an indefinite hang. The write rides
  // the same `pending_cookie_ops` accounting a teardown does.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_outstanding_cookie_write_makes_close_report_not_quiesced() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Hold a write in the pool: it is outstanding when close begins.
    let hold = rig.fs.hold_cookie_writes();
    let _on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-2-2-1").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;

    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
      .await
      .expect("close resolves at the grace boundary, not an indefinite hang")
      .expect("the driver replied");
    assert_eq!(
      pending, 1,
      "the outstanding write is counted — close is honest, not wedged"
    );

    // The held write, released after close, self-reaps against the raised
    // shutdown flag: no cookie file survives.
    hold.release();
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the late write reaped the file it created"
    );
  }

  // A hung TERMINAL unlink must never wedge close: the orderly sweep dispatches
  // it as a tracked, grace-covered job, so close returns `NotQuiesced` within the
  // grace instead of blocking forever inside a synchronous Drop.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_hung_terminal_unlink_does_not_wedge_close() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-1-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The terminal unlink hangs.
    let hold = rig.fs.hold_cookie_removes();
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
      .await
      .expect("close returns within the grace, never wedged on a hung unlink")
      .expect("the driver replied");
    assert_eq!(
      pending, 1,
      "the hung terminal unlink is counted, not papered over"
    );

    // Released, the unlink completes and the cookie is gone.
    hold.release();
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert!(rig.fs.cookie_removes().contains(&path));
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the hung unlink completed once the mount unwedged"
    );
  }

  // The abnormal-path Drop dispatches its unlinks DETACHED, so it never blocks
  // the unwind: a cancelled driver whose terminal unlink is hung still returns
  // promptly (the OLD synchronous Drop would hang here forever), and the reap is
  // still ATTEMPTED best-effort off-reactor.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancelled_driver_with_a_hung_unlink_does_not_block_its_drop() {
    let (rig, driver) = cancellable_rig();
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-2-1")
      .await
      .expect("the write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // The terminal unlink hangs, then the driver is cancelled: Drop must not
    // block on the unlink.
    let hold = rig.fs.hold_cookie_removes();
    driver.abort();
    let joined = tokio::time::timeout(Duration::from_secs(5), driver).await;
    assert!(
      joined.is_ok(),
      "Drop dispatched its unlink detached — the unwind was never blocked on the hung remove"
    );
    assert!(joined.unwrap().unwrap_err().is_cancelled());

    // The reap was still attempted (detached, parked on the hung mount).
    settle(|| rig.fs.cookie_remove_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the abnormal-path Drop still dispatches the reap best-effort"
    );

    // Released, the detached unlink completes.
    hold.release();
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert!(rig.fs.cookie_removes().contains(&path));
  }

  // Finding 1 (fs half): a cancel for a cookie whose write LANDED and CLAIMED — its
  // `reply.send(Ok)` succeeded because the caller's receiver was alive, so the write's own
  // send-failure self-reap did NOT run — but the caller never read it reaps the OWNED cookie
  // through the ledger. This is the delivered-but-unread cookie the umbrella's abandon arm names
  // by token; without the cancel it would survive until teardown.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancel_for_a_delivered_but_unread_cookie_reaps_it() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let name = ".tributaries-sync-1-1-1";
    let path = PathBuf::from("/r").join(name);
    // The write lands and CLAIMS while the caller's receiver is alive but unread.
    let on_reply = sync_root_pending(&rig, scope, "/r", name).await;
    settle(|| rig.fs.cookie_writes() == vec![path.clone()]).await;
    settle_cookie_count(&rig, 1).await;
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the write's Ok reply succeeded and the cookie is OWNED, unread"
    );

    // The caller walks away UNREAD. The driver already saw its send succeed, so nothing
    // self-reaps — the cookie would survive without the token cancel.
    drop(on_reply);

    // The abandon arm cancels by NAME: the driver finds it OWNED and reaps it through the
    // removal state machine.
    rig
      .cookie_removes
      .send(CookieReap::Cancel(name.to_owned()))
      .await
      .unwrap();
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    assert!(
      rig.fs.cookie_removes().contains(&path),
      "the owned cookie was unlinked by the cancel"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the record went with the confirmed unlink"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no file survives the cancel of a delivered-but-unread cookie"
    );

    // The gate and scope are unharmed — a fresh sync still lands.
    admit_sync(&rig, scope, "/r", ".tributaries-sync-1-1-2").await;
  }

  // Finding 1 (fs half): a cancel that arrives while the write is STILL IN THE POOL tombstones
  // the name; when the write lands, its claim consumes the tombstone and is REFUSED, so the write
  // self-reaps the file it just created. The refusal is driven by the tombstone alone (the caller
  // is kept alive), which is why the reply reads `Retired`.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancel_while_the_write_is_in_the_pool_makes_it_self_reap() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let name = ".tributaries-sync-1-2-1";
    // Hold the write in the pool: DISPATCHED, not yet claimed.
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", name).await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write is in the pool, not yet claimed"
    );

    // Cancel by name while it is in the pool: it is not owned, so the driver TOMBSTONES it.
    rig
      .cookie_removes
      .send(CookieReap::Cancel(name.to_owned()))
      .await
      .unwrap();
    settle_tombstones(&rig, 1).await;
    assert_eq!(
      cancel_tombstones(&rig).await,
      1,
      "an in-pool write's cancel is a tombstone"
    );

    // Release the held write: its claim CONSUMES the tombstone and is refused, so it self-reaps
    // the file and answers its still-held caller `Retired`.
    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the driver replies"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "the tombstone forced the claim to refuse — the reply is Retired"
    );
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the refused write self-reaped the file it created"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(cookie_count(&rig).await, 0, "nothing was left owned");
    assert_eq!(
      cancel_tombstones(&rig).await,
      0,
      "the tombstone was consumed by the claim — it never survives its write"
    );
  }

  // The tombstone boundedness rule across all three cancel-versus-write orderings: an
  // unknown-name cancel creates none, a cancel-then-complete's tombstone is consumed by the
  // claim, and a complete-then-cancel is an owned reap that never tombstones. Each ends with zero
  // outstanding tombstones — the bound `|cancelled| <= writes_in_flight` holds.
  #[tokio::test(flavor = "multi_thread")]
  async fn cancel_tombstones_never_survive_their_writes() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Ordering A — cancel an UNKNOWN name: dropped, never a tombstone (the boundedness rule
    // forbids a tombstone for a write not provably in flight).
    rig
      .cookie_removes
      .send(CookieReap::Cancel(".tributaries-sync-nobody".to_owned()))
      .await
      .unwrap();
    for _ in 0..8 {
      tokio::task::yield_now().await;
    }
    assert_eq!(
      cancel_tombstones(&rig).await,
      0,
      "a cancel for an unknown name creates no tombstone"
    );

    // Ordering B — cancel-then-complete: the tombstone is created while the write is in the pool,
    // then CONSUMED by the refused claim.
    {
      let name = ".tributaries-sync-1-3-1";
      let hold = rig.fs.hold_cookie_writes();
      let on_reply = sync_root_pending(&rig, scope, "/r", name).await;
      settle(|| rig.fs.cookie_dispatches() == 1).await;
      rig
        .cookie_removes
        .send(CookieReap::Cancel(name.to_owned()))
        .await
        .unwrap();
      settle_tombstones(&rig, 1).await;
      assert_eq!(
        cancel_tombstones(&rig).await,
        1,
        "the in-pool write's name is tombstoned"
      );
      hold.release();
      let _ = on_reply.await;
      settle_cookie_count(&rig, 0).await;
      settle_tombstones(&rig, 0).await;
      assert_eq!(
        cancel_tombstones(&rig).await,
        0,
        "the claim consumed the tombstone — it never survives its write"
      );
    }

    // Ordering C — complete-then-cancel: the write is OWNED first, so the later cancel reaps it
    // directly and never creates a tombstone.
    {
      let name = ".tributaries-sync-1-3-2";
      let path = admit_sync(&rig, scope, "/r", name).await;
      settle_cookie_count(&rig, 1).await;
      rig
        .cookie_removes
        .send(CookieReap::Cancel(name.to_owned()))
        .await
        .unwrap();
      settle(|| rig.fs.cookie_removes().contains(&path)).await;
      settle_cookie_count(&rig, 0).await;
      assert_eq!(
        cancel_tombstones(&rig).await,
        0,
        "an owned-then-cancelled cookie is reaped directly, never tombstoned"
      );
      assert!(
        rig.fs.files_under("/r").is_empty(),
        "the owned cookie was reaped by the cancel"
      );
    }
  }

  // Finding 2: a self-reap for an ABANDONED caller (its `reply.send(Ok)` fails) whose own unlink
  // FAILS must RE-ASSERT ownership, never discard it — the record is retained as failed WHILE the
  // file is still on disk, and the DRIVER'S OWN retry (no external request) later confirms it.
  //
  // Fail-on-old (the self-reap discards ownership on unlink failure): the record is gone with the
  // file still on disk, so the `cookie_count == 1` retain assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_failed_reply_abandon_self_reap_retains_ownership_and_retries() {
    let rig = rig_with_config(64, retain_config());
    let scope = watch(&rig, "/r").await;

    let name = ".tributaries-sync-2-1-1";
    // Hold the write, then abandon the caller so its `reply.send(Ok)` will FAIL when the write
    // lands — the reply-fail self-reap path.
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", name).await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    drop(on_reply);
    // The self-reap's own unlink FAILS once.
    rig.fs.fail_next_cookie_removes(1);
    hold.release();

    settle(|| rig.fs.cookie_remove_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the self-reap attempt reached the pool and failed"
    );
    // The record is RETAINED as failed while the file is still present — never orphaned.
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "ownership is retained across the failed self-reap"
    );
    assert!(
      !rig.fs.files_under("/r").is_empty(),
      "the file is still on disk, still retry-owned"
    );

    // The driver retries ON ITS OWN and confirms — no external request.
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the driver's own retry removed the file"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the record dropped only once the retry confirmed"
    );
  }

  // Finding 2: a self-reap for a REFUSED claim (the scope retired under the in-flight write)
  // whose unlink FAILS is OWNED as failed, and the retry that removes it is scope-INDEPENDENT —
  // the scope is already gone, yet the driver still owns and drives the file to removal.
  //
  // Fail-on-old (the refused self-reap orphans a failed unlink): no record is inserted, so
  // `cookie_count == 1` fails and the file is stranded forever.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_refused_claim_self_reap_failure_is_owned_and_retried() {
    let rig = rig_with_config(64, retain_config());
    let scope = watch(&rig, "/r").await;

    let name = ".tributaries-sync-2-2-1";
    // The write must be IN the pool before the scope retires (a still-parked write is revoked at
    // its fence instead of self-reaping).
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", name).await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;

    // Retire the scope: the raised flag makes the landing write's claim REFUSE.
    let (reply, on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(on_unwatch.await.unwrap(), "the live scope was unwatched");

    // The refused self-reap's unlink FAILS once: the file must be OWNED as failed, not orphaned.
    rig.fs.fail_next_cookie_removes(1);
    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the driver replies"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "the retiring scope refused the claim"
    );

    settle(|| rig.fs.cookie_remove_dispatches() == 1).await;
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the refused-and-failed self-reap OWNS the file, never orphans it"
    );
    assert!(
      !rig.fs.files_under("/r").is_empty(),
      "the file is still present, retry-owned"
    );

    // The retry is scope-INDEPENDENT — the scope is gone, yet the driver removes the file.
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the scope-independent retry removed the orphan-candidate"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the record dropped once the retry confirmed"
    );
  }

  // Finding 3: duplicate reap requests against a HUNG unlink coalesce to ONE job — the
  // single-flight-per-path invariant. A caller that times out and storms 50 reaps against a wedged
  // mount cannot pile 50 blocking unlink jobs (the pool-exhaustion re-creation Codex named).
  //
  // Fail-on-old (no coalescing): 50 dispatches.
  #[tokio::test(flavor = "multi_thread")]
  async fn duplicate_reap_requests_for_a_hung_unlink_coalesce_to_one_job() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-1-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The terminal unlink hangs; a caller storms 50 reap requests against it.
    let hold = rig.fs.hold_cookie_removes();
    for _ in 0..50 {
      rig
        .cookie_removes
        .send(CookieReap::Remove(path.clone()))
        .await
        .unwrap();
    }
    // The first dispatches ONE unlink (now `Removing`); the other 49 coalesce.
    settle(|| rig.fs.cookie_remove_dispatches() == 1).await;
    for _ in 0..16 {
      tokio::task::yield_now().await;
    }
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "50 requests against a hung unlink coalesce to exactly ONE job"
    );

    // Released, the single unlink confirms and the record drops.
    hold.release();
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    settle_cookie_count(&rig, 0).await;
    assert_eq!(cookie_count(&rig).await, 0);
  }

  // Finding 3: a transient unlink failure is retried by the DRIVER, not the requester — ONE reap
  // request suffices, and the driver's own backed-off retry drives the confirm.
  //
  // Fail-on-old (no retry owner): the file persists forever after its single failed dispatch.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_transient_unlink_failure_is_retried_by_the_driver_not_the_requester() {
    let rig = rig_with_config(64, tuned_config());
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-2-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // ONE reap request; the first unlink fails transiently.
    rig.fs.fail_next_cookie_removes(1);
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();

    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the driver's own retry removed the file after ONE request"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(cookie_count(&rig).await, 0);
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      2,
      "exactly two dispatches: the failed attempt and the driver's retry"
    );
  }

  // Finding 3: past its attempt budget a failing unlink PARKS — it stops retrying (no CPU-spin)
  // yet stays honestly OWNED, and an explicit reap RE-ARMS it with a fresh budget (T9).
  #[tokio::test(flavor = "multi_thread")]
  async fn the_retry_budget_parks_without_spinning() {
    let rig = rig_with_config(64, tuned_config()); // budget = 3
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-3-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The unlink fails effectively forever.
    rig.fs.fail_next_cookie_removes(10_000);
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();

    // One initial attempt plus a budget of 3 retries, then the record PARKS.
    settle(|| rig.fs.cookie_remove_dispatches() == 4).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      4,
      "one attempt plus a budget of 3 retries"
    );

    // Parked: over a generous window the count does NOT grow (no spin), and the cookie is owned.
    for _ in 0..30 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      4,
      "past the budget the record PARKS — no CPU-spinning retry"
    );
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the parked cookie is still honestly owned"
    );

    // A fresh explicit reap RE-ARMS the parked record with a fresh budget (T9): dispatches grow.
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();
    settle(|| rig.fs.cookie_remove_dispatches() >= 5).await;
    assert!(
      rig.fs.cookie_remove_dispatches() >= 5,
      "an explicit reap re-arms a parked record (T9)"
    );

    // Close bridges to finding 4: the still-owned, unremovable cookie holds close in NotQuiesced.
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
      .await
      .expect("close returns within the grace")
      .expect("the driver replied");
    assert!(
      pending >= 1,
      "the still-owned, unremovable cookie holds close in NotQuiesced"
    );
  }

  // Finding 3: a scope whose cookie cleanup is BACKLOGGED past the per-scope cap refuses new syncs
  // with the retryable `CleanupBacklog` — the hard memory bound. On a recovered fs the backlog
  // would drain and syncs resume; here it stays wedged so the cap is provably hit.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_backlogged_scope_refuses_new_syncs_retryably() {
    let rig = rig_with_config(64, tuned_config()); // backlog_cap = 3
    let scope = watch(&rig, "/r").await;

    // Every unlink fails: the backlog fills with owned-but-unremovable cookies.
    rig.fs.fail_next_cookie_removes(1_000_000);

    // Fill the scope's backlog to the cap: three syncs, each reaped-but-failing.
    for seq in 0..3 {
      let name = format!(".tributaries-sync-3-4-{seq}");
      let path = admit_sync(&rig, scope, "/r", &name).await;
      rig
        .cookie_removes
        .send(CookieReap::Remove(path))
        .await
        .unwrap();
      settle_cookie_count(&rig, seq + 1).await;
      assert_eq!(
        cookie_count(&rig).await,
        seq + 1,
        "the failing unlink keeps the cookie owned"
      );
    }

    // The 4th sync is refused CleanupBacklog — a transient, retryable refusal with no physical
    // write (drive past any lingering single-flight gate to reach the cap check).
    let mut outcome = None;
    for _ in 0..400 {
      match sync_root(&rig, scope, "/r", ".tributaries-sync-3-4-cap").await {
        Err(crate::error::SyncRootError::WriteInFlight) => {
          tokio::task::yield_now().await;
          tokio::time::sleep(Duration::from_millis(5)).await;
        }
        other => {
          outcome = Some(other);
          break;
        }
      }
    }
    assert!(
      matches!(
        outcome,
        Some(Err(crate::error::SyncRootError::CleanupBacklog))
      ),
      "the backlogged scope refuses a new sync with the retryable CleanupBacklog, got {outcome:?}"
    );
    assert_eq!(
      cookie_count(&rig).await,
      3,
      "the refusal wrote nothing — the ledger is unchanged at the cap"
    );
  }

  // Finding 4: close reports NotQuiesced BECAUSE a cookie is still owned — a mount whose unlinks
  // fail through every grace retry leaves the file, and close counts the LIVE LEDGER, not a job
  // count that a failed unlink would have drained.
  //
  // Fail-on-old (close counts jobs, ignores the ledger): close returns 0 with the file still on
  // disk — the `pending >= 1` assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_reports_not_quiesced_while_a_cookie_survives_repeated_unlink_failures() {
    let rig = rig_with_config(64, tuned_config());
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-4-1-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // Every unlink fails, through every grace retry.
    rig.fs.fail_next_cookie_removes(100_000);
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
      .await
      .expect("close returns within the grace, never wedged")
      .expect("the driver replied");

    assert!(
      pending >= 1,
      "close reports NotQuiesced BECAUSE the cookie is still owned"
    );
    assert!(
      rig.fs.files_under("/r").contains(&path),
      "the file remains — the live ledger, not a drained job count, is the drain condition"
    );
  }

  // Finding 4: a transiently-failing terminal unlink is RETRIED by the close drain INSIDE the
  // grace — reply `Ok(0)` with the file already gone AT reply time, driven by the drain's own
  // retry, not the registry `Drop`'s post-reply detached tail (whose completion the reply never
  // waits for). The dispatch count is the discriminator: exactly the failed attempt plus the
  // drain's retry.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_retries_a_transiently_failing_unlink_inside_the_grace() {
    let rig = rig_with_config(64, tuned_config());
    let scope = watch(&rig, "/r").await;

    let _path = sync_root(&rig, scope, "/r", ".tributaries-sync-4-2-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The terminal unlink fails ONCE; the drain's own retry (inside the grace) drives the confirm.
    rig.fs.fail_next_cookie_removes(1);
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
      .await
      .expect("close returns within the grace")
      .expect("the driver replied");

    assert_eq!(
      pending, 0,
      "the transient failure was retried and confirmed INSIDE the grace"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the file is gone AT reply time — the drain's retry, not Drop's detached tail"
    );
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      2,
      "exactly the failed attempt and the drain's own retry"
    );
  }

  /// A config whose GLOBAL cookie cap is the low bound while the per-scope cap
  /// sits well above it, so a churn of fresh scopes — each owning at most one
  /// cookie — can only ever be refused by the watcher-wide ceiling.
  fn low_global_cap_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(5),
      cookie_retry_cap: Duration::from_millis(20),
      cookie_retry_budget: 3,
      cookie_backlog_cap: 8,
      cookie_global_cap: 3,
      ..config()
    }
  }

  /// A config whose retry backoff climbs fast under a large cap and a generous
  /// budget, so a few consecutive unlink failures park a record on a deadline
  /// BEYOND the close grace — the state the close-sweep deadline clamp rescues.
  fn far_backoff_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(400),
      cookie_retry_cap: Duration::from_secs(5),
      cookie_retry_budget: 8,
      cookie_backlog_cap: 8,
      cookie_global_cap: 128,
      ..config()
    }
  }

  // The global cookie cap ceilings total owned cookies across every scope, live
  // or retired. A sync → failing-cleanup → unwatch → rewatch churn mints a fresh
  // scope each round, and a fresh scope's own per-scope backlog is always one, so
  // only a watcher-wide ceiling can bound the residue the retired scopes leave.
  // Once the cap is reached a further sync is refused `CleanupBacklog`, and the
  // owned count never climbs past it however long the churn runs.
  #[tokio::test(flavor = "multi_thread")]
  async fn churn_across_retired_scopes_is_bounded_by_the_global_cap() {
    let rig = rig_with_config(64, low_global_cap_config());
    // Every unlink fails forever, so each round's cookie survives its scope's
    // retirement and adds to the global residue.
    rig.fs.fail_next_cookie_removes(1_000_000);

    let cap = low_global_cap_config().cookie_global_cap;
    let mut admitted = 0usize;
    // Churn several rounds past the cap, each on a fresh sibling root.
    for i in 0..(cap + 3) {
      let root = format!("/ra{i}");
      rig.fs.put(&root, FileKind::Dir, 100 + i as u64);
      let scope = watch(&rig, &root).await;
      let name = format!(".tributaries-sync-A-{i}");
      match sync_root(&rig, scope, &root, &name).await {
        Ok(path) => {
          admitted += 1;
          // Ask for the cookie's removal; it fails permanently, so the owned
          // record is retained across the unwatch below.
          rig
            .cookie_removes
            .send(CookieReap::Remove(path))
            .await
            .unwrap();
        }
        Err(crate::error::SyncRootError::CleanupBacklog) => {}
        Err(other) => panic!("unexpected sync error: {other:?}"),
      }
      // Retire the scope. Its failing cookie record stays owned — a retired scope
      // no longer re-arms it, but the file is never orphaned.
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      let _ = on_reply.await;
      assert!(
        cookie_count(&rig).await <= cap,
        "the global cap bounds total owned cookies across retired scopes"
      );
    }

    assert_eq!(
      admitted, cap,
      "exactly the cap's worth of syncs land before the global ceiling refuses"
    );
    assert_eq!(
      cookie_count(&rig).await,
      cap,
      "the residue sits exactly at the global cap, never beyond it"
    );

    // With the cap reached, one more sync on yet another fresh scope is refused
    // retryably — whatever scope owns the residue.
    rig.fs.put("/ra-final", FileKind::Dir, 999);
    let scope = watch(&rig, "/ra-final").await;
    assert!(
      matches!(
        sync_root(&rig, scope, "/ra-final", ".tributaries-sync-A-final").await,
        Err(crate::error::SyncRootError::CleanupBacklog)
      ),
      "a fresh scope is refused because the GLOBAL residue is at the cap"
    );
  }

  // The dedicated cleanup lane makes steady progress even under a saturating
  // command flood. The live loop's select is command-biased, so without a
  // loop-top fairness drain a caller that keeps the bounded command mailbox
  // continuously ready would starve queued reaps — cookies would linger owned.
  // Form: a sustained real flood (a spawned task that never lets the command
  // channel drain) racing a reap for a live owned cookie.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_command_flood_does_not_starve_the_cleanup_lane() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-B-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // Saturate the bounded command channel continuously with a cheap command the
    // driver answers synchronously and statelessly, so the biased select always
    // finds `commands` ready at poll time.
    let commands = rig.commands.clone();
    let flood = tokio::spawn(async move {
      loop {
        let (reply, _drop) = futures_channel::oneshot::channel();
        if commands
          .send(Command::DebugCookieCount { reply })
          .await
          .is_err()
        {
          break;
        }
      }
    });

    // Under the sustained flood, request the reap on the dedicated lane.
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();

    // The loop-top fairness drain services it regardless of the flood: the unlink
    // is dispatched and confirms. Observed fs-side — the flooded command channel
    // cannot carry an observation command through.
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    flood.abort();

    assert!(
      rig.fs.cookie_removes().contains(&path),
      "the queued reap was serviced despite the command flood"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the cookie file is gone"
    );
    // And the registry no longer owns it.
    settle_cookie_count(&rig, 0).await;
    assert_eq!(cookie_count(&rig).await, 0, "the cookie is no longer owned");
  }

  // The registry's abnormal-path Drop dispatches a best-effort unlink only for a
  // record with NO unlink already in flight. A cookie the close sweep already
  // moved to `Removing` (its unlink hung past the grace) has one — a second
  // unlink for the same path is exactly the duplicate the single-flight choke
  // point forbids. So a hung cookie is dispatched exactly ONCE across the whole
  // close.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_dispatches_exactly_one_unlink_for_a_hung_cookie() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let _path = sync_root(&rig, scope, "/r", ".tributaries-sync-C-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The terminal unlink hangs: the close sweep dispatches it and it never
    // confirms within the grace, so the record stays `Removing` through the Drop.
    let hold = rig.fs.hold_cookie_removes();
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
      .await
      .expect("close returns within the grace, never wedged on a hung unlink")
      .expect("the driver replied");
    assert_eq!(pending, 1, "the hung cookie is counted once");

    // The Drop has already run — it precedes the close reply. Give any erroneous
    // second dispatch time to reach the pool, then prove it never happened: the
    // sweep's single unlink is the only one.
    settle(|| rig.fs.cookie_remove_dispatches() >= 2).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the sweep dispatched one unlink; the Drop skipped the still-Removing record"
    );

    // Released, the one hung unlink completes and the file is gone.
    hold.release();
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(rig.fs.files_under("/r").is_empty());
  }

  // A write whose `reply.send(Ok)` fails after it CLAIMED its record is one
  // physical obligation that briefly appears in two places: the claimed record
  // (state `Removing`, its self-reap unlink in flight) AND its scope's still-open
  // `writes_in_flight` slot (cleared only when the write's `CookieWriteDone`
  // lands, which the hung unlink defers). The close count must tally it ONCE.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_counts_a_held_self_reap_obligation_once() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Hold the write in the pool so the reply receiver can be dropped in the
    // window after dispatch (the scope is in `writes_in_flight`) but before the
    // write lands. The parked write is already past the cover-fence cancel prune,
    // so it still writes, claims, and then finds its reply send failed.
    let write_hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-D-1").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write is dispatched and parked"
    );

    // Arm the self-reap's unlink to hang, drop the receiver, then release the
    // write: it lands, claims (the scope is live), its `reply.send(Ok)` fails, and
    // its self-reap transitions the record to `Removing` and hangs in the unlink.
    let remove_hold = rig.fs.hold_cookie_removes();
    drop(on_reply);
    write_hold.release();
    settle(|| rig.fs.cookie_remove_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the self-reap's unlink is in flight, held"
    );
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the claimed record is owned, its scope still in flight"
    );

    // Close: the one obligation is counted once, not once per place it appears.
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
      .await
      .expect("close returns within the grace")
      .expect("the driver replied");
    assert_eq!(
      pending, 1,
      "one physical obligation — the held self-reap — counted once, not twice"
    );

    // Release the hung unlink so the parked pool thread can finish.
    remove_hold.release();
  }

  // A cookie whose unlink has failed several times sits on an exponential-backoff
  // deadline that can exceed the close grace. The close sweep pulls every pending
  // retry forward to one base delay, so a record on a far deadline is still
  // retried inside the grace — and on a recovered fs the retry confirms, so close
  // proves quiescence instead of reporting a spurious NotQuiesced.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_retries_a_pre_existing_long_backoff_within_the_grace() {
    let rig = rig_with_config(64, far_backoff_config());
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-E-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // Fail the unlink three times: with a 400ms base the third failure parks the
    // record on a ~1.6s retry deadline, well past the 1s grace. The fourth attempt
    // (the fs has recovered) would succeed, but it is scheduled far out.
    rig.fs.fail_next_cookie_removes(3);
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();
    settle(|| rig.fs.cookie_remove_dispatches() >= 3).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      3,
      "exactly three failed attempts"
    );

    // Let the third failure's reschedule land, and confirm the far retry has NOT
    // auto-fired: the record waits on a deadline beyond the grace.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      3,
      "the far retry has not fired — the record waits on a >1s deadline"
    );
    assert_eq!(cookie_count(&rig).await, 1, "the cookie is still owned");

    // Close: the sweep clamps the far deadline into the grace; the retry fires and
    // confirms against the recovered fs.
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
      .await
      .expect("close returns within the grace")
      .expect("the driver replied");
    assert_eq!(
      pending, 0,
      "the clamped retry confirmed inside the grace — no spurious NotQuiesced"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the cookie file is gone at reply time"
    );
  }

  /// Settles until cookie-remove dispatches STOP growing across a window longer
  /// than the retry cap: every failing record has spent its budget and PARKED,
  /// with no scheduled retry left to fire. Under a still-failing fs a stable
  /// dispatch count is the proof that the backlog is fully parked — the
  /// precondition the recovery cell must start from, since a record still inside
  /// its budget would drain on the healed fs through the driver's OWN retry
  /// timer, masking whether the admission-time re-arm did the work.
  async fn settle_removes_parked(rig: &Rig) {
    let mut last = usize::MAX;
    for _ in 0..40 {
      let now = rig.fs.cookie_remove_dispatches();
      if now == last {
        return;
      }
      last = now;
      tokio::time::sleep(Duration::from_millis(60)).await;
    }
  }

  // A since-recovered filesystem DRAINS a global-cap-filling backlog of PARKED
  // (budget-spent) records left on RETIRED scopes, and syncs resume — there is no
  // permanent lockout. A parked record on a retired scope has no live scope to
  // sweep it and no timer to retry it, so only the `SyncRoot`-admission re-arm —
  // kicked right before a cap refusal — can ever retry it: the caller that hits
  // the backlog is what drives recovery.
  //
  // Fail-on-old (the admission re-arm disabled): the parked records never retry,
  // the owned count stays pinned at the cap, and every later sync stays refused —
  // the drain settle times out and its `< cap` assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_recovered_fs_drains_the_backlog_and_admits_new_syncs() {
    // global_cap = 3 is the binding ceiling; backlog_cap = 8 never binds, since
    // each scope below owns exactly one cookie.
    let rig = rig_with_config(64, low_global_cap_config());
    let cap = low_global_cap_config().cookie_global_cap;

    // Every unlink fails while the backlog is built, so each scope's cookie
    // survives its retirement and its removal budget spends down to a PARK.
    rig.fs.fail_next_cookie_removes(1_000_000);

    // Fill the GLOBAL cap with parked records spread across scopes that are then
    // RETIRED: watch → sync (the write lands) → unwatch (the retire sweep reaps
    // it, the reap fails through the whole budget, the record parks with no live
    // scope left to re-arm it).
    for i in 0..cap {
      let root = format!("/rp{i}");
      rig.fs.put(&root, FileKind::Dir, 200 + i as u64);
      let scope = watch(&rig, &root).await;
      let _path = sync_root(
        &rig,
        scope,
        &root,
        &format!(".tributaries-sync-r10-recover-{i}"),
      )
      .await
      .expect("the write lands");
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      let _ = on_reply.await;
      settle_cookie_count(&rig, i + 1).await;
      assert_eq!(
        cookie_count(&rig).await,
        i + 1,
        "the failing reap keeps the retired scope's cookie owned"
      );
    }
    settle_removes_parked(&rig).await;
    assert_eq!(
      cookie_count(&rig).await,
      cap,
      "the residue sits exactly at the global cap, every record parked"
    );

    // At the cap a fresh live scope is refused retryably. On the fixed driver this
    // refusal ALSO kicks the re-arm — the fs is still failing, so the re-armed
    // records simply re-park and the cap holds.
    rig.fs.put("/rk", FileKind::Dir, 900);
    let kicker = watch(&rig, "/rk").await;
    assert!(
      matches!(
        sync_root(&rig, kicker, "/rk", ".tributaries-sync-r10-recover-cap").await,
        Err(crate::error::SyncRootError::CleanupBacklog)
      ),
      "a fresh scope is refused while the global residue is at the cap"
    );
    settle_removes_parked(&rig).await;
    assert_eq!(
      cookie_count(&rig).await,
      cap,
      "a still-failing fs drains nothing — the residue is parked back at the cap"
    );

    // The filesystem HEALS: unlinks succeed from here on.
    rig.fs.fail_next_cookie_removes(0);

    // The next sync attempt kicks the re-arm, which re-dispatches the parked
    // records; they confirm against the healed fs and leave the ledger. The
    // attempt itself is still refused — admission reads the cap before the drain
    // it just kicked can land — but it is what drives recovery.
    assert!(
      matches!(
        sync_root(&rig, kicker, "/rk", ".tributaries-sync-r10-recover-kick").await,
        Err(crate::error::SyncRootError::CleanupBacklog)
      ),
      "the kicking sync is refused at admission, having re-armed the parked backlog"
    );
    settle_cookie_count(&rig, 0).await;
    assert!(
      cookie_count(&rig).await < cap,
      "the recovered fs drained the parked backlog — no permanent lockout"
    );

    // Syncs resume, on the SAME driver and the SAME watch — no operator action.
    let path = admit_sync(&rig, kicker, "/rk", ".tributaries-sync-r10-recover-ok").await;
    assert_eq!(
      path,
      PathBuf::from("/rk/.tributaries-sync-r10-recover-ok"),
      "a new sync lands once the backlog has drained"
    );
  }

  // The close obligation count is taken from ONE ledger snapshot, so it can never
  // report a false `Ok(0)` over a live obligation. The foreclosed race: an owned
  // record's unlink confirming BETWEEN a read of the owned IDS (which excluded a
  // same-id in-flight write as the claimed-record de-dup) and a read of `owned`
  // drops a TWO-snapshot count to zero while that write is still outstanding.
  //
  // Form (b), the direct unit: the claimed-self-reap race — one write present in
  // BOTH the ledger and `writes_in_flight` under a single incarnation id — and the
  // inter-snapshot window cannot be forced deterministically through the driver,
  // so the ledger state is built directly and the count asserted at each snapshot
  // point. Faithful because the count is the whole of what close reports, and the
  // single-snapshot guarantee is exactly "1 wherever the atomic read falls
  // relative to the confirm" — asserted below against the torn read that yields 0.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_obligation_count_forecloses_a_false_ok_zero() {
    fn insert_owned(reg: &CookieRegistry<FakeFs>, scope: u64, name: &str, path: &str) -> CookieId {
      let mut inner = lock_ledger(&reg.ledger);
      inner.next_cookie_id += 1;
      let id = CookieId(inner.next_cookie_id);
      let path = PathBuf::from(path);
      inner.obligations.insert(
        id,
        Obligation {
          scope: ScopeId::new(NonZeroU64::new(scope).unwrap()),
          name: name.to_owned(),
          id,
          path: Some(path.clone()),
          last_failure_seq: 0,
          state: RemovalState::Owned,
        },
      );
      inner.by_name.insert(name.to_owned(), id);
      inner.by_path.insert(path, id);
      id
    }
    fn writes_in_flight(
      entries: &[(u64, &str, CookieId)],
    ) -> BTreeMap<ScopeId, (String, CookieId)> {
      entries
        .iter()
        .map(|(scope, name, id)| {
          (
            ScopeId::new(NonZeroU64::new(*scope).unwrap()),
            ((*name).to_owned(), *id),
          )
        })
        .collect()
    }

    // The race state: scope 1's write both CLAIMED its record "N" (id X, unlink
    // unconfirmed) AND still sits in `writes_in_flight` under that same id X — a
    // reply-failed self-reap mid-flight, the one obligation the dedup governs.
    let reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(FakeFs::new(1));
    let id_n = insert_owned(&reg, 1, "N", "/r1/N");
    let in_flight = writes_in_flight(&[(1, "N", id_n)]);
    assert_eq!(
      reg.obligation_count(&in_flight),
      1,
      "an outstanding obligation is counted — never a false 0"
    );

    // The single snapshot is immune to WHERE it falls relative to the owned
    // record's unlink confirming: drop that record (the confirm) and the same
    // obligation is STILL counted, now as the in-flight write whose id the ledger
    // no longer owns. Both snapshot points yield 1.
    lock_ledger(&reg.ledger).retire(id_n, Reaped::ConfirmedGone);
    assert_eq!(
      reg.obligation_count(&in_flight),
      1,
      "after the confirm the same obligation is still counted, via the in-flight write"
    );

    // The foreclosed hazard, made representable: the REPLACED two-snapshot form —
    // read the owned IDS first (they dedup the same-id in-flight write out), let
    // the owned unlink confirm, THEN read `owned` — sums to a FALSE 0 with
    // obligation "N" still in flight. This is the read the single snapshot above
    // makes unrepresentable.
    let id_n = insert_owned(&reg, 1, "N", "/r1/N");
    let in_flight = writes_in_flight(&[(1, "N", id_n)]);
    let ids_snapshot = {
      let inner = lock_ledger(&reg.ledger);
      let owned_ids: std::collections::HashSet<CookieId> =
        inner.obligations.keys().copied().collect();
      in_flight
        .values()
        .filter(|(_, id)| !owned_ids.contains(id))
        .count()
    };
    lock_ledger(&reg.ledger).retire(id_n, Reaped::ConfirmedGone);
    let owned_snapshot = lock_ledger(&reg.ledger).obligations.len();
    assert_eq!(
      ids_snapshot + owned_snapshot,
      0,
      "a read straddling the confirm sums to a FALSE 0 — the single snapshot reads 1 at both points"
    );

    // An UNCLAIMED in-flight write (no owned record bears its id) is one
    // obligation, counted once.
    let reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(FakeFs::new(1));
    assert_eq!(
      reg.obligation_count(&writes_in_flight(&[(1, "M", CookieId(999))])),
      1,
      "an unclaimed in-flight write is one obligation"
    );

    // A CLAIMED self-reap — its `reply.send` failed, so it both claimed record
    // id X AND still sits in `writes_in_flight` under that same id — is ONE
    // physical obligation, counted once rather than once per place it appears.
    let reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(FakeFs::new(1));
    let id_m = insert_owned(&reg, 1, "M", "/r/M");
    assert_eq!(
      reg.obligation_count(&writes_in_flight(&[(1, "M", id_m)])),
      1,
      "a claimed self-reap is one obligation, counted once and never twice"
    );

    // Two DISTINCT in-flight writes reusing ONE name across disjoint scopes (a
    // direct-API name reuse — the umbrella never mints it) are TWO physical
    // obligations: each carries its own dispatch id, so id-dedup counts both where
    // the old name-dedup collapsed them to one (R12-F3).
    let reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(FakeFs::new(1));
    assert_eq!(
      reg.obligation_count(&writes_in_flight(&[
        (1, "N", CookieId(1)),
        (2, "N", CookieId(2))
      ])),
      2,
      "two distinct same-name in-flight writes each count once — id-dedup, never name-dedup"
    );
  }

  // The accepted residual, asserted HONEST: an orderly-close unlink that hangs
  // past the grace and only THEN fails is skipped by the registry `Drop` and its
  // file persists — but close never claimed quiescence over it. Close counts every
  // owned record, so the un-removed cookie comes back in `pending` (`NotQuiesced`)
  // rather than being silently dropped or falsely reported `Ok`.
  //
  // This documents the residual's honesty; it does NOT assert the file is reaped.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_orderly_close_honestly_counts_a_hung_then_failing_unlink() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-r10-residual-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The close-sweep unlink HANGS past the grace, and is armed to FAIL once
    // finally released: a hung-then-failing terminal unlink whose file can never
    // be reclaimed. The hold parks the job before the failure is consulted, so the
    // whole grace elapses with the record `Removing`.
    let hold = rig.fs.hold_cookie_removes();
    rig.fs.fail_next_cookie_removes(1_000_000);

    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(Duration::from_secs(5), on_close)
      .await
      .expect("close returns within the grace, never wedged on the hung unlink")
      .expect("the driver replied");
    assert!(
      pending >= 1,
      "the hung-then-failing unlink is honestly counted as outstanding — never a false Ok"
    );

    // Exactly one unlink was dispatched: the `Drop` skipped the still-`Removing`
    // record rather than duplicating a job the single-flight choke point forbids.
    settle(|| rig.fs.cookie_remove_dispatches() >= 2).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the sweep dispatched one unlink; the Drop skipped the still-Removing record"
    );

    // Release the hung unlink — armed to fail, so it confirms nothing and the file
    // stays. The residual is real, and close already reported it in `pending`.
    hold.release();
    assert!(
      rig.fs.files_under("/r").contains(&path),
      "the hung-then-failing cookie persists — the residual close counted honestly, never reaped and never falsely reported gone"
    );
  }

  // ==== R11-3: the forced same-path ABA and the id guards (cells 1–4) ====

  // The flagship R11-3 cell, forced deterministically. A confirmed unlink for a
  // record that has since been REPLACED at the same path (a direct-API name
  // reuse recreating the file after the old unlink physically ran) must NOT drop
  // the successor: the id guard on the confirm-drop makes the stale completion a
  // no-op. Without it, the stale confirm deletes the live successor record — an
  // untracked file on disk plus a false `Ok(0)` at close (Codex's exact repro).
  //
  // Fail-on-old (the confirm-drop's id guard removed): the stale confirm's
  // path-only drop deletes the successor record — the count drops to 0 with the
  // file still present, and the final close would report `Ok(0)` over `P`.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_confirmed_unlink_for_a_replaced_record_does_not_drop_it() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    let name = ".tributaries-sync-aba-1";

    // First incarnation: write N → P, settle its `CookieWriteDone` (gate open).
    let path = sync_root(&rig, scope, "/r", name)
      .await
      .expect("the first write lands");
    assert_eq!(path, PathBuf::from("/r/.tributaries-sync-aba-1"));
    settle_cookie_count(&rig, 1).await;

    // Reap it, but HOLD the pool job at the R11-3 preemption window: the unlink
    // syscall has run (the file is gone) but the job has not yet taken the
    // ledger lock to confirm-drop.
    let hold = rig.fs.hold_cookie_remove_confirms();
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();
    settle(|| !rig.fs.files_under("/r").contains(&path) && rig.fs.cookie_remove_dispatches() == 1)
      .await;
    assert!(
      !rig.fs.files_under("/r").contains(&path),
      "the unlink syscall ran — the file is gone at the preemption window"
    );
    assert_eq!(rig.fs.cookie_remove_dispatches(), 1);

    // Second incarnation, SAME dir and name — a direct-API name reuse (the rig
    // drives `SyncRoot`, so this is in contract for the test). `create_new`
    // succeeds (the file is gone), and the claim lands a FRESH incarnation keyed
    // by its own id: the predecessor's held-`Removing` record keeps its own key,
    // so both are tracked at once — the ledger count is pessimistic-honest.
    let path2 = admit_sync(&rig, scope, "/r", name).await;
    assert_eq!(path2, path, "the successor lands at the same reused path");
    assert_eq!(
      cookie_count(&rig).await,
      2,
      "both incarnations are tracked — the predecessor is not displaced by the successor's claim"
    );

    // Release the held confirm: the first unlink's job resumes and confirm-drops
    // — but for the STALE incarnation, so the id guard refuses it.
    hold.release();
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    // Let the stale confirm-drop and its `CookieRemoveDone` fully land.
    for _ in 0..24 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the stale confirm was refused by id — the successor record survives"
    );
    assert!(
      rig.fs.files_under("/r").contains(&path),
      "the successor's file survives the stale confirm"
    );

    // The successor reaps normally now, and close proves quiescence.
    rig
      .cookie_removes
      .send(CookieReap::Remove(path.clone()))
      .await
      .unwrap();
    settle(|| rig.fs.files_under("/r").is_empty() && !rig.fs.cookie_removes().is_empty()).await;
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the successor is confirmed gone"
    );

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let pending = on_reply.await.expect("the driver replies");
    assert_eq!(
      pending, 0,
      "close proves quiescence — no untracked file, no false Ok(0)"
    );
  }

  // The birth-overwrite hazard, forced deterministically: write A creates its
  // file and its CLAIM is delayed; A's file is externally deleted; a same-path
  // write B (a different scope) lands and claims the live file; THEN A's delayed
  // claim fires. Because each claim inserts a record keyed by its own unique
  // incarnation id, A's late claim can never displace B's live record — the two
  // coexist under distinct keys, and both reach a typed terminal.
  //
  // Fail-on-old: with the claim keyed by PATH (an insert that overwrites the
  // record at the landing path), A's late claim OVERWRITES B's live record — the
  // record-identity assertion (B's id still owns its `Owned` state) fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_delayed_claim_never_displaces_a_live_same_path_successor() {
    let fs = FakeFs::new(1);
    let mut reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(fs.clone());
    let scope_a = ScopeId::new(NonZeroU64::new(1).unwrap());
    let scope_b = ScopeId::new(NonZeroU64::new(2).unwrap());
    let name = ".tributaries-sync-h1";
    let path = PathBuf::from("/r").join(name);

    // Write A dispatched and created its file at P; its claim is not run yet.
    let guard_a = reg.dispatch_guard(scope_a, name.to_owned());
    fs.put(&path, FileKind::File, 1);
    // A's file is externally deleted before A ever claims.
    fs.remove(&path);

    // Write B (a different scope) lands at the SAME path and claims: its file is
    // the live one now.
    let guard_b = reg.dispatch_guard(scope_b, name.to_owned());
    fs.put(&path, FileKind::File, 2);
    let id_b = guard_b.claim(&path).expect("B claims the live file");
    {
      let inner = lock_ledger(&reg.ledger);
      assert_eq!(inner.obligations.len(), 1, "only B is tracked so far");
      assert_eq!(inner.by_path.get(&path), Some(&id_b), "by_path names B");
    }

    // A's delayed claim finally fires.
    let id_a = guard_a.claim(&path).expect("A's late claim is admitted");
    assert_ne!(id_a, id_b, "A and B are distinct incarnations");
    {
      let inner = lock_ledger(&reg.ledger);
      // B's live record survives by IDENTITY — its own id still owns its state.
      assert!(
        matches!(
          inner.obligations.get(&id_b).map(|ob| &ob.state),
          Some(RemovalState::Owned)
        ),
        "B's live record is never displaced by A's late claim"
      );
      assert!(
        inner.obligations.contains_key(&id_a),
        "A's record coexists under its own key"
      );
      // Pessimistic-honest: both obligations are counted, never one dropped.
      assert_eq!(inner.obligations.len(), 2, "both incarnations are tracked");
      // Newest-claim-wins on the index; the displaced entry never destroys B.
      assert_eq!(inner.by_path.get(&path), Some(&id_a), "by_path names A now");
    }

    // Both incarnations reach a typed terminal, and physical state converges.
    let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();
    let mut pending: BTreeMap<PathBuf, RetrySlot> = BTreeMap::new();
    reg.sweep_owned::<TokioRuntime>(&op_tx, &mut pending);
    settle(|| reg.len() == 0 && fs.files_under("/r").is_empty()).await;
    assert_eq!(reg.len(), 0, "both incarnations are retired");
    assert!(fs.files_under("/r").is_empty(), "the physical file is gone");
  }

  // A confirmed unlink for an incarnation that has since been REPLACED at the
  // same path must retire ONLY its own incarnation: the retire is keyed by id, so
  // a stale confirm for N structurally cannot touch a successor M that reclaimed
  // the path.
  //
  // Fail-on-old: with a path-keyed drop (retire whoever currently occupies the
  // record's path), the stale confirm for N deletes the live successor M — the
  // survivor assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_confirm_retire_is_id_keyed_and_spares_a_same_path_successor() {
    let fs = FakeFs::new(1);
    let mut reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(fs.clone());
    let scope_n = ScopeId::new(NonZeroU64::new(1).unwrap());
    let scope_m = ScopeId::new(NonZeroU64::new(2).unwrap());
    let name = ".tributaries-sync-aba-structural";
    let path = PathBuf::from("/r").join(name);

    // Incarnation N claims P, then its removal is in flight (its unlink ran, so
    // the file is gone) but its confirm has not yet landed.
    let guard_n = reg.dispatch_guard(scope_n, name.to_owned());
    fs.put(&path, FileKind::File, 1);
    let id_n = guard_n.claim(&path).expect("N claims P");
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner
        .obligations
        .get_mut(&id_n)
        .expect("N's record is present")
        .state = RemovalState::Removing { attempts: 0 };
    }
    fs.remove(&path); // N's unlink physically ran

    // Incarnation M reclaims the same path and owns the live file.
    let guard_m = reg.dispatch_guard(scope_m, name.to_owned());
    fs.put(&path, FileKind::File, 2);
    let id_m = guard_m.claim(&path).expect("M reclaims P");

    // N's stale confirm lands: retire N. Keyed by id, it removes only N.
    lock_ledger(&reg.ledger).retire(id_n, Reaped::ConfirmedGone);
    {
      let inner = lock_ledger(&reg.ledger);
      assert!(!inner.obligations.contains_key(&id_n), "N is retired");
      assert!(
        matches!(
          inner.obligations.get(&id_m).map(|ob| &ob.state),
          Some(RemovalState::Owned)
        ),
        "the successor M survives the stale confirm for N"
      );
      assert_eq!(
        inner.by_path.get(&path),
        Some(&id_m),
        "by_path still names M"
      );
    }
    assert!(
      fs.files_under("/r").contains(&path),
      "M's live file survives the stale confirm"
    );

    // M reaps normally to a typed terminal; physical state converges.
    let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();
    let mut pending: BTreeMap<PathBuf, RetrySlot> = BTreeMap::new();
    reg.sweep_owned::<TokioRuntime>(&op_tx, &mut pending);
    settle(|| reg.len() == 0 && fs.files_under("/r").is_empty()).await;
    assert_eq!(reg.len(), 0, "M is confirmed gone");
    assert!(fs.files_under("/r").is_empty(), "the physical file is gone");
  }

  // A stale self-reap (carrying an incarnation id that no longer matches the
  // record at the path) must NEVER physically unlink the path: the successor's
  // live file (or whatever now lives there) is not ours to delete.
  //
  // Fail-on-old is STRUCTURAL: the old `self_reap(refusal: bool)` has no id, and
  // with an ABSENT record its `None => {}` fall-through unlinks `P` outright
  // (`cookie_remove_dispatches == 1`) — the wrong-file-delete the id guard closes.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_stale_self_reap_never_unlinks_a_successor_cookie() {
    let fs = FakeFs::new(1);
    let mut reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(fs.clone());
    let scope = ScopeId::new(NonZeroU64::new(7).unwrap());
    let name = ".tributaries-sync-stale-selfreap";
    let path = PathBuf::from("/r").join(name);

    // A real claim inserts record M (Owned) at P.
    let guard = reg.dispatch_guard(scope, name.to_owned());
    let m = guard.claim(&path).expect("the claim lands");
    let stale = CookieId(m.0 + 999);

    // Case A: record M present, self-reap with a STALE id — no unlink, untouched.
    let residual = self_reap(&fs, &guard, path.clone(), Some(stale));
    assert!(
      residual.is_none(),
      "a stale-id self-reap yields no residual"
    );
    assert_eq!(
      fs.cookie_remove_dispatches(),
      0,
      "no unlink was attempted for a stale id"
    );
    assert!(reg.owns_id(&path, m), "the live record M is untouched");

    // Case B: NO record at P (a racing cancel confirmed our record away, a
    // successor could own the path) — a stale self-reap still must not unlink.
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner.obligations.clear();
      inner.by_path.clear();
      inner.by_name.clear();
    }
    let residual = self_reap(&fs, &guard, path.clone(), Some(stale));
    assert!(
      residual.is_none(),
      "an absent-record self-reap yields no residual"
    );
    assert_eq!(
      fs.cookie_remove_dispatches(),
      0,
      "no unlink for an absent record either — never a wrong-file delete"
    );
  }

  // A stale removal FAILURE (a `CookieRemoveDone{confirmed:false}` for an
  // incarnation the record no longer is) must not bump the successor's attempts
  // nor deschedule its live retry; a stale CONFIRM must not deschedule it either.
  // Only the matching-id confirm clears the slot.
  //
  // Fail-on-old is STRUCTURAL: the old `record_remove_failed(path)` /
  // `on_cookie_remove_done(path, …)` carry no id, so the stale failure bumps
  // attempts to 3 and both stale arms remove the path-keyed slot.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_stale_remove_failure_does_not_touch_the_successors_state() {
    let fs = FakeFs::new(1);
    let reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(fs.clone());
    let cfg = tuned_config();
    let scope = ScopeId::new(NonZeroU64::new(3).unwrap());
    let name = ".tributaries-sync-stale-fail";
    let path = PathBuf::from("/r").join(name);
    let m = CookieId(42);
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner.obligations.insert(
        m,
        Obligation {
          scope,
          name: name.to_owned(),
          id: m,
          path: Some(path.clone()),
          last_failure_seq: 5,
          state: RemovalState::RemoveFailed { attempts: 2 },
        },
      );
      inner.by_name.insert(name.to_owned(), m);
      inner.by_path.insert(path.clone(), m);
    }
    let slot_at = Instant::from_origin(Duration::from_secs(100));
    let mut pending: BTreeMap<PathBuf, RetrySlot> = BTreeMap::new();
    pending.insert(path.clone(), RetrySlot { at: slot_at, id: m });

    let k = CookieId(m.0 + 1); // a stale successor id
    let now = Instant::from_origin(Duration::from_secs(0));

    // Stale failure (id K): attempts stay 2; the live slot is untouched.
    on_cookie_remove_done(&reg, &mut pending, &cfg, path.clone(), k, false, now, false);
    assert!(
      matches!(
        lock_ledger(&reg.ledger)
          .obligations
          .get(&m)
          .map(|ob| &ob.state),
        Some(RemovalState::RemoveFailed { attempts: 2 })
      ),
      "a stale failure never bumps the successor's attempts"
    );
    assert_eq!(
      pending.get(&path).map(|s| s.at),
      Some(slot_at),
      "the live slot's deadline is untouched"
    );
    assert_eq!(
      pending.get(&path).map(|s| s.id),
      Some(m),
      "the live slot still names M"
    );

    // Stale confirm (id K): the live slot is NOT descheduled.
    on_cookie_remove_done(&reg, &mut pending, &cfg, path.clone(), k, true, now, false);
    assert!(
      pending.contains_key(&path),
      "a stale confirm never deschedules M's live retry"
    );

    // Matching confirm (id M): M's own slot is cleared.
    on_cookie_remove_done(&reg, &mut pending, &cfg, path.clone(), m, true, now, false);
    assert!(
      !pending.contains_key(&path),
      "M's own confirm clears M's slot"
    );
  }

  // The internal `Targeted`/`RetryDue` dispatches are id-matched: only a request
  // carrying the record's CURRENT incarnation id transitions it. `Explicit` (the
  // public path-addressed contract) dispatches the record currently at the path.
  //
  // Fail-on-old is STRUCTURAL: the `Targeted(id)`/`RetryDue(id)` variants do not
  // exist, and old `RetryDue` dispatches any `RemoveFailed` at the path.
  #[tokio::test(flavor = "multi_thread")]
  async fn retry_and_targeted_dispatch_are_id_matched() {
    let fs = FakeFs::new(1);
    let reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(fs.clone());
    let scope = ScopeId::new(NonZeroU64::new(9).unwrap());
    let path = PathBuf::from("/r/.tributaries-sync-idmatch");
    let m = CookieId(100);
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner.obligations.insert(
        m,
        Obligation {
          scope,
          name: "n".to_owned(),
          id: m,
          path: Some(path.clone()),
          last_failure_seq: 1,
          state: RemovalState::RemoveFailed { attempts: 1 },
        },
      );
      inner.by_name.insert("n".to_owned(), m);
      inner.by_path.insert(path.clone(), m);
    }
    let mut pending: BTreeMap<PathBuf, RetrySlot> = BTreeMap::new();
    let k = CookieId(m.0 + 7);

    // A stale RetryDue is a no-op.
    {
      let mut inner = lock_ledger(&reg.ledger);
      let d = CookieRegistry::<FakeFs>::removal_decision_locked(
        &mut inner,
        &mut pending,
        &RemovalRequest::RetryDue(k),
      );
      assert!(d.is_none(), "a stale RetryDue dispatches nothing");
      assert!(matches!(
        inner.obligations.get(&m).map(|ob| &ob.state),
        Some(RemovalState::RemoveFailed { attempts: 1 })
      ));
    }
    // A stale Targeted is a no-op.
    {
      let mut inner = lock_ledger(&reg.ledger);
      let d = CookieRegistry::<FakeFs>::removal_decision_locked(
        &mut inner,
        &mut pending,
        &RemovalRequest::Targeted(k),
      );
      assert!(d.is_none(), "a stale Targeted dispatches nothing");
      assert!(matches!(
        inner.obligations.get(&m).map(|ob| &ob.state),
        Some(RemovalState::RemoveFailed { attempts: 1 })
      ));
    }
    // A matching Targeted re-arms the parked record.
    {
      let mut inner = lock_ledger(&reg.ledger);
      let d = CookieRegistry::<FakeFs>::removal_decision_locked(
        &mut inner,
        &mut pending,
        &RemovalRequest::Targeted(m),
      );
      assert_eq!(
        d.map(|(_, id)| id),
        Some(m),
        "a matching Targeted dispatches M"
      );
      assert!(matches!(
        inner.obligations.get(&m).map(|ob| &ob.state),
        Some(RemovalState::Removing { attempts: 0 })
      ));
    }
    // `Explicit` on a fresh `Owned` record dispatches (public semantics pinned).
    let fresh = PathBuf::from("/r/.tributaries-sync-idmatch-2");
    let f = CookieId(200);
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner.obligations.insert(
        f,
        Obligation {
          scope,
          name: "n2".to_owned(),
          id: f,
          path: Some(fresh.clone()),
          last_failure_seq: 0,
          state: RemovalState::Owned,
        },
      );
      inner.by_name.insert("n2".to_owned(), f);
      inner.by_path.insert(fresh.clone(), f);
      let d = CookieRegistry::<FakeFs>::removal_decision_locked(
        &mut inner,
        &mut pending,
        &RemovalRequest::Explicit(fresh.clone()),
      );
      assert_eq!(
        d.map(|(_, id)| id),
        Some(f),
        "Explicit dispatches the record currently at the path"
      );
      assert!(matches!(
        inner.obligations.get(&f).map(|ob| &ob.state),
        Some(RemovalState::Removing { attempts: 0 })
      ));
    }
  }

  // ==== R11-1: fair, refusing-scope-first recovery re-arm (cells 5–7) ====

  /// How many of `scope`'s records are PARKED (`RemoveFailed`, unscheduled) — the
  /// recovery-fairness oracle.
  async fn parked_for(rig: &Rig, scope: ScopeId) -> usize {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugCookieParkedFor { scope, reply })
      .await
      .unwrap();
    on_reply.await.expect("the driver replies")
  }

  // The deterministic pin for R11-1's selection order (cell 6). `rearm_parked_batch`
  // serves the REFUSING scope first (its own budget) and then the rest
  // least-recently-FAILED-first — with `last_failure_seq` refreshed on every
  // failure so repeat offenders sink behind records that have not failed since a
  // mount recovered. Removes are armed to FAIL, so no async unlink ever drops a
  // record: the SYNCHRONOUS `Removing` transition rearm performs under the
  // decision lock is a fully deterministic oracle for which records were served.
  #[tokio::test(flavor = "multi_thread")]
  async fn rearm_serves_least_recently_failed_first() {
    fn insert_owned_rec(
      reg: &CookieRegistry<FakeFs>,
      scope: ScopeId,
      name: &str,
      path: &Path,
    ) -> CookieId {
      let mut inner = lock_ledger(&reg.ledger);
      inner.next_cookie_id += 1;
      let id = CookieId(inner.next_cookie_id);
      inner.obligations.insert(
        id,
        Obligation {
          scope,
          name: name.to_owned(),
          id,
          path: Some(path.to_path_buf()),
          last_failure_seq: 0,
          state: RemovalState::Owned,
        },
      );
      inner.by_name.insert(name.to_owned(), id);
      inner.by_path.insert(path.to_path_buf(), id);
      id
    }
    fn is_removing(reg: &CookieRegistry<FakeFs>, path: &Path) -> bool {
      let inner = lock_ledger(&reg.ledger);
      matches!(
        inner
          .by_path
          .get(path)
          .and_then(|id| inner.obligations.get(id))
          .map(|ob| &ob.state),
        Some(RemovalState::Removing { .. })
      )
    }
    fn is_parked(reg: &CookieRegistry<FakeFs>, path: &Path) -> bool {
      let inner = lock_ledger(&reg.ledger);
      matches!(
        inner
          .by_path
          .get(path)
          .and_then(|id| inner.obligations.get(id))
          .map(|ob| &ob.state),
        Some(RemovalState::RemoveFailed { .. })
      )
    }

    let sa = ScopeId::new(NonZeroU64::new(1).unwrap()); // scope A
    let sb = ScopeId::new(NonZeroU64::new(2).unwrap()); // scope B
    let sc = ScopeId::new(NonZeroU64::new(3).unwrap()); // scope C (refusing, no parked)
    let a1 = PathBuf::from("/a/a1");
    let a2 = PathBuf::from("/a/a2");
    let b1 = PathBuf::from("/b/b1");

    let fs = FakeFs::new(1);
    fs.fail_next_cookie_removes(1_000_000);
    let reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(fs.clone());
    let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();
    let mut pending: BTreeMap<PathBuf, RetrySlot> = BTreeMap::new();

    // Fail each in order: last_failure_seq = 1, 2, 3 for a1, a2, b1.
    let ida1 = insert_owned_rec(&reg, sa, "a1", &a1);
    let ida2 = insert_owned_rec(&reg, sa, "a2", &a2);
    let idb1 = insert_owned_rec(&reg, sb, "b1", &b1);
    assert_eq!(reg.record_remove_failed(ida1), Some(1)); // seq 1
    assert_eq!(reg.record_remove_failed(ida2), Some(1)); // seq 2
    assert_eq!(reg.record_remove_failed(idb1), Some(1)); // seq 3

    // Refusing = C (no parked of C): others = a1,a2,b1 by seq → [a1,a2] (limit 2).
    let n = reg.rearm_parked_batch::<TokioRuntime>(&op_tx, &mut pending, sc, 2);
    assert_eq!(n, 2, "two records re-armed");
    assert!(is_removing(&reg, &a1), "a1 (seq1) served");
    assert!(is_removing(&reg, &a2), "a2 (seq2) served");
    assert!(
      is_parked(&reg, &b1),
      "b1 (seq3) not served — LRU picks the two oldest"
    );

    // Re-fail a1, a2 (now Removing → RemoveFailed) so their seqs become 4, 5 —
    // BEHIND b1's seq 3: the refresh-on-failure rule sinks repeat offenders.
    assert_eq!(reg.record_remove_failed(ida1), Some(1)); // seq 4
    assert_eq!(reg.record_remove_failed(ida2), Some(1)); // seq 5
    let n = reg.rearm_parked_batch::<TokioRuntime>(&op_tx, &mut pending, sc, 2);
    assert_eq!(n, 2);
    assert!(
      is_removing(&reg, &b1),
      "b1 (now oldest at seq3) served this round"
    );
    assert!(is_removing(&reg, &a1), "a1 (seq4) served");
    assert!(
      is_parked(&reg, &a2),
      "a2 (seq5, newest failure) sinks to the back"
    );

    // The two-budget rule: refusing = A, all three parked → a1,a2 (mine) AND b1
    // (others' separate budget) — up to 2·limit dispatches per refusal.
    let fs2 = FakeFs::new(1);
    fs2.fail_next_cookie_removes(1_000_000);
    let reg2 = CookieRegistry::<FakeFs>::new::<TokioRuntime>(fs2.clone());
    let (op_tx2, _op_rx2) = async_channel::unbounded::<OpResult<FakeHandle>>();
    let mut pending2: BTreeMap<PathBuf, RetrySlot> = BTreeMap::new();
    let ja1 = insert_owned_rec(&reg2, sa, "a1", &a1);
    let ja2 = insert_owned_rec(&reg2, sa, "a2", &a2);
    let jb1 = insert_owned_rec(&reg2, sb, "b1", &b1);
    reg2.record_remove_failed(ja1);
    reg2.record_remove_failed(ja2);
    reg2.record_remove_failed(jb1);
    let n = reg2.rearm_parked_batch::<TokioRuntime>(&op_tx2, &mut pending2, sa, 2);
    assert_eq!(
      n, 3,
      "the refusing scope's budget and the others' budget are separate (≤ 2·limit)"
    );
    assert!(
      is_removing(&reg2, &a1),
      "A's a1 served under the mine-budget"
    );
    assert!(
      is_removing(&reg2, &a2),
      "A's a2 served under the mine-budget"
    );
    assert!(
      is_removing(&reg2, &b1),
      "B's b1 served under the SEPARATE others-budget"
    );
  }

  /// The R11-1 recovery-fairness config: a low per-scope backlog cap, a budget of
  /// one, and a fast retry so records park and re-arm in real (multi-thread) time.
  fn rearm_fairness_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(1),
      cookie_retry_cap: Duration::from_millis(4),
      cookie_retry_budget: 1,
      cookie_backlog_cap: 2,
      cookie_global_cap: 128,
      ..config()
    }
  }

  // A cap refusal re-arms the REFUSING scope's own parked backlog FIRST, so a
  // scope whose mount recovered drains its backlog and is re-admitted even while
  // OTHER scopes' still-failing residue dominates the ledger — the R11-1 property
  // end-to-end through the rig. `/rb` recovers; `/ra` (and a churned pad) keep
  // failing; `/rb` is served within a few refusals regardless.
  //
  // Fail-on-old is OVERWHELMING-PROBABILITY, not certain (old selection rides
  // HashMap iteration order over the whole ledger; padding `/ra`'s side so the
  // old first-`limit` batch is almost surely all-`/ra` makes `/rb` starve, but a
  // seed could still serve it). The DETERMINISTIC pin of the selection order is
  // the unit `rearm_serves_least_recently_failed_first` above.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cap_refusal_rearms_the_refusing_scopes_parked_records_first() {
    let rig = rig_with_config(64, rearm_fairness_config());
    rig.fs.put("/ra", FileKind::Dir, 200);
    rig.fs.put("/rb", FileKind::Dir, 201);
    rig.fs.put("/pad", FileKind::Dir, 202);
    let ra = watch(&rig, "/ra").await;
    let rb = watch(&rig, "/rb").await;
    // Both mounts fail their unlinks; a churned pad dominates the ledger.
    rig.fs.fail_cookie_removes_under("/ra");
    rig.fs.fail_cookie_removes_under("/rb");
    rig.fs.fail_cookie_removes_under("/pad");

    // Park two records on each of /ra and /rb (sequentially, so failure order is
    // deterministic: ra1, ra2, rb1, rb2).
    for i in 0..2 {
      let path = admit_sync(&rig, ra, "/ra", &format!(".tributaries-sync-ra-{i}")).await;
      rig
        .cookie_removes
        .send(CookieReap::Remove(path))
        .await
        .unwrap();
      settle_removes_parked(&rig).await;
    }
    for i in 0..2 {
      let path = admit_sync(&rig, rb, "/rb", &format!(".tributaries-sync-rb-{i}")).await;
      rig
        .cookie_removes
        .send(CookieReap::Remove(path))
        .await
        .unwrap();
      settle_removes_parked(&rig).await;
    }

    // Pad /ra's side of the ledger: ≥ 8 parked records across churned (retired)
    // scopes, so the old scope-blind selection is almost surely all-non-rb.
    for j in 0..8 {
      let root = format!("/pad/p{j}");
      rig.fs.put(&root, FileKind::Dir, 300 + j as u64);
      let scope = watch(&rig, &root).await;
      let path = admit_sync(&rig, scope, &root, &format!(".tributaries-sync-pad-{j}")).await;
      rig
        .cookie_removes
        .send(CookieReap::Remove(path))
        .await
        .unwrap();
      settle_removes_parked(&rig).await;
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      let _ = on_reply.await;
      settle_removes_parked(&rig).await;
    }
    assert_eq!(
      parked_for(&rig, rb).await,
      2,
      "/rb has two parked records before recovery"
    );
    assert_eq!(parked_for(&rig, ra).await, 2, "/ra has two parked records");

    // /rb's mount recovers.
    rig.fs.clear_cookie_remove_failures_under("/rb");

    // Loop: each refused sync kicks rearm(refusing=rb); its mine-half re-arms
    // /rb's own backlog, which confirms on the recovered mount and drops.
    let mut admitted = None;
    for _ in 0..3 {
      match sync_root(&rig, rb, "/rb", ".tributaries-sync-rb-recover").await {
        Ok(path) => {
          admitted = Some(path);
          break;
        }
        Err(crate::error::SyncRootError::CleanupBacklog) => {
          settle(|| rig.fs.files_under("/rb").is_empty()).await;
        }
        Err(other) => panic!("unexpected sync error: {other:?}"),
      }
    }
    assert!(
      admitted.is_some(),
      "the recovered /rb was admitted within 3 attempts — its own backlog was re-armed first"
    );

    // The still-failing residue is HONESTLY parked — no lockout, and /rb was
    // served despite the pad dominating the ledger.
    settle_removes_parked(&rig).await;
    assert_eq!(
      parked_for(&rig, ra).await,
      2,
      "/ra's still-failing residue stays parked — never starved rb, never falsely drained"
    );
  }

  // Cell 7: the R10 recovery/global-cap cells
  // (`churn_across_retired_scopes_is_bounded_by_the_global_cap`,
  // `a_recovered_fs_drains_the_backlog_and_admits_new_syncs`) stay green
  // UNMODIFIED — R11-1 is a strict superset (still re-armed on every refusal,
  // still bounded, now prioritized + starvation-free). No new cell; validated by
  // the full-suite run.

  // ==== R11-2: the whole-lifecycle global cap (cells 8–10) ====

  // Hung (blocking, unclaimed) cookie WRITES count against the global cap: the
  // admission gauge is the whole lifecycle — `obligation_count(writes_in_flight)`
  // + `parked_cookies.len()` — not just claimed `owned` records. Three held
  // writes fill a cap of 3, so the fourth is refused promptly (an honest,
  // retryable `Busy`) rather than piling a fourth blocking job on the pool.
  //
  // Fail-on-old (the gauge reverted to `cookies.unremoved()`): with the writes
  // held, `unremoved() == 0` (nothing claimed), so the 4th write is admitted,
  // dispatched, and PARKS behind the hold — its reply never resolves, and the
  // prompt-error assertion times out. Deterministic.
  #[tokio::test(flavor = "multi_thread")]
  async fn hung_writes_count_against_the_global_cap() {
    // global_cap = 3, backlog_cap = 8 (the per-scope cap never binds — each scope
    // owns at most one in-flight write).
    let rig = rig_with_config(64, low_global_cap_config());
    let mut scopes = Vec::new();
    for i in 1..=4 {
      let root = format!("/r{i}");
      rig.fs.put(&root, FileKind::Dir, 400 + i as u64);
      scopes.push((root.clone(), watch(&rig, &root).await));
    }

    // Every cookie write hangs in the pool — a genuinely backlogged/hung fs.
    let hold = rig.fs.hold_cookie_writes();

    // r1, r2, r3 each admit, park, and dispatch a blocking write into the held
    // pool; settle the dispatch growth so each is counted before the next.
    let mut pending_replies = Vec::new();
    for (i, (root, scope)) in scopes.iter().take(3).enumerate() {
      let reply =
        sync_root_pending(&rig, *scope, root, &format!(".tributaries-sync-hung-{i}")).await;
      pending_replies.push(reply);
      let want = i + 1;
      settle(|| rig.fs.cookie_dispatches() >= want).await;
      assert_eq!(
        rig.fs.cookie_dispatches(),
        want,
        "each held write is dispatched and counted before the next admission"
      );
    }

    // The 4th sync: the gauge is `obligation_count` (3 unclaimed hung writes) +
    // parked (0) = 3 ≥ cap → refused PROMPTLY, never queued behind the hold.
    let (root4, scope4) = &scopes[3];
    let r4_reply = sync_root_pending(&rig, *scope4, root4, ".tributaries-sync-hung-4").await;
    let r4 = tokio::time::timeout(Duration::from_secs(3), r4_reply)
      .await
      .expect("the 4th admission refusal resolves promptly, never pends behind the write hold")
      .expect("the driver replies");
    assert!(
      matches!(r4, Err(crate::error::SyncRootError::CleanupBacklog)),
      "the 4th hung write is refused — hung writes count against the whole-lifecycle cap, got {r4:?}"
    );

    // Cleanup: release the hold so the held writes drain, then drop the receivers.
    hold.release();
    settle(|| rig.fs.cookie_writes().len() >= 3).await;
    drop(pending_replies);
  }

  // R12-F3: the global cookie cap dedups in-flight writes by INCARNATION ID, not
  // NAME, so a direct-fs-API caller reusing ONE cookie name across many disjoint
  // scopes cannot bypass it. The public `sync_root` API permits the same normal
  // name on disjoint scopes; once one owned cookie named N exists, the old
  // NAME-dedup excluded EVERY in-flight write named N (its name sat in `names`), so
  // k same-name held writes on k scopes each contributed 0 — an unbounded
  // blocking-pool / `writes_in_flight` bypass. Under id-dedup each held write
  // carries a distinct DISPATCH id, so it is counted and the cap binds. (The
  // umbrella is unaffected — it mints per-sync-unique names.)
  //
  // Fail-on-old (obligation_count reverted to name-dedup): the owned N puts N in
  // `names`, so every same-name held write is excluded, `obligation_count` stays
  // pinned at 1, the gauge never reaches the cap, the (cap+1)-th sync is ADMITTED,
  // its held write PARKS behind the hold, and the prompt-refusal assertion times
  // out. Deterministic via the write hold.
  #[tokio::test(flavor = "multi_thread")]
  async fn same_name_writes_on_disjoint_scopes_each_count_against_the_global_cap() {
    // global_cap = 3, backlog_cap = 8 (the per-scope cap never binds — one cookie
    // per scope).
    let rig = rig_with_config(64, low_global_cap_config());
    let cap = low_global_cap_config().cookie_global_cap;
    // The ONE cookie name reused across every disjoint scope — exactly the
    // direct-API pattern the umbrella never produces.
    let shared = ".tributaries-sync-shared";

    // cap + 1 disjoint scopes, each separately rooted so the shared name lands at a
    // DISTINCT path per scope (name reuse across live paths — direct-API only).
    let mut scopes = Vec::new();
    for i in 0..=cap {
      let root = format!("/rs{i}");
      rig.fs.put(&root, FileKind::Dir, 700 + i as u64);
      scopes.push((root.clone(), watch(&rig, &root).await));
    }

    // Scope 0's sync COMPLETES and leaves cookie N owned (unlink unconfirmed): this
    // is what puts N into `names` and triggered the old name-dedup bypass.
    let (root0, scope0) = &scopes[0];
    let owned = admit_sync(&rig, *scope0, root0, shared).await;
    assert_eq!(owned, PathBuf::from(format!("{root0}/{shared}")));
    settle_cookie_count(&rig, 1).await;

    // From here every write hangs in the pool. The owned N holds one obligation;
    // each held write named N must add one MORE (by its own id), never be masked.
    let hold = rig.fs.hold_cookie_writes();

    // Syncs on scopes 1..cap, all named N: each admits and dispatches a held write.
    // With owned(1) + (cap-1) held writes the gauge reaches the cap.
    let mut pending = Vec::new();
    for (j, (root, scope)) in scopes[1..cap].iter().enumerate() {
      let reply = sync_root_pending(&rig, *scope, root, shared).await;
      pending.push(reply);
      // owned N's completed write (1) + this held write and its predecessors.
      let want = j + 2;
      settle(|| rig.fs.cookie_dispatches() >= want).await;
      assert_eq!(
        rig.fs.cookie_dispatches(),
        want,
        "each same-name held write is dispatched and counted by id before the next admission"
      );
    }

    // The (cap+1)-th sync (scope `cap`), still named N: the gauge is owned(1) +
    // (cap-1) held = cap ≥ cap → refused PROMPTLY. Under name-dedup it would be
    // admitted (every held write masked by the owned N's name) and park behind the
    // hold, timing this out.
    let (root_last, scope_last) = &scopes[cap];
    let last_reply = sync_root_pending(&rig, *scope_last, root_last, shared).await;
    let last = tokio::time::timeout(Duration::from_secs(3), last_reply)
      .await
      .expect("the (cap+1)-th refusal resolves promptly, never pends behind the write hold")
      .expect("the driver replies");
    assert!(
      matches!(last, Err(crate::error::SyncRootError::CleanupBacklog)),
      "the same-name write past the cap is refused — id-dedup counts each once, got {last:?}"
    );

    // Cleanup: release the hold so the held writes drain, then drop the receivers.
    hold.release();
    settle(|| rig.fs.cookie_writes().len() >= cap).await;
    drop(pending);
  }

  // The admission gauge counts each obligation exactly ONCE — a claimed self-reap
  // (its owned record and its in-flight write sharing one incarnation id) is one
  // physical obligation, and the parked-cookies term is disjoint from both — so
  // the whole-lifecycle sum is `obligation_count + parked`, never a naive
  // `owned + writes + parked`. It ALSO pins id-dedup (R12-F3): an owned record
  // plus a DISTINCT same-name write on another scope counts two, not one.
  //
  // GUARD CELL: its fail-on-old targets are a NAIVE widening (which would
  // double-count the claimed self-reap and read 3, a spurious refusal) and the old
  // NAME-dedup (which would mask the distinct same-name write and read 1) — NOT
  // e8269c7, whose failure is cell 8. It pins the dedup, now keyed by id.
  #[tokio::test(flavor = "multi_thread")]
  async fn the_admission_gauge_counts_each_obligation_once() {
    let reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(FakeFs::new(1));
    // A claimed self-reap: record "M" (id X) owned (claim landed) AND its write
    // still in `writes_in_flight` under that SAME id X (its CookieWriteDone hasn't
    // cleared the gate).
    let id = {
      let mut inner = lock_ledger(&reg.ledger);
      inner.next_cookie_id += 1;
      let id = CookieId(inner.next_cookie_id);
      let path = PathBuf::from("/r/M");
      inner.obligations.insert(
        id,
        Obligation {
          scope: ScopeId::new(NonZeroU64::new(1).unwrap()),
          name: "M".to_owned(),
          id,
          path: Some(path.clone()),
          last_failure_seq: 0,
          state: RemovalState::Removing { attempts: 0 },
        },
      );
      inner.by_name.insert("M".to_owned(), id);
      inner.by_path.insert(path, id);
      id
    };
    let in_flight: BTreeMap<ScopeId, (String, CookieId)> = [(
      ScopeId::new(NonZeroU64::new(1).unwrap()),
      ("M".to_owned(), id),
    )]
    .into_iter()
    .collect();
    assert_eq!(
      reg.obligation_count(&in_flight),
      1,
      "the claimed self-reap is deduped to one obligation, never counted twice"
    );
    // The admission gauge adds `parked_cookies.len()`. With one parked write (no
    // record, no `writes_in_flight` entry — disjoint), the gauge is 2, never 3.
    let parked_len = 1usize;
    assert_eq!(
      reg.obligation_count(&in_flight) + parked_len,
      2,
      "the whole-lifecycle gauge counts each stage once — a naive owned+writes+parked would read 3"
    );

    // R12-F3: the dedup key is the incarnation ID, not the name. An owned record
    // named N (id X) plus a DISTINCT in-flight write reusing that NAME on another
    // scope (id Y ≠ X — the direct-API name reuse the umbrella never produces) is
    // TWO obligations: the write's id is not owned, so it is NOT masked by the
    // owned record's shared name. Old name-dedup read 1 here (the bypass).
    let reg2 = CookieRegistry::<FakeFs>::new::<TokioRuntime>(FakeFs::new(1));
    let x = {
      let mut inner = lock_ledger(&reg2.ledger);
      inner.next_cookie_id += 1;
      let x = CookieId(inner.next_cookie_id);
      let path = PathBuf::from("/r1/N");
      inner.obligations.insert(
        x,
        Obligation {
          scope: ScopeId::new(NonZeroU64::new(1).unwrap()),
          name: "N".to_owned(),
          id: x,
          path: Some(path.clone()),
          last_failure_seq: 0,
          state: RemovalState::Owned,
        },
      );
      inner.by_name.insert("N".to_owned(), x);
      inner.by_path.insert(path, x);
      x
    };
    let y = CookieId(x.0 + 1); // a DISTINCT write's dispatch id, same name N
    let same_name_distinct: BTreeMap<ScopeId, (String, CookieId)> = [(
      ScopeId::new(NonZeroU64::new(2).unwrap()),
      ("N".to_owned(), y),
    )]
    .into_iter()
    .collect();
    assert_eq!(
      reg2.obligation_count(&same_name_distinct),
      2,
      "an owned cookie plus a distinct same-name in-flight write count TWO — id-dedup, not name (R12-F3)"
    );
  }

  /// Cell 10's config: a global cap of 2 (backlog never binds), so one claimed
  /// self-reap plus one fresh sync sit exactly at the boundary the dedup governs.
  fn double_bar_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(5),
      cookie_retry_cap: Duration::from_millis(20),
      cookie_retry_budget: 3,
      cookie_backlog_cap: 8,
      cookie_global_cap: 2,
      ..config()
    }
  }

  // A claimed self-reap that is still mid-unlink (in BOTH `writes_in_flight` and
  // `owned`) must count as ONE against the cap, not two — so a second scope's
  // sync is admitted at a cap of 2 rather than double-barred by the same physical
  // obligation appearing in two places.
  //
  // GUARD CELL: old code also admits (it counts `owned == 1`), so this does not
  // fail on e8269c7; it pins the dedup against a naive `owned + writes + parked`
  // widening (which would read 2 and wrongly refuse scope 2).
  #[tokio::test(flavor = "multi_thread")]
  async fn a_claimed_self_reap_does_not_double_bar_admission() {
    let rig = rig_with_config(64, double_bar_config());
    rig.fs.put("/r1", FileKind::Dir, 500);
    rig.fs.put("/r2", FileKind::Dir, 501);
    let s1 = watch(&rig, "/r1").await;
    let s2 = watch(&rig, "/r2").await;

    // Stage scope 1's claimed-but-reply-failed self-reap, parked mid-unlink.
    let hold_w = rig.fs.hold_cookie_writes();
    let r1_reply = sync_root_pending(&rig, s1, "/r1", ".tributaries-sync-double-1").await;
    settle(|| rig.fs.cookie_dispatches() >= 1).await;
    drop(r1_reply); // the caller abandons the sync — reply.send will fail
    let hold_r = rig.fs.hold_cookie_removes();
    hold_w.release(); // the write proceeds: it claims, reply.send fails, self-reap unlinks
    settle(|| rig.fs.cookie_remove_dispatches() >= 1).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the claimed self-reap parked mid-unlink — in both writes_in_flight and owned"
    );

    // Scope 2 admits: the gauge dedups the one physical obligation to 1 < 2. A
    // naive owned(1)+writes(1)+parked(0)=2 would wrongly refuse it.
    let path2 = admit_sync(&rig, s2, "/r2", ".tributaries-sync-double-2").await;
    assert_eq!(
      path2,
      PathBuf::from("/r2/.tributaries-sync-double-2"),
      "scope 2 is admitted and completes — the claimed self-reap did not double-bar the cap"
    );

    // Cleanup: release the unlink so the self-reap confirms and drains.
    hold_r.release();
    settle(|| rig.fs.cookie_removes().iter().any(|p| p.starts_with("/r1"))).await;
  }
}
