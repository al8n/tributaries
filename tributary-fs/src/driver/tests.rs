use super::{testing::*, *};
use std::{
  collections::BTreeSet,
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
  }
}

fn rig_with_capacity(event_capacity: usize) -> Rig {
  rig_with(event_capacity, NullRegistry)
}

fn rig_with(event_capacity: usize, registry: impl ScopeRegistry) -> Rig {
  let fs = FakeFs::new(1);
  fs.put("/r", FileKind::Dir, 1);
  let (cmd_tx, cmd_rx) = async_channel::bounded(16);
  let (ev_tx, ev_rx) = async_channel::bounded(event_capacity);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config(),
    fs.clone(),
    cmd_rx,
    ev_tx,
    registry,
  ));
  Rig {
    fs,
    commands: cmd_tx,
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
  let (ev_tx, ev_rx) = async_channel::bounded(64);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config(),
    fs.clone(),
    cmd_rx,
    ev_tx,
    NullRegistry,
  ));
  let rig = Rig {
    fs,
    commands: cmd_tx,
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
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    tokio::spawn(run::<TokioRuntime, FakeFs>(
      inotify_config(),
      fs.clone(),
      cmd_rx,
      ev_tx,
      NullRegistry,
    ));
    Rig {
      fs,
      commands: cmd_tx,
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
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    tokio::spawn(run::<TokioRuntime, FakeFs>(
      inotify_config(),
      fs.clone(),
      cmd_rx,
      ev_tx,
      registry,
    ));
    Rig {
      fs,
      commands: cmd_tx,
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
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the re-issued grow settles clean over re-attempted coverage"
      );
      assert!(
        arms_at(&rig, "/r/drop") > attempts,
        "the rewound cover made the delta non-empty — the arm was re-attempted"
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

    // Exactly one covering Rescan, re-rooted.
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), std::path::Path::new("/r2"));
    assert!(change.kind().is_rescan(), "{change:?}");

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
/// is a reply-less fire-and-forget; and a read-only tree refuses typed. The
/// driver OWNS every cookie it writes until a `RemoveCookie` unlinks it, so a
/// cookie whose reply the caller abandoned is still reaped when the scope's
/// stream tears down or the driver exits — never leaked.
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

    // And it reaps, idempotently.
    rig
      .commands
      .send(Command::RemoveCookie { path: path.clone() })
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

  // The driver owns every cookie it writes: even with NO `RemoveCookie` — the
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
    assert!(
      rig.fs.cookie_removes().is_empty(),
      "no RemoveCookie was sent — the cookie is still the driver's to reap"
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

    // Retire the scope with no RemoveCookie: the stream teardown reaps the
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
  }
}
