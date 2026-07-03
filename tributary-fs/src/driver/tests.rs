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
    [(scope, PathBuf::from("/r"))],
    "the entry was live before the grant resolved"
  );

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Unwatch { scope, reply })
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
  assert_eq!(registry.live(), [(scope, PathBuf::from("/r"))]);

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
#[tokio::test(start_paused = true)]
async fn storm_no_silent_loss_converges() {
  let seeds: u64 = std::env::var("TRIBUTARY_FS_STORM_SEEDS")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(64);
  for seed in 1..=seeds {
    storm_seed(seed).await;
  }
}

async fn storm_seed(seed: u64) {
  let rig = rig_with_capacity(4);
  let _scope = watch(&rig, "/r").await;
  let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(1);
  let mut next_ino = 100u64;
  let mut next_id = 1u64;
  let mut live: Vec<(PathBuf, u64)> = Vec::new();
  let mut view: BTreeSet<PathBuf> = BTreeSet::new();
  let mut last_epoch: Option<Epoch> = None;

  for _ in 0..30 {
    let mut events = Vec::new();
    match xorshift(&mut s) % 4 {
      0 | 1 => {
        next_ino += 1;
        let path = PathBuf::from(format!("/r/f{next_ino}"));
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
        let new = PathBuf::from(format!("/r/g{next_ino}"));
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
      rig.fs.send_lossy("/r");
    } else {
      rig.fs.send_batch("/r", events);
    }
    // A sometimes-lagging consumer: drain a few events only occasionally.
    if xorshift(&mut s).is_multiple_of(3) {
      for _ in 0..(xorshift(&mut s) % 4) {
        match tokio::time::timeout(Duration::from_millis(100), rig.events.recv()).await {
          Ok(Ok((_, root, change))) => {
            apply(&rig, &mut view, &mut last_epoch, &root, &change);
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
    apply(&rig, &mut view, &mut last_epoch, &root, &change);
  }

  let tree = rig.fs.files_under("/r");
  assert_eq!(
    view, tree,
    "seed {seed}: the reconstructed view converges to the tree"
  );
}

fn apply(
  rig: &Rig,
  view: &mut BTreeSet<PathBuf>,
  last_epoch: &mut Option<Epoch>,
  root: &Path,
  change: &Change,
) {
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
  #[tokio::test(flavor = "multi_thread")]
  async fn descending_storm_converges() {
    let seeds: u64 = std::env::var("TRIBUTARY_FS_STORM_SEEDS")
      .ok()
      .and_then(|v| v.parse().ok())
      .unwrap_or(8);
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
              apply_descending(&rig, &mut view, &mut last_epoch, &root, &change);
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
      apply_descending(&rig, &mut view, &mut last_epoch, &root, &change);
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
    root: &Path,
    change: &Change,
  ) {
    apply(rig, view, last_epoch, root, change);
  }
}
