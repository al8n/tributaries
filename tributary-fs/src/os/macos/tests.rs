use std::{
  fs,
  num::NonZeroUsize,
  path::{Path, PathBuf},
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  thread,
  time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use super::*;
use crate::os::{EventReceiver, FsEventFlags, RawOsEvent, SourceMessage};

fn unique_dir(tag: &str) -> PathBuf {
  let nanos = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("clock after epoch")
    .as_nanos();
  let dir = std::env::temp_dir().join(format!(
    "tributary-fs-{tag}-{}-{nanos:x}",
    std::process::id()
  ));
  fs::create_dir_all(&dir).expect("create test dir");
  // /tmp is a symlink to /private/tmp and FSEvents reports resolved paths.
  dir.canonicalize().expect("canonicalize test dir")
}

/// Drains the queue until `done` says the log suffices or the deadline
/// passes; returns every event seen plus whether an Overflow arrived (its
/// ack drops here, re-arming the dedup as the driver would).
fn recv_until(
  rx: &EventReceiver,
  deadline: Duration,
  mut done: impl FnMut(&[RawOsEvent]) -> bool,
) -> (Vec<RawOsEvent>, bool) {
  let end = Instant::now() + deadline;
  let mut seen = Vec::new();
  let mut overflow = false;
  while !done(&seen) && Instant::now() < end {
    match rx.try_recv() {
      Ok(SourceMessage::Batch(payload)) => seen.extend(payload.events),
      Ok(SourceMessage::Overflow(_ack)) => overflow = true,
      Ok(SourceMessage::Fatal(err)) => panic!("stream died: {err}"),
      Err(async_channel::TryRecvError::Empty) => thread::sleep(Duration::from_millis(10)),
      Err(async_channel::TryRecvError::Closed) => break,
    }
  }
  (seen, overflow)
}

fn has(events: &[RawOsEvent], path: &Path, pred: impl Fn(FsEventFlags) -> bool) -> bool {
  events.iter().any(|e| e.path == path && pred(e.flags))
}

const DEADLINE: Duration = Duration::from_secs(10);

#[test]
fn flag_constants_match_the_system_header() {
  use objc2_core_services as sys;
  let pairs = [
    (
      FsEventFlags::MUST_SCAN_SUBDIRS,
      sys::kFSEventStreamEventFlagMustScanSubDirs,
    ),
    (
      FsEventFlags::USER_DROPPED,
      sys::kFSEventStreamEventFlagUserDropped,
    ),
    (
      FsEventFlags::KERNEL_DROPPED,
      sys::kFSEventStreamEventFlagKernelDropped,
    ),
    (
      FsEventFlags::EVENT_IDS_WRAPPED,
      sys::kFSEventStreamEventFlagEventIdsWrapped,
    ),
    (
      FsEventFlags::HISTORY_DONE,
      sys::kFSEventStreamEventFlagHistoryDone,
    ),
    (
      FsEventFlags::ROOT_CHANGED,
      sys::kFSEventStreamEventFlagRootChanged,
    ),
    (FsEventFlags::MOUNT, sys::kFSEventStreamEventFlagMount),
    (FsEventFlags::UNMOUNT, sys::kFSEventStreamEventFlagUnmount),
    (
      FsEventFlags::ITEM_CREATED,
      sys::kFSEventStreamEventFlagItemCreated,
    ),
    (
      FsEventFlags::ITEM_REMOVED,
      sys::kFSEventStreamEventFlagItemRemoved,
    ),
    (
      FsEventFlags::ITEM_INODE_META_MOD,
      sys::kFSEventStreamEventFlagItemInodeMetaMod,
    ),
    (
      FsEventFlags::ITEM_RENAMED,
      sys::kFSEventStreamEventFlagItemRenamed,
    ),
    (
      FsEventFlags::ITEM_MODIFIED,
      sys::kFSEventStreamEventFlagItemModified,
    ),
    (
      FsEventFlags::ITEM_FINDER_INFO_MOD,
      sys::kFSEventStreamEventFlagItemFinderInfoMod,
    ),
    (
      FsEventFlags::ITEM_CHANGE_OWNER,
      sys::kFSEventStreamEventFlagItemChangeOwner,
    ),
    (
      FsEventFlags::ITEM_XATTR_MOD,
      sys::kFSEventStreamEventFlagItemXattrMod,
    ),
    (
      FsEventFlags::ITEM_IS_FILE,
      sys::kFSEventStreamEventFlagItemIsFile,
    ),
    (
      FsEventFlags::ITEM_IS_DIR,
      sys::kFSEventStreamEventFlagItemIsDir,
    ),
    (
      FsEventFlags::ITEM_IS_SYMLINK,
      sys::kFSEventStreamEventFlagItemIsSymlink,
    ),
    (
      FsEventFlags::OWN_EVENT,
      sys::kFSEventStreamEventFlagOwnEvent,
    ),
    (
      FsEventFlags::ITEM_IS_HARDLINK,
      sys::kFSEventStreamEventFlagItemIsHardlink,
    ),
    (
      FsEventFlags::ITEM_IS_LAST_HARDLINK,
      sys::kFSEventStreamEventFlagItemIsLastHardlink,
    ),
    (
      FsEventFlags::ITEM_CLONED,
      sys::kFSEventStreamEventFlagItemCloned,
    ),
  ];
  for (local, system) in pairs {
    assert_eq!(local.bits(), system);
  }
}

#[test]
fn spawn_rejects_bad_configurations() {
  let err = Source::spawn(SourceConfig::new(Vec::new()))
    .map(|_| ())
    .unwrap_err();
  assert!(matches!(err, SourceError::NoRoots));

  let missing = PathBuf::from("/nonexistent/tributary-fs/root");
  let err = Source::spawn(SourceConfig::new(vec![missing]))
    .map(|_| ())
    .unwrap_err();
  assert!(matches!(err, SourceError::RootUnavailable { .. }));

  let dir = unique_dir("config");
  let mut config = SourceConfig::new(vec![dir.clone()]);
  config.exclusions = (0..9).map(|i| dir.join(format!("x{i}"))).collect();
  let err = Source::spawn(config).map(|_| ()).unwrap_err();
  assert!(matches!(
    err,
    SourceError::TooManyExclusions { supplied: 9 }
  ));
  fs::remove_dir_all(&dir).ok();
}

/// Events may coalesce arbitrarily within the latency window, so every
/// assertion is a flag SUPERSET on a path, never an exact word or sequence.
#[test]
fn smoke_stream_reports_create_modify_rename_remove() {
  let dir = unique_dir("smoke");
  let mut config = SourceConfig::new(vec![dir.clone()]);
  config.latency = Duration::from_millis(20);
  let (handle, rx, meta) = Source::spawn(config).expect("spawn stream");
  assert!(
    meta.mounts.is_empty(),
    "a fresh tempdir has no submounts to seed"
  );
  assert_eq!(meta.root, dir, "the meta carries the canonical root");

  let a = dir.join("a.txt");
  fs::write(&a, b"one").expect("create a");
  let (seen, _) = recv_until(&rx, DEADLINE, |log| {
    has(log, &a, FsEventFlags::item_created)
  });
  let created = seen
    .iter()
    .find(|e| e.path == a && e.flags.item_created())
    .expect("a Created event for the new file");
  assert!(
    created.file_id.is_some(),
    "extended data supplies the inode"
  );
  assert!(created.flags.item_is_file());

  fs::write(&a, b"one two").expect("modify a");
  let (_, _) = recv_until(&rx, DEADLINE, |log| {
    has(log, &a, FsEventFlags::item_modified)
  });

  let b = dir.join("b.txt");
  fs::rename(&a, &b).expect("rename a -> b");
  let (seen, _) = recv_until(&rx, DEADLINE, |log| {
    has(log, &a, FsEventFlags::item_renamed) && has(log, &b, FsEventFlags::item_renamed)
  });
  let source = seen
    .iter()
    .find(|e| e.path == a && e.flags.item_renamed())
    .expect("rename source half");
  let dest = seen
    .iter()
    .find(|e| e.path == b && e.flags.item_renamed())
    .expect("rename destination half");
  if let (Some(from), Some(to)) = (source.file_id, dest.file_id) {
    assert_eq!(from, to, "both rename halves carry the moved inode");
  }

  fs::remove_file(&b).expect("remove b");
  let (_, _) = recv_until(&rx, DEADLINE, |log| {
    has(log, &b, FsEventFlags::item_removed)
  });

  assert!(handle.resume_token().is_some(), "in-sync ids were tracked");
  handle.shutdown();
  // Once the stream deallocates, its strong count on the shared state drops
  // and the channel disconnects.
  let end = Instant::now() + DEADLINE;
  loop {
    match rx.try_recv() {
      Err(async_channel::TryRecvError::Closed) => break,
      Err(async_channel::TryRecvError::Empty) => {
        assert!(Instant::now() < end, "channel disconnects after shutdown");
        thread::sleep(Duration::from_millis(10));
      }
      Ok(_) => {}
    }
  }
  fs::remove_dir_all(&dir).ok();
}

/// An exhausted batch budget must never block the dispatch queue: the batch
/// is dropped and the loss rides the SAME queue as exactly one in-order
/// `Overflow`, whose ack re-arms the dedup for the next loss.
#[test]
fn over_budget_batches_signal_one_inband_overflow() {
  let dir = unique_dir("overflow");
  let mut config = SourceConfig::new(vec![dir.clone()]);
  config.latency = Duration::from_millis(1);
  config.channel_capacity = NonZeroUsize::new(1).expect("nonzero");
  let (handle, rx, meta) = Source::spawn(config).expect("spawn stream");
  assert!(
    meta.mounts.is_empty(),
    "a fresh tempdir has no submounts to seed"
  );

  // Waves spaced past the latency window force multiple callbacks while
  // nothing receives, so the 1-batch budget must overflow.
  for wave in 0..10 {
    for i in 0..5 {
      fs::write(dir.join(format!("w{wave}-f{i}")), b"x").expect("churn");
    }
    thread::sleep(Duration::from_millis(30));
  }

  // Hold the ack: while it lives, further losses are deduped onto it.
  let end = Instant::now() + DEADLINE;
  let ack = loop {
    match rx.try_recv() {
      Ok(SourceMessage::Overflow(ack)) => break ack,
      Ok(SourceMessage::Batch(_)) => {}
      Ok(SourceMessage::Fatal(err)) => panic!("stream died: {err}"),
      Err(_) => {
        assert!(
          Instant::now() < end,
          "dropped batches must surface as an in-band Overflow"
        );
        thread::sleep(Duration::from_millis(10));
      }
    }
  };
  for wave in 0..5 {
    for i in 0..5 {
      fs::write(dir.join(format!("held{wave}-f{i}")), b"x").expect("churn");
    }
    thread::sleep(Duration::from_millis(30));
  }
  while let Ok(msg) = rx.try_recv() {
    assert!(
      matches!(msg, SourceMessage::Batch(_)),
      "an unacknowledged Overflow dedups further losses: {msg:?}"
    );
  }

  // Acknowledge (drop the ack) and lose again: a fresh signal.
  drop(ack);
  for wave in 0..10 {
    for i in 0..5 {
      fs::write(dir.join(format!("again{wave}-f{i}")), b"x").expect("churn");
    }
    thread::sleep(Duration::from_millis(30));
  }
  let end = Instant::now() + DEADLINE;
  loop {
    match rx.try_recv() {
      Ok(SourceMessage::Overflow(_)) => break,
      Ok(SourceMessage::Batch(_)) => {}
      Ok(SourceMessage::Fatal(err)) => panic!("stream died: {err}"),
      Err(_) => {
        assert!(
          Instant::now() < end,
          "an acknowledged signal re-arms for the next loss"
        );
        thread::sleep(Duration::from_millis(10));
      }
    }
  }
  handle.shutdown();
  fs::remove_dir_all(&dir).ok();
}

/// Empirically flushes the teardown race the design argues away: spawn and
/// destroy streams under churn, at randomized points in their lifecycle,
/// through every teardown variant.
#[test]
fn stress_teardown_under_churn() {
  let iterations: usize = std::env::var("TRIBUTARY_FS_STRESS")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(200);
  let dir = unique_dir("stress");

  for i in 0..iterations {
    let (handle, rx, _meta) =
      Source::spawn(SourceConfig::new(vec![dir.clone()])).expect("spawn stream");
    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
      let stop = Arc::clone(&stop);
      let dir = dir.clone();
      thread::spawn(move || {
        let mut n = 0u32;
        while !stop.load(Ordering::Relaxed) {
          let path = dir.join(format!("f{n}"));
          let _ = fs::write(&path, b"x");
          let _ = fs::remove_file(&path);
          n = n.wrapping_add(1);
        }
      })
    };

    // 0–5 ms, deterministically spread across iterations; every fifth
    // iteration tears down immediately after start.
    let delay = Duration::from_micros(if i % 5 == 0 {
      0
    } else {
      (i as u64 * 7919) % 5000
    });
    thread::sleep(delay);
    match i % 3 {
      0 => handle.shutdown(),
      1 => {
        // Receiver first: callbacks observe the closed queue mid-flight.
        drop(rx);
        thread::sleep(Duration::from_micros(500));
        handle.shutdown();
      }
      _ => drop(handle),
    }

    stop.store(true, Ordering::Relaxed);
    churn.join().expect("churn thread");
  }
  fs::remove_dir_all(&dir).ok();
}
