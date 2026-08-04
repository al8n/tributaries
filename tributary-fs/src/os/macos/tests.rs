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

use super::{
  decode::{DecodeBudget, MAX_BATCH_EVENTS, MAX_BATCH_PATH_BYTES},
  *,
};
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
      Ok(SourceMessage::Batch(payload)) => {
        seen.extend(payload.events.into_iter().map(|ev| match ev {
          crate::os::SourceEvent::FsEvents(ev) => ev,
          other => panic!("a mac source only emits FSEvents records: {other:?}"),
        }));
      }
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

  // The pre-start barrier rechecks the FINAL root's kind: a regular file —
  // however the caller's own check was raced — must never get a stream.
  let kind_dir = unique_dir("kind");
  let plain = kind_dir.join("plain.txt");
  fs::write(&plain, b"x").expect("write file");
  let err = Source::spawn(SourceConfig::new(vec![plain]))
    .map(|_| ())
    .unwrap_err();
  assert!(matches!(err, SourceError::NotADirectory { .. }));
  fs::remove_dir_all(&kind_dir).ok();

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

/// The spawn barrier's description of the root is opened for TRAVERSAL, not for
/// reading: a root the caller may enter but not list is watchable, and nothing
/// about FSEvents needs the directory's contents. Opening it `O_RDONLY` would
/// refuse exactly this shape.
#[test]
fn an_execute_only_root_still_passes_the_spawn_barrier() {
  use std::os::unix::fs::PermissionsExt;

  let dir = unique_dir("execonly");
  let root = dir.join("root");
  fs::create_dir(&root).expect("create root");
  fs::set_permissions(&root, fs::Permissions::from_mode(0o111)).expect("drop the read bit");

  let spawned = Source::spawn(SourceConfig::new(vec![root.clone()]));
  fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).ok();
  match spawned {
    Ok((handle, _rx, meta)) => {
      assert_eq!(meta.root, root);
      let _ = handle.shutdown();
    }
    Err(err) => panic!("a traversable root must pass the barrier: {err:?}"),
  }
  fs::remove_dir_all(&dir).ok();
}

/// `MNT_LOCAL` is the whole locality question: fseventsd journals what THIS
/// host's VFS performed, so a volume served from elsewhere changes without any
/// event existing — a gap with no loss signal to degrade through.
#[test]
fn only_a_local_volume_is_watchable() {
  assert!(volume_is_local(libc::MNT_LOCAL as u32));
  assert!(
    volume_is_local((libc::MNT_LOCAL | libc::MNT_RDONLY) as u32),
    "locality is one bit among many, not the whole word"
  );
  assert!(!volume_is_local(0), "an unset bit is a remote volume");
  assert!(
    !volume_is_local(libc::MNT_RDONLY as u32),
    "another flag does not stand in for locality"
  );

  let root = Path::new("/r");
  let refusal = remote_volume_refusal(root, 0).expect("a remote volume is refused");
  match refusal {
    SourceError::RootUnavailable {
      root: refused,
      source,
    } => {
      assert_eq!(refused, root);
      assert_eq!(
        source.kind(),
        std::io::ErrorKind::Unsupported,
        "the refusal names the capability, not a transient failure"
      );
    }
    other => panic!("a remote root must be refused as unavailable: {other:?}"),
  }
  assert!(
    remote_volume_refusal(root, libc::MNT_LOCAL as u32).is_none(),
    "a local volume passes the gate"
  );
}

/// The other half of the gate: the flags actually READ off a live description,
/// so the verdict is not decided by a constant. A temp dir is on a local
/// volume, so the spawn barrier's own read must say so.
#[test]
fn a_live_description_reports_its_volume_locality() {
  let dir = unique_dir("locality");
  let fd = fs::File::open(&dir).expect("open the root");
  let flags = volume_flags(&fd).expect("fstatfs the root");
  assert!(
    volume_is_local(flags),
    "a temp dir is on a local volume; f_flags = {flags:#x}"
  );
  assert!(remote_volume_refusal(&dir, flags).is_none());
  fs::remove_dir_all(&dir).ok();
}

/// The ceiling has to bind the FIRST sizing round. A limit applied only after a
/// growth doubling is a limit an already-oversized table walks straight past —
/// it allocates `count + slack` and, because the read then fits, never reaches
/// the check at all.
#[test]
fn the_mount_ceiling_binds_before_the_first_allocation() {
  assert_eq!(
    mount_table_capacity(5000),
    None,
    "an initial count over the ceiling is refused, not allocated"
  );
  assert_eq!(mount_table_capacity(0), Some(MOUNT_TABLE_SLACK));
  assert_eq!(
    mount_table_capacity(MAX_MOUNT_ENTRIES - MOUNT_TABLE_SLACK),
    Some(MAX_MOUNT_ENTRIES),
    "a table filling the ceiling exactly is still readable"
  );
  assert_eq!(
    mount_table_capacity(MAX_MOUNT_ENTRIES - MOUNT_TABLE_SLACK + 1),
    None
  );
  assert_eq!(
    mount_table_capacity(usize::MAX),
    None,
    "the slack addition is checked, not wrapped"
  );

  assert_eq!(
    grown_mount_table_capacity(MAX_MOUNT_ENTRIES / 2),
    Some(MAX_MOUNT_ENTRIES)
  );
  assert_eq!(grown_mount_table_capacity(MAX_MOUNT_ENTRIES), None);
  assert_eq!(grown_mount_table_capacity(usize::MAX), None);

  assert_eq!(mount_table_bytes::<u32>(4), Some(16));
  assert_eq!(
    mount_table_bytes::<u32>(usize::MAX),
    None,
    "the byte length is checked against the c_int the syscall takes"
  );
  assert_eq!(mount_table_bytes::<[u8; 4096]>(usize::MAX / 8), None);
}

/// The sizing loop's whole policy, exercised with an injected reader so no
/// mount table is needed: an over-ceiling table is refused without ever
/// reading, a table that keeps filling the buffer is refused once growth would
/// pass the ceiling, and an ordinary short read is accepted verbatim.
#[test]
fn the_mount_table_reader_fails_closed_on_every_unbounded_shape() {
  let reads = std::cell::Cell::new(0usize);
  let refused = unsafe {
    read_mount_table::<u64, _>(5000, |_, _| {
      reads.set(reads.get() + 1);
      0
    })
  };
  assert!(refused.is_none(), "an over-ceiling count is refused");
  assert_eq!(reads.get(), 0, "and refused BEFORE any read or allocation");

  // A table that always fills the buffer (a racing mounter, or a kernel that
  // keeps reporting more) grows until the ceiling stops it.
  let largest = std::cell::Cell::new(0usize);
  let fill = |ptr: *mut u64, bytes: libc::c_int| {
    let entries = bytes as usize / size_of::<u64>();
    largest.set(largest.get().max(entries));
    for i in 0..entries {
      // SAFETY: the buffer holds `entries` u64s.
      unsafe { ptr.add(i).write(i as u64) };
    }
    entries as libc::c_int
  };
  let unbounded = unsafe { read_mount_table::<u64, _>(0, fill) };
  assert!(unbounded.is_none(), "an always-full table is never trusted");
  assert!(
    largest.get() <= MAX_MOUNT_ENTRIES,
    "and never asks for more than the ceiling: {}",
    largest.get()
  );

  // The ordinary shape: fewer entries than the buffer holds.
  let short = |ptr: *mut u64, _: libc::c_int| {
    for i in 0..3 {
      // SAFETY: the buffer was sized for 3 + slack entries.
      unsafe { ptr.add(i).write(i as u64 + 7) };
    }
    3
  };
  let table = unsafe { read_mount_table::<u64, _>(3, short) }.expect("a short read is the table");
  assert_eq!(table, vec![7, 8, 9]);

  let failed = unsafe { read_mount_table::<u64, _>(3, |_, _| -1) };
  assert!(failed.is_none(), "a failed read is an UNKNOWN table");
  let unsized_count = unsafe { read_mount_table::<u64, _>(-1, |_, _| 0) };
  assert!(
    unsized_count.is_none(),
    "a failed count is an UNKNOWN table"
  );
}

/// The rewritten reader still reads the real table.
#[test]
fn the_live_mount_table_is_still_readable() {
  let mounts = mounts_under(Path::new("/")).expect("the live mount table reads");
  assert!(
    mounts.iter().all(|path| path != Path::new("/")),
    "the root itself is not a mount UNDER the root"
  );
  let dir = unique_dir("mounts");
  assert_eq!(
    mounts_under(&dir),
    Some(Vec::new()),
    "a fresh temp dir has no submounts"
  );
  fs::remove_dir_all(&dir).ok();
}

/// The transport budget counts BATCHES, so one callback's payload has to be
/// bounded on its own or `budget × batch` is unbounded. Both dimensions bind:
/// an entry count and the path bytes those entries own.
#[test]
fn one_callback_payload_may_not_materialize_without_bound() {
  let mut budget = DecodeBudget::new(2, 100);
  assert!(budget.open());
  assert!(budget.admit(10));
  assert!(budget.open());
  assert!(budget.admit(10));
  assert!(!budget.open(), "the entry count binds on its own");
  assert!(!budget.admit(1));

  let mut budget = DecodeBudget::new(100, 30);
  assert!(budget.admit(20));
  assert!(budget.open(), "20 of 30 bytes leaves the budget open");
  assert!(
    !budget.admit(11),
    "an entry larger than the remainder does not fit"
  );
  assert!(budget.admit(10), "one that does fit is still admitted");
  assert!(!budget.open(), "an exhausted byte budget closes it");

  const {
    assert!(
      MAX_BATCH_PATH_BYTES > 4 * libc::PATH_MAX as usize,
      "a single ordinary path must never be what overruns the byte cap"
    );
    assert!(MAX_BATCH_EVENTS > 0);
  }
}

/// One extended-data entry, in the `UseCFTypes | UseExtendedData` shape the
/// callback is handed: a dictionary carrying `path` (and nothing else when
/// `path` is `None`, which is how a real undecodable entry looks).
fn cf_entry(
  path: Option<&str>,
) -> objc2_core_foundation::CFRetained<objc2_core_foundation::CFDictionary> {
  use objc2_core_foundation::{
    CFDictionary, CFString, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
  };
  let (mut keys, mut values, count) = match path {
    Some(path) => {
      let key = CFString::from_static_str("path");
      let value = CFString::from_str(path);
      (
        vec![
          (&*key as *const CFString)
            .cast::<std::ffi::c_void>()
            .cast_mut(),
        ],
        vec![
          (&*value as *const CFString)
            .cast::<std::ffi::c_void>()
            .cast_mut(),
        ],
        1,
      )
    }
    None => (Vec::new(), Vec::new(), 0),
  };
  // SAFETY: `keys`/`values` hold `count` valid CF objects (CFDictionaryCreate
  // retains them through the CFType callbacks), and the callback tables are the
  // framework's own statics.
  unsafe {
    CFDictionary::new(
      None,
      keys.as_mut_ptr().cast(),
      values.as_mut_ptr().cast(),
      count,
      &raw const kCFTypeDictionaryKeyCallBacks,
      &raw const kCFTypeDictionaryValueCallBacks,
    )
  }
  .expect("build an extended-data entry")
}

/// Runs the real decode over a synthetic callback payload. No stream and no
/// fseventsd — the decode is pure CoreFoundation, so its bounds are provable on
/// any host.
fn decode_payload(entries: &[(Option<&str>, u32, u64)]) -> super::decode::DecodedBatch {
  use objc2_core_foundation::{CFArray, CFDictionary};
  let dicts: Vec<_> = entries.iter().map(|(path, _, _)| cf_entry(*path)).collect();
  let refs: Vec<&CFDictionary> = dicts.iter().map(|d| &**d).collect();
  let array = CFArray::from_objects(&refs);
  let flags: Vec<u32> = entries.iter().map(|(_, flags, _)| *flags).collect();
  let ids: Vec<u64> = entries.iter().map(|(_, _, id)| *id).collect();
  // SAFETY: the array holds one dictionary per entry, and the flag/id vectors
  // hold exactly `entries.len()` elements — the callback's own contract.
  unsafe {
    super::decode::decode_batch(
      entries.len(),
      std::ptr::NonNull::from(&*array).cast(),
      std::ptr::NonNull::from(flags.as_slice()).cast(),
      std::ptr::NonNull::from(ids.as_slice()).cast(),
    )
  }
}

/// The bound, through the real decode: a payload past the cap yields exactly
/// the cap and reports itself LOSSY, so the producer stages no resume point for
/// it and the transport puts an `Overflow` behind it.
#[test]
fn an_oversized_callback_payload_is_truncated_and_reported_lossy() {
  let paths: Vec<String> = (0..MAX_BATCH_EVENTS + 3)
    .map(|i| format!("/r/f{i}"))
    .collect();
  let entries: Vec<_> = paths
    .iter()
    .enumerate()
    .map(|(i, path)| (Some(path.as_str()), 0u32, i as u64 + 1))
    .collect();
  let batch = decode_payload(&entries);
  assert_eq!(
    batch.events.len(),
    MAX_BATCH_EVENTS,
    "the decode stops at the cap instead of following the payload's size"
  );
  assert!(
    batch.lossy,
    "the discarded tail must degrade to an ordered loss, never vanish"
  );

  // A payload inside the cap is untouched.
  let batch = decode_payload(&[(Some("/r/a"), 0, 7), (Some("/r/b"), 0, 8)]);
  assert_eq!(batch.events.len(), 2);
  assert!(!batch.lossy);
  assert_eq!(batch.events[0].path, PathBuf::from("/r/a"));
  assert_eq!(batch.events[1].event_id, 8);
}

/// The wrap latch INVALIDATES every id the stream will ever report, so it has
/// to be read off the raw flag words: an entry the decode could not represent —
/// or one the materialization budget dropped — still carries it. Latching only
/// from decoded events would let a later batch publish a resume point against a
/// reused id space.
#[test]
fn an_undecodable_entry_still_latches_the_id_space_wrap() {
  let wrapped = FsEventFlags::EVENT_IDS_WRAPPED.bits();
  let batch = decode_payload(&[(Some("/r/a"), 0, 5), (None, wrapped, 6)]);
  assert_eq!(
    batch.events.len(),
    1,
    "the entry with no path could not be represented"
  );
  assert!(batch.lossy);
  assert!(
    batch.ids_wrapped,
    "the wrap rides the flag word, not the decoded event"
  );

  let batch = decode_payload(&[(Some("/r/a"), 0, 5)]);
  assert!(!batch.ids_wrapped, "an ordinary payload latches nothing");
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
  let _ = handle.shutdown();
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
/// is dropped and the loss rides the SAME queue as an in-order `Overflow`. The
/// dedup is queue-position-aware — ADJACENT losses (no batch between) collapse
/// onto one `Overflow`, but a `Batch` that lands behind a pending signal ends
/// its run, so a later loss elects a fresh `Overflow` behind that batch (its
/// staleness is otherwise uncovered). Dropping the ack likewise re-arms.
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
  // The held ack's Overflow is still queue-tail-pending. Position-aware dedup:
  // a run of losses with no batch between them collapses onto that one signal,
  // but a Batch that lands resets the position so the NEXT loss elects afresh.
  // So two Overflows never appear back-to-back without a Batch between them —
  // that is the adjacent-loss dedup, now stated per queue position.
  let mut last_was_overflow = false;
  while let Ok(msg) = rx.try_recv() {
    match msg {
      SourceMessage::Batch(_) => last_was_overflow = false,
      SourceMessage::Overflow(_) => {
        assert!(
          !last_was_overflow,
          "adjacent losses (no batch between) must dedup onto one Overflow"
        );
        last_was_overflow = true;
      }
      SourceMessage::Fatal(err) => panic!("stream died: {err}"),
    }
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
  let _ = handle.shutdown();
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
      0 => {
        let _ = handle.shutdown();
      }
      1 => {
        // Receiver first: callbacks observe the closed queue mid-flight.
        drop(rx);
        thread::sleep(Duration::from_micros(500));
        let _ = handle.shutdown();
      }
      _ => drop(handle),
    }

    stop.store(true, Ordering::Relaxed);
    churn.join().expect("churn thread");
  }
  fs::remove_dir_all(&dir).ok();
}
