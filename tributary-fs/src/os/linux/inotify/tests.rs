use super::{
  decode::{DecodeOutcome, InotifyMask, decode_events},
  table::{DrainDecision, WdTable},
};
use tributary_proto::WatchId;

use core::num::NonZeroU64;

fn watch(n: u64) -> WatchId {
  WatchId::new(NonZeroU64::new(n).unwrap())
}

/// Builds one kernel-layout `inotify_event` record: native-endian
/// `{ wd: i32, mask: u32, cookie: u32, len: u32 }` followed by `len` bytes of
/// NUL-padded name.
fn event_bytes(wd: i32, mask: u32, cookie: u32, name: &[u8], pad_to: usize) -> Vec<u8> {
  assert!(pad_to >= name.len());
  let mut buf = Vec::new();
  buf.extend_from_slice(&wd.to_ne_bytes());
  buf.extend_from_slice(&mask.to_ne_bytes());
  buf.extend_from_slice(&cookie.to_ne_bytes());
  buf.extend_from_slice(&(pad_to as u32).to_ne_bytes());
  buf.extend_from_slice(name);
  buf.resize(16 + pad_to, 0);
  buf
}

mod decode {
  use super::*;

  #[test]
  fn packed_multi_event_buffer_decodes_in_order() {
    let mut buf = event_bytes(1, super::super::decode::IN_CREATE, 0, b"a.txt", 8);
    buf.extend(event_bytes(
      2,
      super::super::decode::IN_MOVED_FROM,
      77,
      b"old",
      4,
    ));
    buf.extend(event_bytes(
      2,
      super::super::decode::IN_MOVED_TO,
      77,
      b"new",
      4,
    ));

    let DecodeOutcome { events, lossy } = decode_events(&buf);
    assert!(!lossy);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].wd, 1);
    assert!(events[0].mask.created());
    assert_eq!(events[0].name.as_deref(), Some(b"a.txt".as_slice()));
    assert_eq!(events[1].cookie, 77);
    assert!(events[1].mask.moved_from());
    assert!(events[2].mask.moved_to());
    assert_eq!(events[2].name.as_deref(), Some(b"new".as_slice()));
  }

  #[test]
  fn name_padding_is_trimmed_and_empty_name_is_none() {
    let buf = event_bytes(3, super::super::decode::IN_DELETE_SELF, 0, b"", 16);
    let DecodeOutcome { events, lossy } = decode_events(&buf);
    assert!(!lossy);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].name, None, "all-NUL name decodes to None");
  }

  #[test]
  fn truncated_trailing_record_is_lossy_not_fatal() {
    let mut buf = event_bytes(1, super::super::decode::IN_MODIFY, 0, b"x", 4);
    let whole = event_bytes(1, super::super::decode::IN_MODIFY, 0, b"y", 4);
    buf.extend_from_slice(&whole[..10]); // header cut mid-way

    let DecodeOutcome { events, lossy } = decode_events(&buf);
    assert_eq!(events.len(), 1, "the intact record still decodes");
    assert!(lossy, "a truncated tail marks the batch lossy");
  }

  #[test]
  fn absurd_len_is_lossy_not_a_panic() {
    let mut buf = event_bytes(1, super::super::decode::IN_CREATE, 0, b"ok", 4);
    let mut bad = Vec::new();
    bad.extend_from_slice(&5i32.to_ne_bytes());
    bad.extend_from_slice(&super::super::decode::IN_CREATE.to_ne_bytes());
    bad.extend_from_slice(&0u32.to_ne_bytes());
    bad.extend_from_slice(&(u32::MAX).to_ne_bytes()); // len far beyond the buffer
    buf.extend(bad);

    let DecodeOutcome { events, lossy } = decode_events(&buf);
    assert_eq!(events.len(), 1);
    assert!(lossy);
  }

  /// A lone record whose header claims a `u32::MAX` name length: `at + HEADER +
  /// len` overflows `usize` on a 32-bit target (i686), which would panic on the
  /// add before the slice bound is ever tested. The checked arithmetic keeps it
  /// `lossy` with no events on every pointer width — never a panic.
  #[test]
  fn name_len_overflow_alone_is_lossy_not_a_panic() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&7i32.to_ne_bytes()); // wd
    buf.extend_from_slice(&super::super::decode::IN_CREATE.to_ne_bytes()); // mask
    buf.extend_from_slice(&0u32.to_ne_bytes()); // cookie
    buf.extend_from_slice(&u32::MAX.to_ne_bytes()); // len: absurd, overflows on 32-bit

    let DecodeOutcome { events, lossy } = decode_events(&buf);
    assert!(lossy, "a name length that overflows usize is lossy");
    assert!(
      events.is_empty(),
      "the overflowing record yields no event and stops the walk"
    );
  }

  #[test]
  fn queue_overflow_entry_decodes_with_sentinel_wd() {
    let buf = event_bytes(-1, super::super::decode::IN_Q_OVERFLOW, 0, b"", 0);
    let DecodeOutcome { events, lossy } = decode_events(&buf);
    assert!(!lossy, "overflow is an EVENT, not a decode defect");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].wd, -1);
    assert!(events[0].mask.is_overflow());
    assert_eq!(events[0].name, None);
  }

  #[test]
  fn mask_predicates_match_kernel_bits() {
    assert!(InotifyMask(super::super::decode::IN_IGNORED).is_ignored());
    assert!(InotifyMask(super::super::decode::IN_UNMOUNT).unmount());
    assert!(InotifyMask(super::super::decode::IN_MOVE_SELF).move_self());
    assert!(InotifyMask(super::super::decode::IN_DELETE_SELF).delete_self());
    assert!(InotifyMask(super::super::decode::IN_ATTRIB).attrib());
    assert!(InotifyMask(super::super::decode::IN_DELETE).removed());
    assert!(InotifyMask(super::super::decode::IN_MODIFY).modified());
    let dir_create = InotifyMask(super::super::decode::IN_CREATE | super::super::decode::IN_ISDIR);
    assert!(dir_create.created() && dir_create.is_dir());
  }
}

mod table {
  use super::*;

  #[test]
  fn register_then_ignored_erases_and_fans_out() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(t.anchors(7), &[watch(1)]);

    let fanned = t.on_ignored(7);
    assert_eq!(fanned, vec![watch(1)]);
    assert!(
      t.anchors(7).is_empty(),
      "IGNORED is the authoritative erase"
    );
  }

  #[test]
  fn alias_fans_attribution_to_every_anchor() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    t.alias(7, watch(2)); // the EEXIST path: same inode reached twice
    assert_eq!(t.anchors(7), &[watch(1), watch(2)]);

    let fanned = t.on_ignored(7);
    assert_eq!(fanned, vec![watch(1), watch(2)]);
  }

  #[test]
  fn drain_removes_wd_only_when_the_live_set_empties() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    t.alias(7, watch(2));

    assert_eq!(
      t.begin_drain(watch(1)),
      DrainDecision::KeepWd,
      "a surviving alias keeps the kernel watch"
    );
    assert_eq!(
      t.anchors(7),
      &[watch(2)],
      "the drained anchor stops attributing"
    );

    assert_eq!(
      t.begin_drain(watch(2)),
      DrainDecision::RemoveWd(7),
      "the last live anchor releases the kernel watch"
    );
  }

  #[test]
  fn draining_entry_survives_until_ignored_and_never_double_removes() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));

    // Between rm_watch and the queued IN_IGNORED the entry still exists
    // (attribution answers empty — the anchor was unwatched — but the wd is
    // known, so a re-registration cannot collide).
    assert!(t.contains(7), "draining entry survives until IGNORED");
    assert_eq!(
      t.begin_drain(watch(1)),
      DrainDecision::KeepWd,
      "a second drain of the same anchor never re-issues rm_watch"
    );

    let fanned = t.on_ignored(7);
    assert!(fanned.is_empty(), "no live anchors remained at IGNORED");
    assert!(!t.contains(7));
  }

  /// A `wd`-reuse race: a fresh install lands on a `wd` whose tombstone still
  /// awaits its stale `IN_IGNORED`. Registering must revive the entry as a fresh
  /// live generation, and the stale IGNORED must be ABSORBED — it clears the
  /// remnant without erasing the new anchor (which would silently drop a live
  /// watch, the exact loss this generation-correctness prevents).
  #[test]
  fn register_onto_draining_survives_the_stale_ignored() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));
    assert!(t.contains(7), "the tombstone awaits its IGNORED");

    // The kernel recycled wd 7 for a brand-new watch before the old IGNORED
    // landed.
    t.register(7, watch(2));
    assert_eq!(
      t.anchors(7),
      &[watch(2)],
      "the fresh install replaces the tombstone with a live entry"
    );

    // The OLD incarnation's IGNORED arrives: it is absorbed, not honored.
    let fanned = t.on_ignored(7);
    assert!(
      fanned.is_empty(),
      "the stale IGNORED fans to nobody (it belonged to the drained watch)"
    );
    assert_eq!(
      t.anchors(7),
      &[watch(2)],
      "the new anchor survives the stale IGNORED"
    );

    // The new watch's own eventual IGNORED erases legitimately.
    let fanned = t.on_ignored(7);
    assert_eq!(
      fanned,
      vec![watch(2)],
      "the live watch's own IGNORED erases"
    );
    assert!(!t.contains(7));
  }

  /// A PLAIN draining entry (no reuse) still erases on its IGNORED — the reuse
  /// handling must not change the ordinary self-induced teardown.
  #[test]
  fn plain_drain_still_erases_on_ignored() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));
    let fanned = t.on_ignored(7);
    assert!(
      fanned.is_empty(),
      "a self-drained watch fans nothing at IGNORED"
    );
    assert!(!t.contains(7), "the plain drain's IGNORED erases the entry");
  }

  /// The kernel contract guarantees exactly one final `IN_IGNORED` per `wd`, so a
  /// SECOND IGNORED after a reuse-absorbed one cannot happen — but if it did, it
  /// erases legitimately rather than corrupting state.
  #[test]
  fn second_ignored_after_reuse_erases() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));
    t.register(7, watch(2));

    // First IGNORED: absorbed as the stale remnant.
    assert!(t.on_ignored(7).is_empty());
    assert_eq!(t.anchors(7), &[watch(2)]);

    // A (contract-impossible) second IGNORED erases the live entry.
    assert_eq!(t.on_ignored(7), vec![watch(2)]);
    assert!(!t.contains(7));
  }

  #[test]
  fn unknown_wd_attributes_to_nobody() {
    let t = WdTable::new();
    assert!(t.anchors(99).is_empty());
  }
}

/// Live-kernel smoke: compiled by the Linux-target lint gate on every host,
/// RUN by the container harness (`ci/linux-verify.sh`) and the CI Linux legs.
#[cfg(all(target_os = "linux", not(miri)))]
mod smoke {
  use std::{ffi::OsString, fs, num::NonZeroU64, time::Duration};

  use tributary_proto::WatchId;

  use crate::os::{
    SourceConfig,
    linux::{AnchorRequest, ExpectedObject, RawLinuxEvent, Source, WatchOutcome},
    transport::SourceMessage,
  };

  /// The `(dev, ino)` of `path`, for building an `ExpectedObject` an arm confirms.
  fn ident(path: &std::path::Path) -> ExpectedObject {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path).expect("stat");
    ExpectedObject {
      dev: meta.dev(),
      ino: NonZeroU64::new(meta.ino()).expect("a real inode is non-zero"),
    }
  }

  fn watch(n: u64) -> WatchId {
    WatchId::new(NonZeroU64::new(n).unwrap())
  }

  fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tributary-inotify-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
  }

  fn recv_batch(rx: &crate::os::EventReceiver) -> Vec<RawLinuxEvent> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
      match rx.try_recv() {
        Ok(SourceMessage::Batch(payload)) => {
          return payload
            .events
            .into_iter()
            .map(|ev| match ev {
              crate::os::SourceEvent::Linux(ev) => ev,
              other => panic!("an inotify source only emits Linux records: {other:?}"),
            })
            .collect();
        }
        Ok(_) => continue,
        Err(_) => std::thread::sleep(Duration::from_millis(20)),
      }
    }
    panic!("no batch within the deadline");
  }

  #[test]
  fn spawn_seals_meta_and_arms_through_the_control_path() {
    let dir = scratch("spawn");
    let (handle, rx, meta) = Source::spawn(SourceConfig::new(vec![dir.clone()])).expect("spawn");
    // The barrier sealed the canonical root before any watch existed; nothing
    // can have been delivered yet.
    assert_eq!(meta.root, fs::canonicalize(&dir).unwrap());
    assert!(
      rx.is_empty(),
      "no watch armed at spawn, so nothing delivered"
    );

    let reply = handle.add_watch(AnchorRequest {
      watch: watch(1),
      parent: None,
      name: OsString::from(meta.root.as_os_str()),
      expected: None,
    });
    let wd = match reply.outcome {
      WatchOutcome::Installed(wd) => wd,
      other => panic!("root arm failed: {other:?}"),
    };
    assert!(wd >= 0);
    assert!(reply.anchor.is_some(), "the transient anchor comes back");

    fs::write(dir.join("a.txt"), b"x").unwrap();
    let events = recv_batch(&rx);
    let (anchors, raw) = events[0].as_inotify().unwrap();
    assert_eq!(anchors, &[watch(1)]);
    assert_eq!(raw.name.as_deref(), Some(b"a.txt".as_slice()));

    handle.shutdown();
    let _ = fs::remove_dir_all(&dir);
  }

  #[test]
  fn arming_the_same_inode_twice_aliases() {
    let dir = scratch("alias");
    let (handle, _rx, meta) = Source::spawn(SourceConfig::new(vec![dir.clone()])).expect("spawn");

    let first = handle.add_watch(AnchorRequest {
      watch: watch(1),
      parent: None,
      name: OsString::from(meta.root.as_os_str()),
      expected: None,
    });
    let WatchOutcome::Installed(wd) = first.outcome else {
      panic!("first arm: {:?}", first.outcome);
    };
    let second = handle.add_watch(AnchorRequest {
      watch: watch(2),
      parent: None,
      name: OsString::from(meta.root.as_os_str()),
      expected: None,
    });
    assert_eq!(second.outcome, WatchOutcome::Aliased(wd));

    handle.shutdown();
    let _ = fs::remove_dir_all(&dir);
  }

  /// An arm carrying the CORRECT expected identity installs: the opened object
  /// is the one the enumerate saw.
  #[test]
  fn arm_with_matching_identity_installs() {
    let dir = scratch("verify-ok");
    let (handle, _rx, meta) = Source::spawn(SourceConfig::new(vec![dir.clone()])).expect("spawn");
    let reply = handle.add_watch(AnchorRequest {
      watch: watch(1),
      parent: None,
      name: OsString::from(meta.root.as_os_str()),
      expected: Some(ident(&meta.root)),
    });
    assert!(
      matches!(reply.outcome, WatchOutcome::Installed(_)),
      "a matching identity arms: {:?}",
      reply.outcome
    );
    handle.shutdown();
    let _ = fs::remove_dir_all(&dir);
  }

  /// An arm whose expected identity does NOT match the object at the path is
  /// refused as `Gone` — the object was replaced between the enumerate and the
  /// arm, and installing the watch on the new object would misattribute. The
  /// Monitor's drop+rescan then heals. A fresh scratch directory's real identity
  /// stands in for "some other object", forced to differ by bumping the inode.
  #[test]
  fn arm_with_mismatched_identity_is_gone() {
    let dir = scratch("verify-mismatch");
    let (handle, _rx, meta) = Source::spawn(SourceConfig::new(vec![dir.clone()])).expect("spawn");
    let mut wrong = ident(&meta.root);
    // A different inode: the name now points at another object than the enumerate
    // recorded.
    wrong.ino = NonZeroU64::new(wrong.ino.get() ^ 0xFFFF_FFFF).expect("still non-zero");
    let reply = handle.add_watch(AnchorRequest {
      watch: watch(1),
      parent: None,
      name: OsString::from(meta.root.as_os_str()),
      expected: Some(wrong),
    });
    assert_eq!(
      reply.outcome,
      WatchOutcome::Failed(tributary_proto::WatchError::Gone),
      "a replaced object is refused, not silently mis-armed"
    );
    assert!(
      reply.anchor.is_none(),
      "a refused arm returns no transient anchor"
    );
    handle.shutdown();
    let _ = fs::remove_dir_all(&dir);
  }

  #[test]
  fn missing_target_maps_to_not_found() {
    let dir = scratch("enoent");
    let (handle, _rx, meta) = Source::spawn(SourceConfig::new(vec![dir.clone()])).expect("spawn");
    let reply = handle.add_watch(AnchorRequest {
      watch: watch(1),
      parent: None,
      name: OsString::from(meta.root.join("absent").as_os_str()),
      expected: None,
    });
    assert_eq!(
      reply.outcome,
      WatchOutcome::Failed(tributary_proto::WatchError::NotFound)
    );
    handle.shutdown();
    let _ = fs::remove_dir_all(&dir);
  }

  #[test]
  fn remove_watch_drains_through_ignored() {
    let dir = scratch("drain");
    let (handle, rx, meta) = Source::spawn(SourceConfig::new(vec![dir.clone()])).expect("spawn");
    let reply = handle.add_watch(AnchorRequest {
      watch: watch(1),
      parent: None,
      name: OsString::from(meta.root.as_os_str()),
      expected: None,
    });
    assert!(matches!(reply.outcome, WatchOutcome::Installed(_)));

    handle.remove_watch(watch(1));
    // The self-induced teardown's IGNORED erases silently; later filesystem
    // activity must not be attributed.
    fs::write(dir.join("late.txt"), b"x").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    while let Ok(msg) = rx.try_recv() {
      if let SourceMessage::Batch(payload) = msg {
        assert!(
          payload.events.is_empty(),
          "no attribution after the drain: {:?}",
          payload.events
        );
      }
    }
    handle.shutdown();
    let _ = fs::remove_dir_all(&dir);
  }
}
