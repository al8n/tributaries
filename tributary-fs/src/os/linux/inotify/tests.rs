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

  /// The anchors the table fans a NON-IGNORED record on `wd` to.
  fn attributed(t: &WdTable, wd: i32) -> Vec<WatchId> {
    t.attribute(wd).to_vec()
  }

  #[test]
  fn register_then_ignored_erases_and_fans_out() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(attributed(&t, 7), vec![watch(1)]);

    let fanned = t.on_ignored(7);
    assert_eq!(fanned, vec![watch(1)]);
    assert!(
      attributed(&t, 7).is_empty(),
      "IGNORED is the authoritative erase"
    );
  }

  #[test]
  fn alias_fans_attribution_to_every_anchor() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    t.alias(7, watch(2)); // the EEXIST path: same inode reached twice
    assert_eq!(attributed(&t, 7), vec![watch(1), watch(2)]);

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
      attributed(&t, 7),
      vec![watch(2)],
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

    // Between rm_watch and the queued IN_IGNORED the entry still exists:
    // attribution answers empty (the anchor was unwatched), but the wd stays
    // mapped until its marker — and no fresh install can land on it (grants
    // are monotone below the rebuild threshold).
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

  /// The adoption invariant's data: a mapped `wd` — live or draining — is
  /// never adoptable (and never granted again: a fresh install's `wd`
  /// outgrows it), and only the consumed `IN_IGNORED` frees it.
  #[test]
  fn a_mapped_wd_is_never_adoptable_until_its_marker_is_consumed() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert!(t.contains(7), "a live mapping refuses adoption");
    assert!(t.is_live(7));

    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));
    assert!(t.contains(7), "a draining tombstone still refuses adoption");
    assert!(!t.is_live(7), "a tombstone is not an aliasing target");

    let _ = t.on_ignored(7);
    assert!(!t.contains(7), "the consumed marker frees the wd");
    assert!(!t.is_live(7));
  }

  /// The tombstone the kernel can no longer owe a marker for: `erase_dead` is
  /// the `EINVAL` proof's erase. It frees the `wd` at once — a marker the loss
  /// swallowed would otherwise strand the entry for the fd's whole life — and
  /// leaves the reverse index consistent, so a marker that DID survive behind
  /// the sentinel no-ops on the unmapped `wd` and the next drain of the same
  /// anchor re-issues nothing.
  #[test]
  fn erase_dead_frees_a_tombstone_whose_marker_can_never_come() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));
    assert!(
      t.contains(7),
      "the tombstone stands until it is proven dead"
    );

    t.erase_dead(7);
    assert!(!t.contains(7), "the proof frees the wd immediately");
    assert!(!t.is_live(7));
    assert!(
      t.wd_of(watch(1)).is_none(),
      "the drained anchor keeps no reverse-index entry"
    );
    assert_eq!(
      t.begin_drain(watch(1)),
      DrainDecision::KeepWd,
      "an erased tombstone re-issues no kernel removal"
    );
    assert!(
      t.on_ignored(7).is_empty(),
      "a surviving marker no-ops on the unmapped wd"
    );

    // The erase is per-`wd`: a sibling tombstone is untouched (only the loss
    // reap is wholesale).
    let mut t = WdTable::new();
    t.register(7, watch(1));
    t.register(9, watch(2));
    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));
    assert_eq!(t.begin_drain(watch(2)), DrainDecision::RemoveWd(9));
    t.erase_dead(7);
    assert!(!t.contains(7));
    assert!(
      t.contains(9),
      "the sibling tombstone still awaits its marker"
    );
  }

  /// A PLAIN draining entry still erases on its IGNORED — the ordinary
  /// self-induced teardown.
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

  /// A stale LIVE mapping (its kernel watch died with its markers still
  /// queued) is erased by its OWN marker, fanning the kernel teardown out to
  /// its anchors — and a SECOND marker on the then-unmapped `wd` (a
  /// straggler behind the genuine one) no-ops. Because the `wd` is never
  /// granted again (the no-wrap invariant), no replacement binding can stand
  /// on it for either marker to erase — the post-loss stale marker can only
  /// ever clear the stale mapping it belongs to.
  #[test]
  fn a_stale_mappings_markers_erase_only_the_stale_mapping() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    // The kernel watch behind wd 7 dies (object deleted; markers queued or
    // dropped behind an overflow). A queue loss lands first: live mappings
    // survive it.
    t.on_loss();
    assert_eq!(attributed(&t, 7), vec![watch(1)]);

    // The stale mapping's own marker arrives late (it was queued behind the
    // overflow sentinel): it erases the mapping and fans the teardown.
    assert_eq!(t.on_ignored(7), vec![watch(1)]);
    assert!(!t.contains(7));

    // A straggling duplicate marker trails it: the wd is unmapped, so the
    // straggler no-ops — nothing else can be addressed by it.
    assert!(t.on_ignored(7).is_empty());
    assert!(
      !t.contains(7),
      "a straggling marker maps nothing into being"
    );
  }

  #[test]
  fn unknown_wd_attributes_to_nobody() {
    let t = WdTable::new();
    assert!(attributed(&t, 99).is_empty());
  }

  /// A draining tombstone awaits its own `IN_IGNORED` to erase; a queue loss
  /// can drop that marker, and nothing else reaps a tombstone. `on_loss`
  /// erases draining tombstones so the `wd` is clean for the rescan's
  /// re-arm.
  #[test]
  fn overflow_resolves_a_draining_tombstone() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));
    assert!(t.contains(7), "the tombstone awaits its IGNORED");

    // The overflow may have dropped that IGNORED; the reap erases the
    // tombstone rather than letting it strand.
    t.on_loss();
    assert!(
      !t.contains(7),
      "the draining tombstone is resolved, not stranded"
    );

    // The structure itself accepts a clean re-registration of the freed wd
    // (a FRESH instance's table starts empty anyway; on one live fd the
    // no-wrap invariant means no re-grant ever reaches this).
    t.register(7, watch(2));
    assert_eq!(
      attributed(&t, 7),
      vec![watch(2)],
      "the reused wd attributes immediately"
    );
  }

  /// Reaping a tombstone EARLY — its marker actually survived, queued behind
  /// the loss sentinel — is safe: the straggling marker no-ops on the
  /// unmapped `wd` (never granted again on this fd, so no fresh binding can
  /// be standing there).
  #[test]
  fn a_tombstone_reaped_early_leaves_its_marker_a_noop() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));
    t.on_loss();
    assert!(!t.contains(7));

    // The marker the reap presumed dropped arrives after all.
    assert!(t.on_ignored(7).is_empty(), "the straggler fans to nobody");
    assert!(!t.contains(7));
  }

  /// The loss reap touches only draining tombstones: a live entry — and its
  /// alias fan-out — keeps attributing across a loss. Its events are lost for
  /// that buffer, but the `wd → anchors` mapping is truth the rescan
  /// reconciles, never something to tear down.
  #[test]
  fn overflow_leaves_a_plain_live_entry_intact() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    t.alias(7, watch(2));

    t.on_loss();
    assert_eq!(
      attributed(&t, 7),
      vec![watch(1), watch(2)],
      "a live entry and its alias fan-out survive the loss reap unchanged"
    );
    // Teardown still flows normally afterwards.
    assert_eq!(t.on_ignored(7), vec![watch(1), watch(2)]);
    assert!(!t.contains(7));
  }

  /// The re-add `EEXIST` path: aliasing an anchor already on the entry is a
  /// no-op — a duplicate would fan every record out twice.
  #[test]
  fn an_alias_readd_of_a_present_anchor_dedups() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    t.alias(7, watch(1));
    assert_eq!(
      attributed(&t, 7),
      vec![watch(1)],
      "the re-added anchor appears once"
    );
    assert_eq!(
      t.on_ignored(7),
      vec![watch(1)],
      "one teardown record per anchor"
    );
  }

  /// The reverse index tracks a rebind: draining the old binding then
  /// registering on a new `wd` moves the anchor, with the old entry left
  /// draining for its own marker.
  #[test]
  fn wd_of_follows_a_cross_wd_rebind() {
    let mut t = WdTable::new();
    t.register(7, watch(1));
    assert_eq!(t.wd_of(watch(1)), Some(7));
    assert_eq!(t.begin_drain(watch(1)), DrainDecision::RemoveWd(7));
    assert_eq!(t.wd_of(watch(1)), None);
    t.register(9, watch(1));
    assert_eq!(t.wd_of(watch(1)), Some(9));
    assert_eq!(attributed(&t, 9), vec![watch(1)]);
    // The old tombstone still resolves through its own marker.
    assert!(t.on_ignored(7).is_empty());
    assert!(!t.contains(7));
  }
}

/// Live-kernel smoke: compiled by the Linux-target lint gate on every host,
/// RUN by the container harness (`ci/linux-verify.sh`) and the CI Linux legs.
#[cfg(all(target_os = "linux", not(miri)))]
mod smoke {
  use std::{ffi::OsString, fs, num::NonZeroU64, time::Duration};

  use tributary_proto::WatchId;

  use crate::os::{
    Quiesce, SourceConfig,
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

    // The reader is JOINED by this teardown, and a joined thread is the whole
    // observation: an inotify source can therefore never answer `Unproven`.
    assert_eq!(
      handle.shutdown(),
      Quiesce::Proven,
      "the join proves the stop"
    );
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

    // The reader is JOINED by this teardown, and a joined thread is the whole
    // observation: an inotify source can therefore never answer `Unproven`.
    assert_eq!(
      handle.shutdown(),
      Quiesce::Proven,
      "the join proves the stop"
    );
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
    // The reader is JOINED by this teardown, and a joined thread is the whole
    // observation: an inotify source can therefore never answer `Unproven`.
    assert_eq!(
      handle.shutdown(),
      Quiesce::Proven,
      "the join proves the stop"
    );
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
    // The reader is JOINED by this teardown, and a joined thread is the whole
    // observation: an inotify source can therefore never answer `Unproven`.
    assert_eq!(
      handle.shutdown(),
      Quiesce::Proven,
      "the join proves the stop"
    );
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
    // The reader is JOINED by this teardown, and a joined thread is the whole
    // observation: an inotify source can therefore never answer `Unproven`.
    assert_eq!(
      handle.shutdown(),
      Quiesce::Proven,
      "the join proves the stop"
    );
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
    // The reader is JOINED by this teardown, and a joined thread is the whole
    // observation: an inotify source can therefore never answer `Unproven`.
    assert_eq!(
      handle.shutdown(),
      Quiesce::Proven,
      "the join proves the stop"
    );
    let _ = fs::remove_dir_all(&dir);
  }
}
