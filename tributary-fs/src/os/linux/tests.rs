use std::path::Path;

use tributary_proto::WatchId;

use super::{
  attribute_events, fs_type_is_remote,
  inotify::{
    decode::{IN_CREATE, IN_IGNORED, IN_ISDIR, IN_Q_OVERFLOW, InotifyMask, RawInotifyEvent},
    table::WdTable,
  },
  parse_mountinfo,
};

fn watch(n: u64) -> WatchId {
  WatchId::new(core::num::NonZeroU64::new(n).unwrap())
}

fn event(wd: i32, mask: u32, name: Option<&[u8]>) -> RawInotifyEvent {
  RawInotifyEvent {
    wd,
    mask: InotifyMask(mask),
    cookie: 0,
    name: name.map(<[u8]>::to_vec),
  }
}

#[test]
fn attribution_fans_out_per_alias() {
  let mut table = WdTable::new();
  table.register(3, watch(1));
  table.alias(3, watch(2));

  let batch = attribute_events(vec![event(3, IN_CREATE | IN_ISDIR, Some(b"d"))], &mut table);
  assert!(!batch.lost);
  assert_eq!(batch.events.len(), 1);
  let (anchors, raw) = batch.events[0].as_inotify().unwrap();
  assert_eq!(anchors, &[watch(1), watch(2)]);
  assert_eq!(raw.name.as_deref(), Some(b"d".as_slice()));
}

#[test]
fn overflow_sentinel_marks_lost_and_is_not_forwarded() {
  let mut table = WdTable::new();
  table.register(3, watch(1));

  let batch = attribute_events(
    vec![
      event(-1, IN_Q_OVERFLOW, None),
      event(3, IN_CREATE, Some(b"x")),
    ],
    &mut table,
  );
  assert!(batch.lost);
  assert_eq!(batch.events.len(), 1, "the sentinel itself is not an event");
}

#[test]
fn ignored_consumes_the_entry_and_attributes_live_anchors() {
  let mut table = WdTable::new();
  table.register(3, watch(1));

  let batch = attribute_events(vec![event(3, IN_IGNORED, None)], &mut table);
  assert_eq!(
    batch.events.len(),
    1,
    "kernel-initiated teardown is forwarded"
  );
  assert!(!table.contains(3), "IGNORED is the authoritative erase");

  // The next IGNORED-less record on the erased wd attributes to nothing.
  let batch = attribute_events(vec![event(3, IN_CREATE, Some(b"x"))], &mut table);
  assert!(batch.events.is_empty());
  assert!(!batch.lost, "records for dropped watches are not loss");
}

#[test]
fn draining_wd_attributes_nothing_until_ignored() {
  let mut table = WdTable::new();
  table.register(3, watch(1));
  let _ = table.begin_drain(watch(1));

  let batch = attribute_events(vec![event(3, IN_CREATE, Some(b"x"))], &mut table);
  assert!(batch.events.is_empty());

  // The self-induced teardown's IGNORED erases silently (anchors drained).
  let batch = attribute_events(vec![event(3, IN_IGNORED, None)], &mut table);
  assert!(batch.events.is_empty());
  assert!(!table.contains(3));
}

#[test]
fn mountinfo_extracts_mounts_strictly_under_root() {
  let content = "\
36 25 0:32 / /mnt/a rw,relatime shared:1 - tmpfs tmpfs rw
37 25 0:33 / /mnt/a/inner rw,relatime shared:2 - ext4 /dev/loop0 rw
38 25 0:34 / /mnt/b rw,relatime shared:3 - tmpfs tmpfs rw
39 25 0:35 / / rw,relatime shared:4 - ext4 /dev/root rw
malformed line
40 25 0:36 /
";
  let mounts = parse_mountinfo(content, Path::new("/mnt/a"));
  assert_eq!(mounts, vec![std::path::PathBuf::from("/mnt/a/inner")]);
}

#[test]
fn mountinfo_unescapes_octal_fields() {
  let content = "36 25 0:32 / /mnt/with\\040space rw shared:1 - tmpfs tmpfs rw\n";
  let mounts = parse_mountinfo(content, Path::new("/mnt"));
  assert_eq!(mounts, vec![std::path::PathBuf::from("/mnt/with space")]);
}

#[test]
fn remote_fs_magics_are_refused_and_local_ones_pass() {
  assert!(fs_type_is_remote(0x6969), "NFS");
  assert!(fs_type_is_remote(0xFF53_4D42), "CIFS");
  assert!(fs_type_is_remote(0x6573_5546), "FUSE");
  assert!(!fs_type_is_remote(0xEF53), "ext4 is local");
  assert!(!fs_type_is_remote(0x0102_1994), "tmpfs is local");
  assert!(!fs_type_is_remote(0x9123_683E), "btrfs is local");
}
