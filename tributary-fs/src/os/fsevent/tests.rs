use super::*;

#[test]
fn flag_predicates_match_their_bits() {
  let f = FsEventFlags::new(FsEventFlags::ITEM_CREATED.bits() | FsEventFlags::ITEM_IS_DIR.bits());
  assert!(f.item_created());
  assert!(f.item_is_dir());
  assert!(!f.item_removed());
  assert!(!f.item_renamed());
  assert!(f.contains(FsEventFlags::ITEM_CREATED));
  assert!(!f.contains(FsEventFlags::ITEM_REMOVED));
}

#[test]
fn coalesced_flag_words_report_every_operation() {
  let f = FsEventFlags::new(
    FsEventFlags::ITEM_CREATED.bits()
      | FsEventFlags::ITEM_MODIFIED.bits()
      | FsEventFlags::ITEM_REMOVED.bits()
      | FsEventFlags::ITEM_RENAMED.bits(),
  );
  assert!(f.item_created() && f.item_modified() && f.item_removed() && f.item_renamed());
}

#[test]
fn lost_sync_covers_both_drop_sides() {
  assert!(FsEventFlags::USER_DROPPED.lost_sync());
  assert!(FsEventFlags::KERNEL_DROPPED.lost_sync());
  assert!(!FsEventFlags::MUST_SCAN_SUBDIRS.lost_sync());
  assert!(!FsEventFlags::new(0).lost_sync());
}

#[test]
fn file_id_policy_is_total() {
  assert_eq!(file_id_from_extended(0), None);
  assert_eq!(file_id_from_extended(5).map(|n| n.get()), Some(5));
  assert_eq!(
    file_id_from_extended(-1).map(|n| n.get()),
    Some(u64::MAX),
    "the bit-cast is the lossless inverse of signed journal storage"
  );
}

#[test]
fn path_from_fs_repr_stops_at_the_first_nul() {
  assert_eq!(
    path_from_fs_repr(b"/tmp/a.txt\0slack"),
    Some(PathBuf::from("/tmp/a.txt"))
  );
  assert_eq!(path_from_fs_repr(b"/tmp/x"), Some(PathBuf::from("/tmp/x")));
  assert_eq!(path_from_fs_repr(b""), None);
  assert_eq!(path_from_fs_repr(b"\0"), None);
}

#[cfg(unix)]
#[test]
fn path_from_fs_repr_preserves_non_utf8_bytes() {
  use std::os::unix::ffi::OsStrExt;
  let bytes = b"/tmp/\xC3\x28\0";
  let path = path_from_fs_repr(bytes).expect("non-UTF-8 bytes are still a path");
  assert_eq!(path.as_os_str().as_bytes(), b"/tmp/\xC3\x28");
}
