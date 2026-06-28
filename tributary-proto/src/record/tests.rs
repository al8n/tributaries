use super::*;
use crate::path::Segment;
use core::num::NonZeroU64;
use std::{string::ToString, vec};

fn watch(n: u64) -> WatchId {
  WatchId::new(NonZeroU64::new(n).unwrap())
}

fn cookie(n: u64) -> MoveCookie {
  MoveCookie::new(NonZeroU64::new(n).unwrap())
}

#[test]
fn file_kind_as_str_and_display() {
  for (k, s) in [
    (FileKind::File, "file"),
    (FileKind::Dir, "dir"),
    (FileKind::Symlink, "symlink"),
    (FileKind::Other, "other"),
    (FileKind::Unknown, "unknown"),
  ] {
    assert_eq!(k.as_str(), s);
    assert_eq!(k.to_string(), s);
  }
  assert!(FileKind::Dir.is_dir());
  assert!(FileKind::File.is_file());
  assert!(FileKind::Symlink.is_symlink());
  assert!(FileKind::Other.is_other());
  assert!(FileKind::Unknown.is_unknown());
}

#[test]
fn record_kind_as_str_round_trips() {
  let all = [
    RecordKind::Created,
    RecordKind::Removed,
    RecordKind::Modified,
    RecordKind::Attrib,
    RecordKind::MovedFrom,
    RecordKind::MovedTo,
    RecordKind::MoveSelf,
    RecordKind::DeleteSelf,
    RecordKind::Ignored,
  ];
  for k in all {
    assert_eq!(k.to_string(), k.as_str());
    assert!(!k.as_str().is_empty());
  }
}

#[test]
fn record_kind_move_and_self_predicates() {
  assert!(RecordKind::MovedFrom.is_moved_from());
  assert!(RecordKind::MovedTo.is_moved_to());
  assert!(RecordKind::MovedFrom.is_move_half());
  assert!(RecordKind::MovedTo.is_move_half());
  assert!(!RecordKind::Created.is_move_half());

  assert!(RecordKind::Ignored.is_teardown());
  assert!(!RecordKind::DeleteSelf.is_teardown());

  assert!(RecordKind::MoveSelf.is_self_event());
  assert!(RecordKind::DeleteSelf.is_self_event());
  assert!(RecordKind::Ignored.is_self_event());
  assert!(!RecordKind::Created.is_self_event());
}

#[test]
fn io_class_as_str_and_predicates() {
  for (c, s) in [
    (IoClass::NotFound, "not_found"),
    (IoClass::Permission, "permission"),
    (IoClass::Loop, "loop"),
    (IoClass::OutOfDescriptors, "out_of_descriptors"),
    (IoClass::Io, "io"),
  ] {
    assert_eq!(c.as_str(), s);
    assert_eq!(c.to_string(), s);
  }
  assert!(IoClass::NotFound.is_not_found());
  assert!(IoClass::Permission.is_permission());
  assert!(IoClass::Loop.is_loop());
  assert!(IoClass::OutOfDescriptors.is_out_of_descriptors());
  assert!(IoClass::Io.is_io());
}

#[test]
fn dir_entry_projects_fields() {
  let e = DirEntry::new(Segment::new("sub"), FileKind::Dir);
  assert_eq!(e.name(), &Segment::new("sub"));
  assert_eq!(e.kind(), FileKind::Dir);
  assert!(e.is_dir());

  let f = DirEntry::new(Segment::new("a.txt"), FileKind::File);
  assert!(!f.is_dir());
}

#[test]
fn enumerate_ok_exposes_entries() {
  let entries = vec![
    DirEntry::new(Segment::new("a"), FileKind::File),
    DirEntry::new(Segment::new("b"), FileKind::Dir),
  ];
  let r = EnumerateResult::Ok(entries.clone());
  assert!(r.is_ok());
  assert!(!r.forces_rescan());
  assert_eq!(r.entries(), entries.as_slice());
  assert_eq!(r.failure(), None);
}

#[test]
fn enumerate_partial_forces_rescan_but_keeps_entries() {
  let entries = vec![DirEntry::new(Segment::new("a"), FileKind::File)];
  let r = EnumerateResult::Partial(entries.clone());
  assert!(r.is_partial());
  assert!(r.forces_rescan());
  assert_eq!(r.entries(), entries.as_slice());
}

#[test]
fn enumerate_failed_forces_rescan_and_reports_class() {
  let r = EnumerateResult::Failed(IoClass::Permission);
  assert!(r.is_failed());
  assert!(r.forces_rescan());
  assert_eq!(r.entries(), &[] as &[DirEntry]);
  assert_eq!(r.failure(), Some(IoClass::Permission));
}

#[test]
fn os_record_minimal_has_no_optionals() {
  let r = OsRecord::new(watch(5), RecordKind::Modified);
  assert_eq!(r.watch(), watch(5));
  assert_eq!(r.kind(), RecordKind::Modified);
  assert_eq!(r.name(), None);
  assert_eq!(r.is_dir(), None);
  assert_eq!(r.cookie(), None);
}

#[test]
fn os_record_builders_attach_optionals() {
  let r = OsRecord::new(watch(5), RecordKind::Created)
    .with_name(Segment::new("child"))
    .with_is_dir(true);
  assert_eq!(r.name(), Some(&Segment::new("child")));
  assert_eq!(r.is_dir(), Some(true));
  assert_eq!(r.cookie(), None);

  let moved = OsRecord::new(watch(5), RecordKind::MovedFrom)
    .with_name(Segment::new("old"))
    .with_cookie(cookie(0xABCD));
  assert_eq!(moved.cookie(), Some(cookie(0xABCD)));
  assert!(moved.kind().is_move_half());
}
