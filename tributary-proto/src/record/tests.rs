use super::*;
use crate::{
  id::Identity,
  path::{Location, Segment},
};
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
  assert_eq!(r.target(), None);
  assert_eq!(r.depth(), 0);
  assert_eq!(r.is_dir(), None);
  assert_eq!(r.cookie(), None);
}

#[test]
fn os_record_builders_attach_optionals() {
  let r = OsRecord::new(watch(5), RecordKind::Created)
    .with_name(Segment::new("child"))
    .with_is_dir(true);
  assert_eq!(r.name(), Some(&Segment::new("child")));
  assert_eq!(r.depth(), 1);
  assert_eq!(r.is_dir(), Some(true));
  assert_eq!(r.cookie(), None);

  let moved = OsRecord::new(watch(5), RecordKind::MovedFrom)
    .with_name(Segment::new("old"))
    .with_cookie(cookie(0xABCD));
  assert_eq!(moved.cookie(), Some(cookie(0xABCD)));
  assert!(moved.kind().is_move_half());
}

#[test]
fn os_record_deep_target_reports_no_direct_name() {
  let target = Location::from_segments([Segment::new("a"), Segment::new("b")]);
  let deep = OsRecord::new(watch(5), RecordKind::Created).with_target(target.clone());
  assert_eq!(deep.target(), Some(&target));
  assert_eq!(deep.depth(), 2);
  assert_eq!(deep.name(), None, "a deep target has no direct-child name");

  let one = OsRecord::new(watch(5), RecordKind::Created)
    .with_target(Location::from_segments([Segment::new("only")]));
  assert_eq!(one.name(), Some(&Segment::new("only")));
  assert_eq!(one.depth(), 1);
}

#[test]
fn evidence_of_a_kind_is_that_kind_alone() {
  assert!(Evidence::of(RecordKind::Created).created());
  assert!(Evidence::of(RecordKind::Removed).removed());
  assert!(Evidence::of(RecordKind::Modified).modified());
  assert!(Evidence::of(RecordKind::Attrib).attrib());
  assert!(Evidence::of(RecordKind::MovedFrom).moved());
  assert!(Evidence::of(RecordKind::MovedTo).moved());
  assert!(Evidence::of(RecordKind::MoveSelf).moved());
  // A watched object's own deletion IS a removal of it.
  assert!(Evidence::of(RecordKind::DeleteSelf).removed());
  // A teardown says nothing about the object, only about the watch.
  assert!(Evidence::of(RecordKind::Ignored).is_empty());
  assert!(Evidence::new().is_empty());
  assert!(!Evidence::of(RecordKind::Created).removed());
}

#[test]
fn evidence_union_only_ever_grows() {
  let created = Evidence::new().with_created();
  let attrib = Evidence::new().with_attrib();
  let both = created.union(attrib);
  assert!(both.created() && both.attrib());
  assert_eq!(both.union(Evidence::new()), both);
  assert_eq!(both.union(both), both);
}

#[test]
fn evidence_admits_on_any_proven_fact() {
  let both = Evidence::new().with_created().with_attrib();
  assert!(both.admits(Interest::new().with_created()));
  assert!(both.admits(Interest::new().with_attrib()));
  assert!(!both.admits(Interest::new().with_modified()));
  assert!(!Evidence::new().admits(Interest::all()));
  assert!(!both.admits(Interest::new()));
}

#[test]
fn evidence_primary_prefers_the_structural_verb() {
  let mask = Evidence::new().with_created().with_modified().with_attrib();
  assert_eq!(mask.primary(), Some(RecordKind::Created));
  assert_eq!(
    Evidence::new().with_removed().with_attrib().primary(),
    Some(RecordKind::Removed)
  );
  assert_eq!(
    Evidence::new().with_modified().with_attrib().primary(),
    Some(RecordKind::Modified)
  );
  assert_eq!(
    Evidence::new().with_attrib().primary(),
    Some(RecordKind::Attrib)
  );
  // A move needs a direction no fact set carries, and nothing proves nothing.
  assert_eq!(Evidence::new().with_moved().primary(), None);
  assert_eq!(Evidence::new().primary(), None);
}

#[test]
fn record_from_evidence_keeps_every_fact_and_derives_the_verb() {
  let mask = Evidence::new().with_created().with_attrib();
  let rec = OsRecord::proved(watch(1), mask).expect("a dirent fact names a verb");
  assert_eq!(rec.kind(), RecordKind::Created);
  assert_eq!(rec.evidence(), mask);
  assert_eq!(OsRecord::proved(watch(1), Evidence::new()), None);
  assert_eq!(
    OsRecord::proved(watch(1), Evidence::new().with_moved()),
    None
  );
}

#[test]
fn record_evidence_defaults_to_its_kind_and_only_widens() {
  let rec = OsRecord::new(watch(1), RecordKind::MovedTo);
  assert_eq!(rec.evidence(), Evidence::of(RecordKind::MovedTo));
  let widened = rec.also_proved(Evidence::new().with_modified());
  assert!(widened.evidence().moved() && widened.evidence().modified());
  // `also_proved` unions; it cannot clear what was already stated.
  let again = widened.also_proved(Evidence::new());
  assert!(again.evidence().moved() && again.evidence().modified());
}

#[test]
fn stat_result_reports_what_it_settles() {
  let dir = StatResult::Ok(
    StatEntry::new(FileKind::Dir).with_node(Identity::new(NonZeroU64::new(7).unwrap())),
  );
  assert!(dir.is_ok() && !dir.is_failed());
  assert_eq!(dir.resolved(), Some(FileKind::Dir));
  assert_eq!(dir.entry().unwrap().kind(), FileKind::Dir);
  assert!(dir.entry().unwrap().is_dir());
  assert_eq!(dir.entry().unwrap().node().unwrap().as_u64(), 7);
  assert_eq!(dir.failure(), None);

  // A kind the stat could not read settles nothing, exactly like a failure.
  let unknown = StatResult::found(FileKind::Unknown);
  assert!(unknown.is_ok());
  assert_eq!(unknown.resolved(), None);

  let failed = StatResult::Failed(IoClass::Permission);
  assert!(failed.is_failed() && !failed.is_ok());
  assert_eq!(failed.resolved(), None);
  assert_eq!(failed.entry(), None);
  assert_eq!(failed.failure(), Some(IoClass::Permission));
}
