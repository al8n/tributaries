use super::*;
use crate::path::Segment;
use core::num::NonZeroU64;
use std::string::ToString;

fn change_id(n: u64) -> ChangeId {
  ChangeId::new(NonZeroU64::new(n).unwrap())
}

fn scope(n: u64) -> ScopeId {
  ScopeId::new(NonZeroU64::new(n).unwrap())
}

fn loc(parts: &[&str]) -> Location {
  Location::from_segments(parts.iter().map(|p| Segment::new(*p)))
}

#[test]
fn change_kind_as_str_and_display() {
  let moved = ChangeKind::Moved(loc(&["old"]));
  for (k, s) in [
    (ChangeKind::Created, "created"),
    (ChangeKind::Modified, "modified"),
    (ChangeKind::Removed, "removed"),
    (moved.clone(), "moved"),
    (ChangeKind::Rescan, "rescan"),
  ] {
    assert_eq!(k.as_str(), s);
    assert_eq!(k.to_string(), s);
  }
}

#[test]
fn change_kind_predicates() {
  assert!(ChangeKind::Created.is_created());
  assert!(ChangeKind::Modified.is_modified());
  assert!(ChangeKind::Removed.is_removed());
  assert!(ChangeKind::Moved(loc(&["a"])).is_moved());
  assert!(ChangeKind::Rescan.is_rescan());
}

#[test]
fn moved_from_exposes_source_only_for_moved() {
  let moved = ChangeKind::Moved(loc(&["a", "b"]));
  assert_eq!(moved.moved_from(), Some(&loc(&["a", "b"])));
  assert_eq!(ChangeKind::Created.moved_from(), None);
  assert_eq!(ChangeKind::Rescan.moved_from(), None);
}

#[test]
fn change_projects_fields() {
  let c = Change::new(
    change_id(1),
    scope(2),
    loc(&["src", "lib.rs"]),
    ChangeKind::Modified,
    Epoch::new(7),
  );
  assert_eq!(c.id(), change_id(1));
  assert_eq!(c.scope(), scope(2));
  assert_eq!(c.location(), &loc(&["src", "lib.rs"]));
  assert!(c.kind().is_modified());
  assert_eq!(c.epoch(), Epoch::new(7));
}

#[test]
fn rescan_change_carries_scope() {
  let c = Change::new(
    change_id(5),
    scope(3),
    Location::new(),
    ChangeKind::Rescan,
    Epoch::START,
  );
  assert!(c.kind().is_rescan());
  assert_eq!(c.scope(), scope(3));
  assert!(c.location().is_empty());
}
