use core::num::NonZeroU64;
use std::path::Path;

use tributary_proto::{Change, ChangeId, ChangeKind, Epoch, Location, ScopeId, Segment};

use super::*;

fn change(kind: ChangeKind, location: Location) -> Change {
  Change::new(
    ChangeId::new(NonZeroU64::new(7).unwrap()),
    ScopeId::new(NonZeroU64::new(1).unwrap()),
    location,
    kind,
    Epoch::START,
  )
}

fn root() -> RootHandle {
  RootHandle::new(1, ScopeId::new(NonZeroU64::new(1).unwrap()))
}

fn loc(parts: &[&str]) -> Location {
  Location::from_segments(parts.iter().map(|p| Segment::new(*p)))
}

#[test]
fn created_assembles_absolute_and_relative_paths() {
  let e = Event::from_change(
    root(),
    Path::new("/watch/root"),
    &change(ChangeKind::Created, loc(&["a", "b.txt"])),
  );
  assert_eq!(e.path(), Path::new("/watch/root/a/b.txt"));
  assert_eq!(e.location(), &loc(&["a", "b.txt"]));
  assert!(e.kind().is_created());
  assert_eq!(e.kind().as_str(), "created");
  assert_eq!(e.epoch(), Epoch::START);
  assert!(!e.is_rescan());
}

#[test]
fn moved_carries_the_absolute_source_path() {
  let e = Event::from_change(
    root(),
    Path::new("/watch/root"),
    &change(
      ChangeKind::Moved(loc(&["old", "name"])),
      loc(&["new", "name"]),
    ),
  );
  assert!(e.kind().is_moved());
  let moved = e.kind().moved().expect("a moved payload");
  assert_eq!(moved.from(), Path::new("/watch/root/old/name"));
  assert_eq!(e.path(), Path::new("/watch/root/new/name"));
}

#[test]
fn rescan_at_the_root_names_the_root_itself() {
  let e = Event::from_change(
    root(),
    Path::new("/watch/root"),
    &change(ChangeKind::Rescan, Location::new()),
  );
  assert!(e.is_rescan());
  assert_eq!(e.path(), Path::new("/watch/root"));
  assert!(e.location().is_empty());
}

#[test]
fn kind_predicates_and_display_agree_with_as_str() {
  let kinds = [
    (EventKind::Created, "created"),
    (EventKind::Modified, "modified"),
    (EventKind::Removed, "removed"),
    (EventKind::Rescan, "rescan"),
  ];
  for (kind, name) in kinds {
    assert_eq!(kind.as_str(), name);
    assert_eq!(kind.to_string(), name);
  }
  assert!(EventKind::Modified.is_modified());
  assert!(EventKind::Removed.is_removed());
  assert_eq!(EventKind::Created.moved(), None);
}
