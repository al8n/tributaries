use super::*;
use std::string::ToString;

const ALL: &[WatchError] = &[
  WatchError::NoSpace,
  WatchError::Permission,
  WatchError::NotFound,
  WatchError::Gone,
  WatchError::Io,
];

#[test]
fn as_str_is_stable_snake_case() {
  assert_eq!(WatchError::NoSpace.as_str(), "no_space");
  assert_eq!(WatchError::Permission.as_str(), "permission");
  assert_eq!(WatchError::NotFound.as_str(), "not_found");
  assert_eq!(WatchError::Gone.as_str(), "gone");
  assert_eq!(WatchError::Io.as_str(), "io");
}

#[test]
fn display_routes_through_as_str() {
  for e in ALL {
    assert_eq!(e.to_string(), e.as_str());
  }
}

#[test]
fn predicates_are_exclusive() {
  for e in ALL {
    let set = [
      e.is_no_space(),
      e.is_permission(),
      e.is_not_found(),
      e.is_gone(),
      e.is_io(),
    ];
    assert_eq!(set.iter().filter(|b| **b).count(), 1, "{e:?}");
  }
}

#[test]
fn no_space_is_the_degrade_signal() {
  assert!(WatchError::NoSpace.is_no_space());
  assert!(!WatchError::Io.is_no_space());
}
