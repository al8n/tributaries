use super::*;
use std::{string::ToString, vec};

#[test]
fn segment_projects_str() {
  let s = Segment::new("src");
  assert_eq!(s.as_str(), "src");
  assert!(!s.is_empty());
  assert_eq!(s.to_string(), "src");
}

#[test]
fn segment_from_conversions_agree() {
  assert_eq!(Segment::from("a"), Segment::from("a".to_string()));
  assert_eq!(Segment::new("a"), Segment::from("a"));
}

#[test]
fn segment_borrows_as_str() {
  let s = Segment::new("lib.rs");
  let borrowed: &str = s.borrow();
  assert_eq!(borrowed, "lib.rs");
  assert_eq!(s.as_ref(), "lib.rs");
}

#[test]
fn location_empty_is_root() {
  let root = Location::new();
  assert!(root.is_empty());
  assert_eq!(root.len(), 0);
  assert_eq!(root.name(), None);
  assert_eq!(root.segments(), &[] as &[Segment]);
}

#[test]
fn location_default_equals_new() {
  assert_eq!(Location::default(), Location::new());
}

#[test]
fn location_from_segments_preserves_order() {
  let loc = Location::from_segments([Segment::new("a"), Segment::new("b"), Segment::new("c")]);
  assert_eq!(loc.len(), 3);
  assert_eq!(loc.name(), Some(&Segment::new("c")));
  assert_eq!(
    loc.segments(),
    &[Segment::new("a"), Segment::new("b"), Segment::new("c")]
  );
}

#[test]
fn location_push_and_child_descend() {
  let mut loc = Location::new();
  loc.push(Segment::new("a"));
  let loc = loc.child(Segment::new("b"));
  assert_eq!(loc.segments(), &[Segment::new("a"), Segment::new("b")]);
  assert_eq!(loc.name(), Some(&Segment::new("b")));
}

#[test]
fn location_from_iter() {
  let loc: Location = vec![Segment::new("x"), Segment::new("y")]
    .into_iter()
    .collect();
  assert_eq!(loc.len(), 2);
}

#[test]
fn location_orders_lexicographically_by_segments() {
  let a = Location::from_segments([Segment::new("a")]);
  let ab = Location::from_segments([Segment::new("a"), Segment::new("b")]);
  let b = Location::from_segments([Segment::new("b")]);
  assert!(a < ab);
  assert!(ab < b);
}
