use super::*;
use crate::path::{Location, Segment};
use core::num::NonZeroU64;

fn scope_id(n: u64) -> ScopeId {
  ScopeId::new(NonZeroU64::new(n).unwrap())
}

fn watch_id(n: u64) -> WatchId {
  WatchId::new(NonZeroU64::new(n).unwrap())
}

#[test]
fn all_predicates() {
  let s = Scope::All;
  assert!(s.is_all());
  assert!(!s.is_root());
  assert!(!s.is_subtree());
  assert_eq!(s.root(), None);
  assert_eq!(s.subtree(), None);
}

#[test]
fn root_predicates_and_accessor() {
  let s = Scope::Root(scope_id(3));
  assert!(s.is_root());
  assert!(!s.is_all());
  assert_eq!(s.root(), Some(scope_id(3)));
  assert_eq!(s.subtree(), None);
}

#[test]
fn subtree_predicates_and_accessor() {
  let s = Scope::subtree_of(watch_id(8));
  assert!(s.is_subtree());
  assert!(!s.is_root());
  assert_eq!(s.root(), None);

  let sub = s.subtree().unwrap();
  assert_eq!(sub.watch(), watch_id(8));
  assert!(sub.descent().is_empty());
}

#[test]
fn subtree_with_descent_locates_a_deep_directory() {
  let descent = Location::from_segments([Segment::new("a"), Segment::new("b")]);
  let sub = SubtreeScope::new(watch_id(3)).with_descent(descent.clone());
  assert_eq!(sub.watch(), watch_id(3));
  assert_eq!(sub.descent(), &descent);

  let s: Scope = sub.into();
  assert!(s.is_subtree());
  assert_eq!(s.subtree().unwrap().descent().len(), 2);
}
