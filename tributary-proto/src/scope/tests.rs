use super::*;
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
  let s = Scope::Subtree(watch_id(8));
  assert!(s.is_subtree());
  assert!(!s.is_root());
  assert_eq!(s.subtree(), Some(watch_id(8)));
  assert_eq!(s.root(), None);
}
