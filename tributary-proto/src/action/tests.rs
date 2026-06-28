use super::*;
use core::num::NonZeroU64;

fn watch(n: u64) -> WatchId {
  WatchId::new(NonZeroU64::new(n).unwrap())
}

fn req(n: u64) -> ReqId {
  ReqId::new(NonZeroU64::new(n).unwrap())
}

fn scope(n: u64) -> ScopeId {
  ScopeId::new(NonZeroU64::new(n).unwrap())
}

#[test]
fn watch_target_root() {
  let t = WatchTarget::Root(scope(1));
  assert!(t.is_root());
  assert!(!t.is_child());
  assert_eq!(t.root(), Some(scope(1)));
  assert_eq!(t.as_child(), None);
}

#[test]
fn watch_target_child() {
  let t = WatchTarget::child(watch(2), Segment::new("sub"));
  assert!(t.is_child());
  assert_eq!(t.root(), None);
  let child = t.as_child().unwrap();
  assert_eq!(child.parent(), watch(2));
  assert_eq!(child.name(), &Segment::new("sub"));
}

#[test]
fn watch_action_round_trips() {
  let a = Action::watch(watch(3), WatchTarget::Root(scope(1)), Interest::all());
  assert!(a.is_watch());
  let cmd = a.as_watch().unwrap();
  assert_eq!(cmd.id(), watch(3));
  assert!(cmd.target().is_root());
  assert!(cmd.mask().created());
}

#[test]
fn unwatch_action() {
  let a = Action::Unwatch(watch(4));
  assert!(a.is_unwatch());
  assert_eq!(a.as_unwatch(), Some(watch(4)));
  assert_eq!(a.as_watch(), None);
}

#[test]
fn enumerate_action_round_trips() {
  let a = Action::enumerate(req(7), watch(3));
  assert!(a.is_enumerate());
  let cmd = a.as_enumerate().unwrap();
  assert_eq!(cmd.req(), req(7));
  assert_eq!(cmd.dir(), watch(3));
}

#[test]
fn stat_target_watch_and_child() {
  let w = StatTarget::Watch(watch(5));
  assert!(w.is_watch());
  assert_eq!(w.watch(), Some(watch(5)));

  let c = StatTarget::child(watch(5), Segment::new("f"));
  assert!(c.is_child());
  assert_eq!(c.watch(), None);
  assert_eq!(c.as_child().unwrap().name(), &Segment::new("f"));
}

#[test]
fn stat_action_round_trips() {
  let a = Action::stat(req(9), StatTarget::Watch(watch(5)));
  assert!(a.is_stat());
  let cmd = a.as_stat().unwrap();
  assert_eq!(cmd.req(), req(9));
  assert!(cmd.of().is_watch());
}

#[test]
fn predicates_are_mutually_exclusive() {
  let actions = [
    Action::watch(watch(1), WatchTarget::Root(scope(1)), Interest::new()),
    Action::Unwatch(watch(1)),
    Action::enumerate(req(1), watch(1)),
    Action::stat(req(1), StatTarget::Watch(watch(1))),
  ];
  for a in &actions {
    let set = [a.is_watch(), a.is_unwatch(), a.is_enumerate(), a.is_stat()];
    assert_eq!(set.iter().filter(|b| **b).count(), 1);
  }
}
