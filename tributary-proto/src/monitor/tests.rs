use super::*;
use crate::{
  action::WatchTarget,
  path::Segment,
  record::{DirEntry, FileKind, IoClass},
};
use core::num::NonZeroU64;
use std::{vec, vec::Vec};

fn scope(n: u64) -> ScopeId {
  ScopeId::new(NonZeroU64::new(n).unwrap())
}

fn cookie(n: u64) -> MoveCookie {
  MoveCookie::new(NonZeroU64::new(n).unwrap())
}

fn at(ms: u64) -> Instant {
  Instant::from_origin(Duration::from_millis(ms))
}

fn seg(s: &str) -> Segment {
  Segment::new(s)
}

fn loc(parts: &[&str]) -> Location {
  Location::from_segments(parts.iter().map(|p| Segment::new(*p)))
}

fn per_dir() -> Monitor {
  Monitor::new(Capabilities::new().with_supports_push())
}

fn kernel_recursive() -> Monitor {
  Monitor::new(
    Capabilities::new()
      .with_supports_push()
      .with_kernel_recursive(),
  )
}

fn drain_actions(m: &mut Monitor) -> Vec<Action> {
  let mut out = Vec::new();
  while let Some(a) = m.poll_action() {
    out.push(a);
  }
  out
}

fn drain_events(m: &mut Monitor) -> Vec<Change> {
  let mut out = Vec::new();
  while let Some(e) = m.poll_event() {
    out.push(e);
  }
  out
}

/// Arms a root and brings it live, returning the root's WatchId. Drains any
/// already-queued actions first so the helper composes when several roots are
/// registered, then confirms the new root's bootstrap Watch was queued.
fn live_root(m: &mut Monitor, s: ScopeId) -> WatchId {
  let _ = drain_actions(m);
  let root = m.register_root(s, Interest::all());
  let actions = drain_actions(m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_watch().map(|c| c.id()) == Some(root))
  );
  m.on_watch_result(root, Ok(()));
  root
}

/// A registered root, armed AND past its bootstrap enumerate — i.e. `Live` and idle,
/// the realistic precondition for a subsequent overflow or move (a single outstanding
/// read at a time, so a re-arm on a still-enumerating root would coalesce).
fn live_root_idle(m: &mut Monitor, s: ScopeId) -> WatchId {
  let root = live_root(m, s);
  let boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(m);
  let _ = drain_events(m);
  root
}

#[test]
fn new_reports_capabilities_and_descent() {
  let m = per_dir();
  assert!(m.capabilities().supports_push());
  assert!(m.descends());
  assert_eq!(m.move_window(), DEFAULT_MOVE_WINDOW);

  let k = kernel_recursive();
  assert!(!k.descends());
}

#[test]
fn register_root_mints_and_queues_root_watch() {
  let mut m = per_dir();
  let root = m.register_root(scope(1), Interest::all());
  assert!(m.is_watched(root));
  assert_eq!(m.scope_of(root), Some(scope(1)));

  let actions = drain_actions(&mut m);
  assert_eq!(actions.len(), 1);
  let cmd = actions[0].as_watch().unwrap();
  assert_eq!(cmd.id(), root);
  assert_eq!(cmd.target(), &WatchTarget::Root(scope(1)));
}

#[test]
fn per_dir_watch_success_triggers_enumerate_after_arming() {
  let mut m = per_dir();
  let root = m.register_root(scope(1), Interest::all());
  let _ = drain_actions(&mut m);
  m.on_watch_result(root, Ok(()));

  let actions = drain_actions(&mut m);
  assert_eq!(actions.len(), 1, "per-dir root should enumerate once armed");
  let cmd = actions[0].as_enumerate().unwrap();
  assert_eq!(cmd.dir(), root);
}

#[test]
fn kernel_recursive_watch_success_does_not_enumerate() {
  let mut m = kernel_recursive();
  let root = m.register_root(scope(1), Interest::all());
  let _ = drain_actions(&mut m);
  m.on_watch_result(root, Ok(()));
  assert!(
    drain_actions(&mut m).is_empty(),
    "kernel-recursive backend must not descend"
  );
}

#[test]
fn enumerate_emits_created_and_descends_into_dirs() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);

  m.on_enumerate(
    ReqId::new(NonZeroU64::new(1).unwrap()),
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a.txt"), FileKind::File),
      DirEntry::new(seg("sub"), FileKind::Dir),
    ]),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(events.iter().all(|e| e.kind().is_created()));
  let locations: Vec<&Location> = events.iter().map(|e| e.location()).collect();
  assert!(locations.contains(&&loc(&["a.txt"])));
  assert!(locations.contains(&&loc(&["sub"])));

  let actions = drain_actions(&mut m);
  assert_eq!(
    actions.len(),
    1,
    "only the directory should get a child watch"
  );
  let child = actions[0].as_watch().unwrap();
  assert_eq!(child.target(), &WatchTarget::child(root, seg("sub")));
}

#[test]
fn enumerate_partial_forces_rescan() {
  let mut m = per_dir();
  let _root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);

  m.on_enumerate(
    ReqId::new(NonZeroU64::new(1).unwrap()),
    EnumerateResult::Partial(vec![DirEntry::new(seg("a"), FileKind::File)]),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
}

#[test]
fn enumerate_failed_forces_rescan() {
  let mut m = per_dir();
  let _root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);

  m.on_enumerate(
    ReqId::new(NonZeroU64::new(1).unwrap()),
    EnumerateResult::Failed(IoClass::Permission),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
}

#[test]
fn created_record_emits_created_for_child() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("new.txt")),
    at(10),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_created());
  assert_eq!(events[0].location(), &loc(&["new.txt"]));
  assert_eq!(events[0].scope(), scope(1));
}

#[test]
fn created_directory_record_descends() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(10),
  );
  let actions = drain_actions(&mut m);
  assert_eq!(actions.len(), 1);
  assert_eq!(
    actions[0].as_watch().unwrap().target(),
    &WatchTarget::child(root, seg("d"))
  );
}

#[test]
fn created_directory_record_does_not_descend_when_kernel_recursive() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(10),
  );
  assert!(drain_actions(&mut m).is_empty());
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_created());
}

#[test]
fn removed_and_modified_records_map_to_change_kinds() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed).with_name(seg("x")),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Modified).with_name(seg("y")),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Attrib).with_name(seg("z")),
    at(3),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 3);
  assert!(events[0].kind().is_removed());
  assert!(events[1].kind().is_modified());
  assert!(events[2].kind().is_modified(), "attrib maps to modified");
}

#[test]
fn record_on_unknown_watch_is_ignored() {
  let mut m = per_dir();
  let ghost = WatchId::new(NonZeroU64::new(999).unwrap());
  m.on_os_record(
    OsRecord::new(ghost, RecordKind::Modified).with_name(seg("x")),
    at(1),
  );
  assert!(drain_events(&mut m).is_empty());
}

#[test]
fn paired_move_within_window_becomes_moved() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("old"))
      .with_cookie(cookie(7)),
    at(10),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "from is stashed, not emitted"
  );
  assert_eq!(m.poll_timeout(), Some(at(10) + DEFAULT_MOVE_WINDOW));

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("new"))
      .with_cookie(cookie(7)),
    at(20),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_moved());
  assert_eq!(events[0].location(), &loc(&["new"]));
  assert_eq!(events[0].kind().moved_from(), Some(&loc(&["old"])));
  assert_eq!(m.poll_timeout(), None, "pairing consumed the pending move");
}

#[test]
fn unpaired_moved_from_becomes_removed_after_timeout() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("gone"))
      .with_cookie(cookie(9)),
    at(10),
  );
  m.handle_timeout(at(50));
  assert!(drain_events(&mut m).is_empty(), "still within window");

  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["gone"]));
}

#[test]
fn unpaired_moved_to_becomes_created() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("arrived"))
      .with_cookie(cookie(3)),
    at(10),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_created());
  assert_eq!(events[0].location(), &loc(&["arrived"]));
}

#[test]
fn moved_from_without_cookie_is_removed_immediately() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom).with_name(seg("x")),
    at(1),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_removed());
}

#[test]
fn no_space_watch_result_emits_rescan() {
  let mut m = per_dir();
  let root = m.register_root(scope(1), Interest::all());
  let _ = drain_actions(&mut m);
  m.on_watch_result(root, Err(WatchError::NoSpace));

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].scope(), scope(1));
}

#[test]
fn gone_watch_result_drops_node_and_unwatches() {
  let mut m = per_dir();
  let _root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  m.on_enumerate(
    ReqId::new(NonZeroU64::new(1).unwrap()),
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  let child_watch = drain_actions(&mut m);
  let child_id = child_watch[0].as_watch().unwrap().id();
  let _ = drain_events(&mut m);

  m.on_watch_result(child_id, Err(WatchError::Gone));
  assert!(!m.is_watched(child_id));
  let actions = drain_actions(&mut m);
  assert_eq!(actions, vec![Action::Unwatch(child_id)]);
}

#[test]
fn overflow_root_emits_scoped_rescan() {
  let mut m = per_dir();
  let _root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(Scope::Root(scope(1)), at(5));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].scope(), scope(1));
}

#[test]
fn overflow_all_rescans_every_root() {
  let mut m = per_dir();
  let _r1 = live_root(&mut m, scope(1));
  let _r2 = live_root(&mut m, scope(2));
  let _ = drain_events(&mut m);

  m.on_overflow(Scope::All, at(5));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  let scopes: Vec<ScopeId> = events.iter().map(|e| e.scope()).collect();
  assert!(scopes.contains(&scope(1)));
  assert!(scopes.contains(&scope(2)));
  assert!(events.iter().all(|e| e.kind().is_rescan()));
}

#[test]
fn overflow_subtree_rescans_that_subtree() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(Scope::Subtree(root), at(5));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].scope(), scope(1));
}

// ── Overflow re-arm: the Rescan must also reconcile the proto's own watch set ──

/// Brings a root live with one already-armed, live, empty child directory `name`,
/// returning `(root, child_watch)` and draining every bootstrap action/event.
fn root_with_live_child(m: &mut Monitor, s: ScopeId, name: &str) -> (WatchId, WatchId) {
  let root = live_root(m, s);
  let boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg(name), FileKind::Dir)]),
  );
  let child = drain_actions(m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("child watch armed");
  m.on_watch_result(child, Ok(()));
  let child_boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("child bootstrap enumerate");
  m.on_enumerate(child_boot, EnumerateResult::Ok(vec![]));
  let _ = drain_actions(m);
  let _ = drain_events(m);
  (root, child)
}

/// The overflow Rescan re-enumerates the scope and arms a directory created during
/// the gap — without emitting `Created` (the consumer re-scans off the Rescan).
#[test]
fn overflow_rearms_new_subtree_without_created() {
  let mut m = per_dir();
  let (root, _w_a) = root_with_live_child(&mut m, scope(1), "a");

  m.on_overflow(Scope::Root(scope(1)), at(5));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(
    events[0].kind().is_rescan(),
    "the consumer Rescan is emitted"
  );

  let rearm_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("overflow queues a re-arm enumerate for the root");
  // The gap created a new sibling "b" alongside the surviving "a".
  m.on_enumerate(
    rearm_req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir),
      DirEntry::new(seg("b"), FileKind::Dir),
    ]),
  );

  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("b")))),
    "the newly-appeared directory b is re-armed"
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "a re-arm emits no Created — the consumer re-scans off the Rescan"
  );
}

/// The overflow re-arm prunes a watched directory that vanished during the gap.
#[test]
fn overflow_rearm_prunes_vanished_dir() {
  let mut m = per_dir();
  let (_root, w_a) = root_with_live_child(&mut m, scope(1), "a");

  m.on_overflow(Scope::Root(scope(1)), at(5));
  let _ = drain_events(&mut m);
  let rearm_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("re-arm enumerate");
  // "a" is gone: the fresh enumerate no longer lists it.
  m.on_enumerate(rearm_req, EnumerateResult::Ok(vec![]));

  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().any(|a| a.as_unwatch() == Some(w_a)),
    "the vanished directory a is pruned"
  );
  assert!(!m.is_watched(w_a), "its coverage is dropped");
}

/// A complete re-arm REBUILDS a present child (conservative same-name replace — identity
/// is unknown after overflow), and once the fresh child arms, cascades into it, arming a
/// grandchild created in the gap.
#[test]
fn overflow_rearm_rebuilds_and_cascades_into_child() {
  let mut m = per_dir();
  let (root, w_a) = root_with_live_child(&mut m, scope(1), "a");

  m.on_overflow(Scope::Root(scope(1)), at(5));
  let _ = drain_events(&mut m);
  let root_rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("root re-arm enumerate");
  // "a" is present: the re-arm REPLACES it with a fresh watch, dropping the old one
  // (its identity can't be confirmed after overflow).
  m.on_enumerate(
    root_rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  assert!(!m.is_watched(w_a), "the old child watch is replaced");
  let w_a2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("a")))
        .map(|w| w.id())
    })
    .expect("a fresh watch is installed for a");
  assert_ne!(w_a2, w_a, "it is a new watch, not the reused original");

  // Arming the fresh child cascades the re-arm into it; "a" gained a grandchild "g".
  m.on_watch_result(w_a2, Ok(()));
  let a_rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == w_a2)
        .map(|e| e.req())
    })
    .expect("the re-arm cascades into the fresh a");
  m.on_enumerate(
    a_rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(w_a2, seg("g")))),
    "the new grandchild is armed under the rebuilt child"
  );
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_created()),
    "the cascade emits no Created"
  );
}

/// A kernel-recursive backend manages no per-directory watches, so an overflow
/// Rescan has nothing to re-arm — it emits the Change and queues no enumerate.
#[test]
fn overflow_on_kernel_recursive_does_not_rearm() {
  let mut m = kernel_recursive();
  let _root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_overflow(Scope::Root(scope(1)), at(5));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().all(|a| a.as_enumerate().is_none()),
    "a kernel-recursive backend does not re-arm per-directory"
  );
}

#[test]
fn delete_self_on_root_emits_removed() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(OsRecord::new(root, RecordKind::DeleteSelf), at(1));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_removed());
  assert!(events[0].location().is_empty());
}

#[test]
fn move_self_on_root_emits_rescan() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(OsRecord::new(root, RecordKind::MoveSelf), at(1));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
}

#[test]
fn ignored_record_tears_down_the_watch() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);

  m.on_os_record(OsRecord::new(root, RecordKind::Ignored), at(1));
  assert!(!m.is_watched(root));
  let actions = drain_actions(&mut m);
  assert!(actions.iter().any(|a| a.as_unwatch() == Some(root)));
}

#[test]
fn path_reconstruction_walks_to_root() {
  let mut m = per_dir();
  let _root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_enumerate(
    ReqId::new(NonZeroU64::new(1).unwrap()),
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  let a_id = drain_actions(&mut m)[0].as_watch().unwrap().id();
  let _ = drain_events(&mut m);
  m.on_watch_result(a_id, Ok(()));
  let enumerate_a = drain_actions(&mut m);
  let req_a = enumerate_a[0].as_enumerate().unwrap().req();

  m.on_enumerate(
    req_a,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b.txt"), FileKind::File)]),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert_eq!(
    events[0].location(),
    &loc(&["a", "b.txt"]),
    "nested path reconstructed"
  );
}

#[test]
fn duplicate_pending_created_is_deduped() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("dup")),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("dup")),
    at(2),
  );
  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    1,
    "second identical pending Created suppressed"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("dup")),
    at(3),
  );
  assert_eq!(
    drain_events(&mut m).len(),
    1,
    "after draining, a new one is allowed"
  );
}

#[test]
fn change_ids_are_unique_and_monotonic() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Modified).with_name(seg("a")),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Modified).with_name(seg("b")),
    at(2),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(events[0].id().as_u64() < events[1].id().as_u64());
}

#[test]
fn poll_timeout_reports_earliest_pending_move() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("p"))
      .with_cookie(cookie(1)),
    at(100),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("q"))
      .with_cookie(cookie(2)),
    at(50),
  );
  assert_eq!(m.poll_timeout(), Some(at(50) + DEFAULT_MOVE_WINDOW));
}

#[test]
fn set_move_window_changes_pairing_deadline() {
  let mut m = per_dir();
  m.set_move_window(Duration::from_millis(10));
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("x"))
      .with_cookie(cookie(1)),
    at(0),
  );
  assert_eq!(m.poll_timeout(), Some(at(10)));
}

#[test]
fn unregister_root_drops_subtree() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);

  m.unregister_root(scope(1));
  assert!(!m.is_watched(root));
  assert_eq!(m.scope_of(root), None);
  let actions = drain_actions(&mut m);
  assert!(actions.iter().any(|a| a.as_unwatch() == Some(root)));
}

/// The capability-switch invariant: the same record script yields the same
/// consumer-visible changes under `kernel_recursive` true and false; only the
/// watch-management actions differ.
#[test]
fn capability_switch_yields_same_changes() {
  fn run(mut m: Monitor) -> Vec<(ChangeKind, Location)> {
    let root = live_root(&mut m, scope(1));
    let _ = drain_actions(&mut m);
    let _ = drain_events(&mut m);
    m.on_os_record(
      OsRecord::new(root, RecordKind::Created).with_name(seg("f.txt")),
      at(1),
    );
    m.on_os_record(
      OsRecord::new(root, RecordKind::Modified).with_name(seg("f.txt")),
      at(2),
    );
    m.on_os_record(
      OsRecord::new(root, RecordKind::Removed).with_name(seg("f.txt")),
      at(3),
    );
    drain_events(&mut m)
      .into_iter()
      .map(|e| (e.kind().clone(), e.location().clone()))
      .collect()
  }

  assert_eq!(run(per_dir()), run(kernel_recursive()));
}

// ── Move pairing must validate scope + deadline, not cookie alone ──

/// Two disjoint roots can be on separate backend instances whose cookies collide.
/// A `MovedFrom` in one scope must never pair with a `MovedTo` in another. With
/// the composite `(scope, cookie)` key the cross-scope destination cannot even
/// *consume* the source half: the destination resolves as `Created` in its own
/// scope immediately, while the source stays pending and resolves as `Removed`
/// only on its own deadline (it is not forced to `Removed` early — its real
/// same-scope destination may still arrive within the window).
#[test]
fn cross_scope_move_with_shared_cookie_does_not_pair() {
  let mut m = per_dir();
  let root1 = live_root(&mut m, scope(1));
  let root2 = live_root(&mut m, scope(2));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root1, RecordKind::MovedFrom)
      .with_name(seg("x"))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root2, RecordKind::MovedTo)
      .with_name(seg("y"))
      .with_cookie(cookie(7)),
    at(11),
  );

  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    1,
    "the cross-scope destination cannot consume the source"
  );
  assert!(
    events[0].kind().is_created()
      && events[0].scope() == scope(2)
      && events[0].location() == &loc(&["y"]),
    "destination resolves as Created in its own scope"
  );
  assert_eq!(
    m.poll_timeout(),
    Some(at(10) + DEFAULT_MOVE_WINDOW),
    "scope 1's source half is still pending, not consumed"
  );

  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(
    events[0].kind().is_removed()
      && events[0].scope() == scope(1)
      && events[0].location() == &loc(&["x"]),
    "source resolves as Removed in its own scope on its own deadline"
  );
}

/// A reused / colliding cookie that displaces a still-pending source half must not
/// silently drop the displaced half — it resolves on its own, and the survivor
/// still pairs.
#[test]
fn duplicate_moved_from_cookie_resolves_displaced_half() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(5)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("b"))
      .with_cookie(cookie(5)),
    at(11),
  );
  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    1,
    "the displaced half is not silently dropped"
  );
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["a"]));

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("c"))
      .with_cookie(cookie(5)),
    at(12),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_moved());
  assert_eq!(events[0].kind().moved_from(), Some(&loc(&["b"])));
  assert_eq!(events[0].location(), &loc(&["c"]));
}

/// A destination arriving after the window — before any `handle_timeout` fired —
/// must resolve as `Created`, not pair into a stale `Moved`.
#[test]
fn expired_moved_to_becomes_created_not_moved() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("old"))
      .with_cookie(cookie(8)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("new"))
      .with_cookie(cookie(8)),
    at(200),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(events.iter().all(|e| !e.kind().is_moved()));
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_removed() && e.location() == &loc(&["old"]))
  );
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["new"]))
  );
}

/// The deadline is the exclusive upper bound: a destination at exactly the
/// deadline is already expired (consistent with `handle_timeout`'s `reached`).
#[test]
fn moved_to_at_deadline_does_not_pair() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("old"))
      .with_cookie(cookie(1)),
    at(0),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("new"))
      .with_cookie(cookie(1)),
    at(0) + DEFAULT_MOVE_WINDOW,
  );

  let events = drain_events(&mut m);
  assert!(events.iter().all(|e| !e.kind().is_moved()));
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["new"]))
  );
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_removed() && e.location() == &loc(&["old"]))
  );
}

// ── A renamed watched directory reparents its subtree in place ──

/// Renaming a watched directory reparents its watch subtree onto the new edge in
/// O(1): the watches survive (no Unwatch, no fresh destination watch) and their
/// descendants follow for free, reconstructing under the new path.
#[test]
fn watched_dir_rename_reparents_subtree_in_place() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("g"))
      .with_is_dir(true),
    at(2),
  );
  let w_g = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_g, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  assert!(m.is_watched(w_d) && m.is_watched(w_g));

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );

  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_moved()
      && e.location() == &loc(&["e"])
      && e.kind().moved_from() == Some(&loc(&["d"]))),
    "the directory rename itself is reported"
  );
  // Reparented in O(1), not dropped: both watches survive, no Unwatch is emitted,
  // and no fresh destination watch is installed — descendants follow for free.
  assert!(
    m.is_watched(w_d),
    "the renamed dir's watch is reparented, not dropped"
  );
  assert!(m.is_watched(w_g), "the grandchild follows the reparent");
  let actions = drain_actions(&mut m);
  assert!(actions.iter().all(|a| a.as_unwatch() != Some(w_d)));
  assert!(actions.iter().all(|a| a.as_unwatch() != Some(w_g)));
  assert!(
    actions
      .iter()
      .all(|a| a.as_watch().map(|w| w.target()) != Some(&WatchTarget::child(root, seg("e")))),
    "no fresh destination watch — the existing subtree was reparented"
  );
  // The reparented watches now reconstruct the NEW path.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created).with_name(seg("f")),
    at(20),
  );
  m.on_os_record(
    OsRecord::new(w_g, RecordKind::Created).with_name(seg("h")),
    at(21),
  );
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.location() == &loc(&["e", "f"])),
    "a child of the renamed dir resolves under e"
  );
  assert!(
    events
      .iter()
      .any(|e| e.location() == &loc(&["e", "g", "h"])),
    "a grandchild resolves under e/g"
  );
}

/// A *paired* MovedTo (a watched sibling renamed onto a freed slot) reparents the
/// source's held subtree onto the destination — covering it without a fresh watch.
#[test]
fn paired_moved_to_into_freed_slot_reparents_source() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Watch two sibling directories, "d" and "x".
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("x"))
      .with_is_dir(true),
    at(2),
  );
  let w_x = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_x, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" moves out (eager-dropped, slot freed), then "x" is renamed onto "d".
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("x"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(11),
  );
  let _ = drain_actions(&mut m); // Unwatch(w_d), Unwatch(w_x)
  let _ = drain_events(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("d"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(12),
  );

  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_moved()
      && e.location() == &loc(&["d"])
      && e.kind().moved_from() == Some(&loc(&["x"]))),
    "x -> d is reported as a move"
  );
  // The destination d is covered by reparenting x's held subtree (w_x), not a fresh
  // watch.
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .all(|a| a.as_watch().map(|w| w.target()) != Some(&WatchTarget::child(root, seg("d")))),
    "no fresh destination watch — the source subtree is reparented"
  );
  assert!(m.is_watched(w_x), "the source's watch now covers d");
  m.on_os_record(
    OsRecord::new(w_x, RecordKind::Created).with_name(seg("c")),
    at(20),
  );
  assert!(
    drain_events(&mut m)
      .iter()
      .any(|e| e.location() == &loc(&["d", "c"])),
    "a child arriving on the reparented watch resolves under d"
  );
}

/// A paired MovedTo that overwrites a DIFFERENT watched directory at the slot must
/// replace the stale watch, not idempotently keep it (which would leave the new
/// directory's coverage on a dead watch).
#[test]
fn paired_moved_to_over_watched_dir_replaces_watch() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Watch two sibling directories "a" and "b".
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let w_a = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_a, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("b"))
      .with_is_dir(true),
    at(2),
  );
  let w_b = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_b, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "b" is renamed onto "a", overwriting the watched "a".
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("b"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_actions(&mut m); // Unwatch(w_b) from the source eager-drop
  let _ = drain_events(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("a"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );

  // The stale "a" watch is dropped; the destination is then covered by reparenting
  // b's held subtree (w_b), not a fresh watch.
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().any(|a| a.as_unwatch() == Some(w_a)),
    "the stale destination watch is dropped"
  );
  assert!(
    actions
      .iter()
      .all(|a| a.as_watch().map(|w| w.target()) != Some(&WatchTarget::child(root, seg("a")))),
    "no fresh watch — b's subtree is reparented onto a"
  );
  assert!(!m.is_watched(w_a), "the stale original is gone");
  assert!(m.is_watched(w_b), "b's watch now covers a");
  m.on_os_record(
    OsRecord::new(w_b, RecordKind::Created).with_name(seg("c")),
    at(20),
  );
  assert!(
    drain_events(&mut m)
      .iter()
      .any(|e| e.location() == &loc(&["a", "c"])),
    "a child arriving on the reparented watch resolves under a"
  );
}

/// A file moved onto a watched directory's slot drops the stale directory watch
/// (the slot's object changed) and installs nothing — a file is not descended into.
#[test]
fn moved_to_file_over_watched_dir_drops_stale_watch() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // An unpaired MovedTo of a FILE lands on the watched "d" slot.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("d"))
      .with_cookie(cookie(9))
      .with_is_dir(false),
    at(10),
  );

  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().any(|a| a.as_unwatch() == Some(w_d)),
    "the stale directory watch is dropped"
  );
  assert!(
    actions.iter().all(|a| a.as_watch().is_none()),
    "no new watch is installed for a file destination"
  );
  assert!(!m.is_watched(w_d));
}

/// Contract (the descending backend reports directory-ness for directory
/// appearances — inotify via `IN_ISDIR`): a record with unknown kind
/// (`is_dir() == None`) is treated as a non-directory — emitted, but never
/// descended into and never Rescanned (which would fire on every file).
#[test]
fn unknown_kind_record_does_not_descend_or_rescan() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A `Created` with `is_dir` unset (None).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("u")),
    at(1),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_created());
  assert!(
    drain_actions(&mut m).is_empty(),
    "unknown kind neither descends (no watch) nor Rescans"
  );

  // The same for an unpaired MovedTo of unknown kind.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("v"))
      .with_cookie(cookie(7)),
    at(2),
  );
  let events = drain_events(&mut m);
  assert!(events.iter().any(|e| e.kind().is_created()));
  assert!(
    events.iter().all(|e| !e.kind().is_rescan()),
    "no Rescan for an unknown-kind destination"
  );
  assert!(
    drain_actions(&mut m).is_empty(),
    "no watch for an unknown-kind destination"
  );
}

/// After a watched directory is renamed, a child record still tagged to the old
/// watch must never reconstruct the stale path; re-arming under the new name
/// reconstructs the correct path.
#[test]
fn record_under_renamed_watched_dir_never_uses_stale_path() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );
  let _ = drain_events(&mut m);
  // The paired move reparents the "d" subtree onto "e" in place: the same watch now
  // covers the new path, with no Unwatch and no fresh destination watch.
  let actions = drain_actions(&mut m);
  assert!(actions.iter().all(|a| a.as_unwatch() != Some(w_d)));
  assert!(
    actions
      .iter()
      .all(|a| a.as_watch().map(|w| w.target()) != Some(&WatchTarget::child(root, seg("e")))),
    "no fresh destination watch — the subtree is reparented"
  );
  assert!(m.is_watched(w_d), "the reparented watch survives");

  // A record on the reparented watch reconstructs the correct NEW path, never the
  // stale one.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created).with_name(seg("f.txt")),
    at(14),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert_eq!(
    events[0].location(),
    &loc(&["e", "f.txt"]),
    "child resolves under the new path via the reparented edge"
  );
}

/// A watched directory moved out of the tree is held across the pairing window (so
/// a pair could reparent it); an unpaired source then drops its subtree and emits
/// `Removed` at timeout.
#[test]
fn watched_dir_moved_out_held_then_removed_on_timeout() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  assert!(
    m.is_watched(w_d),
    "a moved-out watched dir is HELD across the window — detached from its old slot \
     (freeing it for a replacement) but kept, so a paired MovedTo can reparent it"
  );

  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["d"]));
  assert!(
    !m.is_watched(w_d),
    "an unpaired move tears the held subtree down at timeout"
  );
  let actions = drain_actions(&mut m);
  assert!(actions.iter().any(|a| a.as_unwatch() == Some(w_d)));
}

// ── Every non-success watch result is coverage loss ──

fn watch_failure_is_coverage_loss(err: WatchError) {
  let mut m = per_dir();
  let _root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  m.on_enumerate(
    ReqId::new(NonZeroU64::new(1).unwrap()),
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  let child_id = drain_actions(&mut m)[0].as_watch().unwrap().id();
  let _ = drain_events(&mut m);

  m.on_watch_result(child_id, Err(err));
  assert!(
    !m.is_watched(child_id),
    "a refused watch is not believed-watched"
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["sub"]));
  let actions = drain_actions(&mut m);
  assert!(actions.iter().any(|a| a.as_unwatch() == Some(child_id)));
}

#[test]
fn permission_watch_failure_is_coverage_loss() {
  watch_failure_is_coverage_loss(WatchError::Permission);
}

#[test]
fn io_watch_failure_is_coverage_loss() {
  watch_failure_is_coverage_loss(WatchError::Io);
}

/// `NoSpace` now also drops the refused node (was: left registered) so a caller
/// never believes the subtree is watched.
#[test]
fn no_space_watch_result_drops_node() {
  let mut m = per_dir();
  let root = m.register_root(scope(1), Interest::all());
  let _ = drain_actions(&mut m);
  m.on_watch_result(root, Err(WatchError::NoSpace));
  assert!(
    !m.is_watched(root),
    "a refused root is dropped, not left registered"
  );
  assert!(drain_events(&mut m).iter().any(|e| e.kind().is_rescan()));
  let actions = drain_actions(&mut m);
  assert!(actions.iter().any(|a| a.as_unwatch() == Some(root)));
}

/// `NotFound` now also emits a `Rescan` (was: silent drop).
#[test]
fn not_found_watch_result_drops_and_rescans() {
  let mut m = per_dir();
  let _root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  m.on_enumerate(
    ReqId::new(NonZeroU64::new(1).unwrap()),
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  let child_id = drain_actions(&mut m)[0].as_watch().unwrap().id();
  let _ = drain_events(&mut m);

  m.on_watch_result(child_id, Err(WatchError::NotFound));
  assert!(!m.is_watched(child_id));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["sub"]));
}

// ── Descent is idempotent via the child index ──

/// A cold enumerate racing a live `Created` for one path installs a single child
/// watch and delivers the change once.
#[test]
fn racing_descent_installs_one_child_watch() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_enumerate(
    ReqId::new(NonZeroU64::new(1).unwrap()),
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(5),
  );

  let actions = drain_actions(&mut m);
  let sub_watches = actions
    .iter()
    .filter(|a| {
      a.as_watch()
        .map(|c| c.target() == &WatchTarget::child(root, seg("sub")))
        .unwrap_or(false)
    })
    .count();
  assert_eq!(sub_watches, 1, "one watch per path despite the race");

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "the Created is not double-delivered");
  assert!(events[0].kind().is_created());
  assert_eq!(events[0].location(), &loc(&["sub"]));
}

/// Dropping a child watch removes it from the child index in lockstep, so a later
/// descent for the same `(parent, name)` re-arms with a fresh watch.
#[test]
fn dropped_child_watch_can_be_reinstalled() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(1),
  );
  let w1 = drain_actions(&mut m)[0].as_watch().unwrap().id();

  m.on_os_record(OsRecord::new(w1, RecordKind::Ignored), at(2));
  assert!(!m.is_watched(w1));
  let _ = drain_actions(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(3),
  );
  let acts = drain_actions(&mut m);
  assert_eq!(acts.len(), 1, "re-descent re-arms the path");
  let w2 = acts[0].as_watch().unwrap().id();
  assert_ne!(w1, w2);
  assert!(m.is_watched(w2));
}

// ── Move dedup must distinguish distinct sources ──

/// Two renames to one destination with different sources are both delivered (the
/// later one is not coalesced away by a source-blind dedup key).
#[test]
fn two_moves_to_one_destination_keep_distinct_sources() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(1)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("dest"))
      .with_cookie(cookie(1)),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("b"))
      .with_cookie(cookie(2)),
    at(12),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("dest"))
      .with_cookie(cookie(2)),
    at(13),
  );

  let events = drain_events(&mut m);
  let moved: Vec<&Change> = events.iter().filter(|e| e.kind().is_moved()).collect();
  assert_eq!(moved.len(), 2, "the later move is not coalesced away");
  assert!(moved.iter().all(|e| e.location() == &loc(&["dest"])));
  let froms: Vec<&Location> = moved.iter().filter_map(|e| e.kind().moved_from()).collect();
  assert!(froms.contains(&&loc(&["a"])));
  assert!(froms.contains(&&loc(&["b"])));
}

/// Truly identical queued moves still coalesce (the dedup is tightened, not
/// removed).
#[test]
fn identical_pending_moves_still_coalesce() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(1)),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("b"))
      .with_cookie(cookie(1)),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(2)),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("b"))
      .with_cookie(cookie(2)),
    at(4),
  );

  let moved = drain_events(&mut m)
    .iter()
    .filter(|e| e.kind().is_moved())
    .count();
  assert_eq!(moved, 1, "truly identical moves are deduped");
}

// ── Pending moves keyed by (scope, cookie); purged on every teardown ──

/// Invariant (a)+(d): an unrelated cross-scope half sharing the cookie does not
/// consume the source, so the CORRECT same-scope destination — arriving after it,
/// still inside the window — pairs in-scope.
#[test]
fn same_scope_destination_pairs_after_unrelated_cross_scope_half() {
  let mut m = per_dir();
  let root1 = live_root(&mut m, scope(1));
  let root2 = live_root(&mut m, scope(2));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root1, RecordKind::MovedFrom)
      .with_name(seg("x"))
      .with_cookie(cookie(7)),
    at(10),
  );
  // Unrelated half in scope 2 reuses cookie 7: a fresh Created, not a consumer of
  // scope 1's still-pending source.
  m.on_os_record(
    OsRecord::new(root2, RecordKind::MovedTo)
      .with_name(seg("y"))
      .with_cookie(cookie(7)),
    at(11),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(
    events[0].kind().is_created()
      && events[0].scope() == scope(2)
      && events[0].location() == &loc(&["y"])
  );

  // Scope 1's real destination arrives later, still inside the window: pairs.
  m.on_os_record(
    OsRecord::new(root1, RecordKind::MovedTo)
      .with_name(seg("z"))
      .with_cookie(cookie(7)),
    at(12),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_moved());
  assert_eq!(events[0].scope(), scope(1));
  assert_eq!(events[0].location(), &loc(&["z"]));
  assert_eq!(events[0].kind().moved_from(), Some(&loc(&["x"])));
  assert_eq!(
    m.poll_timeout(),
    None,
    "the in-scope pair consumed the half"
  );
}

/// Invariant (d): identical cookies in two scopes are fully isolated — neither
/// MovedFrom displaces the other; each times out to `Removed` in its own scope.
#[test]
fn cross_scope_moved_from_halves_are_isolated_and_each_times_out() {
  let mut m = per_dir();
  let root1 = live_root(&mut m, scope(1));
  let root2 = live_root(&mut m, scope(2));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root1, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(5)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root2, RecordKind::MovedFrom)
      .with_name(seg("b"))
      .with_cookie(cookie(5)),
    at(10),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "both halves stashed, neither displaced"
  );
  assert_eq!(m.poll_timeout(), Some(at(10) + DEFAULT_MOVE_WINDOW));

  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2, "each unpaired source times out on its own");
  assert!(events.iter().all(|e| e.kind().is_removed()));
  assert!(
    events
      .iter()
      .any(|e| e.scope() == scope(1) && e.location() == &loc(&["a"]))
  );
  assert!(
    events
      .iter()
      .any(|e| e.scope() == scope(2) && e.location() == &loc(&["b"]))
  );
}

/// Invariant (b): `unregister_root` purges the whole scope's pending halves, so
/// the clock advancing past the deadline resurrects no `Removed`.
#[test]
fn pending_move_purged_on_unregister_root() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("gone"))
      .with_cookie(cookie(1)),
    at(10),
  );
  assert_eq!(m.poll_timeout(), Some(at(10) + DEFAULT_MOVE_WINDOW));

  m.unregister_root(scope(1));
  assert_eq!(m.poll_timeout(), None, "the scope's pending half is purged");

  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_removed()),
    "no Removed resurrected for the unregistered scope"
  );
}

/// Invariant (b): a narrow teardown of the source's watch leaves the half in place
/// (a destination could still arrive), but the liveness guard means it never emits
/// a stale `Removed` once its source is gone.
#[test]
fn dead_source_half_emits_no_removed_after_teardown() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("gone"))
      .with_cookie(cookie(1)),
    at(10),
  );
  assert_eq!(m.poll_timeout(), Some(at(10) + DEFAULT_MOVE_WINDOW));

  // `Ignored` on the root drops it (the half's `from_parent`). The half is NOT
  // purged by the narrow drop — it lingers, still timer-armed...
  m.on_os_record(OsRecord::new(root, RecordKind::Ignored), at(11));
  assert_eq!(
    m.poll_timeout(),
    Some(at(10) + DEFAULT_MOVE_WINDOW),
    "the half lingers (pairable), not purged by a narrow drop"
  );

  // ...but at timeout the liveness guard suppresses its `Removed` (source gone),
  // and the half is removed from the map (timer clears).
  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_removed()),
    "no stale Removed for the torn-down source"
  );
  assert_eq!(
    m.poll_timeout(),
    None,
    "the dead half is gone after timeout"
  );
}

/// The seam Codex pinned: a watched directory moved out must free its `(parent,
/// name)` slot at once, so a *replacement* arriving at the same path during the
/// pending window installs its own watch instead of being silently skipped by the
/// idempotent descent (the stale entry would otherwise still occupy the slot).
#[test]
fn watched_dir_moved_out_then_replaced_installs_new_watch() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Watch "d" (live).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" is moved out (a paired rename is in flight).
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  assert!(
    m.is_watched(w_d),
    "the moved-out dir's watch is held (detached from its old slot) across the window"
  );
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Before the cookie resolves, a DIFFERENT directory is created at the same path.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(11),
  );
  let w_d2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("a watch is installed for the replacement directory");
  assert_ne!(w_d2, w_d, "the replacement gets its own fresh watch");
  m.on_watch_result(w_d2, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The replacement is genuinely covered: a child record resolves to the correct
  // path, proving recursive coverage was not lost.
  m.on_os_record(
    OsRecord::new(w_d2, RecordKind::Created).with_name(seg("child")),
    at(12),
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["d", "child"])),
    "a record under the replacement resolves to d/child, not lost"
  );
}

/// The original's rename pairing must not disturb a replacement installed at the
/// freed slot during the window.
#[test]
fn watched_dir_replacement_survives_pairing() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(11),
  );
  let w_d2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("replacement watched");
  m.on_watch_result(w_d2, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The original "d" finishes its rename to "e" within the window.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let _ = drain_events(&mut m);

  assert!(
    m.is_watched(w_d2),
    "the replacement watch survives the original's pairing"
  );
  assert!(
    m.is_watched(w_d),
    "the original is reparented onto e (not dropped), disjoint from the replacement"
  );
  // The replacement still covers d; the reparented original now covers e — the two
  // are disjoint and neither clobbers the other's slot.
  m.on_os_record(
    OsRecord::new(w_d2, RecordKind::Created).with_name(seg("r")),
    at(20),
  );
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created).with_name(seg("o")),
    at(21),
  );
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.location() == &loc(&["d", "r"])),
    "the replacement still covers d"
  );
  assert!(
    events.iter().any(|e| e.location() == &loc(&["e", "o"])),
    "the reparented original now covers e"
  );
}

/// The original's timeout (unpaired) must not disturb a replacement installed at
/// the freed slot.
#[test]
fn watched_dir_replacement_survives_timeout() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(11),
  );
  let w_d2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("replacement watched");
  m.on_watch_result(w_d2, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The original never paired; its window elapses. It resolves to a Removed for
  // the original object (an interim imprecision the §6 identity model refines),
  // but the replacement's coverage is untouched.
  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let _ = drain_events(&mut m);
  assert!(
    m.is_watched(w_d2),
    "the replacement watch survives the original's timeout"
  );
}

/// A move-half whose source lives inside a directory that is itself renamed follows
/// the reparent: its unpaired timeout emits a `Removed` at the CURRENT path (under
/// the new parent), never the stale pre-rename path.
#[test]
fn inner_move_half_follows_reparented_source() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A child inside "d" starts a rename: its source half is recorded under w_d.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::MovedFrom)
      .with_name(seg("f"))
      .with_cookie(cookie(2)),
    at(10),
  );
  assert_eq!(m.poll_timeout(), Some(at(10) + DEFAULT_MOVE_WINDOW));

  // "d" itself is renamed: the paired move drops w_d's subtree, purging the
  // inner half whose parent was w_d.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  // The inner half lingers, still timer-armed — its source parent w_d was reparented
  // (not dropped), so the half stays live.
  assert_eq!(
    m.poll_timeout(),
    Some(at(10) + DEFAULT_MOVE_WINDOW),
    "the inner half lingers after the parent's reparent"
  );
  let _ = drain_events(&mut m); // the d→e Moved

  // At timeout the unpaired inner half resolves to a Removed at its CURRENT path: the
  // source parent w_d followed the reparent to e, so the child is e/f, never d/f.
  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_removed());
  assert_eq!(
    events[0].location(),
    &loc(&["e", "f"]),
    "the inner half's path follows its reparented parent (e/f, never the stale d/f)"
  );
}

/// Invariant (c): a cookie reused after its half timed out cannot synthesize a
/// stale `Moved` — the prior half is gone, so the destination is a fresh Created.
#[test]
fn reused_cookie_after_timeout_does_not_resolve_stale_half() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(5)),
    at(10),
  );
  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_removed() && events[0].location() == &loc(&["a"]));

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("b"))
      .with_cookie(cookie(5)),
    at(300),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(
    events[0].kind().is_created(),
    "no stale Moved from the expired half"
  );
  assert_eq!(events[0].location(), &loc(&["b"]));
}

/// Invariant (c): a cookie reused after its half was purged by a teardown pairs
/// fresh and never resurfaces the purged source.
#[test]
fn reused_cookie_after_teardown_pairs_fresh() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A source half keyed (scope 1, cookie 5) inside the watched dir "d".
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::MovedFrom)
      .with_name(seg("inner"))
      .with_cookie(cookie(5)),
    at(10),
  );
  // Tear "d" down. The (scope 1, cookie 5) half lingers (narrow drop ≠ purge), but
  // its source w_d is gone, so it is dead — the guard will discard it on reuse.
  m.on_os_record(OsRecord::new(w_d, RecordKind::Ignored), at(11));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Reusing cookie 5 at the root pairs fresh, not against the purged half.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("x"))
      .with_cookie(cookie(5)),
    at(12),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("y"))
      .with_cookie(cookie(5)),
    at(13),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_moved());
  assert_eq!(events[0].location(), &loc(&["y"]));
  assert_eq!(events[0].kind().moved_from(), Some(&loc(&["x"])));
  assert!(
    events
      .iter()
      .all(|e| e.kind().moved_from() != Some(&loc(&["d", "inner"]))),
    "the purged half never resurfaces"
  );
}

// ── Centralized slot reconciliation: the R6 coverage cases ──

/// Remove-then-create at the same slot: the `Removed` must drop the old watch so a
/// following `Created` is NOT mistaken for a duplicate and is freshly watched.
#[test]
fn removed_then_created_at_same_slot_rewatches_replacement() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Watch dir "d".
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" is removed (reconcile Gone → drops the watch), then a new dir "d" is created.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(2),
  );
  assert!(!m.is_watched(w_d), "Removed drops the old slot watch");
  let _ = drain_actions(&mut m); // Unwatch(w_d)
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(3),
  );
  let w_d2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the replacement directory is freshly watched, not skipped as a duplicate");
  assert_ne!(w_d2, w_d, "a new watch, not the dropped original");
  m.on_watch_result(w_d2, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The replacement is genuinely covered.
  m.on_os_record(
    OsRecord::new(w_d2, RecordKind::Created).with_name(seg("child")),
    at(4),
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["d", "child"])),
    "a record under the replacement resolves to d/child"
  );
}

/// An `Ok` enumerate entry of unknown kind is emitted but never watched (the
/// descending-backend `is_dir` contract), while a `Dir` entry in the same result is.
#[test]
fn enumerate_unknown_kind_entry_is_not_watched() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_enumerate(
    ReqId::new(NonZeroU64::new(1).unwrap()),
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("known"), FileKind::Dir),
      DirEntry::new(seg("mystery"), FileKind::Unknown),
    ]),
  );

  // Both are reported as Created.
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(events.iter().all(|e| e.kind().is_created()));

  // Only the known directory is watched; the unknown-kind entry is not.
  let actions = drain_actions(&mut m);
  assert_eq!(actions.len(), 1, "exactly one watch — for the known dir");
  assert_eq!(
    actions[0].as_watch().unwrap().target(),
    &WatchTarget::child(root, seg("known"))
  );
}

/// A child move-half pending under a parent dir survives a NARROW teardown of the
/// parent — it is not purged, so it is still consumed when its destination arrives.
/// With the source parent gone, though, the source path can no longer be described,
/// so the destination resolves as a `Created` (never a `Moved` off a dead parent),
/// and the consumed half leaves no stale `Removed`.
#[test]
fn child_move_half_survives_parent_teardown_and_resolves_created() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Watch dir "p".
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("p"))
      .with_is_dir(true),
    at(1),
  );
  let w_p = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_p, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A child "f" inside "p" starts a rename (source half under w_p).
  m.on_os_record(
    OsRecord::new(w_p, RecordKind::MovedFrom)
      .with_name(seg("f"))
      .with_cookie(cookie(7)),
    at(10),
  );
  // "p" is torn down (narrow drop) BEFORE the destination arrives. The half lingers
  // (not purged) and stays pairable.
  m.on_os_record(OsRecord::new(w_p, RecordKind::Ignored), at(11));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The destination arrives at the still-watched root with the same (scope, cookie):
  // the half is consumed, but its source parent is gone, so it resolves as a Created.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("g"))
      .with_cookie(cookie(7)),
    at(12),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(
    events[0].kind().is_created() && events[0].location() == &loc(&["g"]),
    "with its source parent torn down, the destination is a Created, not a Moved \
     from a dead parent"
  );
  // The half was consumed by the pairing, so nothing lingers into a stale Removed.
  m.handle_timeout(at(12) + DEFAULT_MOVE_WINDOW);
  assert!(
    drain_events(&mut m).is_empty(),
    "the consumed half leaves no stale Removed"
  );
}

// ── Adversarial move/re-arm regressions ──

/// A held (watched-directory) source whose `from_parent` is torn down before the
/// paired `MovedTo` arrives must not reparent a dropped watch: the destination
/// resolves as a `Created` with fresh coverage, and nothing is tied to the dead
/// subtree.
#[test]
fn held_dir_source_with_torn_down_parent_resolves_created() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // root → p (watched) → d (watched, inside p).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("p"))
      .with_is_dir(true),
    at(1),
  );
  let w_p = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_p, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_p, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(2),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" (a watched dir) starts moving out of p: its subtree is held.
  m.on_os_record(
    OsRecord::new(w_p, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(8))
      .with_is_dir(true),
    at(10),
  );
  // "p" is torn down (narrow) BEFORE the destination — this drops the held w_d too.
  m.on_os_record(OsRecord::new(w_p, RecordKind::Ignored), at(11));
  assert!(
    !m.is_watched(w_d),
    "the held source went down with its parent"
  );
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The destination arrives at the surviving root: no reparent of the dropped w_d —
  // a fresh Created with a fresh watch, and nothing tied to the dead subtree.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("g"))
      .with_cookie(cookie(8))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(
    events[0].kind().is_created() && events[0].location() == &loc(&["g"]),
    "a fresh Created, not a Moved off a dead parent"
  );
  let actions = drain_actions(&mut m);
  let w_g = actions
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("g")))
        .map(|w| w.id())
    })
    .expect("g re-armed with a fresh watch");
  assert_ne!(w_g, w_d, "not the dropped original");
  // The fresh coverage is real: a child under g resolves correctly.
  m.on_watch_result(w_g, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_g, RecordKind::Created).with_name(seg("c")),
    at(13),
  );
  assert!(
    drain_events(&mut m)
      .iter()
      .any(|e| e.location() == &loc(&["g", "c"])),
    "g's coverage is live"
  );
}

/// An adversarial move pair that would reparent a directory under its own subtree is
/// rejected: the held source is dropped, no watch is orphaned under the (now-dead)
/// destination parent, and path reconstruction does not loop.
#[test]
fn cyclic_reparent_pair_is_rejected_without_corruption() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // root → d (watched) → sub (watched, inside d).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(2),
  );
  let w_sub = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_sub, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" moves (source half under root, held = w_d)…
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(9))
      .with_is_dir(true),
    at(10),
  );
  // …to INSIDE its own subtree (destination parent = w_sub, a descendant of w_d).
  m.on_os_record(
    OsRecord::new(w_sub, RecordKind::MovedTo)
      .with_name(seg("d"))
      .with_cookie(cookie(9))
      .with_is_dir(true),
    at(11),
  );

  // The cyclic reparent is rejected: the held source subtree is dropped, and no watch
  // is installed under the dead destination parent.
  assert!(!m.is_watched(w_d), "the held source is torn down");
  assert!(!m.is_watched(w_sub), "its subtree went with it");
  // A rejected cyclic pair escalates with a Rescan — never a bogus Moved into a path
  // the Monitor no longer covers.
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_rescan()) && events.iter().all(|e| !e.kind().is_moved()),
    "cyclic pair emits a Rescan, not a Moved"
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .all(|a| a.as_watch().map(|w| w.target()) != Some(&WatchTarget::child(w_sub, seg("d")))),
    "no watch orphaned under the dead destination parent"
  );
  // The machine is still usable — a later record does not loop or panic.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("e")),
    at(12),
  );
  assert!(
    drain_events(&mut m)
      .iter()
      .any(|e| e.location() == &loc(&["e"]))
  );
}

/// A failed (or partial) overflow re-arm enumerate must not drop the repair
/// obligation: the re-arm is re-issued so coverage is eventually reconciled, and a
/// failed read never prunes existing coverage.
#[test]
fn overflow_rearm_reissues_on_failed_enumerate() {
  let mut m = per_dir();
  let (root, w_a) = root_with_live_child(&mut m, scope(1), "a");

  m.on_overflow(Scope::Root(scope(1)), at(5));
  let _ = drain_events(&mut m);
  let rearm_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("re-arm enumerate");

  // The re-arm read fails: the obligation is re-issued (not dropped), and existing
  // coverage is not pruned off the failed read.
  m.on_enumerate(
    rearm_req,
    EnumerateResult::Failed(IoClass::OutOfDescriptors),
  );
  assert!(
    m.is_watched(w_a),
    "a failed read does not prune existing coverage"
  );
  // The re-arm is re-issued for the root (routed by target dir, since a failed read
  // now also cascades a re-arm into the known child "a"); its retry succeeds and now
  // sees a gap-created dir "b", which is armed.
  let root_retry = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the root re-arm is re-issued after a failed read");
  m.on_enumerate(
    root_retry,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir),
      DirEntry::new(seg("b"), FileKind::Dir),
    ]),
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("b")))),
    "the retry re-arms the gap-created directory"
  );
}

/// An adversarial pair moving a directory onto its own ancestor's slot (`root/a/d` →
/// `root/a`) must not leave `child_index` pointing at a removed node: the reparent
/// aborts (dropping the stale ancestor takes the held child with it), so the
/// destination is reconciled with a FRESH watch, not a dead one.
#[test]
fn stale_ancestor_reparent_installs_fresh_coverage() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // root → a (watched) → d (watched, inside a).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let w_a = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_a, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_a, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(2),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" moves from a/d onto "a" itself (its own parent's slot).
  m.on_os_record(
    OsRecord::new(w_a, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(3))
      .with_is_dir(true),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("a"))
      .with_cookie(cookie(3))
      .with_is_dir(true),
    at(11),
  );

  // Both the replaced ancestor and the held source are torn down; a FRESH watch covers
  // root/a — proving `child_index` was not left pointing at the removed held node
  // (which would block re-arming the slot).
  assert!(!m.is_watched(w_a), "the replaced ancestor is dropped");
  assert!(!m.is_watched(w_d), "the held source went with it");
  let _ = drain_events(&mut m);
  let actions = drain_actions(&mut m);
  let w_a2 = actions
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("a")))
        .map(|w| w.id())
    })
    .expect("root/a re-armed with a fresh watch");
  assert_ne!(w_a2, w_a);
  assert_ne!(w_a2, w_d, "not the removed held node");
  // The fresh coverage is real.
  m.on_watch_result(w_a2, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_a2, RecordKind::Created).with_name(seg("c")),
    at(12),
  );
  assert!(
    drain_events(&mut m)
      .iter()
      .any(|e| e.location() == &loc(&["a", "c"])),
    "root/a coverage is live"
  );
}

/// A re-arm enumerate that permanently fails must not spin a fixpoint-draining driver:
/// retries are bounded, then the Monitor escalates to a Rescan and stops re-issuing.
#[test]
fn overflow_rearm_quiesces_after_persistent_failure() {
  let mut m = per_dir();
  let _ = root_with_live_child(&mut m, scope(1), "a");
  m.on_overflow(Scope::Root(scope(1)), at(5));
  let _ = drain_events(&mut m);

  let mut req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()));
  let mut rounds = 0usize;
  while let Some(r) = req {
    rounds += 1;
    assert!(rounds <= 10, "the re-arm must quiesce, not spin");
    m.on_enumerate(r, EnumerateResult::Failed(IoClass::Permission));
    let _ = drain_events(&mut m);
    req = drain_actions(&mut m)
      .iter()
      .find_map(|a| a.as_enumerate().map(|e| e.req()));
  }
  // A failed re-arm also cascades a bounded re-arm into the known child "a", so the
  // exact count varies with the tree; the invariant is quiescence — every
  // per-directory retry is bounded and coalesced, so the loop terminates (here: the
  // root plus its one child).
  assert!(
    rounds <= 2 * (1 + REARM_MAX_RETRIES as usize),
    "bounded per directory, then quiescent — got {rounds}"
  );
}

/// An overflow re-arm that races ahead of a pending move — installing a temporary
/// destination watch — must not lose its re-arm obligation when the paired MovedTo
/// reparents the held source onto that slot: the obligation transfers to the source.
#[test]
fn overflow_rearm_obligation_transfers_across_reparent() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // root → d (watched, live).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let d_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("d bootstrap enumerate");
  m.on_enumerate(d_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" starts moving to "e" (its subtree is held).
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(4))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // An overflow re-arm races ahead, enumerates root, sees the arriving "e", and
  // installs a temporary (pending) destination watch marked for re-arm.
  m.on_overflow(Scope::Root(scope(1)), at(11));
  let _ = drain_events(&mut m);
  let rearm_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("overflow re-arm enumerate");
  m.on_enumerate(
    rearm_req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("e"), FileKind::Dir)]),
  );
  let w_e_temp = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("e")))
        .map(|w| w.id())
    })
    .expect("temp destination watch installed by the re-arm");

  // Now the move pairs: the held source reparents onto "e", dropping the temp watch.
  // Its pending re-arm obligation transfers to the reparented source.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(4))
      .with_is_dir(true),
    at(12),
  );
  assert!(
    !m.is_watched(w_e_temp),
    "the temp destination watch is replaced by the reparent"
  );
  assert!(m.is_watched(w_d), "the held source now covers e");
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().any(|a| a.as_enumerate().is_some()),
    "the re-arm obligation transferred: a re-arm enumerate is queued for the reparented source"
  );
}

/// A cyclic/descendant `MovedTo` arriving PAST the move deadline (the late-destination
/// branch) must not reconcile under a destination parent removed by resolving the
/// stranded source: it escalates with a `Rescan` and orphans no watch.
#[test]
fn late_cyclic_moved_to_does_not_reconcile_under_dead_parent() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // root → d (watched) → sub (watched, inside d).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(2),
  );
  let w_sub = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_sub, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" moves (held); its destination arrives INSIDE its own subtree, but LATE (past
  // the deadline → the late-destination branch).
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(5))
      .with_is_dir(true),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(w_sub, RecordKind::MovedTo)
      .with_name(seg("d"))
      .with_cookie(cookie(5))
      .with_is_dir(true),
    at(200),
  );

  // The stranded source is torn down (taking w_sub with it); no watch is installed
  // under the dead destination parent, and the arrival escalates with a Rescan.
  assert!(!m.is_watched(w_d));
  assert!(!m.is_watched(w_sub));
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "a late cyclic destination escalates with a Rescan"
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .all(|a| a.as_watch().map(|w| w.target()) != Some(&WatchTarget::child(w_sub, seg("d")))),
    "no watch orphaned under the dead destination parent"
  );
}

/// A re-arm obligation transferred to a NOT-YET-LIVE reparented source must survive
/// until that source arms: `start_rearm` is a no-op on a pending watch, so the
/// obligation is held in `rearming` and the source's post-arm enumerate is a re-arm
/// (Created-suppressed), not a normal discovery.
#[test]
fn inherited_rearm_survives_a_pending_reparented_source() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // "d" is created and its watch is queued but NOT yet acknowledged — it is pending.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  let _ = drain_events(&mut m);
  assert!(m.is_watched(w_d), "pending, in the tree but not live");

  // The pending "d" starts moving to "e".
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(6))
      .with_is_dir(true),
    at(2),
  );
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // An overflow re-arm races ahead and installs a temp (pending) watch at "e".
  m.on_overflow(Scope::Root(scope(1)), at(3));
  let _ = drain_events(&mut m);
  let rearm_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("overflow re-arm enumerate");
  m.on_enumerate(
    rearm_req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("e"), FileKind::Dir)]),
  );
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The move pairs: the pending "d" reparents onto "e", inheriting the temp watch's
  // re-arm obligation — but since "d" is not live, the obligation is held until it arms.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(6))
      .with_is_dir(true),
    at(4),
  );
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Now "d" arms: its post-arm enumerate must be a RE-ARM (Created-suppressed), proving
  // the obligation survived the pending window.
  m.on_watch_result(w_d, Ok(()));
  let post_arm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("armed source enumerates");
  m.on_enumerate(
    post_arm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("x"), FileKind::Dir)]),
  );
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_created()),
    "the inherited re-arm suppresses Created — the obligation survived the pending source"
  );
}

/// A re-arm whose parent read returns a `Partial` OMITTING a still-live child must
/// still re-arm that child (its subtree may have gained a gap-created descendant):
/// cascade into every known child, not only the listed ones.
#[test]
fn partial_rearm_rearms_a_child_omitted_from_the_listing() {
  let mut m = per_dir();
  let (_root, w_a) = root_with_live_child(&mut m, scope(1), "a");

  m.on_overflow(Scope::Root(scope(1)), at(5));
  let _ = drain_events(&mut m);
  let rearm_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root re-arm enumerate");
  // The root re-arm returns a Partial that OMITS the still-live child "a".
  m.on_enumerate(rearm_req, EnumerateResult::Partial(vec![]));
  assert!(
    m.is_watched(w_a),
    "a partial read does not prune the omitted child"
  );
  assert!(
    m.is_rearm_enumerating(w_a),
    "the omitted-but-known child is re-armed via the cascade"
  );
}

/// A cold (discovery) enumerate returning `Partial` must still install the visible
/// directories' watches and schedule a retry — not merely emit a `Rescan` and leave a
/// live-but-blind subtree.
#[test]
fn cold_partial_enumerate_arms_visible_and_retries() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root cold enumerate");
  m.on_enumerate(
    boot,
    EnumerateResult::Partial(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  // The visible "a" is armed despite the incomplete read, a Rescan refreshes the
  // consumer's view, and a bounded retry is scheduled for the root.
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("a")))),
    "the visible directory is armed"
  );
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "an incomplete cold read emits a Rescan"
  );
  assert!(
    m.is_rearm_enumerating(root),
    "root is re-armed to complete the read"
  );
}

/// A cold enumerate that repeatedly `Failed`s retries a bounded number of times, then
/// lets a `Rescan` stand — the freshly-armed directory is not left spinning.
#[test]
fn cold_failed_enumerate_retries_bounded_then_rescans() {
  let mut m = per_dir();
  let _root = live_root(&mut m, scope(1));
  let mut req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()));
  let mut rounds = 0usize;
  let mut saw_rescan = false;
  while let Some(r) = req {
    rounds += 1;
    assert!(rounds <= 10, "must quiesce, not spin");
    m.on_enumerate(r, EnumerateResult::Failed(IoClass::Permission));
    if drain_events(&mut m).iter().any(|e| e.kind().is_rescan()) {
      saw_rescan = true;
    }
    req = drain_actions(&mut m)
      .iter()
      .find_map(|a| a.as_enumerate().map(|e| e.req()));
  }
  assert_eq!(
    rounds,
    1 + REARM_MAX_RETRIES as usize,
    "the initial cold read plus the bounded retries, then it stops"
  );
  assert!(
    saw_rescan,
    "an unreadable cold directory escalates with a Rescan"
  );
}

/// A persistently FAILED re-arm of a directory must still re-arm its known children —
/// a gap-created descendant under an existing child would otherwise stay unwatched
/// (the failed parent read never re-reaches its children on its own).
#[test]
fn failed_rearm_still_rearms_known_children() {
  let mut m = per_dir();
  let (root, w_a) = root_with_live_child(&mut m, scope(1), "a");
  m.on_overflow(Scope::Root(scope(1)), at(5));
  let _ = drain_events(&mut m);
  let root_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("root re-arm");

  // The root read Fails — yet the known child "a" is still re-armed.
  m.on_enumerate(root_req, EnumerateResult::Failed(IoClass::Permission));
  assert!(
    m.is_watched(w_a),
    "the child survives the parent's failed read"
  );
  let a_rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_a).map(|e| e.req()))
    .expect("the known child is re-armed on a failed parent read");

  // Driving the child's re-arm arms a gap-created grandchild "g" under "a", no Created.
  m.on_enumerate(
    a_rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(w_a, seg("g")))),
    "the grandchild under the known child is armed"
  );
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_created()),
    "the re-arm suppresses Created"
  );
}

/// A Partial re-arm that positively reports a watched directory NAME as a non-directory
/// (the directory became a file during the overflow gap) drops the stale directory
/// watch, so it cannot keep attributing events or block a later directory at that name.
#[test]
fn partial_rearm_drops_a_dir_replaced_by_a_file() {
  let mut m = per_dir();
  let (root, w_a) = root_with_live_child(&mut m, scope(1), "a");
  m.on_overflow(Scope::Root(scope(1)), at(5));
  let _ = drain_events(&mut m);
  let root_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("root re-arm");

  // The Partial listing reports "a" — now as a FILE, not the previously-watched dir.
  m.on_enumerate(
    root_req,
    EnumerateResult::Partial(vec![DirEntry::new(seg("a"), FileKind::File)]),
  );
  assert!(
    !m.is_watched(w_a),
    "the stale directory watch is dropped when a becomes a file"
  );
}

/// A parent re-arm that Fails must still re-arm a child that is mid-move — detached
/// from `child_index` and held in `pending_moves` for its pairing window — since a
/// gap-created descendant under the held subtree would otherwise stay unwatched.
#[test]
fn failed_rearm_reaches_detached_held_move_source() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // root → d (watched, live).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let d_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("d bootstrap enumerate");
  m.on_enumerate(d_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" starts moving — detached from child_index, its subtree held in pending_moves.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // An overflow re-arm of root FAILS — yet the detached held "d" is still re-armed.
  m.on_overflow(Scope::Root(scope(1)), at(11));
  let _ = drain_events(&mut m);
  let root_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("root re-arm");
  m.on_enumerate(root_req, EnumerateResult::Failed(IoClass::Permission));
  let d_rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("the detached held move-source is re-armed on a failed parent read");

  // Driving the held source's re-arm arms a gap-created grandchild "g" under it.
  m.on_enumerate(
    d_rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(w_d, seg("g")))),
    "the grandchild under the held move-source is armed"
  );
}

/// A complete overflow re-arm issues a FRESH watch for a directory whose name is
/// unchanged but whose object was replaced (deleted + recreated) during the gap: the
/// Monitor cannot confirm identity, so it rebuilds rather than reuse a possibly-dead
/// watch that would keep attributing events for the old object.
#[test]
fn overflow_rearm_replaces_same_name_directory() {
  let mut m = per_dir();
  let (root, w_a) = root_with_live_child(&mut m, scope(1), "a");

  m.on_overflow(Scope::Root(scope(1)), at(5));
  let _ = drain_events(&mut m);
  let root_rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("root re-arm");

  // The listing still shows "a" (same name) — but overflow hid a delete+recreate.
  m.on_enumerate(
    root_rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );

  // The stale watch is dropped and a FRESH one issued for the replacement.
  assert!(!m.is_watched(w_a), "the stale same-name watch is dropped");
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().any(|a| a.as_unwatch() == Some(w_a)),
    "the old watch is unwatched"
  );
  let w_a2 = actions
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("a")))
        .map(|w| w.id())
    })
    .expect("a fresh watch is issued for the replacement");
  assert_ne!(w_a2, w_a, "not the reused stale watch");
}
