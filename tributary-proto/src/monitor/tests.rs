use super::*;
use crate::{
  action::WatchTarget,
  path::Segment,
  record::{DirEntry, FileKind, IoClass},
  scope::SubtreeScope,
};
use core::num::NonZeroU64;
use std::{vec, vec::Vec};

fn scope(n: u64) -> ScopeId {
  ScopeId::new(NonZeroU64::new(n).unwrap())
}

fn cookie(n: u64) -> MoveCookie {
  MoveCookie::new(NonZeroU64::new(n).unwrap())
}

fn ident(n: u64) -> Identity {
  Identity::new(NonZeroU64::new(n).unwrap())
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

  m.on_overflow(Scope::subtree_of(root), at(5));
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
fn delete_self_on_root_emits_removed_and_invalidates() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(OsRecord::new(root, RecordKind::DeleteSelf), at(1));
  let events = drain_events(&mut m);
  // The deletion delivers, and — since the scope's coverage just ended — the
  // no-silent-loss Rescan follows it (dominating by epoch).
  assert_eq!(events.len(), 2);
  assert!(events[0].kind().is_removed());
  assert!(events[0].location().is_empty());
  assert!(events[1].kind().is_rescan());
  assert!(events[1].epoch() > events[0].epoch());
  assert!(!m.is_watched(root), "the dead root's tree is invalidated");
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

/// Invariant (b): a NARROW teardown of the source's watch (a non-root — a root
/// teardown is a whole-scope invalidation that purges the halves) leaves the half in
/// place (a destination could still arrive at a surviving slot), but the liveness
/// guard means it never emits a stale `Removed` once its source is gone.
#[test]
fn dead_source_half_emits_no_removed_after_teardown() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // root → p (watched, live): the half's source parent, torn down narrowly below.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("p"))
      .with_is_dir(true),
    at(1),
  );
  let w_p = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_p, Ok(()));
  let p_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_p).map(|e| e.req()))
    .expect("p bootstrap");
  m.on_enumerate(p_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(w_p, RecordKind::MovedFrom)
      .with_name(seg("gone"))
      .with_cookie(cookie(1)),
    at(10),
  );
  assert_eq!(m.poll_timeout(), Some(at(10) + DEFAULT_MOVE_WINDOW));

  // `Ignored` on p drops it (the half's `from_parent`). The half is NOT purged by
  // the narrow drop — it lingers, still timer-armed...
  m.on_os_record(OsRecord::new(w_p, RecordKind::Ignored), at(11));
  let _ = drain_events(&mut m);
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

/// A watched directory moved out must free its `(parent, name)` slot at once, so a
/// *replacement* arriving at the same path during the pending window installs its own
/// watch instead of being silently skipped by the idempotent descent (the stale entry
/// would otherwise still occupy the slot).
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
  // the original object (an imprecision a future identity-aware resolution could
  // refine), but the replacement's coverage is untouched.
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

// ── Centralized slot reconciliation: coverage cases ──

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

// ── Move / re-arm edge cases ──

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
  // a fresh Created with a fresh watch, nothing tied to the dead subtree, and a
  // destination Rescan (the dead source's interval was covered by no watch).
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("g"))
      .with_cookie(cookie(8))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(
    events[0].kind().is_created() && events[0].location() == &loc(&["g"]),
    "a fresh Created, not a Moved off a dead parent"
  );
  assert!(
    events[1].kind().is_rescan() && events[1].location() == &loc(&["g"]),
    "the failed carry-over re-scans the destination"
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

/// A move pair that would reparent a directory under its own subtree is rejected: the
/// held source is dropped, no watch is orphaned under the (now-dead) destination
/// parent, and path reconstruction does not loop.
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
  // the Monitor no longer covers — and the Rescan points at the scope ROOT: the
  // destination path died with the held subtree, so a location reconstructed through
  // it would be the stale pre-move path.
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_rescan()) && events.iter().all(|e| !e.kind().is_moved()),
    "cyclic pair emits a Rescan, not a Moved"
  );
  assert!(
    events
      .iter()
      .filter(|e| e.kind().is_rescan())
      .all(|e| e.location().is_empty()),
    "the escalation Rescan targets the scope root, not a stale held path"
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

/// A pair moving a directory onto its own ancestor's slot (`root/a/d` →
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
  assert!(
    events
      .iter()
      .filter(|e| e.kind().is_rescan())
      .all(|e| e.location().is_empty()),
    "the escalation Rescan targets the scope root, not a stale held path"
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

/// Every change carries its scope's reconciliation epoch, and a `Rescan` bumps the epoch
/// so it — and every later change — strictly dominates what the consumer already holds.
/// This is the no-silent-loss floor: a mutation in a re-arm's unwatch→rewatch window
/// rides a generation the `Rescan` dominates, with no ordering between the queues.
#[test]
fn changes_carry_epoch_and_rescan_bumps_it() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // A pre-overflow change carries the scope's base generation.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(false),
    at(1),
  );
  let base = drain_events(&mut m)
    .into_iter()
    .find(|e| e.kind().is_created())
    .expect("created a")
    .epoch();

  // An overflow `Rescan` bumps the generation strictly past that change.
  m.on_overflow(Scope::Root(scope(1)), at(2));
  let rescan = drain_events(&mut m)
    .into_iter()
    .find(|e| e.kind().is_rescan())
    .expect("overflow rescan")
    .epoch();
  assert!(
    rescan > base,
    "the Rescan dominates the pre-overflow change"
  );

  // A change after the overflow rides a generation at least the Rescan's, so the Rescan
  // the consumer acts on is never dominated by an unseen later mutation.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("b"))
      .with_is_dir(false),
    at(3),
  );
  let after = drain_events(&mut m)
    .into_iter()
    .find(|e| e.kind().is_created())
    .expect("created b")
    .epoch();
  assert!(
    after >= rescan,
    "a post-overflow change is not dominated below the Rescan"
  );

  // The generation is per-scope: a second scope is unaffected by scope 1's bump.
  let other = live_root_idle(&mut m, scope(2));
  m.on_os_record(
    OsRecord::new(other, RecordKind::Created)
      .with_name(seg("c"))
      .with_is_dir(false),
    at(4),
  );
  let other_epoch = drain_events(&mut m)
    .into_iter()
    .find(|e| e.kind().is_created())
    .expect("created c")
    .epoch();
  assert_eq!(
    other_epoch,
    Epoch::START,
    "a fresh scope starts at the base generation"
  );
}

/// Sets up a root with one live child directory "a" carrying object identity `id`.
fn root_with_identified_child(m: &mut Monitor, id: Identity) -> (WatchId, WatchId) {
  let root = live_root_idle(m, scope(1));
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true)
      .with_node(id),
    at(1),
  );
  let w_a = drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("a")))
        .map(|w| w.id())
    })
    .expect("watch for a");
  m.on_watch_result(w_a, Ok(()));
  let a_boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_a).map(|e| e.req()))
    .expect("a bootstrap enumerate");
  m.on_enumerate(a_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(m);
  let _ = drain_events(m);
  (root, w_a)
}

/// A complete re-arm KEEPS a watch whose object identity is confirmed unchanged: no
/// Unwatch/Watch churn, and the survivor is re-armed downward to catch new grandchildren.
#[test]
fn overflow_rearm_keeps_a_watch_whose_identity_survives() {
  let mut m = per_dir();
  let (root, w_a) = root_with_identified_child(&mut m, ident(100));

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

  // The re-arm reports "a" with the SAME identity — the object survived the overflow.
  m.on_enumerate(
    root_req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(100)),
    ]),
  );
  let actions = drain_actions(&mut m);
  assert!(m.is_watched(w_a), "the watch survives — same identity");
  assert!(
    !actions.iter().any(|a| a.as_unwatch() == Some(w_a)),
    "the surviving watch is kept, not torn down and rebuilt"
  );
  assert!(
    m.is_rearm_enumerating(w_a),
    "the survivor is re-armed to catch gap-created grandchildren"
  );
}

/// A complete re-arm REBUILDS a watch whose object identity changed — a same-name
/// replacement the overflow hid — dropping the stale watch and issuing a fresh one.
#[test]
fn overflow_rearm_rebuilds_a_watch_whose_identity_changed() {
  let mut m = per_dir();
  let (root, w_a) = root_with_identified_child(&mut m, ident(100));

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

  // The re-arm reports "a" with a DIFFERENT identity — deleted and recreated in the gap.
  m.on_enumerate(
    root_req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(200)),
    ]),
  );
  let actions = drain_actions(&mut m);
  assert!(
    !m.is_watched(w_a),
    "the stale watch is dropped — identity changed"
  );
  assert!(
    actions.iter().any(|a| a.as_unwatch() == Some(w_a)),
    "the replaced object's watch is unwatched"
  );
  let w_a2 = actions
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("a")))
        .map(|w| w.id())
    })
    .expect("a fresh watch for the replacement");
  assert_ne!(w_a2, w_a, "a new watch for the new object");
}

/// A slot-changing record that races a directory's outstanding enumerate dirties it, so
/// the possibly-stale listing is re-read (a `Rescan` + retry) rather than trusted — the
/// create-descend window, where an enumerate snapshot could re-arm a since-removed child.
#[test]
fn record_racing_an_enumerate_forces_a_rescan() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // root → d (dir): install and arm it, leaving its cold enumerate outstanding (unfed).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("watch d");
  m.on_watch_result(w_d, Ok(()));
  let d_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("d cold enumerate");
  let _ = drain_events(&mut m);

  // A Removed record for a child of d races that read.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Removed)
      .with_name(seg("x"))
      .with_is_dir(true),
    at(2),
  );
  let _ = drain_events(&mut m);

  // The read returns a stale snapshot still listing "x"; because a record raced it, the
  // Monitor emits a Rescan rather than trusting the listing as a clean discovery.
  m.on_enumerate(
    d_req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("x"), FileKind::Dir)]),
  );
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "a raced (dirty) enumerate emits a Rescan"
  );
}

/// Deterministic fuzz: drive many random input schedules against the Monitor, asserting
/// the structural invariants after every step (via [`Monitor::assert_invariants`]) and
/// that the machine never panics and always drains to a fixpoint in bounded steps. This
/// is the property-test floor — a seeded xorshift generator keeps it reproducible without
/// a `proptest` dependency (which the `no_std` feature matrix would fight).
#[test]
fn random_op_storm_holds_invariants_and_terminates() {
  for seed in 1..=64u64 {
    let mut m = per_dir();
    let mut s = seed.wrapping_mul(2_654_435_761).wrapping_add(12_345);
    let mut rng = || {
      s ^= s << 13;
      s ^= s >> 17;
      s ^= s << 5;
      s
    };

    let mut watches = std::vec![
      m.register_root(scope(1), Interest::all()),
      m.register_root(scope(2), Interest::all()),
    ];
    let mut reqs: std::vec::Vec<ReqId> = std::vec::Vec::new();
    let names = [seg("a"), seg("b"), seg("c")];
    let scopes = [Scope::Root(scope(1)), Scope::Root(scope(2))];
    let kinds = [
      RecordKind::Created,
      RecordKind::Removed,
      RecordKind::Modified,
      RecordKind::MovedFrom,
      RecordKind::MovedTo,
      RecordKind::MoveSelf,
      RecordKind::DeleteSelf,
    ];

    for step in 0..300u64 {
      // Absorb the Monitor's outputs into the driver's queues, then check invariants.
      while let Some(action) = m.poll_action() {
        match action {
          Action::Watch(w) => watches.push(w.id()),
          Action::Enumerate(e) => reqs.push(e.req()),
          _ => {}
        }
      }
      while m.poll_event().is_some() {}
      m.assert_invariants();

      let now = at(step + 1);
      match rng() % 6 {
        0 => {
          let w = watches[(rng() as usize) % watches.len()];
          let res = if rng() % 8 == 0 {
            Err(WatchError::Io)
          } else {
            Ok(())
          };
          m.on_watch_result(w, res);
        }
        1 => {
          if !reqs.is_empty() {
            let req = reqs.swap_remove((rng() as usize) % reqs.len());
            let mut entries = std::vec::Vec::new();
            for n in &names {
              if rng() % 2 == 0 {
                let kind = if rng() % 2 == 0 {
                  FileKind::Dir
                } else {
                  FileKind::File
                };
                entries.push(DirEntry::new(n.clone(), kind));
              }
            }
            let res = match rng() % 5 {
              0 => EnumerateResult::Failed(IoClass::Io),
              1 => EnumerateResult::Partial(entries),
              _ => EnumerateResult::Ok(entries),
            };
            m.on_enumerate(req, res);
          }
        }
        2 => {
          let w = watches[(rng() as usize) % watches.len()];
          let kind = kinds[(rng() as usize) % kinds.len()];
          let mut rec = OsRecord::new(w, kind)
            .with_name(names[(rng() as usize) % names.len()].clone())
            .with_is_dir(rng() % 2 == 0);
          if kind.is_move_half() {
            rec = rec.with_cookie(cookie(1 + rng() % 3));
          }
          m.on_os_record(rec, now);
        }
        3 => m.on_overflow(scopes[(rng() as usize) % scopes.len()].clone(), now),
        4 => m.handle_timeout(at(step + 1 + rng() % 400)),
        _ => {
          let w = watches[(rng() as usize) % watches.len()];
          m.on_os_record(OsRecord::new(w, RecordKind::Ignored), now);
        }
      }
    }

    // Every schedule drains to a fixpoint in a bounded number of steps.
    let mut guard = 0u32;
    while m.poll_action().is_some() {
      guard += 1;
      assert!(
        guard < 100_000,
        "the Monitor drains to a fixpoint (seed {seed})"
      );
    }
    m.assert_invariants();
  }
}

/// A record on a detached-and-held move source is suppressed (not delivered at the stale
/// pre-move path); because the hold was dirtied, the pairing reparent re-scans the
/// destination to recover the change.
#[test]
fn held_source_suppresses_stale_path_events() {
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

  // "d" moves away — detached and held for the pairing window.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(&mut m);

  // A modification on the held source during the window: suppressed — no stale-path event.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Modified).with_name(seg("f")),
    at(11),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "a record on a held source is not delivered at the stale path"
  );

  // The move pairs to "e": the move is delivered, and the dirtied hold re-scans it.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_moved()),
    "the move is delivered"
  );
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "the dirtied hold re-scans the destination to recover the suppressed change"
  );
}

/// A root self-move emits a `Rescan` AND invalidates the stale root tree, so a later
/// record on the moved-away root is ignored rather than delivered at the old root path.
#[test]
fn root_self_move_invalidates_the_stale_tree() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  m.on_os_record(OsRecord::new(root, RecordKind::MoveSelf), at(1));
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "a moved root emits a Rescan"
  );
  assert!(!m.is_watched(root), "the stale root tree is invalidated");

  // A later record on the moved-away root is ignored — no false event at the old path.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("x"))
      .with_is_dir(false),
    at(2),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "records on the invalidated root are ignored"
  );
}

/// A move-in landing inside a held source's subtree is fenced like any other record: it
/// must not reconstruct a Created/Moved at the stale pre-move path, and it dirties the
/// hold so the pairing reparent re-scans. Only the source's OWN pairing gets through.
#[test]
fn move_in_to_a_held_source_is_fenced() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

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

  // "d" is held after its MovedFrom.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(&mut m);

  // An UNRELATED object moves into d (a MovedTo on w_d whose cookie pairs nothing): fenced.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::MovedTo)
      .with_name(seg("x"))
      .with_cookie(cookie(9))
      .with_is_dir(true),
    at(11),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "a move-in inside a held source is fenced, not delivered at the stale path"
  );

  // Pairing d → e: the dirtied hold re-scans the destination.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "the dirtied hold re-scans on pairing"
  );
}

/// A held source's in-flight enumerate returning WHILE it is still held is dropped (not
/// delivered at the stale pre-move path); coverage is recovered when the pairing reparent
/// re-arms the reparented source at its real destination.
#[test]
fn held_source_recovers_coverage_on_pairing() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // root → d: install and arm, but leave d's cold enumerate outstanding (unfed).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_d, Ok(()));
  let d_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("d cold enumerate");
  let _ = drain_events(&mut m);

  // d moves away (held) while its cold enumerate is still in flight.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(&mut m);

  // A directory "g" is created under the held d: suppressed, dirtying the hold.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("g"))
      .with_is_dir(true),
    at(11),
  );
  let _ = drain_events(&mut m);

  // d's cold enumerate returns WHILE d is still held — even listing "g", it is dropped,
  // never delivered at the stale path.
  m.on_enumerate(
    d_req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "a held directory's enumerate is not delivered at the stale pre-move path"
  );

  // Pairing d → e recovers coverage: the reparented source is re-armed (rediscovers "g").
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  assert!(
    m.is_rearm_enumerating(w_d),
    "the dirtied hold re-arms the reparented source to recover coverage"
  );
}

/// A create→remove→create for one path, batched before the consumer drains, delivers all
/// three transitions: the intervening remove is not coalesced away, so the consumer does
/// not converge to "absent" for an object that in fact exists.
#[test]
fn create_remove_create_is_not_coalesced() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  for kind in [
    RecordKind::Created,
    RecordKind::Removed,
    RecordKind::Created,
  ] {
    m.on_os_record(OsRecord::new(root, kind).with_name(seg("x")), at(1));
  }

  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    3,
    "all three transitions are delivered, not coalesced to create+remove"
  );
  assert!(events[0].kind().is_created());
  assert!(events[1].kind().is_removed());
  assert!(events[2].kind().is_created());
}

/// A held (still-pending) source whose watch install FAILS does not Rescan at its stale
/// pre-move path — the failure dirties the hold instead, and pairing/timeout resolves the
/// real path.
#[test]
fn held_pending_source_watch_failure_is_fenced() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // "d" is created; its watch is queued but NOT yet acknowledged (pending).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  let _ = drain_events(&mut m);

  // "d" moves away while still pending → held.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(&mut m);

  // The delayed watch result for the held pending source errors: no stale-path Rescan.
  m.on_watch_result(w_d, Err(WatchError::Gone));
  assert!(
    drain_events(&mut m).is_empty(),
    "a held pending source's watch failure emits no stale-path Rescan"
  );
}

/// A root overflow during a hold dirties the held source, so when the move pairs the
/// reparented source is re-armed — rebuilding any destination coverage the overflow's
/// temporary watch had that the reparent drops.
#[test]
fn root_overflow_during_hold_rearms_the_paired_source() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

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

  // "d" is held after its MovedFrom.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(&mut m);

  // A root overflow dirties the held source (its re-arm may build temp destination
  // coverage the reparent will drop).
  m.on_overflow(Scope::Root(scope(1)), at(11));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // d pairs to e: the dirtied hold re-arms the reparented source, rebuilding coverage.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  assert!(
    m.is_rearm_enumerating(w_d),
    "the root overflow dirtied the hold, so pairing re-arms the moved-in source"
  );
}

/// A subtree overflow targeting a held move source is fenced like a record: it does not
/// Rescan at the stale pre-move path, but dirties the hold so the pairing reparent
/// re-scans the real destination.
#[test]
fn subtree_overflow_on_a_held_source_is_fenced() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

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

  // "d" is held after its MovedFrom.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(&mut m);

  // A subtree overflow on the held source: fenced — no stale-path Rescan.
  m.on_overflow(Scope::subtree_of(w_d), at(11));
  assert!(
    drain_events(&mut m).is_empty(),
    "a subtree overflow on a held source emits no stale-path Rescan"
  );

  // Pairing d → e: the dirtied hold re-scans the destination.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "the dirtied hold re-scans on pairing"
  );
}

/// A watch that arms WHILE held enumerates coverage-only even if the move pairs (clearing
/// the hold) before the read returns: a pre-existing destination child must not surface as
/// a false Created after the move.
#[test]
fn held_origin_enumerate_stays_coverage_only_across_pairing() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // "d" is created; its watch is queued but NOT yet acknowledged (pending).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  let _ = drain_events(&mut m);

  // "d" moves away while still pending → held.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(&mut m);

  // d's watch NOW arms while held: its post-arm enumerate is queued coverage-only.
  m.on_watch_result(w_d, Ok(()));
  let d_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("d post-arm enumerate");

  // The move pairs (d → e), clearing the hold, BEFORE d's enumerate returns.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );
  let _ = drain_events(&mut m);

  // d's enumerate returns listing a PRE-EXISTING child "c": it must not surface as Created.
  m.on_enumerate(
    d_req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("c"), FileKind::Dir)]),
  );
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_created()),
    "a held-origin enumerate stays coverage-only across pairing — no false Created"
  );
}

/// A `Modified`-only registration still maintains coverage: the backend watch is
/// subscribed to the structural kinds (the coverage mask), a new directory is still
/// discovered and armed, unrequested `Created` changes are filtered from delivery, and
/// requested `Modified` changes under the discovered subtree ARE delivered.
#[test]
fn modified_only_interest_keeps_coverage_and_filters_delivery() {
  let mut m = per_dir();
  let mask = Interest::new().with_modified();
  let root = m.register_root(scope(1), mask);
  // The installed watch subscribes to the coverage superset, not the bare request.
  let installed = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().filter(|w| w.id() == root).map(|w| w.mask()))
    .expect("root watch");
  assert!(
    installed.created() && installed.removed() && installed.moved() && installed.ondir(),
    "the backend mask is coverage-augmented with the structural kinds"
  );
  assert!(installed.modified(), "the requested kind is kept");
  m.on_watch_result(root, Ok(()));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A new directory is created: NOT delivered (Created unrequested), but STILL armed.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "an unrequested Created is filtered from delivery"
  );
  let w_d = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the new directory is still armed — coverage is delivery-independent");
  m.on_watch_result(w_d, Ok(()));
  let d_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("d bootstrap enumerate");
  m.on_enumerate(d_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A Modified under the discovered subtree IS delivered (the requested kind)…
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Modified).with_name(seg("f")),
    at(2),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "the requested Modified is delivered");
  assert!(events[0].kind().is_modified());

  // …while an Attrib (a different flag, same Change kind) is not.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Attrib).with_name(seg("f")),
    at(3),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "an unrequested Attrib is filtered even though it maps to a Modified change"
  );
}

/// The `Rescan` no-silent-loss escape is always delivered, even to a scope registered
/// with an empty interest — a consumer that asked for nothing still must learn its
/// view is stale.
#[test]
fn rescan_bypasses_the_delivery_filter() {
  let mut m = per_dir();
  let root = m.register_root(scope(1), Interest::new());
  m.on_watch_result(root, Ok(()));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_overflow(Scope::Root(scope(1)), at(1));
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "Rescan is delivered regardless of the registered interest"
  );
}

/// Move-derived deliveries honor the `ondir` modifier when the moved object's class is
/// known: without `ondir`, a directory's paired rename and an unpaired directory move's
/// timeout `Removed` are both suppressed — while a FILE move still delivers, and the
/// directory coverage (detach + reparent) is interest-independent.
#[test]
fn directory_move_deliveries_honor_ondir() {
  let mut m = per_dir();
  // Everything except dir-targeted delivery.
  let mask = Interest::all().maybe_ondir(false);
  let root = m.register_root(scope(1), mask);
  m.on_watch_result(root, Ok(()));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A directory child is created (delivery suppressed by !ondir) and armed.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("dir armed despite suppressed delivery");
  m.on_watch_result(w_d, Ok(()));
  let d_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("d bootstrap");
  m.on_enumerate(d_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A paired DIRECTORY rename: no Moved delivered, but the reparent still happens.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_moved()),
    "a directory rename is not delivered without ondir"
  );
  assert!(m.is_watched(w_d), "the reparent (coverage) still happened");

  // A FILE move still delivers (target class Some(false) passes the modifier)…
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("f"))
      .with_cookie(cookie(2))
      .with_is_dir(false),
    at(4),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("g"))
      .with_cookie(cookie(2))
      .with_is_dir(false),
    at(5),
  );
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_moved()),
    "a file move is delivered"
  );

  // …and an unpaired DIRECTORY move's timeout Removed is suppressed.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("e"))
      .with_cookie(cookie(3))
      .with_is_dir(true),
    at(6),
  );
  let _ = drain_events(&mut m);
  m.handle_timeout(at(500));
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_removed()),
    "an unpaired directory move's timeout Removed is suppressed without ondir"
  );
}

/// A LATE `MovedTo` whose directory flag is omitted still classifies by the recovered
/// pending half: the stranded source was a held watched directory, so without `ondir`
/// neither its `Removed` nor the late arrival's `Created` is delivered — the class is
/// proven, not unknown.
#[test]
fn late_destination_uses_the_pending_halfs_class_for_ondir() {
  let mut m = per_dir();
  let mask = Interest::all().maybe_ondir(false);
  let root = m.register_root(scope(1), mask);
  m.on_watch_result(root, Ok(()));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A directory child is created (suppressed delivery) and armed.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("dir armed");
  m.on_watch_result(w_d, Ok(()));
  let d_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("d bootstrap");
  m.on_enumerate(d_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // "d" moves away (held), and its destination arrives LATE with NO directory flag.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  let _ = drain_events(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1)),
    at(400),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the pending half proves the class: neither Removed nor Created delivers without ondir"
  );
  // …and COVERAGE also uses the proven class: the late destination is a directory, so
  // it is watched despite the record's omitted flag (delivery and reconciliation must
  // agree, or the moved directory would sit inside the tree silently unwatched).
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("e")))),
    "the late directory destination is re-watched using the pending half's class"
  );
}

/// A paired move whose SOURCE half omitted the directory flag but whose DESTINATION half
/// reports a directory resolves with ONE class on both planes: without `ondir` the
/// `Moved` is suppressed (delivery), while the destination is still reconciled — and
/// watched — as a directory (coverage).
#[test]
fn paired_move_uses_one_class_for_delivery_and_coverage() {
  let mut m = per_dir();
  let mask = Interest::all().maybe_ondir(false);
  let root = m.register_root(scope(1), mask);
  m.on_watch_result(root, Ok(()));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The source half carries NO flag (an unwatched name, so the tree proves nothing)…
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(1)),
    at(1),
  );
  // …and the destination half positively reports a directory.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("b"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );

  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_moved()),
    "the resolution class is a directory, so without ondir the Moved is suppressed"
  );
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("b")))),
    "coverage uses the SAME class: the directory destination is watched"
  );
}

/// `DeleteSelf` tears the reporting watch down immediately: a replacement created at
/// the same slot before the trailing `Ignored` gets a FRESH watch instead of reusing
/// the dead one (which the `Ignored` would then tear down, leaving it unwatched).
#[test]
fn delete_self_frees_the_slot_for_a_replacement() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

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
    .expect("d bootstrap");
  m.on_enumerate(d_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The directory is deleted: its own DeleteSelf arrives BEFORE the parent-side record
  // or the trailing Ignored, and tears the watch down.
  m.on_os_record(OsRecord::new(w_d, RecordKind::DeleteSelf), at(2));
  assert!(
    !m.is_watched(w_d),
    "DeleteSelf tears the reporting watch down"
  );
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A replacement directory is created at the same name: it gets a FRESH watch.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(3),
  );
  let w_d2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("d")))
        .map(|w| w.id())
    })
    .expect("the replacement is freshly watched");
  assert_ne!(w_d2, w_d, "a new watch, not the dead one");

  // The old watch's trailing Ignored is a no-op — it must not clobber the replacement.
  m.on_os_record(OsRecord::new(w_d, RecordKind::Ignored), at(4));
  assert!(
    m.is_watched(w_d2),
    "the stale Ignored does not tear down the replacement"
  );
}

/// A root deletion under a FILTERED interest still signals: the interest-filtered
/// `Removed` is suppressed, but the coverage loss is never silent — an unconditional,
/// epoch-bumping `Rescan` is delivered before the scope's watch tree is invalidated.
#[test]
fn root_delete_self_rescans_despite_a_filtered_interest() {
  let mut m = per_dir();
  // Modified-only, and no dir-target delivery at all.
  let mask = Interest::new().with_modified();
  let root = m.register_root(scope(1), mask);
  m.on_watch_result(root, Ok(()));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let before = m.epoch_of(scope(1));

  m.on_os_record(OsRecord::new(root, RecordKind::DeleteSelf), at(1));
  let events = drain_events(&mut m);
  assert!(
    events.iter().all(|e| !e.kind().is_removed()),
    "the Removed itself is filtered by the registered interest"
  );
  let rescan = events
    .iter()
    .find(|e| e.kind().is_rescan())
    .expect("the coverage loss is signalled by an unfiltered Rescan");
  assert!(rescan.epoch() > before, "the Rescan bumps the scope epoch");
  assert!(!m.is_watched(root), "the scope's tree is invalidated");
}

/// A root torn down by the kernel with no preceding record (`Ignored` without a
/// `DeleteSelf`/`MoveSelf` — an unmount, an external watch removal) also signals with
/// the unconditional `Rescan`: no parent watch exists to report the loss.
#[test]
fn root_ignored_rescans_before_invalidation() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  m.on_os_record(OsRecord::new(root, RecordKind::Ignored), at(1));
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "a kernel-side root teardown signals with a Rescan"
  );
  assert!(!m.is_watched(root), "the scope's tree is invalidated");
}

/// Root invalidation purges the scope's pending move halves: a stale FILE half from the
/// dead root generation must not pair with a same-cookie destination in a re-registered
/// generation of the same `ScopeId` — where its stale class would reconcile a real
/// directory as a file and leave the new subtree silently unwatched.
#[test]
fn root_invalidation_purges_pending_moves_across_generations() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // A FILE source half goes pending in the old generation…
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("f"))
      .with_cookie(cookie(1))
      .with_is_dir(false),
    at(1),
  );
  // …then the root is torn down (unmount-style Ignored) and the scope re-registered.
  m.on_os_record(OsRecord::new(root, RecordKind::Ignored), at(2));
  let _ = drain_events(&mut m);
  let root2 = m.register_root(scope(1), Interest::all());
  m.on_watch_result(root2, Ok(()));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root2)
        .map(|e| e.req())
    })
    .expect("new generation bootstrap");
  m.on_enumerate(boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A DIRECTORY MovedTo with the SAME cookie arrives in the new generation, in-window:
  // the stale half was purged, so this resolves as a fresh Created — classed by its own
  // record — and the directory is watched.
  m.on_os_record(
    OsRecord::new(root2, RecordKind::MovedTo)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_created()) && events.iter().all(|e| !e.kind().is_moved()),
    "the stale cross-generation half does not pair — the arrival is a fresh Created"
  );
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root2, seg("d")))),
    "the directory destination is watched with its own class, not the stale file class"
  );
}

/// A lingering FILE half (its source parent narrowly torn down — invariant (b) keeps it
/// pairable) must not demote a same-cookie DIRECTORY destination: the record is the
/// newer observation, so its positive class wins the join — the arrival delivers and
/// the directory is watched.
#[test]
fn stale_file_half_does_not_demote_a_directory_destination() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // root → p (watched, live).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("p"))
      .with_is_dir(true),
    at(1),
  );
  let w_p = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_p, Ok(()));
  let p_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_p).map(|e| e.req()))
    .expect("p bootstrap");
  m.on_enumerate(p_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A FILE source half under p, then p is narrowly torn down (the half lingers).
  m.on_os_record(
    OsRecord::new(w_p, RecordKind::MovedFrom)
      .with_name(seg("f"))
      .with_cookie(cookie(1))
      .with_is_dir(false),
    at(10),
  );
  m.on_os_record(OsRecord::new(w_p, RecordKind::Ignored), at(11));
  let _ = drain_events(&mut m);

  // A same-cookie DIRECTORY MovedTo under the live root, in-window: the dead-source
  // pairing delivers a fresh Created, and the record's positive directory class wins
  // the join — the destination is watched, not silently demoted by the stale half.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_created()),
    "the dead-source pairing delivers a fresh Created"
  );
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("d")))),
    "the directory destination is watched — the stale file class does not demote it"
  );
}

/// A held source whose watch install FAILS mid-hold still pairs — and because the O(1)
/// carry-over is impossible (the source died), the pairing re-scans the destination in
/// addition to rewatching it: the failure-to-arm interval was seen by no one, and the
/// dirty marker alone cannot survive the source's teardown.
#[test]
fn pairing_after_held_source_watch_failure_rescans_the_destination() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // "d" is created; its watch is queued but NOT yet acknowledged (pending).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  let _ = drain_events(&mut m);

  // "d" moves away while still pending → held…
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(&mut m);

  // …and its delayed watch install FAILS (fenced: no stale-path Rescan), dropping it.
  m.on_watch_result(w_d, Err(WatchError::Gone));
  assert!(drain_events(&mut m).is_empty());

  // The same-cookie destination arrives in-window under the live root: the pairing
  // delivers, the destination is rewatched, AND re-scanned — the failed-arm interval
  // was covered by no watch.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "the destination is re-scanned after a failed carry-over"
  );
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("e")))),
    "the destination is rewatched"
  );
}

/// The trailing non-root `MoveSelf` of a normal in-tree rename (kernel order: MovedFrom,
/// MovedTo, MoveSelf) is a no-op: the node was already reparented, so it must not disturb
/// the carried-over coverage — the subtree stays watched and delivers at its NEW path.
#[test]
fn trailing_move_self_does_not_disturb_a_reparented_subtree() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

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
    .expect("d bootstrap");
  m.on_enumerate(d_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Kernel-ordered rename: MovedFrom, MovedTo, then the moved dir's own MoveSelf.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  m.on_os_record(OsRecord::new(w_d, RecordKind::MoveSelf), at(4));
  let _ = drain_events(&mut m);

  // The reparented watch is intact and delivers at the NEW path.
  assert!(
    m.is_watched(w_d),
    "MoveSelf does not tear down the reparented node"
  );
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created).with_name(seg("c")),
    at(5),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert_eq!(
    events[0].location(),
    &loc(&["e", "c"]),
    "delivery reconstructs through the NEW path"
  );
}

/// A `MoveSelf` arriving mid-hold (after the parent-side MovedFrom, before the pairing
/// MovedTo) neither breaks the pending reparent nor leaks a stale-path event: the held
/// fence covers the window and the pairing still lands the subtree at its destination.
#[test]
fn move_self_mid_hold_preserves_the_pending_reparent() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

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
    .expect("d bootstrap");
  m.on_enumerate(d_boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  // The moved dir's own MoveSelf lands mid-hold; a delivering record follows it.
  m.on_os_record(OsRecord::new(w_d, RecordKind::MoveSelf), at(3));
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Modified).with_name(seg("f")),
    at(3),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "no stale-path delivery from the held window"
  );

  // The pairing still reparents the held subtree (with the dirtied-hold Rescan).
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(4),
  );
  assert!(m.is_watched(w_d), "the held subtree reparented");
  assert!(
    drain_events(&mut m)
      .iter()
      .any(|e| e.kind().is_moved() || e.kind().is_rescan()),
    "the pairing delivers"
  );
}

/// An overflow racing an OUTSTANDING cold enumerate must not be absorbed by it: the
/// pre-overflow snapshot is dirtied, so its result is handled untrusted (reconcile +
/// re-arm retry) and a directory created during the gap — omitted from the stale
/// listing — still ends up armed.
#[test]
fn overflow_during_cold_enumerate_preserves_the_rearm_obligation() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);
  // The bootstrap cold enumerate is queued but its result has NOT arrived yet.
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("bootstrap enumerate");

  // Overflow strikes while that read is in flight.
  m.on_overflow(Scope::Root(scope(1)), at(1));
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "the overflow Rescan is delivered"
  );

  // The pre-overflow snapshot returns clean — but OMITS the gap-created directory "g".
  // Dirtied, it is not trusted: a re-arm retry is queued instead of a clean discovery.
  m.on_enumerate(boot, EnumerateResult::Ok(std::vec::Vec::new()));
  let retry = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the dirtied read is followed by a re-arm retry");
  let _ = drain_events(&mut m);

  // The retry sees the post-overflow truth: "g" exists, and it is armed.
  m.on_enumerate(
    retry,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("g")))),
    "the gap-created directory is armed by the preserved re-arm obligation"
  );
}

/// A fresh re-arm trigger coalescing onto an in-flight read whose retry budget is
/// EXHAUSTED still gets its retry: the bounded ceiling is per obligation, so the
/// trigger resets the carried attempts — otherwise the new obligation dies with the
/// old counter and a gap-created directory stays unwatched.
#[test]
fn rearm_trigger_on_an_exhausted_read_still_retries() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // Drive the re-arm to its final retry: overflow, then REARM_MAX_RETRIES failures.
  m.on_overflow(Scope::Root(scope(1)), at(1));
  let _ = drain_events(&mut m);
  let mut req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("re-arm read");
  for _ in 0..REARM_MAX_RETRIES {
    m.on_enumerate(req, EnumerateResult::Failed(IoClass::Io));
    let _ = drain_events(&mut m);
    req = drain_actions(&mut m)
      .iter()
      .find_map(|a| a.as_enumerate().map(|e| e.req()))
      .expect("bounded retry");
  }

  // The FINAL retry is in flight (attempts at the ceiling) when a fresh overflow lands.
  m.on_overflow(Scope::Root(scope(1)), at(2));
  let _ = drain_events(&mut m);

  // The final read completes with a stale listing omitting the gap-created "g": the
  // fresh obligation's reset budget queues another retry rather than dying at the
  // ceiling…
  m.on_enumerate(req, EnumerateResult::Ok(std::vec::Vec::new()));
  let retry = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the fresh trigger still gets a post-trigger retry");
  let _ = drain_events(&mut m);

  // …and the retry arms "g".
  m.on_enumerate(
    retry,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("g")))),
    "the gap-created directory is armed"
  );
}

/// Create → move-away-from-that-path → create, batched before drain, delivers BOTH
/// creates: a queued `Moved` touches its SOURCE path too, so it breaks the dedup of a
/// later create at that path (a destination-only scan would drop the second create).
#[test]
fn create_move_from_same_path_create_is_not_coalesced() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  // Created /a
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("a")),
    at(1),
  );
  // Move a → b (a file move; pairs into a single Moved(/b from /a)).
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
    at(1),
  );
  // Created /a again — must NOT be coalesced against the first create (the move left /a).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("a")),
    at(1),
  );

  let events = drain_events(&mut m);
  let created = events.iter().filter(|e| e.kind().is_created()).count();
  let moved = events.iter().filter(|e| e.kind().is_moved()).count();
  assert_eq!(
    created, 2,
    "both creates at /a are delivered — the move's source touch breaks the dedup"
  );
  assert_eq!(moved, 1, "the a→b move is delivered once");
}

/// Move → create-at-that-source → move (same paths), batched before drain, delivers BOTH
/// moves: the NEW move touches its source too, so the intervening create at that source
/// breaks its adjacency with the earlier identical move (the symmetric touched-set).
#[test]
fn move_create_move_same_paths_is_not_coalesced() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  // move a → b
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
    at(1),
  );
  // create a (the source path is repopulated)
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("a")),
    at(1),
  );
  // move a → b again (a fresh rename of the recreated /a) — must NOT coalesce with the first
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(2)),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("b"))
      .with_cookie(cookie(2)),
    at(1),
  );

  let events = drain_events(&mut m);
  let moved = events.iter().filter(|e| e.kind().is_moved()).count();
  let created = events.iter().filter(|e| e.kind().is_created()).count();
  assert_eq!(
    moved, 2,
    "the second rename into /b is delivered — the intervening create at /a breaks dedup"
  );
  assert_eq!(created, 1, "the create at /a is delivered once");
}

/// A kernel-recursive backend reports arbitrarily deep paths on its one root watch;
/// the record's multi-segment target must land the change at the joined location,
/// with no descent and no actions.
#[test]
fn deep_created_record_emits_at_joined_location() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_target(loc(&["a", "b", "new.txt"]))
      .with_is_dir(false),
    at(10),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_created());
  assert_eq!(events[0].location(), &loc(&["a", "b", "new.txt"]));
  assert!(
    drain_actions(&mut m).is_empty(),
    "a kernel-recursive monitor never descends"
  );
}

#[test]
fn deep_removed_and_modified_records_emit_at_joined_location() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed).with_target(loc(&["a", "b"])),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Modified).with_target(loc(&["a", "c.txt"])),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Attrib).with_target(loc(&["a", "d.txt"])),
    at(3),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 3);
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["a", "b"]));
  assert!(events[1].kind().is_modified());
  assert_eq!(events[1].location(), &loc(&["a", "c.txt"]));
  assert!(events[2].kind().is_modified());
  assert_eq!(events[2].location(), &loc(&["a", "d.txt"]));
  assert!(drain_actions(&mut m).is_empty());
}

/// The FSEvents shape: two deep halves sharing a driver-minted cookie (the file id)
/// pair into a single `Moved` inside the window — source before destination.
#[test]
fn deep_move_pair_within_window_emits_single_moved() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a", "old"]))
      .with_cookie(cookie(7)),
    at(10),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "an in-window source half stays pending"
  );
  assert!(
    m.poll_timeout().is_some(),
    "the pairing window arms a timer"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["b", "sub", "new"]))
      .with_cookie(cookie(7)),
    at(20),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert_eq!(events[0].kind().moved_from(), Some(&loc(&["a", "old"])));
  assert_eq!(events[0].location(), &loc(&["b", "sub", "new"]));
  assert!(drain_actions(&mut m).is_empty());
  assert_eq!(
    m.poll_timeout(),
    None,
    "the consumed half disarms the timer"
  );
}

#[test]
fn deep_moved_from_unpaired_times_out_to_removed() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a", "gone"]))
      .with_cookie(cookie(3)),
    at(10),
  );
  assert!(drain_events(&mut m).is_empty());

  m.handle_timeout(at(500));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["a", "gone"]));
}

#[test]
fn deep_moved_to_without_pending_is_created() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["x", "arrived"]))
      .with_cookie(cookie(9)),
    at(10),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_created());
  assert_eq!(events[0].location(), &loc(&["x", "arrived"]));
}

#[test]
fn deep_cookieless_moved_from_resolves_immediately() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom).with_target(loc(&["a", "b", "c"])),
    at(10),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["a", "b", "c"]));
  assert_eq!(m.poll_timeout(), None, "a cookie-less half never waits");
}

/// A depth-one record under a kernel-recursive monitor still works via the same
/// target vocabulary (the with_name sugar).
#[test]
fn depth_one_record_still_works_under_kernel_recursive() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("top.txt")),
    at(10),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert_eq!(events[0].location(), &loc(&["top.txt"]));
}

/// A descending monitor's addressing contract is depth-one; a deeper record is a
/// driver bug and escalates to a Rescan + re-arm of the arrival watch, never a
/// mis-attributed delivery.
#[test]
fn deep_record_on_descending_monitor_escalates_rescan() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_target(loc(&["a", "b"])),
    at(5),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_enumerate().map(|e| e.dir()) == Some(root)),
    "the escalation re-arms the arrival watch"
  );
}

/// A self-event kind never carries a target; the malformed combination escalates to
/// a Rescan instead of invalidating the root off a record that addressed a child.
#[test]
fn self_event_with_target_escalates_rescan_not_invalidation() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MoveSelf).with_target(loc(&["a"])),
    at(5),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert!(
    m.is_watched(root),
    "a malformed self-event must not tear down the root"
  );
}

/// FSEvents `MustScanSubDirs` for a deep directory: the located subtree overflow
/// lands the Rescan at the descent under the root watch — targeted, not whole-root —
/// and re-arms nothing on a kernel-recursive backend.
#[test]
fn located_subtree_overflow_rescans_at_descent_kernel_recursive() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(
    SubtreeScope::new(root)
      .with_descent(loc(&["a", "b"]))
      .into(),
    at(5),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["a", "b"]));
  assert_eq!(events[0].scope(), scope(1));
  assert!(
    drain_actions(&mut m).is_empty(),
    "kernel-recursive: the re-arm half is a no-op"
  );

  // A second located overflow strictly advances the scope's epoch.
  let first = events[0].epoch();
  m.on_overflow(
    SubtreeScope::new(root)
      .with_descent(loc(&["a", "b"]))
      .into(),
    at(6),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].epoch() > first, "every overflow bumps the epoch");
}

/// On a descending backend a located overflow re-arms from the nearest watch — the
/// descent has no watch of its own — while the Rescan still lands at the descent.
#[test]
fn located_subtree_overflow_rearms_from_watch_when_descending() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  m.on_overflow(
    SubtreeScope::new(root).with_descent(loc(&["deep"])).into(),
    at(5),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["deep"]));
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_enumerate().map(|e| e.dir()) == Some(root)),
    "the re-arm starts from the nearest watch"
  );
}

#[test]
fn located_overflow_on_unknown_watch_is_dropped() {
  let mut m = kernel_recursive();
  let _root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(
    Scope::subtree_of(WatchId::new(NonZeroU64::new(999).unwrap())),
    at(5),
  );
  assert!(drain_events(&mut m).is_empty());
}

/// The kernel-recursive twin of the op storm: deep multi-segment targets, located
/// subtree overflows, root self-events — the FSEvents-shaped input space. The
/// Monitor must hold its invariants, never descend (no child watches, no
/// enumerates), and drain to a fixpoint under every schedule.
#[test]
fn kernel_recursive_deep_storm_holds_invariants_and_terminates() {
  for seed in 1..=64u64 {
    let mut m = kernel_recursive();
    let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(7);
    let mut rng = || {
      s ^= s << 13;
      s ^= s >> 17;
      s ^= s << 5;
      s
    };

    let roots = [
      m.register_root(scope(1), Interest::all()),
      m.register_root(scope(2), Interest::all()),
    ];
    while m.poll_action().is_some() {}
    m.on_watch_result(roots[0], Ok(()));
    m.on_watch_result(roots[1], Ok(()));

    let names = [seg("a"), seg("b"), seg("c")];
    let kinds = [
      RecordKind::Created,
      RecordKind::Removed,
      RecordKind::Modified,
      RecordKind::MovedFrom,
      RecordKind::MovedTo,
    ];

    for step in 0..300u64 {
      while let Some(action) = m.poll_action() {
        assert!(
          matches!(action, Action::Unwatch(_)),
          "a kernel-recursive monitor queues no descent work: {action:?}"
        );
      }
      while m.poll_event().is_some() {}
      m.assert_invariants();

      let now = at(step + 1);
      let root = roots[(rng() as usize) % roots.len()];
      match rng() % 5 {
        0 | 1 => {
          let kind = kinds[(rng() as usize) % kinds.len()];
          let depth = 1 + (rng() as usize) % 3;
          let target = Location::from_segments(
            (0..depth).map(|_| names[(rng() as usize) % names.len()].clone()),
          );
          let mut rec = OsRecord::new(root, kind)
            .with_target(target)
            .with_is_dir(rng() % 2 == 0);
          if kind.is_move_half() && rng() % 4 != 0 {
            rec = rec.with_cookie(cookie(1 + rng() % 3));
          }
          m.on_os_record(rec, now);
        }
        2 => {
          let sc = match rng() % 3 {
            0 => Scope::Root(scope(1 + rng() % 2)),
            1 => Scope::subtree_of(root),
            _ => {
              let depth = 1 + (rng() as usize) % 2;
              let descent = Location::from_segments(
                (0..depth).map(|_| names[(rng() as usize) % names.len()].clone()),
              );
              SubtreeScope::new(root).with_descent(descent).into()
            }
          };
          m.on_overflow(sc, now);
        }
        3 => m.handle_timeout(at(step + 1 + rng() % 400)),
        _ => {
          let kind = [
            RecordKind::MoveSelf,
            RecordKind::DeleteSelf,
            RecordKind::Ignored,
          ][(rng() as usize) % 3];
          m.on_os_record(OsRecord::new(root, kind), now);
        }
      }
    }

    let mut guard = 0u32;
    while m.poll_action().is_some() {
      guard += 1;
      assert!(
        guard < 100_000,
        "the kernel-recursive Monitor drains to a fixpoint (seed {seed})"
      );
    }
    m.assert_invariants();
  }
}
