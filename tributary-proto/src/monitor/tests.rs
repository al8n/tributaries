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
      match rng() % 7 {
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
        5 => {
          // The barrier's dispatch-time deficit re-signal, interleaved with
          // everything else: the optimistic clear, the heal kicks, and the
          // bridge flush must hold the invariants under any schedule.
          let s = if rng() % 2 == 0 { scope(1) } else { scope(2) };
          let _ = m.resignal_coverage_deficits(s);
        }
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
    // The delivered-epoch contract, asserted over every drained change: an
    // ordinary change never carries a generation greater than the latest
    // DELIVERED Rescan's for its scope, and each delivered Rescan strictly
    // advances that ceiling — no generation exists that no Rescan announced.
    let mut rescan_ceiling: std::collections::BTreeMap<ScopeId, Epoch> =
      std::collections::BTreeMap::new();
    let mut drain_checked = |m: &mut Monitor, seed: u64| {
      while let Some(change) = m.poll_event() {
        let ceiling = rescan_ceiling.entry(change.scope()).or_insert(Epoch::START);
        if change.kind().is_rescan() {
          assert!(
            change.epoch() > *ceiling,
            "each delivered Rescan strictly advances its scope's generation (seed {seed})"
          );
          *ceiling = change.epoch();
        } else {
          assert!(
            change.epoch() <= *ceiling,
            "an ordinary change never outruns the delivered Rescan ceiling (seed {seed})"
          );
        }
      }
    };

    for step in 0..300u64 {
      while let Some(action) = m.poll_action() {
        assert!(
          matches!(action, Action::Unwatch(_)),
          "a kernel-recursive monitor queues no descent work: {action:?}"
        );
      }
      // Batched draining: the queue legally accumulates changes across several
      // inputs, so the adjacency dedup must stay sound under it (subtree-aware
      // Rescan touching, not just point equality).
      if step % 5 == 0 {
        drain_checked(&mut m, seed);
      }
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

    drain_checked(&mut m, seed);
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

/// A second same-location loss after an intervening in-subtree event delivers its own
/// Rescan: that loss can hide changes ordered after the event, so coalescing it into
/// the pre-event Rescan would leave the consumer with no coverage marker after the
/// possibly-stale event — and with a scope epoch no delivered Rescan carries.
#[test]
fn repeated_overflow_around_descendant_event_delivers_both_rescans() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(Scope::Root(scope(1)), at(1));
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_target(loc(&["x"])),
    at(2),
  );
  m.on_overflow(Scope::Root(scope(1)), at(3));

  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    3,
    "rescan, created, rescan — nothing coalesced"
  );
  assert!(events[0].kind().is_rescan());
  assert!(events[1].kind().is_created());
  assert!(events[2].kind().is_rescan());
  assert!(
    events[2].epoch() > events[0].epoch(),
    "the trailing loss carries its own delivered generation"
  );
}

/// An event OUTSIDE the rescanned subtree is unaffected by that Rescan's coverage, so
/// it does not break the coalescing of identical located Rescans around it.
#[test]
fn out_of_subtree_event_keeps_rescan_coalescing() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(
    SubtreeScope::new(root).with_descent(loc(&["a"])).into(),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Modified).with_target(loc(&["b", "f"])),
    at(2),
  );
  m.on_overflow(
    SubtreeScope::new(root).with_descent(loc(&["a"])).into(),
    at(3),
  );

  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    2,
    "an event outside the rescanned subtree keeps the coalescing"
  );
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["a"]));
  assert!(events[1].kind().is_modified());
}

/// Truly-adjacent identical Rescans still coalesce: no covered event separates the
/// two losses, so one delivered instruction stands for both — and because the
/// coalesce is decided BEFORE the trigger's epoch bump, the scope's generation IS
/// the delivered Rescan's, so a following ordinary change carries an announced
/// generation, never a hidden one.
#[test]
fn adjacent_identical_rescans_still_coalesce() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(Scope::Root(scope(1)), at(1));
  m.on_overflow(Scope::Root(scope(1)), at(2));

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(
    m.epoch_of(scope(1)),
    events[0].epoch(),
    "the coalesced trigger never advanced the scope past its delivered Rescan"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_target(loc(&["x"])),
    at(3),
  );
  let after = drain_events(&mut m);
  assert_eq!(after.len(), 1);
  assert!(after[0].kind().is_created());
  assert_eq!(
    after[0].epoch(),
    events[0].epoch(),
    "a change after coalesced losses carries the delivered Rescan's generation"
  );
}

/// The prefix relation holds on the queued side too: a create after a queued ancestor
/// Rescan is a fresh post-rescan transition, never a duplicate of the same-slot create
/// that preceded the Rescan.
#[test]
fn queued_ancestor_rescan_breaks_point_event_coalescing() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_target(loc(&["x"])),
    at(1),
  );
  m.on_overflow(Scope::Root(scope(1)), at(2));
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_target(loc(&["x"])),
    at(3),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 3);
  assert!(events[0].kind().is_created());
  assert!(events[1].kind().is_rescan());
  assert!(events[2].kind().is_created());
}

/// An ancestor transition invalidates the state a descendant Rescan's re-read
/// established, so it breaks the coalescing of identical descendant Rescans — the
/// ancestor direction of the mutual-prefix touch relation.
#[test]
fn ancestor_transition_breaks_descendant_rescan_coalescing() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(
    SubtreeScope::new(root)
      .with_descent(loc(&["a", "b"]))
      .into(),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_target(loc(&["a"]))
      .with_is_dir(true),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_target(loc(&["a"]))
      .with_is_dir(true),
    at(3),
  );
  m.on_overflow(
    SubtreeScope::new(root)
      .with_descent(loc(&["a", "b"]))
      .into(),
    at(4),
  );

  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    4,
    "rescan, removed, created, rescan — nothing coalesced"
  );
  assert!(events[0].kind().is_rescan());
  assert!(events[3].kind().is_rescan());
  assert_eq!(events[3].location(), &loc(&["a", "b"]));
  assert!(
    events[3].epoch() > events[0].epoch(),
    "the post-ancestor loss carries its own delivered generation"
  );
}

/// A move whose SOURCE is an ancestor of the rescanned subtree is an ancestor
/// transition too — the source side of the mutual-prefix relation.
#[test]
fn ancestor_move_breaks_descendant_rescan_coalescing() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(
    SubtreeScope::new(root)
      .with_descent(loc(&["a", "b"]))
      .into(),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(9))
      .with_is_dir(true),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["c"]))
      .with_cookie(cookie(9))
      .with_is_dir(true),
    at(3),
  );
  m.on_overflow(
    SubtreeScope::new(root)
      .with_descent(loc(&["a", "b"]))
      .into(),
    at(4),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 3, "rescan, moved, rescan — nothing coalesced");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[1].kind().moved_from(), Some(&loc(&["a"])));
  assert!(events[2].kind().is_rescan());
}

/// The ancestor direction protects ordinary changes too: an ancestor swap makes a
/// same-slot re-create a DISTINCT transition, not a duplicate — suppressing it would
/// silently lose the child under the recreated parent with no covering Rescan.
#[test]
fn ancestor_transition_breaks_ordinary_coalescing() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_target(loc(&["a", "b"]))
      .with_is_dir(true),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_target(loc(&["a"]))
      .with_is_dir(true),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_target(loc(&["a"]))
      .with_is_dir(true),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_target(loc(&["a", "b"]))
      .with_is_dir(true),
    at(4),
  );

  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    4,
    "created, removed, created, created — the re-created child delivers"
  );
  assert!(events[3].kind().is_created());
  assert_eq!(events[3].location(), &loc(&["a", "b"]));
}

/// Sibling-subtree interleavings stay coalescible: a transition in an unrelated
/// subtree cannot affect this location's object, and a suppressed duplicate of a
/// state fact leaves the consumer at the same final state.
#[test]
fn sibling_event_keeps_ordinary_coalescing() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Modified).with_target(loc(&["a", "f"])),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Modified).with_target(loc(&["b", "g"])),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Modified).with_target(loc(&["a", "f"])),
    at(3),
  );

  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    2,
    "the sibling-separated duplicate Modified coalesces"
  );
  assert!(events[0].kind().is_modified());
  assert!(events[1].kind().is_modified());
  assert_eq!(events[1].location(), &loc(&["b", "g"]));
}

/// A record interleaved with a pending move window and touching its source is a latent
/// ancestor transition the queue-based dedup cannot see: it delivers (its path is its
/// own truth), and the half's resolution owes covering Rescans at both sides.
#[test]
fn kr_interleaved_descendant_fact_dirties_the_pending_move() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_target(loc(&["a", "new.txt"])),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["c"]))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(12),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 4, "created, moved, and two covering rescans");
  assert!(events[0].kind().is_created());
  assert_eq!(events[0].location(), &loc(&["a", "new.txt"]));
  assert_eq!(events[1].kind().moved_from(), Some(&loc(&["a"])));
  assert_eq!(events[1].location(), &loc(&["c"]));
  assert!(events[2].kind().is_rescan());
  assert_eq!(events[2].location(), &loc(&["a"]));
  assert!(events[3].kind().is_rescan());
  assert_eq!(events[3].location(), &loc(&["c"]));
  // Each covering Rescan announces its own bump, dominating the interleaved fact.
  assert!(events[2].epoch() > events[0].epoch());
  assert!(events[3].epoch() > events[2].epoch());
}

/// A located overflow inside the pending window is the same latent transition through
/// the loss path: its own Rescan delivers immediately, and the pairing still owes the
/// covering pair.
#[test]
fn kr_interleaved_located_overflow_dirties_the_pending_move() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_overflow(
    SubtreeScope::new(root)
      .with_descent(loc(&["a", "sub"]))
      .into(),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["c"]))
      .with_cookie(cookie(7)),
    at(12),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 4);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["a", "sub"]));
  assert_eq!(events[1].kind().moved_from(), Some(&loc(&["a"])));
  assert!(events[2].kind().is_rescan());
  assert_eq!(events[2].location(), &loc(&["a"]));
  assert!(events[3].kind().is_rescan());
  assert_eq!(events[3].location(), &loc(&["c"]));
}

/// An unpaired dirty half still owes the source-side cover when it strands: the
/// interleaved fact described a replacement the timeout's Removed contradicts.
#[test]
fn kr_dirty_unpaired_source_times_out_to_removed_and_rescan() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_target(loc(&["a", "x"])),
    at(11),
  );
  m.handle_timeout(at(500));

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 3);
  assert!(events[0].kind().is_created());
  assert!(events[1].kind().is_removed());
  assert_eq!(events[1].location(), &loc(&["a"]));
  assert!(events[2].kind().is_rescan());
  assert_eq!(events[2].location(), &loc(&["a"]));
  assert!(events[2].epoch() > events[1].epoch());
}

/// The fence is precise: a pending window with only hierarchy-unrelated interleavings
/// pairs into a bare Moved — no covering Rescans.
#[test]
fn kr_clean_pending_window_pairs_without_rescans() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_target(loc(&["b", "y"])),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["c"]))
      .with_cookie(cookie(7)),
    at(12),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2, "sibling activity adds no covering rescans");
  assert!(events[0].kind().is_created());
  assert!(events[1].kind().moved_from().is_some());
}

/// The descending-profile sibling: a FILE source has no child watch, so its half is
/// unheld exactly like a kernel-recursive source — the same fence covers it for free.
#[test]
fn per_dir_file_source_pending_window_dirties() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("f"))
      .with_cookie(cookie(9)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("f")),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("g"))
      .with_cookie(cookie(9)),
    at(12),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 4);
  assert!(events[0].kind().is_created());
  assert_eq!(events[0].location(), &loc(&["f"]));
  assert_eq!(events[1].kind().moved_from(), Some(&loc(&["f"])));
  assert_eq!(events[1].location(), &loc(&["g"]));
  assert!(events[2].kind().is_rescan());
  assert_eq!(events[2].location(), &loc(&["f"]));
  assert!(events[3].kind().is_rescan());
  assert_eq!(events[3].location(), &loc(&["g"]));
}

/// The dedup side of the fence: identical adjacent Rescans normally coalesce, but a
/// pending source touching them is a latent transition the queue cannot show — the
/// second loss must deliver its own covering Rescan and epoch.
#[test]
fn pending_source_blocks_rescan_coalescing() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_overflow(
    SubtreeScope::new(root).with_descent(loc(&["a"])).into(),
    at(5),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_overflow(
    SubtreeScope::new(root).with_descent(loc(&["a"])).into(),
    at(11),
  );

  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    2,
    "the second identical loss is not coalescible across a pending source"
  );
  assert!(events[0].kind().is_rescan());
  assert!(events[1].kind().is_rescan());
  assert_eq!(events[1].location(), &loc(&["a"]));
  assert!(events[1].epoch() > events[0].epoch());
}

/// A kernel-recursive pending half re-anchors under a resolved ancestor move — the
/// deep-suffix analogue of the tree carrying per-directory halves through a reparent:
/// its eventual Moved emits from the post-move path, and its covers land there too.
#[test]
fn kr_pending_half_reanchors_under_a_resolved_ancestor_move() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a", "b"]))
      .with_cookie(cookie(5)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["z"]))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(12),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["c", "d"]))
      .with_cookie(cookie(5)),
    at(13),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 4, "two moves and the inner pair's covers");
  assert_eq!(events[0].kind().moved_from(), Some(&loc(&["a"])));
  assert_eq!(events[0].location(), &loc(&["z"]));
  assert_eq!(
    events[1].kind().moved_from(),
    Some(&loc(&["z", "b"])),
    "the inner half's source follows the resolved ancestor move"
  );
  assert_eq!(events[1].location(), &loc(&["c", "d"]));
  assert!(events[2].kind().is_rescan());
  assert_eq!(events[2].location(), &loc(&["z", "b"]));
  assert!(events[3].kind().is_rescan());
  assert_eq!(events[3].location(), &loc(&["c", "d"]));
}

/// The unpaired variant: a re-anchored half strands, and its Removed + cover land at
/// the post-move path rather than the path the consumer no longer holds.
#[test]
fn kr_reanchored_unpaired_half_times_out_at_the_post_move_path() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a", "b"]))
      .with_cookie(cookie(5)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["z"]))
      .with_cookie(cookie(7)),
    at(12),
  );
  let _ = drain_events(&mut m);

  m.handle_timeout(at(500));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["z", "b"]));
  assert!(events[1].kind().is_rescan());
  assert_eq!(events[1].location(), &loc(&["z", "b"]));
}

/// Nested ancestor moves compose: each resolution rewrites the still-pending half, so
/// the innermost object's eventual pairing emits from the fully-relocated path.
#[test]
fn kr_nested_ancestor_moves_compose_on_a_pending_half() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a", "b", "c"]))
      .with_cookie(cookie(5)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["z"]))
      .with_cookie(cookie(7)),
    at(12),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["z", "b"]))
      .with_cookie(cookie(9)),
    at(13),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["w"]))
      .with_cookie(cookie(9)),
    at(14),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["q"]))
      .with_cookie(cookie(5)),
    at(15),
  );

  let events = drain_events(&mut m);
  let moves: Vec<(Location, Location)> = events
    .iter()
    .filter_map(|e| {
      e.kind()
        .moved_from()
        .map(|from| (from.clone(), e.location().clone()))
    })
    .collect();
  assert_eq!(
    moves,
    vec![
      (loc(&["a"]), loc(&["z"])),
      (loc(&["z", "b"]), loc(&["w"])),
      (loc(&["w", "c"]), loc(&["q"])),
    ],
    "each resolution rewrites the still-pending suffix"
  );
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["w", "c"])),
    "the innermost half covers at its fully-relocated source"
  );
}

/// A half parked BETWEEN an ancestor's two halves is marked by no record — the
/// re-anchor itself must dirty it, so its resolution still covers.
#[test]
fn kr_half_parked_between_ancestor_halves_reanchors_dirty() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a", "b"]))
      .with_cookie(cookie(5)),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["z"]))
      .with_cookie(cookie(7)),
    at(12),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["c"]))
      .with_cookie(cookie(5)),
    at(13),
  );

  let events = drain_events(&mut m);
  // The ancestor pair was dirtied by the inner MovedFrom record, so it covers both
  // sides; the inner half was marked by the re-anchor itself and covers at its
  // post-move source.
  assert_eq!(events.len(), 6);
  assert_eq!(events[0].kind().moved_from(), Some(&loc(&["a"])));
  assert!(events[1].kind().is_rescan());
  assert_eq!(events[1].location(), &loc(&["a"]));
  assert!(events[2].kind().is_rescan());
  assert_eq!(events[2].location(), &loc(&["z"]));
  assert_eq!(events[3].kind().moved_from(), Some(&loc(&["z", "b"])));
  assert_eq!(events[3].location(), &loc(&["c"]));
  assert!(events[4].kind().is_rescan());
  assert_eq!(events[4].location(), &loc(&["z", "b"]));
  assert!(events[5].kind().is_rescan());
  assert_eq!(events[5].location(), &loc(&["c"]));
}

/// A stranded ancestor's Removed is itself a subtree transition: a half parked under
/// it (marked by no record) is dirtied by the resolution, so its own later Removed
/// carries a cover instead of landing silently under an already-dropped tree.
#[test]
fn kr_stranded_ancestor_removal_dirties_halves_underneath() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(3)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a", "b"]))
      .with_cookie(cookie(5)),
    at(11),
  );
  m.handle_timeout(at(500));

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 4);
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["a"]));
  assert!(events[1].kind().is_rescan());
  assert_eq!(events[1].location(), &loc(&["a"]));
  assert!(events[2].kind().is_removed());
  assert_eq!(events[2].location(), &loc(&["a", "b"]));
  assert!(
    events[3].kind().is_rescan(),
    "the inner half was dirtied by the ancestor's stranded resolution"
  );
  assert_eq!(events[3].location(), &loc(&["a", "b"]));
}

/// A path names different objects over time: a REPLACEMENT half parked at the exact
/// source of a later-resolving pair belongs to the successor object, so the pair's
/// re-anchor must not relocate it — it stays at the vacated path (dirty) and its own
/// pairing emits from there, never from the departed object's destination.
#[test]
fn kr_same_source_replacement_half_is_not_reanchored() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(9)),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["z"]))
      .with_cookie(cookie(7)),
    at(12),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["w"]))
      .with_cookie(cookie(9)),
    at(13),
  );

  let events = drain_events(&mut m);
  let moves: Vec<(Location, Location)> = events
    .iter()
    .filter_map(|e| {
      e.kind()
        .moved_from()
        .map(|from| (from.clone(), e.location().clone()))
    })
    .collect();
  assert_eq!(
    moves,
    vec![(loc(&["a"]), loc(&["z"])), (loc(&["a"]), loc(&["w"])),],
    "the replacement pairs from the vacated path, not the original's destination"
  );
  assert!(
    events
      .iter()
      .filter(|e| e.kind().is_rescan() && e.location() == &loc(&["w"]))
      .count()
      == 1,
    "the replacement's covers land at its own destination"
  );
}

/// The timeout variant of the same-source replacement: its stranded Removed and
/// cover land at the vacated path the consumer still holds, never at the departed
/// object's destination.
#[test]
fn kr_same_source_replacement_half_times_out_at_the_vacated_path() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(9)),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["z"]))
      .with_cookie(cookie(7)),
    at(12),
  );
  let _ = drain_events(&mut m);

  m.handle_timeout(at(500));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(events[0].kind().is_removed());
  assert_eq!(
    events[0].location(),
    &loc(&["a"]),
    "the stranded replacement resolves at the vacated path, never the original's destination"
  );
  assert!(events[1].kind().is_rescan());
  assert_eq!(events[1].location(), &loc(&["a"]));
}

/// A strict descendant and an exact-source half in one window each follow their own
/// rule: the descendant travels with the moved subtree, the same-path successor stays.
#[test]
fn kr_strict_descendant_reanchors_while_exact_source_stays() {
  let mut m = kernel_recursive();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a", "b"]))
      .with_cookie(cookie(5)),
    at(9),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_target(loc(&["a"]))
      .with_cookie(cookie(9)),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["z"]))
      .with_cookie(cookie(7)),
    at(12),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["c"]))
      .with_cookie(cookie(5)),
    at(13),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_target(loc(&["w"]))
      .with_cookie(cookie(9)),
    at(14),
  );

  let events = drain_events(&mut m);
  let moves: Vec<(Location, Location)> = events
    .iter()
    .filter_map(|e| {
      e.kind()
        .moved_from()
        .map(|from| (from.clone(), e.location().clone()))
    })
    .collect();
  assert_eq!(
    moves,
    vec![
      (loc(&["a"]), loc(&["z"])),
      (loc(&["z", "b"]), loc(&["c"])),
      (loc(&["a"]), loc(&["w"])),
    ],
    "the descendant follows the subtree; the successor keeps the vacated path"
  );
}

/// The per-directory instance of the same boundary: a replacement half anchored at
/// the SAME unmoved parent reconstructs exactly the resolved source, and must not be
/// rewritten under the departed object's destination.
#[test]
fn per_dir_same_source_replacement_half_is_not_reanchored() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(7)),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(9)),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("z"))
      .with_cookie(cookie(7)),
    at(12),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("w"))
      .with_cookie(cookie(9)),
    at(13),
  );

  let events = drain_events(&mut m);
  let moves: Vec<(Location, Location)> = events
    .iter()
    .filter_map(|e| {
      e.kind()
        .moved_from()
        .map(|from| (from.clone(), e.location().clone()))
    })
    .collect();
  assert_eq!(
    moves,
    vec![(loc(&["a"]), loc(&["z"])), (loc(&["a"]), loc(&["w"])),],
    "the per-directory successor half keeps the vacated path"
  );
}

/// A held source whose vacated slot is reoccupied and vacated again (a replacement
/// watched directory moving out under its own cookie) covers the source path when
/// each half resolves: the interleaved facts at the slot contradict the applied
/// moves, and a destination-only rescan cannot repair the vacated path.
#[test]
fn held_source_replacement_covers_the_vacated_path() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let w_a = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_a, Ok(()));
  let _ = drain_actions(&mut m);

  // The original watched dir moves out: its half parks held.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  // A replacement watched dir reoccupies the vacated slot, then moves out too.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(11),
  );
  let w_a2 = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_a2, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(12),
  );
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("z"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(13),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("w"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(14),
  );

  let events = drain_events(&mut m);
  let shape: Vec<(bool, Location)> = events
    .iter()
    .map(|e| (e.kind().is_rescan(), e.location().clone()))
    .collect();
  assert_eq!(
    shape,
    vec![
      (false, loc(&["z"])),
      (true, loc(&["a"])),
      (true, loc(&["z"])),
      (false, loc(&["w"])),
      (true, loc(&["a"])),
      (true, loc(&["w"])),
    ],
    "each held resolution covers the vacated source AND its destination"
  );
  assert_eq!(events[0].kind().moved_from(), Some(&loc(&["a"])));
  assert_eq!(events[3].kind().moved_from(), Some(&loc(&["a"])));
  let rescan_epochs: Vec<Epoch> = events
    .iter()
    .filter(|e| e.kind().is_rescan())
    .map(|e| e.epoch())
    .collect();
  assert!(
    rescan_epochs.windows(2).all(|w| w[0] < w[1]),
    "every delivered cover announces its own bump"
  );
}

/// The strand variant: the replacement's held half times out after the original's
/// pair touched it — the `Removed` at the vacated path carries a covering `Rescan`
/// there, exactly as an unheld dirty half would.
#[test]
fn held_source_replacement_strand_covers_the_vacated_path() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

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
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(11),
  );
  let w_a2 = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_a2, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(12),
  );
  // The original pairs away; its resolution touches the replacement's parked half.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("z"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(13),
  );
  let _ = drain_events(&mut m);

  m.handle_timeout(at(12) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  let shape: Vec<(bool, Location)> = events
    .iter()
    .map(|e| (e.kind().is_rescan(), e.location().clone()))
    .collect();
  assert_eq!(
    shape,
    vec![(false, loc(&["a"])), (true, loc(&["a"]))],
    "the stranded replacement resolves Removed at the vacated path, covered"
  );
  assert!(events[0].kind().is_removed());
}

/// Precision pin: suppression UNDER a held subtree alone (no activity at the
/// vacated source slot) still recovers destination-only — the source-side cover is
/// owed exclusively to source-slot touches, never to under-hold content.
#[test]
fn under_hold_suppression_alone_stays_destination_only() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let w_a = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_a, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  // A record ON the detached subtree: fenced (suppressed), dirtying the hold.
  m.on_os_record(
    OsRecord::new(w_a, RecordKind::Created).with_name(seg("x")),
    at(11),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("z"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );

  let events = drain_events(&mut m);
  let rescans: Vec<&Location> = events
    .iter()
    .filter(|e| e.kind().is_rescan())
    .map(|e| e.location())
    .collect();
  assert_eq!(
    rescans,
    vec![&loc(&["z"])],
    "under-hold suppression recovers at the destination only"
  );
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["a"])),
    "no spurious source cover without a source-slot touch"
  );
}

/// One kernel-recursive-constructed Monitor hosts a DESCENDING scope alongside a KR
/// scope: the descending root bootstraps a cold enumerate on arming, the KR root does
/// not — the per-root profile, not the constructor default, governs each.
#[test]
fn mixed_profiles_descend_independently() {
  let mut m = kernel_recursive();
  let desc = Capabilities::new().with_supports_push().with_native_move();
  let r1 = m.register_root_with_profile(scope(1), Interest::all(), desc);
  let r2 = m.register_root(scope(2), Interest::all());
  m.on_watch_result(r1, Ok(()));
  m.on_watch_result(r2, Ok(()));
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_enumerate().map(|e| e.dir()) == Some(r1)),
    "the descending scope bootstraps a cold enumerate"
  );
  assert!(
    !actions
      .iter()
      .any(|a| a.as_enumerate().map(|e| e.dir()) == Some(r2)),
    "the kernel-recursive scope never enumerates"
  );
}

/// A Created directory record installs a child watch only in the descending scope;
/// the KR scope delivers the change without any descent work.
#[test]
fn per_scope_profile_gates_descent_on_records() {
  let mut m = kernel_recursive();
  let desc = Capabilities::new().with_supports_push().with_native_move();
  let r1 = m.register_root_with_profile(scope(1), Interest::all(), desc);
  let r2 = m.register_root(scope(2), Interest::all());
  m.on_watch_result(r1, Ok(()));
  m.on_watch_result(r2, Ok(()));
  // Settle the descending root's bootstrap read so the record below is post-discovery.
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == r1).map(|e| e.req()))
    .expect("descending bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(vec![]));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(r1, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  m.on_os_record(
    OsRecord::new(r2, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(2),
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(r1, seg("d")))),
    "the descending scope descends into the created directory"
  );
  assert_eq!(
    actions
      .iter()
      .filter(|a| a.as_watch().is_some() || a.as_enumerate().is_some())
      .count(),
    1,
    "the KR scope queues no descent work"
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2, "both scopes deliver the Created");
}

/// A root overflow re-arms (enumerates) the descending scope but is Rescan-only for
/// the KR scope — the dual obligation honors the per-root profile.
#[test]
fn overflow_rearm_respects_scope_profile() {
  let mut m = kernel_recursive();
  let desc = Capabilities::new().with_supports_push().with_native_move();
  let r1 = m.register_root_with_profile(scope(1), Interest::all(), desc);
  let r2 = m.register_root(scope(2), Interest::all());
  m.on_watch_result(r1, Ok(()));
  m.on_watch_result(r2, Ok(()));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == r1).map(|e| e.req()))
    .expect("descending bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(vec![]));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_overflow(Scope::Root(scope(1)), at(5));
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_enumerate().map(|e| e.dir()) == Some(r1)),
    "the descending scope's overflow re-arms its watch set"
  );
  m.on_overflow(Scope::Root(scope(2)), at(6));
  assert!(
    drain_actions(&mut m).is_empty(),
    "the KR scope's overflow queues no re-arm"
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(events.iter().all(|e| e.kind().is_rescan()));
}

/// The mixed-profile twin of the two single-profile storms: ONE Monitor hosts a
/// DESCENDING scope and a KERNEL-RECURSIVE scope simultaneously. The descending
/// scope's driver loop services watch installs and enumerates; the KR scope feeds
/// deep targets and located overflows. Invariants hold after every step, descent
/// work only ever references the descending scope's watches, the delivered-epoch
/// ceiling holds per scope, and the machine drains to a fixpoint.
#[test]
fn mixed_profile_storm_holds_invariants_and_terminates() {
  for seed in 1..=64u64 {
    let mut m = kernel_recursive();
    let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(41);
    let mut rng = || {
      s ^= s << 13;
      s ^= s >> 17;
      s ^= s << 5;
      s
    };

    let desc_caps = Capabilities::new().with_supports_push().with_native_move();
    let desc_root = m.register_root_with_profile(scope(1), Interest::all(), desc_caps);
    let mut cur_desc_root = desc_root;
    let kr_root = m.register_root(scope(2), Interest::all());
    let mut desc_watches = std::vec![desc_root];
    let mut reqs: std::vec::Vec<ReqId> = std::vec::Vec::new();
    while m.poll_action().is_some() {}
    m.on_watch_result(desc_root, Ok(()));
    m.on_watch_result(kr_root, Ok(()));

    let names = [seg("a"), seg("b"), seg("c")];
    let kinds = [
      RecordKind::Created,
      RecordKind::Removed,
      RecordKind::Modified,
      RecordKind::MovedFrom,
      RecordKind::MovedTo,
    ];
    let mut rescan_ceiling: std::collections::BTreeMap<ScopeId, Epoch> =
      std::collections::BTreeMap::new();

    for step in 0..300u64 {
      while let Some(action) = m.poll_action() {
        match action {
          Action::Watch(w) => {
            // Descent work may only ever target the descending scope.
            if let crate::action::WatchTarget::Child { .. } = w.target() {
              assert_eq!(
                m.scope_of(w.id()),
                Some(scope(1)),
                "child watches only in the descending scope (seed {seed})"
              );
            }
            desc_watches.push(w.id());
          }
          Action::Enumerate(e) => {
            assert_eq!(
              m.scope_of(e.dir()),
              Some(scope(1)),
              "enumerates only in the descending scope (seed {seed})"
            );
            reqs.push(e.req());
          }
          _ => {}
        }
      }
      if step % 5 == 0 {
        while let Some(change) = m.poll_event() {
          let ceiling = rescan_ceiling.entry(change.scope()).or_insert(Epoch::START);
          if change.kind().is_rescan() {
            assert!(change.epoch() > *ceiling, "rescan advances (seed {seed})");
            *ceiling = change.epoch();
          } else {
            assert!(
              change.epoch() <= *ceiling,
              "no unannounced epoch (seed {seed})"
            );
          }
        }
      }
      m.assert_invariants();

      let now = at(step + 1);
      match rng() % 7 {
        0 => {
          let w = desc_watches[(rng() as usize) % desc_watches.len()];
          let res = if rng() % 8 == 0 {
            Err(WatchError::NoSpace)
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
          // Depth-one record on a descending-scope watch.
          let w = desc_watches[(rng() as usize) % desc_watches.len()];
          let kind = kinds[(rng() as usize) % kinds.len()];
          let mut rec = OsRecord::new(w, kind)
            .with_name(names[(rng() as usize) % names.len()].clone())
            .with_is_dir(rng() % 2 == 0);
          if kind.is_move_half() && rng() % 4 != 0 {
            rec = rec.with_cookie(cookie(1 + rng() % 3));
          }
          m.on_os_record(rec, now);
        }
        3 => {
          // Deep multi-segment record on the KR root.
          let kind = kinds[(rng() as usize) % kinds.len()];
          let depth = 1 + (rng() as usize) % 3;
          let target = Location::from_segments(
            (0..depth).map(|_| names[(rng() as usize) % names.len()].clone()),
          );
          let mut rec = OsRecord::new(kr_root, kind)
            .with_target(target)
            .with_is_dir(rng() % 2 == 0);
          if kind.is_move_half() && rng() % 4 != 0 {
            rec = rec.with_cookie(cookie(10 + rng() % 3));
          }
          m.on_os_record(rec, now);
        }
        4 => {
          let sc = match rng() % 3 {
            0 => Scope::Root(scope(1 + rng() % 2)),
            1 => Scope::subtree_of(if rng() % 2 == 0 { desc_root } else { kr_root }),
            _ => {
              let descent = Location::from_segments(
                (0..1 + (rng() as usize) % 2)
                  .map(|_| names[(rng() as usize) % names.len()].clone()),
              );
              SubtreeScope::new(kr_root).with_descent(descent).into()
            }
          };
          m.on_overflow(sc, now);
        }
        5 => m.handle_timeout(at(step + 1 + rng() % 400)),
        _ => {
          let kind = [
            RecordKind::MoveSelf,
            RecordKind::DeleteSelf,
            RecordKind::Ignored,
          ][(rng() as usize) % 3];
          let root = if rng() % 2 == 0 { desc_root } else { kr_root };
          m.on_os_record(OsRecord::new(root, kind), now);
        }
      }
      // The descending root may die mid-storm (Ignored/DeleteSelf); re-register the
      // scope with the SAME profile — tracking the CURRENT root so exactly one live
      // registration per scope exists, per the API contract.
      if m.scope_of(cur_desc_root).is_none() && rng() % 2 == 0 {
        cur_desc_root = m.register_root_with_profile(scope(1), Interest::all(), desc_caps);
        desc_watches.push(cur_desc_root);
      }
    }

    let mut guard = 0u32;
    while m.poll_action().is_some() {
      guard += 1;
      assert!(guard < 100_000, "fixpoint (seed {seed})");
    }
    m.assert_invariants();
  }
}

/// A scope the Monitor has never seen — or one already torn down — carries no
/// re-arm work by definition, so the settle predicate is trivially true.
#[test]
fn rearm_settled_unknown_scope_is_settled() {
  let m = per_dir();
  assert!(m.rearm_settled(scope(1)));
}

/// Cold discovery — the bootstrap arm + enumerate of a fresh root, a discovered
/// child's arm + read, and a live-churn `Created` descent — never unsettles the
/// scope: it runs in non-re-arm states by construction, so ordinary churn cannot
/// hold [`Monitor::rearm_settled`] down.
#[test]
fn cold_discovery_never_unsettles_rearm() {
  let mut m = per_dir();
  let s = scope(1);

  let root = m.register_root(s, Interest::all());
  assert!(m.rearm_settled(s), "a pending root arm is not re-arm work");
  m.on_watch_result(root, Ok(()));
  assert!(
    m.rearm_settled(s),
    "a cold bootstrap read is not re-arm work"
  );
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  assert!(
    m.rearm_settled(s),
    "a discovered child's pending arm is not re-arm work"
  );
  let child = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("child watch armed");
  m.on_watch_result(child, Ok(()));
  assert!(m.rearm_settled(s), "a child's cold read is not re-arm work");
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("b"))
      .with_is_dir(true),
    at(1),
  );
  assert!(
    m.rearm_settled(s),
    "live-churn discovery is not re-arm work"
  );
  m.assert_invariants();
}

/// A grow re-arm cascade unsettles the scope until every spawned obligation lands:
/// the root's re-arm read, the re-installed child's arm, and that child's own
/// re-arm read each hold the predicate down in turn, and the final result settles
/// it. A second scope stays settled throughout — the counter is per scope.
#[test]
fn grow_rearm_unsettles_until_results_land() {
  let mut m = per_dir();
  let s = scope(1);
  let (root, child) = root_with_live_child(&mut m, s, "a");
  let other = scope(2);
  let _bystander = live_root_idle(&mut m, other);
  assert!(m.rearm_settled(s));

  // Prune the child subtree (shrink), then grow it back through the public re-arm.
  assert!(m.drop_watch_subtree(child));
  assert!(m.rearm_settled(s), "a prune leaves no re-arm work behind");
  assert!(m.rearm_watch_subtree(root).is_started());
  assert!(!m.rearm_settled(s), "the grow's re-arm read is outstanding");
  m.assert_invariants();

  // The root's re-arm read lists the pruned child: a fresh watch is installed
  // marked to continue the re-arm, so the scope stays unsettled after the root's
  // own read lands.
  let req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("grow re-arm read");
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  assert!(
    !m.rearm_settled(s),
    "the re-installed child still owes its re-arm"
  );
  m.assert_invariants();
  let fresh = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("re-installed child watch");
  m.on_watch_result(fresh, Ok(()));
  assert!(
    !m.rearm_settled(s),
    "the child's own re-arm read is outstanding"
  );
  let child_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("child re-arm read");
  m.on_enumerate(child_req, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s), "the cascade quiesced");
  assert!(m.rearm_settled(other), "an idle scope never unsettled");
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_created()),
    "a grow re-arm emits no Created"
  );
  m.assert_invariants();
}

/// A grow landing on a node whose COLD read is still in flight coalesces: the
/// obligation rides the dirtied cold read, the kickoff reports `Coalesced`, and —
/// by deliberate design — the scope still reads settled while the obligation is
/// latent (cold discovery must never hold a fence down). The dirtied read's
/// completion then escalates into a counted re-arm retry plus a covering
/// `Rescan`, unsettling the scope until the retry lands. A fence consumes the
/// `Coalesced` report as lossy-from-birth precisely because of this window.
#[test]
fn coalesced_grow_rides_the_inflight_cold_read() {
  let mut m = per_dir();
  let s = scope(1);

  // A fresh root whose bootstrap COLD read is still outstanding.
  let root = m.register_root(s, Interest::all());
  m.on_watch_result(root, Ok(()));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  assert!(
    m.rearm_settled(s),
    "a cold bootstrap read is not re-arm work"
  );

  // The grow coalesces onto the in-flight cold read: latent, and reported as such.
  assert!(m.rearm_watch_subtree(root).is_coalesced());
  assert!(
    m.rearm_settled(s),
    "the latent obligation is deliberately invisible to the settle counter"
  );
  m.assert_invariants();

  // The dirtied cold read's completion escalates: a covering Rescan stands and a
  // counted re-arm retry unsettles the scope until it lands clean.
  m.on_enumerate(boot, EnumerateResult::Ok(vec![]));
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "the dirtied read's completion emits the covering Rescan"
  );
  assert!(
    !m.rearm_settled(s),
    "the escalated re-arm retry is a counted obligation"
  );
  let retry = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("escalated re-arm retry read");
  m.on_enumerate(retry, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s), "the escalated obligation quiesced");
  m.assert_invariants();
}

/// The kickoff report's refusal cases: an unknown watch and a kernel-recursive
/// scope (whole-subtree coverage never shrank) both refuse without recording any
/// obligation.
#[test]
fn rearm_kickoff_refusal_cases() {
  let mut m = per_dir();
  let ghost = WatchId::new(NonZeroU64::new(999).unwrap());
  assert!(m.rearm_watch_subtree(ghost).is_refused());

  let mut kr = kernel_recursive();
  let s = scope(7);
  let root = kr.register_root(s, Interest::all());
  kr.on_watch_result(root, Ok(()));
  assert!(kr.rearm_watch_subtree(root).is_refused());
  assert!(kr.rearm_settled(s));
  kr.assert_invariants();
}

/// An unreadable re-arm read keeps the scope unsettled across its bounded retries;
/// exhausting the cap resolves the obligation — the `Rescan` stands, the node goes
/// idle, and the scope settles rather than pending forever.
#[test]
fn rearm_retry_cap_resolution_settles() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  assert!(m.rearm_watch_subtree(root).is_started());
  assert!(!m.rearm_settled(s));

  // Results carrying attempts 0..REARM_MAX_RETRIES each queue a retry read; the
  // result carrying attempts == REARM_MAX_RETRIES lets the Rescan stand instead.
  for _ in 0..REARM_MAX_RETRIES {
    let req = drain_actions(&mut m)
      .iter()
      .find_map(|a| a.as_enumerate().map(|e| e.req()))
      .expect("re-arm read outstanding");
    m.on_enumerate(req, EnumerateResult::Failed(IoClass::Io));
    assert!(
      !m.rearm_settled(s),
      "an incomplete re-arm read retries and stays pending"
    );
    m.assert_invariants();
  }
  let last = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("final retry read");
  m.on_enumerate(last, EnumerateResult::Failed(IoClass::Io));
  assert!(
    m.rearm_settled(s),
    "retries exhausted: the Rescan stands and the scope settles"
  );
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "the exhausted obligation left a standing Rescan"
  );
  m.assert_invariants();
}

/// Tearing down watches mid-cascade settles the scope: a removed node takes its
/// pending count with it (no obligation outlives its node), whether through a
/// narrow subtree drop or a whole-scope unregister.
#[test]
fn drop_subtree_mid_rearm_cascade_settles() {
  let mut m = per_dir();
  let s = scope(1);
  let (root, child) = root_with_live_child(&mut m, s, "a");

  // Drive the cascade to the point where the re-installed child owes its re-arm
  // (Arming { rearm: true }), then drop that subtree.
  assert!(m.drop_watch_subtree(child));
  assert!(m.rearm_watch_subtree(root).is_started());
  let req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("grow re-arm read");
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  assert!(!m.rearm_settled(s), "the cascade is mid-flight");
  let fresh = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("re-installed child watch");
  assert!(m.drop_watch_subtree(fresh));
  assert!(
    m.rearm_settled(s),
    "a dropped mid-cascade subtree settles the scope"
  );
  m.assert_invariants();

  // Whole-scope teardown from a pending state settles too, leaving no residue.
  assert!(m.rearm_watch_subtree(root).is_started());
  assert!(!m.rearm_settled(s));
  m.unregister_root(s);
  assert!(m.rearm_settled(s), "an unregistered scope is settled");
  m.assert_invariants();
}

/// `rebind_root` drops the descended book (those kernel watches died with
/// the old transport), keeps the root's `WatchId`, and resets it to a
/// pending arm that CONTINUES a re-arm: the caller replays the new
/// transport's arm outcome and the rebuild announces nothing — the commit
/// `Rescan` the caller emits already stands for the world change.
#[test]
fn rebind_root_resets_the_root_and_drops_the_book() {
  let mut m = per_dir();
  let (root, w_a) = root_with_live_child(&mut m, scope(1), "a");

  assert_eq!(m.rebind_root(scope(1)), Some(root), "the WatchId survives");
  assert!(m.is_watched(root));
  assert!(!m.is_watched(w_a), "children die with the old transport");
  let actions = drain_actions(&mut m);
  assert!(
    actions
      .iter()
      .any(|a| matches!(a, Action::Unwatch(id) if *id == w_a)),
    "the dropped child's unwatch is queued: {actions:?}"
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "the reset root is a counted obligation"
  );

  // The replayed arm outcome starts the re-arm-flavored rebuild.
  m.on_watch_result(root, Ok(()));
  let req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the rebuild read");
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  let events = drain_events(&mut m);
  assert!(
    events.iter().all(|c| !c.kind().is_created()),
    "a re-arm rebuild announces nothing: {events:?}"
  );
  let child = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the child re-arms on the new transport");
  assert_ne!(child, w_a, "a fresh watch id");
  m.on_watch_result(child, Ok(()));
  let child_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the child rebuild read");
  m.on_enumerate(child_req, EnumerateResult::Ok(vec![]));
  let _ = drain_actions(&mut m);
  assert!(m.rearm_settled(scope(1)), "the rebuild quiesced");
}

/// A rebind is whole-world: an old-world move half can never pair on the
/// new transport, so it is purged — the pairing deadline then resolves
/// NOTHING (no fabricated `Removed` for a world that no longer exists).
#[test]
fn rebind_root_purges_pending_move_halves() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("gone"))
      .with_cookie(cookie(9)),
    at(10),
  );
  assert_eq!(m.rebind_root(scope(1)), Some(root));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  assert!(
    events.iter().all(|c| !c.kind().is_removed()),
    "a purged half resolves nothing: {events:?}"
  );
}

/// The rebind vocabulary is descending-only: a kernel-recursive scope swaps
/// its stream whole (no per-directory book), and an unknown scope has
/// nothing to rebind.
#[test]
fn rebind_root_refuses_kernel_recursive_and_unknown_scopes() {
  let mut kr = kernel_recursive();
  let _root = live_root(&mut kr, scope(1));
  assert_eq!(kr.rebind_root(scope(1)), None);

  let mut m = per_dir();
  assert_eq!(m.rebind_root(scope(9)), None);
}

/// A rebind lands while the root's own read is in flight: the request slot
/// is reclaimed, and the stale result — arriving after the reset — is
/// dropped rather than reconciled into the new world.
#[test]
fn rebind_root_disowns_an_in_flight_root_read() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");

  assert_eq!(m.rebind_root(scope(1)), Some(root));
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("stale"), FileKind::Dir)]),
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().all(|a| a.as_watch().is_none()),
    "a disowned read arms nothing: {actions:?}"
  );
  let events = drain_events(&mut m);
  assert!(
    events.iter().all(|c| !c.kind().is_created()),
    "and announces nothing: {events:?}"
  );
}

/// An arm outcome that crosses a rebind: the child it was for died with the
/// old transport, so the late result is ignored whole — no fabricated
/// events, no second Rescan, no re-arm accounting drift.
#[test]
fn a_late_arm_result_for_a_rebound_child_is_ignored() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  let child = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the child arm is in flight");
  let _ = drain_events(&mut m);

  assert_eq!(m.rebind_root(scope(1)), Some(root));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_watch_result(child, Ok(()));
  assert!(
    drain_actions(&mut m).is_empty(),
    "a dead arm starts nothing"
  );
  assert!(drain_events(&mut m).is_empty(), "and announces nothing");
}

// ---------------------------------------------------------------------------
// Barrier honesty: level-persistent coverage deficits (the F1/F2 class).
//
// A sync barrier's fence reads `coverage_settled`, and its cookie dispatch
// re-signals `resignal_coverage_deficits` — these cells pin the Monitor half
// of the no-false-`Delivered` property: every bridge window closes with a
// covering `Rescan`, every standing hole re-signals ahead of a dispatch, and
// the two fence gates (holds, latent cold reads) hold the window open.
// ---------------------------------------------------------------------------

/// Installs a live, enumerated child directory `name` under `parent` — the
/// realistic precondition for the hole/hold cells (a settled subtree).
fn live_child_dir(m: &mut Monitor, parent: WatchId, name: &str) -> WatchId {
  m.on_os_record(
    OsRecord::new(parent, RecordKind::Created)
      .with_name(seg(name))
      .with_is_dir(true),
    at(1),
  );
  let child = drain_actions(m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the discovered directory arms");
  m.on_watch_result(child, Ok(()));
  let boot = drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == child)
        .map(|e| e.req())
    })
    .expect("the armed child cold-enumerates");
  m.on_enumerate(boot, EnumerateResult::Ok(vec![]));
  let _ = drain_events(m);
  let _ = drain_actions(m);
  child
}

/// A1 (F1): the replace-rebuild bridge window closes with ONE root `Rescan`
/// whose epoch strictly dominates the commit `Rescan`'s — so a change that
/// landed after the commit but before a rebuilt directory's watch armed is ≤
/// a delivered `Rescan`. Fails on old: the stream ended at the commit
/// `Rescan`, and the whole bridge interval was silently lost.
#[test]
fn a_replace_rebuild_settle_emits_a_closing_rescan() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // The descending replace, as the core drives it: rebind, then the commit
  // overflow (whose re-arm kickoff folds into the reset root's pending arm).
  assert_eq!(m.rebind_root(scope(1)), Some(root));
  m.on_overflow(Scope::Root(scope(1)), at(1));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "exactly the commit Rescan: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  let commit_epoch = events[0].epoch();
  let _ = drain_actions(&mut m);

  // The driver replays the pre-armed root; its re-arm read lists a fresh
  // directory `a` — the bridge: `a`'s content changes are dark until its
  // watch arms, and the re-arm read suppresses `Created`.
  m.on_watch_result(root, Ok(()));
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the rebound root re-arm-enumerates");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "the fresh install keeps the window open"
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the rebuild announces nothing mid-window"
  );
  let a_watch = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the rebuilt directory arms");
  m.on_watch_result(a_watch, Ok(()));
  assert!(drain_events(&mut m).is_empty());
  let a_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the rebuilt directory re-arm-enumerates");

  // The settle edge: the window was lossy (commit Rescan) AND armed
  // suppressed coverage (`a`) — the closing Rescan covers the bridge.
  m.on_enumerate(a_read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(scope(1)));
  assert!(m.coverage_settled(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    1,
    "the settle edge emits ONE closing Rescan: {events:?}"
  );
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  assert!(
    events[0].epoch() > commit_epoch,
    "the closing Rescan strictly dominates the commit"
  );
}

/// A2 (regrow guard, fail-on-overreach): a clean prune-then-regrow window —
/// `fresh_rearm` set, no loss — emits NO `Rescan` and no `Created`. Guards
/// the two-bit conjunction: firing on `fresh_rearm` alone would degrade
/// every set-cover regrow of pruned coverage.
#[test]
fn a_clean_regrow_window_emits_nothing() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let a = live_child_dir(&mut m, root, "a");

  // The umbrella prune, then the grow back.
  assert!(m.drop_watch_subtree(a));
  let _ = drain_actions(&mut m);
  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the grow re-arm-enumerates the ancestor");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  let fresh = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the pruned directory re-installs");
  m.on_watch_result(fresh, Ok(()));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the re-installed directory re-arm-enumerates");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  assert!(
    drain_events(&mut m).is_empty(),
    "a clean regrow owes nothing — no Rescan, no Created"
  );
}

/// A3 (F2a): a child arm failure records a standing slot hole past its edge
/// `Rescan`; the dispatch-time re-signal emits a fresh covering `Rescan` at
/// the hole plus a bounded heal kick and optimistically clears it; a re-fail
/// re-records (with its own edge `Rescan`); a heal closes the window with the
/// closing `Rescan` and empties the book. Fails on old: after the edge
/// `Rescan`, `rearm_settled` is instantly and permanently true with nothing
/// recorded — the paired assertions document the fixed lie.
#[test]
fn an_arm_refused_slot_is_recorded_resignaled_and_healed() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // Open the hole: discovery installs `a`, the kernel refuses the watch.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let a1 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the discovered directory arms");
  let _ = drain_events(&mut m);
  m.on_watch_result(a1, Err(WatchError::NoSpace));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "the edge Rescan: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["a"]));
  let edge_epoch = events[0].epoch();

  // The fixed lie, documented: the scope reads settled while the darkness
  // stands — only the deficit book carries the fact.
  assert!(m.rearm_settled(scope(1)));
  assert!(m.coverage_settled(scope(1)));
  assert!(m.has_coverage_deficit(scope(1)));

  // The dispatch-time re-signal: a fresh covering Rescan at the hole's
  // CURRENT location, one heal kick at the parent, the entry cleared.
  assert!(m.resignal_coverage_deficits(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "one covering Rescan per site: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["a"]));
  assert!(events[0].epoch() > edge_epoch, "epoch-bumped, not a replay");
  let kick = drain_actions(&mut m);
  assert!(
    kick
      .iter()
      .any(|a| a.as_enumerate().is_some_and(|e| e.dir() == root)),
    "the heal kick re-reads the hole's parent: {kick:?}"
  );
  assert!(
    !m.has_coverage_deficit(scope(1)),
    "the re-signaled entry is optimistically cleared"
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "the kick is counted work — the next fence parks on it"
  );

  // The kick re-installs the slot; the arm fails again: the failure edge
  // re-records the hole (its own edge Rescan included) BEFORE the settle.
  let kick_req = kick
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the kicked read");
  m.on_enumerate(
    kick_req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  let a2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the heal re-installs the slot");
  m.on_watch_result(a2, Err(WatchError::NoSpace));
  assert!(m.has_coverage_deficit(scope(1)), "the re-fail re-records");
  assert!(m.rearm_settled(scope(1)));
  let events = drain_events(&mut m);
  // The re-fail's edge Rescan at the hole, then the window's closing Rescan
  // at the root (lossy + armed-suppressed — both bits).
  assert_eq!(events.len(), 2, "{events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["a"]));
  assert!(events[1].kind().is_rescan());
  assert_eq!(events[1].location(), &Location::new());
  assert!(events[1].epoch() > events[0].epoch());

  // Heal: re-signal again, and this time the arm succeeds. The heal window
  // closes with the closing Rescan and the book stays empty.
  assert!(m.resignal_coverage_deficits(scope(1)));
  let _ = drain_events(&mut m);
  let kick_req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the second heal kick");
  m.on_enumerate(
    kick_req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  let a3 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the heal re-installs the slot again");
  m.on_watch_result(a3, Ok(()));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the healed slot re-arm-enumerates");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "the heal's closing Rescan: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  assert!(!m.has_coverage_deficit(scope(1)), "the hole is healed");
  assert!(
    !m.resignal_coverage_deficits(scope(1)),
    "a healed scope re-signals nothing"
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "and a no-op re-signal emits nothing"
  );
  m.assert_invariants();
}

/// A4 (F2b): an exhausted re-arm read records a standing interior hole; the
/// re-signal emits at the interior and kicks a fresh read; a clean completion
/// that installs a gap-created directory closes the window with the closing
/// `Rescan`. Fails on old: after the standing `Rescan`, nothing is recorded
/// and nothing precedes a later sync's cookie.
#[test]
fn an_exhausted_read_interior_is_recorded_resignaled_and_healed() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // Discovery installs and arms `a`; its reads fail to exhaustion
  // (the cold read plus REARM_MAX_RETRIES re-arm retries).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let a = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the discovered directory arms");
  let _ = drain_events(&mut m);
  m.on_watch_result(a, Ok(()));
  for round in 0..=REARM_MAX_RETRIES {
    let req = drain_actions(&mut m)
      .iter()
      .find_map(|x| x.as_enumerate().filter(|e| e.dir() == a).map(|e| e.req()))
      .unwrap_or_else(|| panic!("round {round}: a read is outstanding"));
    m.on_enumerate(req, EnumerateResult::Failed(IoClass::Permission));
    let events = drain_events(&mut m);
    assert!(
      events.iter().any(|e| e.kind().is_rescan()),
      "round {round}: each incomplete read stands a Rescan: {events:?}"
    );
  }
  assert!(
    drain_actions(&mut m).is_empty(),
    "exhaustion queues no further retry"
  );
  assert!(m.rearm_settled(scope(1)), "the node stays Live");
  assert!(m.has_coverage_deficit(scope(1)), "the interior is recorded");

  // Re-signal: a covering Rescan at the interior plus a kicked read of it.
  assert!(m.resignal_coverage_deficits(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "{events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["a"]));
  let kick_req = drain_actions(&mut m)
    .iter()
    .find_map(|x| x.as_enumerate().filter(|e| e.dir() == a).map(|e| e.req()))
    .expect("the heal kick re-reads the interior");
  assert!(!m.has_coverage_deficit(scope(1)), "optimistically cleared");
  assert!(!m.rearm_settled(scope(1)), "the kick is counted");

  // The heal: a clean read listing the gap-created directory `b` — its
  // suppressed install is exactly what the closing Rescan must cover.
  m.on_enumerate(
    kick_req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b"), FileKind::Dir)]),
  );
  let b = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the gap-created directory installs");
  m.on_watch_result(b, Ok(()));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the fresh install re-arm-enumerates");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "the closing Rescan: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  assert!(!m.has_coverage_deficit(scope(1)));
  assert!(!m.resignal_coverage_deficits(scope(1)));
  m.assert_invariants();
}

/// A5 (record heal): a delivered `Removed` for a recorded hole's slot clears
/// the deficit — the consumer converged on the removal, so the next
/// re-signal is a no-op. Book-lifecycle precision.
/// The R13 class-kill for the slot-emptying edge: a `Removed`/`File` record
/// that clears a recorded arm-refused hole is NOT convergence for a filtered
/// subscription. The removal is interest- and filter-subject — a
/// `Modified`-only consumer never sees it — so it cannot stand in for the
/// change the hole's darkness hid. The clear therefore stands a covering
/// `Rescan` (root-located, epoch-bumped, filter-bypassing) so every subscriber
/// re-reads. Fails on old: the record cleared the book silently — `events` was
/// just the `Removed` — and a later sync over the dark change resolved a false
/// `Delivered`.
#[test]
fn a_removed_record_over_a_slot_hole_stands_a_covering_rescan() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let a = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the discovered directory arms");
  m.on_watch_result(a, Err(WatchError::NoSpace));
  assert!(m.has_coverage_deficit(scope(1)));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(2),
  );
  // The book entry is cleared — a later re-signal finds nothing — but the
  // clear stands a covering Rescan, so the darkness is not discharged silently.
  assert!(
    !m.has_coverage_deficit(scope(1)),
    "the removal clears the book entry"
  );
  assert!(!m.resignal_coverage_deficits(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    2,
    "the Removed AND its covering Rescan: {events:?}"
  );
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["a"]));
  assert!(
    events[1].kind().is_rescan(),
    "the emptying stands a covering Rescan a filtered sub can see"
  );
  assert_eq!(events[1].location(), &Location::new());
  assert!(
    events[1].epoch() > events[0].epoch(),
    "epoch-bumped, not a replay"
  );
  m.assert_invariants();
}

/// The R13 flagship at the INTEREST/FILTER lens — the closest faithful
/// equivalent to a genuine descending umbrella regression (the umbrella's
/// real-kernel harness cannot inject a per-directory arm failure, and its
/// `FakeSource` sits ABOVE the deficit machinery; see the return note). A real
/// `Modified`-only subscription drives the exact defect sequence: a child arm
/// fails — its opening `Rescan` IS delivered (Rescans bypass the filter); a
/// `Modified` beneath the now-dark child is lost (never recorded — the point);
/// the child's `Removed` arrives. That `Removed` is interest-filtered — the
/// `Modified`-only consumer never sees it — so it cannot account for the lost
/// `Modified`. The emptying must instead stand a covering `Rescan`, which the
/// filter cannot suppress, so the consumer re-reads and a sync here is
/// dominated, never a false `Delivered`. Fails on old: the `Removed` cleared
/// the hole silently, the filtered consumer received NOTHING after the opening
/// `Rescan`, and the lost `Modified` — which postdates it — went uncovered.
#[test]
fn a_removed_over_a_hole_reaches_a_modified_only_subscription() {
  let mut m = per_dir();
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

  // A child directory appears (its Created is FILTERED from delivery) and arms.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the Created is filtered from a Modified-only delivery"
  );
  let a = drain_actions(&mut m)
    .iter()
    .find_map(|x| x.as_watch().map(|w| w.id()))
    .expect("the child arms despite the suppressed delivery");

  // The arm fails: the opening Rescan IS delivered (Rescans bypass the filter),
  // covering everything up to now — but not the change still to come.
  m.on_watch_result(a, Err(WatchError::NoSpace));
  let opening = drain_events(&mut m);
  assert_eq!(
    opening.len(),
    1,
    "the opening Rescan reaches even the filtered sub: {opening:?}"
  );
  assert!(opening[0].kind().is_rescan());
  let opening_epoch = opening[0].epoch();
  assert!(m.has_coverage_deficit(scope(1)));

  // (A Modified lands beneath the dark, unarmed child, AFTER the opening
  // Rescan — so that Rescan does not cover it. It is lost: no record reaches
  // the Monitor because the child is unwatched. That is the point.)

  // The child's Removed arrives. It is FILTERED (a Modified-only sub never sees
  // a Removed), so it cannot account for the lost Modified — the emptying must
  // stand a covering Rescan the filter cannot suppress.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(2),
  );
  let closing = drain_events(&mut m);
  assert!(
    closing.iter().all(|e| !e.kind().is_removed()),
    "the Removed is filtered — the Modified-only sub never sees it: {closing:?}"
  );
  let rescan = closing
    .iter()
    .find(|e| e.kind().is_rescan())
    .expect("the emptying stands a covering Rescan the filter cannot suppress");
  assert!(
    rescan.epoch() > opening_epoch,
    "the covering Rescan postdates the opening one — it covers the lost Modified"
  );
  // The book is clear, so a later sync's re-signal finds nothing: the covering
  // Rescan above is the sole (and sufficient) thing that dominates that sync.
  assert!(!m.has_coverage_deficit(scope(1)));
  assert!(!m.resignal_coverage_deficits(scope(1)));
  m.assert_invariants();
}

/// The general structural-drop carry (R13): a `drop_subtree` driven by a
/// structural record must not silently erase a deficit anchored in the dropped
/// subtree. A live child accrues a standing interior hole; its parent then
/// reports it `Removed`, dropping it. The drop erases the interior entry — but
/// the `Removed` is interest- and filter-subject, so the erasure stands a
/// covering `Rescan` (via `DeficitDischarge::CoveringRescan`) rather than
/// vanishing. Fails on old: the drop cleared the interior silently and a later
/// sync resolved a false `Delivered` over the darkness it hid.
#[test]
fn a_structural_removed_drop_of_a_deficit_anchor_stands_a_covering_rescan() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let (p, edge_epoch) = identityless_child_with_interior_deficit(&mut m, root, "p");
  assert!(m.has_coverage_deficit(scope(1)));
  assert!(m.is_watched(p));

  // The parent reports the child gone: the drop erases the interior hole
  // anchored at `p`. That erasure must carry — the Removed is filter-subject.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("p"))
      .with_is_dir(true),
    at(9),
  );
  assert!(!m.is_watched(p), "the reported-gone child is dropped");
  assert!(
    !m.has_coverage_deficit(scope(1)),
    "the interior hole is erased with its anchor"
  );
  let events = drain_events(&mut m);
  let rescan = events
    .iter()
    .find(|e| e.kind().is_rescan())
    .expect("the structural drop stands a covering Rescan for the erased interior");
  assert_eq!(rescan.location(), &Location::new());
  assert!(
    rescan.epoch() > edge_epoch,
    "epoch-bumped past the hole's edge Rescan"
  );
  m.assert_invariants();
}

/// A6 (collapse): past `DEFICIT_CAP` fine entries the book collapses to a
/// whole-scope marker — ONE root `Rescan` plus ONE root re-arm kick per
/// re-signal, whatever the failure count — and re-failures after the kicked
/// crawl re-record. Bounds memory and re-signal work under mass failure.
#[test]
fn a_mass_failure_collapses_the_book_to_one_root_resignal() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // DEFICIT_CAP + 1 refused arms: the 17th record collapses the book.
  for i in 0..=DEFICIT_CAP {
    let name = std::format!("d{i:02}");
    m.on_os_record(
      OsRecord::new(root, RecordKind::Created)
        .with_name(seg(&name))
        .with_is_dir(true),
      at(1 + i as u64),
    );
    let w = drain_actions(&mut m)
      .iter()
      .find_map(|a| a.as_watch().map(|w| w.id()))
      .expect("each discovered directory arms");
    m.on_watch_result(w, Err(WatchError::NoSpace));
    let _ = drain_events(&mut m);
  }
  assert!(m.has_coverage_deficit(scope(1)));

  // One root Rescan, one root kick — never one per hole.
  assert!(m.resignal_coverage_deficits(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "ONE root Rescan: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  let kicks = drain_actions(&mut m);
  let reads: Vec<ReqId> = kicks
    .iter()
    .filter_map(|a| a.as_enumerate().map(|e| e.req()))
    .collect();
  assert_eq!(reads.len(), 1, "ONE root re-arm kick: {kicks:?}");
  assert!(!m.has_coverage_deficit(scope(1)), "the marker is consumed");

  // The kicked crawl re-attempts everything; still-broken slots re-record
  // through their own failure edges (and collapse again past the cap).
  let listing: Vec<DirEntry> = (0..=DEFICIT_CAP)
    .map(|i| DirEntry::new(seg(&std::format!("d{i:02}")), FileKind::Dir))
    .collect();
  m.on_enumerate(reads[0], EnumerateResult::Ok(listing));
  let arms: Vec<WatchId> = drain_actions(&mut m)
    .iter()
    .filter_map(|a| a.as_watch().map(|w| w.id()))
    .collect();
  assert_eq!(arms.len(), 1 + DEFICIT_CAP, "every hole re-attempts");
  for w in arms {
    m.on_watch_result(w, Err(WatchError::NoSpace));
  }
  assert!(m.has_coverage_deficit(scope(1)), "re-failures re-record");
  let events = drain_events(&mut m);
  assert!(
    events.iter().all(|e| e.kind().is_rescan()),
    "failure edges and the closing Rescan only: {events:?}"
  );
  assert_eq!(
    events.last().map(|e| e.location()),
    Some(&Location::new()),
    "the lossy, fresh-armed window closes at the root: {events:?}"
  );
  m.assert_invariants();
}

/// A7 (hijack): a pure grow whose direct target is a COLD-arming node (a
/// discovery racing the grow) converts it re-arm-flavored — suppressing the
/// cold `Created`s — so the conversion site stands a `Rescan` and the window
/// closes with the closing `Rescan`. Fails on old: zero `Rescan`s — the
/// suppressed discovery was silent loss.
#[test]
fn a_grow_hijacking_a_cold_arming_node_stands_covering_rescans() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // The racing discovery: `a` is installed and still arming (cold).
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let a = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the discovered directory arms");
  let _ = drain_events(&mut m);

  // The grow lands on it: the conversion-site Rescan stands first.
  assert!(m.rearm_watch_subtree(a).is_started());
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "the conversion-site Rescan: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["a"]));

  // The post-arm read is re-arm-flavored: content is reconciled, never
  // announced — the file emits nothing, the directory installs suppressed.
  m.on_watch_result(a, Ok(()));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|x| x.as_enumerate().filter(|e| e.dir() == a).map(|e| e.req()))
    .expect("the converted node reads re-arm-flavored");
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("f"), FileKind::File),
      DirEntry::new(seg("b"), FileKind::Dir),
    ]),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the hijacked discovery is Created-suppressed"
  );
  let b = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the suppressed child directory is reconciled");
  m.on_watch_result(b, Ok(()));
  let b_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the cascade reads the child");
  m.on_enumerate(b_read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "the closing Rescan: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  m.assert_invariants();
}

/// A8 (the two fence gates): `coverage_settled` is false across a held move
/// source (until pairing or timeout) and across a latent coalesced cold read
/// (until its completion's escalation drains) — the exact windows where
/// `rearm_settled` reads true while a covering `Rescan` is still owed.
#[test]
fn coverage_settled_gates_holds_and_latent_cold_reads() {
  // Half 1: the hold, resolved by PAIRING.
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let _d = live_child_dir(&mut m, root, "d");
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  assert!(m.rearm_settled(scope(1)), "a hold is not counted work");
  assert!(!m.coverage_settled(scope(1)), "but it gates the fence");
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(20),
  );
  assert!(
    m.coverage_settled(scope(1)),
    "a clean pairing releases the gate"
  );
  m.assert_invariants();

  // Half 1b: the hold, resolved by TIMEOUT.
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let _d = live_child_dir(&mut m, root, "d");
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(10),
  );
  assert!(!m.coverage_settled(scope(1)));
  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  assert!(
    m.coverage_settled(scope(1)),
    "the stranded half's resolution releases the gate"
  );
  m.assert_invariants();

  // Half 2: the latent coalesced cold read.
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let d = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the discovered directory arms");
  m.on_watch_result(d, Ok(()));
  let cold = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the cold discovery read is in flight");
  let _ = drain_events(&mut m);
  // A located loss folds its re-arm into the in-flight cold read: the
  // kickoff is Coalesced and `rearm_settled` keeps reading true.
  m.on_overflow(SubtreeScope::new(d).into(), at(2));
  assert!(m.rearm_settled(scope(1)), "the folded obligation is latent");
  assert!(!m.coverage_settled(scope(1)), "but it gates the fence");
  let _ = drain_events(&mut m);
  // The completion escalates: a covering Rescan plus a COUNTED retry — the
  // gate hands over to `rearm_settled` with no unfenced instant.
  m.on_enumerate(cold, EnumerateResult::Ok(vec![]));
  assert!(!m.coverage_settled(scope(1)), "the escalation is counted");
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "the dirtied completion stands its Rescan: {events:?}"
  );
  let retry = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the escalation's counted retry");
  m.on_enumerate(retry, EnumerateResult::Ok(vec![]));
  assert!(m.coverage_settled(scope(1)), "the escalation drained");
  m.assert_invariants();
}

/// A9 (teardown GC): every new map — bridge flags, deficit book, held
/// counts, latent reads — is reclaimed with its scope, so a torn-down scope
/// leaves no residue and a fresh registration starts clean. (The recount and
/// anchor-liveness properties themselves run inside `assert_invariants`,
/// exercised by the storm and by every cell here.)
#[test]
fn teardown_reclaims_all_barrier_bookkeeping() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // A standing hole, a held source, and a latent cold read, all at once.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let a = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("a arms");
  m.on_watch_result(a, Err(WatchError::NoSpace));
  let _d = live_child_dir(&mut m, root, "d");
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("c"))
      .with_is_dir(true),
    at(3),
  );
  let c = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("c arms");
  m.on_watch_result(c, Ok(()));
  let _ = drain_actions(&mut m);
  m.on_overflow(SubtreeScope::new(c).into(), at(4));
  assert!(m.has_coverage_deficit(scope(1)));
  assert!(!m.coverage_settled(scope(1)));

  m.unregister_root(scope(1));
  assert!(!m.has_coverage_deficit(scope(1)));
  assert!(
    m.coverage_settled(scope(1)),
    "a dead scope is trivially settled"
  );
  assert!(!m.resignal_coverage_deficits(scope(1)));
  m.assert_invariants();
}

/// A10 (organic pure-grow heal): a clean grow crawl that re-installs a
/// standing hole's slot closes its window with the closing `Rescan` — the
/// heal-clear edge sets BOTH bits itself, because the loss fact travels with
/// the book entry, not with a sticky `saw_rescan`. Contrast A2 (the same
/// grow with no hole emits nothing). Fails on old: the clean crawl
/// re-installs suppressed and emits NOTHING — the hole's dark interval is
/// never covered.
#[test]
fn an_organic_grow_healing_a_hole_emits_the_closing_rescan() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  // The hole: discovery installs `a`, the kernel refuses the watch.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let a1 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the discovered directory arms");
  m.on_watch_result(a1, Err(WatchError::NoSpace));
  let _ = drain_events(&mut m);
  assert!(m.has_coverage_deficit(scope(1)));

  // An otherwise-clean grow reaches the hole: no Rescan of its own, but the
  // slot re-install is the heal edge.
  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the grow re-arm-enumerates");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  let a2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the hole's slot re-installs");
  m.on_watch_result(a2, Ok(()));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the healed slot re-arm-enumerates");
  assert!(
    drain_events(&mut m).is_empty(),
    "nothing is announced mid-window"
  );
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    1,
    "the heal window closes with the closing Rescan: {events:?}"
  );
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  assert!(!m.has_coverage_deficit(scope(1)), "the hole is gone");
  m.assert_invariants();
}

/// Installs a live child directory `name` under `parent` whose interior
/// deficit is then opened and stood: a located overflow re-arms it and its
/// reads exhaust the bounded retries, leaving the standing edge `Rescan` and
/// the recorded interior hole. The child was RECORD-installed, so it carries
/// no identity (as inotify-compiled records never do) — every later crawl
/// diff over the parent drops and rebuilds it. Returns the child's `WatchId`
/// and the standing edge `Rescan`'s epoch; events and actions are drained.
fn identityless_child_with_interior_deficit(
  m: &mut Monitor,
  parent: WatchId,
  name: &str,
) -> (WatchId, Epoch) {
  let child = live_child_dir(m, parent, name);
  m.on_overflow(SubtreeScope::new(child).into(), at(2));
  for round in 0..=REARM_MAX_RETRIES {
    let req = drain_actions(m)
      .iter()
      .find_map(|x| {
        x.as_enumerate()
          .filter(|e| e.dir() == child)
          .map(|e| e.req())
      })
      .unwrap_or_else(|| panic!("round {round}: a re-arm read is outstanding"));
    m.on_enumerate(req, EnumerateResult::Failed(IoClass::Permission));
  }
  assert!(m.rearm_settled(m.scope_of(child).unwrap()));
  assert!(m.has_coverage_deficit(m.scope_of(child).unwrap()));
  let edge_epoch = drain_events(m)
    .iter()
    .filter(|e| e.kind().is_rescan())
    .map(|e| e.epoch())
    .max()
    .expect("the exhaustion stood an edge Rescan");
  let _ = drain_actions(m);
  (child, edge_epoch)
}

/// The organic-drop carry (fail-on-old): a deficit whose ANCHOR node a clean
/// crawl drops must not be erased without a trace. A record-installed
/// directory has no identity, so every crawl over its parent drops and
/// rebuilds it (`identity_matches` cannot confirm survival). When such a
/// node anchors a standing interior hole and the darkness heals on disk
/// before the crawl, the erased entry leaves a PURE grow window with no
/// `saw_rescan` and an empty book — the old code emitted no closing `Rescan`
/// and the next sync resolved a false `Delivered` over whatever landed in
/// the dark interval. The fix re-anchors the erased loss at the surviving
/// parent slot, which the crawl's own re-install heals through the
/// `install_child` interlock: the window must end with a closing `Rescan`
/// (or a still-recorded deficit).
#[test]
fn a_crawl_drop_of_a_deficit_anchor_carries_the_loss() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let (_p, edge_epoch) = identityless_child_with_interior_deficit(&mut m, root, "p");

  // (A change lands under the dark, unarmed interior of `p`; then the disk
  // heals. Neither produces a record — that is the point.)

  // An unrelated PURE set-cover grow crawls the parent: the diff cannot
  // confirm the identity-less `p`, drops it — erasing the interior entry —
  // and rebuilds the slot `Created`-suppressed.
  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the grow re-arm-enumerates the parent");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("p"), FileKind::Dir).with_node(ident(7)),
    ]),
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "the suppressed rebuild keeps the window open — no fence settles here"
  );
  let p2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the dropped slot re-installs");
  m.on_watch_result(p2, Ok(()));
  // The healed interior reads clean, listing the gap directory the dark
  // interval hid; its install is `Created`-suppressed like the rest.
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == p2).map(|e| e.req()))
    .expect("the rebuilt directory re-arm-enumerates");
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  let g = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the gap directory installs");
  m.on_watch_result(g, Ok(()));
  let g_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == g).map(|e| e.req()))
    .expect("the gap directory re-arm-enumerates");
  m.on_enumerate(g_read, EnumerateResult::Ok(vec![]));

  // The settle edge. Honesty demands the erased darkness leave a trace a
  // sync must observe: a closing Rescan ahead of any cookie, or a deficit
  // still recorded for the dispatch re-signal. The old code had neither.
  assert!(m.rearm_settled(scope(1)));
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_rescan()) || m.has_coverage_deficit(scope(1)),
    "an organically erased deficit must close with a Rescan or stay recorded: {events:?}"
  );
  // The carry's exact shape: the re-anchored slot heals through the install
  // interlock, so the window closes with ONE root-located Rescan strictly
  // dominating the edge, and the book is empty.
  assert_eq!(events.len(), 1, "{events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  assert!(events[0].epoch() > edge_epoch);
  assert!(!m.has_coverage_deficit(scope(1)));
  m.assert_invariants();
}

/// The carry's overreach guard (the A2 companion): a crawl that drops and
/// rebuilds an identity-unconfirmable child with NO recorded deficit under
/// it owes nothing. The carry fires only on an ACTUAL erasure, so a pure
/// grow over healthy record-installed coverage still emits NOTHING and no
/// phantom deficit appears.
#[test]
fn a_crawl_rebuild_of_a_deficit_free_child_emits_nothing() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let _p = live_child_dir(&mut m, root, "p");

  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the grow re-arm-enumerates the parent");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("p"), FileKind::Dir).with_node(ident(7)),
    ]),
  );
  let p2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the dropped slot re-installs");
  m.on_watch_result(p2, Ok(()));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == p2).map(|e| e.req()))
    .expect("the rebuilt directory re-arm-enumerates");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  assert!(
    drain_events(&mut m).is_empty(),
    "a deficit-free rebuild owes nothing — no Rescan, no Created"
  );
  assert!(
    !m.has_coverage_deficit(scope(1)),
    "and books no phantom hole"
  );
  m.assert_invariants();
}

/// The carry when the crawl does NOT rebuild the slot (the name vanished
/// from the listing): the loss fact stays booked at the surviving parent —
/// a sync dispatched before the in-flight `Removed` lands re-signals it —
/// and the `Removed`'s arrival clears the re-anchored carry AND stands a
/// covering `Rescan` (the removal is filter-subject, so a `Modified`-only sub
/// that never saw it still learns the darkness ended). Fails on old: the
/// clear was silent, so that filtered sub's next sync resolved a false
/// `Delivered`.
#[test]
fn a_crawl_drop_without_rebuild_keeps_the_loss_booked() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let (_p, _edge) = identityless_child_with_interior_deficit(&mut m, root, "p");

  // The grow's crawl no longer lists `p`: the anchor drops with nothing
  // installed in its place, and the window settles clean.
  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the grow re-arm-enumerates the parent");
  m.on_enumerate(rearm, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(scope(1)));
  assert!(
    drain_events(&mut m).is_empty(),
    "the vanished subtree owes no Rescan of its own"
  );
  assert!(
    m.has_coverage_deficit(scope(1)),
    "the erased interior re-anchored at the parent slot"
  );

  // The vanish's own record clears the re-anchored carry — and, because that
  // Removed is interest- and filter-subject, the clear stands a covering
  // Rescan so a Modified-only sub that never saw the Removed still learns.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("p"))
      .with_is_dir(true),
    at(3),
  );
  assert!(!m.has_coverage_deficit(scope(1)));
  assert!(!m.resignal_coverage_deficits(scope(1)));
  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    2,
    "the Removed AND its covering Rescan: {events:?}"
  );
  assert!(events[0].kind().is_removed());
  assert!(events[1].kind().is_rescan());
  assert_eq!(events[1].location(), &Location::new());
  assert!(events[1].epoch() > events[0].epoch());
  m.assert_invariants();
}

// ---------------------------------------------------------------------------
// Same-transport widen: `widen_root` + the adoption tripwire.
// ---------------------------------------------------------------------------

/// A live, idle descending root with one armed, idle child directory `kid`
/// (identity 70) — the old world every widen cell adopts.
fn widen_base(m: &mut Monitor, s: ScopeId) -> (WatchId, WatchId) {
  let root = live_root_idle(m, s);
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("kid"))
      .with_is_dir(true)
      .with_node(ident(70)),
    at(1),
  );
  let kid = arm_named_child(m, root, "kid");
  let _ = drain_events(m);
  (root, kid)
}

/// Arms the queued child watch `(parent, name)` and settles its cold read.
fn arm_named_child(m: &mut Monitor, parent: WatchId, name: &str) -> WatchId {
  let id = drain_actions(m)
    .iter()
    .filter_map(|a| a.as_watch())
    .find(|c| {
      c.target()
        .as_child()
        .is_some_and(|ch| ch.parent() == parent && ch.name().as_str() == name)
    })
    .map(|c| c.id())
    .expect("the child watch was queued");
  m.on_watch_result(id, Ok(()));
  let boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == id).map(|e| e.req()))
    .expect("the child cold read was queued");
  m.on_enumerate(boot, EnumerateResult::Ok(Vec::new()));
  id
}

/// The outstanding enumerate request reading `dir`.
fn read_of(m: &mut Monitor, dir: WatchId) -> ReqId {
  drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == dir).map(|e| e.req()))
    .expect("the read was queued")
}

#[test]
fn widen_root_depth_one_splices_without_touching_the_old_subtree() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);

  // Epoch baseline: the widen must not dominate anything after this.
  m.on_os_record(
    OsRecord::new(old_root, RecordKind::Created).with_name(seg("pre.txt")),
    at(2),
  );
  let pre = drain_events(&mut m).pop().expect("pre-widen delivery");
  assert!(pre.kind().is_created());
  assert_eq!(pre.location(), &loc(&["pre.txt"]));

  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1))),
    Some(reserved)
  );
  m.assert_invariants();

  // The commit itself: no action (a depth-one widen mints no chain and the new
  // root's arm is the caller's), no event, no epoch bump, no counted work, and
  // the old subtree bit-identical (both watches live, no Unwatch queued). The
  // UNVERIFIED adoption is the one thing standing: it holds the BARRIER
  // predicate (never the re-arm one) until the tail's read confirms the edge.
  assert!(
    drain_actions(&mut m).is_empty(),
    "the splice queues nothing"
  );
  assert!(drain_events(&mut m).is_empty(), "the splice emits nothing");
  assert!(m.rearm_settled(s), "the splice counts no re-arm work");
  assert!(
    !m.coverage_settled(s),
    "the unverified adoption holds the barrier"
  );
  assert!(m.is_watched(old_root) && m.is_watched(kid));

  // Old-subtree deliveries reconstruct through the adopted edge at the SAME
  // epoch — continuity, not domination.
  m.on_os_record(
    OsRecord::new(old_root, RecordKind::Created).with_name(seg("x.txt")),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(kid, RecordKind::Created).with_name(seg("y.txt")),
    at(3),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2, "{events:?}");
  assert_eq!(events[0].location(), &loc(&["b", "x.txt"]));
  assert_eq!(events[1].location(), &loc(&["b", "kid", "y.txt"]));
  assert_eq!(
    events[0].epoch(),
    pre.epoch(),
    "no reconciliation generation bump"
  );

  // The replayed pre-arm brings the new root live and starts its COLD read;
  // its confirming completion releases the barrier.
  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  assert!(
    m.coverage_settled(s),
    "positive verification releases the barrier"
  );
  m.assert_invariants();
}

#[test]
fn widen_root_deep_chain_arms_top_down_and_adopts_at_the_tail() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid) = widen_base(&mut m, s);

  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(
      s,
      reserved,
      vec![seg("b"), seg("c"), seg("d")],
      Some(ident(1))
    ),
    Some(reserved)
  );
  m.assert_invariants();

  // Exactly the two connector arms, top-down: (reserved, "b") then (b, "c").
  let actions = drain_actions(&mut m);
  let watches: Vec<_> = actions.iter().filter_map(|a| a.as_watch()).collect();
  assert_eq!(watches.len(), 2, "{actions:?}");
  let b = watches[0].id();
  assert!(
    watches[0]
      .target()
      .as_child()
      .is_some_and(|ch| ch.parent() == reserved && ch.name().as_str() == "b")
  );
  assert!(
    watches[1]
      .target()
      .as_child()
      .is_some_and(|ch| ch.parent() == b && ch.name().as_str() == "c")
  );
  assert!(drain_events(&mut m).is_empty());

  // The adopted edge sits at the tail: deliveries reconstruct the full chain.
  m.on_os_record(
    OsRecord::new(old_root, RecordKind::Created).with_name(seg("f")),
    at(2),
  );
  let events = drain_events(&mut m);
  assert_eq!(events[0].location(), &loc(&["b", "c", "d", "f"]));
  m.assert_invariants();
}

#[test]
fn adoption_confirmed_by_a_matching_listing_stays_silent() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);

  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
      DirEntry::new(seg("fresh"), FileKind::Dir).with_node(ident(9)),
    ]),
  );
  // Cold discovery announces the newly covered ground as state facts; the
  // adopted slot is REUSED (no rebuild, no rescan) and its interior untouched.
  let events = drain_events(&mut m);
  assert!(events.iter().all(|e| e.kind().is_created()), "{events:?}");
  assert!(m.is_watched(old_root) && m.is_watched(kid));
  let actions = drain_actions(&mut m);
  let armed: Vec<_> = actions.iter().filter_map(|a| a.as_watch()).collect();
  assert_eq!(
    armed.len(),
    1,
    "only the genuinely new slot arms: {actions:?}"
  );
  assert!(
    armed[0]
      .target()
      .as_child()
      .is_some_and(|ch| ch.name().as_str() == "fresh")
  );
  m.assert_invariants();
}

#[test]
fn adoption_name_vanished_escalates_the_scope_root() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);

  // The adopted name is absent from a COMPLETE listing: the subtree's true
  // path is unknowable — one covering root Rescan plus a counted re-arm.
  m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "{events:?}"
  );
  assert!(!m.rearm_settled(s), "the escalation is counted work");
  m.assert_invariants();
}

#[test]
fn adoption_identity_mismatch_escalates_the_scope_root() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);

  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(99)),
    ]),
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "a positively different object at the adopted slot is a stale edge: {events:?}"
  );
  m.assert_invariants();
}

#[test]
fn adoption_after_a_recorded_death_stands_a_located_rescan() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));

  // The adopted subtree dies through its own records mid-window — with no
  // armed parent to mint the parent-side Removed.
  m.on_os_record(OsRecord::new(old_root, RecordKind::DeleteSelf), at(2));
  assert!(!m.is_watched(old_root));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);
  m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["b"])),
    "the unrecorded final teardown owes the vacated slot a re-read: {events:?}"
  );
  m.assert_invariants();
}

#[test]
fn adoption_slot_reoccupied_rescans_and_installs_the_new_object() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.on_os_record(OsRecord::new(old_root, RecordKind::DeleteSelf), at(2));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(100)),
    ]),
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["b"])),
    "{events:?}"
  );
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["b"])),
    "{events:?}"
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().filter_map(|a| a.as_watch()).any(|c| {
      c.target()
        .as_child()
        .is_some_and(|ch| ch.parent() == reserved && ch.name().as_str() == "b")
    }),
    "the new occupant arms through the ordinary reconcile: {actions:?}"
  );
  m.assert_invariants();
}

#[test]
fn a_partial_first_read_keeps_the_adoption_pending() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);

  // An incomplete first read must not silently confirm the edge: the bounded
  // retry (re-arm-flavored) re-checks, and its prune resolves the stale edge
  // through the crawl-rebuild machinery.
  m.on_enumerate(req, EnumerateResult::Partial(Vec::new()));
  let _ = drain_events(&mut m);
  let retry = read_of(&mut m, reserved);
  m.on_enumerate(retry, EnumerateResult::Ok(Vec::new()));
  assert!(
    !m.is_watched(old_root),
    "the vanished adopted edge is pruned, never silently trusted"
  );
  m.assert_invariants();
}

#[test]
fn widen_preserves_a_pending_move_across_the_commit() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);

  // A watched-directory source detaches-and-holds before the widen...
  m.on_os_record(
    OsRecord::new(old_root, RecordKind::MovedFrom)
      .with_name(seg("kid"))
      .with_is_dir(true)
      .with_cookie(cookie(5)),
    at(2),
  );
  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1))),
    Some(reserved)
  );
  assert!(m.is_watched(kid), "the held source rides across the widen");

  // ...and its destination pairs AFTER it, on the same transport, with both
  // sides reconstructed through the adopted chain.
  m.on_os_record(
    OsRecord::new(old_root, RecordKind::MovedTo)
      .with_name(seg("kid2"))
      .with_is_dir(true)
      .with_cookie(cookie(5)),
    at(3),
  );
  let events = drain_events(&mut m);
  let moved = events
    .iter()
    .find(|e| e.kind().is_moved())
    .expect("the pair resolves as a Moved");
  assert_eq!(moved.location(), &loc(&["b", "kid2"]));
  assert_eq!(moved.kind().moved_from(), Some(&loc(&["b", "kid"])));
  m.assert_invariants();
}

#[test]
fn widen_preserves_the_deficit_book_and_its_resignal_addressing() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid) = widen_base(&mut m, s);

  // A refused arm records level-persistent darkness under the OLD world.
  m.on_os_record(
    OsRecord::new(old_root, RecordKind::Created)
      .with_name(seg("dark"))
      .with_is_dir(true),
    at(2),
  );
  let dark = drain_actions(&mut m)
    .iter()
    .filter_map(|a| a.as_watch())
    .find(|c| {
      c.target()
        .as_child()
        .is_some_and(|ch| ch.name().as_str() == "dark")
    })
    .map(|c| c.id())
    .expect("the dark slot's arm was queued");
  m.on_watch_result(dark, Err(WatchError::NoSpace));
  let _ = drain_events(&mut m);
  assert!(m.has_coverage_deficit(s));

  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  assert!(
    m.has_coverage_deficit(s),
    "the old world's standing darkness survives — nothing of it was discharged"
  );
  assert!(m.resignal_coverage_deficits(s));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["b", "dark"])),
    "the re-signal addresses the slot through the adopted chain: {events:?}"
  );
  m.assert_invariants();
}

#[test]
fn widen_refuses_kr_unknown_and_empty_chains() {
  let mut m = kernel_recursive();
  let s = scope(1);
  let root = m.register_root(s, Interest::all());
  m.on_watch_result(root, Ok(()));
  let _ = drain_actions(&mut m);
  let reserved = m.reserve_watch_id();
  assert_eq!(m.widen_root(s, reserved, vec![seg("b")], None), None);

  let mut m = per_dir();
  let reserved = m.reserve_watch_id();
  assert_eq!(m.widen_root(scope(9), reserved, vec![seg("b")], None), None);

  let s = scope(1);
  let _root = live_root_idle(&mut m, s);
  let reserved = m.reserve_watch_id();
  assert_eq!(m.widen_root(s, reserved, Vec::new(), None), None);
  let other = m.reserve_watch_id();
  assert_ne!(reserved, other, "reservations are never reused");
}

#[test]
fn rebind_after_a_depth_one_widen_purges_the_marker() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));

  // A D1 rebind of the widened scope keeps the (new) root node; the adoption
  // marker keyed on it must die with the old world, and the rebound root's
  // re-arm-flavored rebuild proceeds without an adoption escalation.
  assert_eq!(m.rebind_root(s), Some(reserved));
  let _ = drain_events(&mut m);
  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);
  m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_rescan()),
    "no stale adoption escalation after the rebind: {events:?}"
  );
  m.assert_invariants();
}

#[test]
fn widen_while_the_old_root_is_enumerating_reconciles_the_late_read() {
  let mut m = per_dir();
  let s = scope(1);
  let old_root = live_root(&mut m, s);
  let boot = read_of(&mut m, old_root);

  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1))),
    Some(reserved)
  );

  // The outstanding old-world read survives the splice and reconciles under
  // the adopted node, addressed through the chain.
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("late"), FileKind::Dir).with_node(ident(4)),
    ]),
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["b", "late"])),
    "{events:?}"
  );
  m.assert_invariants();
}

#[test]
fn back_to_back_widens_keep_independent_adoption_markers() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid) = widen_base(&mut m, s);

  // Two widens splice before either tail's first read resolves: one scope
  // carries TWO live adoption markers (on distinct, freshly-minted tails).
  let first = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, first, vec![seg("b")], Some(ident(1))),
    Some(first)
  );
  let second = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, second, vec![seg("mid")], Some(ident(1))),
    Some(second)
  );
  m.assert_invariants();

  // Deliveries reconstruct through BOTH adopted edges immediately.
  m.on_os_record(
    OsRecord::new(old_root, RecordKind::Created).with_name(seg("x.txt")),
    at(2),
  );
  let events = drain_events(&mut m);
  assert_eq!(events[0].location(), &loc(&["mid", "b", "x.txt"]));

  // Each marker resolves independently and silently on its own confirming
  // read — inner first, then outer.
  m.on_watch_result(second, Ok(()));
  let outer = read_of(&mut m, second);
  m.on_enumerate(
    outer,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("mid"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  m.on_watch_result(first, Ok(()));
  let inner = read_of(&mut m, first);
  m.on_enumerate(
    inner,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_rescan()),
    "both confirmations are silent: {events:?}"
  );
  assert!(m.is_watched(old_root));
  m.assert_invariants();
}

#[test]
fn an_unverified_adoption_holds_the_barrier_through_retries() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  assert!(!m.coverage_settled(s), "unverified from the commit instant");

  // An INCOMPLETE first read must not release the barrier: the marker stays
  // (the retry re-checks) and the bounded retry is itself counted work.
  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);
  m.on_enumerate(req, EnumerateResult::Partial(Vec::new()));
  let _ = drain_events(&mut m);
  assert!(!m.coverage_settled(s), "an incomplete read keeps the hold");

  // The incomplete read queued BOTH the bounded retry and the cascade into
  // the adopted child; settle that cascade first, then let the retry confirm.
  let actions = drain_actions(&mut m);
  let retry = actions
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == reserved)
        .map(|e| e.req())
    })
    .expect("the bounded retry was queued");
  let cascade = actions
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == old_root)
        .map(|e| e.req())
    })
    .expect("the incomplete read cascades into the adopted child");
  m.on_enumerate(cascade, EnumerateResult::Ok(Vec::new()));
  assert!(!m.coverage_settled(s), "the marker still holds");

  // The retry (re-arm-flavored) confirms the survivor by identity and hands
  // the obligation to the counted rearm cascade; the barrier releases only
  // once THAT quiesces — never before the edge is positively verified.
  m.on_enumerate(
    retry,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  assert!(m.is_watched(old_root), "the confirmed survivor is kept");
  assert!(
    !m.coverage_settled(s),
    "the survivor's cascaded re-arm is still counted"
  );
  let down = read_of(&mut m, old_root);
  m.on_enumerate(down, EnumerateResult::Ok(Vec::new()));
  let _ = drain_events(&mut m);
  assert!(
    m.coverage_settled(s),
    "verification plus a quiesced cascade releases the barrier"
  );
  m.assert_invariants();
}

#[test]
fn a_mismatch_releases_the_barrier_only_with_its_escalation_standing() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);

  // The adopted name vanished: the marker resolves WITH the root Rescan
  // emitted and the counted root re-arm installed — so the scope stays
  // unsettled past the marker's removal, and by the time it settles the
  // covering signal is already ahead of any cookie.
  m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "{events:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "the escalation's counted re-arm holds the barrier"
  );
  m.assert_invariants();
}

#[test]
fn a_connector_reconciled_away_stands_the_closing_rescan() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("a"), seg("b")], Some(ident(1))),
    Some(reserved)
  );
  let _ = drain_actions(&mut m);
  m.on_watch_result(reserved, Ok(()));
  let req = read_of(&mut m, reserved);

  // The dark window replaced the connector with a FILE: the widened root's
  // cold listing reconciles the slot, which tears down the connector, the
  // adopted old tree, and the pending marker in one drop — an erased
  // UNVERIFIED adoption, discharged like an erased deficit: the settle
  // flush's closing root Rescan stands, loudly, where silence would have
  // disarmed every old watch with no signal at all.
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::File)]),
  );
  assert!(!m.is_watched(old_root) && !m.is_watched(kid));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "the erased adoption owes the closing root Rescan: {events:?}"
  );
  assert!(
    m.coverage_settled(s),
    "with the signal standing, the barrier honestly settles"
  );
  m.assert_invariants();
}

#[test]
fn an_exhausted_tail_read_hands_the_marker_to_the_deficit() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.on_watch_result(reserved, Ok(()));

  // A permanently unreadable widened root: the bounded retries exhaust. The
  // marker must hand off to the standing `Rescan` + interior deficit — the
  // barrier then resolves DEGRADED (the dispatch re-signal covers the cookie)
  // instead of wedging forever on a read that will never complete. The tail
  // keeps answering Partial; every cascaded read into the (readable) adopted
  // subtree completes clean.
  for _ in 0..3 {
    assert!(!m.coverage_settled(s), "unresolved while retries remain");
    let mut fed_tail = false;
    for (req, dir) in drain_actions(&mut m)
      .iter()
      .filter_map(|a| a.as_enumerate().map(|e| (e.req(), e.dir())))
    {
      if dir == reserved {
        m.on_enumerate(req, EnumerateResult::Partial(Vec::new()));
        fed_tail = true;
      } else {
        m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
      }
    }
    assert!(fed_tail, "the tail read is outstanding");
  }
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "the exhaustion's covering Rescan stands: {events:?}"
  );
  // The incomplete completions cascaded COUNTED re-arms into the adopted
  // subtree — bounded, completable work (the adopted dirs are readable);
  // drain it. The marker itself is gone: nothing un-completable remains.
  for _ in 0..8 {
    let reads: Vec<ReqId> = drain_actions(&mut m)
      .iter()
      .filter_map(|a| a.as_enumerate().map(|e| e.req()))
      .collect();
    if reads.is_empty() {
      break;
    }
    for req in reads {
      m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
    }
  }
  let _ = drain_events(&mut m);
  assert!(
    m.coverage_settled(s),
    "the exhausted marker no longer wedges the barrier: rearm_settled={} deficit={}",
    m.rearm_settled(s),
    m.has_coverage_deficit(s),
  );
  assert!(
    m.has_coverage_deficit(s),
    "the darkness is booked for the dispatch re-signal"
  );
  m.assert_invariants();
}
