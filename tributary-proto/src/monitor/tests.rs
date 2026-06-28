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
/// A `MovedFrom` in one scope must never pair with a `MovedTo` in another: the
/// source resolves as `Removed`, the destination as `Created`, with no bogus move.
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
  assert_eq!(events.len(), 2, "no bogus pair across roots");
  assert!(events.iter().all(|e| !e.kind().is_moved()));
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_removed() && e.scope() == scope(1) && e.location() == &loc(&["x"])),
    "source resolves as Removed in its own scope"
  );
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_created() && e.scope() == scope(2) && e.location() == &loc(&["y"])),
    "destination resolves as Created in its own scope"
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

// ── A renamed watched directory must not keep stale-path coverage ──

/// Renaming a watched directory drops its now-stale watch subtree (recursively)
/// and rescans the new location, instead of leaving children pinned to the old
/// parent/name edge.
#[test]
fn watched_dir_rename_drops_stale_subtree_and_rescans() {
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
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e"])),
    "the relocated subtree is rescanned under its new path"
  );
  assert!(!m.is_watched(w_d), "old dir node dropped");
  assert!(!m.is_watched(w_g), "grandchild node dropped too");
  let actions = drain_actions(&mut m);
  assert!(actions.iter().any(|a| a.as_unwatch() == Some(w_d)));
  assert!(actions.iter().any(|a| a.as_unwatch() == Some(w_g)));
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
  let _ = drain_actions(&mut m); // the subtree-drop Unwatch(w_d)
  assert!(!m.is_watched(w_d));

  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created).with_name(seg("f.txt")),
    at(12),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "a record on the dropped old watch yields nothing (never the stale path)"
  );

  // Re-establishing the watch under the new name yields the correct path.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("e"))
      .with_is_dir(true),
    at(13),
  );
  let w_e = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.on_watch_result(w_e, Ok(()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  m.on_os_record(
    OsRecord::new(w_e, RecordKind::Created).with_name(seg("f.txt")),
    at(14),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert_eq!(
    events[0].location(),
    &loc(&["e", "f.txt"]),
    "child resolves under the new path"
  );
}

/// A watched directory moved out of the tree (unpaired source) drops its subtree
/// on timeout, not just emitting `Removed`.
#[test]
fn watched_dir_moved_out_drops_subtree_on_timeout() {
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
  assert!(m.is_watched(w_d), "still watched within the pairing window");

  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_removed());
  assert_eq!(events[0].location(), &loc(&["d"]));
  assert!(
    !m.is_watched(w_d),
    "moved-out watched dir's subtree is dropped"
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
