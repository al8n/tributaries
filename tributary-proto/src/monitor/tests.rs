use super::*;
use crate::{
  action::{StatTarget, WatchAck, WatchTarget},
  path::Segment,
  record::{DirEntry, FileKind, IoClass, StatEntry},
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
  let root = m
    .register_root(s, Interest::all())
    .expect("a fresh scope registers");
  let actions = drain_actions(m);
  assert!(
    actions
      .iter()
      .any(|a| a.as_watch().map(|c| c.id()) == Some(root))
  );
  m.ack_watch(root, Ok(WatchAck::Installed));
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
  let root = m
    .register_root(scope(1), Interest::all())
    .expect("a fresh scope registers");
  assert!(m.is_watched(root));
  assert_eq!(m.scope_of(root), Some(scope(1)));

  let actions = drain_actions(&mut m);
  assert_eq!(actions.len(), 1);
  let cmd = actions[0].as_watch().unwrap();
  assert_eq!(cmd.id(), root);
  assert_eq!(cmd.target(), &WatchTarget::Root(scope(1)));
}

/// A `ScopeId` that is already live is REFUSED, and refused strictly before the
/// first mutation — the whole Monitor is bit-identical across the call, through
/// both entry points and under a mask and profile that differ from the live
/// registration's. `ScopeId` is caller-minted, so the duplicate is reachable
/// from the public API rather than only from a Monitor bug.
#[test]
fn a_duplicate_live_scope_is_refused_without_mutating() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let before = std::format!("{m:?}");

  assert_eq!(
    m.register_root(scope(1), Interest::all()),
    None,
    "a live scope refuses a second registration"
  );
  assert_eq!(
    m.register_root_with_profile(scope(1), Interest::new(), Capabilities::new()),
    None,
    "…and through the profile form, which is where every mutation lives"
  );

  assert_eq!(
    std::format!("{m:?}"),
    before,
    "a refused registration mints no handle, consumes no attempt, queues nothing"
  );
  // Spelled out for the books the overwrite used to corrupt, so a regression
  // names the damage instead of handing back two Debug dumps to diff.
  assert_eq!(
    m.roots.get(&scope(1)),
    Some(&root),
    "the scope's root is still the first one"
  );
  assert_eq!(m.scope_interests.get(&scope(1)), Some(&Interest::all()));
  assert_eq!(m.scope_profiles.get(&scope(1)), Some(&m.capabilities));
  assert_eq!(
    m.rearm_pending.get(&scope(1)),
    None,
    "no re-arm-flavored birth was booked"
  );
  assert!(
    drain_actions(&mut m).is_empty(),
    "no watch was queued for the refused root"
  );
  m.assert_invariants();
}

/// The orphan cannot un-register the LIVE root, because the guard admits no
/// orphan. `drop_subtree` removes `roots[scope]` for ANY parentless node it
/// walks, so under an overwrite the first root's own teardown would take the
/// second one's registration with it — leaving a whole live tree standing under
/// a registration that no longer exists, with `location_of_checked` answering
/// `None` and every coverage signal silently no-op. Here the teardown ends the
/// scope honestly instead.
#[test]
fn a_refused_duplicate_leaves_no_orphan_to_unregister_the_live_root() {
  let mut m = per_dir();
  let first = live_root_idle(&mut m, scope(1));
  assert_eq!(m.register_root(scope(1), Interest::all()), None);
  assert_eq!(m.roots.get(&scope(1)), Some(&first));

  // Tear down the first root — the node the overwrite would have orphaned.
  m.on_os_record(OsRecord::new(first, RecordKind::Ignored), at(1));
  assert_eq!(
    m.roots.get(&scope(1)),
    None,
    "the scope's only root is gone with it"
  );
  assert!(
    m.nodes.values().all(|node| node.scope != scope(1)),
    "no node of the scope outlives its registration"
  );
  m.assert_invariants();
}

/// Invariant (B) has teeth. The duplicate is unreachable through the API now,
/// which is the point, so the second parentless node is open-coded exactly as
/// the overwrite produced it: `roots` re-pointed at a fresh root and the
/// incumbent left parentless and unregistered.
#[test]
#[should_panic(expected = "a parentless node is its scope's one registered root")]
fn assert_invariants_catches_a_second_parentless_root() {
  let mut m = per_dir();
  let first = live_root_idle(&mut m, scope(1));
  m.assert_invariants();

  let mut orphaned = m.nodes.get(&first).cloned().expect("the root is live");
  orphaned.children = BTreeSet::new();
  let second = m.reserve_watch_id();
  m.nodes.insert(second, orphaned);
  m.roots.insert(scope(1), second);
  m.assert_invariants();
}

#[test]
fn per_dir_watch_success_triggers_enumerate_after_arming() {
  let mut m = per_dir();
  let root = m
    .register_root(scope(1), Interest::all())
    .expect("a fresh scope registers");
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Ok(WatchAck::Installed));

  let actions = drain_actions(&mut m);
  assert_eq!(actions.len(), 1, "per-dir root should enumerate once armed");
  let cmd = actions[0].as_enumerate().unwrap();
  assert_eq!(cmd.dir(), root);
}

#[test]
fn kernel_recursive_watch_success_does_not_enumerate() {
  let mut m = kernel_recursive();
  let root = m
    .register_root(scope(1), Interest::all())
    .expect("a fresh scope registers");
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Ok(WatchAck::Installed));
  assert!(
    drain_actions(&mut m).is_empty(),
    "kernel-recursive backend must not descend"
  );
}

/// Re-staged on a POST-REGISTRATION cold read (42-10): a registration's own
/// crawl is `Created`-suppressed — the contract reports no inventory for state
/// that merely pre-existed the grant — so the cold-discovery semantics this cell
/// is about now live at a directory the LIVE stream discovers, whose post-arm
/// read is cold. Every assertion is otherwise the original, re-anchored one
/// level down.
#[test]
fn enumerate_emits_created_and_descends_into_dirs() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let d = discovered_child_dir(&mut m, root, "d");
  let read = armed_read(&mut m, d);

  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a.txt"), FileKind::File),
      DirEntry::new(seg("sub"), FileKind::Dir),
    ]),
  );

  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(events.iter().all(|e| e.kind().is_created()));
  let locations: Vec<&Location> = events.iter().map(|e| e.location()).collect();
  assert!(locations.contains(&&loc(&["d", "a.txt"])));
  assert!(locations.contains(&&loc(&["d", "sub"])));

  let actions = drain_actions(&mut m);
  assert_eq!(
    actions.len(),
    1,
    "only the directory should get a child watch"
  );
  let child = actions[0].as_watch().unwrap();
  assert_eq!(child.target(), &WatchTarget::child(d, seg("sub")));
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
  let root = m
    .register_root(scope(1), Interest::all())
    .expect("a fresh scope registers");
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Err(WatchError::NoSpace));

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

  m.ack_watch(child_id, Err(WatchError::Gone));
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
  m.ack_watch(child, Ok(WatchAck::Installed));
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
  m.ack_watch(w_a2, Ok(WatchAck::Installed));
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

/// Re-staged on a POST-REGISTRATION cold read (42-10): the delivery whose path
/// is reconstructed must be one the contract still makes, and a registration's
/// own crawl announces nothing.
#[test]
fn path_reconstruction_walks_to_root() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let a_id = discovered_child_dir(&mut m, root, "a");
  let req_a = armed_read(&mut m, a_id);

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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("g"))
      .with_is_dir(true),
    at(2),
  );
  let w_g = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.ack_watch(w_g, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("x"))
      .with_is_dir(true),
    at(2),
  );
  let w_x = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.ack_watch(w_x, Ok(WatchAck::Installed));
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
  m.ack_watch(w_a, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("b"))
      .with_is_dir(true),
    at(2),
  );
  let w_b = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.ack_watch(w_b, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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

// ── The per-scope bound on parked rename halves ──

/// Reads the parked population of `s` the way the bound does — from membership,
/// so the assertion cannot agree with a counter that drifted from the store.
fn parked_halves(m: &Monitor, s: ScopeId) -> usize {
  m.pending_moves
    .range((s, FIRST_COOKIE)..)
    .take_while(|((half_scope, _), _)| *half_scope == s)
    .count()
}

/// Moves watched directories `d{i}` out of `parent` under cookie `i + 1`, one per
/// index in `range`, returning the watch each source held. Every half is parked
/// under one `now`, so all of them are inside their pairing window together — and
/// the bound is re-read after each one, so the claim is that it held throughout
/// rather than only where the burst happened to stop.
fn burst_moved_from(
  m: &mut Monitor,
  parent: WatchId,
  range: core::ops::Range<u64>,
) -> Vec<(WatchId, Location)> {
  let scope = m.scope_of(parent).expect("a live burst parent");
  range
    .map(|i| {
      let name = std::format!("d{i}");
      let w = live_child_dir(m, parent, &name);
      m.on_os_record(
        OsRecord::new(parent, RecordKind::MovedFrom)
          .with_name(seg(&name))
          .with_cookie(cookie(i + 1))
          .with_is_dir(true),
        at(10),
      );
      assert!(
        parked_halves(m, scope) <= PENDING_MOVE_CAP,
        "the bound holds at every step of the burst"
      );
      (w, loc(&[&name]))
    })
    .collect()
}

/// A scope's parked halves are BOUNDED. Each unpaired cookied source retains a
/// `PendingMove` and the detached subtree it holds until its window elapses, so an
/// unbounded burst would retain both without limit; at the cap a further source is
/// refused, and refusal is exactly unpairability — it tears the held subtree down
/// and degrades to the `Removed` the unpairable path owes.
#[test]
fn burst_of_rename_sources_is_bounded_per_scope() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  let admitted = burst_moved_from(&mut m, root, 0..PENDING_MOVE_CAP as u64);
  assert_eq!(parked_halves(&m, scope(1)), PENDING_MOVE_CAP);
  for (w, _) in &admitted {
    assert!(
      m.is_watched(*w),
      "an admitted source is held for its window"
    );
  }
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // One more unique cookie, with the scope full.
  let refused = live_child_dir(&mut m, root, "over");
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("over"))
      .with_cookie(cookie(PENDING_MOVE_CAP as u64 + 1))
      .with_is_dir(true),
    at(10),
  );

  assert_eq!(
    parked_halves(&m, scope(1)),
    PENDING_MOVE_CAP,
    "the refused source is not parked, so the bound holds"
  );
  assert!(
    !m.is_watched(refused),
    "a source that will never pair does not keep holding its subtree"
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().any(|a| a.as_unwatch() == Some(refused)),
    "the torn-down subtree gives its watch back"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_removed() && e.location() == &loc(&["over"])),
    "the refusal degrades to the unpairable source's `Removed`: {events:?}"
  );

  // The refusal is a decision about ONE record, taken before anything was mutated
  // on its behalf: the halves already parked are untouched and still pair.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("moved"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().moved_from() == Some(&admitted[0].1)),
    "an admitted half still pairs after the refusal: {events:?}"
  );
}

/// A cookie already parked is a REPLACEMENT, so the bound is not asked of it: it
/// rewrites one key rather than adding one, leaving the high-water mark where it
/// was. Refusing it would keep the half the replacement should displace, and pair
/// that half's destination against a source the rename never had.
#[test]
fn same_cookie_source_is_admitted_at_the_bound() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  let admitted = burst_moved_from(&mut m, root, 0..PENDING_MOVE_CAP as u64);
  assert_eq!(parked_halves(&m, scope(1)), PENDING_MOVE_CAP);
  let (displaced_watch, displaced_from) = admitted[0].clone();
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // The full scope's own first cookie, re-used at a different name.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("again"))
      .with_cookie(cookie(1)),
    at(11),
  );
  assert_eq!(
    parked_halves(&m, scope(1)),
    PENDING_MOVE_CAP,
    "a replacement neither grows the store nor is refused by the bound"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_removed() && e.location() == &displaced_from),
    "the displaced half resolves rather than being silently overwritten: {events:?}"
  );
  assert!(
    !m.is_watched(displaced_watch),
    "the displaced half's held subtree is torn down with it"
  );

  // The destination pairs with the REPLACEMENT's source, not the one it displaced.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("arrived"))
      .with_cookie(cookie(1)),
    at(12),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert_eq!(events[0].kind().moved_from(), Some(&loc(&["again"])));
  assert_eq!(events[0].location(), &loc(&["arrived"]));
}

/// The bound is per-SCOPE: one root's burst must not refuse another root's
/// renames, since the two share nothing but the store they are keyed in.
#[test]
fn the_bound_does_not_leak_between_scopes() {
  let mut m = per_dir();
  let root_a = live_root_idle(&mut m, scope(1));
  let root_b = live_root_idle(&mut m, scope(2));

  let _ = burst_moved_from(&mut m, root_a, 0..PENDING_MOVE_CAP as u64);
  let admitted_b = burst_moved_from(&mut m, root_b, 0..PENDING_MOVE_CAP as u64);
  assert_eq!(parked_halves(&m, scope(1)), PENDING_MOVE_CAP);
  assert_eq!(
    parked_halves(&m, scope(2)),
    PENDING_MOVE_CAP,
    "a full scope does not consume another scope's capacity"
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // Overfilling scope 1 refuses scope 1's source and nothing of scope 2's.
  let refused = live_child_dir(&mut m, root_a, "over");
  m.on_os_record(
    OsRecord::new(root_a, RecordKind::MovedFrom)
      .with_name(seg("over"))
      .with_cookie(cookie(PENDING_MOVE_CAP as u64 + 1))
      .with_is_dir(true),
    at(10),
  );
  assert!(!m.is_watched(refused));
  assert_eq!(parked_halves(&m, scope(1)), PENDING_MOVE_CAP);
  assert_eq!(parked_halves(&m, scope(2)), PENDING_MOVE_CAP);
  for (w, _) in &admitted_b {
    assert!(m.is_watched(*w), "scope 2's halves are untouched");
  }
}

// ── A teardown of a subtree that still EXISTS owes its cover unconditionally ──

/// A capacity refusal tears the source's subtree down while the directory still
/// exists and is mid-rename, so the dead handles keep carrying its records: a
/// same-batch `Modified` under the old subtree is discarded as an unrecognized
/// watch, and the destination — deliberately forgotten — arrives as a fresh
/// directory. Every signal the refusal does produce (the degraded `Removed`, the
/// destination's `Created`) is interest-subject, so a `Modified`-only subscription
/// learns of the loss only through the covering `Rescan`, which cannot wait on the
/// dropped subtree having erased a deficit: a fully-proven one erases nothing.
#[test]
fn a_refused_rename_source_covers_a_modified_only_subscriber() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());

  // Fill the scope so the next unique cookie is refused.
  let _ = burst_moved_from(&mut m, root, 0..PENDING_MOVE_CAP as u64);
  assert_eq!(parked_halves(&m, scope(1)), PENDING_MOVE_CAP);

  // The directory the bound will refuse, with a watched descendant of its own.
  let refused = live_child_dir(&mut m, root, "over");
  let inner = live_child_dir(&mut m, refused, "inner");
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("over"))
      .with_cookie(cookie(PENDING_MOVE_CAP as u64 + 1))
      .with_is_dir(true),
    at(10),
  );
  assert_eq!(
    parked_halves(&m, scope(1)),
    PENDING_MOVE_CAP,
    "the source is refused, not parked"
  );
  assert!(
    !m.is_watched(refused) && !m.is_watched(inner),
    "the refusal tore the whole source subtree down"
  );
  // The cover is COUNTED, so the window it opens cannot also close inside the call
  // that opened it: the `Rescan` standing now is the OPENING edge, and
  // `settle_bridges` gates on `rearm_settled`, which the root's own recovery holds
  // down. A barrier reading settled here would be certifying over a subtree that is
  // still blind.
  assert!(
    !m.rearm_settled(scope(1)),
    "the refusal's recovery is counted, not merely latched"
  );
  assert!(!m.coverage_settled(scope(1)));
  assert!(
    m.bridge.contains_key(&scope(1)),
    "so the bridge window stays open across the recovery"
  );
  assert!(
    m.events.iter().any(|e| e.kind().is_rescan()),
    "with its opening Rescan already standing at the scope root"
  );

  // The rename's other half and a modification under the old subtree, in ONE batch:
  // the destination pairs with nothing, and the modification lands on a watch the
  // refusal already dropped.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("moved"))
      .with_cookie(cookie(PENDING_MOVE_CAP as u64 + 1))
      .with_is_dir(true),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(inner, RecordKind::Modified).with_name(seg("f")),
    at(10),
  );

  let events = drain_events(&mut m);
  assert!(
    events.iter().all(|e| !e.kind().is_modified()),
    "the modification itself is lost with the watch that would have carried it: \
     {events:?}"
  );
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "so the refusal owes a covering instruction, and it must bypass the interest \
     that hides its Removed and the destination's Created: {events:?}"
  );
  m.assert_invariants();
}

/// A pairing whose destination names nothing can neither reparent the held subtree
/// nor reconcile a slot to re-cover it at, so — alone among the pairing arms — its
/// teardown ends the subtree's coverage for good while the object stays alive inside
/// the scope. The `Moved` that reports it is interest- and filter-subject, so the
/// cover cannot wait on the drop having erased a deficit either.
#[test]
fn a_nameless_destination_covers_the_held_subtree_it_drops() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let w_d = live_child_dir(&mut m, root, "d");
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  assert!(
    m.is_watched(w_d),
    "the source is held for its pairing window"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );
  assert!(
    !m.is_watched(w_d),
    "an unreparentable held subtree is torn down"
  );
  let opening = drain_events(&mut m);
  assert!(
    opening.iter().any(|e| e.kind().is_rescan()),
    "the dropped coverage is signalled to the subscription the Moved never reaches: \
     {opening:?}"
  );
  // That `Rescan` OPENS the recovery — it does not stand in for it. The pairing
  // consumed the half and released the hold, so `coverage_settled` here rests on
  // the re-arm conjunct alone, and the root crawl holds it down until the object's
  // new home is re-found and armed.
  assert!(
    !m.coverage_settled(scope(1)),
    "the barrier may not certify over a subtree whose new location is still unknown"
  );
  assert!(m.bridge.contains_key(&scope(1)), "the window is still open");

  // The crawl finds the object under its new name; only its acknowledged install
  // and read close the window.
  let root_read = read_of(&mut m, root);
  m.on_enumerate(
    root_read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("elsewhere"), FileKind::Dir)]),
  );
  assert!(!m.coverage_settled(scope(1)));
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_rescan()),
    "no closing Rescan while the re-found destination is still arming"
  );
  let found = arm_named_child(&mut m, root, "elsewhere");
  assert!(m.is_watched(found));
  let closing = drain_events(&mut m);
  assert!(
    closing.iter().any(|e| e.kind().is_rescan()),
    "the closing Rescan lands only after the recovery it closes: {closing:?}"
  );
  assert!(m.coverage_settled(scope(1)));
  m.assert_invariants();
}

// ── The counted cover: its window closes AFTER the recovery, never before ──

/// Answers every queued arm (as installed) and read (as `listing(dir)`) until the
/// driver has nothing outstanding, so a cell can observe what a bridge window emits
/// at its TRUE settle edge rather than mid-recovery.
fn answer_pending_work(m: &mut Monitor, listing: impl Fn(WatchId) -> Vec<DirEntry>) {
  for _ in 0..32 {
    let actions = drain_actions(m);
    if actions.is_empty() {
      return;
    }
    for action in actions {
      if let Some(watch) = action.as_watch() {
        m.ack_watch(watch.id(), Ok(WatchAck::Installed));
      } else if let Some(read) = action.as_enumerate() {
        let entries = listing(read.dir());
        m.on_enumerate(read.req(), EnumerateResult::Ok(entries));
      }
    }
  }
  panic!("the recovery never quiesced");
}

/// Fills `scope(1)`'s parked population to the bound under a live idle root, then
/// stages one further watched directory for the next unique cookie to be refused at.
fn staged_at_the_bound(m: &mut Monitor, root: WatchId, name: &str) -> WatchId {
  let _ = burst_moved_from(m, root, 0..PENDING_MOVE_CAP as u64);
  assert_eq!(parked_halves(m, scope(1)), PENDING_MOVE_CAP);
  let staged = live_child_dir(m, root, name);
  let _ = drain_events(m);
  let _ = drain_actions(m);
  staged
}

/// The `MovedFrom` the bound refuses.
fn refuse_source(m: &mut Monitor, root: WatchId, name: &str, n: u64) {
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg(name))
      .with_cookie(cookie(PENDING_MOVE_CAP as u64 + n))
      .with_is_dir(true),
    at(10),
  );
}

/// The refused source's object survives at a destination the refusal deliberately
/// forgot, so the recovery is the ROOT crawl — the only node guaranteed to be its
/// ancestor. In scope, that crawl re-finds it: the refusal's `Rescan` opens the
/// window, the re-found install is counted behind it, and the closing `Rescan` lands
/// strictly AFTER that install is acknowledged and read. Standing the two bridge
/// bits alone would flush the window inside the refusing call, putting the closing
/// `Rescan` BEFORE the recovery it exists to close.
#[test]
fn a_refusal_closes_its_window_only_after_the_crawl_reinstalls_the_destination() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let refused = staged_at_the_bound(&mut m, root, "over");

  refuse_source(&mut m, root, "over", 1);
  assert!(
    !m.is_watched(refused),
    "the refusal tore the source subtree down"
  );

  // The OPENING edge: exactly one `Rescan`, at the scope root.
  let opening = drain_events(&mut m);
  let rescans: Vec<_> = opening.iter().filter(|e| e.kind().is_rescan()).collect();
  assert_eq!(rescans.len(), 1, "{opening:?}");
  assert!(rescans[0].location().is_empty(), "{opening:?}");
  // Its recovery is COUNTED — the load-bearing conjunct here, since the parked
  // population holds the others down on its own.
  assert!(
    !m.rearm_settled(scope(1)),
    "the root crawl stands behind the opening Rescan"
  );
  assert!(!m.coverage_settled(scope(1)));

  // The crawl re-finds the object under its new name.
  let root_read = read_of(&mut m, root);
  m.on_enumerate(
    root_read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("moved"), FileKind::Dir)]),
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "the fresh destination install is counted in turn"
  );
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_rescan()),
    "no closing Rescan while that install is still arming"
  );

  let dest = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("moved")))
        .map(|w| w.id())
    })
    .expect("the re-found destination arms");
  m.ack_watch(dest, Ok(WatchAck::Installed));
  assert!(!m.rearm_settled(scope(1)));
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_rescan()),
    "nor while its own read is outstanding"
  );

  let dest_read = read_of(&mut m, dest);
  m.on_enumerate(dest_read, EnumerateResult::Ok(Vec::new()));
  let closing = drain_events(&mut m);
  assert!(
    closing.iter().any(|e| e.kind().is_rescan()),
    "the closing Rescan lands only once the destination is armed AND read: {closing:?}"
  );
  assert!(m.rearm_settled(scope(1)));
  m.assert_invariants();
}

/// The same refusal whose object left the scope entirely: the root crawl freshly
/// arms nothing, so `fresh_rearm` never sets and the bridge conjunction suppresses
/// the closing `Rescan` on its own. The barrier settles at crawl end — the
/// conjunction is honest rather than faked.
#[test]
fn a_refusal_whose_destination_left_the_scope_closes_with_no_second_rescan() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let refused = staged_at_the_bound(&mut m, root, "over");

  refuse_source(&mut m, root, "over", 1);
  assert!(!m.is_watched(refused));
  assert_eq!(
    drain_events(&mut m)
      .iter()
      .filter(|e| e.kind().is_rescan())
      .count(),
    1,
    "the opening Rescan"
  );
  assert!(!m.rearm_settled(scope(1)));

  // Nothing new under the root: the object is outside the scope.
  let root_read = read_of(&mut m, root);
  m.on_enumerate(root_read, EnumerateResult::Ok(Vec::new()));
  assert!(
    m.rearm_settled(scope(1)),
    "the barrier settles at crawl end"
  );
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_rescan()),
    "and no closing Rescan is owed — the window armed nothing fresh"
  );
  assert!(
    !m.bridge.contains_key(&scope(1)),
    "the window is over either way"
  );
  m.assert_invariants();
}

/// A refusal whose recovery crawl reaches a node with a COLD read still in flight
/// cannot start a second read there: the obligation coalesces onto that read
/// instead. `rearm_settled` deliberately does not count a dirtied cold read, so
/// the LATENT conjunct is what holds the barrier — and the read's completion
/// escalates into the covering `Rescan` plus a counted retry.
///
/// Re-staged on a POST-REGISTRATION cold read (42-10). The registration crawl is
/// re-arm-flavored and COUNTED now, so the root's own bootstrap read is never the
/// latent case; a live-discovered directory's read is where a cold read lives,
/// and the recovery's root crawl cascades into it exactly as it did into the
/// root's own.
#[test]
fn a_refusal_during_a_cold_read_holds_the_barrier_latently() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  // A live-discovered directory whose COLD read is still outstanding.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true)
      .with_node(ident(5)),
    at(1),
  );
  let d = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the discovered directory arms");
  m.ack_watch(d, Ok(WatchAck::Installed));
  let cold = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == d).map(|e| e.req()))
    .expect("its cold read");
  let _ = drain_events(&mut m);

  let refused = staged_at_the_bound(&mut m, root, "over");
  assert!(m.latent_settled(scope(1)), "nothing is latent yet");

  // The refusal's recovery is the ROOT crawl; its completion cascades into the
  // survivor `d`, whose in-flight COLD read is DIRTIED rather than re-read.
  refuse_source(&mut m, root, "over", 1);
  assert!(!m.is_watched(refused));
  let recovery = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the recovery's root re-arm read");
  let _ = drain_events(&mut m);
  m.on_enumerate(
    recovery,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("d"), FileKind::Dir).with_node(ident(5)),
    ]),
  );
  assert!(
    m.rearm_settled(scope(1)),
    "a dirtied COLD read is not counted by the re-arm predicate"
  );
  assert!(
    !m.latent_settled(scope(1)),
    "so the latent conjunct is what keeps the barrier shut"
  );
  assert!(!m.coverage_settled(scope(1)));
  let _ = drain_events(&mut m);

  // The cold read returns; being dirtied it escalates rather than being trusted.
  m.on_enumerate(cold, EnumerateResult::Ok(Vec::new()));
  assert!(m.latent_settled(scope(1)), "the latent read resolved");
  let escalation = drain_events(&mut m);
  assert!(
    escalation.iter().any(|e| e.kind().is_rescan()),
    "the escalation Rescan: {escalation:?}"
  );
  assert!(!m.rearm_settled(scope(1)), "with a counted retry behind it");
  m.assert_invariants();
}

/// A refusal under a root that is STILL ARMING — the shape a widen leaves behind,
/// a live tree processing records beneath a freshly-minted root. A bare re-arm
/// refuses such a root outright, which would reproduce the very defect this cover
/// exists to prevent: an opening `Rescan` with nothing counted behind it. Inheriting
/// marks the post-arm read instead, so the obligation is counted either way.
#[test]
fn a_refusal_under_a_still_arming_widen_root_is_counted_by_the_arming_mark() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle_with(&mut m, s, Interest::new().with_modified());
  let refused = staged_at_the_bound(&mut m, root, "over");

  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
      .map(|(id, _)| id),
    Some(reserved),
    "the scope's root is now a node whose arm has not answered"
  );
  assert!(m.rearm_settled(s), "the splice itself counts nothing");
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  refuse_source(&mut m, root, "over", 1);
  assert!(!m.is_watched(refused));
  assert!(
    matches!(
      m.nodes.get(&reserved).map(|node| node.state),
      Some(NodeState::Arming { rearm: true, .. })
    ),
    "the still-arming root carries the obligation on its post-arm read"
  );
  assert!(
    !m.rearm_settled(s),
    "which is a counted obligation, unlike a refused re-arm"
  );
  assert!(
    m.bridge.contains_key(&s),
    "so the window cannot flush inside the refusing call"
  );
  let opening = drain_events(&mut m);
  assert!(
    opening.iter().any(|e| e.kind().is_rescan()),
    "behind the opening Rescan: {opening:?}"
  );

  // The arm answers: its read is re-arm-flavored, so the recovery continues.
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  assert!(
    m.is_rearm_enumerating(reserved),
    "the post-arm read reads as a re-arm, not a cold discovery"
  );
  assert!(!m.rearm_settled(s));
  m.assert_invariants();
}

/// An ANCESTOR teardown reclaims a detached-and-held source through the parent link
/// and destroys its dirty marker — the one record that activity under the hold was
/// suppressed at a stale path. After that walk `pending.held` names a dead node, so
/// a capture taken at the half's own resolution reads false; only the walk itself
/// still knows. The funnel therefore owes the cover, and the later timeout finds
/// nothing left to speak for the suppression.
#[test]
fn an_ancestor_teardown_covers_the_under_hold_activity_it_erases() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let w_a = live_child_dir(&mut m, root, "a");
  let w_d = live_child_dir(&mut m, w_a, "d");
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_os_record(
    OsRecord::new(w_a, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  assert!(
    m.is_watched(w_d) && m.held_sources.contains(&w_d),
    "the source is detached and held for its pairing window"
  );

  // Activity under the hold is suppressed at the stale pre-move path; the marker is
  // its only trace.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Modified).with_name(seg("f")),
    at(11),
  );
  assert!(
    m.dirtied_holds.contains(&w_d),
    "the suppression left its marker"
  );
  let suppressed = drain_events(&mut m);
  assert!(
    suppressed.is_empty(),
    "and delivered nothing: {suppressed:?}"
  );
  let _ = drain_actions(&mut m);

  // The ancestor dies. Its walk takes the held source with it — and the marker.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed).with_name(seg("a")),
    at(12),
  );
  assert!(!m.is_watched(w_a) && !m.is_watched(w_d));
  assert!(
    !m.dirtied_holds.contains(&w_d),
    "the marker died with the node it keyed on"
  );
  let cover = drain_events(&mut m);
  assert!(
    cover
      .iter()
      .any(|e| e.kind().is_rescan() && e.location().is_empty()),
    "so the walk itself covers the suppressed Modified — nothing later can: {cover:?}"
  );
  assert!(!m.rearm_settled(scope(1)), "and the cover is counted");

  // The half then times out with its source already dead: no `Removed`, no
  // `Rescan`, nothing that could have stood in for the cover above.
  answer_pending_work(&mut m, |_| Vec::new());
  let _ = drain_events(&mut m);
  m.handle_timeout(at(10_000));
  let expiry = drain_events(&mut m);
  assert!(
    expiry.is_empty(),
    "a half whose anchor died speaks for nothing: {expiry:?}"
  );
  m.assert_invariants();
}

/// A storm of refusals at the bound stacks no unbounded work: every cover after the
/// first coalesces onto the root recovery already in flight, so at most one read is
/// ever outstanding for the root and each refusal adds only its own teardown. The
/// population is released wholesale when the move window elapses, and capacity is
/// restored — the next source parks and is held rather than refused.
#[test]
fn a_refusal_storm_stacks_no_unbounded_work_and_restores_capacity() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let _ = burst_moved_from(&mut m, root, 0..PENDING_MOVE_CAP as u64);
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  for i in 0..16u64 {
    let name = std::format!("over{i}");
    let refused = live_child_dir(&mut m, root, &name);
    let _ = drain_events(&mut m);
    let _ = drain_actions(&mut m);

    refuse_source(&mut m, root, &name, i + 1);
    assert!(!m.is_watched(refused));
    assert_eq!(
      parked_halves(&m, scope(1)),
      PENDING_MOVE_CAP,
      "the bound holds through the storm"
    );
    assert!(
      m.pending_enumerate
        .values()
        .filter(|dir| **dir == root)
        .count()
        <= 1,
      "the root's recovery read is re-armed in place, never stacked"
    );
    assert!(
      m.actions.len() <= 2,
      "one teardown and at most one read per refusal, however long the storm runs"
    );
  }

  // The window elapses: the whole parked population resolves and capacity returns.
  m.handle_timeout(at(10_000));
  assert_eq!(
    parked_halves(&m, scope(1)),
    0,
    "the window's end releases every half"
  );
  let _ = drain_events(&mut m);
  answer_pending_work(&mut m, |_| Vec::new());
  let _ = drain_events(&mut m);

  let again = live_child_dir(&mut m, root, "after");
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("after"))
      .with_cookie(cookie(9999))
      .with_is_dir(true),
    at(10_001),
  );
  assert_eq!(
    parked_halves(&m, scope(1)),
    1,
    "the next source parks instead of being refused"
  );
  assert!(m.is_watched(again), "and is HELD, not torn down");
  m.assert_invariants();
}

/// A pairing whose O(1) carry-over failed rebuilds a KNOWN destination over
/// carried-over content, and does so behind an unconditional edge `Rescan` — the
/// admission that the interval between the source dying and the fresh watch arming
/// was seen by no one. That rebuild must be COUNTED behind its own `Rescan` for the
/// same reason the refusal's is: a cold install leaves the window nothing to wait
/// on, so the conjunction never completes and the barrier settles while the
/// destination is still unread.
#[test]
fn a_failed_carry_over_counts_the_destination_it_rebuilds() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());

  // "d" is created; its watch is queued but NOT yet acknowledged.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  let _ = drain_events(&mut m);

  // It moves away while still pending → held; then its delayed arm FAILS, so no
  // subtree survives to carry over.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  m.ack_watch(w_d, Err(WatchError::Gone));
  answer_pending_work(&mut m, |_| Vec::new());
  let _ = drain_events(&mut m);
  assert!(m.rearm_settled(scope(1)), "a clean slate for the pairing");

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let opening = drain_events(&mut m);
  assert!(
    opening
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e"])),
    "the destination's edge Rescan: {opening:?}"
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "and the rebuild stands counted behind it"
  );
  assert!(!m.coverage_settled(scope(1)));

  let dest = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("e")))
        .map(|w| w.id())
    })
    .expect("the destination arms");
  m.ack_watch(dest, Ok(WatchAck::Installed));
  let read = read_of(&mut m, dest);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("kept"), FileKind::Dir)]),
  );
  // The carried-over child is `Created`-suppressed, which is exactly why the window
  // owes its closing `Rescan` — and why it may not fire until the subtree is armed.
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_rescan()),
    "no closing Rescan while the carried-over child is still arming"
  );
  assert!(!m.rearm_settled(scope(1)));

  let kept = arm_named_child(&mut m, dest, "kept");
  assert!(m.is_watched(kept));
  let closing = drain_events(&mut m);
  assert!(
    closing.iter().any(|e| e.kind().is_rescan()),
    "the closing Rescan covers the content the rebuild suppressed: {closing:?}"
  );
  assert!(m.coverage_settled(scope(1)));
  m.assert_invariants();
}

/// The same debt PAST the pairing window. A late `MovedTo` resolves the stranded
/// half — tearing down the held subtree and every descendant `WatchId` with it —
/// and then rebuilds the object at the destination slot. Unlike a timed-out or
/// displaced half, this one holds the destination record: the object provably
/// survives, so the teardown may not borrow the vanish argument.
///
/// A `Modified`-only subscription is what makes the debt visible. It receives
/// neither the strand's `Removed` nor the arrival's `Created`, and a `Modified`
/// arriving LATER IN THE SAME BATCH on one of the dropped descendant handles is
/// discarded by the unknown-watch guard — it cannot even dirty the hold, whose node
/// is already gone. Without the edge `Rescan` plus the counted rebuild behind it,
/// that subscription is told nothing and the barrier certifies over the silence.
#[test]
fn a_late_destination_covers_and_counts_the_subtree_it_rebuilds() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());

  // root → d (watched, live) → sub (watched, live).
  let w_d = live_child_dir(&mut m, root, "d");
  let w_sub = live_child_dir(&mut m, w_d, "sub");
  let _ = drain_events(&mut m);
  assert!(m.coverage_settled(scope(1)), "a clean slate for the strand");

  // "d" moves away (held), and its destination arrives PAST the window.
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
    at(10) + DEFAULT_MOVE_WINDOW + DEFAULT_MOVE_WINDOW,
  );
  assert!(!m.is_watched(w_d), "the stranded source is torn down");
  assert!(!m.is_watched(w_sub), "and so is every descendant handle");

  let opening = drain_events(&mut m);
  assert!(
    opening
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e"])),
    "the rebuilt destination's edge Rescan: {opening:?}"
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "and the rebuild stands counted behind it"
  );
  assert!(!m.coverage_settled(scope(1)));

  // The rest of the batch: a `Modified` on one of the dropped descendant watches.
  // Nothing in the monitor can attribute it any more — which is precisely why the
  // cover above had to be minted when the subtree was dropped.
  m.on_os_record(
    OsRecord::new(w_sub, RecordKind::Modified).with_name(seg("f.txt")),
    at(10) + DEFAULT_MOVE_WINDOW + DEFAULT_MOVE_WINDOW,
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "a record on a dropped handle is discarded, not delivered"
  );

  // Only the destination's own install AND read close the window.
  let dest = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("e")))
        .map(|w| w.id())
    })
    .expect("the destination arms");
  m.ack_watch(dest, Ok(WatchAck::Installed));
  assert!(!m.rearm_settled(scope(1)));
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_rescan()),
    "no closing Rescan while the destination is still arming"
  );

  let read = read_of(&mut m, dest);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "the carried-over child is counted in turn"
  );
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_rescan()),
    "nor while that child is still arming"
  );

  let sub = arm_named_child(&mut m, dest, "sub");
  assert!(m.is_watched(sub));
  let closing = drain_events(&mut m);
  assert!(
    closing.iter().any(|e| e.kind().is_rescan()),
    "the closing Rescan lands only once the rebuilt subtree is armed AND read: \
     {closing:?}"
  );
  assert!(m.coverage_settled(scope(1)));
  m.assert_invariants();
}

/// The nameless variant: a late destination that names no slot leaves the tree
/// nowhere to re-cover the dropped subtree, so its recovery anchors at the ROOT —
/// the in-window nameless twin's argument, applied past the window.
#[test]
fn a_nameless_late_destination_covers_the_held_subtree_it_drops() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let w_d = live_child_dir(&mut m, root, "d");
  let _ = drain_events(&mut m);
  assert!(m.rearm_settled(scope(1)), "a clean slate for the strand");

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  // The destination record carries the cookie but no name.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo).with_cookie(cookie(1)),
    at(10) + DEFAULT_MOVE_WINDOW + DEFAULT_MOVE_WINDOW,
  );
  assert!(!m.is_watched(w_d));

  let opening = drain_events(&mut m);
  assert!(
    opening
      .iter()
      .any(|e| e.kind().is_rescan() && e.location().is_empty()),
    "the recovery anchors at the root, the one location still known live: {opening:?}"
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "and the root crawl stands counted behind it"
  );
  m.assert_invariants();
}

/// The late destination whose parent died WITH the held subtree (a cyclic arrival):
/// nothing is rebuilt anywhere, so the root escalation carries the whole recovery
/// and must be counted — a bare edge `Rescan` would let the barrier certify on the
/// very next poll over a subtree the monitor no longer covers at all.
#[test]
fn a_late_destination_under_a_dead_parent_counts_its_root_escalation() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let w_d = live_child_dir(&mut m, root, "d");
  let w_sub = live_child_dir(&mut m, w_d, "sub");
  let _ = drain_events(&mut m);
  assert!(m.rearm_settled(scope(1)), "a clean slate for the strand");

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(5))
      .with_is_dir(true),
    at(10),
  );
  // The destination lands INSIDE the held subtree, past the window: resolving the
  // strand drops the destination parent too.
  m.on_os_record(
    OsRecord::new(w_sub, RecordKind::MovedTo)
      .with_name(seg("d"))
      .with_cookie(cookie(5))
      .with_is_dir(true),
    at(10) + DEFAULT_MOVE_WINDOW + DEFAULT_MOVE_WINDOW,
  );
  assert!(!m.is_watched(w_d));
  assert!(!m.is_watched(w_sub));

  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location().is_empty()),
    "the escalation Rescan targets the scope root: {events:?}"
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "and the root crawl stands counted behind it"
  );
  assert!(!m.coverage_settled(scope(1)));
  m.assert_invariants();
}

/// The in-window twin of the cell above: a pairing whose O(1) carry-over cannot even
/// be attempted because the destination sits inside the held source. The teardown
/// removes both endpoints, so — unlike the failed carry-over with a live parent —
/// there is no destination slot to rebuild and count. The root escalation is the
/// entire recovery, and it owes the same counted crawl.
#[test]
fn a_failed_carry_over_under_a_dead_parent_counts_its_root_escalation() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let w_d = live_child_dir(&mut m, root, "d");
  let w_sub = live_child_dir(&mut m, w_d, "sub");
  let _ = drain_events(&mut m);
  assert!(m.rearm_settled(scope(1)), "a clean slate for the pairing");

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(5))
      .with_is_dir(true),
    at(10),
  );
  // In-window, but cyclic: `can_reparent` rejects it and the held subtree is dropped,
  // taking the destination parent with it.
  let outcome = m.on_os_record(
    OsRecord::new(w_sub, RecordKind::MovedTo)
      .with_name(seg("d"))
      .with_cookie(cookie(5))
      .with_is_dir(true),
    at(12),
  );
  assert_eq!(outcome, RecordOutcome::Nothing, "no subtree was carried");
  assert!(!m.is_watched(w_d));
  assert!(!m.is_watched(w_sub));

  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location().is_empty()),
    "the escalation Rescan targets the scope root: {events:?}"
  );
  assert!(
    !m.rearm_settled(scope(1)),
    "and the root crawl stands counted behind it"
  );
  assert!(!m.coverage_settled(scope(1)));
  m.assert_invariants();
}

// ── Every non-success watch result is coverage loss ──

/// Re-staged on a POST-REGISTRATION discovery (42-10): the refusal's edge
/// `Rescan` is asserted to be the window's ONLY event, and a refusal inside the
/// registration window legitimately closes that window with a second, covering
/// `Rescan`. Staging the refused install on the live stream instead keeps the
/// cell about the refusal edge alone.
fn watch_failure_is_coverage_loss(err: WatchError) {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let child_id = discovered_child_dir(&mut m, root, "sub");

  m.ack_watch(child_id, Err(err));
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
  let root = m
    .register_root(scope(1), Interest::all())
    .expect("a fresh scope registers");
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Err(WatchError::NoSpace));
  assert!(
    !m.is_watched(root),
    "a refused root is dropped, not left registered"
  );
  assert!(drain_events(&mut m).iter().any(|e| e.kind().is_rescan()));
  let actions = drain_actions(&mut m);
  assert!(actions.iter().any(|a| a.as_unwatch() == Some(root)));
}

/// `NotFound` now also emits a `Rescan` (was: silent drop). Re-staged on a
/// POST-REGISTRATION discovery for the same reason as
/// [`watch_failure_is_coverage_loss`]: the edge `Rescan` is asserted to be the
/// only event, which a refusal inside the registration window is not.
#[test]
fn not_found_watch_result_drops_and_rescans() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let child_id = discovered_child_dir(&mut m, root, "sub");

  m.ack_watch(child_id, Err(WatchError::NotFound));
  assert!(!m.is_watched(child_id));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1);
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &loc(&["sub"]));
}

// ── Descent is idempotent via the child index ──

/// A bootstrap enumerate racing a live `Created` for one path installs a single
/// child watch and delivers the change once.
///
/// The single delivery is the KERNEL's copy, and that is what changed under 42-10:
/// the listing's copy used to be deduped against it, and is now suppressed
/// outright, because a registration reports no inventory. Either way exactly one
/// `Created` reaches the consumer — the assertion is unchanged and the reason
/// under it is not.
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

/// Dropping a child watch removes it from the child index in lockstep: the slot is
/// re-keyed to the replacement watch rather than left pointing at the dead handle,
/// so a later same-name descent reuses that replacement instead of minting a second
/// watch for one path.
///
/// The drop is driven by a LIVE non-root `Ignored` — the unmount trace — which now
/// rebuilds the slot itself. The cell's earlier form asserted the opposite of that:
/// that the teardown queued nothing and that a subsequent `Created` was what re-armed
/// the path. That assertion encoded the defect (a subtree dropped with no cover and
/// no replacement, while `coverage_settled` kept reading true), so the lockstep
/// property is restated here against the rebuild rather than against the silence.
#[test]
fn an_ignored_child_slot_is_rekeyed_to_its_replacement() {
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
  assert!(!m.is_watched(w1), "the torn-down handle leaves the index");
  let w2 = armed_child(&mut m, root, "sub");
  assert_ne!(w1, w2, "and the slot is re-keyed to a fresh one");
  assert!(m.is_watched(w2));
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(3),
  );
  let acts = drain_actions(&mut m);
  assert!(
    acts.iter().all(|a| a.as_watch().is_none()),
    "one watch per path: the re-descent reuses the replacement, {acts:?}"
  );
  assert_eq!(
    m.child_watch(root, &seg("sub")),
    Some(w2),
    "which is still the slot's occupant"
  );
  m.assert_invariants();
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
  m.ack_watch(w_p, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d2, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d2, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d2, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d2, Ok(WatchAck::Installed));
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

/// An `Ok` enumerate entry of unknown kind is emitted, and — since a kind nobody
/// could read is not evidence of a non-directory — booked as darkness and stat'd,
/// rather than passed over as a file. A `Dir` entry in the same result is watched
/// outright.
///
/// Re-staged on a POST-REGISTRATION cold read (42-10): a registration's own crawl
/// emits no `Created` for either entry. The unknown-kind HANDLING is identical on
/// both flavors — cell 6b covers the bootstrap side.
#[test]
fn enumerate_unknown_kind_entry_is_stat_resolved_not_assumed_a_file() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let d = discovered_child_dir(&mut m, root, "d");
  let read = armed_read(&mut m, d);

  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("known"), FileKind::Dir),
      DirEntry::new(seg("mystery"), FileKind::Unknown),
    ]),
  );

  // Both are reported as Created.
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 2);
  assert!(events.iter().all(|e| e.kind().is_created()));

  // The known directory is watched; the unclassifiable slot is not (it may hold a
  // file) but is asked about, and stands as a coverage deficit until answered.
  let actions = drain_actions(&mut m);
  assert_eq!(actions.len(), 2, "{actions:?}");
  assert_eq!(
    actions[0].as_watch().unwrap().target(),
    &WatchTarget::child(d, seg("known"))
  );
  assert_eq!(
    actions[1].as_stat().unwrap().of(),
    &StatTarget::child(d, seg("mystery"))
  );
  assert!(m.has_coverage_deficit(scope(1)));
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
  m.ack_watch(w_p, Ok(WatchAck::Installed));
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
  m.ack_watch(w_p, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_p, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(2),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_g, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(2),
  );
  let w_sub = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.ack_watch(w_sub, Ok(WatchAck::Installed));
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
  m.ack_watch(w_a, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_a, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(2),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_a2, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(2),
  );
  let w_sub = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.ack_watch(w_sub, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_a, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  // A storm's seeds are statistical convergence coverage, and that is the native
  // runs' job: one seed drives every code path the rest do, while sixty-odd seeds'
  // worth of tree churn exhausts a 32-bit target's entire address space under miri
  // (i686 dies with "no more free addresses"). Miri is here to find UB, so it runs
  // the shape once.
  let seeds: u64 = if cfg!(miri) { 1 } else { 64 };
  for seed in 1..=seeds {
    let mut m = per_dir();
    let mut s = seed.wrapping_mul(2_654_435_761).wrapping_add(12_345);
    let mut rng = || {
      s ^= s << 13;
      s ^= s >> 17;
      s ^= s << 5;
      s
    };

    let mut watches = std::vec![
      m.register_root(scope(1), Interest::all())
        .expect("a fresh scope registers"),
      m.register_root(scope(2), Interest::all())
        .expect("a fresh scope registers"),
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
          } else if rng() % 2 == 0 {
            Ok(WatchAck::Installed)
          } else {
            Ok(WatchAck::Aliased)
          };
          m.ack_watch(w, res);
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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

  // The delayed watch result for the held pending source errors: no stale-path
  // Rescan. The failure dirties the hold — and then DESTROYS the node that marker
  // lives on, so the teardown funnel discharges the debt where it dies, at the one
  // location this drop still knows to be live.
  m.ack_watch(w_d, Err(WatchError::Gone));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .all(|e| e.kind().is_rescan() && e.location().is_empty()),
    "a held pending source's watch failure emits no stale-path Rescan: {events:?}"
  );
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "and the dirty marker it erased is covered, not dropped: {events:?}"
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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

// ── The lowered path's second clause: knowingly stale at the stamp ──
//
// A round trip is trusted only when neither the anchor's chain moved since its
// stamp NOR the path was already stale when stamped. The four cells below drive
// the second clause through each round trip, at both edges of a hold: an answer
// issued BEFORE the source detached (the clock catches it, but its recovery was
// still addressed at the vacated slot) and answers issued DURING the hold (the
// clock cannot catch them at all — no move happens after the issue).

/// Brings `name` live under `root` and then moves it away, returning its watch
/// held and detached for the pairing window with every bootstrap action and
/// event drained — the precondition every held-lowering cell starts from.
fn held_move_source(m: &mut Monitor, root: WatchId, name: &str) -> WatchId {
  let child = live_child_dir(m, root, name);
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg(name))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(m);
  let _ = drain_actions(m);
  child
}

/// A held move source that already covers one live child directory — the coverage
/// a listing, an answer or an acknowledgement taken at the vacated path could end.
fn held_move_source_covering(
  m: &mut Monitor,
  root: WatchId,
  name: &str,
  child: &str,
) -> (WatchId, WatchId) {
  let src = live_child_dir(m, root, name);
  let kid = live_child_dir(m, src, child);
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg(name))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(m);
  let _ = drain_actions(m);
  (src, kid)
}

/// Spends the bounded retries a held read leaves outstanding, answering each with
/// the same replacement listing, so the node is idle again and the pairing's own
/// recovery read is the next one it issues.
fn spend_held_retries(m: &mut Monitor, dir: WatchId, entries: &[DirEntry]) {
  while let Some(req) = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == dir).map(|e| e.req()))
  {
    m.on_enumerate(req, EnumerateResult::Ok(entries.to_vec()));
  }
  let _ = drain_events(m);
}

/// Queues a re-arm read of the held source by failing its parent's read: the
/// parent's cascade reaches a detached-and-held child (`failed_rearm_reaches_
/// detached_held_move_source`), and — unlike an overflow — it leaves the parked
/// half's own dirty flag alone, so what the pairing covers is the hold's debt and
/// nothing else. Returns the request reading the held directory, events drained.
fn read_queued_under_a_hold(m: &mut Monitor, root: WatchId, held: WatchId) -> ReqId {
  assert!(m.rearm_watch_subtree(root).is_started());
  let root_read = read_of(m, root);
  m.on_enumerate(root_read, EnumerateResult::Failed(IoClass::Permission));
  let req = read_of(m, held);
  let _ = drain_events(m);
  req
}

/// A stat issued BEFORE a `MovedFrom` can answer after the source is detached and
/// before its `MovedTo`. The placement clock refuses the answer — but the refusal
/// then reconstructed the held parent's DELIBERATELY stale pre-move location and
/// stood its covering `Rescan` there, sending the consumer to re-read the slot the
/// subtree has left while the real destination kept no re-arm obligation at all.
/// The recovery belongs to the pairing.
#[test]
fn a_stat_answering_mid_rename_recovers_only_at_the_destination() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);

  // root → d, whose listing leaves one slot unclassifiable: that is what asks for
  // a stat, issued while d is still in its slot.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(1),
  );
  let w_d = drain_actions(&mut m)[0].as_watch().unwrap().id();
  m.ack_watch(w_d, Ok(WatchAck::Installed));
  let d_boot = read_of(&mut m, w_d);
  m.on_enumerate(
    d_boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("u"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable slot is stat'd");
  let _ = drain_events(&mut m);

  // "d" moves away: detached and held, so d/u now reconstructs at a path the
  // subtree has left.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // The answer lands mid-hold: refused by the clock, and addressed nowhere.
  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));
  let events = drain_events(&mut m);
  assert!(
    events.is_empty(),
    "a refused stat under a hold stands nothing at the pre-move path: {events:?}"
  );
  assert!(
    m.has_coverage_deficit(s),
    "and its darkness stays booked for the recovery to discharge"
  );

  // The pairing carries the recovery, and it lands at the destination only.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  let rescans: Vec<_> = events.iter().filter(|e| e.kind().is_rescan()).collect();
  assert!(
    rescans
      .iter()
      .all(|e| e.location() != &loc(&["d", "u"]) && e.location() != &loc(&["d"])),
    "nothing points the consumer at the vacated source: {events:?}"
  );
  assert!(
    rescans.iter().any(|e| e.location() == &loc(&["e"])),
    "the dirtied hold re-scans the destination instead: {events:?}"
  );
  m.assert_invariants();
}

/// The other edge of the same clause: a stat ISSUED while its parent is already
/// held. No move happens after the issue, so the clock reads current while the
/// path was stale before the request was even queued — and the answer's covering
/// `Rescan` would name the vacated slot.
#[test]
fn a_stat_issued_under_a_hold_recovers_only_at_the_destination() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = held_move_source(&mut m, root, "d");

  // A re-arm read of the held source lists an unclassifiable slot: the stat is
  // issued here, at a path the hold already made stale.
  let read = read_queued_under_a_hold(&mut m, root, w_d);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("u"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable slot under the held source is stat'd");
  let _ = drain_events(&mut m);

  // An unresolvable answer: the slot's own failure edge. The clock cannot refuse
  // it — nothing moved since it was issued — so only the hold stands between its
  // cover and the vacated path.
  m.on_stat_result(stat, StatResult::Failed(IoClass::Permission));
  let events = drain_events(&mut m);
  assert!(
    events.is_empty(),
    "a stat issued under a hold stands nothing at the pre-move path: {events:?}"
  );
  assert!(
    m.has_coverage_deficit(s),
    "and re-books the darkness it could not settle"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  let rescans: Vec<_> = events.iter().filter(|e| e.kind().is_rescan()).collect();
  assert!(
    rescans
      .iter()
      .all(|e| e.location() != &loc(&["d", "u"]) && e.location() != &loc(&["d"])),
    "nothing points the consumer at the vacated source: {events:?}"
  );
  assert!(
    rescans.iter().any(|e| e.location() == &loc(&["e"])),
    "the recovery lands at the destination: {events:?}"
  );
  m.assert_invariants();
}

/// The stat's other edge: an answer that would RETIRE the slot's incumbent. Under
/// a hold the driver probed the slot the subtree has LEFT, so a `NotFound` there
/// says the replacement lacks that name — never that this subtree's child stopped
/// existing. The incumbent keeps its watch and its coverage, and the recovery
/// belongs to the pairing.
#[test]
fn a_stat_under_a_hold_keeps_its_incumbent_and_recovers_at_the_destination() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  // The incumbent is live BEFORE the move: what this cell drives is the STAT
  // clause, and a slot's incumbent is the same precondition however it arrived.
  let (w_d, w_g) = held_move_source_covering(&mut m, root, "d", "g");

  // A read under the hold can no longer classify the name, which defers the slot
  // to a stat while KEEPING the incumbent standing.
  let read = read_queued_under_a_hold(&mut m, root, w_d);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable slot is stat'd");
  let _ = drain_events(&mut m);

  // The answer would settle the slot empty — at the pre-move path. It settles
  // nothing here, and stands nothing there.
  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));
  assert!(
    m.is_watched(w_g),
    "a NotFound at the vacated path is no evidence that this slot emptied"
  );
  let events = drain_events(&mut m);
  assert!(
    events.is_empty(),
    "and it stands nothing at the pre-move path: {events:?}"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  let rescans: Vec<_> = events.iter().filter(|e| e.kind().is_rescan()).collect();
  assert!(
    rescans
      .iter()
      .all(|e| e.location() != &loc(&["d"]) && e.location() != &loc(&["d", "g"])),
    "nothing points the consumer at the vacated source: {events:?}"
  );
  assert!(
    rescans.iter().any(|e| e.location() == &loc(&["e"])),
    "the recovery lands at the destination: {events:?}"
  );
  m.assert_invariants();
}

/// The read arm of the same clause: a re-arm read ISSUED inside the hold and
/// answering inside it. Its unreadable content owes a `Rescan`, which at the held
/// source's reconstruction would name the vacated path — so it is suppressed, the
/// bounded retry still runs (coverage is never dropped), and the pairing covers.
#[test]
fn a_read_issued_under_a_hold_recovers_only_at_the_destination() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = held_move_source(&mut m, root, "d");

  let read = read_queued_under_a_hold(&mut m, root, w_d);
  m.on_enumerate(read, EnumerateResult::Failed(IoClass::Permission));
  let events = drain_events(&mut m);
  assert!(
    events.is_empty(),
    "an unreadable read under a hold stands no Rescan at the pre-move path: {events:?}"
  );
  assert!(
    m.is_rearm_enumerating(w_d),
    "and the bounded retry still runs, so coverage is not dropped"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  let rescans: Vec<_> = events.iter().filter(|e| e.kind().is_rescan()).collect();
  assert!(
    rescans.iter().all(|e| e.location() != &loc(&["d"])),
    "nothing points the consumer at the vacated source: {events:?}"
  );
  assert!(
    rescans.iter().any(|e| e.location() == &loc(&["e"])),
    "the recovery lands at the destination: {events:?}"
  );
  m.assert_invariants();
}

/// The arm arm of the same clause, and the boundary it must NOT cross: an arm
/// issued inside a hold is deliberate best-effort coverage — it is what keeps a
/// gap-created descendant of a mid-move source watched — so the ISSUE stands and
/// its outcome is still answered here. What the acknowledgement may not do is
/// CERTIFY: it installed against the vacated pre-move path, so it is proof about
/// whatever occupies the slot the subtree has left, and a binding nothing may
/// certify may not be kept either. It is retired, and the pairing — dirtied by
/// the same fence that refused the proof — covers the destination and rebuilds
/// the emptied slot through it.
#[test]
fn an_arm_acknowledged_under_a_hold_is_retired_and_rebuilt_by_the_pairing() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = held_move_source(&mut m, root, "d");

  // A re-arm read of the held source finds a gap-created grandchild: the arm is
  // issued here, inside the hold. That much is invariant — refusing to issue
  // would leave the held subtree unarmed for the whole pairing window.
  let read = read_queued_under_a_hold(&mut m, root, w_d);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  let actions = drain_actions(&mut m);
  let w_g = actions
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("g")))
        .map(|w| w.id())
    })
    .expect("the grandchild under the held move-source is armed");
  let retry = actions
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()));
  let _ = drain_events(&mut m);

  // The acknowledgement lands while still held: answered, and refused as proof.
  m.ack_watch(w_g, Ok(WatchAck::Installed));
  assert!(
    !m.is_watched(w_g),
    "an acknowledgement taken at the vacated path certifies nothing, so the \
     binding it reports is retired rather than kept doubtful"
  );
  let events = drain_events(&mut m);
  assert!(
    events.is_empty(),
    "with nothing announced at the pre-move path: {events:?}"
  );
  if let Some(retry) = retry {
    m.on_enumerate(retry, EnumerateResult::Ok(std::vec::Vec::new()));
  }
  spend_held_retries(&mut m, w_d, &[]);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  let rescans: Vec<_> = events.iter().filter(|e| e.kind().is_rescan()).collect();
  assert!(
    rescans
      .iter()
      .all(|e| e.location() != &loc(&["d"]) && e.location() != &loc(&["d", "g"])),
    "nothing points the consumer at the vacated source: {events:?}"
  );
  assert!(
    rescans.iter().any(|e| e.location() == &loc(&["e"])),
    "the recovery lands at the destination: {events:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and no barrier certifies before the counted rebuild that cover owes"
  );

  // The pairing's crawl rebuilds the retired slot, addressed through the
  // destination this time — on a fresh handle, so nothing the dead one may still
  // be carrying can reach the tree.
  let crawl = read_of(&mut m, w_d);
  m.on_enumerate(
    crawl,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  let rebuilt = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("g")))
        .map(|w| w.id())
    })
    .expect("the pairing's crawl rebuilds the retired slot");
  assert_ne!(rebuilt, w_g, "on a fresh handle, never the retired one");
  m.ack_watch(rebuilt, Ok(WatchAck::Installed));
  settle_reads(&mut m);
  assert!(m.coverage_settled(s), "and the scope settles behind it");
  m.assert_invariants();
}

/// The degraded-recovery edge of the read clause. A COMPLETE read of a held
/// directory lists whatever replaced it at the vacated pre-move path, so a name
/// that listing omits vanished from a slot this subtree has LEFT. Pruning on it
/// retires live coverage of a child that rides the move — and the pairing cannot
/// be relied on to give it back: an incomplete destination read reconstructs no
/// omitted name, so the retired child would stay unwatched with its subtree dark.
#[test]
fn a_held_read_prunes_nothing_over_a_degraded_destination_recovery() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let (w_d, w_k) = held_move_source_covering(&mut m, root, "d", "k");

  // A replacement directory now occupies the vacated path. Its listing OMITS the
  // covered name under one flavor of replacement and positively reports it as a
  // non-directory under the other — the two shapes that retire a watch.
  let replacement = [
    DirEntry::new(seg("k"), FileKind::File),
    DirEntry::new(seg("other"), FileKind::Dir),
  ];
  let read = read_queued_under_a_hold(&mut m, root, w_d);
  m.on_enumerate(read, EnumerateResult::Ok(replacement.to_vec()));
  assert!(
    m.is_watched(w_k),
    "a replacement's complete listing prunes nothing from the subtree it replaced"
  );
  spend_held_retries(&mut m, w_d, &replacement);

  // The move pairs, and the destination's own recovery read comes back INCOMPLETE —
  // the case that reconstructs no omitted name.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let recovery = read_of(&mut m, w_d);
  m.on_enumerate(recovery, EnumerateResult::Partial(std::vec::Vec::new()));
  assert!(
    m.is_watched(w_k),
    "so the child is still covered once the degraded recovery has run"
  );
  m.assert_invariants();
}

/// The same edge for the stat clause: an answer taken at the vacated path may not
/// retire the slot's incumbent. The replacement lacks the name, the stat reports
/// `NotFound`, and the destination's recovery read then FAILS — which rebuilds
/// nothing, so a retirement here would be permanent darkness under a live child.
#[test]
fn a_held_stat_retires_nothing_over_a_degraded_destination_recovery() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let (w_d, w_k) = held_move_source_covering(&mut m, root, "d", "k");

  // The replacement holds a "k" the driver could not classify: that is what defers
  // the covered slot to a stat.
  let read = read_queued_under_a_hold(&mut m, root, w_d);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("k"), FileKind::Unknown)]),
  );
  let actions = drain_actions(&mut m);
  let stat = actions
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable slot is stat'd");
  let retry = actions
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()));
  let _ = drain_events(&mut m);

  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));
  assert!(
    m.is_watched(w_k),
    "a NotFound at the vacated path retires no incumbent"
  );
  if let Some(retry) = retry {
    m.on_enumerate(retry, EnumerateResult::Ok(std::vec::Vec::new()));
  }
  spend_held_retries(&mut m, w_d, &[]);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let recovery = read_of(&mut m, w_d);
  m.on_enumerate(recovery, EnumerateResult::Failed(IoClass::Permission));
  assert!(
    m.is_watched(w_k),
    "so the child is still covered once the degraded recovery has run"
  );
  m.assert_invariants();
}

/// The honest cost of a held retirement, pinned. The rebuild the retirement owes
/// belongs to the pairing's crawl, and that crawl can DEGRADE: a destination read
/// that never completes reconstructs no omitted name, so the retired slot stays
/// dark past the pairing's own cover.
///
/// That darkness must be BOOKED, never silent. The exhausted read records its
/// interior deficit, level-persistent behind the standing `Rescan`, and every sync
/// cookie dispatched over it is preceded by a fresh covering `Rescan` and a heal
/// kick — so the scope may settle, but never quietly.
#[test]
fn a_retirement_under_a_degraded_recovery_is_booked_and_re_signaled() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = held_move_source(&mut m, root, "d");

  // The replacement's child is armed and ACKNOWLEDGED while the hold stands, so
  // the acknowledgement retires it and the pairing owes the rebuild.
  let read = read_queued_under_a_hold(&mut m, root, w_d);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("n"), FileKind::Dir)]),
  );
  let actions = drain_actions(&mut m);
  let w_n = actions
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("n")))
        .map(|w| w.id())
    })
    .expect("the newly-listed name is armed under the hold");
  let retry = actions
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()));
  m.ack_watch(w_n, Ok(WatchAck::Installed));
  assert!(!m.is_watched(w_n), "the under-hold acknowledgement retires");
  if let Some(retry) = retry {
    m.on_enumerate(retry, EnumerateResult::Ok(std::vec::Vec::new()));
  }
  spend_held_retries(&mut m, w_d, &[]);
  // The parent read this setup failed to queue the held read left its own bounded
  // retry outstanding; answer it, so the only work the pairing leaves standing is
  // the crawl under test.
  settle_reads(&mut m);

  // The move pairs: the destination is covered and its crawl starts.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let _ = drain_events(&mut m);

  // That crawl never completes: every read comes back incomplete and reports
  // nothing, so the retired name is reconstructed by no listing at all.
  for _ in 0..=REARM_MAX_RETRIES {
    let recovery = read_of(&mut m, w_d);
    m.on_enumerate(recovery, EnumerateResult::Partial(std::vec::Vec::new()));
  }
  let standing = drain_events(&mut m);
  assert!(
    standing
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e"])),
    "the exhausted crawl leaves its standing Rescan at the destination: {standing:?}"
  );
  assert!(
    m.coverage_settled(s),
    "and the scope settles: an unreadable directory degrades, it does not wedge"
  );

  // Settled is not silent. A sync cookie dispatched over the booked interior is
  // preceded by a fresh cover and a heal kick, so the darkness is re-signaled for
  // as long as it stands.
  assert!(
    m.resignal_coverage_deficits(s),
    "the exhausted interior is booked, and the dispatch seam re-signals it"
  );
  let resignaled = drain_events(&mut m);
  assert!(
    resignaled
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e"])),
    "with a covering Rescan ahead of the cookie: {resignaled:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and the heal kick it stands is counted, so no barrier certifies over it"
  );
  m.assert_invariants();
}

/// The id armed for `(parent, name)` by the actions queued so far.
fn armed_child(m: &mut Monitor, parent: WatchId, name: &str) -> WatchId {
  drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(parent, seg(name)))
        .map(|w| w.id())
    })
    .expect("the name is armed")
}

/// Arms one child of a held move source INSIDE the hold and acknowledges it, so
/// the acknowledgement — taken at the vacated pre-move path — certifies nothing
/// and retires the binding it reports. Returns the now-dead handle, with the tree
/// quiescent and the rebuild owed to the hold's pairing.
fn retired_under_a_hold(m: &mut Monitor, root: WatchId, src: WatchId) -> WatchId {
  let read = read_queued_under_a_hold(m, root, src);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("n"), FileKind::Dir)]),
  );
  let child = armed_child(m, src, "n");
  m.ack_watch(child, Ok(WatchAck::Installed));
  assert!(
    !m.is_watched(child),
    "an acknowledgement taken under the hold retires the binding it reports"
  );
  settle_reads(m);
  child
}

/// Pairs the held move source at "e" and clears everything the pairing itself
/// emits, leaving the subtree re-keyed at the destination with its re-add queued
/// but NOT yet acknowledged.
fn pair_held_source_at(m: &mut Monitor, root: WatchId) {
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let _ = drain_events(m);
}

/// The window the hold's own fence cannot close, closed by DEATH. Pairing removes
/// the hold one step before any recovery has run, and `ingest_record` fences only
/// what is still INSIDE a hold — so a record from a binding installed at the
/// vacated path used to land at a node whose path the reparent had just made
/// current: a change at the destination no later `Rescan` un-emits, or a
/// retirement of coverage the destination genuinely carries.
///
/// The retirement removes the handle before the acknowledgement's own ingest
/// returns, so there is no such window to fence: every later record naming it is
/// discarded as an unrecognized watch, whole — delivery, slot effects, and the
/// discovery that would install off it.
#[test]
fn a_retired_binding_neither_delivers_nor_retires_nor_installs_off_its_dead_handle() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let (w_d, w_k) = held_move_source_covering(&mut m, root, "d", "k");
  let dead = retired_under_a_hold(&mut m, root, w_d);
  pair_held_source_at(&mut m, root);

  // The replacement at the vacated path keeps producing records on the binding it
  // owns — one that would surface a name only IT has, one that would retire a
  // covered sibling the destination carries.
  m.on_os_record(
    OsRecord::new(dead, RecordKind::Created)
      .with_name(seg("x"))
      .with_is_dir(true),
    at(13),
  );
  m.on_os_record(
    OsRecord::new(dead, RecordKind::Removed)
      .with_name(seg("k"))
      .with_is_dir(true),
    at(14),
  );
  let delivered = drain_events(&mut m);
  assert!(
    !delivered
      .iter()
      .any(|e| e.location() == &loc(&["e", "n", "x"]) || e.location() == &loc(&["e", "k"])),
    "no record off the dead binding is delivered at the destination: {delivered:?}"
  );
  assert!(
    m.is_watched(w_k),
    "and none of them retires the coverage the destination genuinely carries"
  );
  let queued = drain_actions(&mut m);
  assert!(
    !queued
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(dead, seg("x")))),
    "nor installs coverage for a name only the dead binding reported: {queued:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and the counted rebuild the pairing owes still holds the barrier"
  );
  m.assert_invariants();

  // The destination's own recovery then comes back INCOMPLETE — the case that
  // reconstructs no omitted name — and changes neither answer.
  let recovery = queued
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    .expect("the pairing's crawl of the destination");
  m.on_enumerate(recovery, EnumerateResult::Partial(std::vec::Vec::new()));
  let after = drain_events(&mut m);
  assert!(
    !after
      .iter()
      .any(|e| e.location() == &loc(&["e", "n", "x"]) || e.location() == &loc(&["e", "k"])),
    "the degraded recovery delivers none of the dead binding's records either: {after:?}"
  );
  assert!(
    m.is_watched(w_k),
    "and retires none of the coverage the destination carries"
  );
  m.assert_invariants();
}

/// BOTH clauses at once, and the flavour that used to make the cover vanish. An
/// arm still in flight when its ancestor moves away is `moved` (the clock saw the
/// chain change) AND `held` (its lowering names the vacated path for the whole
/// pairing window) — and the acknowledgement that answers it is `Aliased`, which
/// proves only that the binding was live, never at which path.
///
/// One predicate, asked once, decides all of that: the answer certifies nothing,
/// so the binding dies. What must then hold is the whole chain — nothing delivered,
/// retired or installed off the dead handle, no barrier certifying over the window
/// the retirement opened, and a closing `Rescan` that postdates the rebuilt read
/// even though not one acknowledgement in the sequence was `Installed`.
#[test]
fn a_binding_both_moved_and_held_is_retired_and_covered_all_aliased() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = live_child_dir(&mut m, root, "d");

  // `c` is discovered from a record and armed; its acknowledgement is still in
  // flight when `d` moves away.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("c"))
      .with_is_dir(true),
    at(2),
  );
  let (w_c, stale) = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("c")))
        .map(|w| (w.id(), w.attempt()))
    })
    .expect("the discovered directory arms");
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_watch_result(w_c, stale, Ok(WatchAck::Aliased));
  assert!(
    !m.is_watched(w_c),
    "an Aliased answer to a lowering that failed both clauses certifies nothing"
  );
  let at_retire = drain_events(&mut m);
  assert!(
    at_retire.is_empty(),
    "and the held branch stands no located cover — the reconstruction would name \
     the path the subtree has left: {at_retire:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "the hold this retirement dirtied holds the barrier"
  );
  m.assert_invariants();

  // The replacement at the vacated path keeps producing records on the binding
  // that `Ok` reported. None of them may reach the tree.
  m.on_os_record(
    OsRecord::new(w_c, RecordKind::Created)
      .with_name(seg("x"))
      .with_is_dir(true),
    at(4),
  );
  let stray = drain_events(&mut m);
  assert!(
    stray.is_empty(),
    "nothing off the retired handle is delivered: {stray:?}"
  );
  let stray_actions = drain_actions(&mut m);
  assert!(
    !stray_actions
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(w_c, seg("x")))),
    "nor installed off it: {stray_actions:?}"
  );

  // The pairing covers the destination and starts the crawl that owes the rebuild.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(5),
  );
  let paired = drain_events(&mut m);
  assert!(
    paired
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e"])),
    "the pairing covers the destination: {paired:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and the rebuild it owes is counted, so nothing certifies over the window yet"
  );
  m.assert_invariants();

  // The crawl rebuilds the retired slot on a fresh handle, counted.
  let crawl = read_of(&mut m, w_d);
  m.on_enumerate(
    crawl,
    EnumerateResult::Ok(vec![DirEntry::new(seg("c"), FileKind::Dir)]),
  );
  let rebuilt = armed_child(&mut m, w_d, "c");
  assert_ne!(rebuilt, w_c, "on a fresh handle, never the retired one");
  assert!(
    !m.coverage_settled(s),
    "the rebuild is not proof until it acknowledges"
  );
  m.assert_invariants();
  m.ack_watch(rebuilt, Ok(WatchAck::Aliased));
  let rebuilt_read = read_of(&mut m, rebuilt);
  m.on_enumerate(rebuilt_read, EnumerateResult::Ok(Vec::new()));
  let closing = drain_events(&mut m);
  assert!(
    m.coverage_settled(s),
    "the scope settles once the rebuilt read completes"
  );
  assert!(
    closing.iter().any(|e| e.kind().is_rescan()),
    "and it settles behind a closing Rescan, though no acknowledgement in the \
     sequence was Installed: {closing:?}"
  );
  m.assert_invariants();
}

/// Answers every enumerate still OUTSTANDING — including one whose queued action
/// an earlier drain already consumed — until the tree is at rest. The cells below
/// read `coverage_settled`, so a residual read left counted by a setup would make
/// the predicate true for a reason that is not the one under test.
fn settle_reads(m: &mut Monitor) {
  for _ in 0..64 {
    let reqs: Vec<ReqId> = m.pending_enumerate.keys().copied().collect();
    if reqs.is_empty() {
      break;
    }
    for req in reqs {
      m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
    }
  }
  assert!(m.pending_enumerate.is_empty(), "the reads settle");
  let _ = drain_actions(m);
  let _ = drain_events(m);
}

/// A SECOND sequential move, before the first pairing's crawl has descended.
///
/// The first pairing owes the retired slot its rebuild, and pays it by re-arming
/// the move SOURCE and letting the crawl re-install what the listing shows. A
/// second `MovedFrom` that detaches that source again lands the crawl right back
/// inside a hold — where an arm it issues lowers the vacated path once more, so
/// its acknowledgement retires once more.
///
/// That is the shape the objection to retire-and-rebuild was about, and it does
/// not spin: each hold window costs at most one retirement, the next pairing
/// carries the same rebuild forward, and no barrier certifies at any point in
/// between. This cell pins both — the convergence and the ordering.
#[test]
fn a_second_sequential_move_converges_the_rebuild_it_carries() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = held_move_source(&mut m, root, "d");
  let dead = retired_under_a_hold(&mut m, root, w_d);

  // First pairing: d → e. It covers the destination and starts the crawl that
  // owes the rebuild; nothing has descended yet.
  pair_held_source_at(&mut m, root);
  let first_crawl = read_of(&mut m, w_d);
  assert!(
    !m.coverage_settled(s),
    "the crawl the first pairing owes is counted"
  );

  // The second move detaches the source again, BEFORE that crawl answers.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("e"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(20),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // The crawl answers inside the new hold, at a path the detach re-pointed: the
  // listing describes a directory this node is not, so none of it reaches its
  // slots and the bounded retry re-reads from where the node now is.
  m.on_enumerate(
    first_crawl,
    EnumerateResult::Ok(vec![DirEntry::new(seg("n"), FileKind::Dir)]),
  );
  // That retry is issued from inside the hold, so its listing may only ADD — which
  // is how the retired name is re-installed, on an arm that lowers the newly
  // vacated path once more and is retired on its own acknowledgement in turn.
  let retry = read_of(&mut m, w_d);
  m.on_enumerate(
    retry,
    EnumerateResult::Ok(vec![DirEntry::new(seg("n"), FileKind::Dir)]),
  );
  let second = armed_child(&mut m, w_d, "n");
  assert_ne!(second, dead, "the rebuild is a fresh handle");
  m.ack_watch(second, Ok(WatchAck::Installed));
  assert!(
    !m.is_watched(second),
    "and its under-hold acknowledgement certifies nothing either"
  );
  assert!(
    !m.coverage_settled(s),
    "with the second hold carrying the same rebuild forward"
  );
  m.assert_invariants();
  settle_reads(&mut m);
  assert!(
    !m.coverage_settled(s),
    "quiescing the reads does not settle it: the hold is the conjunct"
  );

  // The second move pairs elsewhere. THIS crawl is outside every hold, so the
  // name it re-installs finally acknowledges at a path that is its own.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("f"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(21),
  );
  let paired = drain_events(&mut m);
  assert!(
    paired
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["f"])),
    "the second pairing covers ITS destination: {paired:?}"
  );
  let second_crawl = read_of(&mut m, w_d);
  m.on_enumerate(
    second_crawl,
    EnumerateResult::Ok(vec![DirEntry::new(seg("n"), FileKind::Dir)]),
  );
  let third = armed_child(&mut m, w_d, "n");
  m.ack_watch(third, Ok(WatchAck::Installed));
  assert!(
    m.is_watched(third),
    "an acknowledgement at the node's own path certifies"
  );
  settle_reads(&mut m);
  assert!(m.coverage_settled(s), "and the scope converges");

  // And the converged binding delivers, at the path the second move gave it.
  m.on_os_record(
    OsRecord::new(third, RecordKind::Created).with_name(seg("x")),
    at(30),
  );
  assert!(
    drain_events(&mut m)
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["f", "n", "x"])),
    "the rebuilt binding delivers at the destination"
  );
  m.assert_invariants();
}

/// Drop-mid-everything, with a JUST-RETIRED slot inside the torn-down subtree.
/// The retirement empties a slot under a node that is itself inside a hold, and
/// that node is then deleted out from under it — the shape whose earlier
/// incarnations stranded a marker, a request or a coverage obligation at the drop.
///
/// Nothing is left to strand: the retirement took its handle with it at the
/// acknowledgement, so the walk finds an ordinary subtree. The interval the
/// retirement opened and the one the deletion opens are both carried by the hold's
/// pairing, which covers the destination whole. The subscriber here filters
/// removals — the one that would notice a structural signal standing in for a
/// `Rescan`.
#[test]
fn a_torn_down_subtree_containing_a_just_retired_slot_strands_nothing() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle_with(&mut m, s, Interest::new().with_modified());
  // "k" is armed BEFORE the move, so it is a plain live child; only what arms
  // under the hold takes an unprovable acknowledgement.
  let (w_d, w_k) = held_move_source_covering(&mut m, root, "d", "k");

  // A read under the hold descends to "k" and installs "c" there; that arm's
  // acknowledgement is taken at the vacated pre-move path, so it retires.
  let read = read_queued_under_a_hold(&mut m, root, w_d);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("k"), FileKind::Dir)]),
  );
  let k_read = read_of(&mut m, w_k);
  m.on_enumerate(
    k_read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("c"), FileKind::Dir)]),
  );
  let w_c = armed_child(&mut m, w_k, "c");
  m.ack_watch(w_c, Ok(WatchAck::Installed));
  assert!(
    !m.is_watched(w_c),
    "the acknowledgement taken under the hold retires the binding"
  );
  m.assert_invariants();
  settle_reads(&mut m);
  assert!(
    m.bridge.is_empty(),
    "and the window that carried the setup has closed, so nothing is left to \
     close over what follows"
  );

  // "k" is deleted out from under the hold. A self-event resolves the node rather
  // than being fenced, so the subtree carrying the emptied slot dies here.
  m.on_os_record(OsRecord::new(w_k, RecordKind::DeleteSelf), at(20));
  assert!(!m.is_watched(w_k), "the deleted node is gone");
  assert!(
    m.pending_enumerate.is_empty(),
    "with no read of the torn-down subtree left stranded"
  );
  m.assert_invariants();

  // The hold's pairing carries both intervals — the retirement's and the
  // deletion's — in one cover at the destination, which is the only signal a
  // removal-filtering subscription can receive at all.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let covering = drain_events(&mut m);
  assert!(
    covering
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e"])),
    "the pairing covers the destination whole: {covering:?}"
  );
  settle_reads(&mut m);
  assert!(m.coverage_settled(s), "the scope settles behind the cover");
  m.assert_invariants();
}

/// A read ISSUED while held enumerates coverage-only even if the move pairs
/// (clearing the hold) before the read returns: a pre-existing destination child
/// must not surface as a false Created after the move.
#[test]
fn held_origin_enumerate_stays_coverage_only_across_pairing() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let w_d = held_move_source(&mut m, root, "d");

  // d's read is queued INSIDE the hold, so it is coverage-only from birth.
  let d_req = read_queued_under_a_hold(&mut m, root, w_d);

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
  let root = m
    .register_root(scope(1), mask)
    .expect("a fresh scope registers");
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
  m.ack_watch(root, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  let root = m
    .register_root(scope(1), Interest::new())
    .expect("a fresh scope registers");
  m.ack_watch(root, Ok(WatchAck::Installed));
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
  let root = m
    .register_root(scope(1), mask)
    .expect("a fresh scope registers");
  m.ack_watch(root, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  let root = m
    .register_root(scope(1), mask)
    .expect("a fresh scope registers");
  m.ack_watch(root, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  // The strand's `Removed` and the arrival's `Created` are both suppressed by the
  // proven class — and the one delivery left is the teardown's own cover, which no
  // interest filters. An empty drain here would encode the defect: this subscription
  // would learn nothing at all about a watched subtree whose coverage just ended and
  // was rebuilt at another slot.
  let events = drain_events(&mut m);
  let shape: Vec<(bool, Location)> = events
    .iter()
    .map(|e| (e.kind().is_rescan(), e.location().clone()))
    .collect();
  assert_eq!(
    shape,
    vec![(true, loc(&["e"]))],
    "the pending half proves the class: only the covering Rescan is delivered"
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
  let root = m
    .register_root(scope(1), mask)
    .expect("a fresh scope registers");
  m.ack_watch(root, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  let root = m
    .register_root(scope(1), mask)
    .expect("a fresh scope registers");
  m.ack_watch(root, Ok(WatchAck::Installed));
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

// ---------------------------------------------------------------------------
// A LIVE non-root `Ignored` — a teardown no other record speaks for.
//
// A deletion reaches this handler NEVER: `IN_DELETE_SELF` is subscribed and the
// kernel orders it ahead of the trailing `IN_IGNORED`, and the parent-side
// `Removed` reconciles the slot, so either way the node is torn down first and
// the trailing record dies at `ingest_record`'s opening `scope_of`. What
// survives is a teardown whose slot is occupied still — an `IN_IGNORED` whose
// self-record the queue dropped, or the unmount of the filesystem the scope
// itself sits on, whose per-`wd` teardowns are not ordered against the root's —
// and it owes the same two halves a retired binding owes: an unconditional
// located cover, and a counted replacement. These cells pin both, and the delete
// trace's zero cost.
//
// (A submount BELOW the root reaches none of this: the fs layer's enumerate
// lowering fences descent at the scope's mount frame, so no binding is ever
// installed across one. That fence is guarded end to end by
// `a_submount_is_outside_the_scope_and_raises_no_teardown` in the inotify suite.)
// ---------------------------------------------------------------------------

/// A live non-root teardown ends coverage of a subtree whose slot is occupied
/// still, so it stands a LOCATED epoch-bumping `Rescan` at that slot and a
/// COUNTED replacement in it — and the scope reads unsettled from that instant
/// until the replacement arms and its re-arm read lands.
///
/// Fails on old at the barrier assertion with an empty event stream: the drop was
/// deficit-free, so it discharged nothing, queued nothing and emitted nothing
/// while `coverage_settled` never stopped reading true — permanent coverage loss
/// under a certifying barrier.
#[test]
fn an_unmounted_subtree_is_covered_and_recounted() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  // Identified, so the replacement's own identity is a choice this cell can see.
  let mnt = live_child_dir_ident(&mut m, root, "mnt", ident(11));
  let deep = live_child_dir(&mut m, mnt, "deep");
  settle_reads(&mut m);
  assert!(
    m.coverage_settled(s),
    "a settled scope to lose coverage from"
  );
  let before = m.epoch_of(s);

  m.on_os_record(OsRecord::new(mnt, RecordKind::Ignored), at(20));

  // Read INSIDE the window the record opens: the obligation is counted from here
  // until the rebuilt read lands, so a sync barrier cannot dispatch across it.
  assert!(
    !m.coverage_settled(s),
    "the rebuilt slot is counted work no barrier may certify over"
  );
  assert!(!m.is_watched(mnt), "the torn-down binding is gone");
  assert!(!m.is_watched(deep), "and its subtree with it");

  let covering = drain_events(&mut m);
  let rescan = covering
    .iter()
    .find(|e| e.kind().is_rescan())
    .unwrap_or_else(|| panic!("the coverage loss is signalled: {covering:?}"));
  assert_eq!(
    rescan.location(),
    &loc(&["mnt"]),
    "located at the lost slot, not the scope root"
  );
  assert!(
    rescan.epoch() > before,
    "and its generation dominates whatever the consumer acted on before"
  );

  let fresh = armed_child(&mut m, root, "mnt");
  assert_ne!(fresh, mnt, "the slot is rebuilt under a new handle");
  assert_eq!(
    m.node_identity(fresh),
    None,
    "and with NO identity: nothing here proves the slot still holds the object the \
     dead binding named, so carrying it forward would certify an unproven sameness"
  );
  m.ack_watch(fresh, Ok(WatchAck::Installed));
  assert!(
    !m.coverage_settled(s),
    "the acknowledgement alone does not settle it — the read is still owed"
  );

  let read = read_of(&mut m, fresh);
  m.on_enumerate(read, EnumerateResult::Ok(Vec::new()));
  assert!(m.coverage_settled(s), "and it settles once that read lands");
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "with the window's closing Rescan delivered"
  );
  m.assert_invariants();
}

/// The zero-cost guard. An ordinary directory deletion never reaches the live
/// non-root branch, so covering every teardown that DOES reach it costs a deletion
/// nothing: both kernel orderings — the subscribed `DeleteSelf` ahead of its
/// trailing `Ignored`, and the parent-side `Removed` ahead of both — produce
/// exactly one `Removed`, no `Rescan`, and no replacement watch.
///
/// This is the assumption the uniform rule rests on. If it ever fails, the cover
/// is being paid on every deletion and the rule's cost analysis is wrong.
#[test]
fn a_deleted_directory_pays_for_no_cover() {
  for parent_first in [false, true] {
    let mut m = per_dir();
    let s = scope(1);
    let root = live_root_idle(&mut m, s);
    let sub = live_child_dir(&mut m, root, "sub");
    settle_reads(&mut m);

    let removed = OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("sub"))
      .with_is_dir(true);
    if parent_first {
      m.on_os_record(removed, at(30));
      m.on_os_record(OsRecord::new(sub, RecordKind::Ignored), at(31));
    } else {
      m.on_os_record(OsRecord::new(sub, RecordKind::DeleteSelf), at(30));
      m.on_os_record(OsRecord::new(sub, RecordKind::Ignored), at(31));
      m.on_os_record(removed, at(32));
    }

    let events = drain_events(&mut m);
    assert_eq!(
      events.iter().filter(|e| e.kind().is_removed()).count(),
      1,
      "parent_first={parent_first}: the deletion is reported once: {events:?}"
    );
    assert!(
      events.iter().all(|e| !e.kind().is_rescan()),
      "parent_first={parent_first}: and nothing re-enumerates over it: {events:?}"
    );
    let acts = drain_actions(&mut m);
    assert!(
      acts.iter().all(|a| a.as_watch().is_none()),
      "parent_first={parent_first}: no slot is rebuilt for an object that is gone: {acts:?}"
    );
    assert!(
      m.coverage_settled(s),
      "parent_first={parent_first}: and the scope never leaves settled"
    );
    m.assert_invariants();
  }
}

/// An unmount INSIDE a detached-and-held subtree has no location the handler may
/// address: the tree still reconstructs the vacated pre-move path, so a `Rescan`
/// emitted here would send the consumer to re-read a slot the object has left.
/// The debt rides the hold instead, and the pairing pays it at the destination.
#[test]
fn an_unmount_under_a_hold_defers_its_cover_to_the_pairing() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let (src, kid) = held_move_source_covering(&mut m, root, "d", "k");
  assert!(
    !m.dirtied_holds.contains(&src),
    "a clean hold, so the debt below is this record's"
  );

  m.on_os_record(OsRecord::new(kid, RecordKind::Ignored), at(20));
  let during = drain_events(&mut m);
  assert!(
    during.iter().all(|e| !e.kind().is_rescan()),
    "no Rescan names the stale pre-move path: {during:?}"
  );
  assert!(
    m.dirtied_holds.contains(&src),
    "the hold carries the suppressed loss to its resolution"
  );
  assert!(!m.coverage_settled(s), "and the barrier stays shut over it");

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(21),
  );
  let covering = drain_events(&mut m);
  assert!(
    covering
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e"])),
    "the pairing covers the destination the subtree actually occupies: {covering:?}"
  );
  settle_reads(&mut m);
  assert!(
    m.coverage_settled(s),
    "and the scope settles behind the cover"
  );
  m.assert_invariants();
}

/// The same debt, resolved the other way: no destination ever comes, so the move
/// window expires and the teardown reclaims the dirtied hold — whose cover is
/// COUNTED, because the object it stands for was proven to be moving rather than
/// vanishing.
#[test]
fn an_unmount_under_a_hold_is_covered_when_the_move_window_expires() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let (_src, kid) = held_move_source_covering(&mut m, root, "d", "k");

  m.on_os_record(OsRecord::new(kid, RecordKind::Ignored), at(20));
  let during = drain_events(&mut m);
  assert!(
    during.iter().all(|e| !e.kind().is_rescan()),
    "nothing is emitted at the stale path: {during:?}"
  );

  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let covering = drain_events(&mut m);
  assert!(
    covering.iter().any(|e| e.kind().is_rescan()),
    "the expiry pays the hold's debt rather than dropping it: {covering:?}"
  );
  settle_reads(&mut m);
  assert!(m.coverage_settled(s), "and the scope converges");
  m.assert_invariants();
}

/// The held source is ITSELF unmounted. Its destination is unknowable — the
/// pairing that would have named it is exactly what this teardown destroys — so
/// the cover falls back to the one location that cannot be wrong, the scope root,
/// and it is counted: the drop reclaims the hold this handler just dirtied.
#[test]
fn an_ignored_held_source_stands_the_counted_root_cover() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let (src, _kid) = held_move_source_covering(&mut m, root, "d", "k");

  m.on_os_record(OsRecord::new(src, RecordKind::Ignored), at(20));
  let covering = drain_events(&mut m);
  assert!(
    covering
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "the cover anchors at the root: {covering:?}"
  );
  assert!(
    !m.rearm_settled(s),
    "and it is COUNTED — a bare signal would let a barrier through behind it"
  );

  settle_reads(&mut m);
  assert!(
    m.rearm_settled(s),
    "the count is bounded: one root re-read discharges it"
  );
  // The unpaired half is the only conjunct left; expiring it leaves the scope
  // settled, so nothing this record touched wedges the barrier open.
  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  settle_reads(&mut m);
  assert!(m.coverage_settled(s), "and the scope settles whole");
  m.assert_invariants();
}

/// The replacement's own arm is refused — the re-exposed directory is not there.
/// The terminal is the arm-failure funnel's, unchanged and bounded: a located
/// `Rescan`, a standing slot hole every later sync cookie re-signals, and the
/// counted obligation RELEASED rather than stranded on a node that will never arm.
#[test]
fn a_refused_replacement_for_an_unmounted_slot_ends_in_a_deficit() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let mnt = live_child_dir(&mut m, root, "mnt");
  settle_reads(&mut m);

  m.on_os_record(OsRecord::new(mnt, RecordKind::Ignored), at(20));
  let fresh = armed_child(&mut m, root, "mnt");
  let _ = drain_events(&mut m);
  assert!(
    !m.rearm_settled(s),
    "the replacement is counted while it arms"
  );

  m.ack_watch(fresh, Err(WatchError::NotFound));
  let terminal = drain_events(&mut m);
  assert!(
    terminal
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mnt"])),
    "the refusal stands its own located cover: {terminal:?}"
  );
  assert!(!m.is_watched(fresh), "and the refused node is dropped");
  assert!(
    m.rearm_settled(s),
    "the counted obligation is released, never left on a node nothing can arm"
  );
  assert!(
    m.has_coverage_deficit(s),
    "the slot stays dark, so a cookie dispatched over it must re-signal first"
  );
  assert!(m.resignal_coverage_deficits(s), "which it does");
  m.assert_invariants();
}

/// A cascade: a child's unmount and its parent's, in both orders. The parent's
/// drop sweeps whatever replacement the child's record installed, taking that
/// replacement's count with it, so exactly ONE obligation stands either way — the
/// parent's own — the outer cover names the outer loss, and nothing wedges.
#[test]
fn a_cascading_unmount_sweeps_its_replacement_and_wedges_nothing() {
  for child_first in [true, false] {
    let mut m = per_dir();
    let s = scope(1);
    let root = live_root_idle(&mut m, s);
    let p = live_child_dir(&mut m, root, "p");
    let c = live_child_dir(&mut m, p, "c");
    settle_reads(&mut m);
    assert!(m.rearm_pending.is_empty(), "a settled tree to cascade from");

    if child_first {
      m.on_os_record(OsRecord::new(c, RecordKind::Ignored), at(20));
      m.on_os_record(OsRecord::new(p, RecordKind::Ignored), at(21));
    } else {
      m.on_os_record(OsRecord::new(p, RecordKind::Ignored), at(20));
      m.on_os_record(OsRecord::new(c, RecordKind::Ignored), at(21));
    }

    assert_eq!(
      m.rearm_pending.get(&s).copied(),
      Some(1),
      "child_first={child_first}: one standing obligation, not a stranded pair"
    );
    let covering = drain_events(&mut m);
    assert!(
      covering
        .iter()
        .any(|e| e.kind().is_rescan() && e.location() == &loc(&["p"])),
      "child_first={child_first}: the surviving cover names the outer loss: {covering:?}"
    );

    let fresh = armed_child(&mut m, root, "p");
    m.ack_watch(fresh, Ok(WatchAck::Installed));
    settle_reads(&mut m);
    assert!(
      m.rearm_pending.is_empty(),
      "child_first={child_first}: the count returns to zero"
    );
    assert!(
      m.coverage_settled(s),
      "child_first={child_first}: and the scope converges"
    );
    m.assert_invariants();
  }
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
  let root2 = m
    .register_root(scope(1), Interest::all())
    .expect("the Ignored teardown freed the scope: this re-registration is legitimate");
  m.ack_watch(root2, Ok(WatchAck::Installed));
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
  m.ack_watch(w_p, Ok(WatchAck::Installed));
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

  // …and its delayed watch install FAILS (fenced: no stale-path Rescan), dropping it
  // — and with it the dirty marker the failure had just set, whose debt the teardown
  // funnel discharges at the scope root.
  m.ack_watch(w_d, Err(WatchError::Gone));
  let fenced = drain_events(&mut m);
  assert!(
    fenced
      .iter()
      .all(|e| e.kind().is_rescan() && e.location().is_empty()),
    "nothing reconstructs through the stale pre-move path: {fenced:?}"
  );

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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  m.ack_watch(w_d, Ok(WatchAck::Installed));
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
  // A storm's seeds are statistical convergence coverage, and that is the native
  // runs' job: one seed drives every code path the rest do, while sixty-odd seeds'
  // worth of tree churn exhausts a 32-bit target's entire address space under miri
  // (i686 dies with "no more free addresses"). Miri is here to find UB, so it runs
  // the shape once.
  let seeds: u64 = if cfg!(miri) { 1 } else { 64 };
  for seed in 1..=seeds {
    let mut m = kernel_recursive();
    let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(7);
    let mut rng = || {
      s ^= s << 13;
      s ^= s >> 17;
      s ^= s << 5;
      s
    };

    let roots = [
      m.register_root(scope(1), Interest::all())
        .expect("a fresh scope registers"),
      m.register_root(scope(2), Interest::all())
        .expect("a fresh scope registers"),
    ];
    while m.poll_action().is_some() {}
    m.ack_watch(roots[0], Ok(WatchAck::Installed));
    m.ack_watch(roots[1], Ok(WatchAck::Installed));

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
  m.ack_watch(w_a, Ok(WatchAck::Installed));
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
  m.ack_watch(w_a2, Ok(WatchAck::Installed));
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
  m.ack_watch(w_a, Ok(WatchAck::Installed));
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
  m.ack_watch(w_a2, Ok(WatchAck::Installed));
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
  m.ack_watch(w_a, Ok(WatchAck::Installed));
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
  let r1 = m
    .register_root_with_profile(scope(1), Interest::all(), desc)
    .expect("a fresh scope registers");
  let r2 = m
    .register_root(scope(2), Interest::all())
    .expect("a fresh scope registers");
  m.ack_watch(r1, Ok(WatchAck::Installed));
  m.ack_watch(r2, Ok(WatchAck::Installed));
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
  let r1 = m
    .register_root_with_profile(scope(1), Interest::all(), desc)
    .expect("a fresh scope registers");
  let r2 = m
    .register_root(scope(2), Interest::all())
    .expect("a fresh scope registers");
  m.ack_watch(r1, Ok(WatchAck::Installed));
  m.ack_watch(r2, Ok(WatchAck::Installed));
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
  let r1 = m
    .register_root_with_profile(scope(1), Interest::all(), desc)
    .expect("a fresh scope registers");
  let r2 = m
    .register_root(scope(2), Interest::all())
    .expect("a fresh scope registers");
  m.ack_watch(r1, Ok(WatchAck::Installed));
  m.ack_watch(r2, Ok(WatchAck::Installed));
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
  // A storm's seeds are statistical convergence coverage, and that is the native
  // runs' job: one seed drives every code path the rest do, while sixty-odd seeds'
  // worth of tree churn exhausts a 32-bit target's entire address space under miri
  // (i686 dies with "no more free addresses"). Miri is here to find UB, so it runs
  // the shape once.
  let seeds: u64 = if cfg!(miri) { 1 } else { 64 };
  for seed in 1..=seeds {
    let mut m = kernel_recursive();
    let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(41);
    let mut rng = || {
      s ^= s << 13;
      s ^= s >> 17;
      s ^= s << 5;
      s
    };

    let desc_caps = Capabilities::new().with_supports_push().with_native_move();
    let desc_root = m
      .register_root_with_profile(scope(1), Interest::all(), desc_caps)
      .expect("a fresh scope registers");
    let mut cur_desc_root = desc_root;
    let kr_root = m
      .register_root(scope(2), Interest::all())
      .expect("a fresh scope registers");
    let mut desc_watches = std::vec![desc_root];
    let mut reqs: std::vec::Vec<ReqId> = std::vec::Vec::new();
    while m.poll_action().is_some() {}
    m.ack_watch(desc_root, Ok(WatchAck::Installed));
    m.ack_watch(kr_root, Ok(WatchAck::Installed));

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
          } else if rng() % 2 == 0 {
            Ok(WatchAck::Installed)
          } else {
            Ok(WatchAck::Aliased)
          };
          m.ack_watch(w, res);
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
        cur_desc_root = m
          .register_root_with_profile(scope(1), Interest::all(), desc_caps)
          .expect("a fresh scope registers");
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

/// LIVE-CHURN cold discovery — a `Created` record's arm, its cold read, and the
/// grandchild that read discovers — never unsettles the scope: it runs in
/// non-re-arm states by construction, so ordinary churn inside a settled scope
/// cannot hold [`Monitor::rearm_settled`] down.
///
/// Re-staged past the registration (42-10). The two claims this cell used to
/// make about the BOOTSTRAP — that a pending root arm and the root's own read are
/// not re-arm work — are false by design now and inverted: the registration crawl
/// is counted, which
/// [`the_bootstrap_crawl_is_counted_and_its_first_fence_reads_lossy`] pins. What
/// survives is the claim about churn, and it survives unchanged.
#[test]
fn cold_discovery_never_unsettles_rearm() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  assert!(m.rearm_settled(s), "a settled scope, past its registration");

  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  assert!(
    m.rearm_settled(s),
    "a discovered child's pending arm is not re-arm work"
  );
  let child = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("child watch armed");
  m.ack_watch(child, Ok(WatchAck::Installed));
  assert!(m.rearm_settled(s), "a child's cold read is not re-arm work");
  let cold = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == child)
        .map(|e| e.req())
    })
    .expect("the child's cold read");
  m.on_enumerate(
    cold,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  assert!(
    m.rearm_settled(s),
    "a grandchild discovered by a cold read is not re-arm work"
  );
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

/// 42-10 cell 5 — the counted-semantics half. The registration crawl is RE-ARM
/// work from the grant: its root is born re-arm-flavored (which is the
/// suppression), so `rearm_settled` reads false from the registration until the
/// whole crawl quiesces, and a cover fence opened right after the grant
/// consequently reads LOSSY. That is the honest outcome — it instructs exactly
/// the crawl the contract already told the consumer to perform — and it is the
/// price of the suppression, so it is pinned rather than left to drift.
///
/// Mutation that kills it: make the bootstrap crawl uncounted (birth the root
/// `rearm: false` again), which also un-suppresses the inventory.
#[test]
fn the_bootstrap_crawl_is_counted_and_its_first_fence_reads_lossy() {
  let mut m = per_dir();
  let s = scope(1);

  let root = m
    .register_root(s, Interest::all())
    .expect("a fresh scope registers");
  assert!(
    !m.rearm_settled(s),
    "the registration's crawl is counted from the grant"
  );
  assert!(
    !m.coverage_settled(s),
    "so a cover fence opened at the grant reads lossy"
  );
  m.ack_watch(root, Ok(WatchAck::Installed));
  assert!(!m.rearm_settled(s), "the root's own read is counted");
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  assert!(
    !m.rearm_settled(s),
    "and so is the discovered child's pending arm"
  );
  let child = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("child watch armed");
  m.ack_watch(child, Ok(WatchAck::Installed));
  assert!(!m.rearm_settled(s), "and the child's own crawl read");
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == child)
        .map(|e| e.req())
    })
    .expect("the child's crawl read");
  m.on_enumerate(read, EnumerateResult::Ok(Vec::new()));
  assert!(m.rearm_settled(s), "the crawl quiesced");
  assert!(m.coverage_settled(s), "and the fence opens");
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
  m.ack_watch(fresh, Ok(WatchAck::Installed));
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
///
/// Re-staged on a POST-REGISTRATION cold read (42-10): the registration crawl is
/// counted now, so the cold read a grow can coalesce onto is a live-discovered
/// directory's, never the root's own bootstrap read.
#[test]
fn coalesced_grow_rides_the_inflight_cold_read() {
  let mut m = per_dir();
  let s = scope(1);

  // A live-discovered directory whose COLD read is still outstanding.
  let root = live_root_idle(&mut m, s);
  let d = discovered_child_dir(&mut m, root, "d");
  m.ack_watch(d, Ok(WatchAck::Installed));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == d).map(|e| e.req()))
    .expect("the discovered directory's cold read");
  assert!(m.rearm_settled(s), "a cold read is not re-arm work");

  // The grow coalesces onto the in-flight cold read: latent, and reported as such.
  assert!(m.rearm_watch_subtree(d).is_coalesced());
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
  let root = kr
    .register_root(s, Interest::all())
    .expect("a fresh scope registers");
  kr.ack_watch(root, Ok(WatchAck::Installed));
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

  assert_eq!(
    m.rebind_root(scope(1)).map(|(id, _)| id),
    Some(root),
    "the WatchId survives"
  );
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
  m.ack_watch(root, Ok(WatchAck::Installed));
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
  m.ack_watch(child, Ok(WatchAck::Installed));
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
  assert_eq!(m.rebind_root(scope(1)).map(|(id, _)| id), Some(root));
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
  assert_eq!(kr.rebind_root(scope(1)).map(|(id, _)| id), None);

  let mut m = per_dir();
  assert_eq!(m.rebind_root(scope(9)).map(|(id, _)| id), None);
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

  assert_eq!(m.rebind_root(scope(1)).map(|(id, _)| id), Some(root));
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

/// A rebind lands while a ROOT-SLOT stat is outstanding — the one coordinate
/// the rebind's own settlement does not reach. Children are dropped, the root's
/// read is disowned and its arm superseded, but `pending_stat` is keyed by
/// `(root, name)` and the root survives the rebind, so an answer for the OLD
/// root's path would settle the NEW root's slot. Here it would report the slot
/// empty and discharge its recorded darkness, over a world where nothing has
/// been looked at yet.
///
/// The placement clock is what separates the worlds: the rebind records that
/// the root's own placement changed, so the answer is refused as the non-proof
/// it is and the darkness stands for the new world's own crawl to clear.
#[test]
fn a_root_slot_stat_crossing_a_rebind_does_not_settle_the_new_world() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root(&mut m, s);
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  // An unclassifiable slot is what asks for a stat; unwatched, it books its
  // darkness for exactly as long as the answer is owed.
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("u"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassified slot is stat'd");
  assert!(
    m.has_coverage_deficit(s),
    "and books its darkness meanwhile"
  );

  assert_eq!(m.rebind_root(s).map(|(id, _)| id), Some(root));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));
  assert!(
    m.has_coverage_deficit(s),
    "the old world's answer cannot report the new world's slot empty"
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

  assert_eq!(m.rebind_root(scope(1)).map(|(id, _)| id), Some(root));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.ack_watch(child, Ok(WatchAck::Installed));
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
  m.ack_watch(child, Ok(WatchAck::Installed));
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
  assert_eq!(m.rebind_root(scope(1)).map(|(id, _)| id), Some(root));
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
  m.ack_watch(root, Ok(WatchAck::Installed));
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
  m.ack_watch(a_watch, Ok(WatchAck::Installed));
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
  m.ack_watch(fresh, Ok(WatchAck::Installed));
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
  m.ack_watch(a1, Err(WatchError::NoSpace));
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
  m.ack_watch(a2, Err(WatchError::NoSpace));
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
  m.ack_watch(a3, Ok(WatchAck::Installed));
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
  m.ack_watch(a, Ok(WatchAck::Installed));
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
  m.ack_watch(b, Ok(WatchAck::Installed));
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
  m.ack_watch(a, Err(WatchError::NoSpace));
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
  let root = m
    .register_root(scope(1), mask)
    .expect("a fresh scope registers");
  m.ack_watch(root, Ok(WatchAck::Installed));
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
  m.ack_watch(a, Err(WatchError::NoSpace));
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
    m.ack_watch(w, Err(WatchError::NoSpace));
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
    m.ack_watch(w, Err(WatchError::NoSpace));
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

/// The re-signal RETIRES the entry it kicks for, so its kick must land in every
/// state the anchor can be in. A widen splices a fresh root that stays `Arming`
/// until the driver replays its pre-arm outcome, while the old world's collapsed
/// book rides across untouched — and a bare re-arm answers `Refused` for `Arming`.
/// Retiring the whole-scope marker behind a refused kick leaves the scope reading
/// settled AND deficit-free over interiors no crawl ever revisits.
#[test]
fn a_collapsed_book_resignal_counts_its_heal_under_an_arming_root() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root(&mut m, s);

  // Collapse the book: `DEFICIT_CAP` + 1 unclassifiable names in one listing, each
  // booking an uncovered slot.
  let boot = read_of(&mut m, root);
  let unknown: Vec<DirEntry> = (0..=DEFICIT_CAP)
    .map(|i| DirEntry::new(seg(&std::format!("u{i:02}")), FileKind::Unknown))
    .collect();
  m.on_enumerate(boot, EnumerateResult::Ok(unknown));
  assert!(m.has_coverage_deficit(s));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // The widen splices a new root ABOVE this one and discharges nothing: the old
  // world did not end, so its darkness rides across — under a root whose pre-arm
  // outcome the driver has not replayed yet.
  let reserved = m.reserve_watch_id();
  assert!(
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
      .is_some()
  );
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  assert!(
    m.has_coverage_deficit(s),
    "the widen does not discharge the old world's darkness"
  );
  assert!(m.rearm_settled(s), "and nothing is counted yet");

  assert!(m.resignal_coverage_deficits(s));
  assert!(
    !m.has_coverage_deficit(s),
    "the collapsed marker is retired optimistically"
  );
  assert!(
    !m.rearm_settled(s),
    "so a counted heal must stand in its place"
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
  m.ack_watch(a, Ok(WatchAck::Installed));
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
  m.ack_watch(b, Ok(WatchAck::Installed));
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
  m.ack_watch(d, Ok(WatchAck::Installed));
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
  m.ack_watch(a, Err(WatchError::NoSpace));
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
  m.ack_watch(c, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  m.on_overflow(SubtreeScope::new(c).into(), at(4));
  assert!(m.has_coverage_deficit(scope(1)));
  assert!(!m.coverage_settled(scope(1)));

  // The floor an unknown scope reads. Named through the private field because
  // nothing outside this module can name a coverage-work epoch at all.
  let never_acquired = CoverageWorkEpoch(0);
  assert!(
    m.coverage_work_epoch(scope(1)) > never_acquired,
    "work was acquired"
  );

  m.unregister_root(scope(1));
  assert!(!m.has_coverage_deficit(scope(1)));
  assert!(
    m.coverage_settled(scope(1)),
    "a dead scope is trivially settled"
  );
  assert_eq!(
    m.coverage_work_epoch(scope(1)),
    never_acquired,
    "and holds no coverage-work generation"
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
  m.ack_watch(a1, Err(WatchError::NoSpace));
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
  m.ack_watch(a2, Ok(WatchAck::Installed));
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
  m.ack_watch(p2, Ok(WatchAck::Installed));
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
  m.ack_watch(g, Ok(WatchAck::Installed));
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

/// The carry's overreach guard (the A2 companion), and the split between the
/// crawl's TWO obligations. A crawl that drops and rebuilds an
/// identity-unconfirmable child with NO recorded deficit under it books
/// nothing: the carry fires only on an ACTUAL erasure, so no phantom hole
/// appears. It is not silent, though — retiring a watch over a name the
/// listing PROVES is occupied ends live coverage, which the cover below owes
/// independently of any deficit. The `Rescan` is the ONLY instruction the
/// rebuild produces; the suppressed re-install still emits no `Created`.
#[test]
fn a_deficit_free_crawl_rebuild_covers_but_books_nothing() {
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
  m.ack_watch(p2, Ok(WatchAck::Installed));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == p2).map(|e| e.req()))
    .expect("the rebuilt directory re-arm-enumerates");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  let events = drain_events(&mut m);
  assert!(
    events.iter().all(|e| e.kind().is_rescan()),
    "a re-arm rebuild announces no Created: {events:?}"
  );
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "but retiring coverage of a listed-live slot owes its cover: {events:?}"
  );
  assert!(
    !m.has_coverage_deficit(scope(1)),
    "and books no phantom hole"
  );
  m.assert_invariants();
}

/// The pure-grow cover (fail-on-old). [`Monitor::rearm_watch_subtree`] is the
/// ONE entry into the crawl-rebuild path that stands no `Rescan` of its own,
/// and a record-installed child carries no identity, so the crawl retires a
/// child the listing PROVES is occupied — together with every descendant
/// `WatchId`. A record the backend had already queued on one of those ids is
/// then discarded as an unrecognized watch, while the rebuilt slot is
/// `Created`-suppressed: on old, the window closed with nothing on the wire
/// and the next sync resolved a false `Delivered` over the discarded record.
/// The barrier must also stay shut for the whole dark interval, so no cookie
/// can be dispatched ahead of the cover.
#[test]
fn a_pure_grow_crawl_covers_the_live_slot_it_retires() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let p = live_child_dir(&mut m, root, "p");
  let g = live_child_dir(&mut m, p, "g");
  assert!(
    m.coverage_settled(scope(1)),
    "the grow starts from quiescence"
  );

  // A PURE grow: no overflow, no loss, no incomplete read — nothing has stood
  // a `Rescan` for this scope, so the window opens clean.
  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("p"), FileKind::Dir).with_node(ident(7)),
    ]),
  );
  assert!(!m.is_watched(p), "the unconfirmable child is retired");
  assert!(!m.is_watched(g), "and so is its descendant");
  assert!(
    !m.coverage_settled(scope(1)),
    "the counted rebuild holds the barrier shut across the dark window"
  );

  // The record the backend had already queued on the retired descendant
  // arrives and is discarded — the darkness this cover exists for.
  m.on_os_record(
    OsRecord::new(g, RecordKind::Modified).with_name(seg("f")),
    at(4),
  );
  assert!(!m.coverage_settled(scope(1)));

  let p2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the retired slot re-installs");
  m.ack_watch(p2, Ok(WatchAck::Installed));
  let p2_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == p2).map(|e| e.req()))
    .expect("the rebuilt directory re-arm-enumerates");
  m.on_enumerate(
    p2_read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("g"), FileKind::Dir)]),
  );
  let g2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the descendant re-installs");
  m.ack_watch(g2, Ok(WatchAck::Installed));
  let g2_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == g2).map(|e| e.req()))
    .expect("the rebuilt descendant re-arm-enumerates");
  m.on_enumerate(g2_read, EnumerateResult::Ok(vec![]));

  // The barrier reopens only now — and only over a delivered instruction.
  assert!(m.coverage_settled(scope(1)));
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "the retired live slot must leave a covering Rescan: {events:?}"
  );
  assert!(
    events.iter().all(|e| e.kind().is_rescan()),
    "the discarded record's darkness is covered by the Rescan alone — the \
     rebuild announces no Created: {events:?}"
  );
  m.assert_invariants();
}

/// The cover is COALESCED per crawl, not per child: an identity-less backend
/// can confirm no child at all, so one `Rescan` per rebuilt entry would storm
/// a `Rescan` per listing. One crawl retiring three live slots stands exactly
/// ONE opening `Rescan` at the crawled directory, and the window still closes
/// with its own single root `Rescan` once the rebuild quiesces.
#[test]
fn one_crawl_stands_one_cover_not_one_per_child() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  for name in ["a", "b", "c"] {
    let _ = live_child_dir(&mut m, root, name);
  }

  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(7)),
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(8)),
      DirEntry::new(seg("c"), FileKind::Dir).with_node(ident(9)),
    ]),
  );
  let opening = drain_events(&mut m);
  assert_eq!(
    opening.len(),
    1,
    "three retired slots, ONE cover for the crawl: {opening:?}"
  );
  assert!(opening[0].kind().is_rescan());
  assert_eq!(
    opening[0].location(),
    &Location::new(),
    "located at the crawled directory"
  );

  // Drive all three rebuilds to quiescence.
  let installs: Vec<WatchId> = drain_actions(&mut m)
    .iter()
    .filter_map(|a| a.as_watch().map(|w| w.id()))
    .collect();
  assert_eq!(installs.len(), 3, "every retired slot re-installs");
  for id in &installs {
    m.ack_watch(*id, Ok(WatchAck::Installed));
  }
  let reads: Vec<ReqId> = drain_actions(&mut m)
    .iter()
    .filter_map(|a| a.as_enumerate().map(|e| e.req()))
    .collect();
  assert_eq!(reads.len(), 3);
  for req in reads {
    m.on_enumerate(req, EnumerateResult::Ok(vec![]));
  }

  assert!(m.rearm_settled(scope(1)));
  let closing = drain_events(&mut m);
  assert_eq!(
    closing.len(),
    1,
    "and one closing Rescan for the arm gap: {closing:?}"
  );
  assert!(closing[0].kind().is_rescan());
  assert!(closing[0].epoch() > opening[0].epoch());
  m.assert_invariants();
}

/// A live, idle child directory whose object identity the monitor KNOWS, so a
/// listing carrying the same identity confirms it as a survivor and the crawl
/// retires nothing.
fn live_child_dir_ident(m: &mut Monitor, parent: WatchId, name: &str, id: Identity) -> WatchId {
  m.on_os_record(
    OsRecord::new(parent, RecordKind::Created)
      .with_name(seg(name))
      .with_is_dir(true)
      .with_node(id),
    at(1),
  );
  let child = drain_actions(m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the discovered directory arms");
  m.ack_watch(child, Ok(WatchAck::Installed));
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

/// The cover's overreach guard — the gate that keeps the fix bounded. The
/// crawl's OPENING cover answers for RETIREMENT, not churn: a crawl whose
/// every incumbent is identity-confirmed retires no watch at all, so no
/// `WatchId` is invalidated and no queued record is orphaned, and the gate
/// stays silent.
///
/// The fresh name `q` beside the survivors is a second obligation with a
/// second vehicle, and here it is silent for its OWN reason rather than for
/// the crawl's: a suppressed install over ground that reads back EMPTY
/// absorbed nothing, so it supplies no loss half and the window closes on
/// `fresh_rearm` alone. Ground that read back WITH content would stand the
/// closing `Rescan` — see
/// `a_regrow_over_dark_ground_with_content_stands_the_cover` — so what this
/// cell pins is the emptiness of `q`, never a general licence for grows.
#[test]
fn a_crawl_that_retires_nothing_emits_nothing() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let p = live_child_dir_ident(&mut m, root, "p", ident(7));

  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the grow re-arm-enumerates the root");
  // `p` is confirmed unchanged; `q` is new.
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("p"), FileKind::Dir).with_node(ident(7)),
      DirEntry::new(seg("q"), FileKind::Dir),
    ]),
  );
  assert!(m.is_watched(p), "the confirmed survivor keeps its watch");
  let actions = drain_actions(&mut m);
  let q = actions
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the new name installs");
  let p_read = actions
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == p).map(|e| e.req()))
    .expect("the survivor re-arms downward");
  m.on_enumerate(p_read, EnumerateResult::Ok(vec![]));
  m.ack_watch(q, Ok(WatchAck::Installed));
  let q_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == q).map(|e| e.req()))
    .expect("the new directory re-arm-enumerates");
  m.on_enumerate(q_read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  assert!(
    drain_events(&mut m).is_empty(),
    "a crawl that retires nothing owes no cover"
  );
  assert!(
    !m.has_coverage_deficit(scope(1)),
    "and books no phantom hole"
  );
  m.assert_invariants();
}

/// The dark-ground cover (fail-on-old). A PURE set-cover grow re-covers ground
/// the monitor had pruned away, and the crawl that re-arms it is suppressed: it
/// installs watches and announces nothing. Anything that ground gained while it
/// was dark is therefore absorbed in silence — no watch was armed to record it,
/// and the re-arm read emits no `Created` — while the crawl RETIRES nothing, so
/// the crawl's own cover gate stays silent too.
///
/// On old the window closed on `fresh_rearm` alone and the whole interval was
/// lost: nothing supplied the loss half outside the registration window, so a
/// sync barrier settled clean over `fresh`. The fix supplies it from the one
/// place that can know — the freshly-armed node's own listing, which comes back
/// with content.
#[test]
fn a_regrow_over_dark_ground_with_content_stands_the_cover() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let pruned = live_child_dir(&mut m, root, "drop");
  assert!(
    m.coverage_settled(scope(1)),
    "the sequence starts from quiescence"
  );

  // The prune: `/r/drop` leaves coverage entirely. An unsubscribed prune stands
  // nothing by contract, so the window this opens is CLEAN.
  assert!(m.drop_watch_subtree(pruned));
  let _ = drain_actions(&mut m);
  assert!(
    drain_events(&mut m).is_empty(),
    "an unsubscribed prune covers nothing"
  );
  assert!(m.coverage_settled(scope(1)));

  // ... `mkdir /r/drop/fresh` lands HERE, with nothing watching it ...

  // The re-cover. No overflow, no loss, no incomplete read: nothing has stood a
  // `Rescan` for this scope, so the only cover this window can close with is one
  // the regrow itself supplies.
  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("drop"), FileKind::Dir)]),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the crawl retires nothing, so it opens nothing"
  );
  let regrown = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the pruned directory re-installs");
  m.ack_watch(regrown, Ok(WatchAck::Installed));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == regrown)
        .map(|e| e.req())
    })
    .expect("the re-installed directory re-arm-enumerates");

  // The dark window's content, absorbed in silence: `fresh` is listed, and the
  // suppressed read announces no `Created` for it.
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("fresh"), FileKind::Dir)]),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "and the rebuild still announces nothing mid-window"
  );
  let fresh = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the dark ground's directory arms");
  m.ack_watch(fresh, Ok(WatchAck::Installed));
  let fresh_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == fresh)
        .map(|e| e.req())
    })
    .expect("it re-arm-enumerates in turn");
  m.on_enumerate(fresh_read, EnumerateResult::Ok(vec![]));

  // The settle edge: `fresh_rearm` from the regrown install, `saw_rescan` from
  // that node's own non-empty read.
  assert!(m.rearm_settled(scope(1)));
  assert!(m.coverage_settled(scope(1)));
  let closing = drain_events(&mut m);
  assert_eq!(
    closing.len(),
    1,
    "one closing Rescan covers the dark interval: {closing:?}"
  );
  assert!(closing[0].kind().is_rescan());
  assert_eq!(closing[0].location(), &Location::new());
  m.assert_invariants();
}

/// The dark-ground cover's overreach guard, and the reason it is content-gated
/// rather than keyed on the install. The same prune-then-regrow sequence over
/// ground that comes back EMPTY absorbed nothing: there was no unreported
/// content under it, so the closing `Rescan` would instruct the consumer to
/// re-read nothing. Firing on the bare fresh install instead would put one on
/// the wire for every prune/regrow cycle the monitor performs.
#[test]
fn a_regrow_over_empty_dark_ground_stays_silent() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let pruned = live_child_dir(&mut m, root, "drop");

  assert!(m.drop_watch_subtree(pruned));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  assert!(m.coverage_settled(scope(1)));

  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("drop"), FileKind::Dir)]),
  );
  let regrown = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the pruned directory re-installs");
  m.ack_watch(regrown, Ok(WatchAck::Installed));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == regrown)
        .map(|e| e.req())
    })
    .expect("the re-installed directory re-arm-enumerates");

  // Nothing was there while the ground was dark.
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  assert!(m.coverage_settled(scope(1)));
  assert!(
    drain_events(&mut m).is_empty(),
    "empty dark ground absorbed nothing, so it owes nothing"
  );
  assert!(
    !m.has_coverage_deficit(scope(1)),
    "and books no phantom hole"
  );
  m.assert_invariants();
}

/// The marker's lifecycle guard: the question a fresh install leaves is spent
/// at that node's FIRST evidence-clean read, whichever way the verdict goes.
///
/// A node whose first read comes back empty owes nothing — and must not keep
/// the question standing, because the very same node is re-read later on
/// ordinary occasions (an overflow recovery, a deficit heal kick, another
/// grow). A marker cleared only on the firing branch would be answered by THAT
/// read's content and stand a loss half for a window in which the node armed no
/// new ground at all, re-creating the prune/regrow degradation one node at a
/// time. Window two below is clean by construction: `n` appeared while `a` was
/// watched, so its creation was recorded live.
#[test]
fn a_fresh_install_that_read_empty_owes_a_later_rearm_nothing() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let pruned = live_child_dir(&mut m, root, "a");
  assert!(m.drop_watch_subtree(pruned));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Window one: the regrow arms `a` over ground that reads back EMPTY, so the
  // question the install left is answered "no content" — and spent.
  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::Dir)]),
  );
  let regrown = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the pruned directory re-installs");
  m.ack_watch(regrown, Ok(WatchAck::Installed));
  let first = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == regrown)
        .map(|e| e.req())
    })
    .expect("the re-installed directory re-arm-enumerates");
  m.on_enumerate(first, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(scope(1)));
  assert!(
    drain_events(&mut m).is_empty(),
    "window one: empty ground owes nothing"
  );
  let _ = drain_actions(&mut m);

  // Window two: an ordinary later re-arm of that SAME node, whose read now
  // finds a directory that appeared while `a` was covered.
  assert!(m.rearm_watch_subtree(regrown).is_started());
  let second = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == regrown)
        .map(|e| e.req())
    })
    .expect("the later trigger re-arm-enumerates the same node");
  m.on_enumerate(
    second,
    EnumerateResult::Ok(vec![DirEntry::new(seg("n"), FileKind::Dir)]),
  );
  let n = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the new name installs");
  m.ack_watch(n, Ok(WatchAck::Installed));
  let n_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == n).map(|e| e.req()))
    .expect("and re-arm-enumerates in turn");
  m.on_enumerate(n_read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  assert!(m.coverage_settled(scope(1)));
  assert!(
    drain_events(&mut m).is_empty(),
    "window one's spent question answers nothing in window two"
  );
  m.assert_invariants();
}

/// The replace-inherit seam. A mid-re-arm incumbent replaced at its slot is
/// torn down and re-installed, and the replacement is a FRESH watch over ground
/// no watch covers, read-SUPPRESSED through the re-arm obligation it inherits —
/// everything a named install site means, reached at neither of them. The
/// unanswered content question rides across with the obligation, so the
/// replacement's own listing still stands the cover its content is owed.
///
/// A `Modified`-only subscription is what makes the loss visible: the driving
/// `Created` is interest-subject and delivers nothing at all here, so the
/// closing `Rescan` is the whole of this consumer's instruction.
#[test]
fn a_replaced_fresh_install_carries_its_cover_to_the_replacement() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());

  // A pure grow arms `d` over dark ground; its arm is still outstanding, so the
  // node is mid-re-arm with its content question unanswered.
  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("d"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  let stale = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the dark ground arms");
  assert!(drain_events(&mut m).is_empty());

  // The replacement: a `Created` naming a DIFFERENT object at the same name,
  // landing before that arm is acknowledged.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true)
      .with_node(ident(2)),
    at(2),
  );
  assert!(!m.is_watched(stale), "the replaced incumbent is retired");
  let replacement = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the replacement arms in its place");
  assert!(
    drain_events(&mut m).is_empty(),
    "a Modified-only subscriber is told nothing by the Created"
  );

  m.ack_watch(replacement, Ok(WatchAck::Installed));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == replacement)
        .map(|e| e.req())
    })
    .expect("the replacement re-arm-enumerates");
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("x"), FileKind::Dir)]),
  );
  let x = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("its content arms in turn");
  m.ack_watch(x, Ok(WatchAck::Installed));
  let x_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == x).map(|e| e.req()))
    .expect("and re-arm-enumerates");
  m.on_enumerate(x_read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  assert!(m.coverage_settled(scope(1)));
  let closing = drain_events(&mut m);
  assert_eq!(
    closing.len(),
    1,
    "the transferred question still stands its cover: {closing:?}"
  );
  assert!(closing[0].kind().is_rescan());
  assert_eq!(closing[0].location(), &Location::new());
  m.assert_invariants();
}

/// The absent-slot cover (fail-on-old). A crawl retires a child the fresh
/// listing OMITS, and rebuilds NOTHING in its place — the install loop only
/// descends into listed directories — so unlike the listed-directory
/// retirement there is no counted successor whose closing `Rescan` could
/// stand for the window. A `Modified` the backend had already queued on a
/// descendant of the retired subtree then arrives and is discarded as an
/// unrecognized watch, while the vanish's `Removed` is interest-subject: a
/// `Modified`-only subscription receives nothing at all. On old the crawl was
/// silent here — the cover gate read the directories-only `present` index, so
/// an omitted name never set it — and the next sync resolved a clean verdict
/// over the discarded record.
#[test]
fn a_crawl_covers_the_slot_an_absent_name_retires() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let p = live_child_dir(&mut m, root, "p");
  let g = live_child_dir(&mut m, p, "g");
  assert!(
    m.coverage_settled(scope(1)),
    "the grow starts from quiescence"
  );

  // A PURE grow: no overflow, no loss, no incomplete read — nothing has stood
  // a `Rescan` for this scope, so the window opens clean.
  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(rearm, EnumerateResult::Ok(vec![]));
  assert!(!m.is_watched(p), "the omitted name is retired");
  assert!(!m.is_watched(g), "and so is its descendant");

  // Nothing was rebuilt, so the barrier reads settled the instant the crawl
  // returns — which is sound ONLY because the cover is already on the wire at
  // that same instant: a fence resolving on this observation is ordered behind
  // it, and cannot certify a clean window.
  assert!(
    m.coverage_settled(scope(1)),
    "an unrebuilt slot leaves nothing counted to wait on"
  );
  let cover = drain_events(&mut m);
  assert_eq!(
    cover.len(),
    1,
    "so the cover must already be on the wire: {cover:?}"
  );
  assert!(cover[0].kind().is_rescan());
  assert_eq!(
    cover[0].location(),
    &Location::new(),
    "located at the crawled directory"
  );

  // The record the backend had already queued on the retired descendant
  // arrives and is discarded — the darkness the cover exists for. It describes
  // a moment when the object still existed, so the cover's delivery-time
  // re-read is what stands in for it.
  m.on_os_record(
    OsRecord::new(g, RecordKind::Modified).with_name(seg("f")),
    at(4),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the orphaned record delivers nothing of its own"
  );
  m.assert_invariants();
}

/// The same loss through the other door: the listing does not omit the name,
/// it reports it as a FILE. That is equally unrebuilt — `present` indexes
/// directories only, and the install loop skips a non-directory — so the
/// retirement again has no counted successor, and the `Rescan` is again the
/// whole cover. Fails on old for the same reason: a `File` entry is absent
/// from the directories-only index, so the old gate could not see it either.
#[test]
fn a_crawl_covers_the_slot_a_file_entry_retires() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let p = live_child_dir(&mut m, root, "p");
  let g = live_child_dir(&mut m, p, "g");

  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  // The name is still there — as a file. The directory it named is gone.
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("p"), FileKind::File)]),
  );
  assert!(!m.is_watched(p), "the replaced name is retired");
  assert!(!m.is_watched(g), "and so is its descendant");
  assert!(
    drain_actions(&mut m).iter().all(|a| a.as_watch().is_none()),
    "and nothing re-installs over a proven non-directory"
  );

  assert!(
    m.coverage_settled(scope(1)),
    "an unrebuilt slot leaves nothing counted to wait on"
  );
  let cover = drain_events(&mut m);
  assert_eq!(
    cover.len(),
    1,
    "so the cover must already be on the wire: {cover:?}"
  );
  assert!(cover[0].kind().is_rescan());
  assert_eq!(cover[0].location(), &Location::new());

  m.on_os_record(
    OsRecord::new(g, RecordKind::Modified).with_name(seg("f")),
    at(4),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the orphaned record delivers nothing of its own"
  );
  m.assert_invariants();
}

/// The unrebuilt cover coalesces exactly like the listed one: one crawl
/// retiring THREE slots no successor rebuilds — two omitted names and one now
/// listed as a file — stands ONE opening `Rescan` at the crawled directory,
/// not one per child. Nothing is armed fresh, so that cover is also the
/// window's only signal: no rebuild follows to close it.
#[test]
fn one_crawl_stands_one_cover_for_many_unrebuilt_slots() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  for name in ["a", "b", "c"] {
    let _ = live_child_dir(&mut m, root, name);
  }

  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  // `a` and `c` are omitted, `b` is now a file. None is rebuilt.
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b"), FileKind::File)]),
  );
  let opening = drain_events(&mut m);
  assert_eq!(
    opening.len(),
    1,
    "three unrebuilt retirements, ONE cover: {opening:?}"
  );
  assert!(opening[0].kind().is_rescan());
  assert_eq!(
    opening[0].location(),
    &Location::new(),
    "located at the crawled directory"
  );
  assert!(
    drain_actions(&mut m).iter().all(|a| a.as_watch().is_none()),
    "and nothing re-installs"
  );

  assert!(m.rearm_settled(scope(1)));
  assert!(
    drain_events(&mut m).is_empty(),
    "the opening cover is the whole of it — nothing armed fresh to close"
  );
  m.assert_invariants();
}

/// Why the unrebuilt cover must NOT borrow the listed one's `bridge_is_lossy`
/// suppression, and the cross-flavor coalesce in one cell. An overflow
/// recovery stands its own `Rescan` first, so the window is already lossy when
/// its crawl runs; that crawl retires an omitted name (unrebuilt) alongside an
/// identity-unconfirmable directory (rebuilt, and suppressed here precisely
/// because its rebuild is counted). The suppression is sound only for a site
/// that also makes the window counted — and the unrebuilt slot arms nothing,
/// so deferring to the conjunction would defer to a closing `Rescan` this
/// window may never mint. Exactly ONE opening `Rescan` is owed: not zero (the
/// old gate, and a wrongly-suppressed fix, both emit none) and not two.
#[test]
fn an_unrebuilt_retirement_covers_inside_an_already_lossy_window() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let p = live_child_dir(&mut m, root, "p");
  let d = live_child_dir(&mut m, root, "d");

  // The overflow stands the window's opening loss and kicks the crawl.
  m.on_overflow(Scope::Root(scope(1)), at(2));
  let overflowed = drain_events(&mut m);
  assert!(
    overflowed.iter().any(|e| e.kind().is_rescan()),
    "the overflow marks the window lossy: {overflowed:?}"
  );
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the recovery re-arm-enumerates the root");
  // `p` is omitted (unrebuilt); `d` is listed, so it is retired and rebuilt.
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("d"), FileKind::Dir).with_node(ident(9)),
    ]),
  );
  assert!(!m.is_watched(p), "the omitted name is retired");
  assert!(!m.is_watched(d), "and so is the unconfirmable one");

  let opening = drain_events(&mut m);
  assert_eq!(
    opening.len(),
    1,
    "the unrebuilt slot still owes a cover inside a lossy window, and both \
     flavors share it: {opening:?}"
  );
  assert!(opening[0].kind().is_rescan());
  assert_eq!(opening[0].location(), &Location::new());
  m.assert_invariants();
}

/// The cover must reach the subscription that no structural signal reaches. A
/// `Modified`-only subscriber sees neither the retired subtree's `Removed` nor
/// the rebuild's (suppressed) `Created`, so the covering `Rescan` — the one
/// signal that bypasses both interest and filter — is its ONLY instruction to
/// re-read what the retired `WatchId`s stopped covering.
#[test]
fn the_crawl_cover_reaches_a_modified_only_subscription() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  let _p = live_child_dir(&mut m, root, "p");

  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("p"), FileKind::Dir).with_node(ident(7)),
    ]),
  );
  let p2 = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the retired slot re-installs");
  m.ack_watch(p2, Ok(WatchAck::Installed));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == p2).map(|e| e.req()))
    .expect("the rebuilt directory re-arm-enumerates");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));

  assert!(m.rearm_settled(scope(1)));
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_rescan()),
    "a Rescan is delivered regardless of the registered interest: {events:?}"
  );
  m.assert_invariants();
}

/// The carry when the crawl does NOT rebuild the slot (the name vanished
/// from the listing): the retirement's own opening `Rescan` stands, the loss
/// fact stays booked at the surviving parent — a sync dispatched before the
/// in-flight `Removed` lands re-signals it — and the `Removed`'s arrival
/// clears the re-anchored carry AND stands a covering `Rescan` (the removal is
/// filter-subject, so a `Modified`-only sub that never saw it still learns the
/// darkness ended). Fails on old: the clear was silent, so that filtered sub's
/// next sync resolved a false `Delivered`.
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
  let cover = drain_events(&mut m);
  assert_eq!(
    cover.len(),
    1,
    "the retirement stands its own opening Rescan, unrebuilt: {cover:?}"
  );
  assert!(cover[0].kind().is_rescan());
  assert_eq!(cover[0].location(), &Location::new());
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
  m.ack_watch(id, Ok(WatchAck::Installed));
  let boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == id).map(|e| e.req()))
    .expect("the child cold read was queued");
  m.on_enumerate(boot, EnumerateResult::Ok(Vec::new()));
  id
}

/// The ordering fence a confirming listing now stages behind, in one call: the
/// driver requests a reader-queue cut after the listing, and the answered cut
/// licenses every marker staged at or before the instant it was asked for. The
/// cells drive the reach directly, because the reach IS what the driver reads
/// off the monitor when it commits to the batch.
fn seal_adoptions(m: &mut Monitor, s: ScopeId) {
  let Some(reach) = m.adoption_staging_high_water(s) else {
    return;
  };
  m.seal_staged_adoptions(s, reach);
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
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
      .map(|(id, _)| id),
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

  // The replayed pre-arm brings the new root live and starts its COLD read; its
  // confirming completion STAGES the edge, and the fence behind it releases the
  // barrier.
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let req = read_of(&mut m, reserved);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  assert!(
    !m.coverage_settled(s),
    "the confirming listing alone does not release it"
  );
  seal_adoptions(&mut m, s);
  assert!(
    m.coverage_settled(s),
    "positive verification releases the barrier"
  );
  m.assert_invariants();
}

/// A widen preserves every absolute path — that is exactly what
/// [`Reparent::Rerooted`] asserts — so a read already in flight over the old
/// root still describes the directory it was issued for, and its result must be
/// reconciled.
///
/// The spliced-in root is a NEWBORN, though, and a newborn stamped with the
/// clock's current reading postdates every older outstanding request. One rename
/// in an UNRELATED scope between the read's issue and the widen is enough to
/// lift that reading above the read's stamp, and the splice then puts the
/// newborn on the read's ancestor chain — so the chain walk reports a move that
/// touched no path of this scope at all, and the crawl burns a retry (or, past
/// the bound, records a persistent deficit) because somebody else renamed.
///
/// Birth is not a placement change: a newborn is born `NEVER_MOVED` and makes
/// nothing stale.
#[test]
fn a_widen_keeps_an_in_flight_read_valid_across_an_unrelated_scopes_rename() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);

  // The read whose result must survive all of this, issued FIRST so every clock
  // reading below postdates its stamp.
  assert!(m.rearm_watch_subtree(old_root).is_started());
  let req = read_of(&mut m, old_root);

  // An unrelated scope renames a watched directory: two placement funnels (the
  // detach that vacates the slot, the pairing that re-keys it), neither of them
  // on scope 1's chain.
  let other = scope(2);
  let other_root = live_root_idle(&mut m, other);
  let moved = live_child_dir(&mut m, other_root, "elsewhere");
  m.on_os_record(
    OsRecord::new(other_root, RecordKind::MovedFrom)
      .with_name(seg("elsewhere"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(other_root, RecordKind::MovedTo)
      .with_name(seg("arrived"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  assert!(m.is_watched(moved), "the unrelated rename paired");
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // The widen: `b` becomes the new root's name for the old one, and every
  // absolute path under it is unchanged.
  let reserved = m.reserve_watch_id();
  assert!(
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
      .is_some()
  );

  // The in-flight read answers with the world it was issued over, plus one
  // genuinely new directory.
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("kid"), FileKind::Dir).with_node(ident(70)),
      DirEntry::new(seg("fresh"), FileKind::Dir).with_node(ident(71)),
    ]),
  );
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().filter_map(|a| a.as_watch()).any(|c| c
      .target()
      .as_child()
      .is_some_and(|ch| ch.parent() == old_root && ch.name().as_str() == "fresh")),
    "the listing is reconciled — the newly-visible directory is armed: {actions:?}"
  );
  assert!(
    !actions
      .iter()
      .any(|a| a.as_enumerate().is_some_and(|e| e.dir() == old_root)),
    "and no bounded retry is spent re-reading what this result already read: {actions:?}"
  );
  let events = drain_events(&mut m);
  assert!(
    events.is_empty(),
    "a complete crawl that retires nothing owes no Rescan: {events:?}"
  );
  assert!(m.is_watched(kid), "the identity-confirmed survivor is kept");
  m.assert_invariants();
}

/// The DEPTH CAP. A chain longer than one segment would splice intermediate
/// connectors as unidentified cold nodes — edges no marker names, no read
/// re-proves, and no `MoveSelf` of the already-watched old root invalidates, since
/// moving an ANCESTOR of that root emits none. The lone tail marker would confirm
/// over ground nothing inspected, so the splice is not offered at that shape.
///
/// Refused with the whole monitor bit-identical, like its siblings, so the
/// driver's fallback replace starts from an untouched world — and asserted as
/// BIT-identity rather than as a handful of fields, because the claim is that
/// nothing at all happened, not that four counters agree.
#[test]
fn widen_refuses_a_chain_longer_than_one_segment() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);

  // Reserve FIRST: minting an id is the caller's act, not the splice's, and the
  // snapshot must not carry it.
  let reserved = m.reserve_watch_id();
  let before = std::format!("{m:?}");

  assert_eq!(
    m.widen_root(
      s,
      reserved,
      vec![seg("b"), seg("c"), seg("d")],
      Some(ident(1))
    )
    .map(|(id, _)| id),
    None,
    "a three-segment chain is refused"
  );
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("b"), seg("c")], Some(ident(1)))
      .map(|(id, _)| id),
    None,
    "and so is the shortest chain past the cap"
  );
  assert_eq!(
    std::format!("{m:?}"),
    before,
    "the refusal is decided before the first mutation, so the monitor is \
     bit-identical"
  );
  assert!(drain_actions(&mut m).is_empty(), "nothing was queued");
  assert!(drain_events(&mut m).is_empty(), "and nothing was announced");
  assert!(
    m.coverage_settled(s),
    "the barrier was never taken down either"
  );
  m.assert_invariants();

  // And NO WEDGE: the reservation is still spendable at the depth the splice does
  // serve, on the very scope that was just refused.
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
      .map(|(id, _)| id),
    Some(reserved),
    "the refused scope still widens at depth one"
  );
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let req = read_of(&mut m, reserved);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  seal_adoptions(&mut m, s);
  assert!(m.adoptions_settled(s), "and proves its adopted edge");
  assert_eq!(m.child_watch(reserved, &seg("b")), Some(old_root));
  assert!(m.is_watched(old_root) && m.is_watched(kid));
  quiesce(&mut m);
  assert!(m.coverage_settled(s), "and settles");
  m.assert_invariants();
}

#[test]
fn adoption_confirmed_by_a_matching_listing_stays_silent() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
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
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
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
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
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

/// The stale-edge escalation under a root whose pre-arm outcome has NOT been
/// replayed. A widen's spliced root sits in `Arming` until it is, and a widen OVER
/// a widen puts a marker on the node the second splice demoted, whose own arm and
/// read do not wait for the new root's — so the tail can resolve the edge first.
/// This read is what
/// RELEASED the adoption conjunct that had been holding the barrier down, and a
/// re-arm the root's state refuses leaves that release resting on nothing while
/// the stale edge still stands.
#[test]
fn a_stale_adoption_edge_counts_its_escalation_under_an_arming_root() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  let mid = m.reserve_watch_id();
  assert!(
    m.widen_root(s, mid, vec![seg("b")], Some(ident(1)))
      .is_some()
  );
  let reserved = m.reserve_watch_id();
  assert!(
    m.widen_root(s, reserved, vec![seg("mid")], Some(ident(2)))
      .is_some()
  );
  // Only the DEMOTED root is armed and read; `reserved` stays pending.
  m.ack_watch(mid, Ok(WatchAck::Installed));
  let req = read_of(&mut m, mid);
  let _ = drain_events(&mut m);
  assert!(m.rearm_settled(s), "nothing is counted before the verdict");

  // The adopted name is absent from the tail's COMPLETE listing: a stale edge.
  m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "the escalation Rescan targets the scope root: {events:?}"
  );
  assert!(
    !m.rearm_settled(s),
    "and the escalation is counted even though the root is still arming"
  );
  assert!(!m.coverage_settled(s));
  m.assert_invariants();
}

#[test]
fn adoption_after_a_recorded_death_stands_a_located_rescan() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));

  // The adopted subtree dies through its own records mid-window — with no
  // armed parent to mint the parent-side Removed.
  m.on_os_record(OsRecord::new(old_root, RecordKind::DeleteSelf), at(2));
  assert!(!m.is_watched(old_root));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.ack_watch(reserved, Ok(WatchAck::Installed));
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
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.on_os_record(OsRecord::new(old_root, RecordKind::DeleteSelf), at(2));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.ack_watch(reserved, Ok(WatchAck::Installed));
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
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
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
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
      .map(|(id, _)| id),
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
  m.ack_watch(dark, Err(WatchError::NoSpace));
  let _ = drain_events(&mut m);
  assert!(m.has_coverage_deficit(s));

  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
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
  let root = m
    .register_root(s, Interest::all())
    .expect("a fresh scope registers");
  m.ack_watch(root, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("b")], None)
      .map(|(id, _)| id),
    None
  );

  let mut m = per_dir();
  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(scope(9), reserved, vec![seg("b")], None)
      .map(|(id, _)| id),
    None
  );

  let s = scope(1);
  let _root = live_root_idle(&mut m, s);
  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, Vec::new(), None)
      .map(|(id, _)| id),
    None
  );
  let other = m.reserve_watch_id();
  assert_ne!(reserved, other, "reservations are never reused");
}

/// The fifth refusal: an adoption the caller cannot NAME. A root's identity has
/// exactly one source — this parameter — so an absent one is absent for the
/// adopted node's whole life, and the tail's re-proof would confirm the dark
/// window on ignorance. Refused with the tree bit-identical, like its four
/// siblings, so the driver's fallback replace starts from an untouched world.
#[test]
fn widen_refuses_an_adoption_it_cannot_name() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);

  let before_root = m.roots.get(&s).copied();
  let before_nodes = m.nodes.len();
  let before_edges = m.child_index.len();
  let before_markers = m.pending_adoptions.len();
  let before_adopting = m.adopting_by_scope.get(&s).copied();

  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("b")], None)
      .map(|(id, _)| id),
    None
  );

  assert_eq!(
    m.roots.get(&s).copied(),
    before_root,
    "the root never moved"
  );
  assert_eq!(m.nodes.len(), before_nodes, "no node was minted");
  assert_eq!(m.child_index.len(), before_edges, "no edge was spliced");
  assert_eq!(
    m.pending_adoptions.len(),
    before_markers,
    "no marker stands over a splice that did not happen"
  );
  assert_eq!(m.adopting_by_scope.get(&s).copied(), before_adopting);
  assert!(m.is_watched(old_root) && m.is_watched(kid));
  assert!(
    m.coverage_settled(s),
    "and the barrier was never taken down"
  );
  assert!(drain_actions(&mut m).is_empty());
  assert!(drain_events(&mut m).is_empty());
  m.assert_invariants();
}

/// The re-proof is STRICT: a listing that names the right slot with the right
/// kind but no object at all proves nothing, so it escalates rather than
/// certifying the commit→arm window. Same polarity `rearm_enumerate` re-proves
/// its survivors under — an identity-less backend confirms no adopted edge.
#[test]
fn an_identityless_listing_cannot_confirm_the_adopted_edge() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let req = read_of(&mut m, reserved);

  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b"), FileKind::Dir)]),
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "an unprovable edge escalates at the scope root: {events:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and the released marker leaves a counted re-arm holding the barrier"
  );
  m.assert_invariants();
}

/// The full dark-window swap, end to end: inside the commit→arm gap the adopted
/// directory is renamed away and a new one takes its name, and the cold read
/// that discovers it cannot name what it found. A confirming re-proof would
/// have left the old subtree's changes delivered at the new object's path
/// forever, invisibly, with the barrier reading settled — and no later
/// reconcile of that slot would have repaired it, since an unknown identity
/// never forces a replace and each of them REUSES whatever incumbent it finds.
/// The escalation repairs it by emptying the slot: the very listing that failed
/// to prove the edge then installs its occupant fresh, and the counted crawl
/// re-diffs that install once an identity is finally available.
#[test]
fn a_dark_window_swap_installs_the_new_object_instead_of_re_addressing_the_old() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));

  let req = read_of(&mut m, reserved);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b"), FileKind::Dir)]),
  );
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the escalation retires the unproven edge itself — a reconcile handed one \
     would have reused it"
  );
  let installed = m
    .child_watch(reserved, &seg("b"))
    .expect("and the same listing fills the emptied slot");
  assert_ne!(installed, old_root, "with a NEW watch, not the adopted one");
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "{events:?}"
  );
  assert!(!m.coverage_settled(s));

  // The counted re-arm's own read finally names the occupant: a different
  // object, so the stale edge is rebuilt.
  let crawl = read_of(&mut m, reserved);
  m.on_enumerate(
    crawl,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(2)),
    ]),
  );
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the renamed-away subtree stops being addressed as `b`"
  );
  let fresh = m
    .child_watch(reserved, &seg("b"))
    .expect("the new object occupies the slot");
  assert_ne!(fresh, old_root, "and it is a NEW watch, not the reused one");
  assert_ne!(
    fresh, installed,
    "the identity-less install is itself re-diffed, never confirmed on ignorance"
  );
  assert_eq!(m.node_identity(fresh), Some(ident(2)));
  m.assert_invariants();
}

/// Widens `s` and answers the tail's first COMPLETE read with an adopted name
/// the listing cannot CLASSIFY. That is the one entry kind no later
/// reconciliation of the slot decides strictly — the crawl refuses to diff it
/// and the stat it defers to answers permissively — so it is the shape in which
/// a retained stale edge would survive its own escalation. Returns the adopted
/// subtree's two watches and the new root.
fn unclassifiable_adopted_name(m: &mut Monitor, s: ScopeId) -> (WatchId, WatchId, WatchId) {
  let (old_root, kid) = widen_base(m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let req = read_of(m, reserved);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b"), FileKind::Unknown)]),
  );
  (old_root, kid, reserved)
}

/// The escalation must retire the unproven edge ITSELF, because the stat that
/// settles an unclassifiable slot answers through the ORDINARY reconcile, where
/// a `Dir` carrying no identity is no positive difference: handed an incumbent,
/// it would KEEP the very edge the re-proof just refused, and the widen's dark
/// window would end certified by a reuse. Emptied first, the same answer
/// installs.
#[test]
fn an_unprovable_adopted_edge_is_gone_before_an_identityless_dir_stat_lands() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved) = unclassifiable_adopted_name(&mut m, s);
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the refused edge is retired at the escalation"
  );
  assert!(
    m.child_watch(reserved, &seg("b")).is_none(),
    "leaving the slot empty for whatever the stat finds"
  );

  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_stat()
        .filter(|c| c.of() == &StatTarget::child(reserved, seg("b")))
        .map(|c| c.req())
    })
    .expect("the unclassifiable slot is asked about");
  m.on_stat_result(stat, StatResult::Ok(StatEntry::new(FileKind::Dir)));

  let fresh = m
    .child_watch(reserved, &seg("b"))
    .expect("and the answer installs into the empty slot");
  assert_ne!(fresh, old_root, "a FRESH watch, never the adopted one");
  assert!(!m.is_watched(old_root), "which stays retired");
  assert!(!m.has_coverage_deficit(s), "and the slot's darkness heals");
  m.assert_invariants();
}

/// The same edge with the stat FAILING: nothing settles the slot, so nothing
/// would ever have displaced a retained incumbent — the degrade re-books the
/// darkness behind a located `Rescan` and never re-asks. That degrade is honest
/// only because the unproven edge is already gone; with it standing, the slot
/// would read as covered by a watch the proof refused.
#[test]
fn a_failing_stat_cannot_leave_the_refused_adoption_standing() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved) = unclassifiable_adopted_name(&mut m, s);

  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_stat()
        .filter(|c| c.of() == &StatTarget::child(reserved, seg("b")))
        .map(|c| c.req())
    })
    .expect("the unclassifiable slot is asked about");
  m.on_stat_result(stat, StatResult::Failed(IoClass::Permission));

  assert!(!m.is_watched(old_root) && !m.is_watched(kid));
  assert!(
    m.child_watch(reserved, &seg("b")).is_none(),
    "an unresolvable answer occupies nothing"
  );
  assert!(
    m.has_coverage_deficit(s),
    "the darkness stands, re-signalled"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["b"])),
    "behind its own located Rescan: {events:?}"
  );
  m.assert_invariants();
}

/// And with the stat NEVER answered — the case the uncounted booking is written
/// for (an outstanding stat is deliberately no conjunct of `coverage_settled`,
/// so a silent driver degrades a verdict instead of wedging the scope). The
/// escalation's own crawl still cannot classify the name, and the scope settles
/// with the slot booked dark and the adopted subtree gone. A retained edge would
/// have settled here too — but silently, and under a slot no deficit even
/// covers, since a slot an incumbent occupies books none.
#[test]
fn an_unanswered_stat_leaves_darkness_rather_than_a_stale_adopted_edge() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved) = unclassifiable_adopted_name(&mut m, s);

  let crawl = read_of(&mut m, reserved);
  m.on_enumerate(
    crawl,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b"), FileKind::Unknown)]),
  );

  assert!(!m.is_watched(old_root) && !m.is_watched(kid));
  assert!(m.child_watch(reserved, &seg("b")).is_none());
  assert!(m.has_coverage_deficit(s), "the slot is booked dark");
  assert!(
    m.coverage_settled(s),
    "and the barrier resolves degraded rather than wedging on the silence"
  );
  m.assert_invariants();
}

/// The same unclassifiable adopted name reached through a RE-ARM-flavored
/// complete read. An incomplete first cold read proves nothing, so it keeps the
/// marker and queues a bounded retry — and that retry is `Rearm`-flavored, which
/// is the ONLY flavor a complete first read of a widen tail can arrive in. The
/// verdict is owed on it exactly as on a cold one: the crawl it runs is coverage
/// machinery, and against a name it cannot classify that machinery decides
/// nothing at all. Returns the adopted subtree's two watches and the new root.
fn unclassifiable_adopted_name_on_a_retry(
  m: &mut Monitor,
  s: ScopeId,
) -> (WatchId, WatchId, WatchId) {
  let (old_root, kid) = widen_base(m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let first = read_of(m, reserved);
  m.on_enumerate(first, EnumerateResult::Partial(Vec::new()));
  let retry = read_of(m, reserved);
  m.on_enumerate(
    retry,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b"), FileKind::Unknown)]),
  );
  (old_root, kid, reserved)
}

/// The re-arm-flavored retry owes the verdict itself. Handing the edge to its
/// crawl instead loses it twice over: the crawl refuses to diff an
/// unclassifiable name, and the stat it defers to answers through the ordinary
/// reconcile, where a `Dir` with no identity is no positive difference and so
/// KEEPS the incumbent. With the marker already spent on the retry, that
/// retained edge would then be certified by a barrier reading settled.
#[test]
fn a_retrys_unprovable_adopted_edge_is_gone_before_an_identityless_dir_stat_lands() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved) = unclassifiable_adopted_name_on_a_retry(&mut m, s);
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "a re-arm-flavored complete read retires the refused edge like a cold one"
  );
  assert!(
    m.child_watch(reserved, &seg("b")).is_none(),
    "leaving the slot empty for whatever the stat finds"
  );
  assert!(
    !m.coverage_settled(s),
    "and the released marker leaves a counted re-arm holding the barrier"
  );

  // One drain: the escalation's counted re-arm and the slot's stat are both
  // outstanding, and the settle assertion below needs the read the stat would
  // otherwise wash away.
  let actions = drain_actions(&mut m);
  let stat = actions
    .iter()
    .find_map(|a| {
      a.as_stat()
        .filter(|c| c.of() == &StatTarget::child(reserved, seg("b")))
        .map(|c| c.req())
    })
    .expect("the unclassifiable slot is asked about");
  let crawl = actions
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == reserved)
        .map(|e| e.req())
    })
    .expect("the escalation re-reads the scope root");

  m.on_stat_result(stat, StatResult::Ok(StatEntry::new(FileKind::Dir)));
  let fresh = m
    .child_watch(reserved, &seg("b"))
    .expect("and the answer installs into the empty slot");
  assert_ne!(fresh, old_root, "a FRESH watch, never the adopted one");
  assert!(!m.is_watched(old_root), "which stays retired");
  assert!(
    !m.coverage_settled(s),
    "an uncounted stat releases no barrier; the escalation still owes its read"
  );
  assert_eq!(arm_named_child(&mut m, reserved, "b"), fresh);

  // The escalation's read finally names the occupant. The identity-less install
  // the stat made is itself re-diffed rather than confirmed on ignorance, and
  // only once THAT rebuild arms does the barrier come back.
  m.on_enumerate(
    crawl,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(2)),
    ]),
  );
  let rebuilt = arm_named_child(&mut m, reserved, "b");
  assert_ne!(rebuilt, fresh);
  assert_ne!(rebuilt, old_root);
  assert!(!m.is_watched(old_root));
  assert_eq!(m.node_identity(rebuilt), Some(ident(2)));
  assert!(m.coverage_settled(s), "the escalation resolved");
  m.assert_invariants();
}

/// The same retry with the stat FAILING: nothing settles the slot, so nothing
/// would ever displace a retained incumbent. The degrade re-books the darkness
/// behind a located `Rescan` and never re-asks — honest only because the
/// unproven edge is already gone.
#[test]
fn a_failing_stat_cannot_leave_a_retrys_refused_adoption_standing() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved) = unclassifiable_adopted_name_on_a_retry(&mut m, s);

  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_stat()
        .filter(|c| c.of() == &StatTarget::child(reserved, seg("b")))
        .map(|c| c.req())
    })
    .expect("the unclassifiable slot is asked about");
  m.on_stat_result(stat, StatResult::Failed(IoClass::Permission));

  assert!(!m.is_watched(old_root) && !m.is_watched(kid));
  assert!(
    m.child_watch(reserved, &seg("b")).is_none(),
    "an unresolvable answer occupies nothing"
  );
  assert!(
    m.has_coverage_deficit(s),
    "the darkness stands, re-signalled"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["b"])),
    "behind its own located Rescan: {events:?}"
  );
  m.assert_invariants();
}

/// And the retry with the stat NEVER answered — the silent driver the uncounted
/// booking is written for. The escalation's own crawl still cannot classify the
/// name, so the scope settles with the slot booked dark and the adopted subtree
/// gone. A retained edge would have settled here too, silently, and under a slot
/// no deficit even covers: a slot an incumbent occupies books none.
#[test]
fn an_unanswered_stat_after_a_retry_leaves_darkness_rather_than_a_stale_edge() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved) = unclassifiable_adopted_name_on_a_retry(&mut m, s);
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the retry retires the refused edge before anything can defer it"
  );

  let crawl = read_of(&mut m, reserved);
  m.on_enumerate(
    crawl,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b"), FileKind::Unknown)]),
  );

  assert!(!m.is_watched(old_root) && !m.is_watched(kid));
  assert!(m.child_watch(reserved, &seg("b")).is_none());
  assert!(m.has_coverage_deficit(s), "the slot is booked dark");
  assert!(
    m.coverage_settled(s),
    "and the barrier resolves degraded rather than wedging on the silence"
  );
  m.assert_invariants();
}

/// A DIRTIED first cold read is the other way a widen tail's first COMPLETE read
/// arrives re-arm-flavored: a slot-changing record raced the read, so its listing
/// is a possibly-stale snapshot that may not be trusted — including about the
/// adopted name. The marker rides the retry, and the retry owes the verdict.
#[test]
fn a_dirtied_first_cold_read_still_owes_the_adoption_verdict_on_its_retry() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let first = read_of(&mut m, reserved);

  // A record for an unrelated slot races the cold read: the snapshot is stale,
  // never incomplete — so the whole listing (the adopted name included) is
  // re-read rather than trusted, exactly as an unfinished one would be.
  m.on_os_record(
    OsRecord::new(reserved, RecordKind::Removed)
      .with_name(seg("x"))
      .with_is_dir(true),
    at(3),
  );
  m.on_enumerate(
    first,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  assert!(
    m.is_watched(old_root),
    "a dirtied read decides nothing either way"
  );

  let retry = read_of(&mut m, reserved);
  m.on_enumerate(
    retry,
    EnumerateResult::Ok(vec![DirEntry::new(seg("b"), FileKind::Unknown)]),
  );
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the retry's unprovable edge is retired, not handed to its own crawl"
  );
  assert!(m.child_watch(reserved, &seg("b")).is_none());
  assert!(!m.coverage_settled(s));
  m.assert_invariants();
}

/// The strict path did not become unconditionally destructive: a retry whose
/// listing POSITIVELY matches the adopted identity confirms the edge silently,
/// keeping the subtree and its interior. This is what the drop above is measured
/// against — a re-proof that retires a proven edge would cost the widen the O(1)
/// splice it exists for.
#[test]
fn a_retry_that_matches_the_adopted_identity_still_confirms_silently() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let first = read_of(&mut m, reserved);
  m.on_enumerate(first, EnumerateResult::Partial(Vec::new()));
  let _ = drain_events(&mut m);

  let retry = read_of(&mut m, reserved);
  m.on_enumerate(
    retry,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  assert_eq!(
    m.child_watch(reserved, &seg("b")),
    Some(old_root),
    "the proven edge keeps its watch — no rebuild"
  );
  assert!(m.is_watched(kid), "and its interior is untouched");
  seal_adoptions(&mut m, s);
  let events = drain_events(&mut m);
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "a confirmed edge escalates nothing: {events:?}"
  );
  assert!(
    m.adoptions_settled(s),
    "the conjunct is released by the proof, not by a cover"
  );
  m.assert_invariants();
}

#[test]
fn rebind_after_a_depth_one_widen_purges_the_marker() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));

  // A D1 rebind of the widened scope keeps the (new) root node; the adoption
  // marker keyed on it must die with the old world, and the rebound root's
  // re-arm-flavored rebuild proceeds without an adoption escalation.
  assert_eq!(m.rebind_root(s).map(|(id, _)| id), Some(reserved));
  let _ = drain_events(&mut m);
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let req = read_of(&mut m, reserved);
  m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_rescan()),
    "no stale adoption escalation after the rebind: {events:?}"
  );
  m.assert_invariants();
}

/// The outstanding old-world read is the REGISTRATION's own (42-10), so its
/// reconciliation is proven by the coverage it installs rather than by a
/// `Created` it may not emit: the registration crawl reports no inventory. The
/// widen's own post-commit read is untouched by that and keeps its `Created`s —
/// the cells that pin them are unchanged.
#[test]
fn widen_while_the_old_root_is_enumerating_reconciles_the_late_read() {
  let mut m = per_dir();
  let s = scope(1);
  let old_root = live_root(&mut m, s);
  let boot = read_of(&mut m, old_root);

  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
      .map(|(id, _)| id),
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
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().any(|a| a
      .as_watch()
      .is_some_and(|w| w.target() == &WatchTarget::child(old_root, seg("late")))),
    "the late listing installs its child under the adopted node: {actions:?}"
  );
  assert_eq!(
    m.location_of_checked(
      actions
        .iter()
        .find_map(|a| a
          .as_watch()
          .filter(|w| w.target() == &WatchTarget::child(old_root, seg("late")))
          .map(|w| w.id()))
        .expect("the installed child")
    ),
    Some(loc(&["b", "late"])),
    "addressed through the chain"
  );
  assert!(
    !drain_events(&mut m).iter().any(|e| e.kind().is_created()),
    "and the registration's own read announces no inventory"
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
    m.widen_root(s, first, vec![seg("b")], Some(ident(1)))
      .map(|(id, _)| id),
    Some(first)
  );
  let second = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, second, vec![seg("mid")], Some(ident(1)))
      .map(|(id, _)| id),
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
  m.ack_watch(second, Ok(WatchAck::Installed));
  let outer = read_of(&mut m, second);
  m.on_enumerate(
    outer,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("mid"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  m.ack_watch(first, Ok(WatchAck::Installed));
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
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  assert!(!m.coverage_settled(s), "unverified from the commit instant");

  // An INCOMPLETE first read must not release the barrier: the marker stays
  // (the retry re-checks) and the bounded retry is itself counted work.
  m.ack_watch(reserved, Ok(WatchAck::Installed));
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
  seal_adoptions(&mut m, s);
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
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));
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

/// The connector role, at the one depth the splice serves: a widen OVER a widen
/// leaves the previous root as an intermediate node between the current root and
/// the adopted tree — carrying its own unresolved marker — and it is that node the
/// dark window replaces.
#[test]
fn a_connector_reconciled_away_stands_the_closing_rescan() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let mid = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, mid, vec![seg("b")], Some(ident(1)))
      .map(|(id, _)| id),
    Some(mid)
  );
  let reserved = m.reserve_watch_id();
  assert_eq!(
    m.widen_root(s, reserved, vec![seg("a")], Some(ident(2)))
      .map(|(id, _)| id),
    Some(reserved)
  );
  let _ = drain_actions(&mut m);
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let req = read_of(&mut m, reserved);

  // The dark window replaced the connector with a FILE: the widened root's
  // cold listing reconciles the slot, which tears down the connector, the
  // adopted old tree, and BOTH pending markers in one drop — an erased
  // UNVERIFIED adoption, discharged like an erased deficit: the settle
  // flush's closing root Rescan stands, loudly, where silence would have
  // disarmed every old watch with no signal at all.
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("a"), FileKind::File)]),
  );
  assert!(!m.is_watched(mid) && !m.is_watched(old_root) && !m.is_watched(kid));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "the erased adoption owes the closing root Rescan: {events:?}"
  );
  assert!(
    m.adoptions_settled(s),
    "and both markers are released, not left resting on the erasure"
  );

  // Two obligations came out of the one listing, and neither is silent: the OUTER
  // edge was refuted, so its verdict stood a COUNTED cover over the ground it
  // retired, and the inner marker was erased by the same walk, which owes the
  // closing `Rescan` asserted above. The barrier releases when the counted cover's
  // own re-arm completes — never before it.
  assert!(
    !m.rearm_settled(s),
    "the refuted outer edge's cover is counted, so the barrier is held down"
  );
  quiesce(&mut m);
  assert!(
    m.coverage_settled(s),
    "with the signal standing and the cover's re-arm answered, the barrier \
     honestly settles: rearm_settled={}",
    m.rearm_settled(s)
  );
  m.assert_invariants();
}

#[test]
fn an_exhausted_tail_read_hands_the_marker_to_the_deficit() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));

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
  // drain it. The tail keeps answering Partial here exactly as it does above:
  // it is the PERMANENTLY unreadable directory this cell is about, and a read
  // of it that completed clean would heal the very interior asserted below.
  // The marker itself is gone: nothing un-completable remains.
  for _ in 0..8 {
    let reads: Vec<(ReqId, WatchId)> = drain_actions(&mut m)
      .iter()
      .filter_map(|a| a.as_enumerate().map(|e| (e.req(), e.dir())))
      .collect();
    if reads.is_empty() {
      break;
    }
    for (req, dir) in reads {
      if dir == reserved {
        m.on_enumerate(req, EnumerateResult::Partial(Vec::new()));
      } else {
        m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
      }
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

/// Widens `s` TWICE, each splice at the one depth
/// [`Monitor::widen_root`] serves, so the marker that is left standing keys on a
/// node that is NO LONGER the root — the shape whose tail can be held (a root is
/// nobody's child and so is never a move source).
///
/// Back-to-back widens are the only producer of that shape now that the splice
/// is capped at one segment, and they produce it exactly: the first splice makes
/// `mid` the root and marks the `mid/b → old_root` edge; the second splices
/// `reserved` above `mid`, which re-keys `mid` as an ordinary child and marks the
/// `reserved/mid → mid` edge; that OUTER marker is then discharged by the new
/// root's own cold listing, which names `mid` with the identity the splice
/// adopted it under. What survives is one standing marker owned by `mid`, a
/// non-root node — the same object the deep-chain connector used to be, reached
/// the only way that remains.
///
/// Arms both new nodes and settles the new root's own cold read, leaving the
/// tail's read as the only outstanding one. Returns `(old_root, kid, new_root, tail)`.
fn widen_with_a_chain_tail(m: &mut Monitor, s: ScopeId) -> (WatchId, WatchId, WatchId, WatchId) {
  let (old_root, kid) = widen_base(m, s);
  // Widen one: `mid` becomes the root and owes the proof of `mid/b → old_root`.
  let mid = m.reserve_watch_id();
  let _ = m
    .widen_root(s, mid, vec![seg("b")], Some(ident(1)))
    .expect("a depth-one widen splices");
  // Widen two, BEFORE `mid` is acknowledged: nothing of the old world is armed
  // or read by the splice, so `mid`'s own arm outcome is still the caller's to
  // replay and its cold read is still unqueued — which is what lets the drain
  // below capture the NEW root's read alone.
  let reserved = m.reserve_watch_id();
  let _ = m
    .widen_root(s, reserved, vec![seg("mid")], Some(ident(2)))
    .expect("a widen over a widen splices");
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let root_read = drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == reserved)
        .map(|e| e.req())
    })
    .expect("the new root's cold read was queued");
  m.ack_watch(mid, Ok(WatchAck::Installed));
  // The OUTER edge is proven positively — `mid`, a directory, at the identity
  // the second splice adopted it under — so the outer marker stages, its fence
  // releases it, and only the tail's own stands.
  m.on_enumerate(
    root_read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("mid"), FileKind::Dir).with_node(ident(2)),
    ]),
  );
  seal_adoptions(m, s);
  let _ = drain_events(m);
  (old_root, kid, reserved, mid)
}

/// Answers every outstanding read with a clean empty listing until none is left,
/// draining the counted work an escalation stood. Bounded, so work that never
/// quiesces fails here instead of hanging.
fn drain_reads_clean(m: &mut Monitor) {
  for _ in 0..8 {
    let reads: Vec<ReqId> = drain_actions(m)
      .iter()
      .filter_map(|a| a.as_enumerate().map(|e| e.req()))
      .collect();
    if reads.is_empty() {
      let _ = drain_events(m);
      return;
    }
    for req in reads {
      m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
    }
  }
  panic!("the counted work never quiesced");
}

/// Retry exhaustion on the HELD path — the path a widen tail's incomplete reads
/// actually take, since a hold costs a listing its evidence status and routes
/// every completion, even a complete one, to the incomplete handler.
///
/// This is where the site's own covering story is INERT: the located `Rescan` is
/// suppressed (it would name the vacated pre-move path) and the interior deficit
/// is skipped with it, so a bare release would leave the unproven edge standing
/// with only the hold's pairing re-arm to meet it — and that re-arm reconciles
/// permissively, retaining an incumbent it cannot classify. The release must
/// therefore retire the adopted subtree itself, under a cover anchored at the
/// scope ROOT, the one locatable anchor a hold leaves.
#[test]
fn an_exhausted_held_tail_retires_the_adopted_edge_under_a_root_cover() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved, mid) = widen_with_a_chain_tail(&mut m, s);

  // The chain tail moves away and is held for the pairing window.
  m.on_os_record(
    OsRecord::new(reserved, RecordKind::MovedFrom)
      .with_name(seg("mid"))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(20),
  );
  let _ = drain_events(&mut m);
  assert!(
    m.held_sources.contains(&mid),
    "the tail is held, not dropped"
  );

  // Spend the bounded retries. Each answer is COMPLETE and each proves nothing:
  // it describes the path the subtree has left.
  for _ in 0..=REARM_MAX_RETRIES {
    assert!(
      !m.adoptions_settled(s),
      "the edge is unverified while retries remain"
    );
    let req = read_of(&mut m, mid);
    m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
  }

  assert!(
    m.adoptions_settled(s),
    "the exhausted marker is released — kept, it would hold the barrier down \
     with no read left to release it"
  );
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "and the adopted subtree is retired with it: no later reconciliation of that \
     slot decides strictly, so an edge handed on would be RETAINED"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "the retirement stands its cover at the scope root: {events:?}"
  );
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mid"])),
    "never at the vacated pre-move path — the held suppression is intact: {events:?}"
  );
  assert!(
    !m.has_coverage_deficit(s),
    "and the interior deficit really is skipped here, which is why it could \
     never have been the cover"
  );

  // The barrier is covered, not wedged: the hold resolves, the counted work
  // drains, and the scope settles.
  assert!(
    !m.coverage_settled(s),
    "the cover is COUNTED while it stands"
  );
  m.handle_timeout(at(20) + DEFAULT_MOVE_WINDOW);
  drain_reads_clean(&mut m);
  assert!(
    m.coverage_settled(s),
    "and it releases: rearm_settled={} holds={} adoptions={}",
    m.rearm_settled(s),
    m.holds_settled(s),
    m.adoptions_settled(s),
  );
  m.assert_invariants();
}

/// The same exhaustion on the NON-HELD path. Here the site's located `Rescan`
/// and interior deficit do both stand — and neither one retires anything, so the
/// unproven edge would survive them just the same. The retirement and its
/// counted root cover are owed beside them, not instead of them.
#[test]
fn an_exhausted_tail_retires_the_adopted_edge_beside_its_located_rescan() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, _reserved, mid) = widen_with_a_chain_tail(&mut m, s);

  for _ in 0..=REARM_MAX_RETRIES {
    let req = read_of(&mut m, mid);
    m.on_enumerate(req, EnumerateResult::Partial(Vec::new()));
  }

  assert!(m.adoptions_settled(s), "the exhausted marker is released");
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "and the unproven edge is retired rather than handed to a permissive rebuild"
  );
  assert!(
    m.child_watch(mid, &seg("b")).is_none(),
    "leaving an EMPTY slot, which is what makes the later rebuild unambiguous"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mid"])),
    "the unreadable interior keeps its own located Rescan: {events:?}"
  );
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "and the retirement adds the counted root cover: {events:?}"
  );
  assert!(
    m.has_coverage_deficit(s),
    "the unreconciled interior is still booked for the dispatch re-signal"
  );

  drain_reads_clean(&mut m);
  assert!(
    m.coverage_settled(s),
    "the counted cover releases: rearm_settled={}",
    m.rearm_settled(s)
  );
  assert!(!m.is_watched(old_root), "with the edge still retired");
  m.assert_invariants();
}

/// The wedge negative, on a tail that NEVER completes: the counted cover the
/// retirement stands re-reads the very directory whose retries just exhausted,
/// so it must not be able to renew itself. It cannot — the marker is spent, so
/// the second exhaustion stands no second cover — and the scope reaches a
/// settled, honestly-degraded rest: the darkness booked, the adopted subtree
/// gone, the barrier free.
#[test]
fn a_tail_that_never_completes_settles_with_the_adopted_edge_retired() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  m.ack_watch(reserved, Ok(WatchAck::Installed));

  // Every read of the widened root fails forever; everything else answers clean.
  let mut rounds = 0;
  for _ in 0..12 {
    let reads: Vec<(ReqId, WatchId)> = drain_actions(&mut m)
      .iter()
      .filter_map(|a| a.as_enumerate().map(|e| (e.req(), e.dir())))
      .collect();
    if reads.is_empty() {
      break;
    }
    rounds += 1;
    for (req, dir) in reads {
      if dir == reserved {
        m.on_enumerate(req, EnumerateResult::Partial(Vec::new()));
      } else {
        m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
      }
    }
  }
  let _ = drain_events(&mut m);
  assert!(rounds < 12, "the escalation is one-shot, not self-renewing");
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the edge no read ever confirmed is retired, not left standing"
  );
  assert!(m.adoptions_settled(s));
  assert!(
    m.coverage_settled(s),
    "the barrier resolves degraded rather than wedging: rearm_settled={}",
    m.rearm_settled(s)
  );
  assert!(
    m.has_coverage_deficit(s),
    "over darkness the dispatch re-signal still owes a cookie"
  );
  m.assert_invariants();
}

/// Vacates the tail's `b` slot WITHOUT relocating the adopted watch: a cookied
/// `MovedFrom` detaches it and holds its subtree for a pairing that has not
/// arrived yet.
///
/// This is the whole distance a rename may put between the marker's COORDINATE
/// and its OBJECT under the containment invariant, and it is why the marker
/// stores a `WatchId`: `detach_child` clears the `(tail, "b")` index entry but
/// PRESERVES the parent link, so the adopted watch stays a direct child of the
/// node that owes its proof — reachable by that node's drop walk and by every
/// disposal — while the slot the marker names stands empty and open to a
/// replacement.
fn detach_the_adopted_watch(m: &mut Monitor, tail: WatchId) {
  m.on_os_record(
    OsRecord::new(tail, RecordKind::MovedFrom)
      .with_name(seg("b"))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(20),
  );
  let _ = drain_events(m);
}

/// ATTEMPTS the paired rename the containment invariant refuses: the adopted
/// watch itself, out of the tail's `b` slot and on to `(dest_parent, dest_name)`,
/// as one complete pairing.
///
/// Nothing here is a dark window — both halves are recorded in full — and the
/// arm's own acyclicity precondition is satisfied. What declines it is
/// `reparentable_adoption`, asked before the re-key, so what this leaves behind
/// is the not-reparentable route's disposition rather than a moved subtree.
///
/// Returns the pairing's own delivery, because half of what the refusal owes is
/// stated in it.
fn move_the_adopted_watch(
  m: &mut Monitor,
  tail: WatchId,
  dest_parent: WatchId,
  dest_name: &str,
) -> Vec<Change> {
  m.on_os_record(
    OsRecord::new(tail, RecordKind::MovedFrom)
      .with_name(seg("b"))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(20),
  );
  m.on_os_record(
    OsRecord::new(dest_parent, RecordKind::MovedTo)
      .with_name(seg(dest_name))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(20),
  );
  drain_events(m)
}

/// The reviewer's sequence, and the one a marker keyed on a COORDINATE cannot
/// survive: inside the widen's dark window the adopted directory is renamed
/// away and another object takes its name, and the monitor learns both only
/// afterwards, from the tail's own post-arm records. The adopted watch is
/// detached from `mid/b` and held for its pairing, a replacement grows into the
/// vacated `mid/b` carrying its own identity, and the tail's first complete read
/// then lists `b` as exactly that replacement.
///
/// Resolved by NAME the proof reads the slot, finds the replacement, matches
/// the replacement's identity against the replacement's own entry — and
/// CONFIRMS, silently, while the object the widen actually adopted is alive
/// under a path nothing ever proved, its descendants reconstructing through an
/// edge no read ever verified and the barrier free to settle over all of it.
/// Resolved by IDENTITY the occupancy conjunct fails first: the watch that owes
/// the proof no longer holds the slot the listing describes, so nothing the
/// replacement can show discharges it.
///
/// A DETACH is what separates the slot from the object here, not a relocation:
/// the containment invariant keeps the adopted watch parented at the tail (an
/// unproven adopted edge is immovable), and this is exactly the gap it still
/// leaves open — the index entry is free, the parent link is not. The
/// retirement is therefore subtree-local, which is why the tail is still there
/// to reconcile its own listing afterwards.
#[test]
fn a_replacement_in_the_adopted_slot_cannot_pay_the_original_watchs_proof() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, _reserved, mid) = widen_with_a_chain_tail(&mut m, s);
  // Captured before the records: the tail's first read is the proof, and
  // draining actions later would wash it away.
  let tail_read = read_of(&mut m, mid);

  detach_the_adopted_watch(&mut m, mid);
  m.on_os_record(
    OsRecord::new(mid, RecordKind::Created)
      .with_name(seg("b"))
      .with_is_dir(true)
      .with_node(ident(2)),
    at(21),
  );
  let replacement = arm_named_child(&mut m, mid, "b");
  let _ = drain_events(&mut m);
  assert!(
    m.is_watched(old_root),
    "the adopted watch survives the window, held for its pairing"
  );
  assert_eq!(
    m.child_watch(mid, &seg("b")),
    Some(replacement),
    "while a different object holds the adopted slot"
  );
  assert_ne!(replacement, old_root);

  // Those records raced the tail's first read, so it is DIRTY: a possibly-stale
  // snapshot decides nothing either way, and the marker rides the bounded retry
  // (the flavor a widen tail's first COMPLETE read arrives in once anything at
  // all has happened at its slot). That retry is the proof.
  m.on_enumerate(tail_read, EnumerateResult::Ok(Vec::new()));
  assert!(m.is_watched(old_root), "a dirtied read decides nothing");
  let reads: Vec<(ReqId, WatchId)> = drain_actions(&mut m)
    .iter()
    .filter_map(|a| a.as_enumerate().map(|e| (e.req(), e.dir())))
    .collect();
  let proof = reads
    .iter()
    .find(|(_, dir)| *dir == mid)
    .map(|(req, _)| *req)
    .expect("the dirtied read queues the bounded retry");

  // The completion of the adoption read. The listing is the true one: the
  // replacement really is what stands at the adopted name. It describes that
  // replacement perfectly and proves nothing whatever about the object the widen
  // adopted — and, crucially, it gives the re-arm crawl no reason to prune that
  // object either, so nothing downstream will do this proof's work for it.
  m.on_enumerate(
    proof,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(2)),
    ]),
  );
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the unproven edge is retired — a replacement's identity is not its proof"
  );
  assert!(
    m.is_watched(replacement),
    "and the replacement keeps the coverage it was properly discovered with: \
     retiring the OCCUPANT would be the same failure inverted"
  );
  assert!(
    m.is_watched(mid),
    "the retirement is subtree-local: the reading tail is still there"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "under the escalation's counted root cover: {events:?}"
  );

  // Gone BEFORE settlement, which is the whole point: a barrier that settles
  // first has already certified the window.
  assert!(
    !m.coverage_settled(s),
    "the cover is counted while it stands"
  );
  for (req, dir) in reads {
    if dir != mid {
      m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
    }
  }
  // The unpaired half's window elapses: its `Removed` for a subtree already
  // retired is the only thing left holding the moves conjunct.
  m.handle_timeout(at(20) + DEFAULT_MOVE_WINDOW);
  drain_reads_clean(&mut m);
  assert!(
    m.coverage_settled(s),
    "and it releases rather than wedging: rearm_settled={}",
    m.rearm_settled(s)
  );
  assert!(
    !m.is_watched(old_root),
    "with the adopted watch still retired"
  );
  m.assert_invariants();
}

/// The one site that could have relocated an unproven adopted edge, refusing to:
/// [`on_moved_to`](Monitor::on_moved_to)'s pairing arm, the monitor's only
/// rewrite of an existing parent link.
///
/// The refusal needs no path of its own and gets none — it takes the arm's
/// EXISTING not-reparentable route, which already pays both halves of the
/// coverage rule and, taken here, is exactly the disposition an unprovable
/// adopted edge is owed: the source dropped (subtree-LOCAL, since the invariant
/// makes it a direct child of the marker's own node, so the marker's node
/// survives), the pair still emitted, the destination `Rescan`ed at the object's
/// REAL location, and its rebuild COUNTED behind that edge.
///
/// The marker is deliberately left standing. Its adopted watch is now dead, and
/// that is a state the machinery already handles: the tail's first complete read
/// takes the recorded-death branch and re-scans the vacated slot.
#[test]
fn a_paired_move_cannot_relocate_an_unproven_adopted_watch() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, _reserved, mid) = widen_with_a_chain_tail(&mut m, s);
  let tail_read = read_of(&mut m, mid);

  let events = move_the_adopted_watch(&mut m, mid, mid, "elsewhere");
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the refused edge is dropped where it stood, not carried to a new slot"
  );
  assert!(
    m.is_watched(mid),
    "and the drop is LOCAL: the node that owes the proof is a direct parent of \
     what was dropped, never a descendant of it"
  );
  let fresh = m
    .child_watch(mid, &seg("elsewhere"))
    .expect("the destination is reconciled as a fresh move-in");
  assert_ne!(fresh, old_root, "by a new watch, not the refused subtree");
  assert!(
    !m.adoptions_settled(s),
    "the marker is left standing, to resolve through the machinery a dead \
     adopted watch already has"
  );

  assert!(
    events
      .iter()
      .any(|e| e.kind().is_moved() && e.location() == &loc(&["mid", "elsewhere"])),
    "the pairing is still delivered: {events:?}"
  );
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mid", "elsewhere"])),
    "and the opening loss edge names the object's REAL location, never the \
     vacated one: {events:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "the destination's rebuild is COUNTED behind that edge, so the barrier waits"
  );

  // Dirtied by the move records, so the retry carries the verdict — and the
  // verdict finds the adopted watch already gone: the recorded-death branch,
  // which re-scans the slot it vacated and owes no second retirement.
  m.on_enumerate(tail_read, EnumerateResult::Ok(Vec::new()));
  let reads: Vec<(ReqId, WatchId)> = drain_actions(&mut m)
    .iter()
    .filter_map(|a| a.as_enumerate().map(|e| (e.req(), e.dir())))
    .collect();
  let proof = reads
    .iter()
    .find(|(_, dir)| *dir == mid)
    .map(|(req, _)| *req)
    .expect("the dirtied read queues the bounded retry");
  m.on_enumerate(
    proof,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("elsewhere"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  assert!(m.adoptions_settled(s), "the marker resolves");
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mid", "b"])),
    "at the vacated slot the recorded-death branch mourns: {events:?}"
  );

  for (req, dir) in reads {
    if dir != mid {
      m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
    }
  }
  // The counted rebuild is the destination's own arm. The proof read's own crawl
  // re-proves that survivor as well and mints it afresh where it cannot match an
  // identity, so acknowledge whatever now holds the slot and answer its read: the
  // barrier's last conjunct falls with it.
  let armed = m
    .child_watch(mid, &seg("elsewhere"))
    .expect("the destination stays covered throughout");
  m.ack_watch(armed, Ok(WatchAck::Installed));
  drain_reads_clean(&mut m);
  assert!(
    m.coverage_settled(s),
    "and the whole sequence settles rather than wedging: rearm_settled={}",
    m.rearm_settled(s)
  );
  m.assert_invariants();
}

/// The wedge negative for the interception, on the path where NOTHING ever
/// completes. The refusal deliberately leaves the marker standing, and a marker
/// nothing releases is the one unacceptable outcome: `coverage_settled` false for
/// the rest of the process.
///
/// Every read of the tail fails forever, so the recorded-death branch is never
/// reached and the release comes from the bounded retries' own cap. It finds
/// nothing left to retire — the refusal already disposed of the adopted watch —
/// and its counted cover cannot renew itself, because the marker is spent by the
/// time the cover's own re-read could exhaust again. The scope reaches a settled,
/// honestly-degraded rest: the darkness booked, the unproven edge gone, the
/// barrier free.
#[test]
fn an_intercepted_move_still_settles_when_the_tail_never_completes() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved, mid) = widen_with_a_chain_tail(&mut m, s);

  let _ = move_the_adopted_watch(&mut m, mid, mid, "elsewhere");
  assert!(!m.is_watched(old_root) && !m.is_watched(kid));
  assert!(
    !m.adoptions_settled(s),
    "the marker is left standing, with no read that will ever prove it"
  );

  // Every read of the tail is incomplete forever; everything else answers clean
  // and every arm is acknowledged, so nothing but the marker can hold the
  // barrier down.
  let mut rounds = 0;
  for _ in 0..16 {
    let arming: Vec<WatchId> = m
      .nodes
      .iter()
      .filter(|(_, node)| matches!(node.state, NodeState::Arming { .. }))
      .map(|(id, _)| *id)
      .collect();
    for id in &arming {
      m.ack_watch(*id, Ok(WatchAck::Installed));
    }
    let reads: Vec<(ReqId, WatchId)> = drain_actions(&mut m)
      .iter()
      .filter_map(|a| a.as_enumerate().map(|e| (e.req(), e.dir())))
      .collect();
    if arming.is_empty() && reads.is_empty() {
      break;
    }
    rounds += 1;
    for (req, dir) in reads {
      if dir == mid {
        m.on_enumerate(req, EnumerateResult::Partial(Vec::new()));
      } else if dir == reserved {
        // The counted cover re-reads the ROOT, whose listing must keep naming
        // the tail: an empty one would retire it through the ordinary crawl and
        // decide nothing about the marker.
        m.on_enumerate(
          req,
          EnumerateResult::Ok(vec![DirEntry::new(seg("mid"), FileKind::Dir)]),
        );
      } else {
        m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
      }
    }
  }
  let _ = drain_events(&mut m);
  assert!(rounds < 16, "the escalation is one-shot, not self-renewing");
  assert!(
    m.adoptions_settled(s),
    "the retry cap releases the marker the refusal left standing"
  );
  assert!(
    m.child_watch(reserved, &seg("mid")).is_some(),
    "with the tail's slot still covered — the counted cover's crawl rebuilds \
     what it re-proves, so nothing is left unwatched"
  );
  assert!(
    m.coverage_settled(s),
    "and the barrier resolves degraded rather than wedging: rearm_settled={} \
     adoptions={}",
    m.rearm_settled(s),
    m.adoptions_settled(s)
  );
  m.assert_invariants();
}

/// The same double depth-one widen as [`widen_with_a_chain_tail`], with the TAIL
/// left unarmed — the widen's dark window at its widest. `mid` owes the proof and
/// its own pre-arm outcome was never replayed, so its kernel watch does not exist:
/// a mutation of the adopted slot `mid/b` in this window mints no parent-side half
/// for anything to refuse, and the adopted object's own self-events are the entire
/// record of it. Arming the NEW root does not change that — its watch speaks for
/// its own children, of which the adopted slot is not one — and is what discharges
/// the outer marker, so the tail's is the only one the scope is still holding.
///
/// Returns `(old_root, kid, new_root, tail)`.
fn widen_into_an_unarmed_chain(
  m: &mut Monitor,
  s: ScopeId,
) -> (WatchId, WatchId, WatchId, WatchId) {
  let (old_root, kid) = widen_base(m, s);
  let mid = m.reserve_watch_id();
  assert!(
    m.widen_root(s, mid, vec![seg("b")], Some(ident(1)))
      .is_some()
  );
  let reserved = m.reserve_watch_id();
  assert!(
    m.widen_root(s, reserved, vec![seg("mid")], Some(ident(2)))
      .is_some(),
    "the demoting splice lands — and `mid` is never acknowledged, so the node \
     that owes the proof has no kernel watch at all"
  );
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let root_read = drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == reserved)
        .map(|e| e.req())
    })
    .expect("the new root's cold read was queued");
  m.on_enumerate(
    root_read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("mid"), FileKind::Dir).with_node(ident(2)),
    ]),
  );
  seal_adoptions(m, s);
  let _ = drain_events(m);
  (old_root, kid, reserved, mid)
}

/// A depth-one widen whose new root is live and whose confirming listing has
/// been ingested: the marker STANDS, staged, with its fence still to come.
/// Returns `(old_root, kid, new_root)`.
fn widen_staged(m: &mut Monitor, s: ScopeId) -> (WatchId, WatchId, WatchId) {
  let (old_root, kid) = widen_base(m, s);
  let reserved = m.reserve_watch_id();
  let _ = m
    .widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
    .expect("a depth-one widen splices");
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let req = read_of(m, reserved);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  let _ = drain_events(m);
  (old_root, kid, reserved)
}

/// The confirming listing is not the verdict. Its three conjuncts all match, and
/// they all match again after an excursion that left and returned — so a release
/// taken at the completion certifies an interval it never looked at. The listing
/// therefore STAGES, and the record that refutes the interval is still free to
/// arrive and spend the marker while it stands.
///
/// Mutation witness: release at the completion (drop the staging) and the
/// `MoveSelf` below finds no marker, stands no cover, and the barrier reads
/// settled over an undelivered transition.
#[test]
fn a_confirming_listing_stages_the_marker_instead_of_releasing_it() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved) = widen_staged(&mut m, s);

  assert!(
    !m.adoptions_settled(s),
    "the marker stands: the listing read the window's END, not the window"
  );
  assert!(!m.coverage_settled(s), "so the barrier is still held");
  assert_eq!(
    m.adoption_staging_high_water(s),
    Some(1),
    "staged, and stamped against the cuts the scope may be offered"
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "and nothing is escalated by staging itself"
  );
  assert!(m.is_watched(old_root) && m.is_watched(kid));

  // A cut requested BEFORE this staging licenses nothing here.
  m.seal_staged_adoptions(s, 0);
  assert!(
    !m.adoptions_settled(s),
    "a cut that predates the staging cannot seal it"
  );

  // The excursion's own record, arriving on the lane the fence exists to drain
  // first. It finds the marker still standing, which is the whole point.
  m.on_os_record(OsRecord::new(old_root, RecordKind::MoveSelf), at(20));
  assert!(
    m.adoptions_settled(s),
    "and spends it: the edge no listing can prove is retired, not confirmed"
  );
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "inside a counted cover, with the unprovable subtree retired"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "the root cover stands: {events:?}"
  );
  assert!(!m.rearm_settled(s), "counted, not a bare edge");

  // The fence lands afterwards on a marker that is already gone.
  m.seal_staged_adoptions(s, 1);
  assert!(
    drain_events(&mut m).is_empty(),
    "a seal over a spent marker is inert"
  );
  assert!(m.is_watched(reserved), "and touches nothing else");
  m.assert_invariants();
}

/// A SECOND complete read of the chain parent meets a marker already staged, and
/// its confirming reading adds nothing: only the FIRST confirming listing is the
/// confirm, because the cut requested behind it is the one that orders its
/// window. Re-stamping would push the marker past the reach of the cut already
/// out for it — and under a repeating re-arm crawl the stamp would outrun every
/// round trip, so the marker would be re-offered a cut it never reaches the end
/// of.
///
/// Mutation witness: re-stamp on every confirming listing and the staging
/// generation below moves, stranding the request already in flight.
#[test]
fn a_second_complete_read_leaves_a_staged_marker_to_its_fence() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid, reserved) = widen_staged(&mut m, s);

  // A re-arm read of the same directory, listing the same matching entry.
  assert!(m.rearm_watch_subtree(reserved).is_started());
  let again = read_of(&mut m, reserved);
  m.on_enumerate(
    again,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  assert!(
    !m.adoptions_settled(s),
    "the staged marker still stands — this completion is not its verdict"
  );
  assert_eq!(
    m.adoption_staging_high_water(s),
    Some(1),
    "and its stamp did not move, so the cut already out still reaches it"
  );
  assert_eq!(
    m.child_watch(reserved, &seg("b")),
    Some(old_root),
    "the read reconciles its slots as it always did"
  );
  m.assert_invariants();
}

/// The quiet path stays quiet. A widen nothing interfered with pays the fence one
/// round trip and nothing else: no `Rescan`, no epoch bump, no re-arm, and the
/// barrier releases on the confirmation.
///
/// Mutation witness: make the seal retire unconditionally and this cell reports
/// the covering `Rescan` a silent widen must never emit.
#[test]
fn a_sealed_confirm_releases_the_barrier_silently() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved) = widen_staged(&mut m, s);
  let before = m.coverage_work_epoch(s);

  m.seal_staged_adoptions(s, 1);
  assert!(m.adoptions_settled(s), "the confirm is released");
  assert!(m.coverage_settled(s), "and the barrier with it");
  assert!(
    drain_events(&mut m).is_empty(),
    "silently: no `Rescan` of any kind"
  );
  assert!(m.rearm_settled(s), "and no counted cover");
  assert_eq!(
    m.coverage_work_epoch(s),
    before,
    "a release acquires no work, so a proof taken over this scope survives it"
  );
  assert_eq!(
    m.child_watch(reserved, &seg("b")),
    Some(old_root),
    "the adopted watch is REUSED — nothing retired, nothing rebuilt"
  );
  assert!(m.is_watched(kid), "and its interior is untouched");
  assert_eq!(
    m.adoption_staging_high_water(s),
    None,
    "the scope owes no seal, which is what lets its latch be dropped"
  );
  m.assert_invariants();
}

/// The occupancy reading is one-way while the marker stands, so the seal may take
/// it late — and must. A `MovedFrom` detaches the adopted watch after the listing
/// confirmed; the slot reading has degraded and cannot come back, so the seal
/// refuses.
///
/// Mutation witness: drop the seal's occupancy re-check and a detached adopted
/// edge is confirmed.
#[test]
fn the_seal_refuses_an_adopted_watch_that_left_its_slot_after_the_listing() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved) = widen_staged(&mut m, s);

  m.on_os_record(
    OsRecord::new(reserved, RecordKind::MovedFrom)
      .with_name(seg("b"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(20),
  );
  assert_eq!(
    m.child_watch(reserved, &seg("b")),
    None,
    "the slot is vacated, and nothing can restore this watch to it"
  );

  m.seal_staged_adoptions(s, 1);
  assert!(m.adoptions_settled(s), "the marker resolves");
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "as a RETIREMENT, not a confirm"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "under a counted root cover: {events:?}"
  );
  assert!(!m.rearm_settled(s), "counted, so the barrier rests on it");
  m.assert_invariants();
}

/// The adopted WATCH dies after the listing confirmed it. The edge cannot outlive
/// its object, so there is nothing to retire — but the vacated slot owes the
/// consumer a re-read, which is the located `Rescan` the read-time verdict gives
/// the same case.
///
/// Mutation witness: seal a dead adopted watch as a confirm and the slot converges
/// on nothing.
#[test]
fn the_seal_answers_an_adopted_watch_that_died_after_the_listing() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid, reserved) = widen_staged(&mut m, s);

  m.on_os_record(
    OsRecord::new(reserved, RecordKind::Removed)
      .with_name(seg("b"))
      .with_is_dir(true),
    at(20),
  );
  assert!(!m.is_watched(old_root), "the adopted object is gone");
  let _ = drain_events(&mut m);

  m.seal_staged_adoptions(s, 1);
  assert!(m.adoptions_settled(s), "the marker resolves");
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["b"])),
    "at the vacated slot, so the consumer's re-read converges the ghost: {events:?}"
  );
  m.assert_invariants();
}

/// The staging-generation discipline: a cut licenses the stagings that existed
/// when it was asked for, and no others. Two back-to-back widens stage two
/// markers; a cut reaching only the first seals only the first.
///
/// Mutation witness: license the whole staged set from any answered cut and the
/// second marker is sealed by a cut whose request PREDATES its listing — the
/// ordering the seal exists to buy, spent on a window it never covered.
#[test]
fn a_cut_seals_only_the_stagings_it_reaches() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid, first) = widen_staged(&mut m, s);
  assert_eq!(m.adoption_staging_high_water(s), Some(1));

  // A second widen over the first, staged by its own confirming listing.
  let second = m.reserve_watch_id();
  let _ = m
    .widen_root(s, second, vec![seg("mid")], Some(ident(2)))
    .expect("a widen over a widen splices");
  m.ack_watch(second, Ok(WatchAck::Installed));
  let req = read_of(&mut m, second);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("mid"), FileKind::Dir).with_node(ident(2)),
    ]),
  );
  let _ = drain_events(&mut m);
  assert_eq!(
    m.adoption_staging_high_water(s),
    Some(2),
    "both markers are staged, in the order their listings were ingested"
  );

  m.seal_staged_adoptions(s, 1);
  assert!(
    !m.adoptions_settled(s),
    "the newer staging waits for its own cut"
  );
  assert_eq!(
    m.child_watch(first, &seg("b")),
    Some(old_root),
    "while the older one is confirmed silently — its subtree is reused"
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "and neither seal escalates anything"
  );

  m.seal_staged_adoptions(s, 2);
  assert!(m.adoptions_settled(s), "the successor seals the rest");
  assert!(m.coverage_settled(s));
  assert!(
    drain_events(&mut m).is_empty(),
    "still silently: two quiet widens pay two round trips and no cover"
  );
  m.assert_invariants();
}

/// The ingest order the whole design turns on, staged at the seam that owns it.
/// The parent-side half of the rename is consumed pre-commit as benign churn, the
/// object leaves and returns before the chain parent is ever read, and the
/// listing then matches all three conjuncts — so the LISTING cannot tell this
/// window from a quiet one.
///
/// What separates them is only when the verdict is taken. The fence puts the
/// object's own `MoveSelf` — kernel-committed before that listing, because the
/// rename holds the chain parent's lock across the record it emits — ahead of the
/// seal, so no discontinuous edge settles without a covering rescan.
///
/// Mutation witness: take the verdict at the listing and this cell settles with
/// the transition undelivered and no `Rescan` standing for the interval.
#[test]
fn a_change_and_return_inside_the_window_never_settles_uncovered() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  let _ = m
    .widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
    .expect("a depth-one widen splices");
  m.ack_watch(reserved, Ok(WatchAck::Installed));

  // The listing the excursion cannot be told from a quiet window by: the adopted
  // watch still holds the slot (nothing observed a move, so nothing rewrote the
  // link) and the identity came back with the object.
  let req = read_of(&mut m, reserved);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  let _ = drain_events(&mut m);
  assert_eq!(
    m.child_watch(reserved, &seg("b")),
    Some(old_root),
    "every conjunct the proof reads is restored by the return trip"
  );
  assert!(
    !m.coverage_settled(s),
    "and the barrier is still held, because no verdict has been taken"
  );

  // The record still kernel-side at the listing, which the cut forwards ahead of
  // its own reply and the drain feeds before the seal.
  m.on_os_record(OsRecord::new(old_root, RecordKind::MoveSelf), at(20));
  m.seal_staged_adoptions(s, 1);

  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the discontinuous edge is retired rather than certified"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "with a covering rescan standing for the interval: {events:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and the barrier releases onto the cover's counted rebuild, never onto nothing"
  );
  m.assert_invariants();
}

/// The sequence a SNAPSHOT proof cannot survive: inside the widen's dark window
/// the adopted directory is renamed out of `mid/b` and back, and the connector
/// that owes the proof records neither half of either rename — its watch arms
/// only afterwards. The one trace is the adopted object's own `MoveSelf`.
///
/// The return trip restores every conjunct the proof reads. The link still names
/// the adopted watch (nothing observed a move, so nothing rewrote it), and the
/// identity comes back with the object, so the tail's listing is
/// INDISTINGUISHABLE from a listing over a window in which nothing happened. A
/// verdict left to that listing confirms — and what it certifies is an interval in
/// which the adopted subtree's own watches went on delivering at a path the object
/// had left, uncovered, with the barrier free to settle over it.
///
/// So final occupancy and identity are not the proof. They are admissible only
/// because a movement of the adopted watch reaches the marker FIRST, which is what
/// this cell drives.
#[test]
fn an_adopted_watch_seen_to_move_is_not_reproven_by_its_returning_identity() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved, mid) = widen_into_an_unarmed_chain(&mut m, s);
  assert_eq!(
    m.child_watch(mid, &seg("b")),
    Some(old_root),
    "the occupancy conjunct holds going in — and an ABA hands it back intact"
  );

  // The rename out. No parent-side half exists to refuse it: the connector has no
  // kernel watch yet, and the adopted watch is no longer the root, so the moved-root
  // invalidation does not speak for it either.
  m.on_os_record(OsRecord::new(old_root, RecordKind::MoveSelf), at(20));
  assert!(
    m.adoptions_settled(s),
    "the MOVE spends the proof — not a later listing that cannot see it"
  );
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "and the edge nothing can prove any more is retired with it"
  );
  assert!(
    m.is_watched(mid) && m.is_watched(reserved),
    "subtree-locally: the chain that owes the proof stands, so its own read is \
     still to come"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "under the counted root cover, standing BEFORE the coverage it ends: {events:?}"
  );
  assert!(
    !m.rearm_settled(s),
    "which is counted work, not a bare edge"
  );

  // The rename back names a watch the first record already retired, so it dies at
  // the unknown-watch guard: one sighting is all the proof needs to be spent.
  m.on_os_record(OsRecord::new(old_root, RecordKind::MoveSelf), at(21));
  assert!(
    drain_events(&mut m).is_empty(),
    "the return trip adds nothing to escalate"
  );

  // The listing that WOULD have confirmed: the adopted name, a directory, and the
  // very identity the widen named. There is no marker left for it to pay, and the
  // slot it describes is rebuilt from scratch rather than reused.
  m.ack_watch(mid, Ok(WatchAck::Installed));
  let req = read_of(&mut m, mid);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  assert!(
    !m.is_watched(old_root),
    "a returning identity does not resurrect the edge it could not prove"
  );
  let fresh = m
    .child_watch(mid, &seg("b"))
    .expect("the connector's own reconcile re-covers the slot");
  assert_ne!(fresh, old_root, "as a fresh discovery, never a reused edge");
  m.assert_invariants();
}

/// The control, through the SAME unarmed window: with no movement in it the proof
/// still confirms, and still silently. The invalidation answers evidence of a
/// move; it is not a tax on the window itself — which every multi-segment widen
/// has, by construction, since the connector that owes the proof is minted unarmed.
#[test]
fn an_unmoved_adopted_watch_is_confirmed_silently_through_the_same_window() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, _reserved, mid) = widen_into_an_unarmed_chain(&mut m, s);

  m.ack_watch(mid, Ok(WatchAck::Installed));
  let req = read_of(&mut m, mid);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  seal_adoptions(&mut m, s);
  assert!(m.adoptions_settled(s), "the edge is verified");
  assert_eq!(
    m.child_watch(mid, &seg("b")),
    Some(old_root),
    "by REUSING the adopted watch — nothing was retired and nothing rebuilt"
  );
  assert!(m.is_watched(old_root) && m.is_watched(kid));
  let events = drain_events(&mut m);
  assert!(
    events.iter().all(|e| e.kind().is_created()),
    "silently: the cold read announces its new ground and escalates nothing \
     — no `Rescan` of any kind: {events:?}"
  );
  assert!(
    m.rearm_settled(s),
    "and stands no counted cover: rearm_settled={}",
    m.rearm_settled(s)
  );
  assert!(
    m.coverage_settled(s),
    "so the barrier releases on the confirmation itself"
  );
  m.assert_invariants();
}

/// The same invalidation where the marker keys on the scope ROOT — a DEPTH-ONE
/// widen, whose marker parent is the pre-armed reserved root rather than a minted
/// connector. The blind window is a different one (records attributed to the
/// reserved id before the commit are dropped by the unknown-watch guard, so a
/// rename of the adopted object in that interval raises no parent-side half the
/// monitor ever sees either), and the retirement's locality claim is at its
/// sharpest here: the node it must not reach is the root itself.
#[test]
fn a_depth_one_widens_moved_adoption_is_retired_without_reaching_the_root() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid) = widen_base(&mut m, s);
  let reserved = m.reserve_watch_id();
  assert!(
    m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)))
      .is_some()
  );
  let _ = drain_events(&mut m);

  m.on_os_record(OsRecord::new(old_root, RecordKind::MoveSelf), at(20));
  assert!(m.adoptions_settled(s), "the move spends the proof here too");
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "and retires the edge it can no longer prove"
  );
  assert!(
    m.is_watched(reserved) && m.roots.get(&s) == Some(&reserved),
    "while the marker's own key — the scope root — survives its child's \
     retirement, which is the whole content of subtree-locality"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "under the same counted root cover: {events:?}"
  );

  // And it settles: the root's replayed pre-arm outcome carries the cover's
  // counted re-arm, whose read rebuilds the vacated slot.
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let req = read_of(&mut m, reserved);
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  quiesce(&mut m);
  assert!(
    m.coverage_settled(s),
    "rather than wedging: rearm_settled={} adoptions={}",
    m.rearm_settled(s),
    m.adoptions_settled(s)
  );
  let rebuilt = m
    .child_watch(reserved, &seg("b"))
    .expect("with the adopted slot covered again");
  assert_ne!(rebuilt, old_root, "by a fresh watch, not the retired edge");
  m.assert_invariants();
}

/// The signal is about the ADOPTED WATCH, and about nothing else that moved. A
/// rename INSIDE the adopted subtree moves no edge the marker speaks for, and a
/// rename of the connector's OTHER child moves an object that owes no proof at
/// all — the marker's key is its parent, which is exactly why the disposal is
/// resolved by the stored `WatchId` and not by "a child of the node that owes a
/// proof moved".
///
/// Neither may spend the marker, and this cell is what separates the two possible
/// over-broad shapes — an ancestor walk, and a parent lookup with no check of
/// WHICH child it names — from the one the proof actually needs.
#[test]
fn a_move_beside_or_beneath_the_adopted_watch_leaves_the_proof_standing() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, _reserved, mid) = widen_into_an_unarmed_chain(&mut m, s);
  m.ack_watch(mid, Ok(WatchAck::Installed));
  let first_read = read_of(&mut m, mid);

  // A second child grows in the connector, beside the adopted slot.
  m.on_os_record(
    OsRecord::new(mid, RecordKind::Created)
      .with_name(seg("other"))
      .with_is_dir(true)
      .with_node(ident(5)),
    at(20),
  );
  let other = arm_named_child(&mut m, mid, "other");
  let _ = drain_events(&mut m);

  // One rename beneath the adopted watch, one beside it. Neither is the adopted
  // watch's own move, so both take the ordinary non-root no-op.
  m.on_os_record(OsRecord::new(kid, RecordKind::MoveSelf), at(21));
  m.on_os_record(OsRecord::new(other, RecordKind::MoveSelf), at(21));
  assert!(
    !m.adoptions_settled(s),
    "the marker still stands: neither object owes its proof"
  );
  assert!(
    m.is_watched(old_root) && m.is_watched(kid) && m.is_watched(other),
    "nothing is retired"
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "and nothing is escalated: a no-op stays silent"
  );

  // The `Created` raced the connector's first read, so that read decides nothing;
  // the bounded retry carries the verdict, and the verdict CONFIRMS.
  m.on_enumerate(first_read, EnumerateResult::Ok(Vec::new()));
  let proof = read_of(&mut m, mid);
  m.on_enumerate(
    proof,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1)),
      DirEntry::new(seg("other"), FileKind::Dir).with_node(ident(5)),
    ]),
  );
  seal_adoptions(&mut m, s);
  assert!(m.adoptions_settled(s), "the edge is verified");
  assert_eq!(
    m.child_watch(mid, &seg("b")),
    Some(old_root),
    "and reused: the adopted watch never moved"
  );
  m.assert_invariants();
}

/// The wedge negative for the invalidation. The release takes the barrier's
/// adoptions conjunct off, and a scope that cannot settle afterwards is the one
/// unacceptable outcome — so the cover it stands is counted, holds the barrier
/// down through the rebuild, and comes back up ON that rebuild: the adopted slot
/// re-covered by a watch the crawl armed and read, rather than by the edge the
/// move refuted.
#[test]
fn a_move_invalidated_adoption_settles_over_the_slot_it_rebuilds() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid, reserved, _mid) = widen_into_an_unarmed_chain(&mut m, s);

  m.on_os_record(OsRecord::new(old_root, RecordKind::MoveSelf), at(20));
  assert!(
    !m.coverage_settled(s),
    "the cover is COUNTED while it stands, so nothing settles inside it"
  );
  let _ = drain_events(&mut m);

  // Every arm is acknowledged and every read answered, with each surviving
  // directory naming its real children: the widened root holds the connector, and
  // the connector holds the object that came back.
  //
  // The connector is resolved by NAME each round, never by the id captured above,
  // because the cover's own crawl re-proves it too and cannot identity-match it —
  // a widen's chain nodes are minted with no identity — so the first re-armed root
  // listing retires and rebuilds it. That is the escalation's ordinary cost, the
  // same one every other adoption escalation on this path pays, and the slot it
  // has to end up covering is `mid/b`.
  let mut rounds = 0;
  for _ in 0..16 {
    let arming: Vec<WatchId> = m
      .nodes
      .iter()
      .filter(|(_, node)| matches!(node.state, NodeState::Arming { .. }))
      .map(|(id, _)| *id)
      .collect();
    for id in &arming {
      m.ack_watch(*id, Ok(WatchAck::Installed));
    }
    let reads: Vec<(ReqId, WatchId)> = drain_actions(&mut m)
      .iter()
      .filter_map(|a| a.as_enumerate().map(|e| (e.req(), e.dir())))
      .collect();
    if arming.is_empty() && reads.is_empty() {
      break;
    }
    rounds += 1;
    for (req, dir) in reads {
      let entries = if dir == reserved {
        vec![DirEntry::new(seg("mid"), FileKind::Dir).with_node(ident(3))]
      } else if Some(dir) == m.child_watch(reserved, &seg("mid")) {
        vec![DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(1))]
      } else {
        Vec::new()
      };
      m.on_enumerate(req, EnumerateResult::Ok(entries));
    }
  }
  let _ = drain_events(&mut m);
  assert!(
    rounds < 16,
    "the invalidation is one-shot, not self-renewing"
  );
  assert!(
    m.coverage_settled(s),
    "and the barrier resolves rather than wedging: rearm_settled={} adoptions={}",
    m.rearm_settled(s),
    m.adoptions_settled(s)
  );
  let connector = m
    .child_watch(reserved, &seg("mid"))
    .expect("the chain is covered end to end");
  let rebuilt = m
    .child_watch(connector, &seg("b"))
    .expect("with the adopted slot covered again");
  assert_ne!(
    rebuilt, old_root,
    "by a watch the crawl armed and read itself"
  );
  assert!(
    !m.is_watched(old_root),
    "the unprovable edge staying retired throughout"
  );
  m.assert_invariants();
}

/// The third disposal, [`AdoptionDisposal::DiesWithTheWalk`], rests on a claim
/// about the walk itself: the adopted child is on its stack. The containment
/// invariant is what makes the claim true, and this is the case that shows the
/// claim is about the PARENT LINK and not about the slot — because the slot is
/// the one thing a rename can still take away.
///
/// The adopted watch is detached and held: out of `(tail, "b")` in the index,
/// still parented at the tail. The tail then dies with its marker unresolved.
/// The walk descends through its adjacency set, which a detached-and-held child
/// never left, so the child dies with it — and the release's `debug_assert!`
/// states exactly that, read through the child's own parent link.
#[test]
fn a_detached_adopted_watch_still_dies_with_its_markers_walk() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved, mid) = widen_with_a_chain_tail(&mut m, s);

  detach_the_adopted_watch(&mut m, mid);
  assert!(
    m.child_watch(mid, &seg("b")).is_none(),
    "the slot the marker names is vacated"
  );
  assert!(
    m.is_watched(old_root),
    "while the adopted watch itself is alive, held for its pairing"
  );
  assert!(
    !m.adoptions_settled(s),
    "with its marker still standing at the tail"
  );

  // The tail is removed, taking the unresolved marker with it.
  m.on_os_record(
    OsRecord::new(reserved, RecordKind::Removed).with_name(seg("mid")),
    at(30),
  );
  assert!(!m.is_watched(mid), "the tail dies");
  assert!(m.adoptions_settled(s), "and releases its marker");
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "the edge it never proved dies WITH the walk — the parent link the detach \
     preserved is what kept it on the stack"
  );

  let _ = drain_events(&mut m);
  m.handle_timeout(at(20) + DEFAULT_MOVE_WINDOW);
  drain_reads_clean(&mut m);
  assert!(
    m.coverage_settled(s),
    "the walk's own discharge covers rather than wedges: rearm_settled={}",
    m.rearm_settled(s)
  );
  assert!(!m.is_watched(old_root));
  m.assert_invariants();
}

/// And the fourth disposal, [`AdoptionDisposal::CountedRetirement`], on the
/// separation the invariant still permits: the bounded retries exhaust while the
/// adopted watch stands DETACHED — alive, still parented at the tail, and out of
/// the slot the marker names. The retirement is what pays for a marker no read
/// will ever prove, so it must reach the OBJECT; resolved by slot it reaches an
/// EMPTY one, calls that the disposal, and leaves the unproven subtree armed with
/// its conjunct already released.
#[test]
fn an_exhausted_tail_retires_the_detached_adopted_watch_not_its_vacated_slot() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, _reserved, mid) = widen_with_a_chain_tail(&mut m, s);

  detach_the_adopted_watch(&mut m, mid);
  assert!(m.is_watched(old_root));
  assert!(
    m.child_watch(mid, &seg("b")).is_none(),
    "the adopted slot the marker names is vacated"
  );

  // No read is left that could ever prove the edge.
  for _ in 0..=REARM_MAX_RETRIES {
    let req = read_of(&mut m, mid);
    m.on_enumerate(req, EnumerateResult::Partial(Vec::new()));
  }
  assert!(m.adoptions_settled(s), "the exhausted marker is released");
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "and its retirement resolves the WATCH — not the slot the watch left"
  );
  assert!(
    m.is_watched(mid),
    "subtree-locally, so the exhausted reader is still there to book its own \
     interior darkness"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "under the counted root cover the release stands: {events:?}"
  );

  m.handle_timeout(at(20) + DEFAULT_MOVE_WINDOW);
  drain_reads_clean(&mut m);
  assert!(
    m.coverage_settled(s),
    "which releases rather than wedging: rearm_settled={}",
    m.rearm_settled(s)
  );
  assert!(!m.is_watched(old_root), "with the edge still retired");
  m.assert_invariants();
}

/// Moves the child of `from_parent` named `from_name` to `(to_parent, to_name)`
/// as one COMPLETE pairing under `cookie_n`, so the moved subtree is live and
/// unheld at its new place when this returns.
fn move_child(
  m: &mut Monitor,
  from_parent: WatchId,
  from_name: &str,
  to_parent: WatchId,
  to_name: &str,
  cookie_n: u64,
) {
  m.on_os_record(
    OsRecord::new(from_parent, RecordKind::MovedFrom)
      .with_name(seg(from_name))
      .with_cookie(cookie(cookie_n))
      .with_is_dir(true),
    at(20),
  );
  m.on_os_record(
    OsRecord::new(to_parent, RecordKind::MovedTo)
      .with_name(seg(to_name))
      .with_cookie(cookie(cookie_n))
      .with_is_dir(true),
    at(20),
  );
  let _ = drain_events(m);
}

/// Whether `action` is addressed to `dir` — as the parent of a child arm or a
/// slot stat, or as the directory of a read. What a result must issue none of
/// once the node it was reconciling has been destroyed underneath it.
fn addresses(action: &Action, dir: WatchId) -> bool {
  action
    .as_watch()
    .and_then(|c| c.target().as_child().map(|ch| ch.parent()))
    == Some(dir)
    || action.as_enumerate().is_some_and(|e| e.dir() == dir)
    || action
      .as_stat()
      .and_then(|c| c.of().as_child().map(|ch| ch.parent()))
      == Some(dir)
}

/// Acknowledges every queued arm and answers every queued read clean until the
/// scope quiesces — the wedge negative's driver, for sequences whose covers
/// rebuild coverage the monitor must arm before it can settle. Bounded, so work
/// that never quiesces fails here rather than hanging.
fn quiesce(m: &mut Monitor) {
  for _ in 0..16 {
    // Off the TREE rather than off the action queue: an arm a cell drained
    // earlier while collecting reads is still outstanding on its node, and it is
    // the node's state that holds the counter down.
    let arming: Vec<WatchId> = m
      .nodes
      .iter()
      .filter(|(_, node)| matches!(node.state, NodeState::Arming { .. }))
      .map(|(id, _)| *id)
      .collect();
    for id in &arming {
      m.ack_watch(*id, Ok(WatchAck::Installed));
    }
    let reads: Vec<ReqId> = drain_actions(m)
      .iter()
      .filter_map(|a| a.as_enumerate().map(|e| e.req()))
      .collect();
    if arming.is_empty() && reads.is_empty() {
      let _ = drain_events(m);
      return;
    }
    for req in reads {
      m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
    }
  }
  panic!("the scope never quiesced");
}

/// ATTEMPTS the two paired renames that would BURY the tail: the adopted
/// directory out of the tail's `b` slot and into a slot of the widened root, then
/// the tail in UNDER the adopted directory.
///
/// Both are ordinary complete pairings the monitor records in full — nothing here
/// is a dark window — and together they would make the node that owes the
/// adoption proof a DESCENDANT of the object it owes it for. From there a
/// retirement resolving the adopted WATCH destroys the tail as collateral, and
/// every remaining step of the tail's in-flight read addresses a node the tree no
/// longer holds.
///
/// The containment invariant removes that class at the FIRST step: the rename of
/// an unproven adopted watch is refused, its edge disposed of where it stood, and
/// the second rename then has no destination left to move the tail under.
/// Returns the refusal's own delivery, which is where half of what it owes is
/// stated.
fn attempt_to_bury_the_tail(
  m: &mut Monitor,
  new_root: WatchId,
  tail: WatchId,
  adopted: WatchId,
) -> Vec<Change> {
  let events = move_the_adopted_watch(m, tail, new_root, "c");
  assert!(
    !m.is_watched(adopted),
    "the burying rename is refused, and the refused edge disposed of locally"
  );
  assert_eq!(
    m.nodes.get(&tail).and_then(|node| node.parent),
    Some(new_root),
    "so the tail stays put: there is nothing left for it to be moved under"
  );
  events
}

/// The collateral that no longer exists, on the CLEAN verdict path: the read
/// whose completion refutes the edge is the read of the node a retirement
/// following a RELOCATED adopted watch would have destroyed.
///
/// `resolve_adoption` runs strictly above the dispatch — a refused edge must be
/// retired before the crawl can reuse its subtree — so a retirement that reached
/// an ancestor of the reading directory would leave the dispatch crawling a
/// directory no longer in the tree. Reconciled anyway, a listing entry installs a
/// child whose parent link resolves to nothing: it sits in no adjacency set, so no
/// later drop can reach it, it is rearm-counted the moment the crawl continues the
/// re-arm into it, and its `Watch` names a parent the consumer does not know —
/// which the consumer rejects, leaving NO result that could ever release the
/// count. `coverage_settled` would then be false for the rest of the process: the
/// one outcome this whole design treats as unacceptable.
///
/// So the burial is made impossible instead of survivable, and what is asserted is
/// the POSITIVE: the reading directory is still there, and its listing is
/// reconciled INTO it — armed, stat'd and booked at the coordinate it really
/// occupies.
#[test]
fn a_verdict_cannot_bury_the_reading_directory_it_goes_on_reconciling() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved, mid) = widen_with_a_chain_tail(&mut m, s);
  let tail_read = read_of(&mut m, mid);

  let refusal = attempt_to_bury_the_tail(&mut m, reserved, mid, old_root);
  assert!(!m.is_watched(kid), "the refused subtree goes whole");
  assert!(
    refusal
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["c"])),
    "the destination's cover stands at the object's REAL location: {refusal:?}"
  );
  assert!(
    !m.rearm_settled(s),
    "and its rebuild is counted behind that edge"
  );
  assert!(!m.adoptions_settled(s), "with the marker still standing");

  // The moves raced the tail's first read, so it decides nothing; the retry
  // carries the proof, stamped after the moves so its listing is evidence.
  m.on_enumerate(tail_read, EnumerateResult::Ok(Vec::new()));
  let reads: Vec<(ReqId, WatchId)> = drain_actions(&mut m)
    .iter()
    .filter_map(|a| a.as_enumerate().map(|e| (e.req(), e.dir())))
    .collect();
  let proof = reads
    .iter()
    .find(|(_, dir)| *dir == mid)
    .map(|(req, _)| *req)
    .expect("the fenced read queues the bounded retry");

  // The clean completion. The adopted watch is already gone — the refusal
  // disposed of it — so the verdict takes the recorded-death branch and owes no
  // second retirement. The listing carries one entry of each kind the crawl acts
  // on: a directory to install, and a name it cannot classify.
  m.on_enumerate(
    proof,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("orphan"), FileKind::Dir).with_node(ident(8)),
      DirEntry::new(seg("mystery"), FileKind::Unknown),
    ]),
  );
  assert!(m.adoptions_settled(s), "the verdict resolves the marker");
  assert!(
    m.is_watched(mid),
    "and the reading directory is still there — nothing the verdict does can \
     reach an ancestor of it"
  );
  let installed = m
    .child_watch(mid, &seg("orphan"))
    .expect("its listing is reconciled INTO it, not into a hole");
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().any(|a| addresses(a, mid)),
    "arms and stats are addressed to it: {actions:?}"
  );
  assert!(
    m.has_coverage_deficit(s),
    "and the name it could not classify is booked at a coordinate that exists"
  );

  // The wedge negative: every cover this sequence stood releases.
  m.ack_watch(installed, Ok(WatchAck::Installed));
  for req in actions
    .iter()
    .filter_map(|a| a.as_enumerate().map(|e| e.req()))
  {
    m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
  }
  quiesce(&mut m);
  assert!(
    m.rearm_settled(s),
    "the counted rebuilds all land: rearm_pending={:?}",
    m.rearm_pending
  );
  assert!(m.adoptions_settled(s));
  m.assert_invariants();
}

/// The same on the EXHAUSTION path, where what follows the release is not a crawl
/// but an interior deficit.
///
/// A deficit is a claim about the unreconciled interior of a LIVE directory, and
/// the dispatch re-signal reconstructs its location from that directory. Booked
/// against a dead one it would degrade every later fence of the scope and then
/// re-instruct whatever prefix the truncating location walk happened to leave. So
/// the reader must survive its own release — and it does, because the retirement
/// can only ever reach a direct child of it. The deficit is then booked, honestly,
/// at the directory it is about.
#[test]
fn an_exhausted_read_cannot_bury_its_own_directory_and_books_its_interior_at_it() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, _kid, reserved, mid) = widen_with_a_chain_tail(&mut m, s);

  let _ = attempt_to_bury_the_tail(&mut m, reserved, mid, old_root);

  // No read is left that could ever prove the edge.
  for _ in 0..=REARM_MAX_RETRIES {
    let req = read_of(&mut m, mid);
    m.on_enumerate(req, EnumerateResult::Partial(Vec::new()));
  }
  assert!(m.adoptions_settled(s), "the exhausted marker is released");
  assert!(
    m.is_watched(mid),
    "the exhausted reader survives its own release"
  );
  assert!(
    m.has_coverage_deficit(s),
    "so its unreconciled interior is booked at the directory it is about"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mid"])),
    "beside the located `Rescan` this site's own story names: {events:?}"
  );

  quiesce(&mut m);
  assert!(
    m.coverage_settled(s),
    "which releases rather than wedging: rearm_settled={}",
    m.rearm_settled(s)
  );
  m.assert_invariants();
}

/// An erased adoption marker's cover is the walk's own
/// [`DeficitDischarge`](super::DeficitDischarge), and `UnsubscribedPrune` is where
/// that has to be earned: it stands NO cover at all, on the ground that the
/// set-cover proved no subscriber is under the subtree it asked to prune.
///
/// The containment invariant is what makes the ground cover the marker's object
/// too: the adopted watch is a direct child of the marker's own node, so it is
/// inside the pruned subtree by construction and the prune's silence is sound.
/// Were it free to move into RETAINED ground, the prune would end coverage of a
/// subscribed path standing nothing at all — and a narrowing has no broadening
/// delta that would ever restore it, so the fence would settle clean over a
/// retained path left unwatched. That is the silent coverage loss this campaign
/// exists to eliminate, reached through the fix for a different one.
#[test]
fn a_pruned_parent_takes_its_adopted_watch_with_it_so_the_prune_stays_silent() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, _reserved, mid) = widen_with_a_chain_tail(&mut m, s);
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // Where the invariant puts the marker's object: under the marker's own node.
  // The rename that would take it out into retained ground is refused (see
  // `a_paired_move_cannot_relocate_an_unproven_adopted_watch`), so this is the
  // only place a prune of `mid` can find it.
  assert_eq!(
    m.nodes.get(&old_root).and_then(|node| node.parent),
    Some(mid),
    "the adopted watch is a direct child of the node that owes its proof"
  );
  assert!(!m.adoptions_settled(s), "with the marker standing at `mid`");

  // The shrink half of a narrowing reconcile, exactly as `on_set_cover` issues
  // it: drop the one subtree strictly outside the retained cover.
  assert!(m.drop_watch_subtree(mid), "the outside subtree is pruned");
  assert!(!m.is_watched(mid));
  assert!(m.adoptions_settled(s), "which releases the marker it held");
  assert!(
    !m.is_watched(old_root) && !m.is_watched(kid),
    "and the edge no read ever proved dies inside the pruned ground, whole"
  );

  // Nothing is owed for it. The prune stands no cover and asks for no rebuild,
  // and the fence settles clean — over ground the set-cover proved unsubscribed,
  // which now demonstrably includes the adopted watch.
  let actions = drain_actions(&mut m);
  assert!(
    !actions
      .iter()
      .any(|a| a.as_enumerate().is_some() || a.as_watch().is_some()),
    "no counted rebuild is stood: {actions:?}"
  );
  assert!(
    m.coverage_settled(s),
    "and the fence settles clean: rearm_settled={} adoptions={}",
    m.rearm_settled(s),
    m.adoptions_settled(s)
  );
  assert!(
    !m.has_coverage_deficit(s),
    "with no darkness booked over unsubscribed ground either"
  );
  m.assert_invariants();
}

/// The COLD arm of the same collateral, and the one where what is at stake is a
/// DELIVERED LIE rather than a lost obligation.
///
/// A widen's tail is `Arming` until its arm is acknowledged — here the previous
/// root, demoted by a second depth-one widen whose pre-arm outcome the driver
/// never replayed — and both burying
/// renames can land in that interval: the monitor records them in full, and the
/// re-key merely re-addresses the outstanding arm. The tail's first post-arm read
/// is then an ordinary COLD one, stamped after the renames, so it completes as
/// evidence and its verdict runs. Discovery is what a cold read announces: run on
/// past a retirement that had destroyed the reading tail, it would emit a
/// `Created` for every listing entry at a location rebuilt from a node no longer
/// in the tree — which truncates to the scope ROOT and announces the tail's
/// children as the root's.
///
/// It cannot: the burial's first rename is refused, so the tail is still there and
/// its own listing is announced where it actually lives.
#[test]
fn a_cold_read_cannot_bury_its_own_directory_and_announces_at_its_real_location() {
  let mut m = per_dir();
  let s = scope(1);
  let (old_root, kid, reserved, tail) = widen_into_an_unarmed_chain(&mut m, s);

  // Both renames are attempted while the tail is still `Arming`: no read of it is
  // in flight for them to dirty, and a re-key would merely re-address its
  // outstanding arm.
  let _ = attempt_to_bury_the_tail(&mut m, reserved, tail, old_root);
  assert!(!m.is_watched(kid), "the refused subtree goes whole");
  assert!(!m.adoptions_settled(s), "with the marker still standing");

  // The acknowledgement the tail was waiting for. A non-re-arm arm's post-arm
  // read is COLD — discovery, stamped now, so its listing is evidence.
  m.ack_watch(tail, Ok(WatchAck::Installed));
  let cold = read_of(&mut m, tail);
  m.on_enumerate(
    cold,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("orphan"), FileKind::Dir).with_node(ident(8)),
    ]),
  );
  assert!(m.adoptions_settled(s), "the verdict resolves the marker");
  assert!(m.is_watched(tail), "and the reading tail is still there");

  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["mid", "orphan"])),
    "its listing is announced at the coordinate it really occupies: {events:?}"
  );
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["orphan"])),
    "never root-relative, which is what a location rebuilt from a dead node \
     truncates to: {events:?}"
  );
  m.assert_invariants();

  quiesce(&mut m);
  assert!(
    m.coverage_settled(s),
    "which releases rather than wedging: rearm_settled={}",
    m.rearm_settled(s)
  );
  m.assert_invariants();
}

/// **Round six's sequence, end to end.** The one the whole redesign is for, and
/// the only place the fabrication it found could ever have been observed.
///
/// Three depth-one widens, back to back, stack the shape a three-segment chain used
/// to splice in one call: `root → interior → tail → adopted`, with a marker at the
/// tail and the interior an intermediate directory left `Arming`. The root's own
/// listing discharges the OUTERMOST marker, which is what makes the interior an
/// ordinary movable node rather than an unproven adopted edge of its own. The
/// adopted watch is then
/// moved out of the tail, the interior parent is moved in UNDER whatever now holds
/// that destination slot, and the interior's own post-arm COLD read completes with
/// the tail listed FIRST as a non-directory.
///
/// Round six's finding: that first entry's `reconcile_slot` retires the tail,
/// releasing its marker; the marker's adopted watch had been legally reparented
/// ABOVE the interior, so the disposal that followed it destroyed the interior as
/// a mere descendant — and `drop_subtree` returned no collateral outcome, so the
/// COLD loop went on to its remaining entries. Each computed
/// `child_location(interior, …)` through the deliberately lenient location walk,
/// which TRUNCATES a dead id to the empty prefix, and emitted a **root-relative
/// `Created`** — after the retirement's own covering `Rescan`, so nothing
/// re-instructed it. Fabricated events, delivered, for children of a directory the
/// consumer was never told about at that path.
///
/// The redesign refuses the FIRST rename instead of propagating the consequence.
/// The destination slot is then held by a fresh watch rather than by the adopted
/// one, so the second rename builds the same TOPOLOGY over a harmless object: the
/// interior is a descendant of the slot, the tail is a descendant of the interior,
/// and the tail's retirement mid-listing takes only the tail. The remaining
/// entries reconcile into a live directory at its real location.
///
/// The mutation this kills: delete the `reparentable_adoption` conjunct at
/// `on_moved_to`'s pairing arm and the first rename lands, the second one puts the
/// adopted watch above the interior exactly as round six described, and the tail's
/// retirement releases a marker whose adopted watch is no longer beneath it —
/// which the containment `debug_assert!` in
/// [`DiesWithTheWalk`](super::AdoptionDisposal::DiesWithTheWalk) reports before any
/// of the rest can be observed.
#[test]
fn a_cold_reconcile_loop_cannot_lose_its_own_directory_or_fabricate_a_root_created() {
  let mut m = per_dir();
  let s = scope(1);
  let old_root = live_root_idle(&mut m, s);
  // Three splices, innermost first: the tail adopts the old root at `b`, the
  // interior adopts the tail at `mid`, and the final root adopts the interior at
  // `x`. Only the tail is acknowledged — the interior is deliberately left
  // `Arming` across both renames below, so that the read which reconciles its
  // listing is its ordinary post-arm COLD one: the only flavor that announces
  // `Created`s, and so the only one the fabrication could ever have ridden.
  let tail = m.reserve_watch_id();
  let _ = m
    .widen_root(s, tail, vec![seg("b")], Some(ident(1)))
    .expect("the widen splices");
  m.ack_watch(tail, Ok(WatchAck::Installed));
  let interior = m.reserve_watch_id();
  let _ = m
    .widen_root(s, interior, vec![seg("mid")], Some(ident(2)))
    .expect("the widen over it splices");
  let reserved = m.reserve_watch_id();
  let _ = m
    .widen_root(s, reserved, vec![seg("x")], Some(ident(3)))
    .expect("and the widen over that one");
  m.ack_watch(reserved, Ok(WatchAck::Installed));
  let root_read = read_of(&mut m, reserved);
  // The root's listing PROVES its own edge, which is what leaves the interior an
  // ordinary node: an unproven adopted watch is refused a reparent, so an
  // undischarged outer marker would refuse the second rename below for a reason
  // that has nothing to do with what this cell measures.
  m.on_enumerate(
    root_read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("x"), FileKind::Dir).with_node(ident(3)),
    ]),
  );
  seal_adoptions(&mut m, s);
  let _ = drain_events(&mut m);
  assert_eq!(m.child_watch(tail, &seg("b")), Some(old_root));
  assert_eq!(m.child_watch(interior, &seg("mid")), Some(tail));
  assert_eq!(m.child_watch(reserved, &seg("x")), Some(interior));
  assert!(
    !m.adoptions_settled(s),
    "two markers stand: the interior's, for the tail, and the tail's own"
  );

  // Round six's two renames. The first is the adopted watch out of the tail and
  // into a slot of the widened root; the second is the tail's PARENT moved in
  // under whatever now holds that slot — the adopted watch itself if the rename
  // landed, a fresh replacement if it was refused. Either way the topology below
  // is the same, and only one of them is a marker's escaped adopted watch.
  let _ = move_the_adopted_watch(&mut m, tail, reserved, "c");
  let above = m
    .child_watch(reserved, &seg("c"))
    .expect("the destination slot is occupied either way");
  move_child(&mut m, reserved, "x", above, "inside", 62);
  assert_eq!(m.child_watch(above, &seg("inside")), Some(interior));
  assert_eq!(m.child_watch(interior, &seg("mid")), Some(tail));
  assert!(!m.adoptions_settled(s), "the marker stands at the tail");

  // The interior's post-arm COLD read, stamped after both renames so its listing
  // is evidence. `mid` FIRST, so the retirement it triggers happens strictly
  // before the loop reaches the entries that would announce and install.
  m.ack_watch(interior, Ok(WatchAck::Installed));
  let cold = read_of(&mut m, interior);
  m.on_enumerate(
    cold,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("mid"), FileKind::File),
      DirEntry::new(seg("new"), FileKind::Dir).with_node(ident(9)),
      DirEntry::new(seg("mystery"), FileKind::Unknown),
    ]),
  );
  assert!(
    !m.is_watched(tail),
    "the non-directory entry retires the tail"
  );
  assert!(
    m.adoptions_settled(s),
    "releasing the marker it carried, whose adopted watch died with the walk"
  );
  assert!(
    m.is_watched(interior),
    "and the reading directory is UNTOUCHED: the drop was local to the tail's \
     own subtree"
  );

  // The fabrication, absent. Every announcement of this listing names the
  // interior's real location; none is the root-relative one a dead reader's
  // truncated location walk would have produced.
  let events = drain_events(&mut m);
  let real = loc(&["c", "inside"]);
  for change in &events {
    if change.kind().is_created() {
      assert!(
        change.location().starts_with(&real),
        "a `Created` outside the reading directory is fabricated: {change:?} \
         (all: {events:?})"
      );
    }
  }
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["new"])),
    "and specifically not round six's own: {events:?}"
  );
  let announced = real.clone().child(seg("new"));
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &announced),
    "the later entries are announced where they are: {events:?}"
  );

  // And reconciled there too, rather than beneath a coordinate nothing occupies.
  let installed = m
    .child_watch(interior, &seg("new"))
    .expect("the later entry installs under the parent the loop kept");
  let actions = drain_actions(&mut m);
  assert!(
    actions.iter().any(|a| addresses(a, interior)),
    "its arm and its slot stat are addressed to the interior: {actions:?}"
  );
  assert!(
    m.has_coverage_deficit(s),
    "and the unclassifiable name is booked at a coordinate that exists"
  );
  m.assert_invariants();

  // The wedge negative.
  m.ack_watch(installed, Ok(WatchAck::Installed));
  for req in actions
    .iter()
    .filter_map(|a| a.as_enumerate().map(|e| e.req()))
  {
    m.on_enumerate(req, EnumerateResult::Ok(Vec::new()));
  }
  quiesce(&mut m);
  assert!(
    m.rearm_settled(s) && m.adoptions_settled(s),
    "every cover this sequence stood releases: rearm_pending={:?}",
    m.rearm_pending
  );
  m.assert_invariants();
}

/// How deep a nest of standing adoption markers the cell below builds: deep
/// enough that ONE LIVE CALL FRAME PER LINK would overflow the test thread's
/// stack (measured on a debug build: the per-link-frame shape aborts at 2400 links
/// and survives 1200, so this carries margin); shallow enough under miri, where
/// each step costs orders of magnitude more, to stay tractable. Nothing caps the
/// marker count in the monitor, so either value is a sample of an unbounded family
/// rather than a limit.
const ADOPTION_NEST: u64 = if cfg!(miri) { 8 } else { 4000 };

/// `ADOPTION_NEST` back-to-back widens, each adopting the previous root DIRECTLY
/// under the new one — and nothing moving any of them, because nothing can.
///
/// Every marker below the final root is left standing and every adopted watch left
/// exactly where the splice put it: a direct child of the node that owes its proof.
/// At the one depth the splice serves, that child IS the previous root, so the
/// result is one nested chain, `root → previous root → the one before it → …`, in
/// which the newest adopted watch's teardown must release every marker in the nest.
/// Returns `(final_root, newest_adopted, adopted)`, `adopted` innermost-first.
fn nested_adoptions(m: &mut Monitor, s: ScopeId) -> (WatchId, WatchId, Vec<WatchId>) {
  let mut root = live_root_idle(m, s);
  let mut adopted = Vec::new();
  let mut newest_read = None;
  for k in 1..=ADOPTION_NEST {
    let reserved = m.reserve_watch_id();
    let mid = Segment::new(std::format!("mid{k}"));
    let _ = m
      .widen_root(s, reserved, vec![mid], Some(ident(k)))
      .expect("each widen splices");
    // The pre-arm outcome is replayed, as the driver does, and the cold read it
    // queues is captured but deliberately left OUTSTANDING: at depth one the
    // marker keys on the new root itself, so a complete listing answered inside
    // the loop would take the verdict and release the very marker the next link
    // is about to nest under.
    m.ack_watch(reserved, Ok(WatchAck::Installed));
    newest_read = drain_actions(m).iter().find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == reserved)
        .map(|e| e.req())
    });
    let _ = drain_events(m);
    adopted.push(root);
    root = reserved;
  }
  // The OUTERMOST marker alone is discharged, by the final root's own listing
  // naming the newest adopted watch at the identity the splice adopted it under.
  // That leaves the nest keyed strictly BELOW the surviving root — every marker
  // an owner the teardown walk will itself destroy — which is the shape the cell
  // measures. Left standing, it would be a marker whose key survives the walk and
  // whose release is owed to a later read, not to the walk, and the count would
  // say so.
  m.on_enumerate(
    newest_read.expect("the final root's cold read was queued"),
    EnumerateResult::Ok(vec![
      DirEntry::new(
        Segment::new(std::format!("mid{ADOPTION_NEST}")),
        FileKind::Dir,
      )
      .with_node(ident(ADOPTION_NEST)),
    ]),
  );
  seal_adoptions(m, s);
  let _ = drain_events(m);
  let tail = *adopted.last().expect("ADOPTION_NEST is non-zero");
  (root, tail, adopted)
}

/// One walk releases an arbitrarily deep nest of adoption markers, and grows the
/// stack by nothing.
///
/// This is what the escapee worklist was for, and why deleting it is safe. An
/// adopted watch that could be reparented OUT of its marker parent would have to
/// be retired by a SECOND walk once its marker was released, whose own erased
/// markers could free a third, and so on — one link per pending adoption marker,
/// of which nothing caps the number. Driven by re-entering `drop_subtree` the
/// chain spends a call frame per link and can overflow the stack; driven off a
/// heap worklist it needs a second destructive pass whose reach is outside the
/// subtree the caller named, which is the non-locality round six's fabrication
/// came out of.
///
/// The containment invariant removes the chain rather than bounding it: each
/// adopted watch is a direct child of its marker's node, so `ADOPTION_NEST`
/// markers nest inside one another and ONE iterative walk destroys the lot.
///
/// Two claims, and [`ADOPTION_NEST`] is what makes the second testable. That every
/// marker is released is what the assertions state; that nothing recurses per
/// marker is what running at this depth demonstrates, since one live frame per
/// link exhausts the test thread's stack here and aborts the process rather than
/// failing an assertion.
#[test]
fn one_walk_releases_an_arbitrarily_deep_nest_of_adoption_markers() {
  let mut m = per_dir();
  let s = scope(1);
  let (root, tail, adopted) = nested_adoptions(&mut m, s);
  assert_eq!(adopted.len(), ADOPTION_NEST as usize);
  assert!(
    adopted.iter().all(|a| m.is_watched(*a)),
    "every adopted root is alive where its splice put it"
  );
  assert!(!m.adoptions_settled(s), "with every marker still standing");
  m.assert_invariants();

  // The newest tail dies with its marker unresolved. Its adopted watch is the
  // next root, whose own tail holds the next marker, and so on down.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(Segment::new(std::format!("mid{ADOPTION_NEST}"))),
    at(30),
  );
  assert!(!m.is_watched(tail), "the tail dies");
  assert!(
    m.adoptions_settled(s),
    "and one walk releases the whole nest of markers"
  );
  for (link, object) in adopted.iter().enumerate() {
    assert!(
      !m.is_watched(*object),
      "link {link} of the nest died with the same walk — it was under it all \
       along"
    );
  }
  m.assert_invariants();

  let _ = drain_events(&mut m);
  drain_reads_clean(&mut m);
  assert!(
    m.coverage_settled(s),
    "and the covers the walk stood all release: rearm_settled={}",
    m.rearm_settled(s)
  );
  m.assert_invariants();
}

// ---------------------------------------------------------------------------
// The acknowledged reinstall: on a lossy-watch-teardown profile a scope-level
// loss re-proves every retained kernel binding by a re-add whose `Ok` must
// postdate the loss, and the barrier cannot settle before the proof chain
// completes. INV-BIND: a scope's barrier may settle only over bindings whose
// install acknowledgement postdates the scope's last loss signal.
// ---------------------------------------------------------------------------

/// A per-directory profile whose watch teardown records are losable — the
/// inotify shape.
fn reproving() -> Monitor {
  Monitor::new(
    Capabilities::new()
      .with_supports_push()
      .with_lossy_watch_teardown(),
  )
}

/// The re-add `Action::Watch` for `watch` in `actions`, if any, returning its
/// target.
fn readd_of(actions: &[Action], watch: WatchId) -> Option<WatchTarget> {
  actions.iter().find_map(|a| {
    a.as_watch()
      .filter(|w| w.id() == watch)
      .map(|w| w.target().clone())
  })
}

#[test]
fn a_flagged_scope_loss_reissues_the_root_watch_and_holds_the_barrier() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);

  m.on_overflow(Scope::Root(s), at(1));
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|c| c.kind().is_rescan()),
    "the loss stands its covering Rescan first: {events:?}"
  );
  let actions = drain_actions(&mut m);
  assert_eq!(
    readd_of(&actions, root),
    Some(WatchTarget::RearmRoot(s)),
    "the root binding is re-proven by a re-add, never a respawn: {actions:?}"
  );
  assert!(
    !actions.iter().any(|a| a.is_enumerate()),
    "no read runs before the binding acknowledges: {actions:?}"
  );
  assert!(!m.rearm_settled(s), "the re-add is a counted obligation");
  assert!(
    !m.coverage_settled(s),
    "the barrier holds through the reproof"
  );

  m.ack_watch(root, Ok(WatchAck::Aliased));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the acknowledged binding re-arm-reads");
  assert!(!m.rearm_settled(s), "the read keeps the scope unsettled");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.coverage_settled(s));
  assert!(
    drain_events(&mut m).is_empty(),
    "an all-Aliased recovery owes no closing Rescan"
  );
  m.assert_invariants();
}

#[test]
fn a_reproving_recovery_readds_identity_matched_survivors_to_depth() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root(&mut m, s);
  // Build root/a/b, identities carried so the recovery keeps the survivors.
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap read");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let w_a = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("a arms");
  m.ack_watch(w_a, Ok(WatchAck::Installed));
  let a_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("a's cold read");
  m.on_enumerate(
    a_boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(11)),
    ]),
  );
  let w_b = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("b arms");
  m.ack_watch(w_b, Ok(WatchAck::Installed));
  let b_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("b's cold read");
  m.on_enumerate(b_boot, EnumerateResult::Ok(vec![]));
  let _ = drain_events(&mut m);
  assert!(m.rearm_settled(s));

  // The loss: the whole retained chain must re-prove, root → a → b.
  m.on_overflow(Scope::Root(s), at(2));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let root_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the root's reproof read");
  m.on_enumerate(
    root_read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(10)),
      DirEntry::new(seg("fresh"), FileKind::Dir).with_node(ident(12)),
    ]),
  );
  let actions = drain_actions(&mut m);
  assert_eq!(
    readd_of(&actions, w_a),
    Some(WatchTarget::child(root, seg("a"))),
    "the identity-matched survivor is RE-ADDED under its own id: {actions:?}"
  );
  let w_fresh = actions
    .iter()
    .find_map(|a| a.as_watch().filter(|w| w.id() != w_a).map(|w| w.id()))
    .expect("the fresh name installs a fresh watch");
  assert!(
    !actions
      .iter()
      .any(|a| a.as_enumerate().is_some_and(|e| e.dir() == w_a)),
    "the survivor is not read before its binding acknowledges: {actions:?}"
  );
  assert!(!m.rearm_settled(s));

  // Depth: a's acknowledged reproof carries the flavor to b.
  m.ack_watch(w_a, Ok(WatchAck::Aliased));
  let a_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("a's reproof read");
  m.on_enumerate(
    a_read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("b"), FileKind::Dir).with_node(ident(11)),
    ]),
  );
  let actions = drain_actions(&mut m);
  assert_eq!(
    readd_of(&actions, w_b),
    Some(WatchTarget::child(w_a, seg("b"))),
    "the flavor reaches depth 3: {actions:?}"
  );
  m.ack_watch(w_b, Ok(WatchAck::Aliased));
  let b_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("b's reproof read");
  m.on_enumerate(b_read, EnumerateResult::Ok(vec![]));
  assert!(
    !m.rearm_settled(s),
    "the fresh install's chain is still open"
  );

  // The fresh node needs no reproof below it: its own install ACK + cold-free
  // rearm read complete the recovery.
  m.ack_watch(w_fresh, Ok(WatchAck::Installed));
  let fresh_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the fresh install reads");
  m.on_enumerate(fresh_read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.coverage_settled(s));
  m.assert_invariants();
}

#[test]
fn a_reproved_root_ack_err_runs_the_invalidation_funnel() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  m.on_overflow(Scope::Root(s), at(1));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // The re-add resolved against a DIFFERENT object (or nothing): the honest
  // root death the identity-sampling gate cannot see.
  m.ack_watch(root, Err(WatchError::Gone));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|c| c.kind().is_rescan() && c.location() == &Location::new()),
    "the terminal root Rescan stands: {events:?}"
  );
  assert!(
    drain_actions(&mut m).iter().any(|a| a.is_unwatch()),
    "the tree tears down"
  );
  assert!(!m.is_watched(root), "the root is invalidated");
  assert!(m.rearm_settled(s), "nothing is left pending");
  m.assert_invariants();
}

#[test]
fn a_reproved_child_ack_err_records_the_slot_deficit() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root(&mut m, s);
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap read");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let w_a = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("a arms");
  m.ack_watch(w_a, Ok(WatchAck::Installed));
  let a_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("a's cold read");
  m.on_enumerate(a_boot, EnumerateResult::Ok(vec![]));
  let _ = drain_events(&mut m);

  m.on_overflow(Scope::Root(s), at(2));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let root_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the root's reproof read");
  m.on_enumerate(
    root_read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let _ = drain_actions(&mut m);
  m.ack_watch(w_a, Err(WatchError::NotFound));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|c| c.kind().is_rescan() && c.location() == &loc(&["a"])),
    "the failed reproof stands its covering Rescan: {events:?}"
  );
  assert!(!m.is_watched(w_a), "the unprovable subtree is dropped");
  assert!(
    m.has_coverage_deficit(s),
    "the refused slot is booked level-persistent"
  );
  m.assert_invariants();
}

#[test]
fn a_second_loss_invalidates_the_first_binding_ack() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);

  m.on_overflow(Scope::Root(s), at(1));
  let _ = drain_events(&mut m);
  let first = drain_actions(&mut m);
  assert!(readd_of(&first, root).is_some(), "the first re-add issues");

  // A second loss lands while the re-add is in flight: it coalesces (no
  // second action — one watch action per node is outstanding)…
  m.on_overflow(Scope::Root(s), at(2));
  let _ = drain_events(&mut m);
  let coalesced = drain_actions(&mut m);
  assert!(
    readd_of(&coalesced, root).is_none(),
    "the in-flight re-add coalesces: {coalesced:?}"
  );

  // …and the FIRST acknowledgement no longer counts: the binding it certifies
  // may have died with the second loss, its teardown swallowed. The watch is
  // re-issued; nothing reads; the barrier stays down.
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let reissued = drain_actions(&mut m);
  assert_eq!(
    readd_of(&reissued, root),
    Some(WatchTarget::RearmRoot(s)),
    "a stale acknowledgement re-issues the re-add: {reissued:?}"
  );
  assert!(
    !reissued.iter().any(|a| a.is_enumerate()),
    "a stale acknowledgement unlocks no read: {reissued:?}"
  );
  assert!(!m.rearm_settled(s));
  assert!(!m.coverage_settled(s));

  // The postdating acknowledgement is the proof.
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the postdating acknowledgement reads");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.coverage_settled(s));
  m.assert_invariants();
}

#[test]
fn an_installed_readd_ack_stands_exactly_one_closing_rescan() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);

  m.on_overflow(Scope::Root(s), at(1));
  let opening: Vec<Change> = drain_events(&mut m);
  assert_eq!(opening.len(), 1, "the opening Rescan: {opening:?}");
  let _ = drain_actions(&mut m);

  // Installed: the old binding was dead — the window between the loss and
  // this acknowledgement was recorded by nothing.
  m.ack_watch(root, Ok(WatchAck::Installed));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the re-established binding reads");
  assert!(
    drain_events(&mut m).is_empty(),
    "no Rescan before the settle edge"
  );
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  let closing: Vec<Change> = drain_events(&mut m);
  assert_eq!(
    closing.len(),
    1,
    "exactly one closing Rescan at the settle edge: {closing:?}"
  );
  assert!(closing[0].kind().is_rescan());
  assert_eq!(closing[0].location(), &Location::new());
  assert!(
    closing[0].epoch() > opening[0].epoch(),
    "the closing Rescan dominates the window"
  );
  m.assert_invariants();
}

#[test]
fn a_plain_profile_loss_keeps_the_enumerate_rearm() {
  // Unflagged per-directory: byte-identical legacy behavior — the loss
  // re-arms by enumerate, no re-add, no barrier change beyond the read.
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  m.on_overflow(Scope::Root(s), at(1));
  let _ = drain_events(&mut m);
  let actions = drain_actions(&mut m);
  assert!(
    !actions.iter().any(|a| a.is_watch()),
    "an unflagged profile issues no re-add: {actions:?}"
  );
  assert!(
    actions
      .iter()
      .any(|a| a.as_enumerate().is_some_and(|e| e.dir() == root)),
    "the legacy enumerate re-arm runs: {actions:?}"
  );

  // Kernel-recursive: the loss is covered by the stream itself.
  let mut k = kernel_recursive();
  let kr = live_root(&mut k, scope(2));
  let _ = kr;
  m.assert_invariants();
}

#[test]
fn a_rebind_supersedes_an_inflight_recovery_coherently() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);

  // A recovery in flight…
  m.on_overflow(Scope::Root(s), at(1));
  let _ = drain_events(&mut m);
  assert!(readd_of(&drain_actions(&mut m), root).is_some());

  // …superseded by a stream replace, as the core drives it: rebind, then the
  // commit's synthetic scope loss (which coalesces into the reset root — the
  // caller's replay owns the next acknowledgement, so nothing new issues).
  assert_eq!(m.rebind_root(s).map(|(id, _)| id), Some(root));
  m.on_overflow(Scope::Root(s), at(2));
  let _ = drain_events(&mut m);
  let actions = drain_actions(&mut m);
  assert!(
    readd_of(&actions, root).is_none(),
    "the rebound root awaits the replay, not a second action: {actions:?}"
  );
  assert!(!m.rearm_settled(s));

  // The replayed pre-arm outcome predates the commit's loss, so the stamp
  // rule spends one re-add re-proving the binding on the NEW transport —
  // strictly more honest than trusting a pre-commit install across the cut.
  m.ack_watch(root, Ok(WatchAck::Installed));
  let reissued = drain_actions(&mut m);
  assert_eq!(
    readd_of(&reissued, root),
    Some(WatchTarget::RearmRoot(s)),
    "the replay is stale under the commit's loss: {reissued:?}"
  );
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the re-proven root rebuilds");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.is_watched(root), "no spurious invalidation anywhere");
  m.assert_invariants();
}

#[test]
fn a_widen_splice_carries_an_inflight_recovery() {
  let mut m = reproving();
  let s = scope(1);
  let old_root = live_root_idle(&mut m, s);

  // A recovery in flight at the commit: the old root's re-add is issued and
  // counted.
  m.on_overflow(Scope::Root(s), at(1));
  let _ = drain_events(&mut m);
  assert!(readd_of(&drain_actions(&mut m), old_root).is_some());
  assert!(!m.rearm_settled(s));

  // The same-transport widen splices the new root ABOVE the recovery.
  let reserved = m.reserve_watch_id();
  let widened = m.widen_root(s, reserved, vec![seg("r")], Some(ident(1)));
  assert_eq!(widened.map(|(id, _)| id), Some(reserved));
  assert!(
    !m.rearm_settled(s),
    "the in-flight reproof rides the splice, counter intact"
  );
  assert!(!m.coverage_settled(s), "the adoption marker also holds");

  // The old root's acknowledgement lands post-splice and completes against
  // the ADOPTED node — same id, same obligation, new place in the tree.
  m.ack_watch(old_root, Ok(WatchAck::Aliased));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == old_root)
        .map(|e| e.req())
    })
    .expect("the adopted node's reproof read");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  assert!(
    m.rearm_settled(s),
    "the recovery completes across the splice"
  );
  m.assert_invariants();
}

#[test]
fn an_exhausted_reprove_read_still_readds_every_kept_child() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root(&mut m, s);
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap read");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let w_a = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("a arms");
  m.ack_watch(w_a, Ok(WatchAck::Installed));
  let a_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("a's cold read");
  m.on_enumerate(a_boot, EnumerateResult::Ok(vec![]));
  let _ = drain_events(&mut m);
  assert!(m.rearm_settled(s));

  m.on_overflow(Scope::Root(s), at(1));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the root's reproof read");

  // The reproof read never completes clean: every pass is Partial (an
  // unreadable directory in the loss regime), listing the kept child. The
  // FIRST pass must already re-add the survivor — an exhausted read gets no
  // completion, so this cascade is the survivor's only visit.
  m.on_enumerate(
    read,
    EnumerateResult::Partial(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let _ = drain_events(&mut m);
  let pass1 = drain_actions(&mut m);
  assert_eq!(
    readd_of(&pass1, w_a),
    Some(WatchTarget::child(root, seg("a"))),
    "the incomplete-read cascade RE-ADDS the kept child: {pass1:?}"
  );
  assert!(
    !pass1
      .iter()
      .any(|a| a.as_enumerate().is_some_and(|e| e.dir() == w_a)),
    "the survivor is not read before its binding acknowledges: {pass1:?}"
  );
  let retry1 = pass1
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the root read retries");

  // Later passes coalesce onto the in-flight re-add — no stacking.
  m.on_enumerate(
    retry1,
    EnumerateResult::Partial(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let _ = drain_events(&mut m);
  let pass2 = drain_actions(&mut m);
  assert!(
    readd_of(&pass2, w_a).is_none(),
    "the in-flight re-add coalesces across retries: {pass2:?}"
  );
  let retry2 = pass2
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the bounded retry");

  // Exhaustion: the standing Rescan and the interior deficit book the
  // unreadable content — but the kept child's binding obligation SURVIVES the
  // exhaustion, so nothing can settle before its acknowledgement.
  m.on_enumerate(
    retry2,
    EnumerateResult::Partial(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  assert!(
    m.has_coverage_deficit(s),
    "the exhausted interior is booked"
  );
  assert!(
    !m.rearm_settled(s),
    "the kept child's un-acknowledged re-add holds the barrier past the exhaustion"
  );
  assert!(!m.coverage_settled(s));

  m.ack_watch(w_a, Ok(WatchAck::Aliased));
  let a_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the acknowledged child reads");
  m.on_enumerate(a_read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.coverage_settled(s));
  m.assert_invariants();
}

#[test]
fn a_deficit_heal_on_a_lossy_scope_reproves_the_anchor() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);

  // A loss, then a refused install inside its recovery: the slot deficit
  // stands past the settled recovery.
  m.on_overflow(Scope::Root(s), at(1));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the root's reproof read");
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("a"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let w_a = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the fresh name installs");
  m.ack_watch(w_a, Err(WatchError::NoSpace));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  assert!(m.has_coverage_deficit(s), "the refused slot is booked");
  assert!(m.rearm_settled(s), "the recovery itself has settled");

  // The dispatch-seam heal on a lossy scope with a loss on record must
  // re-prove the healing anchor, not merely re-read it: the darkness the
  // deficit hid may include the very teardown records the loss swallowed.
  assert!(m.resignal_coverage_deficits(s));
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|c| c.kind().is_rescan()),
    "the re-signal stands its covering Rescan: {events:?}"
  );
  let kicks = drain_actions(&mut m);
  assert_eq!(
    readd_of(&kicks, root),
    Some(WatchTarget::RearmRoot(s)),
    "the heal kick is the acknowledged re-add, never a bare read: {kicks:?}"
  );
  assert!(
    !kicks.iter().any(|a| a.is_enumerate()),
    "no read runs before the healing anchor acknowledges: {kicks:?}"
  );
  assert!(!m.rearm_settled(s));

  m.ack_watch(root, Ok(WatchAck::Aliased));
  let heal_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the acknowledged anchor heals by reading");
  m.on_enumerate(heal_read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.coverage_settled(s));
  m.assert_invariants();
}

#[test]
fn a_dirtied_hold_pairing_reproves_the_reparented_source() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root(&mut m, s);
  // root/s0/d, identities carried, fully settled.
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap read");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("s0"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let w_s = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("s0 arms");
  m.ack_watch(w_s, Ok(WatchAck::Installed));
  let s_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("s0's cold read");
  m.on_enumerate(
    s_boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("d"), FileKind::Dir).with_node(ident(11)),
    ]),
  );
  let w_d = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("d arms");
  m.ack_watch(w_d, Ok(WatchAck::Installed));
  let d_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("d's cold read");
  m.on_enumerate(d_boot, EnumerateResult::Ok(vec![]));
  let _ = drain_events(&mut m);
  assert!(m.rearm_settled(s));

  // The source detaches mid-move, THEN the loss lands: the recovery cannot
  // reach the held subtree (by design), so the hold is dirtied and the
  // pairing owes the reproof.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("s0"))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(2),
  );
  m.on_overflow(Scope::Root(s), at(3));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the root's reproof read");
  // The moved-away source is absent from the listing; the recovery settles
  // its own side while the hold keeps the barrier down.
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  assert!(m.rearm_settled(s));
  assert!(!m.coverage_settled(s), "the hold keeps the barrier down");

  // The pairing lands: the dirtied hold's re-arm must be the RE-ADD — the
  // reparented source is in-slot at the destination now, and only its
  // acknowledged re-add re-proves the subtree the recovery skipped.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("s1"))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(4),
  );
  let _ = drain_events(&mut m);
  let paired = drain_actions(&mut m);
  assert_eq!(
    readd_of(&paired, w_s),
    Some(WatchTarget::child(root, seg("s1"))),
    "the dirtied pairing re-adds the reparented source at its destination: {paired:?}"
  );
  assert!(
    !paired
      .iter()
      .any(|a| a.as_enumerate().is_some_and(|e| e.dir() == w_s)),
    "the source is not read before its binding acknowledges: {paired:?}"
  );

  // The reproof carries into the held-over descendant.
  m.ack_watch(w_s, Ok(WatchAck::Aliased));
  let s_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the source's reproof read");
  m.on_enumerate(
    s_read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("d"), FileKind::Dir).with_node(ident(11)),
    ]),
  );
  let deeper = drain_actions(&mut m);
  assert_eq!(
    readd_of(&deeper, w_d),
    Some(WatchTarget::child(w_s, seg("d"))),
    "the reproof reaches the descendant the loss recovery could not: {deeper:?}"
  );
  m.ack_watch(w_d, Ok(WatchAck::Aliased));
  let d_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the descendant's reproof read");
  m.on_enumerate(d_read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.coverage_settled(s));
  m.assert_invariants();
}

/// A hold BORN while the recovery is unsettled detaches a subtree the crawl
/// can no longer visit (it re-adds only in-slot survivors), and its pairing
/// destination may already be re-proven — so the O(1) reparent alone would
/// carry a kernel-dead retained subtree into a settled scope with no
/// post-loss acknowledgement. The detach must born-dirty the hold: the
/// pairing then re-adds the reparented source, and the barrier holds until
/// the subtree's acknowledgement chain completes.
#[test]
fn a_hold_born_during_an_unsettled_recovery_pairs_with_the_reproof() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root(&mut m, s);
  // root/{d, p/x/g}, identities carried, fully settled.
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap read");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("d"), FileKind::Dir).with_node(ident(10)),
      DirEntry::new(seg("p"), FileKind::Dir).with_node(ident(11)),
    ]),
  );
  let installs = drain_actions(&mut m);
  let w_d = installs
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("d")))
        .map(|w| w.id())
    })
    .expect("d arms");
  let w_p = installs
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(root, seg("p")))
        .map(|w| w.id())
    })
    .expect("p arms");
  m.ack_watch(w_d, Ok(WatchAck::Installed));
  let d_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("d's cold read");
  m.on_enumerate(d_boot, EnumerateResult::Ok(vec![]));
  m.ack_watch(w_p, Ok(WatchAck::Installed));
  let p_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("p's cold read");
  m.on_enumerate(
    p_boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("x"), FileKind::Dir).with_node(ident(12)),
    ]),
  );
  let w_x = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("x arms");
  m.ack_watch(w_x, Ok(WatchAck::Installed));
  let x_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("x's cold read");
  m.on_enumerate(
    x_boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("g"), FileKind::Dir).with_node(ident(13)),
    ]),
  );
  let w_g = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("g arms");
  m.ack_watch(w_g, Ok(WatchAck::Installed));
  let g_boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("g's cold read");
  m.on_enumerate(g_boot, EnumerateResult::Ok(vec![]));
  let _ = drain_events(&mut m);
  assert!(m.coverage_settled(s));

  // The loss: root re-proves, its read re-adds d and p.
  m.on_overflow(Scope::Root(s), at(2));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let root_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the root's reproof read");
  m.on_enumerate(
    root_read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("d"), FileKind::Dir).with_node(ident(10)),
      DirEntry::new(seg("p"), FileKind::Dir).with_node(ident(11)),
    ]),
  );
  let _ = drain_actions(&mut m);
  // d completes its reproof; p's re-add is still unacknowledged.
  m.ack_watch(w_d, Ok(WatchAck::Aliased));
  let d_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("d's reproof read");
  m.on_enumerate(d_read, EnumerateResult::Ok(vec![]));
  let _ = drain_actions(&mut m);
  assert!(!m.rearm_settled(s), "p's reproof is still outstanding");

  // `mv p/x d/x` while p is mid-reproof: the hold is born during the
  // unsettled recovery and pairs into the ALREADY re-proven d.
  m.on_os_record(
    OsRecord::new(w_p, RecordKind::MovedFrom)
      .with_name(seg("x"))
      .with_cookie(cookie(9))
      .with_is_dir(true),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::MovedTo)
      .with_name(seg("x"))
      .with_cookie(cookie(9))
      .with_is_dir(true),
    at(4),
  );
  let _ = drain_events(&mut m);
  let paired = drain_actions(&mut m);
  assert_eq!(
    readd_of(&paired, w_x),
    Some(WatchTarget::child(w_d, seg("x"))),
    "the recovery-born hold pairs with the RE-ADD at its destination: {paired:?}"
  );

  // p's reproof completes without x (it moved away); the barrier must still
  // hold for x's chain — the moved subtree's bindings are exactly the ones
  // the crawl can no longer reach.
  m.ack_watch(w_p, Ok(WatchAck::Aliased));
  let p_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("p's reproof read");
  m.on_enumerate(p_read, EnumerateResult::Ok(vec![]));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  assert!(
    !m.rearm_settled(s),
    "the moved subtree's unacknowledged re-add holds the barrier"
  );
  assert!(!m.coverage_settled(s));

  // x acknowledges; its reproof read carries the flavor to g.
  m.ack_watch(w_x, Ok(WatchAck::Aliased));
  let x_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("x's reproof read");
  m.on_enumerate(
    x_read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("g"), FileKind::Dir).with_node(ident(13)),
    ]),
  );
  let deeper = drain_actions(&mut m);
  assert_eq!(
    readd_of(&deeper, w_g),
    Some(WatchTarget::child(w_x, seg("g"))),
    "the reproof reaches the held-over descendant: {deeper:?}"
  );
  m.ack_watch(w_g, Ok(WatchAck::Aliased));
  let g_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("g's reproof read");
  m.on_enumerate(g_read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.coverage_settled(s));
  m.assert_invariants();
}

/// The reproving-profile storm: random schedules of scope losses, ACKs
/// (`Installed`/`Aliased`/`Err`, stale-generation ones included), paired and
/// unpaired moves, holds, create/remove churn, incomplete and dirtied reads,
/// located overflows, timeouts, and dispatch-seam deficit re-signals against
/// `lossy_watch_teardown` scopes — asserting INV-BIND at every settle edge:
/// **the barrier may settle only over bindings whose acknowledged (re-)add
/// postdates the scope's last loss.**
///
/// The harness mirrors the stamp rule from the outside, using only the
/// public seam: it records each watch's ISSUE generation (the scope's loss
/// count when its `Action::Watch` was drained — re-issues re-stamp it) and
/// marks the watch proven at that generation when an `Ok` acknowledgement
/// is fed. Whenever `coverage_settled` reads true, every retained
/// acknowledged node of the scope must be proven at the CURRENT loss count;
/// a stale-proven survivor at a settle edge is a possibly-kernel-dead
/// binding the barrier just certified. Enumerate results are mostly
/// faithful listings of the live tree (so identity-matched survivors — the
/// retention fuel — actually arise, and follow moves), randomly perturbed
/// to exercise the rebuild and deficit funnels.
#[test]
fn reproving_storm_settles_only_over_postdating_acks() {
  // Guards the harness against going vacuous: a post-loss settle edge — the
  // one place the invariant bites — must actually be reached.
  let mut settle_edges_checked = 0u64;
  // A storm's seeds are statistical convergence coverage, and that is the native
  // runs' job: one seed drives every code path the rest do, while sixty-odd seeds'
  // worth of tree churn exhausts a 32-bit target's entire address space under miri
  // (i686 dies with "no more free addresses"). Miri is here to find UB, so it runs
  // the shape once.
  let seeds: u64 = if cfg!(miri) { 1 } else { 96 };
  for seed in 1..=seeds {
    let mut m = reproving();
    let mut s = seed.wrapping_mul(2_654_435_761).wrapping_add(97_531);
    let mut rng = move || {
      s ^= s << 13;
      s ^= s >> 17;
      s ^= s << 5;
      s
    };

    let scopes = [scope(1), scope(2)];
    let mut roots: std::collections::BTreeMap<ScopeId, WatchId> = scopes
      .iter()
      .map(|&sc| {
        (
          sc,
          m.register_root(sc, Interest::all())
            .expect("a fresh scope registers"),
        )
      })
      .collect();
    // The outside mirror of the ACK-postdates-loss stamp.
    let mut loss_count: std::collections::BTreeMap<ScopeId, u64> =
      std::collections::BTreeMap::new();
    let mut last_arm_gen: std::collections::BTreeMap<WatchId, u64> =
      std::collections::BTreeMap::new();
    let mut proven_gen: std::collections::BTreeMap<WatchId, u64> =
      std::collections::BTreeMap::new();
    let mut watches: Vec<WatchId> = Vec::new();
    let mut pending_arms: Vec<WatchId> = Vec::new();
    let mut reads: Vec<(ReqId, WatchId)> = Vec::new();
    let names = [seg("a"), seg("b"), seg("c"), seg("d")];
    let mut fresh_ident = 100u64;

    for step in 0..350u64 {
      // Absorb outputs, stamping every drained arm with its scope's current
      // loss count — the issue generation an eventual `Ok` can prove.
      while let Some(action) = m.poll_action() {
        match action {
          Action::Watch(w) => {
            if let Some(ws) = m.scope_of(w.id()) {
              last_arm_gen.insert(w.id(), loss_count.get(&ws).copied().unwrap_or(0));
            }
            if !watches.contains(&w.id()) {
              watches.push(w.id());
            }
            pending_arms.push(w.id());
          }
          Action::Enumerate(e) => reads.push((e.req(), e.dir())),
          _ => {}
        }
      }
      while m.poll_event().is_some() {}
      m.assert_invariants();
      watches.retain(|&w| m.is_watched(w));
      pending_arms.retain(|&w| m.is_watched(w));
      reads.retain(|&(_, dir)| m.is_watched(dir));

      // INV-BIND at the settle edge. `coverage_settled` implies no counted
      // reproof and no standing hold, so every retained acknowledged node
      // must be proven under the loss in force — a deficit booked for
      // node-free darkness may legally stand, but never an unproven binding.
      for &sc in &scopes {
        if !m.coverage_settled(sc) {
          continue;
        }
        let current = loss_count.get(&sc).copied().unwrap_or(0);
        if current > 0 {
          settle_edges_checked += 1;
        }
        for &w in &watches {
          if m.scope_of(w) == Some(sc)
            && let Some(&proven) = proven_gen.get(&w)
          {
            assert_eq!(
              proven, current,
              "INV-BIND violated: scope {sc:?} settled over watch {w:?} whose \
               last acknowledged add predates the loss (seed {seed}, step {step})"
            );
          }
        }
      }

      // A dead root starves the schedule of reproving fuel: re-register.
      for &sc in &scopes {
        let root = roots.get_mut(&sc).expect("both scopes are tracked");
        if !m.is_watched(*root) {
          *root = m
            .register_root(sc, Interest::all())
            .expect("a fresh scope registers");
        }
      }

      let now = at(step + 1);
      match rng() % 12 {
        // Acknowledge an outstanding arm — the dominant fuel. An arm drained
        // before a later loss acknowledges STALE here, exercising the
        // re-issue rule.
        0..=2 if !pending_arms.is_empty() => {
          let w = pending_arms.swap_remove((rng() as usize) % pending_arms.len());
          if rng() % 10 == 0 {
            m.ack_watch(w, Err(WatchError::NotFound));
          } else {
            if let Some(&issued) = last_arm_gen.get(&w) {
              proven_gen.insert(w, issued);
            }
            let ack = if rng() % 3 == 0 {
              WatchAck::Installed
            } else {
              WatchAck::Aliased
            };
            m.ack_watch(w, Ok(ack));
          }
        }
        // Complete a read: a faithful listing of the live tree (survivors
        // arise and follow moves), sometimes perturbed (vanish/replace one)
        // or degraded (`Partial`/`Failed`).
        3..=5 if !reads.is_empty() => {
          let (req, dir) = reads.swap_remove((rng() as usize) % reads.len());
          let mut entries: Vec<DirEntry> = m
            .slot_children(dir)
            .into_iter()
            .map(|(name, id)| {
              let entry = DirEntry::new(name, FileKind::Dir);
              match id {
                Some(id) => entry.with_node(id),
                None => entry,
              }
            })
            .collect();
          match rng() % 8 {
            0 if !entries.is_empty() => {
              let victim = (rng() as usize) % entries.len();
              entries.swap_remove(victim);
            }
            1 => {
              fresh_ident += 1;
              entries.push(
                DirEntry::new(names[(rng() as usize) % names.len()].clone(), FileKind::Dir)
                  .with_node(ident(fresh_ident)),
              );
            }
            _ => {}
          }
          let res = match rng() % 6 {
            0 => EnumerateResult::Partial(entries),
            1 => EnumerateResult::Failed(IoClass::Io),
            _ => EnumerateResult::Ok(entries),
          };
          m.on_enumerate(req, res);
        }
        // A scope-level loss — the binding-re-proving trigger the mirror
        // counts with the Monitor. Damped, so recoveries regularly COMPLETE
        // between losses: the settle edge is where the invariant bites.
        6 if rng() % 3 == 0 => {
          if rng() % 4 == 0 {
            for &sc in &scopes {
              if m.is_watched(roots[&sc]) {
                *loss_count.entry(sc).or_insert(0) += 1;
              }
            }
            m.on_overflow(Scope::All, now);
          } else {
            let sc = scopes[(rng() as usize) % scopes.len()];
            if m.is_watched(roots[&sc]) {
              *loss_count.entry(sc).or_insert(0) += 1;
            }
            m.on_overflow(Scope::Root(sc), now);
          }
        }
        // A located overflow: no kernel-loss evidence, must never bump the
        // proof obligation.
        7 if !watches.is_empty() => {
          let w = watches[(rng() as usize) % watches.len()];
          m.on_overflow(Scope::Subtree(SubtreeScope::new(w)), now);
        }
        // A move: source half at one watch, usually paired promptly at
        // another (a held directory reparents cross-subtree — including into
        // an already re-proven destination), sometimes left to strand. A
        // real slot child is preferred as the source, so detach-and-hold —
        // the funnel that carries a retained subtree out of the crawl's
        // reach — is common rather than incidental.
        8 | 9 if !watches.is_empty() => {
          let from = watches[(rng() as usize) % watches.len()];
          let kids = m.slot_children(from);
          let name = if !kids.is_empty() && rng() % 8 != 0 {
            kids[(rng() as usize) % kids.len()].0.clone()
          } else {
            names[(rng() as usize) % names.len()].clone()
          };
          let ck = cookie(1 + rng() % 4);
          m.on_os_record(
            OsRecord::new(from, RecordKind::MovedFrom)
              .with_name(name)
              .with_cookie(ck)
              .with_is_dir(true),
            now,
          );
          if rng() % 4 != 0 {
            let to = watches[(rng() as usize) % watches.len()];
            m.on_os_record(
              OsRecord::new(to, RecordKind::MovedTo)
                .with_name(names[(rng() as usize) % names.len()].clone())
                .with_cookie(ck)
                .with_is_dir(true),
              now,
            );
          }
        }
        // Create/remove churn; identity-carrying creates grow the retained
        // tree the recoveries must re-prove.
        10 if !watches.is_empty() => {
          let w = watches[(rng() as usize) % watches.len()];
          let name = names[(rng() as usize) % names.len()].clone();
          if rng() % 3 == 0 {
            m.on_os_record(
              OsRecord::new(w, RecordKind::Removed)
                .with_name(name)
                .with_is_dir(rng() % 2 == 0),
              now,
            );
          } else {
            fresh_ident += 1;
            m.on_os_record(
              OsRecord::new(w, RecordKind::Created)
                .with_name(name)
                .with_is_dir(true)
                .with_node(ident(fresh_ident)),
              now,
            );
          }
        }
        // The dispatch seam, time, and teardown noise.
        11 => match rng() % 3 {
          0 => {
            let _ = m.resignal_coverage_deficits(scopes[(rng() as usize) % scopes.len()]);
          }
          1 => m.handle_timeout(at(step + 1 + rng() % 300)),
          _ => {
            if !watches.is_empty() {
              let w = watches[(rng() as usize) % watches.len()];
              m.on_os_record(OsRecord::new(w, RecordKind::Ignored), now);
            }
          }
        },
        // A guarded arm whose pool was empty this step: skip.
        _ => {}
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
  assert!(
    settle_edges_checked > 0,
    "the storm reached post-loss settle edges (the invariant was exercised)"
  );
}

// ---------------------------------------------------------------------------
// The coverage-work epoch: one cell per `coverage_settled` conjunct.
//
// A holder of an ordering proof over a settled scope binds it to
// `coverage_work_epoch` instead of to a list of the events that could unsettle
// the scope. That binding is only as good as its coverage of the conjunction:
// a conjunct whose acquisition funnel does not advance the epoch lets the
// barrier go settled → unsettled → settled with the epoch unmoved, and a proof
// taken before that round would certify over the window it re-opened.
//
// So there is one cell per conjunct, each driving that conjunct alone into
// acquiring work and demanding the epoch move. They exist to FAIL when a
// further conjunct arrives instrumented by nobody: adding one means adding its
// cell here, and a conjunct whose cell cannot be written is a conjunct with no
// acquisition funnel to instrument.
// ---------------------------------------------------------------------------

/// The re-arm conjunct: a node entering a re-arm-flavored state is acquired
/// coverage work.
#[test]
fn a_rearm_obligation_advances_the_coverage_work_epoch() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  assert!(m.coverage_settled(s), "an idle root is settled");
  let before = m.coverage_work_epoch(s);

  assert!(m.rearm_watch_subtree(root).is_started());
  assert!(!m.rearm_settled(s), "the re-arm read is counted");
  assert!(
    m.coverage_work_epoch(s) > before,
    "so acquiring it moves the epoch"
  );

  // Releasing does not: the epoch counts acquisitions, so a scope that
  // quiesces holds it fixed and a proof taken over the quiescence survives.
  let read = read_of(&mut m, root);
  let held = m.coverage_work_epoch(s);
  m.on_enumerate(read, EnumerateResult::Ok(Vec::new()));
  assert!(m.coverage_settled(s), "the re-arm quiesced");
  assert_eq!(
    m.coverage_work_epoch(s),
    held,
    "and quiescing is not an acquisition"
  );
  m.assert_invariants();
}

/// The holds conjunct: a detached-and-held move source is acquired coverage
/// work — the conjunct `rearm_settled` deliberately does not count, and the one
/// the false-clean counterexample travels through.
#[test]
fn a_held_move_source_advances_the_coverage_work_epoch() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let _d = live_child_dir(&mut m, root, "d");
  assert!(m.coverage_settled(s));
  let before = m.coverage_work_epoch(s);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  assert!(m.rearm_settled(s), "a hold is not counted re-arm work");
  assert!(m.held_by_scope.contains_key(&s), "but it is a held source");
  assert!(
    m.coverage_work_epoch(s) > before,
    "which the epoch counts as acquired coverage work"
  );

  // The pairing releases the hold and leaves the epoch where it is — which is
  // exactly what makes a proof taken AFTER this round able to certify, and a
  // proof taken before it unable to.
  let held = m.coverage_work_epoch(s);
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(20),
  );
  assert!(m.coverage_settled(s), "the pairing releases the barrier");
  assert_eq!(
    m.coverage_work_epoch(s),
    held,
    "and a release is not an acquisition"
  );
  m.assert_invariants();
}

/// The latent conjunct: an in-flight COLD read that has just been dirtied with
/// a coalesced re-arm obligation is acquired coverage work, even though the
/// re-arm counter deliberately cannot see it.
#[test]
fn a_latent_cold_read_advances_the_coverage_work_epoch() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
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
  m.ack_watch(d, Ok(WatchAck::Installed));
  let _cold = read_of(&mut m, d);
  let _ = drain_events(&mut m);
  assert!(m.coverage_settled(s), "cold discovery holds nothing down");
  let before = m.coverage_work_epoch(s);

  // A located loss folds its re-arm into the in-flight cold read: `Coalesced`,
  // so the re-arm counter still reads settled and only the latent set holds.
  m.on_overflow(SubtreeScope::new(d).into(), at(2));
  assert!(m.rearm_settled(s), "the folded obligation is latent");
  assert!(!m.latent_settled(s), "the latent set is what holds");
  assert!(
    m.coverage_work_epoch(s) > before,
    "and the epoch counts it as acquired"
  );
  m.assert_invariants();
}

/// The adoptions conjunct: a widen's unverified same-transport adoption edge is
/// acquired coverage work. Its connecting arms and reads are deliberately cold,
/// so without this the barrier would have a conjunct nothing else accounts for.
#[test]
fn an_unverified_adoption_advances_the_coverage_work_epoch() {
  let mut m = per_dir();
  let s = scope(1);
  let (_old_root, _kid) = widen_base(&mut m, s);
  assert!(m.coverage_settled(s), "the old world is settled");
  let before = m.coverage_work_epoch(s);

  let reserved = m.reserve_watch_id();
  let _ = m.widen_root(s, reserved, vec![seg("b")], Some(ident(1)));
  assert!(
    m.adopting_by_scope.contains_key(&s),
    "the commit records the unverified edge"
  );
  assert!(
    m.coverage_work_epoch(s) > before,
    "which the epoch counts as acquired coverage work"
  );
  m.assert_invariants();
}

/// The moves conjunct: a parked rename half is acquired coverage work. Staged
/// on an ordinary FILE, which is the whole point — a file source takes no hold
/// and arms no read, so every other conjunct reads settled while the monitor
/// holds a transition it has consumed and not yet written. A barrier certifying
/// there would dispatch a sync cookie ahead of the `Removed` this half becomes.
#[test]
fn a_parked_rename_half_advances_the_coverage_work_epoch() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  assert!(m.coverage_settled(s), "an idle root is settled");
  let before = m.coverage_work_epoch(s);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("f.txt"))
      .with_cookie(cookie(1))
      .with_is_dir(false),
    at(10),
  );
  assert!(m.rearm_settled(s), "a file move-out arms no re-arm work");
  assert!(
    !m.held_by_scope.contains_key(&s),
    "and detaches no subtree to hold"
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "nothing is written until the half resolves"
  );
  assert!(
    !m.coverage_settled(s),
    "so the parked half alone must gate the fence"
  );
  assert!(
    m.coverage_work_epoch(s) > before,
    "which the epoch counts as acquired coverage work"
  );

  // The window elapses: the half becomes the `Removed` it was holding, the
  // barrier opens, and the epoch stays put — a proof taken after this round
  // certifies, one taken before it cannot.
  let held = m.coverage_work_epoch(s);
  m.handle_timeout(at(10) + DEFAULT_MOVE_WINDOW);
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_removed() && e.location() == &loc(&["f.txt"])),
    "the stranded source resolves into its removal: {events:?}"
  );
  assert!(m.coverage_settled(s), "the resolution releases the gate");
  assert_eq!(
    m.coverage_work_epoch(s),
    held,
    "and a release is not an acquisition"
  );
  m.assert_invariants();
}

/// A root registered with a narrow delivery interest, brought live and past its
/// bootstrap read — the precondition for every admission witness.
fn live_root_idle_with(m: &mut Monitor, s: ScopeId, mask: Interest) -> WatchId {
  let _ = drain_actions(m);
  let root = m.register_root(s, mask).expect("a fresh scope registers");
  let _ = drain_actions(m);
  m.ack_watch(root, Ok(WatchAck::Installed));
  let boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(Vec::new()));
  let _ = drain_actions(m);
  let _ = drain_events(m);
  root
}

/// One native mask that proves a create AND an attribute change admits BOTH
/// subscriptions. Collapsing the mask to its winning verb would deliver only to
/// the create subscriber and leave the attrib one with nothing — no change and
/// no covering `Rescan`.
#[test]
fn a_mask_proving_two_facts_admits_both_interests() {
  let proof = Evidence::new().with_created().with_attrib();

  let mut attrib_only = per_dir();
  let root = live_root_idle_with(&mut attrib_only, scope(1), Interest::new().with_attrib());
  attrib_only.on_os_record(
    OsRecord::proved(root, proof)
      .expect("a create fact names a verb")
      .with_name(seg("f")),
    at(1),
  );
  let events = drain_events(&mut attrib_only);
  assert_eq!(events.len(), 1, "{events:?}");
  assert_eq!(events[0].location(), &loc(&["f"]));

  let mut created_only = per_dir();
  let root = live_root_idle_with(&mut created_only, scope(1), Interest::new().with_created());
  created_only.on_os_record(
    OsRecord::proved(root, proof)
      .expect("a create fact names a verb")
      .with_name(seg("f")),
    at(1),
  );
  let events = drain_events(&mut created_only);
  assert_eq!(events.len(), 1, "{events:?}");
  assert!(events[0].kind().is_created());

  // The narrowing is still exact where nothing was proven: a create-only mask
  // reaches no attrib subscriber.
  let mut attrib_only = per_dir();
  let root = live_root_idle_with(&mut attrib_only, scope(1), Interest::new().with_attrib());
  attrib_only.on_os_record(
    OsRecord::new(root, RecordKind::Created).with_name(seg("g")),
    at(1),
  );
  assert!(drain_events(&mut attrib_only).is_empty());
}

/// The same admission, for the two records whose consumer kinds already
/// coincide: an `Attrib` record must not reach a `modified`-only subscription
/// unless it ALSO proved a content change, and vice versa.
#[test]
fn modified_and_attrib_records_admit_on_what_they_proved() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_modified());
  m.on_os_record(
    OsRecord::new(root, RecordKind::Attrib).with_name(seg("a")),
    at(1),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "a pure metadata record is not a content change"
  );

  m.on_os_record(
    OsRecord::proved(root, Evidence::new().with_modified().with_attrib())
      .expect("a content fact names a verb")
      .with_name(seg("b")),
    at(2),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "{events:?}");
  assert!(events[0].kind().is_modified());
}

/// An unpairable rename half reaches a `moved`-only subscriber. Every degrade
/// path is covered: an immediate cookie-less source and destination, and a
/// cookied source whose pairing window elapses.
#[test]
fn an_unpairable_rename_half_reaches_a_moved_only_subscriber() {
  let mut m = per_dir();
  let root = live_root_idle_with(&mut m, scope(1), Interest::new().with_moved());

  // A cookie-less source degrades to a `Removed` — admitted on the move it is.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom).with_name(seg("gone")),
    at(1),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "{events:?}");
  assert_eq!(events[0].location(), &loc(&["gone"]));

  // A cookie-less destination degrades to a `Created`.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo).with_name(seg("arrived")),
    at(2),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "{events:?}");
  assert_eq!(events[0].location(), &loc(&["arrived"]));

  // A cookied source whose window elapses strands into a `Removed`, resolved
  // long after the record itself is gone — so the half must carry its own facts.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("stranded"))
      .with_cookie(cookie(1)),
    at(3),
  );
  assert!(drain_events(&mut m).is_empty(), "the half is still parked");
  m.handle_timeout(at(3) + DEFAULT_MOVE_WINDOW + Duration::from_millis(1));
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "{events:?}");
  assert_eq!(events[0].location(), &loc(&["stranded"]));
}

/// A listing that cannot classify a real directory does not blind its subtree:
/// the slot is booked dark and stat'd, and the answer arms the watch and
/// descends. Reading `Unknown` as a non-directory would leave the subtree
/// permanently unwatched, with no deficit and no `Rescan` to say so.
#[test]
fn an_unknown_kind_directory_is_resolved_by_its_stat() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root(&mut m, s);
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("d"), FileKind::Unknown)]),
  );
  let _ = drain_events(&mut m);

  let req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("an unclassifiable slot is asked about");
  assert!(
    m.has_coverage_deficit(s),
    "and stands as darkness until it answers"
  );

  m.on_stat_result(
    req,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(1))),
  );
  let actions = drain_actions(&mut m);
  let armed = actions
    .iter()
    .find_map(|a| a.as_watch())
    .expect("the resolved directory is watched");
  assert_eq!(armed.target(), &WatchTarget::child(root, seg("d")));
  assert!(!m.has_coverage_deficit(s), "the darkness is discharged");

  // And the watch really descends: its arm is answered by a read of the subtree.
  let child = armed.id();
  m.ack_watch(child, Ok(WatchAck::Installed));
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_enumerate().map(|e| e.dir()) == Some(child)),
    "the subtree is enumerated, not blind"
  );
}

/// A stat that settles nothing — a failure, or a kind that is `Unknown` again —
/// leaves the deficit standing behind a covering `Rescan`, and never re-asks: an
/// unclassifiable slot must degrade to loud darkness, not to a loop.
#[test]
fn an_unresolvable_stat_stands_the_deficit_and_does_not_re_ask() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root(&mut m, s);
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("d"), FileKind::Unknown)]),
  );
  let _ = drain_events(&mut m);
  let req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("an unclassifiable slot is asked about");

  m.on_stat_result(req, StatResult::Failed(IoClass::Permission));
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["d"])),
    "{events:?}"
  );
  assert!(m.has_coverage_deficit(s), "the darkness still stands");
  let actions = drain_actions(&mut m);
  assert!(
    !actions.iter().any(Action::is_stat),
    "no re-ask: {actions:?}"
  );
  let _ = root;
}

/// A slot the stat cannot find is the benign race — the entry vanished between
/// the listing and the stat — so it settles as empty rather than standing dark.
#[test]
fn a_vanished_unknown_slot_settles_empty() {
  let mut m = per_dir();
  let s = scope(1);
  let _ = live_root(&mut m, s);
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("d"), FileKind::Unknown)]),
  );
  let _ = drain_events(&mut m);
  let req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("an unclassifiable slot is asked about");
  assert!(m.has_coverage_deficit(s));

  m.on_stat_result(req, StatResult::Failed(IoClass::NotFound));
  assert!(!m.has_coverage_deficit(s), "a vanished slot settles empty");
}

/// A late `Err` from a SUPERSEDED arm attempt does not invalidate the current
/// owner of that `WatchId`. Without the attempt token the outcome names only the
/// handle, and a dead transport's synthesized failure tears down the live
/// rebound root it never touched.
#[test]
fn a_superseded_arm_failure_does_not_invalidate_the_current_binding() {
  let mut m = per_dir();
  let s = scope(1);
  let _ = drain_actions(&mut m);
  let root = m
    .register_root(s, Interest::all())
    .expect("a fresh scope registers");
  let stale = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().filter(|c| c.id() == root).map(|c| c.attempt()))
    .expect("the root's bootstrap arm");
  m.ack_watch(root, Ok(WatchAck::Installed));
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(boot, EnumerateResult::Ok(Vec::new()));
  let _ = drain_events(&mut m);

  // The root rebinds onto a new transport, keeping its handle.
  let (rebound, fresh) = m.rebind_root(s).expect("a descending root rebinds");
  assert_eq!(rebound, root);
  assert_ne!(fresh, stale);
  let _ = drain_events(&mut m);

  // The retired transport's failure lands late, naming the arm it answered.
  m.on_watch_result(root, stale, Err(WatchError::Gone));
  assert!(
    m.is_watched(root),
    "the rebound root survives its predecessor"
  );
  assert_eq!(m.scope_of(root), Some(s));
  let events = drain_events(&mut m);
  assert!(events.is_empty(), "and nothing is signalled: {events:?}");

  // The arm that actually owns the handle still completes.
  m.on_watch_result(root, fresh, Ok(WatchAck::Installed));
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_enumerate().map(|e| e.dir()) == Some(root)),
    "the current attempt drives the rebuild"
  );
}

/// A re-arm read that cannot classify an ALREADY-WATCHED name must neither
/// prune it (absence from the directory index is ignorance, not a vanish) nor
/// book darkness over it (the incumbent watch is live coverage). It stats, and
/// a confirming answer leaves the subtree exactly as it was.
#[test]
fn an_unclassifiable_name_over_a_live_watch_keeps_it_and_books_nothing() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root(&mut m, s);
  let boot = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("root bootstrap enumerate");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("d"), FileKind::Dir).with_node(ident(1)),
    ]),
  );
  let child = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|c| c.id()))
    .expect("the directory is armed");
  m.ack_watch(child, Ok(WatchAck::Installed));
  let cold = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the armed child cold-enumerates");
  m.on_enumerate(cold, EnumerateResult::Ok(Vec::new()));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // A re-arm whose listing cannot name the watched directory.
  assert!(m.rearm_watch_subtree(root).is_started());
  let req = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the re-arm reads the root");
  m.on_enumerate(
    req,
    EnumerateResult::Ok(vec![DirEntry::new(seg("d"), FileKind::Unknown)]),
  );

  assert!(m.is_watched(child), "the incumbent watch is not pruned");
  assert!(
    !m.has_coverage_deficit(s),
    "and a covered slot is not booked dark"
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable name is still asked about");

  // Confirming it changes nothing: same identity, same watch, no rebuild.
  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(1))),
  );
  assert!(m.is_watched(child));
  assert!(!m.has_coverage_deficit(s));
  m.assert_invariants();
}

// ---------------------------------------------------------------------------
// The retirement flavor a crawl DEFERS: a name whose listed kind is unknown.
// The crawl may neither prune such a name (ignorance is not a vanish) nor
// decide it, so it skips the entry — which leaves BOTH halves of what it owes
// the incumbent riding on the slot's stat: the survivor's downward descent, and
// the cover a retirement of proven-live coverage owes. These cells pin each
// answer's half.
// ---------------------------------------------------------------------------

/// Builds the deferral every cell below turns on: a settled `root/p/g` under a
/// `Modified`-only subscription, then a PURE grow (no overflow, no loss, no
/// incomplete read — nothing has stood a `Rescan`, so the window opens clean)
/// whose COMPLETE listing cannot classify `p`. Returns the outstanding stat.
fn deferred_unknown_slot(m: &mut Monitor, s: ScopeId) -> (WatchId, WatchId, WatchId, ReqId) {
  let root = live_root_idle_with(m, s, Interest::new().with_modified());
  let p = live_child_dir_ident(m, root, "p", ident(7));
  let g = live_child_dir_ident(m, p, "g", ident(8));
  assert!(m.coverage_settled(s), "the grow starts from quiescence");

  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("p"), FileKind::Unknown)]),
  );

  assert!(m.is_watched(p), "the unclassifiable name keeps its watch");
  assert!(
    !m.has_coverage_deficit(s),
    "and a covered slot is not booked dark"
  );
  assert!(
    drain_events(m).is_empty(),
    "the crawl retires nothing here, so it covers nothing"
  );
  assert!(
    m.coverage_settled(s),
    "and the deferral leaves NOTHING counted — what the answer does to `p` is \
     all that stands between the retirement and a clean verdict"
  );
  let stat = drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_stat()
        .filter(|c| c.of() == &StatTarget::child(root, seg("p")))
        .map(|c| c.req())
    })
    .expect("the unclassifiable name is asked about");
  (root, p, g, stat)
}

/// The descent a confirmed survivor is owed (fail-on-old). The crawl skipped
/// `p` before either re-arm branch could run, so the recursive re-arm it owed
/// that subtree exists only if the stat's confirmation performs it. On old the
/// confirmation reused the incumbent and returned: no read of `p` was ever
/// issued, the scope read settled, and a directory created under `p` while the
/// slot was deferred stayed unwatched with nothing booked to say so.
#[test]
fn a_confirmed_survivor_receives_the_descent_the_crawl_deferred() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, p, g, stat) = deferred_unknown_slot(&mut m, s);

  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );
  assert!(m.is_watched(p), "the confirmed survivor keeps its watch");
  assert!(
    !m.rearm_settled(s),
    "and the deferred descent is counted work the barrier must now wait on"
  );
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == p).map(|e| e.req()))
    .expect("the survivor is re-armed downward");

  // The descent reaches the subtree: the directory created under `p` while the
  // slot was deferred is armed off this very read.
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("g"), FileKind::Dir).with_node(ident(8)),
      DirEntry::new(seg("n"), FileKind::Dir),
    ]),
  );
  let actions = drain_actions(&mut m);
  let n = actions
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("a directory created during the deferral is armed");
  let g_read = actions
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == g).map(|e| e.req()))
    .expect("and the confirmed grandchild re-arms downward too");
  m.on_enumerate(g_read, EnumerateResult::Ok(vec![]));
  assert!(m.is_watched(g), "the grandchild keeps its watch");

  // The record the backend had queued on that descendant still delivers: this
  // answer ended no coverage, so nothing was orphaned and nothing is covered.
  m.on_os_record(
    OsRecord::new(g, RecordKind::Modified).with_name(seg("f")),
    at(4),
  );
  let delivered = drain_events(&mut m);
  assert_eq!(delivered.len(), 1, "{delivered:?}");
  assert!(delivered[0].kind().is_modified());
  assert_eq!(delivered[0].location(), &loc(&["p", "g", "f"]));

  m.ack_watch(n, Ok(WatchAck::Installed));
  let n_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == n).map(|e| e.req()))
    .expect("the fresh directory reads");
  m.on_enumerate(n_read, EnumerateResult::Ok(vec![]));
  assert!(m.coverage_settled(s), "and the descent quiesces");
  m.assert_invariants();
}

/// A replacement answer (fail-on-old): the name holds a DIFFERENT directory, so
/// the incumbent's subtree is retired and its slot rebuilt. The retirement ends
/// coverage of an object that was there — every `WatchId` under `p` dies while
/// records naming them may already sit queued — so it owes the opening cover,
/// and the rebuild is made COUNTED so no barrier settles before the
/// acknowledgement chain closes the window. On old the replace ran through
/// `reconcile_slot` alone: the drop erased no deficit so it stood no bridge
/// bits, the fresh watch was born uncounted, and the whole retirement was
/// silent.
#[test]
fn a_stat_replacement_covers_and_counts_the_slot_it_rebuilds() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, p, g, stat) = deferred_unknown_slot(&mut m, s);

  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(9))),
  );
  assert!(!m.is_watched(p), "the replaced incumbent is retired");
  assert!(!m.is_watched(g), "and so is its descendant");
  assert!(
    !m.coverage_settled(s),
    "the rebuild is counted, so no barrier settles over the retirement"
  );
  let cover = drain_events(&mut m);
  assert_eq!(
    cover.len(),
    1,
    "the retirement stands its opening cover: {cover:?}"
  );
  assert!(cover[0].kind().is_rescan());
  assert_eq!(
    cover[0].location(),
    &loc(&["p"]),
    "located off the surviving parent"
  );

  // The record the backend had already queued on the retired descendant now
  // arrives and is discarded — the darkness the cover exists for.
  m.on_os_record(
    OsRecord::new(g, RecordKind::Modified).with_name(seg("f")),
    at(4),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the orphaned record delivers nothing of its own"
  );

  let fresh = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the successor arms");
  assert_ne!(fresh, p, "a rebuilt slot is a new watch");
  m.ack_watch(fresh, Ok(WatchAck::Installed));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == fresh)
        .map(|e| e.req())
    })
    .expect("the successor reads");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  assert!(m.coverage_settled(s));
  let closing = drain_events(&mut m);
  assert!(
    closing
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "and the counted rebuild closes the window it opened: {closing:?}"
  );
  m.assert_invariants();
}

/// A `File` answer (fail-on-old): the name is a proven non-directory, so the
/// incumbent is retired and NOTHING rebuilds its slot. There is no counted
/// successor to close a window, which makes the cover unconditional rather than
/// deferrable — and the barrier reads settled the instant the answer returns,
/// so the cover must already be on the wire at that same instant. On old this
/// path emitted nothing at all: `drop_subtree` covers only what it ERASED, and
/// a clean subtree erases nothing.
#[test]
fn a_stat_that_reports_a_file_covers_the_watch_it_retires() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, p, g, stat) = deferred_unknown_slot(&mut m, s);

  m.on_stat_result(stat, StatResult::Ok(StatEntry::new(FileKind::File)));
  assert!(
    !m.is_watched(p),
    "a proven non-directory retires the incumbent"
  );
  assert!(!m.is_watched(g), "and so is its descendant");
  assert!(
    drain_actions(&mut m).iter().all(|a| a.as_watch().is_none()),
    "and nothing re-installs over a proven non-directory"
  );
  assert!(
    m.coverage_settled(s),
    "an unrebuilt retirement leaves nothing counted to wait on"
  );
  let cover = drain_events(&mut m);
  assert_eq!(
    cover.len(),
    1,
    "so the cover must already be on the wire: {cover:?}"
  );
  assert!(cover[0].kind().is_rescan());
  assert_eq!(
    cover[0].location(),
    &loc(&["p"]),
    "located off the surviving parent"
  );

  m.on_os_record(
    OsRecord::new(g, RecordKind::Modified).with_name(seg("f")),
    at(4),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the orphaned record delivers nothing of its own"
  );
  m.assert_invariants();
}

/// A `NotFound` answer (fail-on-old): the benign race — the entry was gone
/// before the stat ran. The slot settles empty, and the retirement is still a
/// retirement: the object existed when the listing named it, records describing
/// it may already be queued against the `WatchId`s this drop invalidates, and
/// the vanish's own `Removed` is interest-subject (and may itself be one of the
/// orphaned records). No successor exists, so the cover is unconditional. On
/// old the vanish settled the slot in silence.
#[test]
fn a_vanished_stat_slot_covers_the_watch_it_retires() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, p, g, stat) = deferred_unknown_slot(&mut m, s);

  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));
  assert!(!m.is_watched(p), "the vanished slot retires the incumbent");
  assert!(!m.is_watched(g), "and so is its descendant");
  assert!(
    !m.has_coverage_deficit(s),
    "a vanished slot settles empty rather than dark"
  );
  assert!(
    m.coverage_settled(s),
    "an unrebuilt retirement leaves nothing counted to wait on"
  );
  let cover = drain_events(&mut m);
  assert_eq!(
    cover.len(),
    1,
    "so the cover must already be on the wire: {cover:?}"
  );
  assert!(cover[0].kind().is_rescan());
  assert_eq!(
    cover[0].location(),
    &loc(&["p"]),
    "located off the surviving parent"
  );

  m.on_os_record(
    OsRecord::new(g, RecordKind::Modified).with_name(seg("f")),
    at(4),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the orphaned record delivers nothing of its own"
  );
  m.assert_invariants();
}

/// The obligation is carried in the REQUEST, and a coalesced ask upgrades it.
/// One stat serves every read that re-encounters the name, so the answer must
/// honor the strongest deferral any of them made: a plain grow queues the stat,
/// a later loss recovery re-encounters the same unclassifiable name under a
/// REPROVE crawl, and the survivor must then be RE-ADDED — an identity match
/// proves only that the name still holds the object, never that our watch is
/// still its live binding. Fails on old (no descent at all is performed); fails
/// too if the obligation is written once and kept rather than raised.
#[test]
fn a_deferred_descent_upgrades_to_the_strongest_deferral() {
  let mut m = reproving();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let p = live_child_dir_ident(&mut m, root, "p", ident(7));

  // A plain grow defers first: the stat is queued owing a bare re-arm.
  assert!(m.rearm_watch_subtree(root).is_started());
  let grow = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    grow,
    EnumerateResult::Ok(vec![DirEntry::new(seg("p"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable name is asked about");

  // Then a loss recovery re-reads the same listing under a reproof. Its crawl
  // skips the name exactly as the first one did — and coalesces onto the stat
  // already outstanding, which must inherit the stronger obligation.
  m.on_overflow(Scope::Root(s), at(2));
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let recovery = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the acknowledged root re-arm-reads");
  m.on_enumerate(
    recovery,
    EnumerateResult::Ok(vec![DirEntry::new(seg("p"), FileKind::Unknown)]),
  );
  assert!(
    drain_actions(&mut m).iter().all(|a| !a.is_stat()),
    "one slot, one outstanding stat"
  );
  assert!(
    m.rearm_settled(s),
    "and the deferral itself leaves nothing counted"
  );

  // The answer confirms the same object — and the reproof, not the plain
  // re-arm, is what it owes: a re-add, not a bare read.
  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );
  assert!(m.is_watched(p), "the confirmed survivor keeps its watch");
  let actions = drain_actions(&mut m);
  assert_eq!(
    readd_of(&actions, p),
    Some(WatchTarget::child(root, seg("p"))),
    "the survivor's binding is re-proven, not merely re-read: {actions:?}"
  );
  assert!(
    !actions.iter().any(|a| a.is_enumerate()),
    "no read runs before the binding acknowledges: {actions:?}"
  );
  assert!(!m.rearm_settled(s), "the re-add is a counted obligation");
  m.assert_invariants();
}

/// The settlement is fenced to its own scope: a retirement in scope 1 puts
/// nothing on scope 2's wire, acquires no work scope 2's barrier must wait on,
/// and books no darkness there. The cover is located off the retired slot's own
/// parent, which belongs to exactly one disjoint root.
#[test]
fn a_stat_retirement_is_fenced_to_its_own_scope() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, _p, _g, stat) = deferred_unknown_slot(&mut m, s);
  let other = live_root_idle_with(&mut m, scope(2), Interest::new().with_modified());
  let q = live_child_dir_ident(&mut m, other, "q", ident(3));
  let epoch = m.coverage_work_epoch(scope(2));

  m.on_stat_result(stat, StatResult::Ok(StatEntry::new(FileKind::File)));

  let events = drain_events(&mut m);
  assert!(
    events.iter().all(|e| e.scope() == s),
    "the cover belongs to the retiring scope alone: {events:?}"
  );
  assert!(m.is_watched(q), "the other scope keeps its coverage");
  assert!(
    m.coverage_settled(scope(2)),
    "and its barrier is untouched by scope 1's retirement"
  );
  assert_eq!(
    m.coverage_work_epoch(scope(2)),
    epoch,
    "no coverage work was acquired for it"
  );
  assert!(!m.has_coverage_deficit(scope(2)));
  m.assert_invariants();
}

/// The cover condition's SHAPE, pinned. Written as a list of the retirement
/// flavors that owe a cover, an entry kind nobody enumerated sets no flag and
/// defaults to SILENCE — which is precisely how each successive flavor escaped.
/// It is written the other way round: every retirement owes the cover, and only
/// one whose counted successor the crawl PROVES may defer to the window's
/// closing `Rescan`. Here a name is retired under a kind the crawl names
/// nowhere (neither the directory index nor any branch mentions it) inside an
/// already-lossy window — the one place a default-silent gate would suppress
/// the cover outright.
#[test]
fn a_retirement_under_an_unenumerated_kind_still_covers() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle_with(&mut m, s, Interest::new().with_modified());
  let p = live_child_dir(&mut m, root, "p");
  let g = live_child_dir(&mut m, p, "g");

  // The overflow stands the window's opening loss and kicks the crawl, so the
  // window is ALREADY lossy when the retirement lands.
  m.on_overflow(Scope::Root(s), at(2));
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "the overflow marks the window lossy"
  );
  let rearm = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the recovery re-arm-enumerates the root");

  // The name is still listed — as neither a directory, nor a file, nor an
  // unclassifiable kind. Nothing rebuilds it, so nothing counted will ever
  // close this window on its behalf.
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("p"), FileKind::Other)]),
  );
  assert!(!m.is_watched(p), "the retirement happens whatever the kind");
  assert!(!m.is_watched(g), "and so does its descendant's");
  assert!(
    drain_actions(&mut m).iter().all(|a| a.as_watch().is_none()),
    "and nothing re-installs"
  );
  let cover = drain_events(&mut m);
  assert_eq!(
    cover.len(),
    1,
    "an unenumerated kind defaults to covering, never to silence: {cover:?}"
  );
  assert!(cover[0].kind().is_rescan());
  assert_eq!(
    cover[0].location(),
    &Location::new(),
    "located at the crawled directory"
  );

  m.on_os_record(
    OsRecord::new(g, RecordKind::Modified).with_name(seg("f")),
    at(4),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the orphaned record delivers nothing of its own"
  );
  m.assert_invariants();
}

// ---------------------------------------------------------------------------
// WHO the deferred descent belongs to. A stat is addressed to a SLOT — a
// `(parent, name)` coordinate — and a rename invalidates that coordinate while
// the object it named lives on: the source leaves the slot with its subtree
// intact, so the answer finds no incumbent and settles the obligation against
// nothing. The obligation belongs to the WATCH, which a reparent preserves, not
// to the slot, which a reparent empties. These cells pin that it survives the
// rename in either completion order and in either flavor, and that a hold which
// never pairs covers rather than forgets.
// ---------------------------------------------------------------------------

/// A reproof deferral primed to be raced by a rename: a settled `root/p/g` on a
/// lossy-watch-teardown profile with a scope loss on record, whose recovery
/// crawl could not classify `p` — so `p` keeps its (unproven) binding, the
/// reproof it is owed rides on the slot's outstanding stat, and the scope is
/// quiescent again.
fn deferred_reprove_of_a_survivor(
  m: &mut Monitor,
  s: ScopeId,
) -> (WatchId, WatchId, WatchId, ReqId) {
  let root = live_root_idle(m, s);
  let p = live_child_dir_ident(m, root, "p", ident(7));
  let g = live_child_dir_ident(m, p, "g", ident(8));

  m.on_overflow(Scope::Root(s), at(1));
  let _ = drain_events(m);
  let _ = drain_actions(m);
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let recovery = drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the acknowledged root re-arm-reads");
  m.on_enumerate(
    recovery,
    EnumerateResult::Ok(vec![DirEntry::new(seg("p"), FileKind::Unknown)]),
  );

  let stat = drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_stat()
        .filter(|c| c.of() == &StatTarget::child(root, seg("p")))
        .map(|c| c.req())
    })
    .expect("the unclassifiable name is asked about");
  let _ = drain_events(m);
  assert!(m.is_watched(p), "the unclassifiable name keeps its watch");
  assert!(
    readd_of(&drain_actions(m), p).is_none(),
    "and the crawl skipped it, so its binding is still unproven"
  );
  assert!(
    m.coverage_settled(s),
    "the deferral itself leaves NOTHING counted — which is exactly why the \
     rename below is not born dirty"
  );
  (root, p, g, stat)
}

/// The rename that empties the slot the stat is addressed to, with the answer
/// landing FIRST (fail-on-old). The source leaves `(root, p)` while its stat is
/// still outstanding, so the `NotFound` reply finds no incumbent and — keyed to
/// the coordinate — settles the deferred reproof against nothing. The pairing
/// destination then carries the subtree over in O(1) with the hold undirtied,
/// so on old NOTHING re-added it: a kernel-dead binding reached `Live` under a
/// scope whose every barrier read settled.
#[test]
fn a_deferred_reprove_follows_the_source_out_of_the_slot_it_was_keyed_to() {
  let mut m = reproving();
  let s = scope(1);
  let (root, p, g, stat) = deferred_reprove_of_a_survivor(&mut m, s);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("p"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  assert!(m.is_watched(p), "the source is detached, not torn down");

  // The answer for a slot the source has left: it decides the empty slot, and
  // the obligation it carried is not the empty slot's to settle.
  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));
  assert!(
    m.is_watched(p),
    "the held subtree is untouched by the answer"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("q"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  let actions = drain_actions(&mut m);
  assert_eq!(
    readd_of(&actions, p),
    Some(WatchTarget::child(root, seg("q"))),
    "the reparented source's binding is re-proven at its NEW slot: {actions:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and the barrier holds until that re-add completes"
  );

  // The reproof descends through the carried subtree exactly as it would have
  // from the slot: the acknowledged re-add reads, and the retained grandchild
  // is re-added rather than merely re-listed.
  m.ack_watch(p, Ok(WatchAck::Aliased));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == p).map(|e| e.req()))
    .expect("the re-proven source reads");
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("g"), FileKind::Dir).with_node(ident(8)),
    ]),
  );
  let actions = drain_actions(&mut m);
  assert_eq!(
    readd_of(&actions, g),
    Some(WatchTarget::child(p, seg("g"))),
    "the retained grandchild's binding is re-proven too: {actions:?}"
  );
  assert!(!m.coverage_settled(s), "the chain is still counted");

  m.ack_watch(g, Ok(WatchAck::Aliased));
  let g_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == g).map(|e| e.req()))
    .expect("the re-proven grandchild reads");
  m.on_enumerate(g_read, EnumerateResult::Ok(vec![]));
  assert!(
    m.coverage_settled(s),
    "and only a completed proof chain settles the barrier"
  );
  m.assert_invariants();
}

/// The same race with the PAIR completing first (fail-on-old). Here the
/// reparent has already happened when the answer lands, so no site downstream of
/// it could still consult the stat: the obligation must already be riding on the
/// identity the reparent carried, or it is gone. Pins that the fix is not a
/// special case of one interleaving.
#[test]
fn a_deferred_reprove_survives_a_rename_that_completes_before_the_answer() {
  let mut m = reproving();
  let s = scope(1);
  let (root, p, _g, stat) = deferred_reprove_of_a_survivor(&mut m, s);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("p"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("q"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  let actions = drain_actions(&mut m);
  assert_eq!(
    readd_of(&actions, p),
    Some(WatchTarget::child(root, seg("q"))),
    "the reparent discharges the obligation the moved watch carried: {actions:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and the barrier holds until that re-add completes"
  );

  // The late answer decides only the vacated slot. It must not re-arm, re-add
  // or otherwise speak for the subtree that left it.
  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));
  let late = drain_actions(&mut m);
  assert!(
    readd_of(&late, p).is_none(),
    "the vacated slot's answer owes the departed subtree nothing: {late:?}"
  );
  assert!(m.is_watched(p), "and retires nothing it does not hold");
  m.assert_invariants();
}

/// The plain re-arm flavor. A pure grow on a profile that re-proves nothing
/// defers a bare downward re-arm, and it is owed to the survivor just as much:
/// without it a directory created under the moved subtree during the deferral
/// stays unwatched with nothing booked to say so. On old the rename dropped it
/// exactly as it dropped the reproof.
#[test]
fn a_deferred_rearm_follows_the_source_a_rename_moved_out_of_its_slot() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let p = live_child_dir_ident(&mut m, root, "p", ident(7));

  assert!(m.rearm_watch_subtree(root).is_started());
  let grow = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the grow re-arm-enumerates the root");
  m.on_enumerate(
    grow,
    EnumerateResult::Ok(vec![DirEntry::new(seg("p"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable name is asked about");
  assert!(m.coverage_settled(s), "the deferral leaves nothing counted");

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("p"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(2),
  );
  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("q"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(3),
  );

  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == p).map(|e| e.req()))
    .expect("the reparented source is re-armed downward");
  assert!(
    !m.rearm_settled(s),
    "and that descent is counted work the barrier must wait on"
  );

  // The descent reaches the subtree: a directory created under the source while
  // the slot was deferred is armed off this very read.
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("n"), FileKind::Dir)]),
  );
  let n = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("a directory created during the deferral is armed");
  m.ack_watch(n, Ok(WatchAck::Installed));
  let n_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == n).map(|e| e.req()))
    .expect("the fresh directory reads");
  m.on_enumerate(n_read, EnumerateResult::Ok(vec![]));
  assert!(m.coverage_settled(s), "and the descent quiesces");
  m.assert_invariants();
}

/// The hold that never pairs, so the obligation has nowhere to go (fail-on-old).
/// The timeout tears the held subtree down, which discharges the descent by
/// destroying what owed it — but the only signal it stands on its own is the
/// stranded source's `Removed`, which is interest- and filter-subject, and the
/// scope reads settled the instant the half leaves the store. An obligation that
/// cannot be transferred resolves toward a COUNTED cover, never toward silence.
#[test]
fn a_deferred_descent_a_hold_cannot_carry_stands_a_counted_cover() {
  let mut m = reproving();
  let s = scope(1);
  let (root, p, _g, stat) = deferred_reprove_of_a_survivor(&mut m, s);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("p"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));
  let _ = drain_events(&mut m);

  m.handle_timeout(at(2) + DEFAULT_MOVE_WINDOW);
  assert!(!m.is_watched(p), "the unpaired hold tears its subtree down");
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &Location::new()),
    "the undischarged obligation stands its cover: {events:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and it is COUNTED — a bare edge `Rescan` the next poll certifies over \
     would leave the window nothing to wait on"
  );

  let recover = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the counted cover re-crawls the root");
  m.on_enumerate(recover, EnumerateResult::Ok(vec![]));
  assert!(m.coverage_settled(s), "and the recovery settles it");
  m.assert_invariants();
}

/// Creates and arms a watched child directory under `parent`, returning its watch.
fn armed_child_dir(m: &mut Monitor, parent: WatchId, name: &str, when: Instant) -> WatchId {
  m.on_os_record(
    OsRecord::new(parent, RecordKind::Created)
      .with_name(seg(name))
      .with_is_dir(true),
    when,
  );
  let w = drain_actions(m)
    .iter()
    .find_map(|a| a.as_watch().map(|c| c.id()))
    .expect("the created directory is armed");
  m.ack_watch(w, Ok(WatchAck::Installed));
  let _ = drain_actions(m);
  let _ = drain_events(m);
  w
}

/// The reported slot names where the subtree WAS: the capture happens before the
/// re-key, so it is still the key a consumer's own path-anchored bookkeeping holds
/// when the report reaches it.
#[test]
fn record_outcome_reports_a_landed_directory_reparent() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let w_d = armed_child_dir(&mut m, root, "d", at(1));

  let parked = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  assert_eq!(
    parked,
    RecordOutcome::Nothing,
    "parking a half moves no subtree"
  );

  let outcome = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );

  assert_eq!(
    outcome,
    RecordOutcome::Reparented {
      from_parent: root,
      from: loc(&["d"]),
    },
    "the destination reports the pre-reparent slot"
  );
  assert!(!outcome.is_nothing());
  assert_eq!(outcome.reparented(), Some((root, &loc(&["d"]))));
  // The report is of a reparent that genuinely happened: the same watch covers the
  // destination, and it reconstructs the NEW path.
  assert!(m.is_watched(w_d), "the subtree was carried, not rebuilt");
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created).with_name(seg("f")),
    at(12),
  );
  assert!(
    drain_events(&mut m)
      .iter()
      .any(|e| e.location() == &loc(&["e", "f"]))
  );
  m.assert_invariants();
}

/// The slot is a `(from_parent, from)` pair reconstructed at report time, not a path
/// pinned when the source half was parked: a half whose own anchor was reparented
/// mid-window reports where the source ACTUALLY was. This is the skew a mirror kept
/// beside the Monitor cannot avoid and a reported outcome cannot have.
#[test]
fn record_outcome_reparent_slot_follows_a_reparented_anchor() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let w_d = armed_child_dir(&mut m, root, "d", at(1));
  let w_g = armed_child_dir(&mut m, w_d, "g", at(2));

  // An inner half parks under w_d, anchored at d/g.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::MovedFrom)
      .with_name(seg("g"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(10),
  );
  // Its anchor is then itself renamed d → e, carried by the tree.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );
  let outer = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  assert_eq!(
    outer,
    RecordOutcome::Reparented {
      from_parent: root,
      from: loc(&["d"]),
    }
  );
  let _ = drain_events(&mut m);

  // The inner half now pairs. Its source is e/g — reconstructed through the anchor
  // that moved — never the stale d/g the parking record described.
  let inner = m.on_os_record(
    OsRecord::new(w_d, RecordKind::MovedTo)
      .with_name(seg("g2"))
      .with_cookie(cookie(2))
      .with_is_dir(true),
    at(13),
  );
  assert_eq!(
    inner,
    RecordOutcome::Reparented {
      from_parent: w_d,
      from: loc(&["e", "g"]),
    },
    "the reported source follows the anchor's own reparent"
  );
  assert!(m.is_watched(w_g));
  // And the delivered change agrees with the report.
  assert!(drain_events(&mut m).iter().any(
    |e| e.kind().moved_from() == Some(&loc(&["e", "g"])) && e.location() == &loc(&["e", "g2"])
  ));
  m.assert_invariants();
}

/// Past its pairing window the half strands and the arrival is a fresh object: no
/// subtree is carried anywhere, so nothing is reported.
#[test]
fn record_outcome_is_nothing_past_the_pairing_window() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let w_d = armed_child_dir(&mut m, root, "d", at(1));

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  // Exactly at the deadline the half is already expired (the window is half-open).
  let outcome = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10) + DEFAULT_MOVE_WINDOW,
  );

  assert_eq!(outcome, RecordOutcome::Nothing);
  assert!(!m.is_watched(w_d), "the stranded source was torn down");
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_moved()),
    "a late destination is a Created, not a Moved"
  );
  m.assert_invariants();
}

/// A paired, in-window rename of a NON-directory emits a `Moved` and reparents
/// nothing. The delivered change and the reported outcome are different questions,
/// and only the second one answers "did a watched subtree change parents".
#[test]
fn record_outcome_is_nothing_for_an_unheld_file_source() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("old"))
      .with_cookie(cookie(7)),
    at(10),
  );
  let outcome = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("new"))
      .with_cookie(cookie(7)),
    at(11),
  );

  assert_eq!(outcome, RecordOutcome::Nothing);
  assert!(outcome.is_nothing() && outcome.reparented().is_none());
  let events = drain_events(&mut m);
  assert!(
    events.iter().any(|e| e.kind().is_moved()),
    "the rename is still delivered"
  );
  m.assert_invariants();
}

/// A directory whose watch was REFUSED holds no subtree to carry: the pair still
/// delivers a `Moved` and arms fresh coverage at the destination, but the Monitor
/// reparented nothing and says so.
#[test]
fn record_outcome_is_nothing_for_an_unarmed_directory_source() {
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
  m.ack_watch(w_d, Err(WatchError::Gone));
  assert!(!m.is_watched(w_d), "the arm was refused");
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  let outcome = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );

  assert_eq!(outcome, RecordOutcome::Nothing);
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("e")))),
    "the destination is armed fresh, not carried"
  );
  m.assert_invariants();
}

/// A cookieless move half can never pair, so neither half can reparent anything.
#[test]
fn record_outcome_is_nothing_for_a_cookieless_move() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let w_d = armed_child_dir(&mut m, root, "d", at(1));

  let from = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_is_dir(true),
    at(10),
  );
  assert_eq!(from, RecordOutcome::Nothing);
  assert!(
    !m.is_watched(w_d),
    "an unpairable source is torn down at once"
  );

  let to = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_is_dir(true),
    at(11),
  );
  assert_eq!(to, RecordOutcome::Nothing);
  m.assert_invariants();
}

/// A half displaced off its key by a same-cookie successor is resolved, not parked:
/// its own destination arrives to find nothing to pair with, reparents nothing, and
/// reports nothing — while the successor that DID pair reports its own slot.
#[test]
fn record_outcome_is_nothing_for_a_displaced_pending_half() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let w_d1 = armed_child_dir(&mut m, root, "d1", at(1));
  let _w_d2 = armed_child_dir(&mut m, root, "d2", at(2));

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d1"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(10),
  );
  // A second source on the SAME (scope, cookie) displaces the first, which resolves.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d2"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(11),
  );
  assert!(!m.is_watched(w_d1), "the displaced half resolved");
  let _ = drain_events(&mut m);

  let paired = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  assert_eq!(
    paired,
    RecordOutcome::Reparented {
      from_parent: root,
      from: loc(&["d2"]),
    },
    "the surviving half reports its own slot, never the displaced one's"
  );

  // The displaced half's own destination: the key is empty, so this is a fresh
  // arrival that carries no subtree.
  let orphan = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("f"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(13),
  );
  assert_eq!(orphan, RecordOutcome::Nothing);
  m.assert_invariants();
}

/// A half whose `from_parent` was torn down mid-window has no source path left to
/// report: the pair degrades to a `Created` and the outcome to `Nothing`, so a
/// consumer never re-anchors off a path that no longer names anything.
#[test]
fn record_outcome_is_nothing_when_the_source_parent_died() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let w_p = armed_child_dir(&mut m, root, "p", at(1));
  let w_d = armed_child_dir(&mut m, w_p, "d", at(2));

  m.on_os_record(
    OsRecord::new(w_p, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(8))
      .with_is_dir(true),
    at(10),
  );
  // The anchor is torn down before the destination arrives; the held source goes
  // with it through the parent link.
  m.on_os_record(OsRecord::new(w_p, RecordKind::Ignored), at(11));
  assert!(!m.is_watched(w_d));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  let outcome = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("g"))
      .with_cookie(cookie(8))
      .with_is_dir(true),
    at(12),
  );

  assert_eq!(outcome, RecordOutcome::Nothing);
  assert!(
    drain_events(&mut m).iter().all(|e| !e.kind().is_moved()),
    "a rename off a dead anchor is a Created"
  );
  m.assert_invariants();
}

/// A destination inside the source's own subtree is a cycle: `can_reparent` refuses,
/// the held subtree is torn down, and the record reports `Nothing` — the Monitor
/// intended a reparent and performed none.
#[test]
fn record_outcome_is_nothing_when_a_cyclic_reparent_is_rejected() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let w_d = armed_child_dir(&mut m, root, "d", at(1));
  let w_sub = armed_child_dir(&mut m, w_d, "sub", at(2));

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(9))
      .with_is_dir(true),
    at(10),
  );
  let outcome = m.on_os_record(
    OsRecord::new(w_sub, RecordKind::MovedTo)
      .with_name(seg("d"))
      .with_cookie(cookie(9))
      .with_is_dir(true),
    at(11),
  );

  assert_eq!(outcome, RecordOutcome::Nothing);
  assert!(!m.is_watched(w_d) && !m.is_watched(w_sub));
  m.assert_invariants();
}

/// The sliver a read-only accessor cannot see. Every conjunct of the reparenting
/// precondition holds — the half is paired, in-window, held, and its `from_parent`
/// is still watched — and `can_reparent` agrees; the re-key still ABORTS, because
/// dropping the stale object at the destination (the source's own parent) takes the
/// held source with it. A consumer that re-anchored on the precondition alone would
/// move its bookkeeping to a destination the Monitor covers with a FRESH watch. The
/// outcome is `Nothing`, so it does not.
#[test]
fn record_outcome_is_nothing_when_the_reparent_aborts_on_a_dead_endpoint() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let w_a = armed_child_dir(&mut m, root, "a", at(1));
  let w_d = armed_child_dir(&mut m, w_a, "d", at(2));

  // a/d moves onto "a" itself: the destination parent (root) survives, so the
  // precondition is fully satisfied when it is evaluated.
  m.on_os_record(
    OsRecord::new(w_a, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(3))
      .with_is_dir(true),
    at(10),
  );
  let outcome = m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("a"))
      .with_cookie(cookie(3))
      .with_is_dir(true),
    at(11),
  );

  assert_eq!(outcome, RecordOutcome::Nothing);
  assert!(!m.is_watched(w_a), "the replaced ancestor is dropped");
  assert!(!m.is_watched(w_d), "and the held source went with it");
  assert!(
    drain_actions(&mut m)
      .iter()
      .any(|a| { a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(root, seg("a"))) }),
    "root/a is covered by a FRESH watch, not the carried one"
  );
  m.assert_invariants();
}

/// Only a `MovedTo` can carry a subtree between parents, so it is the only kind with
/// an outcome to report; everything else is `Nothing` by construction.
#[test]
fn record_outcome_is_nothing_for_every_non_moved_to_record() {
  let mut m = per_dir();
  let root = live_root(&mut m, scope(1));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  let w_c1 = armed_child_dir(&mut m, root, "c1", at(1));
  let w_c2 = armed_child_dir(&mut m, root, "c2", at(2));
  let w_c3 = armed_child_dir(&mut m, root, "c3", at(3));

  for kind in [
    RecordKind::Created,
    RecordKind::Modified,
    RecordKind::Attrib,
    RecordKind::Removed,
  ] {
    assert_eq!(
      m.on_os_record(OsRecord::new(root, kind).with_name(seg("f")), at(10)),
      RecordOutcome::Nothing,
      "{kind:?} reparents nothing"
    );
  }
  assert_eq!(
    m.on_os_record(
      OsRecord::new(root, RecordKind::MovedFrom)
        .with_name(seg("c1"))
        .with_cookie(cookie(4))
        .with_is_dir(true),
      at(11),
    ),
    RecordOutcome::Nothing,
    "parking a source half reparents nothing"
  );
  for (watch, kind) in [
    (w_c1, RecordKind::MoveSelf),
    (w_c2, RecordKind::DeleteSelf),
    (w_c3, RecordKind::Ignored),
  ] {
    assert_eq!(
      m.on_os_record(OsRecord::new(watch, kind), at(12)),
      RecordOutcome::Nothing,
      "{kind:?} reparents nothing"
    );
  }
  // An unpaired destination (a cookie with no parked half) is a fresh Created too.
  assert_eq!(
    m.on_os_record(
      OsRecord::new(root, RecordKind::MovedTo)
        .with_name(seg("z"))
        .with_cookie(cookie(99))
        .with_is_dir(true),
      at(13),
    ),
    RecordOutcome::Nothing,
    "an unpaired destination reparents nothing"
  );
  m.assert_invariants();
}

// ── The checked location accessor: total, or absent — never a short answer ──

/// An armed, live, IDLE child directory `name` under `parent`: its bootstrap
/// enumerate is answered empty, so it accepts records of its own and a deeper
/// child can be nested beneath it.
fn idle_child_dir(m: &mut Monitor, parent: WatchId, name: &str, when: Instant) -> WatchId {
  m.on_os_record(
    OsRecord::new(parent, RecordKind::Created)
      .with_name(seg(name))
      .with_is_dir(true),
    when,
  );
  let w = drain_actions(m)
    .iter()
    .find_map(|a| a.as_watch().map(|c| c.id()))
    .expect("the created directory is armed");
  m.ack_watch(w, Ok(WatchAck::Installed));
  let boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the armed child bootstrap-enumerates");
  m.on_enumerate(boot, EnumerateResult::Ok(vec![]));
  let _ = drain_actions(m);
  let _ = drain_events(m);
  w
}

/// A healthy tree resolves to the FULL location at every depth — the checked walk
/// agrees with the lenient one exactly where the lenient one is entitled to answer.
#[test]
fn location_of_checked_resolves_a_nested_watch() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let w_a = idle_child_dir(&mut m, root, "a", at(1));
  let w_b = idle_child_dir(&mut m, w_a, "b", at(2));

  assert_eq!(m.location_of_checked(w_a), Some(loc(&["a"])));
  assert_eq!(
    m.location_of_checked(w_b),
    Some(loc(&["a", "b"])),
    "the full two-segment location, not a prefix of it"
  );
  assert_eq!(m.location_of_checked(w_b).unwrap(), m.location_of(w_b));
  m.assert_invariants();
}

/// The scope root is a location — the EMPTY one — and a handle with no node is
/// `None`. The two must not collapse: `None` is "cannot be placed", not "at the
/// root", and a caller joining onto a root path distinguishes them here or nowhere.
#[test]
fn location_of_checked_places_the_scope_root_at_the_empty_location() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));

  assert_eq!(m.location_of_checked(root), Some(Location::new()));
  assert!(
    m.location_of_checked(root).is_some_and(|at| at.is_empty()),
    "the root resolves, and resolves to zero segments"
  );

  let unplaced = m.reserve_watch_id();
  assert_eq!(
    m.location_of_checked(unplaced),
    None,
    "a handle with no node is unplaceable, not at the root"
  );
  assert_ne!(m.location_of_checked(unplaced), m.location_of_checked(root));
  m.assert_invariants();
}

/// The cell this accessor exists for. With an ancestor gone from under it, the
/// lenient walk stops where the tree stops and hands back the SUFFIX it had
/// collected — a location that composes into a real-looking path one level under
/// the root. The checked walk refuses instead.
///
/// The severed link is written directly into the node map: no public input
/// produces one (a subtree drop takes the whole subtree, so a survivor never
/// outlives its parent), and the tree is left structurally inconsistent
/// afterwards — hence no `assert_invariants` here.
#[test]
fn location_of_checked_refuses_a_node_whose_ancestor_is_gone() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let w_a = idle_child_dir(&mut m, root, "a", at(1));
  let w_b = idle_child_dir(&mut m, w_a, "b", at(2));
  assert_eq!(m.location_of_checked(w_b), Some(loc(&["a", "b"])));

  m.nodes.remove(&w_a);

  assert_eq!(
    m.location_of(w_b),
    loc(&["b"]),
    "the lenient walk truncates to a plausible-but-wrong near-root location"
  );
  assert_eq!(
    m.location_of_checked(w_b),
    None,
    "the checked walk reports the same tree as unanswerable"
  );
}

/// A cycle is unreachable through the public API — `can_reparent` refuses a splice
/// into the moving subtree, and `assert_invariants` asserts acyclicity on every
/// property-test step — so the back-edge is written straight into the node map to
/// exercise the bound. The lenient walk spends its whole budget fabricating
/// segments; the checked walk spends the same budget and then answers `None`.
#[test]
fn location_of_checked_refuses_a_cycle() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let w_a = idle_child_dir(&mut m, root, "a", at(1));
  let w_b = idle_child_dir(&mut m, w_a, "b", at(2));

  m.nodes
    .get_mut(&w_a)
    .expect("the middle node is live")
    .parent = Some(w_b);

  assert!(
    m.location_of(w_b).len() > 2,
    "the lenient walk invents segments the tree does not have: {:?}",
    m.location_of(w_b),
  );
  assert_eq!(
    m.location_of_checked(w_b),
    None,
    "an exhausted bound is absence, never the segments collected on the way"
  );
  assert_eq!(m.location_of_checked(w_a), None);
  assert_eq!(
    m.location_of_checked(root),
    Some(Location::new()),
    "a node ABOVE the cycle still resolves — refusal is per-walk, not per-tree"
  );
}

/// The lenient walk keeps the contract its internal callers were written against:
/// it always answers, it never panics, an unknown handle reads as the empty
/// location, and a severed chain truncates. Those are the branches the checked twin
/// converts to `None`, so pinning them here also pins that the two are genuinely
/// different functions rather than one wrapping the other.
#[test]
fn lenient_location_of_keeps_its_truncating_contract() {
  let mut m = per_dir();
  let root = live_root_idle(&mut m, scope(1));
  let w_a = idle_child_dir(&mut m, root, "a", at(1));
  let w_b = idle_child_dir(&mut m, w_a, "b", at(2));

  assert_eq!(m.location_of(root), Location::new());
  assert_eq!(m.location_of(w_b), loc(&["a", "b"]));

  let unplaced = m.reserve_watch_id();
  assert_eq!(
    m.location_of(unplaced),
    Location::new(),
    "an unknown handle reads as the root — indistinguishable from the root itself"
  );
  assert_ne!(
    m.location_of_checked(unplaced),
    Some(m.location_of(unplaced)),
    "the checked form is not the lenient form wrapped in Some"
  );

  m.nodes.remove(&w_a);
  assert_eq!(m.location_of(w_b), loc(&["b"]), "truncation, as before");
  assert_ne!(
    m.location_of_checked(w_b),
    Some(m.location_of(w_b)),
    "and the checked form does not agree with that truncation either"
  );
}

// ---------------------------------------------------------------------------
// An outstanding arm is addressed to a `(parent, name)` slot, and a rename
// empties that slot while the node it named lives on. The arm must follow the
// node — re-addressed at every re-key, retired where the node has no slot at
// all, and never dispatched once superseded — so a scope's barrier settles only
// over an acknowledgement that proves the binding at the node's FINAL slot.
// ---------------------------------------------------------------------------

/// A reproving scope holding `root/s0` (identity-carried, settled), with `s0`
/// detached mid-move and a scope loss on record — so the recovery skipped the
/// held subtree and the pairing owes the source its re-add.
fn reproof_hold_at_s0(m: &mut Monitor, s: ScopeId) -> (WatchId, WatchId) {
  let root = live_root(m, s);
  let boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("bootstrap read");
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("s0"), FileKind::Dir).with_node(ident(10)),
    ]),
  );
  let w_s = drain_actions(m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("s0 arms");
  m.ack_watch(w_s, Ok(WatchAck::Installed));
  let s_boot = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("s0's cold read");
  m.on_enumerate(s_boot, EnumerateResult::Ok(vec![]));
  let _ = drain_events(m);
  let _ = drain_actions(m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("s0"))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(2),
  );
  m.on_overflow(Scope::Root(s), at(3));
  let _ = drain_events(m);
  let _ = drain_actions(m);
  m.ack_watch(root, Ok(WatchAck::Aliased));
  let read = drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().map(|e| e.req()))
    .expect("the root's reproof read");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  let _ = drain_events(m);
  let _ = drain_actions(m);
  (root, w_s)
}

/// Two complete rename pairs inside one batch: the first pairing issues the
/// source's re-add at `s1`, and the second moves the source to `s2` before the
/// driver has polled anything. `start_reinstall` deliberately issues nothing
/// for a node already `Arming`, so without the re-addressing the queued re-add
/// would stay aimed at the slot the source left — and its failure, still
/// naming the current attempt, would retire the live `s2` subtree.
#[test]
fn a_rename_before_polling_re_addresses_the_queued_readd() {
  let mut m = reproving();
  let s = scope(1);
  let (root, w_s) = reproof_hold_at_s0(&mut m, s);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("s1"))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(4),
  );
  // No poll between the pairs: the re-add for `s1` is still queued when the
  // source moves again.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("s1"))
      .with_cookie(cookie(8))
      .with_is_dir(true),
    at(5),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("s2"))
      .with_cookie(cookie(8))
      .with_is_dir(true),
    at(6),
  );

  let actions = drain_actions(&mut m);
  assert_eq!(
    readd_of(&actions, w_s),
    Some(WatchTarget::child(root, seg("s2"))),
    "the re-add follows the source to its final slot: {actions:?}"
  );
  assert_eq!(
    actions
      .iter()
      .filter_map(|a| a.as_watch())
      .filter(|w| w.id() == w_s)
      .count(),
    1,
    "and the superseded one never reaches the driver: {actions:?}"
  );
  assert!(
    !m.rearm_settled(s),
    "the re-add is still a counted obligation"
  );
  assert!(!m.coverage_settled(s), "so the barrier holds");

  // Only the acknowledgement of the FINAL slot's arm releases it.
  m.ack_watch(w_s, Ok(WatchAck::Aliased));
  let s_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_s).map(|e| e.req()))
    .expect("the re-proven source reads");
  m.on_enumerate(s_read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.coverage_settled(s));
  assert!(m.is_watched(w_s), "the live subtree is retired by nothing");
  m.assert_invariants();
}

/// The same rename, one step later: the driver has already TAKEN the re-add
/// for `s1` when the source moves to `s2`. Nothing can retarget an arm the
/// driver holds, so the fix is supersession — the in-flight acknowledgement
/// answers for a slot the source has left and must certify no binding, while a
/// fresh arm addresses the destination.
#[test]
fn a_rename_after_polling_supersedes_the_inflight_readd() {
  let mut m = reproving();
  let s = scope(1);
  let (root, w_s) = reproof_hold_at_s0(&mut m, s);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("s1"))
      .with_cookie(cookie(7))
      .with_is_dir(true),
    at(4),
  );
  let dispatched = drain_actions(&mut m);
  let inflight = dispatched
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.id() == w_s)
        .map(|w| (w.attempt(), w.target().clone()))
    })
    .expect("the pairing re-adds the source");
  assert_eq!(inflight.1, WatchTarget::child(root, seg("s1")));

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("s1"))
      .with_cookie(cookie(8))
      .with_is_dir(true),
    at(5),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("s2"))
      .with_cookie(cookie(8))
      .with_is_dir(true),
    at(6),
  );
  // The in-flight arm answers for the vacated slot — and it FAILS, because
  // nothing stands at `s1` any more. Applied to the source it no longer
  // addresses, that failure retires the live `s2` subtree and leaves a slot
  // deficit in its place; discarded, it decides nothing at all.
  m.on_watch_result(w_s, inflight.0, Err(WatchError::NotFound));
  assert!(
    m.is_watched(w_s),
    "a failure at the vacated slot retires the subtree that left it: nothing"
  );
  assert!(
    !m.has_coverage_deficit(s),
    "and books no darkness for a slot that is covered"
  );
  assert!(
    !m.rearm_settled(s),
    "an outcome for a slot the source left certifies no binding either way"
  );
  assert!(!m.coverage_settled(s), "so the barrier still holds");

  let reissued = drain_actions(&mut m);
  assert_eq!(
    readd_of(&reissued, w_s),
    Some(WatchTarget::child(root, seg("s2"))),
    "a fresh arm addresses the destination: {reissued:?}"
  );
  assert!(
    !reissued
      .iter()
      .any(|a| a.as_enumerate().is_some_and(|e| e.dir() == w_s)),
    "and no read runs before that arm acknowledges: {reissued:?}"
  );

  let final_attempt = reissued
    .iter()
    .find_map(|a| a.as_watch().filter(|w| w.id() == w_s).map(|w| w.attempt()))
    .expect("the destination's arm");
  m.on_watch_result(w_s, final_attempt, Ok(WatchAck::Aliased));
  let s_read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_s).map(|e| e.req()))
    .expect("the re-proven source reads");
  m.on_enumerate(s_read, EnumerateResult::Ok(vec![]));
  assert!(m.rearm_settled(s));
  assert!(m.coverage_settled(s));
  m.assert_invariants();
}

/// A detached move source occupies no slot at all, so its pending arm has no
/// coordinate to name: dispatching it would bind this handle to whatever
/// replacement took the vacated path, and the pairing would then carry that
/// binding to the destination. The arm is retired at the detach and
/// re-addressed only once the reparent gives the node a slot again.
#[test]
fn a_pending_arm_is_never_dispatched_at_the_slot_its_move_vacated() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);

  // A directory is discovered and its arm queued but not yet polled…
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  // …when the same batch renames it away.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  let vacated = drain_actions(&mut m);
  assert!(
    !vacated
      .iter()
      .filter_map(|a| a.as_watch())
      .any(|w| w.target().as_child().is_some_and(|c| *c.name() == seg("a"))),
    "no arm reaches the driver naming the vacated slot: {vacated:?}"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("b"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  let paired = drain_actions(&mut m);
  let arms: Vec<_> = paired.iter().filter_map(|a| a.as_watch()).collect();
  assert_eq!(arms.len(), 1, "exactly one arm survives: {paired:?}");
  assert_eq!(
    arms[0].target(),
    &WatchTarget::child(root, seg("b")),
    "and it names where the source landed: {paired:?}"
  );
  m.assert_invariants();
}

/// A read is dispatched against the reader's `(parent, name)` slot too. One
/// taken while the directory moves away describes this object only if the
/// driver read before the rename; otherwise it lists whatever replaced it. A
/// cold snapshot trusted at the destination would announce a stranger's
/// entries as `Created` there, so the detach dirties the read: no discoveries,
/// one covering `Rescan`, and a retry against wherever the node has landed.
#[test]
fn a_read_dispatched_at_a_vacated_slot_is_not_trusted_at_the_destination() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  m.on_os_record(
    OsRecord::new(root, RecordKind::Created)
      .with_name(seg("a"))
      .with_is_dir(true),
    at(1),
  );
  let w_a = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("a arms");
  m.ack_watch(w_a, Ok(WatchAck::Installed));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_a).map(|e| e.req()))
    .expect("a's cold read");
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("a"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(2),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("b"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("ghost"), FileKind::Dir).with_node(ident(77)),
    ]),
  );
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_created()),
    "a snapshot of the vacated slot announces no discoveries: {events:?}"
  );
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["b"])),
    "it stands a covering Rescan at the destination instead: {events:?}"
  );
  assert!(
    m.is_rearm_enumerating(w_a),
    "and re-reads wherever the node has landed"
  );
  m.assert_invariants();
}

/// A widen re-keys the OLD root under the chain's tail, which changes what the
/// scope-addressed targets resolve to: an outstanding
/// [`WatchTarget::RearmRoot`] would re-add the NEW root's path under the
/// adopted node's handle. The splice re-addresses it down the chain, and the
/// scope-addressed one never reaches the driver.
#[test]
fn a_widen_re_addresses_the_adopted_roots_outstanding_readd() {
  let mut m = reproving();
  let s = scope(1);
  let old_root = live_root_idle(&mut m, s);

  // A recovery in flight whose re-add is still QUEUED.
  m.on_overflow(Scope::Root(s), at(1));
  let _ = drain_events(&mut m);

  let reserved = m.reserve_watch_id();
  assert!(
    m.widen_root(s, reserved, vec![seg("r")], Some(ident(1)))
      .is_some()
  );
  let actions = drain_actions(&mut m);
  assert!(
    !actions
      .iter()
      .filter_map(|a| a.as_watch())
      .any(|w| w.target().is_rearm_root()),
    "no arm still claims the adopted node IS the scope's root: {actions:?}"
  );
  assert_eq!(
    readd_of(&actions, old_root),
    Some(WatchTarget::child(reserved, seg("r"))),
    "the re-add follows the adopted node down the chain: {actions:?}"
  );

  m.ack_watch(old_root, Ok(WatchAck::Aliased));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == old_root)
        .map(|e| e.req())
    })
    .expect("the adopted node's reproof read");
  m.on_enumerate(read, EnumerateResult::Ok(vec![]));
  assert!(
    m.rearm_settled(s),
    "the recovery completes across the splice"
  );
  m.assert_invariants();
}

/// The moved clause ALONE at the acknowledgement seam — no hold anywhere — where
/// discarding the verdict is not enough. An ancestor's rename leaves this node's
/// own `(parent, name)`, and so its attempt, untouched, so an outcome for an arm
/// issued before the rename arrives past the supersession fence naming a path that
/// is now somebody else's. For a FAILURE that is the whole story; for a SUCCESS the
/// driver has already installed and attributed a kernel binding at that path.
///
/// A cold discovery's arm is counted by nothing (`Arming { rearm: false }` is not a
/// re-arm state), so before the retirement this window was not merely unfenced but
/// SETTLED: a sync cookie could certify over a subtree whose binding sits somewhere
/// else entirely. The retirement closes it on both halves at once — the binding
/// dies, and the slot is rebuilt COUNTED behind a located cover.
#[test]
fn a_stale_install_at_a_moved_chain_is_retired_and_the_slot_rebuilt_counted() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = live_child_dir(&mut m, root, "d");

  // A child discovered from a record — identity-less, armed, and NOT yet
  // acknowledged when the rename lands.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("c"))
      .with_is_dir(true),
    at(2),
  );
  let (w_c, stale_attempt) = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("c")))
        .map(|w| (w.id(), w.attempt()))
    })
    .expect("the discovered directory arms");

  // The ANCESTOR moves, and its pairing completes: `c` keeps its slot under
  // `d`, so nothing supersedes its in-flight arm and no hold is left standing.
  // Only the placement clock knows the path that arm was issued against moved.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(4),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // The arm succeeds — at the vacated path.
  m.on_watch_result(w_c, stale_attempt, Ok(WatchAck::Installed));
  assert!(
    !m.is_watched(w_c),
    "a binding installed at a path the chain has left certifies nothing, so it \
     is retired"
  );
  let cover = drain_events(&mut m);
  assert!(
    cover
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e", "c"])),
    "and the retirement covers the slot it ended, located at the node's CURRENT \
     path: {cover:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "with the counted rebuild holding the barrier over the window it opened"
  );
  // INSIDE the window, where the rebuild is still outstanding.
  m.assert_invariants();
  let replacement = drain_actions(&mut m);
  let rebuilt = replacement
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("c")))
        .map(|w| w.id())
    })
    .expect("the slot is rebuilt where the node now sits");
  assert_ne!(
    rebuilt, w_c,
    "on a fresh handle: the retired one is what may not be trusted"
  );

  // The replacement at the vacated path keeps producing records on the binding
  // the retired handle opened. None of them may reach the tree.
  m.on_os_record(
    OsRecord::new(w_c, RecordKind::Created)
      .with_name(seg("x"))
      .with_is_dir(true),
    at(5),
  );
  let delivered = drain_events(&mut m);
  assert!(
    !delivered
      .iter()
      .any(|e| e.location() == &loc(&["e", "c", "x"])),
    "no record off the retired binding is delivered at the destination: {delivered:?}"
  );
  let queued = drain_actions(&mut m);
  assert!(
    !queued
      .iter()
      .any(|a| a.as_watch().map(|w| w.target()) == Some(&WatchTarget::child(w_c, seg("x")))),
    "nor installs coverage for a name only the retired binding reported: {queued:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and the barrier is still held by the rebuild"
  );

  // The rebuild acknowledges — proof at a path that IS this node's — and its own
  // read completes.
  m.ack_watch(rebuilt, Ok(WatchAck::Installed));
  let c_read = read_of(&mut m, rebuilt);
  m.on_enumerate(c_read, EnumerateResult::Ok(vec![]));
  assert!(
    m.coverage_settled(s),
    "the scope settles once the rebuilt read completes"
  );

  m.on_os_record(
    OsRecord::new(rebuilt, RecordKind::Created).with_name(seg("y")),
    at(6),
  );
  assert!(
    drain_events(&mut m)
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["e", "c", "y"])),
    "and the rebuilt binding delivers at the node's own path"
  );
  m.assert_invariants();
}

/// The moved-success retirement's COVER — the half its counted rebuild is not.
///
/// The binding this `Ok` reported sits at the path the subtree left, so a
/// modification of a file that ALREADY existed at the destination is recorded by
/// nobody: not by the retired binding, and not yet by the rebuild. Neither edge of
/// the rebuild announces it afterwards — the replacement's read is a re-arm, so
/// every pre-existing entry it lists is `Created`-suppressed, and an `Aliased`
/// acknowledgement proves the binding was live all along and so marks no dark
/// window at all.
///
/// So the cover is emitted AT THE RETIREMENT, unconditionally on flavour, and the
/// rebuild is what keeps the barrier shut until the consumer's re-read has
/// something to read. `Aliased` throughout, which is where the flavour-conditional
/// rule used to lose the cover entirely.
#[test]
fn a_moved_success_retire_covers_the_destination_it_blinded() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = live_child_dir(&mut m, root, "d");

  // `c` is discovered from a record and armed; its acknowledgement is still in
  // flight when the ANCESTOR is renamed, so the install lands at `d/c` — a path
  // the subtree has left for `e/c`.
  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("c"))
      .with_is_dir(true),
    at(2),
  );
  let (w_c, stale_attempt) = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("c")))
        .map(|w| (w.id(), w.attempt()))
    })
    .expect("the discovered directory arms");
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(4),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_watch_result(w_c, stale_attempt, Ok(WatchAck::Aliased));
  let cover = drain_events(&mut m);
  assert!(
    cover
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["e", "c"])),
    "the retirement stands its cover for the destination it blinded, whatever \
     the acknowledgement's flavour: {cover:?}"
  );
  let replacement = drain_actions(&mut m);
  let rebuilt = replacement
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("c")))
        .map(|w| w.id())
    })
    .expect("the counted rebuild addresses the node where it now sits");

  // INSIDE the window, which is where the darkness is. `e/c/f` already existed at
  // the destination and changes now: the real destination carries no binding yet,
  // and the retired one is gone, so nothing about the modification reaches the
  // consumer as a change.
  m.on_os_record(
    OsRecord::new(w_c, RecordKind::Modified).with_name(seg("f")),
    at(5),
  );
  let blind = drain_events(&mut m);
  assert!(
    blind.iter().all(|e| !e.kind().is_modified()),
    "the destination's modification is delivered by nobody: {blind:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "and the rebuild holds the barrier over the blind subtree"
  );
  m.assert_invariants();

  // The rebuild acknowledges at its WEAKEST flavour: `Aliased` witnesses no dark
  // window of its own and marks none. The cover the retirement already stood is
  // what carries the interval, so nothing here depends on the flavour.
  m.ack_watch(rebuilt, Ok(WatchAck::Aliased));
  let c_read = read_of(&mut m, rebuilt);
  m.on_enumerate(
    c_read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("f"), FileKind::File)]),
  );
  let closing = drain_events(&mut m);
  assert!(
    !closing
      .iter()
      .any(|e| e.location() == &loc(&["e", "c", "f"])),
    "the rebuilt read is Created-suppressed, so the pre-existing entry is never \
     announced either: {closing:?}"
  );
  assert!(
    m.coverage_settled(s),
    "the scope settles once the rebuilt read completes"
  );
  m.assert_invariants();
}

/// The `Err` half of the same clause, and the one the retirement must NOT reach.
/// A refused arm created no binding, so there is nothing installed at the vacated
/// path to retire — and retiring anyway would tear down a node whose object is
/// alive and armable at its new location. The verdict is discarded, the handle
/// lives on, and its obligation is re-issued at wherever the node sits now.
#[test]
fn a_stale_failure_at_a_moved_chain_readdresses_rather_than_retires() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = live_child_dir(&mut m, root, "d");

  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("c"))
      .with_is_dir(true),
    at(2),
  );
  let (w_c, stale_attempt) = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("c")))
        .map(|w| (w.id(), w.attempt()))
    })
    .expect("the discovered directory arms");
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(4),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_watch_result(w_c, stale_attempt, Err(WatchError::Permission));
  assert!(
    m.is_watched(w_c),
    "a verdict about somebody else's path may not retire this node"
  );
  let events = drain_events(&mut m);
  assert!(
    events.is_empty(),
    "and it ends no coverage, so it owes no cover: {events:?}"
  );
  let actions = drain_actions(&mut m);
  assert_eq!(
    readd_of(&actions, w_c),
    Some(WatchTarget::child(w_d, seg("c"))),
    "the same handle is re-addressed where the node now sits: {actions:?}"
  );
  m.assert_invariants();
}

/// The rebuild's FLAVOUR, cold half. The retiree here was a cold discovery — its
/// `Created` record already announced the directory to the consumer — so a
/// replacement that read as a discovery would announce its contents a second time.
/// The rebuild is re-arm-flavoured whatever the retiree was, so its read is
/// `Created`-suppressed and the located cover the retirement stood is what
/// instructs the re-read.
#[test]
fn a_cold_retiree_rebuilds_counted_and_announces_nothing_twice() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = live_child_dir(&mut m, root, "d");

  m.on_os_record(
    OsRecord::new(w_d, RecordKind::Created)
      .with_name(seg("c"))
      .with_is_dir(true),
    at(2),
  );
  let (w_c, stale_attempt) = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("c")))
        .map(|w| (w.id(), w.attempt()))
    })
    .expect("the discovered directory arms");
  assert!(
    !m.has_rearm_obligation(w_c),
    "staging: the retiree's own arm is a cold discovery, counted by nothing"
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(4),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_watch_result(w_c, stale_attempt, Ok(WatchAck::Installed));
  let rebuilt = armed_child(&mut m, w_d, "c");
  assert!(
    m.has_rearm_obligation(rebuilt),
    "the rebuild is COUNTED, though the retiree's own arm was not"
  );
  let _ = drain_events(&mut m);

  m.ack_watch(rebuilt, Ok(WatchAck::Installed));
  let read = read_of(&mut m, rebuilt);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("y"), FileKind::Dir)]),
  );
  let announced = drain_events(&mut m);
  assert!(
    !announced
      .iter()
      .any(|e| e.kind().is_created() && e.location() == &loc(&["e", "c", "y"])),
    "and its read is Created-suppressed, so nothing is announced twice: {announced:?}"
  );
  let grandchild = armed_child(&mut m, rebuilt, "y");
  m.ack_watch(grandchild, Ok(WatchAck::Installed));
  settle_reads(&mut m);
  assert!(
    m.coverage_settled(s),
    "the scope settles behind the rebuild"
  );
  m.assert_invariants();
}

/// The rebuild's FLAVOUR, re-arm half — and the ordering the whole cover rests on.
/// A retiree that was itself part of a crawl is rebuilt counted like any other, and
/// the window's closing `Rescan` may only be minted once that rebuild's own READ
/// has completed: minting it at the acknowledgement would send the consumer to
/// re-read a subtree still being walked, and the change that lands in between would
/// then be behind the last `Rescan` the consumer ever saw.
#[test]
fn a_rearm_retirees_closing_rescan_postdates_the_rebuilt_read() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = live_child_dir(&mut m, root, "d");

  // A crawl of `d` installs `c` counted: this retiree's arm is re-arm-flavoured.
  assert!(m.rearm_watch_subtree(w_d).is_started());
  let crawl = read_of(&mut m, w_d);
  m.on_enumerate(
    crawl,
    EnumerateResult::Ok(vec![DirEntry::new(seg("c"), FileKind::Dir)]),
  );
  let (w_c, stale_attempt) = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_watch()
        .filter(|w| w.target() == &WatchTarget::child(w_d, seg("c")))
        .map(|w| (w.id(), w.attempt()))
    })
    .expect("the crawl arms the listed directory");
  assert!(
    m.has_rearm_obligation(w_c),
    "staging: the retiree's own arm is counted"
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(4),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  m.on_watch_result(w_c, stale_attempt, Ok(WatchAck::Installed));
  let rebuilt = armed_child(&mut m, w_d, "c");
  let at_retire = drain_events(&mut m);
  assert!(
    !at_retire
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&[])),
    "no closing Rescan at the retirement — the rebuild has not even armed: \
     {at_retire:?}"
  );

  m.ack_watch(rebuilt, Ok(WatchAck::Installed));
  let acked = drain_events(&mut m);
  assert!(
    !acked
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&[])),
    "nor at its acknowledgement — its read is still walking the subtree: {acked:?}"
  );
  assert!(
    !m.coverage_settled(s),
    "which is what holds the window open"
  );

  let read = read_of(&mut m, rebuilt);
  m.on_enumerate(read, EnumerateResult::Ok(Vec::new()));
  let closing = drain_events(&mut m);
  assert!(
    closing
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&[])),
    "the closing Rescan is minted at the settle edge the rebuilt read reaches: \
     {closing:?}"
  );
  assert!(m.coverage_settled(s));
  m.assert_invariants();
}

/// The retirement's ROOT branch. A root has no slot to rebuild and no parent to
/// cover at — its lowered path IS the scope's ground — so an acknowledgement that
/// does not describe it can only be a root invalidation, exactly as a refused root
/// install is.
///
/// Every ordinary route here is closed by the arm funnels themselves: a rebind
/// records the root's placement change and only then adopts the arm whose outcome
/// it hands back, so the replay is stamped current. What reaches the clause is a
/// further root swap recorded between that adopt and the replay — the one
/// interleaving that would otherwise certify the scope's root against the world the
/// swap replaced.
#[test]
fn an_unprovable_root_acknowledgement_invalidates_the_root() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let (rebound, attempt) = m.rebind_root(s).expect("a descending scope rebinds");
  assert_eq!(rebound, root, "the rebind keeps the root handle");
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A second root swap is recorded before the first one's outcome is replayed.
  m.moved_placement(root);
  m.on_watch_result(root, attempt, Ok(WatchAck::Installed));
  assert!(
    !m.is_watched(root),
    "an acknowledgement that describes a world the root has left certifies nothing"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&[])),
    "and the invalidation is never silent: {events:?}"
  );
  m.assert_invariants();
}

/// A retirement inside an incomplete read's reconcile can stand a counted
/// cover, and that re-arm lands on the very directory being reconciled — which
/// then queues its own bounded retry on top. Two reads for one node is the one
/// thing `NodeState::Enumerating` cannot express, so the earlier request must
/// be reclaimed rather than stranded in `pending_enumerate`.
#[test]
fn a_counted_cover_inside_an_incomplete_read_strands_no_request() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_b = idle_child_dir(&mut m, root, "B", at(1));
  let w_c = idle_child_dir(&mut m, w_b, "C", at(2));

  // C detaches mid-move and its hold is dirtied by suppressed activity.
  m.on_os_record(
    OsRecord::new(w_b, RecordKind::MovedFrom)
      .with_name(seg("C"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(3),
  );
  m.on_os_record(
    OsRecord::new(w_c, RecordKind::Created)
      .with_name(seg("x"))
      .with_is_dir(true),
    at(4),
  );
  let _ = drain_events(&mut m);
  let _ = drain_actions(&mut m);

  // The root re-reads incompletely, and the listing retires B — whose subtree
  // carries the dirtied hold, so the drop stands a counted cover at the root.
  m.on_overflow(Scope::Subtree(SubtreeScope::new(root)), at(5));
  let read = drain_actions(&mut m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the root re-arm read");
  m.on_enumerate(
    read,
    EnumerateResult::Partial(vec![DirEntry::new(seg("B"), FileKind::File)]),
  );
  assert!(!m.is_watched(w_b), "the listing retired B");
  assert!(m.is_rearm_enumerating(root), "and the root re-reads");
  m.assert_invariants();
}

// ---------------------------------------------------------------------------
// 42-10: the registration window. A registration reports no inventory — the
// contract says pre-existing state is not a change — so its crawl is
// suppressed; and because the arm-before-readdir invariant is per-DIRECTORY,
// that suppression owes a loss half, which is what the bootstrap mark supplies.
// ---------------------------------------------------------------------------

/// Registers a root and brings its post-arm read to the point of answering,
/// returning `(root, req)`. The read is the crawl's, so it is re-arm-flavored
/// and announces nothing.
fn bootstrap_read(m: &mut Monitor, s: ScopeId) -> (WatchId, ReqId) {
  let root = live_root(m, s);
  let req = drain_actions(m)
    .iter()
    .find_map(|a| {
      a.as_enumerate()
        .filter(|e| e.dir() == root)
        .map(|e| e.req())
    })
    .expect("the armed root reads");
  (root, req)
}

/// A directory the LIVE stream discovers under `parent` — a record-driven cold
/// install, still `Arming`. The post-registration staging every cell that needs
/// a COLD read now uses: a registration's own crawl is `Created`-suppressed.
fn discovered_child_dir(m: &mut Monitor, parent: WatchId, name: &str) -> WatchId {
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
  let _ = drain_events(m);
  child
}

/// Arms `dir` (whose install the crawl just queued) and returns its own read's
/// request.
fn armed_read(m: &mut Monitor, dir: WatchId) -> ReqId {
  m.ack_watch(dir, Ok(WatchAck::Installed));
  drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == dir).map(|e| e.req()))
    .expect("the armed directory reads")
}

/// The watch the last drained action installs — the crawl's fresh child.
fn queued_install(m: &mut Monitor) -> WatchId {
  drain_actions(m)
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the crawl installs the discovered directory")
}

/// 42-10 cell 2b — THE LOSS HALF. An entry created in a directory the bootstrap
/// crawl DISCOVERED but had not yet armed is recorded by nobody: the
/// arm-before-readdir invariant is per-DIRECTORY, so `deep`'s own arm postdates
/// the grant, and the suppressed read that finally lists it announces nothing.
/// The window's closing `Rescan` is the only instruction that covers that gap,
/// and it must stand — otherwise this design trades over-delivery for SILENT
/// under-delivery, which is strictly worse.
///
/// Mutation that kills it: drop the loss half (`mark_bootstrap_loss` at
/// `rearm_enumerate`'s install loop). The window then closes silent.
#[test]
fn a_gap_create_under_a_bootstrap_armed_directory_is_dominated_by_the_closing_rescan() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, read) = bootstrap_read(&mut m, s);

  // The crawl discovers `sub` — a FRESH install, so its arm postdates the grant.
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "the bootstrap crawl announces no inventory"
  );
  let sub = queued_install(&mut m);

  // …and `deep` under it, likewise armed only now.
  let read = armed_read(&mut m, sub);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("deep"), FileKind::Dir)]),
  );
  assert!(drain_events(&mut m).is_empty(), "still no inventory");
  let deep = queued_install(&mut m);

  // THE GAP: `gap.txt` is created under `deep` between the grant and `deep`'s
  // own arm. No kernel record describes it (nothing was watching `deep` yet),
  // and the suppressed read that lists it emits no `Created`.
  let read = armed_read(&mut m, deep);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("gap.txt"), FileKind::File)]),
  );

  // The crawl has quiesced, so the window closes — with exactly one `Rescan` at
  // the scope root, which postdates the gap create by construction.
  assert!(m.rearm_settled(s), "the counted crawl quiesced");
  let events = drain_events(&mut m);
  assert_eq!(
    events.len(),
    1,
    "the closing Rescan is the window's one signal: {events:?}"
  );
  assert!(
    events[0].kind().is_rescan(),
    "and it is a Rescan, not an inventory Created: {:?}",
    events[0]
  );
  assert_eq!(
    events[0].location(),
    &Location::new(),
    "located at the scope root, dominating the whole crawl"
  );
  m.assert_invariants();
}

/// 42-10 cell 1 — the finding itself, over a DEPTH-2 pre-populated tree: the
/// registration delivers ZERO `Created`s and exactly one closing `Rescan`, at
/// coverage settle. Depth 2 is deliberate: a flat fixture would pass an
/// under-fix that suppressed only the root's own read.
///
/// Mutation that kills it: revert the suppression (birth the root
/// `rearm: false`), which restores the inventory.
#[test]
fn a_registration_over_a_deep_tree_delivers_no_inventory() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, read) = bootstrap_read(&mut m, s);

  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("top.txt"), FileKind::File),
      DirEntry::new(seg("sub"), FileKind::Dir),
    ]),
  );
  let sub = queued_install(&mut m);
  let read = armed_read(&mut m, sub);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("mid.txt"), FileKind::File),
      DirEntry::new(seg("deep"), FileKind::Dir),
    ]),
  );
  let deep = queued_install(&mut m);
  let read = armed_read(&mut m, deep);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("leaf.txt"), FileKind::File)]),
  );

  assert!(m.rearm_settled(s), "the crawl quiesced");
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_created()),
    "a registration reports no inventory at any depth: {events:?}"
  );
  assert_eq!(events.len(), 1, "exactly one signal: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  // …and the coverage the silent crawl took is real, all three levels of it.
  assert!(m.is_watched(sub) && m.is_watched(deep));
  m.assert_invariants();
}

/// 42-10 cell 1b — the self-scaling silence. A registration over an EMPTY root,
/// and over a FILES-ONLY root, is completely silent: no `Created`, and no
/// `Rescan` either. The root's own birth sets `fresh_rearm`, but nothing armed
/// fresh BELOW it, so no loss half stands and the bridge conjunction refuses to
/// fire.
///
/// Mutation that kills it: seed `saw_rescan` at registration instead of at a
/// fresh descendant install — a silent root would then close with a `Rescan`
/// instructing a re-read of nothing.
#[test]
fn a_registration_over_a_childless_root_is_completely_silent() {
  for listing in [
    std::vec::Vec::new(),
    vec![
      DirEntry::new(seg("a.txt"), FileKind::File),
      DirEntry::new(seg("b.txt"), FileKind::File),
    ],
  ] {
    let mut m = per_dir();
    let s = scope(1);
    let (_root, read) = bootstrap_read(&mut m, s);
    m.on_enumerate(read, EnumerateResult::Ok(listing.clone()));

    assert!(m.rearm_settled(s));
    assert!(
      drain_events(&mut m).is_empty(),
      "a root with no subdirectories registers in silence: {listing:?}"
    );
    m.assert_invariants();
  }
}

/// 42-10 cell 2a — the suppression takes only the LISTING's copy. A create
/// landing in an ALREADY-ARMED directory during the walk is recorded by the
/// kernel, and that record is delivered exactly once: the suppressed read
/// neither announces it a second time nor swallows the kernel's copy.
///
/// Mutation that kills it: broaden the suppression to the kernel-sourced path.
#[test]
fn a_create_in_an_armed_directory_during_the_walk_is_delivered_once() {
  let mut m = per_dir();
  let s = scope(1);
  let (root, read) = bootstrap_read(&mut m, s);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  let sub = queued_install(&mut m);
  let sub_read = armed_read(&mut m, sub);
  assert!(drain_events(&mut m).is_empty(), "no inventory so far");

  // `sub` is armed and its read is in flight: a create landing now IS recorded.
  m.on_os_record(
    OsRecord::new(sub, RecordKind::Created).with_name(seg("live.txt")),
    at(1),
  );
  let delivered: Vec<Change> = drain_events(&mut m);
  assert_eq!(
    delivered.len(),
    1,
    "the kernel copy delivers: {delivered:?}"
  );
  assert!(delivered[0].kind().is_created());
  assert_eq!(delivered[0].location(), &loc(&["sub", "live.txt"]));

  // …and the suppressed read that also lists it says nothing more about it.
  m.on_enumerate(
    sub_read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("live.txt"), FileKind::File)]),
  );
  assert!(
    !drain_events(&mut m).iter().any(|e| e.kind().is_created()),
    "the listing's copy is suppressed, so the create is delivered exactly once"
  );
  let _ = root;
  m.assert_invariants();
}

/// 42-10 cell 3 — suppression is about DELIVERY, never about structure. A deep
/// descendant that only the suppressed read discovers is still installed and
/// armed, and a later mutation under it is delivered normally.
///
/// Mutation that kills it: suppress the structure lowering too (skip the
/// crawl's installs), which would leave the subtree blind for the process's
/// life.
#[test]
fn a_descendant_found_only_by_the_suppressed_read_is_still_armed() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, read) = bootstrap_read(&mut m, s);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  let sub = queued_install(&mut m);
  let read = armed_read(&mut m, sub);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("deep"), FileKind::Dir)]),
  );
  let deep = queued_install(&mut m);
  let read = armed_read(&mut m, deep);
  m.on_enumerate(read, EnumerateResult::Ok(Vec::new()));
  let _ = drain_events(&mut m);

  // The suppressed crawl armed it, so the kernel records under it are OURS.
  assert!(m.is_watched(deep));
  m.on_os_record(
    OsRecord::new(deep, RecordKind::Created).with_name(seg("after.txt")),
    at(2),
  );
  let events = drain_events(&mut m);
  assert_eq!(events.len(), 1, "{events:?}");
  assert!(events[0].kind().is_created());
  assert_eq!(events[0].location(), &loc(&["sub", "deep", "after.txt"]));
  m.assert_invariants();
}

/// 42-10 cell 6b (ordering 1: the answer beats the settle edge) — the
/// unclassifiable-entry stat detour. A bootstrap listing entry of unknown kind
/// is reconciled by no read: it books darkness and asks for a kind, and the
/// directory it turns out to be is installed by the stat's ANSWER. That install
/// is an ordinary cold one, so without routing it through the crawl's own
/// suppression the whole subtree behind it announces itself as `Created`s — the
/// registration inventory, leaking straight back on any `DT_UNKNOWN`-prone
/// filesystem.
///
/// Mutation that kills it: leave the empty-slot stat install cold.
#[test]
fn a_bootstrap_stat_answered_before_the_settle_edge_installs_suppressed() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, read) = bootstrap_read(&mut m, s);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("sub"), FileKind::Dir),
      DirEntry::new(seg("mystery"), FileKind::Unknown),
    ]),
  );
  let actions = drain_actions(&mut m);
  let sub = actions
    .iter()
    .find_map(|a| a.as_watch().map(|w| w.id()))
    .expect("the classified directory installs");
  let stat = actions
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable slot is stat'd");
  assert!(drain_events(&mut m).is_empty(), "no inventory so far");

  // `sub` is still arming, so the crawl is counted and the mark still stands.
  assert!(!m.rearm_settled(s), "staging: the window is still open");
  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );
  let mystery = queued_install(&mut m);
  let read = armed_read(&mut m, mystery);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("inner.txt"), FileKind::File),
      DirEntry::new(seg("innerdir"), FileKind::Dir),
    ]),
  );
  let inner = queued_install(&mut m);
  let read = armed_read(&mut m, inner);
  m.on_enumerate(read, EnumerateResult::Ok(Vec::new()));
  let read = armed_read(&mut m, sub);
  m.on_enumerate(read, EnumerateResult::Ok(Vec::new()));

  assert!(m.rearm_settled(s), "the crawl quiesced");
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_created()),
    "the stat-detour subtree announces no inventory either: {events:?}"
  );
  assert_eq!(events.len(), 1, "one closing Rescan covers it: {events:?}");
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  assert!(m.is_watched(mystery) && m.is_watched(inner));
  m.assert_invariants();
}

/// 42-10 cell 6b (ordering 2: the answer arrives AFTER the settle edge) — the
/// C1 case. The stat is deliberately uncounted, so a bootstrap-queued one can
/// still be outstanding when the scope's first settle edge buries the bootstrap
/// mark. Routing the answer's install off the LIVE mark would install cold here
/// and resurrect the leak; the `StatSlot` is stamped at QUEUE time instead, and
/// the answer routes off the stamp.
///
/// Mutation that kills it: leave the empty-slot stat install cold. (Keying the
/// routing on the live mark instead of the stamp kills exactly this ordering,
/// which is why both are staged.)
#[test]
fn a_bootstrap_stat_answered_after_the_settle_edge_installs_suppressed() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, read) = bootstrap_read(&mut m, s);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("mystery"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable slot is stat'd");

  // The settle edge has already passed — nothing counted is left, the window is
  // closed, and the bootstrap mark is buried — while the stat is still owed.
  assert!(m.rearm_settled(s), "staging: the first settle edge passed");
  assert!(
    drain_events(&mut m).is_empty(),
    "and it closed silently: nothing armed fresh"
  );

  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );
  let mystery = queued_install(&mut m);
  let read = armed_read(&mut m, mystery);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![
      DirEntry::new(seg("inner.txt"), FileKind::File),
      DirEntry::new(seg("innerdir"), FileKind::Dir),
    ]),
  );
  let inner = queued_install(&mut m);
  let read = armed_read(&mut m, inner);
  m.on_enumerate(read, EnumerateResult::Ok(Vec::new()));

  assert!(m.rearm_settled(s), "the answer's own sub-window quiesced");
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_created()),
    "a late answer installs suppressed too: {events:?}"
  );
  assert_eq!(
    events.len(),
    1,
    "and its sub-window closes with one covering Rescan: {events:?}"
  );
  assert!(events[0].kind().is_rescan());
  assert_eq!(events[0].location(), &Location::new());
  assert!(m.is_watched(mystery) && m.is_watched(inner));
  m.assert_invariants();
}

/// 42-10 cell 6c — the stamped stat's SETTLEMENT-LOSS half, and the liveness
/// property that is the whole reason it is a loss signal rather than a barrier
/// conjunct.
///
/// A driver that never answers must cost a degraded verdict, never a wedge:
/// [`Monitor::coverage_settled`] reads true here and keeps reading true however
/// much the scope is pumped, while
/// [`Monitor::stat_loss_outstanding`] reports the window honestly. Both
/// halves are asserted together because either alone is satisfiable by a
/// mistake — a signal that never stands is silent, and a signal that also gates
/// the barrier trades this design's silent-loss hole for a liveness one.
///
/// Mutation that kills it: make the outstanding stamped stat a conjunct of
/// `coverage_settled` (`&& !self.stat_loss_outstanding(scope)`). The scope
/// then never settles at all, and every barrier built on it waits for an answer
/// nobody owes.
#[test]
fn a_never_answered_bootstrap_stat_stands_as_loss_without_wedging_the_barrier() {
  let mut m = per_dir();
  let s = scope(1);
  let (root, read) = bootstrap_read(&mut m, s);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("mystery"), FileKind::Unknown)]),
  );
  let _stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable slot is stat'd");

  assert!(
    m.stat_loss_outstanding(s),
    "the registration window owes an answer for a slot it never covered"
  );
  assert!(
    m.coverage_settled(s),
    "and the barrier still settles: an uncounted stat wedges nothing"
  );
  assert!(
    m.has_coverage_deficit(s),
    "the slot's darkness is booked, so the dispatch re-signal keeps covering it"
  );

  // Pump the scope past the settle edge repeatedly. Nothing here can answer the
  // stat, so a barrier that has taken the answer as a precondition would never
  // recover from it.
  for tick in 0..8 {
    m.on_os_record(
      OsRecord::new(root, RecordKind::Created).with_name(seg("noise.txt")),
      at(tick + 2),
    );
    let _ = drain_events(&mut m);
    let _ = drain_actions(&mut m);
    assert!(
      m.coverage_settled(s),
      "the barrier stays settled across the whole wait"
    );
    assert!(
      m.stat_loss_outstanding(s),
      "and the loss stays standing for exactly as long"
    );
  }
  m.assert_invariants();
}

/// The stamped stat's loss half is released by the ANSWER ARRIVING, whatever the
/// answer says — a directory, a file, a kind still nobody can read, a vanish, or
/// a bare I/O failure. Each of those terminals either covers the slot or re-books
/// its darkness in the deficit book, and none of them leaves a request
/// outstanding; a release keyed on the resolving answers alone would strand the
/// loss forever on the failing ones, degrading the scope's every later fence for
/// the rest of its life.
///
/// Mutation that kills it: release the loss only in `ingest_stat_result`'s
/// resolving `Ok` arm instead of at the request's removal — the failing shapes
/// then leave `stat_loss_outstanding` standing with nothing owed.
#[test]
fn every_answer_shape_releases_the_bootstrap_stat_loss() {
  for answer in [
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
    StatResult::Ok(StatEntry::new(FileKind::File)),
    StatResult::Ok(StatEntry::new(FileKind::Unknown)),
    StatResult::Failed(IoClass::NotFound),
    StatResult::Failed(IoClass::Io),
  ] {
    let mut m = per_dir();
    let s = scope(1);
    let (_root, read) = bootstrap_read(&mut m, s);
    m.on_enumerate(
      read,
      EnumerateResult::Ok(vec![DirEntry::new(seg("mystery"), FileKind::Unknown)]),
    );
    let stat = drain_actions(&mut m)
      .iter()
      .find_map(|a| a.as_stat().map(|c| c.req()))
      .expect("the unclassifiable slot is stat'd");
    assert!(
      m.stat_loss_outstanding(s),
      "staging: the loss stands before the answer ({answer:?})"
    );

    m.on_stat_result(stat, answer);
    assert!(
      !m.stat_loss_outstanding(s),
      "the answer releases the loss whatever it says: {answer:?}"
    );
    m.assert_invariants();

    // A duplicate answer for a request already spent releases nothing a second
    // time — the counter would otherwise underflow on a driver that re-reports.
    m.on_stat_result(stat, answer);
    assert!(!m.stat_loss_outstanding(s));
    m.assert_invariants();
  }
}

/// …and the one release the answer cannot perform: the stat's PARENT dies while
/// the request is still in flight. No answer can ever settle a slot that no
/// longer exists, so the parent's own teardown is the release — the same
/// `NodeMarker::StatSlots` walk that reclaims the request itself.
///
/// Mutation that kills it: release the loss only in `ingest_stat_result` and not
/// at the `StatSlots` marker. The pruned parent's stamp then outlives every
/// object it described and degrades the scope's fences forever.
#[test]
fn a_parent_teardown_releases_an_outstanding_bootstrap_stat_loss() {
  let mut m = per_dir();
  let s = scope(1);
  let (_root, read) = bootstrap_read(&mut m, s);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  let sub = queued_install(&mut m);
  let read = armed_read(&mut m, sub);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("mystery"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable slot under sub is stat'd");
  let _ = drain_events(&mut m);
  assert!(
    m.stat_loss_outstanding(s),
    "staging: the crawl stamped the stat inside the registration window"
  );

  // The consumer prunes `sub` — the slot, and with it the request, are gone.
  assert!(m.drop_watch_subtree(sub), "the prune drops the subtree");
  assert!(
    !m.stat_loss_outstanding(s),
    "the parent's teardown releases the loss its request was standing for"
  );
  m.assert_invariants();

  // And a late answer for the reclaimed request releases nothing twice.
  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );
  assert!(!m.stat_loss_outstanding(s));
  m.assert_invariants();
}

// ---------------------------------------------------------------------------
// The EMPTY-SLOT classification stat's settlement loss. Same signal as the
// registration window's, different trigger and different blast radius: a read
// that covered the slot with NOTHING owes it in any window, and the routes that
// reach it — a pure grow, a record-driven cold read — stand no `Rescan` of
// their own, so the loss is all there is between a fence and a certified
// window.
// ---------------------------------------------------------------------------

/// The re-arm read `dir`'s grow just queued.
fn grow_read(m: &mut Monitor, dir: WatchId) -> ReqId {
  drain_actions(m)
    .iter()
    .find_map(|a| a.as_enumerate().filter(|e| e.dir() == dir).map(|e| e.req()))
    .expect("the grow re-arm-enumerates the directory")
}

/// A PURE grow of `dir` whose listing names one entry no kind could be read for,
/// at a slot nothing occupies. Returns the outstanding stat's request.
///
/// This is the route the whole suite turns on: `rearm_watch_subtree` stands no
/// `Rescan`, and a crawl that retires nothing emits none either, so the window
/// this opens is covered by whatever the stat itself stands and by nothing else.
fn pure_grow_listing_unknown(m: &mut Monitor, s: ScopeId, dir: WatchId) -> ReqId {
  assert!(
    !m.in_bootstrap_window(s),
    "staging: the registration window closed at the scope's first settle"
  );
  assert!(m.rearm_watch_subtree(dir).is_started());
  let rearm = grow_read(m, dir);
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("mystery"), FileKind::Unknown)]),
  );
  let stat = drain_actions(m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable slot is stat'd");
  assert!(
    drain_events(m).is_empty(),
    "and the route delivers nothing: no Rescan of any kind stands for the hole"
  );
  stat
}

/// An empty-slot `Unknown` stands its scope's settlement loss with the
/// registration window long closed.
///
/// `mystery` may be a directory, and until the stat says so nothing watches it:
/// the crawl reconciled no watch into the slot, booked the darkness, and stood
/// no `Rescan`. The deficit alone does not close that window — it re-signals at
/// a sync cookie's DISPATCH, which an ordinary set-cover reply passes nowhere
/// near.
///
/// Mutation that kills it: narrow `queue_stat`'s loss predicate back to the
/// registration stamp (`let stands_loss = bootstrap;`). The post-window hole
/// then stands nothing at all.
#[test]
fn an_empty_slot_unknown_outside_the_registration_window_stands_the_scope_loss() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  assert!(
    !m.stat_loss_outstanding(s),
    "staging: a quiesced scope owes no loss"
  );

  let _stat = pure_grow_listing_unknown(&mut m, s, root);

  assert!(
    m.stat_loss_outstanding(s),
    "the scope covers `mystery` with nothing until the stat answers"
  );
  assert!(
    m.has_coverage_deficit(s),
    "the darkness is booked too, so the dispatch re-signal keeps covering it"
  );
  assert!(
    m.coverage_settled(s),
    "and the barrier settles regardless: the stat is uncounted"
  );
  m.assert_invariants();
}

/// The cover a settling verdict's standing stat loss owes — and the two things
/// standing it must not do.
///
/// [`Monitor::cover_stat_loss`] stands ONE root-covering `Rescan`: the slot's
/// kind is exactly what nobody knows, so there is nothing to locate the cover
/// at, and a registration-stamped request stands the loss over ground the crawl
/// announced nothing for anywhere under the root. What it must not do is acquire
/// counted coverage work. A heal kick here — the one thing
/// [`Monitor::resignal_coverage_deficits`] does that this does not — re-opens
/// the barrier and moves the coverage-work epoch, so the fence that asked for
/// the cover would find its ordering proof retired and its scope unsettled, and
/// a scope whose stat never answers would be covered, re-opened, re-settled and
/// covered again without ever reporting the verdict the loss exists to produce.
///
/// Both halves are asserted together because either alone is satisfiable by a
/// mistake: a call that stands nothing is silent, and one that stands a cover by
/// re-opening the barrier trades the silent-loss hole for a liveness one.
///
/// The loss is LEVEL-persistent, so the call discharges nothing — the second
/// verdict over the same standing request stands its own cover.
///
/// Mutation that kills it: heal-kick the scope as the deficit re-signal does.
/// The barrier re-opens, the epoch moves, and the fence waiting on both never
/// resolves.
#[test]
fn covering_a_standing_stat_loss_stands_a_root_rescan_and_acquires_no_work() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  assert!(
    !m.cover_stat_loss(s),
    "a scope standing no loss has nobody to instruct"
  );
  assert!(drain_events(&mut m).is_empty(), "and so stands nothing");

  let _stat = pure_grow_listing_unknown(&mut m, s, root);
  assert!(m.stat_loss_outstanding(s), "staging: the loss stands");
  assert!(m.coverage_settled(s), "staging: and the barrier is settled");
  let epoch = m.coverage_work_epoch(s);

  assert!(
    m.cover_stat_loss(s),
    "the settling verdict's cover is stood"
  );
  let emitted = drain_events(&mut m);
  assert_eq!(emitted.len(), 1, "{emitted:?}");
  assert!(
    emitted[0].kind().is_rescan() && emitted[0].location() == &loc(&[]),
    "and it covers the whole root: {emitted:?}"
  );
  assert!(
    drain_actions(&mut m).is_empty(),
    "nothing is kicked: a counted heal would re-open the very barrier the \
     verdict resolves against"
  );
  assert!(m.coverage_settled(s), "so the barrier stays settled");
  assert_eq!(
    m.coverage_work_epoch(s),
    epoch,
    "and the ordering proof the settling fence holds is not retired"
  );
  assert!(
    m.stat_loss_outstanding(s),
    "the cover instructs the consumer; it does not discharge the darkness"
  );

  assert!(
    m.cover_stat_loss(s),
    "so the next verdict over the same request stands its own"
  );
  let emitted = drain_events(&mut m);
  assert_eq!(emitted.len(), 1, "{emitted:?}");
  assert!(emitted[0].kind().is_rescan(), "{emitted:?}");
  m.assert_invariants();
}

/// The liveness property that is the whole reason this is a loss signal rather
/// than a barrier conjunct, on the post-window trigger.
///
/// A driver that never answers must cost a degraded verdict, never a wedge:
/// [`Monitor::coverage_settled`] reads true here and keeps reading true however
/// much the scope is pumped, while [`Monitor::stat_loss_outstanding`] reports
/// the window honestly. Both halves are asserted together because either alone
/// is satisfiable by a mistake — a signal that never stands is silent, and a
/// signal that also gates the barrier trades this design's silent-loss hole for
/// a liveness one.
///
/// Mutation that kills it: make the outstanding stat a conjunct of
/// `coverage_settled` (`&& !self.stat_loss_outstanding(scope)`). The scope then
/// never settles at all, and every barrier built on it waits for an answer
/// nobody owes.
#[test]
fn a_never_answered_empty_slot_stat_stands_as_loss_without_wedging_the_barrier() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let _stat = pure_grow_listing_unknown(&mut m, s, root);

  // Pump the scope past the settle edge repeatedly. Nothing here can answer the
  // stat, so a barrier that has taken the answer as a precondition would never
  // recover from it.
  for tick in 0..8 {
    m.on_os_record(
      OsRecord::new(root, RecordKind::Created).with_name(seg("noise.txt")),
      at(tick + 10),
    );
    let _ = drain_events(&mut m);
    let _ = drain_actions(&mut m);
    assert!(
      m.coverage_settled(s),
      "the barrier stays settled across the whole wait"
    );
    assert!(
      m.stat_loss_outstanding(s),
      "and the loss stays standing for exactly as long"
    );
  }
  m.assert_invariants();
}

/// …and an OCCUPIED slot stands none. The counterpart the cells above need to
/// mean anything: a signal raised by every unclassifiable entry would degrade
/// every fence of every scope that ever meets a `DT_UNKNOWN` file, which is
/// indistinguishable from the fix working and strictly worse than the defect.
///
/// An incumbent watch is live coverage whatever the listing failed to name — the
/// same occupation check that decides whether the darkness is booked at all —
/// so the window it spans is covered, and the stat only decides whether to keep
/// or retire it.
///
/// Mutation that kills it: stand the loss unconditionally in `queue_stat`
/// (`let stands_loss = true;`). Every scope with an outstanding slot stat then
/// reads lossy, answered or not, covered or not.
#[test]
fn an_occupied_slot_unknown_stands_no_loss() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let sub = live_child_dir(&mut m, root, "sub");

  assert!(m.rearm_watch_subtree(root).is_started());
  let rearm = grow_read(&mut m, root);
  m.on_enumerate(
    rearm,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Unknown)]),
  );
  let _stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable name is stat'd whether or not it is covered");
  let _ = drain_events(&mut m);

  assert!(m.is_watched(sub), "the unsettled name keeps its incumbent");
  assert!(
    !m.stat_loss_outstanding(s),
    "a slot a live watch covers is not a window a fence may not certify"
  );
  assert!(
    !m.has_coverage_deficit(s),
    "and nothing books darkness over it either"
  );
  m.assert_invariants();
}

/// The empty-slot loss is released by the ANSWER ARRIVING, whatever the answer
/// says — a directory, a file, a kind still nobody can read, a vanish, or a bare
/// I/O failure. Each of those terminals either covers the slot or re-books its
/// darkness in the deficit book behind a `Rescan` of its own, and none of them
/// leaves a request outstanding; a release keyed on the resolving answers alone
/// would strand the loss forever on the failing ones, degrading the scope's
/// every later fence for the rest of its life.
///
/// Mutation that kills it: release the loss only in `ingest_stat_result`'s
/// resolving `Ok` arm instead of at the request's removal — the failing shapes
/// then leave `stat_loss_outstanding` standing with nothing owed.
#[test]
fn every_answer_shape_releases_the_empty_slot_stat_loss() {
  for answer in [
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
    StatResult::Ok(StatEntry::new(FileKind::File)),
    StatResult::Ok(StatEntry::new(FileKind::Unknown)),
    StatResult::Failed(IoClass::NotFound),
    StatResult::Failed(IoClass::Io),
  ] {
    let mut m = per_dir();
    let s = scope(1);
    let root = live_root_idle(&mut m, s);
    let stat = pure_grow_listing_unknown(&mut m, s, root);
    assert!(
      m.stat_loss_outstanding(s),
      "staging: the loss stands before the answer ({answer:?})"
    );

    m.on_stat_result(stat, answer);
    assert!(
      !m.stat_loss_outstanding(s),
      "the answer releases the loss whatever it says: {answer:?}"
    );
    m.assert_invariants();

    // A duplicate answer for a request already spent releases nothing a second
    // time — the counter would otherwise underflow on a driver that re-reports.
    m.on_stat_result(stat, answer);
    assert!(!m.stat_loss_outstanding(s));
    m.assert_invariants();
  }
}

/// …and the one release the answer cannot perform: the stat's PARENT dies while
/// the request is still in flight. No answer can ever settle a slot that no
/// longer exists, so the parent's own teardown is the release — the same
/// `NodeMarker::StatSlots` walk that reclaims the request itself.
///
/// Mutation that kills it: release the loss only in `ingest_stat_result` and not
/// at the `StatSlots` marker. The pruned parent's hole then outlives every
/// object it described and degrades the scope's fences forever.
#[test]
fn a_parent_teardown_releases_an_outstanding_empty_slot_stat_loss() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let sub = live_child_dir(&mut m, root, "sub");
  let stat = pure_grow_listing_unknown(&mut m, s, sub);
  assert!(
    m.stat_loss_outstanding(s),
    "staging: the grow under `sub` covered `sub/mystery` with nothing"
  );

  // The consumer prunes `sub` — the slot, and with it the request, are gone.
  assert!(m.drop_watch_subtree(sub), "the prune drops the subtree");
  assert!(
    !m.stat_loss_outstanding(s),
    "the parent's teardown releases the loss its request was standing for"
  );
  m.assert_invariants();

  // And a late answer for the reclaimed request releases nothing twice.
  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );
  assert!(!m.stat_loss_outstanding(s));
  m.assert_invariants();
}

/// The dedup does not escape the loss. A stat is coalesced across every read
/// that re-encounters the name, so a slot that was OCCUPIED when the first read
/// asked — and is emptied under the standing request — books its darkness at the
/// next read with only that older request left to stand for it.
///
/// The loss therefore RISES on a coalesced queue, exactly as a deferred descent
/// upgrades. Returning silently from the dedup would leave this second read's
/// hole covered by nothing at all, which is the original defect one indirection
/// further along.
///
/// Mutation that kills it: return from `queue_stat`'s dedup without calling
/// `raise_stat_loss`. The emptied slot's window is then certified `Applied`
/// again.
#[test]
fn a_re_list_of_an_emptied_slot_raises_the_standing_stat_loss() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let sub = live_child_dir(&mut m, root, "sub");

  // Read one finds the slot OCCUPIED, so its stat stands no loss.
  assert!(m.rearm_watch_subtree(root).is_started());
  let first = grow_read(&mut m, root);
  m.on_enumerate(
    first,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable name is stat'd");
  let _ = drain_events(&mut m);
  assert!(
    !m.stat_loss_outstanding(s),
    "staging: an occupied slot degrades nothing"
  );

  // The incumbent leaves under the standing request. That retirement stands its
  // own counted cover and re-arms the root, so the window it opens is spent
  // here — the hole read two books below must be covered by nothing of its own.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(20),
  );
  let cover = grow_read(&mut m, root);
  m.on_enumerate(cover, EnumerateResult::Ok(vec![]));
  assert!(
    drain_events(&mut m).iter().any(|e| e.kind().is_rescan()),
    "the retirement's window closes with its covering Rescan"
  );
  let _ = drain_actions(&mut m);
  assert!(!m.is_watched(sub), "the removal empties the slot");
  assert!(
    !m.has_coverage_deficit(s),
    "an emptied slot is not yet darkness — nothing has claimed the name back"
  );
  assert!(
    !m.stat_loss_outstanding(s),
    "and the standing request still describes the slot as it found it: occupied"
  );

  // Read two lists the same name unclassifiable at the now-EMPTY slot: it books
  // the hole, and its stat coalesces onto the request already outstanding.
  assert!(m.rearm_watch_subtree(root).is_started());
  let second = grow_read(&mut m, root);
  m.on_enumerate(
    second,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Unknown)]),
  );
  assert!(
    drain_events(&mut m).is_empty(),
    "a pure grow over an empty slot delivers nothing at all"
  );
  assert!(
    m.has_coverage_deficit(s),
    "the second read books the hole it covered with nothing"
  );
  assert!(
    m.stat_loss_outstanding(s),
    "and the coalesced request must stand for it"
  );
  m.assert_invariants();

  // One request, one release: the raised loss clears exactly once.
  m.on_stat_result(stat, StatResult::Failed(IoClass::Io));
  assert!(!m.stat_loss_outstanding(s));
  m.assert_invariants();
}

// ---------------------------------------------------------------------------
// The RELEASE's replacement. Releasing the settlement loss ENDS an obligation,
// so it owes a cover wherever nothing else stood one — and the fine deficit
// entry whose heal is that cover everywhere else is exactly what a book
// collapsed past `DEFICIT_CAP` does not have.
// ---------------------------------------------------------------------------

/// `DEFICIT_CAP` + 1 unclassifiable names at empty slots under `dir`, delivered
/// by a PURE grow so no read, no record and no arm stands a `Rescan` of its own
/// for any of them. The book collapses to the whole-scope marker and keeps no
/// fine entry, so each returned request stands a loss with no heal behind it.
/// Returns every slot's name paired with the request that owes it.
fn collapsing_grow_listing_unknown(
  m: &mut Monitor,
  s: ScopeId,
  dir: WatchId,
) -> Vec<(Segment, ReqId)> {
  assert!(
    !m.in_bootstrap_window(s),
    "staging: the registration window closed at the scope's first settle"
  );
  assert!(m.rearm_watch_subtree(dir).is_started());
  let rearm = grow_read(m, dir);
  let unknown: Vec<DirEntry> = (0..=DEFICIT_CAP)
    .map(|i| DirEntry::new(seg(&std::format!("u{i:02}")), FileKind::Unknown))
    .collect();
  m.on_enumerate(rearm, EnumerateResult::Ok(unknown));
  let stats: Vec<(Segment, ReqId)> = drain_actions(m)
    .iter()
    .filter_map(|a| a.as_stat())
    .filter_map(|cmd| {
      cmd
        .of()
        .as_child()
        .map(|child| (child.name().clone(), cmd.req()))
    })
    .collect();
  assert_eq!(
    stats.len(),
    1 + DEFICIT_CAP,
    "every unclassifiable slot is stat'd"
  );
  assert!(
    drain_events(m).is_empty(),
    "and the route delivers nothing: no Rescan of any kind stands for the holes"
  );
  assert!(
    m.has_coverage_deficit(s),
    "the mass darkness is booked — as the whole-scope marker"
  );
  assert!(
    !m.slot_deficit_booked(s, dir, &stats[0].0),
    "and the collapse keeps NO fine entry for any settlement to heal"
  );
  stats
}

/// An empty slot that turns out to be a DIRECTORY, answered outside the
/// registration window over a COLLAPSED book: the released loss is transferred
/// to a covering `Rescan` rather than released into silence.
///
/// Every other cover this shape could rest on is absent by construction. The
/// grow is pure, so the read that listed the slot stood no `Rescan`. The install
/// is a cold `install_child`, so `remove_slot_deficit` is the only heal on the
/// path — and the collapse left it nothing to remove, so it sets neither bridge
/// bit. The request is not registration-stamped, so the suppressed-install
/// detour (which stands its own loss half) does not run. `settle_stat_slot`
/// covers what a RETIREMENT ended and there was no incumbent to retire. Until
/// this answer the window was covered by the settlement loss alone; the answer
/// releases it, so the answer owes the replacement.
///
/// Mutation that kills it: drop the transfer (return
/// `false` from `ingest_stat_result`'s resolving arm instead of
/// `stands_loss && dark_interval && !healed && …`). The directory is then
/// armed behind nothing at all, and the next fence certifies the interval its
/// contents went unrecorded in.
#[test]
fn a_collapsed_book_directory_answer_transfers_the_released_loss_to_a_rescan() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let stats = collapsing_grow_listing_unknown(&mut m, s, root);
  let (name, stat) = stats[0].clone();
  assert!(m.stat_loss_outstanding(s), "staging: the loss stands");

  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );

  assert!(
    m.child_watch(root, &name).is_some(),
    "the answer arms the directory the listing could not name"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["u00"])),
    "and the released loss becomes the slot's covering Rescan: {events:?}"
  );
  m.assert_invariants();
}

/// The same shape once the slot is proven to hold NO directory — a file, or a
/// vanish. The interval is the same interval: the slot may have been a directory
/// for all of it, and a replacement's `Removed`/`Created` records are interest-
/// and filter-subject, so a `Modified`-only subscription is told nothing by them.
/// The transfer is owed by the terminal that ends the darkness, not by the one
/// that ends it a particular way.
///
/// Mutation that kills it: restrict the transfer to answers that INSTALLED a
/// directory — `&& installed.is_some()` in the resolving arm, `false` in the
/// vanish arm. The file and the vanish then release the loss over a book with no
/// entry to heal, and the next fence certifies their interval.
#[test]
fn a_collapsed_book_non_directory_answer_transfers_the_released_loss_too() {
  for answer in [
    StatResult::Ok(StatEntry::new(FileKind::File)),
    StatResult::Failed(IoClass::NotFound),
  ] {
    let mut m = per_dir();
    let s = scope(1);
    let root = live_root_idle(&mut m, s);
    let stats = collapsing_grow_listing_unknown(&mut m, s, root);
    let (name, stat) = stats[0].clone();

    m.on_stat_result(stat, answer);

    assert!(
      m.child_watch(root, &name).is_none(),
      "nothing is watched there ({answer:?})"
    );
    let events = drain_events(&mut m);
    assert!(
      events
        .iter()
        .any(|e| e.kind().is_rescan() && e.location() == &loc(&["u00"])),
      "the released loss still becomes a covering Rescan ({answer:?}): {events:?}"
    );
    m.assert_invariants();
  }
}

/// …and the transfer does NOT fire where a heal already stands the cover. The
/// counterpart the cells above need to mean anything: a second `Rescan` over
/// every ordinary empty-slot answer would double every heal's instruction and be
/// indistinguishable from the fix working (A2 overreach).
///
/// An UNCOLLAPSED book holds the slot's fine entry, and `install_child`'s
/// `remove_slot_deficit` turns it into both bridge bits — the window's closing
/// `Rescan`, one instruction, at the root that dominates the slot.
///
/// Mutation that kills it: drop the `!healed` conjunct from the transfer. Every
/// healed empty-slot answer then stands a located `Rescan` on top of the closing
/// one it already earned.
#[test]
fn a_booked_empty_slot_answer_leaves_the_cover_to_its_heal() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let stat = pure_grow_listing_unknown(&mut m, s, root);
  assert!(
    m.slot_deficit_booked(s, root, &seg("mystery")),
    "staging: an uncollapsed book records the hole finely"
  );

  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );

  let events = drain_events(&mut m);
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
    "the heal's cover is not doubled at the slot: {events:?}"
  );
  assert!(
    !m.has_coverage_deficit(s),
    "and the heal consumed the entry it covered for"
  );
  m.assert_invariants();
}

/// …and a slot a live watch already covers earns no transfer either, however the
/// loss came to stand. A registration-stamped request over an OCCUPIED slot
/// stands the loss for the window's sake ([`StatSlot::stands_loss`]) and books
/// no darkness at all: the incumbent covered the slot for the whole interval, so
/// there is no dark interval to hand off. Standing one anyway would degrade
/// every registration that ever meets a `DT_UNKNOWN` name over ground it already
/// watches.
///
/// Mutation that kills it: drop the `incumbent.is_none()` conjunct from the
/// transfer. Every covered registration-window slot then stands a `Rescan` for a
/// window nothing was ever dark in.
#[test]
fn an_occupied_slot_answer_stands_no_transfer() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root(&mut m, s);
  let boot = read_of(&mut m, root);
  m.on_enumerate(
    boot,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
  );
  let sub = m
    .child_watch(root, &seg("sub"))
    .expect("the crawl arms sub");
  m.ack_watch(sub, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  // A re-list inside the still-open registration window cannot name `sub`'s
  // kind. The slot is OCCUPIED, so nothing books darkness — but the stamp
  // stands the loss regardless, which is the whole shape under test.
  assert!(
    m.in_bootstrap_window(s),
    "staging: the window is still open"
  );
  assert!(m.rearm_watch_subtree(root).is_started());
  let relist = grow_read(&mut m, root);
  m.on_enumerate(
    relist,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable name is stat'd whether or not it is covered");
  let _ = drain_events(&mut m);
  assert!(m.stat_loss_outstanding(s), "staging: the stamp stands it");
  assert!(
    !m.slot_deficit_booked(s, root, &seg("sub")),
    "and an occupied slot books no darkness to heal"
  );

  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(1))),
  );

  let events = drain_events(&mut m);
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["sub"])),
    "a slot that was never dark is handed nothing: {events:?}"
  );
  assert!(m.is_watched(sub), "and its incumbent is kept");
  m.assert_invariants();
}

/// The racing install: a `Created` names `(parent, name)` a directory of `node`
/// while that slot's stat is still outstanding, returning the watch it fills the
/// slot with.
///
/// The occupation every route to a filled slot reduces to, and the one whose
/// cover depends entirely on the book: `install_child`'s `remove_slot_deficit`
/// stands both bridge bits when it removes a real entry, and stands NOTHING
/// where the collapse left it no entry to remove.
fn install_racing_the_stat(
  m: &mut Monitor,
  parent: WatchId,
  name: &str,
  node: Identity,
) -> WatchId {
  m.on_os_record(
    OsRecord::new(parent, RecordKind::Created)
      .with_name(seg(name))
      .with_is_dir(true)
      .with_node(node),
    at(2),
  );
  let child = m
    .child_watch(parent, &seg(name))
    .expect("the created directory occupies the slot");
  let _ = drain_actions(m);
  let _ = drain_events(m);
  child
}

/// …but an OCCUPIED slot at the answer is not the same claim as a slot that was
/// never dark, and no reading taken at the answer can tell the two apart.
///
/// The book is collapsed, so the empty slot's `Unknown` books no fine entry and
/// the request's settlement loss is the only thing covering it. A `Created` then
/// installs the directory before the answer returns: that occupation's one cover
/// is `remove_slot_deficit`, which finds nothing to remove and stands neither
/// bridge bit. When the answer lands, the slot holds a live watch — of the very
/// directory the answer is about to confirm — while the interval BEFORE the
/// install is covered by nothing at all. Reading the fill as proof that no
/// darkness ever stood there passes the fence from degraded to certified over
/// exactly that interval.
///
/// Mutation that kills it: decide the transfer from the live slot again
/// (`incumbent.is_none()` in place of `dark_interval`). The racing install then
/// silences the answer that owes the cover.
#[test]
fn a_racing_install_over_a_collapsed_book_still_transfers_the_released_loss() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let stats = collapsing_grow_listing_unknown(&mut m, s, root);
  let (name, stat) = stats[0].clone();
  assert_eq!(
    name,
    seg("u00"),
    "staging: the first collapsed slot is `u00`"
  );

  let racing = install_racing_the_stat(&mut m, root, "u00", ident(7));
  assert!(
    !m.slot_deficit_booked(s, root, &name),
    "staging: the collapse left the occupation's heal nothing to remove"
  );
  assert!(
    m.stat_loss_outstanding(s),
    "so the standing loss is still the whole of what covers the interval"
  );

  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );

  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["u00"])),
    "the released loss still becomes the slot's covering Rescan: {events:?}"
  );
  assert_eq!(
    m.child_watch(root, &name),
    Some(racing),
    "and the answer confirms the racing install rather than replacing it"
  );
  m.assert_invariants();
}

/// …and the same race over an UNCOLLAPSED book leaves the cover to the heal that
/// stood it. The counterpart the cell above needs: a transfer that fired over
/// every filled slot would double every ordinary occupation's instruction, which
/// is indistinguishable from the fix working (A2 overreach).
///
/// The install here removes a REAL entry, so it stands both bridge bits and the
/// window closes with its `Rescan` — the cover the request's darkness was
/// waiting for, and the answer must not stand a second at the slot.
///
/// Mutation that kills it: drop `remove_slot_deficit`'s discharge of the
/// outstanding request's darkness. The heal then stands its cover and the answer
/// stands another one on top of it.
#[test]
fn a_racing_install_that_heals_the_hole_leaves_the_cover_to_its_heal() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let stat = pure_grow_listing_unknown(&mut m, s, root);
  assert!(
    m.slot_deficit_booked(s, root, &seg("mystery")),
    "staging: an uncollapsed book records the hole finely"
  );

  let racing = install_racing_the_stat(&mut m, root, "mystery", ident(7));
  assert!(
    !m.slot_deficit_booked(s, root, &seg("mystery")),
    "the racing install heals the hole, which is what stands its cover"
  );

  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(7))),
  );

  let events = drain_events(&mut m);
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
    "the heal's cover is not doubled at the slot: {events:?}"
  );
  assert_eq!(
    m.child_watch(root, &seg("mystery")),
    Some(racing),
    "and the answer confirms the racing install"
  );
  m.assert_invariants();
}

/// …and the occupation that never touches `install_child` at all is covered by
/// the same carried fact, with nothing written for it.
///
/// A paired `MovedFrom`/`MovedTo` re-keys a held subtree straight onto the dark
/// slot ([`Monitor::reparent`]): a second occupation path, which consults no
/// deficit and heals no hole whatever the book holds. Deciding the transfer at
/// the occupation instead would have had to name this site too — and the next
/// one after it.
///
/// Mutation that kills it: decide the transfer from the live slot again
/// (`incumbent.is_none()` in place of `dark_interval`). The move-in then
/// silences the answer exactly as the install does.
#[test]
fn a_move_in_occupation_still_transfers_the_released_loss() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let stats = collapsing_grow_listing_unknown(&mut m, s, root);
  let (name, stat) = stats[0].clone();
  assert_eq!(
    name,
    seg("u00"),
    "staging: the first collapsed slot is `u00`"
  );

  // A live directory elsewhere under the root, for the move to carry in.
  let d = discovered_child_dir(&mut m, root, "d");
  let read = armed_read(&mut m, d);
  m.on_enumerate(read, EnumerateResult::Ok(std::vec::Vec::new()));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("d"))
      .with_cookie(cookie(3))
      .with_is_dir(true),
    at(10),
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("u00"))
      .with_cookie(cookie(3))
      .with_is_dir(true),
    at(11),
  );
  assert_eq!(
    m.child_watch(root, &name),
    Some(d),
    "the move-in occupies the slot without passing through install_child"
  );
  assert!(
    !m.slot_deficit_booked(s, root, &name),
    "staging: and the collapsed book holds no entry it could have healed"
  );
  let _ = drain_events(&mut m);

  m.on_stat_result(stat, StatResult::Ok(StatEntry::new(FileKind::Dir)));

  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["u00"])),
    "the released loss still becomes the slot's covering Rescan: {events:?}"
  );
  assert_eq!(
    m.child_watch(root, &name),
    Some(d),
    "and the moved-in subtree keeps the slot"
  );
  m.assert_invariants();
}

/// …and the same move-in over an UNCOLLAPSED book is what a reading of the book
/// gets wrong. The entry IS recorded here, so "this hole is booked" predicts a
/// heal — and the settlement performs none: `reconcile_slot` finds the slot
/// occupied and reuses what the move-in put there, `install_child` returns at its
/// occupation check without reaching `remove_slot_deficit`, and
/// `settle_stat_slot` covers nothing for a retained incumbent. The entry is left
/// standing for a sync cookie's DISPATCH to re-signal, which an ordinary
/// set-cover reply passes nowhere near, while the loss that was covering the
/// pre-move interval has already been released.
///
/// Which is why the transfer is decided from the cover this call OBSERVED being
/// stood rather than from the book it read beforehand: a booked entry says the
/// darkness was recorded, never that anything has since covered it.
///
/// Run over every way the reconcile comes to reuse what it finds — identities
/// that MATCH, and an identity absent on either side — because the three reach
/// the same occupation check by the same `replace == false` and not one of them
/// heals. One decision covers all three.
///
/// Mutation that kills it: decide the transfer from the book again (`!booked`,
/// read before the reconcile, in place of `!healed`). The move-in then silences
/// every answer whose slot the book still holds an entry for.
#[test]
fn a_move_in_over_a_booked_hole_still_transfers_the_released_loss() {
  for (installed, answered) in [
    (Some(ident(7)), Some(ident(7))),
    (None, Some(ident(7))),
    (Some(ident(7)), None),
  ] {
    let mut m = per_dir();
    let s = scope(1);
    let root = live_root_idle(&mut m, s);
    let stat = pure_grow_listing_unknown(&mut m, s, root);
    assert!(
      m.slot_deficit_booked(s, root, &seg("mystery")),
      "staging: an uncollapsed book records the hole finely ({installed:?})"
    );

    // A live directory elsewhere under the root, for the move to carry in. Its
    // identity is the cell's parameter: the answer below either matches it or
    // cannot be compared with it.
    let mut created = OsRecord::new(root, RecordKind::Created)
      .with_name(seg("d"))
      .with_is_dir(true);
    if let Some(node) = installed {
      created = created.with_node(node);
    }
    m.on_os_record(created, at(1));
    let d = m
      .child_watch(root, &seg("d"))
      .expect("the created directory occupies its own slot");
    let read = armed_read(&mut m, d);
    m.on_enumerate(read, EnumerateResult::Ok(std::vec::Vec::new()));
    let _ = drain_actions(&mut m);
    let _ = drain_events(&mut m);

    m.on_os_record(
      OsRecord::new(root, RecordKind::MovedFrom)
        .with_name(seg("d"))
        .with_cookie(cookie(3))
        .with_is_dir(true),
      at(10),
    );
    m.on_os_record(
      OsRecord::new(root, RecordKind::MovedTo)
        .with_name(seg("mystery"))
        .with_cookie(cookie(3))
        .with_is_dir(true),
      at(11),
    );
    assert_eq!(
      m.child_watch(root, &seg("mystery")),
      Some(d),
      "the move-in occupies the slot without passing through install_child"
    );
    assert!(
      m.slot_deficit_booked(s, root, &seg("mystery")),
      "and the entry it consulted no book for is still standing, healed by nobody"
    );
    let paired = drain_events(&mut m);
    assert!(
      !paired
        .iter()
        .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
      "staging: and the pairing itself covers the slot with nothing: {paired:?}"
    );

    let mut answer = StatEntry::new(FileKind::Dir);
    if let Some(node) = answered {
      answer = answer.with_node(node);
    }
    m.on_stat_result(stat, StatResult::Ok(answer));

    let events = drain_events(&mut m);
    assert!(
      events
        .iter()
        .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
      "the released loss becomes the slot's covering Rescan ({installed:?} vs \
       {answered:?}): {events:?}"
    );
    assert_eq!(
      m.child_watch(root, &seg("mystery")),
      Some(d),
      "and the answer keeps the moved-in subtree it had no grounds to replace"
    );
    m.assert_invariants();
  }
}

/// The dedup's own escape hatch, which the loss half is allowed to take and the
/// darkness half is not.
///
/// A registration-stamped request over an OCCUPIED slot already stands the
/// scope's loss with no darkness behind it. Its incumbent then dies, and the
/// next read to list the name unclassifiable coalesces onto that same request —
/// reporting an EMPTY slot to a row whose loss is already standing. Returning at
/// the loss's idempotence would drop that report, and the answer would then
/// meet a slot a racing install had refilled with a carried fact saying the slot
/// was never dark: the release lands on nothing, over an interval no watch and
/// no book covered.
///
/// The collapse is what strips every other cover from the sequence: no fine
/// entry is booked for the emptied slot, so the refill heals nothing and the
/// answer has no heal to defer to either.
///
/// Mutation that kills it: raise the darkness BELOW the loss's early return in
/// `raise_stat_darkness`. The second read's emptiness is then lost and the
/// answer stands nothing.
#[test]
fn an_emptied_slot_raises_its_darkness_past_an_already_standing_loss() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root(&mut m, s);
  let boot = read_of(&mut m, root);

  // One armed directory plus enough unclassifiable names to COLLAPSE the book.
  let mut entries = vec![DirEntry::new(seg("sub"), FileKind::Dir)];
  entries.extend(
    (0..=DEFICIT_CAP).map(|i| DirEntry::new(seg(&std::format!("u{i:02}")), FileKind::Unknown)),
  );
  m.on_enumerate(boot, EnumerateResult::Ok(entries));
  let sub = m
    .child_watch(root, &seg("sub"))
    .expect("the crawl arms sub");
  m.ack_watch(sub, Ok(WatchAck::Installed));
  let _ = drain_actions(&mut m);
  let _ = drain_events(&mut m);
  assert!(
    m.in_bootstrap_window(s),
    "staging: sub's own unanswered read keeps the registration window open"
  );
  assert!(
    !m.slot_deficit_booked(s, root, &seg("u00")),
    "staging: and the book collapsed, so it keeps no fine entry for any slot"
  );

  // The stamped request, queued over a slot `sub` covers: the loss stands on the
  // stamp alone and the darkness half is false.
  assert!(m.rearm_watch_subtree(root).is_started());
  let relist = grow_read(&mut m, root);
  m.on_enumerate(
    relist,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Unknown)]),
  );
  let stat = drain_actions(&mut m)
    .iter()
    .find_map(|a| a.as_stat().map(|c| c.req()))
    .expect("the unclassifiable name is stat'd whether or not it is covered");
  let _ = drain_events(&mut m);
  assert!(
    m.stat_loss_outstanding(s),
    "staging: the stamp stands the loss"
  );

  // The incumbent dies under the standing request. Nothing books the darkness —
  // the book is collapsed — and the drop erased no entry, so it stood no cover.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(3),
  );
  assert!(
    m.child_watch(root, &seg("sub")).is_none(),
    "staging: the slot is empty from here"
  );
  let _ = drain_events(&mut m);

  // The read that reports it: it coalesces onto the request already standing the
  // loss, which is the return the darkness must be raised ahead of.
  assert!(m.rearm_watch_subtree(root).is_started());
  let relist = grow_read(&mut m, root);
  m.on_enumerate(
    relist,
    EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Unknown)]),
  );
  assert!(
    drain_actions(&mut m).iter().all(|a| a.as_stat().is_none()),
    "staging: the re-list coalesced onto the standing request rather than queuing a second"
  );
  let _ = drain_events(&mut m);

  let racing = install_racing_the_stat(&mut m, root, "sub", ident(9));

  m.on_stat_result(
    stat,
    StatResult::Ok(StatEntry::new(FileKind::Dir).with_node(ident(9))),
  );

  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["sub"])),
    "the emptied-then-refilled slot still earns the released loss's cover: {events:?}"
  );
  assert_eq!(
    m.child_watch(root, &seg("sub")),
    Some(racing),
    "and the answer confirms the refill"
  );
  m.assert_invariants();
}

/// …and the direction the emptiness reading fails in on its own: a vacancy some
/// other path has ALREADY covered.
///
/// A `File`/`Gone` reconcile arriving from outside the request removes the
/// slot's fine entry — which stands the covering `Rescan` for exactly this
/// vacancy and discharges the request's carried darkness — and leaves the slot
/// EMPTY, because that is what those occupants mean. An answer that read "empty,
/// therefore uncovered" would then stand a second cover over the interval the
/// first already took: a redundant epoch bump, a degraded cover state, and a
/// consumer enumeration nothing asked for. Which is why the live term asks about
/// the CURRENT VACANCY ([`StatSlot::vacancy_covered`]) rather than about
/// emptiness.
///
/// Run over every answer shape, because the question is about the vacancy and
/// not about how the answer describes it — including the DIRECTORY the answer
/// may still install, whose own arm is counted work no fence passes anyway.
///
/// Mutation that kills it: decide the live term from emptiness again
/// (`incumbent.is_none()` in place of `incumbent.is_none() && !vacancy_covered`).
/// The already-covered vacancy then earns a second `Rescan` at the slot.
#[test]
fn a_covered_vacancy_answer_stands_no_second_cover() {
  for answer in [
    StatResult::Ok(StatEntry::new(FileKind::File)),
    StatResult::Failed(IoClass::NotFound),
    StatResult::Ok(StatEntry::new(FileKind::Dir)),
  ] {
    let mut m = per_dir();
    let s = scope(1);
    let root = live_root_idle(&mut m, s);
    let stat = pure_grow_listing_unknown(&mut m, s, root);
    assert!(
      m.slot_deficit_booked(s, root, &seg("mystery")),
      "staging: an uncollapsed book records the hole finely ({answer:?})"
    );

    // The external settlement. It heals the hole, which is the one act that
    // stands the slot's cover, and it settles the slot as EMPTY.
    m.on_os_record(
      OsRecord::new(root, RecordKind::Removed).with_name(seg("mystery")),
      at(3),
    );
    assert!(
      !m.slot_deficit_booked(s, root, &seg("mystery")),
      "the reconcile healed the hole, which is what stood its cover ({answer:?})"
    );
    assert!(
      m.child_watch(root, &seg("mystery")).is_none(),
      "and the slot reads empty for the rest of the request ({answer:?})"
    );
    let stood = drain_events(&mut m);
    assert!(
      stood.iter().any(|e| e.kind().is_rescan()),
      "staging: the heal's cover is the one instruction the window earns \
       ({answer:?}): {stood:?}"
    );

    m.on_stat_result(stat, answer);

    let events = drain_events(&mut m);
    assert!(
      !events
        .iter()
        .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
      "a vacancy already handed to a cover is not covered twice ({answer:?}): {events:?}"
    );
    m.assert_invariants();
  }
}

/// …and the darkness NO read and NO cover ever touched still transfers, which is
/// the case the live term exists for and the one a narrowing to the carried fact
/// alone would lose.
///
/// A registration-stamped request over an OCCUPIED slot books no darkness — the
/// stamp is what stands its loss — and its incumbent then dies under it with
/// nothing re-listing the name. No read observes the emptiness, so the carried
/// fact stays silent; the drop erased no deficit and the emptied slot had none
/// booked, so no cover was stood for the SLOT. The slot is dark from the drop to
/// the answer and the released loss is all that was covering it.
///
/// It is also the boundary of what a teardown may be credited with. The drop
/// erases the descent this request's read booked against the dying incumbent,
/// which is a COUNTED debt, so it does emit a root `Rescan` here
/// ([`Monitor::stand_counted_cover`]) — a cover stood on a claim about an object
/// that survives somewhere unnameable, not on anything the walk did to this slot.
/// Reading it as this vacancy's cover is exactly the inference the answer is not
/// entitled to make: a walk can owe that debt having emptied nothing at all.
///
/// Two mutations kill it. Narrow the interval to the carried fact alone
/// (`dark_uncovered` in place of the disjunction) and the silently emptied slot
/// releases its loss into silence. Fold the counted debt's cover into
/// `drop_subtree`'s answer and the teardown's raise swallows this transfer too.
#[test]
fn a_silently_dropped_incumbent_still_transfers_the_released_loss() {
  for answer in [
    StatResult::Ok(StatEntry::new(FileKind::File)),
    StatResult::Failed(IoClass::NotFound),
  ] {
    let mut m = per_dir();
    let s = scope(1);
    let root = live_root(&mut m, s);
    let boot = read_of(&mut m, root);
    m.on_enumerate(
      boot,
      EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Dir)]),
    );
    let sub = m
      .child_watch(root, &seg("sub"))
      .expect("the crawl arms sub");
    m.ack_watch(sub, Ok(WatchAck::Installed));
    let _ = drain_actions(&mut m);
    let _ = drain_events(&mut m);

    // The stamped request, queued over a slot `sub` covers: the loss stands on
    // the stamp alone and the darkness half is false.
    assert!(
      m.in_bootstrap_window(s),
      "staging: sub's own unanswered read keeps the registration window open \
       ({answer:?})"
    );
    assert!(m.rearm_watch_subtree(root).is_started());
    let relist = grow_read(&mut m, root);
    m.on_enumerate(
      relist,
      EnumerateResult::Ok(vec![DirEntry::new(seg("sub"), FileKind::Unknown)]),
    );
    let stat = drain_actions(&mut m)
      .iter()
      .find_map(|a| a.as_stat().map(|c| c.req()))
      .expect("the unclassifiable name is stat'd whether or not it is covered");
    let _ = drain_events(&mut m);
    assert!(
      m.stat_loss_outstanding(s),
      "staging: the stamp stands the loss ({answer:?})"
    );
    assert!(
      !m.slot_deficit_booked(s, root, &seg("sub")),
      "staging: and an occupied slot books no darkness ({answer:?})"
    );

    // The incumbent dies under the standing request. Nothing re-lists the name
    // afterwards, so no read reports the emptiness to the request at all.
    m.on_os_record(
      OsRecord::new(root, RecordKind::Removed)
        .with_name(seg("sub"))
        .with_is_dir(true),
      at(3),
    );
    assert!(
      m.child_watch(root, &seg("sub")).is_none(),
      "staging: the slot is empty from here ({answer:?})"
    );
    assert!(
      !m.slot_deficit_booked(s, root, &seg("sub")),
      "staging: with no hole booked for anything to heal ({answer:?})"
    );
    let dropped = drain_events(&mut m);
    assert!(
      !dropped
        .iter()
        .any(|e| e.kind().is_rescan() && e.location() == &loc(&["sub"])),
      "staging: and nothing stood a cover addressed at the vacancy ({answer:?}): \
       {dropped:?}"
    );

    m.on_stat_result(stat, answer);

    let events = drain_events(&mut m);
    assert!(
      events
        .iter()
        .any(|e| e.kind().is_rescan() && e.location() == &loc(&["sub"])),
      "the released loss becomes the emptied slot's covering Rescan ({answer:?}): \
       {events:?}"
    );
    m.assert_invariants();
  }
}

/// …and a cover stood for one vacancy covers exactly that one. The edge the
/// suppressor above needs to be safe: a stale cover left standing over a FRESH
/// darkness is a missed cover, which is the expensive direction.
///
/// The slot is emptied and covered, RE-OCCUPIED — which ends the vacancy the
/// cover was stood for, healing nothing, since the entry it would have healed is
/// already gone — and then emptied again. The second vacancy is nobody's: no
/// read reports it, no removal covers it. So the answer owes it the transfer,
/// and the fact recorded for the first vacancy must not speak for it.
///
/// Mutation that kills it: drop `vacate_child_slot`'s clear (leave the raw
/// `child_index` removal). The first vacancy's cover then silences every later
/// darkness at the same slot for as long as the request stands.
#[test]
fn a_re_emptied_slot_is_a_fresh_vacancy_the_old_cover_does_not_reach() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let stat = pure_grow_listing_unknown(&mut m, s, root);
  assert!(
    m.slot_deficit_booked(s, root, &seg("mystery")),
    "staging: an uncollapsed book records the hole finely"
  );

  // The first vacancy, and the removal that covers it.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed).with_name(seg("mystery")),
    at(3),
  );
  assert!(
    !m.slot_deficit_booked(s, root, &seg("mystery")),
    "staging: the heal stood the first vacancy's cover"
  );
  let _ = drain_events(&mut m);

  // Re-occupied, then emptied again. The install heals nothing — the entry it
  // would have removed went with the cover above — so neither edge stands
  // anything for the darkness the second emptying opens.
  let refilled = install_racing_the_stat(&mut m, root, "mystery", ident(7));
  assert!(
    m.is_watched(refilled),
    "staging: the slot is occupied again"
  );
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("mystery"))
      .with_is_dir(true),
    at(4),
  );
  assert!(
    m.child_watch(root, &seg("mystery")).is_none(),
    "staging: and empty again, on a vacancy of its own"
  );
  assert!(
    !m.slot_deficit_booked(s, root, &seg("mystery")),
    "staging: with no hole booked for anything to heal"
  );
  let reopened = drain_events(&mut m);
  assert!(
    !reopened
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
    "staging: and nothing covered the fresh darkness: {reopened:?}"
  );

  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));

  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
    "the released loss covers the vacancy the earlier cover never reached: {events:?}"
  );
  m.assert_invariants();
}

/// The racing install of [`install_racing_the_stat`], brought live and given an
/// INTERIOR deficit of its own: a child slot the kernel refused to arm, booked
/// against the racing directory rather than against the slot under test.
///
/// What it stages is the parting of the two acts. The install spent the slot's
/// own fine entry, so the settlement that later empties the slot finds nothing
/// there to turn — while its TEARDOWN erases this interior hole, which is real
/// coverage and stands the scope's covering `Rescan`.
fn racing_install_carrying_a_deficit(
  m: &mut Monitor,
  s: ScopeId,
  parent: WatchId,
  name: &str,
) -> WatchId {
  let child = install_racing_the_stat(m, parent, name, ident(9));
  m.ack_watch(child, Ok(WatchAck::Installed));
  let read = read_of(m, child);
  m.on_enumerate(
    read,
    EnumerateResult::Ok(vec![DirEntry::new(seg("deep"), FileKind::Dir)]),
  );
  let deep = m
    .child_watch(child, &seg("deep"))
    .expect("the racing directory's own read arms its interior");
  m.ack_watch(deep, Err(WatchError::NoSpace));
  assert!(
    m.slot_deficit_booked(s, child, &seg("deep")),
    "staging: the refusal books an interior hole the teardown will have to erase"
  );
  assert!(
    !m.slot_deficit_booked(s, parent, &seg(name)),
    "staging: and the install spent the slot's own entry, so the removal stands nothing"
  );
  let _ = drain_actions(m);
  let _ = drain_events(m);
  child
}

/// …and the act that stands a vacancy's cover is not always the removal. The
/// emptying settlement has TWO of them, and the request must hear from either.
///
/// A directory races into the slot and spends its fine entry, then acquires an
/// interior deficit of its own. The external `File`/`Gone` reconcile that empties
/// the slot again therefore turns no entry at all — its `remove_slot_deficit`
/// answers `false` — while the TEARDOWN inside the same reconcile erases the
/// interior hole and discharges it as the scope's covering `Rescan`, root-located
/// and so dominating this slot. Read off the removal alone, the answer sees an
/// empty slot with no cover recorded and stands a second one: another epoch, and
/// a consumer enumeration the closing `Rescan` already asked for.
///
/// The vacancy is genuinely covered: the walk that stands the `Rescan` is the
/// walk that empties the slot, and a `Removed` proves the object is gone, so
/// nothing survives the cover to go on being dark.
///
/// Mutation that kills it: bind the raise to the removal again — call
/// `drop_subtree` directly from `reconcile_slot`'s `File`/`Gone` arm in place of
/// `drop_departed_occupant`.
#[test]
fn a_covering_teardown_stands_the_vacancys_cover_the_removal_cannot() {
  for answer in [
    StatResult::Ok(StatEntry::new(FileKind::File)),
    StatResult::Failed(IoClass::NotFound),
  ] {
    let mut m = per_dir();
    let s = scope(1);
    let root = live_root_idle(&mut m, s);
    let stat = pure_grow_listing_unknown(&mut m, s, root);
    let racing = racing_install_carrying_a_deficit(&mut m, s, root, "mystery");
    assert!(
      m.stat_loss_outstanding(s),
      "staging: the request still stands its loss ({answer:?})"
    );

    m.on_os_record(
      OsRecord::new(root, RecordKind::Removed)
        .with_name(seg("mystery"))
        .with_is_dir(true),
      at(6),
    );
    assert!(
      !m.is_watched(racing),
      "staging: the teardown ran ({answer:?})"
    );
    assert!(
      m.child_watch(root, &seg("mystery")).is_none(),
      "and the slot reads empty for the rest of the request ({answer:?})"
    );
    let stood = drain_events(&mut m);
    assert!(
      stood
        .iter()
        .any(|e| e.kind().is_rescan() && e.location().is_empty()),
      "staging: the teardown's discharge stands the scope's cover ({answer:?}): {stood:?}"
    );
    let epoch = m.epoch_of(s);

    m.on_stat_result(stat, answer);

    let events = drain_events(&mut m);
    assert!(
      !events
        .iter()
        .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
      "a vacancy the teardown already covered is not covered twice ({answer:?}): {events:?}"
    );
    assert_eq!(
      m.epoch_of(s),
      epoch,
      "and the consumer is charged no second enumeration ({answer:?})"
    );
    m.assert_invariants();
  }
}

/// …and the same teardown reached through the object's OWN deletion. The
/// parent-side `Removed` and the child-side `DeleteSelf` describe one departure,
/// the driver may deliver either first, and whichever arrives first performs the
/// teardown — so a raise wired only to the reconcile leaves this door open: by
/// the time the `Removed` follows, the watch is already gone and its settlement
/// finds neither a subtree to tear down nor an entry to turn.
///
/// Mutation that kills it: call `drop_subtree` directly from `on_delete_self` in
/// place of `drop_departed_occupant`.
#[test]
fn a_delete_self_teardown_stands_the_vacancys_cover_too() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let stat = pure_grow_listing_unknown(&mut m, s, root);
  let racing = racing_install_carrying_a_deficit(&mut m, s, root, "mystery");

  m.on_os_record(OsRecord::new(racing, RecordKind::DeleteSelf), at(6));
  assert!(
    m.child_watch(root, &seg("mystery")).is_none(),
    "staging: the object's own deletion empties the slot"
  );
  let stood = drain_events(&mut m);
  assert!(
    stood
      .iter()
      .any(|e| e.kind().is_rescan() && e.location().is_empty()),
    "staging: and its teardown stands the scope's cover: {stood:?}"
  );
  let epoch = m.epoch_of(s);

  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));

  let events = drain_events(&mut m);
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
    "the vacancy the deletion covered is not covered twice: {events:?}"
  );
  assert_eq!(m.epoch_of(s), epoch);
  m.assert_invariants();
}

/// …and through the third door: an unpairable move-out. A `MovedFrom` the monitor
/// cannot remember — no cookie, or a bound that refused the half — tears the
/// source subtree down where it stands and degrades to a `Removed`. The object
/// has left the slot, which is the same proof the two doors above carry, and the
/// teardown's discharge is the same covering `Rescan`.
///
/// Mutation that kills it: call `drop_subtree` directly from `on_moved_from`'s
/// unpairable arm in place of `drop_departed_occupant`.
#[test]
fn an_unpairable_move_out_teardown_stands_the_vacancys_cover_too() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let stat = pure_grow_listing_unknown(&mut m, s, root);
  let racing = racing_install_carrying_a_deficit(&mut m, s, root, "mystery");

  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedFrom)
      .with_name(seg("mystery"))
      .with_is_dir(true),
    at(6),
  );
  assert!(
    !m.is_watched(racing),
    "staging: a half that can never pair is torn down where it stands"
  );
  let stood = drain_events(&mut m);
  assert!(
    stood
      .iter()
      .any(|e| e.kind().is_rescan() && e.location().is_empty()),
    "staging: and its teardown stands the scope's cover: {stood:?}"
  );
  let epoch = m.epoch_of(s);

  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));

  let events = drain_events(&mut m);
  assert!(
    !events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
    "the vacancy the move-out covered is not covered twice: {events:?}"
  );
  assert_eq!(m.epoch_of(s), epoch);
  m.assert_invariants();
}

/// …and the overreach guard the three cells above need to mean anything: a
/// teardown that erased NOTHING stands nothing, so the vacancy it opens is still
/// the answer's to cover.
///
/// The same race, minus the interior deficit. The install spent the slot's fine
/// entry, so the removal turns none; the torn-down directory anchored no coverage,
/// so its walk discharges nothing (A2) and the `Removed` that drove it is
/// interest- and filter-subject. Nothing at all covered the emptying, and the
/// released loss is all the interval ever had.
///
/// Mutation that kills it: raise unconditionally in `drop_departed_occupant` —
/// drop the `stood` guard and mark every teardown's vacancy covered. The
/// uncovered emptying then releases its loss into silence.
#[test]
fn a_teardown_that_erased_nothing_leaves_the_vacancy_to_the_answer() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let stat = pure_grow_listing_unknown(&mut m, s, root);
  let racing = install_racing_the_stat(&mut m, root, "mystery", ident(9));
  assert!(
    !m.slot_deficit_booked(s, root, &seg("mystery")),
    "staging: the install spent the slot's own entry"
  );

  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("mystery"))
      .with_is_dir(true),
    at(6),
  );
  assert!(!m.is_watched(racing), "staging: the teardown ran");
  let quiet = drain_events(&mut m);
  assert!(
    !quiet.iter().any(|e| e.kind().is_rescan()),
    "staging: and it erased no coverage, so it stood nothing: {quiet:?}"
  );

  m.on_stat_result(stat, StatResult::Failed(IoClass::NotFound));

  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location() == &loc(&["mystery"])),
    "the released loss becomes the uncovered vacancy's Rescan: {events:?}"
  );
  m.assert_invariants();
}

/// The sibling shape the transfer deliberately does not reach, and why it is not
/// the same defect: a slot whose answer lands under a HOLD.
///
/// The degrade re-books the darkness and stands no `Rescan` — the
/// reconstruction is the vacated pre-move path, so a cover addressed there would
/// send the consumer to the slot the subtree has LEFT — and the release still
/// happens, so on the collapsed book's reasoning this too would be a release
/// with nothing behind it. It is not, and the difference is the hold itself: a
/// detached-and-held move source holds [`Monitor::coverage_settled`] DOWN for
/// exactly as long as it stands — twice over, through the held source
/// ([`Monitor::holds_settled`]) and through the parked rename half that detached
/// it ([`Monitor::moves_settled`]) — so there is no window between the release
/// and the pairing in which any fence could certify anything. The pairing then
/// stands the destination's covering `Rescan`, which the answer itself booked by
/// dirtying the hold.
///
/// Both halves are pinned together because either alone is satisfiable by a
/// mistake: a barrier that never reopens is a wedge, and a cover that never
/// stands is the defect.
///
/// Mutation that kills it: make the hold invisible to the barrier — drop BOTH
/// the `holds_settled` and `moves_settled` conjuncts of `coverage_settled`.
/// Either alone leaves the window closed, which is the redundancy this cell
/// records; with neither, the scope reads settled across the whole held window
/// and a fence resolved inside it certifies an interval whose recovery has not
/// been emitted yet.
#[test]
fn a_held_answer_hands_its_released_loss_to_a_barrier_the_hold_holds_down() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let w_d = held_move_source(&mut m, root, "d");

  // A re-arm read of the held source lists an unclassifiable name at a slot
  // nothing occupies: darkness booked, stat queued, loss stood. The read is
  // ANSWERED, so the counted work it opened is spent and the hold is the only
  // thing left holding the barrier down.
  assert!(m.rearm_watch_subtree(w_d).is_started());
  let unknown = vec![DirEntry::new(seg("u"), FileKind::Unknown)];
  let mut queued = None;
  loop {
    let actions = drain_actions(&mut m);
    if queued.is_none() {
      queued = actions.iter().find_map(|a| a.as_stat().map(|c| c.req()));
    }
    let Some(req) = actions
      .iter()
      .find_map(|a| a.as_enumerate().filter(|e| e.dir() == w_d).map(|e| e.req()))
    else {
      break;
    };
    m.on_enumerate(req, EnumerateResult::Ok(unknown.clone()));
  }
  let stat = queued.expect("the unclassifiable slot under the held source is stat'd");
  let _ = drain_events(&mut m);
  assert!(
    m.stat_loss_outstanding(s),
    "staging: the empty slot stands the loss"
  );
  assert!(
    m.rearm_settled(s),
    "staging: no counted work is outstanding — the stat is uncounted"
  );
  assert!(
    !m.coverage_settled(s),
    "staging: so the hold's own conjuncts are all that hold the barrier down"
  );

  // The answer settles nothing and may be addressed nowhere: it releases the
  // loss and stands no `Rescan` of its own.
  m.on_stat_result(stat, StatResult::Failed(IoClass::Permission));
  let events = drain_events(&mut m);
  assert!(
    events.is_empty(),
    "nothing is addressed at the vacated pre-move path: {events:?}"
  );
  assert!(
    !m.stat_loss_outstanding(s),
    "the answer released the loss, as every answer shape does"
  );
  assert!(
    !m.coverage_settled(s),
    "and the release hands off to a barrier the hold is still holding down"
  );

  // The pairing is what reopens it, and it stands the destination's cover first.
  m.on_os_record(
    OsRecord::new(root, RecordKind::MovedTo)
      .with_name(seg("e"))
      .with_cookie(cookie(1))
      .with_is_dir(true),
    at(12),
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .filter(|e| e.kind().is_rescan())
      .any(|e| e.location() == &loc(&["e"])),
    "the dirtied hold's recovery lands at the destination: {events:?}"
  );
  m.assert_invariants();
}

// ---------------------------------------------------------------------------
// The RELEASE-side twin. A settlement loss leaves `pending_stat` at exactly two
// sites — the answer's arrival and the PARENT'S DEATH — and both end the same
// obligation over the same interval, so both owe the same replacement. The
// cells above pin the answer's; these pin the reclamation's, which every
// discharge table already calls discharged because the COUNTER is released
// there. The counter is not the obligation.
// ---------------------------------------------------------------------------

/// A loss-standing stat under `dir` whose booked darkness the DISPATCH
/// RE-SIGNAL has already spent — the second way the fine entry can be missing
/// when the request's parent dies, and the one no collapse is needed for.
///
/// The re-signal's `Rescan` covers changes up to itself and no further: the slot
/// is still dark behind it, the request is still outstanding, and the entry a
/// later erasure could have discharged is gone. Its heal kick is completed and
/// its window spent here, so nothing it stood is left for a later drop to ride.
fn resignalled_grow_listing_unknown(m: &mut Monitor, s: ScopeId, dir: WatchId) -> ReqId {
  let stat = pure_grow_listing_unknown(m, s, dir);
  assert!(
    m.slot_deficit_booked(s, dir, &seg("mystery")),
    "staging: an uncollapsed book records the hole finely"
  );
  assert!(
    m.resignal_coverage_deficits(s),
    "the dispatch re-signal fires the hole's Rescan and clears the entry"
  );
  let heal = grow_read(m, dir);
  m.on_enumerate(heal, EnumerateResult::Ok(vec![]));
  let _ = drain_actions(m);
  let _ = drain_events(m);
  assert!(
    !m.has_coverage_deficit(s),
    "staging: the book now holds nothing for any erasure to discharge"
  );
  assert!(
    m.stat_loss_outstanding(s),
    "while the request — and the darkness it carries — still stands"
  );
  stat
}

/// The parent of an unanswered loss-standing stat DEPARTS, over a book that
/// collapsed past `DEFICIT_CAP` and so kept no fine entry to erase.
///
/// The reclamation releases the loss — no answer can ever reach a slot that no
/// longer exists — and a release owes the darkness a cover. Every other
/// candidate is absent by construction: the `Deficits` marker erases nothing (a
/// collapsed book holds no fine entry), the parent-side removal turns none
/// either, the grow that opened the window was pure, and the `Removed` that drove
/// the teardown is interest- and filter-subject. Until this record the interval
/// was covered by the settlement loss alone.
///
/// Mutation that kills it: answer `ErasedCover::Nothing` from the `StatSlots`
/// reclaim. The scope then reads settled and unlossy over an interval in which
/// `sub/u00` may have been a directory nothing watched and nothing announced.
#[test]
fn a_departing_parent_transfers_a_collapsed_books_released_stat_loss() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let sub = live_child_dir(&mut m, root, "sub");
  let _stats = collapsing_grow_listing_unknown(&mut m, s, sub);
  assert!(
    m.stat_loss_outstanding(s),
    "staging: the mass darkness is covered by the standing requests alone"
  );
  assert!(
    m.coverage_settled(s),
    "staging: and nothing counted holds the barrier down meanwhile"
  );

  // The parent leaves. Its slots die with it, so no answer can ever arrive.
  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(20),
  );

  assert!(!m.is_watched(sub), "the removal tears the parent down");
  assert!(
    !m.stat_loss_outstanding(s),
    "and reclaims every request it was holding, releasing the loss with them"
  );
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location().is_empty()),
    "so the released loss becomes the scope's covering Rescan: {events:?}"
  );
  m.assert_invariants();
}

/// …and the same departure over an UNCOLLAPSED book whose entry a dispatch
/// re-signal already spent. The two shapes are one defect: what the reclamation
/// can lean on is not "a deficit was booked" but "an erasure happened here", and
/// an entry cleared optimistically at a cookie's dispatch leaves the walk
/// nothing to erase while the slot stays exactly as dark as it was.
///
/// Mutation that kills it: answer `ErasedCover::Nothing` from the `StatSlots`
/// reclaim. The interval AFTER the re-signal — which its `Rescan` does not
/// reach, and which the request was still standing for — passes from a degraded
/// fence to a certified one at the teardown.
#[test]
fn a_departing_parent_transfers_a_released_stat_loss_the_resignal_already_spent() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let sub = live_child_dir(&mut m, root, "sub");
  let _stat = resignalled_grow_listing_unknown(&mut m, s, sub);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(20),
  );

  assert!(!m.is_watched(sub), "the removal tears the parent down");
  assert!(!m.stat_loss_outstanding(s), "releasing the standing loss");
  let events = drain_events(&mut m);
  assert!(
    events
      .iter()
      .any(|e| e.kind().is_rescan() && e.location().is_empty()),
    "which the reclamation hands to the scope's covering Rescan: {events:?}"
  );
  m.assert_invariants();
}

/// …and the overreach guard the two cells above need to mean anything: a
/// reclaimed request whose darkness was already COVERED hands over nothing.
///
/// The transfer is owed for the interval the slot spent dark, never for the
/// counter's release as such — so the question at the reclamation is the answer's
/// question, asked of the same two facts the request carries. Here a racing
/// `Created` healed the booked hole, which stood the window's closing `Rescan`
/// and discharged the request's claim; the slot has held a live watch ever since.
/// Standing a second cover would charge the scope an epoch and a full
/// re-enumeration for an interval already handed to the first — the cost every
/// spurious cover carries, and the reason the release-side test is not merely
/// "did a loss stand".
///
/// Mutation that kills it: discharge every reclaimed loss-standing row
/// (`ErasedCover::Discharge` whenever `standing > 0`). The healed slot then
/// re-covers on every teardown that meets it.
#[test]
fn a_departing_parents_covered_darkness_stands_no_second_cover() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let sub = live_child_dir(&mut m, root, "sub");
  let _stat = pure_grow_listing_unknown(&mut m, s, sub);
  let racing = install_racing_the_stat(&mut m, sub, "mystery", ident(7));
  assert!(
    !m.slot_deficit_booked(s, sub, &seg("mystery")),
    "staging: the racing install healed the hole, which is what stood its cover"
  );
  assert!(
    m.stat_loss_outstanding(s),
    "staging: the loss stands on until the answer or the parent releases it"
  );
  let epoch = m.epoch_of(s);

  m.on_os_record(
    OsRecord::new(root, RecordKind::Removed)
      .with_name(seg("sub"))
      .with_is_dir(true),
    at(20),
  );

  assert!(!m.is_watched(sub), "the removal tears the parent down");
  assert!(!m.is_watched(racing), "and the racing install with it");
  assert!(
    !m.stat_loss_outstanding(s),
    "releasing the loss the request was standing"
  );
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_rescan()),
    "an interval the heal already covered is not covered twice: {events:?}"
  );
  assert_eq!(
    m.epoch_of(s),
    epoch,
    "and the consumer is charged no second enumeration"
  );
  m.assert_invariants();
}

/// The erasure is REPORTED, never placed: the walk's own [`DeficitDischarge`]
/// decides what it is worth, and a terminal reason stands nothing.
///
/// Both terminal reasons, over the shape that has nothing BUT the reclaimed
/// darkness to discharge. A proven-unsubscribed prune has no subscriber to lie
/// to, and an unregistered scope has no barrier left at all — the caller's own
/// terminal `Rescan` and whole-book wipe own coverage from there. Forcing a cover
/// onto either would be a `Rescan` for a scope nobody is watching, which is the
/// failure the reason argument exists to prevent.
///
/// Mutation that kills it: emit the covering `Rescan` at the `StatSlots` reclaim
/// itself instead of returning `ErasedCover::Discharge` for the discharge to
/// place.
#[test]
fn a_terminal_reason_stands_nothing_for_the_reclaimed_darkness() {
  // The proven-unsubscribed prune.
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let sub = live_child_dir(&mut m, root, "sub");
  let _stat = resignalled_grow_listing_unknown(&mut m, s, sub);

  assert!(m.drop_watch_subtree(sub), "the prune drops the subtree");
  assert!(
    !m.stat_loss_outstanding(s),
    "which releases the loss the same way"
  );
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_rescan()),
    "but coverage outside every committed subscription is owed nothing: {events:?}"
  );
  m.assert_invariants();

  // The scope's own teardown.
  let mut m = per_dir();
  let root = live_root_idle(&mut m, s);
  let sub = live_child_dir(&mut m, root, "sub");
  let _stat = resignalled_grow_listing_unknown(&mut m, s, sub);

  m.unregister_root(s);
  assert!(!m.stat_loss_outstanding(s), "the teardown releases it too");
  let events = drain_events(&mut m);
  assert!(
    !events.iter().any(|e| e.kind().is_rescan()),
    "and a scope that is gone has no barrier left to hand anything to: {events:?}"
  );
  m.assert_invariants();
}

/// …and the third reason CARRIES it instead of covering it. A crawl rebuild's
/// non-survivor branch has no coverage story of its own, so what it does with an
/// erased cover is re-anchor it as a slot hole at the SURVIVING parent — the same
/// coarser coordinate every deficit erased inside the dropped subtree lands on.
///
/// The listing omits `sub`, so the crawl retires it and rebuilds nothing there:
/// the hole stays booked for the dispatch re-signal until the vanish's `Removed`
/// converges it, which is exactly what the darkness of a slot beneath `sub`
/// needs. The crawl's own opening `Rescan` covers the retirement; it does not
/// cover a dark interval that outlives it, and the book is what does.
///
/// Mutation that kills it: answer `ErasedCover::Nothing` from the `StatSlots`
/// reclaim. The re-anchor then fires only for subtrees that happened to still
/// hold a fine entry, and this darkness leaves no trace at all.
#[test]
fn a_crawl_rebuild_re_anchors_the_reclaimed_darkness_at_the_surviving_parent() {
  let mut m = per_dir();
  let s = scope(1);
  let root = live_root_idle(&mut m, s);
  let sub = live_child_dir(&mut m, root, "sub");
  let _stat = resignalled_grow_listing_unknown(&mut m, s, sub);

  // A grow of the ROOT whose listing no longer names `sub`: the crawl retires it
  // through the rebuild branch rather than through any record.
  assert!(m.rearm_watch_subtree(root).is_started());
  let crawl = grow_read(&mut m, root);
  m.on_enumerate(crawl, EnumerateResult::Ok(vec![]));

  assert!(!m.is_watched(sub), "the crawl retires the vanished name");
  assert!(!m.stat_loss_outstanding(s), "releasing the standing loss");
  assert!(
    m.slot_deficit_booked(s, root, &seg("sub")),
    "and the darkness it was standing for is re-anchored at the surviving parent"
  );
  m.assert_invariants();
}
