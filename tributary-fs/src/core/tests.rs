use super::*;
use std::time::Duration;

const WINDOW: Duration = Duration::from_millis(100);

fn at(ms: u64) -> Instant {
  Instant::from_origin(Duration::from_millis(ms))
}

fn ev(path: &str, flags: FsEventFlags, event_id: u64, file_id: u64) -> RawOsEvent {
  RawOsEvent {
    path: PathBuf::from(path),
    flags,
    event_id,
    file_id: NonZeroU64::new(file_id),
  }
}

fn flags(bits: &[FsEventFlags]) -> FsEventFlags {
  FsEventFlags::new(bits.iter().fold(0, |acc, f| acc | f.bits()))
}

fn drain(core: &mut DriverCore) -> Vec<Effect> {
  let mut out = Vec::new();
  while let Some(effect) = core.poll_effect() {
    out.push(effect);
  }
  out
}

fn emits(effects: &[Effect]) -> Vec<&Change> {
  effects
    .iter()
    .filter_map(|e| match e {
      Effect::Emit { change, .. } => Some(change),
      _ => None,
    })
    .collect()
}

fn probes(effects: &[Effect]) -> Vec<(ProbeId, PathBuf)> {
  effects
    .iter()
    .filter_map(|e| match e {
      Effect::Probe { probe, path } => Some((*probe, path.clone())),
      _ => None,
    })
    .collect()
}

/// A mount refresh whose root is still ALIVE at identity `(1, 1)` — the shared
/// identity every `live_core` scope spawns with — so the mount-trust suites
/// exercise device trust without tripping the folded-in root-death check.
fn alive_refresh(mounts: Vec<PathBuf>, authoritative: bool) -> MountRefresh {
  MountRefresh {
    mounts,
    authoritative,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
  }
}

/// A core with one live scope rooted at `/r` on device 1, its birth refresh
/// fed (an authoritative empty table): event-side trust is open.
fn live_core() -> (DriverCore, ScopeId) {
  let mut core = DriverCore::new(WINDOW);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let effects = drain(&mut core);
  assert!(
    matches!(effects.as_slice(), [Effect::SpawnStream { root, .. }] if root == Path::new("/r")),
    "registration spawns the stream: {effects:?}"
  );
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      mounts: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    }),
  );
  let effects = drain(&mut core);
  assert_eq!(
    refresh_requests(&effects),
    1,
    "a spawned scope is born closed and arms its birth refresh: {effects:?}"
  );
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
  assert!(drain(&mut core).is_empty(), "a refreshed KR root is silent");
  (core, scope)
}

/// A live core whose birth refresh could NOT read the mount table: device
/// boundaries stay unknown, so event-side identity/cookie trust is refused.
fn live_core_blind_mounts() -> (DriverCore, ScopeId) {
  let mut core = DriverCore::new(WINDOW);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      mounts: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    }),
  );
  let _ = drain(&mut core);
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), false), at(0));
  assert!(drain(&mut core).is_empty());
  (core, scope)
}

fn loc(parts: &[&str]) -> Location {
  Location::from_segments(parts.iter().map(|p| Segment::new(*p)))
}

#[test]
fn single_verb_flags_ground_directly() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev(
        "/r/a/new.txt",
        flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_IS_FILE]),
        1,
        10,
      ),
      ev("/r/a/gone.txt", flags(&[FsEventFlags::ITEM_REMOVED]), 2, 0),
      ev("/r/a/hot.txt", flags(&[FsEventFlags::ITEM_MODIFIED]), 3, 11),
      ev(
        "/r/a/meta.txt",
        flags(&[FsEventFlags::ITEM_XATTR_MOD]),
        4,
        12,
      ),
    ],
    at(1),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 4, "{effects:?}");
  assert!(emitted[0].kind().is_created());
  assert_eq!(emitted[0].location(), &loc(&["a", "new.txt"]));
  assert!(emitted[1].kind().is_removed());
  assert!(emitted[2].kind().is_modified());
  assert!(
    emitted[3].kind().is_modified(),
    "attrib conflates into modified at the change level"
  );
}

#[test]
fn flagless_event_escalates_located_rescan() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/dirty", FsEventFlags::new(0), 1, 0)],
    at(1),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["dirty"]));
}

#[test]
fn multi_verb_word_probes_and_grounds_on_present() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/x",
      flags(&[
        FsEventFlags::ITEM_CREATED,
        FsEventFlags::ITEM_REMOVED,
        FsEventFlags::ITEM_MODIFIED,
      ]),
      1,
      7,
    )],
    at(1),
  );
  let effects = drain(&mut core);
  assert!(emits(&effects).is_empty(), "nothing emits before the probe");
  let reqs = probes(&effects);
  assert_eq!(reqs.len(), 1);
  assert_eq!(reqs[0].1, PathBuf::from("/r/x"));

  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(7),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(
    emitted[0].kind().is_created(),
    "a create-ish flag on an existing object grounds as Created"
  );
}

#[test]
fn multi_verb_word_grounds_missing_as_removed() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/x",
      flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_REMOVED]),
      1,
      7,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  let emitted_effects = drain(&mut core);
  let emitted = emits(&emitted_effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_removed());
}

#[test]
fn probe_failure_escalates_located_rescan() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/denied",
      flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_MODIFIED]),
      1,
      7,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(reqs[0].0, ProbeOutcome::Failed, at(2));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["denied"]));
}

#[test]
fn same_batch_rename_pair_grounds_by_probes_into_single_moved() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev(
        "/r/a/old",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        10,
        42,
      ),
      ev(
        "/r/b/new",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        11,
        42,
      ),
    ],
    at(1),
  );
  // No pre-pairing exists: every rename half probes, and the probes' device
  // evidence decides the cookies that let the Monitor pair them.
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2, "both halves of a same-batch pair probe");
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 2, "{effects:?}");
  assert_eq!(emitted[0].kind().moved_from(), Some(&loc(&["a", "old"])));
  assert_eq!(emitted[0].location(), &loc(&["b", "new"]));
  // FSEvents has no rename token, so an evidence-granted pair always wears
  // its covering rescan (here at the halves' deepest common ancestor — the
  // root): a same-batch inode reuse that satisfied every proof would
  // mis-pair, and the cover is what keeps that recoverable.
  assert!(
    emitted[1].kind().is_rescan() && emitted[1].location() == &loc(&[]),
    "{emitted:?}"
  );
  assert_eq!(core.poll_timeout(), None, "pairing consumed both halves");
}

#[test]
fn lone_vanished_rename_half_degrades_to_immediate_removal() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/a/left",
      flags(&[FsEventFlags::ITEM_RENAMED]),
      10,
      42,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 1);
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  // A vanished path has no contemporaneous device evidence and no same-batch
  // partner evidenced its fileID, so no cookie is minted: the Monitor
  // resolves the half immediately instead of holding a pairing window.
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "{effects:?}");
  assert!(emitted[0].kind().is_removed());
  assert_eq!(emitted[0].location(), &loc(&["a", "left"]));
  assert_eq!(core.poll_timeout(), None, "no cookie, no window");
}

#[test]
fn cross_batch_vanished_source_degrades_to_remove_plus_create() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/a/old", flags(&[FsEventFlags::ITEM_RENAMED]), 10, 42)],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(
    emitted[0].kind().is_removed(),
    "no same-batch partner evidence: the vanished source resolves now"
  );

  core.on_batch_events(
    scope,
    vec![ev("/r/b/new", flags(&[FsEventFlags::ITEM_RENAMED]), 11, 42)],
    at(10),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(11),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "{effects:?}");
  assert!(
    emitted[0].kind().is_created(),
    "the destination half finds no pending source and arrives fresh"
  );
  assert_eq!(emitted[0].location(), &loc(&["b", "new"]));
}

#[test]
fn appeared_directory_move_in_creates_and_rescans_subtree() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/incoming",
      flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_DIR]),
      10,
      42,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::Dir,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 2, "{effects:?}");
  assert!(
    emitted[0].kind().is_created(),
    "an unpaired destination half is a fresh arrival"
  );
  assert!(
    emitted[1].kind().is_rescan(),
    "an appeared directory delivered no child events — rescan it"
  );
  assert_eq!(emitted[1].location(), &loc(&["incoming"]));
}

#[test]
fn cookieless_rename_half_degrades_immediately() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/anon", flags(&[FsEventFlags::ITEM_RENAMED]), 10, 0)],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(
    emitted[0].kind().is_removed(),
    "a cookie-less source half cannot pair and resolves now"
  );
  assert_eq!(
    core.poll_timeout(),
    None,
    "no window for a cookie-less half"
  );
}

#[test]
fn parked_root_queues_later_batches_in_order() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/first",
      flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_REMOVED]),
      1,
      5,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 1);

  // A later batch must not overtake the parked one.
  core.on_batch_events(
    scope,
    vec![ev("/r/second", flags(&[FsEventFlags::ITEM_CREATED]), 2, 6)],
    at(2),
  );
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "the queued batch waits behind the probe"
  );

  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(5),
      dev: 1,
    },
    at(3),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 2, "{effects:?}");
  assert_eq!(emitted[0].location(), &loc(&["first"]));
  assert_eq!(emitted[1].location(), &loc(&["second"]));
}

#[test]
fn root_overflow_drops_parked_work_under_the_rescan() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/pending",
      flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_REMOVED]),
      1,
      5,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));

  core.on_root_overflow(scope, at(2));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &Location::new());

  // The cancelled probe's late result is ignored, not misapplied.
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(3));
  assert!(emits(&drain(&mut core)).is_empty());
}

#[test]
fn must_scan_subdirs_clamps_to_descent_or_root() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/deep/dir", FsEventFlags::MUST_SCAN_SUBDIRS, 1, 0)],
    at(1),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["deep", "dir"]));

  // Hierarchical coalescing can put the path ABOVE the root (even "/").
  core.on_batch_events(
    scope,
    vec![ev("/", FsEventFlags::MUST_SCAN_SUBDIRS, 2, 0)],
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(
    emitted[0].location(),
    &Location::new(),
    "clamped to the root"
  );
}

#[test]
fn drops_and_id_wrap_rescan_the_whole_root() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/",
      flags(&[FsEventFlags::MUST_SCAN_SUBDIRS, FsEventFlags::USER_DROPPED]),
      1,
      0,
    )],
    at(1),
  );
  let emitted_effects = drain(&mut core);
  let emitted = emits(&emitted_effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert!(!core.resume_poisoned(scope));

  core.on_batch_events(
    scope,
    vec![ev("/", FsEventFlags::EVENT_IDS_WRAPPED, 2, 0)],
    at(2),
  );
  let emitted_effects = drain(&mut core);
  assert_eq!(emits(&emitted_effects).len(), 1);
  assert!(
    core.resume_poisoned(scope),
    "a wrap poisons the resume token"
  );
}

#[test]
fn root_changed_missing_is_delete_self() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r", FsEventFlags::ROOT_CHANGED, 0, 0)],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 1);
  assert_eq!(reqs[0].1, PathBuf::from("/r"));

  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 2, "{effects:?}");
  assert!(
    emitted[0].kind().is_removed(),
    "a deleted root is a Removed"
  );
  assert!(emitted[1].kind().is_rescan(), "root death is never silent");
  assert!(
    effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
    "the dead root's stream is torn down: {effects:?}"
  );
}

#[test]
fn root_changed_present_is_move_self() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r", FsEventFlags::ROOT_CHANGED, 0, 0)],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::Dir,
      file_id: NonZeroU64::new(9),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "{effects:?}");
  assert!(
    emitted[0].kind().is_rescan(),
    "a moved root rescans, no Removed"
  );
  assert!(
    effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { .. })),
  );
}

/// Root-death-via-refresh (design §7, the fanotify unmount gap): a refresh that
/// finds the root MISSING lowers exactly like a `RootChanged`-probe resolving
/// `Missing` — a terminal Removed + Rescan, then the scope's teardown. This is
/// the kernel-recursive backends' only unmount/replace detection (no in-tree
/// signal), riding the refresh cadence (birth + every loss) with no new timer.
#[test]
fn refresh_finding_root_gone_is_delete_self() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: Vec::new(),
      authoritative: true,
      root: RootLiveness::Missing,
    },
    at(5),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 2, "{effects:?}");
  assert!(emitted[0].kind().is_removed(), "a gone root is a Removed");
  assert!(emitted[1].kind().is_rescan(), "root death is never silent");
  assert!(
    effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
    "the dead root's stream is torn down: {effects:?}"
  );
}

/// A refresh finding the root REPLACED (present, different identity) or
/// UNREADABLE lowers like a `RootChanged`-probe resolving `Present`/`Failed`: a
/// terminal Rescan (no Removed) and teardown.
#[test]
fn refresh_finding_root_replaced_is_move_self() {
  for root in [
    RootLiveness::Present(crate::os::RootIdentity::new(1, 999)),
    RootLiveness::Unreadable,
  ] {
    let (mut core, scope) = live_core();
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root,
      },
      at(5),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{root:?}: {effects:?}");
    assert!(
      emitted[0].kind().is_rescan(),
      "{root:?}: a replaced/unreadable root rescans, no Removed",
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "{root:?}: the dead scope tears down",
    );
  }
}

/// A refresh finding the root still ALIVE (same identity) is NOT a death: the
/// folded-in liveness check is inert on the healthy path — no emission, no
/// teardown — and the mount trust it carries still installs (a later loss no
/// longer re-arms once authority is back).
#[test]
fn refresh_finding_root_alive_only_updates_trust() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: vec![PathBuf::from("/r/vol")],
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    },
    at(5),
  );
  let effects = drain(&mut core);
  assert!(
    !effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { .. }) | matches!(e, Effect::Emit { .. })),
    "an alive root neither dies nor emits: {effects:?}"
  );
}

#[test]
fn unmount_at_root_ends_the_scope() {
  let (mut core, scope) = live_core();
  core.on_batch_events(scope, vec![ev("/r", FsEventFlags::UNMOUNT, 1, 0)], at(1));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert!(
    effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
  );
}

#[test]
fn mount_under_root_rescans_and_degrades_identity() {
  let (mut core, scope) = live_core();
  core.on_batch_events(scope, vec![ev("/r/vol", FsEventFlags::MOUNT, 1, 0)], at(1));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));
}

#[test]
fn source_fatal_invalidates_the_root() {
  let (mut core, scope) = live_core();
  core.on_source_fatal(scope, at(1));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert!(
    effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
  );
}

#[test]
fn unwatch_tears_down_and_silences_the_scope() {
  let (mut core, scope) = live_core();
  core.on_unwatch(scope);
  let effects = drain(&mut core);
  assert!(
    effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
  );
  core.on_batch_events(
    scope,
    vec![ev("/r/late", flags(&[FsEventFlags::ITEM_CREATED]), 9, 9)],
    at(5),
  );
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "a dead scope feeds nothing"
  );
}

#[test]
fn consumer_lag_parks_one_dominating_rescan() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/a", flags(&[FsEventFlags::ITEM_CREATED]), 1, 3)],
    at(1),
  );
  let effects = drain(&mut core);
  let first = match &effects[..] {
    [Effect::Emit { change, .. }] => change.clone(),
    other => panic!("expected one emit: {other:?}"),
  };

  // The consumer refused it: the core bumps the epoch and parks the Rescan.
  core.on_delivery(scope, Delivery::Refused, at(2));
  // Changes produced while lagged are dominated and dropped.
  core.on_batch_events(
    scope,
    vec![ev("/r/b", flags(&[FsEventFlags::ITEM_CREATED]), 2, 4)],
    at(3),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "only the parked Rescan is offered: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert!(emitted[0].epoch() > first.epoch(), "the Rescan dominates");

  // Refused again: no synchronous re-offer (that would spin the executing
  // loop while the channel cannot drain); the retry rides the core's timer.
  core.on_delivery(scope, Delivery::Refused, at(4));
  assert!(emits(&drain(&mut core)).is_empty(), "no immediate re-offer");
  let retry = core.poll_timeout().expect("the refusal arms a retry timer");
  core.on_timeout(retry);
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "the retry re-offers the parked Rescan");
  assert!(emitted[0].kind().is_rescan());

  // Accepted: the scope returns to normal flow.
  core.on_delivery(scope, Delivery::Accepted, at(40));
  core.on_batch_events(
    scope,
    vec![ev("/r/c", flags(&[FsEventFlags::ITEM_CREATED]), 3, 5)],
    at(41),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_created());
}

#[test]
fn newer_rescan_replaces_the_parked_one() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/a", flags(&[FsEventFlags::ITEM_CREATED]), 1, 3)],
    at(1),
  );
  let _ = drain(&mut core);
  core.on_delivery(scope, Delivery::Refused, at(2));
  let offered = emits(&drain(&mut core))
    .first()
    .map(|c| c.epoch())
    .expect("a parked rescan is offered");

  // A fresh loss while the offer is in flight mints a newer dominating
  // Rescan; the old acceptance must not end the lag.
  core.on_root_overflow(scope, at(3));
  core.on_delivery(scope, Delivery::Accepted, at(4));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the newer Rescan is re-offered: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert!(emitted[0].epoch() > offered);

  core.on_delivery(scope, Delivery::Accepted, at(5));
  core.on_batch_events(
    scope,
    vec![ev("/r/d", flags(&[FsEventFlags::ITEM_CREATED]), 9, 9)],
    at(6),
  );
  assert_eq!(emits(&drain(&mut core)).len(), 1, "flow resumed");
}

#[test]
fn identity_minting_respects_devices_and_mounts() {
  let state = ScopeState {
    watch: WatchId::new(NonZeroU64::new(1).unwrap()),
    profile: BackendKind::FsEvents,
    requested: PathBuf::from("/r"),
    root: Some(Arc::new(PathBuf::from("/r"))),
    root_dev: Some(1),
    identity: Some(crate::os::RootIdentity::new(1, 1)),
    mounts: vec![PathBuf::from("/r/vol")],
    mounts_authoritative: true,
    refresh_pending: false,
    refresh_stale: false,
    lag: LagState::Normal,
    park: Park::default(),
    resume_poisoned: false,
  };
  let fid = NonZeroU64::new(7);
  assert!(mint(&state, Path::new("/r/a"), fid, None).is_some());
  assert!(mint(&state, Path::new("/r/a"), fid, Some(1)).is_some());
  assert!(
    mint(&state, Path::new("/r/a"), fid, Some(2)).is_none(),
    "a foreign device never mints"
  );
  assert!(
    mint(&state, Path::new("/r/vol/x"), fid, None).is_none(),
    "a foreign-mount prefix never mints"
  );
  assert!(mint(&state, Path::new("/r/a"), None, Some(1)).is_none());
}

#[test]
fn blind_mount_table_refuses_event_side_trust() {
  let state = ScopeState {
    watch: WatchId::new(NonZeroU64::new(1).unwrap()),
    profile: BackendKind::FsEvents,
    requested: PathBuf::from("/r"),
    root: Some(Arc::new(PathBuf::from("/r"))),
    root_dev: Some(1),
    identity: Some(crate::os::RootIdentity::new(1, 1)),
    mounts: Vec::new(),
    mounts_authoritative: false,
    refresh_pending: false,
    refresh_stale: false,
    lag: LagState::Normal,
    park: Park::default(),
    resume_poisoned: false,
  };
  let fid = NonZeroU64::new(7);
  assert!(
    mint(&state, Path::new("/r/a"), fid, None).is_none(),
    "an unseeded table proves nothing about devices"
  );
  assert!(
    cookie_for(&state, fid, 2).is_none(),
    "a cookie needs live root-device probe evidence"
  );
  assert!(
    cookie_for(&state, fid, 1).is_some(),
    "root-device probe evidence mints regardless of the table"
  );
  assert!(
    mint(&state, Path::new("/r/a"), fid, Some(1)).is_some(),
    "probe-carried device evidence still decides"
  );
}

#[test]
fn probed_foreign_device_is_learned_as_a_mount() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/vol/x",
      flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_MODIFIED]),
      1,
      5,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(5),
      dev: 99,
    },
    at(2),
  );
  let _ = drain(&mut core);
  let state = core.scopes.get(&scope).expect("scope lives");
  assert!(
    state.mounts.iter().any(|m| m == Path::new("/r/vol/x")),
    "the foreign device's prefix is remembered: {:?}",
    state.mounts
  );
}

#[test]
fn outside_and_invalid_paths_escalate_to_root_rescan() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/elsewhere/x",
      flags(&[FsEventFlags::ITEM_CREATED]),
      1,
      5,
    )],
    at(1),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &Location::new());

  // A prefix that matches mid-component is NOT under the root.
  core.on_batch_events(
    scope,
    vec![ev("/rextra/x", flags(&[FsEventFlags::ITEM_CREATED]), 2, 6)],
    at(2),
  );
  let effects = drain(&mut core);
  assert!(emits(&effects)[0].kind().is_rescan());
}

#[cfg(unix)]
#[test]
fn non_utf8_segment_escalates_to_root_rescan() {
  use std::{ffi::OsString, os::unix::ffi::OsStringExt};
  let (mut core, scope) = live_core();
  let path = PathBuf::from(OsString::from_vec(b"/r/\xff\xfe".to_vec()));
  core.on_batch_events(
    scope,
    vec![RawOsEvent {
      path,
      flags: flags(&[FsEventFlags::ITEM_CREATED]),
      event_id: 1,
      file_id: NonZeroU64::new(5),
    }],
    at(1),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &Location::new());
}

#[test]
fn history_done_is_swallowed() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/x", FsEventFlags::HISTORY_DONE, 1, 0)],
    at(1),
  );
  assert!(emits(&drain(&mut core)).is_empty());
}

#[test]
fn lag_entry_purges_the_scopes_queued_emits() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev("/r/a", flags(&[FsEventFlags::ITEM_CREATED]), 1, 10),
      ev("/r/b", flags(&[FsEventFlags::ITEM_CREATED]), 2, 11),
      ev("/r/c", flags(&[FsEventFlags::ITEM_CREATED]), 3, 12),
    ],
    at(1),
  );

  // Deliver only the first queued emit; the rest stay queued behind it.
  let first = core.poll_effect();
  assert!(
    matches!(first, Some(Effect::Emit { .. })),
    "the first change is offered: {first:?}"
  );
  core.on_delivery(scope, Delivery::Refused, at(2));

  // Everything still queued was dominated the moment the refusal minted the
  // Rescan; the only emit left offerable is that Rescan itself.
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the queued ordinary emits are purged: {effects:?}"
  );
  assert!(
    emitted[0].kind().is_rescan(),
    "the parked dominating Rescan is the sole offer"
  );

  // Accepting it ends the lag; later changes flow again.
  core.on_delivery(scope, Delivery::Accepted, at(3));
  core.on_batch_events(
    scope,
    vec![ev("/r/d", flags(&[FsEventFlags::ITEM_CREATED]), 4, 13)],
    at(4),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1);
  assert!(emitted[0].kind().is_created());
}

#[test]
fn teardown_flushes_a_parked_rescan() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/a", flags(&[FsEventFlags::ITEM_CREATED]), 1, 10)],
    at(1),
  );
  let first = core.poll_effect();
  assert!(matches!(first, Some(Effect::Emit { .. })));
  core.on_delivery(scope, Delivery::Refused, at(2));

  // The root dies while the scope is lagged: the terminal Rescan replaces the
  // parked one, and the teardown must still surface it — a consumer that
  // never learns its coverage ended is the silent-loss failure mode.
  core.on_source_fatal(scope, at(3));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the parked terminal Rescan is flushed at teardown: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert!(
    effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
    "the dead stream is torn down"
  );
}

#[test]
fn terminal_rescan_retries_until_accepted() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/a", flags(&[FsEventFlags::ITEM_CREATED]), 1, 10)],
    at(1),
  );
  assert!(matches!(core.poll_effect(), Some(Effect::Emit { .. })));
  core.on_delivery(scope, Delivery::Refused, at(2));

  // The root dies while the scope is lagged: the terminal Rescan is offered
  // after the teardown is dispatched.
  core.on_source_fatal(scope, at(3));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "{effects:?}");
  assert!(emitted[0].kind().is_rescan());

  // Refused again: the scope state is gone, but the terminal Rescan is not —
  // it re-arms on the retry timer and is re-offered until accepted.
  core.on_delivery(scope, Delivery::Refused, at(4));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "no synchronous re-offer for a dead scope either"
  );
  let retry = core
    .poll_timeout()
    .expect("the dying delivery arms the retry timer");
  core.on_timeout(retry);
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "the terminal Rescan retries: {effects:?}");
  assert!(emitted[0].kind().is_rescan());

  core.on_delivery(scope, Delivery::Accepted, at(60));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "accepted: nothing owed"
  );
  assert_eq!(core.poll_timeout(), None, "no timer stays armed");
}

#[test]
fn root_death_rescan_survives_refusal_after_teardown() {
  let (mut core, scope) = live_core();
  // A Normal (never-lagged) scope dies: the terminal Rescan is a queued
  // effect at teardown time and must still be retryable, not one-shot.
  core.on_source_fatal(scope, at(1));
  let offered = loop {
    match core.poll_effect() {
      Some(Effect::Emit { change, .. }) => break change,
      Some(_) => continue,
      None => panic!("a terminal Rescan is owed"),
    }
  };
  assert!(offered.kind().is_rescan());

  core.on_delivery(scope, Delivery::Refused, at(2));
  let retry = core
    .poll_timeout()
    .expect("the refusal arms a retry for the dead scope");
  core.on_timeout(retry);
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "{effects:?}");
  assert!(emitted[0].kind().is_rescan());

  core.on_delivery(scope, Delivery::Accepted, at(60));
  assert_eq!(core.poll_timeout(), None);
}

#[test]
fn same_fileid_chain_degrades_under_a_covering_rescan() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev("/r/x/a", flags(&[FsEventFlags::ITEM_RENAMED]), 1, 42),
      ev("/r/x/b", flags(&[FsEventFlags::ITEM_RENAMED]), 2, 42),
      ev("/r/x/c", flags(&[FsEventFlags::ITEM_RENAMED]), 3, 42),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 3, "an ambiguous group probes every member");
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(reqs[1].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[2].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "an ambiguous chain never fabricates a Moved: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_rescan() && c.location() == &loc(&["x"])),
    "the group is covered by one located Rescan: {emitted:?}"
  );
  assert_eq!(
    core.poll_timeout(),
    None,
    "no cookie half is left pending a pair"
  );
}

#[test]
fn cross_device_fileid_collision_never_pairs() {
  let (mut core, scope) = live_core();
  // Learn the foreign prefix first (a mounted volume under the root).
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/vol",
      flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_MODIFIED]),
      1,
      5,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::Dir,
      file_id: NonZeroU64::new(5),
      dev: 99,
    },
    at(2),
  );
  let _ = drain(&mut core);

  // The same fileID on both devices in one batch: one under the mount, one
  // native. Device-scoped ids must never pre-pair them.
  core.on_batch_events(
    scope,
    vec![
      ev("/r/vol/twin", flags(&[FsEventFlags::ITEM_RENAMED]), 10, 77),
      ev("/r/native", flags(&[FsEventFlags::ITEM_RENAMED]), 11, 77),
    ],
    at(3),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2, "a device-ambiguous pair never pre-pairs");
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(4));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(77),
      dev: 1,
    },
    at(4),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "device-scoped ids never fabricate a move: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_removed() && c.location() == &loc(&["vol", "twin"])),
    "the foreign vanished half degrades to Removed: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_created() && c.location() == &loc(&["native"])),
    "the native surviving half degrades to Created: {emitted:?}"
  );
  assert_eq!(
    core.poll_timeout(),
    None,
    "no half is left pending a pair the devices forbid"
  );
}

#[test]
fn foreign_device_singleton_rename_half_gets_no_cookie() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/alien", flags(&[FsEventFlags::ITEM_RENAMED]), 1, 88)],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(88),
      dev: 7,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "{effects:?}");
  assert!(
    emitted[0].kind().is_created(),
    "a foreign-device destination half degrades to Created"
  );
  assert_eq!(
    core.poll_timeout(),
    None,
    "no cookie: nothing waits to pair"
  );
}

#[test]
fn impure_rename_words_never_take_the_pairing_fast_path() {
  let (mut core, scope) = live_core();
  // Two halves share a fileID, but the destination word coalesced a content
  // change: trusting it as just-a-rename would drop the Modified silently.
  core.on_batch_events(
    scope,
    vec![
      ev("/r/old", flags(&[FsEventFlags::ITEM_RENAMED]), 1, 42),
      ev(
        "/r/new",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_MODIFIED]),
        2,
        42,
      ),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(
    reqs.len(),
    2,
    "a coalesced word forces both halves through probes"
  );
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_modified() && c.location() == &loc(&["new"])),
    "the coalesced content change is surfaced: {emitted:?}"
  );
  assert!(
    emitted.iter().any(|c| c.kind().moved_from().is_some()),
    "the rename itself still pairs through the cookie window: {emitted:?}"
  );
}

#[test]
fn rename_coalesced_with_create_and_remove_grounds_by_existence() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev(
        "/r/gone",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_REMOVED]),
        1,
        7,
      ),
      ev(
        "/r/here",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_CREATED]),
        2,
        8,
      ),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2);
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(8),
      dev: 1,
    },
    at(2),
  );
  core.on_timeout(at(400));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_removed() && c.location() == &loc(&["gone"])),
    "a vanished impure half degrades to Removed: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_created() && c.location() == &loc(&["here"])),
    "a surviving impure half degrades to Created: {emitted:?}"
  );
}

#[test]
fn seeded_mount_blocks_pairing_before_any_probe_learns_it() {
  let mut core = DriverCore::new(WINDOW);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  // The volume was ALREADY mounted at spawn: only the seeded table knows —
  // and the union keeps the seed even when the birth refresh (racing an
  // unmount, say) no longer lists it.
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      mounts: vec![PathBuf::from("/r/vol")],
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    }),
  );
  let _ = drain(&mut core);
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
  core.on_batch_events(
    scope,
    vec![
      ev("/r/vol/twin", flags(&[FsEventFlags::ITEM_RENAMED]), 10, 77),
      ev("/r/native", flags(&[FsEventFlags::ITEM_RENAMED]), 11, 77),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(
    reqs.len(),
    2,
    "a pre-mounted foreign volume never pre-pairs by fileID"
  );
}

#[test]
fn birth_window_refuses_cookies_until_the_refresh_installs() {
  // A mount can appear between the spawn's seed read and stream start,
  // landing in neither the seed nor the event stream — so a scope is born
  // trust-closed, and only the post-live birth refresh installs authority.
  let mut core = DriverCore::new(WINDOW);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      mounts: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    }),
  );
  assert_eq!(
    refresh_requests(&drain(&mut core)),
    1,
    "the spawn arms the birth refresh"
  );

  // A rename lands while the birth window is still closed: the vanished
  // half's cookie grant needs the table, which cannot yet prove root-device.
  core.on_batch_events(
    scope,
    vec![
      ev("/r/old", flags(&[FsEventFlags::ITEM_RENAMED]), 1, 42),
      ev("/r/new", flags(&[FsEventFlags::ITEM_RENAMED]), 2, 42),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2);
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  core.on_timeout(at(400));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "no Moved may pair inside the closed birth window: {emitted:?}"
  );

  // The birth refresh installs; the same shape now grounds into one Moved.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
  core.on_batch_events(
    scope,
    vec![
      ev("/r/old2", flags(&[FsEventFlags::ITEM_RENAMED]), 3, 43),
      ev("/r/new2", flags(&[FsEventFlags::ITEM_RENAMED]), 4, 43),
    ],
    at(500),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(501));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(43),
      dev: 1,
    },
    at(501),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().moved_from() == Some(&loc(&["old2"])) && c.location() == &loc(&["new2"])),
    "installed trust pairs the same shape: {emitted:?}"
  );
}

#[test]
fn a_loss_racing_the_birth_refresh_rearms_it_once() {
  let mut core = DriverCore::new(WINDOW);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      mounts: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    }),
  );
  assert_eq!(
    refresh_requests(&drain(&mut core)),
    1,
    "birth refresh armed"
  );

  // A loss overlaps the in-flight birth refresh: it coalesces (no second
  // effect), marking the outstanding read stale instead.
  core.on_root_overflow(scope, at(1));
  assert_eq!(
    refresh_requests(&drain(&mut core)),
    0,
    "a racing loss coalesces onto the outstanding refresh"
  );

  // The stale read's result is discarded and exactly one re-read arms.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
  assert_eq!(
    refresh_requests(&drain(&mut core)),
    1,
    "the stale result re-arms exactly once"
  );
  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(
    !state.mounts_authoritative,
    "trust stays closed until a post-loss read installs"
  );

  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(state.mounts_authoritative, "the fresh read installs");
}

#[test]
fn blind_mount_table_suppresses_the_pairing_fast_path() {
  let (mut core, scope) = live_core_blind_mounts();
  core.on_batch_events(
    scope,
    vec![
      ev("/r/old", flags(&[FsEventFlags::ITEM_RENAMED]), 1, 42),
      ev("/r/new", flags(&[FsEventFlags::ITEM_RENAMED]), 2, 42),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(
    reqs.len(),
    2,
    "no authoritative device evidence, no fast pairing"
  );
  // Existence probes still converge the halves — with cookies refused, the
  // survivor is a Created and the vanished half a Removed.
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  core.on_timeout(at(400));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_removed() && c.location() == &loc(&["old"])),
    "{emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_created() && c.location() == &loc(&["new"])),
    "{emitted:?}"
  );
}

#[test]
fn mount_in_batch_blocks_same_batch_rename_trust() {
  let (mut core, scope) = live_core();
  // The MOUNT and a colliding-fileID pure-rename pair arrive in ONE batch:
  // the trust mutation must be visible before any cookie decision — the
  // vanished half under the just-mounted volume is decided event-side (a
  // gone path has no device to stat).
  core.on_batch_events(
    scope,
    vec![
      ev("/r/vol", flags(&[FsEventFlags::MOUNT]), 1, 0),
      ev("/r/vol/twin", flags(&[FsEventFlags::ITEM_RENAMED]), 2, 77),
      ev("/r/native", flags(&[FsEventFlags::ITEM_RENAMED]), 3, 77),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2, "both halves probe; nothing pre-pairs");
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(77),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "a same-batch mount never lets device-scoped ids pair: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_rescan() && c.location() == &loc(&["vol"])),
    "the mount's own located rescan still lands: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_removed() && c.location() == &loc(&["vol", "twin"])),
    "the foreign half degrades cookie-less: {emitted:?}"
  );
  assert_eq!(
    core.poll_timeout(),
    None,
    "the foreign half minted no cookie to wait on"
  );
}

fn refresh_requests(effects: &[Effect]) -> usize {
  effects
    .iter()
    .filter(|e| matches!(e, Effect::RefreshMounts { .. }))
    .count()
}

/// Feeds one same-batch rename pair (gone source, present destination on the
/// root device) and returns the emitted changes — `Moved` under healthy
/// trust, `Removed`+`Created` while trust is closed.
fn feed_pair(core: &mut DriverCore, scope: ScopeId, ids: (u64, u64), fid: u64) -> Vec<Change> {
  core.on_batch_events(
    scope,
    vec![
      ev("/r/a/old", flags(&[FsEventFlags::ITEM_RENAMED]), ids.0, fid),
      ev("/r/b/new", flags(&[FsEventFlags::ITEM_RENAMED]), ids.1, fid),
    ],
    at(ids.0),
  );
  let reqs = probes(&drain(core));
  assert_eq!(reqs.len(), 2);
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(ids.0 + 1));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(fid),
      dev: 1,
    },
    at(ids.0 + 1),
  );
  emits(&drain(core)).into_iter().cloned().collect()
}

#[test]
fn loss_revokes_mount_trust_and_requests_one_refresh() {
  let (mut core, scope) = live_core();
  core.on_root_overflow(scope, at(1));
  let effects = drain(&mut core);
  assert_eq!(
    refresh_requests(&effects),
    1,
    "a loss signal requests exactly one mount refresh: {effects:?}"
  );
  assert!(
    emits(&effects).iter().any(|c| c.kind().is_rescan()),
    "the overflow's own rescan still lands"
  );

  // While the refresh is outstanding, trust is closed: the vanished half of
  // a same-batch pair cannot be granted its cookie, so the pair degrades.
  let emitted = feed_pair(&mut core, scope, (10, 11), 42);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "no pairing while device trust is revoked: {emitted:?}"
  );

  // Further losses coalesce onto the outstanding refresh.
  core.on_root_overflow(scope, at(20));
  assert_eq!(refresh_requests(&drain(&mut core)), 0, "coalesced");

  // The refresh landed after the second loss: its snapshot is stale, so it
  // is discarded and exactly one more refresh runs.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
  assert_eq!(refresh_requests(&drain(&mut core)), 1, "stale re-arm");
  let emitted = feed_pair(&mut core, scope, (30, 31), 43);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "still closed until a current refresh installs"
  );

  // A current refresh restores authority; pairing resumes (the granted pair
  // carries its covering rescan alongside the Moved).
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
  assert_eq!(refresh_requests(&drain(&mut core)), 0);
  let emitted = feed_pair(&mut core, scope, (40, 41), 44);
  assert_eq!(emitted[0].kind().moved_from(), Some(&loc(&["a", "old"])));
  assert!(
    emitted.iter().any(|c| c.kind().is_rescan()),
    "the granted pair wears its cover: {emitted:?}"
  );
}

#[test]
fn failed_refresh_keeps_trust_closed() {
  let (mut core, scope) = live_core();
  core.on_root_overflow(scope, at(1));
  let _ = drain(&mut core);
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), false), at(0));
  assert_eq!(
    refresh_requests(&drain(&mut core)),
    0,
    "a failed refresh does not spin"
  );
  let emitted = feed_pair(&mut core, scope, (10, 11), 42);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "an unreadable mount table proves nothing: {emitted:?}"
  );
}

#[test]
fn refresh_union_keeps_learned_foreign_prefixes() {
  let (mut core, scope) = live_core();
  // A probe learns a foreign-device prefix.
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/vol/x",
      flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_MODIFIED]),
      1,
      5,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(5),
      dev: 9,
    },
    at(2),
  );
  let _ = drain(&mut core);

  core.on_root_overflow(scope, at(3));
  let _ = drain(&mut core);
  // The fresh snapshot does not list the learned prefix (it is not a real
  // mount point); the union must keep it — replacement would re-trust a
  // known-foreign subtree.
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![PathBuf::from("/r/other")], true),
    at(0),
  );
  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(state.mounts_authoritative);
  assert!(state.mounts.iter().any(|m| m == Path::new("/r/vol/x")));
  assert!(state.mounts.iter().any(|m| m == Path::new("/r/other")));
}

#[test]
fn kernel_loss_flags_revoke_trust_but_coverage_rescans_do_not() {
  // MustScanSubDirs is kernel-side loss: the coalesced-away window may have
  // carried a mount transition.
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/deep",
      flags(&[FsEventFlags::MUST_SCAN_SUBDIRS, FsEventFlags::USER_DROPPED]),
      1,
      0,
    )],
    at(1),
  );
  assert_eq!(refresh_requests(&drain(&mut core)), 1);

  // An id wrap is a loss signal too.
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r", flags(&[FsEventFlags::EVENT_IDS_WRAPPED]), 1, 0)],
    at(1),
  );
  assert_eq!(refresh_requests(&drain(&mut core)), 1);

  // A synthesized coverage rescan (an appeared directory) loses no events
  // and must NOT thrash the trust table.
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev(
      "/r/incoming",
      flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_DIR]),
      10,
      42,
    )],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::Dir,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  assert_eq!(
    refresh_requests(&drain(&mut core)),
    0,
    "an appeared directory is coverage, not loss"
  );
}

#[test]
fn same_batch_unmount_keeps_colliding_rename_foreign() {
  // The volume was known at spawn; a rename coalesces into the SAME batch as
  // the volume's unmount, with a root-device object colliding on the fileID.
  let mut core = DriverCore::new(WINDOW);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      mounts: vec![PathBuf::from("/r/vol")],
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    }),
  );
  let _ = drain(&mut core);
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![PathBuf::from("/r/vol")], true),
    at(0),
  );

  core.on_batch_events(
    scope,
    vec![
      ev("/r/vol", flags(&[FsEventFlags::UNMOUNT]), 1, 0),
      ev("/r/vol/twin", flags(&[FsEventFlags::ITEM_RENAMED]), 2, 77),
      ev("/r/native", flags(&[FsEventFlags::ITEM_RENAMED]), 3, 77),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2);
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(77),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "the unmount's trust-removal is deferred past the batch, so the gone \
     half under the old volume stays foreign: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_removed() && c.location() == &loc(&["vol", "twin"]))
  );

  // The removal applies at settlement: the NEXT batch sees the prefix gone.
  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(
    !state.mounts.iter().any(|m| m == Path::new("/r/vol")),
    "post-batch, the unmounted prefix leaves the table"
  );
}

#[test]
fn vanished_half_grant_requires_partner_evidence() {
  // The destination probes onto a FOREIGN device: no cookie, no evidence —
  // so the vanished source is never granted its cookie either.
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev("/r/a/old", flags(&[FsEventFlags::ITEM_RENAMED]), 10, 42),
      ev("/r/b/new", flags(&[FsEventFlags::ITEM_RENAMED]), 11, 42),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 2,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "no root-device evidence, no grant: {emitted:?}"
  );
  assert_eq!(core.poll_timeout(), None, "nothing waits on a cookie");
}

/// The path was replaced between the FSEvents callback and the lstat: the
/// event carried inode 42 but the probe read 99. No cookie may bridge the two
/// objects — the pair degrades and the stale view is covered by a located
/// rescan, never a fabricated `Moved`.
#[test]
fn replaced_path_between_callback_and_probe_never_cookies() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev(
        "/r/a/old",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        10,
        42,
      ),
      ev(
        "/r/b/new",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        11,
        42,
      ),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2);
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(99),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "a mismatched probe identity must never pair: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_removed() && c.location() == &loc(&["a", "old"])),
    "the vanished half degrades to a removal: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_created() && c.location() == &loc(&["b", "new"])),
    "the surviving half degrades to a creation: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_rescan() && c.location() == &loc(&["b", "new"])),
    "the stale path view is covered by a located rescan: {emitted:?}"
  );
}

/// A probe-only fileID establishes NO grant evidence: the probe proves what
/// occupies the path NOW, not which object the batch's events were about, so
/// a partner whose EVENT word carried no fileID cannot vouch for a vanished
/// half. The pair degrades to a removal plus a creation — never a `Moved`
/// bridging two unproven objects.
#[test]
fn probe_only_fileid_establishes_no_grant_evidence() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev(
        "/r/a/gone",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        10,
        42,
      ),
      ev(
        "/r/b/kept",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        11,
        0,
      ),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2);
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "a probe-only fileID must not vouch for a vanished partner: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_removed() && c.location() == &loc(&["a", "gone"])),
    "{emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_created() && c.location() == &loc(&["b", "kept"])),
    "{emitted:?}"
  );
  assert_eq!(core.poll_timeout(), None, "no grant, no pairing window");
}

/// The grant's honest residual, pinned: an inode recycled WITHIN one batch
/// satisfies every proof the machinery can demand (FSEvents supplies no
/// rename token), so the mis-pair itself cannot be prevented event-side —
/// but it is never silent: the granted pair's covering rescan lands at the
/// halves' deepest common ancestor and re-grounds whatever really happened.
#[test]
fn fileid_reuse_within_batch_is_covered() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev(
        "/r/a/gone",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        10,
        42,
      ),
      ev(
        "/r/a/sub/unrelated",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        11,
        42,
      ),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2);
  core.on_probe_result(reqs[0].0, ProbeOutcome::Missing, at(2));
  core.on_probe_result(
    reqs[1].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_rescan() && c.location() == &loc(&["a"])),
    "whatever the reuse paired into is covered at the deepest common \
     ancestor: {emitted:?}"
  );
}

/// Two present partners evidencing one fileID (a pure pair plus an ungrouped
/// impure half) make the grant ambiguous: the Monitor would pair the cookie
/// with whichever destination feeds first, while a single-representative
/// cover — chosen by probe completion order — could point at the other.
/// Ambiguity suppresses the cookie entirely, and one cover spans the source
/// and EVERY evidenced partner.
#[test]
fn ambiguous_grant_partners_suppress_the_cookie_under_one_cover() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev(
        "/r/d/gone",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        10,
        42,
      ),
      ev(
        "/r/d/x",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        11,
        42,
      ),
      // Impure word: ungrouped (no chain suppression), probe-grounded, and —
      // when present with the event fileID its probe confirms — a second
      // evidence entry for 42.
      ev(
        "/r/d/y",
        flags(&[
          FsEventFlags::ITEM_RENAMED,
          FsEventFlags::ITEM_MODIFIED,
          FsEventFlags::ITEM_IS_FILE,
        ]),
        12,
        42,
      ),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 3);
  let by_path = |p: &str| {
    reqs
      .iter()
      .find(|(_, path)| path == Path::new(p))
      .expect("a probe per half")
      .0
  };
  // Probes answer OUT of event order: completion order must not decide
  // anything about the grant or its cover.
  for path in ["/r/d/y", "/r/d/x"] {
    core.on_probe_result(
      by_path(path),
      ProbeOutcome::Present {
        kind: FileKind::File,
        file_id: NonZeroU64::new(42),
        dev: 1,
      },
      at(2),
    );
  }
  core.on_probe_result(by_path("/r/d/gone"), ProbeOutcome::Missing, at(2));
  let emitted_effects = drain(&mut core);
  let emitted = emits(&emitted_effects);
  assert!(
    emitted.iter().all(|c| c.kind().moved_from().is_none()),
    "an ambiguous grant must not pair anything: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_rescan() && c.location() == &loc(&["d"])),
    "one cover spans the source and every evidenced partner: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_removed() && c.location() == &loc(&["d", "gone"])),
    "the vanished half degrades to its cookie-less removal: {emitted:?}"
  );
}

/// The single-partner happy path is untouched by the ambiguity fence, and is
/// itself completion-order independent: the partner probe answering first
/// changes nothing about the pairing or the cover.
#[test]
fn single_partner_grant_is_probe_order_independent() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev(
        "/r/d/gone",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        10,
        42,
      ),
      ev(
        "/r/d/new",
        flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
        11,
        42,
      ),
    ],
    at(1),
  );
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 2);
  let by_path = |p: &str| {
    reqs
      .iter()
      .find(|(_, path)| path == Path::new(p))
      .expect("a probe per half")
      .0
  };
  // Destination probe completes before the source's.
  core.on_probe_result(
    by_path("/r/d/new"),
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
    },
    at(2),
  );
  core.on_probe_result(by_path("/r/d/gone"), ProbeOutcome::Missing, at(2));
  let emitted_effects = drain(&mut core);
  let emitted = emits(&emitted_effects);
  assert!(
    emitted.iter().any(|c| {
      c.kind().moved_from() == Some(&loc(&["d", "gone"])) && c.location() == &loc(&["d", "new"])
    }),
    "the unambiguous pair still becomes one move: {emitted:?}"
  );
  assert!(
    emitted
      .iter()
      .any(|c| c.kind().is_rescan() && c.location() == &loc(&["d"])),
    "its cover names the actually-paired destination's ancestor: {emitted:?}"
  );
}

/// A spawn failure never surfaces publicly: the caller got Err instead of a
/// handle, so the Monitor's internal failure rescan for the root must not be
/// delivered — not even through the dying retry.
#[test]
fn spawn_failure_emits_nothing_public() {
  let mut core = DriverCore::new(WINDOW);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_stream_spawned(scope, Err(SourceError::StartFailed));
  let effects = drain(&mut core);
  assert!(
    emits(&effects).is_empty(),
    "a never-live scope owes no public coverage: {effects:?}"
  );
  assert!(
    effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
    "{effects:?}"
  );
  assert_eq!(core.poll_timeout(), None, "no dying delivery waits");
  core.on_timeout(at(10_000));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "nothing to retry for a never-live scope"
  );
}

/// The final-root rejection path is equally silent — the same never-live
/// fence covers a scope the driver refused before it went live.
#[test]
fn spawn_rejection_emits_nothing_public() {
  let mut core = DriverCore::new(WINDOW);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_spawn_rejected(scope);
  let effects = drain(&mut core);
  assert!(
    emits(&effects).is_empty(),
    "a rejected scope owes no public coverage: {effects:?}"
  );
  assert_eq!(core.poll_timeout(), None);
  core.on_timeout(at(10_000));
  assert!(emits(&drain(&mut core)).is_empty());
}

mod lowering {
  use super::*;

  fn state_with_root(root: &str) -> ScopeState {
    ScopeState {
      watch: WatchId::new(NonZeroU64::new(99).unwrap()),
      profile: BackendKind::FsEvents,
      requested: PathBuf::from(root),
      root: Some(Arc::new(PathBuf::from(root))),
      root_dev: Some(1),
      identity: Some(crate::os::RootIdentity::new(1, 1)),
      mounts: Vec::new(),
      mounts_authoritative: true,
      refresh_pending: false,
      refresh_stale: false,
      lag: LagState::Normal,
      park: Park::default(),
      resume_poisoned: false,
    }
  }

  enum Expect {
    Root,
    Target(&'static [&'static str]),
    Outside,
  }

  /// The lowering property table over root and path edge shapes — above all
  /// the filesystem root `/`, the one canonical root that ends with the
  /// separator (its descendants strip to a bare remainder).
  #[test]
  fn lowering_covers_root_and_prefix_edge_cases() {
    let cases: &[(&str, &str, Expect)] = &[
      ("/", "/", Expect::Root),
      ("/", "/tmp", Expect::Target(&["tmp"])),
      ("/", "/tmp/a", Expect::Target(&["tmp", "a"])),
      ("/", "//tmp//x", Expect::Target(&["tmp", "x"])),
      ("/a", "/a", Expect::Root),
      ("/a", "/a/b", Expect::Target(&["b"])),
      ("/a", "/a/b/c", Expect::Target(&["b", "c"])),
      ("/a", "/ab", Expect::Outside),
      ("/a", "/b/c", Expect::Outside),
      ("/a", "/", Expect::Outside),
      ("/a/b", "/a/b/c/d", Expect::Target(&["c", "d"])),
      ("/a/b", "/a/bc", Expect::Outside),
      ("/a/b", "/a/b/", Expect::Root),
    ];
    for (root, path, expect) in cases {
      let state = state_with_root(root);
      match (lower(&state, Path::new(path)), expect) {
        (Lowered::Root, Expect::Root) => {}
        (Lowered::Target(got), Expect::Target(parts)) => {
          assert_eq!(got, loc(parts), "root {root} path {path}");
        }
        (Lowered::Outside, Expect::Outside) => {}
        (got, _) => {
          let shape = match got {
            Lowered::Root => "Root".to_string(),
            Lowered::Target(l) => format!("Target({l:?})"),
            Lowered::Outside => "Outside".to_string(),
          };
          panic!("root {root} path {path}: unexpected {shape}");
        }
      }
    }
  }

  #[cfg(unix)]
  #[test]
  fn non_utf8_segments_lower_outside() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
    let state = state_with_root("/r");
    let path = PathBuf::from(OsStr::from_bytes(b"/r/\xC3\x28"));
    assert!(matches!(lower(&state, &path), Lowered::Outside));
  }

  /// A scope rooted at the filesystem root grounds its descendants as
  /// LOCATED events — not whole-root rescans (the pre-fix behavior made a
  /// `/` root unusable).
  #[test]
  fn filesystem_root_scope_grounds_descendants_located() {
    let mut core = DriverCore::new(WINDOW);
    let scope = core.on_watch(PathBuf::from("/"), Interest::all(), BackendKind::FsEvents);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/"),
        root_dev: 1,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::FsEvents,
      }),
    );
    let _ = drain(&mut core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));

    core.on_batch_events(
      scope,
      vec![ev(
        "/tmp/x.txt",
        flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_IS_FILE]),
        1,
        10,
      )],
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert!(emitted[0].kind().is_created());
    assert_eq!(
      emitted[0].location(),
      &loc(&["tmp", "x.txt"]),
      "a / root lowers descendants to located events"
    );

    // A deep MustScanSubDirs clamps to a LOCATED subtree rescan, not the root.
    core.on_batch_events(
      scope,
      vec![ev("/tmp", flags(&[FsEventFlags::MUST_SCAN_SUBDIRS]), 2, 0)],
      at(2),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      emitted
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&["tmp"])),
      "{emitted:?}"
    );

    // A mount transition under / records located coverage, not a root wipe.
    core.on_batch_events(
      scope,
      vec![ev(
        "/Volumes/usb",
        flags(&[FsEventFlags::MOUNT, FsEventFlags::ITEM_IS_DIR]),
        3,
        0,
      )],
      at(3),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      emitted
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&["Volumes", "usb"])),
      "{emitted:?}"
    );
  }
}

/// A stuck probe must not let parked batches escape the transport budget: the
/// payload's permit rides through the park (active AND queued), so once the
/// budget is exhausted the callback's acquire fails, the excess batch degrades
/// to an ordered `Overflow`, and the loss flush returns every slot.
#[test]
fn stuck_probe_backpressures_the_callback_through_the_park() {
  use crate::os::{
    SourceEvent, SourceMessage,
    transport::{TransportState, forward_batch},
  };

  let (mut core, scope) = live_core();
  let transport = TransportState::new(2);
  let mut queue: Vec<SourceMessage> = Vec::new();

  // Batch 1: a rename half needs a probe — the batch parks, slot retained.
  forward_batch(
    &transport,
    vec![SourceEvent::FsEvents(ev(
      "/r/a",
      flags(&[FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE]),
      10,
      7,
    ))],
    false,
    |msg| {
      queue.push(msg);
      true
    },
  );
  let SourceMessage::Batch(payload) = queue.remove(0) else {
    panic!("batch 1 rides the queue");
  };
  core.on_batch(scope, payload, at(1));
  let effects = drain(&mut core);
  assert_eq!(probes(&effects).len(), 1, "the rename half probes");
  assert_eq!(
    transport.in_flight(),
    1,
    "the parked active batch holds its slot"
  );

  // Batch 2 queues behind the park, still holding its slot.
  forward_batch(
    &transport,
    vec![SourceEvent::FsEvents(ev(
      "/r/b",
      flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_IS_FILE]),
      11,
      8,
    ))],
    false,
    |msg| {
      queue.push(msg);
      true
    },
  );
  let SourceMessage::Batch(payload) = queue.remove(0) else {
    panic!("batch 2 rides the queue");
  };
  core.on_batch(scope, payload, at(2));
  assert!(drain(&mut core).is_empty(), "a queued batch feeds nothing");
  assert_eq!(
    transport.in_flight(),
    2,
    "the queued parked batch holds its slot too"
  );

  // Batch 3: the budget is exhausted — dropped at the callback, degraded to
  // the in-order Overflow.
  forward_batch(
    &transport,
    vec![SourceEvent::FsEvents(ev(
      "/r/c",
      flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_IS_FILE]),
      12,
      9,
    ))],
    false,
    |msg| {
      queue.push(msg);
      true
    },
  );
  let SourceMessage::Overflow(ack) = queue.remove(0) else {
    panic!("the over-budget batch degrades to an Overflow");
  };
  assert!(queue.is_empty(), "the dropped batch itself never rides");

  // The driver's protocol: drop the ack, then feed the loss.
  drop(ack);
  core.on_root_overflow(scope, at(3));
  let effects = drain(&mut core);
  assert!(
    emits(&effects).iter().any(|c| c.kind().is_rescan()),
    "the loss becomes a covering Rescan"
  );
  assert_eq!(
    transport.in_flight(),
    0,
    "the loss flush returns every parked slot"
  );
}

/// One kernel batch can carry loss, an ordinary event, and loss again; the delivered
/// sequence keeps a covering rescan AFTER the possibly-stale event — the trailing loss
/// is never coalesced into the leading one.
#[test]
fn repeated_in_batch_loss_keeps_a_trailing_covering_rescan() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![
      ev("/r", FsEventFlags::MUST_SCAN_SUBDIRS, 1, 0),
      ev(
        "/r/x",
        flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_IS_FILE]),
        2,
        11,
      ),
      ev("/r", FsEventFlags::MUST_SCAN_SUBDIRS, 3, 0),
    ],
    at(10),
  );

  let effects = drain(&mut core);
  let changes = emits(&effects);
  let created_at = changes
    .iter()
    .position(|c| c.kind().is_created())
    .expect("the grounded create is delivered");
  let trailing_rescan = changes
    .iter()
    .rposition(|c| c.kind().is_rescan())
    .expect("a covering rescan is delivered");
  assert!(
    trailing_rescan > created_at,
    "a covering rescan follows the possibly-stale event"
  );
  assert_eq!(
    changes.iter().filter(|c| c.kind().is_rescan()).count(),
    2,
    "each loss keeps its own covering rescan"
  );
}

mod descending {
  //! The inotify (descending) profile: the Monitor descends per directory,
  //! and the core executes its watch/enumerate vocabulary as effects.

  use super::*;
  use crate::{
    core::{RawDirEntry, RawEnumerate},
    os::linux::{RawInotifyEvent, RawLinuxEvent, inotify::decode::InotifyMask},
  };
  use tributary_proto::WatchError;

  fn entry(name: &str, kind: FileKind, dev: u64, ino: u64) -> RawDirEntry {
    RawDirEntry {
      name: name.as_bytes().to_vec(),
      kind,
      dev,
      ino,
    }
  }

  fn listed(entries: Vec<RawDirEntry>) -> RawEnumerate {
    RawEnumerate::Listed {
      entries,
      complete: true,
    }
  }

  const IN_CREATE: u32 = 0x0000_0100;
  const IN_DELETE: u32 = 0x0000_0200;
  const IN_MOVED_FROM: u32 = 0x0000_0040;
  const IN_MOVED_TO: u32 = 0x0000_0080;
  const IN_ISDIR: u32 = 0x4000_0000;
  const IN_IGNORED: u32 = 0x0000_8000;

  fn inotify(anchors: &[WatchId], mask: u32, cookie: u32, name: Option<&[u8]>) -> RawLinuxEvent {
    RawLinuxEvent::Inotify {
      anchors: anchors.to_vec(),
      event: RawInotifyEvent {
        wd: 1,
        mask: InotifyMask(mask),
        cookie,
        name: name.map(|n| n.to_vec()),
      },
    }
  }

  /// Registration under the descending profile spawns the stream; the spawn
  /// result arms the ROOT through the same effect path as every descendant
  /// (the source starts with no watches), and the arm's success
  /// cold-enumerates the root — the dormant vocabulary is live.
  fn live_descending() -> (DriverCore, ScopeId, ReqId, WatchId) {
    let mut core = DriverCore::new(WINDOW);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify);
    let effects = drain(&mut core);
    assert!(
      matches!(effects.as_slice(), [Effect::SpawnStream { root, .. }] if root == Path::new("/r")),
      "registration spawns the stream: {effects:?}"
    );
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Inotify,
      }),
    );
    let effects = drain(&mut core);
    let root_watch = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch {
          watch,
          parent,
          path,
          ..
        } if path.as_path() == Path::new("/r") && watch == parent => Some(*watch),
        _ => None,
      })
      .expect("the spawned descending root arms through the effect path");
    core.on_watch_installed(root_watch, crate::os::linux::WatchOutcome::Installed(1));
    let effects = drain(&mut core);
    let (req, watch) = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, watch, path } if path.as_path() == Path::new("/r") => {
          Some((*req, *watch))
        }
        _ => None,
      })
      .expect("a descending root cold-enumerates after arming");
    assert_eq!(watch, root_watch, "the enumerate reads the armed root");
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(&mut core);
    (core, scope, req, watch)
  }

  #[test]
  fn descending_registration_cold_enumerates_the_root() {
    let (_core, _scope, _req, _watch) = live_descending();
  }

  #[test]
  fn cold_listing_installs_children_and_emits_inventory() {
    let (mut core, _scope, req, _root) = live_descending();
    core.on_enumerated(
      req,
      listed(vec![
        entry("a.txt", FileKind::File, 1, 10),
        entry("sub", FileKind::Dir, 1, 11),
      ]),
    );
    let effects = drain(&mut core);
    let created: Vec<&Change> = emits(&effects);
    assert_eq!(created.len(), 2, "cold inventory delivers: {effects:?}");
    let add = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the discovered directory is armed");
    // The arm's success continues the descent: the child cold-enumerates.
    core.on_watch_installed(add, crate::os::linux::WatchOutcome::Installed(2));
    let effects = drain(&mut core);
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { path, .. } if path.as_path() == Path::new("/r/sub")
      )),
      "the armed child cold-enumerates: {effects:?}"
    );
  }

  #[test]
  fn aliased_outcome_is_coverage() {
    let (mut core, _scope, req, _root) = live_descending();
    core.on_enumerated(req, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, .. } => Some(*watch),
        _ => None,
      })
      .expect("arm queued");
    core.on_watch_installed(add, crate::os::linux::WatchOutcome::Aliased(7));
    let effects = drain(&mut core);
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::Enumerate { .. })),
      "an aliased anchor is covered coverage — the descent continues: {effects:?}"
    );
  }

  #[test]
  fn watch_failure_drops_and_rescans() {
    let (mut core, _scope, req, _root) = live_descending();
    core.on_enumerated(req, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, .. } => Some(*watch),
        _ => None,
      })
      .expect("arm queued");
    core.on_watch_installed(
      add,
      crate::os::linux::WatchOutcome::Failed(WatchError::NoSpace),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "a refused arm is never a silent blind spot: {effects:?}"
    );
  }

  #[test]
  fn partial_listing_rescans_and_retries() {
    let (mut core, _scope, req, root) = live_descending();
    core.on_enumerated(
      req,
      RawEnumerate::Listed {
        entries: vec![entry("a.txt", FileKind::File, 1, 10)],
        complete: false,
      },
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "an incomplete listing rescans: {effects:?}"
    );
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { watch, .. } if *watch == root
      )),
      "and retries the read: {effects:?}"
    );
  }

  #[test]
  fn foreign_device_directory_is_not_descended() {
    let (mut core, _scope, req, _root) = live_descending();
    core.on_enumerated(
      req,
      listed(vec![
        entry("vol", FileKind::Dir, 2, 20),
        entry("here", FileKind::Dir, 1, 21),
      ]),
    );
    let effects = drain(&mut core);
    let armed: Vec<&Path> = effects
      .iter()
      .filter_map(|e| match e {
        Effect::AddWatch { path, .. } => Some(path.as_path()),
        _ => None,
      })
      .collect();
    assert_eq!(
      armed,
      vec![Path::new("/r/here")],
      "the mount boundary is the scope boundary — a foreign-device directory \
       is delivered but never descended: {effects:?}"
    );
  }

  #[test]
  fn inotify_events_lower_depth_one_with_native_cookies() {
    let (mut core, scope, req, root) = live_descending();
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);
    core.on_inotify_events(
      scope,
      vec![
        inotify(&[root], IN_CREATE | IN_ISDIR, 0, Some(b"d")),
        inotify(&[root], IN_MOVED_FROM, 7, Some(b"old")),
        inotify(&[root], IN_MOVED_TO, 7, Some(b"new")),
        inotify(&[root], IN_DELETE, 0, Some(b"gone")),
      ],
      at(1),
    );
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      changes
        .iter()
        .any(|c| c.kind().is_created() && c.location() == &loc(&["d"])),
      "created lowers depth-one: {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|c| c.kind().moved_from() == Some(&loc(&["old"])) && c.location() == &loc(&["new"])),
      "native cookies pair in the Monitor window: {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|c| c.kind().is_removed() && c.location() == &loc(&["gone"])),
      "removed lowers: {changes:?}"
    );
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { path, .. } if path.as_path() == Path::new("/r/d")
      )),
      "a created directory descends: {effects:?}"
    );
  }

  #[test]
  fn anchor_fanout_duplicates_records_per_alias() {
    let (mut core, scope, req, root) = live_descending();
    core.on_enumerated(req, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, .. } => Some(*watch),
        _ => None,
      })
      .expect("arm queued");
    core.on_watch_installed(add, crate::os::linux::WatchOutcome::Installed(2));
    let _ = drain(&mut core);
    // One kernel record attributed to BOTH anchors: each gets its own copy.
    core.on_inotify_events(
      scope,
      vec![inotify(&[root, add], IN_CREATE, 0, Some(b"x"))],
      at(2),
    );
    let changes: Vec<Location> = emits(&drain(&mut core))
      .iter()
      .map(|c| c.location().clone())
      .collect();
    assert!(
      changes.contains(&loc(&["x"])),
      "root anchor copy: {changes:?}"
    );
    assert!(
      changes.contains(&loc(&["sub", "x"])),
      "aliased anchor copy: {changes:?}"
    );
  }

  #[test]
  fn non_utf8_name_escalates_a_located_rescan() {
    let (mut core, scope, req, root) = live_descending();
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);
    core.on_inotify_events(
      scope,
      vec![inotify(&[root], IN_CREATE, 0, Some(&[0xFF, 0xFE]))],
      at(1),
    );
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      changes.iter().any(|c| c.kind().is_rescan()),
      "an unrepresentable name re-reads its directory — never silent: {changes:?}"
    );
  }

  #[test]
  fn ignored_resolves_the_anchor() {
    let (mut core, scope, req, _root) = live_descending();
    core.on_enumerated(req, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, .. } => Some(*watch),
        _ => None,
      })
      .expect("arm queued");
    core.on_watch_installed(add, crate::os::linux::WatchOutcome::Installed(2));
    let _ = drain(&mut core);
    core.on_inotify_events(scope, vec![inotify(&[add], IN_IGNORED, 0, None)], at(3));
    let effects = drain(&mut core);
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::RemoveWatch { watch, .. } if *watch == add)),
      "the kernel teardown disarms the dropped child: {effects:?}"
    );
  }

  #[test]
  fn non_utf8_listing_entry_degrades_to_partial() {
    let (mut core, _scope, req, root) = live_descending();
    core.on_enumerated(
      req,
      listed(vec![RawDirEntry {
        name: vec![0xFF, 0xFE],
        kind: FileKind::File,
        dev: 1,
        ino: 30,
      }]),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "an unrepresentable entry cannot be silently omitted: {effects:?}"
    );
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { watch, .. } if *watch == root
      )),
      "the degraded listing retries: {effects:?}"
    );
  }
}

mod kernel_recursive_fanotify {
  //! The fanotify (kernel-recursive) profile: one superblock mark covers the
  //! whole root, so the Monitor never descends. Records are precise verbs
  //! lowered to root-relative targets with interned-FID identity, and
  //! `FAN_RENAME` pairs atomically through a minted counter cookie.

  use super::*;
  use crate::os::linux::{
    RawLinuxEvent,
    fanotify::{
      AdmittedEvent, AdmittedRename,
      fid::{
        FAN_ATTRIB, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF, FAN_MODIFY, FAN_ONDIR, FAN_RENAME,
        FanMask,
      },
    },
  };
  use std::num::NonZeroU64;

  /// A live fanotify scope rooted at `/r`: the KR spawn doubles as the root's
  /// watch-result, and the birth refresh installs authoritative (empty) trust.
  fn live_fanotify() -> (DriverCore, ScopeId) {
    let mut core = DriverCore::new(WINDOW);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify);
    let effects = drain(&mut core);
    assert!(
      matches!(effects.as_slice(), [Effect::SpawnStream { root, .. }] if root == Path::new("/r")),
      "registration spawns the stream: {effects:?}"
    );
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Fanotify,
      }),
    );
    let effects = drain(&mut core);
    assert_eq!(
      refresh_requests(&effects),
      1,
      "a spawned KR scope is born closed and arms its birth refresh: {effects:?}"
    );
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(drain(&mut core).is_empty(), "a refreshed KR root is silent");
    (core, scope)
  }

  fn dirent(mask: u64, path: &str, identity: Option<u64>) -> RawLinuxEvent {
    RawLinuxEvent::Fanotify(AdmittedEvent {
      mask: FanMask::new(mask),
      path: Some(PathBuf::from(path)),
      identity: identity.and_then(NonZeroU64::new),
      rename: None,
    })
  }

  fn feed(core: &mut DriverCore, scope: ScopeId, events: Vec<RawLinuxEvent>) {
    let events = events.into_iter().map(SourceEvent::Linux).collect();
    core.on_batch(scope, BatchPayload::detached(events), at(1));
  }

  /// A create/delete/modify/attrib batch lowers to one record each, addressed
  /// by the root-relative target with the interned identity attached.
  #[test]
  fn precise_verbs_lower_to_root_relative_records() {
    let (mut core, scope) = live_fanotify();
    feed(
      &mut core,
      scope,
      vec![
        dirent(FAN_CREATE, "/r/a/new.txt", Some(10)),
        dirent(FAN_DELETE, "/r/a/gone.txt", None),
        dirent(FAN_MODIFY, "/r/a/hot.txt", Some(11)),
        dirent(FAN_ATTRIB, "/r/a/meta.txt", Some(12)),
      ],
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 4, "{effects:?}");
    assert!(emitted[0].kind().is_created());
    assert_eq!(emitted[0].location(), &loc(&["a", "new.txt"]));
    assert!(emitted[1].kind().is_removed());
    assert_eq!(emitted[1].location(), &loc(&["a", "gone.txt"]));
    assert!(emitted[2].kind().is_modified());
    assert!(
      emitted[3].kind().is_modified(),
      "attrib conflates into modified at the change level"
    );
  }

  /// A `FAN_RENAME` (both directory FIDs and both names in one event) lowers to
  /// a SINGLE `Moved` through the Monitor: the minted counter cookie pairs the
  /// adjacent `MovedFrom`/`MovedTo` with no window and no probe.
  #[test]
  fn rename_pairs_into_one_moved() {
    let (mut core, scope) = live_fanotify();
    feed(
      &mut core,
      scope,
      vec![RawLinuxEvent::Fanotify(AdmittedEvent {
        mask: FanMask::new(FAN_RENAME),
        path: None,
        identity: None,
        rename: Some(AdmittedRename {
          old_path: PathBuf::from("/r/old.txt"),
          new_path: PathBuf::from("/r/sub/new.txt"),
          identity: NonZeroU64::new(20),
        }),
      })],
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    let moved: Vec<&Change> = emitted
      .iter()
      .filter(|c| c.kind().is_moved())
      .copied()
      .collect();
    assert_eq!(
      moved.len(),
      1,
      "the atomic rename is one Moved: {effects:?}"
    );
    assert_eq!(
      moved[0].location(),
      &loc(&["sub", "new.txt"]),
      "destination"
    );
    assert_eq!(
      moved[0].kind().moved_from(),
      Some(&loc(&["old.txt"])),
      "source paired with no window"
    );
    assert!(
      emitted.iter().all(|c| !c.kind().is_removed()),
      "a paired rename never degrades to a bare removal: {effects:?}"
    );
  }

  /// The moved object's interned identity rides BOTH halves of the rename onto
  /// the Monitor records — it lives on the rename half, not on the (always
  /// `None`) top-level event identity, so the lowering must read it from there.
  #[test]
  fn rename_records_carry_the_moved_object_node() {
    let (mut core, scope) = live_fanotify();
    let nodes = core.compiled_fanotify_nodes(
      scope,
      vec![AdmittedEvent {
        mask: FanMask::new(FAN_RENAME),
        path: None,
        identity: None,
        rename: Some(AdmittedRename {
          old_path: PathBuf::from("/r/old.txt"),
          new_path: PathBuf::from("/r/sub/new.txt"),
          identity: NonZeroU64::new(77),
        }),
      }],
    );
    let expected = Some(tributary_proto::Identity::new(NonZeroU64::new(77).unwrap()));
    assert_eq!(
      nodes,
      vec![expected, expected],
      "both the MovedFrom and MovedTo carry the rename half's interned identity"
    );
  }

  /// Two renames in one batch mint DISTINCT cookies, so their halves never
  /// cross-pair — each is its own Moved.
  #[test]
  fn distinct_renames_get_distinct_cookies() {
    let (mut core, scope) = live_fanotify();
    feed(
      &mut core,
      scope,
      vec![
        RawLinuxEvent::Fanotify(AdmittedEvent {
          mask: FanMask::new(FAN_RENAME),
          path: None,
          identity: None,
          rename: Some(AdmittedRename {
            old_path: PathBuf::from("/r/a.txt"),
            new_path: PathBuf::from("/r/b.txt"),
            identity: None,
          }),
        }),
        RawLinuxEvent::Fanotify(AdmittedEvent {
          mask: FanMask::new(FAN_RENAME),
          path: None,
          identity: None,
          rename: Some(AdmittedRename {
            old_path: PathBuf::from("/r/c.txt"),
            new_path: PathBuf::from("/r/d.txt"),
            identity: None,
          }),
        }),
      ],
    );
    let effects = drain(&mut core);
    let moved: Vec<&Change> = emits(&effects)
      .into_iter()
      .filter(|c| c.kind().is_moved())
      .collect();
    assert_eq!(
      moved.len(),
      2,
      "two independent renames, two Moveds: {effects:?}"
    );
    let dests: Vec<&Location> = moved.iter().map(|c| c.location()).collect();
    assert!(dests.contains(&&loc(&["b.txt"])));
    assert!(dests.contains(&&loc(&["d.txt"])));
  }

  /// A `DELETE_SELF` on the ROOT object is the scope's death — the same
  /// Ignored lifecycle the FSEvents unmount uses: a terminal `Rescan`.
  #[test]
  fn root_delete_self_is_scope_death() {
    let (mut core, scope) = live_fanotify();
    feed(
      &mut core,
      scope,
      vec![RawLinuxEvent::Fanotify(AdmittedEvent {
        mask: FanMask::new(FAN_DELETE_SELF | FAN_ONDIR),
        path: Some(PathBuf::from("/r")),
        identity: Some(NonZeroU64::new(1).unwrap()),
        rename: None,
      })],
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "root death surfaces as a terminal Rescan: {effects:?}"
    );
    // The scope tore down: its stream is destroyed.
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the dead root's stream is torn down: {effects:?}"
    );
  }

  /// A directory create carries the directory flag through to the record.
  #[test]
  fn directory_create_flags_is_dir() {
    let (mut core, scope) = live_fanotify();
    feed(
      &mut core,
      scope,
      vec![dirent(FAN_CREATE | FAN_ONDIR, "/r/newdir", Some(30))],
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1);
    assert!(emitted[0].kind().is_created());
    assert_eq!(emitted[0].location(), &loc(&["newdir"]));
  }
}

/// `Backend::Auto` resolves the backend only once the source has spawned, so
/// the Monitor profile registered up front is PROVISIONAL. These pin the
/// reconcile at [`DriverCore::on_stream_spawned`]: the resolved
/// `RootMeta.backend` becomes the scope's profile before its watch-result is
/// fed (design §5).
mod auto_selection {
  use super::*;
  use crate::os::linux::{
    RawLinuxEvent,
    fanotify::{
      AdmittedEvent,
      fid::{FAN_CREATE, FanMask},
    },
  };
  use std::num::NonZeroU64;

  /// Provisional descending profile (the Linux platform default under Auto),
  /// but the probe resolved FANOTIFY: the core adopts the kernel-recursive
  /// profile — the spawn doubles as the root's watch-result (NO per-directory
  /// AddWatch), and a subsequent fanotify event lowers root-relative, proving
  /// the KR profile is the one now running.
  #[test]
  fn auto_provisional_inotify_adopts_probed_fanotify() {
    let mut core = DriverCore::new(WINDOW);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        // The probe picked fanotify despite the provisional inotify profile.
        backend: BackendKind::Fanotify,
      }),
    );
    let effects = drain(&mut core);
    assert!(
      !effects
        .iter()
        .any(|e| matches!(e, Effect::AddWatch { .. }) | matches!(e, Effect::Enumerate { .. })),
      "an adopted KR profile arms no per-directory watch: {effects:?}"
    );
    assert_eq!(
      refresh_requests(&effects),
      1,
      "the KR scope still arms its birth refresh: {effects:?}"
    );
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));

    // A kernel-recursive fanotify event lowers root-relative with no
    // per-directory arm — only possible under the adopted KR profile.
    let event = RawLinuxEvent::Fanotify(AdmittedEvent {
      mask: FanMask::new(FAN_CREATE),
      path: Some(PathBuf::from("/r/deep/child.txt")),
      identity: NonZeroU64::new(9),
      rename: None,
    });
    core.on_batch(
      scope,
      BatchPayload::detached(vec![SourceEvent::Linux(event)]),
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      !effects.iter().any(|e| matches!(e, Effect::AddWatch { .. })),
      "the KR event needs no arm: {effects:?}"
    );
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{effects:?}");
    assert!(emitted[0].kind().is_created());
    assert_eq!(emitted[0].location(), &loc(&["deep", "child.txt"]));
  }

  /// Provisional inotify AND the probe resolved inotify (the Auto fallback):
  /// the profile is unchanged, so the descending flow runs — the spawn arms the
  /// ROOT through the effect path (a per-directory AddWatch), exactly as a
  /// forced inotify would.
  #[test]
  fn auto_provisional_inotify_keeps_inotify_on_fallback() {
    let mut core = DriverCore::new(WINDOW);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Inotify,
      }),
    );
    let effects = drain(&mut core);
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { watch, parent, path, .. }
          if path.as_path() == Path::new("/r") && watch == parent
      )),
      "the descending root arms through the effect path: {effects:?}"
    );
  }
}
