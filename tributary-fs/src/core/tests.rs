use super::*;
use std::time::Duration;

const WINDOW: Duration = Duration::from_millis(100);
/// The root-liveness tick interval the shared harness cores run with. Only a
/// fanotify scope arms it, and the FSEvents/inotify suites never drive time
/// this far, so it is inert everywhere except the fanotify liveness-tick suite.
const LIVENESS: Duration = Duration::from_secs(30);

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
    // No frame change exercised: the captured `root_mnt_id` stays intact.
    root_mnt_id: None,
  }
}

/// A core with one live scope rooted at `/r` on device 1, its birth refresh
/// fed (an authoritative empty table): event-side trust is open.
fn live_core() -> (DriverCore, ScopeId) {
  let mut core = DriverCore::new(WINDOW, LIVENESS);
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
      root_mnt_id: None,
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
  let mut core = DriverCore::new(WINDOW, LIVENESS);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
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
      root_mnt_id: None,
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
        root_mnt_id: None,
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
      root_mnt_id: None,
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
    root_mnt_id: None,
    identity: Some(crate::os::RootIdentity::new(1, 1)),
    mounts: vec![PathBuf::from("/r/vol")],
    mounts_authoritative: true,
    refresh_pending: false,
    refresh_stale: false,
    lag: LagState::Normal,
    park: Park::default(),
    resume_poisoned: false,
    publicly_live: true,
    liveness_deadline: None,
    applied_cover: None,
    settle_floor: None,
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
    root_mnt_id: None,
    identity: Some(crate::os::RootIdentity::new(1, 1)),
    mounts: Vec::new(),
    mounts_authoritative: false,
    refresh_pending: false,
    refresh_stale: false,
    lag: LagState::Normal,
    park: Park::default(),
    resume_poisoned: false,
    publicly_live: true,
    liveness_deadline: None,
    applied_cover: None,
    settle_floor: None,
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
  let mut core = DriverCore::new(WINDOW, LIVENESS);
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
      root_mnt_id: None,
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
  let mut core = DriverCore::new(WINDOW, LIVENESS);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
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
  let mut core = DriverCore::new(WINDOW, LIVENESS);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
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
  let mut core = DriverCore::new(WINDOW, LIVENESS);
  let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents);
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
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
  let mut core = DriverCore::new(WINDOW, LIVENESS);
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
  let mut core = DriverCore::new(WINDOW, LIVENESS);
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

/// The set-cover broadening-delta rule, in isolation and cross-platform: the
/// retained prefixes a re-issued cover must re-arm are exactly those the PREVIOUS applied cover
/// did not already cover — never keyed on which watches happen to survive, so growing back to a
/// retained ANCESTOR (whose connecting watch is still armed) or to the whole root re-arms the
/// descendants the narrower cover pruned.
#[test]
fn broadening_delta_is_the_uncovered_retained_prefixes() {
  let p = |s: &str| PathBuf::from(s);

  // No previous cover (FULL) — nothing was pruned, so growing to any cover re-arms nothing.
  assert!(broadening_delta(None, &[p("/r/a"), p("/r/b")]).is_empty());

  // A prefix INSIDE a previously-retained subtree was never pruned — not broadening.
  let prev = [p("/r/a")];
  assert!(broadening_delta(Some(&prev), &[p("/r/a")]).is_empty());
  assert!(
    broadening_delta(Some(&prev), &[p("/r/a/x")]).is_empty(),
    "deeper inside a retained subtree is already covered"
  );

  // A sibling OUTSIDE every previously-retained subtree is broadening — its subtree was pruned.
  assert_eq!(
    broadening_delta(Some(&prev), &[p("/r/a"), p("/r/b")]),
    vec![Path::new("/r/b")],
    "a sibling outside the previous cover must be re-armed"
  );

  // Growing to a retained ANCESTOR of the previous cover is broadening: the ancestor kept its
  // connecting watch, but its OTHER descendants were pruned (the exact retained-ancestor case).
  let deep = [p("/r/a/b/deep")];
  assert_eq!(
    broadening_delta(Some(&deep), &[p("/r/a/b")]),
    vec![Path::new("/r/a/b")],
    "an ancestor of the previous cover is broadening — its other descendants were pruned"
  );

  // The root-key / full-cover cancel broadens against any narrower cover (re-arm everything).
  assert_eq!(
    broadening_delta(Some(&deep), &[p("/r")]),
    vec![Path::new("/r")],
    "a root-key cancel is broadening against any narrower cover"
  );
}

/// The antichain MEET the settle floor folds with — the coverage guaranteed by
/// BOTH covers: the deeper prefix of each nested pair, nothing from disjoint
/// pairs, `None` (FULL) as the identity, and the result normalized to cover
/// form.
#[test]
fn cover_meet_is_the_coverage_guaranteed_by_both() {
  let p = |s: &str| PathBuf::from(s);

  // FULL (`None`) is the meet identity: meet(FULL, A) = A.
  assert_eq!(
    cover_meet(None, &[p("/x"), p("/y")]),
    vec![p("/x"), p("/y")],
    "full coverage guarantees whatever the other cover does"
  );

  // A nested pair keeps the DEEPER prefix — the intersection of the two subtrees.
  assert_eq!(cover_meet(Some(&[p("/x")]), &[p("/x/y")]), vec![p("/x/y")]);
  assert_eq!(cover_meet(Some(&[p("/x/y")]), &[p("/x")]), vec![p("/x/y")]);

  // Disjoint covers guarantee NOTHING in common — an empty meet is meaningful.
  assert_eq!(
    cover_meet(Some(&[p("/x")]), &[p("/z")]),
    Vec::<PathBuf>::new()
  );

  // Equal prefixes meet to themselves, once (dedup).
  assert_eq!(cover_meet(Some(&[p("/x")]), &[p("/x")]), vec![p("/x")]);

  // Pairwise over antichains: each nested pair contributes its deeper member;
  // members nested in nothing on the other side drop out.
  assert_eq!(
    cover_meet(
      Some(&[p("/r/a"), p("/r/b")]),
      &[p("/r/a/deep"), p("/r/b"), p("/r/c")]
    ),
    vec![p("/r/a/deep"), p("/r/b")]
  );

  // Cover normal form: a NON-antichain input ({/x/y} beside {/x}) collapses —
  // the pairwise set {/x/y, /x} prunes the member inside the other's subtree,
  // because cover({/x/y, /x}) IS cover({/x}).
  assert_eq!(
    cover_meet(Some(&[p("/x")]), &[p("/x/y"), p("/x")]),
    vec![p("/x")]
  );

  // Prefix tests are componentwise, never byte-wise: /xy is not under /x.
  assert_eq!(
    cover_meet(Some(&[p("/x")]), &[p("/xy")]),
    Vec::<PathBuf>::new()
  );
}

/// The `Noop` refusals that need no descending machinery: an unknown scope,
/// and a kernel-recursive scope — its whole-subtree coverage never narrowed,
/// reported explicitly as `KernelRecursive` rather than walked as silence.
/// Neither records `applied_cover` (the stream was never reconciled) nor opens
/// a fence window. The remaining refusals (`NotLive`, `RefusedCover`) and the
/// recording behavior live with the descending suites below.
#[test]
fn set_cover_refuses_unknown_and_kernel_recursive_scopes() {
  let (mut core, scope) = live_core(); // FSEvents: kernel-recursive
  assert_eq!(
    core.on_set_cover(scope, &[PathBuf::from("/r/a")]),
    CoverReconcile::Noop(CoverNoop::KernelRecursive),
    "kernel-recursive coverage never narrowed — an explicit refusal, not a silent walk"
  );
  let state = core.scopes.get(&scope).unwrap();
  assert_eq!(
    state.applied_cover, None,
    "a refused cover is never recorded"
  );
  assert_eq!(state.settle_floor, None);
  assert!(
    core.cover_fences.is_empty(),
    "a refusal opens no fence window"
  );

  let ghost = ScopeId::new(NonZeroU64::new(999).unwrap());
  assert_eq!(
    core.on_set_cover(ghost, &[PathBuf::from("/r/a")]),
    CoverReconcile::Noop(CoverNoop::UnknownScope),
  );
}

/// A kernel-recursive scope's `Rescan` churn creates NO set-cover loss memory:
/// its coverage never narrows (`on_set_cover` refuses it before recording
/// anything), so `applied_cover` is never `Some`, there is no claim to
/// degrade, and the route-time loss handling skips the scope entirely rather
/// than cycling map entries on every overflow.
#[test]
fn kernel_recursive_rescan_creates_no_loss_memory() {
  let (mut core, scope) = live_core();
  core.on_root_overflow(scope, at(2));
  let effects = drain(&mut core);
  assert!(
    emits(&effects).iter().any(|c| c.kind().is_rescan()),
    "the overflow's covering Rescan is delivered: {effects:?}"
  );
  assert!(
    core.cover_fences.is_empty(),
    "no loss-memory entry for a kernel-recursive scope"
  );
  let state = core.scopes.get(&scope).unwrap();
  assert_eq!(state.applied_cover, None);
  assert_eq!(state.settle_floor, None);
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
      root_mnt_id: None,
      identity: Some(crate::os::RootIdentity::new(1, 1)),
      mounts: Vec::new(),
      mounts_authoritative: true,
      refresh_pending: false,
      refresh_stale: false,
      lag: LagState::Normal,
      park: Park::default(),
      resume_poisoned: false,
      publicly_live: true,
      liveness_deadline: None,
      applied_cover: None,
      settle_floor: None,
    }
  }

  /// The pure mount-boundary decision the enumerate lowering fences on. The mount
  /// id is the PRIMARY fence (a same-device bind is caught by a differing mount id);
  /// the device is the belt that governs when a mount id is unknown on either side.
  #[test]
  fn crosses_mount_boundary_truth_table() {
    fn raw(dev: u64, mnt_id: Option<u64>) -> RawDirEntry {
      RawDirEntry {
        name: b"x".to_vec(),
        kind: FileKind::Dir,
        dev,
        ino: 9,
        mnt_id,
      }
    }
    let mut both_known = state_with_root("/r");
    both_known.root_dev = Some(1);
    both_known.root_mnt_id = Some(42);
    // Both mount ids known: the mount id alone decides — a same-device bind on a
    // different mount IS a boundary; a same-mount child is not.
    assert!(
      crosses_mount_boundary(&both_known, &raw(1, Some(77))),
      "a same-device child on a different mount is a boundary (the bind breach)"
    );
    assert!(
      !crosses_mount_boundary(&both_known, &raw(1, Some(42))),
      "a same-mount child is in-root even though a separate device would not be"
    );
    assert!(
      crosses_mount_boundary(&both_known, &raw(2, Some(42))),
      "a different device is still a boundary even when the mount id happens to match"
    );
    // Child mount id unknown (below 5.8 / mask unset): the device belt governs.
    assert!(
      !crosses_mount_boundary(&both_known, &raw(1, None)),
      "a same-device child with an unknown mount id is NOT over-fenced — the belt governs"
    );
    assert!(
      crosses_mount_boundary(&both_known, &raw(2, None)),
      "a foreign-device child with an unknown mount id is a boundary by the belt"
    );
    // Root mount id unknown (the whole scope has no mount id): device belt only.
    let mut root_unknown = state_with_root("/r");
    root_unknown.root_dev = Some(1);
    root_unknown.root_mnt_id = None;
    assert!(
      !crosses_mount_boundary(&root_unknown, &raw(1, Some(77))),
      "with the root mount id unknown, a same-device child is in-root regardless of its mount id"
    );
    assert!(
      crosses_mount_boundary(&root_unknown, &raw(2, Some(77))),
      "with the root mount id unknown, the device belt still fences a foreign device"
    );
    // Root device unknown (an off-unix fake): never a boundary — one scope.
    let mut dev_unknown = state_with_root("/r");
    dev_unknown.root_dev = None;
    dev_unknown.root_mnt_id = None;
    assert!(
      !crosses_mount_boundary(&dev_unknown, &raw(2, Some(77))),
      "with an unknown root device (off-unix fake), nothing crosses the boundary"
    );
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
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = core.on_watch(PathBuf::from("/"), Interest::all(), BackendKind::FsEvents);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/"),
        root_dev: 1,
        root_mnt_id: None,
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
      mnt_id: None,
    }
  }

  /// An enumerated entry on the root's DEVICE but a differing MOUNT id — a
  /// `mount --bind` of a same-superblock directory, the boundary the device check
  /// alone misses. The scope's `root_mnt_id` must be set (see `live_descending_mnt`)
  /// for the fence to fire.
  fn entry_on_mount(name: &str, kind: FileKind, dev: u64, ino: u64, mnt_id: u64) -> RawDirEntry {
    RawDirEntry {
      name: name.as_bytes().to_vec(),
      kind,
      dev,
      ino,
      mnt_id: Some(mnt_id),
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
    live_descending_with(None)
  }

  /// Like [`live_descending`] but with the scope's root MOUNT id set, so the
  /// enumerate lowering fences a same-device child on a different mount (a bind).
  fn live_descending_mnt(root_mnt_id: u64) -> (DriverCore, ScopeId, ReqId, WatchId) {
    live_descending_with(Some(root_mnt_id))
  }

  fn live_descending_with(root_mnt_id: Option<u64>) -> (DriverCore, ScopeId, ReqId, WatchId) {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
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
        root_mnt_id,
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

  /// Spawns a descending scope at `root` and returns it with its PENDING root
  /// arm — the stream is live and `root` is populated, but coverage (and the
  /// caller's deferred grant) does not begin until the root arm resolves.
  fn spawned_with_pending_root_arm_at(core: &mut DriverCore, root: &str) -> (ScopeId, WatchId) {
    let scope = core.on_watch(PathBuf::from(root), Interest::all(), BackendKind::Inotify);
    let _ = drain(core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from(root),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Inotify,
      }),
    );
    let root_watch = drain(core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch {
          watch,
          parent,
          path,
          ..
        } if path.as_path() == Path::new(root) && watch == parent => Some(*watch),
        _ => None,
      })
      .expect("the descending root arms through the effect path");
    (scope, root_watch)
  }

  /// A live descending scope at `root`: spawned, root arm installed, birth
  /// refresh fed — publicly live and delivering. Returns the scope and its root
  /// watch (the anchor a live record attributes to).
  fn live_descending_at(core: &mut DriverCore, root: &str) -> (ScopeId, WatchId) {
    let (scope, root_watch) = spawned_with_pending_root_arm_at(core, root);
    core.on_watch_installed(root_watch, crate::os::linux::WatchOutcome::Installed(1));
    // Consume the cold enumerate the successful root arm queues.
    let req = drain(core).iter().find_map(|e| match e {
      Effect::Enumerate { req, watch, .. } if *watch == root_watch => Some(*req),
      _ => None,
    });
    if let Some(req) = req {
      core.on_enumerated(req, listed(Vec::new()));
      let _ = drain(core);
    }
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(core);
    (scope, root_watch)
  }

  /// A descending scope's ROOT ARM failing is a NEVER-LIVE end: the caller's
  /// deferred grant resolved `Err` (the driver answers before this feeds the
  /// core), so the Monitor's root-watch failure `Rescan` must NOT be emitted —
  /// the fence keys on public liveness (the root arm), not on `root` being
  /// populated at spawn. The scope tears down silently, and no dying-retry timer
  /// promotes anything.
  #[test]
  fn descending_root_arm_failure_is_never_live_and_silent() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let (scope, root_watch) = spawned_with_pending_root_arm_at(&mut core, "/r");
    core.on_watch_installed(
      root_watch,
      crate::os::linux::WatchOutcome::Failed(WatchError::NotFound),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty(),
      "a failed root arm emits no public event (the deferred grant already got Err): {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the never-live scope tears down: {effects:?}"
    );
    assert_eq!(
      core.poll_timeout(),
      None,
      "a never-live scope arms no dying-retry timer"
    );
    core.on_timeout(at(10_000));
    assert!(
      emits(&drain(&mut core)).is_empty(),
      "nothing to retry for a never-publicly-live scope"
    );
  }

  /// A root-arm failure while a SIBLING scope is live and emitting: the fence is
  /// per-scope, so the live sibling delivers normally and only the failed scope
  /// stays silent — and the failed scope promotes no dying delivery.
  #[test]
  fn root_arm_failure_leaves_a_live_sibling_untouched() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let (live, live_root) = live_descending_at(&mut core, "/live");
    let (failed, failed_root) = spawned_with_pending_root_arm_at(&mut core, "/r");
    core.on_watch_installed(
      failed_root,
      crate::os::linux::WatchOutcome::Failed(WatchError::NotFound),
    );
    let _ = drain(&mut core);
    // The live sibling still delivers a depth-one create.
    core.on_inotify_events(
      live,
      vec![inotify(&[live_root], IN_CREATE, 0, Some(b"hot.txt"))],
      at(2),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      !emitted.is_empty() && emitted.iter().all(|c| c.scope() == live),
      "only the live sibling emits; the failed scope stays silent: {effects:?}"
    );
    assert!(
      emitted
        .iter()
        .any(|c| c.kind().is_created() && c.location() == &loc(&["hot.txt"])),
      "the live sibling's create is delivered: {effects:?}"
    );
    assert!(
      !core.dying_contains(failed),
      "the never-live failed scope promotes no dying delivery"
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
  fn same_device_bind_on_a_different_mount_is_not_descended() {
    // The bind breach the device check alone misses: `bound` shares the root's
    // DEVICE (1) but sits on a DIFFERENT mount id (77) — a `mount --bind` of a
    // same-superblock directory. The mount-id fence lowers it non-descendable while
    // `here` (same mount, 42) is descended.
    let (mut core, _scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![
        entry_on_mount("bound", FileKind::Dir, 1, 20, 77),
        entry_on_mount("here", FileKind::Dir, 1, 21, 42),
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
      "a same-device directory on a DIFFERENT mount (a bind) is fenced by mount id, \
       never descended, though its device equals the root's: {effects:?}"
    );
  }

  #[test]
  fn mount_id_unknown_falls_back_to_the_device_check() {
    // The honest below-5.8 degrade: the scope reports a root mount id (42), but the
    // executor could not read the child's (`mnt_id: None`). The fence declines and
    // the DEVICE belt governs — a same-device child is descended (not over-fenced on
    // a mount-id read miss), a foreign-device one is not.
    let (mut core, _scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![
        entry("same_dev", FileKind::Dir, 1, 20),
        entry("foreign_dev", FileKind::Dir, 2, 21),
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
      vec![Path::new("/r/same_dev")],
      "with the child mount id unknown, the device belt alone decides: the \
       same-device child is descended, the foreign-device one is not: {effects:?}"
    );
  }

  /// A same-object RE-MOUNT of the root (unmount + re-bind: `(dev, ino)` unchanged,
  /// so the refresh's death gate passes, but the root now lives on a NEW mount)
  /// updates the scope's descent-fence frame through `on_mounts_refreshed` — so
  /// after the refresh a child on the NEW mount is descended and one on the OLD
  /// frame is fenced. Without the frame refresh, every descendant on the re-mounted
  /// root would read as a boundary (its mount id differs from the frozen spawn one)
  /// and lower non-descendable until re-watch — the inotify-side shape of the
  /// fanotify live-walk staleness (design §7).
  #[test]
  fn root_remount_refreshes_the_descent_fence_frame() {
    // Spawn on mount 42, then cold-enumerate the root: a `sub` on mount 42 (same
    // frame) is descended and armed; a `bound42on77` on mount 77 is a boundary. This
    // is the BASELINE frame (42) before the re-mount.
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![
        entry_on_mount("sub", FileKind::Dir, 1, 20, 42),
        entry_on_mount("bound_on_77", FileKind::Dir, 1, 21, 77),
      ]),
    );
    let effects = drain(&mut core);
    let sub_arm = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the same-frame (42) child is descended before the re-mount");
    assert!(
      !effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { path, .. } if path.as_path() == Path::new("/r/bound_on_77")
      )),
      "a mount-77 child is a boundary while the scope frame is 42: {effects:?}"
    );

    // The root is UNMOUNTED and RE-BOUND at the same path: identity `(1, 1)` is
    // unchanged (the death gate passes), but it now lives on mount 77. The refresh
    // carries the fresh frame, and the core adopts it.
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
        root_mnt_id: Some(77),
      },
      at(1),
    );
    let _ = drain(&mut core);

    // Arm the `sub` child so it cold-enumerates — a fresh enumerate that fences its
    // entries against the scope's NOW-updated frame (77). The enumerated directory
    // is `/r/sub`, but `crosses_mount_boundary` always fences on the SCOPE root's
    // frame, so this reads the refreshed value.
    core.on_watch_installed(sub_arm, crate::os::linux::WatchOutcome::Installed(2));
    let req2 = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/sub") => Some(*req),
        _ => None,
      })
      .expect("the armed child cold-enumerates after the re-mount refresh");

    // Under the NEW frame (77): a child on mount 77 is now DESCENDED, and one back on
    // the OLD frame (42) is now the boundary — the fence flipped with the refresh.
    core.on_enumerated(
      req2,
      listed(vec![
        entry_on_mount("now_in_root", FileKind::Dir, 1, 30, 77),
        entry_on_mount("now_boundary", FileKind::Dir, 1, 31, 42),
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
      vec![Path::new("/r/sub/now_in_root")],
      "after the same-object re-mount refresh, the scope frame is 77: a mount-77 child \
       descends and a mount-42 (old-frame) child is fenced — the frame followed the \
       re-mount: {effects:?}"
    );
  }

  /// A transient mnt-id read MISS on a refresh (`root_mnt_id: None`) must NOT drop
  /// the scope's known frame to the device belt: a captured `Some(42)` survives, so
  /// the mount-id fence keeps working across a refresh that momentarily could not
  /// read the frame. Guards the "only adopt a `Some`" rule in `on_mounts_refreshed`.
  #[test]
  fn refresh_with_no_frame_keeps_the_captured_one() {
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![entry_on_mount("sub", FileKind::Dir, 1, 20, 42)]),
    );
    let sub_arm = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the same-frame child is descended and armed");

    // A refresh that could not read the root's mount id (below 5.8, a mask miss): the
    // frame is left intact, NOT dropped.
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
        root_mnt_id: None,
      },
      at(1),
    );
    let _ = drain(&mut core);

    // The next enumerate still fences on the captured frame (42): a mount-77 child is
    // still a boundary (the fence did not degrade to device-only).
    core.on_watch_installed(sub_arm, crate::os::linux::WatchOutcome::Installed(2));
    let req2 = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/sub") => Some(*req),
        _ => None,
      })
      .expect("the armed child cold-enumerates");
    core.on_enumerated(
      req2,
      listed(vec![entry_on_mount(
        "still_boundary",
        FileKind::Dir,
        1,
        30,
        77,
      )]),
    );
    let effects = drain(&mut core);
    assert!(
      !effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { path, .. } if path.as_path() == Path::new("/r/sub/still_boundary")
      )),
      "a None-frame refresh kept the captured frame (42), so a mount-77 child is still \
       fenced — a transient read miss never drops a known frame: {effects:?}"
    );
  }

  /// Frame adoption is gated behind the identity match: a refresh whose sample is a
  /// REPLACED root (a different `(dev, ino)`) carrying a fresh frame takes the death
  /// path and NEVER adopts that frame. Because the executor now samples identity and
  /// frame from ONE object, a `Present`-but-mismatched verdict IS that replacement's
  /// own frame — adopting it would fence the live (still-original) scope's children
  /// against the replacement's mount. `on_mounts_refreshed` evaluates the death gate
  /// first and returns, so the frame block never runs; this pins that pairing.
  #[test]
  fn a_replaced_root_refresh_never_adopts_the_new_objects_frame() {
    // Spawn on frame 42, descend a same-frame child so the scope has armed coverage
    // and a captured frame to (not) overwrite.
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![entry_on_mount("sub", FileKind::Dir, 1, 20, 42)]),
    );
    let sub_arm = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the same-frame child is descended and armed");
    core.on_watch_installed(sub_arm, crate::os::linux::WatchOutcome::Installed(2));
    let _ = drain(&mut core);

    // The refresh's ONE sample is a REPLACED object (ino 999, was ino 1) on a new
    // mount (77). Identity mismatch ⇒ MoveSelf death; the frame (77) rides the SAME
    // sample but must NOT be adopted.
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 999)),
        root_mnt_id: Some(77),
      },
      at(1),
    );
    let effects = drain(&mut core);

    // A replaced root is a MoveSelf: it lowers its terminal Rescan (no Removed) and
    // tears the stream down — the frame was never adopted because the identity did
    // not match. A dead, torn-down scope has no live frame to observe: the teardown
    // IS the proof the frame block never ran (it sits after the death gate, which
    // returned first).
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "a replaced root rescans (no Removed): {effects:?}"
    );
    assert!(
      emitted[0].kind().is_rescan(),
      "the replaced-root MoveSelf lowers its terminal rescan, never silent"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the replaced root's stream tears down rather than adopting the new frame: {effects:?}"
    );
  }

  /// A STALE refresh never publishes the descent frame. A loss overlapped the read,
  /// so its snapshot may predate the lost window; the frame it carries is as suspect
  /// as its mount table, and gating the adoption behind the stale check keeps
  /// `crosses_mount_boundary` reading only an authoritative frame — the exact hole a
  /// pre-stale-gate adoption left (an overflow re-arm consuming a discarded frame).
  #[test]
  fn a_stale_refresh_never_publishes_the_descent_frame() {
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![entry_on_mount("sub", FileKind::Dir, 1, 20, 42)]),
    );
    let _ = drain(&mut core);

    // A loss marked the outstanding refresh stale; it then completes ALIVE but
    // carries a DIFFERENT frame (77) that must NOT be adopted.
    core
      .scopes
      .get_mut(&scope)
      .expect("scope is live")
      .refresh_stale = true;
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
        root_mnt_id: Some(77),
      },
      at(1),
    );
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      1,
      "a stale completion re-arms exactly one fresh read"
    );
    assert_eq!(
      core.scopes.get(&scope).expect("scope is live").root_mnt_id,
      Some(42),
      "a stale refresh publishes NOTHING — the captured authoritative frame survives, \
       so an overflow re-arm can never fence current-mount children under a discarded frame"
    );
  }

  /// Death-first ordering under the frame gate: the root-liveness verdict is
  /// evaluated BEFORE the stale gate, so a stale refresh whose root is GONE still
  /// dies — even though it also carries a (never-adopted) frame. Moving the frame
  /// adoption behind the stale gate must not regress that ordering.
  #[test]
  fn a_stale_refresh_finding_the_root_gone_still_dies() {
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![entry_on_mount("sub", FileKind::Dir, 1, 20, 42)]),
    );
    let _ = drain(&mut core);

    core
      .scopes
      .get_mut(&scope)
      .expect("scope is live")
      .refresh_stale = true;
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Missing,
        root_mnt_id: Some(77),
      },
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      2,
      "a gone root still dies through the stale gate: {effects:?}"
    );
    assert!(emitted[0].kind().is_removed(), "a gone root is a Removed");
    assert!(emitted[1].kind().is_rescan(), "root death is never silent");
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the dead root's stream tears down even under a stale completion: {effects:?}"
    );
  }

  /// The re-arm-replay: a NON-stale refresh whose frame CHANGED (a same-object
  /// re-mount) reconciles the children the last enumerate already classified. Adopting
  /// the new frame keeps FUTURE enumerates correct, but a child fenced as a boundary
  /// under the OLD frame is not re-read by the adoption alone — the frame change
  /// rescans-and-re-arms the root so it is re-checked, closing the blind subtree the
  /// overflow re-arm would otherwise leave (its enumerate races AHEAD of the frame
  /// adoption and reads the pre-adoption frame).
  #[test]
  fn a_changed_frame_reconciles_already_classified_children() {
    // Frame 42: `stays` (mount 42) is descended, `arrives` (mount 77) is a boundary.
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![
        entry_on_mount("stays", FileKind::Dir, 1, 20, 42),
        entry_on_mount("arrives", FileKind::Dir, 1, 21, 77),
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
      vec![Path::new("/r/stays")],
      "before the re-mount only the mount-42 child is descended: {effects:?}"
    );

    // The same-object re-mount moves the root to mount 77 (identity unchanged). The
    // non-stale refresh adopts the new frame AND reconciles.
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
        root_mnt_id: Some(77),
      },
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the frame change reconciles with a covering rescan: {effects:?}"
    );
    let req2 = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the frame-change reconcile re-enumerates the root under the new frame");

    // The reconcile re-enumerate reads the SAME children under frame 77: `arrives`
    // (mount 77) is now in-scope and gets watched — no blind subtree — while `stays`
    // (mount 42) is now the boundary the re-mount left behind.
    core.on_enumerated(
      req2,
      listed(vec![
        entry_on_mount("stays", FileKind::Dir, 1, 20, 42),
        entry_on_mount("arrives", FileKind::Dir, 1, 21, 77),
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
    assert!(
      armed.contains(&Path::new("/r/arrives")),
      "the reconcile watches the mount-77 child fenced under the old frame — no blind \
       subtree: {effects:?}"
    );
    assert!(
      !armed.contains(&Path::new("/r/stays")),
      "the mount-42 child the re-mount left behind is now the boundary: {effects:?}"
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
        mnt_id: None,
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

  // --- The set-cover fence: reconcile disposition, lossy window, settle floor ---

  fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
  }

  /// The root listing the fence suites share: two subdirectories on the root
  /// device, stable inode identities so a re-arm read identity-keeps a live
  /// survivor.
  fn root_listing() -> Vec<RawDirEntry> {
    vec![
      entry("keep", FileKind::Dir, 1, 11),
      entry("drop", FileKind::Dir, 1, 12),
    ]
  }

  /// Answers every queued arm with `Installed` and every queued enumerate with
  /// its listing from `listings` (absent paths list empty), repeating until a
  /// drain holds neither — the hand-driven equivalent of the async driver's
  /// execute-effects loop, quiescing a discovery or re-arm cascade.
  fn run_cascade(core: &mut DriverCore, listings: &BTreeMap<&str, Vec<RawDirEntry>>) {
    let mut wd = 100;
    for _ in 0..32 {
      let effects = drain(core);
      let mut progressed = false;
      for effect in &effects {
        match effect {
          Effect::AddWatch { watch, .. } => {
            wd += 1;
            core.on_watch_installed(*watch, crate::os::linux::WatchOutcome::Installed(wd));
            progressed = true;
          }
          Effect::Enumerate { req, path, .. } => {
            let entries = listings
              .get(path.to_str().expect("test paths are UTF-8"))
              .cloned()
              .unwrap_or_default();
            core.on_enumerated(*req, listed(entries));
            progressed = true;
          }
          _ => {}
        }
      }
      if !progressed {
        return;
      }
    }
    panic!("the cascade did not quiesce within the iteration bound");
  }

  /// A live descending scope at `/r` whose cold discovery armed `keep` and
  /// `drop`, then shrunk in place to `{/r/keep}` with the shrink's window
  /// already observed settled and CLEAN: `drop`'s watch is pruned and
  /// `applied_cover == settle_floor == {/r/keep}` — the shared start of the
  /// grow-fence suites.
  fn shrunk_to_keep() -> (DriverCore, ScopeId, WatchId) {
    let (mut core, scope, req, root_watch) = live_descending();
    core.on_enumerated(req, listed(root_listing()));
    run_cascade(&mut core, &BTreeMap::new());
    assert!(
      core.monitor.rearm_settled(scope),
      "cold discovery is not re-arm work"
    );
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    assert!(
      drain(&mut core)
        .iter()
        .any(|e| matches!(e, Effect::RemoveWatch { .. })),
      "the shrink prunes /r/drop"
    );
    // A shrink grows nothing, so the scope reads settled at once: the
    // observation is immediate, fence-less, and clean — it resets the floor
    // to the applied cover and clears the scope's fence entry.
    assert_eq!(core.poll_cover_settlements(), Vec::new());
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(state.applied_cover, Some(vec![p("/r/keep")]));
    assert_eq!(state.settle_floor, Some(vec![p("/r/keep")]));
    assert!(core.cover_fences.is_empty());
    (core, scope, root_watch)
  }

  /// `on_set_cover` validates the retained cover against the LIVE scope root
  /// before acting on it, reporting each refusal as a typed `Noop`. A cover
  /// ENTIRELY outside the root is a caller error — refused (`RefusedCover`, no
  /// prune, `applied_cover` untouched), so a typo / relative / stale path can
  /// never mark every in-root watch strictly-outside and SILENTLY PRUNE the
  /// whole scope; a PARTIALLY out-of-root cover proceeds with the in-root
  /// subset only. Exercised on a childless descending scope: prune/grow are
  /// structural no-ops, so the observable effect is exactly the filter + the
  /// `applied_cover` recording it guards.
  #[test]
  fn set_cover_validates_retained_against_the_scope_root() {
    let (mut core, scope, req, _root) = live_descending();
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);
    let applied = |core: &DriverCore| core.scopes.get(&scope).unwrap().applied_cover.clone();

    // (1) A cover ENTIRELY outside the root is refused: nothing pruned, `applied_cover`
    // stays `None` — a typo / relative / stale path can never silently collapse coverage.
    assert_eq!(
      core.on_set_cover(scope, &[p("/outside"), p("relative/x")]),
      CoverReconcile::Noop(CoverNoop::RefusedCover),
    );
    assert_eq!(
      applied(&core),
      None,
      "an all-out-of-root cover is refused — never recorded, never a full prune"
    );

    // (1b) An EMPTY cover is refused the same way (defensive — never prune the whole tree).
    assert_eq!(
      core.on_set_cover(scope, &[]),
      CoverReconcile::Noop(CoverNoop::RefusedCover),
    );

    // (2) The root itself is a valid retained prefix (the boundary case): honored and recorded.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r")]),
      CoverReconcile::Reconciling
    );
    assert_eq!(
      applied(&core),
      Some(vec![p("/r")]),
      "the root path itself is within the root and honored"
    );

    // (3) A MIXED cover proceeds with the in-root subset ONLY — the out-of-root prefix is dropped.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/a"), p("/elsewhere")]),
      CoverReconcile::Reconciling
    );
    assert_eq!(
      applied(&core),
      Some(vec![p("/r/a")]),
      "only the in-root prefix is honored; the out-of-root one is filtered away"
    );

    // (3b) An ESCAPING path that lexically begins with the root — `Path::starts_with` does not
    // resolve `..` — is refused too: a canonical retained path never carries
    // `.`/`..` components, so any that does is a caller error, never honored (alone or mixed).
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/../outside")]),
      CoverReconcile::Noop(CoverNoop::RefusedCover),
    );
    assert_eq!(
      applied(&core),
      Some(vec![p("/r/a")]),
      "a dot-dot-escaping cover is refused — never recorded, never a prune"
    );
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/b"), p("/r/./b/../../etc")]),
      CoverReconcile::Reconciling
    );
    assert_eq!(
      applied(&core),
      Some(vec![p("/r/b")]),
      "in a mixed cover, only the canonical in-root prefix survives the component check"
    );

    // (4) A later all-out-of-root cover is STILL refused — it must not overwrite or reset the
    // prior, still-correct coverage (the `/r/b` recorded by the mixed case above).
    assert_eq!(
      core.on_set_cover(scope, &[p("/bad")]),
      CoverReconcile::Noop(CoverNoop::RefusedCover),
    );
    assert_eq!(
      applied(&core),
      Some(vec![p("/r/b")]),
      "an all-out-of-root cover leaves the prior applied cover untouched"
    );
  }

  /// A set-cover between a descending scope's SPAWN and its root-arm GRANT is
  /// refused `NotLive`: the root's arm is still COLD, and a grow would mark it
  /// re-arm-flavored — suppressing the initial inventory's `Created`s (re-arms
  /// deliberately emit none). The refusal perturbs nothing, and the later cold
  /// discovery delivers its inventory intact.
  #[test]
  fn set_cover_before_the_grant_is_refused_not_live() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let (scope, root_watch) = spawned_with_pending_root_arm_at(&mut core, "/r");
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Noop(CoverNoop::NotLive),
    );
    // A second pre-grant cover must stay refused too: recording the first would
    // seed the broadening delta whose grow performs the cold-to-re-arm conversion.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/other")]),
      CoverReconcile::Noop(CoverNoop::NotLive),
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(state.applied_cover, None, "a refused cover records nothing");
    assert_eq!(state.settle_floor, None);
    assert!(
      core.cover_fences.is_empty(),
      "no fence window opens pre-grant"
    );

    // The grant commits: the root arms, cold-enumerates, and the inventory's
    // `Created`s flow — cold discovery was not converted into a re-arm.
    core.on_watch_installed(root_watch, crate::os::linux::WatchOutcome::Installed(1));
    let req = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, watch, .. } if *watch == root_watch => Some(*req),
        _ => None,
      })
      .expect("the granted root cold-enumerates");
    core.on_enumerated(req, listed(vec![entry("keep", FileKind::Dir, 1, 11)]));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_created()),
      "cold discovery still emits its inventory: {effects:?}"
    );
  }

  /// The fence's core promise: an acked grow's fence PENDS until the re-arm
  /// cascade quiesces — not until its effects are queued — and a clean window
  /// resolves `Applied`; the clean settle resets the floor to the now-truthful
  /// applied cover and clears the scope's fence state.
  #[test]
  fn cover_fence_pends_until_the_grow_cascade_settles() {
    let (mut core, scope, _root) = shrunk_to_keep();
    // Grow back: /r/drop's broadening delta re-arms its deepest still-watched
    // ancestor — the root.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    assert!(
      !core.monitor.rearm_settled(scope),
      "the grow started counted re-arm work"
    );
    assert_eq!(
      core.poll_cover_settlements(),
      Vec::new(),
      "the fence pends while the cascade runs"
    );
    // Quiesce: the root's re-arm read re-installs `drop` and cascades down
    // (`keep` is identity-kept, never re-armed).
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    assert!(core.monitor.rearm_settled(scope));
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(fence, CoverSettle::Applied)]
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(state.applied_cover, Some(vec![p("/r/keep"), p("/r/drop")]));
    assert_eq!(
      state.settle_floor, state.applied_cover,
      "a clean settle resets the floor to the truthful applied cover"
    );
    assert!(
      core.cover_fences.is_empty(),
      "settling clears the scope's fence state"
    );
  }

  /// Abandoned fences (cancelled `set_cover` callers) are pruned from the
  /// scope's pending list WITHOUT touching the loss memory, the settle-floor
  /// bookkeeping, or any still-awaited fence: only the survivors resolve at
  /// the settle, and the cover repair is identical. Fail-on-old: pending
  /// tuples lived until the settle, so an issue-and-cancel storm against a
  /// stalled scope accumulated one tuple per processed request.
  #[test]
  fn abandoned_fences_are_pruned_without_touching_the_settle_bookkeeping() {
    let (mut core, scope, _root) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    // A cancel storm: many fences opened against the stalled cascade, all but
    // one abandoned. The pending list shrinks to the survivor immediately.
    let survivor = core.open_cover_fence(scope);
    let abandoned: std::collections::BTreeSet<FenceId> =
      (0..64).map(|_| core.open_cover_fence(scope)).collect();
    assert_eq!(core.cover_fences.get(&scope).unwrap().pending.len(), 65);
    core.abandon_cover_fences(&abandoned);
    let entry = core.cover_fences.get(&scope).unwrap();
    assert_eq!(
      entry.pending.len(),
      1,
      "the abandoned tuples are gone; the awaited fence survives"
    );
    assert!(!entry.lossy, "abandonment never fabricates loss memory");
    assert_eq!(
      core.poll_cover_settlements(),
      Vec::new(),
      "the surviving fence still pends on the stalled cascade"
    );
    // Quiesce: only the survivor resolves, with the clean-settle repair intact.
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(survivor, CoverSettle::Applied)]
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(state.applied_cover, Some(vec![p("/r/keep"), p("/r/drop")]));
    assert_eq!(
      state.settle_floor, state.applied_cover,
      "the clean settle's floor reset is unaffected by the abandonment"
    );
    assert!(core.cover_fences.is_empty());
  }

  /// A `Rescan` passing `route_event` inside the window degrades the fence
  /// AND immediately degrades the coverage claim to the EMPTY cover (the
  /// `Rescan`'s cause is opaque — an overflow recovery can drop a survivor,
  /// so no narrower claim is provable) — so re-issuing the same cover
  /// computes a FULL broadening delta and the grow re-attempts. This is the
  /// applied-cover-lie regression: without the degrade, the re-issue would
  /// compute an empty delta and settle clean over the hole the failed arm
  /// left.
  #[test]
  fn lossy_window_degrades_and_rewinds_the_applied_cover() {
    let (mut core, scope, _root) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    // The re-arm read runs, but the re-installed `drop`'s ARM fails: the
    // Monitor drops the subtree and stands a covering Rescan — the loss the
    // window must catch.
    let req = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the grow re-arms the root");
    core.on_enumerated(req, listed(root_listing()));
    let effects = drain(&mut core);
    // The surviving `keep` is identity-kept and re-armed DOWNWARD — a clean
    // counted read; answer it so the failed arm below is the cascade's last
    // obligation.
    let keep = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/keep") => Some(*req),
        _ => None,
      })
      .expect("the survivor re-arms downward");
    core.on_enumerated(keep, listed(Vec::new()));
    let add = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/drop") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the re-arm re-installs the pruned directory");
    core.on_watch_installed(
      add,
      crate::os::linux::WatchOutcome::Failed(WatchError::NoSpace),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the failed arm stands a covering Rescan: {effects:?}"
    );
    // The failure ended the obligation (dropped-with-standing-Rescan): the
    // fence settles Degraded. The Rescan already degraded the claim at route
    // time, so the settle-time rewind lands on the same degraded floor.
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(fence, CoverSettle::Degraded)]
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.applied_cover,
      Some(Vec::new()),
      "the loss degrades the claim to the empty cover — nothing below the root is claimed"
    );
    assert_eq!(
      state.settle_floor,
      Some(Vec::new()),
      "the settle floor folds down with the degraded claim"
    );
    // The regression: re-issuing the SAME cover must re-attempt the grow.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let effects = drain(&mut core);
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::Enumerate { path, .. } if path.as_path() == Path::new("/r"))),
      "the degraded claim yields a full broadening delta — the grow re-attempts: {effects:?}"
    );
  }

  /// The F0 amendment end-to-end: a grow landing on a directory whose COLD
  /// read is in flight coalesces into the dirty bit — a latent obligation the
  /// settle counter deliberately does not see, so the scope reads settled
  /// while the coverage work is outstanding. The fence opened for that
  /// reconcile resolves `Degraded` (lossy from birth) even though NO Rescan
  /// passed in its window — without the born-lossy memory this poll would
  /// resolve `Applied` over the latent hole.
  #[test]
  fn coalesced_grow_makes_the_fence_lossy_from_birth() {
    let (mut core, scope, root_watch) = shrunk_to_keep();
    // Live churn re-creates `/r/drop`: cold discovery arms it and its COLD
    // read goes in flight — deliberately left unanswered.
    core.on_inotify_events(
      scope,
      vec![inotify(
        &[root_watch],
        IN_CREATE | IN_ISDIR,
        0,
        Some(b"drop"),
      )],
      at(5),
    );
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/drop") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("cold discovery arms the re-created directory");
    core.on_watch_installed(add, crate::os::linux::WatchOutcome::Installed(9));
    assert!(
      drain(&mut core).iter().any(
        |e| matches!(e, Effect::Enumerate { path, .. } if path.as_path() == Path::new("/r/drop"))
      ),
      "the cold read is in flight"
    );
    assert!(
      core.monitor.rearm_settled(scope),
      "a cold read is not re-arm work — the scope reads settled"
    );
    // The grow's delta lands exactly on the in-flight cold read: Coalesced.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    assert!(
      core.monitor.rearm_settled(scope),
      "the latent obligation is invisible to the settle counter"
    );
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(fence, CoverSettle::Degraded)],
      "a Coalesced kickoff makes the fence lossy from birth"
    );
    assert_eq!(
      core.scopes.get(&scope).unwrap().applied_cover,
      Some(vec![p("/r/keep")]),
      "the born-lossy settle rewinds to the floor like any lossy settle"
    );
  }

  /// The reply-less-reconcile interaction, both directions: (i) a coalesced
  /// reconcile with NO fence of its own (`request_set_cover` is reply-less)
  /// still marks every ALREADY-PENDING fence of the scope lossy; (ii) the loss
  /// memory clears with the settle OBSERVATION, so a fence opened for a LATER
  /// reconcile — after the latent obligation escalated, quiesced, and was
  /// observed — resolves `Applied`: nothing leaks past an observation.
  #[test]
  fn reply_less_coalesce_marks_pending_fences_and_clears_at_settle() {
    let (mut core, scope, root_watch) = shrunk_to_keep();
    // An acked reconcile with nothing to grow: its fence pends clean on an
    // already-settled scope (unpolled, so the window stays open).
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let pending = core.open_cover_fence(scope);

    // Live churn re-creates `/r/drop`; its cold read goes in flight.
    core.on_inotify_events(
      scope,
      vec![inotify(
        &[root_watch],
        IN_CREATE | IN_ISDIR,
        0,
        Some(b"drop"),
      )],
      at(5),
    );
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/drop") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("cold discovery arms the re-created directory");
    core.on_watch_installed(add, crate::os::linux::WatchOutcome::Installed(9));
    let cold = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/drop") => Some(*req),
        _ => None,
      })
      .expect("the cold read is in flight");

    // (i) The REPLY-LESS grow coalesces into the cold read: no fence of its
    // own, but the already-pending fence is marked and resolves Degraded.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(pending, CoverSettle::Degraded)],
      "a reply-less coalesce degrades the fences already pending"
    );
    assert_eq!(
      core.scopes.get(&scope).unwrap().applied_cover,
      Some(vec![p("/r/keep")]),
      "the lossy settle rewound the reply-less over-claim"
    );
    assert!(core.cover_fences.is_empty());

    // The latent obligation completes: the dirtied cold read escalates (a
    // covering Rescan plus a counted re-arm retry). The Rescan records fresh
    // loss memory — an entry of its own, no reconcile needed — and degrades
    // the rewound claim to the empty cover.
    core.on_enumerated(cold, listed(Vec::new()));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the dirtied read's completion emits the covering Rescan: {effects:?}"
    );
    assert!(
      core
        .cover_fences
        .get(&scope)
        .is_some_and(|entry| entry.lossy),
      "the Rescan records loss memory even with no unobserved reconcile"
    );
    assert_eq!(
      core.scopes.get(&scope).unwrap().applied_cover,
      Some(Vec::new()),
      "the Rescan degrades the claim to the empty cover"
    );
    let retry = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/drop") => Some(*req),
        _ => None,
      })
      .expect("the escalated re-arm retry read");
    core.on_enumerated(retry, listed(Vec::new()));
    let _ = drain(&mut core);
    assert!(core.monitor.rearm_settled(scope), "the escalation quiesced");
    // The settle OBSERVATION clears the Rescan's pending-empty entry (no fence
    // to resolve) — only now does the loss memory stop marking new fences.
    assert_eq!(core.poll_cover_settlements(), Vec::new());
    assert!(
      core.cover_fences.is_empty(),
      "the observation clears the entry the Rescan created"
    );

    // (ii) A LATER reconcile's fence starts clean: the observed memory did not
    // leak. The degraded claim makes BOTH prefixes a real broadening delta;
    // the watches are Live, so the re-arms are counted work that settles clean.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let later = core.open_cover_fence(scope);
    run_cascade(&mut core, &BTreeMap::new());
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(later, CoverSettle::Applied)],
      "the observed memory does not leak onto a later fence"
    );
  }

  /// Supersession: two acked reconciles park two fences (FIFO); both resolve
  /// at ONE settle instant, reported in open order. Coverage is latest-wins by
  /// ordered application; lossiness only accretes between settles (an opening
  /// fence inherits it, a loss marks all pending), so fences settling together
  /// agree — here both clean, both `Applied`. The first grow's cascade
  /// quiesces UN-POLLED before the superseding grow re-unsettles the scope:
  /// had the second cascade instead re-armed a child whose re-arm read was
  /// still IN FLIGHT, it would dirty that read, whose completion stands a
  /// `Rescan` (the Monitor's dirty-window recovery) — and both fences would
  /// honestly degrade.
  #[test]
  fn superseding_fences_resolve_together_at_one_settle() {
    let (mut core, scope, _root) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let first = core.open_cover_fence(scope);
    // The first grow's cascade runs to quiescence — but with no settlement
    // poll in between, its fence stays pending.
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    // The superseding cover broadens further: its delta re-arms the idle root
    // with a fresh counted read, re-unsettling the scope for BOTH fences.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop"), p("/r/extra")]),
      CoverReconcile::Reconciling
    );
    let second = core.open_cover_fence(scope);
    assert_eq!(
      core.poll_cover_settlements(),
      Vec::new(),
      "both fences pend on the same scope settle"
    );
    let listing = vec![
      entry("keep", FileKind::Dir, 1, 11),
      entry("drop", FileKind::Dir, 1, 12),
      entry("extra", FileKind::Dir, 1, 13),
    ];
    run_cascade(&mut core, &BTreeMap::from([("/r", listing)]));
    assert_eq!(
      core.poll_cover_settlements(),
      vec![
        (first, CoverSettle::Applied),
        (second, CoverSettle::Applied)
      ],
      "one settle instant resolves every pending fence, FIFO"
    );
    assert_eq!(
      core.scopes.get(&scope).unwrap().applied_cover,
      Some(vec![p("/r/keep"), p("/r/drop"), p("/r/extra")]),
      "coverage is latest-wins by ordered application"
    );
  }

  /// Scope teardown mid-fence: the pending fences resolve `Degraded` (the
  /// terminal Rescan covers the caller) at the NEXT settlement poll — the
  /// driver's one choke point — and no fence state survives the scope.
  #[test]
  fn teardown_mid_fence_degrades_and_clears() {
    let (mut core, scope, _root) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    core.on_unwatch(scope);
    assert!(
      drain(&mut core)
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the unwatch tears the scope down mid-cascade"
    );
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(fence, CoverSettle::Degraded)],
      "teardown mid-fence resolves Degraded at the next poll"
    );
    assert!(
      core.cover_fences.is_empty(),
      "no fence state outlives the scope"
    );
    assert_eq!(
      core.poll_cover_settlements(),
      Vec::new(),
      "resolution is one-shot"
    );
  }

  /// Answers every enumerate in `effects` (the root with `root_listing`,
  /// children empty), then quiesces whatever that feeds — the overflow-recovery
  /// helper for the out-of-window loss suites, whose assertions need the
  /// drained effects before the cascade is served.
  fn serve_enumerates_then_quiesce(core: &mut DriverCore, effects: &[Effect]) {
    for effect in effects {
      if let Effect::Enumerate { req, path, .. } = effect {
        let listing = if path.as_path() == Path::new("/r") {
          root_listing()
        } else {
          Vec::new()
        };
        core.on_enumerated(*req, listed(listing));
      }
    }
    run_cascade(core, &BTreeMap::from([("/r", root_listing())]));
  }

  /// Out-of-window coverage loss: a covering `Rescan` landing AFTER a clean
  /// settle observation and BEFORE the next reconcile — no fence entry exists
  /// — must not leave `applied_cover` falsely authoritative. The `Rescan`
  /// creates the loss-memory entry and immediately degrades the claim to the
  /// EMPTY cover, so re-issuing the IDENTICAL cover computes a full broadening
  /// delta and re-arms the retained set; without the degrade the re-issue's
  /// delta is empty — no repair, an instant clean settle, `Applied` over the
  /// hole. The honest two-step: the first re-issue's fence inherits the
  /// pre-reissue loss memory and settles `Degraded`; the second re-issue after
  /// that observation settles `Applied`.
  #[test]
  fn out_of_window_loss_degrades_the_claim_and_the_reissue_reproves() {
    let (mut core, scope, _root) = shrunk_to_keep();
    // Grow back to {keep, drop} and OBSERVE the clean settle: the claim is
    // truthful and no fence entry remains — the out-of-window start state.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(fence, CoverSettle::Applied)]
    );
    assert!(
      core.cover_fences.is_empty(),
      "no fence entry survives the clean settle"
    );

    // The out-of-window loss: an overflow's covering Rescan with no reconcile
    // in flight. The recovery re-arm itself quiesces cleanly — the standing
    // Rescan is the only loss evidence left behind.
    core.on_root_overflow(scope, at(9));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the overflow stands a public covering Rescan: {effects:?}"
    );
    serve_enumerates_then_quiesce(&mut core, &effects);
    assert!(
      core.monitor.rearm_settled(scope),
      "the overflow recovery quiesced — the loss is fully out-of-window"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.applied_cover,
      Some(Vec::new()),
      "the loss degrades the claim immediately: nothing below the root is claimed"
    );
    assert_eq!(
      state.settle_floor,
      Some(Vec::new()),
      "the settle floor folds down with the claim"
    );
    assert!(
      core
        .cover_fences
        .get(&scope)
        .is_some_and(|entry| entry.lossy),
      "the Rescan created the loss-memory entry no reconcile had opened"
    );

    // First re-issue of the IDENTICAL cover: the degraded claim yields a FULL
    // broadening delta, so both retained prefixes re-arm.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let first = core.open_cover_fence(scope);
    let effects = drain(&mut core);
    for retained in ["/r/keep", "/r/drop"] {
      assert!(
        effects.iter().any(
          |e| matches!(e, Effect::Enumerate { path, .. } if path.as_path() == Path::new(retained))
        ),
        "the re-issue re-arms {retained} against the degraded claim: {effects:?}"
      );
    }
    serve_enumerates_then_quiesce(&mut core, &effects);
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(first, CoverSettle::Degraded)],
      "the first re-issue inherits the pre-reissue loss memory"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.applied_cover,
      Some(Vec::new()),
      "the lossy settle rewinds to the degraded floor — the claim stays unproven"
    );

    // Second re-issue after the observation: a fresh window, a full delta
    // again, and a clean settle that finally re-proves the claim.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let second = core.open_cover_fence(scope);
    let effects = drain(&mut core);
    serve_enumerates_then_quiesce(&mut core, &effects);
    assert_eq!(
      core.poll_cover_settlements(),
      vec![(second, CoverSettle::Applied)],
      "the clean re-issue applies honestly"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(state.applied_cover, Some(vec![p("/r/keep"), p("/r/drop")]));
    assert_eq!(
      state.settle_floor, state.applied_cover,
      "the clean settle resets the floor to the re-proven claim"
    );
    assert!(core.cover_fences.is_empty());
  }

  /// The entry-creating mark cannot leak: an out-of-window `Rescan` on a scope
  /// with NO narrowing record creates a pending-empty loss-memory entry and
  /// degrades nothing (there is no claim — a never-narrowed scope self-heals
  /// through the Monitor's own re-arm), and the next settle observation clears
  /// the entry exactly like any other, reporting no fences.
  #[test]
  fn out_of_window_loss_without_a_claim_clears_at_the_next_observation() {
    let (mut core, scope, req, _root) = live_descending();
    core.on_enumerated(req, listed(root_listing()));
    run_cascade(&mut core, &BTreeMap::new());
    assert!(core.monitor.rearm_settled(scope));

    core.on_root_overflow(scope, at(5));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the overflow stands a public covering Rescan: {effects:?}"
    );
    serve_enumerates_then_quiesce(&mut core, &effects);
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.applied_cover, None,
      "a never-narrowed scope has no claim to degrade"
    );
    assert_eq!(state.settle_floor, None);
    assert!(
      core
        .cover_fences
        .get(&scope)
        .is_some_and(|entry| entry.lossy),
      "the loss memory is recorded even with no reconcile in flight"
    );
    assert_eq!(
      core.poll_cover_settlements(),
      Vec::new(),
      "a pending-empty entry resolves no fence"
    );
    assert!(
      core.cover_fences.is_empty(),
      "the observation clears the entry — nothing leaks"
    );
  }
}

mod kernel_recursive_fanotify {
  //! The fanotify (kernel-recursive) profile: one superblock mark covers the
  //! whole root, so the Monitor never descends. Records are precise verbs
  //! lowered to root-relative targets with NO node identity (design §4.9), and
  //! `FAN_RENAME` pairs atomically through a minted counter cookie.

  use super::*;
  use crate::os::linux::{
    RawLinuxEvent,
    fanotify::{
      AdmittedEvent, AdmittedRename,
      fid::{
        FAN_ATTRIB, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF, FAN_MODIFY, FAN_MOVE_SELF, FAN_ONDIR,
        FAN_RENAME, FanMask,
      },
    },
  };

  /// A live fanotify scope rooted at `/r`: the KR spawn doubles as the root's
  /// watch-result, and the birth refresh installs authoritative (empty) trust.
  fn live_fanotify() -> (DriverCore, ScopeId) {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
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
        root_mnt_id: None,
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

  fn dirent(mask: u64, path: &str) -> RawLinuxEvent {
    RawLinuxEvent::Fanotify(AdmittedEvent {
      mask: FanMask::new(mask),
      path: Some(PathBuf::from(path)),
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
        dirent(FAN_CREATE, "/r/a/new.txt"),
        dirent(FAN_DELETE, "/r/a/gone.txt"),
        dirent(FAN_MODIFY, "/r/a/hot.txt"),
        dirent(FAN_ATTRIB, "/r/a/meta.txt"),
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
        rename: Some(AdmittedRename {
          old_path: PathBuf::from("/r/old.txt"),
          new_path: PathBuf::from("/r/sub/new.txt"),
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
          rename: Some(AdmittedRename {
            old_path: PathBuf::from("/r/a.txt"),
            new_path: PathBuf::from("/r/b.txt"),
          }),
        }),
        RawLinuxEvent::Fanotify(AdmittedEvent {
          mask: FanMask::new(FAN_RENAME),
          path: None,
          rename: Some(AdmittedRename {
            old_path: PathBuf::from("/r/c.txt"),
            new_path: PathBuf::from("/r/d.txt"),
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

  /// A `DELETE_SELF` on the ROOT object is the scope's death, PRESERVING the verb:
  /// the Monitor emits the user-visible `Removed` for the vanished root AND the
  /// terminal `Rescan` (never silent), then tears the scope down. Collapsing the
  /// self-event to `Ignored` used to drop that `Removed`.
  #[test]
  fn root_delete_self_is_scope_death() {
    let (mut core, scope) = live_fanotify();
    feed(
      &mut core,
      scope,
      vec![RawLinuxEvent::Fanotify(AdmittedEvent {
        mask: FanMask::new(FAN_DELETE_SELF | FAN_ONDIR),
        path: Some(PathBuf::from("/r")),
        rename: None,
      })],
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      emitted
        .iter()
        .any(|c| c.kind().is_removed() && c.location() == &loc(&[])),
      "a real root deletion surfaces the user-visible Removed at the root: {effects:?}"
    );
    assert!(
      emitted.iter().any(|c| c.kind().is_rescan()),
      "root death is never silent — the terminal Rescan follows: {effects:?}"
    );
    // The scope tore down: its stream is destroyed.
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the dead root's stream is torn down: {effects:?}"
    );
  }

  /// A `MOVE_SELF` on the ROOT object is likewise the scope's death, but a moved
  /// root's new path is unknowable — so it lowers to a terminal `Rescan` ONLY (no
  /// Removed), then tears the scope down. This is the verb distinction the collapse
  /// to `Ignored` erased.
  #[test]
  fn root_move_self_is_scope_death_rescan_only() {
    let (mut core, scope) = live_fanotify();
    feed(
      &mut core,
      scope,
      vec![RawLinuxEvent::Fanotify(AdmittedEvent {
        mask: FanMask::new(FAN_MOVE_SELF | FAN_ONDIR),
        path: Some(PathBuf::from("/r")),
        rename: None,
      })],
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      emitted.iter().any(|c| c.kind().is_rescan()),
      "a moved root surfaces the terminal Rescan: {effects:?}"
    );
    assert!(
      emitted.iter().all(|c| !c.kind().is_removed()),
      "a moved root carries NO Removed — its new path is unknowable: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the moved root's stream is torn down: {effects:?}"
    );
  }

  /// A directory create carries the directory flag through to the record.
  #[test]
  fn directory_create_flags_is_dir() {
    let (mut core, scope) = live_fanotify();
    feed(
      &mut core,
      scope,
      vec![dirent(FAN_CREATE | FAN_ONDIR, "/r/newdir")],
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1);
    assert!(emitted[0].kind().is_created());
    assert_eq!(emitted[0].location(), &loc(&["newdir"]));
  }

  /// A live inotify (descending) scope, spawned and root-armed, with its birth
  /// refresh fed — the comparison peer for the liveness-tick gate. inotify's
  /// unmount is signalled in-band (`IN_UNMOUNT`), so it must NOT arm the tick.
  fn live_inotify() -> (DriverCore, ScopeId) {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
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
      .expect("the descending root arms through the effect path");
    core.on_watch_installed(root_watch, crate::os::linux::WatchOutcome::Installed(1));
    let _ = drain(&mut core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(&mut core);
    (core, scope)
  }

  /// The composition's one timer: a fanotify scope arms a periodic root-liveness
  /// deadline (its birth refresh at `at(0)` seeds it at `+LIVENESS`), and the
  /// tick coming due fires a `RefreshMounts` — the ONLY way a signal-silent
  /// unmount is ever observed. An inotify scope, whose unmount is in-band, arms
  /// no such deadline and fires no tick.
  #[test]
  fn liveness_tick_refreshes_a_fanotify_root_but_not_an_inotify_one() {
    let (mut core, _scope) = live_fanotify();
    assert_eq!(
      core.poll_timeout(),
      Some(at(30_000)),
      "a fanotify scope arms the liveness deadline one interval past its birth refresh"
    );
    // Before the deadline: no tick.
    core.on_timeout(at(29_999));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      0,
      "the tick does not fire early"
    );
    // At the deadline: exactly one refresh, and the deadline re-arms.
    core.on_timeout(at(30_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      1,
      "the due tick fires the root-liveness refresh"
    );
    assert_eq!(
      core.poll_timeout(),
      Some(at(60_000)),
      "the tick re-arms one interval out"
    );

    // inotify: no liveness deadline, so no tick ever fires.
    let (mut core, _scope) = live_inotify();
    assert_eq!(
      core.poll_timeout(),
      None,
      "an inotify scope arms no liveness deadline (its unmount is in-band)"
    );
    core.on_timeout(at(1_000_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      0,
      "an inotify scope never fires a liveness tick"
    );
  }

  /// The tick's payoff end to end: a fanotify root unmounted with no loss (the
  /// L4.1 quiet case) is caught when the periodic refresh finds it gone — the
  /// refresh completion runs the same terminal Removed + Rescan + teardown a
  /// loss-triggered refresh would, but here reached SOLELY by the tick.
  #[test]
  fn liveness_tick_finding_root_gone_dies_end_to_end() {
    let (mut core, scope) = live_fanotify();
    // The tick comes due and fires the refresh — no loss, no birth, just time.
    core.on_timeout(at(30_000));
    let effects = drain(&mut core);
    assert_eq!(
      refresh_requests(&effects),
      1,
      "the tick armed the refresh: {effects:?}"
    );
    // The refresh executor comes back with the root GONE (the quiet unmount).
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Missing,
        root_mnt_id: None,
      },
      at(30_001),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 2, "{effects:?}");
    assert!(emitted[0].kind().is_removed(), "a gone root is a Removed");
    assert!(
      emitted[1].kind().is_rescan(),
      "the tick-detected death is never silent"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the dead root's stream tears down: {effects:?}"
    );
  }

  /// `Duration::ZERO` disables the tick: a fanotify scope then arms NO liveness
  /// deadline, so a quiet unmount is only ever caught by the loss-triggered
  /// refresh (the pre-L4.2 behavior). The loss path itself is unaffected.
  #[test]
  fn liveness_interval_zero_disables_the_tick() {
    let mut core = DriverCore::new(WINDOW, Duration::ZERO);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Fanotify,
      }),
    );
    let _ = drain(&mut core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(&mut core);
    assert_eq!(
      core.poll_timeout(),
      None,
      "a zero interval arms no liveness deadline"
    );
    core.on_timeout(at(10_000_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      0,
      "no tick ever fires when the interval is zero"
    );
    // The loss-triggered refresh still works with the tick disabled.
    core.on_root_overflow(scope, at(1));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      1,
      "the loss path still arms a refresh regardless of the tick"
    );
  }

  /// The admission closure at the DRIVER layer, tick-INDEPENDENT: the admission classifier
  /// turns a FID-only root self-event (`target_fid` = the root anchor, `dir_fid` =
  /// None — the shape the pre-inversion admission DROPPED) into a `RootDeath` whose
  /// forwarded event carries the root's OWN path, so it lowers through the SAME
  /// terminal death lifecycle an in-tree `DELETE_SELF` uses, with NO dependence on
  /// the periodic liveness tick. This drives that forwarded event into a scope whose
  /// `root_liveness_interval` is `ZERO` (the tick disabled) and asserts it STILL
  /// reaches terminal Removed + Rescan + teardown — the fix does not lean on the
  /// tick. (The classifier half — that the FID-only shape becomes exactly this
  /// `RootDeath(root path)`, not a drop — is pinned in the fanotify
  /// `classification_totality` suite; the container unmount cell covers the
  /// quiet-unmount arm the tick still bounds.)
  #[test]
  fn fid_only_root_death_dies_without_the_liveness_tick() {
    let mut core = DriverCore::new(WINDOW, Duration::ZERO);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Fanotify,
      }),
    );
    let _ = drain(&mut core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(&mut core);
    assert_eq!(
      core.poll_timeout(),
      None,
      "the tick is disabled — no liveness deadline is armed"
    );

    // The `RootDeath` admitted form the classifier produces for a FID-only root
    // self-event: the root's OWN path, so compile lowers it to the death lifecycle.
    feed(
      &mut core,
      scope,
      vec![RawLinuxEvent::Fanotify(AdmittedEvent {
        mask: FanMask::new(FAN_DELETE_SELF | FAN_ONDIR),
        path: Some(PathBuf::from("/r")),
        rename: None,
      })],
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      emitted.iter().any(|c| c.kind().is_removed()),
      "the FID-only root delete still surfaces the user-visible Removed: {effects:?}"
    );
    assert!(
      emitted.iter().any(|c| c.kind().is_rescan()),
      "root death is a terminal Rescan even with the tick disabled: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the dead root's stream tears down without any tick: {effects:?}"
    );
  }

  /// The pure root delete-FROM-ITS-PARENT reaches terminal root death WITHOUT the liveness
  /// tick, end to end through the admission seam AND the lowering. The kernel reports the
  /// watched root deleted as a `FAN_DELETE|FAN_ONDIR` dirent under the root's OWN
  /// (out-of-root) parent — `dir_fid` foreign, `target_fid` = the root. The admission
  /// classifier's action-aware foreign-parent path turns that into a `RootDeath` on the
  /// root's own path (never the `ForeignDrop` the dir_fid-only gate produced, which lost the
  /// death to the tick), and the driver lowers it to the SAME terminal Removed + Rescan +
  /// teardown an in-tree `DELETE_SELF` uses — here with `root_liveness_interval` = `ZERO`, so
  /// no tick can be the detector. Composing `classify` with the core proves the whole path,
  /// not just the pre-built admitted form the sibling FID-only case drives.
  #[test]
  fn root_delete_from_parent_dies_without_the_liveness_tick() {
    use crate::os::linux::fanotify::{
      Admission, MemoBatch, classify,
      fid::{Fid, RawFanotifyEvent},
      map::{FidMap, SeedEntry},
    };

    // The admission map holds the watched root /r as its anchor (fid 1); fid 99 is the
    // root's out-of-root parent — foreign to the map.
    fn seed_fid(tag: u8) -> Fid {
      Fid::new([tag; 8], Box::from(&[tag][..]))
    }
    let mut map = FidMap::new();
    map.seed([SeedEntry::root(seed_fid(1), Path::new("/r"))]);

    // The pure root delete as reported by its FOREIGN parent: parent out-of-root, the
    // affected `target_fid` the root itself.
    let raw = RawFanotifyEvent {
      mask: FanMask::new(FAN_DELETE | FAN_ONDIR),
      dir_fid: Some(seed_fid(99)),
      target_fid: Some(seed_fid(1)),
      name: Some(b"r".to_vec()),
      rename: None,
    };
    let Admission::RootDeath(admitted) = classify(&mut map, &raw, &mut MemoBatch::new()) else {
      panic!("the root delete-from-parent must classify as RootDeath, not a firehose drop");
    };

    // Drive that admitted event into a fanotify scope whose liveness tick is DISABLED.
    let mut core = DriverCore::new(WINDOW, Duration::ZERO);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Fanotify,
      }),
    );
    let _ = drain(&mut core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(&mut core);
    assert_eq!(
      core.poll_timeout(),
      None,
      "the tick is disabled — no liveness deadline is armed"
    );

    feed(&mut core, scope, vec![RawLinuxEvent::Fanotify(admitted)]);
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      emitted.iter().any(|c| c.kind().is_removed()),
      "the root delete-from-parent surfaces the user-visible Removed: {effects:?}"
    );
    assert!(
      emitted.iter().any(|c| c.kind().is_rescan()),
      "root death is a terminal Rescan even with the tick disabled: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the dead root's stream tears down without any tick: {effects:?}"
    );
  }

  /// Death survives a stale completion: a SECOND liveness tick fires before the
  /// FIRST refresh returns, marking the outstanding read stale — and that read
  /// then comes back with the root GONE. The death evidence must STILL be
  /// emitted, because root-liveness is evaluated before the stale gate, so a
  /// stale completion never discards a terminal verdict. With an interval
  /// shorter than refresh latency EVERY completion is stale, so a stale-gated
  /// death check would let the quiet unmount stay live indefinitely.
  #[test]
  fn stale_refresh_finding_root_gone_still_dies() {
    let (mut core, scope) = live_fanotify();
    // First tick: arms the refresh (now in flight) and re-arms the deadline.
    core.on_timeout(at(30_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      1,
      "the first tick armed the refresh"
    );
    // Second tick BEFORE the first refresh returns: it coalesces onto the
    // outstanding read (no new effect) and marks it stale.
    core.on_timeout(at(60_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      0,
      "a tick mid-refresh coalesces — exactly one outstanding refresh"
    );
    // The stale read finally returns with the root GONE (the quiet unmount).
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Missing,
        root_mnt_id: None,
      },
      at(60_001),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      2,
      "a stale completion still delivers the death lifecycle: {effects:?}"
    );
    assert!(emitted[0].kind().is_removed(), "a gone root is a Removed");
    assert!(
      emitted[1].kind().is_rescan(),
      "the stale-completion death is never silent"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the dead root's stream tears down even though the read was stale: {effects:?}"
    );
  }

  /// The same discarded-evidence shape reached via a LOSS (a backed-up pool /
  /// overlapping loss window), not a second tick: a loss overlaps the in-flight
  /// liveness refresh, marking it stale, and the read returns the root REPLACED
  /// (`Unreadable`). The MoveSelf death still lowers.
  #[test]
  fn loss_stale_refresh_finding_root_replaced_still_dies() {
    let (mut core, scope) = live_fanotify();
    core.on_timeout(at(30_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      1,
      "the tick armed a refresh"
    );
    // A loss overlaps the outstanding refresh: it coalesces and marks it stale.
    core.on_root_overflow(scope, at(30_500));
    let effects = drain(&mut core);
    assert_eq!(
      refresh_requests(&effects),
      0,
      "the overlapping loss coalesces onto the outstanding refresh"
    );
    // The stale read returns UNREADABLE (root moved out from under the mark).
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Unreadable,
        root_mnt_id: None,
      },
      at(31_000),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "a replaced root rescans (no Removed): {effects:?}"
    );
    assert!(
      emitted[0].kind().is_rescan(),
      "the stale-completion MoveSelf still lowers its terminal rescan"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the dead scope tears down"
    );
  }

  /// The original stale purpose stays pinned: a stale refresh whose root is
  /// still ALIVE discards its (possibly superseded) mount-set and re-arms one
  /// fresh read, keeping device trust closed — the mount-table gate the stale
  /// flag actually exists for is untouched by moving the death check ahead of it.
  #[test]
  fn stale_refresh_of_a_live_root_still_discards_the_mount_set() {
    let (mut core, scope) = live_fanotify();
    core.on_timeout(at(30_000));
    let _ = drain(&mut core);
    // A loss overlaps the refresh, marking it stale.
    core.on_root_overflow(scope, at(30_500));
    let _ = drain(&mut core);
    // The stale read returns ALIVE but carries a mount it must NOT install (the
    // snapshot may predate the lost window).
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: vec![PathBuf::from("/r/stale-vol")],
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
        root_mnt_id: None,
      },
      at(31_000),
    );
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      1,
      "a stale-but-alive completion re-arms exactly one fresh read"
    );
    let state = core.scopes.get(&scope).expect("scope is live");
    assert!(
      !state.mounts_authoritative,
      "the superseded snapshot does not restore authority"
    );
    assert!(
      !state.mounts.iter().any(|m| m == Path::new("/r/stale-vol")),
      "the superseded mount-set is discarded, not installed"
    );
  }

  /// A kernel-recursive scope adopts a changed frame but does NOT reconcile: its one
  /// superblock mark covers the whole subtree, so the descent frame is inert (no
  /// per-directory coverage to rebuild). A same-object re-mount that moves the frame
  /// must not emit a spurious rescan — the replay is a descending-scope concern only.
  #[test]
  fn a_kernel_recursive_frame_change_adopts_but_never_reconciles() {
    let (mut core, scope) = live_fanotify();
    core
      .scopes
      .get_mut(&scope)
      .expect("scope is live")
      .root_mnt_id = Some(42);
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
        root_mnt_id: Some(77),
      },
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      effects.is_empty(),
      "a kernel-recursive frame change triggers no reconcile: {effects:?}"
    );
    assert_eq!(
      core.scopes.get(&scope).expect("scope is live").root_mnt_id,
      Some(77),
      "the KR scope still adopts the authoritative frame (inert, but kept current)"
    );
  }

  /// A LIVE, NON-stale refresh whose mount table could NOT be read (a transient
  /// `/proc/self/mountinfo` failure yields a non-authoritative read) must CLOSE a
  /// previously-open authority — the non-authoritative counterpart to the stale
  /// gate. Leaving it open would keep proving paths root-device by their absence
  /// from a table that was never re-read across the mount change the refresh was
  /// meant to reconcile. Authority re-opens only with a later authoritative read;
  /// probe-read device evidence still decides throughout.
  #[test]
  fn a_live_non_authoritative_refresh_closes_a_previously_open_authority() {
    let (mut core, scope) = live_fanotify();
    // Birth installed authoritative (empty) trust, so absence grants event-side trust.
    let state = core.scopes.get(&scope).expect("scope is live");
    assert!(state.mounts_authoritative, "birth installed authority");
    assert!(
      device_trusted(state, Path::new("/r/a"), None),
      "an open authoritative table trusts a path absent from it"
    );

    // A live, non-stale refresh whose live mount table could not be read.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), false), at(1));
    let effects = drain(&mut core);
    assert_eq!(
      refresh_requests(&effects),
      0,
      "a non-authoritative read closes authority without busy-looping a re-read: {effects:?}"
    );
    let state = core.scopes.get(&scope).expect("scope is live");
    assert!(
      !state.mounts_authoritative,
      "the unreadable table closes the previously-open authority"
    );
    assert!(
      !device_trusted(state, Path::new("/r/a"), None),
      "closed authority no longer trusts a path by its absence from the table"
    );
    assert!(
      device_trusted(state, Path::new("/r/a"), Some(1)),
      "root-device probe evidence still trusts while authority is closed"
    );

    // A later authoritative read re-opens authority.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let state = core.scopes.get(&scope).expect("scope is live");
    assert!(
      state.mounts_authoritative,
      "a later authoritative refresh re-opens authority"
    );
    assert!(
      device_trusted(state, Path::new("/r/a"), None),
      "re-opened authority trusts the absent path again"
    );
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

  /// Provisional descending profile (the Linux platform default under Auto),
  /// but the probe resolved FANOTIFY: the core adopts the kernel-recursive
  /// profile — the spawn doubles as the root's watch-result (NO per-directory
  /// AddWatch), and a subsequent fanotify event lowers root-relative, proving
  /// the KR profile is the one now running.
  #[test]
  fn auto_provisional_inotify_adopts_probed_fanotify() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
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
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
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

/// The RDCW lowering: pump-paired events on a kernel-recursive Windows scope
/// lower from watch-relative names — precise verbs directly, paired renames
/// through the counter-cookie path, escalations and unknown verbs to located
/// rescans, widows into the Monitor's own move window.
mod rdcw_lowering {
  use super::*;
  use crate::os::windows::{RawWindowsEvent, RdcwAction, RdcwEvent, RdcwName, RdcwRecord};

  fn rdcw(action: RdcwAction, components: &[&str]) -> RdcwRecord {
    RdcwRecord {
      action,
      name: RdcwName::Utf8(components.iter().map(|c| (*c).to_owned()).collect()),
      file_id: None,
      parent_id: None,
      attributes: None,
      reparse_tag: None,
    }
  }

  fn payload(events: Vec<RdcwEvent>) -> BatchPayload {
    BatchPayload::detached(
      events
        .into_iter()
        .map(|event| SourceEvent::Windows(RawWindowsEvent::Rdcw(event)))
        .collect(),
    )
  }

  /// A live RDCW scope: registered, spawned (the KR spawn doubles as the
  /// watch-result), birth refresh fed.
  fn live_scope(core: &mut DriverCore) -> ScopeId {
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Rdcw);
    let _ = drain(core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Rdcw,
      }),
    );
    let _ = drain(core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(core);
    scope
  }

  #[test]
  fn precise_verbs_lower_at_their_locations() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    core.on_batch(
      scope,
      payload(vec![
        RdcwEvent::Single(rdcw(RdcwAction::Added, &["deep", "made.txt"])),
        RdcwEvent::Single(rdcw(RdcwAction::Modified, &["deep", "made.txt"])),
        RdcwEvent::Single(rdcw(RdcwAction::Removed, &["gone.txt"])),
      ]),
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      !effects.iter().any(|e| matches!(e, Effect::AddWatch { .. })),
      "a KR event never arms: {effects:?}"
    );
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 3, "{emitted:?}");
    assert!(emitted[0].kind().is_created());
    assert_eq!(emitted[0].location(), &loc(&["deep", "made.txt"]));
    assert!(emitted[1].kind().is_modified());
    assert_eq!(emitted[1].location(), &loc(&["deep", "made.txt"]));
    assert!(emitted[2].kind().is_removed());
    assert_eq!(emitted[2].location(), &loc(&["gone.txt"]));
  }

  #[test]
  fn a_pump_paired_rename_becomes_one_moved_change() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    core.on_batch(
      scope,
      payload(vec![RdcwEvent::Renamed {
        old: rdcw(RdcwAction::RenamedOld, &["a", "old.txt"]),
        new: rdcw(RdcwAction::RenamedNew, &["b", "new.txt"]),
      }]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert_eq!(
      emitted[0].kind().moved_from(),
      Some(&loc(&["a", "old.txt"])),
      "the counter cookie pairs the halves into one Moved"
    );
    assert_eq!(emitted[0].location(), &loc(&["b", "new.txt"]));
  }

  #[test]
  fn an_escalated_component_covers_its_decodable_ancestor() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    core.on_batch(
      scope,
      payload(vec![RdcwEvent::Single(RdcwRecord {
        action: RdcwAction::Modified,
        name: RdcwName::Escalate {
          prefix: vec!["deep".to_owned()],
        },
        file_id: None,
        parent_id: None,
        attributes: None,
        reparse_tag: None,
      })]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert!(
      emitted[0].kind().is_rescan() && emitted[0].location() == &loc(&["deep"]),
      "the undecodable leaf is covered at its named ancestor: {emitted:?}"
    );
  }

  #[test]
  fn an_unknown_action_covers_its_target() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    core.on_batch(
      scope,
      payload(vec![RdcwEvent::Single(rdcw(
        RdcwAction::Unknown(99),
        &["odd.bin"],
      ))]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert!(
      emitted[0].kind().is_rescan() && emitted[0].location() == &loc(&["odd.bin"]),
      "a verb outside the vocabulary rescans the object it names: {emitted:?}"
    );
  }

  #[test]
  fn widows_degrade_immediately_and_never_fabricate_a_moved() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    core.on_batch(
      scope,
      payload(vec![
        RdcwEvent::WidowOld(rdcw(RdcwAction::RenamedOld, &["lonely.txt"])),
        RdcwEvent::WidowNew(rdcw(RdcwAction::RenamedNew, &["arrived.txt"])),
      ]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 2, "{emitted:?}");
    assert!(
      emitted[0].kind().is_removed() && emitted[0].location() == &loc(&["lonely.txt"]),
      "a cookie-less FROM resolves immediately as the Removed degrade: {emitted:?}"
    );
    assert!(
      emitted[1].kind().is_created() && emitted[1].location() == &loc(&["arrived.txt"]),
      "a cookie-less TO resolves immediately as the Created degrade: {emitted:?}"
    );
    assert!(
      emitted.iter().all(|c| c.kind().moved_from().is_none()),
      "a widow never fabricates a Moved: {emitted:?}"
    );
  }
}

/// The USN lowering: admitted journal events on a kernel-recursive Windows
/// scope — pre-resolved targets lower directly, atomic renames through the
/// counter-cookie path, the root death and the map overflow as terminals.
mod usn_lowering {
  use super::*;
  use crate::os::windows::{
    RawWindowsEvent,
    usn::{UsnAdmitted, UsnTarget, reason},
  };

  fn payload(events: Vec<UsnAdmitted>) -> BatchPayload {
    BatchPayload::detached(
      events
        .into_iter()
        .map(|event| SourceEvent::Windows(RawWindowsEvent::Usn(event)))
        .collect(),
    )
  }

  fn live_scope(core: &mut DriverCore) -> ScopeId {
    let scope = core.on_watch(
      PathBuf::from("/r"),
      Interest::all(),
      BackendKind::UsnJournal,
    );
    let _ = drain(core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::UsnJournal,
      }),
    );
    let _ = drain(core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(core);
    scope
  }

  fn resolved(components: &[&str]) -> UsnTarget {
    UsnTarget::Resolved(components.iter().map(|c| (*c).to_owned()).collect())
  }

  #[test]
  fn deltas_lower_by_the_verb_partition() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(
      scope,
      payload(vec![
        UsnAdmitted::Single {
          delta: reason::FILE_CREATE | reason::DATA_EXTEND,
          target: resolved(&["a", "new.txt"]),
          is_dir: false,
        },
        UsnAdmitted::Single {
          delta: reason::DATA_OVERWRITE,
          target: resolved(&["a", "new.txt"]),
          is_dir: false,
        },
        UsnAdmitted::Single {
          delta: reason::SECURITY_CHANGE,
          target: resolved(&["a"]),
          is_dir: true,
        },
      ]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 3, "{emitted:?}");
    assert!(emitted[0].kind().is_created(), "structural wins the merge");
    assert_eq!(emitted[0].location(), &loc(&["a", "new.txt"]));
    assert!(emitted[1].kind().is_modified());
    assert!(
      emitted[2].kind().is_modified(),
      "Attrib folds to the consumer's Modified: {emitted:?}"
    );
  }

  #[test]
  fn an_admitted_rename_becomes_one_moved() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(
      scope,
      payload(vec![UsnAdmitted::Renamed {
        old: resolved(&["a", "old.txt"]),
        new: resolved(&["b", "new.txt"]),
        is_dir: false,
      }]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert_eq!(
      emitted[0].kind().moved_from(),
      Some(&loc(&["a", "old.txt"]))
    );
    assert_eq!(emitted[0].location(), &loc(&["b", "new.txt"]));
  }

  #[test]
  fn hard_links_ground_through_a_located_rescan() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(
      scope,
      payload(vec![UsnAdmitted::Single {
        delta: reason::HARD_LINK_CHANGE,
        target: resolved(&["a", "linked"]),
        is_dir: false,
      }]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1);
    assert!(
      emitted[0].kind().is_rescan() && emitted[0].location() == &loc(&["a", "linked"]),
      "link-count direction is grounded by the re-read: {emitted:?}"
    );
  }

  #[test]
  fn escalations_cover_the_parent() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(
      scope,
      payload(vec![UsnAdmitted::Single {
        delta: reason::DATA_OVERWRITE,
        target: UsnTarget::EscalateAt(vec!["a".into()]),
        is_dir: false,
      }]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      emitted[0].kind().is_rescan() && emitted[0].location() == &loc(&["a"]),
      "{emitted:?}"
    );
  }

  #[test]
  fn the_root_death_ends_the_scope_loudly() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(scope, payload(vec![UsnAdmitted::RootDeath]), at(1));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      emitted
        .iter()
        .any(|c| c.kind().is_removed() || c.kind().is_rescan()),
      "the death owes its terminal delivery: {emitted:?}"
    );
  }

  #[test]
  fn a_map_overflow_covers_the_root() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(scope, payload(vec![UsnAdmitted::MapOverflow]), at(1));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1);
    assert!(
      emitted[0].kind().is_rescan() && emitted[0].location() == &loc(&[]),
      "{emitted:?}"
    );
  }
}
