use super::*;
use std::time::Duration;

const WINDOW: Duration = Duration::from_millis(100);
/// The root-liveness tick interval the shared harness cores run with. Only a
/// fanotify scope arms it, and the FSEvents/inotify suites never drive time
/// this far, so it is inert everywhere except the fanotify liveness-tick suite.
const LIVENESS: Duration = Duration::from_secs(30);

/// No scope holds counted-but-unread lane items, which is what every cell that
/// is not about the residue deferral means by "the driver polls".
static NO_RESIDUE: BTreeSet<ScopeId> = BTreeSet::new();
/// The steady-state settlement pass: a live boundary whose source drain spent
/// every item it counted.
const DRAINED: SettlePass<'static> = SettlePass::Live {
  unspent: &NO_RESIDUE,
};

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

/// INV-PARK: a LOCATED Rescan minted while lagged (here a flagless-word
/// escalation; a deficit re-signal and an incomplete read route identically)
/// must not replace the parked root-covering instruction — the coverages
/// merge, keeping the root location while adopting the newer mint's epoch.
/// Fails on old: newest-wins parked the located slice, so events dropped
/// outside it were promised a re-enumeration that no longer covered them.
#[test]
fn a_located_rescan_under_lag_keeps_the_parked_root_coverage() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/a", flags(&[FsEventFlags::ITEM_CREATED]), 1, 3)],
    at(1),
  );
  let first = emits(&drain(&mut core))
    .first()
    .cloned()
    .cloned()
    .expect("the created event emits");

  // Lag entry parks the root-covering Rescan (epoch e+1); the parked offer
  // is deliberately NOT drained, so the merge below lands pre-offer.
  core.on_delivery(scope, Delivery::Refused, at(2));
  // A flagless word escalates to a LOCATED Rescan at [sub] (epoch e+2)
  // while the scope is lagged.
  core.on_batch_events(scope, vec![ev("/r/sub", FsEventFlags::new(0), 2, 0)], at(3));

  let effects = drain(&mut core);
  let offered = emits(&effects);
  assert_eq!(
    offered.len(),
    1,
    "one parked instruction offers: {effects:?}"
  );
  assert!(offered[0].kind().is_rescan());
  assert!(
    offered[0].location().is_empty(),
    "the parked coverage stays at the root — the located mint merged, it did \
     not replace: {:?}",
    offered[0]
  );
  assert_eq!(
    offered[0].epoch().as_u64(),
    first.epoch().as_u64() + 2,
    "the merged instruction adopts the located mint's (newest) epoch"
  );
}

/// A merge landing while the parked offer is IN FLIGHT: accepting the stale
/// offer must not end the lag — the merged (wider, newer) instruction
/// re-offers and only its acceptance returns the scope to normal flow.
/// Fails on old: the in-flight/idle handling survives, but the re-offer was
/// the located slice, not the root-covering merge.
#[test]
fn accepting_a_stale_offer_re_offers_the_merged_parked_rescan() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/a", flags(&[FsEventFlags::ITEM_CREATED]), 1, 3)],
    at(1),
  );
  let first = emits(&drain(&mut core))
    .first()
    .cloned()
    .cloned()
    .expect("the created event emits");
  core.on_delivery(scope, Delivery::Refused, at(2));
  // The parked root Rescan is offered — in flight at epoch e+1.
  let stale = emits(&drain(&mut core))
    .first()
    .cloned()
    .cloned()
    .expect("the parked Rescan offers");
  assert!(stale.location().is_empty());

  // A located mint merges while the offer is in flight (epoch e+2).
  core.on_batch_events(scope, vec![ev("/r/sub", FsEventFlags::new(0), 2, 0)], at(3));
  // The stale acceptance names a superseded epoch: the lag holds and the
  // merged instruction becomes offerable immediately.
  core.on_delivery(scope, Delivery::Accepted, at(4));
  let effects = drain(&mut core);
  let merged = emits(&effects);
  assert_eq!(merged.len(), 1, "the merged Rescan re-offers: {effects:?}");
  assert!(merged[0].kind().is_rescan());
  assert!(
    merged[0].location().is_empty(),
    "root coverage survives the in-flight merge: {:?}",
    merged[0]
  );
  assert_eq!(merged[0].epoch().as_u64(), first.epoch().as_u64() + 2);

  // Accepting the CURRENT instruction ends the lag.
  core.on_delivery(scope, Delivery::Accepted, at(5));
  core.on_batch_events(
    scope,
    vec![ev("/r/c", flags(&[FsEventFlags::ITEM_CREATED]), 3, 5)],
    at(6),
  );
  let effects = drain(&mut core);
  let flowed = emits(&effects);
  assert_eq!(flowed.len(), 1, "flow resumed");
  assert!(flowed[0].kind().is_created());
}

/// The covering-merge lattice: location = the longest common prefix (the
/// join of the two subtree coverages), id + epoch = the newer change's, and
/// neither input's coverage ever narrows.
#[test]
fn covering_merge_joins_coverage_and_adopts_the_newest_mint() {
  use tributary_proto::{ChangeId, ChangeKind, Epoch};
  let id = |n: u64| ChangeId::new(NonZeroU64::new(n).unwrap());
  let scope = ScopeId::new(NonZeroU64::new(1).unwrap());
  let rescan = |n: u64, location: Location, epoch: u64| {
    Change::new(
      id(n),
      scope,
      location,
      ChangeKind::Rescan,
      Epoch::new(epoch),
    )
  };
  let cases: &[(&[&str], &[&str], &[&str])] = &[
    (&[], &["a", "b"], &[]),                           // root × located → root
    (&["a", "b"], &[], &[]),                           // located × root → root (newer covers)
    (&["a"], &["a", "b"], &["a"]),                     // newer nested in prev → prev coverage
    (&["a", "b"], &["a"], &["a"]),                     // newer contains prev → newer coverage
    (&["a", "x"], &["b", "y"], &[]),                   // disjoint → the root joins them
    (&["a", "b", "c"], &["a", "b", "d"], &["a", "b"]), // deep common ancestor
    (&["a"], &["a"], &["a"]),                          // equal → unchanged coverage
  ];
  for (prev_loc, newer_loc, want) in cases {
    let prev = rescan(1, loc(prev_loc), 1);
    let newer = rescan(2, loc(newer_loc), 2);
    let merged = DriverCore::covering_merge(&prev, newer);
    assert_eq!(
      merged.location(),
      &loc(want),
      "join of {prev_loc:?} and {newer_loc:?}"
    );
    assert!(merged.kind().is_rescan());
    assert_eq!(merged.id(), id(2), "the newer mint's id");
    assert_eq!(merged.epoch(), Epoch::new(2), "the newer mint's epoch");
    // The join covers both inputs: each input location extends it.
    for input in [prev_loc, newer_loc] {
      assert!(
        loc(input).starts_with(merged.location()),
        "{input:?} is inside the merged coverage {want:?}"
      );
    }
  }
}

/// A consumer unwatch of a lagged scope promotes the parked instruction into
/// the dying set: after a located mint the promoted terminal must still
/// cover the root — the drops it licenses were scope-wide. Fails on old: the
/// narrowed located slice was promoted, so the terminal promise shrank below
/// the drop set (a consumer unwatch mints no terminal Rescan of its own to
/// heal it, unlike the death funnels).
#[test]
fn unwatch_of_a_narrowed_lagged_scope_promotes_root_coverage() {
  let (mut core, scope) = live_core();
  core.on_batch_events(
    scope,
    vec![ev("/r/a", flags(&[FsEventFlags::ITEM_CREATED]), 1, 3)],
    at(1),
  );
  let first = emits(&drain(&mut core))
    .first()
    .cloned()
    .cloned()
    .expect("the created event emits");
  core.on_delivery(scope, Delivery::Refused, at(2));
  // The located mint lands while lagged, pre-offer.
  core.on_batch_events(scope, vec![ev("/r/sub", FsEventFlags::new(0), 2, 0)], at(3));

  core.on_unwatch(scope);
  assert!(
    core.dying_contains(scope),
    "the parked instruction survives"
  );
  let effects = drain(&mut core);
  let terminal = emits(&effects)
    .first()
    .cloned()
    .cloned()
    .expect("the dying terminal offers");
  assert!(terminal.kind().is_rescan());
  assert!(
    terminal.location().is_empty(),
    "the terminal promise covers the root: {terminal:?}"
  );
  assert_eq!(terminal.epoch().as_u64(), first.epoch().as_u64() + 2);
  core.on_delivery(scope, Delivery::Accepted, at(4));
  assert!(!core.dying_contains(scope), "the acceptance retires it");
}

/// The epoch-announcement contract across a lag with located mints: no
/// delivered change ever carries a generation that no delivered Rescan
/// announced (the merged instruction announces the maximal folded epoch).
/// A property guard, not an old-vs-new discriminator — the pre-fix break was
/// coverage, not epochs.
#[test]
fn delivered_epochs_are_always_announced_by_a_delivered_rescan() {
  let (mut core, scope) = live_core();
  let mut delivered: Vec<Change> = Vec::new();
  let deliver_all = |core: &mut DriverCore, delivered: &mut Vec<Change>, t: u64| {
    for change in emits(&drain(core)) {
      delivered.push(change.clone());
      core.on_delivery(scope, Delivery::Accepted, at(t));
    }
  };

  core.on_batch_events(
    scope,
    vec![ev("/r/a", flags(&[FsEventFlags::ITEM_CREATED]), 1, 3)],
    at(1),
  );
  deliver_all(&mut core, &mut delivered, 1);
  // Lag entry, then TWO located mints folded into the parked instruction.
  core.on_batch_events(
    scope,
    vec![ev("/r/b", flags(&[FsEventFlags::ITEM_CREATED]), 2, 4)],
    at(2),
  );
  let _ = drain(&mut core);
  core.on_delivery(scope, Delivery::Refused, at(3));
  core.on_batch_events(scope, vec![ev("/r/sub", FsEventFlags::new(0), 3, 0)], at(4));
  core.on_batch_events(
    scope,
    vec![ev("/r/other/x", FsEventFlags::new(0), 4, 0)],
    at(5),
  );
  deliver_all(&mut core, &mut delivered, 6);
  // Post-lag flow rides the announced generation.
  core.on_batch_events(
    scope,
    vec![ev("/r/c", flags(&[FsEventFlags::ITEM_CREATED]), 5, 6)],
    at(7),
  );
  deliver_all(&mut core, &mut delivered, 7);

  assert!(
    delivered.iter().any(|c| c.kind().is_rescan()),
    "the lag delivered its instruction: {delivered:?}"
  );
  let mut announced = tributary_proto::Epoch::START;
  for change in &delivered {
    if change.kind().is_rescan() {
      announced = announced.max(change.epoch());
    } else {
      assert!(
        change.epoch() <= announced,
        "{change:?} rides a generation no delivered Rescan announced \
         (announced {announced:?}) in {delivered:?}"
      );
    }
  }
}

#[test]
fn identity_minting_respects_devices_and_mounts() {
  let state = ScopeState {
    watch: WatchId::new(NonZeroU64::new(1).unwrap()),
    root_attempt: None,
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
    refresh_world_stale: false,
    lag: LagState::Normal,
    park: Park::default(),
    resume_poisoned: false,
    publicly_live: true,
    liveness_deadline: None,
    applied_cover: None,
    settle_floor: None,
    pending_widen: None,
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
    root_attempt: None,
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
    refresh_world_stale: false,
    lag: LagState::Normal,
    park: Park::default(),
    resume_poisoned: false,
    publicly_live: true,
    liveness_deadline: None,
    applied_cover: None,
    settle_floor: None,
    pending_widen: None,
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

/// A kernel-recursive scope's loss `Rescan` DOES create set-cover loss memory,
/// even though its coverage never narrows.
///
/// The narrowing argument only covers `applied_cover`: `on_set_cover` refuses a
/// kernel-recursive scope before recording anything, so there is no coverage
/// claim to rewind, and both `applied_cover` and `settle_floor` stay `None`.
/// It does NOT cover the fence, because `sync_root` opens a cover fence for any
/// scope without consulting the profile. Skipping the mark therefore left a real
/// queue overflow invisible to a pending sync fence, which then resolved clean
/// over a window the kernel had already dropped events from.
///
/// The entry costs one map slot per LOSS — a kernel-recursive scope's only
/// `Rescan` sources are a real loss and a root death, not churn — and the next
/// settlement poll removes it whether or not a fence was pending, so it is loss
/// memory, not a leak.
#[test]
fn kernel_recursive_loss_rescan_marks_loss_memory() {
  let (mut core, scope) = live_core();
  core.on_root_overflow(scope, at(2));
  let effects = drain(&mut core);
  assert!(
    emits(&effects).iter().any(|c| c.kind().is_rescan()),
    "the overflow's covering Rescan is delivered: {effects:?}"
  );
  assert!(
    core
      .cover_fences
      .get(&scope)
      .is_some_and(|entry| entry.lossy),
    "the overflow marks the scope's loss memory lossy, so a sync fence opened \
     across this window cannot resolve clean"
  );
  let state = core.scopes.get(&scope).unwrap();
  assert_eq!(
    state.applied_cover, None,
    "a kernel-recursive scope still records no coverage claim"
  );
  assert_eq!(state.settle_floor, None);
  assert_eq!(
    core.poll_cover_settlements(DRAINED),
    Vec::new(),
    "no fence was pending, so the poll yields nothing"
  );
  assert!(
    core.cover_fences.is_empty(),
    "and it clears the entry rather than accumulating one per loss"
  );
}

mod lowering {
  use super::*;

  fn state_with_root(root: &str) -> ScopeState {
    ScopeState {
      watch: WatchId::new(NonZeroU64::new(99).unwrap()),
      root_attempt: None,
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
      refresh_world_stale: false,
      lag: LagState::Normal,
      park: Park::default(),
      resume_poisoned: false,
      publicly_live: true,
      liveness_deadline: None,
      applied_cover: None,
      settle_floor: None,
      pending_widen: None,
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
  const IN_MOVE_SELF: u32 = 0x0000_0800;
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
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Installed(1),
    );
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

  /// 42-10, end to end through the core: the bootstrap listing installs and arms
  /// its children in SILENCE, and the window closes with one covering `Rescan` at
  /// the scope root.
  ///
  /// Was `cold_listing_installs_children_and_emits_inventory`, whose two
  /// `Created`s were the registration inventory the contract denies. Its
  /// coverage half — the child is armed, and its arm continues the descent — is
  /// kept verbatim; only the delivery half inverts, and the `Rescan` that
  /// replaces it is asserted rather than merely tolerated.
  #[test]
  fn bootstrap_listing_installs_children_without_an_inventory() {
    let (mut core, scope, req, _root) = live_descending();
    core.on_enumerated(
      req,
      listed(vec![
        entry("a.txt", FileKind::File, 1, 10),
        entry("sub", FileKind::Dir, 1, 11),
      ]),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty(),
      "a registration reports no inventory: {effects:?}"
    );
    let add = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the discovered directory is armed");
    // The arm's success continues the descent: the child enumerates.
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let effects = drain(&mut core);
    let child_read = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/sub") => Some(*req),
        _ => None,
      })
      .expect("the armed child enumerates");
    assert!(
      emits(&effects).is_empty(),
      "still nothing announced: {effects:?}"
    );

    // The crawl quiesces, and the window closes with its one covering `Rescan`.
    core.on_enumerated(child_read, listed(Vec::new()));
    let effects = drain(&mut core);
    let closing = emits(&effects);
    assert_eq!(closing.len(), 1, "one closing signal: {effects:?}");
    assert!(closing[0].kind().is_rescan());
    assert_eq!(closing[0].location(), &loc(&[]));
    assert!(core.monitor.rearm_settled(scope));
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
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Aliased(7),
    );
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
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Failed(WatchError::NoSpace),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "a refused arm is never a silent blind spot: {effects:?}"
    );
  }

  /// A transport loss on the inotify profile re-proves the root binding by a
  /// re-add mapped through the SELF-PARENTED root-arm shape — carrying the
  /// barrier identity as `expected`, so a different-object rebind fails the
  /// open-verify — and never a stream (re)spawn. The re-arm read runs only
  /// once the re-add acknowledges.
  #[test]
  fn a_scope_loss_reissues_the_root_binding_before_the_rearm_read() {
    let (mut core, scope, req, root_watch) = live_descending();
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);

    core.on_root_overflow(scope, at(2));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the loss stands its covering Rescan: {effects:?}"
    );
    assert!(
      !effects
        .iter()
        .any(|e| matches!(e, Effect::SpawnStream { .. })),
      "a re-add never respawns the stream: {effects:?}"
    );
    assert!(
      !effects
        .iter()
        .any(|e| matches!(e, Effect::Enumerate { .. })),
      "no read runs before the binding acknowledges: {effects:?}"
    );
    let expected = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch {
          watch,
          parent,
          path,
          expected,
          ..
        } if *watch == root_watch && watch == parent && path.as_path() == Path::new("/r") => {
          Some(*expected)
        }
        _ => None,
      })
      .expect("the root re-add rides the self-parented arm shape");
    assert_eq!(
      expected.map(|e| (e.dev, e.ino.get())),
      Some((1, 1)),
      "the re-add carries the barrier identity, so a different-object rebind fails Gone"
    );

    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Aliased(1),
    );
    let read = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the acknowledged binding re-arm-reads");
    core.on_enumerated(read, listed(Vec::new()));
    let _ = drain(&mut core);
    assert!(core.monitor.rearm_settled(scope));
  }

  /// A cover fence opened mid-recovery cannot settle before the binding
  /// acknowledgement chain completes — the free barrier gating: the re-add
  /// rides the states the settle counter already counts.
  #[test]
  fn a_fence_opened_mid_recovery_waits_for_the_binding_ack() {
    let (mut core, scope, req, root_watch) = live_descending();
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);

    core.on_root_overflow(scope, at(2));
    let _ = drain(&mut core);
    let fence = core.open_cover_fence(scope);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the un-acknowledged re-add holds the fence"
    );

    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Aliased(1),
    );
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the acknowledged binding's read still holds it"
    );
    let read = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the reproof read");
    core.on_enumerated(read, listed(Vec::new()));
    let _ = drain(&mut core);
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "the fence resolves only past the full acknowledgement chain (lossy window)"
    );
  }

  /// Arms `sub` under a live descending scope, settles it, then runs the
  /// scope-loss reproof up to `sub`'s re-add: returns the core with the
  /// re-add DISPATCHED, ready for its acknowledgement — or its refusal.
  fn reproving_child() -> (DriverCore, ScopeId, WatchId, WatchId) {
    let (mut core, scope, req, root) = live_descending();
    core.on_enumerated(req, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    let sub = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the discovered directory is armed");
    core.on_watch_installed(
      sub,
      core.arm_attempt(sub),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let read = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/sub") => Some(*req),
        _ => None,
      })
      .expect("the armed child cold-enumerates");
    core.on_enumerated(read, listed(Vec::new()));
    let _ = drain(&mut core);

    // Scope loss: the reproof storm re-adds the root, whose acknowledged
    // re-add re-reads the tree and re-adds the kept survivor.
    core.on_root_overflow(scope, at(2));
    let _ = drain(&mut core);
    core.on_watch_installed(
      root,
      core.arm_attempt(root),
      crate::os::linux::WatchOutcome::Aliased(1),
    );
    let read = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the acknowledged root re-add re-reads");
    core.on_enumerated(read, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    assert!(
      drain(&mut core).iter().any(|e| matches!(
        e,
        Effect::AddWatch { watch, path, .. }
          if path.as_path() == Path::new("/r/sub") && *watch == sub
      )),
      "the kept survivor is re-added"
    );
    (core, scope, sub, root)
  }

  /// Finishes `sub`'s reproof read (found in `effects`, the drain that
  /// followed its acknowledgement) and asserts the recovery settles with the
  /// binding standing.
  fn settle_reproved_child(
    core: &mut DriverCore,
    scope: ScopeId,
    sub: WatchId,
    effects: &[Effect],
  ) {
    let read = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/sub") => Some(*req),
        _ => None,
      })
      .expect("the re-proved child re-reads");
    core.on_enumerated(read, listed(Vec::new()));
    let _ = drain(core);
    assert!(core.monitor.rearm_settled(scope));
    assert!(
      core.scope_of_watch(sub).is_some(),
      "the re-proved binding stands"
    );
    assert!(
      !core.resignal_coverage_deficits(scope),
      "no deficit is booked against the re-proved slot"
    );
  }

  /// The survivor re-add's happy path: an `Aliased` acknowledgement (the
  /// binding was live all along) continues into the reproof read and the
  /// recovery settles with the binding standing and no deficit booked.
  #[test]
  fn an_acknowledged_survivor_readd_settles_the_recovery() {
    let (mut core, scope, sub, _root) = reproving_child();
    core.on_watch_installed(
      sub,
      core.arm_attempt(sub),
      crate::os::linux::WatchOutcome::Aliased(2),
    );
    let effects = drain(&mut core);
    settle_reproved_child(&mut core, scope, sub, &effects);
  }

  /// A survivor re-add REFUSED mid-reproof (`Failed(Io)` — the reader's
  /// `wd`-collision refusal, among other transient installs): the slot lands
  /// in the install-refusal funnel, never a silent drop — a located covering
  /// `Rescan` stands, the watch is released, and the darkness is
  /// level-persistent (the pre-cookie seam re-signals it rather than
  /// certifying delivery over the unwatched slot). The refusal is not an
  /// acknowledgement: nothing re-proves the binding until a retry's real ACK.
  #[test]
  fn a_refused_survivor_readd_stands_a_located_rescan_and_a_persistent_deficit() {
    let (mut core, scope, sub, _root) = reproving_child();
    core.on_watch_installed(
      sub,
      core.arm_attempt(sub),
      crate::os::linux::WatchOutcome::Failed(WatchError::Io),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&["sub"])),
      "the refused re-add stands its located covering Rescan: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::RemoveWatch { watch, .. } if *watch == sub)),
      "the refused slot's watch is released: {effects:?}"
    );
    assert!(
      core.resignal_coverage_deficits(scope),
      "the refused slot is booked as a standing deficit"
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&["sub"])),
      "the re-signal covers the still-dark slot: {effects:?}"
    );
  }

  /// The refusal's retry makes progress: the deficit re-signal heal-kicks the
  /// slot's healing anchor (reproof-flavored — the anchor re-adds, its
  /// acknowledged read re-arms the slot fresh); the retry's REAL
  /// acknowledgement (its next `add_watch` steps past the refused `wd`) is
  /// what re-covers the slot — the deficit then stops re-signaling.
  #[test]
  fn a_refused_readd_heals_through_the_deficit_retry() {
    let (mut core, scope, sub, root) = reproving_child();
    core.on_watch_installed(
      sub,
      core.arm_attempt(sub),
      crate::os::linux::WatchOutcome::Failed(WatchError::Io),
    );
    let _ = drain(&mut core);

    assert!(core.resignal_coverage_deficits(scope));
    assert!(
      drain(&mut core).iter().any(|e| matches!(
        e,
        Effect::AddWatch { watch, parent, .. } if watch == parent && *watch == root
      )),
      "the heal kick re-proves the healing anchor's binding"
    );
    core.on_watch_installed(
      root,
      core.arm_attempt(root),
      crate::os::linux::WatchOutcome::Aliased(1),
    );
    let read = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the acknowledged anchor re-reads the refused slot's level");
    core.on_enumerated(read, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    let retry = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the heal re-arms the slot");
    core.on_watch_installed(
      retry,
      core.arm_attempt(retry),
      crate::os::linux::WatchOutcome::Installed(3),
    );
    let read = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/sub") => Some(*req),
        _ => None,
      })
      .expect("the retried arm's ACK continues into its read");
    core.on_enumerated(read, listed(Vec::new()));
    let _ = drain(&mut core);
    assert!(core.monitor.rearm_settled(scope));
    assert!(
      !core.resignal_coverage_deficits(scope),
      "the retry's real ACK re-covered the slot — no standing deficit"
    );
  }

  /// A cover fence spanning a refusal never certifies clean: the refused
  /// re-add resolves the recovery with a lossy window, so the fence settles
  /// `Degraded` — the covering `Rescan` owns the truth — never `Applied` over
  /// the momentarily unwatched slot.
  #[test]
  fn a_fence_spanning_a_refused_readd_settles_degraded_never_applied() {
    let (mut core, scope, sub, _root) = reproving_child();
    let fence = core.open_cover_fence(scope);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the un-answered re-add holds the fence"
    );
    core.on_watch_installed(
      sub,
      core.arm_attempt(sub),
      crate::os::linux::WatchOutcome::Failed(WatchError::Io),
    );
    let _ = drain(&mut core);
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "a refusal inside the window degrades the fence — never Applied"
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
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Installed(1),
    );
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
      core.arm_attempt(root_watch),
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
      core.arm_attempt(failed_root),
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
    core.on_watch_installed(
      sub_arm,
      core.arm_attempt(sub_arm),
      crate::os::linux::WatchOutcome::Installed(2),
    );
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
    core.on_watch_installed(
      sub_arm,
      core.arm_attempt(sub_arm),
      crate::os::linux::WatchOutcome::Installed(2),
    );
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
    core.on_watch_installed(
      sub_arm,
      core.arm_attempt(sub_arm),
      crate::os::linux::WatchOutcome::Installed(2),
    );
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
    // The frame-change replay is a scope-level loss on the inotify profile,
    // so the root's binding is re-proven first: the reconcile's re-read comes
    // only once the re-add acknowledges.
    let readd = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch {
          watch,
          parent,
          path,
          ..
        } if watch == parent && path.as_path() == Path::new("/r") => Some(*watch),
        _ => None,
      })
      .expect("the frame-change reconcile re-proves the root binding");
    core.on_watch_installed(
      readd,
      core.arm_attempt(readd),
      crate::os::linux::WatchOutcome::Aliased(1),
    );
    let req2 = drain(&mut core)
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
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Installed(2),
    );
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
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Installed(2),
    );
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
  /// Spends the REGISTRATION window's loss memory (42-10). A registration closes
  /// its window with one covering `Rescan` at the scope root, and the scope's
  /// cover-fence entry remembers that loss until a settle observation clears it —
  /// so a first fence opened straight after the grant inherits it and resolves
  /// `Degraded`. That is the design's stated consequence, not a defect; a cell
  /// whose subject is a LATER window spends the memory here first, exactly as
  /// [`shrunk_to_keep`] does with its own.
  fn clear_registration_loss(core: &mut DriverCore, scope: ScopeId) {
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());
    assert!(
      !core.cover_fences.contains_key(&scope),
      "the registration window's loss memory is spent"
    );
  }

  fn run_cascade(core: &mut DriverCore, listings: &BTreeMap<&str, Vec<RawDirEntry>>) {
    let mut wd = 100;
    for _ in 0..32 {
      let effects = drain(core);
      let mut progressed = false;
      for effect in &effects {
        match effect {
          Effect::AddWatch { watch, .. } => {
            wd += 1;
            core.on_watch_installed(
              *watch,
              core.arm_attempt(*watch),
              crate::os::linux::WatchOutcome::Installed(wd),
            );
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
  /// An open cover fence whose grow re-arm is still outstanding when a root
  /// replace commits: the commit is a whole-scope loss (the covering
  /// Rescan), so once the rebound world's rebuild quiesces the fence
  /// settles `Degraded` — never `Applied` over work the rebind cut, never
  /// wedged open.
  #[test]
  fn an_open_cover_fence_settles_degraded_across_a_replace() {
    let (mut core, scope, root_watch) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    assert!(!core.monitor.rearm_settled(scope));
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());

    // The replace commits mid-fence: /r moves to /r2 on a new transport.
    core.on_root_replaced(
      scope,
      RootMeta {
        root: PathBuf::from("/r2"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Inotify,
      },
      at(3),
    );
    let _ = drain(&mut core);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the rebound root's rebuild is counted work — the fence still pends"
    );

    // The driver replays the pre-armed outcome; the rebuild quiesces.
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Installed(99),
    );
    run_cascade(&mut core, &BTreeMap::from([("/r2", Vec::new())]));
    assert!(core.monitor.rearm_settled(scope));
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "the commit's loss memory resolves the fence honestly"
    );
  }

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
    // A LIVE verdict of either kind also owes the ordering proof the driver buys
    // with one empty control batch per window — the request that latches it in
    // flight, then the batch reply the reader's queue cut precedes — so every
    // sans-I/O cell expecting one performs those two steps itself.
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(state.applied_cover, Some(vec![p("/r/keep")]));
    assert_eq!(state.settle_floor, Some(vec![p("/r/keep")]));
    assert!(core.cover_fences.is_empty());
    (core, scope, root_watch)
  }

  /// A mark licenses nothing outside the epoch it was stamped under.
  ///
  /// Every cell below rests on this, and it is a property of the TYPE rather than
  /// of any protocol here: a `CutMark` keeps its reach stamped, so the reach
  /// cannot be read at all without naming the epoch it is read under, and a mark
  /// read under any other epoch yields nothing to license a verdict with. A site
  /// that samples the window under one epoch and spends the sample under another
  /// therefore cannot reach the false-clean defect by forgetting to re-check —
  /// there is no accessor that skips the check.
  ///
  /// Both directions are asserted because the rule is EQUALITY and not recency: a
  /// mark is exactly as silent under a stamp on either side of its own. Reading it
  /// as an ordering instead would license a proof over coverage work the scope
  /// acquired after the cut was taken, which is the whole defect.
  ///
  /// Asserted on a bare `u64` stamp rather than through `CutMark`: a production
  /// mark stamps with a `CoverageWorkEpoch`, which only the Monitor mints and only
  /// ever as the epoch a scope reads NOW, so naming three of them here would mean
  /// driving a scope through two acquisitions just to buy stamps for a property
  /// that belongs to the stamped value alone. That unforgeability is the other
  /// half of the guarantee, and the compiler enforces it rather than this cell:
  /// nothing recovers an incarnation from a sample, so no site can satisfy the
  /// check with the stamp it is already holding.
  ///
  /// Mutation witness: let the stamped read yield its value whatever stamp it is
  /// read under and both `None`s below become the reach.
  #[test]
  fn a_mark_licenses_nothing_outside_the_epoch_it_was_stamped_under() {
    let sample = Stamped::new(7u64, 3u64);

    assert_eq!(
      sample.current(7),
      Some(&3),
      "the epoch it was stamped under reads the reach it earned"
    );
    assert_eq!(
      sample.current(8),
      None,
      "coverage work moving the scope on leaves the mark licensing nothing"
    );
    assert_eq!(
      sample.current(6),
      None,
      "and a stamp on the other side of its own is no more current, so the rule \
       is equality rather than recency"
    );

    // Which of two samples is the stronger stays answerable — it is a question
    // about the stamps, and within one stamp about the reaches — while answering
    // it hands out neither reach, so it is never a licence to spend one.
    assert!(
      Stamped::new(8u64, 0u64).supersedes(&sample),
      "a later epoch supersedes outright, however short its reach"
    );
    assert!(
      !Stamped::new(6u64, 9u64).supersedes(&sample),
      "and a departed epoch supersedes nothing, however far its reach"
    );
    assert!(
      Stamped::new(7u64, 4u64).supersedes(&sample),
      "while within one epoch the further reach wins"
    );
  }

  /// Formatting a stamped sample discloses neither the reach nor its stamp.
  ///
  /// A `Debug` rendering is a read that costs no stamp, so a derived one would be
  /// the whole guarantee's back door: a site could format a mark, lift the reach
  /// out of the text, and license a verdict without ever naming the epoch it was
  /// reading under. The stamp is withheld with it because these stamps are only
  /// unforgeable as values — the `u64` used here renders as text that parses back
  /// into a stamp, which is all a site needs to read a sample under the very
  /// epoch that sample carries.
  ///
  /// Asserted on the impl rather than on a `CutMark` because that is where the
  /// rendering is decided: every carrier of a stamped value wraps it in a single
  /// field, so a derive there can only delegate here and has no field of its own
  /// to disclose.
  ///
  /// Mutation witness: restore `#[derive(Debug)]` on the type and both the reach
  /// and the stamp appear in the rendering below.
  #[test]
  fn formatting_a_stamped_sample_discloses_nothing() {
    // Digit strings long enough that neither can turn up incidentally in a type
    // name, a field count, or the other field's text.
    let sample = Stamped::new(58_231_774u64, 90_460_913u64);
    let compact = format!("{sample:?}");
    let expanded = format!("{sample:#?}");

    for rendering in [&compact, &expanded] {
      assert!(
        !rendering.contains("90460913"),
        "the reach must not be recoverable from a rendering: {rendering}"
      );
      assert!(
        !rendering.contains("58231774"),
        "nor the stamp, which a site could parse back and read the reach under: \
         {rendering}"
      );
    }

    assert_eq!(
      compact, "Stamped { .. }",
      "and the rendering carries no other disclosure either"
    );
  }

  /// A predecessor's completion cannot prove a request made after it.
  ///
  /// The completion signal is per scope, and a scope's batches are a QUEUE: a
  /// batch still recorded as running can complete after a later proof request has
  /// been queued and latched. Its cut was taken before that request existed, so
  /// licensing the request from it would certify over anything the kernel
  /// committed in between — the same false-clean defect, reached through the
  /// completion rather than through the snapshot.
  ///
  /// The request therefore carries a token and only its own completion closes it.
  /// A predecessor's token cannot match, however close behind it arrives.
  ///
  /// Mutation witness: make `prove_cut` accept any in-flight request regardless of
  /// token and the stale completion below certifies the window.
  #[test]
  fn a_predecessor_completion_cannot_prove_a_later_request() {
    let (mut core, scope, _root) = shrunk_to_keep();

    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let pending = core.open_cover_fence(scope);

    // The request this window actually owes, token 7.
    core.mark_cut_inflight(scope, 7);

    // A predecessor batch — dispatched before the request existed, so carrying an
    // earlier token — completes now.
    core.prove_cut(scope, 6);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "a cut taken before this request existed does not prove it"
    );

    // The request's own completion does.
    core.prove_cut(scope, 7);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(pending, CoverSettle::Applied)],
      "and the matching completion releases the window"
    );
  }

  /// A reconcile extending the window invalidates the proof taken before it.
  ///
  /// The latch lives on the scope's ENTRY, which every fence of one unsettled
  /// window shares — so a proof bought for the window as it then stood would,
  /// unreset, license whatever a later reconcile added to it. That is the same
  /// defect one level up: the added work's own terminal proof is routinely an
  /// enumerate, which never crosses the reader, so a record the kernel committed
  /// during it would be certified over by the earlier batch's reply.
  ///
  /// Staged without opening a second fence, so only the reconcile's own reset can
  /// be what withholds the verdict — a fence opened here would carry an ordinal
  /// beyond the proof's reach, and this cell must not be able to pass on that
  /// instead. Staged on a PRUNE, which
  /// is the coverage move the epoch binding cannot see: a drop only releases
  /// work, so no acquisition funnel fires and the scope reads the same epoch
  /// either side of it — asserted below, so the reset stays the only candidate.
  ///
  /// Mutation witness: drop the reset at `on_set_cover`'s entry-ensure and the
  /// pending fence resolves `Applied` on a proof taken over the coverage the
  /// shrink then dropped.
  #[test]
  fn a_reconcile_invalidates_a_proof_taken_before_it() {
    let (mut core, scope, req, _root) = live_descending();
    core.on_enumerated(req, listed(root_listing()));
    run_cascade(&mut core, &BTreeMap::new());
    clear_registration_loss(&mut core, scope);

    // The full cover: nothing is outside it and the never-pruned initial claim
    // already covers it, so this opens the window without moving any coverage.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let pending = core.open_cover_fence(scope);
    let epoch = core.monitor.coverage_work_epoch(scope);
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);

    // The window is re-opened by a reconcile that drops `/r/drop`'s subtree. No
    // new fence joins and the epoch stands still, so the only thing that can
    // withhold the verdict below is this reconcile's own reset.
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
    assert_eq!(
      core.monitor.coverage_work_epoch(scope),
      epoch,
      "a prune only releases coverage work, so the epoch cannot flag it"
    );
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the proof predates the reconcile that extended this window"
    );

    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(pending, CoverSettle::Applied)],
      "and the re-proven window resolves the fence it actually covers"
    );
  }

  /// A reconcile that moves no coverage cannot invalidate the proof taken before
  /// it — the exact counterpart of the cell above, and the reason that one is
  /// conditional rather than unconditional.
  ///
  /// A re-issue of an already-applied cover grows nothing and prunes nothing, so
  /// it extends the window by nothing: the standing proof orders precisely the
  /// window that remains, and re-asking would buy no ordering. Invalidating there
  /// is not merely a wasted round trip. `set_cover` requests need not be
  /// acknowledged, so a caller may issue them faster than a cut completes — and
  /// against an unconditional reset, EVERY completed proof lands on a latch a
  /// later re-issue has already reset. The window would then never settle clean
  /// under sustained same-cover traffic, and its fences would never resolve: not
  /// a slow path, an indefinite one.
  ///
  /// Retention rides on that: pending fences and their callers' parked replies
  /// only ever drain at a settle, so a window that cannot settle accumulates them
  /// for as long as the traffic lasts. Asserted here as the entry vanishing at
  /// the settle — with it go every pending tuple and every parked reply.
  ///
  /// Mutation witness: reset unconditionally and the flood below leaves the fence
  /// unresolved forever, however many proofs complete.
  #[test]
  fn a_reconcile_moving_no_coverage_keeps_the_proof_taken_before_it() {
    let (mut core, scope, _root) = shrunk_to_keep();

    // A window with nothing to grow and nothing left to prune: it quiesces the
    // instant it opens, so the ordering proof is the only thing between it and a
    // clean verdict.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let pending = core.open_cover_fence(scope);
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "the settled clean window owes a proof"
    );
    core.mark_cut_inflight(scope, 1);

    // Reply-less re-issues of the same cover, arriving while that request is out.
    // Each is a whole reconcile — validated, walked, recorded — that moves no
    // coverage at all.
    for _ in 0..64 {
      assert_eq!(
        core.on_set_cover(scope, &[p("/r/keep")]),
        CoverReconcile::Reconciling
      );
    }
    assert_eq!(
      core.cover_fences[&scope].pending.len(),
      1,
      "a reply-less reconcile opens no fence, so the traffic retains nothing"
    );

    // The reply the window has been waiting on lands behind all of it, and the
    // traffic keeps arriving afterwards.
    core.prove_cut(scope, 1);
    for _ in 0..64 {
      assert_eq!(
        core.on_set_cover(scope, &[p("/r/keep")]),
        CoverReconcile::Reconciling
      );
    }

    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(pending, CoverSettle::Applied)],
      "the proof still orders the window the traffic never changed"
    );
    assert!(
      core.cover_fences.is_empty(),
      "and the settle drains the entry, so nothing is retained past it"
    );
  }

  /// A fence may not inherit an ordering proof older than itself.
  ///
  /// The proof one empty control batch buys is scoped to the window as it stood
  /// when the request was made. A fence opened afterwards covers a LATER window,
  /// so anything the kernel committed between the two is outside what that proof
  /// ordered — and certifying the new fence from it would certify over exactly
  /// the records the proof existed to surface. The fence's open ordinal is what
  /// excludes it: the ordinal sits beyond the proof's mark, so the proof
  /// licenses it nothing and the driver asks again.
  ///
  /// Staged on a zero-work re-issue — the same cover, so nothing grows and
  /// nothing prunes and the barrier reads settled at once. That window has no
  /// counted work to hook a proof onto, which is why it cannot be covered by
  /// making the cascade end in an acknowledged arm.
  ///
  /// Mutation witness: let a standing proof license every pending fence rather
  /// than only those it reaches, and the later fence resolves `Applied` on a
  /// proof taken before it existed.
  #[test]
  fn a_fence_never_inherits_a_proof_older_than_itself() {
    let (mut core, scope, _root) = shrunk_to_keep();

    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling,
      "a re-issue of the same cover still opens a window"
    );
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);

    let later = core.open_cover_fence(scope);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the later fence may not certify on a proof taken before it existed"
    );

    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(later, CoverSettle::Applied)],
      "and once the window it actually covers is proven, it resolves"
    );
  }

  /// A proof settles the fences it was requested behind, however many join the
  /// window while it is out.
  ///
  /// Scoping a proof to the window as it stood at the REQUEST cuts both ways: a
  /// fence opened afterwards is outside what the proof ordered, and a fence
  /// already pending is squarely inside it. Reading only the first half — by
  /// discarding the whole proof the moment any successor fence joins the
  /// entry — starves the very fences that proof was bought for. Successors can
  /// arrive faster than a cut completes, and then every reply lands on a latch
  /// some later fence has already cleared, so the window never settles clean at
  /// all and the callers parked behind it are never answered.
  ///
  /// The open ordinal reads both halves at once. The reply below licenses its
  /// own tranche and nothing beyond it: the fence it was requested behind
  /// resolves, and the four that joined afterwards wait for a successor of
  /// their own — which they are offered the moment it lands.
  ///
  /// Mutation witness: discard the proof whenever a fence opens and the first
  /// fence never resolves, though the proof it asked for completes.
  #[test]
  fn a_proof_settles_the_tranche_it_was_requested_behind() {
    let (mut core, scope, _root) = shrunk_to_keep();

    // The window the request is made for: one fence, on a re-issue that grows
    // nothing and prunes nothing, so it quiesces the instant it opens and the
    // ordering proof is the only thing between it and a clean verdict.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let first = core.open_cover_fence(scope);
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "the settled clean window owes a proof"
    );
    core.mark_cut_inflight(scope, 1);

    // Acknowledged covers keep arriving while that batch is out, each opening
    // its own fence onto the same entry. The driver sends only what it is
    // offered, and the request already out is not offered again.
    let later: Vec<FenceId> = (0..4)
      .map(|_| {
        assert_eq!(
          core.on_set_cover(scope, &[p("/r/keep")]),
          CoverReconcile::Reconciling
        );
        core.open_cover_fence(scope)
      })
      .collect();

    // The reply lands, ordering exactly the window the first fence covers.
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(first, CoverSettle::Applied)],
      "the fence the proof was requested behind settles clean, and the fences \
       that opened after the request do not ride it"
    );

    // Those are offered a successor at once — a window may never be left
    // holding fences with nothing asked for them.
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "the fences beyond the proof's reach ask again"
    );
    core.mark_cut_inflight(scope, 2);
    core.prove_cut(scope, 2);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      later
        .iter()
        .map(|fence| (*fence, CoverSettle::Applied))
        .collect::<Vec<_>>(),
      "and the successor resolves the tranche that outlived the first proof"
    );
    assert!(
      core.cover_fences.is_empty(),
      "the last pending fence going drains the entry"
    );
  }

  /// Acknowledged covers arriving faster than a cut completes still resolve,
  /// and retain only what one flight can accumulate.
  ///
  /// This is the liveness half of scoping a proof to the fences it was
  /// requested behind. Each request licenses everything pending at the instant
  /// it was latched, and the fences that join behind it are offered a successor
  /// the moment it lands — so a fence waits on the first request latched after
  /// it opened, and on no more than the one round trip already in flight,
  /// whatever the arrival rate. Retention follows: what a window holds is the
  /// fences of a single flight, not of the traffic.
  ///
  /// What that rules out is a window that never settles at all. Pending fences
  /// and their callers' parked replies drain only at a settle, so under a rule
  /// that lets a new fence discard the standing request — cancelling it before
  /// its reply can land — a scope taking steady acknowledged covers wastes
  /// every proof, resolves no fence, and grows its retained state with the
  /// traffic. That is not a slow path but an indefinite one.
  ///
  /// Mutation witness: discard the proof whenever a fence opens and the window
  /// retains the whole traffic instead of one flight's worth of it.
  #[test]
  fn acknowledged_covers_outpacing_the_cut_resolve_in_bounded_state() {
    let (mut core, scope, _root) = shrunk_to_keep();

    // The driver's loop, one round per iteration: an acknowledged cover arrives
    // and opens a fence, whatever reply is due lands, settlements are polled,
    // and the loop top offers the scope a cut which the driver commits to
    // sending. A reply takes three rounds, so fences arrive three times faster
    // than the proofs that license them.
    const FLIGHT: usize = 3;
    const ARRIVALS: usize = 64;

    let mut token = 0;
    let mut due: Option<(usize, u64)> = None;
    let mut displaced = 0;
    let mut opened = Vec::new();
    let mut settled = Vec::new();

    for round in 0..ARRIVALS + 4 * FLIGHT {
      if round < ARRIVALS {
        assert_eq!(
          core.on_set_cover(scope, &[p("/r/keep")]),
          CoverReconcile::Reconciling
        );
        opened.push(core.open_cover_fence(scope));
      }
      if let Some((lands, out)) = due
        && lands == round
      {
        core.prove_cut(scope, out);
        due = None;
      }
      settled.extend(core.poll_cover_settlements(DRAINED));

      let held = core
        .cover_fences
        .get(&scope)
        .map_or(0, |entry| entry.pending.len());
      assert!(
        held <= 2 * FLIGHT,
        "round {round}: the window retains the fences of one flight, not of \
         the whole traffic ({held} held)"
      );
      let offered = core.covers_awaiting_cut();
      assert!(
        held == 0 || due.is_some() || !offered.is_empty(),
        "round {round}: {held} fences wait with no proof out and none offered"
      );
      if !offered.is_empty() {
        // The driver sends what it is offered; a request still out would have
        // its reply orphaned by the overwrite.
        displaced += usize::from(due.is_some());
        token += 1;
        core.mark_cut_inflight(scope, token);
        due = Some((round + FLIGHT, token));
      }
    }

    assert_eq!(
      displaced, 0,
      "no request out was ever displaced by a fence that joined behind it"
    );
    assert_eq!(
      settled,
      opened
        .iter()
        .map(|fence| (*fence, CoverSettle::Applied))
        .collect::<Vec<_>>(),
      "every fence the traffic opened settled clean, in open order"
    );
    assert!(
      core.cover_fences.is_empty(),
      "and the last one going drained the entry"
    );
  }

  /// Latching the successor a later fence needs does not spend the proof its
  /// predecessors have already earned.
  ///
  /// A proven prefix and a request out for the fences beyond it are two
  /// different claims, and the driver's loop is what makes keeping them apart
  /// load-bearing: it latches the cuts it is offered at the loop top and
  /// resolves settlements below that, so the successor a mid-flight fence needs
  /// is always latched BEFORE the tranche its predecessor proved gets to
  /// resolve. Held in one slot the two are indistinguishable, and the successor
  /// erases an authority already earned — leaving the fence that bought it
  /// waiting on a reply that says nothing about it.
  ///
  /// Staged on re-issues of the applied cover, which grow nothing and prune
  /// nothing: each window quiesces the instant it opens, so the ordering proof
  /// is the only thing between its fences and a clean verdict.
  ///
  /// Mutation witness: let the latch clear the proven prefix and the first fence
  /// never resolves, though the cut it was waiting on completed before the
  /// successor existed.
  #[test]
  fn a_latched_successor_never_spends_the_proof_it_follows() {
    let (mut core, scope, _root) = shrunk_to_keep();

    // The window the first request is made for.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let first = core.open_cover_fence(scope);
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "the settled clean window owes a proof"
    );
    core.mark_cut_inflight(scope, 1);

    // A second acknowledged cover joins the entry while that batch is out, so
    // its fence sits past everything the request can license.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let second = core.open_cover_fence(scope);

    // The reply lands, and the driver's next loop top offers and latches the
    // successor the second fence needs before it resolves anything.
    core.prove_cut(scope, 1);
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "the fence beyond the proof's reach asks for its own"
    );
    core.mark_cut_inflight(scope, 2);

    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(first, CoverSettle::Applied)],
      "the fence the landed proof was requested behind still settles on it"
    );

    core.prove_cut(scope, 2);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(second, CoverSettle::Applied)],
      "and the successor resolves the fence it was latched for"
    );
    assert!(
      core.cover_fences.is_empty(),
      "the last pending fence going drains the entry"
    );
  }

  /// A window taking one new fence per proof round resolves every one of them,
  /// holding the fences of a single flight rather than of the whole traffic.
  ///
  /// The liveness this shape tests is the driver's own: successors are latched
  /// at the loop top, ABOVE the settlement resolved below, so every proof lands
  /// with a successor latched on top of it before the fences it licenses are
  /// allowed to resolve. If that successor spent the proof, no round would ever
  /// resolve a fence, and each would add one more to the entry: not a slow path
  /// but an indefinite one, with every caller's parked reply retained behind it,
  /// under nothing more exotic than a steady stream of acknowledged covers.
  ///
  /// Keeping the two apart bounds it instead. Each request licenses everything
  /// pending when it was latched and the prefix keeps what it earns, so a fence
  /// waits on the first request latched after it opened and on no more than the
  /// one round trip already out, whatever the arrival rate.
  ///
  /// Mutation witness: let the latch clear the proven prefix and the window
  /// retains every fence the traffic ever opened, resolving none of them.
  #[test]
  fn a_fence_a_proof_round_still_resolves_in_bounded_state() {
    let (mut core, scope, _root) = shrunk_to_keep();

    // The driver's loop, one round per iteration and in its order: commands are
    // taken (an acknowledged cover arrives and opens a fence), results are fed
    // back (whatever reply is due lands), the loop top offers a cut which the
    // driver commits to sending, and settlements resolve underneath it.
    const FLIGHT: usize = 3;
    const ARRIVALS: usize = 64;

    let mut token = 0;
    let mut due: Option<(usize, u64)> = None;
    let mut displaced = 0;
    let mut opened = Vec::new();
    let mut settled = Vec::new();

    for round in 0..ARRIVALS + 4 * FLIGHT {
      if round < ARRIVALS {
        assert_eq!(
          core.on_set_cover(scope, &[p("/r/keep")]),
          CoverReconcile::Reconciling
        );
        opened.push(core.open_cover_fence(scope));
      }
      if let Some((lands, out)) = due
        && lands == round
      {
        core.prove_cut(scope, out);
        due = None;
      }
      for _ in core.covers_awaiting_cut() {
        // The driver sends what it is offered; a request still out would have
        // its reply orphaned by the one that displaced it.
        displaced += usize::from(due.is_some());
        token += 1;
        core.mark_cut_inflight(scope, token);
        due = Some((round + FLIGHT, token));
      }
      settled.extend(core.poll_cover_settlements(DRAINED));

      let held = core
        .cover_fences
        .get(&scope)
        .map_or(0, |entry| entry.pending.len());
      assert!(
        held <= 2 * FLIGHT,
        "round {round}: the window retains the fences of one flight, not of \
         the whole traffic ({held} held)"
      );
      assert!(
        held == 0 || due.is_some(),
        "round {round}: {held} fences ended the round with nothing out to \
         license them"
      );
    }

    assert_eq!(
      displaced, 0,
      "no request out was ever displaced by a fence that joined behind it"
    );
    assert_eq!(
      settled,
      opened
        .iter()
        .map(|fence| (*fence, CoverSettle::Applied))
        .collect::<Vec<_>>(),
      "every fence the traffic opened settled clean, in open order"
    );
    assert!(
      core.cover_fences.is_empty(),
      "and the last one going drained the entry"
    );
  }

  /// Coverage work acquired and released under a standing proof invalidates it.
  ///
  /// The barrier is a conjunction over several kinds of coverage work, so it can
  /// go settled → UNSETTLED → settled again without any reconcile and without
  /// any new fence — the two window changes that reset the latch at their own
  /// site. This is that path, end to end and through the conjunct
  /// `rearm_settled` deliberately does not count: the reader forwards a
  /// `MovedFrom` under a proof already taken, the settle-edge drain turns it
  /// into a held-source obligation, and a paired `MovedTo` releases it.
  ///
  /// The window that re-opened is a real one. An overflow the kernel committed
  /// after the cut can still be sitting unread across that whole round, and the
  /// lane snapshot the drain sees is empty — so a proof kept valid through it
  /// would suppress the second cut and certify `Applied` over exactly the record
  /// the proof existed to surface, irreversibly. Binding the proof to the
  /// scope's coverage-work epoch is what makes the round visible: the hold's
  /// acquisition moves the epoch, the release does not move it back, and the
  /// stale proof licenses nothing.
  ///
  /// Mutation witness: accept any `Proven` regardless of epoch and the fence
  /// resolves `Applied` here, ahead of the loss below.
  #[test]
  fn a_hold_and_release_invalidates_a_proof_taken_before_it() {
    let (mut core, scope, root_watch) = shrunk_to_keep();

    // A window with nothing to grow: it quiesces the instant it opens, so the
    // ordering proof is the only thing between it and a clean verdict.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let pending = core.open_cover_fence(scope);
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "the settled clean window owes a proof"
    );
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert!(
      core.covers_awaiting_cut().is_empty(),
      "which the batch reply supplies"
    );

    // The proven cut forwards a `MovedFrom`; ingesting it detaches and holds
    // the source, which re-opens the barrier with no reconcile in sight.
    core.on_inotify_events(
      scope,
      vec![inotify(
        &[root_watch],
        IN_MOVED_FROM | IN_ISDIR,
        7,
        Some(b"keep"),
      )],
      at(5),
    );
    let _ = drain(&mut core);
    assert!(
      core.monitor.rearm_settled(scope),
      "a hold is not counted re-arm work"
    );
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "but the hold gates the fence"
    );

    // The pairing releases the hold; the barrier reads settled again, and the
    // lane the drain snapshots is empty either way.
    core.on_inotify_events(
      scope,
      vec![inotify(
        &[root_watch],
        IN_MOVED_TO | IN_ISDIR,
        7,
        Some(b"kept"),
      )],
      at(10),
    );
    let _ = drain(&mut core);
    assert!(
      core.barrier_settled(scope),
      "the pairing releases the barrier"
    );

    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "a proof taken before the hold's round cannot certify across it"
    );
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "so the window is offered a fresh cut instead"
    );

    // What that second cut is for: the record the kernel held across the round
    // reaches the fence as loss, where the stale proof would have already
    // certified the window clean over it.
    core.on_root_overflow(scope, at(11));
    run_cascade(
      &mut core,
      &BTreeMap::from([("/r", vec![entry("kept", FileKind::Dir, 1, 11)])]),
    );
    // Taking that loss does not excuse the window from the cut: it is offered
    // one over the epoch the recovery moved, and only the reply releases the
    // fence.
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "a degraded window owes the same ordering proof a clean one does"
    );
    core.mark_cut_inflight(scope, 2);
    core.prove_cut(scope, 2);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(pending, CoverSettle::Degraded)],
      "the fence reports the loss it had not yet certified over"
    );
  }

  /// A scope that settles and then stays settled converges: its coverage-work
  /// epoch stops moving, so the next proof taken over it survives to certify.
  ///
  /// This is the liveness half of binding the proof to that epoch. Invalidating
  /// on every acquisition is only safe if a quiescent scope acquires nothing —
  /// otherwise the fence would chase a moving value and a clean window could
  /// never resolve. Coverage work is acquired at the four funnels and released
  /// everywhere else, and a release never moves the epoch, so quiescence alone
  /// is enough: no consumer silence and no timer is required.
  #[test]
  fn a_settled_scope_holds_its_epoch_still_so_a_proof_sticks() {
    let (mut core, scope, root_watch) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let pending = core.open_cover_fence(scope);

    // Idle churn that acquires no coverage work: a plain file `Created` under
    // a live directory reconciles a slot and starts nothing.
    let epoch = core.monitor.coverage_work_epoch(scope);
    core.on_inotify_events(
      scope,
      vec![inotify(&[root_watch], IN_CREATE, 0, Some(b"f.txt"))],
      at(5),
    );
    let _ = drain(&mut core);
    assert!(core.barrier_settled(scope), "the scope is still settled");
    assert_eq!(
      core.monitor.coverage_work_epoch(scope),
      epoch,
      "and acquired nothing, so the epoch stands still"
    );

    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    let quiet = core.monitor.coverage_work_epoch(scope);
    core.on_inotify_events(
      scope,
      vec![inotify(&[root_watch], IN_CREATE, 0, Some(b"g.txt"))],
      at(6),
    );
    let _ = drain(&mut core);
    assert_eq!(
      core.monitor.coverage_work_epoch(scope),
      quiet,
      "more of the same churn still acquires nothing"
    );
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(pending, CoverSettle::Applied)],
      "so the proof taken over the quiet window certifies it"
    );
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
  /// refused `NotLive`: no caller holds a handle yet, so there is no coverage
  /// claim to reconcile. The refusal perturbs nothing — the grant's own crawl
  /// then takes the whole coverage, in the silence the contract requires.
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

    // The grant commits: the root arms, reads, and takes its coverage. The tail
    // used to assert the inventory's `Created`s here, as a guard that the refused
    // covers had not converted the root's discovery into a re-arm. Registration
    // IS a re-arm now, deliberately (42-10), so that guard is re-pinned on what
    // it was really about — the refusals recorded nothing, so the grant's own
    // crawl is what installs the coverage, and it installs all of it.
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Installed(1),
    );
    let req = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, watch, .. } if *watch == root_watch => Some(*req),
        _ => None,
      })
      .expect("the granted root enumerates");
    core.on_enumerated(req, listed(vec![entry("keep", FileKind::Dir, 1, 11)]));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty(),
      "and it reports no inventory: {effects:?}"
    );
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { path, .. } if path.as_path() == Path::new("/r/keep")
      )),
      "the grant's crawl takes the coverage the refused covers never claimed: \
       {effects:?}"
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
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the fence pends while the cascade runs"
    );
    // Quiesce: the root's re-arm read re-installs `drop` and cascades down
    // (`keep` is identity-kept, never re-armed).
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    assert!(core.monitor.rearm_settled(scope));
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
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

  /// The clean verdict's CERTIFICATION gate: a settled CLEAN window is withheld
  /// — never degraded, never lost — when the boundary may not certify
  /// ([`SettlePass::Closing`], the close drain), because there is no stream
  /// left to certify against. The withheld pass promotes no floor and KEEPS the
  /// fence, so the resolution is deferred: the driver's dropped reply then
  /// reads `Closed` rather than a verdict minted over a scope being torn down.
  /// A LOSSY window resolves regardless at THIS boundary — nothing may be held
  /// over at close, where no later pass would ever answer it.
  #[test]
  fn a_settle_the_boundary_may_not_certify_is_withheld_not_degraded() {
    let (mut core, scope, _root) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    assert!(core.monitor.rearm_settled(scope), "the cascade quiesced");
    let floor_before = core.scopes.get(&scope).unwrap().settle_floor.clone();

    assert_eq!(
      core.poll_cover_settlements(SettlePass::Closing),
      Vec::new(),
      "the quiesced CLEAN window is withheld while the boundary may not certify"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.settle_floor, floor_before,
      "the withheld pass promotes no floor — nothing was certified"
    );
    assert_ne!(
      state.settle_floor, state.applied_cover,
      "the grow's claim is still un-certified while the verdict is withheld"
    );
    assert!(
      core.cover_fences.contains_key(&scope),
      "the withheld fence is kept, not dropped"
    );
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Applied)],
      "a boundary that may certify then certifies exactly once"
    );

    // The lossy twin: a marked window resolves even where a clean one is withheld.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let lossy = core.open_cover_fence(scope);
    core
      .cover_fences
      .get_mut(&scope)
      .expect("the fence entry exists")
      .mark_lossy();
    run_cascade(&mut core, &BTreeMap::new());
    assert_eq!(
      core.poll_cover_settlements(SettlePass::Closing),
      vec![(lossy, CoverSettle::Degraded)],
      "a lossy window reports its honest verdict regardless"
    );
  }

  /// The residue gate: while a scope's own lane still holds items the settle
  /// edge COUNTED and did not read, no verdict that ANSWERS a caller may
  /// resolve for it — the LOSSY one included.
  ///
  /// A degraded verdict is not falsifiable by more loss, which is why the close
  /// boundary above resolves it freely. It is falsifiable by DEATH. An unread
  /// terminal `Fatal` among those counted items has not yet folded the fence,
  /// so the scope's liveness still reads live everywhere a live verdict is
  /// consumed; and a `Degraded` is a LIVE verdict, dispatching the fence's
  /// parked cookie write exactly as an `Applied` does. Answering `Ok` there
  /// mints a barrier the dead stream can never report — precisely the
  /// successful-but-unsatisfiable oneshot [`CoverSettle::Dead`] exists to
  /// refuse.
  ///
  /// Three facts are pinned, in order: the withhold keeps the fence INTACT (a
  /// deferral, never a decision); the set is per SCOPE, so a neighbour's
  /// backlog decides nothing here; and ingesting the residue resolves the very
  /// fence that was withheld — `Dead`, through the already-settled list no
  /// deferral gates — so the deferral cannot outlive the residue that caused
  /// it and cannot swallow the answer.
  ///
  /// The close boundary is a different pass and is pinned by the cell above:
  /// it refuses the clean verdict but defers NOTHING, because a fence held
  /// over there would strand its caller forever. [`SettlePass::Closing`]
  /// carries no residue set at all, so that separation is structural.
  ///
  /// Mutation witness: let a lossy window resolve while its scope holds
  /// residual counted items (drop the `withholds` gate, or apply it only to
  /// clean windows) and the first poll below reports `Degraded` — the verdict
  /// that dispatches the cookie — for a scope whose death is still unread.
  #[test]
  fn a_lossy_settle_is_withheld_while_its_scope_holds_unread_lane_items() {
    let (mut core, scope, _root) = shrunk_to_keep();
    let elsewhere = ScopeId::new(NonZeroU64::new(4242).unwrap());
    assert_ne!(scope, elsewhere, "the neighbour is a different scope");

    // A settled LOSSY window — the shape whose verdict answers a caller and
    // dispatches its parked cookie.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let first = core.open_cover_fence(scope);
    core
      .cover_fences
      .get_mut(&scope)
      .expect("the fence entry exists")
      .mark_lossy();
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    assert!(
      core.barrier_settled(scope),
      "staging: the window must be SETTLED, or every poll below is vacuously empty"
    );
    // The window's ordering proof is bought first — where the driver's loop top
    // latches it, above the settlement it resolves below — so the residue gate
    // this cell is about is the only thing that can withhold the verdict.
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);

    assert_eq!(
      core.poll_cover_settlements(SettlePass::Live {
        unspent: &BTreeSet::from([scope])
      }),
      Vec::new(),
      "a settled lossy window whose scope still owes counted lane items resolves \
       nothing — a death may be sitting in exactly those items"
    );
    assert!(
      core.cover_fences.contains_key(&scope),
      "the withheld fence is KEPT, so the caller is deferred rather than decided"
    );

    // Per scope, not global: a neighbour's residue is about a neighbour's lane.
    assert_eq!(
      core.poll_cover_settlements(SettlePass::Live {
        unspent: &BTreeSet::from([elsewhere])
      }),
      vec![(first, CoverSettle::Degraded)],
      "another scope's unread items defer nothing here"
    );

    // A second settled lossy window, withheld the same way — and this time the
    // residue really is the terminal Fatal.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    let second = core.open_cover_fence(scope);
    core
      .cover_fences
      .get_mut(&scope)
      .expect("the fence entry exists")
      .mark_lossy();
    run_cascade(&mut core, &BTreeMap::new());
    assert!(
      core.barrier_settled(scope),
      "staging: the second window settled"
    );
    core.mark_cut_inflight(scope, 2);
    core.prove_cut(scope, 2);
    let residue = SettlePass::Live {
      unspent: &BTreeSet::from([scope]),
    };
    assert_eq!(
      core.poll_cover_settlements(residue),
      Vec::new(),
      "withheld again — the gate is a standing property of the residue, not a one-shot"
    );

    // Reading the residue is what decides it: the terminal Fatal folds the
    // fence, and the SAME pass that withheld the live verdict reports the death.
    core.on_source_fatal(scope, at(5));
    assert!(
      drain(&mut core)
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the terminal Fatal funnels the scope's teardown"
    );
    assert_eq!(
      core.poll_cover_settlements(residue),
      vec![(second, CoverSettle::Dead)],
      "the withheld fence resolves Dead once its residue is read — the answer the \
       caller had to get instead of a Degraded that would have dispatched its cookie"
    );
    assert!(
      core.cover_fences.is_empty(),
      "no fence state outlives the scope"
    );
  }

  /// A LOSSY window owes the ordering proof exactly as a clean one does, and is
  /// offered one — the same rule read from both sides.
  ///
  /// More loss genuinely cannot falsify a degraded verdict, which is what the
  /// old exemption rested on. That is a statement about LOSS and silent about
  /// DEATH. A `Degraded` is a LIVE verdict: it answers its caller and
  /// dispatches the fence's parked sync cookie exactly as an `Applied` does. So
  /// a scope whose root died while the record saying so sits unread in the
  /// kernel queue would be answered `Ok` for a cookie written into a directory
  /// nothing watches — and the loss that degraded the window covers nothing
  /// that happened after it. Only the cut surfaces a kernel-resident record;
  /// the settle-edge drain sees an empty lane and reads spent.
  ///
  /// Both halves are pinned together because either alone is a defect. Requiring
  /// the proof without OFFERING it parks every lossy fence forever, and its
  /// caller's parked reply with it: the offer and the settle gate carry the same
  /// exemption and no other, so a fence that must have a proof is always asked
  /// for one.
  ///
  /// Mutation witness: exempt the lossy window on either side. Exempted at the
  /// settle gate, the first poll below mints `Degraded` with no proof in hand;
  /// exempted at the offer, the window is never asked for a cut and the fence
  /// never resolves at all.
  #[test]
  fn a_lossy_fence_is_not_licensed_without_a_current_cut_proof() {
    let (mut core, scope, _root) = shrunk_to_keep();

    // A settled LOSSY window: the shape whose verdict answers a caller and
    // dispatches its parked cookie.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    core
      .cover_fences
      .get_mut(&scope)
      .expect("the fence entry exists")
      .mark_lossy();
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    assert!(
      core.barrier_settled(scope),
      "staging: the window must be SETTLED, or every poll below is vacuously empty"
    );

    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "a degraded verdict is a live verdict, so its window owes the cut"
    );
    assert!(
      core.cover_fences.contains_key(&scope),
      "the unproven fence is KEPT — the window is retried, never decided"
    );
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "and it is asked for one, which is what keeps the requirement live"
    );

    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "the proof licenses the window; its public verdict is unchanged by owing one"
    );
    assert!(
      core.cover_fences.is_empty(),
      "the last pending fence going drains the entry"
    );
  }

  /// What that cut is FOR: a root death the kernel still holds reaches the fence
  /// ahead of its verdict, so the fence resolves `Dead` — refusing the parked
  /// cookie — where the exempted window answered `Degraded` and dispatched it.
  ///
  /// The staging is the reachable shape of the defect. The window is degraded by
  /// a loss; its coverage work quiesces OFF the reader (an enumerate completes
  /// on the blocking pool and crosses no lane), so the settle-edge drain reads
  /// spent and every liveness map still says the scope is alive; and the root's
  /// own `IN_MOVE_SELF` is kernel-resident throughout. Withholding the verdict
  /// for want of the proof is precisely what leaves room for the reader's
  /// pre-reply cut to put that record on the lane, which is what the record
  /// arriving ahead of the batch's completion models here.
  ///
  /// Mutation witness: exempt the lossy window at the settle gate and the first
  /// poll answers its caller over a root that is already gone.
  #[test]
  fn an_unread_root_death_under_a_lossy_fence_is_caught_by_the_cut_it_owes() {
    let (mut core, scope, root_watch) = shrunk_to_keep();

    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    core
      .cover_fences
      .get_mut(&scope)
      .expect("the fence entry exists")
      .mark_lossy();
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    assert!(
      core.barrier_settled(scope),
      "staging: the coverage work quiesced, and it quiesced off the reader"
    );
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the degraded window is withheld for want of its ordering proof"
    );

    // The reader cuts its kernel queue onto the lane BEFORE answering any batch,
    // so the root's own death is ingested ahead of the proof that batch mints.
    core.on_inotify_events(
      scope,
      vec![inotify(&[root_watch], IN_MOVE_SELF, 0, None)],
      at(5),
    );
    assert!(
      drain(&mut core)
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the root's own move is the scope's death"
    );
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);

    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Dead)],
      "the fence reports the death the cut surfaced — the verdict that REFUSES \
       the parked cookie, never the Degraded that would have written it into a \
       directory nothing watches"
    );
    assert!(
      core.cover_fences.is_empty(),
      "no fence state outlives the scope"
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
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the surviving fence still pends on the stalled cascade"
    );
    // Quiesce: only the survivor resolves, with the clean-settle repair intact.
    run_cascade(&mut core, &BTreeMap::from([("/r", root_listing())]));
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
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
      core.arm_attempt(add),
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
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
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
  /// re-arm counter deliberately does not see, so `rearm_settled` reads true
  /// while the coverage work is outstanding. The fence opened for that
  /// reconcile is GATED across the latency (`coverage_settled` counts the
  /// latent read — a settle inside it would dispatch a sync cookie the
  /// escalation's covering `Rescan` does not precede) and resolves `Degraded`
  /// once the escalation drains: the born-lossy memory marked it at open, and
  /// the escalation `Rescan` marks it again — never `Applied` over the hole.
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
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Installed(9),
    );
    let cold = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/drop") => Some(*req),
        _ => None,
      })
      .expect("the cold read is in flight");
    assert!(
      core.monitor.rearm_settled(scope),
      "a cold read is not re-arm work — the counter reads settled"
    );
    // The grow's delta lands exactly on the in-flight cold read: Coalesced.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    assert!(
      core.monitor.rearm_settled(scope),
      "the latent obligation is invisible to the re-arm counter"
    );
    assert!(
      !core.monitor.coverage_settled(scope),
      "but not to the fence predicate"
    );
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the fence is gated across the latent read — no settle inside the window"
    );
    // The completion escalates: a covering Rescan plus a COUNTED retry — the
    // gate hands over to the re-arm counter with no unfenced instant.
    core.on_enumerated(cold, listed(Vec::new()));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the dirtied read's completion emits the covering Rescan: {effects:?}"
    );
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the escalation's counted retry keeps the fence parked"
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
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "the drained window resolves Degraded — born-lossy, and Rescan-marked"
    );
    assert_eq!(
      core.scopes.get(&scope).unwrap().applied_cover,
      Some(Vec::new()),
      "the mid-window escalation Rescan degraded the claim to the empty cover"
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
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Installed(9),
    );
    let cold = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/drop") => Some(*req),
        _ => None,
      })
      .expect("the cold read is in flight");

    // (i) The REPLY-LESS grow coalesces into the cold read: no fence of its
    // own, but the already-pending fence is marked lossy — and GATED across
    // the latent read (`coverage_settled`), so it cannot resolve inside the
    // window the coalesced obligation leaves dark.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the latent obligation gates the settle — no fence resolves inside it"
    );

    // The latent obligation completes: the dirtied cold read escalates (a
    // covering Rescan plus a counted re-arm retry). The Rescan re-marks the
    // still-parked fence and degrades the over-claim to the empty cover.
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
      "the coalesce and its escalation record the loss memory"
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
    // The settle OBSERVATION resolves the marked fence Degraded and clears
    // the loss memory with it.
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(pending, CoverSettle::Degraded)],
      "a reply-less coalesce degrades the fences already pending"
    );
    assert!(
      core.cover_fences.is_empty(),
      "the observation clears the entry with the fences"
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
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(later, CoverSettle::Applied)],
      "the observed memory does not leak onto a later fence"
    );
  }

  /// B1 (F1 fence): a sync-shaped fence opened across a descending replace
  /// pends through the WHOLE rebuild, and the routed event sequence carries
  /// the commit `Rescan` … the closing `Rescan` (strictly higher epoch)
  /// BEFORE the settle observation that would dispatch a cookie — so a
  /// bridge-window change (dark until its directory's watch armed,
  /// suppressed by the re-arm read) is ≤ a `Rescan` that precedes every
  /// dispatched write. Fails on old: the stream ended at the commit `Rescan`.
  #[test]
  fn a_fence_across_a_replace_sees_the_closing_rescan_before_settling() {
    let (mut core, scope, req, root_watch) = live_descending();
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);

    let fence = core.open_cover_fence(scope);
    core.on_root_replaced(
      scope,
      RootMeta {
        root: PathBuf::from("/r2"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        identity: crate::os::RootIdentity::new(1, 1),
        ancestors: Vec::new(),
        backend: BackendKind::Inotify,
      },
      at(3),
    );
    let effects = drain(&mut core);
    let commit_epoch = emits(&effects)
      .iter()
      .find(|c| c.kind().is_rescan())
      .map(|c| c.epoch())
      .expect("the commit Rescan is routed");
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());

    // The driver replays the pre-armed root; the commit's synthetic loss
    // postdates that pre-arm on the inotify profile, so the replay's ACK is
    // stale under the stamp rule and one re-add re-proves the binding on the
    // NEW transport before the re-arm read runs. Its read then lists a fresh
    // directory `a` — the bridge. The fence pends until `a`'s own read lands.
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Installed(99),
    );
    let readd = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch {
          watch,
          parent,
          path,
          ..
        } if watch == parent && path.as_path() == Path::new("/r2") => Some(*watch),
        _ => None,
      })
      .expect("the rebound root's binding is re-proven post-commit");
    assert_eq!(readd, root_watch, "the re-add names the surviving root");
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Aliased(99),
    );
    let rearm = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r2") => Some(*req),
        _ => None,
      })
      .expect("the rebound root re-arm-enumerates");
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());
    core.on_enumerated(rearm, listed(vec![entry("a", FileKind::Dir, 1, 21)]));
    let a_watch = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r2/a") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the rebuilt directory arms");
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the fresh install keeps the fence parked"
    );
    core.on_watch_installed(
      a_watch,
      core.arm_attempt(a_watch),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let a_read = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r2/a") => Some(*req),
        _ => None,
      })
      .expect("the rebuilt directory re-arm-enumerates");
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());

    // The settle edge: the closing Rescan is ROUTED (in the effect queue) by
    // the same input that drained the last obligation — strictly before any
    // settlement poll can observe the settle and dispatch a parked cookie.
    core.on_enumerated(a_read, listed(Vec::new()));
    let effects = drain(&mut core);
    let closing = emits(&effects)
      .iter()
      .find(|c| c.kind().is_rescan())
      .map(|c| c.epoch())
      .expect("the closing Rescan is routed at the settle edge");
    assert!(
      closing > commit_epoch,
      "the closing Rescan strictly dominates the commit"
    );
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "only then does the fence resolve (the commit made the window lossy)"
    );
  }

  /// B2 (F2 seam): the core's dispatch-side re-signal — a standing
  /// arm-refused hole yields one epoch-bumped covering `Rescan` at the
  /// hole's path, already drained into the effect queue when the call
  /// returns (ahead of any write the caller dispatches next), plus a bounded
  /// heal kick; a second call is a no-op. Fails on old: the seam did not
  /// exist — after the failure's edge `Rescan`, nothing preceded a cookie.
  #[test]
  fn resignal_puts_a_fresh_covering_rescan_in_the_effects_before_returning() {
    let (mut core, scope, req, _root) = live_descending();
    core.on_enumerated(req, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the discovered directory arms");
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Failed(WatchError::NoSpace),
    );
    let effects = drain(&mut core);
    let edge_epoch = emits(&effects)
      .iter()
      .find(|c| c.kind().is_rescan())
      .map(|c| c.epoch())
      .expect("the failure's edge Rescan is routed");

    assert!(
      core.resignal_coverage_deficits(scope),
      "the hole re-signals"
    );
    let effects = drain(&mut core);
    let fresh = emits(&effects)
      .iter()
      .find(|c| c.kind().is_rescan())
      .cloned()
      .expect("the covering Rescan is queued before the call returned");
    assert_eq!(
      fresh.location(),
      &Location::from_segments([Segment::new("sub")])
    );
    assert!(
      fresh.epoch() > edge_epoch,
      "epoch-bumped — a fresh instruction, not the edge replayed"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::Enumerate { path, .. } if path.as_path() == Path::new("/r"))),
      "the bounded heal kick re-reads the hole's parent: {effects:?}"
    );
    assert!(
      !core.resignal_coverage_deficits(scope),
      "the re-signaled entry was cleared — a second call is a no-op"
    );
  }

  /// The cookie seam under lag (INV-PARK): the pre-dispatch deficit
  /// re-signal mints a LOCATED covering `Rescan`; on a lagged scope it must
  /// fold into the parked root instruction, not replace it — the barrier's
  /// one delivered instruction still covers every scope-wide drop the lag
  /// licenses. Fails on old: newest-wins parked the deficit's slice, so the
  /// sync's Rescan no longer covered writes outside it.
  #[test]
  fn a_deficit_resignal_under_lag_merges_into_the_parked_root_rescan() {
    let (mut core, scope, req, root_watch) = live_descending();
    core.on_enumerated(req, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the discovered directory arms");
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Failed(WatchError::NoSpace),
    );
    let edge_epoch = emits(&drain(&mut core))
      .iter()
      .find(|c| c.kind().is_rescan())
      .map(|c| c.epoch())
      .expect("the refused arm's edge Rescan is routed");

    // A refused delivery enters lag; the parked offer is not drained, so the
    // re-signal below merges pre-offer.
    core.on_inotify_events(
      scope,
      vec![inotify(&[root_watch], IN_CREATE, 0, Some(b"f.txt"))],
      at(1),
    );
    let _ = drain(&mut core);
    core.on_delivery(scope, Delivery::Refused, at(2));

    assert!(
      core.resignal_coverage_deficits(scope),
      "the standing hole re-signals ahead of the cookie dispatch"
    );
    let effects = drain(&mut core);
    let offered = emits(&effects);
    assert_eq!(
      offered.len(),
      1,
      "one parked instruction offers: {effects:?}"
    );
    assert!(offered[0].kind().is_rescan());
    assert!(
      offered[0].location().is_empty(),
      "the re-signal merged into the root coverage: {:?}",
      offered[0]
    );
    assert!(
      offered[0].epoch() > edge_epoch,
      "the merged instruction rides the re-signal's fresh epoch"
    );
  }

  /// B3 (P3 fence): a fence opened over a detached-and-held move source
  /// pends until the hold resolves — pairing or timeout — and then settles
  /// under the existing verdict rules (a clean hold's window stays clean).
  /// Fails on old: `rearm_settled` never counted the hold, so the fence
  /// settled mid-window and a cookie could beat the resolution's covering
  /// `Rescan`. (The latent-cold twin gate is pinned by
  /// `coalesced_grow_makes_the_fence_lossy_from_birth`.)
  #[test]
  fn a_fence_pends_across_a_held_move_source_until_resolution() {
    // Pairing resolution.
    let (mut core, scope, req, root_watch) = live_descending();
    core.on_enumerated(req, listed(vec![entry("d", FileKind::Dir, 1, 11)]));
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, .. } => Some(*watch),
        _ => None,
      })
      .expect("the discovered directory arms");
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let cold = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/d") => Some(*req),
        _ => None,
      })
      .expect("the armed child enumerates");
    core.on_enumerated(cold, listed(Vec::new()));
    let _ = drain(&mut core);
    clear_registration_loss(&mut core, scope);

    core.on_inotify_events(
      scope,
      vec![inotify(
        &[root_watch],
        IN_MOVED_FROM | IN_ISDIR,
        7,
        Some(b"d"),
      )],
      at(5),
    );
    let _ = drain(&mut core);
    let fence = core.open_cover_fence(scope);
    assert!(core.monitor.rearm_settled(scope), "a hold is not counted");
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "but the fence is gated across it"
    );
    core.on_inotify_events(
      scope,
      vec![inotify(
        &[root_watch],
        IN_MOVED_TO | IN_ISDIR,
        7,
        Some(b"e"),
      )],
      at(10),
    );
    let _ = drain(&mut core);
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Applied)],
      "a clean pairing releases the gate under the existing verdict rules"
    );

    // Timeout resolution.
    let (mut core, scope, req, root_watch) = live_descending();
    core.on_enumerated(req, listed(vec![entry("d", FileKind::Dir, 1, 11)]));
    let add = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, .. } => Some(*watch),
        _ => None,
      })
      .expect("the discovered directory arms");
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let cold = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/d") => Some(*req),
        _ => None,
      })
      .expect("the armed child enumerates");
    core.on_enumerated(cold, listed(Vec::new()));
    let _ = drain(&mut core);
    clear_registration_loss(&mut core, scope);

    core.on_inotify_events(
      scope,
      vec![inotify(
        &[root_watch],
        IN_MOVED_FROM | IN_ISDIR,
        9,
        Some(b"d"),
      )],
      at(5),
    );
    let _ = drain(&mut core);
    let fence = core.open_cover_fence(scope);
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());
    core.on_timeout(at(5) + WINDOW);
    let _ = drain(&mut core);
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Applied)],
      "the stranded half's resolution releases the gate"
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
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "both fences pend on the same scope settle"
    );
    let listing = vec![
      entry("keep", FileKind::Dir, 1, 11),
      entry("drop", FileKind::Dir, 1, 12),
      entry("extra", FileKind::Dir, 1, 13),
    ];
    run_cascade(&mut core, &BTreeMap::from([("/r", listing)]));
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
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

  /// Scope teardown mid-fence: the pending fences resolve `Dead` (the terminal
  /// Rescan covers the caller) at the NEXT settlement poll — the driver's one
  /// choke point — and no fence state survives the scope.
  ///
  /// `Dead` rather than `Degraded` because the driver's liveness maps still read
  /// live at this instant: the teardown only QUEUED its `TeardownStream`. A
  /// consumer that must refuse a dead scope reads the fact off the verdict, which
  /// is the only place it exists yet.
  #[test]
  fn teardown_mid_fence_resolves_dead_and_clears() {
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
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Dead)],
      "teardown mid-fence resolves Dead at the next poll"
    );
    assert!(
      core.cover_fences.is_empty(),
      "no fence state outlives the scope"
    );
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "resolution is one-shot"
    );
  }

  /// Answers every arm and enumerate in `effects` (arms as `Aliased` — the
  /// ordinary all-bindings-live recovery; the root's listing is
  /// `root_listing`, children empty), then quiesces whatever that feeds — the
  /// overflow-recovery helper for the out-of-window loss suites, whose
  /// assertions need the drained effects before the cascade is served.
  fn serve_enumerates_then_quiesce(core: &mut DriverCore, effects: &[Effect]) {
    for effect in effects {
      match effect {
        Effect::AddWatch { watch, .. } => {
          core.on_watch_installed(
            *watch,
            core.arm_attempt(*watch),
            crate::os::linux::WatchOutcome::Aliased(900),
          );
        }
        Effect::Enumerate { req, path, .. } => {
          let listing = if path.as_path() == Path::new("/r") {
            root_listing()
          } else {
            Vec::new()
          };
          core.on_enumerated(*req, listed(listing));
        }
        _ => {}
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
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
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
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
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
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
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
    // The repair rides the entry's removal, which is a settle observation like
    // any other and rests on the same ordering proof — a pending-empty entry has
    // no fence to exclude, so any proof under the current epoch reaches it.
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "a pending-empty entry resolves no fence"
    );
    assert!(
      core.cover_fences.is_empty(),
      "the observation clears the entry — nothing leaks"
    );
  }

  /// Brings up `/r/{a/b}` and stops with `b`'s arm dispatched but unanswered, so
  /// the caller owns whichever round trip it wants to catch mid-flight. Every
  /// cell below needs the same three levels, because the hazard is an ANCESTOR
  /// move — two levels are not enough to have one.
  fn descending_a_b() -> (DriverCore, ScopeId, WatchId, WatchId, WatchId) {
    let (mut core, scope, req, root) = live_descending();
    core.on_enumerated(req, listed(vec![entry("a", FileKind::Dir, 1, 11)]));
    let effects = drain(&mut core);
    let w_a = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/a") => Some(*watch),
        _ => None,
      })
      .expect("a arms");
    core.on_watch_installed(
      w_a,
      core.arm_attempt(w_a),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let a_req = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/a") => Some(*req),
        _ => None,
      })
      .expect("a cold-reads");
    core.on_enumerated(a_req, listed(vec![entry("b", FileKind::Dir, 1, 12)]));
    let w_b = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/a/b") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("b arms");
    (core, scope, root, w_a, w_b)
  }

  /// `mv /r/a /r/c`, then a replacement directory at the vacated `/r/a`. Both
  /// halves pair inside the window, so the hold is over by the time the caller's
  /// in-flight result lands — which is precisely when nothing else is left to
  /// catch it.
  fn move_a_to_c_and_replace(core: &mut DriverCore, scope: ScopeId, root: WatchId) {
    core.on_inotify_events(
      scope,
      vec![inotify(&[root], IN_MOVED_FROM | IN_ISDIR, 7, Some(b"a"))],
      at(5),
    );
    core.on_inotify_events(
      scope,
      vec![inotify(&[root], IN_MOVED_TO | IN_ISDIR, 7, Some(b"c"))],
      at(6),
    );
    core.on_inotify_events(
      scope,
      vec![inotify(&[root], IN_CREATE | IN_ISDIR, 0, Some(b"a"))],
      at(7),
    );
    let _ = drain(core);
  }

  /// A DESCENDANT's arm is lowered to `/r/a/b`, its ancestor `a` is renamed to
  /// `c`, a replacement directory takes the vacated `/r/a` — and only then does
  /// the arm acknowledge. Nothing that watches the node's own slot can see this:
  /// `b` never left `(a, "b")`, so its arm attempt is never superseded and the
  /// hold is over by the time the answer lands.
  ///
  /// Accepting it would certify a binding opened under the REPLACEMENT as the
  /// coverage of `/r/c/b`, attributing every record the replacement's subtree
  /// produces to a directory somewhere else while the real one stays unwatched.
  /// The placement fence answers it as the non-proof it is — and a binding
  /// nothing may certify is not kept either: the watch is RETIRED, so the
  /// executor disarms the kernel binding the driver actually opened, and the slot
  /// is rebuilt on a fresh handle addressed at the destination.
  #[test]
  fn a_descendant_arm_acknowledging_past_its_ancestors_move_is_not_a_binding() {
    let (mut core, scope, root, _w_a, w_b) = descending_a_b();
    let stale_attempt = core.arm_attempt(w_b);
    move_a_to_c_and_replace(&mut core, scope, root);

    core.on_watch_installed(
      w_b,
      stale_attempt,
      crate::os::linux::WatchOutcome::Installed(9),
    );
    let effects = drain(&mut core);
    assert!(
      !effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { watch, .. } if *watch == w_b
      )),
      "the stale acknowledgement does not carry b to Live and start its read: {effects:?}"
    );
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::RemoveWatch { watch, .. } if *watch == w_b
      )),
      "the binding it reported is disarmed rather than kept doubtful: {effects:?}"
    );
    let rebuilt = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/c/b") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the slot is rebuilt at the destination b actually occupies");
    assert_ne!(rebuilt, w_b, "on a fresh handle, never the retired one");

    // And the rebuild is a real obligation, not a formality: answering IT is
    // what finally covers the destination.
    core.on_watch_installed(
      rebuilt,
      core.arm_attempt(rebuilt),
      crate::os::linux::WatchOutcome::Installed(10),
    );
    let effects = drain(&mut core);
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { path, .. } if path.as_path() == Path::new("/r/c/b")
      )),
      "the acknowledgement of the LIVE path descends into the real destination: {effects:?}"
    );
  }

  /// The same descendant arm, acknowledging INSIDE the pairing window rather
  /// than past it — the half the detach edge owns, and the one the hold cannot
  /// answer on its own. The hold suppresses DELIVERY under a moved subtree and
  /// makes a read there coverage-only, but it has no verdict on a BINDING: the
  /// acknowledgement would carry `b` to `Live` on a watch opened at a path the
  /// subtree had already left, and the pairing's O(1) reparent re-arms nothing
  /// unless something dirtied the hold — so `b` would keep a kernel binding on
  /// the replacement's child for the rest of its life, delivering its records at
  /// `/r/c/b`.
  ///
  /// The fence answers it at the detach edge instead: the binding is retired
  /// rather than certified, and the hold is dirtied, which obliges the pairing to
  /// `Rescan` and re-arm the real destination. What is NOT re-issued in place is
  /// the arm — a replacement armed under the hold would lower the same vacated
  /// path and be retired again — so the REBUILD is what the pairing owes, and the
  /// pairing's crawl is what addresses it through the destination.
  #[test]
  fn a_descendant_arm_acknowledging_inside_the_hold_is_not_a_binding_either() {
    let (mut core, scope, root, _w_a, w_b) = descending_a_b();
    let stale_attempt = core.arm_attempt(w_b);
    // Only the source half: the hold is open when the acknowledgement lands.
    core.on_inotify_events(
      scope,
      vec![inotify(&[root], IN_MOVED_FROM | IN_ISDIR, 7, Some(b"a"))],
      at(5),
    );
    let _ = drain(&mut core);

    core.on_watch_installed(
      w_b,
      stale_attempt,
      crate::os::linux::WatchOutcome::Installed(9),
    );
    let effects = drain(&mut core);
    assert!(
      !effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { watch, .. } if *watch == w_b
      )),
      "a binding opened under the vacated path does not carry b to Live: {effects:?}"
    );
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::RemoveWatch { watch, .. } if *watch == w_b
      )),
      "it is disarmed instead: {effects:?}"
    );
    assert!(
      !effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { watch, .. } if *watch == w_b
      )),
      "and nothing is re-armed in place — under the hold that arm would open the \
       vacated path all over again: {effects:?}"
    );

    // Pairing: the dirtied hold is what makes the destination re-covered rather
    // than silently carried over by the O(1) reparent.
    core.on_inotify_events(
      scope,
      vec![inotify(&[root], IN_MOVED_TO | IN_ISDIR, 7, Some(b"c"))],
      at(6),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&["c"])),
      "the pairing covers the destination it had to re-arm: {effects:?}"
    );

    // And its crawl rebuilds the retired slot, addressed through the destination.
    let req = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/c") => Some(*req),
        _ => None,
      })
      .expect("the pairing re-reads the destination");
    core.on_enumerated(req, listed(vec![entry("b", FileKind::Dir, 1, 12)]));
    let effects = drain(&mut core);
    let rebuilt = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/c/b") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the crawl rebuilds the retired slot at the live path");
    assert_ne!(rebuilt, w_b, "on a fresh handle, never the retired one");
    core.on_watch_installed(
      rebuilt,
      core.arm_attempt(rebuilt),
      crate::os::linux::WatchOutcome::Installed(11),
    );
    let effects = drain(&mut core);
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { path, .. } if path.as_path() == Path::new("/r/c/b")
      )),
      "and the arm addressed at the live path finally converges: {effects:?}"
    );
  }

  /// The other side of the same fence: an arm whose lowering is CORRECT, and
  /// which the fence must therefore not refuse.
  ///
  /// One inotify batch, in order: a record under `a` discovers `b` and queues its
  /// arm; the next two rename `a` onto `c`. The core derives an action's absolute
  /// path when it DRAINS the action — after the whole batch has been fed — so the
  /// arm opens at `/r/c/b`, the destination the pairing left the node at. The
  /// acknowledgement is then a proof about the node's CURRENT binding, and a
  /// placement stamped back at enqueue would read it as stale and RETIRE it: a
  /// live binding torn down, its subtree re-crawled, and every record the gap
  /// swallows carried only by whatever the rebuild's own read happens to see.
  #[test]
  fn an_arm_lowered_after_its_ancestors_pairing_is_a_binding() {
    let (mut core, scope, req, root) = live_descending();
    core.on_enumerated(req, listed(vec![entry("a", FileKind::Dir, 1, 11)]));
    let effects = drain(&mut core);
    let w_a = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/a") => Some(*watch),
        _ => None,
      })
      .expect("a arms");
    core.on_watch_installed(
      w_a,
      core.arm_attempt(w_a),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let a_req = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/a") => Some(*req),
        _ => None,
      })
      .expect("a cold-reads");
    core.on_enumerated(a_req, listed(vec![]));
    let _ = drain(&mut core);

    core.on_inotify_events(
      scope,
      vec![
        inotify(&[w_a], IN_CREATE | IN_ISDIR, 0, Some(b"b")),
        inotify(&[root], IN_MOVED_FROM | IN_ISDIR, 7, Some(b"a")),
        inotify(&[root], IN_MOVED_TO | IN_ISDIR, 7, Some(b"c")),
      ],
      at(5),
    );
    let effects = drain(&mut core);
    let (w_b, attempt) = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch {
          watch,
          attempt,
          path,
          ..
        } if path.as_path() == Path::new("/r/c/b") => Some((*watch, *attempt)),
        _ => None,
      })
      .expect("the descendant's arm lowers at the destination the pairing left it at");

    core.on_watch_installed(w_b, attempt, crate::os::linux::WatchOutcome::Installed(9));
    let effects = drain(&mut core);
    // INSIDE the window a false retirement would open: its teardown and rebuild
    // are issued in this very drain.
    assert!(
      !effects
        .iter()
        .any(|e| matches!(e, Effect::RemoveWatch { watch, .. } if *watch == w_b)),
      "an arm the drain already addressed at the destination is a binding: {effects:?}"
    );
    let b_req = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/c/b") => Some(*req),
        _ => None,
      })
      .expect("the acknowledgement carries b to Live and descends into it");
    core.on_enumerated(b_req, listed(vec![]));
    let _ = drain(&mut core);

    // And the binding delivers: a retirement would have taken exactly this handle.
    core.on_inotify_events(
      scope,
      vec![inotify(&[w_b], IN_CREATE, 0, Some(b"x"))],
      at(6),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().is_created() && c.location() == &loc(&["c", "b", "x"])),
      "records off the proven binding stay deliverable: {effects:?}"
    );
    assert!(
      core.monitor.coverage_settled(scope),
      "and nothing is left holding the scope's barrier: {effects:?}"
    );
  }

  /// A slot stat is lowered to `/r/a/u`, the probed slot's parent `a` is renamed
  /// to `c`, a replacement takes `/r/a` — and the probe then answers for the
  /// vacated path. The Monitor keys the request by `(parent, name)`, which the
  /// rename carries intact, so without the fence the answer settles `/r/c/u`
  /// with what was found at `/r/a/u`: a `NotFound` there would discharge the
  /// slot's recorded darkness while the destination really holds an
  /// unclassified object.
  ///
  /// The degrade is covered AND counted — the deficit stands, so every later
  /// sync re-signals it — rather than a one-shot `Rescan` that leaves nothing
  /// behind.
  #[test]
  fn a_slot_stat_answering_past_its_parents_move_does_not_discharge_the_deficit() {
    let (mut core, scope, req, root) = live_descending();
    core.on_enumerated(req, listed(vec![entry("a", FileKind::Dir, 1, 11)]));
    let effects = drain(&mut core);
    let w_a = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/a") => Some(*watch),
        _ => None,
      })
      .expect("a arms");
    core.on_watch_installed(
      w_a,
      core.arm_attempt(w_a),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let a_req = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/a") => Some(*req),
        _ => None,
      })
      .expect("a cold-reads");
    // An unclassifiable entry is the one thing that asks for a stat.
    core.on_enumerated(a_req, listed(vec![entry("u", FileKind::Unknown, 1, 12)]));
    let effects = drain(&mut core);
    let probe = probes(&effects)
      .into_iter()
      .find(|(_, path)| path.as_path() == Path::new("/r/a/u"))
      .map(|(probe, _)| probe)
      .expect("the unclassified slot is probed at its lowered path");
    assert!(
      core.monitor.has_coverage_deficit(scope),
      "an unwatched unclassified slot books its darkness while the answer is owed"
    );

    move_a_to_c_and_replace(&mut core, scope, root);
    core.on_probe_result(probe, ProbeOutcome::Missing, at(8));
    let _ = drain(&mut core);
    assert!(
      core.monitor.has_coverage_deficit(scope),
      "an answer for the vacated path cannot report the destination's slot empty"
    );
  }

  /// A DESCENDANT's read is lowered to `/r/a/b`, its ancestor `a` is renamed to
  /// `c`, a replacement takes `/r/a` — and the read then returns the
  /// REPLACEMENT's listing. The hold that fences a read at a stale path is over
  /// by then, and `b` itself was never detached, so the read presents as a clean
  /// cold discovery of `/r/c/b`.
  ///
  /// Reconciling it would announce the replacement's children as created at the
  /// destination and arm watches for names that are not there, while the real
  /// destination's own children stay undiscovered. The placement fence answers
  /// it as a read that told us nothing: no entry is reconciled, and the
  /// destination keeps a watch AND a re-read rather than a bare `Rescan`.
  #[test]
  fn a_descendant_read_completing_past_its_ancestors_move_reconciles_nothing() {
    let (mut core, scope, root, _w_a, w_b) = descending_a_b();
    core.on_watch_installed(
      w_b,
      core.arm_attempt(w_b),
      crate::os::linux::WatchOutcome::Installed(3),
    );
    let b_req = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/a/b") => Some(*req),
        _ => None,
      })
      .expect("b cold-reads at its lowered path");

    move_a_to_c_and_replace(&mut core, scope, root);
    core.on_enumerated(b_req, listed(vec![entry("ghost", FileKind::Dir, 1, 99)]));
    let effects = drain(&mut core);
    assert!(
      !effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { path, .. } if path.as_path() == Path::new("/r/c/b/ghost")
      )),
      "the replacement's child is not armed under the destination: {effects:?}"
    );
    assert!(
      !emits(&effects)
        .iter()
        .any(|c| c.location() == &loc(&["c", "b", "ghost"])),
      "and it is not announced there either: {effects:?}"
    );
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { watch, path, .. }
          if *watch == w_b && path.as_path() == Path::new("/r/c/b")
      )),
      "the destination is re-read where it actually is: {effects:?}"
    );
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&["c", "b"])),
      "under a covering Rescan for the content the read could not report: {effects:?}"
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
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Installed(1),
    );
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
    let Admission::RootDeath(admitted) = classify(&mut map, &raw, &mut MemoBatch::new(), &[])
    else {
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
    live_scope_with(core, Interest::all())
  }

  /// The same, under a narrowed subscription — the shape an admission claim
  /// needs, since `Interest::all()` admits on any fact at all.
  fn live_scope_with(core: &mut DriverCore, interest: Interest) -> ScopeId {
    let scope = core.on_watch(PathBuf::from("/r"), interest, BackendKind::Rdcw);
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

  /// A named-stream action reports its OWNER, not the stream. The decoder cut
  /// the `owner:stream` suffix, so the location here is an ordinary path, and
  /// the record proves content AND metadata: creating, writing, resizing or
  /// deleting an alternate data stream changes bytes reachable through the
  /// owner and changes the owner's stream surface. Neither `Created` nor
  /// `Removed` may be proven — no dirent appeared or vanished.
  #[test]
  fn stream_actions_modify_their_owner() {
    for action in [
      RdcwAction::StreamAdded,
      RdcwAction::StreamRemoved,
      RdcwAction::StreamModified,
    ] {
      let mut core = DriverCore::new(WINDOW, LIVENESS);
      let scope = live_scope(&mut core);
      core.on_batch(
        scope,
        payload(vec![RdcwEvent::Single(rdcw(
          action,
          &["deep", "owner.txt"],
        ))]),
        at(1),
      );
      let effects = drain(&mut core);
      let emitted = emits(&effects);
      assert_eq!(emitted.len(), 1, "{action:?}: {emitted:?}");
      assert!(emitted[0].kind().is_modified(), "{action:?}: {emitted:?}");
      assert_eq!(emitted[0].location(), &loc(&["deep", "owner.txt"]));
      assert!(
        !emitted[0].kind().is_created() && !emitted[0].kind().is_removed(),
        "{action:?}: a stream mutation is not a dirent lifecycle: {emitted:?}"
      );
    }
  }

  /// The same stream mutation reaches an ATTRIB-only subscription. The USN arm
  /// files named-stream reasons under metadata, so an RDCW arm that proved only
  /// content would make the backend choice decide whether the subscriber hears
  /// about it at all.
  #[test]
  fn a_stream_action_admits_an_attrib_only_subscription() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope_with(&mut core, Interest::new().with_attrib());
    core.on_batch(
      scope,
      payload(vec![RdcwEvent::Single(rdcw(
        RdcwAction::StreamModified,
        &["owner.txt"],
      ))]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert_eq!(emitted[0].location(), &loc(&["owner.txt"]));
    // A `Rescan` reaches every subscription regardless of what it asked for,
    // so accepting one here would make the cell true for a lowering that
    // decodes no stream action at all.
    assert!(
      !emitted[0].kind().is_rescan(),
      "the fact must be DELIVERED, not covered: {emitted:?}"
    );
  }

  /// A name the decoder refused — a WTF-16 component or a generated 8.3 alias —
  /// covers its deepest usable ancestor instead of publishing a location the
  /// consumer's index does not use.
  #[test]
  fn a_refused_name_covers_its_parent_rather_than_naming_the_object() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(
      scope,
      payload(vec![RdcwEvent::Single(RdcwRecord {
        action: RdcwAction::Removed,
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
      "{emitted:?}"
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
    usn::{
      UsnAdmission, UsnAdmitted, UsnFence, UsnTarget,
      decode::{UsnName, UsnRecord},
      map::FrnMap,
      reason,
    },
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
    live_scope_with(core, Interest::all())
  }

  fn live_scope_with(core: &mut DriverCore, interest: Interest) -> ScopeId {
    let scope = core.on_watch(PathBuf::from("/r"), interest, BackendKind::UsnJournal);
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

  const USN_ROOT: u128 = 1;

  /// A live admission over the same `/r` the lowering scopes watch, with one
  /// mapped directory `a`. Driving the REAL admission (rather than hand-built
  /// `UsnAdmitted`) is what makes these cells witnesses for the source's own
  /// delta and batch decisions.
  fn seeded_admission() -> UsnAdmission {
    let mut map = FrnMap::new(USN_ROOT, None);
    map.seed([(10, USN_ROOT, "a".into())]);
    UsnAdmission::new(map, 64)
  }

  fn usn_record(frn: u128, parent: u128, reason_mask: u32, attrs: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: attrs,
      name: UsnName::Utf8(name.into()),
    }
  }

  /// Admits `records` as one read's worth of journal traffic and returns what a
  /// subscriber actually received for it — the cells about session bounds need
  /// each step's DELIVERY separately, because what they are about is which
  /// moment a repair arrives at, not whether one ever does.
  fn step(
    core: &mut DriverCore,
    scope: ScopeId,
    admission: &mut UsnAdmission,
    records: Vec<UsnRecord>,
  ) -> Vec<Change> {
    let mut admitted = Vec::new();
    for record in records {
      admission.admit(record, &mut admitted);
    }
    core.on_batch(scope, payload(admitted), at(1));
    emits(&drain(core)).into_iter().cloned().collect()
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

  /// One journal delta unions everything that happened to a file in the session,
  /// so a `FILE_CREATE | BASIC_INFO_CHANGE` proves a create AND an attribute
  /// change. Naming the record by the structural verb must not un-prove the
  /// other: an attrib-only subscription is admitted on the fact it asked about.
  #[test]
  fn a_merged_delta_admits_every_interest_it_proves() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope_with(&mut core, Interest::new().with_attrib());
    core.on_batch(
      scope,
      payload(vec![UsnAdmitted::Single {
        delta: reason::FILE_CREATE | reason::SECURITY_CHANGE,
        target: resolved(&["a", "new.txt"]),
        is_dir: false,
      }]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert_eq!(emitted[0].location(), &loc(&["a", "new.txt"]));

    // And the narrowing is still exact where nothing else was proven.
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope_with(&mut core, Interest::new().with_attrib());
    core.on_batch(
      scope,
      payload(vec![UsnAdmitted::Single {
        delta: reason::FILE_CREATE,
        target: resolved(&["a", "new.txt"]),
        is_dir: false,
      }]),
      at(1),
    );
    let effects = drain(&mut core);
    assert!(emits(&effects).is_empty(), "{effects:?}");
  }

  #[test]
  fn an_admitted_rename_becomes_one_moved() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(
      scope,
      payload(vec![UsnAdmitted::Renamed {
        old: resolved(&["a", "old.txt"]),
        old_content: 0,
        new: resolved(&["b", "new.txt"]),
        new_content: 0,
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

  /// A rename record's fresh content bits are evidence, and the choice to NAME
  /// the record a move must not consume them: a `RENAME_OLD_NAME |
  /// DATA_OVERWRITE` record proves a move AND a write, and NTFS coalescing can
  /// make it the only record the content class ever gets before the close.
  ///
  /// Driven through the REAL admission and asserted from a modified-only
  /// subscription, which no `Moved` verb admits on its own — so the cell is a
  /// witness for the evidence surviving the paired path, not for the pairing.
  #[test]
  fn a_paired_rename_admits_the_content_it_proves() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope_with(&mut core, Interest::new().with_modified());
    let mut adm = seeded_admission();
    let mut admitted = Vec::new();
    adm.admit(
      usn_record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "old.txt",
      ),
      &mut admitted,
    );
    adm.admit(
      usn_record(
        50,
        USN_ROOT,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE | reason::RENAME_NEW_NAME,
        0x20,
        "new.txt",
      ),
      &mut admitted,
    );
    assert!(
      matches!(&admitted[..], [UsnAdmitted::Renamed { old_content, .. }]
        if old_content & reason::DATA_OVERWRITE != 0),
      "the pair carries the departing record's content bits: {admitted:?}"
    );

    core.on_batch(scope, payload(admitted), at(1));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the content evidence widens the pairing's ONE change, never adds a \
       second delivery: {emitted:?}"
    );
    assert_eq!(
      emitted[0].kind().moved_from(),
      Some(&loc(&["a", "old.txt"]))
    );
    assert_eq!(emitted[0].location(), &loc(&["new.txt"]));
  }

  /// The same fact through the boundary degrade: a rename whose other end is
  /// outside the root lowers to the in-root end's membership verb, and that
  /// naming choice must not consume the content evidence either.
  #[test]
  fn a_boundary_rename_admits_the_content_it_proves() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope_with(&mut core, Interest::new().with_modified());
    let mut adm = seeded_admission();
    let mut admitted = Vec::new();
    adm.admit(
      usn_record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "old.txt",
      ),
      &mut admitted,
    );
    // The arriving half lands under an unmapped parent: out of root.
    adm.admit(
      usn_record(
        50,
        999,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE | reason::RENAME_NEW_NAME,
        0x20,
        "gone.txt",
      ),
      &mut admitted,
    );
    core.on_batch(scope, payload(admitted), at(1));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert_eq!(emitted[0].location(), &loc(&["a", "old.txt"]));
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

  /// A map that contradicts itself covers the root exactly like an overflow
  /// does; the difference is what the SOURCE does behind the cover — reseed
  /// rather than die — which the cover is agnostic to.
  #[test]
  fn a_map_inconsistency_covers_the_root() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(scope, payload(vec![UsnAdmitted::MapInconsistent]), at(1));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert!(
      emitted[0].kind().is_rescan() && emitted[0].location() == &loc(&[]),
      "{emitted:?}"
    );
  }

  /// A rename half the admission could not pair, or could not keep in-root, is
  /// NAMED by its membership verb and still ADMITS a move-only subscription:
  /// the degrade chooses a verb, and a verb choice must not narrow admission.
  /// Without the move fact the subscriber receives neither half and no rescan.
  #[test]
  fn a_degraded_rename_half_reaches_a_move_only_subscription() {
    for delta in [
      reason::FILE_DELETE | reason::RENAME_OLD_NAME,
      reason::FILE_CREATE | reason::RENAME_NEW_NAME,
    ] {
      let mut core = DriverCore::new(WINDOW, LIVENESS);
      let scope = live_scope_with(&mut core, Interest::new().with_moved());
      core.on_batch(
        scope,
        payload(vec![UsnAdmitted::Single {
          delta,
          target: resolved(&["a", "half.txt"]),
          is_dir: false,
        }]),
        at(1),
      );
      let effects = drain(&mut core);
      let emitted = emits(&effects);
      assert_eq!(emitted.len(), 1, "delta {delta:#x}: {emitted:?}");
      assert_eq!(emitted[0].location(), &loc(&["a", "half.txt"]));
    }
  }

  /// And the degrade still NAMES the membership verb for everyone else: the
  /// move fact widens admission, it does not rewrite the report.
  #[test]
  fn a_degraded_rename_half_still_names_its_membership_verb() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(
      scope,
      payload(vec![
        UsnAdmitted::Single {
          delta: reason::FILE_DELETE | reason::RENAME_OLD_NAME,
          target: resolved(&["gone.txt"]),
          is_dir: false,
        },
        UsnAdmitted::Single {
          delta: reason::FILE_CREATE | reason::RENAME_NEW_NAME,
          target: resolved(&["here.txt"]),
          is_dir: false,
        },
      ]),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 2, "{emitted:?}");
    assert!(emitted[0].kind().is_removed(), "{emitted:?}");
    assert!(emitted[1].kind().is_created(), "{emitted:?}");
    assert!(
      emitted.iter().all(|c| c.kind().moved_from().is_none()),
      "a degraded half never fabricates a paired Moved: {emitted:?}"
    );
  }

  /// What the consumer actually saw. A contradiction's root `Rescan` used to be
  /// followed, in the SAME delivery, by records whose paths the very same
  /// verdict had disowned: a subscriber re-read at the Rescan, believed itself
  /// consistent again, and diverged on the next record — and the source's own
  /// loss signal arrived only afterwards, too late to dominate any of it.
  #[test]
  fn a_contradicted_buffer_delivers_nothing_after_its_root_cover() {
    let mut map = FrnMap::new(USN_ROOT, None);
    map.seed([(10, USN_ROOT, "a".into()), (20, 10, "p".into())]);
    let mut admission = UsnAdmission::new(map, 64);
    let mut admitted = Vec::new();
    admission.admit_batch(
      vec![
        usn_record(50, 20, reason::FILE_CREATE, 0x20, "before.txt"),
        // History replayed out of order: "a was created under p", against a
        // map where p already sits inside a.
        usn_record(10, 20, reason::FILE_CREATE, 0x10, "a"),
        usn_record(60, 20, reason::FILE_CREATE, 0x20, "after.txt"),
      ],
      &mut admitted,
    );

    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(scope, payload(admitted), at(1));
    let emitted: Vec<Change> = emits(&drain(&mut core)).into_iter().cloned().collect();
    assert!(
      !emitted
        .iter()
        .any(|c| c.location() == &loc(&["a", "p", "after.txt"])),
      "nothing resolved through the disowned topology is delivered: {emitted:?}"
    );
    let last = emitted.last().expect("the cover is delivered");
    assert!(
      last.kind().is_rescan() && last.location() == &loc(&[]),
      "the root cover is the delivery's last word: {emitted:?}"
    );
  }

  /// The convergence a modified-only subscription depends on, over the exact
  /// stream NTFS produces for two writes and a close: `DATA_OVERWRITE`, then —
  /// because a repeat of an already-recorded kind writes no record — NOTHING,
  /// then `DATA_OVERWRITE | CLOSE`. Three changes, two records.
  ///
  /// A close repair armed by observing a wholly-repeated record cannot fire
  /// here, because the middle record does not exist. The subscriber heard one
  /// `Modified`, read the file at it, and held its half-written contents with
  /// nothing left in the stream to correct them.
  #[test]
  fn two_writes_then_a_close_deliver_twice_to_a_modified_only_subscription() {
    let mut admission = seeded_admission();
    let mut admitted = Vec::new();
    for mask in [
      reason::DATA_OVERWRITE,
      // The second write records nothing; the close is the next record.
      reason::DATA_OVERWRITE | reason::CLOSE,
    ] {
      admission.admit(usn_record(50, 10, mask, 0x20, "f.txt"), &mut admitted);
    }

    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope_with(&mut core, Interest::new().with_modified());
    for event in admitted {
      core.on_batch(scope, payload(vec![event]), at(1));
    }
    let emitted: Vec<Change> = emits(&drain(&mut core)).into_iter().cloned().collect();
    assert_eq!(
      emitted.len(),
      2,
      "the close must re-report content the journal never recorded a second time: {emitted:?}"
    );
    assert!(
      emitted.iter().all(|c| c.kind().is_modified()),
      "{emitted:?}"
    );
    assert!(
      emitted
        .iter()
        .all(|c| c.location() == &loc(&["a", "f.txt"])),
      "{emitted:?}"
    );
  }

  /// The same convergence across a class boundary. Write, an unrecorded second
  /// write, then a time stamp set: the touch is METADATA and no `Modified`
  /// subscription ever hears it, so only the close can repair the content.
  /// When a fresh bit of any class was treated as compensation, the close said
  /// nothing about content and the subscriber's newest delivery described a
  /// half-written file forever.
  #[test]
  fn a_modified_only_subscription_converges_across_a_metadata_touch() {
    let mut admission = seeded_admission();
    let mut admitted = Vec::new();
    for mask in [
      reason::DATA_EXTEND,
      // The second write records nothing; the time stamp set is a new kind
      // and records the accumulated mask.
      reason::DATA_EXTEND | reason::BASIC_INFO_CHANGE,
      reason::DATA_EXTEND | reason::BASIC_INFO_CHANGE | reason::CLOSE,
    ] {
      admission.admit(usn_record(50, 10, mask, 0x20, "f.txt"), &mut admitted);
    }

    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope_with(&mut core, Interest::new().with_modified());
    for event in admitted {
      core.on_batch(scope, payload(vec![event]), at(1));
    }
    let emitted: Vec<Change> = emits(&drain(&mut core)).into_iter().cloned().collect();
    assert_eq!(
      emitted.len(),
      2,
      "the close re-reports the write no record ever named: {emitted:?}"
    );
    assert!(
      emitted.iter().all(|c| c.kind().is_modified()),
      "{emitted:?}"
    );
    assert!(
      emitted
        .iter()
        .all(|c| c.location() == &loc(&["a", "f.txt"])),
      "{emitted:?}"
    );
  }

  /// The same convergence when the object has TWO names and only one of them
  /// is watched. A journal record names the link its handle was opened
  /// through, so a file linked as `a/in.txt` inside the tree and as `out.txt`
  /// outside it can be written through the watched name, suppress its repeat,
  /// and produce its close — the only convergence the journal offers — under
  /// the outside name.
  ///
  /// Routed there the replay was dropped as out-of-root and the modified-only
  /// subscriber, which had already read the file at the first write, was left
  /// holding half-written contents indefinitely. The repair is owed to the
  /// link the notice went to, and arrives as a cover: the summary proves the
  /// class changed and can prove nothing about when or through which handle.
  #[test]
  fn a_close_through_an_unwatched_hard_link_still_converges_the_watched_one() {
    let mut admission = seeded_admission();
    let mut admitted = Vec::new();
    admission.admit(
      usn_record(50, 10, reason::DATA_OVERWRITE, 0x20, "in.txt"),
      &mut admitted,
    );
    // The second write records nothing; the close names the OUTSIDE link,
    // whose parent the map does not know.
    admission.admit(
      usn_record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "out.txt",
      ),
      &mut admitted,
    );

    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope_with(&mut core, Interest::new().with_modified());
    for event in admitted {
      core.on_batch(scope, payload(vec![event]), at(1));
    }
    let emitted: Vec<Change> = emits(&drain(&mut core)).into_iter().cloned().collect();
    assert!(
      emitted
        .first()
        .is_some_and(|c| c.kind().is_modified() && c.location() == &loc(&["a", "in.txt"])),
      "the first write delivers at the watched link: {emitted:?}"
    );
    assert!(
      emitted
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&["a", "in.txt"])),
      "and the close still repairs it: {emitted:?}"
    );
  }

  /// The same convergence when the delivery that needs repairing was a RENAME.
  ///
  /// A `RENAME_OLD_NAME | DATA_OVERWRITE` record proves a move AND a write, and
  /// the pair lowers to ONE `Moved` located at the destination whose fact set
  /// carries that write — which is why a modified-only subscription, admitted on
  /// nothing a `Moved` verb proves by itself, hears it at all. The repeat that
  /// follows writes no record (the class is already in the session's cumulative
  /// mask) and the close lands on an out-of-root hard link, so the rename is the
  /// LAST thing this subscription is ever told about the file.
  ///
  /// Registering nothing for the rename left the session owing nothing, the
  /// close's own routing was dropped as out-of-root, and the subscriber that
  /// read at the `Moved` held half-written contents indefinitely.
  #[test]
  fn a_paired_rename_that_proves_content_still_converges_at_its_close() {
    let mut admission = seeded_admission();
    let mut admitted = Vec::new();
    admission.admit(
      usn_record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "old.txt",
      ),
      &mut admitted,
    );
    admission.admit(
      usn_record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE | reason::RENAME_NEW_NAME,
        0x20,
        "new.txt",
      ),
      &mut admitted,
    );
    // The second write records nothing; the close names the OUTSIDE link.
    admission.admit(
      usn_record(
        50,
        999,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE | reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "out.txt",
      ),
      &mut admitted,
    );

    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope_with(&mut core, Interest::new().with_modified());
    core.on_batch(scope, payload(admitted), at(1));
    let emitted: Vec<Change> = emits(&drain(&mut core)).into_iter().cloned().collect();
    assert!(
      emitted
        .first()
        .is_some_and(|c| c.kind().moved_from() == Some(&loc(&["a", "old.txt"]))
          && c.location() == &loc(&["a", "new.txt"])),
      "the premise: the rename's own write reaches a modified-only \
       subscription, at the destination: {emitted:?}"
    );
    assert!(
      emitted
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&["a", "new.txt"])),
      "and the close repairs the link that delivery reached: {emitted:?}"
    );
  }

  /// What a subscriber actually receives while a build cache churns under an
  /// exclusion — asserted through a core carrying NO exclusions of its own, so
  /// the common layer's delivery-side fence is inert and everything here is the
  /// USN admission's own doing.
  ///
  /// The common fence could never have covered this anyway. It drops COMPILED
  /// records, and by then the map has already learned each incarnation of the
  /// excluded directory: with a cap in force the third create answers
  /// `MapOverflow`, which lowers to a root-wide `Rescan` and kills the source —
  /// so an exclusion the caller added to shed load ended the watch on ground it
  /// was still watching.
  #[test]
  fn excluded_churn_reaches_no_subscriber_and_never_ends_the_scope() {
    let mut map = FrnMap::new(USN_ROOT, Some(2));
    map.seed([(10, USN_ROOT, "keep".into())]);
    let mut admission = UsnAdmission::new(map, 64).with_fence(UsnFence::new(
      PathBuf::from("/r"),
      vec![PathBuf::from("/r/cache")],
    ));
    let mut admitted = Vec::new();
    for round in 0..200u128 {
      let frn = 1000 + round;
      for mask in [
        reason::FILE_CREATE,
        reason::FILE_CREATE | reason::DATA_EXTEND,
        reason::FILE_CREATE | reason::DATA_EXTEND | reason::FILE_DELETE,
      ] {
        admission.admit(
          usn_record(frn, USN_ROOT, mask, 0x10, "cache"),
          &mut admitted,
        );
      }
    }
    // One ordinary change in the reported tree, after all of it.
    admission.admit(
      usn_record(50, 10, reason::DATA_OVERWRITE, 0x20, "f.txt"),
      &mut admitted,
    );

    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);
    core.on_batch(scope, payload(admitted), at(1));
    let emitted: Vec<Change> = emits(&drain(&mut core)).into_iter().cloned().collect();
    assert_eq!(
      emitted.len(),
      1,
      "six hundred excluded records deliver nothing: {emitted:?}"
    );
    assert!(
      emitted[0].kind().is_modified() && emitted[0].location() == &loc(&["keep", "f.txt"]),
      "and the reported tree's own change still arrives: {emitted:?}"
    );
  }

  /// What a subscriber receives when a WATCHED hard link is renamed after an
  /// UNWATCHED one — the shape the latent rename debt existed for.
  ///
  /// `a/in.txt` and an out-of-root `out.txt` are two links of one file, and the
  /// subscriber holds `a/in.txt` from the create it was delivered. Then:
  ///
  /// 1. the OUTSIDE link is renamed. Neither endpoint is a link this scope
  ///    reports, so nothing is delivered;
  /// 2. `a/in.txt` is renamed;
  /// 3. the last handle closes, through the OUTSIDE link.
  ///
  /// Step 2 was believed to write NO RECORD, because the rename bits already
  /// stood for the file reference — so the subscriber had to be sent back to the
  /// whole root at step 3, and, the journal being volume-wide, so did every
  /// other file rename on the disk. The journal writes both halves of every
  /// move: step 2 arrives as an ordinary `Moved`, and step 3 has nothing to say.
  #[test]
  fn a_renamed_watched_hard_link_reaches_the_subscriber_as_a_move() {
    let mut adm = seeded_admission();
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    let created = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(50, 10, reason::FILE_CREATE, 0x20, "in.txt")],
    );
    assert!(
      created
        .iter()
        .any(|c| c.kind().is_created() && c.location() == &loc(&["a", "in.txt"])),
      "the premise: the subscriber's state holds a/in.txt: {created:?}"
    );

    let outside = step(
      &mut core,
      scope,
      &mut adm,
      vec![
        usn_record(50, 999, reason::RENAME_OLD_NAME, 0x20, "out.txt"),
        usn_record(50, 999, reason::RENAME_NEW_NAME, 0x20, "out2.txt"),
      ],
    );
    assert!(
      outside.is_empty(),
      "the premise: the outside link's move is not this scope's business and \
       delivers nothing: {outside:?}"
    );

    // `a/in.txt` is renamed, and the journal writes both of its halves.
    let moved = step(
      &mut core,
      scope,
      &mut adm,
      vec![
        usn_record(50, 10, reason::RENAME_OLD_NAME, 0x20, "in.txt"),
        usn_record(50, 10, reason::RENAME_NEW_NAME, 0x20, "in2.txt"),
      ],
    );
    assert!(
      moved
        .iter()
        .any(|c| c.kind().moved_from() == Some(&loc(&["a", "in.txt"]))
          && c.location() == &loc(&["a", "in2.txt"])),
      "the subscriber is told where the watched link went, by name: {moved:?}"
    );

    let closed = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        50,
        999,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "out2.txt",
      )],
    );
    assert!(
      closed.is_empty(),
      "and the close sends it nowhere: a file rename anywhere on the volume no \
       longer rescans the watched root: {closed:?}"
    );
  }

  /// And the same silence on a DIRECTORY costs the watched tree nothing, because
  /// there the source can PROVE the sequence above is unreachable: NTFS forbids
  /// hard links to directories, so the link its records name is its only one and
  /// an unreported endpoint is the whole truth about where it is.
  ///
  /// Asserted on DELIVERY rather than on the flag, because this is where the
  /// cost lives: the journal is volume-wide, and a directory rename in an
  /// unwatched corner of the disk must not answer with a rescan — still less
  /// with the reseed a mapped directory's stale location buys.
  #[test]
  fn a_directory_renamed_outside_the_tree_sends_the_subscriber_nowhere() {
    let mut adm = seeded_admission();
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    let churn = step(
      &mut core,
      scope,
      &mut adm,
      vec![
        usn_record(70, 999, reason::RENAME_OLD_NAME, 0x10, "d"),
        usn_record(
          70,
          999,
          reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
          0x10,
          "d2",
        ),
        usn_record(
          70,
          999,
          reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME | reason::CLOSE,
          0x10,
          "d2",
        ),
      ],
    );
    assert!(
      churn.is_empty(),
      "unwatched directory churn reaches no subscriber: {churn:?}"
    );
  }

  /// What a subscriber receives when the session cap takes a FILE whose rename
  /// it had already admitted, and the file then moves AGAIN.
  ///
  /// A pure in-root rename delivers a `Moved` and nothing replayable with it, so
  /// the session retains no link and the eviction has nothing to surrender. What
  /// the eviction used to also take was the FACT that a rename had been
  /// admitted, because the second move on the same open handle was believed to
  /// write no record — so the close on an out-of-root hard link had to send the
  /// subscriber back to the whole root.
  ///
  /// The second move writes its own two records, so the eviction has nothing to
  /// remember: the subscriber is told the file's new name by name, and the close
  /// adds nothing. A cap that bites now costs a repeated WRITE's repair and
  /// never a move's.
  #[test]
  fn an_evicted_files_second_move_still_reaches_the_subscriber_by_name() {
    let mut map = FrnMap::new(USN_ROOT, None);
    map.seed([(10, USN_ROOT, "a".into())]);
    // One live session slot: the next subject's first record evicts this one.
    let mut adm = UsnAdmission::new(map, 1);
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    let moved = step(
      &mut core,
      scope,
      &mut adm,
      vec![
        usn_record(50, 10, reason::RENAME_OLD_NAME, 0x20, "old.txt"),
        usn_record(
          50,
          10,
          reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
          0x20,
          "new.txt",
        ),
      ],
    );
    assert!(
      moved
        .iter()
        .any(|c| c.kind().moved_from() == Some(&loc(&["a", "old.txt"]))
          && c.location() == &loc(&["a", "new.txt"])),
      "the premise: the first move is delivered, and the consumer's state for \
       the file moves with it: {moved:?}"
    );

    let evicting = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        60,
        10,
        reason::DATA_OVERWRITE,
        0x20,
        "other.txt",
      )],
    );
    assert!(
      !evicting.iter().any(|c| c.kind().is_rescan()),
      "the premise: an unrelated subject takes the slot, saying nothing about \
       the renamed file: {evicting:?}"
    );

    // The second move, on a session the cap has already forgotten.
    let again = step(
      &mut core,
      scope,
      &mut adm,
      vec![
        usn_record(50, 10, reason::RENAME_OLD_NAME, 0x20, "new.txt"),
        usn_record(50, 10, reason::RENAME_NEW_NAME, 0x20, "third.txt"),
      ],
    );
    assert!(
      again
        .iter()
        .any(|c| c.kind().moved_from() == Some(&loc(&["a", "new.txt"]))
          && c.location() == &loc(&["a", "third.txt"])),
      "the second move is delivered by its own records, whatever the cap did to \
       the entry: {again:?}"
    );

    // And the close, on an out-of-root hard link, has nothing left to repair.
    let closed = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        50,
        999,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "elsewhere.txt",
      )],
    );
    assert!(
      !closed.iter().any(|c| c.kind().is_rescan()),
      "the close covers nothing: {closed:?}"
    );
  }

  /// A COVER IS THE LAST WORD OF THE RECORD THAT PAID IT, asserted on what the
  /// subscriber receives AND in what order.
  ///
  /// The verdict that reaches this is the orphan ledger's anonymous residue: its
  /// bound took a debt's NAME, so some session this source stopped tracking is
  /// still owed a repair and no close proves whose. It is paid with the reseed
  /// spine, which says the MAP is untrustworthy — and the record paying it would
  /// resolve its own name through that same map. Lowering it anyway sends the
  /// subscriber back to the filesystem and then immediately hands it an event at
  /// a name the source has just disowned, re-diverging it on the spot.
  #[test]
  fn a_paid_cover_reaches_the_subscriber_with_nothing_behind_it() {
    let mut map = FrnMap::new(USN_ROOT, None);
    map.seed([(10, USN_ROOT, "a".into())]);
    // One live session slot, and — the ledger takes the same bound — one named
    // orphan debt.
    let mut adm = UsnAdmission::new(map, 1);
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    // Three writers in turn: each evicts its predecessor, which owes a repair to
    // the link it just delivered at. The second eviction has no name left to
    // record and falls into the residue.
    for (frn, name) in [(50u128, "one.txt"), (60, "two.txt"), (70, "three.txt")] {
      let delivered = step(
        &mut core,
        scope,
        &mut adm,
        vec![usn_record(frn, 10, reason::DATA_OVERWRITE, 0x20, name)],
      );
      assert!(
        delivered
          .iter()
          .any(|c| c.kind().is_modified() && c.location() == &loc(&["a", name])),
        "the premise: each writer's own change is delivered: {delivered:?}"
      );
    }

    // An unrelated subject's close. The residue rides along, because it names
    // nobody and this close may be the debtor's.
    let closed = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        80,
        10,
        reason::FILE_CREATE | reason::CLOSE,
        0x20,
        "fresh.txt",
      )],
    );
    assert!(
      closed
        .first()
        .is_some_and(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "the cover comes first: {closed:?}"
    );
    assert!(
      closed
        .iter()
        .all(|c| c.location() != &loc(&["a", "fresh.txt"])),
      "and nothing follows it at a name resolved through the map it disowned: \
       {closed:?}"
    );
  }

  /// What a subscriber receives when the cap takes a session whose rename half
  /// is still PARKED in the pairer.
  ///
  /// A parked half is a record already observed and not yet lowered, so nothing
  /// it owes has been registered: an unrelated record observed in that window
  /// took the entry at its emptiest, the ledger recorded no debt because none
  /// existed yet, and the half then widowed into registrations with no entry
  /// left to reach. The close on an out-of-root hard link delivered nothing at
  /// all, and a subscriber that had read the file at the parked half's own write
  /// held half-written contents for good.
  ///
  /// The carried half proves a WRITE besides its move, which is what makes it
  /// owe a registration: a repeated write is still silent, and its repair still
  /// has to reach the link the notice went to.
  #[test]
  fn a_parked_half_is_lowered_before_the_cap_can_take_its_session() {
    let mut map = FrnMap::new(USN_ROOT, None);
    map.seed([(10, USN_ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 1);
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    // One read's worth: a pure OLD half, then an unrelated subject's write.
    let widowed = step(
      &mut core,
      scope,
      &mut adm,
      vec![
        usn_record(
          50,
          10,
          reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
          0x20,
          "old.txt",
        ),
        usn_record(60, 10, reason::DATA_OVERWRITE, 0x20, "other.txt"),
      ],
    );
    assert!(
      widowed
        .first()
        .is_some_and(|c| c.location() == &loc(&["a", "old.txt"])),
      "the premise: the parked half is delivered first, in journal order: \
       {widowed:?}"
    );

    // A further write records nothing; the close lands on an out-of-root hard
    // link, so its own routing reaches no subscriber.
    let closed = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "elsewhere.txt",
      )],
    );
    assert!(
      closed
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "the close still covers the repair the cap could no longer name: {closed:?}"
    );
  }

  /// What a subscriber receives when the ORPHAN LEDGER reaches its own bound.
  ///
  /// Three writers and one session slot: each new subject evicts the previous
  /// one, and the third eviction pushes the ledger past what it can NAME. A
  /// bound that answered that by dropping the oldest debt and paying its cover
  /// on the spot covered everything up to that instant and nothing after it —
  /// and the session behind that debt was still OPEN, so its next write was
  /// recorded as nothing at all and its close, landing on an out-of-root hard
  /// link, delivered nothing either.
  #[test]
  fn a_ledger_at_its_bound_still_covers_what_the_forgotten_sessions_do_next() {
    let mut map = FrnMap::new(USN_ROOT, None);
    map.seed([(10, USN_ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 1);
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    for (frn, name) in [(50u128, "first.txt"), (60, "second.txt"), (70, "third.txt")] {
      let delivered = step(
        &mut core,
        scope,
        &mut adm,
        vec![usn_record(frn, 10, reason::DATA_OVERWRITE, 0x20, name)],
      );
      assert!(
        delivered
          .iter()
          .any(|c| c.kind().is_modified() && c.location() == &loc(&["a", name])),
        "the premise: each writer's own change is delivered at its link: \
         {delivered:?}"
      );
    }

    // The first writer goes on writing. Its class already stands in the
    // session's mask, so NTFS records nothing, and it closes on an out-of-root
    // hard link.
    let closed = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "outside.txt",
      )],
    );
    assert!(
      closed
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "the close of a session the ledger stopped naming still covers it: \
       {closed:?}"
    );

    // And a subject the ledger never held is covered by the same residue: it
    // cannot tell whose close this is, so while it stands it is owed at each.
    let stranger = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        80,
        999,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "stranger.txt",
      )],
    );
    assert!(
      stranger
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "an unnameable debt is covered conservatively, never settled early: \
       {stranger:?}"
    );
  }

  /// What a subscriber receives when the record that ends a session is also the
  /// record that completes its parked rename half.
  ///
  /// NTFS ends a session with a summary of everything it accumulated plus
  /// `CLOSE`, so the arriving half and the retirement can be ONE record. The
  /// retirement runs first, and it is what reads out the obligations the parked
  /// departing half had not registered yet — so the half is widowed ahead of it,
  /// and BOTH ends reach the subscriber as their own membership verbs.
  ///
  /// This shape used to answer with a root `Rescan` and then refuse to name the
  /// destination at all, because the cover disowned the record carrying it: the
  /// subscriber was sent back to the filesystem instead of being told where the
  /// directory went. The move writes both of its records, so both are delivered.
  #[test]
  fn a_close_merged_with_its_rename_half_names_both_ends() {
    let mut adm = seeded_admission();
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    let parked = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(10, USN_ROOT, reason::RENAME_OLD_NAME, 0x10, "a")],
    );
    assert!(
      parked.is_empty(),
      "the premise: the departing half is parked, so nothing it owes is booked \
       and nothing is delivered: {parked:?}"
    );

    let closed = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        10,
        USN_ROOT,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        0x10,
        "a2",
      )],
    );
    assert!(
      closed
        .iter()
        .any(|c| c.kind().is_removed() && c.location() == &loc(&["a"])),
      "the departure reaches the subscriber: {closed:?}"
    );
    assert!(
      closed.iter().any(|c| c.location() == &loc(&["a2"])),
      "and so does the destination the cover used to refuse to name: {closed:?}"
    );
    assert!(
      !closed
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "and the subscriber is not sent back to the whole root for it: {closed:?}"
    );
  }

  /// The same window, entered by a rename that CROSSES the reported tree's
  /// boundary — a departing endpoint OUTSIDE the root, an arriving one inside —
  /// asserted on what the subscriber receives and in what order.
  ///
  /// The departing half is drained ahead of the close exactly as it must be, and
  /// registers nothing: its endpoint is not one this scope reports, so its
  /// lowering is discarded there. The arriving endpoint rides the closing record
  /// itself, and it is DELIVERED — the subject arrived at a name this scope
  /// reports, and its own record says so. This used to be answered with a root
  /// `Rescan` that then disowned the very record carrying the arrival, so the
  /// subscriber was never told the name at all.
  #[test]
  fn a_crossing_into_the_root_reports_the_arrival_its_close_carries() {
    let mut adm = seeded_admission();
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    let parked = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        50,
        999,
        reason::RENAME_OLD_NAME,
        0x20,
        "outside.txt",
      )],
    );
    assert!(
      parked.is_empty(),
      "the premise: the departing half names a parent outside the root, so it \
       is parked and reports nothing: {parked:?}"
    );

    let closed = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        50,
        10,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "in.txt",
      )],
    );
    assert!(
      closed
        .iter()
        .any(|c| c.kind().is_created() && c.location() == &loc(&["a", "in.txt"])),
      "the crossing's reported end reaches the subscriber by name: {closed:?}"
    );
    assert!(
      !closed
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "and nothing sends it back to the whole root: {closed:?}"
    );
  }

  /// The other crossing form, at the same window: a departing endpoint the
  /// caller EXCLUDED, an arriving one inside the reported tree.
  ///
  /// An excluded endpoint resolves through the map and an out-of-root one does
  /// not, which is why the suppression rule keeps three answers apart rather
  /// than two. The excluded half reports nothing and the reported one — merged
  /// into the record that retires the session — is delivered, where a root
  /// `Rescan` used to stand in its place and then disown it.
  ///
  /// Asserted through a core carrying NO exclusions of its own, so the common
  /// layer's delivery-side fence is inert and everything here is the USN
  /// admission's own doing.
  #[test]
  fn an_excluded_to_reported_crossing_reports_the_arrival_its_close_carries() {
    let mut map = FrnMap::new(USN_ROOT, None);
    map.seed([(10, USN_ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64).with_fence(UsnFence::new(
      PathBuf::from("/r"),
      vec![PathBuf::from("/r/a/cache")],
    ));
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    let parked = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(50, 10, reason::RENAME_OLD_NAME, 0x20, "cache")],
    );
    assert!(
      parked.is_empty(),
      "the premise: the departing endpoint resolves and is fenced off, so it \
       is parked and reports nothing: {parked:?}"
    );

    let closed = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        50,
        10,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "kept.txt",
      )],
    );
    assert!(
      closed
        .iter()
        .any(|c| c.kind().is_created() && c.location() == &loc(&["a", "kept.txt"])),
      "the reported end reaches the subscriber by name: {closed:?}"
    );
    assert!(
      !closed
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "and nothing sends it back to the whole root: {closed:?}"
    );
  }

  /// The same window, closed by a record that completes NOTHING.
  ///
  /// This one was silent twice over. The close's delta was empty, so admission
  /// returned before the pairer was reached: the departing half stayed parked
  /// past the record that retired its own session, and the close delivered
  /// nothing whatsoever. The departure surfaced only at whatever later record
  /// or boundary flush drained the carry — and a departure is no discharge
  /// here, because a standing `RENAME_OLD_NAME` at a close whose summary never
  /// carried the arriving half means the destination was never observed and may
  /// be in-root. So the half is drained while its entry is still there to book
  /// against, and it is the record that ended the session that delivers it.
  #[test]
  fn a_close_that_completes_nothing_still_delivers_its_parked_half() {
    let mut adm = seeded_admission();
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_scope(&mut core);

    let parked = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(10, USN_ROOT, reason::RENAME_OLD_NAME, 0x10, "a")],
    );
    assert!(
      parked.is_empty(),
      "the premise: parked, unbooked: {parked:?}"
    );

    let closed = step(
      &mut core,
      scope,
      &mut adm,
      vec![usn_record(
        10,
        USN_ROOT,
        reason::RENAME_OLD_NAME | reason::CLOSE,
        0x10,
        "a",
      )],
    );
    assert!(
      closed
        .iter()
        .any(|c| c.kind().is_removed() && c.location() == &loc(&["a"])),
      "the departure reaches the subscriber at the record that ended the \
       session, not at some later one: {closed:?}"
    );
  }
}

/// The replace commit on a kernel-recursive scope: the world swaps, the old
/// world's owed work is dominated by the epoch-bumped covering Rescan, and
/// deliveries flow under the NEW root immediately.
mod root_replaced {
  use super::*;
  use crate::os::windows::{RawWindowsEvent, RdcwAction, RdcwEvent, RdcwName, RdcwRecord};

  fn meta(root: &str, dev: u64, ino: u128, backend: BackendKind) -> RootMeta {
    RootMeta {
      root: PathBuf::from(root),
      root_dev: dev,
      root_mnt_id: None,
      mounts: Vec::new(),
      identity: crate::os::RootIdentity::new(dev, ino),
      ancestors: Vec::new(),
      backend,
    }
  }

  fn live_kr_scope(core: &mut DriverCore) -> ScopeId {
    let scope = core.on_watch(PathBuf::from("/a/b"), Interest::all(), BackendKind::Rdcw);
    let _ = drain(core);
    core.on_stream_spawned(scope, Ok(meta("/a/b", 1, 1, BackendKind::Rdcw)));
    let _ = drain(core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(core);
    scope
  }

  fn rdcw_payload(action: RdcwAction, components: &[&str]) -> BatchPayload {
    BatchPayload::detached(vec![SourceEvent::Windows(RawWindowsEvent::Rdcw(
      RdcwEvent::Single(RdcwRecord {
        action,
        name: RdcwName::Utf8(components.iter().map(|c| (*c).to_owned()).collect()),
        file_id: None,
        parent_id: None,
        attributes: None,
        reparse_tag: None,
      }),
    ))])
  }

  #[test]
  fn the_commit_swaps_the_world_and_covers_by_domination() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = live_kr_scope(&mut core);

    // Pre-replace: an event lowers under the OLD root.
    core.on_batch(scope, rdcw_payload(RdcwAction::Added, &["pre.txt"]), at(1));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(emitted[0].kind().is_created());

    // The replace commit: /a/b widens to /a on the same device.
    core.on_root_replaced(scope, meta("/a", 1, 1, BackendKind::Rdcw), at(2));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert!(
      emitted
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "the commit emits the covering full-root Rescan: {emitted:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::RefreshMounts { scope: s, .. } if *s == scope)),
      "the new world re-arms its mount refresh: {effects:?}"
    );

    // Post-replace: deliveries carry the NEW canonical root...
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(3));
    let _ = drain(&mut core);
    core.on_batch(scope, rdcw_payload(RdcwAction::Added, &["post.txt"]), at(4));
    let effects = drain(&mut core);
    let delivered = effects.iter().find_map(|e| match e {
      Effect::Emit { root, change, .. } => Some((root.clone(), change.clone())),
      _ => None,
    });
    let (root, change) = delivered.expect("the post-replace event delivers");
    assert_eq!(root.as_path(), Path::new("/a"), "the delivery root swapped");
    assert!(change.kind().is_created());
    assert_eq!(change.location(), &loc(&["post.txt"]));
  }

  #[test]
  fn parked_probe_work_is_cut_never_readdressed() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    // An FSEvents scope: its ambiguous flag words PARK batches on probes.
    let scope = core.on_watch(
      PathBuf::from("/a/b"),
      Interest::all(),
      BackendKind::FsEvents,
    );
    let _ = drain(&mut core);
    core.on_stream_spawned(scope, Ok(meta("/a/b", 1, 1, BackendKind::FsEvents)));
    let _ = drain(&mut core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(&mut core);

    // An ambiguous event parks awaiting its grounding probe.
    core.on_batch_events(
      scope,
      vec![ev(
        "/a/b/mystery.txt",
        flags(&[FsEventFlags::ITEM_CREATED, FsEventFlags::ITEM_REMOVED]),
        7,
        0,
      )],
      at(1),
    );
    let effects = drain(&mut core);
    let parked = probes(&effects);
    assert!(
      !parked.is_empty(),
      "the ambiguous event grounds through a probe: {effects:?}"
    );

    // The replace lands while the probe is in flight: the parked batch is
    // dominated. The probe's LATE result must then be a no-op.
    core.on_root_replaced(scope, meta("/a", 1, 1, BackendKind::FsEvents), at(2));
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "the cut covers the parked work"
    );
    // The late probe result addressed to the purged context is dropped.
    core.on_probe_result(parked[0].0, ProbeOutcome::Missing, at(3));
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .all(|c| !c.kind().is_created() && !c.kind().is_removed()),
      "no old-world verb is fabricated after the cut: {effects:?}"
    );
  }
  /// A mount refresh in flight across the commit carries the REPLACED
  /// world's facts — its liveness verdict included. The cross-world gate
  /// discards it whole (the old object's identity must never read as the
  /// new root's death) and re-reads the live world.
  #[test]
  fn an_in_flight_refresh_across_the_commit_cannot_kill_the_swapped_scope() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = core.on_watch(PathBuf::from("/a/b"), Interest::all(), BackendKind::Rdcw);
    let _ = drain(&mut core);
    core.on_stream_spawned(scope, Ok(meta("/a/b", 1, 1, BackendKind::Rdcw)));
    // The birth refresh is dispatched and STILL OUT when the commit lands.
    let _ = drain(&mut core);
    core.on_root_replaced(scope, meta("/a", 1, 2, BackendKind::Rdcw), at(1));
    let _ = drain(&mut core);

    // The old-world completion: alive, but at the OLD identity (1, 1) —
    // without the gate this reads as the (1, 2) root replaced, and kills.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let effects = drain(&mut core);
    assert!(
      core.scopes.contains_key(&scope),
      "the swapped scope survives the cross-world verdict"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::RefreshMounts { scope: s, .. } if *s == scope)),
      "the live world is re-read: {effects:?}"
    );
    assert!(
      emits(&effects).is_empty(),
      "no fabricated death or churn: {effects:?}"
    );

    // The re-read reports the LIVE world — the new identity installs
    // authority; the same verdict that killed above is now death evidence
    // no gate discards (same world, real facts).
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 2)),
        root_mnt_id: None,
      },
      at(3),
    );
    let _ = drain(&mut core);
    assert!(core.scopes.contains_key(&scope));
    let state = core.scopes.get(&scope).unwrap();
    assert!(
      state.mounts_authoritative,
      "the live read installed authority"
    );
  }

  /// The descending commit: the world swaps, the per-directory book rebinds
  /// (children dropped with the old transport), the covering Rescan stands,
  /// and the replayed pre-arm outcome rebuilds coverage RE-ARM flavored —
  /// arms without announcements, the Rescan already said everything.
  #[test]
  fn a_descending_commit_rebinds_and_rebuilds_rearm_flavored() {
    fn entry(name: &str, kind: FileKind, dev: u64, ino: u64) -> crate::core::RawDirEntry {
      crate::core::RawDirEntry {
        name: name.as_bytes().to_vec(),
        kind,
        dev,
        ino,
        mnt_id: None,
      }
    }
    fn listed(entries: Vec<crate::core::RawDirEntry>) -> crate::core::RawEnumerate {
      crate::core::RawEnumerate::Listed {
        entries,
        complete: true,
      }
    }
    use crate::os::linux::WatchOutcome;

    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = core.on_watch(PathBuf::from("/a/b"), Interest::all(), BackendKind::Inotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(scope, Ok(meta("/a/b", 1, 1, BackendKind::Inotify)));
    let effects = drain(&mut core);
    let root_watch = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch {
          watch,
          parent,
          path,
          ..
        } if path.as_path() == Path::new("/a/b") && watch == parent => Some(*watch),
        _ => None,
      })
      .expect("the descending root arms through the effect path");
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      WatchOutcome::Installed(1),
    );
    let effects = drain(&mut core);
    let req = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/a/b") => Some(*req),
        _ => None,
      })
      .expect("the cold read");
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    core.on_enumerated(req, listed(vec![entry("sub", FileKind::Dir, 1, 11)]));
    let effects = drain(&mut core);
    let child = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/a/b/sub") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the discovered child arms");
    core.on_watch_installed(child, core.arm_attempt(child), WatchOutcome::Installed(2));
    let effects = drain(&mut core);
    let child_req = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/a/b/sub") => {
          Some(*req)
        }
        _ => None,
      })
      .expect("the child read");
    core.on_enumerated(child_req, listed(vec![]));
    let _ = drain(&mut core);

    // The commit: /a/b widens to /a on a new transport the driver already
    // pre-armed. The core owes the Rescan and the refresh — but NO arm: the
    // rebound root awaits the replay.
    core.on_root_replaced(scope, meta("/a", 1, 1, BackendKind::Inotify), at(2));
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&[])),
      "the covering Rescan at the new root: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::RefreshMounts { scope: s, .. } if *s == scope)),
      "authority fails closed until the new world's refresh: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .all(|e| !matches!(e, Effect::AddWatch { .. })),
      "the rebound root waits for the replayed pre-arm: {effects:?}"
    );

    // The replay: the commit's synthetic loss postdates the pre-arm on the
    // inotify profile, so its ACK is stale under the stamp rule — one re-add
    // re-proves the binding on the new transport, and only its own ACK
    // unlocks the re-arm-flavored rebuild.
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      WatchOutcome::Installed(9),
    );
    let readd = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch {
          watch,
          parent,
          path,
          ..
        } if watch == parent && path.as_path() == Path::new("/a") => Some(*watch),
        _ => None,
      })
      .expect("the rebound root's binding is re-proven post-commit");
    assert_eq!(readd, root_watch, "the re-add names the surviving root");
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      WatchOutcome::Aliased(9),
    );
    let effects = drain(&mut core);
    let rebuild = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, watch, path } if path.as_path() == Path::new("/a") => {
          Some((*req, *watch))
        }
        _ => None,
      })
      .expect("the rebuild reads the NEW root: {effects:?}");
    assert_eq!(rebuild.1, root_watch, "the same surviving watch id");
    core.on_enumerated(
      rebuild.0,
      listed(vec![
        entry("b", FileKind::Dir, 1, 1),
        entry("sub2", FileKind::Dir, 1, 21),
      ]),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().all(|c| !c.kind().is_created()),
      "a re-arm rebuild announces nothing: {effects:?}"
    );
    for path in ["/a/b", "/a/sub2"] {
      assert!(
        effects
          .iter()
          .any(|e| matches!(e, Effect::AddWatch { path: p, .. } if p.as_path() == Path::new(path))),
        "the rebuild re-arms {path}: {effects:?}"
      );
    }
  }
}

/// The same-transport WIDEN commit (`on_root_widened`): the world splices
/// above the live root with NO cut — no covering Rescan, no epoch bump, no
/// park/probe/read purge — and every old-subtree delivery re-roots at its
/// unchanged absolute path.
mod root_widened {
  use super::*;
  use crate::{
    core::{RawDirEntry, RawEnumerate},
    os::linux::{RawInotifyEvent, RawLinuxEvent, inotify::decode::InotifyMask},
  };

  const IN_CREATE: u32 = 0x0000_0100;

  fn inotify(anchors: &[WatchId], mask: u32, name: &[u8]) -> RawLinuxEvent {
    RawLinuxEvent::Inotify {
      anchors: anchors.to_vec(),
      event: RawInotifyEvent {
        wd: 1,
        mask: InotifyMask(mask),
        cookie: 0,
        name: Some(name.to_vec()),
      },
    }
  }

  fn meta(root: &str, ino: u128) -> RootMeta {
    RootMeta {
      root: PathBuf::from(root),
      root_dev: 1,
      root_mnt_id: None,
      mounts: Vec::new(),
      identity: crate::os::RootIdentity::new(1, ino),
      ancestors: Vec::new(),
      backend: BackendKind::Inotify,
    }
  }

  /// Opens the witnessed window and commits the widen — the driver's
  /// begin → pre-arm → commit order, minus the transport. The window stays
  /// clean unless the cell taints it in between, so the commit applies.
  fn widen(core: &mut DriverCore, scope: ScopeId, meta: RootMeta, now: Instant) -> WatchId {
    let reserved = core.reserve_watch_id();
    core.begin_widen_watch(scope, reserved);
    assert!(matches!(
      core.on_root_widened(scope, meta, reserved, now),
      WidenCommit::Committed(_)
    ));
    reserved
  }

  /// A live descending scope rooted at `root`, its root armed; the birth cold
  /// read (returned) is fed empty unless `feed_boot` is false — the
  /// outstanding-read survival cell keeps it in flight across the widen.
  fn live_at(root: &str, ino: u128, feed_boot: bool) -> (DriverCore, ScopeId, WatchId, ReqId) {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = core.on_watch(PathBuf::from(root), Interest::all(), BackendKind::Inotify);
    let _ = drain(&mut core);
    core.on_stream_spawned(scope, Ok(meta(root, ino)));
    let effects = drain(&mut core);
    let root_watch = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, parent, .. } if watch == parent => Some(*watch),
        _ => None,
      })
      .expect("the descending root arms through the effect path");
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Installed(1),
    );
    let effects = drain(&mut core);
    let req = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, .. } => Some(*req),
        _ => None,
      })
      .expect("the armed root cold-enumerates");
    if feed_boot {
      core.on_enumerated(
        req,
        RawEnumerate::Listed {
          entries: Vec::new(),
          complete: true,
        },
      );
      let _ = drain(&mut core);
    }
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(&mut core);
    (core, scope, root_watch, req)
  }

  #[test]
  fn the_commit_splices_the_world_without_domination() {
    let (mut core, scope, root_watch, _boot) = live_at("/r/sub", 1, true);

    // Pre-widen: a delivery under the old root pins the epoch.
    core.on_batch(
      scope,
      BatchPayload::detached(vec![SourceEvent::Linux(inotify(
        &[root_watch],
        IN_CREATE,
        b"pre.txt",
      ))]),
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      !emits(&effects).is_empty(),
      "pre feed produced: {effects:?}"
    );
    let pre = emits(&effects)[0].clone();
    assert!(pre.kind().is_created());

    let reserved = widen(&mut core, scope, meta("/r", 9), at(2));
    core.on_watch_installed(
      reserved,
      core.arm_attempt(reserved),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().all(|c| !c.kind().is_rescan()),
      "the widen emits no covering Rescan: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::Enumerate { .. })),
      "the widened root cold-reads: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::RefreshMounts { scope: s, .. } if *s == scope)),
      "the new world re-arms its mount refresh: {effects:?}"
    );

    // Post-widen: the SAME watch delivers, re-rooted and chain-prefixed at the
    // same absolute path, on the SAME epoch — continuity, not domination.
    core.on_batch(
      scope,
      BatchPayload::detached(vec![SourceEvent::Linux(inotify(
        &[root_watch],
        IN_CREATE,
        b"post.txt",
      ))]),
      at(3),
    );
    let effects = drain(&mut core);
    let delivered = effects
      .iter()
      .find_map(|e| match e {
        Effect::Emit { root, change, .. } => Some((root.clone(), change.clone())),
        _ => None,
      })
      .expect("the old subtree keeps delivering");
    assert_eq!(delivered.0.as_path(), Path::new("/r"));
    assert_eq!(delivered.1.location(), &loc(&["sub", "post.txt"]));
    assert_eq!(delivered.1.epoch(), pre.epoch(), "no generation bump");
  }

  #[test]
  fn a_deep_widen_arms_the_connecting_chain() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/a/b", 1, true);

    let reserved = widen(&mut core, scope, meta("/r", 9), at(1));
    let effects = drain(&mut core);
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { parent, path, .. }
          if *parent == reserved && path.as_path() == Path::new("/r/a")
      )),
      "the connector arms under the new root at its absolute path: {effects:?}"
    );
    let _ = scope;
  }

  #[test]
  fn an_outstanding_old_world_read_survives_the_commit() {
    let (mut core, scope, root_watch, boot) = live_at("/r/sub", 1, false);
    // The birth cold read of /r/sub is still in flight.
    let _reserved = widen(&mut core, scope, meta("/r", 9), at(1));
    let _ = drain(&mut core);

    // It resolves AFTER the commit and reconciles under the adopted node —
    // addressed through the chain, with the discovered child armed.
    core.on_enumerated(
      boot,
      RawEnumerate::Listed {
        entries: vec![RawDirEntry {
          name: b"kid".to_vec(),
          kind: FileKind::Dir,
          dev: 1,
          ino: 5,
          mnt_id: None,
        }],
        complete: true,
      },
    );
    let effects = drain(&mut core);
    // The outstanding read is the REGISTRATION's own, so its reconciliation is
    // proven by the coverage it installs rather than by a `Created` it may not
    // emit (42-10): a registration reports no inventory. The widen's OWN
    // post-commit read is untouched by that and keeps its `Created`s — the cells
    // that pin them are unchanged.
    assert!(
      !emits(&effects).iter().any(|c| c.kind().is_created()),
      "the registration's own read announces no inventory: {effects:?}"
    );
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { path, .. } if path.as_path() == Path::new("/r/sub/kid")
      )),
      "the late read reconciles through the adopted chain — the discovered child \
       arms at its absolute path: {effects:?}"
    );
    let _ = root_watch;
  }

  /// A lag-parked Rescan crossing the commit is the WIDENED scope's drop
  /// license (INV-PARK): post-commit the lag keeps dropping scope-wide —
  /// added ground and its cold-read discoveries included — so the parked
  /// instruction re-parks at the NEW root, never merely re-based under the
  /// adopted prefix. Fails on old: the prefix-joined location covered only
  /// the old subtree while licensing widened-scope drops.
  #[test]
  fn a_lag_parked_rescan_widens_to_the_new_root_at_the_commit() {
    let (mut core, scope, root_watch, _boot) = live_at("/r/sub", 1, true);

    // Refuse a delivery: the scope goes lagged and parks a dominating Rescan
    // minted against the OLD world (root-located: empty location).
    core.on_batch(
      scope,
      BatchPayload::detached(vec![SourceEvent::Linux(inotify(
        &[root_watch],
        IN_CREATE,
        b"x.txt",
      ))]),
      at(1),
    );
    let _ = drain(&mut core);
    core.on_delivery(scope, Delivery::Refused, at(1));
    // The lag's dominating Rescan offers once (minted against the OLD world,
    // root-located) — refuse it too, so it parks across the widen.
    let offered = drain(&mut core);
    assert!(
      offered
        .iter()
        .any(|e| matches!(e, Effect::Emit { change, .. } if change.kind().is_rescan())),
      "{offered:?}"
    );
    core.on_delivery(scope, Delivery::Refused, at(2));
    let _ = drain(&mut core);

    let _reserved = widen(&mut core, scope, meta("/r", 9), at(3));
    let _ = drain(&mut core);

    // The retry offers the parked Rescan under the NEW root — re-parked at
    // the widened root itself, so it covers the old world it was minted for
    // AND the added ground whose changes the standing lag keeps dropping.
    core.on_timeout(at(10_000));
    let effects = drain(&mut core);
    let offered = effects
      .iter()
      .find_map(|e| match e {
        Effect::Emit { root, change, .. } if change.kind().is_rescan() => {
          Some((root.clone(), change.clone()))
        }
        _ => None,
      })
      .unwrap_or_else(|| panic!("the parked Rescan re-offers: {effects:?}"));
    assert_eq!(offered.0.as_path(), Path::new("/r"));
    assert!(
      offered.1.location().is_empty(),
      "the parked license covers the widened root, not the adopted prefix: {:?}",
      offered.1
    );
  }

  #[test]
  fn a_refused_widen_reports_and_mutates_nothing() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let reserved = core.reserve_watch_id();
    // No such scope: the refusal is REPORTED (never a silent unit return), so
    // the driver's commit can translate it into the loud stream-replace
    // fallback instead of replying Ok over a registry/core divergence.
    assert_eq!(
      core.on_root_widened(
        ScopeId::new(core::num::NonZeroU64::new(77).unwrap()),
        meta("/r", 9),
        reserved,
        at(1),
      ),
      WidenCommit::Refused
    );
  }

  #[test]
  fn the_cover_claim_survives_the_widen() {
    let (mut core, scope, _root_watch, boot) = live_at("/r/sub", 1, false);
    // Two armed children under the old root.
    core.on_enumerated(
      boot,
      RawEnumerate::Listed {
        entries: vec![
          RawDirEntry {
            name: b"keep".to_vec(),
            kind: FileKind::Dir,
            dev: 1,
            ino: 21,
            mnt_id: None,
          },
          RawDirEntry {
            name: b"a".to_vec(),
            kind: FileKind::Dir,
            dev: 1,
            ino: 22,
            mnt_id: None,
          },
        ],
        complete: true,
      },
    );
    let effects = drain(&mut core);
    for child in ["/r/sub/keep", "/r/sub/a"] {
      let watch = effects
        .iter()
        .find_map(|e| match e {
          Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new(child) => {
            Some(*watch)
          }
          _ => None,
        })
        .unwrap_or_else(|| panic!("{child} arms: {effects:?}"));
      core.on_watch_installed(
        watch,
        core.arm_attempt(watch),
        crate::os::linux::WatchOutcome::Installed(9),
      );
    }
    let reads: Vec<ReqId> = drain(&mut core)
      .iter()
      .filter_map(|e| match e {
        Effect::Enumerate { req, .. } => Some(*req),
        _ => None,
      })
      .collect();
    for req in reads {
      core.on_enumerated(
        req,
        RawEnumerate::Listed {
          entries: Vec::new(),
          complete: true,
        },
      );
    }
    let _ = drain(&mut core);

    // Narrow the cover: `a` is pruned and the claim records `[keep]`.
    assert!(matches!(
      core.on_set_cover(scope, &[PathBuf::from("/r/sub/keep")]),
      CoverReconcile::Reconciling
    ));
    let effects = drain(&mut core);
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::RemoveWatch { .. })),
      "the narrowed cover prunes the outside subtree: {effects:?}"
    );

    // The widen: the claim must ride across UNCHANGED (ratified (c)). A
    // D1-style reset to `None` would claim full coverage over the pruned
    // ground, and the re-cover below would compute an EMPTY broadening delta
    // — leaving the hole dark behind a clean claim.
    let reserved = widen(&mut core, scope, meta("/r", 9), at(2));
    core.on_watch_installed(
      reserved,
      core.arm_attempt(reserved),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let _ = drain(&mut core);

    // Re-covering the pruned ground computes a REAL delta against the
    // preserved claim: the grow re-arms it — the observable of preservation.
    assert!(matches!(
      core.on_set_cover(
        scope,
        &[PathBuf::from("/r/sub/keep"), PathBuf::from("/r/sub/a")]
      ),
      CoverReconcile::Reconciling
    ));
    let effects = drain(&mut core);
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::Enumerate { .. })),
      "the preserved claim re-arms the previously pruned ground: {effects:?}"
    );
  }

  /// The barrier gate ≡ [`Monitor::coverage_settled`] — the deleted
  /// `root_verified` conjunct cannot silently return. A CLEAN witnessed
  /// window's commit (INV-ROOT) already proved the reserved binding live, so
  /// once the Monitor's conjuncts clear (adoption verified, cold reads done)
  /// a fence resolves `Applied` WITHOUT any mount refresh — the happy path no
  /// longer serializes certification behind a refresh round-trip.
  #[test]
  fn barrier_is_coverage_settled() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);
    let reserved = widen(&mut core, scope, meta("/r", 1), at(2));
    core.on_watch_installed(
      reserved,
      core.arm_attempt(reserved),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let effects = drain(&mut core);
    let req = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, .. } => Some(*req),
        _ => None,
      })
      .expect("the widened root cold-reads");

    // Mid-window (the Monitor's own conjuncts still pending): the fence holds
    // on coverage_settled alone — the two predicates agree.
    let fence = core.open_cover_fence(scope);
    assert_eq!(
      core.barrier_settled(scope),
      core.monitor.coverage_settled(scope),
      "the barrier gate is exactly the Monitor's predicate"
    );
    assert!(
      core.poll_cover_settlements(DRAINED).is_empty(),
      "the unresolved adoption holds the fence"
    );

    // Positive adoption verification: every Monitor conjunct clears — and the
    // fence resolves Applied with NO refresh ever fed.
    core.on_enumerated(
      req,
      RawEnumerate::Listed {
        entries: vec![RawDirEntry {
          name: b"sub".to_vec(),
          kind: FileKind::Dir,
          dev: 1,
          ino: 1,
          mnt_id: None,
        }],
        complete: true,
      },
    );
    let _ = drain(&mut core);
    assert_eq!(
      core.barrier_settled(scope),
      core.monitor.coverage_settled(scope),
      "the settled side agrees too — no hidden conjunct"
    );
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    let settled = core.poll_cover_settlements(DRAINED);
    assert_eq!(
      settled,
      vec![(fence, CoverSettle::Applied)],
      "a clean widen window certifies without the refresh"
    );
  }

  /// The refresh death gate SURVIVES as the steady-state negative belt (its
  /// positive is never consulted — INV-ROOT owns the widen window): a
  /// POST-COMMIT refresh finding a different object at the widened path runs
  /// the death funnel — terminal Rescan, stream teardown — and an unresolved
  /// fence degrades with it, never certifying over the divergence.
  #[test]
  fn a_stale_root_binding_dies_before_the_barrier_clears() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);
    let reserved = widen(&mut core, scope, meta("/r", 1), at(2));
    core.on_watch_installed(
      reserved,
      core.arm_attempt(reserved),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let effects = drain(&mut core);
    let req = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, .. } => Some(*req),
        _ => None,
      })
      .expect("the widened root cold-reads");
    core.on_enumerated(
      req,
      RawEnumerate::Listed {
        entries: vec![RawDirEntry {
          name: b"sub".to_vec(),
          kind: FileKind::Dir,
          dev: 1,
          ino: 1,
          mnt_id: None,
        }],
        complete: true,
      },
    );
    let _ = drain(&mut core);
    let fence = core.open_cover_fence(scope);

    // The refresh finds a DIFFERENT object at the widened path — a
    // post-commit divergence whose own records have not drained (the standing
    // in-band funnel would otherwise have run already). The death funnel runs
    // — terminal Rescan, stream teardown — and the unresolved fence degrades:
    // the barrier never certifies over the divergence.
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        mounts: Vec::new(),
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 99)),
        root_mnt_id: None,
      },
      at(3),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the death funnel's terminal Rescan: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the stale-bound stream tears down: {effects:?}"
    );
    let settled = core.poll_cover_settlements(DRAINED);
    assert_eq!(
      settled,
      vec![(fence, CoverSettle::Dead)],
      "the root died under the fence, so the barrier resolves Dead — never \
       Delivered over the gap, and never a bare Degraded that would leave a \
       parked consumer to re-derive the death from maps that still read live"
    );
  }

  // ───────────────────────── the witnessed window (INV-ROOT) ─────────────────────────
  //
  // One deterministic cell per failure-table row of
  // docs/2026-07-19-d2-golden-root-binding.md: the reserved root's records
  // are intercepted at the compile latch (never dropped at the Monitor's
  // unknown-watch guard), every scope loss taints, and the commit gates on
  // the clean window — so no barrier can certify over a binding whose window
  // was not provably clean, with the statx identity never consulted.

  const IN_DELETE_SELF: u32 = 0x0000_0400;
  const IN_MOVE_SELF: u32 = 0x0000_0800;
  const IN_UNMOUNT: u32 = 0x0000_2000;
  const IN_IGNORED: u32 = 0x0000_8000;

  /// A nameless self-event record attributed to `anchor`.
  fn self_event(anchor: WatchId, mask: u32) -> RawLinuxEvent {
    RawLinuxEvent::Inotify {
      anchors: vec![anchor],
      event: RawInotifyEvent {
        wd: 2,
        mask: InotifyMask(mask),
        cookie: 0,
        name: None,
      },
    }
  }

  /// Opens a witnessed window on a live scope — the driver's reservation
  /// step, without committing.
  fn open_window(core: &mut DriverCore, scope: ScopeId) -> WatchId {
    let reserved = core.reserve_watch_id();
    core.begin_widen_watch(scope, reserved);
    reserved
  }

  /// W1 — the row that killed statx: the filesystem under the widened root is
  /// unmounted and remounted with the SAME identity inside the window. The
  /// reserved watch's `IN_UNMOUNT`/`IN_IGNORED` land at the compile latch
  /// (they would have been dropped at the unknown-watch guard), a fresh
  /// identity-MATCHING refresh changes nothing — path identity does not prove
  /// the watch installed — and the commit refuses into the fallback with the
  /// old world untouched.
  #[test]
  fn widen_window_unmount_rebind_refuses() {
    let (mut core, scope, root_watch, _boot) = live_at("/r/sub", 1, true);
    let reserved = open_window(&mut core, scope);

    // The unmount burst on the reserved wd: IN_UNMOUNT then the final
    // IN_IGNORED, both lowered to the death latch.
    core.on_inotify_events(
      scope,
      vec![
        self_event(reserved, IN_UNMOUNT),
        self_event(reserved, IN_IGNORED),
      ],
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty(),
      "a window record is consumed, never delivered: {effects:?}"
    );

    // The remounted fs re-stats to the SAME identity — the exact sample the
    // retired root_verified instrument would have certified on. It must not
    // matter: the death was witnessed in-band.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let _ = drain(&mut core);

    assert_eq!(
      core.on_root_widened(scope, meta("/r", 1), reserved, at(3)),
      WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::RootDeath(RecordKind::Ignored),
        benign: 0,
      }),
      "a matching identity never overrides the witnessed death"
    );

    // The refusal left the old world bit-identical and live: the old root
    // still delivers on its unchanged watch.
    assert_eq!(
      core.root_path(scope).expect("scope lives").as_path(),
      Path::new("/r/sub"),
      "no splice landed"
    );
    core.on_batch(
      scope,
      BatchPayload::detached(vec![SourceEvent::Linux(inotify(
        &[root_watch],
        IN_CREATE,
        b"after.txt",
      ))]),
      at(4),
    );
    let effects = drain(&mut core);
    let change = emits(&effects)
      .first()
      .cloned()
      .cloned()
      .expect("the old coverage never blinked");
    assert!(change.kind().is_created());
    assert_eq!(change.location(), &loc(&["after.txt"]));
  }

  /// W2 — the R2 counterexample at its root: the reserved root is swapped
  /// away inside the window. Its `IN_MOVE_SELF` taints and the commit refuses
  /// at once — no refresh round-trip, no held fences.
  #[test]
  fn widen_window_moveself_refuses() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);
    let reserved = open_window(&mut core, scope);
    core.on_inotify_events(scope, vec![self_event(reserved, IN_MOVE_SELF)], at(1));
    let _ = drain(&mut core);
    assert_eq!(
      core.on_root_widened(scope, meta("/r", 1), reserved, at(2)),
      WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::RootDeath(RecordKind::MoveSelf),
        benign: 0,
      })
    );
  }

  /// W3 — the rename ABA: the reserved root moves away and back (same inode,
  /// watch alive, statx matches — every sampling verifier passes it). The
  /// witnessed window restores root-move strictness: both `MOVE_SELF`s taint,
  /// the first cause wins, and the commit refuses.
  #[test]
  fn widen_window_aba_moveself_refuses() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);
    let reserved = open_window(&mut core, scope);
    core.on_inotify_events(
      scope,
      vec![
        self_event(reserved, IN_MOVE_SELF),
        self_event(reserved, IN_MOVE_SELF),
      ],
      at(1),
    );
    let _ = drain(&mut core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let _ = drain(&mut core);
    assert_eq!(
      core.on_root_widened(scope, meta("/r", 1), reserved, at(3)),
      WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::RootDeath(RecordKind::MoveSelf),
        benign: 0,
      }),
      "an ABA'd root refuses even though the object is back at the path"
    );
  }

  /// W4 — delete + inode-recycle: the reserved root is removed and a new
  /// object with a COLLIDING `(dev, ino)` appears at the path. Identity
  /// sampling is constitutionally blind to the reuse; the witnessed
  /// `DELETE_SELF` is not.
  #[test]
  fn widen_window_deleteself_refuses() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);
    let reserved = open_window(&mut core, scope);
    core.on_inotify_events(
      scope,
      vec![
        self_event(reserved, IN_DELETE_SELF),
        self_event(reserved, IN_IGNORED),
      ],
      at(1),
    );
    let _ = drain(&mut core);
    // The recycled inode re-stats to the same identity as the dead object.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let _ = drain(&mut core);
    assert_eq!(
      core.on_root_widened(scope, meta("/r", 1), reserved, at(3)),
      WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::RootDeath(RecordKind::DeleteSelf),
        benign: 0,
      }),
      "the FIRST death record is the recorded cause, not the trailing Ignored"
    );
  }

  /// W5 — a loss signal inside the window, with NO reserved record at all:
  /// the loss may have carried the death records themselves, so the window
  /// can no longer witness their absence. Coarse by design — any scope loss
  /// taints — and the follow-up refresh's matching identity again changes
  /// nothing.
  #[test]
  fn widen_window_overflow_taints() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);
    let reserved = open_window(&mut core, scope);
    core.on_root_overflow(scope, at(1));
    let _ = drain(&mut core);
    // The loss-armed refresh completes alive-and-matching — the R3-2 shape.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let _ = drain(&mut core);
    assert_eq!(
      core.on_root_widened(scope, meta("/r", 1), reserved, at(3)),
      WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::Loss,
        benign: 0,
      }),
      "an unattributable loss taints the whole window"
    );
  }

  /// W9 — benign new-ground churn commits: non-death records on the reserved
  /// wd are consumed by the latch (counted, never delivered, never fed to the
  /// Monitor) and the clean window commits; the post-commit cold read owns
  /// the convergence. A death record AFTER the benign run still refuses, and
  /// the taint carries the benign count — the fallback's diagnostics.
  #[test]
  fn widen_window_benign_churn_commits() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);
    let reserved = open_window(&mut core, scope);
    core.on_inotify_events(
      scope,
      vec![
        inotify(&[reserved], IN_CREATE, b"fresh.txt"),
        inotify(&[reserved], IN_CREATE, b"other"),
      ],
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty(),
      "window churn is consumed, never delivered: {effects:?}"
    );
    assert!(
      matches!(
        core.on_root_widened(scope, meta("/r", 1), reserved, at(2)),
        WidenCommit::Committed(_)
      ),
      "benign churn never taints"
    );
    // The replayed arm's cold read converges the new ground as Created.
    core.on_watch_installed(
      reserved,
      core.arm_attempt(reserved),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let effects = drain(&mut core);
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::Enumerate { .. })),
      "the widened root cold-reads the churned ground: {effects:?}"
    );

    // The diagnostics leg: benign records preceding a death are counted on
    // the taint the fallback carries.
    let (mut core, scope, _root_watch, _boot) = live_at("/q/sub", 1, true);
    let reserved = open_window(&mut core, scope);
    core.on_inotify_events(
      scope,
      vec![
        inotify(&[reserved], IN_CREATE, b"a"),
        inotify(&[reserved], IN_CREATE, b"b"),
        self_event(reserved, IN_IGNORED),
      ],
      at(1),
    );
    let _ = drain(&mut core);
    assert_eq!(
      core.on_root_widened(scope, meta("/q", 1), reserved, at(2)),
      WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::RootDeath(RecordKind::Ignored),
        benign: 2,
      })
    );
  }

  /// W10/W11 (post-commit regime) — the commit is a regime boundary, not a
  /// flush: a death record drained AFTER a clean commit lands on the
  /// now-KNOWN root and runs the ordinary invalidation funnel — terminal
  /// Rescan, stream teardown — never silence.
  #[test]
  fn widen_death_after_commit_invalidates() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);
    let reserved = widen(&mut core, scope, meta("/r", 1), at(1));
    core.on_watch_installed(
      reserved,
      core.arm_attempt(reserved),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let _ = drain(&mut core);

    // The same record that TAINTS pre-commit INVALIDATES post-commit.
    core.on_inotify_events(scope, vec![self_event(reserved, IN_IGNORED)], at(2));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the known-root death funnel's terminal Rescan: {effects:?}"
    );
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the widened stream tears down honestly: {effects:?}"
    );
  }

  /// The window lifecycle: abort clears (a fresh begin follows without
  /// tripping the single-flight assert), a tainted commit consumes, the
  /// fallback replace commit clears a leftover window, and unknown scopes
  /// are no-ops — no path leaks an entry into a later widen's reservation.
  #[test]
  fn widen_begin_abort_lifecycle() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);

    // abort → a fresh begin is legal (the failed-pre-arm unwind).
    let _first = open_window(&mut core, scope);
    core.abort_widen_watch(scope);
    let second = open_window(&mut core, scope);

    // A tainted commit CONSUMES the window — the next begin is legal too.
    core.on_root_overflow(scope, at(1));
    let _ = drain(&mut core);
    assert!(matches!(
      core.on_root_widened(scope, meta("/r", 1), second, at(2)),
      WidenCommit::TaintedWindow(_)
    ));
    let _third = open_window(&mut core, scope);

    // The fallback replace commit clears a leftover window outright.
    core.on_root_replaced(scope, meta("/w", 7), at(3));
    let _ = drain(&mut core);
    let _fourth = open_window(&mut core, scope);
    core.abort_widen_watch(scope);

    // Unknown scopes: both entry points are silent no-ops.
    let ghost = ScopeId::new(core::num::NonZeroU64::new(4_040).unwrap());
    core.begin_widen_watch(
      ghost,
      WatchId::new(core::num::NonZeroU64::new(9_990).unwrap()),
    );
    core.abort_widen_watch(ghost);
  }
}

mod exclusions {
  //! The common-layer exclusion fence: the enforcement every backend that has
  //! no admission-time decision of its own runs on.
  //!
  //! A cell whose claim is that ground was never ARMED asserts on COVERAGE —
  //! `covered_paths()`, the arms the core holds or is trying to hold — and not
  //! only on what happened to be delivered. A delivery-only assertion cannot tell
  //! a directory that was never armed from one that was armed and simply had
  //! nothing to report yet, and "never armed" is the whole content of the option.
  //!
  //! The converse is just as load-bearing and the two are not interchangeable: a
  //! cell whose claim is that nothing EMERGED from an exclusion asserts on
  //! delivery, because a leak can happen over coverage that is legitimately still
  //! held at the instant the record is classified.

  use super::*;
  use crate::{
    core::{RawDirEntry, RawEnumerate},
    os::{
      linux::{
        RawInotifyEvent, RawLinuxEvent, WatchOutcome,
        fanotify::{
          AdmittedEvent,
          fid::{FAN_CREATE, FAN_ONDIR, FanMask},
        },
        inotify::decode::InotifyMask,
      },
      windows::{RawWindowsEvent, RdcwAction, RdcwEvent, RdcwName, RdcwRecord},
    },
  };

  const IN_CREATE: u32 = 0x0000_0100;
  const IN_DELETE: u32 = 0x0000_0200;
  const IN_MOVED_FROM: u32 = 0x0000_0040;
  const IN_MOVED_TO: u32 = 0x0000_0080;
  const IN_MODIFY: u32 = 0x0000_0002;
  const IN_DELETE_SELF: u32 = 0x0000_0400;
  const IN_ISDIR: u32 = 0x4000_0000;

  /// A core enforcing `paths`, exactly as the driver builds one from the
  /// watcher's options.
  fn excluding(paths: &[&str]) -> DriverCore {
    DriverCore::new(WINDOW, LIVENESS).with_exclusions(paths.iter().map(PathBuf::from).collect())
  }

  fn entry(name: &str, kind: FileKind) -> RawDirEntry {
    RawDirEntry {
      name: name.as_bytes().to_vec(),
      kind,
      dev: 1,
      ino: 10 + u64::from(name.as_bytes()[0]),
      mnt_id: None,
    }
  }

  fn listed(entries: Vec<RawDirEntry>) -> RawEnumerate {
    RawEnumerate::Listed {
      entries,
      complete: true,
    }
  }

  fn inotify(anchor: WatchId, mask: u32, cookie: u32, name: Option<&str>) -> RawLinuxEvent {
    RawLinuxEvent::Inotify {
      anchors: vec![anchor],
      event: RawInotifyEvent {
        wd: 1,
        mask: InotifyMask(mask),
        cookie,
        name: name.map(|n| n.as_bytes().to_vec()),
      },
    }
  }

  /// Registers, spawns and arms a descending root at `/r` on `core`, returning
  /// its scope, the root's cold-enumerate request and the root watch.
  fn live_descending(core: &mut DriverCore) -> (ScopeId, ReqId, WatchId) {
    let scope = core.on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify);
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
        } if path.as_path() == Path::new("/r") && watch == parent => Some(*watch),
        _ => None,
      })
      .expect("the descending root arms through the effect path");
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      WatchOutcome::Installed(1),
    );
    let req = drain(core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the armed root cold-enumerates");
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(core);
    (scope, req, root_watch)
  }

  /// A live RDCW (kernel-recursive) scope at `/r` on `core`.
  fn live_rdcw(core: &mut DriverCore) -> ScopeId {
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

  fn rdcw(action: RdcwAction, components: &[&str], is_dir: bool) -> RdcwRecord {
    RdcwRecord {
      action,
      name: RdcwName::Utf8(components.iter().map(|c| (*c).to_owned()).collect()),
      file_id: None,
      parent_id: None,
      attributes: is_dir.then_some(0x10),
      reparse_tag: None,
    }
  }

  fn rdcw_payload(events: Vec<RdcwEvent>) -> BatchPayload {
    BatchPayload::detached(
      events
        .into_iter()
        .map(|event| SourceEvent::Windows(RawWindowsEvent::Rdcw(event)))
        .collect(),
    )
  }

  /// Whether any delivered change names `first` as its leading segment, on
  /// either end of a move — "did the caller hear the excluded path at all".
  fn mentions(changes: &[&Change], first: &str) -> bool {
    let heads = |location: &Location| {
      location
        .segments()
        .first()
        .is_some_and(|segment| segment.as_str() == first)
    };
    changes
      .iter()
      .any(|change| heads(change.location()) || change.kind().moved_from().is_some_and(heads))
  }

  /// The cold half of the fence: an excluded entry never leaves the listing, so
  /// the Monitor never stages it, never announces it and never arms it — while
  /// `cached` proves the rule is a SUBTREE test, not a name-prefix one.
  ///
  /// Revert witness: drop the `self.excluded(&path)` skip in `on_enumerated` and
  /// `/r/cache` joins the coverage set and the inventory.
  #[test]
  fn a_cold_listing_never_stages_an_excluded_directory() {
    let mut core = excluding(&["/r/cache"]);
    let (_scope, req, _root) = live_descending(&mut core);
    core.on_enumerated(
      req,
      listed(vec![
        entry("cache", FileKind::Dir),
        entry("cached", FileKind::Dir),
        entry("keep.txt", FileKind::File),
      ]),
    );
    let effects = drain(&mut core);

    assert_eq!(
      core.covered_paths(),
      vec![PathBuf::from("/r"), PathBuf::from("/r/cached")],
      "the excluded directory never entered coverage, and the name-prefix \
       neighbour did: {effects:?}"
    );
    let changes = emits(&effects);
    assert!(
      !mentions(&changes, "cache"),
      "nothing about the excluded directory is announced: {changes:?}"
    );
    assert!(
      changes.is_empty(),
      "a registration reports no inventory at all (42-10), excluded or not: \
       {changes:?}"
    );
    assert!(
      !changes.iter().any(|change| change.kind().is_rescan()),
      "a filtered listing is not a partial one — no covering rescan is owed, and \
       above all none naming the excluded path: {changes:?}"
    );

    // The crawl quiesces. The window closes with ONE covering `Rescan`, at the
    // scope ROOT — the exclusion fence is what keeps that signal from ever being
    // located at, or otherwise naming, the excluded path.
    let add = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path, .. } if path.as_path() == Path::new("/r/cached") => {
          Some(*watch)
        }
        _ => None,
      })
      .expect("the included directory arms");
    core.on_watch_installed(
      add,
      core.arm_attempt(add),
      crate::os::linux::WatchOutcome::Installed(2),
    );
    let read = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r/cached") => {
          Some(*req)
        }
        _ => None,
      })
      .expect("and enumerates");
    core.on_enumerated(read, listed(Vec::new()));
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      !mentions(&changes, "cache"),
      "and the closing signal names nothing excluded either: {changes:?}"
    );
    assert_eq!(changes.len(), 1, "one closing Rescan: {effects:?}");
    assert!(changes[0].kind().is_rescan());
    assert_eq!(changes[0].location(), &loc(&[]));
  }

  /// The live half, in its create shape: a directory created under an exclusion
  /// after the cold read is fenced by the same rule the listing was.
  ///
  /// Revert witness: drop the `Planned::Rec` arm of `fenced` and the create
  /// installs `/r/cache` and queues its arm.
  #[test]
  fn a_live_create_of_an_excluded_directory_never_enters_coverage() {
    let mut core = excluding(&["/r/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);

    core.on_inotify_events(
      scope,
      vec![
        inotify(root, IN_CREATE | IN_ISDIR, 0, Some("cache")),
        inotify(root, IN_CREATE | IN_ISDIR, 0, Some("cached")),
      ],
      at(1),
    );
    let effects = drain(&mut core);

    assert_eq!(
      core.covered_paths(),
      vec![PathBuf::from("/r"), PathBuf::from("/r/cached")],
      "the live create under the exclusion armed nothing: {effects:?}"
    );
    assert!(
      !effects.iter().any(|e| matches!(
        e,
        Effect::AddWatch { path, .. } if path.as_path() == Path::new("/r/cache")
      )),
      "no arm is even attempted for the excluded directory: {effects:?}"
    );
    let changes = emits(&effects);
    assert!(
      !mentions(&changes, "cache"),
      "and nothing about it is delivered: {changes:?}"
    );
  }

  /// The live half, in its move-in shape — the path a create-only fence would
  /// miss. A directory RENAMED onto an excluded path arms exactly as a created
  /// one does, so it has to be fenced by the same rule.
  ///
  /// The rename's reported half still reports: `other` left the reported tree,
  /// which is a real change to it, and the caller learns so as the removal the
  /// crossing amounts to from inside.
  #[test]
  fn a_move_onto_an_excluded_path_never_enters_coverage() {
    let mut core = excluding(&["/r/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("other", FileKind::Dir)]));
    let _ = drain(&mut core);
    assert_eq!(
      core.covered_paths(),
      vec![PathBuf::from("/r"), PathBuf::from("/r/other")],
      "staging: the reported directory is covered"
    );

    core.on_inotify_events(
      scope,
      vec![
        inotify(root, IN_MOVED_FROM | IN_ISDIR, 7, Some("other")),
        inotify(root, IN_MOVED_TO | IN_ISDIR, 7, Some("cache")),
      ],
      at(1),
    );
    core.on_timeout(at(1_000));
    let effects = drain(&mut core);

    assert_eq!(
      core.covered_paths(),
      vec![PathBuf::from("/r")],
      "the moved directory left the reported tree — it is uncovered, and the \
       excluded destination never took its place: {effects:?}"
    );
    let changes = emits(&effects);
    assert!(
      !mentions(&changes, "cache"),
      "the excluded destination is never named: {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_removed() && change.location() == &loc(&["other"])),
      "the crossing is still reported, as the half inside the reported tree: {changes:?}"
    );
  }

  /// The exclusion fences the whole SUBTREE, not just its top: a directory the
  /// fence declined is never enumerated, so nothing beneath it can be
  /// discovered, armed or retained. This is the coverage-budget property — an
  /// exclusion cannot consume the coverage the rest of the tree competes for,
  /// however much churns inside it.
  ///
  /// Revert witness: with either half of the fence reverted `/r/cache` is armed,
  /// its cold read is dispatched, and the two hundred directories below it enter
  /// coverage on the back of it.
  #[test]
  fn excluded_churn_cannot_consume_the_coverage_budget() {
    let mut core = excluding(&["/r/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(
      req,
      listed(vec![
        entry("cache", FileKind::Dir),
        entry("keep", FileKind::Dir),
      ]),
    );
    let effects = drain(&mut core);
    assert!(
      !effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { path, .. } if path.as_path() == Path::new("/r/cache")
      )),
      "the excluded directory is never read, so its subtree is unreachable: {effects:?}"
    );

    // Sustained live churn on the excluded name, the shape a build cache makes.
    for round in 0..200 {
      core.on_inotify_events(
        scope,
        vec![
          inotify(root, IN_CREATE | IN_ISDIR, 0, Some("cache")),
          inotify(root, IN_MODIFY, 0, Some("cache")),
          inotify(root, IN_DELETE | IN_ISDIR, 0, Some("cache")),
        ],
        at(2 + round),
      );
    }
    let effects = drain(&mut core);

    assert_eq!(
      core.covered_paths(),
      vec![PathBuf::from("/r"), PathBuf::from("/r/keep")],
      "six hundred excluded records later the coverage set is unchanged: {effects:?}"
    );
    assert!(
      emits(&effects).is_empty(),
      "and nothing was delivered from inside the exclusion: {effects:?}"
    );
  }

  /// A suppressed directory must not turn into a rescan naming it — the defect
  /// that made the backend-local fix unavailable. The fence never refuses an arm
  /// (the one route that produces such a rescan), and it also drops a located
  /// rescan whose whole subtree is excluded, while leaving the root-wide cover
  /// standing: loss over ground the caller IS watching is never silent.
  #[test]
  fn suppression_never_produces_a_rescan_naming_the_excluded_path() {
    let mut core = excluding(&["/r/cache"]);
    let scope = live_rdcw(&mut core);

    core.on_batch(
      scope,
      rdcw_payload(vec![
        // An undecodable name under the exclusion: the lowering covers it with a
        // located rescan at its deepest decodable ancestor, which is inside.
        RdcwEvent::Single(RdcwRecord {
          action: RdcwAction::Modified,
          name: RdcwName::Escalate {
            prefix: vec!["cache".to_owned(), "deep".to_owned()],
          },
          file_id: None,
          parent_id: None,
          attributes: None,
          reparse_tag: None,
        }),
        // A verb outside the vocabulary, likewise inside.
        RdcwEvent::Single(rdcw(RdcwAction::Unknown(99), &["cache", "odd"], false)),
        // The same escalation OUTSIDE the exclusion still covers.
        RdcwEvent::Single(RdcwRecord {
          action: RdcwAction::Modified,
          name: RdcwName::Escalate {
            prefix: vec!["keep".to_owned()],
          },
          file_id: None,
          parent_id: None,
          attributes: None,
          reparse_tag: None,
        }),
      ]),
      at(1),
    );
    let effects = drain(&mut core);
    let changes = emits(&effects);

    assert!(
      !mentions(&changes, "cache"),
      "no rescan names the path the caller asked never to hear about: {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_rescan() && change.location() == &loc(&["keep"])),
      "a located rescan outside the exclusion still covers its subtree: {changes:?}"
    );

    // A scope-wide loss is never suppressed, whatever the exclusions cover.
    core.on_root_overflow(scope, at(2));
    let changes = drain(&mut core);
    let changes = emits(&changes);
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_rescan() && change.location().is_empty()),
      "the root-wide cover stands: it covers reported ground too: {changes:?}"
    );
  }

  /// An exclusion covering the watched root silences everything below it — and
  /// still may not silence the one record that says the watch is over.
  ///
  /// Revert witness: drop the `is_self_event` guard in `fenced` and the scope's
  /// death is swallowed, leaving the caller holding a handle to a dead root with
  /// nothing to tell it so.
  #[test]
  fn a_root_death_survives_an_exclusion_covering_the_root() {
    let mut core = excluding(&["/r"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("sub", FileKind::Dir)]));
    let effects = drain(&mut core);
    assert_eq!(
      core.covered_paths(),
      vec![PathBuf::from("/r")],
      "an exclusion over the root subtracts everything under it: {effects:?}"
    );

    core.on_inotify_events(scope, vec![inotify(root, IN_DELETE_SELF, 0, None)], at(1));
    let effects = drain(&mut core);
    assert!(
      effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "the root's own death is never suppressed: {effects:?}"
    );
  }

  /// The Windows kernel-recursive profile gets the same enforcement off the same
  /// rule: records are addressed by root-relative location rather than by a
  /// per-directory anchor, and one fence covers both shapes.
  #[test]
  fn a_kernel_recursive_scope_delivers_nothing_from_inside_an_exclusion() {
    let mut core = excluding(&["/r/cache"]);
    let scope = live_rdcw(&mut core);

    core.on_batch(
      scope,
      rdcw_payload(vec![
        RdcwEvent::Single(rdcw(RdcwAction::Added, &["cache", "deep", "o.tmp"], false)),
        RdcwEvent::Single(rdcw(RdcwAction::Modified, &["cache"], true)),
        RdcwEvent::Single(rdcw(RdcwAction::Added, &["cached", "kept.txt"], false)),
      ]),
      at(1),
    );
    let changes = drain(&mut core);
    let changes = emits(&changes);

    assert!(
      !mentions(&changes, "cache"),
      "the excluded subtree and its own directory are both silent: {changes:?}"
    );
    assert_eq!(
      changes.len(),
      1,
      "only the name-prefix neighbour survives — a subtree test, not a prefix \
       one: {changes:?}"
    );
    assert_eq!(changes[0].location(), &loc(&["cached", "kept.txt"]));
  }

  /// A rename crossing the boundary on a kernel-recursive scope reports the half
  /// that lies in the reported tree, and only that half: the object left, which
  /// the caller needs, without naming where it went, which the caller refused.
  #[test]
  fn a_kernel_recursive_crossing_rename_reports_its_reported_half() {
    let mut core = excluding(&["/r/cache"]);
    let scope = live_rdcw(&mut core);

    core.on_batch(
      scope,
      rdcw_payload(vec![RdcwEvent::Renamed {
        old: rdcw(RdcwAction::RenamedOld, &["keep", "f.txt"], false),
        new: rdcw(RdcwAction::RenamedNew, &["cache", "f.txt"], false),
      }]),
      at(1),
    );
    core.on_timeout(at(1_000));
    let changes = drain(&mut core);
    let changes = emits(&changes);

    assert!(
      !mentions(&changes, "cache"),
      "the excluded destination is never named: {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_removed() && change.location() == &loc(&["keep", "f.txt"])),
      "the crossing is reported as what it is from inside — a departure: {changes:?}"
    );
  }

  /// The composition with a backend that enforces exclusions ITSELF: fanotify
  /// decides at admission, where it holds the atomic rename pair, and the common
  /// fence stands down for it rather than re-deciding half a pair at a time.
  ///
  /// The witness is a record whose target is inside the exclusion arriving from
  /// the fanotify source: only the source can put one there (its own fence drops
  /// the rest), and it does so deliberately, for the crossing shapes. Delivering
  /// it is the proof the core did not double-suppress; the same record on a
  /// non-enforcing profile is dropped by the cell above.
  #[test]
  fn the_fence_stands_down_for_a_backend_that_enforces_exclusions_itself() {
    let mut core = excluding(&["/r/cache"]);
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

    core.on_batch(
      scope,
      BatchPayload::detached(vec![SourceEvent::Linux(RawLinuxEvent::Fanotify(
        AdmittedEvent {
          mask: FanMask::new(FAN_CREATE | FAN_ONDIR),
          path: Some(PathBuf::from("/r/cache/kid")),
          rename: None,
        },
      ))]),
      at(1),
    );
    let changes = drain(&mut core);
    let changes = emits(&changes);

    assert_eq!(
      changes.len(),
      1,
      "the admission fence already decided; the core does not re-decide: {changes:?}"
    );
    assert_eq!(changes[0].location(), &loc(&["cache", "kid"]));
  }

  /// The RE-ARM read after a scope loss goes through the same fence as the cold
  /// one: a loss re-proves every retained binding and re-reads every interior,
  /// so a listing that arrives on THAT path must not be the way an excluded
  /// directory finally gets in. Same entry point, same rule, both enumerate
  /// flavours — which is also the rescan-driven re-enumeration path.
  ///
  /// Revert witness: drop the `on_enumerated` skip and `/r/cache` enters coverage
  /// here even though the cold read declined it.
  #[test]
  fn a_post_loss_rearm_read_fences_the_same_entry_the_cold_read_did() {
    let mut core = excluding(&["/r/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("keep", FileKind::Dir)]));
    let _ = drain(&mut core);

    core.on_root_overflow(scope, at(2));
    let effects = drain(&mut core);
    let readd = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, attempt, .. } if *watch == root => Some(*attempt),
        _ => None,
      })
      .expect("a scope loss re-proves the root binding");
    core.on_watch_installed(root, readd, WatchOutcome::Installed(2));
    let rearm = drain(&mut core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the re-proved root re-reads its interior");
    core.on_enumerated(
      rearm,
      listed(vec![
        entry("keep", FileKind::Dir),
        entry("cache", FileKind::Dir),
      ]),
    );
    let effects = drain(&mut core);

    assert_eq!(
      core.covered_paths(),
      vec![PathBuf::from("/r"), PathBuf::from("/r/keep")],
      "the re-arm listing is fenced exactly like the cold one: {effects:?}"
    );
  }

  /// An empty exclusion set changes nothing anywhere — the fast path, and the
  /// guard that keeps every existing profile's lowering untouched.
  #[test]
  fn no_exclusions_leaves_every_lowering_untouched() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("cache", FileKind::Dir)]));
    let _ = drain(&mut core);
    core.on_inotify_events(
      scope,
      vec![inotify(root, IN_CREATE | IN_ISDIR, 0, Some("build"))],
      at(1),
    );
    let _ = drain(&mut core);
    assert_eq!(
      core.covered_paths(),
      vec![
        PathBuf::from("/r"),
        PathBuf::from("/r/build"),
        PathBuf::from("/r/cache"),
      ],
      "with no exclusions configured every directory is covered as before"
    );
  }

  /// An entry with an explicit inode, so a re-arm listing can present the SAME
  /// object under a new name — which is what makes the Monitor treat a renamed
  /// directory as a survivor to cascade into rather than a replacement to rebuild.
  fn entry_ino(name: &str, kind: FileKind, ino: u64) -> RawDirEntry {
    RawDirEntry {
      name: name.as_bytes().to_vec(),
      kind,
      dev: 1,
      ino,
      mnt_id: None,
    }
  }

  /// The inode [`entry`] mints for `name`, so a rename can restate it.
  fn ino_of(name: &str) -> u64 {
    10 + u64::from(name.as_bytes()[0])
  }

  /// Installs the queued arm for `path` and returns its watch together with the
  /// cold-enumerate request the install dispatches.
  fn arm(core: &mut DriverCore, effects: &[Effect], path: &str) -> (WatchId, ReqId) {
    let watch = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch { watch, path: p, .. } if p.as_path() == Path::new(path) => Some(*watch),
        _ => None,
      })
      .unwrap_or_else(|| panic!("{path} is armed: {effects:?}"));
    core.on_watch_installed(watch, core.arm_attempt(watch), WatchOutcome::Installed(1));
    let req = drain(core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path: p, .. } if p.as_path() == Path::new(path) => Some(*req),
        _ => None,
      })
      .unwrap_or_else(|| panic!("{path} enumerates once armed"));
    (watch, req)
  }

  /// The enumerate request outstanding for `path`, if the drain dispatched one.
  fn enumerate_of(effects: &[Effect], path: &str) -> Option<ReqId> {
    effects.iter().find_map(|e| match e {
      Effect::Enumerate { req, path: p, .. } if p.as_path() == Path::new(path) => Some(*req),
      _ => None,
    })
  }

  /// A directory rename inside the watched root, as inotify reports it: two
  /// cookied halves on the parent watch.
  fn rename_dir(root: WatchId, cookie: u32, from: &str, to: &str) -> Vec<RawLinuxEvent> {
    vec![
      inotify(root, IN_MOVED_FROM | IN_ISDIR, cookie, Some(from)),
      inotify(root, IN_MOVED_TO | IN_ISDIR, cookie, Some(to)),
    ]
  }

  /// `count` directories moved clean OUT of the watched root, numbered from
  /// `first`. Each half is reported (so the fence keeps it) and each cookie is
  /// unique, so none of them ever pairs: the Monitor parks a half per source and
  /// holds it for the whole pairing window — the residue a burst leaves behind.
  ///
  /// Cookies are numbered from `first + 1`, so a cell that needs a cookie of its
  /// own picks one outside `first..first + count`.
  fn move_outs(root: WatchId, first: usize, count: usize) -> Vec<RawLinuxEvent> {
    (first..first + count)
      .map(|i| {
        let cookie = u32::try_from(i).expect("the burst fits a cookie") + 1;
        inotify(
          root,
          IN_MOVED_FROM | IN_ISDIR,
          cookie,
          Some(&format!("gone{i}")),
        )
      })
      .collect()
  }

  /// How many unpaired rename sources the burst cells stage.
  ///
  /// Any number the geometry pass would once have refused at would do; a burst
  /// is now just a burst, so this is sized for a legible failure message rather
  /// than against a threshold. What every burst cell asserts is that the number
  /// does not matter — the classification of a later rename is the same as it
  /// would be with no burst at all.
  const BURST: usize = 32;

  /// Whether a change names ground under the `/r/a/cache` exclusion the rename
  /// cells stage — at its own location or at a move's source end, since a move
  /// out of the exclusion would report it there.
  fn names_the_exclusion(change: &&Change) -> bool {
    let inside = |location: &Location| {
      location
        .segments()
        .iter()
        .map(Segment::as_str)
        .take(2)
        .eq(["a", "cache"])
    };
    inside(change.location()) || change.kind().moved_from().is_some_and(inside)
  }

  /// A directory rename can move a subtree ACROSS the exclusion boundary without
  /// either of its own endpoints being excluded, and the record-by-record fence
  /// cannot see it: both endpoints are reported, so the pair is preserved and the
  /// Monitor answers it by re-parenting the known watch subtree in place. That
  /// carry-over is only complete while the exclusion geometry over the subtree is
  /// unchanged.
  ///
  /// Out of the exclusion: `/r/a/cache` is excluded, so the cold walk of `/r/a`
  /// armed nothing there. Renaming `/r/a` to `/r/b` makes that directory reportable
  /// at `/r/b/cache`, and a bare re-parent would leave it unwatched forever —
  /// silent, permanent loss under a path the caller is watching.
  ///
  /// Asserted on COVERAGE and then on DELIVERY: the defect is a subtree left
  /// unarmed, which a delivery-only assertion cannot distinguish from a subtree
  /// that simply had nothing to say.
  ///
  /// Revert witness: drop the `reparent_geometry` call in `fence_exclusions` and no
  /// re-enumeration of `/r` is dispatched at all, so `/r/b/cache` never enters
  /// `covered_paths` and the modification under it is delivered to no one.
  #[test]
  fn a_rename_out_of_an_exclusion_arms_the_newly_reportable_subtree() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("a", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (_a, a_req) = arm(&mut core, &effects, "/r/a");
    core.on_enumerated(
      a_req,
      listed(vec![
        entry("cache", FileKind::Dir),
        entry("keep", FileKind::Dir),
      ]),
    );
    let effects = drain(&mut core);
    assert_eq!(
      core.covered_paths(),
      vec![
        PathBuf::from("/r"),
        PathBuf::from("/r/a"),
        PathBuf::from("/r/a/keep"),
      ],
      "staging: the exclusion kept `/r/a/cache` out of coverage: {effects:?}"
    );

    // `/r/a` -> `/r/b`. Both endpoints are reported, so the fence preserves the
    // pair and the Monitor re-parents; the geometry escalation rides after it.
    core.on_inotify_events(scope, rename_dir(root, 7, "a", "b"), at(1));
    let effects = drain(&mut core);
    let root_reread =
      enumerate_of(&effects, "/r").expect("the geometry change re-enumerates from the destination");
    let changes = emits(&effects);
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_rescan() && change.location() == &loc(&["b"])),
      "the repair covers the destination it is about to re-read: {changes:?}"
    );
    assert!(
      !mentions(&changes, "a") || changes.iter().any(|change| change.kind().is_moved()),
      "the rename itself is still reported: {changes:?}"
    );

    // The re-arm read of `/r` finds the same object under its new name, so the
    // Monitor keeps the node and cascades the re-arm into it.
    core.on_enumerated(
      root_reread,
      listed(vec![entry_ino("b", FileKind::Dir, ino_of("a"))]),
    );
    let effects = drain(&mut core);
    let moved_reread = enumerate_of(&effects, "/r/b")
      .expect("the cascade re-reads the moved directory at its NEW path");

    // Lowered against `/r/b`, so `cache` no longer matches the exclusion.
    core.on_enumerated(
      moved_reread,
      listed(vec![
        entry("cache", FileKind::Dir),
        entry_ino("keep", FileKind::Dir, ino_of("keep")),
      ]),
    );
    let effects = drain(&mut core);
    assert!(
      core.covered_paths().contains(&PathBuf::from("/r/b/cache")),
      "the newly reportable directory entered coverage: {:?} / {effects:?}",
      core.covered_paths()
    );

    // Coverage is only half the claim: prove a change under it now reaches the
    // caller, which is exactly what the defect lost.
    let (cache, cache_req) = arm(&mut core, &effects, "/r/b/cache");
    core.on_enumerated(cache_req, listed(Vec::new()));
    let _ = drain(&mut core);
    core.on_inotify_events(
      scope,
      vec![inotify(cache, IN_CREATE, 0, Some("fresh.o"))],
      at(2),
    );
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      changes
        .iter()
        .any(|change| change.location() == &loc(&["b", "cache", "fresh.o"])),
      "and a change under it is delivered: {changes:?}"
    );
  }

  /// The other direction of the same geometry change, where the cost is a budget
  /// one rather than a loss one: `/r/b/cache` is covered, and renaming `/r/b` to
  /// `/r/a` moves it under the `/r/a/cache` exclusion. A bare re-parent would keep
  /// spending kernel watches — and delivering — on exactly the ground the caller
  /// excluded to shed.
  ///
  /// The repair is the same one mechanism: the re-enumeration is lowered against
  /// the destination, the excluded child never reaches the listing, and the
  /// Monitor's re-arm read prunes the name it no longer sees.
  ///
  /// Revert witness: drop the `reparent_geometry` call in `fence_exclusions` and
  /// `/r/a/cache` stays in `covered_paths` for the rest of the scope's life.
  #[test]
  fn a_rename_into_an_exclusion_sheds_the_subtree_it_no_longer_reports() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("b", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (_b, b_req) = arm(&mut core, &effects, "/r/b");
    core.on_enumerated(
      b_req,
      listed(vec![
        entry("cache", FileKind::Dir),
        entry("keep", FileKind::Dir),
      ]),
    );
    let effects = drain(&mut core);
    let (_cache, cache_req) = arm(&mut core, &effects, "/r/b/cache");
    core.on_enumerated(cache_req, listed(Vec::new()));
    let effects = drain(&mut core);
    assert!(
      core.covered_paths().contains(&PathBuf::from("/r/b/cache")),
      "staging: nothing excludes `/r/b/cache`, so it is covered: {effects:?}"
    );

    core.on_inotify_events(scope, rename_dir(root, 9, "b", "a"), at(1));
    let effects = drain(&mut core);
    let root_reread =
      enumerate_of(&effects, "/r").expect("the geometry change re-enumerates from the destination");
    core.on_enumerated(
      root_reread,
      listed(vec![entry_ino("a", FileKind::Dir, ino_of("b"))]),
    );
    let effects = drain(&mut core);
    let moved_reread = enumerate_of(&effects, "/r/a")
      .expect("the cascade re-reads the moved directory at its NEW path");

    // The listing is lowered against `/r/a`, so `cache` is now excluded and never
    // reaches the Monitor: a complete re-arm read prunes the name it cannot see.
    core.on_enumerated(
      moved_reread,
      listed(vec![
        entry("cache", FileKind::Dir),
        entry_ino("keep", FileKind::Dir, ino_of("keep")),
      ]),
    );
    let effects = drain(&mut core);

    assert!(
      !core
        .covered_paths()
        .iter()
        .any(|path| path.ends_with("cache")),
      "the now-excluded subtree stopped consuming coverage: {:?} / {effects:?}",
      core.covered_paths()
    );
    assert!(
      core.covered_paths().contains(&PathBuf::from("/r/a")),
      "while the reported directory that carried it is still covered: {:?}",
      core.covered_paths()
    );
  }

  /// The same geometry change, asserted on DELIVERY and inside ONE read: a
  /// rename into an exclusion followed — in the same buffer — by an event from a
  /// descendant watch that rode across with it.
  ///
  /// This is where classifying the whole batch before FEEDING any of it leaks.
  /// The suffix record is anchored at the descendant's OWN watch, and the core
  /// derives that watch's path from the Monitor's tree — which, until the pair
  /// ahead of it is fed, still places the descendant at `/r/b/cache`. So a fence
  /// that runs over the whole buffer first judges the record reportable and keeps
  /// it. The re-parent then lands, the record resolves at `/r/a/cache/fresh.o` —
  /// inside the exclusion — and is delivered there. The escalation riding after
  /// the pair cannot take it back: a `Rescan` covers what comes NEXT, it does not
  /// unsay a record already retained ahead of it.
  ///
  /// A coverage assertion cannot see this: coverage is legitimately still held at
  /// the moment the record is classified, and the re-arm sheds it afterwards
  /// ([`a_rename_into_an_exclusion_sheds_the_subtree_it_no_longer_reports`] is
  /// that half). The leak is a delivery, so the witness reads deliveries.
  ///
  /// Revert witness: classify the batch before feeding it — hoist the fence back
  /// into a pass of its own ahead of the hand-off — and `fresh.o` is delivered at
  /// `a/cache/fresh.o`.
  #[test]
  fn a_rename_into_an_exclusion_fences_the_rest_of_its_own_read() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("b", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (_b, b_req) = arm(&mut core, &effects, "/r/b");
    core.on_enumerated(b_req, listed(vec![entry("cache", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (cache, cache_req) = arm(&mut core, &effects, "/r/b/cache");
    core.on_enumerated(cache_req, listed(Vec::new()));
    let _ = drain(&mut core);
    assert!(
      core.covered_paths().contains(&PathBuf::from("/r/b/cache")),
      "staging: nothing excludes `/r/b/cache`, so it is covered and armed: {:?}",
      core.covered_paths()
    );

    // ONE read: the pair that moves the subtree under the exclusion, then the
    // descendant watch's own record behind it. Deterministic by construction —
    // the three records are one `on_inotify_events` call, which is one buffer.
    let mut read = rename_dir(root, 9, "b", "a");
    read.push(inotify(cache, IN_CREATE, 0, Some("fresh.o")));
    core.on_inotify_events(scope, read, at(1));
    let effects = drain(&mut core);
    let changes = emits(&effects);

    assert!(
      !changes.iter().any(names_the_exclusion),
      "the descendant record behind the rename is classified against the path the \
       rename gave it, so nothing under the exclusion is delivered: {changes:?}"
    );
    // Non-vacuity: the batch really was processed, the re-parent really landed,
    // and the repair really rode after it — the suppression above is the fence
    // deciding, not the whole read going missing.
    assert!(
      changes.iter().any(|change| change.kind().is_moved()),
      "the rename itself is still reported: {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_rescan() && change.location() == &loc(&["a"])),
      "and the geometry repair still covers the destination: {changes:?}"
    );
  }

  /// The geometry rule is asked of BOTH endpoints and of nothing else: a rename
  /// with no exclusion at or under either end leaves the O(1) re-parent alone.
  /// Without this the fix would be "re-enumerate on every directory rename in an
  /// excluded scope", which is a different and much more expensive rule.
  #[test]
  fn a_geometry_neutral_rename_still_reparents_without_a_re_read() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("x", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (_x, x_req) = arm(&mut core, &effects, "/r/x");
    core.on_enumerated(x_req, listed(vec![entry("deep", FileKind::Dir)]));
    let _ = drain(&mut core);

    core.on_inotify_events(scope, rename_dir(root, 11, "x", "y"), at(1));
    let effects = drain(&mut core);

    assert!(
      enumerate_of(&effects, "/r").is_none(),
      "no exclusion lies under either endpoint, so nothing is re-read: {effects:?}"
    );
    let changes = emits(&effects);
    assert!(
      changes.iter().any(|change| change.kind().is_moved()),
      "and the rename is reported as the move it is: {changes:?}"
    );
    assert!(
      !changes.iter().any(|change| change.kind().is_rescan()),
      "with no covering rescan standing over it: {changes:?}"
    );
  }

  /// A directory moved clean OUT of the watched root pairs with nothing — no
  /// destination half ever arrives — and that has to degrade HONESTLY: the
  /// source is a transition already consumed from the kernel, so dropping it
  /// quietly would be silent loss.
  ///
  /// Asserted as a COUNT, not an existence: one removal standing in for a burst
  /// of them is exactly the failure this is about, so an under-count must fail.
  ///
  /// The other half is what the degrade must NOT cost. A burst of unpaired
  /// sources is ordinary filesystem churn — a build tree emptied, a directory of
  /// scratch directories moved away — and it must not convert into scope-wide
  /// `Rescan`s that re-prove the whole tree. The geometry pass retains nothing of
  /// its own for such a burst to fill, so there is no bound for it to reach and
  /// no refusal for it to trip.
  #[test]
  fn an_unpaired_rename_source_degrades_to_a_removal_at_its_window() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("a", FileKind::Dir)]));
    let _ = drain(&mut core);

    core.on_inotify_events(scope, move_outs(root, 0, BURST), at(1));
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      !changes.iter().any(|change| change.kind().is_removed()),
      "staging: nothing resolves while every half is still pairable: {changes:?}"
    );
    assert!(
      !changes.iter().any(|change| change.kind().is_rescan()),
      "and the burst costs no covering rescan on the way in: {changes:?}"
    );

    // Past every parked half's pairing window.
    core.on_timeout(at(1) + WINDOW);
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert_eq!(
      changes
        .iter()
        .filter(|change| change.kind().is_removed())
        .count(),
      BURST,
      "every unpaired source resolves as the removal it turned out to be: \
       {changes:?}"
    );
    assert!(
      !changes.iter().any(|change| change.kind().is_rescan()),
      "and none of them needed covering: {changes:?}"
    );
  }

  /// Arms `/r/b/cache` under a core excluding `/r/a/cache`, so renaming `/r/b`
  /// to `/r/a` is the geometry change that carries a covered subtree UNDER the
  /// exclusion. Returns the scope, the root watch and the `cache` watch — the
  /// descendant whose own records ride behind the pair.
  fn crossing_rename_tree(core: &mut DriverCore) -> (ScopeId, WatchId, WatchId) {
    let (scope, req, root) = live_descending(core);
    core.on_enumerated(req, listed(vec![entry("b", FileKind::Dir)]));
    let effects = drain(core);
    let (_b, b_req) = arm(core, &effects, "/r/b");
    core.on_enumerated(b_req, listed(vec![entry("cache", FileKind::Dir)]));
    let effects = drain(core);
    let (cache, cache_req) = arm(core, &effects, "/r/b/cache");
    core.on_enumerated(cache_req, listed(Vec::new()));
    let _ = drain(core);
    assert!(
      core.covered_paths().contains(&PathBuf::from("/r/b/cache")),
      "staging: nothing excludes `/r/b/cache`, so it is covered and armed: {:?}",
      core.covered_paths()
    );
    (scope, root, cache)
  }

  /// What ONE read carrying the destination of the `/r/b` -> `/r/a` rename, with
  /// the descendant watch's own record behind it, must produce: the pair
  /// resolves, the re-parent lands before the record behind it is classified, the
  /// located repair lands at the destination, and no scope-wide cover stands over
  /// the read.
  ///
  /// Stated once, because the burst cells below exist to show that the answer is
  /// the SAME one this read gets with no burst at all — restating it per cell
  /// invites the three to drift into asserting three different things.
  fn assert_the_crossing_pair_is_addressed(changes: &[&Change]) {
    assert!(
      changes.iter().any(|change| change.kind().is_moved()),
      "non-vacuity: the pair really resolves in this read: {changes:?}"
    );
    assert!(
      !changes.iter().any(names_the_exclusion),
      "the destination moved the subtree before the record behind it was \
       classified, so nothing under the exclusion is delivered: {changes:?}"
    );
    assert!(
      !changes
        .iter()
        .any(|change| change.location().segments().last().map(Segment::as_str) == Some("fresh.o")),
      "the descendant record is fenced at the path the rename gave it rather \
       than delivered at the one it left: {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_rescan() && change.location() == &loc(&["a"])),
      "and the geometry repair covers the destination: {changes:?}"
    );
    assert!(
      !changes
        .iter()
        .any(|change| change.kind().is_rescan() && change.location().segments().is_empty()),
      "with no scope-wide cover standing over the read: {changes:?}"
    );
  }

  /// A burst of unpaired rename sources already parked in the scope must not
  /// change how the NEXT rename is classified.
  ///
  /// The three cells here are the same scenario under the three orderings a
  /// burst can take against the source it must not disturb, because the phase at
  /// which a source is parked is exactly what used to decide whether it survived:
  /// this one parks the burst FIRST and renames afterwards, the next parks the
  /// surviving source BEFORE the burst, and the third co-batches the two in one
  /// read.
  ///
  /// Asserted on DELIVERY, because that is where every failure surfaces: a
  /// rename the pass declines to classify loses its `Moved`, a subtree whose move
  /// the Monitor never performs delivers the record riding behind it under the
  /// excluded destination, and a pass that gives up on the read replaces both
  /// with a scope-wide cover.
  #[test]
  fn a_burst_of_parked_sources_never_disturbs_a_later_rename() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, root, cache) = crossing_rename_tree(&mut core);

    core.on_inotify_events(scope, move_outs(root, 0, BURST), at(1));
    let _ = drain(&mut core);

    // ONE read: the pair that carries the subtree under the exclusion, then the
    // descendant watch's own record behind it.
    let mut read = rename_dir(root, 900, "b", "a");
    read.push(inotify(cache, IN_CREATE, 0, Some("fresh.o")));
    core.on_inotify_events(scope, read, at(2));
    let effects = drain(&mut core);

    assert_the_crossing_pair_is_addressed(&emits(&effects));
  }

  /// The same guarantee for a source parked BEFORE the burst: its destination
  /// arrives two reads later, and the burst in between must have forgotten
  /// nothing about it.
  ///
  /// This is the ordering that used to be dangerous. A source displaced to make
  /// room for a later one loses nothing the Monitor knows — the Monitor keeps its
  /// half and pairs it regardless — so the two stores disagree about whether the
  /// destination relocated a watched subtree, and the record riding behind the
  /// destination is then judged at ground the rename has already vacated.
  #[test]
  fn a_source_parked_before_a_burst_still_pairs_and_re_anchors() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, root, cache) = crossing_rename_tree(&mut core);

    // Read one: the source half of `/r/b`, whose destination is still to come.
    core.on_inotify_events(
      scope,
      vec![inotify(root, IN_MOVED_FROM | IN_ISDIR, 900, Some("b"))],
      at(1),
    );
    let _ = drain(&mut core);

    // Read two: the burst lands behind it.
    core.on_inotify_events(scope, move_outs(root, 0, BURST), at(2));
    let _ = drain(&mut core);

    // Read three, ONE read: the destination lands `/r/b` at `/r/a`, then the
    // descendant watch's own record behind it.
    let mut read = vec![inotify(root, IN_MOVED_TO | IN_ISDIR, 900, Some("a"))];
    read.push(inotify(cache, IN_CREATE, 0, Some("fresh.o")));
    core.on_inotify_events(scope, read, at(3));
    let effects = drain(&mut core);

    assert_the_crossing_pair_is_addressed(&emits(&effects));
  }

  /// And the same guarantee when the burst is CO-BATCHED with the source it must
  /// not disturb — one read carrying both.
  ///
  /// The distinction from the cell above is the phase lag, which is why the
  /// ordering is worth its own cell rather than being folded in. Under
  /// batch-then-settle the whole read is classified before the Monitor hears any
  /// of it, so at the moment the burst is walked the surviving source has no half
  /// at the Monitor at all and anything asked about the Monitor mid-read reads a
  /// not-yet as a never-was. This profile feeds at classify time, so by the time
  /// the burst is walked the source ahead of it has physically landed.
  #[test]
  fn a_source_co_batched_with_a_burst_still_pairs_and_re_anchors() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, root, cache) = crossing_rename_tree(&mut core);
    assert_eq!(
      core.monitor.poll_timeout(),
      None,
      "staging: the Monitor holds no pending half before this read"
    );

    // ONE read: the source half of `/r/b` and the whole burst behind it.
    let mut read = vec![inotify(root, IN_MOVED_FROM | IN_ISDIR, 900, Some("b"))];
    read.extend(move_outs(root, 0, BURST));
    core.on_inotify_events(scope, read, at(1));
    let _ = drain(&mut core);

    // ONE read: the destination, then the descendant watch's own record.
    let mut read = vec![inotify(root, IN_MOVED_TO | IN_ISDIR, 900, Some("a"))];
    read.push(inotify(cache, IN_CREATE, 0, Some("fresh.o")));
    core.on_inotify_events(scope, read, at(2));
    let effects = drain(&mut core);

    assert_the_crossing_pair_is_addressed(&emits(&effects));
  }

  /// A kernel move cookie is a small recycled integer, so one cookie can name a
  /// SECOND rename while the first is still parked — and the destination that
  /// eventually arrives must move the subtree that really moved.
  ///
  /// The Monitor resolves this by displacement: a same-key half replaces the one
  /// it finds and the displaced half resolves on its own (it can no longer pair,
  /// so it degrades to the removal it turned out to be). Whatever the geometry
  /// pass believes about which source a cookie names must agree with that,
  /// exactly, or the destination pairs at the Monitor against one rename while
  /// this pass judges the other — repairing an exclusion crossing that did not
  /// happen and missing the one that did. There is no second belief to keep in
  /// step: the source end IS the Monitor's own report of the reparent it
  /// performed, and the addressing IS the tree that reparent rewrote.
  ///
  /// Asserted on DELIVERY at both ends — the reported move names the replacement
  /// as its source, and the descendant of the subtree that really moved is fenced
  /// at its new home.
  #[test]
  fn a_reused_cookie_addresses_the_subtree_that_really_moved() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(
      req,
      listed(vec![entry("b", FileKind::Dir), entry("x", FileKind::Dir)]),
    );
    let effects = drain(&mut core);
    let (_b, b_req) = arm(&mut core, &effects, "/r/b");
    core.on_enumerated(b_req, listed(Vec::new()));
    let _ = drain(&mut core);
    let (_x, x_req) = arm(&mut core, &effects, "/r/x");
    core.on_enumerated(x_req, listed(vec![entry("cache", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (cache, cache_req) = arm(&mut core, &effects, "/r/x/cache");
    core.on_enumerated(cache_req, listed(Vec::new()));
    let _ = drain(&mut core);
    assert!(
      core.covered_paths().contains(&PathBuf::from("/r/x/cache")),
      "staging: nothing excludes `/r/x/cache`, so it is covered and armed: {:?}",
      core.covered_paths()
    );

    // Read one: cookie 900 names a rename of `/r/b`, whose destination never
    // arrives.
    core.on_inotify_events(
      scope,
      vec![inotify(root, IN_MOVED_FROM | IN_ISDIR, 900, Some("b"))],
      at(1),
    );
    let _ = drain(&mut core);

    // Read two: the kernel reuses cookie 900 for a rename of `/r/x`.
    core.on_inotify_events(
      scope,
      vec![inotify(root, IN_MOVED_FROM | IN_ISDIR, 900, Some("x"))],
      at(2),
    );
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_removed() && change.location() == &loc(&["b"])),
      "staging: the reuse displaced `/r/b`'s half, which resolves as the removal \
       it turned out to be: {changes:?}"
    );

    // Read three: the destination lands `/r/x` at `/r/a`, which puts `cache`
    // under the exclusion — then the descendant watch's own record behind it, in
    // the SAME read.
    let mut read = vec![inotify(root, IN_MOVED_TO | IN_ISDIR, 900, Some("a"))];
    read.push(inotify(cache, IN_CREATE, 0, Some("fresh.o")));
    core.on_inotify_events(scope, read, at(3));
    let effects = drain(&mut core);
    let changes = emits(&effects);

    assert!(
      changes
        .iter()
        .any(|change| change.kind().moved_from() == Some(&loc(&["x"]))
          && change.location() == &loc(&["a"])),
      "the destination pairs with the REPLACEMENT, so the reported move names \
       `x` as its source rather than the `b` it displaced: {changes:?}"
    );
    assert!(
      !changes.iter().any(names_the_exclusion),
      "and nothing under the exclusion is delivered: {changes:?}"
    );
    assert!(
      !changes
        .iter()
        .any(|change| change.location().segments().last().map(Segment::as_str) == Some("fresh.o")),
      "the subtree that really moved is the one that moved, so its descendant \
       record is fenced rather than delivered at the path it left: {changes:?}"
    );
  }

  /// The [`RootMeta`] a stream REPLACE commits over `/r` — the same canonical
  /// root and the same object, which is what a transport respawn under a live
  /// path looks like from here (the identity is the one [`alive_refresh`]
  /// vouches for, so the commit is a replace and not a disguised root death).
  fn replaced_meta() -> RootMeta {
    RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
      mounts: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::Inotify,
    }
  }

  /// Replays the pre-armed root binding a descending replace commits against and
  /// answers the re-arm-flavored rebuild read, so the scope is live in the new
  /// world rather than parked mid-rebind.
  fn finish_replace(core: &mut DriverCore, scope: ScopeId, root: WatchId, kids: Vec<RawDirEntry>) {
    core.on_watch_installed(root, core.arm_attempt(root), WatchOutcome::Installed(9));
    let _ = drain(core);
    core.on_watch_installed(root, core.arm_attempt(root), WatchOutcome::Aliased(9));
    let effects = drain(core);
    let rebuild = enumerate_of(&effects, "/r").expect("the rebound root re-reads its world");
    core.on_enumerated(rebuild, listed(kids));
    let _ = drain(core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(3));
    let _ = drain(core);
  }

  /// Parks a burst of unpaired rename sources on `/r` — every cookie unique, so
  /// none of them ever pairs and the Monitor holds every half for the whole
  /// pairing window.
  fn park_a_burst(core: &mut DriverCore, scope: ScopeId, root: WatchId, now: Instant) {
    core.on_inotify_events(scope, move_outs(root, 0, BURST), now);
    let _ = drain(core);
    assert_eq!(
      core.monitor.poll_timeout(),
      Some(now + WINDOW),
      "staging: the burst's halves are parked and waiting on their window"
    );
  }

  /// A root replacement committed while rename halves are parked must leave the
  /// scope classifying LATER renames exactly as it would have classified them
  /// with nothing parked at all.
  ///
  /// The rebind the commit performs purges the Monitor's own pending halves for
  /// the scope ([`Monitor::rebind_root`]), so from that instant no destination
  /// can pair anywhere. That cut is only safe if nothing else in the scope was
  /// holding rename state of its own with a lifetime the purge does not reach:
  /// such state would be orphaned at the commit, alive until a deadline the purge
  /// has just taken off the Monitor's timer, and shaping the classification of
  /// every rename until something happened to arm a timer and drain it.
  ///
  /// So: park a burst, replace the root BEFORE the pairing window elapses,
  /// advance long past that window with NO timer of any kind fired, and require
  /// the next directory rename to be classified healthily — reported as the move
  /// it is, with its located repair, and no scope-wide cover standing over it.
  ///
  /// The scheduler assertion after the commit is the mechanism half: the purge is
  /// what leaves the core with no work due, and a core that still reported work
  /// due here would be holding rename state the replace did not reach.
  ///
  /// Deterministic by construction: the burst is one `on_inotify_events` call,
  /// which is one read, and the rename is another.
  #[test]
  fn a_replace_with_parked_halves_still_classifies_later_renames() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("b", FileKind::Dir)]));
    let _ = drain(&mut core);

    park_a_burst(&mut core, scope, root, at(1));

    // The commit, inside the pairing window: the halves the burst parked die
    // here.
    core.on_root_replaced(scope, replaced_meta(), at(2));
    let _ = drain(&mut core);
    finish_replace(&mut core, scope, root, vec![entry("b", FileKind::Dir)]);
    assert_eq!(
      core.poll_timeout(),
      None,
      "the cut took every parked half with it, so nothing is left needing a \
       timer — which is exactly why none fires"
    );

    // Long past the pairing window, with `on_timeout` never driven: the scope
    // renames a directory into the exclusion's parent, the shape that owes a
    // located repair.
    core.on_inotify_events(scope, rename_dir(root, 900, "b", "a"), at(1_000));
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      changes.iter().any(|change| change.kind().is_moved()),
      "the rename is classified and reported: {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_rescan() && change.location() == &loc(&["a"])),
      "with its located geometry repair: {changes:?}"
    );
    assert!(
      !changes
        .iter()
        .any(|change| change.kind().is_rescan() && change.location().segments().is_empty()),
      "and no scope-wide cover standing over it: {changes:?}"
    );
  }

  /// The other half of the same cut, at the pairing itself: a source the replace
  /// orphaned is keyed by a KERNEL cookie, and cookies wrap — so a destination in
  /// the NEW world can carry a cookie the retired world minted, and must pair with
  /// nothing.
  ///
  /// Held far below any burst on purpose: one parked half, so the property is the
  /// cut's own and not a side effect of anything the volume of parked state might
  /// trigger.
  ///
  /// A destination that paired here would relocate a subtree the retired world
  /// named and mint a geometry repair for a rename that never happened.
  #[test]
  fn a_replace_orphaned_source_cannot_be_paired_by_a_wrapped_cookie() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("b", FileKind::Dir)]));
    let _ = drain(&mut core);

    // ONE source parked.
    core.on_inotify_events(
      scope,
      vec![inotify(root, IN_MOVED_FROM | IN_ISDIR, 900, Some("b"))],
      at(1),
    );
    let _ = drain(&mut core);
    assert_eq!(
      core.monitor.poll_timeout(),
      Some(at(1) + WINDOW),
      "staging: exactly one half is parked, and it is still pairable"
    );

    core.on_root_replaced(scope, replaced_meta(), at(2));
    let _ = drain(&mut core);
    finish_replace(&mut core, scope, root, vec![entry("c", FileKind::Dir)]);

    // The new world reuses cookie 900 for a rename of its own. The Monitor has
    // no half for it — the rebind purged them — so this destination pairs with
    // nothing inside the reported tree, and the geometry pass must agree.
    core.on_inotify_events(
      scope,
      vec![inotify(root, IN_MOVED_TO | IN_ISDIR, 900, Some("a"))],
      at(4),
    );
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_created() && change.location() == &loc(&["a"])),
      "non-vacuity: the destination really was classified, and pairing with \
       nothing it is a fresh directory rather than a move: {changes:?}"
    );
    assert!(
      !changes.iter().any(|change| change.kind().is_rescan()),
      "and it relocated nothing and repaired nothing: {changes:?}"
    );
  }

  /// Rename state with its OWN deadline must be represented in the scheduler, or
  /// nothing ever comes back to resolve it.
  ///
  /// `poll_timeout` is the core's whole statement of when it has work to do. A
  /// deadline absent from it is reached only as a side effect of some OTHER timer
  /// happening to be armed — which is not a rule, it is a coincidence, and it
  /// survives only until the mechanism supplying the coincidence changes.
  ///
  /// The cheaper form of the rule is to hold the deadline in ONE place, and the
  /// geometry pass now does: the Monitor's own pairing deadline is the only one a
  /// parked rename has, so this cell pins the whole census leg rather than one
  /// derived copy of it.
  ///
  /// Revert witness: drop the Monitor's leg from `poll_timeout` and the core
  /// reports no work due while every half of a burst sits waiting to resolve.
  #[test]
  fn the_pairing_deadline_is_one_the_scheduler_knows() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("b", FileKind::Dir)]));
    let _ = drain(&mut core);

    core.on_inotify_events(scope, move_outs(root, 0, BURST), at(1));
    let _ = drain(&mut core);
    assert_eq!(
      core.poll_timeout(),
      Some(at(1) + WINDOW),
      "the pairing deadline is what keeps the timer armed"
    );

    // And the wake it asks for is the one that resolves them.
    core.on_timeout(at(1) + WINDOW);
    let _ = drain(&mut core);
    assert_eq!(core.poll_timeout(), None, "and the timer stands down");
  }

  /// The geometry escalation is for a backend whose coverage is per-directory.
  /// A kernel-recursive one has no per-directory watches to re-arm — its single
  /// stream already covers the destination the instant the re-parent lands — so
  /// escalating there would manufacture a covering `Rescan` that repairs nothing,
  /// on a backend (USN) that decides its own rename geometry at admission anyway.
  ///
  /// USN is the witness because it is the only kernel-recursive lowering that
  /// mints a cookied move pair carrying `is_dir`, which is exactly the shape the
  /// geometry pass keys on: every other guard would let this through.
  ///
  /// Revert witness: drop `caps_for(..).kernel_recursive()` from the geometry
  /// gate and this scope grows a covering `Rescan` it never asked for.
  #[test]
  fn the_geometry_pass_stands_down_for_a_kernel_recursive_backend() {
    use crate::os::windows::usn::{UsnAdmitted, UsnTarget};

    let mut core = excluding(&["/r/a/cache"]);
    let scope = core.on_watch(
      PathBuf::from("/r"),
      Interest::all(),
      BackendKind::UsnJournal,
    );
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
        backend: BackendKind::UsnJournal,
      }),
    );
    let _ = drain(&mut core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    let _ = drain(&mut core);

    // `/r/a` -> `/r/b`, with `/r/a/cache` excluded: the exact geometry change a
    // descending scope escalates on.
    core.on_batch(
      scope,
      BatchPayload::detached(vec![SourceEvent::Windows(RawWindowsEvent::Usn(
        UsnAdmitted::Renamed {
          old: UsnTarget::Resolved(vec!["a".to_owned()]),
          old_content: 0,
          new: UsnTarget::Resolved(vec!["b".to_owned()]),
          new_content: 0,
          is_dir: true,
        },
      ))]),
      at(1),
    );
    core.on_timeout(at(1_000));
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      changes.iter().any(|change| change.kind().is_moved()),
      "the rename is forwarded as the move it is: {changes:?}"
    );
    assert!(
      !changes.iter().any(|change| change.kind().is_rescan()),
      "and no geometry escalation is manufactured for it: {changes:?}"
    );
  }

  /// Every arm this drain queued, by the absolute path the effect carries — the
  /// addressing an executor and a fake both open by.
  fn armed_paths(effects: &[Effect]) -> Vec<PathBuf> {
    effects
      .iter()
      .filter_map(|e| match e {
        Effect::AddWatch { path, .. } => Some(path.as_ref().clone()),
        _ => None,
      })
      .collect()
  }

  /// Arms `/r/p/q/cache` under a core excluding `/r/a/cache`, so a later rename
  /// of `q` to `a` is the geometry change that moves a covered subtree under the
  /// exclusion. Returns the scope, the root watch, the `p` watch and the `cache`
  /// watch.
  fn chained_rename_tree(core: &mut DriverCore) -> (ScopeId, WatchId, WatchId, WatchId) {
    let (scope, req, root) = live_descending(core);
    core.on_enumerated(req, listed(vec![entry("p", FileKind::Dir)]));
    let effects = drain(core);
    let (p, p_req) = arm(core, &effects, "/r/p");
    core.on_enumerated(p_req, listed(vec![entry("q", FileKind::Dir)]));
    let effects = drain(core);
    let (_q, q_req) = arm(core, &effects, "/r/p/q");
    core.on_enumerated(q_req, listed(vec![entry("cache", FileKind::Dir)]));
    let effects = drain(core);
    let (cache, cache_req) = arm(core, &effects, "/r/p/q/cache");
    core.on_enumerated(cache_req, listed(Vec::new()));
    let _ = drain(core);
    assert!(
      core
        .covered_paths()
        .contains(&PathBuf::from("/r/p/q/cache")),
      "staging: nothing excludes `/r/p/q/cache`, so it is covered and armed: {:?}",
      core.covered_paths()
    );
    (scope, root, p, cache)
  }

  /// A directory renamed TWICE — once by an ANCESTOR's rename, then on its own —
  /// must still be addressed at the ground it landed on.
  ///
  /// The hazard is a source end pinned as an ABSOLUTE path while `q` still lived
  /// at `/r/p/q`. Renaming `/r/p` to `/r/s` moves `q` with it, but a pinned path
  /// keeps naming `/r/p/q`, ground nothing occupies any more. A geometry decision
  /// taken over `/r/p/q` -> `/r/a` then judges a rename between two paths, one of
  /// which no longer exists — while the subtree that really moved landed at
  /// `/r/a`, whose child `cache` the caller excluded.
  ///
  /// What makes it right is that the source is not pinned anywhere. The Monitor
  /// reports it as a `(WatchId, Location)` slot reconstructed from the live tree,
  /// so an ancestor's re-parent updates it for free — and the `Moved` says so: its
  /// source end reads `s/q`.
  ///
  /// Asserted on DELIVERY and on COVERAGE, the two halves this module keeps
  /// apart: the record riding behind the pair is classified against the vacated
  /// ground, so it is kept and delivered INSIDE the exclusion, and the coverage
  /// set keeps naming a path the rename left.
  ///
  /// Coverage over `/r/a/cache` is legitimately still held at this instant — the
  /// repair's re-arm is what sheds it, which
  /// [`a_rename_into_an_exclusion_sheds_the_subtree_it_no_longer_reports`] pins.
  /// What is asserted here is the addressing itself: the moved subtree must be
  /// named where it landed.
  #[test]
  fn a_chained_rename_addresses_the_subtree_where_it_landed() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, root, p, cache) = chained_rename_tree(&mut core);

    // Read one: `q`'s source half, captured at `/r/p/q`. Its destination is
    // still to come.
    core.on_inotify_events(
      scope,
      vec![inotify(p, IN_MOVED_FROM | IN_ISDIR, 100, Some("q"))],
      at(1),
    );
    let _ = drain(&mut core);

    // Read two: the ANCESTOR moves. `/r/p` -> `/r/s` carries `q` to `/r/s/q`,
    // and neither endpoint has an exclusion under it, so this rename owes no
    // repair of its own — it only moves the ground the parked source names.
    core.on_inotify_events(scope, rename_dir(root, 101, "p", "s"), at(2));
    let effects = drain(&mut core);
    assert!(
      !emits(&effects)
        .iter()
        .any(|change| change.kind().is_rescan()),
      "staging: the ancestor's rename changes no exclusion geometry: {effects:?}"
    );

    // Read three, ONE read: `q`'s destination lands it at `/r/a`, which puts
    // `cache` under the exclusion — then the descendant watch's own record
    // behind it.
    let mut read = vec![inotify(root, IN_MOVED_TO | IN_ISDIR, 100, Some("a"))];
    read.push(inotify(cache, IN_CREATE, 0, Some("fresh.o")));
    core.on_inotify_events(scope, read, at(3));
    let effects = drain(&mut core);
    let changes = emits(&effects);

    assert!(
      changes.iter().any(
        |change| change.kind().moved_from() == Some(&loc(&["s", "q"]))
          && change.location() == &loc(&["a"])
      ),
      "non-vacuity: the pair resolves in this read, and the Monitor's own slot \
       reports the source at the path the ancestor's rename moved it to: \
       {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_rescan() && change.location() == &loc(&["a"])),
      "and the repair is placed at the destination the subtree really landed on: \
       {changes:?}"
    );
    assert!(
      !changes.iter().any(names_the_exclusion),
      "the destination moved the subtree before the record behind it was \
       classified, so nothing under the exclusion is delivered: {changes:?}"
    );
    assert!(
      !core
        .covered_paths()
        .iter()
        .any(|path| path.starts_with("/r/s/q")),
      "and no coverage still names the ground the rename vacated: {:?}",
      core.covered_paths()
    );
  }

  /// The same chain inside ONE read, where the ancestor's rename and the
  /// dependent one are classified by a single pass over a single buffer.
  ///
  /// The staleness this guards against is not a cross-read effect: the hand-off
  /// happens per RECORD as the fence walks the buffer, so a source pinned by this
  /// buffer's first record would be invalidated by its third and consumed already
  /// stale by its fourth. Delivery is asserted for the same reason as in the
  /// cross-read twin: a `Rescan` covers what comes next and cannot unsay a
  /// record already retained ahead of it.
  #[test]
  fn a_chained_rename_within_one_read_addresses_the_subtree_where_it_landed() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, root, p, cache) = chained_rename_tree(&mut core);

    // ONE read: `q`'s source, the ancestor's whole rename, `q`'s destination,
    // then the descendant watch's own record behind all of it.
    let mut read = vec![inotify(p, IN_MOVED_FROM | IN_ISDIR, 100, Some("q"))];
    read.extend(rename_dir(root, 101, "p", "s"));
    read.push(inotify(root, IN_MOVED_TO | IN_ISDIR, 100, Some("a")));
    read.push(inotify(cache, IN_CREATE, 0, Some("fresh.o")));
    core.on_inotify_events(scope, read, at(1));
    let effects = drain(&mut core);
    let changes = emits(&effects);

    assert!(
      changes.iter().any(
        |change| change.kind().moved_from() == Some(&loc(&["s", "q"]))
          && change.location() == &loc(&["a"])
      ),
      "non-vacuity: both pairs resolve in this one read, and the Monitor's slot \
       reports the dependent source where the ancestor's rename left it: \
       {changes:?}"
    );
    assert!(
      !changes.iter().any(names_the_exclusion),
      "nothing under the exclusion is delivered: {changes:?}"
    );
    assert!(
      !core
        .covered_paths()
        .iter()
        .any(|path| path.starts_with("/r/s/q")),
      "and no coverage still names the ground the rename vacated: {:?}",
      core.covered_paths()
    );
  }

  /// A destination that arrives PAST the pairing window relocates nothing, and
  /// the two sides must agree about that.
  ///
  /// The Monitor consumes a parked half only while it is still pairable
  /// (`!now.reached(deadline)`); past that edge the source already stranded, so
  /// it resolves the half as a `Removed`, tears the held subtree down and rebuilds
  /// the arrival at its own slot. That rebuild's walk is fenced entry by entry,
  /// which is exactly why a destination that pairs with nothing owes no repair.
  ///
  /// A destination arm deciding for itself — consuming a parked source whenever it
  /// finds one — would mint the located repair for a crossing that never happened:
  /// a re-enumeration of the scope root on the strength of a relocation the
  /// Monitor never performed. The arm asks the Monitor instead, and a past-window
  /// arrival relocates nothing, so it repairs nothing.
  ///
  /// The REPAIR's own artefact is what the assertion reads, because it is what
  /// would outlive the read — the whole of what the core would have done on the
  /// strength of a relocation that did not happen. It is read as that
  /// re-enumeration rather than as the destination's covering `Rescan`, because
  /// the Monitor mints one of those for a reason of its own here: the strand tore
  /// down a watched subtree the arriving record proves is alive, and every other
  /// signal that teardown emits is interest- and filter-subject. A `Rescan` at the
  /// destination is therefore no longer evidence that the core repaired anything.
  ///
  /// No timer of any kind is driven here: the strand must not depend on
  /// `on_timeout` happening to have run first.
  #[test]
  fn a_late_destination_repairs_nothing_the_monitor_did_not_relocate() {
    let mut core = excluding(&["/r/a/cache"]);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("b", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (_b, b_req) = arm(&mut core, &effects, "/r/b");
    core.on_enumerated(b_req, listed(vec![entry("cache", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (_cache, cache_req) = arm(&mut core, &effects, "/r/b/cache");
    core.on_enumerated(cache_req, listed(Vec::new()));
    let _ = drain(&mut core);
    assert!(
      core.covered_paths().contains(&PathBuf::from("/r/b/cache")),
      "staging: nothing excludes `/r/b/cache`, so it is covered and armed: {:?}",
      core.covered_paths()
    );

    core.on_inotify_events(
      scope,
      vec![inotify(root, IN_MOVED_FROM | IN_ISDIR, 900, Some("b"))],
      at(1),
    );
    let _ = drain(&mut core);

    // Long past `at(1) + WINDOW`, with the Monitor's timeout never driven: the
    // half is still parked and no longer pairable.
    core.on_inotify_events(
      scope,
      vec![inotify(root, IN_MOVED_TO | IN_ISDIR, 900, Some("a"))],
      at(1_000),
    );
    let effects = drain(&mut core);
    let changes = emits(&effects);

    assert!(
      !changes.iter().any(|change| change.kind().is_moved()),
      "non-vacuity: the Monitor refuses the past-window half, so the arrival is \
       not a move: {changes:?}"
    );
    assert!(
      changes
        .iter()
        .any(|change| change.kind().is_created() && change.location() == &loc(&["a"])),
      "and it really was classified, as the fresh object it pairs with nothing \
       to be: {changes:?}"
    );
    assert!(
      enumerate_of(&effects, "/r").is_none(),
      "and the core repaired nothing on the strength of it: a located repair \
       re-enumerates the scope root, and nothing was relocated: {effects:?}"
    );
    // The one `Rescan` present is the Monitor's own: the strand's teardown of a
    // still-live watched subtree, which no interest filters. Its rebuilt
    // destination is counted behind it, and the exclusion still fences that
    // rebuild's walk entry by entry.
    assert!(
      changes
        .iter()
        .filter(|change| change.kind().is_rescan())
        .map(|change| change.location())
        .eq([&loc(&["a"])]),
      "exactly the strand teardown's own cover, at the destination: {changes:?}"
    );
    let (_a, a_req) = arm(&mut core, &effects, "/r/a");
    core.on_enumerated(a_req, listed(vec![entry("cache", FileKind::Dir)]));
    let _ = drain(&mut core);
    assert!(
      !core
        .covered_paths()
        .iter()
        .any(|path| path.starts_with("/r/a/cache")),
      "the rebuild's walk is fenced entry by entry: {:?}",
      core.covered_paths()
    );
  }

  /// Addressing is not an exclusions-only concern, and no repair pass gates it.
  ///
  /// `covered_paths` is the core's statement of what it holds a kernel watch for,
  /// and every arm and every enumerate the core dispatches is addressed by joining
  /// onto the same derivation. A rename the Monitor answered with an O(1)
  /// re-parent moves the whole subtree with it — in the configuration the caller
  /// gets by default, with no exclusion set to bring a fence into play.
  ///
  /// The cell is stated in the DEFAULT configuration deliberately: a repaired
  /// mirror would have satisfied it only where the repair was invoked from, and
  /// the repair used to be invoked from the exclusion fence alone.
  ///
  /// Asserted as an EQUALITY: an under-count would let a silently-shrinking set
  /// pass, and the point is that the set names the tree that exists.
  #[test]
  fn a_rename_with_no_exclusions_still_addresses_the_tree_that_exists() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("a", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (_a, a_req) = arm(&mut core, &effects, "/r/a");
    core.on_enumerated(a_req, listed(vec![entry("deep", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (_deep, deep_req) = arm(&mut core, &effects, "/r/a/deep");
    core.on_enumerated(deep_req, listed(Vec::new()));
    let _ = drain(&mut core);
    assert_eq!(
      core.covered_paths(),
      vec![
        PathBuf::from("/r"),
        PathBuf::from("/r/a"),
        PathBuf::from("/r/a/deep"),
      ],
      "staging: with nothing excluded the whole tree is covered"
    );

    core.on_inotify_events(scope, rename_dir(root, 7, "a", "b"), at(1));
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      changes
        .iter()
        .any(|change| change.kind().moved_from() == Some(&loc(&["a"]))
          && change.location() == &loc(&["b"])),
      "non-vacuity: the Monitor re-parented the subtree in place: {changes:?}"
    );

    assert_eq!(
      core.covered_paths(),
      vec![
        PathBuf::from("/r"),
        PathBuf::from("/r/b"),
        PathBuf::from("/r/b/deep"),
      ],
      "and the coverage set names the tree that exists, not the one the rename \
       replaced"
    );
  }

  /// The same question where it addresses I/O: a directory created UNDER a moved
  /// subtree is armed at the path the core joins onto its parent's, and the arm is
  /// the one an executor opens by.
  ///
  /// The Monitor names the new directory from the node tree the re-parent updated,
  /// so a core that addressed by any OTHER description of that tree would emit an
  /// arm and a delivery that disagree about which object they mean. Both are
  /// derived from the one tree, so they cannot.
  #[test]
  fn a_watch_armed_under_a_moved_subtree_is_addressed_at_its_new_path() {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let (scope, req, root) = live_descending(&mut core);
    core.on_enumerated(req, listed(vec![entry("a", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (_a, a_req) = arm(&mut core, &effects, "/r/a");
    core.on_enumerated(a_req, listed(vec![entry("deep", FileKind::Dir)]));
    let effects = drain(&mut core);
    let (deep, deep_req) = arm(&mut core, &effects, "/r/a/deep");
    core.on_enumerated(deep_req, listed(Vec::new()));
    let _ = drain(&mut core);

    core.on_inotify_events(scope, rename_dir(root, 7, "a", "b"), at(1));
    let _ = drain(&mut core);

    // A directory created under the moved subtree, reported on the descendant's
    // own watch — the one the rename carried across.
    core.on_inotify_events(
      scope,
      vec![inotify(deep, IN_CREATE | IN_ISDIR, 0, Some("newdir"))],
      at(2),
    );
    let effects = drain(&mut core);
    let changes = emits(&effects);
    assert!(
      changes
        .iter()
        .any(|change| change.location() == &loc(&["b", "deep", "newdir"])),
      "non-vacuity: the Monitor reports the new directory under the subtree's \
       new name: {changes:?}"
    );

    assert_eq!(
      armed_paths(&effects),
      vec![PathBuf::from("/r/b/deep/newdir")],
      "and the arm addresses the same object the delivery named: {effects:?}"
    );
  }
}
