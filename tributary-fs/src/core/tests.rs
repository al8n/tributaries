use super::*;
use std::time::Duration;

const WINDOW: Duration = Duration::from_millis(100);
/// The periodic-refresh tick interval the shared harness cores run with. Both
/// Linux profiles arm it (#74); the FSEvents suites do not arm it at all and the
/// descending suites rarely drive time this far, so it is inert outside the
/// cells that name it.
const LIVENESS: Duration = Duration::from_secs(30);

/// The scope's delivery lane, for cells whose transport never swaps.
fn lane_zero(_: ScopeId) -> u64 {
  0
}
/// The lane the cells above hand the seal latch; a cell that swaps transports
/// names its lanes itself.
const LANE_ZERO: fn(ScopeId) -> u64 = lane_zero;

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

/// The driver's adoption-seal fence in one step, on lane `lane`: offer, latch,
/// answer, resolve. Cells that are not ABOUT the fence use this to get past it;
/// the fence's own cells drive the four calls apart.
fn seal_adoptions(core: &mut DriverCore, scope: ScopeId, lane: u64, token: u64) {
  core.mark_adoption_cut_inflight(scope, lane, token);
  core.prove_adoption_cut(scope, lane, token);
  core.resolve_adoption_seals(&|_| lane, &NO_RESIDUE);
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

/// The effects a drain carried that something is OWED for — every effect but the
/// frame publications.
///
/// [`Effect::PublishFrame`] tells a live fanotify source which world the core is
/// in and asks for nothing back: it opens no round trip, answers no ticket,
/// delivers nothing to the consumer, and the source discharges it by remembering
/// a number. So no cell asking "what did this transition make the core DO" is
/// about it, and a quiet drain is quiet whether or not one rode along. The cells
/// that ARE about it read it through [`frame_publications`] instead, which is
/// where the stamp's own witnesses live.
fn obliged(effects: &[Effect]) -> Vec<&Effect> {
  effects
    .iter()
    .filter(|effect| !matches!(effect, Effect::PublishFrame { .. }))
    .collect()
}

/// The frame epochs `effects` published to a source, in order — the core-owned,
/// monotone counter an unrequested whole-root generation is stamped with.
fn frame_publications(effects: &[Effect]) -> Vec<u64> {
  effects
    .iter()
    .filter_map(|effect| match effect {
      Effect::PublishFrame { epoch, .. } => Some(*epoch),
      _ => None,
    })
    .collect()
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
fn alive_refresh(mounts: Vec<MountRow>, authoritative: bool) -> MountRefresh {
  MountRefresh {
    mounts,
    authoritative,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    // No frame change exercised: the captured `root_mnt_id` stays intact.
    root_mnt_id: None,
    root_incarnation: None,
  }
}

/// The same, carrying the root's CURRENT mount frame — what a real Linux refresh
/// answers and what `on_mounts_refreshed` adopts. A cell needs it before any seam
/// entry under the root can be `Mount` or `SameMount` at all: `Standing::decide`
/// compares the boundary's id against the scope's, and a scope with no id of its
/// own reads every entry `Unknown`.
fn framed_refresh(
  mounts: Vec<MountRow>,
  authoritative: bool,
  root_mnt_id: Option<u64>,
) -> MountRefresh {
  MountRefresh {
    mounts,
    authoritative,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    root_mnt_id,
    root_incarnation: None,
  }
}

/// [`framed_refresh`] carrying the INCARNATION token as well — the fact that
/// separates two mounts sharing one recycled id. `None` is every host that
/// answers no token, and every window a refresh could not prove quiet.
fn incarnate_refresh(
  mounts: Vec<MountRow>,
  authoritative: bool,
  root_mnt_id: Option<u64>,
  root_incarnation: Option<crate::os::RootIncarnation>,
) -> MountRefresh {
  MountRefresh {
    mounts,
    authoritative,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    root_mnt_id,
    root_incarnation,
  }
}

/// The 6.8+ token: a mount id the kernel never recycles.
fn unique(id: u64) -> crate::os::RootIncarnation {
  crate::os::RootIncarnation::Unique(id)
}

/// A table row with no identity at all — what macOS' `getfsstat`, a pre-5.8
/// Linux kernel and every fake report. The suites that only care WHERE a mount
/// is use this; the ones that exercise identity spell `MountRow` out.
fn bare(location: &str) -> MountRow {
  MountRow {
    location: PathBuf::from(location),
    mnt_id: None,
    parent_id: None,
    dev: None,
  }
}

/// A table row carrying the identity `/proc/self/mountinfo` supplies on a
/// kernel that answers mount ids, with the PARENT left unanswered — an unknown
/// half never reads as a difference, so a cell that says nothing about parenting
/// gets exactly the verdicts the device alone decides. The cells that exercise
/// re-parenting use [`row_under`].
fn row(location: &str, mnt_id: u64, dev: u64) -> MountRow {
  MountRow {
    location: PathBuf::from(location),
    mnt_id: Some(mnt_id),
    parent_id: None,
    dev: Some(dev),
  }
}

/// A table row that also names the mount it hangs off — field 2 of a mountinfo
/// line.
fn row_under(location: &str, mnt_id: u64, parent_id: u64, dev: u64) -> MountRow {
  MountRow {
    parent_id: Some(parent_id),
    ..row(location, mnt_id, dev)
  }
}

/// Everything `scope` holds about boundaries under its root — the CENSUS rows
/// first, in read order, then the LEDGER entries in insertion order — as
/// `(location, mnt_id, dev)`.
///
/// The two structures answer different questions, but almost every cell here asks
/// the one they answer together: what does this scope believe stands under its
/// root, and with which identity. `mnt_id` is the census KEY where the host
/// answered one and the entry's own `Standing` otherwise, so a `SameMount` entry
/// reads back as the root's id exactly as the seam read it.
///
/// `dev` is a census fact ONLY, and reads `None` for every ledger entry — the
/// ledger stores no device, because nothing joins on one. A cell asserting a
/// device is therefore asserting about a row, which is where the same-place
/// replacement is decided.
fn recorded(core: &DriverCore, scope: ScopeId) -> Vec<(PathBuf, Option<u64>, Option<u64>)> {
  let state = core.scopes.get(&scope).expect("scope is live");
  state
    .census
    .iter()
    .map(|row| {
      let id = match row.key {
        Key::Id(id) => Some(id),
        Key::Location(_) => None,
      };
      (row.location.clone(), id, row.dev)
    })
    .chain(state.ledger.iter().map(|entry| {
      let id = match entry.standing {
        Standing::Mount(id) => Some(id),
        Standing::SameMount => state.root_mnt_id,
        Standing::Unknown => None,
      };
      (entry.location.clone(), id, None)
    }))
    .collect()
}

/// The recorded locations, BORROWED — [`recorded`] without its per-entry
/// `PathBuf` clone, for the cells that only ask how many there are, which is
/// first, or whether one is present.
///
/// The clone matters at one place in this suite and it matters a lot there: the
/// cells that hold the ledger at `MAX_BOUNDARIES` read it several times, and each
/// read used to allocate a thousand paths. An interpreted 32-bit run pays for
/// every one of those out of the single 4 GB address space the whole shard
/// shares, which is where `fs-rest` exhausted it.
fn recorded_locations(core: &DriverCore, scope: ScopeId) -> Vec<&Path> {
  let state = core.scopes.get(&scope).expect("scope is live");
  state
    .census
    .iter()
    .map(|row| row.location.as_path())
    .chain(state.ledger.iter().map(|entry| entry.location.as_path()))
    .collect()
}

/// A core with one live scope rooted at `/r` on device 1, its birth refresh
/// fed (an authoritative empty table): event-side trust is open.
fn live_core() -> (DriverCore, ScopeId) {
  live_core_with(Interest::all())
}

/// The same, under a narrowed subscription — the shape an admission claim
/// needs, since `Interest::all()` admits on any fact at all.
fn live_core_with(interest: Interest) -> (DriverCore, ScopeId) {
  let mut core = DriverCore::new(WINDOW, LIVENESS);
  let scope = core
    .on_watch(PathBuf::from("/r"), interest, BackendKind::FsEvents)
    .expect("a fresh scope registers");
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
      declined: Vec::new(),
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
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents)
    .expect("a fresh scope registers");
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
      mounts: Vec::new(),
      declined: Vec::new(),
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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
      root_incarnation: None,
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
        root_incarnation: None,
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
      mounts: vec![bare("/r/vol")],
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: None,
      root_incarnation: None,
    },
    at(5),
  );
  let effects = drain(&mut core);
  assert!(
    !effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { .. })),
    "an alive root does not die: {effects:?}"
  );
  // The one thing it DOES emit is the arrival cover for the row it just
  // recorded — a mount transition, not a liveness verdict.
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "{effects:?}");
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));

  // Fed the same table again, the liveness check is wholly inert: no death, no
  // teardown, and no emission at all.
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: vec![bare("/r/vol")],
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: None,
      root_incarnation: None,
    },
    at(6),
  );
  let effects = drain(&mut core);
  assert!(
    !effects
      .iter()
      .any(|e| matches!(e, Effect::TeardownStream { .. }) | matches!(e, Effect::Emit { .. })),
    "an alive root over an unchanged table neither dies nor emits: {effects:?}"
  );
}

/// #74's core mapping: a mount that was in the last authoritative table read and
/// is not in this one DEPARTED, and its subtree gets a LOCATED COVER — the same
/// shape `compile::fsevents`' `plan_mount` plans for the volume change macOS
/// does signal, reached here from the table alone.
///
/// It is a COVER, never a delivery: a bind mount (or a mount in another
/// namespace) can make the same directory appear and disappear with the watched
/// object unchanged, so a synthesized record would fabricate an event that did
/// not happen, while a cover only obliges re-enumeration.
#[test]
fn a_departed_mount_covers_its_located_subtree() {
  let (mut core, scope) = live_core();
  // Read one records the mount. This scope's spawn barrier listed none, so the
  // row is an ARRIVAL and covers its own location — see
  // `an_arrived_mount_covers_its_located_subtree`, which is that direction's
  // cell; here it is only the staging that puts the mount in the set. (A barrier
  // that DID list it records it at the swap instead, and the first read merely
  // confirms — see `a_mount_seeded_at_spawn_and_still_mounted_covers_nothing`.)
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(1));
  assert_eq!(
    emits(&drain(&mut core)).len(),
    1,
    "staging: the arrival is recorded, and covered once"
  );

  // Read two: the mount is gone, and NOTHING signalled it.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "one cover per departed mount: {effects:?}"
  );
  assert!(
    emitted[0].kind().is_rescan(),
    "a departure is covered, never delivered: {emitted:?}"
  );
  assert_eq!(
    emitted[0].location(),
    &loc(&["vol"]),
    "the cover is LOCATED at the departed mount, not the whole root"
  );

  // And it is covered ONCE: the baseline moved with the read, so the next
  // identical frame re-derives nothing.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(3));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "the departure is covered once, not on every later refresh"
  );
}

/// The refresh diffs through a KEY INDEX instead of a scan per row, and the index
/// must decide everything the scan did — including the two things an index gets
/// wrong for free.
///
/// The scan was `find` per row over the records and then a scan of the FRAME per
/// record: O(rows x records) comparisons on every refresh of every root, which a
/// container's or a systemd host's mount namespace makes into a driver stall, and
/// a stalled single-threaded driver is how the queue loss this file exists to
/// avoid actually happens.
///
/// The frame here interleaves an ARRIVAL ahead of two unchanged rows on purpose,
/// and repeats the arrival's row. The census is the read's own order, so an
/// interleave must not reorder or duplicate anything, and TWO transitions at one
/// location must not buy two covers: `/r/a` is listed under a new mount id, which
/// is a departure and an arrival at that one place.
///
/// MUTATION WITNESS (drop the key dedup in `census_of`): the repeated row enters
/// the census twice and this FAILS at `the census is the read's own order`.
#[test]
fn the_refresh_diffs_through_a_key_index_without_disturbing_read_order() {
  let (mut core, scope) = live_core();
  // Two listed mounts, in this read order.
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row("/r/a", 10, 100), row("/r/b", 11, 101)], true),
    at(1),
  );
  assert_eq!(
    emits(&drain(&mut core)).len(),
    2,
    "staging: two arrivals, each covered once"
  );

  // One frame carrying, IN THIS ORDER: an arrival, a NEW mount id at the first
  // listed location, an unchanged row, and a DUPLICATE of the arrival's row (ids
  // are unique among live mounts, so a repeat is malformed — and it must not
  // become a second row and a second cover).
  core.on_mounts_refreshed(
    scope,
    alive_refresh(
      vec![
        row("/r/new", 12, 102),
        row("/r/a", 99, 100),
        row("/r/b", 11, 101),
        row("/r/new", 12, 102),
      ],
      true,
    ),
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.iter().map(|c| c.location()).collect::<Vec<_>>(),
    vec![&loc(&["new"]), &loc(&["a"])],
    "one cover for the arrival and one for the key change at /r/a, IN FRAME \
     ORDER, and the duplicate row adds neither: {effects:?}"
  );
  assert_eq!(
    recorded(&core, scope),
    vec![
      (PathBuf::from("/r/new"), Some(12), Some(102)),
      (PathBuf::from("/r/a"), Some(99), Some(100)),
      (PathBuf::from("/r/b"), Some(11), Some(101)),
    ],
    "the census is the read's own order, written wholesale — no in-place update, \
     no index to keep valid across a push, and no duplicate key"
  );

  // The departure side reads the new census through a set for the same reason.
  // `/r/b` alone survives; the other two are gone.
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row("/r/b", 11, 101)], true),
    at(3),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.iter().map(|c| c.location()).collect::<Vec<_>>(),
    vec![&loc(&["new"]), &loc(&["a"])],
    "both departures are covered, in CENSUS order: {effects:?}"
  );
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/b"), Some(11), Some(101))],
    "and only the row the read still lists is kept"
  );
}

/// **Cell (b): the same mount at a NEW location covers BOTH.** A move reveals the
/// ground it left and shadows the ground it landed on, and the consumer is owed a
/// re-read of each.
///
/// `mount --move` produces this, and so — indistinguishably — does a
/// `Location`-keyed host's mount departing at one place while another arrives at
/// a second. Covering both is what makes the ambiguity harmless.
///
/// It is also what makes cross-read id RECYCLING benign. Mount ids are allocated
/// lowest-free, so a mount that departs and another that arrives inside one
/// refresh window can share an id; keyed alone, that reads as "nothing happened".
/// Read WITH the location, it reads as a move — and a move covers the old
/// location, which is exactly the cover the real departure owed.
///
/// MUTATION WITNESS (cover only the new location): drop `covered.push(was
/// .location.clone())` from the move arm and this FAILS at `the ground the mount
/// LEFT is covered` — the revealed subtree silent, which is #74 by another door.
/// MUTATION WITNESS (cover on a PRESENCE rather than a transition): make the
/// unchanged arm push a cover too, and this FAILS at `a move is a transition
/// between two observations, derived once` — one cover per live mount per tick,
/// forever, which is the storm the whole rule exists to make unreachable.
#[test]
fn the_same_mount_at_a_new_location_covers_both() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(scope, alive_refresh(vec![row("/r/a", 10, 99)], true), at(1));
  let effects = drain(&mut core);
  assert_eq!(
    emits(&effects)
      .iter()
      .map(|c| c.location())
      .collect::<Vec<_>>(),
    vec![&loc(&["a"])],
    "staging: one arrival, covered at the location the read rendered: {effects:?}"
  );

  // The SAME mount, rendered somewhere else. Nothing arrived and nothing left.
  core.on_mounts_refreshed(scope, alive_refresh(vec![row("/r/b", 10, 99)], true), at(2));
  let effects = drain(&mut core);
  let covers: Vec<&Location> = emits(&effects).iter().map(|c| c.location()).collect();
  assert!(
    covers.contains(&&loc(&["a"])),
    "the ground the mount LEFT is covered — revealed, and never enumerated: \
     {effects:?}"
  );
  assert!(
    covers.contains(&&loc(&["b"])),
    "and so is the ground it landed on — shadowed, and enumerated as something \
     else: {effects:?}"
  );
  assert_eq!(covers.len(), 2, "two locations, two covers: {effects:?}");
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/b"), Some(10), Some(99))],
    "and it is ONE mount throughout — the key never changed, so the census holds \
     a single row, at its new location"
  );

  // And the move is spent: the same read again derives nothing.
  core.on_mounts_refreshed(scope, alive_refresh(vec![row("/r/b", 10, 99)], true), at(3));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "a move is a transition between two observations, derived once"
  );
}

/// **R15 F2, the trust half.** An authoritative read REPLACES the table
/// component: a row it does not list is a mount the host says is gone, and the
/// path it covered is root-device again.
///
/// The union this replaced kept every location the host ever presented for the
/// life of the scope, on the argument that a stale extra prefix only ever vetoes
/// while a missing one grants trust never proven. The direction is right and the
/// conclusion was wrong: unbounded residency is not a safe direction, and the
/// premise fails here — the read is not silent about `/r/vol`, it is a complete
/// snapshot that says the mount is gone. What genuinely cannot survive
/// replacement is a prefix no snapshot would ever list, and those live in
/// `learned_mounts` (see [`a_learned_prefix_survives_the_table_replacement`]).
///
/// MUTATION WITNESS (union, the old shape): make `install_mount_table` extend
/// instead of clearing first and this FAILS at `the departed row is gone from the
/// table` — the historical mountpoint still there, still vetoing a mount the host
/// says departed.
/// MUTATION WITNESS (replace the whole veto, not just the table): point
/// `install_mount_table` at `learned_mounts` as well and
/// [`a_learned_prefix_survives_the_table_replacement`] FAILS instead — the two
/// halves pin opposite directions and neither alone is the invariant.
#[test]
fn an_authoritative_read_replaces_the_departed_table_row() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(1));
  let _ = drain(&mut core);
  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(
    mint(state, Path::new("/r/vol/x"), NonZeroU64::new(7), None).is_none(),
    "staging: while the row stands, an event-side identity under it refuses to mint"
  );

  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
  let _ = drain(&mut core);

  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(state.mounts_authoritative, "the read was authoritative");
  assert!(
    !state.mount_table.iter().any(|m| m == Path::new("/r/vol")),
    "the departed row is gone from the table: an authoritative snapshot is \
     complete, so a location it does not list is a mount that is not there — and \
     retaining it forever is a leak, not a safe direction: {:?}",
    state.mount_table
  );
  assert!(
    mint(state, Path::new("/r/vol/x"), NonZeroU64::new(7), None).is_some(),
    "and the ground the mount was hiding mints again"
  );
}

/// **R15 F2, the bound.** N distinct mountpoints that arrive and depart leave N
/// nothing behind: the table component holds one snapshot's rows, never a
/// history.
///
/// This is the leak itself. Every authoritative refresh used to append the
/// locations it read to a vector nothing ever removed from on Linux, so a
/// long-lived scope on a container host retained one `PathBuf` per HISTORICAL
/// unique mountpoint — and paid a linear scan of that history per current row on
/// every refresh, on a single-threaded driver whose stalls are the queue loss the
/// whole file exists to avoid.
///
/// The cell counts against what is CURRENTLY mounted, not against a constant: the
/// churn count is a loop bound, and the verdict is `mount_table.len()` versus the
/// one row the last read listed. A ceiling of "at most N" would pass on the
/// leaking code for N large enough.
///
/// MUTATION WITNESS (union, the old shape): make `install_mount_table` extend
/// instead of clearing first and this FAILS at `the table holds one snapshot, not
/// a history` with `left: 25, right: 1`.
/// MUTATION WITNESS (the other direction — install nothing): make
/// `install_mount_table` drop its rows and it FAILS at the same site with `left:
/// 0, right: 1`, so the bound cannot be met by simply never building the table.
#[test]
fn mount_churn_leaves_the_table_the_size_of_one_snapshot() {
  let (mut core, scope) = live_core();
  const CHURN: usize = 24;
  for turn in 0..CHURN {
    let vol = format!("/r/vol-{turn}");
    core.on_mounts_refreshed(
      scope,
      alive_refresh(vec![bare("/r/live"), bare(&vol)], true),
      at(2 * turn as u64 + 1),
    );
    let _ = drain(&mut core);
    // And it departs again, exactly as a container's private namespace churns.
    core.on_mounts_refreshed(
      scope,
      alive_refresh(vec![bare("/r/live")], true),
      at(2 * turn as u64 + 2),
    );
    let _ = drain(&mut core);
  }

  let state = core.scopes.get(&scope).expect("scope is live");
  assert_eq!(
    state.mount_table.len(),
    1,
    "the table holds one snapshot, not a history: the last read listed one row, \
     so one row is what a scope that watched {CHURN} mounts come and go retains: \
     {:?}",
    state.mount_table
  );
  assert!(
    state.mount_table.iter().any(|m| m == Path::new("/r/live")),
    "and it is the row that is still mounted: {:?}",
    state.mount_table
  );
}

/// **R15 F2, the veto half.** A prefix learned from something OTHER than a
/// snapshot survives every table replacement, and only evidence its mount is gone
/// retires it.
///
/// This is why the two components exist. An in-band `Mount` word can describe a
/// mount that arrived AFTER the snapshot currently in flight was read, and a
/// probe's foreign device is a path arbitrarily deep inside a volume that no
/// mountinfo row will ever name — so neither is a row, and an install that
/// replaced either away would re-trust a subtree this scope has direct evidence
/// is foreign. The evidence that DOES retire one is the in-band unmount word,
/// applied at settlement.
///
/// MUTATION WITNESS (one undifferentiated set): make `apply_mount_add` push to
/// `mount_table` and this FAILS at `the in-band mount word survives the
/// authoritative install` — the very shape the union was standing in for, now
/// carried by a set the install cannot reach.
/// MUTATION WITNESS (a learned prefix retired by a cadence): make
/// `install_mount_table` clear `learned_mounts` too and it FAILS at the same
/// assertion.
/// MUTATION WITNESS (the other direction — never retired at all): drop the
/// `learned_mounts.retain` from `settle`'s deferred-unmount loop and it FAILS at
/// `the unmount word retires it` — the veto outliving the mount it describes,
/// which is the leak on the half a snapshot may not touch.
#[test]
fn a_learned_prefix_survives_the_table_replacement() {
  let (mut core, scope) = live_core();
  // An in-band mount word: the volume is live and the snapshot in flight predates
  // it, which is exactly the case a table row cannot represent.
  core.on_batch_events(
    scope,
    vec![ev("/r/late", flags(&[FsEventFlags::MOUNT]), 1, 0)],
    at(1),
  );
  let _ = drain(&mut core);
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/other")], true), at(2));
  let _ = drain(&mut core);

  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(
    state
      .learned_mounts
      .iter()
      .any(|m| m == Path::new("/r/late")),
    "the in-band mount word survives the authoritative install: the read that \
     replaced the table was taken before the mount existed, so its silence about \
     `/r/late` is ignorance rather than evidence: {:?}",
    state.learned_mounts
  );
  assert!(
    mint(state, Path::new("/r/late/x"), NonZeroU64::new(7), None).is_none(),
    "and the veto still stands: nothing under it mints"
  );

  // The unmount word is the evidence that retires it — and the only thing that
  // does.
  core.on_batch_events(
    scope,
    vec![ev("/r/late", flags(&[FsEventFlags::UNMOUNT]), 2, 0)],
    at(3),
  );
  let _ = drain(&mut core);
  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(
    !state
      .learned_mounts
      .iter()
      .any(|m| m == Path::new("/r/late")),
    "the unmount word retires it: {:?}",
    state.learned_mounts
  );
  assert!(
    mint(state, Path::new("/r/late/x"), NonZeroU64::new(7), None).is_some(),
    "and the revealed ground mints again"
  );
}

/// A LIVE, NON-stale refresh whose mount table could NOT be read (a transient
/// `/proc/self/mountinfo` failure yields a non-authoritative read) must CLOSE a
/// previously-open authority — the non-authoritative counterpart to the stale
/// gate. Leaving it open would keep proving paths root-device by their absence
/// from a table that was never re-read across the mount change the refresh was
/// meant to reconcile. Authority re-opens only with a later authoritative read;
/// probe-read device evidence still decides throughout.
///
/// Driven on FSEvents, and the profile is the point rather than a convenience:
/// authority gates the ABSENCE leg of [`device_trusted`], and FSEvents is the one
/// backend with a consumer of it ([`consumes_absence_trust`]). On a backend that
/// consumes none, every assertion below about a path being untrusted would pass
/// for a reason that has nothing to do with authority.
#[test]
fn a_live_non_authoritative_refresh_closes_a_previously_open_authority() {
  let (mut core, scope) = live_core();
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

/// **R15 F2, the gate.** A backend with no consumer of absence-based trust
/// maintains no table AND is granted nothing by its emptiness — one predicate
/// decides both, so skipping the maintenance cannot become a grant.
///
/// The four-way per-backend argument was recorded prose and consumed by nothing:
/// only FSEvents mints an identity with no device read (`record_from_event` ->
/// `mint(.., None)`) or grants a vanished half its cookie under a table veto.
/// inotify reads a real `dev` off the fd it pinned, fanotify holds no identity to
/// mint at all, and a Windows watch is scoped to one volume by construction. So on
/// every backend but FSEvents the table was written and never read — pure cost,
/// and on Linux an unbounded one.
///
/// MUTATION WITNESS (gate the read but not the build): drop the
/// `consumes_absence_trust(state.profile) &&` conjunct from `device_trusted` and
/// this FAILS at `a backend that maintains no table is granted nothing by its
/// emptiness` — an empty table read as TOTAL trust, which is the one direction
/// skipping the maintenance could ever fail in, and the reason one predicate
/// spells both.
/// MUTATION WITNESS (the other direction — build for a backend that reads
/// nothing): make `consumes_absence_trust` answer `true` for `Fanotify` and it
/// FAILS at `a backend with no absence-trust consumer builds no table` with the
/// row installed, which is the cost this removes.
#[test]
fn a_backend_with_no_absence_consumer_neither_builds_nor_reads_the_table() {
  let (mut core, scope) = live_core_fanotify(vec![row("/r/vol", 77, 9)], Some(42));
  core.on_mounts_refreshed(
    scope,
    framed_refresh(vec![row("/r/vol", 77, 9)], true, Some(42)),
    at(1),
  );
  let _ = drain(&mut core);

  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(
    state.mounts_authoritative,
    "staging: the read was authoritative"
  );
  assert!(
    state.mount_table.is_empty(),
    "a backend with no absence-trust consumer builds no table: {:?}",
    state.mount_table
  );
  assert!(
    !device_trusted(state, Path::new("/r/vol/x"), None),
    "a backend that maintains no table is granted nothing by its emptiness: one \
     predicate gates the build and the read, so a consumer that appears without \
     flipping it fails CLOSED"
  );
  assert!(
    device_trusted(state, Path::new("/r/vol/x"), Some(1)),
    "and direct device evidence still decides on its own — it returns before the \
     table is consulted at all"
  );
}

/// A read that could not see the live table has witnessed nothing depart. Its
/// empty mount list is ignorance, not evidence, and it must neither cover NOR
/// clobber the baseline — the two failures are opposite and both are real. Diff
/// it and one unreadable `/proc/self/mountinfo` reports every mount under the
/// root as gone; install it and the departure that happens next is swallowed,
/// because the baseline it would have been diffed against is now empty.
#[test]
fn a_blind_refresh_is_never_a_departure() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(1));
  let _ = drain(&mut core);

  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), false), at(2));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "a non-authoritative read covers nothing"
  );

  // The baseline survived it, so a real departure is still derivable afterwards.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(3));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the blind read did not clobber the baseline, so the departure after it is \
     still covered: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));
}

/// A STALE completion is discarded whole before the table is ever consulted (the
/// module doc's publication invariant), so it can neither derive a departure nor
/// move the baseline — the same table+frame snapshot that must not install a
/// table must not install a coverage verdict either.
#[test]
fn a_stale_refresh_is_never_a_departure() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(1));
  let _ = drain(&mut core);

  // Two losses: the first arms a refresh, the second marks the in-flight one
  // stale. Their own covering Rescans are drained here.
  core.on_root_overflow(scope, at(2));
  let _ = drain(&mut core);
  core.on_root_overflow(scope, at(3));
  let _ = drain(&mut core);

  // The stale completion reports the mount gone. It is discarded whole.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(4));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "a stale snapshot's absence is not a departure"
  );

  // And the baseline is intact, so the departure the next NON-stale read sees is
  // still derivable — a stale read that had installed its table would have
  // swallowed it.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(5));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the stale read did not clobber the baseline: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));
}

/// The one profile that signals a below-root departure in band must not be
/// covered TWICE for it. `plan_mount` already planned the located cover for the
/// `UNMOUNT` word and `settle` dropped the prefix from the trust table; the
/// baseline follows that same signalled removal, so the next authoritative read
/// re-derives nothing.
#[test]
fn a_signalled_unmount_is_not_re_covered_by_the_next_refresh() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(1));
  let _ = drain(&mut core);

  core.on_batch_events(
    scope,
    vec![ev("/r/vol", FsEventFlags::UNMOUNT, 1, 0)],
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the in-band unmount covers once: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));

  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(3));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "the table read re-covers nothing the backend already announced"
  );
}

/// A KERNEL-RECURSIVE profile gets the departure cover too — every `live_core`
/// cell above is FSEvents, and each earns its `Rescan` from the diff alone.
/// The `frame_changed` replay beside it IS skipped for such a profile, and that
/// asymmetry is deliberate: the replay exists because only a DESCENDING scope
/// consumes `root_mnt_id`, whereas a departure changes what the tree CONTAINS —
/// the directory the mount was covering is readable again and its contents were
/// never enumerated — which one recursive mark leaves as unread as per-directory
/// watches do. This pins the asymmetry from the other side: the same frame
/// change that replays nothing here still covers the departure.
#[test]
fn a_kernel_recursive_frame_change_skips_its_replay_but_not_the_departure() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: vec![bare("/r/vol")],
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: Some(10),
      root_incarnation: None,
    },
    at(1),
  );
  let _ = drain(&mut core);

  // The frame CHANGED and the mount departed in the same read.
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: Vec::new(),
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: Some(11),
      root_incarnation: None,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the frame replay is skipped for a kernel-recursive scope, the departure is not: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(
    emitted[0].location(),
    &loc(&["vol"]),
    "and what survives is the LOCATED departure cover, not a root-wide replay"
  );
}

/// The BIRTH WINDOW's departure, and why the spawn seed must not be thrown away.
///
/// The spawn barrier reads the live table; the cold crawl that follows reads
/// each child's DEVICE and declines to descend beneath a foreign one. Those are
/// separate detached jobs with no start order between them, so a lazy unmount in
/// the gap leaves a subtree the crawl declined and nothing ever enumerated,
/// while the first authoritative refresh sees the prefix already gone.
///
/// With the baseline cleared at spawn, that read derives nothing AND installs
/// the post-departure frame — so no later read can derive it either, and the
/// coverage under the now-exposed directory is dead for the life of the scope.
/// Seeded, the same read covers it. Coverage was DECLINED on the strength of
/// that mount, which is exactly what makes its departure matter.
#[test]
fn a_mount_seeded_at_spawn_and_gone_by_the_first_read_is_covered() {
  let mut core = DriverCore::new(WINDOW, LIVENESS);
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents)
    .expect("a fresh scope registers");
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
      mounts: vec![bare("/r/vol")],
      declined: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    }),
  );
  let effects = drain(&mut core);
  assert_eq!(
    refresh_requests(&effects),
    1,
    "the birth refresh arms: {effects:?}"
  );
  assert!(
    !core
      .scopes
      .get(&scope)
      .expect("scope is live")
      .mounts_authoritative,
    "the seed opens NO authority — only a refresh's own read of the live table does"
  );

  // `umount -l /r/vol` between the barrier and the first authoritative read.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the birth-window departure is covered: {effects:?}"
  );
  assert!(
    emitted[0].kind().is_rescan(),
    "a departure is covered, never delivered: {emitted:?}"
  );
  assert_eq!(emitted[0].location(), &loc(&["vol"]));

  // Once, not forever: the read that covered it also became the baseline.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(1));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "the seeded departure is covered once, not on every later refresh"
  );
}

/// The seed's other direction, which is the ordinary case: a prefix still
/// mounted at the first authoritative read is no departure. Seeding costs a
/// cover only when a mount actually left during the window it covers, so the
/// conservative direction buys back no cover storms.
#[test]
fn a_mount_seeded_at_spawn_and_still_mounted_covers_nothing() {
  let mut core = DriverCore::new(WINDOW, LIVENESS);
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents)
    .expect("a fresh scope registers");
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
      mounts: vec![bare("/r/vol")],
      declined: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    }),
  );
  let _ = drain(&mut core);
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(0));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "a seed the first read confirms is no departure"
  );
}

/// A world SWAP seeds the same way, for the same reason: the replacement's own
/// covering `Rescan` does not make the seed redundant, because the
/// re-enumeration that cover obliges IS the crawl that reads a mount's foreign
/// device and declines beneath it — so it loses the identical race to a lazy
/// unmount.
///
/// Also pins that the seed OUTLIVES the commit's own stale round trip: the
/// commit arms twice (the world swap, then the trust cut), so its refresh
/// completes stale and publishes nothing, and only the read after it is the new
/// world's first authoritative one.
#[test]
fn a_mount_seeded_by_a_replace_and_gone_by_its_first_read_is_covered() {
  let (mut core, scope) = live_core();
  core.on_root_replaced(
    scope,
    RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
      mounts: vec![bare("/r/vol")],
      declined: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    },
    at(1),
  );
  let _ = drain(&mut core);

  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "the commit's self-condemned refresh publishes nothing at all"
  );

  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(3));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the replace window's departure is covered: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));
}

/// The ARRIVAL direction, which the paths-only set could only ever half-do.
///
/// A mount that APPEARS shadows ground the consumer may already have
/// enumerated: the directory it lands on had contents, and after the mount those
/// contents are a different filesystem's. That obliges the same cover a
/// departure does, which is why `compile::fsevents`' `plan_mount` plans
/// `Planned::Over(located(..))` for ANY non-root volume change rather than for
/// unmounts alone — a departures-only posture is weaker than the reference
/// profile it cites.
///
/// It matters most for the class NO seam observes: a mount created after the
/// watcher settles runs no enumerate (there is no event), no walk (spawn-only)
/// and no arm, so the table diff is its sole detector rather than a second one.
#[test]
fn an_arrived_mount_covers_its_located_subtree() {
  let (mut core, scope) = live_core();
  // Nothing was mounted at spawn, and nothing has been. Then one appears —
  // long after every crawl this scope will ever run.
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(1));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(emitted.len(), 1, "one cover per arrival: {effects:?}");
  assert!(
    emitted[0].kind().is_rescan(),
    "an arrival is covered, never delivered — a bind can make a directory \
     appear with the watched object unchanged: {emitted:?}"
  );
  assert_eq!(
    emitted[0].location(),
    &loc(&["vol"]),
    "the cover is LOCATED at the arriving mount, not the whole root"
  );
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/vol"), None, None)],
    "and the arrival is RECORDED, which is what makes its departure derivable"
  );

  // Bounded per TRANSITION, not per tick: the record the cover installed is
  // what makes every later read of the same table quiet.
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(2));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "a still-mounted row is CONFIRMED, not re-covered"
  );
}

/// The same-path REMOUNT: `umount /r/vol && mount -t tmpfs none /r/vol` between
/// two reads. The location is in both frames, so a paths-only set sees nothing
/// at all and the consumer keeps whatever it enumerated off the OLD filesystem.
///
/// Identity closes it, and the verdict is a re-record rather than a drop: the
/// mount that is there NOW is real, and dropping it would leave its own eventual
/// departure underivable — the one direction this whole mechanism exists for.
#[test]
fn a_replaced_mount_covers_and_re_records_the_new_identity() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row("/r/vol", 41, 7)], true),
    at(1),
  );
  let _ = drain(&mut core);

  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row("/r/vol", 55, 9)], true),
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "a different mount at the same location is one cover: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/vol"), Some(55), Some(9))],
    "RE-RECORDED with the new identity, not dropped: a mount is still there"
  );

  // And the re-record settles: the same identity read again is no transition.
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row("/r/vol", 55, 9)], true),
    at(3),
  );
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "the replacement is covered once, not on every later refresh"
  );

  // The replacement's own departure is derivable from the NEW record.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(4));
  let effects = drain(&mut core);
  assert_eq!(
    emits(&effects).len(),
    1,
    "the re-recorded mount's departure is still covered: {effects:?}"
  );
  assert!(
    recorded(&core, scope).is_empty(),
    "and THAT drop is a real departure"
  );
}

/// **Issue #74 over a STACK, driven from the BYTES `/proc/self/mountinfo` hands
/// back** — the same-path remount above works from hand-built rows, and a
/// hand-built frame cannot express a stack at all.
///
/// A mount MOVED onto an occupied mount point keeps its older id, so mountinfo —
/// which lists a namespace in mount creation order — prints it BEFORE the mount
/// it now hides. Every member of the stack is its own row here, so nothing has to
/// decide which of them a lookup reaches: each has its own id, and `umount -l` of
/// one is that id's departure whichever member it was.
///
/// **Several rows at one location, one cover.** The consumer re-reads a place,
/// not a vfsmount, so the covers are deduplicated by location before they lower:
/// two members arriving is one cover, one of them departing is one cover, and the
/// whole stack departing at once is one cover. What scales with the stack is the
/// census, not the consumer's work.
///
/// MUTATION WITNESS (per-location grouping restored in `parse_mountinfo`): answer
/// each location with its LAST row and this FAILS at `the departure of one member
/// is covered` with `left: 0` — the selected row byte-identical across an unmount
/// the core then cannot see, which is the silent loss itself.
/// MUTATION WITNESS (dedup dropped): remove `dedup_locations(&mut covered)` and
/// this FAILS at `two members arriving at ONE location is ONE cover` with `left:
/// 2` — one re-read of the same ground per member of the stack.
#[test]
fn a_stack_at_one_location_is_covered_once_per_transition() {
  // 55 is mounted at `/r/vol`; 20 — older, created elsewhere — is then
  // `mount --move`d on top of it, so 20's parent is 55. Creation order lists 20
  // first.
  let stacked = || {
    crate::os::linux::parse_mountinfo(
      b"20 55 0:48 / /r/vol rw,relatime shared:7 - tmpfs moved rw\n\
        36 25 0:32 / /r rw,relatime shared:1 - ext4 /dev/root rw\n\
        55 36 0:44 / /r/vol rw,relatime shared:3 - tmpfs hidden rw\n",
      Path::new("/r"),
    )
  };
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(scope, alive_refresh(stacked(), true), at(1));
  let effects = drain(&mut core);
  assert_eq!(
    emits(&effects).len(),
    1,
    "two members arriving at ONE location is ONE cover — the consumer re-reads \
     a place, not a vfsmount: {effects:?}"
  );
  assert_eq!(
    recorded(&core, scope),
    vec![
      (PathBuf::from("/r/vol"), Some(20), Some(0x30)),
      (PathBuf::from("/r/vol"), Some(55), Some(0x2c)),
    ],
    "and BOTH members are in the census, each keyed by its own id — that is \
     what makes either one's departure derivable"
  );

  // `umount -l /r/vol` detaches the moved mount and reveals the one beneath it.
  let revealed = crate::os::linux::parse_mountinfo(
    b"36 25 0:32 / /r rw,relatime shared:1 - ext4 /dev/root rw\n\
      55 36 0:44 / /r/vol rw,relatime shared:3 - tmpfs hidden rw\n",
    Path::new("/r"),
  );
  core.on_mounts_refreshed(scope, alive_refresh(revealed, true), at(2));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the departure of one member is covered — the ground it hid is now reachable \
     and nothing else will ever say so: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/vol"), Some(55), Some(0x2c))],
    "and the survivor stays recorded, so ITS departure stays derivable"
  );

  // The whole stack leaving AT ONCE is still one cover: a fresh scope, seeded
  // with both members, reading an empty table.
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(scope, alive_refresh(stacked(), true), at(1));
  let _ = drain(&mut core);
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "two departures at ONE location is ONE cover: {effects:?}"
  );
  assert_eq!(emitted[0].location(), &loc(&["vol"]));
  assert!(
    recorded(&core, scope).is_empty(),
    "and the census is empty, because both members really did leave"
  );
}

/// A mount id is allocated LOWEST-FREE, so a mount that departs and one that
/// arrives inside a single refresh window hand the newcomer the id the other
/// freed. If it also lands at the same location on the same device — a bind of
/// the same source, re-taken over a different mount — the device comparison reads
/// CONTINUITY, no cover fires, and the ground the newcomer shadows is never
/// re-read.
///
/// Field 2 is what says otherwise: the mount a row hangs off. A recycled id
/// re-attached under a different mount is a different vfsmount whatever id it
/// inherited, so reading BOTH halves turns that silent match into a replacement.
/// It NARROWS the window rather than closing it — the same id, the same parent,
/// the same location and the same device is still continuity below 6.8, where
/// `STATX_MNT_ID_UNIQUE` closes it — and narrowing costs at most one redundant
/// cover of ground that was covered anyway.
///
/// The parent is compared, never walked: nothing resolves it to another census
/// row or climbs a chain of them.
///
/// MUTATION WITNESS: drop the `identity_changed(was.parent_id, row.parent_id)`
/// disjunct from the replacement arm and this FAILS at `the re-parented mount is
/// covered` with `left: 0` — the silent match itself.
#[test]
fn a_recycled_mount_id_under_a_new_parent_is_a_replacement() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row_under("/r/vol", 41, 36, 7)], true),
    at(1),
  );
  let _ = drain(&mut core);

  // The same id at the same location on the same device, hanging off a DIFFERENT
  // mount — everything a device comparison can see is unchanged.
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row_under("/r/vol", 41, 55, 7)], true),
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the re-parented mount is covered: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));

  // Bounded per TRANSITION: the census re-recorded the new parent, so reading the
  // same table again is quiet.
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row_under("/r/vol", 41, 55, 7)], true),
    at(3),
  );
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "the replacement is covered once, not on every later refresh"
  );

  // An UNKNOWN half never reads as a difference. A host that answers no parent
  // at all (macOS, a fake, a row whose field 2 would not parse) fires nothing
  // here — the same honest degrade the device half already makes.
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row("/r/vol", 41, 7)], true),
    at(4),
  );
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "an unanswered parent is unknown, never different"
  );
}

/// CONDEMN ON A TRANSITION, NEVER ON AN ABSENCE, from the side that storms
/// without it — cell (d)'s `SameMount` half, and cell (c)'s belt half beside it.
///
/// A fence decline does not imply a mountinfo row. `crosses_mount_boundary`
/// fires on `device_boundary || mount_boundary`, so a **btrfs subvolume** inside
/// the root trips the DEVICE belt while carrying the root's own `mnt_id`. It is
/// not a vfsmount: it has no mountinfo row EVER, no read of the table will list
/// it, and `openat2(RESOLVE_NO_XDEV)` opens it without complaint.
///
/// So it never enters a census, so it transitions in none, so nothing condemns
/// it. Covering it on its ABSENCE from a read would be a permanent cover storm —
/// one cover per subvolume per tick, on every default snapper / Fedora /
/// docker-btrfs layout — and it is structurally unreachable here rather than
/// suppressed by a predicate.
///
/// The `Mount(77)` entry beside it pins the other half: a seam-observed vfsmount
/// the census never listed IS covered by the first read that does not list it,
/// and is gone from the ledger afterwards.
///
/// # Nothing here is `Unknown`, deliberately
///
/// Both entries were decided from two known ids, which is what lets the cell read
/// a LOCATED cover at all: one `Unknown` entry anywhere would put the scope in
/// the fail-closed state, where every authoritative refresh covers the whole root
/// and no located cover is emitted (see `ScopeState::fails_closed`, and the cells
/// that own that rule). So this is also the ≥5.8 evidence in miniature — a scope
/// whose every seam could answer an id pays nothing for the id-less design at
/// all.
///
/// MUTATION WITNESS (condemn on an absence): make the join drop a `SameMount`
/// entry the census did not list — `Standing::SameMount => false` with a
/// `departed.push` beside it — and the first refresh emits two covers, which
/// FAILS at `staging: the mount-backed entry is condemned, and nothing else is`.
#[test]
fn a_same_mount_entry_survives_every_refresh_untouched() {
  // The subvolume, and the shape of what re-observes it: the seams (an enumerate
  // decline, a walk, a probe answer) are the ONLY thing that ever sees one, and
  // they go on seeing it for as long as it is there.
  let subvolume = || LedgerEntry {
    location: PathBuf::from("/r/subvol"),
    standing: Standing::SameMount,
  };

  let (mut core, scope) = live_core();
  {
    let state = core.scopes.get_mut(&scope).expect("scope is live");
    state.root_mnt_id = Some(42);
    state.ledger.push(subvolume());
    // A real vfsmount seen by something that is not the table: no census has
    // keyed it, and its mount id differs from the root's, so it is the belt.
    state.ledger.push(LedgerEntry {
      location: PathBuf::from("/r/seam"),
      standing: Standing::Mount(77),
    });
  }

  // The table lists neither, and never will list the first.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(1));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "staging: the mount-backed entry is condemned, and nothing else is: {effects:?}"
  );
  assert_eq!(
    emitted[0].location(),
    &loc(&["seam"]),
    "and the cover is LOCATED — with nothing `Unknown` held, the scope is not \
     failing closed and pays no root cover at all: {emitted:?}"
  );
  assert!(
    !emitted.iter().any(|c| c.location() == &loc(&["subvol"])),
    "the SAME-MOUNT boundary covers nothing: no vfsmount can carry the root's \
     own mount id, so its absence from a census proves nothing at all: {effects:?}"
  );

  // Every later tick reads the same absent table, with the seam re-observing the
  // subvolume in between — which is the steady state on any btrfs layout, and
  // where a set that condemned on an absence would storm FOREVER: it would cover
  // and drop what the seam records straight back, once per subvolume per tick,
  // for the life of the scope.
  for tick in 2..6 {
    let state = core.scopes.get_mut(&scope).expect("scope is live");
    if !state
      .ledger
      .iter()
      .any(|held| held.location.as_path() == Path::new("/r/subvol"))
    {
      state.ledger.push(subvolume());
    }
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(tick));
    assert!(
      emits(&drain(&mut core)).is_empty(),
      "tick {tick}: a same-mount boundary is not a departure, ever — this is \
       where a per-tick storm would show"
    );
  }
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/subvol"), Some(42), None)],
    "and it survives UNTOUCHED — never joined, never condemned; the vfsmount \
     entry beside it is spent and gone"
  );
}

/// A live FANOTIFY scope: the one profile whose source admits by directory-FID
/// MEMBERSHIP, and therefore the one whose departures owe an admission round
/// trip before their cover.
///
/// `seeded` rows enter the coverage set at the SPAWN BARRIER, and that is
/// load-bearing for every cell below rather than a convenience. A row this scope
/// learns from a later refresh instead is an ARRIVAL, and an arrival fires a
/// cover at the very location a departure assertion then reads — so a cell that
/// staged its mount through the refresh would pass on the wrong signal. Seeded,
/// the first read merely CONFIRMS and covers nothing, and the only thing that can
/// ever cover the location is what the cell is about.
fn live_core_fanotify(seeded: Vec<MountRow>, root_mnt_id: Option<u64>) -> (DriverCore, ScopeId) {
  live_core_fanotify_polling(LIVENESS, seeded, root_mnt_id)
}

/// The same, with the root-liveness interval chosen by the caller —
/// `Duration::ZERO` being the supported setting that arms NO periodic tick at all,
/// so nothing but a loss or an explicitly armed read ever refreshes this scope
/// again. A cell about what converges WITHOUT a cadence needs it, or it is reading
/// the clock rather than the mechanism.
fn live_core_fanotify_polling(
  liveness: Duration,
  seeded: Vec<MountRow>,
  root_mnt_id: Option<u64>,
) -> (DriverCore, ScopeId) {
  let mut core = DriverCore::new(WINDOW, liveness);
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify)
    .expect("a fresh scope registers");
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id,
      mounts: seeded.clone(),
      declined: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::Fanotify,
    }),
  );
  let _ = drain(&mut core);
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: seeded,
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id,
      root_incarnation: None,
    },
    at(0),
  );
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "staging: the seeded rows are CONFIRMED by the first read, never arrivals"
  );
  (core, scope)
}

/// The admission requests a drain carried, as `(ticket, location, frame)`.
fn admissions(effects: &[Effect]) -> Vec<(crate::os::AdmitTicket, PathBuf, crate::os::ScopeFrame)> {
  effects
    .iter()
    .filter_map(|e| match e {
      Effect::AdmitBoundaries { requests, .. } => Some(requests),
      _ => None,
    })
    .flatten()
    .map(|request| (request.ticket, request.location.clone(), request.frame))
    .collect()
}

/// The WHOLE-ROOT RECOVERY requests `effects` asked a source for, in order — the
/// root-scope sibling of [`admissions`], and the effect the fail-closed rule and
/// the departure collapse both emit.
///
/// The whole request, not just its ticket: the frame EPOCH it is issued at rides
/// with it and the reply must echo it back, so a cell that asserts what the core
/// asked for has to be able to see it.
fn recoveries(effects: &[Effect]) -> Vec<crate::os::RecoveryRequest> {
  effects
    .iter()
    .filter_map(|e| match e {
      Effect::RecoverRoot { request, .. } => Some(*request),
      _ => None,
    })
    .collect()
}

/// The descent frame `scope` currently holds — what a reseed walking the root
/// this core still points at would read off the fd it reopened.
fn root_frame(core: &DriverCore, scope: ScopeId) -> Option<u64> {
  core.scopes.get(&scope).expect("scope is live").root_mnt_id
}

/// How many times `scope`'s descent frame has moved — the counter a round trip is
/// stamped with, and the one a reply must still carry to be applied.
fn frame_epoch(core: &DriverCore, scope: ScopeId) -> u64 {
  core.scopes.get(&scope).expect("scope is live").frame_epoch
}

/// Answers the ONE whole-root recovery `effects` asked for, as a reader does
/// once its reseed has rebuilt the map: the complete generation the walk
/// produced, the ticket cutoff it discharges, and the loss it implies, all in
/// the one message.
///
/// The reply is the CURRENT-FRAME one: the request's own epoch, echoed as a
/// reader echoes it, and the root mount id this scope still holds — what a walk
/// that reopened the same root would have read. The superseded shapes are built
/// by the cells that test them.
fn answer_one_recovery(
  core: &mut DriverCore,
  scope: ScopeId,
  effects: &[Effect],
  declined: Vec<crate::os::DeclinedBoundary>,
  now: Instant,
) -> Vec<Effect> {
  let asked = recoveries(effects);
  assert_eq!(
    asked.len(),
    1,
    "exactly one whole-root recovery was asked for: {effects:?}"
  );
  let root_mnt_id = root_frame(core, scope);
  core.on_root_recovered(
    scope,
    crate::os::RootRecovery {
      declined,
      cutoff: asked[0].ticket,
      epoch: asked[0].epoch,
      root_mnt_id,
    },
    now,
  );
  drain(core)
}

/// Answers one recovery request the caller has already CAPTURED, rather than one
/// found in an effect list.
///
/// [`answer_one_recovery`] reads its request out of the drain that produced it,
/// which is right for a cell whose next step is the reply. A cell that stages an
/// interleaving has drained several times since, and the request it wants to
/// answer is one it is holding — the whole point being that the request stayed
/// outstanding across everything in between.
fn answer_captured_recovery(
  core: &mut DriverCore,
  scope: ScopeId,
  request: crate::os::RecoveryRequest,
  declined: Vec<crate::os::DeclinedBoundary>,
  now: Instant,
) -> Vec<Effect> {
  let root_mnt_id = root_frame(core, scope);
  core.on_root_recovered(
    scope,
    crate::os::RootRecovery {
      declined,
      cutoff: request.ticket,
      epoch: request.epoch,
      root_mnt_id,
    },
    now,
  );
  drain(core)
}

/// How many covers this scope is holding PARKED on an outstanding admission.
fn parked_admits(core: &DriverCore, scope: ScopeId) -> usize {
  core
    .scopes
    .get(&scope)
    .expect("scope is live")
    .pending_admits
    .len()
}

/// Answers the ONE admission round trip `effects` opened, as the reader does
/// once its walk has put the revealed ground in the map, and returns whatever
/// the reply produced.
///
/// Every fanotify departure goes through this: on that profile the cover is
/// parked on the round trip, so a cell that only fed the refresh would read an
/// empty effect list and conclude nothing was covered.
fn answer_one_admission(
  core: &mut DriverCore,
  scope: ScopeId,
  effects: &[Effect],
  now: Instant,
) -> Vec<Effect> {
  answer_one_admission_with(core, scope, effects, crate::os::AdmitOutcome::Admitted, now)
}

/// The same, with the walk's verdict chosen by the caller — the cells that need
/// [`StillCovered`](crate::os::AdmitOutcome::StillCovered), where the walk
/// reopened the location and found the boundary is still there (a subvolume, or a
/// mount the refresh raced).
fn answer_one_admission_with(
  core: &mut DriverCore,
  scope: ScopeId,
  effects: &[Effect],
  outcome: crate::os::AdmitOutcome,
  now: Instant,
) -> Vec<Effect> {
  let requested = admissions(effects);
  assert_eq!(
    requested.len(),
    1,
    "exactly one admission round trip was opened: {effects:?}"
  );
  core.on_admitted(
    scope,
    crate::os::AdmitReport {
      ticket: requested[0].0,
      outcome,
    },
    now,
  );
  drain(core)
}

/// #74's fanotify half, and the ordering the whole stage exists for: a departed
/// mount's cover is PARKED on an admission round trip and reaches the consumer
/// only once the source can actually see the ground it is being sent to re-read.
///
/// fanotify's map admits by directory-handle membership and its seed walk stops
/// AT a mount, so the subtree a departure reveals has no handles in it at all.
/// A located `Rescan` alone would tell the consumer to re-enumerate ground the
/// reader still drops every event on — with no loss signal, since an unknown
/// handle is "provably outside the root" — and no crawl would ever repair it
/// (`Monitor::start_rearm` refuses a non-descending scope outright). So the
/// cover waits.
#[test]
fn a_fanotify_departure_parks_its_cover_until_admission_completes() {
  let (mut core, scope) = live_core_fanotify(vec![row("/r/vol", 77, 9)], Some(42));

  // `umount -l /r/vol`: the row leaves the table and the kernel says nothing.
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: Vec::new(),
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: Some(42),
      root_incarnation: None,
    },
    at(1),
  );
  let effects = drain(&mut core);
  assert!(
    emits(&effects).is_empty(),
    "NOTHING is emitted at the verdict: covering here would send the consumer \
     to re-read ground the source is still blind to: {effects:?}"
  );
  let requested = admissions(&effects);
  assert_eq!(
    requested.len(),
    1,
    "one admission round trip per departed boundary: {effects:?}"
  );
  assert_eq!(requested[0].1, PathBuf::from("/r/vol"));
  assert_eq!(
    requested[0].2,
    crate::os::ScopeFrame {
      root_dev: Some(1),
      root_mnt_id: Some(42),
    },
    "and it carries the scope's CURRENT frame — what the walk refuses a \
     still-covered location against"
  );
  assert_eq!(parked_admits(&core, scope), 1, "the cover is parked on it");
  assert!(
    recorded(&core, scope).is_empty(),
    "the record left the set with the verdict, so no later refresh re-derives \
     the same departure and parks a second round trip"
  );

  // The reader walked the revealed ground into the map and answered.
  core.on_admitted(
    scope,
    crate::os::AdmitReport {
      ticket: requested[0].0,
      outcome: crate::os::AdmitOutcome::Admitted,
    },
    at(2),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "and NOW the cover goes out, exactly once: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(
    emitted[0].location(),
    &loc(&["vol"]),
    "located at the departed mount, not the whole root"
  );
  assert_eq!(parked_admits(&core, scope), 0, "and the round trip retires");
}

/// Cell (e): a location the walk finds STILL COVERED is a SEAM OBSERVATION of
/// whatever is standing there — recorded on its own terms, covering nothing — and
/// the next read that does not list it covers it.
///
/// Nothing was revealed, so the consumer has no new ground to read: `crossed_by`
/// refused because a boundary is at the location, and the ground beneath it is as
/// hidden as it was before the mount left. What the walk DID produce is an
/// identity read off the fd it pinned, and that is exactly what a decline or a
/// probe answer produces — so it goes through `record_boundary`, which decides
/// its `Standing` from the two ids and holds it as the belt for the window before
/// the next census.
///
/// A live boundary that is not recorded has no derivable departure ever again,
/// which is why the answer carries what the walk read at all. The second half of
/// this cell is that derivation.
///
/// MUTATION WITNESS (cover on the refusal): emit `mount_cover` from the
/// `StillCovered` arm and this FAILS at `nothing was revealed, so nothing is
/// covered`.
/// MUTATION WITNESS (record nothing): drop the `record_boundary` call and this
/// FAILS at `and the boundary is in the LEDGER` — and, one refresh later, at `the
/// entry the walk left is the belt`, which is the coverage the finding costs.
#[test]
fn a_still_covered_admission_records_what_the_walk_read_and_covers_nothing() {
  let (mut core, scope) = live_core_fanotify(vec![row("/r/vol", 77, 9)], Some(42));
  let refresh = |mounts: Vec<MountRow>| MountRefresh {
    mounts,
    authoritative: true,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    root_mnt_id: Some(42),
    root_incarnation: None,
  };

  core.on_mounts_refreshed(scope, refresh(Vec::new()), at(1));
  let first = admissions(&drain(&mut core));
  assert_eq!(first.len(), 1, "staging: the departure parks its cover");

  core.on_admitted(
    scope,
    crate::os::AdmitReport {
      ticket: first[0].0,
      // What the walk read off the fd it pinned: a boundary whose mount id
      // differs from the root's, standing where the census said nothing is.
      outcome: crate::os::AdmitOutcome::StillCovered {
        dev: Some(9),
        mnt_id: Some(77),
      },
    },
    at(2),
  );
  let effects = drain(&mut core);
  assert!(
    emits(&effects).is_empty(),
    "nothing was revealed, so nothing is covered — the ground under the boundary \
     the walk found is as hidden as it was: {effects:?}"
  );
  assert_eq!(parked_admits(&core, scope), 0, "and the round trip retires");
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/vol"), Some(77), None)],
    "and the boundary is in the LEDGER, with the identity the walk read"
  );

  // The derivation the recording bought. No census has ever keyed 77, so this
  // read's join is the one place its departure was ever derivable.
  core.on_mounts_refreshed(scope, refresh(Vec::new()), at(3));
  let effects = drain(&mut core);
  let parked = admissions(&effects);
  assert_eq!(
    parked.len(),
    1,
    "the entry the walk left is the belt: the first read that does not list its \
     id derives the departure: {effects:?}"
  );
  assert_eq!(parked[0].1, PathBuf::from("/r/vol"));
  assert!(
    recorded(&core, scope).is_empty(),
    "and the entry is spent — derived once, never twice"
  );
}

/// **R10 F2, the core half.** An admission round trip is opened against the
/// descent frame in force when the departure is PARKED and answered arbitrarily
/// later. Everything the reply can still ask for is relative to that frame — which
/// record goes back, and whether a located cover may be released — so a root that
/// re-mounted in between makes the answer about a world this scope has left.
///
/// The sequence is the mount-id recycling one, spelled as the kernel allocates:
/// ids are LOWEST-FREE, so the departure that frees `/r/vol`'s id 77 hands it
/// straight to the root's own same-object re-mount. The reply then carries the
/// identity the walk read against the OLD root id 42, and deciding a `Standing`
/// from it under the NEW frame answers a question about a world this scope has
/// left.
///
/// The whole-root recovery is the answer instead, and it is the same answer the
/// departure COLLAPSE gives for the same reason: its reseed walks from the root
/// and reads its fence from the fd it reopens, so it is on the CURRENT frame by
/// construction; its complete generation re-records every boundary still live; and
/// its root cover dominates the located one this round trip was holding.
///
/// The executor's own refusal is the other half and covers the requests that had
/// not run yet (`a_revealed_walk_refuses_a_request_whose_frame_the_root_no_longer_has`);
/// this covers the ones that had.
///
/// **R15 F3.** And the recovery is asked for ONCE, by whichever site first finds
/// the need unserved. The refresh that moved the frame already sees this ticket
/// parked across worlds and asks on the strength of it, with a cutoff that
/// subsumes the ticket; this reply can arrive after that. The arm used to
/// overwrite `pending_recovery` unconditionally, making a source that had already
/// begun the first reseed owe a second whole-root walk and a second report — and
/// at the supported boundary budget of one, the second report kills a source with
/// nothing wrong with it.
///
/// MUTATION WITNESS (epoch check removed): drop the `pending_admits[index].epoch
/// != state.frame_epoch` branch from `on_admitted` and this FAILS at `and NOT by
/// the located cover it was holding` — the reply answered on its own terms, the
/// located cover out and the stale-id record back in the set.
/// MUTATION WITNESS (epoch never bumped): delete the `frame_changed` bump in
/// `on_mounts_refreshed` and this FAILS at `staging: the refresh that moved the
/// frame asks` with `left: 0, right: 1` — the check is intact but nothing ever
/// makes it fire, which is the half a cell written only against `on_admitted`
/// would miss.
/// MUTATION WITNESS (overwrite unconditionally, the R15 F3 shape): drop the
/// `state.owes_whole_root()` guard from `on_admitted`'s superseded arm, leaving a
/// bare `request_root_recovery`, and this FAILS at `and the reply itself asks for
/// nothing further` carrying a second `RecoverRoot` — a duplicate whole-root walk
/// queued behind one already running.
#[test]
fn an_admission_answered_after_the_frame_moved_recovers_the_whole_root() {
  let (mut core, scope) = live_core_fanotify(vec![row("/r/vol", 77, 9)], Some(42));
  let refresh = |root_mnt_id: u64| MountRefresh {
    mounts: Vec::new(),
    authoritative: true,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    root_mnt_id: Some(root_mnt_id),
    root_incarnation: None,
  };

  // `umount -l /r/vol` frees mount id 77 and parks the departure's cover.
  core.on_mounts_refreshed(scope, refresh(42), at(1));
  let parked = admissions(&drain(&mut core));
  assert_eq!(parked.len(), 1, "staging: the departure parks its cover");
  assert_eq!(
    parked[0].2,
    crate::os::ScopeFrame {
      root_dev: Some(1),
      root_mnt_id: Some(42),
    },
    "staging: the request carries the frame in force when it was parked"
  );

  // The root is unmounted and re-bound at its own path — same object, so the
  // death gate passes — and takes the id the departure just freed.
  core.on_mounts_refreshed(scope, refresh(77), at(2));
  let moved = drain(&mut core);
  assert!(
    emits(&moved).is_empty(),
    "staging: the re-mount itself covers nothing; the parked round trip is still \
     the only thing outstanding"
  );
  let standing = recoveries(&moved);
  assert_eq!(
    standing.len(),
    1,
    "staging: the refresh that moved the frame asks — it can SEE the ticket \
     parked across worlds, which is the whole of the need: {moved:?}"
  );
  assert_eq!(
    standing[0].epoch,
    frame_epoch(&core, scope),
    "staging: and asks in the world it just published"
  );

  // The reply the reader sent before any of that: the walk found the boundary
  // still standing, and read the identity the record already carried.
  core.on_admitted(
    scope,
    crate::os::AdmitReport {
      ticket: parked[0].0,
      outcome: crate::os::AdmitOutcome::StillCovered {
        dev: Some(9),
        mnt_id: Some(42),
      },
    },
    at(3),
  );
  let effects = drain(&mut core);
  assert!(
    recoveries(&effects).is_empty(),
    "and the reply itself asks for nothing further: a reply from a SUPERSEDED \
     frame discharges into the whole-root recovery, and the one that is already \
     out carries a cutoff that subsumes this very ticket — a second request buys \
     a second whole-root walk and, at a boundary budget of one, a second report \
     that kills the source: {effects:?}"
  );
  assert!(
    emits(&effects).is_empty(),
    "and NOT by the located cover it was holding — the recovery carries the root \
     cover on its own reply, after the reseed that makes the ground visible: \
     {effects:?}"
  );
  assert!(
    recorded(&core, scope).is_empty(),
    "nor is the condemned record put back: it would carry mount id 42, which is \
     no longer any root's, and the rebase that repairs such a record has already \
     run past it. The recovery's own generation re-records whatever is still live."
  );
  assert_eq!(
    parked_admits(&core, scope),
    0,
    "the round trip is discharged either way — a cover no reply will ever \
     release is the one thing this must not leave behind"
  );

  // And the ONE recovery that was asked for carries the cover, for the ground
  // this reply's located cover would have named and for the rest of the root.
  let released = answer_one_recovery(&mut core, scope, &moved, Vec::new(), at(4));
  assert!(
    emits(&released)
      .iter()
      .any(|change| change.kind().is_rescan()),
    "the standing recovery's own reply covers the root: nothing was dropped by \
     declining to ask twice: {released:?}"
  );
}

/// **R15 F3, the other direction.** The same arm still ASKS when nothing is
/// serving the need — and it decides that while the ticket is still PARKED,
/// because the parked ticket is the need's only witness.
///
/// The recovery the frame-moving refresh asked for is resolved here with no
/// source to take it ([`DriverCore::on_recovery_unreachable`]): the round trip
/// ends, but nothing reseeded, so the map still cannot see the ground the
/// departure revealed and the reply that then arrives is owed a fresh request.
///
/// Deriving that AFTER the retire is the trap: `owes_whole_root` reads the parked
/// set, this ticket is the only entry in it that crosses a world, and an arm that
/// retired it first would read its own emptied set and conclude nothing is owed —
/// the cadence rule's first shape (a derivation cannot see evidence that was
/// DISCARDED), on a set this very arm had just emptied.
///
/// MUTATION WITNESS (retire before judging): move `state.pending_admits.remove(index)`
/// above `on_admitted`'s `if state.owes_whole_root()` block and this FAILS at `the
/// arm asks: nothing is serving the need` with `left: 0, right: 1` — the cover
/// dropped and no reseed ever asked for, on a scope with no tick to save it.
/// MUTATION WITNESS (never ask): delete that block and it FAILS at the same site
/// with the same values.
#[test]
fn an_admission_answered_with_no_recovery_standing_asks_for_one() {
  // No tick: every request in this cell is one some site explicitly made.
  let (mut core, scope) =
    live_core_fanotify_polling(Duration::ZERO, vec![row("/r/vol", 77, 9)], Some(42));
  let refresh = |root_mnt_id: u64| MountRefresh {
    mounts: Vec::new(),
    authoritative: true,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    root_mnt_id: Some(root_mnt_id),
    root_incarnation: None,
  };

  core.on_mounts_refreshed(scope, refresh(42), at(1));
  let parked = admissions(&drain(&mut core));
  assert_eq!(parked.len(), 1, "staging: the departure parks its cover");

  core.on_mounts_refreshed(scope, refresh(77), at(2));
  assert_eq!(
    recoveries(&drain(&mut core)).len(),
    1,
    "staging: the moved frame asks for the recovery the parked ticket owes"
  );

  // No source took it: the round trip ends having reseeded nothing.
  core.on_recovery_unreachable(scope, at(3));
  let _ = drain(&mut core);

  core.on_admitted(
    scope,
    crate::os::AdmitReport {
      ticket: parked[0].0,
      outcome: crate::os::AdmitOutcome::Admitted,
    },
    at(4),
  );
  let effects = drain(&mut core);
  assert_eq!(
    recoveries(&effects).len(),
    1,
    "the arm asks: nothing is serving the need, and the ticket it is about to \
     retire is the only thing that says the need exists — judged while it is \
     still parked, or the derivation reads a set this arm had just emptied: \
     {effects:?}"
  );
  assert_eq!(
    parked_admits(&core, scope),
    0,
    "and the ticket is retired all the same: its one reply has come"
  );
  assert!(
    emits(&effects).is_empty(),
    "no located cover: the record belongs to a world this scope has left: {effects:?}"
  );
}

/// A `StillCovered` says a boundary is standing at the location — never that the
/// SAME boundary is. Believe the identity the walk read and the state converges;
/// believe the identity that departed and it never does.
///
/// The shape is ordinary and this cell is it end to end: a real mount ON TOP OF a
/// btrfs subvolume. The mount owns a mountinfo row, so a census keys it; when it
/// departs, the walk re-opens the location and finds the SUBVOLUME — another
/// device, the ROOT's own mount id, and no table row ever. `crossed_by` fires on
/// the device leg, so the answer is `StillCovered`, and recording the DEPARTED
/// mount's identity there would make every later authoritative refresh find that
/// id absent, derive the departure again, park another admission, get the same
/// answer, and start over: one round trip per tick, for the life of the scope.
///
/// **A cell that only checked the recording would pass with the defect present**,
/// which is why the assertion that matters is the SECOND refresh deriving
/// nothing. Convergence is the property.
///
/// MUTATION WITNESS (read the walk's two equal ids as a mount): drop the
/// `SameMount` arm from `Standing::decide` so two known ids that AGREE decide
/// `Mount` like any others, and this FAILS at `the state CONVERGES` with `left:
/// 1, right: 0` — the second identical refresh deriving the same departure
/// again, which is the storm itself.
#[test]
fn a_mount_departing_off_a_subvolume_converges_to_the_boundary_beneath_it() {
  // The mount that is about to depart: its own id, its own device.
  let (mut core, scope) = live_core_fanotify(vec![row("/r/sub", 77, 5)], Some(42));
  let refresh = |mounts: Vec<MountRow>| MountRefresh {
    mounts,
    authoritative: true,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    root_mnt_id: Some(42),
    root_incarnation: None,
  };

  core.on_mounts_refreshed(scope, refresh(Vec::new()), at(1));
  let effects = drain(&mut core);
  let requested = admissions(&effects);
  assert_eq!(
    requested.len(),
    1,
    "staging: the row left the table, so the departure is derived and its cover \
     parks: {effects:?}"
  );

  core.on_admitted(
    scope,
    crate::os::AdmitReport {
      ticket: requested[0].0,
      // What the walk found once the mount was gone: the subvolume it had been
      // sitting on. Another device — so `crossed_by` refuses the reseed — and the
      // ROOT's own mount id, which is what says no table row will ever list it.
      outcome: crate::os::AdmitOutcome::StillCovered {
        dev: Some(9),
        mnt_id: Some(42),
      },
    },
    at(2),
  );
  let effects = drain(&mut core);
  assert!(
    emits(&effects).is_empty(),
    "the ground is still hidden, so nothing is covered: {effects:?}"
  );
  // Read now, asserted BELOW the convergence: what the ledger holds is the
  // MECHANISM, and the convergence is what the finding costs, so the storm has to
  // trip on the storm rather than on a readout a later refactor could weaken.
  let recorded_after_reply = recorded(&core, scope);

  // THE ASSERTION. The same authoritative table, again: the entry is
  // `SameMount`, so it joins no census and the read derives nothing at all. With
  // the DEPARTED mount's identity recorded in its place this is a second
  // departure and a second round trip — and then a third, and a fourth.
  core.on_mounts_refreshed(scope, refresh(Vec::new()), at(3));
  let effects = drain(&mut core);
  assert_eq!(
    admissions(&effects).len(),
    0,
    "the state CONVERGES: a second authoritative refresh over the same table \
     derives no departure at all: {effects:?}"
  );
  assert!(
    emits(&effects).is_empty(),
    "and emits nothing — not a located cover, and not the whole-root cover a \
     scope holding an `Unknown` entry would owe: {effects:?}"
  );

  // A third, because "converges" is a claim about every later refresh and not
  // about the next one.
  core.on_mounts_refreshed(scope, refresh(Vec::new()), at(4));
  let effects = drain(&mut core);
  assert!(
    admissions(&effects).is_empty() && emits(&effects).is_empty(),
    "and it stays converged: {effects:?}"
  );
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/sub"), Some(42), None)],
    "with the boundary still recorded, so a seam that later observes it change \
     has something to change"
  );
  assert_eq!(
    recorded_after_reply,
    recorded(&core, scope),
    "and what the reply recorded is what is still standing: the boundary that is \
     THERE — the subvolume the walk read off its own fd, not the mount that \
     departed"
  );
}

/// The ladder's loss rung, from the CORE's side. The scoped walk failed twice, so
/// the reader fell back to the whole-map reseed and answered with the one
/// indivisible [`RootRecovery`](crate::os::RootRecovery) — the reseed's complete
/// generation, the ticket cutoff, and the loss — instead of three separable
/// messages ending in a `Covered` reply.
///
/// **The generation and the discharge arrive together, and that is the point.**
/// The three-message shape let the reply retire the parked record while the
/// generation that would have re-recorded a still-live boundary went missing, so
/// this cell asserts BOTH halves off the one message: the ticket is discharged
/// AND the boundary the reseed re-declined is back in the coverage set.
///
/// MUTATION WITNESS (discharge): make the cutoff exclusive (`>=` instead of `>`
/// in the retain) and this FAILS at `the recovery discharges the parked round
/// trip` with `left: 1, right: 0`.
/// MUTATION WITNESS (evidence): drop the `record_declined` call from
/// `on_root_recovered` and it FAILS at `the recovery's generation re-records what
/// is still live` with an empty left — the exact silent-blindness shape F3 named,
/// since nothing would then derive that boundary's next departure.
#[test]
fn a_root_recovery_discharges_the_parked_ticket_and_restores_the_witness() {
  let (mut core, scope) = live_core_fanotify(vec![row("/r/vol", 77, 9)], Some(42));
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: Vec::new(),
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: Some(42),
      root_incarnation: None,
    },
    at(1),
  );
  let requested = admissions(&drain(&mut core));
  assert_eq!(requested.len(), 1, "staging");
  assert_eq!(
    parked_admits(&core, scope),
    1,
    "staging: the cover is parked"
  );

  core.on_root_recovered(
    scope,
    crate::os::RootRecovery {
      // The reseed re-declined it: the mount is still there after all.
      declined: vec![crate::os::DeclinedBoundary {
        location: PathBuf::from("/r/vol"),
        dev: 9,
        mnt_id: Some(77),
      }],
      cutoff: requested[0].0,
      // The current-frame reply: nothing has moved this scope's frame since the
      // round trip opened, and the reseed reopened the root the core still holds.
      epoch: frame_epoch(&core, scope),
      root_mnt_id: root_frame(&core, scope),
    },
    at(2),
  );
  let effects = drain(&mut core);
  assert_eq!(
    parked_admits(&core, scope),
    0,
    "the recovery discharges the parked round trip — by CUTOFF, with no reply of \
     its own: {effects:?}"
  );
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/vol"), Some(77), None)],
    "the recovery's generation re-records what is still live, so its next \
     departure is still derivable — the witness a dropped report would have lost"
  );
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "and it covers, once, at ROOT scope: {effects:?}"
  );
  assert_eq!(
    emitted[0].location(),
    &loc(&[]),
    "the whole root, which dominates every located cover it stood in for: \
     {emitted:?}"
  );
}

/// A departure burst large enough to COLLAPSE — the natural way this core mints a
/// whole-root recovery, and the shape the reader's own fold answers.
///
/// Sixty-five boundaries, one past the pending-admission bound, so one refresh
/// that finds the table empty condemns more than the bound allows and the whole
/// run becomes ONE recovery instead of a located walk each. Every one of them is
/// a distinct census key, so every one really is a departure transition and the
/// collapse is reached on evidence rather than on a shortcut.
fn collapsing_burst() -> Vec<MountRow> {
  (0..=(MAX_PENDING_ADMITS as u64))
    .map(|n| row(&format!("/r/m{n}"), 200 + n, 9))
    .collect()
}

/// A whole-root reseed's generation as this suite spells it: one PROVEN subvolume
/// (the root's own mount id, a foreign device, and no table row ever).
///
/// Proven rather than mount-backed on purpose. It is exempt from condemnation and
/// from the fail-closed rule alike, so a refresh AFTER a recovery installs it is
/// silent — which is what lets a cell tell "the generation was installed" from
/// "the state kept churning".
fn reseed_generation() -> Vec<crate::os::DeclinedBoundary> {
  vec![crate::os::DeclinedBoundary {
    location: PathBuf::from("/r/subvol"),
    dev: 99,
    mnt_id: Some(42),
  }]
}

/// **R12 F1, the EPOCH leg.** A recovery whose reseed walked a root this scope has
/// since turned over TWICE publishes nothing — even though the mount id it reports
/// is, digit for digit, the id the scope holds now.
///
/// Mount ids are allocated LOWEST-FREE, so the id a root gives up on an unmount is
/// exactly the one the next mount at that path takes. The walk fenced against
/// mount 42; that mount died; the root came back as 77 and then, on the next
/// turn, as a THIRD mount that took 42 again. Two different mounts, one id, and
/// nothing in an id comparison can tell them apart — which is precisely what
/// [`ScopeState::frame_epoch`] exists for: it counts WORLDS, core-side, and no
/// reading of an id from another moment can make it agree.
///
/// What the stale generation would do if installed is the finding: it describes
/// where coverage ended under a root that is gone, so the boundaries the live root
/// actually has are retired by a walk that never looked at them, and the cover
/// riding with it tells the consumer to re-read ground this source's map may not
/// hold.
///
/// The tail is the convergence half, and it is why the rejection is not just a
/// refusal: the debt rides the mount refresh the mismatch arms, that refresh
/// stamps the fresh request with the frame it just published, and THAT reply is
/// applied. The second refresh is then silent — a cell that stopped at the first
/// cover could not tell a converged state from one that keeps re-deriving.
///
/// MUTATION WITNESS (epoch leg dropped): remove `recovery.epoch !=
/// state.frame_epoch` from `on_root_recovered`'s disjunction and this FAILS at
/// `the superseded generation is NOT installed` — the walked id matches, so the
/// id leg passes it through and only the epoch stands between a dead mount's map
/// and the live root's coverage set.
/// MUTATION WITNESS (the epoch never moves): delete the `frame_changed` bump in
/// `on_mounts_refreshed` and it FAILS at the same site with the same values — the
/// check is intact but nothing ever makes it fire, which is the half a cell
/// written only against `on_root_recovered` would miss.
#[test]
fn a_recovery_from_a_world_two_turns_back_publishes_nothing_and_converges() {
  let (mut core, scope) = live_core_fanotify(collapsing_burst(), Some(42));
  let refresh = |root_mnt_id: u64| MountRefresh {
    mounts: Vec::new(),
    authoritative: true,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    root_mnt_id: Some(root_mnt_id),
    root_incarnation: None,
  };

  // The burst collapses into ONE recovery, issued against mount 42.
  core.on_mounts_refreshed(scope, refresh(42), at(1));
  let effects = drain(&mut core);
  let asked = recoveries(&effects);
  assert_eq!(
    asked.len(),
    1,
    "staging: the burst collapsed into one whole-root recovery: {effects:?}"
  );
  assert!(
    admissions(&effects).is_empty(),
    "staging: and into NOTHING located — the recovery subsumes them: {effects:?}"
  );
  assert_eq!(
    asked[0].epoch,
    frame_epoch(&core, scope),
    "staging: stamped with the frame in force when it was issued"
  );

  // The root turns over twice while that reseed is out, and the second turn takes
  // back the id the first one freed. Each turn leaves the outstanding round trip
  // ISSUED IN A WORLD THIS SCOPE HAS LEFT, which is a fact about the scope's own
  // state rather than about any reply — so each turn re-asks, stamped with the
  // world it will be judged in. That is not a spin: it is one request per world
  // change, and a world change is the thing that invalidated the last one.
  core.on_mounts_refreshed(scope, refresh(77), at(2));
  let turning = drain(&mut core);
  core.on_mounts_refreshed(scope, refresh(42), at(3));
  let turned = drain(&mut core);
  assert!(
    emits(&turning).is_empty() && emits(&turned).is_empty(),
    "staging: the turnover itself covers nothing — the collapse already took \
     every record: {turning:?} {turned:?}"
  );
  let live = recoveries(&turned);
  assert_eq!(
    recoveries(&turning).len(),
    1,
    "staging: the first turn re-asks — the round trip it left behind can never \
     be applied here: {turning:?}"
  );
  assert_eq!(live.len(), 1, "staging: and so does the second: {turned:?}");
  assert_eq!(
    live[0].epoch,
    frame_epoch(&core, scope),
    "staging: stamped with the world it will be judged in"
  );
  assert_eq!(
    root_frame(&core, scope),
    Some(42),
    "staging: and the scope is back on the very id the outstanding walk fenced \
     against"
  );

  // The reply from the FIRST world, at last.
  core.on_root_recovered(
    scope,
    crate::os::RootRecovery {
      declined: reseed_generation(),
      cutoff: asked[0].ticket,
      epoch: asked[0].epoch,
      root_mnt_id: Some(42),
    },
    at(4),
  );
  let effects = drain(&mut core);
  assert!(
    recorded(&core, scope).is_empty(),
    "the superseded generation is NOT installed: it says where coverage ended \
     under a mount that is gone, and this scope's set is relative to the one \
     standing there now"
  );
  assert!(
    emits(&effects).is_empty(),
    "and NOTHING covers on it: a root cover here promises the consumer that a \
     map built in another world holds the ground it is about to re-read: \
     {effects:?}"
  );
  assert!(
    recoveries(&effects).is_empty(),
    "nor is a fresh one asked for ON THE SPOT — that is the reseed-per-turn \
     spin, since a walk repeated now reads exactly what this one did: {effects:?}"
  );
  assert_eq!(
    refresh_requests(&effects),
    0,
    "nor is a read armed: the disagreement is the EPOCH alone — this scope is \
     already on the very id the walk fenced against — and a round trip issued in \
     the world it still holds is standing, whose reply carries the generation, \
     the cutoff and the cover together. The only thing a read could do here is \
     move the frame out from under THAT request and refuse it too, which is the \
     cycle rather than a step out of it: {effects:?}"
  );

  // That refresh asks for NOTHING MORE, and that is the anti-duplicate half of
  // the same rule: a round trip issued in the world this scope still holds will
  // come back carrying the generation, the cutoff and the cover, so a second
  // request buys a duplicate whole-root walk and nothing else.
  core.on_mounts_refreshed(scope, refresh(42), at(5));
  let effects = drain(&mut core);
  assert!(
    recoveries(&effects).is_empty(),
    "a live request in THIS world already covers the need — asking again would \
     buy a second whole-root walk for one obligation: {effects:?}"
  );

  // Convergence: the request the last turnover minted is answered in the world it
  // was asked in, and it publishes everything the superseded reply could not.
  let effects = answer_one_recovery(&mut core, scope, &turned, reseed_generation(), at(6));
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "and THAT reply is applied: the cover the first one was carrying is still \
     owed, and this is where it goes out: {effects:?}"
  );
  assert_eq!(emitted[0].location(), &loc(&[]), "over the whole root");
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/subvol"), Some(42), None)],
    "with the generation installed this time"
  );

  // The SECOND refresh, which is where a state that only looked settled shows.
  core.on_mounts_refreshed(scope, refresh(42), at(7));
  let settled = drain(&mut core);
  assert!(
    emits(&settled).is_empty()
      && recoveries(&settled).is_empty()
      && admissions(&settled).is_empty(),
    "the state CONVERGES: the debt was discharged once, and an identical \
     refresh now derives nothing at all: {settled:?}"
  );
}

/// **R12 F1, the WALKED-ID leg.** A recovery whose reseed reopened the root and
/// found a DIFFERENT mount than the core still holds publishes nothing — even
/// though the core's own epoch has not moved, because the core is the party that
/// has not caught up.
///
/// This is the half no core-side counter can see. The reseed runs on the reader
/// thread and re-reads the root's frame off the fd it reopens; the mount refresh
/// runs on the blocking pool and is what moves `root_mnt_id`. Nothing orders the
/// two, so the walk can observe a re-mount the core has not ingested — and with
/// the supported ZERO root-liveness interval there may be no later refresh to
/// ingest it at all. The generation would then sit in the set describing a frame
/// this scope never adopted, permanently.
///
/// The reply's id is therefore read as evidence about the SOURCE's world, which
/// is exactly the fact the core cannot re-derive.
///
/// MUTATION WITNESS (id leg dropped): remove the `walked_elsewhere` disjunct from
/// `on_root_recovered` and this FAILS at `a generation from a root this scope has
/// not adopted is NOT installed` — the epoch matches, so nothing else is looking.
/// MUTATION WITNESS (the debt asked on the spot): re-request the recovery inside
/// the mismatch branch instead of arming for it and this FAILS at `and NOT
/// another walk against the frame that was just rejected` — the reseed-per-turn
/// spin, since the repeat walk reads the very id this one did.
///
/// The unknown-passes half of the same comparison has its own cell
/// ([`a_recovery_with_no_walked_mount_id_is_judged_on_its_epoch_alone`]), where a
/// `None` leg is what a strict `!=` would reject.
#[test]
fn a_recovery_that_walked_a_root_the_core_has_not_adopted_publishes_nothing() {
  let (mut core, scope) = live_core_fanotify(collapsing_burst(), Some(42));
  let refresh = |root_mnt_id: u64| MountRefresh {
    mounts: Vec::new(),
    authoritative: true,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    root_mnt_id: Some(root_mnt_id),
    root_incarnation: None,
  };

  core.on_mounts_refreshed(scope, refresh(42), at(1));
  let effects = drain(&mut core);
  let asked = recoveries(&effects);
  assert_eq!(
    asked.len(),
    1,
    "staging: one collapsed recovery: {effects:?}"
  );

  // The reseed reopened the root and found mount 77 there. No refresh has run, so
  // this core still believes 42 and its epoch has not moved.
  assert_eq!(
    asked[0].epoch,
    frame_epoch(&core, scope),
    "staging: the core's own stamp still matches — the epoch leg cannot fire \
     here, so this cell reads the walked id and nothing else"
  );
  core.on_root_recovered(
    scope,
    crate::os::RootRecovery {
      declined: reseed_generation(),
      cutoff: asked[0].ticket,
      epoch: asked[0].epoch,
      root_mnt_id: Some(77),
    },
    at(2),
  );
  let effects = drain(&mut core);
  assert!(
    recorded(&core, scope).is_empty(),
    "a generation from a root this scope has not adopted is NOT installed: the \
     coverage set is relative to a frame this walk was not taken on"
  );
  assert!(
    emits(&effects).is_empty(),
    "and it covers nothing: {effects:?}"
  );
  assert_eq!(
    refresh_requests(&effects),
    1,
    "the answer is a mount refresh — the core is the stale party here, and an \
     authoritative re-read is the only thing that moves its frame: {effects:?}"
  );
  assert!(
    recoveries(&effects).is_empty(),
    "and NOT another walk against the frame that was just rejected: {effects:?}"
  );

  // That refresh lands on what the source already saw, and carries the debt.
  core.on_mounts_refreshed(scope, refresh(77), at(3));
  let effects = drain(&mut core);
  let again = recoveries(&effects);
  assert_eq!(again.len(), 1, "the owed recovery goes out: {effects:?}");
  let effects = answer_one_recovery(&mut core, scope, &effects, reseed_generation(), at(4));
  assert_eq!(
    emits(&effects).len(),
    1,
    "and the reply from the world the two now share IS applied: {effects:?}"
  );

  core.on_mounts_refreshed(scope, refresh(77), at(5));
  let settled = drain(&mut core);
  assert!(
    emits(&settled).is_empty() && recoveries(&settled).is_empty(),
    "the state CONVERGES rather than trading a reseed per turn: {settled:?}"
  );
}

/// **R12 F1, the honest degrade.** A recovery from a host that reports NO root
/// mount id is judged on its epoch alone — the `None`-passes rule every other
/// unknown leg of [`ScopeFrame::crossed_by`](crate::os::ScopeFrame) follows.
///
/// Below Linux 5.8 there is no `STATX_MNT_ID` at all, so a walk answers no frame
/// and the core holds none either; on the 5.17 fanotify floor the mask bit can
/// still come back unset, which leaves a scope that knows its own id reading a
/// report that does not. Treating unknown as "different" would reject every
/// recovery such a pairing can ever produce — and since a repeat walk reports the
/// same nothing, the rejection would never clear: a permanent whole-root reseed
/// per refresh, which is the cost this whole design is built to bound.
///
/// So both phases are here, in the order they occur, and each pins one leg:
/// UNKNOWN cannot be what rejects, and with the id silent the EPOCH is the only
/// thing left doing the checking.
///
/// MUTATION WITNESS (unknown read as different): replace the `matches!` in
/// `on_root_recovered` with `recovery.root_mnt_id != state.root_mnt_id` and this
/// FAILS at `an id-less report on the CURRENT epoch is applied` with `left: [],
/// right: [("/r/subvol", Some(42), Some(99))]` — a host that cannot report a
/// mount id locked out of recovering at all.
/// MUTATION WITNESS (epoch leg dropped): remove `recovery.epoch !=
/// state.frame_epoch` from the same disjunction and it FAILS at `an id-less
/// report is checked by the EPOCH` — with the id silent, nothing else is
/// looking, and a generation from the previous world walks straight in.
#[test]
fn a_recovery_with_no_walked_mount_id_is_judged_on_its_epoch_alone() {
  let (mut core, scope) = live_core_fanotify(collapsing_burst(), Some(42));
  let refresh = |root_mnt_id: u64| MountRefresh {
    mounts: Vec::new(),
    authoritative: true,
    root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
    root_mnt_id: Some(root_mnt_id),
    root_incarnation: None,
  };
  let idless_reply = |asked: &crate::os::RecoveryRequest| crate::os::RootRecovery {
    declined: reseed_generation(),
    cutoff: asked.ticket,
    epoch: asked.epoch,
    // The walk ran and completed; the kernel simply answered no mount id for the
    // root it reopened. That is an UNKNOWN, never a failed read — a failed one is
    // an incomplete walk and reaches the core as no recovery at all.
    root_mnt_id: None,
  };

  core.on_mounts_refreshed(scope, refresh(42), at(1));
  let effects = drain(&mut core);
  let asked = recoveries(&effects);
  assert_eq!(
    asked.len(),
    1,
    "staging: one collapsed recovery: {effects:?}"
  );

  // Phase 1: the frame moves under the outstanding walk, which re-asks in the
  // world the reply will be judged in.
  core.on_mounts_refreshed(scope, refresh(77), at(2));
  let turned = drain(&mut core);
  let again = recoveries(&turned);
  assert_eq!(
    again.len(),
    1,
    "staging: the turnover re-asks — the outstanding round trip belongs to the \
     world before it: {turned:?}"
  );
  core.on_root_recovered(scope, idless_reply(&asked[0]), at(3));
  let effects = drain(&mut core);
  assert!(
    recorded(&core, scope).is_empty() && emits(&effects).is_empty(),
    "an id-less report is checked by the EPOCH: the walk cannot say which root \
     it read, so the core's own count of worlds is the whole of the evidence: \
     {effects:?}"
  );
  assert_eq!(
    refresh_requests(&effects),
    0,
    "and it arms NO read: the request phase 1 re-asked is standing in the world \
     this scope still holds, so the reply that is coming already carries \
     everything a read could ask for again — and phase 2 is that reply: \
     {effects:?}"
  );

  // Phase 2: the same silence about the id, this time on the current epoch.
  core.on_root_recovered(scope, idless_reply(&again[0]), at(5));
  let effects = drain(&mut core);
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/subvol"), Some(42), None)],
    "an id-less report on the CURRENT epoch is applied: unknown PASSES, exactly \
     as it does at every other frame fence, or this host could never recover at \
     all"
  );
  assert_eq!(
    emits(&effects).len(),
    1,
    "and the cover it carries goes out with it: {effects:?}"
  );
}

/// No source to ask. The scope has no live handle, or its reader thread is
/// already gone, so the request was refused at the driver and the round trip
/// resolves inline. Nothing was admitted and nothing ever will be — but the
/// refresh's verdict still stands, so the cover goes out on it alone, exactly as
/// it does for every backend that keeps no admission map.
///
/// The alternative — holding the cover — is the one unacceptable answer: it
/// would strand a departure the table saw behind a reply that cannot come.
#[test]
fn an_unreachable_admission_covers_on_the_refreshs_verdict_alone() {
  let (mut core, scope) = live_core_fanotify(vec![row("/r/vol", 77, 9)], Some(42));
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: Vec::new(),
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: Some(42),
      root_incarnation: None,
    },
    at(1),
  );
  let requested = admissions(&drain(&mut core));
  assert_eq!(requested.len(), 1, "staging");

  core.on_admitted(
    scope,
    crate::os::AdmitReport {
      ticket: requested[0].0,
      outcome: crate::os::AdmitOutcome::Unreachable,
    },
    at(2),
  );
  let emitted = emits(&drain(&mut core)).len();
  assert_eq!(
    emitted, 1,
    "the cover is not stranded by an unreachable source"
  );
  assert_eq!(parked_admits(&core, scope), 0);
}

/// A world swap landing between the verdict and the admission KILLS the parked
/// cover with the old world — the `refresh_world_stale` discipline, applied to
/// the one other thing this core holds across a round trip.
///
/// The parked location is a path under a root this scope no longer watches, the
/// reader that was going to answer it is being retired with its transport, and
/// the swap's own covering `Rescan` owes the consumer the whole new tree
/// regardless. A reply that arrives anyway — a straggler on the retired lane —
/// finds no ticket and is inert, which is exactly what the core-wide monotone
/// ticket counter guarantees: it can never collide with one the new world parked.
#[test]
fn a_world_swap_kills_a_parked_admission_cover() {
  let (mut core, scope) = live_core_fanotify(vec![row("/r/vol", 77, 9)], Some(42));
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: Vec::new(),
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: Some(42),
      root_incarnation: None,
    },
    at(1),
  );
  let requested = admissions(&drain(&mut core));
  assert_eq!(requested.len(), 1, "staging: a cover is parked");

  core.on_root_replaced(
    scope,
    RootMeta {
      root: PathBuf::from("/r2"),
      root_dev: 1,
      root_mnt_id: Some(43),
      mounts: Vec::new(),
      declined: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 2),
      ancestors: Vec::new(),
      backend: BackendKind::Fanotify,
    },
    at(2),
  );
  let _ = drain(&mut core);
  assert_eq!(
    parked_admits(&core, scope),
    0,
    "the parked cover died with the old world"
  );

  // The straggler, from the retired reader.
  core.on_admitted(
    scope,
    crate::os::AdmitReport {
      ticket: requested[0].0,
      outcome: crate::os::AdmitOutcome::Admitted,
    },
    at(3),
  );
  let effects = drain(&mut core);
  assert!(
    emits(&effects).is_empty(),
    "and it covers NOTHING in the new world — the location it names is not even \
     under this root any more: {effects:?}"
  );
}

/// A scope torn down with a round trip outstanding answers nothing at all, and
/// that is the whole lifecycle: the parked cover dies with the scope's state,
/// the reader abandons the request unrun (teardown wins over every long op
/// there), and a reply that somehow arrives afterwards finds no scope and is
/// inert.
///
/// No cover is owed. A scope's coverage obligation ends with its own terminal
/// record, and there is no subscription left to re-enumerate for.
#[test]
fn a_scope_torn_down_with_a_parked_admission_answers_nothing() {
  let (mut core, scope) = live_core_fanotify(vec![row("/r/vol", 77, 9)], Some(42));
  core.on_mounts_refreshed(
    scope,
    MountRefresh {
      mounts: Vec::new(),
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: Some(42),
      root_incarnation: None,
    },
    at(1),
  );
  let requested = admissions(&drain(&mut core));
  assert_eq!(requested.len(), 1, "staging: a cover is parked");

  core.on_unwatch(scope);
  let _ = drain(&mut core);
  assert!(
    !core.scopes.contains_key(&scope),
    "staging: the scope and everything parked on it are gone"
  );

  core.on_admitted(
    scope,
    crate::os::AdmitReport {
      ticket: requested[0].0,
      outcome: crate::os::AdmitOutcome::Admitted,
    },
    at(3),
  );
  let effects = drain(&mut core);
  assert!(
    effects.is_empty(),
    "a reply to a dead scope is inert: {effects:?}"
  );
}

/// The gate is FANOTIFY, not kernel-recursiveness — and the distinction is the
/// whole of it.
///
/// FSEvents, `ReadDirectoryChangesW` and the USN journal are kernel-recursive
/// too, and all three see the ground a departure reveals the instant the mount
/// leaves: their marks cover a tree or a volume, never a set of handles. Only
/// fanotify admits by MEMBERSHIP and can therefore be blind to it. Gate on
/// `is_kernel_recursive()` and three backends buy a round trip their source does
/// not need — one their handle would refuse, turning every departure cover into
/// an `Unreachable` detour through the driver.
///
/// Driven on FSEvents, which is publicly live at spawn (its stream IS the
/// coverage), so the cover it emits is observable in the same step it condemns.
#[test]
fn a_kernel_recursive_non_fanotify_departure_covers_with_no_round_trip() {
  let (mut core, scope) = live_core();
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(1));
  assert_eq!(
    emits(&drain(&mut core)).len(),
    1,
    "staging: the arrival records and covers once"
  );

  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
  let effects = drain(&mut core);
  assert!(
    admissions(&effects).is_empty(),
    "a source with no admission map is asked for no admission: {effects:?}"
  );
  assert_eq!(
    emits(&effects).len(),
    1,
    "it covers in the same step it condemns: {effects:?}"
  );
  assert_eq!(parked_admits(&core, scope), 0, "and parks nothing");
}

/// Cell (f): an ID-LESS host keys its census BY LOCATION, and a departure by
/// path still covers — parity with the id-answering host, not a degrade to
/// silence.
///
/// macOS `getfsstat` answers no mount id, and neither does any fake. `Key` is
/// the honest degrade there: the rendered location IS the key, so a row that
/// stops being listed is a departure and a row at a new location is an arrival —
/// the same two transitions an id-keyed census derives, reached by the only fact
/// the host will answer.
///
/// What such a host CANNOT observe is a same-path remount with an unchanged
/// device, because nothing about the two reads differs. That is stated as a
/// residual rather than papered over, and it is strictly narrower than the class
/// this cell holds.
///
/// MUTATION WITNESS (require an id to key a row): drop the `Key::Location` arm so
/// an id-less row is skipped, and this FAILS at `staging: the arrival covers and
/// records` with `left: 0, right: 1` — every mount on every id-less host silently
/// unobservable, which is #74 un-fixed there.
#[test]
fn an_id_less_host_covers_a_departure_by_path() {
  let (mut core, scope) = live_core();
  assert_eq!(
    core.scopes.get(&scope).expect("scope is live").root_mnt_id,
    None,
    "staging: the scope frame is unknown, as it is below 5.8"
  );

  // Every identity this host can report is `None`, so the row's own rendered
  // location is the only thing two reads can be compared on.
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(1));
  let effects = drain(&mut core);
  assert_eq!(
    emits(&effects).len(),
    1,
    "staging: the arrival covers and records: {effects:?}"
  );

  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the location key this read no longer carries is the departure: {effects:?}"
  );
  assert!(emitted[0].kind().is_rescan());
  assert_eq!(emitted[0].location(), &loc(&["vol"]));
  assert!(
    recorded(&core, scope).is_empty(),
    "covered AND gone from the census — derived once, never twice"
  );
}

/// Cell (d), the `Unknown` half: an entry a seam recorded on a host that answers
/// no mount ids fails the whole scope closed until a census row STANDS at its
/// location, and clears the moment one does.
///
/// It is the whole ARC of the fail-closed rule in one trace. While the entry is
/// held, every authoritative refresh covers the WHOLE ROOT — not once, not on a
/// cadence, every one. The read that finally lists the location clears the entry
/// on the very refresh that read it, the root covers STOP, and from then on that
/// location's departure is covered precisely, at its own location, like any other
/// census row's.
///
/// MUTATION WITNESS (liveness): narrow `fails_closed` so no entry satisfies it,
/// and this FAILS at `tick 1: every authoritative refresh covers the whole root
/// while an ambiguity is held` with `left: 0, right: 1`.
/// MUTATION WITNESS (cost): read the trigger BEFORE the ledger join, so a row
/// standing where the last `Unknown` entry sat cannot clear it on the refresh
/// that read it, and this FAILS at `and the arrival is LOCATED, not the root
/// cover a held ambiguity buys` — a whole-root cover one refresh later than the
/// evidence that ended it.
#[test]
fn an_unknown_entry_fails_the_scope_closed_until_a_row_stands_at_its_location() {
  let (mut core, scope) = live_core();
  core
    .scopes
    .get_mut(&scope)
    .expect("scope is live")
    .ledger
    .push(LedgerEntry {
      location: PathBuf::from("/r/vol"),
      standing: Standing::Unknown,
    });

  // Listed by no census, and joined by none: nothing has proven a vfsmount
  // there, and nothing has proven one is not. The scope FAILS CLOSED while it
  // holds the entry.
  for tick in 1..=3 {
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(tick));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "tick {tick}: every authoritative refresh covers the whole root while an \
       ambiguity is held: {effects:?}"
    );
    assert_eq!(
      emitted[0].location(),
      &loc(&[]),
      "tick {tick}: and it is the ROOT, not the entry's own location — no \
       per-entry evidence exists to aim it with: {emitted:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), None, None)],
      "tick {tick}: and the entry is RETAINED, which is what keeps the row that \
       may still stand there able to clear it"
    );
  }

  // A NON-authoritative refresh installs no census and diffs nothing, so it
  // witnesses no absence and owes no cover — the fail-closed rule is about reads
  // actually taken, not about ticks.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), false), at(4));
  assert!(
    emits(&drain(&mut core)).is_empty(),
    "a refresh that could not read the table observed nothing to fail closed over"
  );

  // The table lists it, id-lessly — a `Location` key at exactly that place.
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(5));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the row ENDS the fail-closed state on the very refresh that read it: the \
     census owns the location, the ledger entry is dropped, and what is left is \
     the row's own ARRIVAL: {effects:?}"
  );
  assert_eq!(
    emitted[0].location(),
    &loc(&["vol"]),
    "and the arrival is LOCATED, not the root cover a held ambiguity buys: \
     {emitted:?}"
  );
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/vol"), None, None)],
    "the ledger entry is gone and the census row stands in its place"
  );

  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(6));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "and the census now derives the departure the ledger never could: {effects:?}"
  );
  assert_eq!(
    emitted[0].location(),
    &loc(&["vol"]),
    "covered PRECISELY — the root-wide cost is paid only while an ambiguity is \
     actually held: {emitted:?}"
  );
  assert!(
    recorded(&core, scope).is_empty(),
    "and the departed row leaves the census with its cover"
  );
}

/// SEAM 4: a boundary-bearing PROBE ANSWER, recorded rather than discarded.
///
/// `stat_result` lowers a slot stat into the Monitor's vocabulary by consuming
/// the kind and the inode — and deliberately DROPPING the probed device, because
/// what it is minting is an identity and the enumerate's descent gate still
/// governs whether the Monitor may go below the slot at all. That reasoning is
/// about MINTING and it is untouched here. What it left on the floor is a
/// recorded-quality observation about coverage: the device AND the mount id a
/// probe reads at the only moment anything looked at that path.
///
/// This scope's own frame carries NO mount id (`live_core` spawns without one —
/// macOS, pre-5.8 Linux, every fake), so the entry is `Unknown` here whatever the
/// probe answered, and only a census row standing at its location occupies it.
/// That is the degrade, not the design: the sibling cell stages a scope whose
/// frame IS known and shows the same probe deciding `Mount`.
#[test]
fn a_probe_answer_records_the_boundary_its_stat_discards() {
  fn req(n: u64) -> ReqId {
    ReqId::new(NonZeroU64::new(n).expect("req ids start at one"))
  }
  fn slot_stat(core: &mut DriverCore, scope: ScopeId, n: u64, path: &str, dev: u64, now: Instant) {
    // The Monitor's own `Action::Stat` is unreachable through this driver's
    // listing (it lowers every `FileType` it can name), so the purpose is minted
    // directly — the request shape is the point, not the route to it.
    let probe = core.mint_probe(
      scope,
      ProbePurpose::SlotKind {
        req: req(n),
        path: PathBuf::from(path),
      },
    );
    core.on_probe_result(
      probe,
      ProbeOutcome::Present {
        kind: FileKind::Dir,
        file_id: NonZeroU64::new(n + 10),
        dev,
        // A host that answers no mount ids — which is the host this scope's own
        // frame describes.
        mnt_id: None,
      },
      now,
    );
  }

  let (mut core, scope) = live_core();
  slot_stat(&mut core, scope, 1, "/r/vol", 99, at(1));
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/vol"), None, None)],
    "the foreign device the stat discards is recorded — with no mount id, \
     because this host answers none"
  );

  // An answer on the root's own device observed no boundary, so it records none.
  slot_stat(&mut core, scope, 2, "/r/plain", 1, at(2));
  assert_eq!(
    recorded(&core, scope).len(),
    1,
    "a root-device answer is not a boundary"
  );

  // Device-only until a row says otherwise: absence from a frame DROPS nothing.
  // It is ambiguous rather than proven (this host answers no ids at all), so the
  // scope fails closed for as long as it holds it.
  for tick in 3..=4 {
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(tick));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "tick {tick}: a probe-recorded boundary could still be a real mount that \
       departed, and nothing here can say — so the whole root is covered: \
       {effects:?}"
    );
    assert_eq!(emitted[0].location(), &loc(&[]));
    assert_eq!(
      recorded(&core, scope).len(),
      1,
      "tick {tick}: and it stays in the set, where a row can still reach it"
    );
  }

  // A read whose census STANDS at the location occupies the entry, whatever keys
  // that row, and from then on the location's departure is the census's to derive
  // — precisely, because the entry that failed the scope closed is gone. The row
  // is itself an arrival and owes its own cover.
  core.on_mounts_refreshed(
    scope,
    alive_refresh(vec![row("/r/vol", 77, 99)], true),
    at(5),
  );
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the row occupies the entry and ends the fail-closed state on the very \
     refresh that read it, leaving its own arrival: {effects:?}"
  );
  assert_eq!(
    emitted[0].location(),
    &loc(&["vol"]),
    "and the arrival is LOCATED, not the root cover a held ambiguity buys: \
     {emitted:?}"
  );
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(6));
  let effects = drain(&mut core);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the confirmed record departs like any other: {effects:?}"
  );
  assert_eq!(emitted[0].location(), &loc(&["vol"]));
  assert!(recorded(&core, scope).is_empty());
}

/// F1's SIBLING, staged as the same reachable sequence on the seam that answers a
/// probe rather than a walk: a mount ARRIVES after the baseline, is FIRST OBSERVED
/// by a slot stat, and DEPARTS before any refresh confirms a row at its location.
///
/// `record_probe_boundary` used to pass `None` for the mount id because the probe
/// had none to give, which mints a permanently-EXEMPT record — the same defect the
/// fanotify walk's device belt had, on a different seam. So the refresh that no
/// longer listed the location condemned nothing, and the cover the revealed ground
/// was owed never fired. Answering the id from the probe's own `statx` is the fix,
/// and it leaves `None` meaning only "the host cannot say" (which is the cell
/// above).
///
/// Every frame here is EMPTY of rows except the one that adopts the root's frame,
/// which lists nothing either: a listed row would fire an ARRIVAL cover that the
/// departure assertion could not be told apart from.
#[test]
fn a_mount_seen_only_by_a_probe_still_has_its_departure_derived() {
  fn slot_stat(core: &mut DriverCore, scope: ScopeId, path: &str, dev: u64, mnt_id: Option<u64>) {
    let probe = core.mint_probe(
      scope,
      ProbePurpose::SlotKind {
        req: ReqId::new(NonZeroU64::new(1).expect("req ids start at one")),
        path: PathBuf::from(path),
      },
    );
    core.on_probe_result(
      probe,
      ProbeOutcome::Present {
        kind: FileKind::Dir,
        file_id: NonZeroU64::new(11),
        dev,
        mnt_id,
      },
      at(1),
    );
  }

  let (mut core, scope) = live_core();
  // The BASELINE: authoritative, listing nothing, and adopting the root's own
  // mount frame — without which the scope decides every entry `Unknown` and the
  // sequence below cannot be staged at all.
  core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(1));
  assert!(
    drain(&mut core).is_empty(),
    "staging: an empty baseline covers nothing"
  );
  assert!(
    recorded(&core, scope).is_empty(),
    "staging: and records nothing"
  );

  // The mount ARRIVES, after the baseline, and the only thing that ever looks at
  // it is the Monitor's slot stat.
  slot_stat(&mut core, scope, "/r/vol", 99, Some(77));
  drain(&mut core);
  assert_eq!(
    recorded(&core, scope),
    vec![(PathBuf::from("/r/vol"), Some(77), None)],
    "the probe records the mount id it read beside the device — a record with \
     both halves is one the partition can classify"
  );

  // It DEPARTS before any refresh confirmed a row for it.
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
  let effects = drain(&mut core);
  assert!(
    recorded(&core, scope).is_empty(),
    "the record is CONDEMNED, not exempt for the scope's whole life"
  );
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "and the departure the ground was owed is covered: {effects:?}"
  );
  assert_eq!(emitted[0].location(), &loc(&["vol"]));

  // The control leg: a SUBVOLUME the same probe answers for — foreign device, the
  // root's own mount id — stays exempt across the identical refresh.
  slot_stat(&mut core, scope, "/r/sub", 99, Some(42));
  drain(&mut core);
  let held = vec![(PathBuf::from("/r/sub"), Some(42), None)];
  assert_eq!(recorded(&core, scope), held, "staging: recorded exempt");
  core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(3));
  let effects = drain(&mut core);
  assert!(
    emits(&effects).is_empty(),
    "a subvolume is not a departure: {effects:?}"
  );
  assert_eq!(
    recorded(&core, scope),
    held,
    "and it survives UNTOUCHED — the same seam, the opposite verdict, decided by \
     the id the probe now answers"
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
    frame_epoch: 0,
    generation: Generation::Verified { epoch: 0 },
    pending_recovery: None,
    published_epoch: None,
    identity: Some(crate::os::RootIdentity::new(1, 1)),
    mount_table: vec![PathBuf::from("/r/vol")],
    learned_mounts: Vec::new(),
    mounts_authoritative: true,
    census: Vec::new(),
    ledger: Vec::new(),
    pending_admits: Vec::new(),
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
    root_incarnation: None,
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
    frame_epoch: 0,
    generation: Generation::Verified { epoch: 0 },
    pending_recovery: None,
    published_epoch: None,
    identity: Some(crate::os::RootIdentity::new(1, 1)),
    mount_table: Vec::new(),
    learned_mounts: Vec::new(),
    mounts_authoritative: false,
    census: Vec::new(),
    ledger: Vec::new(),
    pending_admits: Vec::new(),
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
    root_incarnation: None,
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
      mnt_id: None,
    },
    at(2),
  );
  let _ = drain(&mut core);
  let state = core.scopes.get(&scope).expect("scope lives");
  assert!(
    state
      .learned_mounts
      .iter()
      .any(|m| m == Path::new("/r/vol/x")),
    "the foreign device's prefix is remembered: {:?}",
    state.learned_mounts
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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

/// One FSEvents rename word for a surviving `/r/new` that no source half
/// accompanies — a move INTO the tree — carrying `extra` alongside the rename,
/// under a scope subscribed to exactly `interest`.
///
/// A LONE half is what makes an admission claim decidable here: an
/// evidence-granted PAIR always wears a covering rescan (see
/// `same_batch_rename_pair_grounds_by_probes_into_single_moved`), and that
/// rescan would stand behind any record the consumer was not admitted to,
/// hiding the very silence these cells are about. Nothing waits on a timer
/// either — the one probe is answered inside the fixture — so a claim about
/// what this word delivers is decided by the drained effects.
fn moved_in_word(interest: Interest, extra: &[FsEventFlags]) -> Vec<Effect> {
  let (mut core, scope) = live_core_with(interest);
  let mut word = vec![FsEventFlags::ITEM_RENAMED, FsEventFlags::ITEM_IS_FILE];
  word.extend_from_slice(extra);
  core.on_batch_events(scope, vec![ev("/r/new", flags(&word), 1, 42)], at(1));
  let reqs = probes(&drain(&mut core));
  assert_eq!(reqs.len(), 1, "the half probes for existence: {reqs:?}");
  core.on_probe_result(
    reqs[0].0,
    ProbeOutcome::Present {
      kind: FileKind::File,
      file_id: NonZeroU64::new(42),
      dev: 1,
      mnt_id: None,
    },
    at(2),
  );
  drain(&mut core)
}

#[test]
fn a_rename_word_carrying_only_metadata_reaches_metadata_and_not_content() {
  // The measured `mv a b; chmod 700 b` destination word: ITEM_IS_FILE |
  // ITEM_CHANGE_OWNER | ITEM_RENAMED, carrying NO ITEM_MODIFIED. OR-ing the
  // two facts into one bool minted a `Modified` record, whose evidence is
  // `{modified}` alone: the metadata change then reached nobody who asked for
  // exactly it, and — the effect list being empty, not merely short — no
  // rescan stood behind the silence.
  let effects = moved_in_word(
    Interest::new().with_attrib(),
    &[FsEventFlags::ITEM_CHANGE_OWNER],
  );
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the metadata change reaches the subscription that asked for it: {effects:?}"
  );
  assert!(emitted[0].kind().is_modified(), "{emitted:?}");
  assert_eq!(emitted[0].location(), &loc(&["new"]));

  let effects = moved_in_word(
    Interest::new().with_modified(),
    &[FsEventFlags::ITEM_CHANGE_OWNER],
  );
  assert!(
    emits(&effects).is_empty(),
    "a chmod is not an edit: a content-only subscription is never told one happened: {effects:?}"
  );
}

#[test]
fn a_rename_word_proving_both_facts_is_admitted_by_either_subscription() {
  // One word proving a content AND a metadata change, alongside the coalesced
  // CREATED bit real words carry. ONE record answers it, taking its verb from
  // the fact set (`Modified` outranks `Attrib`) while carrying both facts, so
  // neither narrowed subscription is left out.
  let extra = &[
    FsEventFlags::ITEM_MODIFIED,
    FsEventFlags::ITEM_XATTR_MOD,
    FsEventFlags::ITEM_CREATED,
  ];
  for interest in [
    Interest::new().with_attrib(),
    Interest::new().with_modified(),
  ] {
    let effects = moved_in_word(interest, extra);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "one record, one change: {effects:?}");
    // Existence already grounded this half: a folded-in `created` fact would
    // win `Evidence::primary` and rename the record `Created`.
    assert!(emitted[0].kind().is_modified(), "{emitted:?}");
    assert_eq!(emitted[0].location(), &loc(&["new"]));
  }

  // The `moved` fact rides the move half alone; folding it in here too would
  // hand a move-only subscription a second change for the same word.
  let effects = moved_in_word(Interest::new().with_moved(), extra);
  let emitted = emits(&effects);
  assert_eq!(
    emitted.len(),
    1,
    "the move half, and nothing else: {effects:?}"
  );
  assert!(emitted[0].kind().is_created(), "{emitted:?}");
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
      mnt_id: None,
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
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents)
    .expect("a fresh scope registers");
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
      mounts: vec![bare("/r/vol")],
      declined: Vec::new(),
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
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents)
    .expect("a fresh scope registers");
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
      mounts: Vec::new(),
      declined: Vec::new(),
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
      mnt_id: None,
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
      mnt_id: None,
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
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents)
    .expect("a fresh scope registers");
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
      mounts: Vec::new(),
      declined: Vec::new(),
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
    },
    at(2),
  );
  let _ = drain(&mut core);

  core.on_root_overflow(scope, at(3));
  let _ = drain(&mut core);
  // The fresh snapshot does not list the learned prefix (it is not a real
  // mount point, so no row will ever name it). The authoritative install
  // REPLACES the table component, and the learned prefix survives it in the
  // half no snapshot reaches — replacement of the whole veto would re-trust a
  // subtree an lstat proved foreign.
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/other")], true), at(0));
  let state = core.scopes.get(&scope).expect("scope is live");
  assert!(state.mounts_authoritative);
  assert!(
    state
      .learned_mounts
      .iter()
      .any(|m| m == Path::new("/r/vol/x")),
    "the probe-learned prefix is not a table row and no install may drop it: {:?}",
    state.learned_mounts
  );
  assert!(
    state.mount_table.iter().any(|m| m == Path::new("/r/other")),
    "and the snapshot's own row installs beside it: {:?}",
    state.mount_table
  );
  assert!(
    mint(state, Path::new("/r/vol/x/deep"), NonZeroU64::new(8), None).is_none(),
    "so a path under the learned prefix still refuses to mint"
  );
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
      mnt_id: None,
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
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents)
    .expect("a fresh scope registers");
  let _ = drain(&mut core);
  core.on_stream_spawned(
    scope,
    Ok(RootMeta {
      root: PathBuf::from("/r"),
      root_dev: 1,
      root_mnt_id: None,
      mounts: vec![bare("/r/vol")],
      declined: Vec::new(),
      identity: crate::os::RootIdentity::new(1, 1),
      ancestors: Vec::new(),
      backend: BackendKind::FsEvents,
    }),
  );
  let _ = drain(&mut core);
  core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(0));

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
      mnt_id: None,
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
    !state
      .learned_mounts
      .iter()
      .any(|m| m == Path::new("/r/vol"))
      && !state.mount_table.iter().any(|m| m == Path::new("/r/vol")),
    "post-batch, the unmounted prefix leaves BOTH halves of the veto: the word is \
     evidence the mount is gone, which is the one thing that retires a learned \
     prefix, and leaving the row would veto on a mount already announced departed"
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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
      mnt_id: None,
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
        mnt_id: None,
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
      mnt_id: None,
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
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents)
    .expect("a fresh scope registers");
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
  let scope = core
    .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::FsEvents)
    .expect("a fresh scope registers");
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

/// The cover/park deduplication, in isolation: repeated locations collapse to
/// their FIRST occurrence and the surviving order is untouched.
///
/// It is a pure function, and it is tested as one because in 2a its caller-level
/// consequence is not observable. On the cover side the Monitor coalesces two
/// identical overflows, so an emitted-cover assertion reads green with the
/// deduplication gone; on the parked side two departures at one location are
/// unreachable, because an observation at a location a census row stands at is
/// Occupied at intake and a census keys at most one row per location today. The
/// rule is here for the diff's own contract and for 2b, where several rows per
/// location become ordinary and a location really can transition twice in one
/// read.
///
/// MUTATION WITNESS: make `dedup_locations` a no-op and this FAILS at `two
/// transitions at one place collapse to one`.
/// MUTATION WITNESS (order): `sort` + `dedup` instead, and this FAILS at `two
/// transitions at one place collapse to one` with `left: ["/r/a", "/r/b",
/// "/r/c"]` — the right SET, in path order rather than in the order the
/// transitions were derived.
#[test]
fn dedup_locations_keeps_the_first_of_each_place_in_order() {
  let p = |s: &str| PathBuf::from(s);
  let mut none: Vec<PathBuf> = Vec::new();
  dedup_locations(&mut none);
  assert!(none.is_empty(), "empty in, empty out");

  let mut one = vec![p("/r/a")];
  dedup_locations(&mut one);
  assert_eq!(one, vec![p("/r/a")], "a single place is untouched");

  // The shape the diff produces: an arrival at `/r/b`, a move out of `/r/a`, and
  // a second transition naming `/r/a` again.
  let mut many = vec![p("/r/b"), p("/r/a"), p("/r/c"), p("/r/a"), p("/r/b")];
  dedup_locations(&mut many);
  assert_eq!(
    many,
    vec![p("/r/b"), p("/r/a"), p("/r/c")],
    "two transitions at one place collapse to one"
  );
  assert_eq!(
    many.first(),
    Some(&p("/r/b")),
    "and the survivors keep the order the diff produced them in — a cover set is \
     not sorted, it is derived"
  );
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
      frame_epoch: 0,
      generation: Generation::Verified { epoch: 0 },
      pending_recovery: None,
      published_epoch: None,
      identity: Some(crate::os::RootIdentity::new(1, 1)),
      mount_table: Vec::new(),
      learned_mounts: Vec::new(),
      mounts_authoritative: true,
      census: Vec::new(),
      ledger: Vec::new(),
      pending_admits: Vec::new(),
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
      root_incarnation: None,
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
    let scope = core
      .on_watch(PathBuf::from("/"), Interest::all(), BackendKind::FsEvents)
      .expect("a fresh scope registers");
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify)
      .expect("a fresh scope registers");
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
        declined: Vec::new(),
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

  /// Puts `entries` straight into the ledger, in insertion order — which is the
  /// order eviction reads.
  ///
  /// BUILT rather than listed, and that is a footprint decision. Filling the
  /// ledger to [`MAX_BOUNDARIES`] through an enumerate costs some seven
  /// allocations per entry plus a containment scan against every incumbent —
  /// quadratic in a bound of 1024 — and an interpreted 32-bit run pays for all of
  /// it out of the single 4 GB address space the whole shard shares. That is
  /// where `fs-rest` exhausted it.
  ///
  /// It costs the cells that use it nothing, because none of them is ABOUT the
  /// fill: their subject is what the bound DECIDES once the ledger is full, and
  /// for that the incumbents only have to BE there in the right shape. Filling
  /// one from a real listing IS
  /// [`the_ledger_is_hard_bounded_and_evicts_the_oldest`]'s subject, and that
  /// cell keeps its listing.
  fn saturate(
    core: &mut DriverCore,
    scope: ScopeId,
    entries: impl IntoIterator<Item = LedgerEntry>,
  ) {
    core
      .scopes
      .get_mut(&scope)
      .expect("scope is live")
      .ledger
      .extend(entries);
  }

  /// One `Unknown` entry: a device, and a seam that could answer no mount id on
  /// EITHER side of the comparison, so nothing can tell a genuine vfsmount from a
  /// subvolume. This is the shape that may never be evicted — it is the only
  /// witness a departure there will ever have — and therefore the shape that
  /// forces the bound to refuse instead.
  fn ambiguous_at(location: impl Into<PathBuf>) -> LedgerEntry {
    LedgerEntry {
      location: location.into(),
      standing: Standing::Unknown,
    }
  }

  /// One `SameMount` entry: the ROOT's own mount id on a foreign device. No
  /// mountinfo read will ever list it, so nothing can promote it into a witness —
  /// which is what makes it the only entry free to evict.
  fn proven_at(location: impl Into<PathBuf>) -> LedgerEntry {
    LedgerEntry {
      location: location.into(),
      standing: Standing::SameMount,
    }
  }

  #[test]
  fn descending_registration_cold_enumerates_the_root() {
    let (_core, _scope, _req, _watch) = live_descending();
  }

  /// #74's measured case, on the profile it was filed against. A lazy unmount
  /// below the root emits NO `IN_UNMOUNT` and no `IN_IGNORED` — the watches under
  /// it simply stop meaning anything — so nothing in band tells this scope its
  /// coverage there died. The periodic refresh's departure diff is the only
  /// signal, and it lands a located cover plus the re-arm that reconciles the
  /// descending coverage the cover obliges.
  #[test]
  fn a_lazily_departed_mount_covers_and_re_arms_the_descending_subtree() {
    let (mut core, scope, req, root_watch) = live_descending();
    // Close the birth crawl first: with its cold read still outstanding the
    // re-arm below only marks that read dirty, and the fresh enumerate this cell
    // is about never appears.
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);

    core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(1));
    let effects = drain(&mut core);
    assert_eq!(
      emits(&effects).len(),
      1,
      "staging: the arrival records the mount, and covers it once"
    );
    // The arrival's own cover obliges a re-read, and that read must be CLOSED
    // before the departure below: with it still outstanding the departure's
    // cover only marks it dirty, and the fresh enumerate this cell is about
    // never appears — the same discipline the birth crawl needed above.
    for req in effects.iter().filter_map(|e| match e {
      Effect::Enumerate { req, .. } => Some(*req),
      _ => None,
    }) {
      core.on_enumerated(req, listed(Vec::new()));
    }
    let _ = drain(&mut core);

    // `umount -l /r/vol`: the table loses the row, the kernel says nothing.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "one cover for the departure: {effects:?}");
    assert!(
      emitted[0].kind().is_rescan(),
      "coverage that died silently is covered, not delivered: {emitted:?}"
    );
    assert_eq!(emitted[0].location(), &loc(&["vol"]));
    assert!(
      effects.iter().any(|e| matches!(
        e,
        Effect::Enumerate { watch, .. } if *watch == root_watch
      )),
      "and the descending re-arm re-reads from the nearest watch: {effects:?}"
    );
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
    let scope = core
      .on_watch(PathBuf::from(root), Interest::all(), BackendKind::Inotify)
      .expect("a fresh scope registers");
    let _ = drain(core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from(root),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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

  /// SEAM 1: the enumerate DECLINE is also an OBSERVATION, and this is the
  /// mount-backed half of it.
  ///
  /// `core::on_enumerated` is the single site where a boundary-crossing dir entry
  /// is lowered to `FileKind::Other`, and it holds everything the ledger wants —
  /// the location, the entry's device, and its mount id. Recording there closes
  /// the LATENCY window the census alone leaves open: a mount observed at second
  /// *t* would otherwise wait for the next tick to be keyed, and a departure
  /// inside that window would be underivable.
  ///
  /// The `Standing` is the seam's own two ids: this entry's mount id differs from
  /// the root's, so it is `Mount`, and the first read that does not key it is its
  /// departure — exactly as if a census had listed it.
  #[test]
  fn an_enumerate_decline_records_a_mount_backed_boundary() {
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![
        // A `mount --bind` of a same-superblock directory: the root's DEVICE,
        // a different MOUNT (77). Declined by the mount fence.
        entry_on_mount("bound", FileKind::Dir, 1, 20, 77),
        // Same mount as the root: descended, and no kind of boundary.
        entry_on_mount("here", FileKind::Dir, 1, 21, 42),
      ]),
    );
    let _ = drain(&mut core);
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/bound"), Some(77), None)],
      "the DECLINED entry enters the coverage set, with the identity the \
       enumerate read — and only it: a descended sibling is not a boundary"
    );

    // Mount-backed, so the very next authoritative frame that no longer lists it
    // condemns it: cover, then drop. Nothing else had to record it first.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(1));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "a seam-recorded vfsmount departs like any other: {effects:?}"
    );
    assert!(emitted[0].kind().is_rescan());
    assert_eq!(emitted[0].location(), &loc(&["bound"]));
    assert!(
      recorded(&core, scope).is_empty(),
      "condemned means covered AND dropped"
    );
  }

  /// INTAKE OCCUPANCY, by LOCATION: a seam re-declining a boundary a census row
  /// already stands at records nothing — and that is what keeps the pre-5.8
  /// floor kernel out of a permanent fail-closed.
  ///
  /// On Linux 4.11-5.7 the two halves of the identity come from different places
  /// and only one of them answers: `/proc/self/mountinfo` has carried mount ids
  /// since forever, so every census row there is `Id`-keyed, while
  /// `statx(STATX_MNT_ID)` does not exist, so every seam answers `None` and every
  /// entry it could mint is `Unknown`. The id leg of the occupancy rule therefore
  /// never fires on that kernel, and without the LOCATION leg every ordinary
  /// enumerate of a directory holding a listed mount would push an `Unknown`
  /// entry and fail the whole scope closed until the next refresh's join dropped
  /// it — a whole-root cover per refresh, for as long as anything under the root
  /// is being listed.
  ///
  /// The scope here is exactly that host in miniature: a frame that DOES answer an
  /// id (so the fail-closed is attributable to the seam and not to the frame),
  /// a census row that is `Id`-keyed, and a listing whose entry answers no id at
  /// all.
  ///
  /// MUTATION WITNESS: drop the location leg (`row.location == location`) from
  /// `record_boundary`'s occupancy test and this FAILS at `the ledger stays
  /// empty` — and, one read later, at `and the scope does not fail closed`, which
  /// is the cost.
  #[test]
  fn a_decline_at_a_location_the_census_stands_at_records_nothing() {
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);
    core.on_mounts_refreshed(
      scope,
      framed_refresh(vec![row("/r/vol", 77, 99)], true, Some(42)),
      at(1),
    );
    let effects = drain(&mut core);
    assert_eq!(
      emits(&effects).len(),
      1,
      "staging: the census keys the mount and covers its arrival: {effects:?}"
    );

    // The arrival's own re-arm crawl lists the root again, and the fence declines
    // the mount it already knows about — with NO mount id, because this host
    // answers none at a seam.
    let relist = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the arrival's cover re-arms and re-reads the root");
    core.on_enumerated(
      relist,
      listed(vec![RawDirEntry {
        name: b"vol".to_vec(),
        kind: FileKind::Dir,
        dev: 99,
        ino: 7,
        mnt_id: None,
      }]),
    );
    let _ = drain(&mut core);
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(77), Some(99))],
      "the ledger stays empty: a census row STANDS at that location, so the \
       observation is Occupied at intake whatever its standing"
    );

    // And the cost, if it had not been: the next authoritative read would answer
    // one whole-root recovery instead of nothing at all.
    core.on_mounts_refreshed(
      scope,
      framed_refresh(vec![row("/r/vol", 77, 99)], true, Some(42)),
      at(2),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty(),
      "and the scope does not fail closed — an unchanged census over an empty \
       ledger derives and recovers nothing: {effects:?}"
    );
  }

  /// SEAM 1 again, for the class no census will EVER list.
  ///
  /// A btrfs subvolume trips the DEVICE belt while carrying the root's own mount
  /// id. It is not a vfsmount: `/proc/self/mountinfo` has no row for it and never
  /// will, and `openat2(RESOLVE_NO_XDEV)` opens it without complaint. So seam 1
  /// is its only observer — and, condemn on an absence rather than a transition,
  /// its absence from every census reads as a departure on every single tick: one
  /// cover plus one re-arm crawl per subvolume per tick, on every default snapper
  /// / Fedora / docker-btrfs layout.
  ///
  /// This is the first place in the system that a `SameMount` entry is actually
  /// produced.
  #[test]
  fn an_enumerate_decline_records_an_exempt_same_mount_boundary() {
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      // The subvolume: a foreign DEVICE (99) on the ROOT's own mount (42).
      listed(vec![entry_on_mount("subvol", FileKind::Dir, 99, 20, 42)]),
    );
    let _ = drain(&mut core);
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/subvol"), Some(42), None)],
      "the decline records it — nothing else ever will"
    );

    // Every condemnation mechanism there is, run over and over. The refresh's
    // absence diff is the only one, and it must never fire here.
    for tick in 1..6 {
      core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(tick));
      assert!(
        emits(&drain(&mut core)).is_empty(),
        "tick {tick}: a subvolume is not a departure, ever"
      );
    }
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/subvol"), Some(42), None)],
      "and it survives UNTOUCHED — exempt from the mechanism, not merely quiet \
       about it"
    );
  }

  /// PREVENTION, both halves: what the core hands the executor for a
  /// `Created`-learned child, and where a refusal of that arm terminates.
  ///
  /// A directory the Monitor learns from a `Created` record is armed with NO
  /// enumerate in between, so `crosses_mount_boundary` never judges it — and
  /// inotify's `Created` compiles to a bare record with no identity, so the arm's
  /// own object guard (`expected`) is `None` and passes whatever it opens. The
  /// scope FRAME is therefore the only thing that can refuse the landing, which
  /// is why it rides every arm rather than being folded into `expected`.
  ///
  /// The refusal's terminal is the second half, and the design ACCEPTS it: a
  /// failed arm reaches the Monitor's `Err` arm, which emits a located `Rescan`,
  /// books a level-persistent slot deficit and drops the node. It queues no
  /// enumerate and calls no re-arm — so for a crossing no census will ever list
  /// (no row, no arrival, no crawl) nothing re-records anything, and the slot
  /// stays a deficit re-signalled ahead of every sync cookie. Signalled, not
  /// silent.
  #[test]
  fn a_created_childs_arm_carries_the_frame_and_its_refusal_stands_a_deficit() {
    let (mut core, scope, req, root_watch) = live_descending_mnt(42);
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);

    core.on_inotify_events(
      scope,
      vec![inotify(
        &[root_watch],
        IN_CREATE | IN_ISDIR,
        0,
        Some(b"subvol"),
      )],
      at(1),
    );
    let effects = drain(&mut core);
    let (watch, expected, frame) = effects
      .iter()
      .find_map(|e| match e {
        Effect::AddWatch {
          watch,
          path,
          expected,
          frame,
          ..
        } if path.as_path() == Path::new("/r/subvol") => Some((*watch, *expected, *frame)),
        _ => None,
      })
      .expect("a created directory is armed with no enumerate in between");
    assert_eq!(
      expected, None,
      "the object guard is vacuous here — a `Created` record carries no identity"
    );
    assert_eq!(
      (frame.root_dev, frame.root_mnt_id),
      (Some(1), Some(42)),
      "so the arm carries the SCOPE FRAME, which is what can still refuse it"
    );

    // What the executor answers when the landing sits across that frame.
    core.on_watch_installed(
      watch,
      core.arm_attempt(watch),
      crate::os::linux::WatchOutcome::Failed(WatchError::Gone),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().is_rescan() && c.location() == &loc(&["subvol"])),
      "the refusal is never a silent blind spot: {effects:?}"
    );
    assert!(
      !effects.iter().any(
        |e| matches!(e, Effect::Enumerate { path, .. } if path.as_path() == Path::new("/r/subvol"))
      ),
      "and it summons no re-enumerate — the recorder for a boundary a census \
       will key is the next read's ARRIVAL side, and an exempt one has none: \
       {effects:?}"
    );
    assert!(
      core.resignal_coverage_deficits(scope),
      "the refused slot is the accepted terminal: a standing deficit, \
       re-signalled ahead of every sync cookie"
    );
  }

  /// The LEDGER's REMOVAL PATH — the debt seam 1 incurs by producing entries at
  /// all.
  ///
  /// Nothing else can drop an exempt one. No census lists a subvolume, and the
  /// only other removal is settlement's signalled-unmount `retain`, which serves
  /// the FSEvents `UNMOUNT` word alone. The design's answer is that their
  /// lifecycle is "the ordinary event flow, since deleting a subvolume emits real
  /// delete events on the parent" — true about the filesystem, and false about
  /// the code until a seam consumed those events. Without it the ledger grows
  /// monotonically for the life of a scope, reset only at a world swap.
  ///
  /// It runs over the WHOLE ledger, with no standing test, and the `Mount(77)`
  /// entry here is why that is sound rather than merely uniform: the driving
  /// record proves the LOCATION is gone — a mountpoint cannot be unlinked while a
  /// mount is on it — so the boundary was already detached and the ground it
  /// revealed left with the directory. Nothing the census owns is reachable from
  /// here, because a ledger entry is by construction something no census keys.
  ///
  /// MUTATION WITNESS (the pass never runs): return early from
  /// `retire_removed_boundaries` unconditionally and this FAILS at `both entries
  /// die with their locations` — both still held, and the ledger growing by one
  /// `PathBuf` per deleted boundary for the life of the scope.
  #[test]
  fn a_removed_location_drops_its_ledger_entry() {
    let (mut core, scope, req, root_watch) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![
        // The subvolume: the root's own mount id on a foreign device, so
        // `SameMount`, and nobody's to remove but this.
        entry_on_mount("subvol", FileKind::Dir, 99, 20, 42),
        // A real bind seen before any census keyed it: `Mount(77)`, the belt.
        entry_on_mount("bound", FileKind::Dir, 1, 21, 77),
      ]),
    );
    let _ = drain(&mut core);
    assert_eq!(
      recorded(&core, scope).len(),
      2,
      "staging: both boundaries are recorded"
    );

    core.on_inotify_events(
      scope,
      vec![
        inotify(&[root_watch], IN_DELETE | IN_ISDIR, 0, Some(b"subvol")),
        inotify(&[root_watch], IN_DELETE | IN_ISDIR, 0, Some(b"bound")),
      ],
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      recorded(&core, scope).is_empty(),
      "both entries die with their locations: a mountpoint cannot be unlinked \
       while a mount is on it, so each delete proves the boundary was already \
       detached"
    );
    assert_eq!(
      emits(&effects).len(),
      2,
      "and no cover is owed for either — the deletes themselves are what the \
       consumer is told: {effects:?}"
    );

    // Nothing is left to re-derive: the next authoritative read over an empty
    // table has no census row and no entry to condemn.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty(),
      "and the read that follows derives nothing at all: {effects:?}"
    );
  }

  /// **Cell (a): the case #74 v4 was written for.** A mount at `R/a/x`, then
  /// `mv R/a R/b`, then a lazy unmount of `R/b/x` — and the departure cover lands
  /// at `R/b/x`, where the ground actually is.
  ///
  /// The bug reproduces with NO torn read at all, which is why path-keying rather
  /// than tearing is the defect. `rename(2)` bumps no mount-namespace generation,
  /// so `mounts_poll` never fires and the next census renders the row under its
  /// NEW label — while a path-keyed set still names the old one. Diffed that way,
  /// the departure is derived against a stale `R/a/x`, the cover goes to a
  /// directory that no longer exists, and the revealed ground at `R/b/x` is never
  /// covered by anything at all.
  ///
  /// Identity is what makes the two reads comparable, and the rename repair is
  /// what keeps the HINT honest: the paired `Moved` the core already compiles and
  /// delivers re-roots every location at-or-under the source before the change
  /// leaves.
  ///
  /// MUTATION WITNESS (no rebase): delete the `rebase_hints` call from
  /// `route_event` and this FAILS at `and the hint moved with the directory` —
  /// the census still naming `/r/a/x`, which one read later is the cover landing
  /// at a directory that no longer exists while `R/b/x` stays dark.
  #[test]
  fn a_renamed_directory_moves_the_hint_a_later_departure_covers() {
    let (mut core, scope, req, root_watch) = live_descending_mnt(42);
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);

    // The census keys the mount by its own id, and renders it under `a`.
    core.on_mounts_refreshed(
      scope,
      framed_refresh(vec![row("/r/a/x", 77, 99)], true, Some(42)),
      at(1),
    );
    let effects = drain(&mut core);
    assert_eq!(
      emits(&effects)
        .iter()
        .filter(|c| c.location() == &loc(&["a", "x"]))
        .count(),
      1,
      "staging: the arrival is covered at the location the read rendered: \
       {effects:?}"
    );

    // `mv /r/a /r/b`, paired in the Monitor's window by its native cookie.
    core.on_inotify_events(
      scope,
      vec![
        inotify(&[root_watch], IN_MOVED_FROM | IN_ISDIR, 9, Some(b"a")),
        inotify(&[root_watch], IN_MOVED_TO | IN_ISDIR, 9, Some(b"b")),
      ],
      at(2),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().moved_from() == Some(&loc(&["a"])) && c.location() == &loc(&["b"])),
      "staging: the halves pair into one `Moved`: {effects:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/b/x"), Some(77), Some(99))],
      "and the hint moved with the directory — the KEY did not, because a mount \
       id is absolute"
    );

    // `umount -l /r/b/x`: no `IN_UNMOUNT`, no hangup, no `Rescan`. The read that
    // no longer keys 77 is the only observer there is.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(3));
    let effects = drain(&mut core);
    let covers: Vec<&Location> = emits(&effects)
      .iter()
      .filter(|c| c.kind().is_rescan())
      .map(|c| c.location())
      .collect();
    assert!(
      covers.contains(&&loc(&["b", "x"])),
      "the cover lands where the ground is: {effects:?}"
    );
    assert!(
      !covers.contains(&&loc(&["a", "x"])),
      "and never at the label the mount table last rendered before the rename: \
       {effects:?}"
    );
  }

  /// F3's class: the retire passes test containment against a SET built once per
  /// pass, and the set must decide exactly what the per-record scan decided —
  /// at-or-under, COMPONENT-WISE.
  ///
  /// `retire_removed_boundaries` runs on every compiled batch, so its old
  /// `records x vanished` scan was the one place a per-event cost compounded. The
  /// replacement probes each record's own ancestors against an ordered set, which
  /// is the same predicate only while it stays component-wise: `/r/gone2` shares
  /// a BYTE prefix with `/r/gone` and is not under it, and retiring it would drop
  /// a live boundary's record on a delete that never touched it.
  #[test]
  fn a_removal_retires_at_and_under_its_path_and_never_a_string_neighbour() {
    let (mut core, scope, _req, root_watch) = live_descending_mnt(42);
    // Seam 2, deepest FIRST: the containment rule inside `record_boundary`
    // refuses a record beneath one already held, so `/r/gone/inner` has to be
    // recorded before `/r/gone` is.
    core.on_walk_boundaries(
      scope,
      crate::os::WalkBoundaries {
        declined: vec![
          crate::os::DeclinedBoundary {
            location: PathBuf::from("/r/gone/inner"),
            dev: 99,
            mnt_id: Some(42),
          },
          crate::os::DeclinedBoundary {
            location: PathBuf::from("/r/gone"),
            dev: 99,
            mnt_id: Some(42),
          },
          crate::os::DeclinedBoundary {
            location: PathBuf::from("/r/gone2"),
            dev: 99,
            mnt_id: Some(42),
          },
        ],
        reach: crate::os::WalkReach::Partial,
      },
      at(1),
    );
    assert_eq!(
      recorded(&core, scope)
        .iter()
        .map(|(path, ..)| path.clone())
        .collect::<Vec<_>>(),
      vec![
        PathBuf::from("/r/gone/inner"),
        PathBuf::from("/r/gone"),
        PathBuf::from("/r/gone2"),
      ],
      "staging: three exempt records — one AT the doomed path, one UNDER it, and \
       one whose path merely shares its bytes"
    );

    core.on_inotify_events(
      scope,
      vec![inotify(
        &[root_watch],
        IN_DELETE | IN_ISDIR,
        0,
        Some(b"gone"),
      )],
      at(1),
    );
    let _ = drain(&mut core);
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/gone2"), Some(42), None)],
      "the record AT the vanished path and the one UNDER it both go; the string \
       neighbour is a different directory and stays"
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
        root_incarnation: None,
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
        root_incarnation: None,
      },
      at(1),
    );
    let _ = drain(&mut core);

    // The next enumerate still fences on the captured frame (42): a mount-77 child is
    // still a boundary (the fence did not degrade to the device belt alone).
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
        root_incarnation: None,
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
        root_incarnation: None,
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
        root_incarnation: None,
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
        root_incarnation: None,
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
    let _ = run_cascade_probing(core, listings);
  }

  /// [`run_cascade`], additionally reporting every `Effect::Probe` it passed
  /// over. A cascade answers arms and reads; the slot-kind stat an
  /// unclassifiable listing entry asks for is deliberately left OUTSTANDING —
  /// no cascade can answer it — so a cell that needs the request must be handed
  /// it from here.
  fn run_cascade_probing(
    core: &mut DriverCore,
    listings: &BTreeMap<&str, Vec<RawDirEntry>>,
  ) -> Vec<(ProbeId, PathBuf)> {
    let mut probes = Vec::new();
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
          Effect::Probe { probe, path } => probes.push((*probe, path.clone())),
          _ => {}
        }
      }
      if !progressed {
        return probes;
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
        declined: Vec::new(),
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

  /// [`root_listing`] plus one entry no kind could be read for — the
  /// `DT_UNKNOWN` shape. The crawl reconciles nothing for `mystery`: it books
  /// the slot as darkness and asks the driver for a kind.
  fn root_listing_with_unknown() -> Vec<RawDirEntry> {
    let mut entries = root_listing();
    entries.push(entry("mystery", FileKind::Unknown, 1, 13));
    entries
  }

  /// The same listing once the slot has been classified, for the re-arm reads a
  /// later window performs: an unchanged `mystery` must re-list as what it turned
  /// out to be, or the read would retire its watch and stand a `Rescan` of its
  /// own — a cover the cells below must not be able to pass on.
  fn root_listing_with_classified() -> Vec<RawDirEntry> {
    let mut entries = root_listing();
    entries.push(entry("mystery", FileKind::Dir, 1, 13));
    entries
  }

  /// A live descending scope at `/r` whose REGISTRATION listing carried one
  /// unclassifiable entry: `keep` and `drop` are armed, the registration
  /// window's own loss memory is spent, and the stat that must decide
  /// `/r/mystery` is outstanding and stamped with that window
  /// ([`Monitor::stat_loss_outstanding`]).
  ///
  /// The stat is uncounted and no conjunct of the barrier, so the scope reads
  /// settled here with `/r/mystery` covered by nothing — which is the whole
  /// window the two cells below are about.
  fn bootstrapped_with_unknown_slot() -> (DriverCore, ScopeId, ProbeId) {
    let (mut core, scope, req, _root) = live_descending();
    core.on_enumerated(req, listed(root_listing_with_unknown()));
    let probes = run_cascade_probing(&mut core, &BTreeMap::new());
    let (probe, path) = probes
      .into_iter()
      .find(|(_, path)| path.as_path() == Path::new("/r/mystery"))
      .expect("the unclassifiable slot is probed for its kind");
    assert_eq!(path, p("/r/mystery"));
    assert!(
      core.monitor.rearm_settled(scope),
      "the crawl quiesced without waiting for the stat"
    );
    clear_registration_loss(&mut core, scope);
    assert!(
      core.monitor.stat_loss_outstanding(scope),
      "and the stamped stat outlives the window that queued it"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(state.applied_cover, None, "no claim has been recorded yet");
    assert_eq!(state.settle_floor, None);
    (core, scope, probe)
  }

  /// Narrows `scope` to `{/r/keep}` and observes the settle, so the scope has a
  /// recorded floor for the broadening cover below to under-claim against.
  /// Reply-less, so no fence's verdict rides it.
  fn narrow_to_keep(core: &mut DriverCore, scope: ScopeId) {
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep")]),
      CoverReconcile::Reconciling
    );
    assert!(
      drain(core)
        .iter()
        .any(|e| matches!(e, Effect::RemoveWatch { .. })),
      "the shrink prunes what /r/keep leaves out"
    );
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(state.applied_cover, Some(vec![p("/r/keep")]));
    assert_eq!(state.settle_floor, Some(vec![p("/r/keep")]));
  }

  /// 42-10 cell 6c — a fence may not certify a window a REGISTRATION-stamped
  /// stat is still owed an answer for.
  ///
  /// `/r/mystery` may be a directory, and until the stat says so the scope holds
  /// no watch on it: an entry created beneath it is recorded by nobody. The stat
  /// is deliberately uncounted and deliberately no conjunct of
  /// [`Monitor::coverage_settled`], so the barrier quiesces regardless — the
  /// window between the queue and the answer is exactly a settled scope with an
  /// uncovered slot, and a fence opened inside it used to resolve `Applied`.
  ///
  /// Both halves of the honest verdict are pinned, because the verdict alone
  /// under-states it: the fence reports `Degraded`, AND the settle floor is left
  /// under-claimed instead of promoting the broadened cover — which is what
  /// makes the next `set_cover` recompute a real broadening delta rather than
  /// ride a claim nothing proved.
  ///
  /// Staged as a BROADENING cover so the two are distinguishable at all: after a
  /// narrow to `{/r/keep}` the floor and the applied claim differ, and a clean
  /// settle would promote the floor to `{/r/keep, /r/drop}`.
  ///
  /// The cover the verdict owes is pinned with it, and BEFORE it: the settling
  /// observation stands the scope-level `Rescan` and holds the tranche over for
  /// it, so the instruction reaches the consumer ahead of the answer that
  /// promises it.
  ///
  /// Mutation that kills it: drop the settlement's
  /// `stat_loss_outstanding` consult in `poll_cover_settlements`. The
  /// fence then certifies the window and promotes the floor over a slot the
  /// scope has never covered.
  #[test]
  fn a_fence_over_an_unanswered_bootstrap_stat_settles_degraded_and_keeps_its_floor() {
    let (mut core, scope, _probe) = bootstrapped_with_unknown_slot();
    narrow_to_keep(&mut core, scope);

    // The broadening cover: a PURE grow, which stands no `Rescan` of its own —
    // so the standing stat is the only thing that can degrade this window.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    run_cascade(
      &mut core,
      &BTreeMap::from([("/r", root_listing_with_unknown())]),
    );
    assert!(
      core.monitor.rearm_settled(scope),
      "the regrow quiesced, so nothing counted withholds the verdict"
    );
    assert!(
      core.monitor.stat_loss_outstanding(scope),
      "and the slot is still uncovered when the fence is asked"
    );

    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the observation stands the cover first and holds the tranche over for it"
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{effects:?}");
    assert!(
      emitted[0].kind().is_rescan() && emitted[0].location() == &loc(&[]),
      "the cover is the scope's, since the slot's kind is exactly what nobody \
       knows: {emitted:?}"
    );
    // Dequeuing an effect is not delivering it — the driver's flush reports the
    // send's outcome, and only an ACCEPTANCE puts the instruction on the stream.
    core.on_delivery(scope, Delivery::Accepted, at(1));

    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "a settled scope with an unanswered registration stat is not a covered one"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.settle_floor,
      Some(Vec::new()),
      "the floor drops with that cover rather than promoting the broadened one, \
       so the next `set_cover` recomputes a real delta"
    );
    assert_eq!(
      state.applied_cover,
      Some(Vec::new()),
      "and the optimistic claim goes with it, as it does under any other cover"
    );
  }

  /// …and the loss is exactly as short-lived as the request. Once the stat is
  /// answered the slot is covered, the signal clears, and the next window
  /// certifies normally — `Applied`, with the floor promoted to the cover it
  /// just proved.
  ///
  /// The counterpart the cell above needs to mean anything: a signal that never
  /// cleared would degrade every fence the scope ever opens, which is
  /// indistinguishable from the fix working and strictly worse than the defect.
  ///
  /// Mutation that kills it: release the loss nowhere (drop the
  /// `stat_loss_dec` at `ingest_stat_result`'s request removal). The
  /// answered scope then never certifies again.
  #[test]
  fn an_answered_bootstrap_stat_lets_the_next_fence_certify() {
    let (mut core, scope, probe) = bootstrapped_with_unknown_slot();

    // The answer: `mystery` is a directory after all. Its install is routed
    // through the crawl's own suppression (C1), so the sub-window it opens is
    // counted and closes with a covering `Rescan` — spent below, exactly as the
    // registration window's own was, so the fence beneath is not riding it.
    core.on_probe_result(
      probe,
      ProbeOutcome::Present {
        kind: FileKind::Dir,
        file_id: NonZeroU64::new(13),
        dev: 1,
        mnt_id: None,
      },
      at(1),
    );
    run_cascade(
      &mut core,
      &BTreeMap::from([("/r", root_listing_with_classified())]),
    );
    assert!(
      !core.monitor.stat_loss_outstanding(scope),
      "the answer released the loss it was standing for"
    );
    clear_registration_loss(&mut core, scope);
    narrow_to_keep(&mut core, scope);

    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    run_cascade(
      &mut core,
      &BTreeMap::from([("/r", root_listing_with_classified())]),
    );
    assert!(core.monitor.rearm_settled(scope));

    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Applied)],
      "the answered scope certifies its window like any other"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.settle_floor,
      Some(vec![p("/r/keep"), p("/r/drop")]),
      "and the clean verdict promotes the floor to the cover it proved"
    );
  }

  /// The same window, and the registration has nothing to do with it: a LATER
  /// grow lists an unclassifiable name at a slot nothing occupies, and a fence
  /// opened between that queue and its answer may not certify it either.
  ///
  /// `/r/mystery` may be a directory, and until the probe says so the scope holds
  /// no watch on it: an entry created beneath it is recorded by nobody. Every
  /// cover the registration case could fall back on is absent here — the window
  /// is long closed, so nothing stamps the request, and the grow is PURE, so the
  /// read that found the slot stood no `Rescan` of its own. The standing coverage
  /// deficit does not close it: that re-signals at a sync cookie's DISPATCH,
  /// which this set-cover reply passes nowhere near.
  ///
  /// Both halves of the honest verdict are pinned, because the verdict alone
  /// under-states it: the fence reports `Degraded`, AND the settle floor is left
  /// under-claimed instead of promoting the broadened cover — which is what
  /// makes the next `set_cover` recompute a real broadening delta rather than
  /// ride a claim nothing proved.
  ///
  /// The cover the verdict owes is pinned with it, and BEFORE it: the settling
  /// observation stands the scope-level `Rescan` and holds the tranche over for
  /// it, so the instruction reaches the consumer ahead of the answer that
  /// promises it.
  ///
  /// Mutation that kills it: narrow `queue_stat`'s loss predicate back to the
  /// registration stamp (`let stands_loss = bootstrap;`). The fence then
  /// certifies the window and promotes the floor over a slot the scope has never
  /// covered.
  #[test]
  fn a_fence_over_an_unanswered_empty_slot_stat_settles_degraded_and_keeps_its_floor() {
    let (mut core, scope, _root) = shrunk_to_keep();
    assert!(
      !core.monitor.stat_loss_outstanding(scope),
      "staging: the shrunk scope owes no loss, and its registration window is spent"
    );

    // The broadening cover: a PURE grow, which stands no `Rescan` of its own —
    // so the standing stat is the only thing that can degrade this window.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    run_cascade(
      &mut core,
      &BTreeMap::from([("/r", root_listing_with_unknown())]),
    );
    assert!(
      core.monitor.rearm_settled(scope),
      "the regrow quiesced, so nothing counted withholds the verdict"
    );
    assert!(
      core.monitor.stat_loss_outstanding(scope),
      "and the slot is still uncovered when the fence is asked"
    );

    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "the observation stands the cover first and holds the tranche over for it"
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "{effects:?}");
    assert!(
      emitted[0].kind().is_rescan() && emitted[0].location() == &loc(&[]),
      "the cover is the scope's, since the slot's kind is exactly what nobody \
       knows: {emitted:?}"
    );
    // Dequeuing an effect is not delivering it — the driver's flush reports the
    // send's outcome, and only an ACCEPTANCE puts the instruction on the stream.
    core.on_delivery(scope, Delivery::Accepted, at(1));

    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "a settled scope with an unanswered empty-slot stat is not a covered one"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.settle_floor,
      Some(Vec::new()),
      "the floor drops with that cover rather than promoting the broadened one, \
       so the next `set_cover` recomputes a real delta"
    );
    assert_eq!(
      state.applied_cover,
      Some(Vec::new()),
      "and the optimistic claim goes with it, as it does under any other cover"
    );
  }

  /// [`run_cascade`], additionally answering every `Effect::Emit` the drain
  /// offers — accepting each where `accept`, refusing each otherwise — and
  /// reporting the changes it offered, in offer order. The driver's flush
  /// reports each send's outcome synchronously, so a cell that drops one models
  /// a driver that cannot exist.
  fn run_cascade_delivering(
    core: &mut DriverCore,
    listings: &BTreeMap<&str, Vec<RawDirEntry>>,
    accept: bool,
    now: Instant,
  ) -> Vec<Change> {
    let mut offered = Vec::new();
    let mut wd = 200;
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
          Effect::Emit { scope, change, .. } => {
            offered.push(change.clone());
            let delivery = if accept {
              Delivery::Accepted
            } else {
              Delivery::Refused
            };
            core.on_delivery(*scope, delivery, now);
            progressed = true;
          }
          _ => {}
        }
      }
      if !progressed {
        return offered;
      }
    }
    panic!("the cascade did not quiesce within the iteration bound");
  }

  /// Staging for the cell below: a tranche licensed over a standing empty-slot
  /// stat, whose cover the consumer's channel REFUSED — and whose replacement
  /// ordering proof is already in hand.
  ///
  /// The refusal is the driver's `Full` arm: it purges the queued cover, folds it
  /// into the scope's never-narrowing parked `Rescan` (INV-PARK), and signals the
  /// overflow — which re-opens the scope's coverage work and so retires the proof
  /// the standing pass held. The offer that instruction then makes is refused
  /// too (the channel has had no chance to drain), so the lane ends parked on its
  /// delivery retry. Rebuilding past all of it is the sequence that matters:
  /// overflow recovery, replacement proof, and the tranche licensed again with
  /// the cover offered, refused, and still undelivered.
  fn stat_cover_refused(core: &mut DriverCore, scope: ScopeId) -> FenceId {
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    let listings = BTreeMap::from([("/r", root_listing_with_unknown())]);
    run_cascade(core, &listings);
    assert!(core.monitor.stat_loss_outstanding(scope));
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "staging: the observation stands the cover and holds the tranche for the \
       one flush that offers it"
    );
    assert!(
      core.take_cover_flush_due(),
      "staging: and asks the driver for that flush"
    );

    let offered = run_cascade_delivering(core, &listings, false, at(1));
    assert_eq!(offered.len(), 2, "{offered:?}");
    assert!(
      offered
        .iter()
        .all(|change| change.kind().is_rescan() && change.location() == &loc(&[])),
      "staging: the refused cover, then the dominating instruction it folded \
       into: {offered:?}"
    );
    assert!(
      core.monitor.rearm_settled(scope),
      "staging: the overflow's own recovery quiesced"
    );
    assert!(
      core.monitor.stat_loss_outstanding(scope),
      "staging: and the slot is dark throughout — nothing answered the stat"
    );
    core.mark_cut_inflight(scope, 2);
    core.prove_cut(scope, 2);
    fence
  }

  /// THE ANSWER IS NOT GATED ON CONSUMER PROGRESS. `Degraded` reports a covering
  /// `Rescan` EMITTED, never one delivered, so the offer's outcome may not decide
  /// when the verdict is minted: a caller awaiting `set_cover` while its own
  /// channel sits full and unread would otherwise be waiting on itself.
  ///
  /// Here the loop-top `try_send` refuses the cover, the refusal purges it into
  /// the scope's parked dominating instruction, that instruction's own offer is
  /// refused too, and the lane ends parked on its delivery retry with the
  /// consumer still holding nothing. The very next observation answers anyway.
  /// The latch is preserved across all of it — no second cover is stood, which is
  /// what keeps a scope whose stat never answers from re-instructing a consumer
  /// on every pass — and no second re-top is asked for, because the ordering the
  /// flag buys was spent on the flush that made the refused offer.
  ///
  /// Mutation that kills it: gate the resolution on the delivery — hold while the
  /// scope's cover is undelivered, by watermark, by lane state, or by looking for
  /// the emit in the queue. The observation below then reports nothing, the
  /// caller's reply is parked behind a channel only the caller can drain, and
  /// this cell fails on the assertion that names it. This is a LIVENESS failure:
  /// no verdict arrives while the consumer does not read.
  #[test]
  fn a_stat_cover_refused_by_a_full_consumer_still_answers_its_tranche() {
    let (mut core, scope, _root) = shrunk_to_keep();
    let fence = stat_cover_refused(&mut core, scope);
    assert!(
      matches!(
        core.scopes.get(&scope).map(|state| &state.lag),
        Some(LagState::Lagged { .. })
      ),
      "staging: the lane is parked on its retry — the consumer has taken nothing"
    );

    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "the tranche is licensed again and answers: the cover was emitted, and \
       delivering it is not what the verdict claims"
    );
    assert!(
      !core.take_cover_flush_due(),
      "and asks for no second flush — the one it already took is the whole ordering"
    );

    // The instruction is not lost by being answered ahead of: it stays parked and
    // the lane's own retry re-offers it, behind the verdict.
    core.on_timeout(at(100));
    let effects = drain(&mut core);
    let retried = emits(&effects);
    assert_eq!(retried.len(), 1, "{effects:?}");
    assert!(
      retried[0].kind().is_rescan() && retried[0].location() == &loc(&[]),
      "the covering `Rescan` is re-offered after the answer: {retried:?}"
    );
  }

  /// …and it answers after exactly ONE flush, however busy the lane. The hold is
  /// spent by the re-top, not by the queue draining: an epoch names a
  /// reconciliation generation and not one instruction, so every ordinary change
  /// routed after the covering `Rescan` carries that same generation, and the
  /// driver ingests a source snapshot immediately BEFORE it polls settlements and
  /// leaves those effects queued. A scope that is merely busy therefore has an
  /// emit at the cover's own epoch resident at every observation it ever reaches.
  ///
  /// Here the consumer accepts everything it is offered and one ordinary
  /// same-epoch change arrives after the flush. The tranche resolves regardless,
  /// and with it the settlement report a fence's parked cookie dispatches out of.
  ///
  /// Mutation that kills it: spend the hold on the queue instead of on the flush
  /// — hold while any emit at the cover's generation is still queued for the
  /// scope, the natural way to write "make sure the cover got out". The unrelated
  /// `Created` below answers yes, and answers yes again on every later pass a
  /// producing lane reaches, so the acknowledgement and its cookie are parked for
  /// as long as the scope stays busy. This is a LIVENESS failure — no verdict
  /// arrives at all — on a healthy lane whose consumer is keeping up.
  #[test]
  fn a_stat_cover_answers_behind_one_flush_however_busy_the_lane() {
    let (mut core, scope, root) = shrunk_to_keep();
    let listings = BTreeMap::from([("/r", root_listing_with_unknown())]);

    // The broadening cover: a PURE grow, standing no `Rescan` of its own, so the
    // standing stat is the only thing that can degrade this window.
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    run_cascade(&mut core, &listings);
    assert!(core.monitor.rearm_settled(scope));
    assert!(core.monitor.stat_loss_outstanding(scope));
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);

    // One ordinary change on the lane, left QUEUED — what the loop-top drain
    // leaves behind when it ingests a snapshot just before this observation.
    let mut churned = 0u64;
    let mut churn = |core: &mut DriverCore| {
      churned += 1;
      core.on_inotify_events(
        scope,
        vec![inotify(
          &[root],
          IN_CREATE,
          0,
          Some(format!("f{churned}").as_bytes()),
        )],
        at(100 + churned),
      );
    };
    let queued_epochs = |core: &DriverCore| -> Vec<tributary_proto::Epoch> {
      core
        .effects
        .iter()
        .filter_map(|effect| match effect {
          Effect::Emit { change, .. } => Some(change.epoch()),
          _ => None,
        })
        .collect()
    };

    churn(&mut core);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      Vec::new(),
      "staging: the observation stands the cover and holds the tranche for the flush"
    );
    assert!(
      core.take_cover_flush_due(),
      "staging: and asks for the flush"
    );

    // The re-top's flush, with a consumer that takes everything it is offered.
    let flushed = drain(&mut core);
    let offered = emits(&flushed);
    let cover = offered
      .iter()
      .find(|change| change.kind().is_rescan() && change.location() == &loc(&[]))
      .map(|change| change.epoch())
      .expect("staging: the flush offers the cover");
    for _ in &offered {
      core.on_delivery(scope, Delivery::Accepted, at(200));
    }

    // …and the lane keeps producing. Nothing has bumped the generation since the
    // cover was minted, so this ordinary change carries the cover's OWN epoch and
    // is resident when the observation below runs.
    churn(&mut core);
    assert_eq!(
      queued_epochs(&core),
      vec![cover],
      "staging: unrelated traffic at the cover's own generation is queued at the \
       observation"
    );

    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "the verdict answers behind the one flush that offered the cover, whatever \
       else the lane has since queued"
    );
  }

  /// …and the loss is exactly as short-lived as the request on this trigger too.
  /// Once the probe is answered the slot is covered, the signal clears, and the
  /// next window certifies normally — `Applied`, with the floor promoted to the
  /// cover it just proved.
  ///
  /// The counterpart the cell above needs to mean anything: a signal that never
  /// cleared — or one every unclassifiable entry raised — would degrade every
  /// fence the scope ever opens, which is indistinguishable from the fix working
  /// and strictly worse than the defect.
  ///
  /// Mutation that kills it: release the loss nowhere (drop the `stat_loss_dec`
  /// at `ingest_stat_result`'s request removal). The answered scope then never
  /// certifies again.
  #[test]
  fn an_answered_empty_slot_stat_lets_the_next_fence_certify() {
    let (mut core, scope, _root) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let probes = run_cascade_probing(
      &mut core,
      &BTreeMap::from([("/r", root_listing_with_unknown())]),
    );
    let (probe, path) = probes
      .into_iter()
      .find(|(_, path)| path.as_path() == Path::new("/r/mystery"))
      .expect("the unclassifiable slot is probed for its kind");
    assert_eq!(path, p("/r/mystery"));
    assert!(core.monitor.stat_loss_outstanding(scope));

    // The answer: `mystery` is a directory after all. Its install heals the
    // booked hole, which stands the covering `Rescan` — spent below, so the
    // fence beneath is not riding it.
    core.on_probe_result(
      probe,
      ProbeOutcome::Present {
        kind: FileKind::Dir,
        file_id: NonZeroU64::new(13),
        dev: 1,
        mnt_id: None,
      },
      at(1),
    );
    run_cascade(
      &mut core,
      &BTreeMap::from([("/r", root_listing_with_classified())]),
    );
    assert!(
      !core.monitor.stat_loss_outstanding(scope),
      "the answer released the loss it was standing for"
    );
    // The heal's own covering `Rescan` is a loss like any other, and it is spent
    // here, so the fence below is measuring the stat and nothing else.
    clear_registration_loss(&mut core, scope);
    assert_eq!(
      core.scopes.get(&scope).unwrap().settle_floor,
      Some(Vec::new()),
      "the heal's Rescan degraded the narrowed claim, as every Rescan does — \
       so the floor below has somewhere to be promoted FROM"
    );

    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    run_cascade(
      &mut core,
      &BTreeMap::from([("/r", root_listing_with_classified())]),
    );
    assert!(core.monitor.rearm_settled(scope));

    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Applied)],
      "the answered scope certifies its window like any other"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.settle_floor,
      Some(vec![p("/r/keep"), p("/r/drop")]),
      "and the clean verdict promotes the floor to the cover it proved"
    );
  }

  /// The fine entries a Monitor deficit book holds before it collapses to the
  /// whole-scope marker, plus one. Restated here because the constant itself is
  /// private to the Monitor; the staging below asserts the collapse rather than
  /// trusting the number.
  const PAST_DEFICIT_CAP: usize = 17;

  /// [`root_listing`] plus enough unclassifiable names to COLLAPSE the scope's
  /// deficit book. Past the cap the book keeps no fine entry at all, so nothing
  /// any of these slots' answers settles has a hole to heal — and the heal is
  /// what stands the covering `Rescan` for every ordinary empty-slot answer.
  fn root_listing_past_the_deficit_cap() -> Vec<RawDirEntry> {
    let mut entries = root_listing();
    for i in 0..PAST_DEFICIT_CAP {
      entries.push(entry(
        &std::format!("u{i:02}"),
        FileKind::Unknown,
        1,
        20 + i as u64,
      ));
    }
    entries
  }

  /// A fence held open ACROSS the answers, over a book that collapsed: the
  /// observation that finally reads the scope finds neither the standing loss nor
  /// a heal, and it must still not certify the window.
  ///
  /// This is the whole shape the settlement loss exists for, run past its
  /// release. The grow is pure, so the read that listed `/r/uNN` stood no
  /// `Rescan`. Every slot is empty, so each request stands the loss. Every answer
  /// resolves to a DIRECTORY, so each install is a cold `install_child` whose
  /// only cover is `remove_slot_deficit` — and the collapsed book left it nothing
  /// to remove. And the window is never observed while the loss stands: a re-arm
  /// read left outstanding keeps the fence pending across every answer, exactly
  /// as any other unfinished coverage work would.
  ///
  /// So the release is the last thing standing between this fence and `Applied`
  /// over intervals during which seventeen directories were watched by nobody.
  /// The verdict must be `Degraded`, and the settle floor must keep its
  /// under-claim so the next `set_cover` recomputes a real broadening delta.
  ///
  /// Mutation that kills it: drop the transfer in `ingest_stat_result` (return
  /// `false` from the resolving arm). The fence then reports `Applied` and
  /// promotes the floor over ground it never covered.
  #[test]
  fn a_fence_held_past_a_collapsed_book_answer_settles_degraded_and_keeps_its_floor() {
    let (mut core, scope, _root) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    assert!(
      !core.monitor.rearm_settled(scope),
      "staging: the grow's counted work holds the fence open from the start"
    );
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());

    // Drive the grow, holding `/r/keep`'s re-arm READ back: that is the counted
    // work that keeps the fence pending across every answer below, so no
    // observation can spend the loss before the transfer has to stand.
    let listings = BTreeMap::from([("/r", root_listing_past_the_deficit_cap())]);
    let mut probes = Vec::new();
    let mut held_read = None;
    let mut wd = 200;
    for _ in 0..64 {
      let effects = drain(&mut core);
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
            if held_read.is_none() && path.as_path() == Path::new("/r/keep") {
              held_read = Some(*req);
              continue;
            }
            let entries = listings
              .get(path.to_str().expect("test paths are UTF-8"))
              .cloned()
              .unwrap_or_default();
            core.on_enumerated(*req, listed(entries));
            progressed = true;
          }
          Effect::Probe { probe, path } => probes.push((*probe, path.clone())),
          _ => {}
        }
      }
      if !progressed {
        break;
      }
    }
    let held_read = held_read.expect("the survivor `/r/keep` is re-armed and re-read");
    assert_eq!(
      probes.len(),
      PAST_DEFICIT_CAP,
      "every unclassifiable slot is probed for its kind"
    );
    assert!(
      core.monitor.stat_loss_outstanding(scope),
      "staging: and each of them stands the scope's settlement loss"
    );
    assert!(
      !core.monitor.rearm_settled(scope),
      "staging: the held read keeps the fence pending across the answers"
    );

    // Every slot turns out to be a directory. Each install heals nothing — the
    // collapsed book holds no entry — so the loss each release ends is the whole
    // of what covered its interval.
    for (probe, path) in probes {
      let ino = path
        .to_str()
        .and_then(|path| path.rsplit('u').next())
        .and_then(|digits| digits.parse::<u64>().ok())
        .expect("every probe names one of the unclassifiable slots");
      core.on_probe_result(
        probe,
        ProbeOutcome::Present {
          kind: FileKind::Dir,
          file_id: NonZeroU64::new(20 + ino),
          dev: 1,
          mnt_id: None,
        },
        at(5),
      );
    }
    assert!(
      !core.monitor.stat_loss_outstanding(scope),
      "the answers released every loss they stood"
    );

    // Only now does the scope quiesce, and only now is it observed.
    core.on_enumerated(held_read, listed(Vec::new()));
    run_cascade(&mut core, &listings);
    assert!(core.monitor.rearm_settled(scope));
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "a window whose only cover was the released loss is not a certified one"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.settle_floor,
      Some(Vec::new()),
      "and the floor keeps its under-claim rather than promoting the broadened cover"
    );
  }

  /// The same fence, held past a racing OCCUPATION of every dark slot: the
  /// answers land on slots a create has already filled, and the window may not
  /// certify over the interval BEFORE those fills either.
  ///
  /// Every cover is stripped exactly as above — pure grow, collapsed book, no
  /// heal for any answer to defer to — and one more thing is true here: each
  /// slot holds a live watch by the time its answer arrives. That watch covers
  /// the slot from its own arm forward and says nothing at all about the
  /// interval between the listing that could not name the entry and the create
  /// that filled it, which is exactly the interval the settlement loss was
  /// standing for. The occupation could not hand that interval to a cover
  /// either: `remove_slot_deficit` is its only one, and the collapse left it
  /// nothing to remove.
  ///
  /// So an answer that read the filled slot as proof of an unbroken cover would
  /// release the loss into silence and hand this fence `Applied` over seventeen
  /// intervals during which seventeen directories were watched by nobody.
  ///
  /// Mutation that kills it: decide the transfer from the live slot again
  /// (`incumbent.is_none()` in place of `dark_interval` in
  /// `ingest_stat_result`). Every answer then finds its slot occupied, stands
  /// nothing, and the fence certifies the window.
  #[test]
  fn a_fence_held_past_a_racing_occupation_settles_degraded_and_keeps_its_floor() {
    let (mut core, scope, root_watch) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    assert!(
      !core.monitor.rearm_settled(scope),
      "staging: the grow's counted work holds the fence open from the start"
    );
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());

    // Drive the grow, holding `/r/keep`'s re-arm READ back: that is the counted
    // work that keeps the fence pending across every answer below.
    let listings = BTreeMap::from([("/r", root_listing_past_the_deficit_cap())]);
    let mut probes = Vec::new();
    let mut held_read = None;
    let mut wd = 300;
    for _ in 0..64 {
      let effects = drain(&mut core);
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
            if held_read.is_none() && path.as_path() == Path::new("/r/keep") {
              held_read = Some(*req);
              continue;
            }
            let entries = listings
              .get(path.to_str().expect("test paths are UTF-8"))
              .cloned()
              .unwrap_or_default();
            core.on_enumerated(*req, listed(entries));
            progressed = true;
          }
          Effect::Probe { probe, path } => probes.push((*probe, path.clone())),
          _ => {}
        }
      }
      if !progressed {
        break;
      }
    }
    let held_read = held_read.expect("the survivor `/r/keep` is re-armed and re-read");
    assert_eq!(
      probes.len(),
      PAST_DEFICIT_CAP,
      "every unclassifiable slot is probed for its kind"
    );
    assert!(
      core.monitor.stat_loss_outstanding(scope),
      "staging: and each of them stands the scope's settlement loss"
    );

    // THE RACE. A create fills every dark slot while its probe is still
    // outstanding, so each answer will meet a slot that reads occupied.
    let names: Vec<String> = (0..PAST_DEFICIT_CAP)
      .map(|i| std::format!("u{i:02}"))
      .collect();
    let creates: Vec<RawLinuxEvent> = names
      .iter()
      .map(|name| {
        inotify(
          &[root_watch],
          IN_CREATE | IN_ISDIR,
          0,
          Some(name.as_bytes()),
        )
      })
      .collect();
    core.on_inotify_events(scope, creates, at(3));
    let mut occupied = 0usize;
    for _ in 0..64 {
      let effects = drain(&mut core);
      let mut progressed = false;
      for effect in &effects {
        match effect {
          Effect::AddWatch { watch, path, .. } => {
            // Matched as a PATH and not as a string: an arm's path is `join`ed
            // onto its parent, so the separator between them is the platform's.
            occupied += usize::from(
              names
                .iter()
                .any(|name| path.as_path() == Path::new("/r").join(name)),
            );
            wd += 1;
            core.on_watch_installed(
              *watch,
              core.arm_attempt(*watch),
              crate::os::linux::WatchOutcome::Installed(wd),
            );
            progressed = true;
          }
          Effect::Enumerate { req, path, .. } => {
            assert_ne!(
              path.as_path(),
              Path::new("/r/keep"),
              "the held read is not re-issued while it is outstanding"
            );
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
        break;
      }
    }
    assert_eq!(
      occupied, PAST_DEFICIT_CAP,
      "staging: every dark slot is filled and armed before its answer returns"
    );
    assert!(
      core.monitor.stat_loss_outstanding(scope),
      "staging: and not one of those fills discharged a loss — the collapsed book \
       left each occupation's heal nothing to remove"
    );
    assert!(
      !core.monitor.rearm_settled(scope),
      "staging: the held read still keeps the fence pending across the answers"
    );

    // Every answer confirms the directory the create already installed. Nothing
    // is retired, nothing is healed: the released loss is the whole of what
    // covered each interval.
    for (probe, path) in probes {
      let ino = path
        .to_str()
        .and_then(|path| path.rsplit('u').next())
        .and_then(|digits| digits.parse::<u64>().ok())
        .expect("every probe names one of the unclassifiable slots");
      core.on_probe_result(
        probe,
        ProbeOutcome::Present {
          kind: FileKind::Dir,
          file_id: NonZeroU64::new(20 + ino),
          dev: 1,
          mnt_id: None,
        },
        at(5),
      );
    }
    assert!(
      !core.monitor.stat_loss_outstanding(scope),
      "the answers released every loss they stood"
    );

    // Only now does the scope quiesce, and only now is it observed.
    core.on_enumerated(held_read, listed(Vec::new()));
    run_cascade(&mut core, &listings);
    assert!(core.monitor.rearm_settled(scope));
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "a filled slot is not proof the slot was never dark"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.settle_floor,
      Some(Vec::new()),
      "and the floor keeps its under-claim rather than promoting the broadened cover"
    );
  }

  /// The same fence, and this time the book is NOT collapsed: it holds the dark
  /// slot's fine entry from the moment the grow could not name the kind until
  /// well past the answer, and nothing ever turns that entry into a cover.
  ///
  /// A paired RENAME occupies `/r/mystery` while the probe is outstanding. That
  /// occupation is an O(1) re-key of an existing subtree — it consults no deficit
  /// and heals no hole — so the entry stands, and when the answer arrives naming
  /// the very directory the rename carried in, the settlement REUSES it: nothing
  /// is installed, nothing is removed, nothing is retired, and the entry is left
  /// for a sync cookie's DISPATCH to re-signal, which this set-cover reply passes
  /// nowhere near.
  ///
  /// So a recorded hole is not a cover, and an answer that read the book as a
  /// promise of one would release the loss into silence and hand this fence
  /// `Applied` over the interval before the rename — during which `/r/mystery`
  /// may have been a directory watched by nobody.
  ///
  /// Mutation that kills it: decide the transfer from the book again (`!booked`,
  /// read before the reconcile, in place of `!healed` in `ingest_stat_result`).
  /// The standing entry then suppresses the cover the release owed and the fence
  /// certifies the window.
  #[test]
  fn a_fence_held_past_a_move_in_over_a_booked_hole_settles_degraded_and_keeps_its_floor() {
    let (mut core, scope, root_watch) = shrunk_to_keep();
    assert_eq!(
      core.on_set_cover(scope, &[p("/r/keep"), p("/r/drop")]),
      CoverReconcile::Reconciling
    );
    let fence = core.open_cover_fence(scope);
    assert!(
      !core.monitor.rearm_settled(scope),
      "staging: the grow's counted work holds the fence open from the start"
    );
    assert_eq!(core.poll_cover_settlements(DRAINED), Vec::new());

    // Drive the grow, holding `/r/keep`'s re-arm READ back: that is the counted
    // work that keeps the fence pending across the answer below, so no
    // observation can spend the loss before the transfer has to stand.
    let listings = BTreeMap::from([("/r", root_listing_with_unknown())]);
    let mut probes = Vec::new();
    let mut held_read = None;
    let mut wd = 400;
    for _ in 0..64 {
      let effects = drain(&mut core);
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
            if held_read.is_none() && path.as_path() == Path::new("/r/keep") {
              held_read = Some(*req);
              continue;
            }
            let entries = listings
              .get(path.to_str().expect("test paths are UTF-8"))
              .cloned()
              .unwrap_or_default();
            core.on_enumerated(*req, listed(entries));
            progressed = true;
          }
          Effect::Probe { probe, path } => probes.push((*probe, path.clone())),
          _ => {}
        }
      }
      if !progressed {
        break;
      }
    }
    let held_read = held_read.expect("the survivor `/r/keep` is re-armed and re-read");
    let (probe, path) = probes
      .into_iter()
      .find(|(_, path)| path.as_path() == Path::new("/r/mystery"))
      .expect("the unclassifiable slot is probed for its kind");
    assert_eq!(path, p("/r/mystery"));
    assert!(
      core.monitor.stat_loss_outstanding(scope),
      "staging: and the empty slot stands the scope's settlement loss"
    );
    assert!(
      core.monitor.has_coverage_deficit(scope),
      "staging: the darkness is booked, and one entry does not collapse a book"
    );

    // THE OCCUPATION. `/r/drop` is renamed onto the dark slot inside one batch,
    // so the pairing carries the subtree over with no round trip between the
    // halves to dirty the hold — an O(1) re-key, consulting no book.
    core.on_inotify_events(
      scope,
      vec![
        inotify(&[root_watch], IN_MOVED_FROM | IN_ISDIR, 9, Some(b"drop")),
        inotify(&[root_watch], IN_MOVED_TO | IN_ISDIR, 9, Some(b"mystery")),
      ],
      at(3),
    );
    assert!(
      core.monitor.has_coverage_deficit(scope),
      "staging: the re-key healed nothing — the slot's entry is still standing"
    );
    assert!(
      core.monitor.stat_loss_outstanding(scope),
      "staging: so the released loss is still the whole of what covers the interval"
    );
    assert!(
      !core.monitor.rearm_settled(scope),
      "staging: the held read still keeps the fence pending across the answer"
    );

    // The answer names the directory the rename carried in — same device, same
    // inode — so the settlement keeps it and installs nothing.
    core.on_probe_result(
      probe,
      ProbeOutcome::Present {
        kind: FileKind::Dir,
        file_id: NonZeroU64::new(12),
        dev: 1,
        mnt_id: None,
      },
      at(5),
    );
    assert!(
      !core.monitor.stat_loss_outstanding(scope),
      "the answer released the loss it was standing for"
    );

    // Only now does the scope quiesce, and only now is it observed.
    let settled = BTreeMap::from([(
      "/r",
      vec![
        entry("keep", FileKind::Dir, 1, 11),
        entry("mystery", FileKind::Dir, 1, 12),
      ],
    )]);
    core.on_enumerated(held_read, listed(Vec::new()));
    run_cascade(&mut core, &settled);
    assert!(core.monitor.rearm_settled(scope));
    core.mark_cut_inflight(scope, 1);
    core.prove_cut(scope, 1);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Degraded)],
      "a booked hole nothing healed is not a covered one"
    );
    let state = core.scopes.get(&scope).unwrap();
    assert_eq!(
      state.settle_floor,
      Some(Vec::new()),
      "and the floor keeps its under-claim rather than promoting the broadened cover"
    );
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
        declined: Vec::new(),
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

  /// Re-lists `/r` after a scope loss and hands back `entries`, returning the
  /// effects — the loss → re-arm → cold-read sequence the Monitor runs, which is
  /// exactly the sequence F3's failure needs (the loss is what eats the deletion
  /// records the compiled-removal pass would otherwise consume).
  fn relist_root_after_loss(
    core: &mut DriverCore,
    scope: ScopeId,
    root_watch: WatchId,
    entries: RawEnumerate,
    now: Instant,
  ) {
    core.on_root_overflow(scope, now);
    let _ = drain(core);
    core.on_watch_installed(
      root_watch,
      core.arm_attempt(root_watch),
      crate::os::linux::WatchOutcome::Aliased(1),
    );
    let read = drain(core)
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, path, .. } if path.as_path() == Path::new("/r") => Some(*req),
        _ => None,
      })
      .expect("the loss re-arm re-reads the root");
    core.on_enumerated(read, entries);
    let _ = drain(core);
  }

  /// A COMPLETE re-listing RETIRES the ledger entries at children it did not
  /// decline — the descending profile's generation.
  ///
  /// An exempt entry had exactly one removal path — a compiled `Removed`/
  /// `MovedFrom` in the event stream — and a loss window is precisely what
  /// empties that stream. So repeated creation and deletion of distinct flat
  /// subvolumes, each deletion lost, retained one `PathBuf` per missed deletion
  /// for the scope's whole life and made every linear scan of the ledger slower.
  /// The listing that the loss's own recovery already runs is the answer: it
  /// names every child of the directory, so an entry at a child it did not name
  /// is a boundary whose directory is gone.
  #[test]
  fn a_complete_relisting_retires_the_ledger_entries_it_did_not_decline() {
    let (mut core, scope, req, root_watch) = live_descending_mnt(42);
    // Three flat subvolumes: another device, but the ROOT's own mount id — the
    // device leg is what declines them, and the partition exempts them.
    core.on_enumerated(
      req,
      listed(vec![
        entry_on_mount("a", FileKind::Dir, 99, 11, 42),
        entry_on_mount("b", FileKind::Dir, 99, 12, 42),
        entry_on_mount("c", FileKind::Dir, 99, 13, 42),
      ]),
    );
    let _ = drain(&mut core);
    assert_eq!(
      recorded(&core, scope)
        .iter()
        .map(|(path, ..)| path.clone())
        .collect::<Vec<_>>(),
      vec![
        PathBuf::from("/r/a"),
        PathBuf::from("/r/b"),
        PathBuf::from("/r/c")
      ],
      "staging: three exempt records, learned by seam 1's own fence"
    );

    // `b` and `c` are deleted while a loss window swallows their records, so
    // nothing compiled ever names them. The recovery's own re-listing names `a`
    // alone.
    relist_root_after_loss(
      &mut core,
      scope,
      root_watch,
      listed(vec![entry_on_mount("a", FileKind::Dir, 99, 11, 42)]),
      at(2),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/a"), Some(42), None)],
      "the two the listing did not name are retired; the one it re-declined stays"
    );
  }

  /// The two ways a re-listing must NOT retire: a child it still DECLINES is
  /// live, and an INCOMPLETE read proves nothing about a name it never reached.
  #[test]
  fn a_relisting_retires_nothing_it_did_not_authoritatively_re_observe() {
    let (mut core, scope, req, root_watch) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![
        entry_on_mount("a", FileKind::Dir, 99, 11, 42),
        entry_on_mount("b", FileKind::Dir, 99, 12, 42),
      ]),
    );
    let _ = drain(&mut core);
    let both = recorded(&core, scope);
    assert_eq!(both.len(), 2, "staging: two exempt records");

    // An INCOMPLETE listing that names neither: a read cut short says nothing
    // about the names it never reached.
    relist_root_after_loss(
      &mut core,
      scope,
      root_watch,
      RawEnumerate::Listed {
        entries: Vec::new(),
        complete: false,
      },
      at(2),
    );
    assert_eq!(
      recorded(&core, scope),
      both,
      "an incomplete read retires nothing — absence from it is not evidence"
    );

    // A COMPLETE listing that still declines both leaves both standing.
    relist_root_after_loss(
      &mut core,
      scope,
      root_watch,
      listed(vec![
        entry_on_mount("a", FileKind::Dir, 99, 11, 42),
        entry_on_mount("b", FileKind::Dir, 99, 12, 42),
      ]),
      at(3),
    );
    assert_eq!(
      recorded(&core, scope),
      both,
      "and a re-declined boundary is re-observed, not retired"
    );

    // A complete listing that names `b` as an ORDINARY in-root directory: the
    // location is no longer a boundary at all, which is as good a retirement as
    // the name vanishing.
    relist_root_after_loss(
      &mut core,
      scope,
      root_watch,
      listed(vec![
        entry_on_mount("a", FileKind::Dir, 99, 11, 42),
        entry("b", FileKind::Dir, 1, 12),
      ]),
      at(4),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/a"), Some(42), None)],
      "a child the fence no longer declines is not a boundary any more"
    );
  }

  /// The ledger is HARD BOUNDED, so it is finite even where every reconciliation
  /// path fails.
  ///
  /// The containment rule inside `record_boundary` was once documented as the
  /// growth bound and never was one: it refuses an entry BENEATH an existing one
  /// and says nothing about a flat run of siblings, which is exactly the shape a
  /// churning subvolume layout produces.
  ///
  /// Eviction is oldest-first and safe in the cover direction: a `SameMount`
  /// entry joins no census and can never become a witness, so dropping one can
  /// only ever cause an extra arrival cover, never withhold one that was owed.
  ///
  /// # The bound is crossed by BUILDING the incumbents, not by listing them
  ///
  /// This cell used to drive all 1030 intakes through one enumerate. That is the
  /// same shape three sibling cells were cut from, and it is what finally
  /// exhausted the i686 miri shard's 4 GB address space — `resource exhaustion:
  /// there are no more free addresses in the address space`, reported against
  /// this cell on the first `fs-rest` run CI ever took to a verdict. A full-scale
  /// listing allocates a `RawDirEntry` (and its name `Vec`) per child on top of
  /// every record, and the interpreter holds all of it at once.
  ///
  /// What that costs in coverage is stated rather than assumed: **nothing in the
  /// intake path branches on a listing's SIZE.** `on_enumerated` walks entries one
  /// at a time and calls `record_boundary` per declined child, and `record_boundary`
  /// calls [`make_room_in_ledger`] per push — so a listing of 1030 exercises
  /// the same decisions as a listing of 12 against a ledger already near the bound,
  /// 1030 times instead of 12. The 12 that still ride the seam keep the seam in the
  /// path being tested. The one thing genuinely no longer walked at full scale is
  /// the containment scan's `entries x children` cost, which is a performance
  /// property this cell never asserted and which no assertion here reads.
  ///
  /// The incumbents sit under `/r/held` rather than at `/r`, exactly as
  /// [`the_bound_refuses_a_new_entry_before_it_evicts_a_witness`]'s do: a
  /// complete listing of `/r` speaks for its OWN level, so entries parented there
  /// would have to be re-named by it merely to survive its relisting sweep.
  ///
  /// MUTATION WITNESS (bound removed): pass `usize::MAX` as the cap in
  /// `record_boundary`'s `make_room_in_ledger` call, so every observation
  /// pushes, and this FAILS at `the set stops at the bound instead of growing with
  /// the churn` with `left: 1030, right: 1024` — the unbounded growth the bound
  /// exists for.
  /// MUTATION WITNESS (eviction newest-first): make the retain in
  /// `make_room_in_ledger` walk from the tail (`retain` over a reversed
  /// vector, re-reversed after) and this FAILS at `the six OLDEST records were
  /// evicted` with `left: "/r/held/d0"` — the record most likely to be stale kept
  /// and the freshest observation dropped.
  #[test]
  fn the_ledger_is_hard_bounded_and_evicts_the_oldest() {
    // FIXED LITERALS, tied to the bound by a COMPILE-TIME guard rather than
    // derived from it. A cell in this class once sized its burst off
    // `MAX_BOUNDARIES`, so raising the constant silently rebuilt it
    // at 65 537 rows and hung instead of failing. Here a changed bound breaks the
    // BUILD, and the verdict below never re-parameterises itself.
    const PRELOADED: usize = 1018;
    const LISTED: usize = 12;
    const EVICTED: usize = 6;
    const {
      assert!(PRELOADED + LISTED == MAX_BOUNDARIES + EVICTED);
      assert!(PRELOADED < MAX_BOUNDARIES);
      assert!(EVICTED > 0);
    }

    let (mut core, scope, req, _root) = live_descending_mnt(42);
    // `SameMount` entries — the root's own mount id on a foreign device — which
    // is the only population `make_room_in_ledger` may evict, and therefore the
    // one whose eviction ORDER this cell is about.
    saturate(
      &mut core,
      scope,
      (0..PRELOADED).map(|n| proven_at(format!("/r/held/d{n}"))),
    );

    let entries: Vec<RawDirEntry> = (PRELOADED..PRELOADED + LISTED)
      .map(|n| {
        entry_on_mount(
          &format!("d{n}"),
          FileKind::Dir,
          99,
          100 + n as u64,
          // The root's own mount id: every one of these is exempt too, so the
          // listing crosses the bound in the same partition it was built in.
          42,
        )
      })
      .collect();
    core.on_enumerated(req, listed(entries));
    let _ = drain(&mut core);

    let held = recorded_locations(&core, scope);
    assert_eq!(
      held.len(),
      MAX_BOUNDARIES,
      "the set stops at the bound instead of growing with the churn"
    );
    assert_eq!(
      *held.first().expect("the bound is nonzero"),
      Path::new(&format!("/r/held/d{EVICTED}")),
      "the six OLDEST records were evicted — insertion order is the eviction order"
    );
    assert_eq!(
      *held.last().expect("the bound is nonzero"),
      Path::new(&format!("/r/d{}", PRELOADED + LISTED - 1)),
      "and the newest observation is the one kept, never the one refused"
    );
  }

  /// F1: on a host that answers NO mount ids, the record the bound would have
  /// evicted is the one thing a later mountinfo row can still upgrade into a
  /// departure witness — so it is kept and the NEW observation is refused, and
  /// the departure cover it eventually owes still arrives.
  ///
  /// The exempt entries are two populations that only look alike. A `SameMount`
  /// entry is a subvolume and can never be promoted. An `Unknown` entry is what a
  /// GENUINE post-census vfsmount looks like on pre-5.8 / mask-absent Linux until
  /// a row stands at its location — and the eviction that read the two as one
  /// dropped the second silently.
  ///
  /// Staged so the departure assertion cannot be confused with the arrival: the
  /// row is SEEDED by one refresh, whose single located ARRIVAL cover is
  /// asserted, and only the read AFTER that is the departure.
  #[test]
  fn the_bound_refuses_a_new_entry_before_it_evicts_a_witness() {
    // No mount ids anywhere: the scope has no frame, so EVERY record is exempt
    // and ambiguous — the host where the bound is under the most pressure and
    // where the eviction was most wrong.
    let (mut core, scope, req, root_watch) = live_descending_with(None);
    // The birth read first, and EMPTY, so the partition below is built into a
    // settled scope. It is BUILT rather than listed (see `saturate`), and it
    // sits under `/r/held` because the re-listing below is of the ROOT: a
    // complete listing speaks for its own level, so incumbents parented at `/r`
    // would have to be re-named by it — a thousand entries — merely to survive
    // its relisting sweep.
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);
    saturate(
      &mut core,
      scope,
      (0..MAX_BOUNDARIES).map(|n| ambiguous_at(format!("/r/held/b{n}"))),
    );
    let held = recorded_locations(&core, scope);
    assert_eq!(
      held.len(),
      MAX_BOUNDARIES,
      "staging: the partition is exactly at the bound, and every record is \
       ambiguous — none carries an id, and neither does the scope"
    );
    assert_eq!(
      *held.first().expect("at the bound"),
      Path::new("/r/held/b0"),
      "staging: /r/held/b0 is the OLDEST record — the one an oldest-first \
       eviction takes"
    );

    // One more boundary is observed, on the seam a re-listing rides. It names no
    // incumbent — none is a child of the root — so the relisting sweep has no
    // opinion about them and the only intake decision this read makes is the new
    // boundary's.
    relist_root_after_loss(
      &mut core,
      scope,
      root_watch,
      listed(vec![entry("over", FileKind::Dir, 99, 9999)]),
      at(2),
    );
    let held = recorded_locations(&core, scope);
    assert_eq!(
      held.len(),
      MAX_BOUNDARIES,
      "the bound still binds — intake is what stops, not the set that grows"
    );
    assert!(
      held.contains(&Path::new("/r/held/b0")),
      "and the oldest AMBIGUOUS record is kept: it may still be a genuine mount \
       whose row has not been read yet, and it is the only thing that upgrade \
       can reach"
    );
    assert!(
      !held.contains(&Path::new("/r/over")),
      "the NEW observation is what is refused instead — refusing only ever \
       costs an extra arrival cover later"
    );

    // /r/held/b0 really was a mount, and the surviving record is what the row can
    // still reach: the first authoritative read that lists it CONFIRMS the
    // record in place and marks it row-confirmed, which is the upgrade an
    // eviction would have thrown away.
    core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/held/b0")], true), at(3));
    let _ = drain(&mut core);

    // The mount departs. A census key that stops being listed is a departure on
    // any kernel, so the row LEAVES the census — the witness the bound refused to
    // evict did its job. The cover itself is root-wide, because 1023 `Unknown`
    // entries are still held and this scope is paying the fail-closed cost.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(4));
    let effects = drain(&mut core);
    let held = recorded_locations(&core, scope);
    assert!(
      !held.contains(&Path::new("/r/held/b0")),
      "the upgraded witness is condemned on its absence — which is the whole \
       point of keeping it"
    );
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "one cover for the departure: {effects:?}");
    assert!(
      emitted[0].kind().is_rescan(),
      "a departure is covered, never delivered: {emitted:?}"
    );
    assert_eq!(
      emitted[0].location(),
      &loc(&[]),
      "and it is ROOT-wide: this scope still holds 1023 ambiguous records, so \
       it fails closed and pays the accepted cost on every frame it reads"
    );
  }

  /// F1's other half: a record PROVEN to share the root's mount still evicts
  /// silently, and it is preferred over an older AMBIGUOUS one.
  ///
  /// A `SameMount` entry describes something no mountinfo read will ever list, so
  /// nothing can promote it and it can never become a witness. That is what makes
  /// it — and only it — free to drop.
  #[test]
  fn eviction_prefers_a_same_mount_entry_over_an_older_unknown_one() {
    let (mut core, scope, req, _root) = live_descending_mnt(42);
    // The birth read first, and EMPTY, so the ledger below is built into a
    // settled scope rather than racing a listing that would speak for the root's
    // own level.
    core.on_enumerated(req, listed(Vec::new()));
    let _ = drain(&mut core);
    // The OLDEST entry is `Unknown` (no id answered for it), then the ledger is
    // filled to the bound with `SameMount` entries — built, not listed, because
    // this cell is about which of them EVICTION takes (see `saturate`).
    saturate(
      &mut core,
      scope,
      std::iter::once(ambiguous_at("/r/amb"))
        .chain((0..MAX_BOUNDARIES - 1).map(|n| proven_at(format!("/r/p{n}")))),
    );
    let held = recorded_locations(&core, scope);
    assert_eq!(
      held.len(),
      MAX_BOUNDARIES,
      "staging: at the bound, one ambiguous record at the FRONT"
    );
    assert_eq!(
      *held.first().expect("at the bound"),
      Path::new("/r/amb"),
      "staging: the ambiguous record is the oldest"
    );

    // One more proven subvolume. Room is made, and it is made from the proven
    // partition — the oldest PROVEN record, not the oldest record.
    core.on_walk_boundaries(
      scope,
      crate::os::WalkBoundaries {
        declined: vec![crate::os::DeclinedBoundary {
          location: PathBuf::from("/r/fresh"),
          dev: 99,
          mnt_id: Some(42),
        }],
        reach: crate::os::WalkReach::Partial,
      },
      at(1),
    );
    let held = recorded_locations(&core, scope);
    assert_eq!(held.len(), MAX_BOUNDARIES, "the bound still binds");
    assert!(
      held.contains(&Path::new("/r/amb")),
      "the ambiguous record is passed over even though it is the oldest"
    );
    assert!(
      !held.contains(&Path::new("/r/p0")),
      "the oldest PROVEN subvolume is what leaves — it can never be promoted, \
       so dropping it can never cost a cover"
    );
    assert!(
      held.contains(&Path::new("/r/fresh")),
      "and the fresh observation is admitted, because room really was made"
    );
  }

  /// A `SameMount` entry survives the root's frame moving, and the re-listing
  /// still owns its removal — cell (g)'s claim on the DESCENDING profile, where
  /// the re-listing is the removal path.
  ///
  /// The seam decided `SameMount` from two ids it read at one instant, and a
  /// same-object re-mount of the root moves neither of them. Under the predicate
  /// this replaced — `mnt_id == root_mnt_id`, re-asked on every read — the entry
  /// flipped to mount-backed the moment the root moved, was condemned and covered
  /// as a departure, and its real removal path never saw it again because the
  /// retire pass refused to touch anything mount-backed.
  ///
  /// This profile DOES replay the root under a changed frame (a descending scope
  /// re-classifies every child against the new frame), so a root-wide cover here
  /// is expected and correct. What may not appear is a cover LOCATED at the
  /// subvolume: that one could only be a departure verdict.
  #[test]
  fn a_same_mount_entry_survives_a_root_frame_change_for_the_retire_pass() {
    let (mut core, scope, req, root_watch) = live_descending_mnt(42);
    core.on_enumerated(
      req,
      listed(vec![entry_on_mount("sub", FileKind::Dir, 99, 11, 42)]),
    );
    let _ = drain(&mut core);
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/sub"), Some(42), None)],
      "staging: a proven subvolume — the ROOT's own mount id, another device"
    );

    // The root is unmounted and re-bound at the same path: same object (the death
    // gate passes), new mount.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(43)), at(2));
    let effects = drain(&mut core);
    assert!(
      !emits(&effects)
        .iter()
        .any(|change| change.location() == &loc(&["sub"])),
      "a live subvolume is not a departure just because the root re-mounted — \
       the root-wide frame replay is the only cover this read owes: {effects:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/sub"), Some(43), None)],
      "the entry is untouched — its standing was decided at the seam and no \
       later frame re-decides it"
    );

    // The frame replay's own re-arm re-reads the root, and by then the subvolume
    // has been deleted, so the complete listing names no child at all. That
    // re-listing is the descending profile's removal path for a ledger entry, and
    // it is the only one this entry has.
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
      .expect("the changed frame's replay re-reads the root");
    core.on_enumerated(read, listed(Vec::new()));
    let _ = drain(&mut core);
    assert!(
      recorded(&core, scope).is_empty(),
      "the retire pass still owns it: a re-listing that does not name the child \
       retires the entry, silently"
    );
  }

  /// **R6, the refusal half on SEAM 1**: a boundary the bound refuses leaves the
  /// listing CLEAN, and the scope's fail-closed state is what pays for it.
  ///
  /// The bound only ever refuses when the ledger is full of witnesses — a
  /// `SameMount` entry would have been evicted to make room — and a scope holding
  /// even one `Unknown` entry already covers its whole root on every
  /// authoritative refresh. That cover strictly dominates anything this seam
  /// could stand for the refusal, so standing one is pure duplication.
  ///
  /// It was not free duplication, either. The announcement had to be LATCHED per
  /// saturation episode or it stormed (every later enumerate re-observes the same
  /// refused locations, and every cover's own re-arm crawl re-enumerates), and
  /// that latch silenced every refusal after the first for the life of the
  /// episode — the fifth finding against per-record bounded evidence on an id-less
  /// host, and the one the scope-wide rule replaces.
  ///
  /// Both legs read the SAME listing and differ only in whether the partition had
  /// room for what it declined, so the refusal is the only variable between them
  /// — and the accepting leg is what stops the refusing one passing vacuously.
  ///
  /// MUTATION WITNESS: re-introduce the degrade (`lossy = true` on a refusal) and
  /// this FAILS at `a refusal does not degrade the listing that saw it` with a
  /// rescan present in the effects. Remove the intake refusal itself and it FAILS
  /// at `the bound still binds` with 1025 records held.
  #[test]
  fn a_boundary_refused_at_the_bound_leaves_the_listing_clean() {
    /// The ONE listing both legs read: the root, naming a single child across a
    /// device boundary. Whether its decline is admitted or refused is the whole
    /// difference between them.
    ///
    /// The incumbents behind it are BUILT rather than listed (see [`saturate`]),
    /// and they sit under `/r/held` rather than at the root's own children
    /// because a complete listing speaks for its own level: incumbents parented
    /// at `/r` would be retired by this listing's relisting sweep for not being
    /// named.
    fn one_boundary() -> Vec<RawDirEntry> {
      vec![entry("x", FileKind::Dir, 99, 7)]
    }

    // Control: one short of the bound, so the listing's decline is ADMITTED —
    // and the listing is clean.
    //
    // SCOPED so the control's partition is gone before the leg below builds its
    // own. A shadowed `core` binding is not dropped at the shadowing — it lives
    // to the end of the function — so both partitions used to be resident at
    // once, and an interpreted 32-bit run pays for that peak out of an address
    // space the whole shard shares.
    {
      let (mut core, scope, req, _root) = live_descending_with(None);
      saturate(
        &mut core,
        scope,
        (0..MAX_BOUNDARIES - 1).map(|n| ambiguous_at(format!("/r/held/b{n}"))),
      );
      core.on_enumerated(req, listed(one_boundary()));
      let effects = drain(&mut core);
      assert_eq!(
        recorded_locations(&core, scope).len(),
        MAX_BOUNDARIES,
        "control: there was room, and the observation took it"
      );
      assert!(
        !emits(&effects).iter().any(|c| c.kind().is_rescan()),
        "control: a listing that refuses nothing is complete: {effects:?}"
      );
    }

    // At the bound. The same listing's decline is refused — an ambiguous record
    // may still be upgraded into a departure witness, so the incumbents are kept
    // — and the listing that observed it is NOT degraded.
    let (mut core, scope, req, _root) = live_descending_with(None);
    saturate(
      &mut core,
      scope,
      (0..MAX_BOUNDARIES).map(|n| ambiguous_at(format!("/r/held/b{n}"))),
    );
    core.on_enumerated(req, listed(one_boundary()));
    let effects = drain(&mut core);
    assert_eq!(
      recorded_locations(&core, scope).len(),
      MAX_BOUNDARIES,
      "the bound still binds — intake is what stops, not the set that grows"
    );
    assert!(
      !emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "a refusal does not degrade the listing that saw it: {effects:?}"
    );

    // What pays for it instead: this scope's partition is full of ambiguous
    // records, so it FAILS CLOSED and the next authoritative refresh covers the
    // whole root — which dominates the located cover the refused boundary would
    // have owed, and keeps on dominating it for as long as the refusal can recur.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(9));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the saturated scope fails closed: {effects:?}"
    );
    assert_eq!(
      emitted[0].location(),
      &loc(&[]),
      "over the WHOLE root — the refused location included, which is the only \
       thing that could have covered it: {emitted:?}"
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
    let (mut core, scope) = spawned_fanotify(None, Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "a refreshed KR root is silent"
    );
    (core, scope)
  }

  /// The same spawn, stopped one step SHORT of the birth refresh, on a root whose
  /// mount frame is `root_mnt_id` and whose seed WALK declined `declined`.
  ///
  /// The refresh is left to the caller deliberately. A cell that lets a helper
  /// feed one cannot tell a DEPARTURE cover from the ARRIVAL cover the same
  /// helper's frame would fire at the same location — the false green this suite
  /// has already produced twice. Here the frame is always the cell's own, and the
  /// coverage set is readable before any frame at all has been diffed.
  fn spawned_fanotify(
    root_mnt_id: Option<u64>,
    declined: Vec<crate::os::DeclinedBoundary>,
  ) -> (DriverCore, ScopeId) {
    spawned_fanotify_polling(LIVENESS, root_mnt_id, declined)
  }

  /// The same spawn with the root-liveness interval chosen by the caller —
  /// `Duration::ZERO` being the supported setting that arms NO periodic tick at
  /// all, so nothing but a loss or an explicitly armed read ever refreshes again.
  /// The cells about what survives WITHOUT a cadence need that, and a cell that
  /// silently relied on the tick to converge would be reading the clock rather
  /// than the mechanism.
  fn spawned_fanotify_polling(
    liveness: Duration,
    root_mnt_id: Option<u64>,
    declined: Vec<crate::os::DeclinedBoundary>,
  ) -> (DriverCore, ScopeId) {
    let mut core = DriverCore::new(WINDOW, liveness);
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify)
      .expect("a fresh scope registers");
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
        declined,
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
    (core, scope)
  }

  /// What the walk's MOUNT fence declines: a `mount --bind` of a same-superblock
  /// directory, so the device belt cannot see it and only the differing mount id
  /// marks it. Both halves known, so the seam decides `Mount` at once.
  fn bind_decline(location: &str, mnt_id: u64) -> crate::os::DeclinedBoundary {
    crate::os::DeclinedBoundary {
      location: PathBuf::from(location),
      dev: 1,
      mnt_id: Some(mnt_id),
    }
  }

  /// What the walk's DEVICE BELT declines: a btrfs subvolume. It is on another
  /// device but on the ROOT'S OWN MOUNT — that is what a subvolume is — so the
  /// walk's `statx` answers `root_mnt_id`, so the seam decides `SameMount`: no
  /// mountinfo row will ever list it and no census will ever own it.
  ///
  /// The id is not optional decoration. The walk reads it for EVERY decline, both
  /// fences alike, so a decline carrying no id would model a host that answers no
  /// mount ids at all rather than a subvolume — a different, much rarer case, and
  /// the one whose conflation with this one let a genuine mount be recorded
  /// permanently exempt.
  fn subvolume_decline(location: &str, dev: u64, root_mnt_id: u64) -> crate::os::DeclinedBoundary {
    crate::os::DeclinedBoundary {
      location: PathBuf::from(location),
      dev,
      mnt_id: Some(root_mnt_id),
    }
  }

  /// What the walk's DEVICE BELT declines when the object really is a MOUNT: a
  /// foreign device AND a mount id of its own. The belt is what stops the walk,
  /// but the `statx` above it is what makes the record classifiable — which is
  /// the whole of F1.
  fn mount_decline(location: &str, dev: u64, mnt_id: u64) -> crate::os::DeclinedBoundary {
    crate::os::DeclinedBoundary {
      location: PathBuf::from(location),
      dev,
      mnt_id: Some(mnt_id),
    }
  }

  /// A decline from a host that answers NO mount ids — the pre-5.8 degrade, the
  /// only remaining way a walk record is born without one.
  fn idless_decline(location: &str, dev: u64) -> crate::os::DeclinedBoundary {
    crate::os::DeclinedBoundary {
      location: PathBuf::from(location),
      dev,
      mnt_id: None,
    }
  }

  /// One PARTIAL walk report — a moved-in subtree walk or an admission reseed,
  /// which saw one subtree and prove nothing about the rest of the root.
  fn partial_walk(declined: Vec<crate::os::DeclinedBoundary>) -> crate::os::WalkBoundaries {
    crate::os::WalkBoundaries {
      declined,
      reach: crate::os::WalkReach::Partial,
    }
  }

  /// One WHOLE-ROOT walk report — a post-loss map reseed that ran to completion,
  /// and therefore the complete boundary set under the root — taken on the frame
  /// the scope CURRENTLY holds, which is what a reseed that reopened the same root
  /// would have read. The superseded shape is built by the cell that tests it.
  fn whole_root_walk_on(
    root_mnt_id: Option<u64>,
    epoch: u64,
    declined: Vec<crate::os::DeclinedBoundary>,
  ) -> crate::os::WalkBoundaries {
    crate::os::WalkBoundaries {
      declined,
      reach: crate::os::WalkReach::WholeRoot { root_mnt_id, epoch },
    }
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
  /// refresh fed — the descending half of the tick gate. It DOES arm the tick:
  /// `IN_UNMOUNT` covers only the eager path, and a lazy unmount is silent at
  /// the root and below it alike (#74).
  fn live_inotify() -> (DriverCore, ScopeId) {
    let mut core = DriverCore::new(WINDOW, LIVENESS);
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify)
      .expect("a fresh scope registers");
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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

  /// The composition's one timer: BOTH Linux profiles arm a periodic refresh
  /// deadline (the birth refresh at `at(0)` seeds it at `+LIVENESS`), and the
  /// tick coming due fires a `RefreshMounts` — the only way a signal-silent
  /// unmount, at the root or below it, is ever observed. #74 is why inotify is
  /// here: a LAZY unmount emits neither `IN_UNMOUNT` nor `IN_IGNORED`, measured
  /// as 120 s of nothing at all, so "its unmount is in-band" — the premise this
  /// cell used to assert — holds only for the eager path. FSEvents is the peer
  /// that still arms nothing: `RootChanged` covers its root and the `UNMOUNT`
  /// flag word covers every departure below it.
  #[test]
  fn liveness_tick_refreshes_both_linux_profiles_but_not_fsevents() {
    for (label, (mut core, _scope)) in [("fanotify", live_fanotify()), ("inotify", live_inotify())]
    {
      assert_eq!(
        core.poll_timeout(),
        Some(at(30_000)),
        "{label}: the deadline is armed one interval past the birth refresh"
      );
      // Before the deadline: no tick.
      core.on_timeout(at(29_999));
      assert_eq!(
        refresh_requests(&drain(&mut core)),
        0,
        "{label}: the tick does not fire early"
      );
      // At the deadline: exactly one refresh, and the deadline re-arms.
      core.on_timeout(at(30_000));
      assert_eq!(
        refresh_requests(&drain(&mut core)),
        1,
        "{label}: the due tick fires the refresh"
      );
      assert_eq!(
        core.poll_timeout(),
        Some(at(60_000)),
        "{label}: the tick re-arms one interval out"
      );
    }

    // FSEvents: no deadline, so no tick ever fires.
    let (mut core, _scope) = live_core();
    assert_eq!(
      core.poll_timeout(),
      None,
      "an FSEvents scope arms no tick (both its silences are signalled in band)"
    );
    core.on_timeout(at(1_000_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      0,
      "an FSEvents scope never fires a tick"
    );
  }

  /// The tick is COALESCING, not invalidation — and conflating the two starves
  /// this whole composition.
  ///
  /// The interval is any nonzero duration the caller likes, and refresh latency
  /// is whatever a blocking pool gives it, so latency at or past the interval is
  /// an ordinary operating point rather than a corner. There EVERY completion
  /// lands with a tick already fired on top of it. A tick that condemned the
  /// in-flight snapshot would therefore discard every completion in turn — the
  /// mount-table install, the frame adoption and the DEPARTURE diff all sit
  /// BEHIND `on_mounts_refreshed`'s stale gate — and the re-armed read would be
  /// condemned by the next tick, forever. Only the root-death check would
  /// survive, because it is evaluated in FRONT of that gate; the below-root
  /// silence this composition exists to break would be permanent.
  ///
  /// Driven here with no completion between two ticks, which is that steady
  /// state exactly: every read this scope completes was tick-raced.
  #[test]
  fn a_tick_coalescing_onto_an_in_flight_refresh_still_publishes_it() {
    let (mut core, scope) = live_fanotify();
    // Tick one arms the read that carries the baseline...
    core.on_timeout(at(30_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      1,
      "the due tick arms one refresh"
    );
    // ...and tick two comes due before it lands. Pure cadence: no second
    // effect, and no condemnation of the read already out.
    core.on_timeout(at(60_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      0,
      "a tick over an in-flight read stacks no second effect"
    );

    core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(60_001));
    let effects = drain(&mut core);
    assert_eq!(
      emits(&effects).len(),
      1,
      "staging: a first frame records the row, covering the arrival: {effects:?}"
    );
    assert_eq!(
      refresh_requests(&effects),
      0,
      "the tick-raced completion is PUBLISHED, not discarded-and-re-armed: {effects:?}"
    );
    assert!(
      core
        .scopes
        .get(&scope)
        .expect("scope is live")
        .mounts_authoritative,
      "and it installed its table: a cadence witnesses no transition to distrust"
    );

    // The same shape again, now carrying the departure — the read a
    // stale-marking tick would throw away, and with it the only evidence the
    // mount ever left.
    core.on_timeout(at(100_000));
    core.on_timeout(at(200_000));
    let _ = drain(&mut core);
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(200_001));
    // On fanotify the cover is PARKED on an admission round trip — the source
    // admits by handle membership and is blind to the ground the departure just
    // revealed — so the departure is READ here and DELIVERED once the reader
    // answers. What this cell is about is that the tick-raced read derived it at
    // all.
    let effects = drain(&mut core);
    let effects = answer_one_admission(&mut core, scope, &effects, at(200_002));
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the departure diff runs on a tick-raced read: {effects:?}"
    );
    assert!(emitted[0].kind().is_rescan());
    assert_eq!(emitted[0].location(), &loc(&["vol"]));
  }

  /// The half of `refresh_stale` a coalescing tick must NOT touch: a LOSS
  /// condemnation stands, and a tick riding the same in-flight read cannot
  /// absolve it. The loss window may have carried a mount transition, so its
  /// snapshot is suspect no matter how many ticks agree it is due.
  #[test]
  fn a_tick_never_absolves_a_loss_condemned_refresh() {
    let (mut core, scope) = live_fanotify();
    core.on_timeout(at(30_000));
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      1,
      "the due tick arms one refresh"
    );
    // A loss overlaps the in-flight read: condemned.
    core.on_root_overflow(scope, at(30_500));
    let _ = drain(&mut core);
    // A tick rides the same read afterwards. It must change nothing.
    core.on_timeout(at(60_000));
    let _ = drain(&mut core);

    core.on_mounts_refreshed(scope, alive_refresh(vec![bare("/r/vol")], true), at(60_001));
    let effects = drain(&mut core);
    assert_eq!(
      refresh_requests(&effects),
      1,
      "the loss-condemned completion is still discarded and re-armed: {effects:?}"
    );
    assert!(
      !core
        .scopes
        .get(&scope)
        .expect("scope is live")
        .mounts_authoritative,
      "a superseded snapshot restores no authority"
    );
    // The table component is the wrong observable on THIS backend — fanotify
    // consumes no absence-based trust, so it maintains none
    // ([`consumes_absence_trust`]) and an assertion about its emptiness would pass
    // for a reason that has nothing to do with staleness. What the stale gate
    // actually withholds here is the COVERAGE diff, which sits behind it.
    assert!(
      recorded(&core, scope).is_empty(),
      "and the snapshot's rows are discarded rather than diffed: a stale read may \
       predate the lost window, so recording its rows would call an incumbent an \
       arrival: {:?}",
      recorded(&core, scope)
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
        root_incarnation: None,
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
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify)
      .expect("a fresh scope registers");
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify)
      .expect("a fresh scope registers");
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify)
      .expect("a fresh scope registers");
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
        root_incarnation: None,
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
        root_incarnation: None,
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
        mounts: vec![bare("/r/stale-vol")],
        authoritative: true,
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
        root_mnt_id: None,
        root_incarnation: None,
      },
      at(31_000),
    );
    assert_eq!(
      refresh_requests(&drain(&mut core)),
      1,
      "a stale-but-alive completion re-arms exactly one fresh read"
    );
    assert!(
      !core
        .scopes
        .get(&scope)
        .expect("scope is live")
        .mounts_authoritative,
      "the superseded snapshot does not restore authority"
    );
    assert!(
      recorded(&core, scope).is_empty(),
      "the superseded mount-set is discarded, not installed — read through the \
       COVERAGE set, which is what the stale gate withholds on a backend that \
       maintains no trust table at all: {:?}",
      recorded(&core, scope)
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
        root_incarnation: None,
      },
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      obliged(&effects).is_empty(),
      "a kernel-recursive frame change triggers no reconcile: {effects:?}"
    );
    assert_eq!(
      core.scopes.get(&scope).expect("scope is live").root_mnt_id,
      Some(77),
      "the KR scope still adopts the authoritative frame (inert, but kept current)"
    );
  }

  /// SEAM 2, the SPAWN driver: the boundaries the fanotify seed walk declined
  /// reach the coverage set through the spawn result.
  ///
  /// This is the seam's whole reason to exist. A descending profile learns its
  /// boundaries from its own enumerates and re-learns them on every cover's
  /// re-arm crawl; a kernel-recursive mark runs NO enumerate — `start_rearm`
  /// refuses outright on a non-descending scope — so the walk is the only place
  /// fanotify ever fences a directory, and a decline it dropped is a boundary
  /// nothing in the system would see again.
  ///
  /// The set is read BEFORE any frame is diffed, so what it holds came from the
  /// walk and from nothing else.
  #[test]
  fn a_spawn_seed_walks_declines_enter_the_coverage_set() {
    let (mut core, scope) = spawned_fanotify(
      Some(42),
      vec![
        // The mount fence's decline: same device, different mount.
        bind_decline("/r/bound", 77),
        // The device belt's: foreign device, on the root's own mount.
        subvolume_decline("/r/subvol", 99, 42),
      ],
    );
    assert_eq!(
      recorded(&core, scope),
      vec![
        (PathBuf::from("/r/bound"), Some(77), None),
        (PathBuf::from("/r/subvol"), Some(42), None),
      ],
      "both declines are recorded with the identity the WALK read — no frame has \
       been diffed yet, so nothing else could have put them here"
    );

    // The first authoritative frame lists NOTHING. It therefore has no arrival to
    // cover, so every cover it emits is a departure — the distinction this suite
    // has twice got wrong by letting a helper feed the frame.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(1));
    let effects = drain(&mut core);
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/subvol"), Some(42), None)],
      "the derived departure leaves at the verdict; the `SameMount` decline \
       joins no census at all"
    );
    // The cover is PARKED on the admission round trip this profile owes (the map
    // has no handles for the ground the bind's departure revealed), and lands on
    // the reply.
    let effects = answer_one_admission(&mut core, scope, &effects, at(2));
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "only the `Mount` decline is a departure witness: {effects:?}"
    );
    assert!(emitted[0].kind().is_rescan());
    assert_eq!(
      emitted[0].location(),
      &loc(&["bound"]),
      "and the cover is LOCATED at the departed bind"
    );
  }

  /// The EXEMPT half of the spawn driver, held against every condemnation path
  /// there is — the shape that storms if an absence were read as a departure.
  ///
  /// A btrfs subvolume trips the walk's DEVICE belt while carrying the root's own
  /// mount id, so the seam decides `SameMount` — and `/proc/self/mountinfo` has no
  /// row for one and never will, so no census can ever key it. Read its absence
  /// from a census as a departure and every tick covers and re-records it,
  /// forever, on every default snapper / Fedora / docker-btrfs layout.
  ///
  /// The re-declining walks in the loop are the steady state, not decoration: on
  /// this profile a reseed or a moved-in subtree walk re-observes the same
  /// boundary for as long as it is there, and re-recording it must stay
  /// idempotent — one record, no cover.
  #[test]
  fn a_walk_declined_subvolume_survives_every_condemnation_path() {
    let (mut core, scope) =
      spawned_fanotify(Some(42), vec![subvolume_decline("/r/subvol", 99, 42)]);
    let held = vec![(PathBuf::from("/r/subvol"), Some(42), None)];
    assert_eq!(
      recorded(&core, scope),
      held,
      "staging: the walk recorded it"
    );

    for tick in 1..6 {
      // A live walk re-declines it, exactly as the reseed and the move-in walk do
      // for as long as the subvolume is there.
      core.on_walk_boundaries(
        scope,
        partial_walk(vec![subvolume_decline("/r/subvol", 99, 42)]),
        at(1),
      );
      assert!(
        drain(&mut core).is_empty(),
        "tick {tick}: re-observing a recorded boundary is not an event"
      );
      core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(tick));
      assert!(
        emits(&drain(&mut core)).is_empty(),
        "tick {tick}: a subvolume is not a departure, ever"
      );
      assert_eq!(
        recorded(&core, scope),
        held,
        "tick {tick}: and it survives UNTOUCHED — exempt from the mechanism, not \
         merely quiet about it"
      );
    }
  }

  /// SEAM 2, the LIVE drivers: what the post-loss whole-map reseed and the
  /// moved-in subtree walk decline reaches the same set, through the source's one
  /// ordered queue rather than the spawn result they are long past.
  ///
  /// The two walks are one landing site on purpose — and it is the site the
  /// admission reseed will attach to as well, since it runs on the same reader
  /// thread with the same result type.
  ///
  /// The `Standing` is settled here exactly as it is for a spawn decline: a
  /// walk's fence is not a mountinfo row, so a live decline is a departure
  /// witness only when its own mount id says so.
  #[test]
  fn a_live_walks_declines_enter_the_set_through_the_queue() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      recorded(&core, scope).is_empty(),
      "staging: a walk that declined nothing records nothing"
    );

    // The post-loss reseed's declines.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![bind_decline("/r/bound", 77)]),
      at(1),
    );
    // The moved-in subtree walk's: a foreign directory brings its own boundaries
    // in with it, and nothing else will ever look at them.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/moved/sub", 99, 42)]),
      at(1),
    );
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "recording a boundary is an observation, never a consumer event"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![
        (PathBuf::from("/r/bound"), Some(77), None),
        (PathBuf::from("/r/moved/sub"), Some(42), None),
      ],
      "both live walks land in the same set the spawn walk seeds"
    );

    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(1));
    let effects = drain(&mut core);
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/moved/sub"), Some(42), None)],
      "and the move-in walk's exempt decline is untouched"
    );
    let effects = answer_one_admission(&mut core, scope, &effects, at(2));
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the reseed's mount-backed decline departs like any other: {effects:?}"
    );
    assert_eq!(emitted[0].location(), &loc(&["bound"]));
  }

  /// A REPLACED boundary is re-recorded with its new identity and NEVER dropped,
  /// on the profile where that is the only thing standing between the scope and a
  /// silent loss of the record.
  ///
  /// On a descending profile a drop is survivable: the cover re-arms a crawl, the
  /// crawl re-enumerates, and the enumerate fence re-declines whatever is still
  /// there. `Monitor::start_rearm` refuses outright when the scope does not
  /// descend, so on fanotify there is NO crawl — nothing re-observes the location
  /// until the next authoritative read, and a location the diff dropped is not in
  /// the set for that read to compare against. Drop-after-cover here loses the
  /// record on the first replacement and with it the replacement's own eventual
  /// departure.
  #[test]
  fn a_kernel_recursive_replaced_mount_re_records_rather_than_dropping() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(
      scope,
      alive_refresh(vec![row("/r/vol", 41, 7)], true),
      at(0),
    );
    let effects = drain(&mut core);
    assert_eq!(
      emits(&effects).len(),
      1,
      "staging: the ARRIVAL covers once — this is the cover the departure \
       assertion below must not be confused with: {effects:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(41), Some(7))],
      "staging: the arrival is recorded with its identity"
    );

    // `umount /r/vol && mount -t tmpfs none /r/vol` between two reads: the
    // location is in BOTH frames, so only identity sees it at all.
    core.on_mounts_refreshed(
      scope,
      alive_refresh(vec![row("/r/vol", 55, 9)], true),
      at(1),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the replacement is one cover: {effects:?}"
    );
    assert_eq!(emitted[0].location(), &loc(&["vol"]));
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(55), Some(9))],
      "RE-RECORDED IN PLACE with the new identity: on a KR profile no crawl \
       would ever put it back"
    );
    assert!(
      !effects
        .iter()
        .any(|e| matches!(e, Effect::Enumerate { .. }) || matches!(e, Effect::AddWatch { .. })),
      "and the cover summons no crawl here — which is exactly why the record had \
       to survive it: {effects:?}"
    );

    // The proof the re-record is load-bearing: the REPLACEMENT's own departure is
    // still derivable, which a drop would have made impossible.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let effects = drain(&mut core);
    assert!(
      recorded(&core, scope).is_empty(),
      "and THAT drop is a real departure"
    );
    let effects = answer_one_admission(&mut core, scope, &effects, at(3));
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the re-recorded mount's departure is covered: {effects:?}"
    );
    assert_eq!(emitted[0].location(), &loc(&["vol"]));
  }

  /// F1's REACHABLE SEQUENCE, staged end to end: a mount that ARRIVES after the
  /// baseline, is FIRST OBSERVED by a live walk, and DEPARTS before any refresh
  /// ever confirms a row at its location.
  ///
  /// This is the class the device belt's missing `statx` opened. A walk decline
  /// recorded with `mnt_id: None` is `Unknown`, which joins no census — so the
  /// refresh that no longer listed the location emitted neither a located cover
  /// nor an admission request, and the walk had never seeded the revealed subtree
  /// into the FID map. The source is then blind
  /// to that ground with no loss signal, until some unrelated whole-map reseed
  /// happens to run: #74's own bug class, reintroduced in a narrow window.
  ///
  /// Every frame this cell feeds is EMPTY, on purpose. A frame that listed the
  /// location would fire an ARRIVAL cover, which is indistinguishable at the
  /// assertion from the departure cover the cell exists to read — the false green
  /// this suite has already produced twice.
  #[test]
  fn a_mount_seen_only_by_a_live_walk_still_has_its_departure_derived() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    // The BASELINE: authoritative, and listing nothing at all.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: an empty baseline covers nothing"
    );
    assert!(
      recorded(&core, scope).is_empty(),
      "staging: and records nothing — every record below came from the walk"
    );

    // The mount ARRIVES, after the baseline, and a LIVE walk is the only thing
    // that ever sees it: another device (the belt is what declines) carrying a
    // mount id of its own (the `statx` the belt no longer skips).
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![mount_decline("/r/vol", 99, 77)]),
      at(1),
    );
    assert!(
      drain(&mut core).is_empty(),
      "recording a boundary is an observation, never a consumer event"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(77), None)],
      "the walk's decline carries the mount id it read from the pinned fd"
    );

    // It DEPARTS before any refresh confirmed a row. The frame is empty again —
    // the same emptiness as the baseline, so nothing here can be an arrival.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(1));
    let effects = drain(&mut core);
    assert!(
      recorded(&core, scope).is_empty(),
      "the record is CONDEMNED by the refresh that no longer lists it — not \
       exempt for the scope's whole life"
    );
    // And what is owed FIRST on this profile is the admission reseed: the walk
    // stopped at this very boundary, so the ground its departure revealed has no
    // handles in the map at all.
    let effects = answer_one_admission(&mut core, scope, &effects, at(2));
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the departure's cover lands once the map can see the ground: {effects:?}"
    );
    assert_eq!(emitted[0].location(), &loc(&["vol"]));
  }

  /// The control leg for the cell above, and the reason the fix is a `statx`
  /// rather than "treat an id-less decline as a departure witness": the SUBVOLUME
  /// the belt also declines carries the ROOT'S OWN mount id, decides `SameMount`,
  /// and costs no cover on any tick.
  #[test]
  fn a_subvolume_seen_by_the_same_belt_stays_exempt() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/sub", 99, 42)]),
      at(1),
    );
    let held = vec![(PathBuf::from("/r/sub"), Some(42), None)];
    assert_eq!(recorded(&core, scope), held, "staging: recorded exempt");

    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(1));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty() && admissions(&effects).is_empty(),
      "a subvolume is not a departure — no cover, and no admission round trip \
       either: {effects:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      held,
      "and it survives UNTOUCHED: the same belt, the opposite verdict, decided \
       by the id the belt now reads"
    );
  }

  /// A COMPLETE whole-root walk is a GENERATION, and every ledger entry it did
  /// not decline is retired.
  ///
  /// Nothing else can retire an exempt one here. No census lists a subvolume, and
  /// the compiled-removal pass reads the event stream, which is exactly what a
  /// loss window empties. So before this, one deletion lost to an overflow kept
  /// its `PathBuf` for the scope's whole life, and every linear scan of the
  /// ledger paid for it.
  ///
  /// It runs over the WHOLE ledger, and the `Mount(77)` entry here is retired
  /// with the rest: a walk that ran to completion from the root declined every
  /// boundary that is still there, so one it did not decline is not there any
  /// more — whatever the seam's two ids said it was. That is sound because the
  /// ledger holds nothing a census owns, and because both callers carry their own
  /// root-wide cover behind the report.
  #[test]
  fn a_whole_root_walk_retires_the_ledger_entries_it_did_not_decline() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    // Three flat subvolumes and one real bind, all observed by ordinary partial
    // walks — the shape a long-lived scope accretes.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![
        subvolume_decline("/r/a", 99, 42),
        subvolume_decline("/r/b", 99, 42),
        subvolume_decline("/r/c", 99, 42),
        bind_decline("/r/bound", 77),
      ]),
      at(1),
    );
    assert_eq!(
      recorded(&core, scope).len(),
      4,
      "staging: four entries, three of them exempt"
    );

    // A PARTIAL walk retires nothing, whatever it declines: it saw one subtree.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/a", 99, 42)]),
      at(1),
    );
    assert_eq!(
      recorded(&core, scope).len(),
      4,
      "a partial report proves nothing about the rest of the root"
    );

    // The post-loss reseed: a whole-root walk that ran to completion. `/r/b` and
    // `/r/c` were deleted while the deletions' records were lost, so the walk
    // does not decline them.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(
        root_frame(&core, scope),
        frame_epoch(&core, scope),
        vec![subvolume_decline("/r/a", 99, 42)],
      ),
      at(1),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/a"), Some(42), None)],
      "everything the complete walk did not decline is retired — the two \
       subvolumes it no longer saw AND the bind, which a walk that reached every \
       live boundary would have declined; only the one it did decline survives"
    );
    assert!(
      drain(&mut core).is_empty(),
      "retiring is not an event: the callers of a complete generation each carry \
       a root-wide cover of their own behind the report"
    );

    // An EMPTY whole-root walk is a generation too — the state the reconciliation
    // most needs to reach, and the one a "skip empty reports" shortcut loses.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(
        root_frame(&core, scope),
        frame_epoch(&core, scope),
        Vec::new(),
      ),
      at(1),
    );
    assert!(
      recorded(&core, scope).is_empty(),
      "no boundary anywhere under the root retires the last entry"
    );
  }

  /// The bytes `/r/od\xffl` names — a directory whose name is legal on every
  /// Linux filesystem and spellable by no `str`.
  ///
  /// Unix-only, because that is the only host where a `PathBuf` can even HOLD
  /// these bytes; the finding is a Linux one (fanotify, `/proc`, raw dirents) and
  /// the guard it is about is shared cross-platform code.
  #[cfg(unix)]
  fn undecodable_location() -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(b"/r/od\xffl"))
  }

  /// **R7 F1.** The coverage set is INTERNAL and keyed by `PathBuf`, so what may
  /// enter it is decided by CONTAINMENT and never by protocol representability.
  ///
  /// The guard this pins replaced a `matches!(lower(..), Lowered::Target(_))`
  /// screen, and `lower` answers `Outside` for any path with a non-UTF-8
  /// component. So a fanotify walk that DECLINED a boundary at such a path —
  /// reporting its raw location and its mount identity, which for a mount that
  /// arrived after the spawn table snapshot is the only witness there will ever
  /// be — recorded nothing at all. A lazy departure below it then produced
  /// neither an admission round trip nor a cover, and the revealed subtree stayed
  /// absent from the FID map with every event on it silently rejected.
  ///
  /// Where the lowering went instead is the second half: `mount_cover` degrades an
  /// unrepresentable location to a WHOLE-ROOT cover. Over-covering, never silence.
  ///
  /// The two containment halves the guard still enforces are asserted beside it,
  /// because a "just drop the screen" fix would lose them: a record AT the root
  /// could never be matched by a frame (`parse_mountinfo` filters the root's own
  /// row out) and would be covered and re-recorded on every tick, and a record
  /// OUTSIDE the root is not this scope's ground at all.
  ///
  /// MUTATION WITNESS (the finding): restore
  /// `if !matches!(lower(state, location), Lowered::Target(_)) { return; }` in
  /// `record_boundary` and this FAILS at `the declined boundary is RECORDED` with
  /// an empty left — the sole witness dropped, exactly as reported.
  /// MUTATION WITNESS (strictness): drop the `path != root` half of
  /// `strictly_under_root` and it FAILS at `a boundary AT the root is still
  /// refused` — the record that would be covered and re-recorded forever.
  /// MUTATION WITNESS (containment): drop the `path.starts_with(root)` half and
  /// it FAILS at `a boundary OUTSIDE the root is still refused`.
  #[cfg(unix)]
  #[test]
  fn a_declined_boundary_is_recorded_by_containment_not_by_representability() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    let location = undecodable_location();
    assert!(
      location.to_str().is_none(),
      "staging: no `str` spells this location, so the lowering answers Outside \
       for it"
    );
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![crate::os::DeclinedBoundary {
        location: location.clone(),
        dev: 9,
        mnt_id: Some(77),
      }]),
      at(1),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(location.clone(), Some(77), None)],
      "the declined boundary is RECORDED: the set is keyed by PathBuf, and the \
       walk answered both halves of its identity"
    );

    // The two containment halves, on the same set and after it already holds a
    // record, so neither refusal can be mistaken for the containment rule.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![
        crate::os::DeclinedBoundary {
          location: PathBuf::from("/r"),
          dev: 9,
          mnt_id: Some(78),
        },
        crate::os::DeclinedBoundary {
          location: PathBuf::from("/elsewhere"),
          dev: 9,
          mnt_id: Some(79),
        },
      ]),
      at(1),
    );
    let held = recorded(&core, scope);
    assert!(
      !held.iter().any(|(path, ..)| path == Path::new("/r")),
      "a boundary AT the root is still refused: no census can ever key it, so \
       one would fail the scope closed for its whole life: {held:?}"
    );
    assert!(
      !held
        .iter()
        .any(|(path, ..)| path == Path::new("/elsewhere")),
      "a boundary OUTSIDE the root is still refused: {held:?}"
    );
    assert_eq!(
      held.len(),
      1,
      "and the ledger is otherwise untouched: {held:?}"
    );

    // The departure. The record is mount-backed (its id is not the root's), so
    // the refresh condemns it — and on fanotify the cover parks on an admission
    // round trip that the raw location addresses.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(2));
    let effects = drain(&mut core);
    let requested = admissions(&effects);
    assert_eq!(
      requested.len(),
      1,
      "the departure opens its round trip, addressed by the RAW path: {effects:?}"
    );
    assert_eq!(requested[0].1, location);

    let effects = answer_one_admission(&mut core, scope, &effects, at(3));
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "and the cover goes out — never silence, which is what the dropped record \
       bought: {effects:?}"
    );
    assert!(emitted[0].kind().is_rescan());
    assert_eq!(
      emitted[0].location(),
      &loc(&[]),
      "over the WHOLE root: the lowering happens HERE, at cover emission, where \
       an unrepresentable location has a safe degrade rather than at the record, \
       where it had only silence"
    );
  }

  /// The FILL-IN rule, and why a seam never covers a replacement: a known
  /// identity change at a recorded location is left to the REFRESH, which covers
  /// it far better than the seam could.
  ///
  /// The seam has only a DOMINATING cover to give — a root-wide one — because a
  /// `record_boundary` observation carries no location the core may act on. The
  /// next authoritative read, arriving at the same fact as a census ARRIVAL,
  /// covers the BOUNDARY: one located `Rescan` instead of a re-read of the entire
  /// tree. So the seam stays quiet, and the entry standing at the location is
  /// left exactly as its own seam decided it — the containment rule refuses the
  /// second observation rather than letting it align the entry with whatever
  /// replaced what it describes.
  ///
  /// There was once an exception here, standing a prompt cover when the record
  /// carried an outstanding absence claim. It went with the claim: a scope that
  /// cannot tell one incarnation from another fails closed and covers its whole
  /// root every refresh, which is strictly more than the exception ever bought.
  #[test]
  fn a_seam_leaves_a_replacement_to_the_refresh_that_covers_it_precisely() {
    let (mut core, scope) = spawned_fanotify(None, Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    core.on_walk_boundaries(
      scope,
      partial_walk(vec![idless_decline("/r/vol", 99)]),
      at(1),
    );
    let held = vec![(PathBuf::from("/r/vol"), None, None)];
    assert_eq!(
      recorded(&core, scope),
      held,
      "staging: one ambiguous record, observed by the walk alone"
    );

    // The same-path remount, seen by the walk first. The refresh has not read a
    // row yet, so it still owes this transition a cover.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![idless_decline("/r/vol", 77)]),
      at(2),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty(),
      "the seam stands NO cover here: the only one it could stand is root-wide, \
       and the refresh is about to cover the boundary itself: {effects:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      held,
      "and it fills in nothing — keeping the identity is what lets the refresh \
       SEE the replacement when the row lands"
    );

    // The row lands, and it is the refresh that reads the disagreement.
    core.on_mounts_refreshed(
      scope,
      alive_refresh(vec![row("/r/vol", 55, 77)], true),
      at(3),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the replacement is covered exactly once: {effects:?}"
    );
    assert_eq!(
      emitted[0].location(),
      &loc(&["vol"]),
      "and LOCATED at the boundary — not the whole root, which is all the seam \
       had to offer"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(55), Some(77))],
      "the row re-identifies the record, and confirms it"
    );
  }

  /// **R12 F1, the twin.** A whole-root generation whose walk fenced against a
  /// root this scope does not hold publishes NEITHER half.
  ///
  /// It is the same defect [`DriverCore::on_root_recovered`] gates, on the other
  /// message that carries a complete generation. "What this walk did not decline
  /// is not there any more" names a particular ROOT MOUNT; applied under a
  /// different one it deletes entries for boundaries the walk never looked at —
  /// and it deletes them from the one structure no mount table can rebuild, so
  /// nothing puts them back, no later departure there is derivable, the ground
  /// such a departure would reveal is never admitted, and its events drop with no
  /// signal at all.
  ///
  /// The RECORDING half goes with it, for the reason a superseded admission reply
  /// records nothing either: a boundary read against another root has its
  /// `Standing` decided against that root's id, which says nothing about this
  /// one.
  ///
  /// **What the mismatch owes is a generation, not a cover.** A complete report is
  /// produced only behind a loss, and the `Overflow` immediately behind it on the
  /// source's one ordered queue covers the whole root whether or not this lands —
  /// so no cover is stranded. But dropping the generation is not free: an exempt
  /// boundary that appeared since the last one is now recorded nowhere. That need
  /// is not RECORDED here; it is DERIVED
  /// ([`ScopeState::generation_stale`](crate::core::ScopeState)) from a coverage
  /// set whose exempt partition was last verified in a world this scope has left.
  ///
  /// **A refresh IS armed, and that is the fix rather than a cost.** It used to
  /// arm none, on the argument that the `Overflow` a message later arms one
  /// anyway. But a boundary report does not advance the loss dedup position, so a
  /// later loss can ride an OLDER `Overflow` already queued ahead of this report —
  /// whose refresh completes before this report is even ingested — and with
  /// liveness polling off there is then no later refresh at all. The read armed
  /// here is what moves the frame this report says is wrong; a following
  /// `Overflow` coalesces onto it rather than buying a second.
  ///
  /// MUTATION WITNESS (gate dropped): remove the frame check from
  /// `on_walk_boundaries` and this FAILS at `NEITHER half of a generation from
  /// another root lands` — `/r/b` retired by a walk that never looked at this
  /// root, and `/r/new` recorded against a frame the rebase has run past.
  /// MUTATION WITNESS (no read armed): drop the `arm_refresh` from the mismatch
  /// arm and it FAILS at `the mismatch arms the read that moves the frame` with
  /// `left: 0, right: 1` — and, with the tick off, the owed generation is then
  /// asked for by nothing at all.
  #[test]
  fn a_whole_root_generation_from_another_root_publishes_neither_half() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    // Two exempt boundaries the seam observed. No mountinfo row will ever list
    // either, so a whole-root generation is the ONLY thing that can retire one.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/a", 99, 42)]),
      at(1),
    );
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/b", 98, 42)]),
      at(1),
    );
    let held = recorded(&core, scope);
    assert_eq!(held.len(), 2, "staging: two exempt records: {held:?}");

    // The post-loss reseed reopened the root and found mount 77 standing there.
    // This core has not run the refresh that would adopt it, so its coverage set
    // is still relative to 42. The generation declines only `/r/a`, and names one
    // boundary this scope has never heard of.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(
        Some(77),
        frame_epoch(&core, scope),
        vec![
          subvolume_decline("/r/a", 99, 77),
          subvolume_decline("/r/new", 97, 77),
        ],
      ),
      at(2),
    );
    let effects = drain(&mut core);
    assert_eq!(
      recorded(&core, scope),
      held,
      "NEITHER half of a generation from another root lands: `/r/b` is not \
       retired by a walk that never looked at this root, and `/r/new` does not \
       enter carrying a frame the rebase has already run past"
    );
    assert!(
      emits(&effects).is_empty(),
      "it covers nothing — the loss behind it owns the cover: {effects:?}"
    );
    assert_eq!(
      refresh_requests(&effects),
      1,
      "the mismatch arms the read that moves the frame — this report says the \
       core's frame is wrong, and only a read can settle that: {effects:?}"
    );
    assert!(
      recoveries(&effects).is_empty(),
      "nor is a walk asked for on the spot: the core is the stale party here, so \
       an immediate re-request is answered by a walk that reads the very same \
       root and is refused identically: {effects:?}"
    );

    // The read the mismatch armed. It adopts the root the walk saw, which moves
    // the frame — and a coverage set last verified in the world before it is now
    // owed a generation, derived rather than remembered.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(77)), at(3));
    let effects = drain(&mut core);
    let asked = recoveries(&effects);
    assert_eq!(
      asked.len(),
      1,
      "the owed generation is asked for by the next authoritative refresh: \
       {effects:?}"
    );
    assert_eq!(
      asked[0].epoch,
      frame_epoch(&core, scope),
      "stamped with the frame that refresh just published"
    );
    let effects = answer_one_recovery(
      &mut core,
      scope,
      &effects,
      vec![subvolume_decline("/r/a", 99, 77)],
      at(4),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/a"), Some(77), None)],
      "and THAT generation lands: `/r/b` retires on a walk of the root this \
       scope actually holds"
    );
    assert_eq!(
      emits(&effects).len(),
      1,
      "behind the root cover the recovery carries: {effects:?}"
    );

    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(77)), at(5));
    let settled = drain(&mut core);
    assert!(
      recoveries(&settled).is_empty() && emits(&settled).is_empty(),
      "the debt was discharged ONCE — a second refresh owes nothing: {settled:?}"
    );
  }

  /// The honest degrade on the same gate: a walk that completed but could not read
  /// a mount id for the root it reopened still produces a GENERATION.
  ///
  /// `Ok(None)` is an unknown, never a failed read — a `statx` that fails leaves
  /// the walk incomplete and reaches the core as no report at all — and every
  /// unknown frame leg in this design PASSES. It has to: below Linux 5.8 nothing
  /// in the system reports a mount id, so reading unknown as "different" would
  /// leave such a host with no way to retire an exempt entry ever again —
  /// the growth the generation exists to bound. The core-owned EPOCH beside it
  /// carries the check there, which is exactly why the id leg may degrade.
  ///
  /// MUTATION WITNESS (unknown read as different): compare with `walked !=
  /// state.root_mnt_id` in `on_walk_boundaries` and this FAILS at `an unknown
  /// frame PASSES` — the retirement refused, and with it the only removal path
  /// an exempt entry has.
  /// MUTATION WITNESS (every report disputes the frame): hoist the mismatch arm's
  /// `arm_refresh` above the `if` in `on_walk_boundaries`, so an APPLIED
  /// generation arms a read too, and it FAILS at `an applied generation disputes
  /// nothing` with `left: 1, right: 0` — a mount-table read bought behind every
  /// loss barrier, which is the cost the gate exists to spend only on a report
  /// that actually contradicts the frame.
  #[test]
  fn a_whole_root_generation_that_read_no_mount_id_is_still_a_generation() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/gone", 99, 42)]),
      at(1),
    );
    assert_eq!(
      recorded(&core, scope).len(),
      1,
      "staging: one exempt record only a generation can retire"
    );

    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(None, frame_epoch(&core, scope), Vec::new()),
      at(2),
    );
    let applied = drain(&mut core);
    assert!(
      recorded(&core, scope).is_empty(),
      "an unknown frame PASSES, exactly as it does at every other frame fence: \
       the walk completed, so what it did not decline is not there any more"
    );
    assert_eq!(
      refresh_requests(&applied),
      0,
      "and an applied generation disputes nothing, so it arms no read: the read \
       a REFUSED one arms is what moves the frame it disagrees with, and a report \
       that agreed has nothing to move: {applied:?}"
    );

    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(3));
    let effects = drain(&mut core);
    assert_eq!(
      recoveries(&effects).len(),
      0,
      "nothing is owed: the generation was applied, so no refresh has to buy a \
       second whole-root walk to replace it: {effects:?}"
    );
  }

  /// The one thing a whole-root walk may NOT speak for: ground BENEATH a boundary
  /// it declined, which it never descended into.
  ///
  /// Reachable through the containment rule's one gap — it refuses a record
  /// beneath an existing one but accepts one ABOVE it — so a set can genuinely
  /// hold `/r/a/deep` and `/r/a` at once.
  #[test]
  fn a_whole_root_walk_does_not_retire_what_it_could_not_descend() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    // Recorded deepest-first, which is the order the containment rule permits.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/a/deep", 99, 42)]),
      at(1),
    );
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/a", 98, 42)]),
      at(1),
    );
    assert_eq!(
      recorded(&core, scope).len(),
      2,
      "staging: a record ABOVE an existing one is accepted — the containment rule \
       only ever refused one BENEATH"
    );

    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(
        root_frame(&core, scope),
        frame_epoch(&core, scope),
        vec![subvolume_decline("/r/a", 98, 42)],
      ),
      at(1),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![
        (PathBuf::from("/r/a/deep"), Some(42), None),
        (PathBuf::from("/r/a"), Some(42), None),
      ],
      "the walk stopped AT `/r/a`, so it observed nothing below it and retires \
       nothing there"
    );
  }

  /// **R12 F1.** Mount ids RECYCLE, so a generation stamped with the walked id
  /// alone is admitted from an incarnation of the root that has already died.
  ///
  /// Linux allocates mount ids lowest-free. A root that goes A → B → A is back on
  /// the very id the core holds, while a generation still queued from the FIRST A
  /// describes a mount that no longer exists — and "what this walk did not decline
  /// is not there any more" then retires ledger entries for boundaries the live
  /// incarnation never showed it. No mount table can restore them, so those
  /// departures become underivable: the ground is never admitted and its events
  /// drop with no signal at all.
  ///
  /// The second stamp is the core's own frame EPOCH, published down the control
  /// mailbox and sampled by the walk before it starts. It counts WORLDS, core-side,
  /// so nothing the kernel does to an id can forge it — which is exactly why a
  /// recycle cannot pass it.
  ///
  /// The cell drives the recycle through the real adoption path (two refreshes,
  /// two frame moves) rather than poking the epoch, so what it reads is the same
  /// counter production increments.
  ///
  /// MUTATION WITNESS (id leg only): drop the `stamped != state.frame_epoch`
  /// disjunct from `on_walk_boundaries` and this FAILS at `the generation from
  /// the incarnation BEFORE the recycle retires nothing` with `left: [], right:
  /// [("/r/keep", Some(42), Some(99))]` — `/r/keep` retired by a walk of a mount
  /// that had already been unmounted twice over.
  /// MUTATION WITNESS (a known id read as a mismatch): add `|| walked.is_some()`
  /// to the same disjunction — the mirror of the `None`-as-different mistake, and
  /// the strict direction — and it FAILS at `and the CURRENT world's generation
  /// still lands`, every sound generation refused, which is the growth the
  /// reconciliation exists to bound.
  #[test]
  fn a_recycled_root_mount_id_cannot_pass_a_generation_from_the_incarnation_before_it() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(0));
    let effects = drain(&mut core);
    assert!(obliged(&effects).is_empty(), "staging: empty baseline");
    let born = frame_epoch(&core, scope);
    assert_eq!(
      frame_publications(&effects),
      vec![born],
      "the birth refresh SEEDS the source with the world it was spawned into — a \
       fresh reader's mailbox starts at zero: {effects:?}"
    );

    // One exempt boundary. No mountinfo row will ever list it, so only a
    // whole-root generation can take it out of the set.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/keep", 99, 42)]),
      at(1),
    );
    let held = recorded(&core, scope);
    assert_eq!(held.len(), 1, "staging: one exempt record: {held:?}");

    // A → B: the root re-mounts onto 77.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(77)), at(2));
    let effects = drain(&mut core);
    let moved = frame_epoch(&core, scope);
    assert!(moved != born, "staging: the frame move bumped the epoch");
    assert_eq!(
      frame_publications(&effects),
      vec![moved],
      "and the move is published, or the source would keep stamping the world \
       before it: {effects:?}"
    );
    // B → A: 77 goes away and the root is back on 42, the id it started on.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(3));
    let effects = drain(&mut core);
    let recycled = frame_epoch(&core, scope);
    assert_eq!(
      root_frame(&core, scope),
      Some(42),
      "staging: the id really did recycle — this is the whole premise"
    );
    assert!(
      recycled != born && recycled != moved,
      "while the epoch did NOT: it counts worlds, and three worlds have passed"
    );
    assert_eq!(
      frame_publications(&effects),
      vec![recycled],
      "the recycle is a world change like any other: {effects:?}"
    );

    // The delayed generation from the FIRST A. Its walked id is 42 — the id the
    // core holds right now — and it declines nothing.
    core.on_walk_boundaries(scope, whole_root_walk_on(Some(42), born, Vec::new()), at(4));
    assert_eq!(
      recorded(&core, scope),
      held,
      "the generation from the incarnation BEFORE the recycle retires nothing: \
       its id matches by accident, and an accident is not evidence"
    );

    // The same generation, stamped with the world the core is actually in.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), recycled, Vec::new()),
      at(5),
    );
    assert!(
      recorded(&core, scope).is_empty(),
      "and the CURRENT world's generation still lands — the epoch refuses a stale \
       walk, never a sound one"
    );
  }

  /// **R12 F3.** A recovery whose reply was refused is re-asked by a
  /// NON-AUTHORITATIVE refresh, with no liveness tick anywhere in the run.
  ///
  /// The discharge used to live inside the authoritative mount-table branch alone.
  /// Nothing about the need depends on the table: the frame is adopted out of the
  /// root's own `statx`, above that branch, and a failed table read does not touch
  /// it. So a scope whose one mismatch-armed refresh came back non-authoritative
  /// fell through a branch that closes trust and schedules nothing — and with
  /// `root_liveness_interval` zero (a supported setting) or a persistently
  /// unreadable mountinfo, the refused cutoff was never replaced: the collapsed
  /// admissions stayed parked forever, and neither their generation nor a root
  /// cover was ever published.
  ///
  /// The cell runs the whole thing at `Duration::ZERO`, so nothing can converge by
  /// waiting — there is no tick to wait for.
  ///
  /// MUTATION WITNESS (discharge confined to the table branch): delete
  /// `recover_root = fanotify && state.owes_whole_root();` from
  /// `on_mounts_refreshed`'s non-authoritative arm and this FAILS at `the
  /// non-authoritative refresh still asks for the owed recovery` with `left: 0,
  /// right: 1` — after which the parked cover is never released and the assertion
  /// below it never runs.
  /// MUTATION WITNESS (the latch never releases): make `owes_whole_root`'s
  /// outstanding arm `Some(_) => false` — suppressing on ANY outstanding round
  /// trip rather than only one issued in the world this scope still holds — and it
  /// FAILS at the same assertion, because a reply that can never be applied would
  /// silence every later request for as long as the scope lived.
  #[test]
  fn a_refused_recovery_is_re_asked_by_a_non_authoritative_refresh_with_no_tick() {
    let (mut core, scope) =
      live_core_fanotify_polling(Duration::ZERO, vec![row("/r/vol", 55, 77)], Some(42));

    // The mount departs. On fanotify the cover PARKS on a round trip.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(1));
    let effects = drain(&mut core);
    assert_eq!(
      admissions(&effects).len(),
      1,
      "staging: one departure, one parked cover: {effects:?}"
    );
    assert_eq!(parked_admits(&core, scope), 1, "staging: and it is parked");
    assert!(
      emits(&effects).is_empty(),
      "staging: nothing is covered yet — that is what parking MEANS: {effects:?}"
    );

    // The root re-mounts. The parked round trip belongs to the world before it,
    // so no located reply can answer it any more and the refresh asks for the one
    // whole-root recovery that can.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(77)), at(2));
    let effects = drain(&mut core);
    let asked = recoveries(&effects);
    assert_eq!(
      asked.len(),
      1,
      "staging: the parked cover crossed a world boundary, so one recovery is \
       asked for: {effects:?}"
    );

    // The reply comes back having walked a root the core has not adopted: the
    // source is ahead, the core is the stale party, and NOTHING is applied.
    core.on_root_recovered(
      scope,
      crate::os::RootRecovery {
        declined: Vec::new(),
        cutoff: asked[0].ticket,
        epoch: asked[0].epoch,
        root_mnt_id: Some(99),
      },
      at(3),
    );
    let effects = drain(&mut core);
    assert_eq!(
      parked_admits(&core, scope),
      1,
      "the refused reply discharges nothing — its cutoff cannot be applied in a \
       world it did not walk"
    );
    assert!(
      emits(&effects).is_empty(),
      "and it covers nothing: {effects:?}"
    );
    assert_eq!(
      refresh_requests(&effects),
      1,
      "what it does is arm the read that will move the frame: {effects:?}"
    );
    assert!(
      recoveries(&effects).is_empty(),
      "asking again on the spot would be answered by a walk reading the very \
       same root and refused identically: {effects:?}"
    );

    // THE READ THE MISMATCH ARMED COMES BACK WITH NO TABLE. The old code stopped
    // here forever.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), false, Some(99)), at(4));
    let effects = drain(&mut core);
    let again = recoveries(&effects);
    assert_eq!(
      again.len(),
      1,
      "the non-authoritative refresh still asks for the owed recovery: the frame \
       it just read is all the request needs, and the table is not part of it: \
       {effects:?}"
    );
    assert_eq!(
      again[0].epoch,
      frame_epoch(&core, scope),
      "stamped with the frame that read just published"
    );

    // And it converges: the reply for the world the core now holds discharges the
    // parked cover by cutoff and publishes the root cover it was carrying.
    let effects = answer_one_recovery(&mut core, scope, &effects, Vec::new(), at(5));
    assert_eq!(
      parked_admits(&core, scope),
      0,
      "the cutoff discharges the cover that had been parked since the world \
       before last"
    );
    assert_eq!(
      emits(&effects).len(),
      1,
      "and the root cover finally reaches the consumer: {effects:?}"
    );

    // Settled: nothing is owed a second time.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(99)), at(6));
    let settled = drain(&mut core);
    assert!(
      recoveries(&settled).is_empty() && emits(&settled).is_empty(),
      "a scope that owes nothing asks for nothing: {settled:?}"
    );
  }

  /// **R12 F5.** A reply that a NEWER one has already dominated costs no third
  /// walk — and it costs none because there is no debt to forget to clear.
  ///
  /// The old shape recorded "a recovery is owed" as a boolean at the refusal site.
  /// A newer reply landing behind it applied the generation, the cutoff and the
  /// cover — everything the boolean stood for — and did not clear it, so the
  /// refresh the refusal had armed bought a third whole-root walk and a third
  /// `Rescan` over an already-current map. Deriving the need instead makes that
  /// unreachable: the refusal records nothing, and the dominating reply advances
  /// the very watermark the need is read from.
  ///
  /// MUTATION WITNESS (the applied generation is not banked): drop
  /// `state.generation_applied();` from `on_root_recovered`'s success path and this
  /// FAILS at `the refresh the refusal armed asks for nothing` with `left: 1,
  /// right: 0` — the whole-root walk and `Rescan` the finding is about, on a map
  /// that was already current.
  /// MUTATION WITNESS (the refused reply is applied anyway): remove the `return`
  /// from the mismatch arm so the stale reply falls through, and it FAILS at `the
  /// refused reply retires nothing` — `/r/keep` deleted by a walk of a world this
  /// scope had already left.
  #[test]
  fn a_reply_a_newer_one_dominates_costs_no_third_walk() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/keep", 99, 42)]),
      at(1),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/keep"), Some(42), None)],
      "staging: one exempt record only a whole-root generation can retire"
    );

    // World two: the frame moves, so the set's last generation is a world behind
    // and one recovery is asked for.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(77)), at(2));
    let effects = drain(&mut core);
    let first = recoveries(&effects);
    assert_eq!(first.len(), 1, "staging: one recovery asked: {effects:?}");

    // World three, while that walk is still out. The refresh sees a round trip
    // issued in a world it has left and asks again — this is the reply that will
    // dominate.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(88)), at(3));
    let effects = drain(&mut core);
    let second = recoveries(&effects);
    assert_eq!(
      second.len(),
      1,
      "staging: the superseded round trip is re-asked in the world it will be \
       judged in: {effects:?}"
    );
    assert!(
      second[0].ticket > first[0].ticket,
      "staging: and the newer cutoff dominates the older one"
    );

    // The OLD reply lands first and is refused: it answers for world two.
    core.on_root_recovered(
      scope,
      crate::os::RootRecovery {
        declined: Vec::new(),
        cutoff: first[0].ticket,
        epoch: first[0].epoch,
        root_mnt_id: Some(77),
      },
      at(4),
    );
    let refused = drain(&mut core);
    assert_eq!(
      recorded(&core, scope),
      // The seam decided its standing once, so no frame move touches it: the
      // entry is the same entry, and it is still there.
      vec![(PathBuf::from("/r/keep"), Some(88), None)],
      "the refused reply retires nothing: it walked a world this scope has left"
    );
    assert_eq!(
      refresh_requests(&refused),
      0,
      "and it arms no read: the round trip world three minted is standing at this \
       scope's current epoch, so the need is already served — which is the same \
       fact the refresh below then observes, one message earlier and for free: \
       {refused:?}"
    );

    // The NEWER reply lands and applies everything the refusal left owed. Its walk
    // found a DIFFERENT subvolume standing and `/r/keep` gone, so the set still
    // holds ground only a generation can speak for — which is what makes the
    // watermark it banks observable at the refresh below.
    let covered = answer_one_recovery(
      &mut core,
      scope,
      &effects,
      vec![subvolume_decline("/r/other", 97, 88)],
      at(5),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/other"), Some(88), None)],
      "the dominating reply's generation lands: what it did not decline is gone, \
       and what it did enters"
    );
    assert_eq!(
      emits(&covered).len(),
      1,
      "with the root cover it carries: {covered:?}"
    );

    // The refresh the REFUSAL armed. Nothing is owed any more, and nothing asks.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(88)), at(6));
    let settled = drain(&mut core);
    assert_eq!(
      recoveries(&settled).len(),
      0,
      "the refresh the refusal armed asks for nothing — the newer reply already \
       did everything the refusal left owed, so a third whole-root walk and a \
       third `Rescan` buy nothing: {settled:?}"
    );
    assert!(
      emits(&settled).is_empty(),
      "and covers nothing: {settled:?}"
    );
  }

  /// **R12 F4, the producing half.** One departure verdict publishes its whole
  /// burst of round trips as ONE indivisible request.
  ///
  /// Posted one at a time, a source can wake on a PREFIX of the burst: it
  /// snapshots that prefix into a whole-root recovery, and the remainder — arriving
  /// while that recovery's walk runs — becomes a SECOND obligation with a second
  /// whole-root walk and a second report behind it. The boundary budget's supported
  /// floor is one permit, held until the driver consumes the message, so that
  /// second report claims nothing and kills a source with nothing wrong with it.
  /// The reader's own fold ("a burst costs one walk") can only see a burst it is
  /// handed whole.
  ///
  /// MUTATION WITNESS (published one at a time): replace the single
  /// `effects.push_back(Effect::AdmitBoundaries { scope, requests })` with a loop
  /// pushing one effect per request and this FAILS at `ONE request carries the
  /// whole burst` with `left: 3, right: 1` — three separately-postable messages
  /// where the verdict produced one.
  /// MUTATION WITNESS (a partial burst): have the collector `.take(1)` the
  /// departed run and it FAILS at `and it carries every one of them` with `left:
  /// 1, right: 3` — two covers parked against requests no source was ever handed.
  #[test]
  fn a_departure_burst_is_published_as_one_indivisible_request() {
    let (mut core, scope) = live_core_fanotify(
      vec![
        row("/r/one", 51, 71),
        row("/r/two", 52, 72),
        row("/r/three", 53, 73),
      ],
      Some(42),
    );

    // All three depart in the same table read — the burst this seam is shaped
    // around.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(1));
    let effects = drain(&mut core);
    let bursts: Vec<&Effect> = effects
      .iter()
      .filter(|effect| matches!(effect, Effect::AdmitBoundaries { .. }))
      .collect();
    assert_eq!(
      bursts.len(),
      1,
      "ONE request carries the whole burst — a source that could see a prefix of \
       it would pay a second whole-root walk for the rest, and at a boundary \
       budget of one that second report kills the source: {effects:?}"
    );
    let requested = admissions(&effects);
    assert_eq!(
      requested.len(),
      3,
      "and it carries every one of them: {effects:?}"
    );
    assert_eq!(
      requested
        .iter()
        .map(|(_, at, _)| at.clone())
        .collect::<Vec<_>>(),
      vec![
        PathBuf::from("/r/one"),
        PathBuf::from("/r/two"),
        PathBuf::from("/r/three"),
      ],
      "in the order the verdict condemned them"
    );
    assert!(
      requested[0].0 < requested[1].0 && requested[1].0 < requested[2].0,
      "with monotone tickets, which is what makes ONE cutoff answer the run: \
       {requested:?}"
    );
    assert_eq!(
      parked_admits(&core, scope),
      3,
      "one parked cover per round trip, and not one of them released yet"
    );
    assert!(
      emits(&effects).is_empty(),
      "nothing is covered until the walks answer: {effects:?}"
    );
  }

  /// **THE FAIL-CLOSED RULE, on the profile that needs the routing.** A scope
  /// holding an AMBIGUOUS record covers its WHOLE ROOT on every authoritative
  /// refresh — through the source's whole-root recovery, never as a bare
  /// positional cover.
  ///
  /// # Why the whole root, and why every refresh
  ///
  /// An ambiguous record is one whose identity cannot say whether the boundary it
  /// names is still there — on Linux 4.11–5.7 that is EVERY seam record, genuine
  /// vfsmounts included. A refresh that does not list it cannot say either: the
  /// mount table never lists a subvolume, and never lists a mount the host cannot
  /// key by id. Three designs tried to pay for that per record (cover once; cover
  /// on a generation cadence; latch a refusal) and each produced a fresh silent
  /// loss, because on an id-less host a re-observation of an ambiguous boundary
  /// is bit-for-bit identical whether it is the old mount or a new one. So no
  /// per-record decision is made at all.
  ///
  /// # Why it may not be a bare cover HERE
  ///
  /// fanotify admits by directory-handle membership. Ground the map has never
  /// seen is ground the source is blind to, so a `Scope::Root` cover emitted
  /// straight from the refresh would send the consumer to re-read a tree the
  /// source cannot report on, and every mutation until some later reseed would
  /// drop on an unknown handle with no loss signal. The cover therefore travels
  /// WITH the reseed, on the reply — admission-before-cover, at root scope.
  ///
  /// MUTATION WITNESS (never): disable the trigger and this FAILS at `exactly one
  /// whole-root recovery was asked for` with `left: 0, right: 1` — the silent-loss
  /// direction, and #74's own bug class on every 4.11–5.7 host.
  /// MUTATION WITNESS (once): SPEND the obligation instead of holding it (drop
  /// the entries as the recovery goes out — the `bool` shape the first design
  /// used) and it FAILS at `tick 3: and nothing LOCATED is asked for either`: the
  /// scope stops failing closed, the next refresh derives nothing, and every one
  /// after it is silent.
  /// MUTATION WITNESS (routing): emit `Scope::Root` from the refresh instead of
  /// asking the source and it FAILS at `tick 2: nothing reaches the consumer on
  /// the verdict itself` — the consumer gets a cover for ground the FID map does
  /// not hold.
  /// MUTATION WITNESS (spin): answer the recovery through the loss path
  /// (`on_root_overflow`) and it FAILS at `tick 2: and the recovery does NOT
  /// summon its own next refresh` with `left: 1, right: 0` — a loss re-arms the
  /// table read, the read fails closed again, and the pair turns over as fast as
  /// the driver can run it.
  #[test]
  fn an_unknown_entry_recovers_the_whole_root_on_every_authoritative_refresh() {
    let (mut core, scope) = spawned_fanotify(None, Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    // The mount arrives after the baseline and a LIVE walk is the only thing that
    // ever sees it. The walk's `statx` succeeds with the mnt-id bit unset, so the
    // decline carries a device and no id — the shape a genuine vfsmount takes on
    // a kernel that answers no mount ids at all.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![idless_decline("/r/vol", 99)]),
      at(1),
    );
    let held = vec![(PathBuf::from("/r/vol"), None, None)];
    assert_eq!(
      recorded(&core, scope),
      held,
      "staging: ambiguous — no id on the record, and none on the scope either"
    );

    // Every frame here is EMPTY, on purpose: a frame that listed the location
    // would upgrade the record and end the very state under test. Each recovery's
    // own generation RE-DECLINES the boundary, which is what a reseed of a tree
    // where the mount is still there produces — and what keeps the record (and
    // therefore the fail-closed state) alive across the loop.
    for tick in 2..=4 {
      core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(tick));
      let effects = drain(&mut core);
      assert!(
        emits(&effects).is_empty(),
        "tick {tick}: nothing reaches the consumer on the verdict itself — the \
         ground a departure here would reveal has no handles at all: {effects:?}"
      );
      assert!(
        admissions(&effects).is_empty(),
        "tick {tick}: and nothing LOCATED is asked for either: no per-record \
         evidence exists to aim a located walk with: {effects:?}"
      );
      let effects = answer_one_recovery(
        &mut core,
        scope,
        &effects,
        vec![idless_decline("/r/vol", 99)],
        at(tick),
      );
      let emitted = emits(&effects);
      assert_eq!(
        emitted.len(),
        1,
        "tick {tick}: every authoritative refresh recovers the whole root: \
         {effects:?}"
      );
      assert_eq!(
        recorded(&core, scope),
        held,
        "tick {tick}: and the recovery's own generation keeps the still-live \
         boundary recorded — one record, re-observed, never a duplicate"
      );
      assert!(emitted[0].kind().is_rescan());
      assert_eq!(
        emitted[0].location(),
        &loc(&[]),
        "tick {tick}: over the WHOLE root, behind the reseed that made it \
         readable: {emitted:?}"
      );
      assert_eq!(
        refresh_requests(&effects),
        0,
        "tick {tick}: and the recovery does NOT summon its own next refresh. \
         Routing it through the loss path would: a loss re-arms the table read, \
         the read fails closed again, and the pair spins as fast as the driver \
         can turn it over — a whole-map reseed per iteration, not the one \
         per LIVENESS TICK this design accepts: {effects:?}"
      );
    }

    // A NON-authoritative refresh installs no frame and diffs nothing, so it
    // witnesses no absence: the rule is about frames actually read.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), false), at(5));
    let effects = drain(&mut core);
    assert!(
      recoveries(&effects).is_empty() && emits(&effects).is_empty(),
      "a refresh that could not read the table observed nothing to fail closed \
       over: {effects:?}"
    );
  }

  /// **THE ≥5.8 CASE, which is what makes the cost above narrow.** With every
  /// record carrying a mount id and the scope carrying a frame, the ambiguous
  /// partition is EMPTY — so no whole-root recovery is ever asked for, and a
  /// departure is covered precisely at its own location.
  ///
  /// This is the cell that proves the fail-closed cost is not paid on modern
  /// kernels. `root_mnt_id` is read at spawn (a failure there is a spawn failure,
  /// not a `None`), and every seam that records reads the boundary's own id from
  /// the fd it pinned — a `statx` that fails yields an incomplete walk or a
  /// `Failed` probe and records nothing. So on Linux ≥ 5.8 an entry is `Mount` or
  /// `SameMount`, and never `Unknown`.
  ///
  /// The fanotify backend requires `FAN_REPORT_TARGET_FID` (5.17), so it cannot
  /// run on a host that pays the cost at all — but the routing above must still be
  /// right, because the departure COLLAPSE reaches it on any kernel.
  ///
  /// MUTATION WITNESS: make `fails_closed` answer `true` for a `SameMount` entry
  /// as well (use `is_exempt` instead of the `Unknown` match) and this FAILS at
  /// `no whole-root recovery is ever asked for` with a non-empty left — every
  /// btrfs layout on every modern kernel would pay the id-less cost.
  #[test]
  fn an_id_bearing_scope_never_recovers_the_root_and_covers_precisely() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    // Both shapes a ≥5.8 walk can produce: a subvolume (the root's own mount id)
    // and a real mount (an id of its own). Neither is ambiguous.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![
        subvolume_decline("/r/subvol", 99, 42),
        mount_decline("/r/vol", 98, 77),
      ]),
      at(1),
    );
    assert!(
      drain(&mut core).is_empty(),
      "staging: recording is not an event"
    );

    // The mount departs; the subvolume is where it always was. The table lists
    // neither, and never will list the subvolume.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let effects = drain(&mut core);
    assert!(
      recoveries(&effects).is_empty(),
      "no whole-root recovery is ever asked for: with every id known, nothing \
       here is ambiguous and the fail-closed cost is not paid: {effects:?}"
    );
    let effects = answer_one_admission(&mut core, scope, &effects, at(3));
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "one cover, for the one departure: {effects:?}"
    );
    assert_eq!(
      emitted[0].location(),
      &loc(&["vol"]),
      "LOCATED at the mount that left — not the root: {emitted:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/subvol"), Some(42), None)],
      "and the proven subvolume is untouched by any of it"
    );
  }

  /// **R6 F4, the producer side.** A departure burst past `MAX_PENDING_ADMITS`
  /// collapses HERE, where it is produced, into ONE whole-root recovery — and the
  /// recovery's cutoff discharges the whole parked run in one linear pass.
  ///
  /// One refresh can condemn every mount under the root at once (a container
  /// teardown, a `umount -R`, an automounter expiring a tree), so the natural
  /// burst is the namespace's. Handing that run to the source unbounded meant: a
  /// request queued per departure, a located walk attempted per request, a reply
  /// sent per ticket, and — the quadratic part — the core retiring each reply by
  /// SEARCHING its parked vector. The collapse is not a weaker answer: a whole-map
  /// reseed walks strictly more ground than the located walks it replaces, its
  /// complete generation re-records every boundary still live, and the root cover
  /// dominates every located cover it stands in for.
  ///
  /// MUTATION WITNESS (collapse): raise the cap so the burst fits and this FAILS
  /// at `the burst must exceed the bound` — the burst is a FIXED size, never one
  /// derived from the constant, so a raised bound cannot quietly re-parameterize
  /// the verdict into passing.
  /// MUTATION WITNESS (collapse removed): drop the burst disjunct from the
  /// recover condition and this FAILS at `not one request per departure` with 96
  /// requests inside the one `AdmitBoundaries` effect on the left.
  /// MUTATION WITNESS (replace, not add): keep parking the departed records
  /// alongside the recovery and it FAILS at the same site — the collapse would
  /// then owe both the recovery and every located request it exists to avoid.
  #[test]
  fn a_departure_burst_past_the_bound_collapses_into_one_root_recovery() {
    // A FIXED burst, deliberately not one derived from the bound: a size that
    // scaled with the constant would report the same verdict for every value of
    // it, including a value that admits the whole burst.
    const BURST: usize = 96;
    const {
      assert!(
        BURST > MAX_PENDING_ADMITS,
        "the burst must exceed the bound, or this cell asserts nothing"
      );
    }
    let seeded: Vec<MountRow> = (0..BURST)
      .map(|n| row(&format!("/r/m{n}"), 100 + n as u64, 200 + n as u64))
      .collect();
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(seeded.clone(), true), at(0));
    let effects = drain(&mut core);
    assert_eq!(
      emits(&effects).len(),
      seeded.len(),
      "staging: every row ARRIVES and is covered once: {effects:?}"
    );
    assert_eq!(recorded(&core, scope).len(), seeded.len(), "staging");

    // All of them depart at once.
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(1));
    let effects = drain(&mut core);
    assert!(
      admissions(&effects).is_empty(),
      "not one request per departure: that run is what the bound exists to \
       absorb, and absorbing it at the source is absorbing it too late: \
       {effects:?}"
    );
    assert_eq!(
      recoveries(&effects).len(),
      1,
      "the burst collapses into ONE recovery: {effects:?}"
    );
    assert_eq!(
      parked_admits(&core, scope),
      0,
      "and nothing is parked for it — the reply carries the root cover itself"
    );
    assert!(
      emits(&effects).is_empty(),
      "with nothing reaching the consumer until the map can see the ground: \
       {effects:?}"
    );

    // The reseed re-declines one of them: it was still there after all, and the
    // recovery's own generation is what puts it back.
    let effects = answer_one_recovery(
      &mut core,
      scope,
      &effects,
      vec![mount_decline("/r/m0", 200, 100)],
      at(2),
    );
    assert_eq!(
      parked_admits(&core, scope),
      0,
      "the cutoff discharges the whole parked run"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/m0"), Some(100), None)],
      "and the still-live boundary comes back as a fresh observation — the \
       witness a per-ticket `StillCovered` would have restored one at a time"
    );
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "one cover for the whole burst: {effects:?}"
    );
    assert_eq!(emitted[0].location(), &loc(&[]));
  }

  /// No source to ask for the recovery. The scope has no live handle, or its
  /// reader thread is already gone, so the request was refused at the driver.
  ///
  /// The cover is still owed and goes out on the refresh's verdict alone —
  /// exactly what an unreachable located admission does. What is NOT done is
  /// retiring the parked tickets: a request that never reached a source
  /// discharges nothing, and each parked round trip is resolved on its own terms.
  #[test]
  fn an_unreachable_root_recovery_covers_on_the_refreshs_verdict_alone() {
    let (mut core, scope) = spawned_fanotify(None, Vec::new());
    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![idless_decline("/r/vol", 99)]),
      at(1),
    );
    let _ = drain(&mut core);

    core.on_mounts_refreshed(scope, alive_refresh(Vec::new(), true), at(2));
    let effects = drain(&mut core);
    assert_eq!(recoveries(&effects).len(), 1, "staging");

    core.on_recovery_unreachable(scope, at(3));
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the cover is never stranded behind a reply that cannot come: {effects:?}"
    );
    assert_eq!(emitted[0].location(), &loc(&[]));
  }

  /// CONTAINMENT, now unconditional: a recorded boundary absorbs anything
  /// observed beneath it.
  ///
  /// While the ancestor is a recorded boundary the ground under it is already
  /// declined, so a second record there addresses coverage nobody has — and the
  /// ancestor's own departure cover dominates the whole subtree. Dropping the
  /// containment rule outright would record every nested boundary a walk could
  /// reach and spend a cover on each, which is the cost direction the rule exists
  /// to bound.
  ///
  /// The rule once had an exception — a record whose absence had been CLAIMED did
  /// not absorb, because its own liveness was in doubt. The claim is gone with the
  /// rest of the per-record absence apparatus: a scope that cannot say whether its
  /// recorded boundaries are still there fails closed and covers the whole root,
  /// which dominates every descendant this rule declines to record.
  #[test]
  fn a_recorded_boundary_absorbs_what_is_observed_beneath_it() {
    let (mut core, scope) = spawned_fanotify(None, vec![idless_decline("/r/b", 99)]);
    let held = vec![(PathBuf::from("/r/b"), None, None)];
    assert_eq!(
      recorded(&core, scope),
      held,
      "staging: one record, no frame diffed yet, so nothing is claimed"
    );

    core.on_walk_boundaries(
      scope,
      partial_walk(vec![idless_decline("/r/b/y/n", 98)]),
      at(1),
    );
    assert!(drain(&mut core).is_empty());
    assert_eq!(
      recorded(&core, scope),
      held,
      "contained: the live boundary above it already declines this ground, and \
       its departure covers the whole subtree"
    );
  }

  /// A same-object re-mount of the ROOT moves `root_mnt_id`, and a `SameMount`
  /// entry does not move with it — because its standing was never a function of
  /// the live root's id in the first place.
  ///
  /// The seam read two ids at one instant and they agreed. That is a fact, and a
  /// fact does not need maintaining. The predicate this replaced re-asked
  /// `mnt_id == root_mnt_id` on every read, so the moment the root's own id
  /// changed, every live subvolume entry read mount-backed at once and a whole
  /// rebase pass existed only to walk that back.
  ///
  /// On this profile the consequence was not one bad cover but an indefinite
  /// storm: the departure retain removed the record, the admission walk correctly
  /// answered `StillCovered` (the subvolume is still there), the core put the
  /// UNCHANGED old-id record back, and the next refresh derived the same false
  /// departure again — forever. So the second refresh is asserted as well as the
  /// first: the first proves the misclassification is gone, the second proves the
  /// loop that fed it is gone with it.
  ///
  /// Every read here is empty of rows, so nothing can be an arrival cover; and
  /// this profile suppresses the `frame_changed` re-enumerate replay (one
  /// recursive mark already covers the whole subtree), so a cover here could only
  /// be a departure verdict.
  #[test]
  fn a_root_remount_leaves_its_same_mount_entries_alone() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/sub", 99, 42)]),
      at(1),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/sub"), Some(42), None)],
      "staging: a `SameMount` entry — the root's own mount id, on another device"
    );

    // `umount -l /r && mount --bind <same object> /r`: identity unchanged, so the
    // death gate passes, but the root now lives on a DIFFERENT mount.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(43)), at(2));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty() && admissions(&effects).is_empty(),
      "a live subvolume is not a departure just because the ROOT re-mounted: \
       {effects:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/sub"), Some(43), None)],
      "the entry is untouched: `SameMount` was decided at the seam, so no later \
       frame can turn it into a departure witness"
    );

    // The second read is where the storm lived: `StillCovered` used to reinsert
    // the unchanged old-id record for this very read to condemn again.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(43)), at(3));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty() && admissions(&effects).is_empty(),
      "and the next refresh emits NOTHING — no cover, no round trip, no storm: \
       {effects:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/sub"), Some(43), None)],
      "one entry, once, still `SameMount`"
    );
  }

  /// A PARKED cover's location is a hint like any other, and a rename that moves
  /// the ground while the round trip is out moves it too.
  ///
  /// The departure is derived, its cover parks on an admission, and only then does
  /// the directory above it get renamed. Unrebased, the reply releases the cover at
  /// a path that no longer exists — `mount_cover` lowers it to a located `Rescan`
  /// the consumer re-reads nothing for, while the revealed ground at the new path
  /// stays dark. It is #74's own shape inside the admission window.
  ///
  /// Nothing else reads the parked location: the reply is matched by TICKET, so
  /// moving it is the whole repair.
  ///
  /// MUTATION WITNESS: skip `state.pending_admits` in `rebase_hints` and this
  /// FAILS at `the released cover lands where the ground is` — the Rescan comes
  /// out at the stale `a/x`.
  #[test]
  fn a_rename_moves_a_parked_covers_location_too() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(
      scope,
      framed_refresh(vec![row("/r/a/x", 77, 99)], true, Some(42)),
      at(0),
    );
    let effects = drain(&mut core);
    assert_eq!(
      emits(&effects).len(),
      1,
      "staging: the census keys the mount and covers its arrival: {effects:?}"
    );

    // `umount -l /r/a/x`: the read no longer keys 77, so the departure parks.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(1));
    let parked_effects = drain(&mut core);
    let parked = admissions(&parked_effects);
    assert_eq!(
      parked.len(),
      1,
      "staging: the cover parks: {parked_effects:?}"
    );
    assert_eq!(parked[0].1, PathBuf::from("/r/a/x"));

    // `mv /r/a /r/b` WHILE the round trip is out.
    feed(
      &mut core,
      scope,
      vec![RawLinuxEvent::Fanotify(AdmittedEvent {
        mask: FanMask::new(FAN_RENAME),
        path: None,
        rename: Some(AdmittedRename {
          old_path: PathBuf::from("/r/a"),
          new_path: PathBuf::from("/r/b"),
        }),
      })],
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects)
        .iter()
        .any(|c| c.kind().moved_from() == Some(&loc(&["a"])) && c.location() == &loc(&["b"])),
      "staging: the rename pairs into one `Moved`: {effects:?}"
    );

    // The reply releases the cover, and it must land on the ground as it stands
    // NOW.
    let effects = answer_one_admission(&mut core, scope, &parked_effects, at(2));
    let emitted = emits(&effects);
    assert_eq!(emitted.len(), 1, "one released cover: {effects:?}");
    assert_eq!(
      emitted[0].location(),
      &loc(&["b", "x"]),
      "the released cover lands where the ground is, not at the label the \
       departure was derived under: {emitted:?}"
    );
  }

  /// Cell (g): a ROOT FRAME CHANGE with an unchanged table covers nothing at all.
  ///
  /// Mount ids are ABSOLUTE. A census row's key is the mount's own id and a
  /// ledger entry's `Standing` was decided from the two ids one seam read at one
  /// instant — neither is relative to the root's frame, so a same-object remount
  /// of the root (unmount + rebind: the identity is unchanged, so the death gate
  /// passes) moves nothing this scope holds. The census survives the change and
  /// the very same table diffs to silence.
  ///
  /// That is the whole reason the root-relative rebase pass is gone rather than
  /// generalised. The predicate it repaired asked `mnt_id == root_mnt_id` on
  /// every read, so when the root's id moved, every subvolume record started
  /// reading mount-backed at once and the rebase existed only to walk that back —
  /// a maintenance pass for a derivation that should never have been re-derived.
  ///
  /// MUTATION WITNESS (drop the census on a frame change): clear `state.census`
  /// when `frame_changed`, and this FAILS at `an unchanged table covers nothing`
  /// — every row reads as an arrival.
  #[test]
  fn a_root_frame_change_with_an_unchanged_table_covers_nothing() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    let table = || vec![row("/r/a", 10, 99), row("/r/b", 11, 98)];
    core.on_mounts_refreshed(scope, framed_refresh(table(), true, Some(42)), at(0));
    let effects = drain(&mut core);
    assert_eq!(
      emits(&effects).len(),
      2,
      "staging: both rows arrive and both are covered: {effects:?}"
    );

    // The root re-mounts onto 43. The table is byte-for-byte what it was.
    core.on_mounts_refreshed(scope, framed_refresh(table(), true, Some(43)), at(1));
    let effects = drain(&mut core);
    assert!(
      obliged(&effects).is_empty(),
      "an unchanged table covers nothing across a root frame change — no cover, \
       no admission, and no recovery: {effects:?}"
    );
    assert_eq!(
      recorded(&core, scope),
      vec![
        (PathBuf::from("/r/a"), Some(10), Some(99)),
        (PathBuf::from("/r/b"), Some(11), Some(98)),
      ],
      "and the census is the one the read installed, unrebased"
    );

    // With a SAME-MOUNT entry beside it — a subvolume recorded carrying the
    // OLD root's id — the frame change is still silent about it. A design that
    // re-derived provenance from the live root would read every one of these as
    // mount-backed the instant the root moved, and condemn the lot.
    core
      .scopes
      .get_mut(&scope)
      .expect("scope is live")
      .ledger
      .push(LedgerEntry {
        location: PathBuf::from("/r/subvol"),
        standing: Standing::SameMount,
      });
    core.on_mounts_refreshed(scope, framed_refresh(table(), true, Some(44)), at(2));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).is_empty() && admissions(&effects).is_empty(),
      "no false departure per subvolume: a `SameMount` entry joins no census, so \
       a frame that moved under it condemns nothing: {effects:?}"
    );
    assert_eq!(
      recorded(&core, scope).last(),
      Some(&(PathBuf::from("/r/subvol"), Some(44), None)),
      "and it is held, untouched, under whichever frame the root is on now"
    );
  }

  /// **R13 F1.** A whole-root generation REJECTED before this scope ever recorded
  /// an exempt boundary is still owed, and no predicate over the coverage set can
  /// see that.
  ///
  /// `generation_stale` asks whether the set's exempt partition was last verified
  /// in a world this scope has left, and it reads the records the set HOLDS. The
  /// rejected report's declines are precisely what would have PUT the first exempt
  /// record there — so after the rejection the set holds none, `holds_exempt_record`
  /// reads false, and the derivation answers "nothing owed" about a scope that has
  /// just lost a generation.
  ///
  /// The production window is a SOURCE ADOPTION, and it needs no re-mount at all: a
  /// freshly spawned reader's mailbox starts at zero while the core's frame epoch
  /// has already moved (a birth alone bumps it), so that reader's first autonomous
  /// generation is stamped with a world the core has left and is refused on the
  /// epoch. The refresh that refusal arms then reads back the very same mount id,
  /// so the frame epoch does not move either, and the birth watermark still equals
  /// it. Nothing derivable says a generation was ever owed, and no mountinfo row
  /// can ever restore an exempt boundary.
  ///
  /// So the rejection RETAINS evidence. That is not the obligation boolean this
  /// design deleted three rounds ago: it is set by an observation and discharged by
  /// exactly one event — a generation landing — with no site that decides the need
  /// has passed. The second half of this cell is that discharge, because evidence
  /// that never clears is a whole-root walk per refresh forever.
  ///
  /// MUTATION WITNESS (derive it instead): make `ScopeState::generation_stale`'s
  /// `Generation::Lost` arm derive rather than answer — `Generation::Lost { .. } =>
  /// self.holds_exempt_record()` — and this FAILS at `staging: and it arms the read
  /// that would settle the frame` with `left: 0, right: 1`. The loss goes
  /// unrecorded, so the arm that would buy the read finds nothing owed and the R13
  /// assertion behind it never runs: the scope sits with an unverified exempt
  /// partition and asks for nothing, forever.
  /// MUTATION WITNESS (never discharged): drop `state.generation_applied();` from
  /// `on_root_recovered`'s applied path and this FAILS at `the discharge is the
  /// generation LANDING` carrying `[RecoverRoot { .. request: RecoveryRequest {
  /// ticket: AdmitTicket(2), epoch: 1 } }]` — a whole-root reseed bought on every
  /// refresh for the life of the scope.
  #[test]
  fn a_generation_lost_before_the_first_exempt_record_is_still_owed() {
    // The source-adoption window, staged out of the birth alone: the spawn bumps
    // the frame epoch to its first world while a fresh reader's mailbox is still
    // at zero.
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(0));
    let effects = drain(&mut core);
    let born = frame_epoch(&core, scope);
    assert!(
      born != 0,
      "staging: the core has already left the world a fresh mailbox stamps with"
    );
    assert!(obliged(&effects).is_empty(), "staging: empty baseline");
    assert!(
      recorded(&core, scope).is_empty(),
      "staging: NOTHING is recorded yet — this is the state the derivation is \
       blind in"
    );

    // The adopted source's first autonomous generation, stamped with the zero its
    // mailbox starts at, and carrying the FIRST exempt record this scope would
    // ever have held. No mountinfo row lists a subvolume, so this message is the
    // only thing that could have recorded it.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), 0, vec![subvolume_decline("/r/vol", 99, 42)]),
      at(1),
    );
    let effects = drain(&mut core);
    assert!(
      recorded(&core, scope).is_empty(),
      "staging: the stale-stamped report publishes neither half — its decline is \
       gone with it: {effects:?}"
    );
    assert_eq!(
      refresh_requests(&effects),
      1,
      "staging: and it arms the read that would settle the frame: {effects:?}"
    );

    // That read. It finds the SAME mount id — nothing re-mounted; the source was
    // simply younger than the world — so the frame epoch does not move and the
    // birth watermark still equals it.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(2));
    let effects = drain(&mut core);
    assert_eq!(
      frame_epoch(&core, scope),
      born,
      "staging: the refresh moved NOTHING — every epoch-shaped derivation reads \
       this scope as current"
    );
    let asked = recoveries(&effects);
    assert_eq!(
      asked.len(),
      1,
      "the rejected generation is asked for again: the coverage set cannot show \
       what a discarded report was carrying, so the rejection is what remembers \
       it: {effects:?}"
    );
    assert_eq!(
      asked[0].epoch, born,
      "stamped with the frame this refresh published, not the one the report \
       disputed"
    );

    // Answered. The reseed walks the root this scope holds and hands back the
    // boundary the rejected report was carrying.
    let effects = answer_one_recovery(
      &mut core,
      scope,
      &effects,
      vec![subvolume_decline("/r/vol", 99, 42)],
      at(3),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(42), None)],
      "and the exempt boundary finally enters the set: {effects:?}"
    );

    // The discharge. Evidence that only ever accumulates is a whole-root walk per
    // refresh; this is the half that says an APPLIED generation ends it.
    core.on_mounts_refreshed(scope, framed_refresh(Vec::new(), true, Some(42)), at(4));
    let settled = drain(&mut core);
    assert!(
      recoveries(&settled).is_empty(),
      "the discharge is the generation LANDING — nothing else clears it, and \
       nothing keeps asking once it has: {settled:?}"
    );
  }

  /// **R13 F2.** An A → B → A the refreshes never OBSERVED must not admit the
  /// first A's generation.
  ///
  /// The frame epoch is what a recycled mount id cannot forge — but only when the
  /// epoch actually moves, and it moves on a refresh SEEING a different id. Between
  /// two refreshes that both read A, an unmount and a remount are invisible: the
  /// comparison passes, the epoch stands still, and a walk that fenced against the
  /// dead A arrives with BOTH stamps matching. Its generation then retires exempt
  /// records the live incarnation never presented, out of the one partition no
  /// mountinfo row can restore.
  ///
  /// What closes it is a token the host observed a TRANSITION for rather than a
  /// value this scope re-read: the unique mount id where the kernel has one (6.8+),
  /// and the mount-namespace generation below that. The core compares it and moves
  /// the frame on it, which is all it needs to know.
  ///
  /// The second half is the direction that matters just as much: a token that did
  /// NOT move must leave the frame alone. A conservative bump on every refresh
  /// would refuse every sound generation and buy a whole-root reseed per tick for
  /// the life of every scope holding an exempt record.
  ///
  /// MUTATION WITNESS (token ignored): compute `frame_changed` from the mount id
  /// alone in `on_mounts_refreshed` and this FAILS at `the unobserved recycle
  /// moves the frame` with `left: 1, right: 2` — the epoch standing still through a
  /// remount, which is what lets the first A's generation delete `/r/keep` on a
  /// walk of a mount unmounted two transitions ago.
  /// MUTATION WITNESS (bump on any token): use `refresh.root_incarnation.is_some()`
  /// for `incarnation_moved` and this FAILS at `a token that did not move leaves
  /// the frame where it was` with `left: 4, right: 3` — every later generation
  /// refused on an epoch that counts refreshes rather than worlds.
  #[test]
  fn an_unobserved_root_mount_recycle_still_moves_the_frame() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    // The first refresh installs both the id and the incarnation token; nothing
    // is compared against a token the scope did not have.
    core.on_mounts_refreshed(
      scope,
      incarnate_refresh(Vec::new(), true, Some(42), Some(unique(1))),
      at(0),
    );
    let effects = drain(&mut core);
    assert!(obliged(&effects).is_empty(), "staging: empty baseline");
    let born = frame_epoch(&core, scope);

    // One exempt boundary. Only a whole-root generation can take it out.
    core.on_walk_boundaries(
      scope,
      partial_walk(vec![subvolume_decline("/r/keep", 99, 42)]),
      at(1),
    );
    let held = recorded(&core, scope);
    assert_eq!(held.len(), 1, "staging: one exempt record: {held:?}");

    // A → B → A, entirely between two refreshes. This read sees the SAME mount id
    // the last one did — the id was freed and handed straight back — and the only
    // thing that differs is the incarnation token.
    core.on_mounts_refreshed(
      scope,
      incarnate_refresh(Vec::new(), true, Some(42), Some(unique(2))),
      at(2),
    );
    let effects = drain(&mut core);
    let recycled = frame_epoch(&core, scope);
    assert_eq!(
      root_frame(&core, scope),
      Some(42),
      "staging: the id really did come back — this is the whole premise"
    );
    assert_eq!(
      recycled,
      born + 1,
      "the unobserved recycle moves the frame: an id comparison sees a value and \
       this sees a transition: {effects:?}"
    );
    assert_eq!(
      frame_publications(&effects),
      vec![recycled],
      "and the move is published, or the source keeps stamping the dead world: \
       {effects:?}"
    );

    // The delayed generation from the FIRST A. Both of the stamps it carries are
    // the ones the core held when the walk began.
    core.on_walk_boundaries(scope, whole_root_walk_on(Some(42), born, Vec::new()), at(3));
    assert_eq!(
      recorded(&core, scope),
      held,
      "the first A's generation retires nothing: its walked id matches by \
       recycling and its epoch is a world old"
    );

    // The other direction. A refresh whose token is UNCHANGED proves the root is
    // on the same mount, and must leave the frame exactly where it is.
    core.on_mounts_refreshed(
      scope,
      incarnate_refresh(Vec::new(), true, Some(42), Some(unique(2))),
      at(4),
    );
    let effects = drain(&mut core);
    assert_eq!(
      frame_epoch(&core, scope),
      recycled,
      "a token that did not move leaves the frame where it was — a bump per \
       refresh would refuse every sound generation there is: {effects:?}"
    );
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), recycled, Vec::new()),
      at(5),
    );
    assert!(
      recorded(&core, scope).is_empty(),
      "and the CURRENT world's generation still lands"
    );
  }

  /// **R14 F1.** A refused recovery must not be able to suppress its own retry
  /// forever, and the sequence that does it is one no reading this core can take
  /// tells apart from a healthy scope.
  ///
  /// On Linux 6.8+ a transient same-object self-bind puts a mount B over the root.
  /// The reseed walk reopens the path and fences against B; B departs before the
  /// refresh; the root is back on the mount OBJECT it started on, so the legacy id
  /// AND the never-recycled unique token both read exactly as they did — no
  /// transition exists for the frame to move on, and none should. The reply is
  /// refused on the walked id, and the round trip it answered used to be LEFT
  /// STANDING at the current epoch, where `owes_whole_root` short-circuits on it
  /// before ever reading the retained rejection. Every later refresh was then
  /// silent, and the rejected generation's evidence — the only record of an exempt
  /// boundary that appeared since the last one landed, which no mountinfo row can
  /// reconstruct — was stranded with the cutoff-covered recovery behind it.
  ///
  /// The reply DISCHARGES the round trip it dominates: an answer has come and no
  /// second one will, so a record whose whole meaning is "a request is out" may not
  /// outlive it. The rejection then lands in `owes_whole_root`'s `None` arm, where
  /// the retained evidence has always been read — the ordering needed no change,
  /// the field did — and the refresh this refusal armed re-asks on the frame it
  /// just published, unmoved, which is the whole point.
  ///
  /// The second half is what "dominates" is doing there: a request minted AFTER the
  /// reply was produced sits above its cutoff and is still genuinely outstanding,
  /// so the discharge must leave it alone.
  ///
  /// MUTATION WITNESS (keep the answered round trip): leave `state.pending_recovery`
  /// standing on `on_root_recovered`'s mismatch arm and this FAILS at `the departed
  /// self-bind's retry goes out` with `left: 0, right: 1` — the retry silent
  /// forever, on a reading of the world that stopped being true before the refresh
  /// that read it.
  /// MUTATION WITNESS (discharge a round trip the reply does not answer): retire
  /// `pending_recovery` unconditionally instead of on the cutoff test and this
  /// FAILS at `a NEWER request is left standing` with `left: 1, right: 0` — a
  /// duplicate whole-root walk asked for while the live one is still in flight.
  #[test]
  fn a_recovery_that_fenced_against_a_departed_mount_is_re_asked_on_the_unmoved_frame() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    let refresh = |token: u64| incarnate_refresh(Vec::new(), true, Some(42), Some(unique(token)));
    core.on_mounts_refreshed(scope, refresh(1), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    // Something owes a generation: a report stamped with the zero a freshly adopted
    // source's mailbox starts at, refused on the epoch. Its declines are gone and
    // no mount table can put them back.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), 0, vec![subvolume_decline("/r/vol", 99, 42)]),
      at(1),
    );
    drain(&mut core);
    core.on_mounts_refreshed(scope, refresh(1), at(2));
    let effects = drain(&mut core);
    let asked = recoveries(&effects);
    assert_eq!(
      asked.len(),
      1,
      "staging: the owed recovery goes out: {effects:?}"
    );

    // The reseed reopened the root while a same-object self-bind stood over it, so
    // it fenced against a mount this core has never seen. Nothing is applied.
    core.on_root_recovered(
      scope,
      crate::os::RootRecovery {
        declined: Vec::new(),
        cutoff: asked[0].ticket,
        epoch: asked[0].epoch,
        root_mnt_id: Some(77),
      },
      at(3),
    );
    let refused = drain(&mut core);
    assert!(
      recoveries(&refused).is_empty(),
      "staging: nothing is re-asked on the spot — the core may be the stale party, \
       and a re-request with no table read between them is the spin: {refused:?}"
    );
    assert_eq!(
      refresh_requests(&refused),
      1,
      "staging: the refusal buys ONE table read, so whatever it asks for next is \
       stamped with a frame just published: {refused:?}"
    );

    // The self-bind is gone before that read lands. The root is back on the mount
    // OBJECT it started on: same legacy id, same never-recycled token.
    core.on_mounts_refreshed(scope, refresh(1), at(4));
    let effects = drain(&mut core);
    assert_eq!(
      frame_epoch(&core, scope),
      asked[0].epoch,
      "staging: the world really did not move, and the token proves it did not — \
       which is the whole difficulty of this sequence: {effects:?}"
    );
    let again = recoveries(&effects);
    assert_eq!(
      again.len(),
      1,
      "the departed self-bind's retry goes out: the reply that came and went \
       discharged the round trip it answered, so the retained rejection is READ \
       rather than short-circuited by a record of a request nothing is waiting \
       on: {effects:?}"
    );
    assert_eq!(
      again[0].epoch,
      frame_epoch(&core, scope),
      "and it is stamped with the world this refresh published"
    );

    // It converges: the fresh walk reopens the same root, reads the id this core
    // holds, and its generation lands.
    let effects = answer_one_recovery(
      &mut core,
      scope,
      &effects,
      vec![subvolume_decline("/r/vol", 99, 42)],
      at(5),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(42), None)],
      "the exempt boundary the refused generation was carrying finally lands: \
       {effects:?}"
    );
    core.on_mounts_refreshed(scope, refresh(1), at(6));
    let settled = drain(&mut core);
    assert!(
      recoveries(&settled).is_empty(),
      "and the debt is discharged ONCE: {settled:?}"
    );

    // The other half of the discharge. Owe a generation again, let the world move
    // while its request is out, and deliver the OLD world's reply BEHIND the
    // request that move already sent.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), 0, vec![subvolume_decline("/r/vol", 99, 42)]),
      at(7),
    );
    drain(&mut core);
    core.on_mounts_refreshed(scope, refresh(1), at(8));
    let effects = drain(&mut core);
    let stale = recoveries(&effects);
    assert_eq!(stale.len(), 1, "staging: one request out in the old world");
    core.on_mounts_refreshed(scope, refresh(2), at(9));
    let effects = drain(&mut core);
    assert_eq!(
      recoveries(&effects).len(),
      1,
      "staging: the world moved, so the round trip it took with it is owed again: \
       {effects:?}"
    );

    core.on_root_recovered(
      scope,
      crate::os::RootRecovery {
        declined: Vec::new(),
        cutoff: stale[0].ticket,
        epoch: stale[0].epoch,
        root_mnt_id: Some(42),
      },
      at(10),
    );
    drain(&mut core);
    core.on_mounts_refreshed(scope, refresh(2), at(11));
    let quiet = drain(&mut core);
    assert!(
      recoveries(&quiet).is_empty(),
      "a NEWER request is left standing: this reply's cutoff is a world old and \
       answers nothing this scope is waiting on, so discharging on it would buy a \
       second whole-root walk while the live one is still in flight: {quiet:?}"
    );
  }

  /// **R14 F1, the other direction.** Spending the retry must not become a loop
  /// that spends itself. The refusal arms a table read, the read re-derives the
  /// need and re-asks, and the re-ask is refused — one whole-root reseed per turn
  /// with nothing but the driver's own scheduling between them, which is the spin
  /// the standing round trip was buying off with a prediction.
  ///
  /// It is bounded by EVIDENCE instead, at the one edge that closes the loop. The
  /// FIRST refusal buys one read, because the core may be the stale party and the
  /// retry must be stamped with a frame just published. The refusal of the request
  /// spent on that read — same frame, same foreign root, so the second walk was
  /// raised in full knowledge of the first — is the observation the prediction
  /// wanted, and it arms nothing of its own. What is left is one recovery per
  /// REFRESH, which is precisely what a `fails_closed` scope already pays on every
  /// authoritative refresh, and never one per scheduler round.
  ///
  /// MUTATION WITNESS (arm on every refusal): drop the `reasked` guard on
  /// `on_root_recovered`'s `arm_refresh` and this FAILS at `a disagreement already
  /// re-asked under arms no read of its own` with `left: 1, right: 0` — the refusal
  /// re-arming the read that produces the next refusal, with no cadence anywhere in
  /// the cycle.
  /// MUTATION WITNESS (suppress on the repeat instead of bounding the arming):
  /// keep the answered round trip standing whenever `reasked` holds — the shape
  /// that turns the repeat into a confirmed suppression — and this FAILS at `and
  /// the retry is not silenced` with `left: 0, right: 1`. The refusal is the one
  /// thing that stops being derivable once the record no longer means
  /// "outstanding", so the same silence R14 F1 is about comes straight back, merely
  /// one observation later.
  #[test]
  fn a_repeated_refusal_arms_no_read_of_its_own() {
    let (mut core, scope) = spawned_fanotify(Some(42), Vec::new());
    let refresh = |token: u64| incarnate_refresh(Vec::new(), true, Some(42), Some(unique(token)));
    core.on_mounts_refreshed(scope, refresh(1), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), 0, vec![subvolume_decline("/r/vol", 99, 42)]),
      at(1),
    );
    drain(&mut core);
    core.on_mounts_refreshed(scope, refresh(1), at(2));
    let effects = drain(&mut core);
    let first = recoveries(&effects);
    assert_eq!(
      first.len(),
      1,
      "staging: the owed recovery goes out: {effects:?}"
    );

    let refuse = |core: &mut DriverCore, request: crate::os::RecoveryRequest, now| {
      core.on_root_recovered(
        scope,
        crate::os::RootRecovery {
          declined: Vec::new(),
          cutoff: request.ticket,
          epoch: request.epoch,
          root_mnt_id: Some(77),
        },
        now,
      );
      drain(core)
    };

    let refused = refuse(&mut core, first[0], at(3));
    assert_eq!(
      refresh_requests(&refused),
      1,
      "staging: the FIRST refusal buys a read — the core may be the stale party, \
       and only a read of the live table can say: {refused:?}"
    );

    // The read lands and nothing moved. The retry is spent here.
    core.on_mounts_refreshed(scope, refresh(1), at(4));
    let effects = drain(&mut core);
    let second = recoveries(&effects);
    assert_eq!(
      second.len(),
      1,
      "staging: the retry goes out on the frame that read just published: \
       {effects:?}"
    );

    // Refused identically: same frame, same foreign root. This walk was raised
    // knowing about the first refusal, so its refusal is evidence rather than a
    // repeat of the same guess.
    let refused = refuse(&mut core, second[0], at(5));
    assert_eq!(
      refresh_requests(&refused),
      0,
      "a disagreement already re-asked under arms no read of its own: the refusal \
       arming the read that re-derives the need is the one cycle with no cadence \
       in it, and two walks disagreeing the same way is the observation that a \
       third read changes nothing: {refused:?}"
    );
    assert!(
      recoveries(&refused).is_empty(),
      "and nothing is asked for on the spot either: {refused:?}"
    );

    // Bounded, not silenced. The refresh cadence still re-derives the need, at the
    // rate a fail-closed scope already recovers at.
    core.on_mounts_refreshed(scope, refresh(1), at(6));
    let effects = drain(&mut core);
    assert_eq!(
      recoveries(&effects).len(),
      1,
      "and the retry is not silenced: the generation is still owed and no reply is \
       outstanding, so every refresh that comes re-asks — one per refresh is the \
       cost a fails-closed scope pays already: {effects:?}"
    );
  }

  /// **The third edge on the same cycle.** R14 closed the retry loop with retained
  /// evidence about the DISAGREEMENT — same frame, same foreign root — and that
  /// evidence covers exactly one of the two ways a reply is refused. An EPOCH
  /// mismatch carries no such key (the epoch is what moved, so no two refusals can
  /// ever share one), and the arming itself is what moves it: the refusal arms a
  /// read, the read finds the frame moved and bumps the epoch, the bump refuses the
  /// reply already in flight, and that refusal arms the next read. Nothing in that
  /// cycle is a cadence, and a pre-6.8 host reads any mount anywhere as a frame move
  /// ([`RootIncarnation::Namespace`](crate::os::RootIncarnation)), so a busy
  /// namespace turns it over at whole-root-walk speed for as long as the churn lasts
  /// — the reader walking instead of reading, with `FAN_Q_OVERFLOW` behind it.
  ///
  /// The arm is a VERDICT — *a read is owed* — and it must name the observation that
  /// proves it. "A reply was refused" is a fact about the read that already
  /// happened; what says a read is still owed is
  /// [`owes_whole_root`](ScopeState::owes_whole_root), whose FIRST arm is exactly
  /// this case: while a round trip stands in the world this scope still holds, "the
  /// reply that is coming carries the generation, the cutoff and the cover
  /// together", so a read that can only invalidate it buys nothing at all.
  ///
  /// MUTATION WITNESS (arm on every refusal, R14's shape): drop the
  /// `owes_whole_root()` conjunct from `on_root_recovered`'s `arm_refresh` and this
  /// FAILS at `a refusal a live round trip already answers arms no read` with
  /// `left: 1, right: 0` — the refusal arming the read whose epoch bump refuses the
  /// next reply.
  /// MUTATION WITNESS (never arm): remove the `arm_refresh` from the mismatch arm
  /// altogether and this FAILS at `a refusal with nothing outstanding still buys its
  /// read` with `left: 0, right: 1` — the R13 hole back, an owed generation nobody
  /// ever asks for once the tick is off.
  #[test]
  fn a_refusal_a_live_round_trip_answers_arms_no_read() {
    // No tick at all: every read in this cell is one some site explicitly armed,
    // so a convergence here is the mechanism rather than the clock.
    let (mut core, scope) = spawned_fanotify_polling(Duration::ZERO, Some(42), Vec::new());
    let refresh = |token: u64| incarnate_refresh(Vec::new(), true, Some(42), Some(unique(token)));
    core.on_mounts_refreshed(scope, refresh(1), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    // Something owes a generation, and only retained evidence says so: the
    // rejected report's declines went out with it.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), 0, vec![subvolume_decline("/r/vol", 99, 42)]),
      at(1),
    );
    drain(&mut core);
    core.on_mounts_refreshed(scope, refresh(1), at(2));
    let effects = drain(&mut core);
    let first = recoveries(&effects);
    assert_eq!(
      first.len(),
      1,
      "staging: the owed recovery goes out: {effects:?}"
    );

    // The frame moves while that request is out — one unrelated mount on a
    // pre-6.8 host is enough — so the world it was asked in is gone and a FRESH
    // request goes out stamped with the world just published.
    core.on_mounts_refreshed(scope, refresh(2), at(3));
    let effects = drain(&mut core);
    let live = recoveries(&effects);
    assert_eq!(
      live.len(),
      1,
      "staging: the moved frame owes the round trip again: {effects:?}"
    );
    assert_eq!(
      live[0].epoch,
      frame_epoch(&core, scope),
      "staging: and the live request is stamped with the current world"
    );

    // Now the FIRST request's reply lands. Its walk read the very root this core
    // still holds — the disagreement is the epoch alone, which is the leg no
    // retained evidence can key.
    core.on_root_recovered(
      scope,
      crate::os::RootRecovery {
        declined: Vec::new(),
        cutoff: first[0].ticket,
        epoch: first[0].epoch,
        root_mnt_id: Some(42),
      },
      at(4),
    );
    let refused = drain(&mut core);
    assert_eq!(
      refresh_requests(&refused),
      0,
      "a refusal a live round trip already answers arms no read: the reply that is \
       coming for the standing request carries the generation, the cutoff and the \
       cover together, so the only thing this read could do is move the frame out \
       from under it and refuse it too — which is the cycle, not a step out of it: \
       {refused:?}"
    );
    assert!(
      recoveries(&refused).is_empty(),
      "and nothing is asked for on the spot either: {refused:?}"
    );
    assert_eq!(
      recoveries(&drain(&mut core)).len(),
      0,
      "the standing request is not re-issued: it is still genuinely outstanding"
    );

    // The standing request is then refused too — a foreign root this time — and
    // its own cutoff discharges it. NOW nothing is outstanding, the retained
    // rejection still stands, and the read is owed for real.
    core.on_root_recovered(
      scope,
      crate::os::RootRecovery {
        declined: Vec::new(),
        cutoff: live[0].ticket,
        epoch: live[0].epoch,
        root_mnt_id: Some(77),
      },
      at(5),
    );
    let spent = drain(&mut core);
    assert_eq!(
      refresh_requests(&spent),
      1,
      "a refusal with nothing outstanding still buys its read: the round trip is \
       over, the rejection is retained, and with no tick armed this is the only \
       thing that will ever re-derive the need: {spent:?}"
    );

    // And it converges: the read publishes a frame, the retry goes out on it, and
    // the generation the first rejection was carrying finally lands.
    core.on_mounts_refreshed(scope, refresh(2), at(6));
    let effects = drain(&mut core);
    assert_eq!(
      recoveries(&effects).len(),
      1,
      "the retry goes out on the frame that read published: {effects:?}"
    );
    let effects = answer_one_recovery(
      &mut core,
      scope,
      &effects,
      vec![subvolume_decline("/r/vol", 99, 42)],
      at(7),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(42), None)],
      "and the exempt boundary lands: {effects:?}"
    );
  }

  /// **R15 F1.** A rejected AUTONOMOUS generation arms no read while a round trip
  /// stands in the world this scope still holds.
  ///
  /// The interleaving is ordinary and the arm used to be unconditional. A reader
  /// samples epoch N, takes a current-epoch recovery request while its own
  /// post-loss reseed is still running, and its unrequested report arrives stamped
  /// N — so `pending_recovery` already covers the very generation this report was
  /// carrying, at N+1, with the cutoff and the root cover riding the same reply.
  /// What the report proves is that a generation was LOST, which the rejection
  /// retains; what says a READ is owed is
  /// [`owes_whole_root`](ScopeState::owes_whole_root), and it says nothing is.
  ///
  /// The read is not free. On a host whose incarnation token is the mount-namespace
  /// counter (5.17–6.7, where fanotify runs but `statmount` does not exist), any
  /// mount anywhere reads as a frame move, so the read this armed moves the epoch
  /// out from under the open recovery, refuses it, and buys a whole-root walk to
  /// replace one already running — with the reader walking instead of reading and
  /// `FAN_Q_OVERFLOW` behind it.
  ///
  /// Both directions in one run: the first rejection has nothing outstanding and
  /// MUST buy its read; the second has the round trip that read bought and must
  /// not.
  ///
  /// MUTATION WITNESS (arm unconditionally, the shape before this): drop the
  /// `state.owes_whole_root()` guard from `on_walk_boundaries`' mismatch arm,
  /// leaving a bare `arm_refresh`, and this FAILS at `a rejection a live round trip
  /// already answers arms no read` with `left: 1, right: 0`.
  /// MUTATION WITNESS (never arm): delete that guarded `arm_refresh` outright and
  /// it FAILS at `staging: with nothing outstanding the rejection buys its read`
  /// with `left: 0, right: 1` — the R13 hole, an owed generation nobody ever asks
  /// for once the tick is off.
  #[test]
  fn a_rejected_autonomous_report_arms_no_read_behind_a_live_round_trip() {
    // No tick at all: every read here is one some site explicitly armed.
    let (mut core, scope) = spawned_fanotify_polling(Duration::ZERO, Some(42), Vec::new());
    let refresh = |token: u64| incarnate_refresh(Vec::new(), true, Some(42), Some(unique(token)));
    core.on_mounts_refreshed(scope, refresh(1), at(0));
    let effects = drain(&mut core);
    assert!(
      recoveries(&effects).is_empty(),
      "staging: nothing is owed yet: {effects:?}"
    );
    let stale = frame_epoch(&core, scope).wrapping_sub(1);

    // ONE. A report stamped in a world this scope has left, with nothing
    // outstanding. The declines went out with it, so the need is real and only the
    // retained rejection will ever say so.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), stale, vec![subvolume_decline("/r/vol", 99, 42)]),
      at(1),
    );
    let effects = drain(&mut core);
    assert_eq!(
      refresh_requests(&effects),
      1,
      "staging: with nothing outstanding the rejection buys its read — with no \
       tick armed nothing else would ever re-derive the need: {effects:?}"
    );

    // The read comes back and the owed recovery goes out on the frame it
    // published. A round trip now stands in the world this scope holds.
    core.on_mounts_refreshed(scope, refresh(1), at(2));
    let effects = drain(&mut core);
    let standing = recoveries(&effects);
    assert_eq!(
      standing.len(),
      1,
      "staging: the retained rejection is re-derived and asked for: {effects:?}"
    );
    assert_eq!(
      standing[0].epoch,
      frame_epoch(&core, scope),
      "staging: and it stands in the world this scope still holds"
    );

    // TWO. The reader's autonomous reseed — started before it took that request —
    // lands stamped in the world it sampled.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), stale, vec![subvolume_decline("/r/vol", 99, 42)]),
      at(3),
    );
    let effects = drain(&mut core);
    assert_eq!(
      refresh_requests(&effects),
      0,
      "a rejection a live round trip already answers arms no read: the reply that \
       is coming carries the generation, the cutoff and the cover together, so a \
       read can only move the frame out from under it and refuse it too: {effects:?}"
    );
    assert!(
      recoveries(&effects).is_empty(),
      "and nothing is asked for on the spot either: {effects:?}"
    );

    // Nothing was silenced by declining: the standing round trip answers, and the
    // generation the rejections were owed lands on it.
    let effects = answer_captured_recovery(
      &mut core,
      scope,
      standing[0],
      vec![subvolume_decline("/r/vol", 99, 42)],
      at(4),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(42), None)],
      "the exempt boundary lands on the reply that was already coming: {effects:?}"
    );
  }

  /// **One decision, three arms.** All three arms that schedule a whole-root
  /// recovery ask the identical question — [`is one still
  /// unserved?`](ScopeState::owes_whole_root) — so one staging refuses all three.
  ///
  /// A different one of them was found incomplete each round while each spelled its
  /// own conjunct set: `on_walk_boundaries` armed unconditionally, `on_admitted`
  /// overwrote a round trip already out, `on_root_recovered` was fixed a round
  /// earlier and its siblings were not. This drives all three against ONE standing
  /// current-world recovery: whichever of them stops consulting
  /// [`owes_whole_root`](ScopeState::owes_whole_root) fails at its own labelled
  /// assertion.
  ///
  /// MUTATION WITNESS (arm A bypasses): drop the `owes_whole_root()` guard from
  /// `on_walk_boundaries`' mismatch arm and this FAILS at `ARM A (a rejected
  /// autonomous generation)` with `left: 1, right: 0`.
  /// MUTATION WITNESS (arm B bypasses): drop the `!reasked && owes_whole_root()`
  /// guard from `on_root_recovered`'s mismatch arm and it FAILS at `ARM B (a
  /// refused recovery reply)` with `left: 1, right: 0`.
  /// MUTATION WITNESS (arm C bypasses): drop the `owes_whole_root()` guard from
  /// `on_admitted`'s superseded arm and it FAILS at `ARM C (a superseded admission
  /// reply)` with `left: 1, right: 0`.
  #[test]
  fn all_three_recovery_arms_defer_to_one_standing_round_trip() {
    // No tick: every request below is one some arm explicitly made.
    let (mut core, scope) =
      live_core_fanotify_polling(Duration::ZERO, vec![row("/r/vol", 77, 9)], Some(42));
    let refresh = |root_mnt_id: u64| MountRefresh {
      mounts: Vec::new(),
      authoritative: true,
      root: RootLiveness::Present(crate::os::RootIdentity::new(1, 1)),
      root_mnt_id: Some(root_mnt_id),
      root_incarnation: None,
    };

    // A departure parks a cover; two frame moves then leave that ticket stranded
    // in a world this scope has left, with a SUPERSEDING recovery outstanding in
    // the world it does hold.
    core.on_mounts_refreshed(scope, refresh(42), at(1));
    let parked = admissions(&drain(&mut core));
    assert_eq!(parked.len(), 1, "staging: the departure parks its cover");

    core.on_mounts_refreshed(scope, refresh(77), at(2));
    let superseded = recoveries(&drain(&mut core));
    assert_eq!(
      superseded.len(),
      1,
      "staging: the moved frame asks for the recovery the parked ticket owes"
    );

    core.on_mounts_refreshed(scope, refresh(88), at(3));
    let standing = recoveries(&drain(&mut core));
    assert_eq!(
      standing.len(),
      1,
      "staging: the frame moved again, so the first request can never be applied \
       and a fresh one replaces it"
    );
    assert_eq!(
      standing[0].epoch,
      frame_epoch(&core, scope),
      "staging: and THAT one stands in the world this scope holds — the state all \
       three arms below meet"
    );
    assert_eq!(
      parked_admits(&core, scope),
      1,
      "staging: with the located cover still parked across two worlds"
    );

    // ARM A — an autonomous whole-root generation stamped in a world this scope
    // has left.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(88), superseded[0].epoch, Vec::new()),
      at(4),
    );
    let a = drain(&mut core);
    assert_eq!(
      refresh_requests(&a) + recoveries(&a).len(),
      0,
      "ARM A (a rejected autonomous generation) schedules nothing: {a:?}"
    );

    // ARM B — the SUPERSEDED request's own reply. Its cutoff falls below the
    // standing request's ticket, so the standing one survives it and is still the
    // thing that answers.
    core.on_root_recovered(
      scope,
      crate::os::RootRecovery {
        declined: Vec::new(),
        cutoff: superseded[0].ticket,
        epoch: superseded[0].epoch,
        root_mnt_id: Some(88),
      },
      at(5),
    );
    let b = drain(&mut core);
    assert_eq!(
      refresh_requests(&b) + recoveries(&b).len(),
      0,
      "ARM B (a refused recovery reply) schedules nothing: {b:?}"
    );

    // ARM C — the located admission reply from the world the ticket was parked in.
    core.on_admitted(
      scope,
      crate::os::AdmitReport {
        ticket: parked[0].0,
        outcome: crate::os::AdmitOutcome::Admitted,
      },
      at(6),
    );
    let c = drain(&mut core);
    assert_eq!(
      refresh_requests(&c) + recoveries(&c).len(),
      0,
      "ARM C (a superseded admission reply) schedules nothing: {c:?}"
    );
    assert!(
      emits(&c).is_empty(),
      "and releases no located cover: it names a world this scope has left: {c:?}"
    );

    // And the one round trip all three deferred to carries the whole obligation.
    let released = answer_captured_recovery(&mut core, scope, standing[0], Vec::new(), at(7));
    assert!(
      emits(&released)
        .iter()
        .any(|change| change.kind().is_rescan()),
      "the standing recovery covers the root: nothing the three arms declined to \
       ask for was lost: {released:?}"
    );
    assert_eq!(
      parked_admits(&core, scope),
      0,
      "and no cover is left parked on a reply that can never come"
    );
  }

  /// **An `Unreachable` resolution ends the ROUND TRIP and nothing else.** The
  /// refusal key survives it, because a request no source ever took is not an
  /// observation about anybody's world.
  ///
  /// `pending_recovery` and [`Generation`] answer different questions, so the one
  /// site that resolves a request nothing answered writes only the first. Dropping
  /// the key there would look harmless — it is "just" a retry brake — and it
  /// reopens the loop R14 closed: the refusal arms a table read, the read re-derives
  /// the need and re-asks, the re-ask is refused, and with an unreachable in the
  /// cycle there is no landed generation anywhere to make either walk fresh
  /// information. Two walks that fenced against the same foreign root while this
  /// scope held the same frame are still two walks, whatever happened to the request
  /// in between.
  ///
  /// Both directions, because the key is an OBSERVATION and not a mute button: the
  /// SAME disagreement falls back to the refresh cadence, and a DIFFERENT foreign
  /// root arms again — the source's world demonstrably moved between the two walks.
  ///
  /// MUTATION WITNESS (the key goes with the round trip): add `state.generation =
  /// Generation::Lost { refused: None };` to `DriverCore::on_recovery_unreachable`
  /// and this FAILS at `a repeat across an unreachable arms no read of its own`
  /// with `left: 1, right: 0` — the refusal arming the read that produces the next
  /// refusal, with no cadence anywhere in the cycle.
  /// MUTATION WITNESS (key PRESENCE, not the key itself): make
  /// `ScopeState::generation_lost` compute `let reasked = disagreement.is_some() &&
  /// held.is_some();` and it FAILS at `a DIFFERENT foreign root re-opens the
  /// arming` with `left: 0, right: 1` — one refusal silencing this arm for every
  /// later disagreement, however far the source's world has moved.
  #[test]
  fn an_unreachable_resolution_keeps_the_refusal_key() {
    // No tick: every read below is one some site explicitly armed.
    let (mut core, scope) = spawned_fanotify_polling(Duration::ZERO, Some(42), Vec::new());
    let refresh = |token: u64| incarnate_refresh(Vec::new(), true, Some(42), Some(unique(token)));
    core.on_mounts_refreshed(scope, refresh(1), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    // A generation is lost, so a recovery is owed and the refresh buys it.
    core.on_walk_boundaries(
      scope,
      whole_root_walk_on(Some(42), 0, vec![subvolume_decline("/r/vol", 99, 42)]),
      at(1),
    );
    drain(&mut core);
    core.on_mounts_refreshed(scope, refresh(1), at(2));
    let effects = drain(&mut core);
    let first = recoveries(&effects);
    assert_eq!(
      first.len(),
      1,
      "staging: the owed recovery goes out: {effects:?}"
    );

    let refuse = |core: &mut DriverCore, request: crate::os::RecoveryRequest, walked, now| {
      core.on_root_recovered(
        scope,
        crate::os::RootRecovery {
          declined: Vec::new(),
          cutoff: request.ticket,
          epoch: request.epoch,
          root_mnt_id: Some(walked),
        },
        now,
      );
      drain(core)
    };

    // Refused on foreign root 77. Nothing was keyed before, so the retry is spent
    // here and the read it buys is what puts a freshly published frame under it.
    let refused = refuse(&mut core, first[0], 77, at(3));
    assert_eq!(
      refresh_requests(&refused),
      1,
      "staging: the FIRST refusal buys a read: {refused:?}"
    );

    // The retry goes out — and NO SOURCE TAKES IT. The round trip ends with no
    // walk, no generation, and no reading of anybody's world.
    core.on_mounts_refreshed(scope, refresh(1), at(4));
    let effects = drain(&mut core);
    let spent = recoveries(&effects);
    assert_eq!(
      spent.len(),
      1,
      "staging: the retry goes out on the frame that read published: {effects:?}"
    );
    core.on_recovery_unreachable(scope, at(5));
    let resolved = drain(&mut core);
    assert!(
      emits(&resolved)
        .iter()
        .any(|change| change.kind().is_rescan()),
      "staging: the cover is never stranded behind a reply that cannot come: \
       {resolved:?}"
    );

    // The need is still owed, so the next refresh asks again.
    core.on_mounts_refreshed(scope, refresh(1), at(6));
    let effects = drain(&mut core);
    let reasked = recoveries(&effects);
    assert_eq!(
      reasked.len(),
      1,
      "staging: an unreachable resolution ends the request, never the need: \
       {effects:?}"
    );

    // Refused on the SAME foreign root, the same frame. The unreachable resolved a
    // request; it observed nothing, so this is still the second walk raised in full
    // knowledge of the first.
    let repeat = refuse(&mut core, reasked[0], 77, at(7));
    assert_eq!(
      refresh_requests(&repeat),
      0,
      "a repeat across an unreachable arms no read of its own: a request no source \
       took is not an observation of anybody's world, so nothing about it makes \
       either walk fresh information: {repeat:?}"
    );
    assert!(
      recoveries(&repeat).is_empty(),
      "and nothing is asked for on the spot either: {repeat:?}"
    );

    // Bounded, not silenced — and a DIFFERENT foreign root is fresh information.
    core.on_mounts_refreshed(scope, refresh(1), at(8));
    let effects = drain(&mut core);
    let moved = recoveries(&effects);
    assert_eq!(
      moved.len(),
      1,
      "staging: the refresh cadence still re-derives the need: {effects:?}"
    );
    let elsewhere = refuse(&mut core, moved[0], 88, at(9));
    assert_eq!(
      refresh_requests(&elsewhere),
      1,
      "a DIFFERENT foreign root re-opens the arming: the source's world moved \
       between the two walks, so the second reply is fresh information rather than \
       a repeat: {elsewhere:?}"
    );
  }

  /// **A generation that LANDS discharges the refusal key with the evidence it was
  /// lost with**, so the next refusal on a foreign root this scope has seen before
  /// is fresh information and buys its own read.
  ///
  /// The key bounds ONE cycle — refusal arms a read, the read re-asks, the re-ask is
  /// refused — and that cycle needs both walks to have run with nothing landing in
  /// between. A complete generation applied to the coverage set is exactly what
  /// makes a later disagreement a new fact: the set was verified after the first
  /// refusal, so a walk that disputes the frame now is disputing a frame this scope
  /// has evidence for.
  ///
  /// Keeping the key past a landing is a SILENCE with no cadence to escape it: the
  /// arm would decline forever on a disagreement observed once, arbitrarily long
  /// ago, whatever landed since.
  ///
  /// The contrast is `a_repeated_refusal_arms_no_read_of_its_own`, which drives the
  /// same two refusals on the same foreign root with NO generation between them and
  /// pins the opposite answer.
  ///
  /// MUTATION WITNESS (the landing discharges nothing): drop
  /// `state.generation_applied();` from `on_root_recovered`'s applied path and this
  /// FAILS at `a refusal after a landed generation buys its read` with `left: 0,
  /// right: 1` — the retry brake latched shut for the life of the scope on one
  /// disagreement seen once.
  ///
  /// The other direction has no mutation: a key held beside a
  /// [`Generation::Verified`] is unrepresentable, so the landing cannot half-clear.
  #[test]
  fn an_applied_generation_drops_the_refusal_key() {
    // No tick: every read below is one some site explicitly armed.
    let (mut core, scope) = spawned_fanotify_polling(Duration::ZERO, Some(42), Vec::new());
    let refresh = |token: u64| incarnate_refresh(Vec::new(), true, Some(42), Some(unique(token)));
    core.on_mounts_refreshed(scope, refresh(1), at(0));
    assert!(
      obliged(&drain(&mut core)).is_empty(),
      "staging: empty baseline"
    );

    let lose = |core: &mut DriverCore, now| {
      core.on_walk_boundaries(
        scope,
        whole_root_walk_on(Some(42), 0, vec![subvolume_decline("/r/vol", 99, 42)]),
        now,
      );
      drain(core)
    };
    let refuse = |core: &mut DriverCore, request: crate::os::RecoveryRequest, now| {
      core.on_root_recovered(
        scope,
        crate::os::RootRecovery {
          declined: Vec::new(),
          cutoff: request.ticket,
          epoch: request.epoch,
          root_mnt_id: Some(77),
        },
        now,
      );
      drain(core)
    };

    lose(&mut core, at(1));
    core.on_mounts_refreshed(scope, refresh(1), at(2));
    let effects = drain(&mut core);
    let first = recoveries(&effects);
    assert_eq!(
      first.len(),
      1,
      "staging: the owed recovery goes out: {effects:?}"
    );
    let refused = refuse(&mut core, first[0], at(3));
    assert_eq!(
      refresh_requests(&refused),
      1,
      "staging: the first refusal on foreign root 77 buys a read and keys on it: \
       {refused:?}"
    );

    // The retry goes out and this time it LANDS: a complete generation, applied.
    core.on_mounts_refreshed(scope, refresh(1), at(4));
    let effects = drain(&mut core);
    let retry = recoveries(&effects);
    assert_eq!(retry.len(), 1, "staging: the retry goes out: {effects:?}");
    let applied = answer_captured_recovery(
      &mut core,
      scope,
      retry[0],
      vec![subvolume_decline("/r/vol", 99, 42)],
      at(5),
    );
    assert_eq!(
      recorded(&core, scope),
      vec![(PathBuf::from("/r/vol"), Some(42), None)],
      "staging: the generation landed — the exempt boundary is in the set: \
       {applied:?}"
    );

    // A later loss, and a later refusal on the very foreign root the key held.
    lose(&mut core, at(6));
    core.on_mounts_refreshed(scope, refresh(1), at(7));
    let effects = drain(&mut core);
    let third = recoveries(&effects);
    assert_eq!(
      third.len(),
      1,
      "staging: the fresh loss is owed a generation and the refresh buys it: \
       {effects:?}"
    );
    let refused = refuse(&mut core, third[0], at(8));
    assert_eq!(
      refresh_requests(&refused),
      1,
      "a refusal after a landed generation buys its read: the key bounds one \
       cycle of refusal-arms-read-re-asks, and a complete generation applied \
       between the two walks is what makes this disagreement a new fact rather \
       than the same one twice: {refused:?}"
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
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify)
      .expect("a fresh scope registers");
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify)
      .expect("a fresh scope registers");
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
    let scope = core
      .on_watch(PathBuf::from("/r"), interest, BackendKind::Rdcw)
      .expect("a fresh scope registers");
    let _ = drain(core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
    let scope = core
      .on_watch(PathBuf::from("/r"), interest, BackendKind::UsnJournal)
      .expect("a fresh scope registers");
    let _ = drain(core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
      declined: Vec::new(),
      identity: crate::os::RootIdentity::new(dev, ino),
      ancestors: Vec::new(),
      backend,
    }
  }

  fn live_kr_scope(core: &mut DriverCore) -> ScopeId {
    let scope = core
      .on_watch(PathBuf::from("/a/b"), Interest::all(), BackendKind::Rdcw)
      .expect("a fresh scope registers");
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
    let scope = core
      .on_watch(
        PathBuf::from("/a/b"),
        Interest::all(),
        BackendKind::FsEvents,
      )
      .expect("a fresh scope registers");
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
    let scope = core
      .on_watch(PathBuf::from("/a/b"), Interest::all(), BackendKind::Rdcw)
      .expect("a fresh scope registers");
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
        root_incarnation: None,
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
    let scope = core
      .on_watch(PathBuf::from("/a/b"), Interest::all(), BackendKind::Inotify)
      .expect("a fresh scope registers");
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
      declined: Vec::new(),
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
    let scope = core
      .on_watch(PathBuf::from(root), Interest::all(), BackendKind::Inotify)
      .expect("a fresh scope registers");
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
    // The birth refresh reports the root ALIVE at the identity this scope was
    // spawned with — `alive_refresh` hard-codes inode 1, which reads as a root
    // replacement for any other `ino` and would tear the scope down.
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, ino)),
        ..alive_refresh(Vec::new(), true)
      },
      at(0),
    );
    let _ = drain(&mut core);
    (core, scope, root_watch, req)
  }

  /// The widen seeds its departure baseline from the widened world's own barrier
  /// read, exactly as a spawn and a replace do. The ADDED ground is enumerated
  /// by the chain arm's cold read, which declines beneath any mount it finds
  /// there, so a lazy unmount racing that read is invisible to a baseline that
  /// starts empty — and stays invisible forever after, because the first
  /// authoritative read installs the post-departure frame as the new baseline.
  #[test]
  fn a_mount_seeded_by_a_widen_and_gone_by_its_first_read_is_covered() {
    let (mut core, scope, _root_watch, _boot) = live_at("/r/sub", 1, true);
    widen(
      &mut core,
      scope,
      RootMeta {
        mounts: vec![bare("/r/vol")],
        declined: Vec::new(),
        ..meta("/r", 9)
      },
      at(1),
    );
    let _ = drain(&mut core);

    // The commit-armed refresh IS the widened world's first authoritative read,
    // and the mount its own barrier listed is already gone from it.
    core.on_mounts_refreshed(
      scope,
      MountRefresh {
        root: RootLiveness::Present(crate::os::RootIdentity::new(1, 9)),
        ..alive_refresh(Vec::new(), true)
      },
      at(2),
    );
    let effects = drain(&mut core);
    let emitted = emits(&effects);
    assert_eq!(
      emitted.len(),
      1,
      "the widen window's departure is covered: {effects:?}"
    );
    assert!(emitted[0].kind().is_rescan());
    assert_eq!(emitted[0].location(), &loc(&["vol"]));
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

  /// W13 — the old root sits more than one segment below the new one. The splice
  /// would mint intermediate connectors whose edges no marker names, no read
  /// re-proves, and no `MoveSelf` of the already-watched old root invalidates
  /// (moving an ANCESTOR of that root emits none), so `Monitor::widen_root`
  /// serves depth one only. Screened at the chain, that is a LEGITIMATE fallback
  /// rather than the loud driver-bug channel — the widen was well-formed and the
  /// window was clean, the shape is simply one no proof covers — and the window
  /// is spent HERE, because the driver's tainted arm deliberately does not close
  /// it and a leaked entry would poison a later widen's reservation if the
  /// fallback's own spawn then failed.
  #[test]
  fn widen_of_a_deep_root_spends_the_window_and_falls_back() {
    let (mut core, scope, root_watch, _boot) = live_at("/r/a/b", 1, true);
    let reserved = open_window(&mut core, scope);
    assert_eq!(
      core.on_root_widened(scope, meta("/r", 9), reserved, at(2)),
      WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::UnprovableChain,
        benign: 0,
      }),
      "a two-segment chain falls back, it does not commit — and NOT through \
       `Refused`, the driver-bug channel whose `debug_assert!` this build would \
       have tripped"
    );
    assert!(
      core
        .scopes
        .get(&scope)
        .expect("scope lives")
        .pending_widen
        .is_none(),
      "the disposal SPENDS the window — nothing downstream closes it"
    );

    // No splice landed and no watch was armed for one: the old world is exactly
    // where it was, still delivering on its own watch.
    assert_eq!(
      core.root_path(scope).expect("scope lives").as_path(),
      Path::new("/r/a/b"),
      "no splice landed"
    );
    let effects = drain(&mut core);
    assert!(
      !effects
        .iter()
        .any(|e| matches!(e, Effect::AddWatch { parent, .. } if *parent == reserved)),
      "and nothing was armed beneath a root that was never spliced: {effects:?}"
    );
    core.on_batch(
      scope,
      BatchPayload::detached(vec![SourceEvent::Linux(inotify(
        &[root_watch],
        IN_CREATE,
        b"after.txt",
      ))]),
      at(3),
    );
    let effects = drain(&mut core);
    let change = emits(&effects)
      .first()
      .cloned()
      .cloned()
      .expect("the old coverage never blinked");
    assert_eq!(change.location(), &loc(&["after.txt"]));

    // And the fallback the caller owes lands: the general stream replace re-roots
    // to the SAME distant ancestor the splice declined, through a fresh spawn
    // barrier — so the depth cap costs the widen its zero-gap shortcut and not
    // the capability. The scope settles on the new root rather than wedging.
    core.on_root_replaced(scope, meta("/r", 9), at(4));
    let _ = drain(&mut core);
    assert_eq!(
      core.root_path(scope).expect("scope lives").as_path(),
      Path::new("/r"),
      "the stream replace carries the widen the splice refused, at any depth"
    );
    let effects = drain(&mut core);
    assert!(
      !effects
        .iter()
        .any(|e| matches!(e, Effect::TeardownStream { scope: s } if *s == scope)),
      "and the scope is live on it, not torn down: {effects:?}"
    );
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
    seal_adoptions(&mut core, scope, 0, 9);
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

  /// A live descending scope widened from `/r/sub` to `/r`, its new root armed
  /// and its confirming listing ingested: the adoption marker STANDS, staged,
  /// with its ordering fence still to come.
  fn staged_widen() -> (DriverCore, ScopeId, WatchId, WatchId) {
    let (mut core, scope, root_watch, _boot) = live_at("/r/sub", 1, true);
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
    (core, scope, root_watch, reserved)
  }

  /// The fence's whole purpose, at the seam that owns the ingest order: the
  /// adopted object's `MoveSelf` is still kernel-side when the confirming listing
  /// lands, and the cut is what puts it on the lane ahead of the verdict. Fed in
  /// that order it spends the marker, and the seal that follows is inert.
  ///
  /// Mutation witness: take the verdict at the listing (never stage) and the
  /// record below arrives after a certificate that already covered its interval.
  #[test]
  fn the_cut_puts_a_lagging_move_ahead_of_the_seal() {
    let (mut core, scope, root_watch, _reserved) = staged_widen();
    assert!(
      !core.monitor.coverage_settled(scope),
      "the staged marker holds the barrier"
    );

    // The record the listing could not see, ingested by the drain the cut's
    // reply is ordered behind.
    core.on_batch(
      scope,
      BatchPayload::detached(vec![SourceEvent::Linux(self_event(
        root_watch,
        IN_MOVE_SELF,
      ))]),
      at(3),
    );
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the spend stands its counted cover: {effects:?}"
    );
    assert!(
      !core.monitor.coverage_settled(scope),
      "and the barrier rests on that cover's rebuild, never on nothing"
    );

    // The answered cut lands afterwards, on a marker that is already resolved.
    core.mark_adoption_cut_inflight(scope, 0, 1);
    core.prove_adoption_cut(scope, 0, 1);
    core.resolve_adoption_seals(&LANE_ZERO, &NO_RESIDUE);
    assert!(
      emits(&drain(&mut core)).is_empty(),
      "the seal is inert over a spent marker"
    );
  }

  /// **The wedge.** Three ordinary API calls — widen, non-widening replace, widen
  /// — retire the transport the first seal's batch was addressed to. Its
  /// completion can no longer prove anything, and the second marker must still be
  /// offered a cut of its own.
  ///
  /// Both of the latch's escapes run here at once, deliberately: the replace bumps
  /// the lane the latch is stamped with, AND its rebind releases the marker whose
  /// staging the latch existed for.
  ///
  /// Mutation witness: drop the lane stamp and the clear-on-empty sweep, and the
  /// orphaned request answers for the second staging forever — `coverage_settled`
  /// false for the rest of the scope's life.
  #[test]
  fn a_transport_swap_under_a_staged_marker_does_not_strand_the_next_one() {
    let (mut core, scope, _root_watch, _reserved) = staged_widen();
    let lane_zero = |_: ScopeId| 0;
    let lane_one = |_: ScopeId| 1;
    assert_eq!(
      core.adoptions_awaiting_cut(&lane_zero),
      vec![scope],
      "the staged marker owes a cut"
    );
    core.mark_adoption_cut_inflight(scope, 0, 1);
    assert!(
      core.adoptions_awaiting_cut(&lane_zero).is_empty(),
      "one round trip at a time — a successor would only orphan this one"
    );

    // The non-widening replace: the lane moves and the rebind releases the marker
    // the batch's token was bought for. The scope LIVES.
    let _ = core.on_root_replaced(scope, meta("/elsewhere/sub", 5), at(3));
    assert!(
      core.scopes.contains_key(&scope),
      "the scope survives its own transport swap"
    );
    // The orphaned batch answers under the retired generation.
    core.prove_adoption_cut(scope, 0, 1);
    core.resolve_adoption_seals(&lane_one, &NO_RESIDUE);

    let _ = drain(&mut core);

    // The third call: widen again, on the lane the replace minted.
    let second = widen(&mut core, scope, meta("/elsewhere", 6), at(4));
    core.on_watch_installed(
      second,
      core.arm_attempt(second),
      crate::os::linux::WatchOutcome::Installed(4),
    );
    let effects = drain(&mut core);
    let req = effects
      .iter()
      .find_map(|e| match e {
        Effect::Enumerate { req, .. } => Some(*req),
        _ => None,
      })
      .expect("the second widened root cold-reads");
    core.on_enumerated(
      req,
      RawEnumerate::Listed {
        entries: vec![RawDirEntry {
          name: b"sub".to_vec(),
          kind: FileKind::Dir,
          dev: 1,
          ino: 5,
          mnt_id: None,
        }],
        complete: true,
      },
    );
    let _ = drain(&mut core);

    assert_eq!(
      core.adoptions_awaiting_cut(&lane_one),
      vec![scope],
      "THE WEDGE: the second staging must be offered a cut of its own"
    );
    core.mark_adoption_cut_inflight(scope, 1, 2);
    core.prove_adoption_cut(scope, 1, 2);
    core.resolve_adoption_seals(&lane_one, &NO_RESIDUE);
    assert_eq!(
      core.monitor.adoption_staging_high_water(scope),
      None,
      "and it seals rather than wedging"
    );
    // The choke point runs every pass, and the next one sweeps a latch whose
    // obligation is gone — which is what keeps it from outliving one.
    core.resolve_adoption_seals(&lane_one, &NO_RESIDUE);
    assert!(
      core.adoption_seals.is_empty(),
      "leaving no latch behind for the next widen to trip over"
    );
  }

  /// The latch's SECOND escape, held apart from the first on purpose. A request
  /// or a proof taken on a lane the scope has stopped reading orders nothing
  /// about the one it does — so it answers for nothing, licenses nothing, and the
  /// scope is offered a successor on the live lane.
  ///
  /// It is exercised alone here because in the tree as it stands the two escapes
  /// always fire together: every lane bump comes with a rebind or a teardown, and
  /// both release every marker of the scope. That makes this leg defence in depth
  /// rather than a live path — which is exactly why it needs a cell of its own,
  /// since the release leg would otherwise mask its absence.
  ///
  /// Mutation witness: drop the lane comparison from `answers_for` and
  /// `licenses_through`, and a stale request answers for the live lane while a
  /// proof taken on a retired queue licenses a confirm over it.
  #[test]
  fn a_seal_latch_speaks_only_for_the_lane_it_was_taken_on() {
    let (mut core, scope, _root_watch, _reserved) = staged_widen();
    let live = |_: ScopeId| 1;
    core.mark_adoption_cut_inflight(scope, 0, 1);
    assert!(
      core.adoptions_awaiting_cut(&LANE_ZERO).is_empty(),
      "one round trip at a time on the lane the request was taken on"
    );
    assert_eq!(
      core.adoptions_awaiting_cut(&live),
      vec![scope],
      "and none at all on a lane it never cut"
    );

    core.prove_adoption_cut(scope, 0, 1);
    core.resolve_adoption_seals(&live, &NO_RESIDUE);
    assert!(
      !core.monitor.coverage_settled(scope),
      "a proof of a retired queue licenses no confirm on the live one"
    );
    assert_eq!(
      core.adoptions_awaiting_cut(&live),
      vec![scope],
      "so the scope is still owed a cut it can actually use"
    );

    // On the lane it WAS taken on, the same proof is exactly what it says.
    core.resolve_adoption_seals(&LANE_ZERO, &NO_RESIDUE);
    assert!(core.monitor.coverage_settled(scope), "and it seals there");
  }

  /// Only the request actually out closes this latch, and only by its own token
  /// — which is what makes every stale completion inert. A predecessor batch's
  /// cut was taken before the live request existed, so licensing a staging with
  /// it would spend an ordering the cut never bought.
  ///
  /// The demand side is the same rule from the other end: a successor asked for
  /// while a request is travelling would only orphan it, so it is refused and the
  /// latch keeps the token it already holds.
  ///
  /// Mutation witness: close whatever is in flight regardless of token, and the
  /// foreign completion below seals a staging no answered cut of this scope's
  /// ever reached.
  #[test]
  fn only_the_seal_request_actually_out_closes_the_latch() {
    let (mut core, scope, _root_watch, _reserved) = staged_widen();
    core.mark_adoption_cut_inflight(scope, 0, 1);
    // Refused: the latch already answers for everything staged.
    core.mark_adoption_cut_inflight(scope, 0, 2);

    core.prove_adoption_cut(scope, 0, 2);
    core.resolve_adoption_seals(&LANE_ZERO, &NO_RESIDUE);
    assert!(
      !core.monitor.coverage_settled(scope),
      "a completion carrying a token this latch never issued closes nothing"
    );

    core.prove_adoption_cut(scope, 0, 1);
    core.resolve_adoption_seals(&LANE_ZERO, &NO_RESIDUE);
    assert!(
      core.monitor.coverage_settled(scope),
      "and the request that was actually out does"
    );
  }

  /// The seal releases the barrier INSIDE the driver's choke point, which is the
  /// one release that does not ride an ingest of its own. Whatever the pass does
  /// with the barrier afterwards must therefore see it — so a fence waiting on
  /// that release is owed its cut at the very instant the seal takes it.
  ///
  /// Mutation witness: release at the listing rather than staging, and the fence
  /// below is offered its cut before the sync that opens it can exist. The
  /// ORDERING this property constrains — that the driver resolves the seals above
  /// its cover-fence demand — is a property of the loop, and is pinned end to end
  /// by `a_sync_opened_under_a_staged_adoption_still_answers`; this cell pins the
  /// core-side fact that loop depends on.
  #[test]
  fn a_fence_opened_under_a_staged_marker_is_owed_its_cut_when_the_seal_lands() {
    let (mut core, scope, _root_watch, _reserved) = staged_widen();
    core.mark_adoption_cut_inflight(scope, 0, 1);

    // The sync arrives while the seal's cut is out: its fence opens over a
    // barrier the marker still holds down, so it is offered nothing yet.
    let fence = core.open_cover_fence(scope);
    assert!(
      core.covers_awaiting_cut().is_empty(),
      "a fence under a standing marker owes nothing — the barrier is not settled"
    );

    core.prove_adoption_cut(scope, 0, 1);
    core.resolve_adoption_seals(&LANE_ZERO, &NO_RESIDUE);
    assert_eq!(
      core.covers_awaiting_cut(),
      vec![scope],
      "the release and the demand are one instant, or the loop parks between them"
    );
    core.mark_cut_inflight(scope, 2);
    core.prove_cut(scope, 2);
    assert_eq!(
      core.poll_cover_settlements(DRAINED),
      vec![(fence, CoverSettle::Applied)],
      "and the fence answers its caller"
    );
  }

  /// A cut whose batch can never prove it — the reader died under the current
  /// generation — fails CLOSED. The teardown that answers everything the scope is
  /// owed releases the marker with the tree, and the latch goes with it.
  ///
  /// Mutation witness: keep the latch past its obligation and a torn-down scope
  /// still holds a request nothing can close.
  #[test]
  fn an_unanswerable_seal_cut_folds_into_the_scopes_teardown() {
    let (mut core, scope, _root_watch, _reserved) = staged_widen();
    core.mark_adoption_cut_inflight(scope, 0, 1);

    core.on_source_fatal(scope, at(3));
    let _ = drain(&mut core);
    assert!(
      core.monitor.coverage_settled(scope),
      "the teardown releases the marker with the tree"
    );
    core.resolve_adoption_seals(&LANE_ZERO, &NO_RESIDUE);
    assert!(
      core.adoption_seals.is_empty(),
      "and the latch is dropped with the obligation it stood for"
    );
    assert!(
      core.adoptions_awaiting_cut(&|_: ScopeId| 0).is_empty(),
      "nothing hangs"
    );
  }

  /// A loss ingested while the marker is staged is the reader's own conservative
  /// exit from an unprovable cut, and it precedes the reply by construction. The
  /// seal must not jump it: the loss's epoch-bumped `Rescan` and counted re-arm
  /// stand first, and the barrier releases onto that rebuild.
  ///
  /// The withholding below is the other half of the same rule, and the one a
  /// mutation can reach: a lane the drain did not finish may still hold exactly
  /// the record the round trip was bought to surface, so no verdict may be taken
  /// over it.
  ///
  /// Mutation witness: drop the unspent filter from `resolve_adoption_seals` and
  /// the seal resolves over a lane nobody finished reading.
  #[test]
  fn a_loss_under_a_staged_marker_stands_before_the_seal() {
    let (mut core, scope, _root_watch, _reserved) = staged_widen();
    core.mark_adoption_cut_inflight(scope, 0, 1);

    // The unprovable cut's conservative exit: one whole-instance loss, enqueued
    // ahead of the reply that carries the token.
    core.on_root_overflow(scope, at(3));
    let effects = drain(&mut core);
    assert!(
      emits(&effects).iter().any(|c| c.kind().is_rescan()),
      "the loss stands its own covering Rescan first: {effects:?}"
    );
    assert!(
      !core.monitor.coverage_settled(scope),
      "on counted re-arm work, so nothing settles over the loss"
    );

    core.prove_adoption_cut(scope, 0, 1);
    let residue = BTreeSet::from([scope]);
    core.resolve_adoption_seals(&LANE_ZERO, &residue);
    assert!(
      core.monitor.adoption_staging_high_water(scope).is_some(),
      "a lane the drain did not finish may still hold the record the cut forwarded"
    );

    core.resolve_adoption_seals(&LANE_ZERO, &NO_RESIDUE);
    assert!(
      core.monitor.adoption_staging_high_water(scope).is_none(),
      "and the verdict is taken once that lane is spent"
    );
    assert!(
      !core.monitor.coverage_settled(scope),
      "with the seal's outcome postdating the loss either way — the rebuild is \
       still counted"
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
        root_incarnation: None,
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

  /// W12 — the OLD root's identity does not fit the Monitor's enumerate-mint
  /// space (a synthesized `ino == 0`; a ReFS file id past `u64` behaves the
  /// same). The splice would install no expected object at the adopted edge,
  /// so its dark-window tripwire would have nothing to re-prove against and
  /// `Monitor::widen_root` refuses outright. Screened at the mint, that is a
  /// LEGITIMATE fallback rather than the loud driver-bug channel — and the
  /// window is spent HERE, because the driver's tainted arm deliberately does
  /// not close it and a leaked entry would poison a later widen's reservation
  /// if the fallback's own spawn then failed.
  #[test]
  fn widen_unmintable_old_identity_spends_the_window_and_falls_back() {
    let (mut core, scope, root_watch, _boot) = live_at("/r/sub", 0, true);
    let reserved = open_window(&mut core, scope);
    assert_eq!(
      core.on_root_widened(scope, meta("/r", 9), reserved, at(2)),
      WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::UnmintableIdentity,
        benign: 0,
      }),
      "an unprovable adoption edge falls back, it does not commit"
    );
    assert!(
      core
        .scopes
        .get(&scope)
        .expect("scope lives")
        .pending_widen
        .is_none(),
      "the disposal SPENDS the window — nothing downstream closes it"
    );

    // The old world is untouched and still delivering on its own watch.
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
      at(3),
    );
    let effects = drain(&mut core);
    let change = emits(&effects)
      .first()
      .cloned()
      .cloned()
      .expect("the old coverage never blinked");
    assert_eq!(change.location(), &loc(&["after.txt"]));

    // And the fallback the caller owes lands: the general stream replace
    // re-establishes the binding from a fresh spawn barrier, needing no
    // identity of the old root to do it.
    core.on_root_replaced(scope, meta("/r", 9), at(4));
    let _ = drain(&mut core);
    assert_eq!(
      core.root_path(scope).expect("scope lives").as_path(),
      Path::new("/r"),
      "the stream replace carries the widen the splice refused"
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
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Inotify)
      .expect("a fresh scope registers");
    let _ = drain(core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Rdcw)
      .expect("a fresh scope registers");
    let _ = drain(core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
    let scope = core
      .on_watch(PathBuf::from("/r"), Interest::all(), BackendKind::Fanotify)
      .expect("a fresh scope registers");
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
      declined: Vec::new(),
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
    // `poll_timeout` reports the EARLIEST deadline, and a descending scope now
    // holds one of its own — the periodic mount refresh seeded by the birth
    // refresh at `at(0)` (#74; the commit's own refresh completes stale, so it
    // re-seeds nothing). Naming that exact instant makes the same statement the
    // bare `None` did: the burst's halves would be due at `at(1) + WINDOW`, three
    // orders of magnitude sooner, so a survivor could not hide behind the tick.
    assert_eq!(
      core.poll_timeout(),
      Some(at(0) + LIVENESS),
      "the cut took every parked half with it, so the only deadline left is the \
       scope's periodic refresh — which is exactly why no pairing timer fires"
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

    // And the wake it asks for is the one that resolves them: afterwards the
    // earliest deadline is the scope's periodic mount refresh (#74) — 30 s out,
    // versus the 100 ms pairing window — so naming it says the rename deadline
    // is gone, exactly as the bare `None` did before the tick existed.
    core.on_timeout(at(1) + WINDOW);
    let _ = drain(&mut core);
    assert_eq!(
      core.poll_timeout(),
      Some(at(0) + LIVENESS),
      "and the pairing timer stands down"
    );
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
    let scope = core
      .on_watch(
        PathBuf::from("/r"),
        Interest::all(),
        BackendKind::UsnJournal,
      )
      .expect("a fresh scope registers");
    let _ = drain(&mut core);
    core.on_stream_spawned(
      scope,
      Ok(RootMeta {
        root: PathBuf::from("/r"),
        root_dev: 1,
        root_mnt_id: None,
        mounts: Vec::new(),
        declined: Vec::new(),
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
