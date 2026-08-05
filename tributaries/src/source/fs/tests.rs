/// The fs-to-neutral fault classification (the error half of the fs binding,
/// [`watch_error_from_fs`](super::watch_error_from_fs)): each fs watch-root failure maps
/// to its honest neutral [`FaultKind`](crate::error::FaultKind), a closed watcher maps
/// to the umbrella's own `Closed`, and the whole concrete fs error survives in the
/// fault's box.
#[test]
fn watch_error_from_fs_classifies_honestly() {
  use std::path::PathBuf;

  use tributary_fs::{SourceError, WatchRootError};

  use crate::error::FaultKind;

  let cases = [
    (
      WatchRootError::NotFound {
        path: PathBuf::from("/missing"),
      },
      FaultKind::NotFound,
    ),
    (
      WatchRootError::NotADirectory {
        path: PathBuf::from("/file"),
      },
      FaultKind::NotADirectory,
    ),
    (
      WatchRootError::Overlaps {
        path: PathBuf::from("/a/b"),
        existing: PathBuf::from("/a"),
      },
      FaultKind::Conflict,
    ),
    (
      WatchRootError::Source(SourceError::Unsupported),
      FaultKind::Unsupported,
    ),
    (
      WatchRootError::Source(SourceError::InstanceLimit),
      FaultKind::Capacity,
    ),
    // A source failure outside the classified cases degrades to the conservative Other.
    (
      WatchRootError::Source(SourceError::CreateFailed),
      FaultKind::Other,
    ),
  ];
  for (err, expected) in cases {
    let mapped = super::watch_error_from_fs(err);
    let fault = mapped
      .fault()
      .expect("a classified arm failure carries its fault");
    assert_eq!(
      fault.kind(),
      expected,
      "the fs case maps to its honest neutral kind"
    );
    assert!(
      fault.downcast_ref::<WatchRootError>().is_some(),
      "the whole fs error is preserved in the box"
    );
  }

  assert!(
    super::watch_error_from_fs(WatchRootError::Closed).is_closed(),
    "a closed fs watcher maps to the umbrella's own Closed, with no fault payload"
  );
}

/// The fs-to-neutral EVENT binding ([`SourceEvent::from_fs`](super::SourceEvent::from_fs)),
/// driven from a real lower-layer [`tributary_fs::Event`] all the way to the delivery a
/// source-only subscriber receives — the propagation of a rename's SOURCE coordinate across
/// the seam.
///
/// A rename carries two root-relative coordinates and the neutral `SourceEvent` keys on the
/// destination, so the source endpoint's own location travels in the separate
/// `move_from_location` slot. Everything downstream of that slot already had cells: the
/// projection tests hand-build a `SourceEvent` that *already* carries the field, and the fs
/// crate's own event tests stop one layer below the binding. The binding itself — the single
/// `Moved::location()` → `with_move_from_location` attachment — had none, so deleting it left
/// the whole suite green while every real filesystem move-out projection silently went back to
/// being root-anchored, which a location-aware [`Filter`](crate::Filter) reads as a change at
/// the watched root and can reject outright.
///
/// The event is minted through `tributary_fs`'s own assembly (`Event::from_change_under_instance`,
/// the seam that mints exactly what `Watcher` delivers) rather than hand-built here, and the
/// projection runs through the production [`SourceRoutable`] adapter and the real
/// [`route::fan_out`], so the rebase is the shipped arithmetic and not a restatement of it.
///
/// FAIL-ON-REVERT: drop the `with_move_from_location` attachment at the end of
/// `SourceEvent::from_fs` (return `source_event` unconditionally) and the move-out projection
/// comes back root-anchored — the location assertion fails while the key assertion still
/// passes, which is precisely the silence this cell exists to break.
#[test]
fn a_real_fs_move_carries_its_source_coordinate_into_the_move_out_projection() {
  use core::num::NonZeroU64;
  use std::{ffi::OsString, path::Path};

  use tributary_fs::Event as FsEvent;
  use tributary_proto::{Change, ChangeId, ChangeKind, Epoch, Location, ScopeId, Segment};

  use crate::{
    driver::SourceRoutable,
    event::{Event, path_components},
    route::{ReservedEndpoints, fan_out},
    source::SourceEvent,
    subscription::Subscription,
  };

  fn loc(parts: &[&str]) -> Location {
    Location::from_segments(parts.iter().map(|p| Segment::new(*p)))
  }

  // A real rename INSIDE the watched root `/watch/root`: `old/name` → `new/name`. Both
  // endpoints are under the root, which is exactly when the fs layer reports a `Moved`.
  let change = Change::new(
    ChangeId::new(NonZeroU64::new(7).expect("nonzero")),
    ScopeId::new(NonZeroU64::new(1).expect("nonzero")),
    loc(&["new", "name"]),
    ChangeKind::Moved(loc(&["old", "name"])),
    Epoch::new(3),
  );
  let fs_event = FsEvent::from_change_under_instance(1, Path::new("/watch/root"), &change);
  let moved = fs_event
    .kind()
    .moved()
    .expect("the lower layer reports a paired rename");
  assert_eq!(
    moved.location(),
    &loc(&["old", "name"]),
    "the lower layer states the source endpoint's own root-relative coordinate"
  );

  // THE BINDING under test.
  let source_event = SourceEvent::from_fs(&fs_event);
  assert_eq!(
    source_event.move_from_location(),
    Some(&loc(&["old", "name"])),
    "…and the conversion carries it across the seam rather than dropping it"
  );

  // A subscriber covering ONLY the source endpoint, one level below the watched root: it
  // receives the synthesized move-out `Removed`, and its coordinate must be the SOURCE
  // endpoint's, rebased into this subscription's own key.
  let sub = Subscription::for_test(ScopeId::new(NonZeroU64::new(9).expect("nonzero")));
  let canonical = path_components(Path::new("/watch/root/old"));
  let routable = SourceRoutable::<'_, OsString, (), _>::new(&source_event, ReservedEndpoints::None);
  let delivered: Vec<Event<OsString, ()>> = fan_out(
    &routable,
    &[sub],
    |_| Some(canonical.as_slice()),
    |_, _| true,
  );

  assert_eq!(delivered.len(), 1, "the source-only subscriber is served");
  let projected = &delivered[0];
  assert!(
    projected.kind().is_removed(),
    "source-only coverage projects the move to a Removed: {projected:?}"
  );
  assert_eq!(
    projected.key(),
    path_components(Path::new("/watch/root/old/name")).as_slice(),
    "keyed on the move's source endpoint"
  );
  assert_eq!(
    projected.location(),
    &loc(&["name"]),
    "and located at that same endpoint, rebased into the subscription's coordinate — \
     never root-anchored, which would name the watched root itself"
  );
}

// The integration suite drives a real kernel watch on a tokio runtime — so it is gated
// on the runtime feature, off miri (which cannot execute the syscalls), and onto the
// platforms with a real backend (elsewhere `tributary-fs` compiles but arms fail at
// runtime), exactly like the umbrella integration suite. The key ↔ path round-trip
// (the portable part) stays with the parent module's tests.
#[cfg(all(
  feature = "tokio",
  not(miri),
  any(target_os = "macos", target_os = "linux")
))]
mod integration {
  use std::{ffi::OsString, path::PathBuf, time::Duration};

  use agnostic_lite::tokio::TokioRuntime;
  use tempfile::TempDir;
  use tributary_fs::{RootHandle, WatchRootError, WatcherOptions};

  use super::super::{FsSource, OPPORTUNISTIC_RELEASE_HANDOFFS, key_to_path};
  use crate::{
    event::path_components,
    source::{Source, SourceEvent, SyncToken},
  };

  /// Generous ceiling for one expected observation; CI runners are slow and FSEvents
  /// batches on its own latency timer.
  const DEADLINE: Duration = Duration::from_secs(20);

  /// A fresh, **canonicalized** scratch tempdir. The temp root is a symlink on macOS
  /// (`/var` → `/private/var`), and both FSEvents and the key coordinate are canonical, so
  /// the arm key and the delivered event's key must be compared against the canonical path.
  fn scratch() -> (TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
      .prefix("tributaries-source-it-")
      .tempdir()
      .expect("create temp dir");
    let canonical = dir
      .path()
      .canonicalize()
      .expect("canonicalize scratch root");
    (dir, canonical)
  }

  /// Grows `retained` on a live root, retrying the documented-retryable
  /// [`WatchError::CoverageIncomplete`]: on a descending backend the fence
  /// conservatively degrades any window a covering `Rescan` touched — including
  /// a grow that coalesced into the root's still-in-flight cold read — and the
  /// caller's contract is to re-issue; a clean settle then applies.
  async fn grow_until_applied(
    source: &mut FsSource<TokioRuntime>,
    handle: tributary_fs::RootHandle,
    retained: &[Vec<OsString>],
  ) {
    for _ in 0..40 {
      match source.grow(handle, retained).await {
        Ok(()) => return,
        Err(err) if err.is_coverage_incomplete() => {
          tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(err) => panic!("grow of a live root failed: {err}"),
      }
    }
    panic!("grow never applied within the retry budget");
  }

  /// Pulls from the source until an event satisfying `pred` arrives or `timeout` lapses,
  /// returning it (`None` on lapse — used both for a positive wait and a negative window).
  async fn wait_for(
    source: &mut FsSource<TokioRuntime>,
    timeout: Duration,
    mut pred: impl FnMut(&SourceEvent<OsString, RootHandle>) -> bool,
  ) -> Option<SourceEvent<OsString, RootHandle>> {
    tokio::time::timeout(timeout, async {
      while let Some(event) = source.next().await {
        if pred(&event) {
          return Some(event);
        }
      }
      None
    })
    .await
    .ok()
    .flatten()
  }

  /// The fs binding end to end: arm a tempdir (and confirm the reported canonical key), a
  /// change under it surfaces as a [`SourceEvent`] owned by the armed handle at the file's
  /// key, and after `disarm` a subsequent change no longer surfaces for that root.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_arms_delivers_then_disarms() {
    let (_dir, root) = scratch();
    let root_key = path_components(&root);

    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // Arm the tempdir; the source reports the fs-canonical key it committed to, which for
    // an already-canonical root is the root's own components.
    let armed = source.arm(&root_key).await.expect("arm the tempdir");
    assert_eq!(
      armed.canonical_key(),
      root_key.as_slice(),
      "arm reports the filesystem-canonical key it armed"
    );

    // A file created under the root is delivered as a SourceEvent owned by the armed
    // handle, located at the file's key.
    let file = root.join("probe.txt");
    std::fs::write(&file, b"hi").expect("write probe");
    let observed = wait_for(&mut source, DEADLINE, |event| {
      event.handle() == armed.handle() && key_to_path(event.key()) == file
    })
    .await
    .expect("the armed root delivers the file change under its handle and key");
    assert!(
      observed.kind().is_created() || observed.kind().is_modified(),
      "a fresh file surfaces as a create or modify, got {:?}",
      observed.kind()
    );

    // Disarm the root: a synchronous, non-blocking release REQUEST (it returns at once, no `.await`).
    // The transport teardown is queued — applied at the next `arm` or at `Drop` — but the handle is
    // logically dead immediately (contract clause 3), so `root_key` answers `None`.
    source.disarm(armed.handle());
    assert_eq!(
      source.root_key(armed.handle()),
      None,
      "a disarmed handle is logically dead immediately, even before its transport teardown applies"
    );
  }

  /// The synchronous release queue (design source doc §2.4): `disarm` is a fire-and-forget REQUEST
  /// that returns at once (its transport teardown queued), the freed handle is logically dead
  /// immediately (`root_key` → None, contract clause 3), and the queued release is applied by a later
  /// `arm` — so re-arming the SAME key succeeds with no
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps) surfaced (contract clause 2). The re-arm
  /// hands the queued release to the watcher via the NON-BLOCKING `request_unwatch`; whether the
  /// driver applies that reply-less teardown before the re-watch's own disjointness check (no
  /// conflict) or not (the conflict-triggered retry then AWAITS the release the watcher NAMES against
  /// the still-lingering root), no `Overlaps` reaches the caller either way.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_disarm_queues_release_drained_at_next_arm() {
    let (_dir, root) = scratch();
    let root_key = path_components(&root);

    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // Arm the tempdir → the first handle, live.
    let first = source.arm(&root_key).await.expect("arm the tempdir");
    assert_eq!(
      source.root_key(first.handle()),
      Some(root_key.clone()),
      "the armed root is live"
    );

    // Disarm it: SYNCHRONOUS — returns immediately, no `.await`. The transport teardown is queued.
    source.disarm(first.handle());
    assert_eq!(
      source.root_key(first.handle()),
      None,
      "the released handle is logically dead immediately (contract clause 3)"
    );

    // Re-arm the SAME key. Its queued release (the oldest) is applied by `arm`'s opportunistic bounded
    // application BEFORE the new watch, so the real `Watcher` never surfaces `Overlaps` against the
    // just-released root (contract clause 2).
    let second = source
      .arm(&root_key)
      .await
      .expect("re-arm of the same key succeeds — the pending release applied before the watch");
    assert_ne!(
      first.handle(),
      second.handle(),
      "the re-arm mints a fresh generation-unique handle"
    );
    assert_eq!(
      second.canonical_key(),
      root_key.as_slice(),
      "the re-arm reports the same canonical key"
    );
    assert_eq!(
      source.root_key(first.handle()),
      None,
      "the OLD handle stays released after the re-arm applied its queued teardown"
    );
    assert_eq!(
      source.root_key(second.handle()),
      Some(root_key.clone()),
      "the fresh root is live"
    );

    // The re-armed root genuinely delivers: a change under it surfaces for the NEW handle (proving the
    // release was applied and the fresh watch is live).
    let file = root.join("after-rearm.txt");
    std::fs::write(&file, b"hi").expect("write probe");
    let observed = wait_for(&mut source, DEADLINE, |event| {
      event.handle() == second.handle() && key_to_path(event.key()) == file
    })
    .await
    .expect("the re-armed root delivers the change under its fresh handle");
    assert!(
      observed.kind().is_created() || observed.kind().is_modified(),
      "a fresh file surfaces as a create or modify, got {:?}",
      observed.kind()
    );
  }

  /// A DISJOINT arm AWAITS NOTHING for releases, and its opportunistic hand-off is HARD
  /// BUDGETED. Each drained release is `request_unwatch`ed (a reply-less `try_send`) and moved to the
  /// in-flight sidecar, never awaited — so a caller-bounded `Watch` (and any `close` queued behind it)
  /// is decoupled from every release's teardown latency (contract clause 2/5) — and the drain stops
  /// after [`OPPORTUNISTIC_RELEASE_HANDOFFS`] entries even when the channel still has room (the
  /// per-arm constant, not the channel's capacity, is the latency bound). Queue three disjoint
  /// releases A, B, C, then arm a disjoint D: exactly the two OLDEST (A, B — FIFO) are handed over
  /// non-blocking, C stays queued for a later drain, NONE is awaited-and-applied, and all three stay
  /// logically dead (`pending_set`), while D arms with no overlap and no awaited release work.
  ///
  /// Fail-on-old: the retired opportunistic loop AWAITED `unwatch` for the two oldest, REMOVING them
  /// from `pending_set` — so `pending_set.len()` would be 1 here, not 3. And the retired channel-room drain
  /// handed over ALL three — `pending_releases` would be empty here, not len 1.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_disjoint_arm_applies_releases_non_blocking() {
    let (_dir, parent) = scratch();
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // Arm three disjoint siblings A, B, C — all FIRST, before any disarm, so each arm's opportunistic
    // drain walks an empty queue and the backlog is not drained as it is built.
    let mut handles = Vec::new();
    for name in ["a", "b", "c"] {
      let sub = parent.join(name);
      std::fs::create_dir_all(&sub).expect("create subroot");
      let armed = source
        .arm(&path_components(&sub))
        .await
        .expect("arm subroot");
      handles.push(armed.handle());
    }
    // THEN disarm all three → queue [A, B, C], none handed to the watcher yet.
    for &handle in &handles {
      source.disarm(handle);
    }
    assert_eq!(
      source.pending_releases.len(),
      3,
      "three disjoint releases are queued, none yet handed over"
    );
    assert!(source.enqueued.is_empty(), "nothing in flight yet");

    // Arm a disjoint D: the opportunistic drain hands the two OLDEST to the watcher non-blocking —
    // moving them queue → in-flight — then stops at the per-arm budget even though the bounded(16)
    // channel still has room, and AWAITS none of them. D overlaps no live root, so it arms first try
    // with no awaited release work.
    let d = parent.join("d");
    std::fs::create_dir_all(&d).expect("create d");
    let d_key = path_components(&d);
    let armed_d = source.arm(&d_key).await.expect("arm disjoint D");
    assert_eq!(
      source.pending_releases.len(),
      1,
      "the drain stopped at the per-arm budget (2) with channel room to spare — the newest release \
       stays queued for a later drain"
    );
    assert_eq!(
      source.enqueued.len(),
      OPPORTUNISTIC_RELEASE_HANDOFFS,
      "exactly the budgeted number moved to the in-flight sidecar via `request_unwatch` — none awaited"
    );
    assert_eq!(
      source.pending_set.len(),
      3,
      "the disjoint arm awaited NO release teardown, so all three stay logically dead \
       (a retired awaited application would have removed them from `pending_set`)"
    );
    assert_eq!(
      source.root_key(armed_d.handle()),
      Some(d_key),
      "the disjoint D armed and is live"
    );
  }

  /// Shape regression: an arm's AWAITED release work does not scale with the backlog depth — it is
  /// ZERO for a disjoint arm. Queue **many** disjoint releases (watch+disarm N disjoint subroots), then
  /// arm ANOTHER disjoint key: the opportunistic drain hands releases to the watcher non-blocking
  /// (queue → in-flight, bounded by the channel's room), AWAITING none, so every one of the N stays
  /// logically dead (`pending_set` still holds all N) — split between still-queued and in-flight, but
  /// never awaited-and-removed. A `close` behind that `Watch` is decoupled from the whole cleanup.
  ///
  /// Fail-on-old: the retired opportunistic loop AWAITED two `unwatch`es, so `pending_set.len()` would
  /// be N − 2, not N.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_disjoint_arm_cost_is_independent_of_release_backlog() {
    const N: usize = 32;
    let (_dir, parent) = scratch();
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // Build a backlog of N queued releases over N disjoint sibling subroots. Arm all N FIRST, then
    // disarm all N — otherwise each arm's opportunistic drain would hand off the previous disarm and
    // the backlog would never accumulate.
    let mut handles = Vec::new();
    for i in 0..N {
      let sub = parent.join(format!("r{i}"));
      std::fs::create_dir_all(&sub).expect("create subroot");
      let armed = source
        .arm(&path_components(&sub))
        .await
        .expect("arm subroot");
      handles.push(armed.handle());
    }
    for &handle in &handles {
      source.disarm(handle);
    }
    assert_eq!(
      source.pending_releases.len(),
      N,
      "N disjoint releases are queued"
    );

    // Arm one MORE disjoint subroot: it overlaps none of the backlog, so the drain hands releases over
    // non-blocking and AWAITS none — the arm's awaited release work is ZERO, independent of backlog
    // depth.
    let other = parent.join("other");
    std::fs::create_dir_all(&other).expect("create other");
    let other_key = path_components(&other);
    let armed = source
      .arm(&other_key)
      .await
      .expect("arm the extra disjoint subroot");
    assert_eq!(
      source.pending_set.len(),
      N,
      "the disjoint arm awaited NO release teardown — every one of the N stays logically dead, whether \
       still queued or handed over in-flight (arm cost is independent of backlog depth)"
    );
    assert_eq!(
      source.pending_releases.len() + source.enqueued.len(),
      N,
      "all N releases are accounted for — split between still-queued and non-blocking in-flight, none \
       awaited-and-removed"
    );
    assert_eq!(
      source.root_key(armed.handle()),
      Some(other_key),
      "the extra disjoint subroot armed and is live"
    );
  }

  /// An ancestor arm over N released-but-lingering descendants succeeds via the
  /// conflict-triggered retry — no [`Overlaps`](tributary_fs::WatchRootError::Overlaps) reaches the
  /// caller. Watch+disarm N disjoint tempdir SUBDIRS, then watch their PARENT: the parent overlaps
  /// every still-lingering descendant, so the watcher rejects with `Overlaps` NAMING one at a time;
  /// each retry unwatches exactly the named descendant and re-attempts, until the parent arms cleanly
  /// (contract clause 2). Asserts the parent is live (no overlap surfaced — the awaited work was
  /// bounded by the conflicts actually named), the whole descendant backlog was applied, and the armed
  /// parent genuinely delivers.
  ///
  /// **N deliberately exceeds the retired `OVERLAP_RETRY_CAP` (64)**: the retry is now a
  /// STRUCTURAL progress bound (the queued + in-flight release sets strictly shrink each retry), not a
  /// fixed ceiling. Fail-on-old: with the 64-retry cap, the ~65+ named conflicts an ancestor over 67
  /// released descendants must resolve would trip the cap and surface `Overlaps` to the caller instead
  /// of arming the parent.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_ancestor_arm_over_many_released_descendants_succeeds() {
    const N: usize = 67;
    let (_dir, parent) = scratch();
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // Arm N disjoint descendants under `parent` — all FIRST — then disarm all N (the dirs stay on disk,
    // only the watches are released, so they linger as kernel watches until applied). Arming all before
    // disarming keeps each arm's opportunistic application from draining the backlog as it is built.
    let mut handles = Vec::new();
    for i in 0..N {
      let sub = parent.join(format!("d{i}"));
      std::fs::create_dir_all(&sub).expect("create descendant");
      let armed = source
        .arm(&path_components(&sub))
        .await
        .expect("arm descendant");
      handles.push(armed.handle());
    }
    for &handle in &handles {
      source.disarm(handle);
    }
    assert_eq!(
      source.pending_releases.len(),
      N,
      "N descendant releases are queued"
    );

    // Arm the PARENT (an ancestor of all N). It overlaps every still-lingering descendant; the watcher
    // names each conflict and the conflict-triggered retry unwatches exactly it and re-attempts — so
    // the parent arms with NO `Overlaps` surfaced to the caller (contract clause 2).
    let parent_key = path_components(&parent);
    let armed = source.arm(&parent_key).await.expect(
      "the ancestor arm resolves each named descendant conflict and succeeds — no Overlaps",
    );
    assert_eq!(
      source.root_key(armed.handle()),
      Some(parent_key),
      "the parent armed and is live"
    );
    assert!(
      source.pending_releases.is_empty(),
      "every queued release was applied by the conflict-triggered retry — the parent overlaps them \
       all, so each is NAMED and unwatched before the parent can arm (nothing stays merely queued)"
    );
    // Any leftover in-flight sidecar entries are releases the driver applied on its own (from the
    // non-blocking hand-off) that this arm never conflict-matched; every one is DEAD at the watcher,
    // so no descendant watch lingers — the next arm's top-of-arm prune reclaims the stale marks.
    for &handle in &handles {
      assert_eq!(
        source.root_key(handle),
        None,
        "every released descendant is logically dead — none survives as a live watch"
      );
    }

    // The armed parent genuinely delivers: a change under one of the (now folded) descendant dirs
    // surfaces for the parent's handle, proving the fresh recursive watch is live.
    let file = parent.join("d0").join("after.txt");
    std::fs::write(&file, b"hi").expect("write probe under the parent");
    let observed = wait_for(&mut source, DEADLINE, |event| {
      event.handle() == armed.handle() && key_to_path(event.key()) == file
    })
    .await
    .expect("the armed parent delivers a change under it");
    assert!(
      observed.kind().is_created() || observed.kind().is_modified(),
      "a fresh file surfaces as a create or modify, got {:?}",
      observed.kind()
    );
  }

  /// A rejection whose named conflict is NOT a pending (released) root — a genuine LIVE
  /// overlap — surfaces immediately, WITHOUT the retired index-0 fallback wrongly unwatching an
  /// unrelated pending root to mask it. Arm a LIVE child watch, disarm several disjoint roots (so the
  /// pending queue stays non-empty past the opportunistic application), then arm the child's ANCESTOR:
  /// the watcher names the LIVE child as the conflict, which EXACT-matches no pending entry, so the arm
  /// surfaces `Overlaps` and leaves the unrelated pending root untouched.
  ///
  /// Fail-on-old: the index-0 fallback would unwatch the unrelated pending root (releasing a watch the
  /// umbrella still considers pending) and retry, so it would be gone — the assertion that it survives
  /// flips.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_unmatched_overlap_surfaces_without_touching_unrelated_pending() {
    let (_dir_p, parent) = scratch();
    let child = parent.join("child");
    std::fs::create_dir_all(&child).expect("create child");
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // A LIVE child watch — the genuine overlap the ancestor arm below hits (never released, so never
    // pending).
    source
      .arm(&path_components(&child))
      .await
      .expect("arm the live child");

    // Arm three DISJOINT roots (separate tempdirs) FIRST, then disarm them all — arming-before-
    // disarming keeps each arm's opportunistic drain from handing the backlog off as it is built. At
    // the parent arm the drain hands these disjoint releases to the watcher non-blocking (queue →
    // in-flight sidecar), but every one stays dead-marked in `pending_set`. The `survivor` is a
    // disjoint release the ancestor arm never conflict-matches — exactly the entry the retired index-0
    // fallback would have WRONGLY grabbed and awaited to mask the real (live-child) conflict.
    let mut dirs = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..3 {
      let (dir, root) = scratch();
      let armed = source
        .arm(&path_components(&root))
        .await
        .expect("arm a disjoint root");
      handles.push(armed.handle());
      dirs.push(dir); // keep each tempdir on disk for the test's lifetime
    }
    for &handle in &handles {
      source.disarm(handle);
    }
    let survivor = *handles.last().expect("at least one disjoint root");

    // Arm the child's ANCESTOR: it overlaps the LIVE child (which the watcher names), and the child is
    // NOT a pending entry — so the arm surfaces `Overlaps` immediately.
    let err = source
      .arm(&path_components(&parent))
      .await
      .expect_err("the ancestor arm surfaces the live-child overlap");
    assert!(
      err.fault().is_some_and(|fault| fault.kind().is_conflict()),
      "an unmatched (live) conflict surfaces as a Conflict fault, not looped-away — got {err:?}"
    );
    assert!(
      matches!(err.as_fs(), Some(WatchRootError::Overlaps { .. })),
      "the concrete fs Overlaps survives in the box for downcast"
    );
    assert!(
      source.pending_set.contains(&survivor),
      "the unrelated release is untouched by the conflict path — no index-0 fallback awaited-and-\
       removed it to mask the real conflict"
    );
  }

  /// a conflict against an IN-FLIGHT (request-enqueued) release resolves WITHOUT surfacing
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps). The opportunistic drain hands a queued
  /// release to the watcher via the reply-less `request_unwatch` and moves it to the in-flight sidecar;
  /// if the SAME arm's watch then overlaps that release before the driver has applied the reply-less
  /// teardown, the watcher NAMES it — matching the sidecar, not the (now-empty) queue — and the arm
  /// AWAITS an acked `unwatch` of it (which, enqueued after the reply-less request on the one FIFO
  /// channel, forces the teardown to land) and retries to success.
  ///
  /// Driven on a **current-thread** runtime so the window is deterministic: between the drain's
  /// `try_send` and the re-watch's disjointness check there is NO `.await`, so the single-threaded
  /// driver cannot run and apply the reply-less teardown first — the re-watch is GUARANTEED to see the
  /// root still live and take the in-flight-conflict path. Fail-on-broken-fallback: without the sidecar
  /// match, the named conflict would match no queue entry and the arm would surface `Overlaps` — the
  /// re-arm's `expect` below would panic.
  #[tokio::test(flavor = "current_thread")]
  async fn fs_source_conflict_against_in_flight_release_resolves() {
    let (_dir, root) = scratch();
    let root_key = path_components(&root);
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // Arm the root, then disarm it → one queued release, still live at the watcher.
    let first = source.arm(&root_key).await.expect("arm the root");
    source.disarm(first.handle());
    assert_eq!(source.pending_releases.len(), 1, "one release queued");

    // Re-arm the SAME key. On current-thread, the drain's `request_unwatch` moves the release to the
    // in-flight sidecar but the driver has NOT run (no await since the `try_send`), so the re-watch's
    // disjointness check still sees the root live and the watcher NAMES it. The named conflict is in
    // the sidecar (not the queue), so the in-flight fallback awaits its `unwatch` and retries.
    let second = source.arm(&root_key).await.expect(
      "the in-flight-release conflict resolves via the sidecar fallback — no Overlaps surfaced",
    );
    assert_ne!(
      first.handle(),
      second.handle(),
      "the re-arm mints a fresh generation-unique handle"
    );
    assert_eq!(
      source.root_key(first.handle()),
      None,
      "the old handle stays released"
    );
    assert_eq!(
      source.root_key(second.handle()),
      Some(root_key),
      "the re-armed root is live"
    );
  }

  /// [`grow`](crate::Source::grow) short-circuits a kernel-recursive root (FSEvents /
  /// fanotify) to `Ok` WITHOUT the awaited command round-trip — coverage on such a backend never
  /// narrows, so there is nothing to reconcile inside the caller-bounded window — while a
  /// descending backend (inotify) genuinely round-trips through the watcher's fenced
  /// `set_cover` and maps its settled outcome to `Ok`. One cross-platform test, branched on the
  /// live root's reported backend: on macOS the backend IS kernel-recursive (the short-circuit
  /// leg), on unprivileged Linux it is inotify (the round-trip leg).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_grow_short_circuits_kernel_recursive_roots() {
    let (_dir, root) = scratch();
    let root_key = path_components(&root);
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    let armed = source.arm(&root_key).await.expect("arm the tempdir");
    let kernel_recursive = source
      .watcher
      .backend_of(armed.handle())
      .expect("the armed root reports its backend")
      .is_kernel_recursive();

    // Grow to full coverage (the cancel-equivalent shape the umbrella sends): a no-op reconcile
    // either way, but only the descending backend pays the round-trip.
    grow_until_applied(&mut source, armed.handle(), std::slice::from_ref(&root_key)).await;
    if kernel_recursive {
      assert_eq!(
        source.cover_round_trips, 0,
        "a kernel-recursive root is answered by the short-circuit (no round-trip)"
      );
    } else {
      assert!(
        source.cover_round_trips >= 1,
        "a descending root awaits the watcher's fenced set_cover (once per grow attempt)"
      );
    }
  }

  /// [`grow`](crate::Source::grow) of a root the watcher has since torn down (root death) maps
  /// the driver's `Skipped(UnknownRoot)` answer to a retryable [`FaultKind::NotFound`]
  /// fault — deliberately NOT `CoverageIncomplete` (nothing degraded; the root is GONE) — so the
  /// umbrella's retry re-plans, finds the dead root via `root_key`, and retires it. Deleting the
  /// watched directory kills the root; the registry forgetting it is what routes the grow past
  /// the kernel-recursive short-circuit (`backend_of` answers `None`) into the real round-trip.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_grow_dead_root_maps_to_not_found() {
    // An outer dir holds the watched root, so deleting the root does not delete the temp dir
    // out from under the still-open handle.
    let (_dir, outer) = scratch();
    let root = outer.join("watched");
    std::fs::create_dir_all(&root).expect("create the watched root");
    let root_key = path_components(&root);
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    let armed = source.arm(&root_key).await.expect("arm the watched root");
    std::fs::remove_dir_all(&root).expect("delete the watched root");

    // Wait (bounded) until the watcher's registry forgets the dead root — the driver tears it
    // down autonomously; `root_key` answering `None` is the source-level observation.
    let deadline = std::time::Instant::now() + DEADLINE;
    while source.root_key(armed.handle()).is_some() {
      assert!(
        std::time::Instant::now() < deadline,
        "the deleted root was never torn down"
      );
      tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let err = source
      .grow(armed.handle(), &[root_key])
      .await
      .expect_err("growing a dead root fails");
    let fault = err.fault().expect("the dead-root grow carries its fault");
    assert!(
      fault.kind().is_not_found(),
      "a concurrently-dead root classifies as NotFound (root-gone, not coverage-degraded), got {:?}",
      fault.kind()
    );
    assert!(
      !err.is_coverage_incomplete(),
      "root death is not the degraded-fence error"
    );
  }

  /// The full-channel deferral queue ([`Source::set_cover`] contract clauses 3/6). The bounded
  /// control channel cannot be forced full hermetically (the driver drains it concurrently), so
  /// the prompt path is asserted end to end and the deferral logic on the queue seam itself:
  /// a prune with channel room forwards immediately (nothing queued); a deferred entry is
  /// latest-wins per handle; an awaited [`grow`](crate::Source::grow) — and a newer `set_cover`
  /// of the same handle — SUPERSEDES the handle's queued prune (removed, never re-forwarded, so
  /// a stale snapshot can never land after the newer cover); and a deferred entry is
  /// re-forwarded at the next watcher-touching op.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_deferred_prunes_are_latest_wins_superseded_and_reforwarded() {
    let (_dir, root) = scratch();
    let keep = root.join("keep");
    let drop_dir = root.join("drop");
    std::fs::create_dir_all(&keep).expect("create keep");
    std::fs::create_dir_all(&drop_dir).expect("create drop");
    let root_key = path_components(&root);
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");
    let armed = source.arm(&root_key).await.expect("arm the tempdir");

    // Prompt path: with channel room the prune is handed over immediately — nothing defers.
    source.set_cover(armed.handle(), &[path_components(&keep)]);
    assert!(
      source.deferred_prunes.is_empty(),
      "a prune the control channel accepts is never queued"
    );

    // Latest-wins per handle on the deferral seam (the full-channel fallback path).
    source.defer_prune(armed.handle(), vec![keep.clone()]);
    source.defer_prune(armed.handle(), vec![drop_dir.clone()]);
    assert_eq!(
      source.deferred_prunes.get(&armed.handle()),
      Some(&vec![drop_dir.clone()]),
      "a re-deferred prune REPLACES the handle's stale snapshot (latest-wins, clause 6)"
    );

    // An awaited grow SUPERSEDES the handle's queued prune: removed outright, never forwarded.
    grow_until_applied(&mut source, armed.handle(), std::slice::from_ref(&root_key)).await;
    assert!(
      source.deferred_prunes.is_empty(),
      "the grow superseded the queued prune (clause 6)"
    );
    assert_eq!(
      source.deferred_forwards, 0,
      "the superseded prune was REMOVED, not re-forwarded — the grow's fresh cover is authoritative"
    );

    // A NEWER set_cover of the same handle supersedes its queued snapshot too: the stale entry
    // must never be re-forwarded around the newer cover (it would land AFTER it, stale-wins).
    source.defer_prune(armed.handle(), vec![drop_dir.clone()]);
    source.set_cover(armed.handle(), &[path_components(&keep)]);
    assert!(
      source.deferred_prunes.is_empty(),
      "the newer prune superseded the handle's queued snapshot"
    );
    assert_eq!(
      source.deferred_forwards, 0,
      "the stale same-handle snapshot was REMOVED, never re-forwarded (latest-wins, clause 6)"
    );

    // A `replace` SUPERSEDES the handle's queued prune as well. The retarget re-covers the root,
    // so a snapshot holding the OLD retained set is stale — re-forwarded after the replace
    // committed, it would narrow the re-covered root back to the old subtree, a silent coverage
    // loss with no `Rescan` to redeem it.
    let (_dir_moved, moved) = scratch();
    source.defer_prune(armed.handle(), vec![drop_dir.clone()]);
    source
      .replace(armed.handle(), &path_components(&moved))
      .await
      .expect("retarget the root");
    assert!(
      source.deferred_prunes.is_empty(),
      "the replace superseded the handle's queued prune"
    );
    assert_eq!(
      source.deferred_forwards, 0,
      "the superseded prune was REMOVED, never re-forwarded around the replace"
    );

    // A deferred prune IS re-forwarded at the next watcher-touching op on OTHER handles
    // (clause 3): an unrelated arm flushes it.
    source.defer_prune(armed.handle(), vec![keep.clone()]);
    let (_dir2, other) = scratch();
    source
      .arm(&path_components(&other))
      .await
      .expect("arm a disjoint second root");
    assert!(
      source.deferred_prunes.is_empty(),
      "the next watcher-touching op flushed the deferred prune"
    );
    assert_eq!(
      source.deferred_forwards, 1,
      "the flush re-forwarded exactly the one deferred entry"
    );
  }

  /// A REAL fs failure round-trips through the neutral surface with full fidelity:
  /// arming a non-existent path classifies as a `NotFound` fault, and the concrete
  /// [`WatchRootError`] is recoverable from the box via both the `as_fs` sugar and the
  /// underlying [`SourceFault::downcast_ref`](crate::SourceFault::downcast_ref).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_not_found_round_trips_through_downcast() {
    let (_dir, root) = scratch();
    let missing = root.join("missing");
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    let err = source
      .arm(&path_components(&missing))
      .await
      .expect_err("arming a non-existent path fails");
    assert!(err.is_source(), "the arm failure is a fault, got {err:?}");
    let fault = err.fault().expect("a Source error carries its fault");
    assert!(
      fault.kind().is_not_found(),
      "a non-existent path classifies as NotFound, got {:?}",
      fault.kind()
    );
    assert!(
      matches!(err.as_fs(), Some(WatchRootError::NotFound { .. })),
      "as_fs recovers the concrete fs error from the box"
    );
    assert!(
      matches!(
        fault.downcast_ref::<WatchRootError>(),
        Some(WatchRootError::NotFound { .. })
      ),
      "downcast_ref recovers the same concrete fs error"
    );
  }

  /// (S1-i) HOSTILE FOREIGN-FLOOD — bounds the `disarm`/`set_cover` deferral structures at their doors. A hostile
  /// direct caller floods both with FRESH, distinct FOREIGN brands (handles minted by a SECOND
  /// watcher, so `root_path` answers `None` for every one). Each dies at its door, so none of the
  /// four deferral structures grows with the flood size `N` — they stay bounded by the live-OWN-root
  /// count (here 1, and this source never disarms its own root, so the bound is 0).
  ///
  /// Fail-on-old: against the genuine pre-S1 code (the fire-and-forget `bool` everywhere, no doors)
  /// both structures grow monotonically to `N` and the `<= 1` bound assertions fail. Reverting only
  /// the `disarm` door regrows `pending_releases` on its own; the `set_cover` half needs the whole
  /// `bool` collapse (the door AND the request-site `Rejected` arm), because with the tri-state kept
  /// a foreign `set_cover` is `Rejected`, never `Busy`, so nothing defers even with the door gone.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_hostile_foreign_flood_stays_bounded() {
    const N: usize = 8;
    // This source (A) with exactly ONE live own root — the whole flood is foreign, so nothing it
    // admits can land in a deferral structure.
    let (_dir_own, own) = scratch();
    let mut source =
      FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource A");
    source
      .arm(&path_components(&own))
      .await
      .expect("arm the one own root");

    // A SECOND source (B) mints 2N distinct FOREIGN brands, split into DISJOINT sets for the disarm
    // flood and the set_cover flood: a `disarm` dead-marks its handle in `pending_set`, which would
    // early-return a later `set_cover` of the SAME handle — so sharing brands would mask the
    // set_cover door's growth under the old code and defeat the fail-on-old.
    let (_dir_b, parent_b) = scratch();
    let mut foreign =
      FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource B");
    let mut disarm_brands = Vec::new();
    let mut cover_brands = Vec::new();
    for i in 0..(2 * N) {
      let sub = parent_b.join(format!("f{i}"));
      std::fs::create_dir_all(&sub).expect("create foreign subroot");
      let handle = foreign
        .arm(&path_components(&sub))
        .await
        .expect("arm foreign subroot")
        .handle();
      if i % 2 == 0 {
        disarm_brands.push(handle);
      } else {
        cover_brands.push(handle);
      }
    }

    // The flood: every brand is a fresh, distinct FOREIGN handle — the exact unbounded-growth vector.
    let cover = path_components(&own);
    for &fh in &disarm_brands {
      source.disarm(fh);
    }
    for &fh in &cover_brands {
      source.set_cover(fh, std::slice::from_ref(&cover));
    }

    // Every foreign disarm/prune died at its door: none of the four structures grew with N.
    assert!(
      source.pending_releases.len() <= 1,
      "pending_releases stays bounded by live own roots — foreign disarms dropped at the door \
       (flood N={N}), got {}",
      source.pending_releases.len()
    );
    assert!(
      source.enqueued.len() <= 1,
      "enqueued stays bounded (nothing foreign was ever handed over), got {}",
      source.enqueued.len()
    );
    assert!(
      source.pending_set.len() <= 1,
      "pending_set stays bounded — a foreign disarm never dead-marks (flood N={N}), got {}",
      source.pending_set.len()
    );
    assert!(
      source.deferred_prunes.len() <= 1,
      "deferred_prunes stays bounded — foreign prunes dropped at the door (flood N={N}), got {}",
      source.deferred_prunes.len()
    );
  }

  /// (S1-ii) FRONT-WEDGE — prevents permanent starvation of genuine releases. A foreign brand
  /// sitting at the FRONT of `pending_releases` (injected directly: the `disarm` door would refuse it
  /// at entry, so this white-box setup exercises the drain-side belt-and-suspenders kill) must not
  /// wedge the queue. The opportunistic drain sees the foreign `request_unwatch` as `Rejected`, DROPS
  /// it, and CONTINUES — so the genuine release queued behind it is handed to the in-flight sidecar
  /// on the SAME arm.
  ///
  /// Fail-on-old: revert the drain's `Rejected`-drop to a re-front-and-break and the foreign entry
  /// re-fronts forever — the genuine release never reaches the sidecar and the drain assertion fails
  /// (no hang: a single bounded arm, then the structures are inspected).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_front_wedge_foreign_entry_does_not_starve_genuine_release() {
    let (_dir_a, root_a) = scratch();
    let mut source =
      FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource A");
    // A GENUINE own live root to release.
    let genuine = source
      .arm(&path_components(&root_a))
      .await
      .expect("arm the genuine root")
      .handle();

    // A FOREIGN brand from a second watcher.
    let (_dir_b, root_b) = scratch();
    let mut foreign_src =
      FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource B");
    let foreign = foreign_src
      .arm(&path_components(&root_b))
      .await
      .expect("arm the foreign root")
      .handle();

    // Inject the foreign entry at the FRONT, then queue the genuine release behind it via a real
    // `disarm` (its door passes — the root is live) → order [foreign, genuine].
    source
      .pending_releases
      .push_back((foreign, Some(root_b.clone())));
    source.pending_set.insert(foreign);
    source.disarm(genuine);
    assert_eq!(
      source.pending_releases.len(),
      2,
      "the foreign wedge sits ahead of the genuine release"
    );

    // Arm a DISJOINT key: the opportunistic drain (budget 2) drops the foreign (Rejected) and hands
    // over the genuine (Enqueued) on this same arm.
    let (_dir_d, d) = scratch();
    source
      .arm(&path_components(&d))
      .await
      .expect("arm the disjoint trigger");

    assert!(
      source.enqueued.iter().any(|(h, _)| *h == genuine),
      "the genuine release drained past the foreign wedge into the in-flight sidecar"
    );
    assert!(
      !source.pending_releases.iter().any(|(h, _)| *h == foreign),
      "the foreign entry was DROPPED, not re-fronted (no permanent wedge)"
    );
    assert!(
      !source.pending_set.contains(&foreign),
      "the foreign entry's dead-mark went with it"
    );
  }

  /// (S1-iii) DEAD-OWN DISARM DOOR. Disarming a handle whose OWN root has already died (the watcher
  /// tore it down, so `root_path` answers `None`) drops the disarm at the door: nothing is queued or
  /// dead-marked, and both `root_key` and `root_path` keep answering `None` for it (no panic, no
  /// leak, no wedge).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_dead_own_disarm_door_retains_nothing() {
    // An outer dir holds the watched root so deleting the root does not unlink the tempdir out from
    // under the still-open handle.
    let (_dir, outer) = scratch();
    let root = outer.join("watched");
    std::fs::create_dir_all(&root).expect("create the watched root");
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    let handle = source
      .arm(&path_components(&root))
      .await
      .expect("arm the watched root")
      .handle();
    std::fs::remove_dir_all(&root).expect("delete the watched root");

    // Wait (bounded) until the watcher forgets the dead root — `root_key` answering `None` is the
    // source-level observation that the driver tore it down.
    let deadline = std::time::Instant::now() + DEADLINE;
    while source.root_key(handle).is_some() {
      assert!(
        std::time::Instant::now() < deadline,
        "the deleted root was never torn down"
      );
      tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Disarm the now-dead handle: the door drops it entirely.
    source.disarm(handle);
    assert!(
      source.pending_releases.is_empty(),
      "a dead-own disarm queues no release"
    );
    assert!(
      !source.pending_set.contains(&handle),
      "a dead-own disarm leaves no dead-mark"
    );
    assert_eq!(
      source.root_key(handle),
      None,
      "root_key still answers None for the dead handle"
    );
    assert_eq!(
      source.watcher.root_path(handle),
      None,
      "root_path still answers None for the dead handle"
    );
  }

  /// (S1-iv) BUSY PRESERVED. A genuine release that meets a momentarily FULL control channel must be
  /// re-fronted and RETRIED — never dropped (dropping is reserved for `Rejected`/never-valid work).
  /// On a CURRENT-THREAD runtime the driver cannot run between synchronous calls, so the channel is
  /// filled deterministically: the arm's drain sees `Busy`, re-fronts the genuine release (it stays
  /// queued, nothing enqueued), and the NEXT arm — after the channel drained during the previous
  /// arm's blocking watch — hands it over. This is exactly the old full-channel backpressure,
  /// unchanged.
  #[tokio::test(flavor = "current_thread")]
  async fn fs_source_busy_release_re_fronts_and_retries() {
    let (_dir, parent) = scratch();
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // Four disjoint sibling roots: one to flood the channel (kept live, never disarmed), one genuine
    // release, and two disjoint arm triggers.
    let make = |name: &str| {
      let p = parent.join(name);
      std::fs::create_dir_all(&p).expect("create subroot");
      p
    };
    let fill = make("fill");
    let rel = make("rel");
    let trig1 = make("trig1");
    let trig2 = make("trig2");
    let fill_h = source
      .arm(&path_components(&fill))
      .await
      .expect("arm the fill root")
      .handle();
    let rel_h = source
      .arm(&path_components(&rel))
      .await
      .expect("arm the release root")
      .handle();

    // Fill the control channel to capacity via prompt `set_cover` on the live fill root. The driver
    // is not scheduled between these synchronous calls (current-thread, no await), so the moment one
    // call DEFERS (its `request_set_cover` returned `Busy`) the channel is full — robust to the exact
    // capacity.
    let fill_cover = path_components(&fill);
    let mut guard = 0;
    while source.deferred_prunes.is_empty() {
      source.set_cover(fill_h, std::slice::from_ref(&fill_cover));
      guard += 1;
      assert!(
        guard < 1000,
        "the bounded channel should fill well before this"
      );
    }

    // Queue a genuine release behind the now-full channel.
    source.disarm(rel_h);
    assert!(
      source.pending_releases.iter().any(|(h, _)| *h == rel_h),
      "the genuine release is queued"
    );

    // Arm a disjoint trigger: the drain hits the FULL channel, gets `Busy`, and RE-FRONTS the genuine
    // release (it is NOT dropped). The watch's own blocking send then drains the channel (the driver
    // runs during that await), but the drain already broke — the release stays queued.
    source
      .arm(&path_components(&trig1))
      .await
      .expect("arm the first trigger");
    assert!(
      source.pending_releases.iter().any(|(h, _)| *h == rel_h),
      "a Busy drain RE-FRONTS the genuine release — Busy is not Rejected, so it is never dropped"
    );
    assert!(
      !source.enqueued.iter().any(|(h, _)| *h == rel_h),
      "the Busy release was not handed over"
    );

    // Arm another disjoint trigger: the channel drained during the previous arm, so the drain now
    // gets `Enqueued` and hands the genuine release over — the retry succeeds (semantics unchanged).
    source
      .arm(&path_components(&trig2))
      .await
      .expect("arm the second trigger");
    assert!(
      source.enqueued.iter().any(|(h, _)| *h == rel_h),
      "the re-fronted release drains on the next opportunity — Busy backpressure retries, unchanged"
    );
    assert!(
      !source.pending_releases.iter().any(|(h, _)| *h == rel_h),
      "the genuine release left the queue once the channel had room"
    );
  }

  /// A STALE cancel — an OLDER incarnation's token — must never consume a LATER incarnation's
  /// `pending_syncs` entry. `cancel_sync` inspects the stored token before removing anything, so a
  /// token mismatch touches nothing and the live entry survives intact for its own incarnation's
  /// matching cancel; only a matching token removes the entry and fires the watcher-side cancel.
  #[tokio::test(flavor = "current_thread")]
  async fn fs_source_cancel_sync_stale_token_leaves_current_entry_intact() {
    let (_dir, root) = scratch();
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");
    let handle = source
      .arm(&path_components(&root))
      .await
      .expect("arm the root")
      .handle();

    // Arrange the CURRENT incarnation's entry directly — a real watcher-minted ticket paired with
    // tokenB — mirroring what `begin_sync` leaves behind for an abandoned in-flight sync.
    let token_a = SyncToken::new(1, 1, 1, 0xA);
    let token_b = SyncToken::new(1, 1, 2, 0xB);
    let (_, ticket_b) = source.watcher.mint_sync_ticket();
    source.pending_syncs.insert(handle, (token_b, ticket_b));

    // A STALE cancel for the OLD incarnation (tokenA != tokenB): must be a pure no-op. Against the
    // pre-fix remove-first code, the very next assertion fails immediately (fail-fast, no hang) —
    // the mismatched cancel had already removed the entry before comparing the token.
    source.cancel_sync(handle, token_a);
    assert_eq!(
      source.pending_syncs.get(&handle),
      Some(&(token_b, ticket_b)),
      "a stale/mismatched-token cancel must leave the current incarnation's entry INTACT"
    );
    assert_eq!(
      source.sync_cancels_requested, 0,
      "a stale/mismatched-token cancel must issue no watcher-side cancel"
    );

    // The MATCHING cancel (tokenB): removes the entry and fires exactly one watcher-side cancel.
    source.cancel_sync(handle, token_b);
    assert_eq!(
      source.pending_syncs.get(&handle),
      None,
      "a matching-token cancel removes the entry"
    );
    assert_eq!(
      source.sync_cancels_requested, 1,
      "a matching-token cancel issues exactly one watcher-side cancel"
    );
  }
}

/// The reserved namespace is the binding's business: it renders a cookie's
/// name from the owner's token and classifies EVERY leaf matching a shape this
/// binding has minted as an artifact — ours, another instance's, or a crashed
/// process's leftover from an earlier release — while an ordinary file (or a
/// name merely containing the prefix deeper in the path) is never one.
#[tokio::test]
async fn the_reserved_namespace_classifies_every_cookie_and_only_cookies() {
  use std::ffi::OsString;

  use agnostic_lite::tokio::TokioRuntime;
  use tributary_fs::WatcherOptions;

  use crate::{Source, SyncToken, source::FsSource};

  let source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build");
  let key =
    |parts: &[&str]| -> Vec<OsString> { parts.iter().map(|p| OsString::from(*p)).collect() };

  // Our own cookie, rendered from a token.
  let name = super::cookie_name(SyncToken::new(7, 42, 3, 0xdead_beef));
  assert_eq!(name, ".tributaries-sync-7-42-3-00000000deadbeef");
  // The trailing nonce is what an external writer cannot predict — but
  // classification keys on the SHAPE, not on the value, so a cookie is a cookie
  // whatever its nonce.
  assert!(source.is_sync_artifact(&key(&[
    "/",
    "r",
    ".tributaries-sync-7-42-3-00000000deadbeef"
  ])));
  assert!(source.is_sync_artifact(&key(&["/", "r", &name])));

  // A FOREIGN instance's cookie, and a crashed process's leftover: both are
  // suppressed too — the namespace is total over the grammar, never
  // own-pending-only. Every writer of a real cookie is this same minter.
  assert!(source.is_sync_artifact(&key(&[
    "/",
    "r",
    ".tributaries-sync-9-999-1-ffffffffffffffff"
  ])));
  assert!(source.is_sync_artifact(&key(&[
    "/",
    "r",
    ".tributaries-sync-0-1-0-0000000000000000"
  ])));

  // The THREE-field shape this binding minted before the name carried a nonce.
  // A cookie outlives the process that wrote it, so a leftover on disk was named
  // by whichever release was running then: dropping this shape would make the
  // first watch after an upgrade report every stale cookie as a user create.
  for legacy_leftover in [
    ".tributaries-sync-9-999-1",
    ".tributaries-sync-0-1-0",
    ".tributaries-sync-18446744073709551615-4294967295-18446744073709551615",
  ] {
    assert!(
      source.is_sync_artifact(&key(&["/", "r", legacy_leftover])),
      "{legacy_leftover} is a cookie an earlier release of this binding minted"
    );
  }

  // The whole minted range round-trips: the extremes of every field are still
  // recognized by the classifier that has to suppress them.
  for token in [
    SyncToken::new(0, 0, 0, 0),
    SyncToken::new(u64::MAX, u32::MAX, u64::MAX, u64::MAX),
    SyncToken::new(1, 1, 1, 1),
  ] {
    let minted = super::cookie_name(token);
    assert!(
      source.is_sync_artifact(&key(&["/", "r", &minted])),
      "the minter and the classifier must agree on {minted}"
    );
  }

  // The fs layer's cookie DIRECTORY is in the same namespace and is likewise not
  // a user change — for any uid, since two users may watch one tree.
  assert!(source.is_sync_artifact(&key(&["/", "r", ".tributaries-sync-cookies"])));
  assert!(source.is_sync_artifact(&key(&["/", "r", ".tributaries-sync-cookies-501"])));

  // Ordinary files are not artifacts — including one whose PARENT carries a
  // COOKIE's name rather than the cookie directory's: only the directory this
  // driver actually creates makes its children artifacts.
  assert!(!source.is_sync_artifact(&key(&["/", "r", "a.txt"])));
  assert!(!source.is_sync_artifact(&key(&[
    "/",
    "r",
    ".tributaries-sync-7-42-3-00000000deadbeef",
    "inner.txt"
  ])));
  assert!(!source.is_sync_artifact(&key(&["/", "r", "not-a-.tributaries-sync-1"])));

  // A USER file that merely opens with the reserved stem is a user change: the
  // namespace is reserved, but only its minted grammar is suppressed. Each of
  // these is a real name a caller could choose, and a bare prefix test would
  // erase every one of them from the stream with no Rescan and no diagnostic.
  for user_leaf in [
    // Prose, not fields.
    ".tributaries-sync-notes.txt",
    ".tributaries-sync-",
    // Too few fields for either minted shape.
    ".tributaries-sync-7-42",
    // The right field count, but a nonce that is not sixteen lowercase hex.
    ".tributaries-sync-7-42-3-DEADBEEFDEADBEEF",
    ".tributaries-sync-7-42-3-00000000deadbee",
    ".tributaries-sync-7-42-3-00000000deadbeeff",
    ".tributaries-sync-7-42-3-zzzzzzzzzzzzzzzz",
    // Right shape, but a decimal field the minter cannot render.
    ".tributaries-sync-07-42-3-00000000deadbeef",
    ".tributaries-sync-7-4294967296-3-00000000deadbeef",
    ".tributaries-sync--42-3-00000000deadbeef",
    ".tributaries-sync-7-42-3-4-00000000deadbeef",
    ".tributaries-sync-07-42-3",
    // The cookie directory's stem with a non-numeric qualifier.
    ".tributaries-sync-cookies-mine",
  ] {
    assert!(
      !source.is_sync_artifact(&key(&["/", "r", user_leaf])),
      "{user_leaf} is not a minted artifact — suppressing it would erase a user file"
    );
  }
}

/// The cookie leaf that reaches this classifier is NOT always one this crate minted:
/// [`tributary_fs::Watcher::sync_root`] takes the cookie's name from its own caller and
/// accepts any normal component, so a second consumer of `tributary-fs` watching the same
/// tree writes cookies whose names this crate cannot predict at all. What identifies
/// those is the directory they land in — the fs driver's own `0o700` cookie directory —
/// so an immediate child of one is an artifact whatever its leaf.
///
/// Getting this wrong is worse than the over-broad prefix test it replaced: a leaf
/// grammar alone republishes another watcher's GENUINE cookie create and unlink as user
/// changes on every consumer stream, which is precisely the leak the reserved namespace
/// exists to close.
///
/// Fail-on-old: with a leaf-only grammar, every name below except the last is a normal
/// filename with no reserved shape, so each assertion reads `false` and the cell fails on
/// its first cookie.
#[tokio::test]
async fn a_foreign_watchers_cookie_is_an_artifact_by_the_directory_it_lands_in() {
  use std::ffi::OsString;

  use agnostic_lite::tokio::TokioRuntime;
  use tributary_fs::WatcherOptions;

  use crate::{Source, source::FsSource};

  let source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build");
  let key =
    |parts: &[&str]| -> Vec<OsString> { parts.iter().map(|p| OsString::from(*p)).collect() };

  for cookie_dir in [".tributaries-sync-cookies", ".tributaries-sync-cookies-501"] {
    for leaf in [
      // A real lower-layer cookie name from this workspace's own fs-watcher cells.
      ".tributaries-sync-admission-retry",
      // A caller that never adopted the reserved stem at all: still a cookie, because
      // `sync_root` let it choose the name and the directory is the driver's.
      "barrier-cookie",
      // The shapes this crate mints are children of that directory too.
      ".tributaries-sync-7-42-3-00000000deadbeef",
      ".tributaries-sync-9-999-1",
    ] {
      assert!(
        source.is_sync_artifact(&key(&["/", "r", cookie_dir, leaf])),
        "{leaf} inside {cookie_dir} is a cookie some watcher wrote, not a user change"
      );
    }
  }

  // Only the IMMEDIATE parent counts. Nothing this driver writes is nested deeper, so a
  // deeper descendant is read as a user change rather than silently erased.
  assert!(!source.is_sync_artifact(&key(&[
    "/",
    "r",
    ".tributaries-sync-cookies-501",
    "sub",
    "notes.txt"
  ])));
  // A directory whose name only resembles the cookie directory's is not one, so its
  // children stay user changes.
  assert!(!source.is_sync_artifact(&key(&[
    "/",
    "r",
    ".tributaries-sync-cookies-mine",
    "notes.txt"
  ])));
}
