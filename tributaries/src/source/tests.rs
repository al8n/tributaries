use std::ffi::OsString;

use super::{Source, key_to_path};
use crate::event::path_components;

/// Compile-time proof that the **two** async [`Source`] futures — [`arm`](Source::arm) and the event
/// pump [`next`](Source::next) — are `Send`, so the owner (which drives them inline in one `select!`
/// loop) can be spawned via [`R::spawn_detach`](agnostic_lite::RuntimeLite::spawn_detach) on a
/// multi-threaded tokio or smol executor. [`disarm`](Source::disarm) is synchronous (it returns no
/// future). Never invoked — it only has to type-check: a regression that dropped a `Send` bound would
/// stop `needs_send` from accepting that future and fail this build. The generic bound is the
/// guarantee, so this holds for every implementor (including an out-of-tree custom source), not just
/// [`FsSource`].
#[allow(dead_code)]
fn assert_source_futures_send<C, S: Source<C>>(s: &mut S, key: &[C], handle: S::Handle) {
  fn needs_send<F: Send>(_: F) {}
  needs_send(s.arm(key));
  needs_send(s.next());
  // `disarm` is synchronous — no future to prove `Send`; the call keeps `handle` exercised.
  s.disarm(handle);
}

/// Asserts a component sequence round-trips: rebuilding a path from key components and
/// re-decomposing it yields the original components. This is the fs binding's key ↔ path
/// contract — events are located by re-decomposing a canonical path, so the two
/// directions must be exact inverses on canonical component sequences.
fn assert_round_trips(components: &[&str]) {
  let key: Vec<OsString> = components.iter().map(OsString::from).collect();
  let path = key_to_path(&key);
  assert_eq!(
    path_components(&path),
    key,
    "key ↔ path round-trip of {components:?}"
  );
}

#[test]
fn round_trips_multi_component() {
  assert_round_trips(&["a", "b", "c"]);
}

#[test]
fn round_trips_single_component() {
  assert_round_trips(&["only"]);
}

// The absolute cases pivot on the leading root component, whose spelling is
// platform-specific; the crate's real backends are unix, and miri runs on the unix host.
#[cfg(unix)]
#[test]
fn round_trips_absolute_multi_component() {
  // `/usr/local` decomposes to `["/", "usr", "local"]` and rebuilds back.
  assert_round_trips(&["/", "usr", "local"]);
}

#[cfg(unix)]
#[test]
fn round_trips_root() {
  assert_round_trips(&["/"]);
}

// The integration suite drives a real kernel watch on a tokio runtime — syscalls miri
// cannot execute — so it is gated on the runtime feature and off miri, exactly like the
// umbrella integration suite. The key ↔ path round-trip above is the miri-scoped part.
#[cfg(all(feature = "tokio", not(miri)))]
mod integration {
  use std::{ffi::OsString, path::PathBuf, time::Duration};

  use agnostic_lite::tokio::TokioRuntime;
  use tempfile::TempDir;
  use tributary_fs::{RootHandle, WatchRootError, WatcherOptions};

  use super::super::{FsSource, OPPORTUNISTIC_RELEASES, Source, SourceEvent, key_to_path};
  use crate::{error::WatchError, event::path_components};

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
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps) surfaced (contract clause 2). Here the single
  /// queued release is the oldest, so the re-arm's OPPORTUNISTIC bounded application tears it down
  /// before the watch (had it been deeper in the queue, the conflict-triggered retry would resolve the
  /// watcher's own `Overlaps` rejection instead — Codex R29); either way no `Overlaps` reaches the
  /// caller.
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
    // just-released root (contract clause 2, Codex R29).
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

  /// R29-F1: a DISJOINT arm's release work is HARD-BOUNDED — it applies at most
  /// [`OPPORTUNISTIC_RELEASES`] of the OLDEST queued releases up front (FIFO), never the whole backlog,
  /// so a caller-bounded `Watch` (and any `close` queued behind it) is decoupled from the release
  /// cleanup (contract clause 2). Queue three disjoint releases A, B, C (in that order), then arm a
  /// disjoint D: exactly the two OLDEST (A, B) are applied opportunistically — C stays queued — and D
  /// arms with no overlap and no retry.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_disjoint_arm_applies_at_most_the_opportunistic_oldest() {
    // The FIFO-order assertion below is meaningful only if exactly two of three are applied.
    assert_eq!(
      OPPORTUNISTIC_RELEASES, 2,
      "this test is written for a bound of 2"
    );
    let (_dir, parent) = scratch();
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // Arm three disjoint siblings A, B, C — all FIRST, before any disarm, so each arm's opportunistic
    // application pops from an empty queue and the backlog is not drained as it is built.
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
    // THEN disarm all three in order → queue [A, B, C] (A oldest).
    for &handle in &handles {
      source.disarm(handle);
    }
    assert_eq!(
      source.pending_releases.len(),
      3,
      "three disjoint releases are queued"
    );

    // Arm a disjoint D: the opportunistic bounded application unwatches the two OLDEST (A, B) up front;
    // D overlaps none of the live roots, so it arms first try with no retry. C — the newest — is left
    // queued (beyond the opportunistic bound).
    let d = parent.join("d");
    std::fs::create_dir_all(&d).expect("create d");
    let d_key = path_components(&d);
    let armed_d = source.arm(&d_key).await.expect("arm disjoint D");
    assert_eq!(
      source.pending_releases.len(),
      1,
      "the disjoint arm applied at most the 2 opportunistic oldest (A, B); C stays queued"
    );
    assert!(
      !source.pending_set.contains(&handles[0]) && !source.pending_set.contains(&handles[1]),
      "the two OLDEST releases (A, B) were the ones applied — FIFO"
    );
    assert!(
      source.pending_set.contains(&handles[2]),
      "the newest release (C) is beyond the opportunistic bound and stays queued"
    );
    assert_eq!(
      source.root_key(armed_d.handle()),
      Some(d_key),
      "the disjoint D armed and is live"
    );
  }

  /// R29-F1/F2 shape regression: an arm's release work does not scale with the backlog depth. Queue
  /// **many** disjoint releases (watch+disarm N disjoint subroots), then arm ANOTHER disjoint key and
  /// assert it applies **at most the opportunistic bound** (pending stays ≥ N − bound) — so a `close`
  /// queued behind that `Watch` is decoupled from the whole cleanup. The old whole-backlog drain would
  /// have awaited N unwatches here; the bounded application awaits at most
  /// [`OPPORTUNISTIC_RELEASES`].
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_disjoint_arm_cost_is_independent_of_release_backlog() {
    const N: usize = 32;
    let (_dir, parent) = scratch();
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // Build a backlog of N queued releases over N disjoint sibling subroots. Arm all N FIRST, then
    // disarm all N — otherwise each arm's opportunistic application would drain the previous disarm and
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

    // Arm one MORE disjoint subroot: it overlaps none of the backlog, so it applies only the ≤ bound
    // opportunistic oldest — the arm's release work is independent of the backlog depth (R29).
    let other = parent.join("other");
    std::fs::create_dir_all(&other).expect("create other");
    let other_key = path_components(&other);
    let armed = source
      .arm(&other_key)
      .await
      .expect("arm the extra disjoint subroot");
    let remaining = source.pending_releases.len();
    assert!(
      remaining >= N - OPPORTUNISTIC_RELEASES,
      "the disjoint arm applied at most OPPORTUNISTIC_RELEASES of the N queued (pending {remaining} ≥ \
       {}) — arm cost is independent of backlog depth (R29), so a close behind that Watch is decoupled",
      N - OPPORTUNISTIC_RELEASES
    );
    assert_eq!(
      source.root_key(armed.handle()),
      Some(other_key),
      "the extra disjoint subroot armed and is live"
    );
  }

  /// R29-F1 (i) / R30-F2: an ancestor arm over N released-but-lingering descendants succeeds via the
  /// conflict-triggered retry — no [`Overlaps`](tributary_fs::WatchRootError::Overlaps) reaches the
  /// caller. Watch+disarm N disjoint tempdir SUBDIRS, then watch their PARENT: the parent overlaps
  /// every still-lingering descendant, so the watcher rejects with `Overlaps` NAMING one at a time;
  /// each retry unwatches exactly the named descendant and re-attempts, until the parent arms cleanly
  /// (contract clause 2). Asserts the parent is live (no overlap surfaced — the awaited work was
  /// bounded by the conflicts actually named), the whole descendant backlog was applied, and the armed
  /// parent genuinely delivers.
  ///
  /// **N deliberately exceeds the retired `OVERLAP_RETRY_CAP` (64)** (Codex R30-F2): the retry is now a
  /// STRUCTURAL progress bound (pending strictly shrinks each retry), not a fixed ceiling. Fail-on-old:
  /// with the 64-retry cap, ~65 named conflicts (67 descendants less the 2 applied opportunistically)
  /// would trip the cap and surface `Overlaps` to the caller instead of arming the parent.
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
    // the parent arms with NO `Overlaps` surfaced to the caller (contract clause 2, Codex R29).
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
      source.pending_releases.is_empty() && source.pending_set.is_empty(),
      "every released descendant was applied (opportunistically or by the retry) — nothing left pending"
    );

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

  /// R30-F2 (ii): a rejection whose named conflict is NOT a pending (released) root — a genuine LIVE
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

    // Arm `OPPORTUNISTIC_RELEASES + 1` DISJOINT roots (separate tempdirs) FIRST, then disarm them all —
    // arming-before-disarming keeps each arm's opportunistic application from draining the backlog as it
    // is built (mirroring the ancestor test). The queue then stays non-empty PAST the opportunistic
    // application the parent arm runs: the LAST-disarmed handle survives as the front of the remaining
    // queue — exactly the entry the retired index-0 fallback would grab.
    let mut dirs = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..(OPPORTUNISTIC_RELEASES + 1) {
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
      matches!(err, WatchError::Fs(WatchRootError::Overlaps { .. })),
      "an unmatched (live) conflict surfaces as Overlaps, not looped-away"
    );
    assert!(
      source.pending_set.contains(&survivor),
      "the unrelated pending root is untouched — no index-0 fallback released it (Codex R30-F2)"
    );
  }

  /// M2-B set_cover PROMPT application (Codex R37-F2): `FsSource::set_cover` forwards the reconcile to
  /// the watcher's control channel the instant it is called — via the non-blocking reply-less
  /// [`request_set_cover`](tributary_fs::Watcher::request_set_cover) — so a `Covered`-outside grow
  /// (which arms NOTHING, hence has no future `arm` to drain a queue) applies without waiting. When the
  /// channel has room (the normal case) NOTHING is left queued. This is the end-to-end regression: a
  /// grow re-issue with NO subsequent arm drains through the prompt path, asserted by `pending_set_covers`
  /// staying empty. The macOS watcher's `set_cover` is a whole-subtree no-op at the KERNEL, so the kernel
  /// reconcile itself is exercised by the linux-CI grow suites; here it is the FsSource queue that must
  /// empty. A root-key cover (the cancel-equivalent) forwards likewise — the core reconciles it to full
  /// coverage via its broadening delta — and, having dropped any older queued entry (latest-wins), queues
  /// nothing either.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn fs_source_set_cover_applies_promptly_without_a_later_arm() {
    let (_dir, root) = scratch();
    let root_key = path_components(&root);
    let mut source = FsSource::<TokioRuntime>::new(WatcherOptions::new()).expect("build FsSource");

    // A live armed root — after `arm` resolves, its watch command has been consumed, so the bounded
    // control channel has room.
    let armed = source.arm(&root_key).await.expect("arm the tempdir");
    let handle = armed.handle();

    // A subtree cover UNDER the root — the shape the umbrella forwards on a `Covered` commit, with NO
    // subsequent arm to drain a queue. The prompt path applies it at once, leaving nothing queued.
    let b_key = path_components(&root.join("b"));
    source.set_cover(handle, std::slice::from_ref(&b_key));
    assert!(
      source.pending_set_covers.is_empty(),
      "set_cover applies PROMPTLY via the reply-less request when the control channel has room — a \
       Covered-outside grow no longer waits for an unrelated arm (Codex R37-F2)"
    );

    // A newer cover for the SAME handle also forwards promptly (latest-wins has nothing stale to drop,
    // since the prior one was already applied, not queued).
    let c_key = path_components(&root.join("c"));
    source.set_cover(handle, &[b_key.clone(), c_key.clone()]);
    assert!(
      source.pending_set_covers.is_empty(),
      "a re-issued fresh cover also forwards promptly"
    );

    // The cancel-equivalent (retain the root's OWN key) forwards promptly too — the core grows back to
    // FULL coverage via its broadening delta — and queues nothing.
    source.set_cover(handle, std::slice::from_ref(&root_key));
    assert!(
      source.pending_set_covers.is_empty(),
      "a root-key cancel forwards promptly and queues nothing"
    );
  }
}
