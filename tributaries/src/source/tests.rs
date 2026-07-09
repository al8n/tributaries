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
  use tributary_fs::{RootHandle, WatcherOptions};

  use super::super::{FsSource, Source, SourceEvent, key_to_path};
  use crate::event::path_components;

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
  /// immediately (`root_key` → None, contract clause 3), and the queued release is drained at the TOP
  /// of the next `arm` — so re-arming the SAME (overlapping) key succeeds with no
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps), release-before-subsequent-arm by
  /// construction (contract clause 2).
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

    // Re-arm the SAME key. Its queued release is drained at the TOP of `arm` BEFORE the new watch, so
    // the real `Watcher` never reports `Overlaps` against the just-released root (contract clause 2).
    let second = source
      .arm(&root_key)
      .await
      .expect("re-arm of the same key succeeds — the pending release drained before the watch");
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
}
