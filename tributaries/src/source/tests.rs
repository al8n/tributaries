use std::ffi::OsString;

use super::{Source, key_to_path};
use crate::event::path_components;

/// Compile-time proof that a [`Source`]'s event-pump future ([`Source::next`]) is `Send`,
/// so the driver can pump a generic `S: Source<C>` on a task spawned on a multi-threaded
/// tokio or smol executor. Never invoked — it only has to type-check: a regression that
/// dropped the `Send` bound would stop `needs_send` from accepting the future and fail
/// this build. The generic bound is the guarantee, so this holds for every implementor
/// (including an out-of-tree custom source), not just [`FsSource`]. `arm`/`disarm` run on
/// the single-writer control path and carry no `Send` bound, so they are not asserted.
#[allow(dead_code)]
fn assert_source_next_send<C, S: Source<C>>(s: &mut S) {
  fn needs_send<F: Send>(_: F) {}
  needs_send(s.next());
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

  /// A short window to confirm the *absence* of an event: `disarm` awaits the stream
  /// teardown, so a change made afterwards cannot be delivered — this only has to outlast
  /// scheduling jitter, keeping the negative check fast.
  const QUIET: Duration = Duration::from_secs(2);

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

    // Disarm the root: `disarm` awaits the stream teardown, so a file created afterwards
    // must never surface for that handle.
    source.disarm(armed.handle()).await;
    let after = root.join("after-disarm.txt");
    std::fs::write(&after, b"bye").expect("write after disarm");
    let leaked = wait_for(&mut source, QUIET, |event| {
      event.handle() == armed.handle() && key_to_path(event.key()) == after
    })
    .await;
    assert!(
      leaked.is_none(),
      "a disarmed root delivers no further events for its handle"
    );
  }
}
