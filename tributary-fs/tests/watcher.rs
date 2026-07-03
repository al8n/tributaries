//! End-to-end integration through the public API against real FSEvents.
//!
//! Real-kernel timing is nondeterministic, so every assertion is
//! convergence-style: wait (bounded) until the expected fact is observed;
//! extra events — coalesced kinds, additional `Rescan`s — are always legal.

#![cfg(all(target_os = "macos", feature = "tokio"))]

use std::{
  path::{Path, PathBuf},
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use tributary_fs::{Event, Interest, TokioWatcher, WatcherOptions};

/// Generous ceiling for one expected observation; macOS CI runners are slow.
const DEADLINE: Duration = Duration::from_secs(20);

/// A fresh canonicalized scratch root (`/tmp` is a symlink — FSEvents reports
/// resolved paths, so the root must be canonical before comparisons).
fn scratch_root(tag: &str) -> PathBuf {
  static COUNTER: AtomicU32 = AtomicU32::new(0);
  let dir = std::env::temp_dir()
    .canonicalize()
    .expect("canonicalize temp dir")
    .join(format!(
      "tributary-fs-it-{}-{}-{}",
      tag,
      std::process::id(),
      COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
  std::fs::create_dir_all(&dir).expect("create scratch root");
  dir
}

fn watcher() -> TokioWatcher {
  TokioWatcher::new(WatcherOptions::new()).expect("build watcher")
}

/// Waits until an event satisfying `pred` arrives, or the deadline lapses.
async fn wait_for(
  watcher: &mut TokioWatcher,
  mut pred: impl FnMut(&Event) -> bool,
) -> Option<Event> {
  tokio::time::timeout(DEADLINE, async {
    while let Some(event) = watcher.next().await {
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

/// An event "covers" a path when it names it directly or is a `Rescan` at the
/// path or one of its ancestors (a rescan obliges re-enumeration below it).
fn covers(event: &Event, path: &Path) -> bool {
  event.path() == path || (event.is_rescan() && path.starts_with(event.path()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_and_remove_converge() {
  let root = scratch_root("create");
  let mut w = watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  assert_eq!(w.root_path(handle), Some(root.clone()));

  let file = root.join("a.txt");
  std::fs::write(&file, b"hello").expect("create");
  let seen = wait_for(&mut w, |e| {
    covers(e, &file) && (e.kind().is_created() || e.kind().is_modified() || e.is_rescan())
  })
  .await;
  assert!(
    seen.is_some(),
    "the creation of {} was observed",
    file.display()
  );

  std::fs::remove_file(&file).expect("remove");
  let seen = wait_for(&mut w, |e| {
    covers(e, &file) && (e.kind().is_removed() || e.is_rescan())
  })
  .await;
  assert!(
    seen.is_some(),
    "the removal of {} was observed",
    file.display()
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_is_a_move_or_the_documented_degrade() {
  let root = scratch_root("rename");
  let mut w = watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  let from = root.join("old.txt");
  let to = root.join("new.txt");
  std::fs::write(&from, b"payload").expect("create");
  assert!(
    wait_for(&mut w, |e| covers(e, &from)).await.is_some(),
    "the creation was observed"
  );

  std::fs::rename(&from, &to).expect("rename");
  let seen = wait_for(&mut w, |e| {
    let paired_move = e
      .kind()
      .moved()
      .is_some_and(|m| m.from() == from && e.path() == to);
    let degraded_create = e.kind().is_created() && e.path() == to;
    paired_move || degraded_create || covers(e, &to)
  })
  .await;
  assert!(
    seen.is_some(),
    "the rename surfaced as a Moved, its documented degrade, or a covering rescan"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_roots_are_rejected() {
  let root = scratch_root("overlap");
  let sub = root.join("sub");
  std::fs::create_dir_all(&sub).expect("create subdir");

  let w = watcher();
  let _outer = w.watch(&root, Interest::all()).await.expect("watch outer");

  let err = w
    .watch(&sub, Interest::all())
    .await
    .expect_err("a nested root must be rejected");
  assert!(err.is_overlaps(), "got {err:?}");

  let _ = std::fs::remove_dir_all(&root);
}

/// The last component with its ASCII case swapped — a second spelling of the
/// SAME object on the default case-insensitive APFS. `None` when the volume
/// is case-sensitive (the spellings are then genuinely different names, and
/// identity-based disjointness has nothing to prove).
fn case_alias_of(path: &Path) -> Option<PathBuf> {
  use std::os::unix::fs::MetadataExt;
  let name = path.file_name()?.to_str()?;
  let swapped: String = name
    .chars()
    .map(|c| {
      if c.is_ascii_lowercase() {
        c.to_ascii_uppercase()
      } else {
        c.to_ascii_lowercase()
      }
    })
    .collect();
  if swapped == name {
    return None;
  }
  let alias = path.with_file_name(swapped);
  let original = std::fs::metadata(path).ok()?;
  let aliased = std::fs::metadata(&alias).ok()?;
  ((original.dev(), original.ino()) == (aliased.dev(), aliased.ino())).then_some(alias)
}

/// Root disjointness is decided by object identity, so a case-swapped
/// spelling of a watched root — or a path nested through one — is rejected
/// exactly like the canonical spelling, while a genuinely distinct sibling is
/// admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_aliased_roots_are_rejected_on_insensitive_volumes() {
  let root = scratch_root("caseal");
  let Some(alias) = case_alias_of(&root) else {
    eprintln!("skipping: the volume is case-sensitive");
    return;
  };
  std::fs::create_dir_all(root.join("sub")).expect("create subdir");

  let w = watcher();
  let _held = w
    .watch(&root, Interest::all())
    .await
    .expect("watch original");

  let err = w
    .watch(&alias, Interest::all())
    .await
    .expect_err("one subtree, two spellings");
  assert!(err.is_overlaps(), "got {err:?}");

  let err = w
    .watch(alias.join("sub"), Interest::all())
    .await
    .expect_err("nested through the aliased spelling");
  assert!(err.is_overlaps(), "got {err:?}");

  let sibling = scratch_root("caseal-sib");
  let _distinct = w
    .watch(&sibling, Interest::all())
    .await
    .expect("a distinct sibling is admitted");

  let _ = std::fs::remove_dir_all(&root);
  let _ = std::fs::remove_dir_all(&sibling);
}

/// Two concurrent watches of one object under different spellings admit
/// exactly one winner (the reservation-time identity makes the collision
/// deterministic).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_case_aliased_watches_admit_exactly_one() {
  let root = scratch_root("caserace");
  let Some(alias) = case_alias_of(&root) else {
    eprintln!("skipping: the volume is case-sensitive");
    return;
  };

  let w = watcher();
  let (a, b) = tokio::join!(
    w.watch(&root, Interest::all()),
    w.watch(&alias, Interest::all())
  );
  assert_eq!(
    u8::from(a.is_ok()) + u8::from(b.is_ok()),
    1,
    "exactly one spelling wins: {a:?} / {b:?}"
  );

  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_and_non_directory_roots_are_rejected() {
  let root = scratch_root("badroots");
  let w = watcher();

  let err = w
    .watch(root.join("nope"), Interest::all())
    .await
    .expect_err("a missing root must be rejected");
  assert!(err.is_not_found(), "got {err:?}");

  let file = root.join("plain.txt");
  std::fs::write(&file, b"x").expect("create file");
  let err = w
    .watch(&file, Interest::all())
    .await
    .expect_err("a non-directory root must be rejected");
  assert!(err.is_not_a_directory(), "got {err:?}");

  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unwatch_stops_delivery() {
  let root = scratch_root("unwatch");
  let mut w = watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");

  // Prove the watch is live, then stop it.
  let probe = root.join("before.txt");
  std::fs::write(&probe, b"x").expect("create");
  assert!(wait_for(&mut w, |e| covers(e, &probe)).await.is_some());
  w.unwatch(handle).await.expect("unwatch");

  // A second unwatch of the same handle no longer names a live root.
  let err = w.unwatch(handle).await.expect_err("handle is dead");
  assert!(err.is_unknown_root(), "got {err:?}");

  // Give any decoded trailing events a moment to flush, then churn: nothing
  // about the new file may arrive.
  tokio::time::sleep(Duration::from_millis(500)).await;
  while tokio::time::timeout(Duration::from_millis(100), w.next())
    .await
    .is_ok()
  {}
  let after = root.join("after.txt");
  std::fs::write(&after, b"x").expect("create");
  let quiet = tokio::time::timeout(Duration::from_secs(2), async {
    while let Some(event) = w.next().await {
      assert_ne!(
        event.path(),
        after.as_path(),
        "an unwatched root delivered {event:?}"
      );
    }
  })
  .await;
  assert!(quiet.is_err(), "the stream stayed quiet after unwatch");

  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleted_root_surfaces_and_kills_the_handle() {
  let outer = scratch_root("rootdeath");
  let root = outer.join("watched");
  std::fs::create_dir_all(&root).expect("create watched root");

  let mut w = watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  let canonical = w.root_path(handle).expect("root path");

  std::fs::remove_dir_all(&root).expect("delete the watched root");
  let seen = wait_for(&mut w, |e| {
    e.root() == handle && (e.is_rescan() || (e.kind().is_removed() && e.path() == canonical))
  })
  .await;
  assert!(
    seen.is_some(),
    "the root's death surfaced as a Removed or a Rescan"
  );

  // The scope was torn down; the handle no longer names a live root.
  let err = match w.unwatch(handle).await {
    Err(err) => err,
    Ok(()) => {
      // The teardown may still be in flight; a second attempt must fail.
      tokio::time::sleep(Duration::from_millis(500)).await;
      w.unwatch(handle)
        .await
        .expect_err("handle outlived its root")
    }
  };
  assert!(err.is_unknown_root() || err.is_closed(), "got {err:?}");

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&outer);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_quiesces() {
  let root = scratch_root("close");
  let w = watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");
  tokio::time::timeout(Duration::from_secs(10), w.close())
    .await
    .expect("close resolved within its deadline")
    .expect("close confirmed");
  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewatch_after_root_death_succeeds() {
  let outer = scratch_root("rewatch");
  let root = outer.join("watched");
  std::fs::create_dir_all(&root).expect("create watched root");

  let mut w = watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  std::fs::remove_dir_all(&root).expect("delete the watched root");
  let seen = wait_for(&mut w, |e| e.root() == handle && e.is_rescan()).await;
  assert!(seen.is_some(), "the root's death surfaced");

  // The dead root's registry entry must stop blocking a fresh watch of the
  // recreated path; the driver's teardown propagates asynchronously, so poll.
  std::fs::create_dir_all(&root).expect("recreate the root");
  let deadline = std::time::Instant::now() + DEADLINE;
  let rewatched = loop {
    match w.watch(&root, Interest::all()).await {
      Ok(handle) => break handle,
      Err(err) if err.is_overlaps() => {
        assert!(
          std::time::Instant::now() < deadline,
          "the dead root kept blocking a fresh watch: {err:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
      Err(err) => panic!("unexpected watch failure: {err:?}"),
    }
  };
  assert_ne!(rewatched, handle, "a fresh scope for the recreated root");

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&outer);
}
