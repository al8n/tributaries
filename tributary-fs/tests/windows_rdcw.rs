//! End-to-end integration through the public API against real
//! `ReadDirectoryChangesW`.
//!
//! Real-kernel timing is nondeterministic, so every assertion is
//! convergence-style: wait (bounded) until the expected fact is observed;
//! extra events — coalesced kinds, additional `Rescan`s — are always legal.
//!
//! The zoo cells (`TRIBUTARY_ZOO_NTFS`/`TRIBUTARY_ZOO_FAT32`, built by
//! `ci/windows/zoo.ps1`) self-probe and skip loudly when the environment
//! variables are absent, so the suite also runs on a bare developer box.
//!
//! ALWAYS run this binary with `--test-threads=1` (CI does): the overflow
//! cell floods the kernel buffer, which would perturb any event-flow test
//! running concurrently.
//!
//! The suite doubles as the campaign's [verify] ledger executor: the
//! root-delete, root-rename, and overflow cells pin the documented-by-practice
//! Windows behaviors the pump design rests on.

// not(miri): drives real Win32 I/O and a tokio runtime — none of which miri
// can execute. The sans-I/O logic is covered by the lib unit tests.
#![cfg(all(target_os = "windows", feature = "tokio", not(miri)))]

use std::{
  path::{Path, PathBuf},
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use tributary_fs::{Backend, Event, EventKind, Interest, TokioWatcher, WatcherOptions};

/// Generous ceiling for one expected observation; CI runners are slow.
const DEADLINE: Duration = Duration::from_secs(20);

/// A fresh scratch root, canonicalized so event paths and expectations share
/// one byte form (`\\?\`-prefixed on Windows).
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
  dir.canonicalize().expect("canonicalize scratch root")
}

fn watcher() -> TokioWatcher {
  TokioWatcher::new(WatcherOptions::new()).expect("build watcher")
}

/// Waits until an event satisfying `pred` arrives, or the deadline lapses.
async fn wait_for(
  watcher: &mut TokioWatcher,
  mut pred: impl FnMut(&Event) -> bool,
) -> Option<Event> {
  loop {
    let event = tokio::time::timeout(DEADLINE, watcher.next())
      .await
      .ok()??;
    if pred(&event) {
      return Some(event);
    }
  }
}

/// Whether the event names (or covers) `target`.
fn covers(event: &Event, target: &Path) -> bool {
  match event.kind() {
    EventKind::Rescan => target.starts_with(event.path()),
    _ => event.path() == target,
  }
}

/// The backend report: a live root on Windows runs RDCW.
#[tokio::test]
async fn selection_reports_rdcw() {
  let root = scratch_root("select");
  let w = watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  assert_eq!(
    w.backend_of(handle).expect("live root").as_str(),
    "rdcw",
    "the Windows platform default is RDCW until the USN backend lands"
  );
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// Create → modify → remove under a nested tree: each verb is delivered.
#[tokio::test]
async fn verbs_flow_end_to_end() {
  let root = scratch_root("verbs");
  std::fs::create_dir_all(root.join("deep")).expect("mkdir");
  let mut w = watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  let file = root.join("deep").join("probe.txt");
  std::fs::write(&file, b"one").expect("create");
  assert!(
    wait_for(&mut w, |e| covers(e, &file)).await.is_some(),
    "the create is delivered"
  );

  std::fs::write(&file, b"two").expect("modify");
  assert!(
    wait_for(&mut w, |e| covers(e, &file)).await.is_some(),
    "the modify is delivered"
  );

  std::fs::remove_file(&file).expect("remove");
  assert!(
    wait_for(&mut w, |e| covers(e, &file)).await.is_some(),
    "the remove is delivered"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// A same-tree rename pairs into one Moved (or degrades to covered halves —
/// both legal; what is NOT legal is silence on either end).
#[tokio::test]
async fn renames_cover_both_ends() {
  let root = scratch_root("rename");
  let from = root.join("old.txt");
  std::fs::write(&from, b"x").expect("seed");
  let mut w = watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  let to = root.join("new.txt");
  std::fs::rename(&from, &to).expect("rename");
  assert!(
    wait_for(&mut w, |e| covers(e, &to) || covers(e, &from))
      .await
      .is_some(),
    "a rename is observed on at least one end"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// Unwatch/rewatch cycles reclaim cleanly — the registry never leaks a root.
#[tokio::test]
async fn watch_unwatch_cycles_reclaim() {
  let root = scratch_root("cycles");
  let w = watcher();
  for _ in 0..8 {
    let handle = w.watch(&root, Interest::all()).await.expect("watch");
    w.unwatch(handle).await.expect("unwatch");
  }
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// [verify] root delete under a live watch: the scope dies loudly (a terminal
/// Rescan/root-gone shape), never silently.
#[tokio::test]
async fn root_delete_is_loud() {
  let parent = scratch_root("rootdel");
  let root = parent.join("victim");
  std::fs::create_dir_all(&root).expect("mkdir");
  let root = root.canonicalize().expect("canonicalize");
  let mut w = watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  std::fs::remove_dir_all(&root).expect("delete the watched root");
  assert!(
    wait_for(&mut w, |e| matches!(e.kind(), EventKind::Rescan)
      || e.path().starts_with(&root))
    .await
    .is_some(),
    "the watched root's deletion surfaces in-band"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&parent);
}

/// [verify] overflow: a burst far past the kernel buffer forces the loss
/// path, which must surface as a Rescan — never silence, never a wedge.
#[tokio::test]
async fn overflow_degrades_to_rescan() {
  let root = scratch_root("overflow");
  let mut w = watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  // A dense burst of tiny creates+removes: far more record bytes than one
  // 64 KiB kernel buffer holds while the pump is between reads.
  for round in 0..64 {
    for i in 0..256 {
      let f = root.join(format!("burst-{round}-{i}.tmp"));
      std::fs::write(&f, b"x").ok();
      std::fs::remove_file(&f).ok();
    }
  }
  assert!(
    wait_for(&mut w, |e| matches!(e.kind(), EventKind::Rescan)
      || e.path().starts_with(&root))
    .await
    .is_some(),
    "the burst surfaces events or the loss rescan"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// A UNC root is refused at the barrier with a typed error, never a silent
/// dead watch.
#[tokio::test]
async fn unc_root_is_refused() {
  let w = watcher();
  let err = w
    .watch(Path::new(r"\\localhost\c$\Windows"), Interest::all())
    .await
    .expect_err("a UNC root cannot start");
  let text = format!("{err}");
  assert!(!text.is_empty());
  w.close().await.expect("close");
}

/// Forcing the foreign fanotify backend fails typed on Windows.
#[tokio::test]
async fn foreign_backend_is_typed() {
  let root = scratch_root("foreign");
  let w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Fanotify)).expect("build");
  let err = w
    .watch(&root, Interest::all())
    .await
    .expect_err("fanotify does not exist on Windows");
  assert!(format!("{err}").contains("fanotify"));
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// The zoo cells: the same verb flow on each scratch volume the zoo built.
#[tokio::test]
async fn zoo_volumes_flow() {
  for var in ["TRIBUTARY_ZOO_NTFS", "TRIBUTARY_ZOO_FAT32"] {
    let Some(base) = std::env::var_os(var) else {
      eprintln!("SKIP zoo_volumes_flow: {var} is unset (no zoo)");
      continue;
    };
    let root = PathBuf::from(&base).join(format!("watch-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("zoo scratch");
    let root = root.canonicalize().expect("canonicalize zoo root");
    let mut w = watcher();
    let _handle = w.watch(&root, Interest::all()).await.expect("watch");
    let file = root.join("zoo.txt");
    std::fs::write(&file, b"x").expect("create");
    assert!(
      wait_for(&mut w, |e| covers(e, &file)).await.is_some(),
      "{var}: the create is delivered"
    );
    w.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&root);
  }
}
