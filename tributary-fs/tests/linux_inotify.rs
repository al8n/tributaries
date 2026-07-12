//! End-to-end integration through the public API against real inotify.
//!
//! Real-kernel timing is nondeterministic, so every assertion is
//! convergence-style: wait (bounded) until the expected fact is observed;
//! extra events — coalesced kinds, additional `Rescan`s — are always legal.
//!
//! The privileged cells (queue overflow, watch-limit exhaustion, the bind-mount
//! boundary) self-probe and skip loudly without `CAP_SYS_ADMIN`; the
//! `inotify-priv` suite of `ci/linux-verify.sh` (or `sudo -E` in CI) unlocks
//! them.
//!
//! ALWAYS run this binary with `--test-threads=1` (the verify script and CI
//! do): the sysctl cells shrink the user namespace's inotify limits, which
//! would starve any event-flow test running concurrently.

// not(miri): drives real inotify/statx syscalls and a tokio runtime — none of
// which miri can execute. The sans-I/O logic is covered by the lib unit tests.
#![cfg(all(target_os = "linux", feature = "tokio", not(miri)))]

use std::{
  path::{Path, PathBuf},
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
  },
  time::Duration,
};

use tributary_fs::{Backend, Event, Interest, TokioWatcher, WatcherOptions};

/// Generous ceiling for one expected observation; CI runners are slow.
const DEADLINE: Duration = Duration::from_secs(20);

/// A fresh scratch root under `TMPDIR` (the container mounts a tmpfs there,
/// keeping every test on container-native paths), canonicalized so event
/// paths and expectations share one byte form.
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
  if event.path() == path {
    return true;
  }
  event.is_rescan() && path.starts_with(event.path())
}

/// Snapshot-and-set one `/proc/sys` knob; `None` = unwritable (unprivileged).
fn sysctl_swap(knob: &str, value: &str) -> Option<String> {
  let path = format!("/proc/sys/{knob}");
  let old = std::fs::read_to_string(&path).ok()?.trim().to_string();
  std::fs::write(&path, value).ok()?;
  Some(old)
}

fn sysctl_restore(knob: &str, value: &str) {
  let _ = std::fs::write(format!("/proc/sys/{knob}"), value);
}

/// Loud self-probe for the privileged cells.
fn privileged_or_skip(cell: &str) -> bool {
  match sysctl_swap("fs/inotify/max_queued_events", "16384") {
    Some(old) => {
      sysctl_restore("fs/inotify/max_queued_events", &old);
      true
    }
    None => {
      eprintln!("SKIP {cell}: needs CAP_SYS_ADMIN (run via linux-verify.sh inotify-priv)");
      false
    }
  }
}

/// Suite 1 (§6.3): create/modify/remove churn converges through the
/// descending profile — every mutated path ends covered. Both facts are
/// collected in ONE pass over the stream (waiting twice would discard the
/// events the second wait needs).
#[tokio::test]
async fn churn_converges() {
  let root = scratch_root("churn");
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  std::fs::create_dir_all(root.join("a/b")).unwrap();
  std::fs::write(root.join("a/b/one.txt"), b"1").unwrap();
  std::fs::write(root.join("top.txt"), b"t").unwrap();
  std::fs::remove_file(root.join("top.txt")).unwrap();

  let deep = root.join("a/b/one.txt");
  let top = root.join("top.txt");
  let mut saw_deep = false;
  let mut saw_top = false;
  let _ = tokio::time::timeout(DEADLINE, async {
    while let Some(event) = w.next().await {
      saw_deep |= covers(&event, &deep);
      saw_top |= covers(&event, &top);
      if saw_deep && saw_top {
        break;
      }
    }
  })
  .await;
  assert!(saw_deep, "the deep create is observed after descent");
  assert!(saw_top, "the top-level churn is observed");
}

/// Suite 2: native cookie pairing — a same-directory rename surfaces as one
/// `Moved` (kernel cookies pair inside the Monitor's window; no settle logic
/// exists driver-side).
#[tokio::test]
async fn rename_pairs_into_moved() {
  let root = scratch_root("rename");
  std::fs::write(root.join("old.txt"), b"x").unwrap();
  // This cell pins PAIRING correctness, not window tightness: when the two
  // rename halves split across reader batches, a sanitizer-slowed host can
  // stretch the gap past the default move window, and the halves then
  // LEGALLY degrade to Removed + Created — a different contract than the
  // one under test. A generous window keeps the cell about the pairing.
  let mut w = TokioWatcher::new(WatcherOptions::new().with_move_window(Duration::from_secs(10)))
    .expect("build watcher");
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  std::fs::rename(root.join("old.txt"), root.join("new.txt")).unwrap();

  let from = root.join("old.txt");
  let to = root.join("new.txt");
  let moved = wait_for(&mut w, |e| {
    e.kind().moved().is_some_and(|m| m.from() == from) && e.path() == to
  })
  .await;
  assert!(moved.is_some(), "the same-dir rename pairs into one Moved");

  // Cross-directory pairing needs BOTH directories armed at rename time
  // (the kernel reports each half on its own watched parent — an unarmed
  // destination honestly degrades to Removed + the enumerate's Created).
  // Prove `sub`'s watch is live first: an event for a file inside it can
  // only arrive after the arm.
  std::fs::create_dir(root.join("sub")).unwrap();
  std::fs::write(root.join("sub/probe.txt"), b"p").unwrap();
  let probe = root.join("sub/probe.txt");
  assert!(
    wait_for(&mut w, |e| covers(e, &probe)).await.is_some(),
    "the created directory arms and its content surfaces"
  );

  std::fs::rename(root.join("new.txt"), root.join("sub/into.txt")).unwrap();
  let to2 = root.join("sub/into.txt");
  assert!(
    wait_for(&mut w, |e| e.kind().moved().is_some() && e.path() == to2)
      .await
      .is_some(),
    "the cross-dir rename pairs into one Moved"
  );
}

/// Suite 3: `IN_IGNORED` teardown — a kernel-removed watched directory
/// resolves (`Removed` covered) and its siblings keep flowing.
#[tokio::test]
async fn kernel_teardown_resolves_and_siblings_flow() {
  let root = scratch_root("ignored");
  std::fs::create_dir(root.join("gone")).unwrap();
  std::fs::create_dir(root.join("stays")).unwrap();
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  std::fs::remove_dir(root.join("gone")).unwrap();
  let gone = root.join("gone");
  assert!(
    wait_for(&mut w, |e| covers(e, &gone)).await.is_some(),
    "the removed watched directory is observed"
  );

  std::fs::write(root.join("stays/alive.txt"), b"y").unwrap();
  let alive = root.join("stays/alive.txt");
  assert!(
    wait_for(&mut w, |e| covers(e, &alive)).await.is_some(),
    "siblings keep delivering after a kernel-side teardown"
  );
}

/// Suite 3b: self-induced teardown — after `unwatch` acknowledges, churn
/// produces nothing (bounded quiet-window assertion).
#[tokio::test]
async fn unwatch_quiesces() {
  let root = scratch_root("unwatch");
  let mut w = watcher();
  let h = w.watch(&root, Interest::all()).await.expect("watch");
  w.unwatch(h).await.expect("unwatch");

  std::fs::write(root.join("after.txt"), b"z").unwrap();
  let got = tokio::time::timeout(Duration::from_secs(2), w.next()).await;
  assert!(
    !matches!(got, Ok(Some(_))),
    "no event may arrive after unwatch acknowledged"
  );
}

/// Suite 4: the wd follows the inode — a watched directory renamed within the
/// root keeps its coverage (the Monitor's O(1) reparent, end to end against
/// the real kernel).
#[tokio::test]
async fn moved_directory_keeps_coverage() {
  let root = scratch_root("reparent");
  std::fs::create_dir(root.join("before")).unwrap();
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  std::fs::rename(root.join("before"), root.join("after")).unwrap();
  std::fs::write(root.join("after/inside.txt"), b"i").unwrap();

  let inside = root.join("after/inside.txt");
  assert!(
    wait_for(&mut w, |e| covers(e, &inside)).await.is_some(),
    "a file created under the moved directory is observed at its new path"
  );
}

/// Suite 5 (privileged): deterministic queue overflow — a 16-slot kernel
/// queue plus a rename storm forces `IN_Q_OVERFLOW`, which must surface as an
/// epoch-bumped `Rescan`, never silence.
#[tokio::test]
async fn queue_overflow_surfaces_as_rescan() {
  if !privileged_or_skip("queue_overflow_surfaces_as_rescan") {
    return;
  }
  let old = sysctl_swap("fs/inotify/max_queued_events", "16").expect("shrink queue");
  let root = scratch_root("overflow");
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  let mut observed = false;
  'bursts: for burst in 0..3 {
    for i in 0..400 {
      let a = root.join(format!("f-{burst}-{i}-a"));
      let b = root.join(format!("f-{burst}-{i}-b"));
      std::fs::write(&a, b"x").unwrap();
      std::fs::rename(&a, &b).unwrap();
      std::fs::remove_file(&b).unwrap();
    }
    if wait_for(&mut w, |e| e.is_rescan()).await.is_some() {
      observed = true;
      break 'bursts;
    }
  }
  sysctl_restore("fs/inotify/max_queued_events", &old);
  assert!(observed, "a forced kernel overflow surfaces as a Rescan");
}

/// Whether this kernel actually enforces `fs/inotify/max_user_watches`. Some
/// containerized kernels accept the sysctl write — it even reads back as the new
/// value — yet never charge watches against it, so an exhaustion cell can never
/// fire. Adds watches on `dirs` to a private inotify fd: an `ENOSPC` before they
/// are exhausted proves the limit bites; adding strictly more than `limit`
/// without one proves it does not. Closing the fd releases every probe watch, so
/// the real watch that follows starts from a clean budget.
fn inotify_enforces_watch_limit(dirs: &[PathBuf], limit: usize) -> bool {
  use std::os::unix::ffi::OsStrExt;
  let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
  if fd < 0 {
    return false;
  }
  let mut enforced = false;
  let mut added = 0usize;
  for dir in dirs {
    let Ok(cpath) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
      continue;
    };
    let wd = unsafe { libc::inotify_add_watch(fd, cpath.as_ptr(), libc::IN_ATTRIB) };
    if wd < 0 {
      // A freshly-created dir yields only the watch-limit `ENOSPC` here — which is
      // exactly the enforcement being probed for.
      enforced = std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSPC);
      break;
    }
    added += 1;
    if added > limit {
      break;
    }
  }
  unsafe {
    libc::close(fd);
  }
  enforced
}

/// Suite 6 (privileged): watch-limit exhaustion — `ENOSPC` mid-descent lands
/// on the Monitor's `NoSpace` path: honest `Rescan`, no silence, no panic,
/// and the watcher survives.
#[tokio::test]
async fn watch_limit_exhaustion_is_honest() {
  if !privileged_or_skip("watch_limit_exhaustion_is_honest") {
    return;
  }
  let root = scratch_root("nospace");
  let mut dirs = Vec::new();
  for i in 0..12 {
    let dir = root.join(format!("d{i}"));
    std::fs::create_dir(&dir).unwrap();
    dirs.push(dir);
  }
  let old = sysctl_swap("fs/inotify/max_user_watches", "8").expect("shrink watches");
  // The exhaustion path is inotify-specific: `max_user_watches` does not bound the
  // kernel-recursive fanotify backend that `Backend::Auto` selects under privilege,
  // so pin inotify below. Then probe whether this kernel actually enforces the
  // shrink — some containerized kernels accept and echo the write yet never charge
  // watches against it — so a non-enforcing kernel soft-skips rather than failing
  // on an exhaustion that could not happen.
  let enforced = inotify_enforces_watch_limit(&dirs, 8);

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let watched = w.watch(&root, Interest::all()).await;
  let honest = match watched {
    // The descent hit the ceiling after the root armed: coverage loss must
    // surface as a Rescan.
    Ok(_) => wait_for(&mut w, |e| e.is_rescan()).await.is_some(),
    // Or the ceiling hit the root arm itself: a typed error is equally
    // honest.
    Err(_) => true,
  };
  sysctl_restore("fs/inotify/max_user_watches", &old);
  // Only an enforcing kernel exercises the exhaustion path. Where the limit does
  // not bite AND watching succeeded with no rescan, exhaustion never triggered —
  // soft-skip. Whenever it WAS triggered (the limit really bites) the honesty
  // assertion below stands unweakened: a real silent NoSpace still fails here.
  if !enforced && !honest {
    eprintln!(
      "SKIP watch_limit_exhaustion_is_honest: this kernel does not enforce the \
       max_user_watches shrink; exhaustion never triggered"
    );
    return;
  }
  assert!(honest, "watch exhaustion surfaces as Rescan or typed error");
}

/// Suite 7 (privileged): a bind mount inside the root is a MOUNT BOUNDARY, not an
/// alias to descend. `root/b` bound from `root/a` sits on a different mount id, so
/// the enumerate lowering marks it non-descendable — the Monitor never arms a watch
/// under it, and a write reached through the bind spelling (`root/b/...`) surfaces
/// only under the ORIGINAL (`root/a/...`), never a second time under `b`.
///
/// On Linux a directory has exactly one inode-sharing spelling per bind (hardlinked
/// directories do not exist), so a directory bind is the only alias the EEXIST
/// fan-out ever handled — and the mount-id fence now makes that case a uniform
/// boundary on both backends (design-consistent), the intended change. The EEXIST
/// alias machinery remains the belt for any NON-mount aliasing.
#[tokio::test]
async fn bind_mount_inside_root_is_a_boundary() {
  if !privileged_or_skip("bind_mount_inside_root_is_a_boundary") {
    return;
  }
  let root = scratch_root("bind-boundary");
  std::fs::create_dir(root.join("a")).unwrap();
  std::fs::create_dir(root.join("b")).unwrap();
  let status = std::process::Command::new("mount")
    .arg("--bind")
    .arg(root.join("a"))
    .arg(root.join("b"))
    .status()
    .expect("run mount");
  if !status.success() {
    eprintln!("SKIP bind_mount_inside_root_is_a_boundary: bind mount refused");
    return;
  }

  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");
  // A write reached through the BIND spelling `root/b/shared.txt` lands on the same
  // object as `root/a/shared.txt` (b is bound from a). The original `a` is watched
  // (same mount as root); the bind `b` is a boundary and is not.
  let via_a = root.join("a/shared.txt");
  let via_b = root.join("b/shared.txt");
  std::fs::write(&via_b, b"s").unwrap();

  // The original spelling is observed — `a` is in-root and descended.
  let saw_a = wait_for(&mut w, |e| covers(e, &via_a)).await.is_some();
  // The bind spelling must NOT surface: `b` was fenced as a mount boundary and
  // never armed, so no watch reports a `b/...` path. A bounded quiet window proves
  // its absence.
  let leaked_b = tokio::time::timeout(Duration::from_secs(3), async {
    while let Some(event) = w.next().await {
      if event.path().starts_with(root.join("b")) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  let _ = std::process::Command::new("umount")
    .arg("-l")
    .arg(root.join("b"))
    .status();
  assert!(
    saw_a,
    "the write to the bound object is observed under the original in-root spelling"
  );
  assert!(
    !leaked_b,
    "the bind point is a mount boundary — no event surfaces under its spelling"
  );
}

/// §7's documented limitation, pinned end to end: a non-UTF-8 name cannot
/// become a `Segment`, so it escalates to a covering located `Rescan` —
/// coverage-honest, never a panic, never silence.
#[tokio::test]
async fn non_utf8_name_escalates_to_rescan() {
  use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
  let root = scratch_root("nonutf8");
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  let weird = root.join(OsStr::from_bytes(&[0xFF, 0xFE, b'x']));
  std::fs::write(&weird, b"?").unwrap();

  // The covering Rescan lands at the parent directory (or an ancestor, up to
  // the root itself) — anywhere that obliges re-reading the affected region.
  assert!(
    wait_for(&mut w, |e| e.is_rescan()
      && (e.path().starts_with(&root) || root.starts_with(e.path())))
    .await
    .is_some(),
    "an undeliverable name surfaces as a covering Rescan"
  );
}

/// Reader-teardown fairness under sustained traffic (the container companion to
/// the hermetic mid-drain unit test). A producer churns files continuously so the
/// inotify fd stays readable, then the watcher is CLOSED under that load.
/// `close()` must fully quiesce (`Ok(())`): the reader observes the shutdown
/// between reads rather than after an `EAGAIN` the sustained stream never yields.
/// Without the interleaved control check the teardown `join` would wedge past the
/// close grace and surface as `NotQuiesced`.
#[tokio::test]
async fn close_quiesces_under_sustained_traffic() {
  let root = scratch_root("close-load");
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  let stop = Arc::new(AtomicBool::new(false));
  let producer = {
    let root = root.clone();
    let stop = Arc::clone(&stop);
    std::thread::spawn(move || {
      let mut i = 0u64;
      while !stop.load(Ordering::Relaxed) {
        let p = root.join(format!("churn-{}", i % 64));
        let _ = std::fs::write(&p, b"x");
        let _ = std::fs::remove_file(&p);
        i = i.wrapping_add(1);
      }
    })
  };

  // Confirm the stream is actually flowing (the reader is under load) before
  // tearing down, so the close races a live drain rather than an idle one.
  assert!(
    wait_for(&mut w, |e| e.path().starts_with(&root))
      .await
      .is_some(),
    "events flow under the producer before close"
  );

  let closed = tokio::time::timeout(DEADLINE, w.close()).await;
  stop.store(true, Ordering::Relaxed);
  producer.join().expect("producer joins");
  assert!(
    matches!(closed, Ok(Ok(()))),
    "close must fully quiesce under sustained traffic — the reader observes shutdown mid-drain, \
     not after an EAGAIN that never comes: {closed:?}"
  );
}

/// Widening `x/y` → `x` on the descending backend: the pre-arm + rebind
/// commit bridges the swap with one covering `Rescan`, the rebuilt tree is
/// live on the NEW inotify instance (writes under old and new ground both
/// deliver), and repeated swaps neither leak watch descriptors into refusals
/// nor strand the old coverage — the old root re-watches cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_root_widens_and_rebinds() {
  let root = scratch_root("replace-widen");
  let sub = root.join("y");
  std::fs::create_dir_all(sub.join("deep")).expect("create tree");
  let mut w = watcher();
  let handle = w.watch(&sub, Interest::all()).await.expect("watch");
  std::fs::write(sub.join("pre.txt"), b"pre").expect("write pre");

  w.replace_root(handle, &root)
    .await
    .expect("the swap commits");
  assert_eq!(w.root_path(handle), Some(root.clone()));
  let covering = wait_for(&mut w, |e| e.is_rescan() && e.path() == root).await;
  assert!(covering.is_some(), "the covering Rescan arrives");

  // The rebuilt (re-armed) tree is live on the new instance: old ground...
  let old_ground = sub.join("deep").join("old-ground.txt");
  std::fs::write(&old_ground, b"x").expect("write old ground");
  assert!(
    wait_for(&mut w, |e| covers(e, &old_ground)).await.is_some(),
    "the old subtree is re-armed on the new fd"
  );
  // ...and newly covered ground alike.
  let outside = root.join("outside.txt");
  std::fs::write(&outside, b"x").expect("write outside");
  assert!(
    wait_for(&mut w, |e| covers(e, &outside)).await.is_some(),
    "newly covered ground is live"
  );

  // Swap back (narrowing) and once more: watch bookkeeping survives cycles —
  // a leak of the old fd's descriptors would surface as arm refusals here.
  for _ in 0..3 {
    w.replace_root(handle, &sub).await.expect("narrow commits");
    w.replace_root(handle, &root).await.expect("widen commits");
  }
  let probe = root.join("after-cycles.txt");
  std::fs::write(&probe, b"x").expect("write probe");
  assert!(
    wait_for(&mut w, |e| covers(e, &probe)).await.is_some(),
    "coverage is live after swap cycles"
  );

  match w.watch(&sub, Interest::all()).await {
    Err(tributary_fs::WatchRootError::Overlaps { existing, .. }) => assert_eq!(existing, root),
    other => panic!("the widened coverage must contain the old root: {other:?}"),
  }
  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}
