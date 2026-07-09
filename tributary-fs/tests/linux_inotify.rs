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
  let mut w = watcher();
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

/// Total inotify watch descriptors held by THIS process, summed across every inotify fd:
/// an inotify fd's `/proc/self/fdinfo/<fd>` lists one `inotify wd:<n> ...` line per live
/// per-directory watch. Run with `--test-threads=1` (this binary always is), so the single
/// watcher under test is the only inotify fd and this reflects its descending watch count.
fn count_inotify_wds() -> usize {
  let mut total = 0;
  let Ok(entries) = std::fs::read_dir("/proc/self/fdinfo") else {
    return 0;
  };
  for entry in entries.flatten() {
    if let Ok(content) = std::fs::read_to_string(entry.path()) {
      total += content
        .lines()
        .filter(|line| line.starts_with("inotify wd:"))
        .count();
    }
  }
  total
}

/// M2-B set-cover, end to end against real inotify: a wide root that armed per-directory
/// watches over TWO nested subtrees is reconciled in place down to a retained cover, then
/// **grown back**. Phase 1 (shrink): the strictly-outside subtree's watch descriptors are
/// reclaimed (the wd count drops), the retained subtree keeps delivering with NO gap (its
/// watches are never re-armed), and the pruned subtree stops delivering — the whole point of
/// shrinking the kernel coverage rather than releasing and re-arming. Phase 2 (grow, Codex
/// R36): re-issuing a cover that once again includes the pruned subtree re-arms it in place,
/// so a fresh deep write under it IS delivered again — the bidirectional dual, without which a
/// survivor watching a previously-pruned subtree would sit over a hole no watch backs.
#[tokio::test]
async fn set_cover_prunes_outside_subtree_then_grows_it_back() {
  let root = scratch_root("shrink");
  std::fs::create_dir_all(root.join("keep/deep")).unwrap();
  std::fs::create_dir_all(root.join("drop/deep")).unwrap();

  // Pin inotify: the shrink prunes PER-DIRECTORY watches, which only the descending backend holds
  // (a kernel-recursive fanotify mark has none, and its shrink is a documented no-op).
  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let h = w.watch(&root, Interest::all()).await.expect("watch root");

  // Both nested subtrees must be armed before the shrink: a write deep under each surfaces, proving
  // /keep/deep and /drop/deep hold live per-directory watches.
  let keep_probe = root.join("keep/deep/before.txt");
  let drop_probe = root.join("drop/deep/before.txt");
  std::fs::write(&keep_probe, b"x").unwrap();
  std::fs::write(&drop_probe, b"x").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &keep_probe)).await.is_some(),
    "the /keep subtree is armed (its deep write surfaces)"
  );
  assert!(
    wait_for(&mut w, |e| covers(e, &drop_probe)).await.is_some(),
    "the /drop subtree is armed (its deep write surfaces)"
  );

  let before = count_inotify_wds();
  assert!(
    before >= 5,
    "root + keep + keep/deep + drop + drop/deep all hold watches before the shrink (got {before})"
  );

  // Shrink the wide root down to the /keep cover: /drop and /drop/deep are strictly outside it, so
  // their watches are pruned; the root (connecting ancestor) and /keep + /keep/deep stay armed with
  // NO re-arm.
  w.set_cover(h, vec![root.join("keep")])
    .await
    .expect("set_cover prune");

  // The pruned subtree's descriptors are reclaimed (the disarms apply asynchronously, fire-and-forget).
  let reclaimed = tokio::time::timeout(DEADLINE, async {
    loop {
      if count_inotify_wds() < before {
        return true;
      }
      tokio::time::sleep(Duration::from_millis(25)).await;
    }
  })
  .await
  .unwrap_or(false);
  assert!(
    reclaimed,
    "the strictly-outside /drop subtree's watch descriptors are reclaimed after the shrink"
  );

  // Drain any pre-shrink stragglers (a trailing /drop event decoded before its wd's `IN_IGNORED`)
  // so the pruned-stops quiet window below sees ONLY post-shrink deliveries — the wds are already
  // reclaimed above, so nothing new can enter for /drop, and this just clears the backlog.
  let _ = tokio::time::timeout(Duration::from_millis(500), async {
    while w.next().await.is_some() {}
  })
  .await;

  // RETAINED keeps flowing with NO gap: a fresh write under /keep/deep still surfaces — its watches
  // were never re-armed, so no event under them could have been missed.
  let keep_after = root.join("keep/deep/after.txt");
  std::fs::write(&keep_after, b"y").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &keep_after)).await.is_some(),
    "the retained /keep/deep subtree still delivers after the shrink (no gap, no re-crawl)"
  );

  // PRUNED stops: a write deep under /drop produces nothing within a bounded quiet window — its
  // parent watches were removed, and the still-armed root only sees its own direct entries.
  let drop_after = root.join("drop/deep/after.txt");
  std::fs::write(&drop_after, b"z").unwrap();
  let leaked = tokio::time::timeout(Duration::from_secs(3), async {
    while let Some(event) = w.next().await {
      if event.path().starts_with(root.join("drop")) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    !leaked,
    "the pruned /drop subtree stops delivering after the shrink"
  );

  // PHASE 2 — GROW BACK (Codex R36): re-issue a cover that once again includes /drop. The
  // set-cover is bidirectional, so /drop's per-directory watches are re-armed in place (its
  // deepest still-watched ancestor — the root — is re-armed, re-installing /drop and /drop/deep
  // and cascading down), with no re-crawl of the retained /keep.
  w.set_cover(h, vec![root.join("keep"), root.join("drop")])
    .await
    .expect("set_cover grow");

  // Drain the re-arm's coverage-maintenance traffic (no `Created`/`Rescan` is emitted for the
  // re-arm itself, but pre-existing quiescent entries may produce nothing) so the probe below
  // observes only the fresh post-grow write.
  let _ = tokio::time::timeout(Duration::from_millis(500), async {
    while w.next().await.is_some() {}
  })
  .await;

  // The previously-pruned /drop/deep now holds live per-directory watches again: a fresh deep
  // write under it IS delivered — the regression the grow half closes.
  let drop_regrown = root.join("drop/deep/regrown.txt");
  std::fs::write(&drop_regrown, b"w").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &drop_regrown))
      .await
      .is_some(),
    "the re-armed /drop/deep subtree delivers again after the set-cover grew it back (Codex R36)"
  );
}
