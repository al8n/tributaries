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

/// Scales every real-kernel timing budget in this binary. Under sanitizer
/// instrumentation the runtime is slowed several fold while the raw syscalls the
/// producer issues are not, so a fixed budget that is generous natively becomes
/// marginal: the CI sanitizer job sets this so the cells keep their coverage
/// instead of being skipped. Unset (native runs) it is 1 and nothing changes.
fn timing_scale() -> u32 {
  std::env::var("TRIBUTARY_FS_TIMING_SCALE")
    .ok()
    .and_then(|v| v.parse().ok())
    .filter(|n| *n > 0)
    .unwrap_or(1)
}

fn scaled(d: Duration) -> Duration {
  d * timing_scale()
}

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

/// A watcher pinned to the inotify (descending) backend. The D2 same-fd widen
/// continuity is inotify-specific; under `CAP_SYS_ADMIN` (root / sudo /
/// privileged CI) `Backend::Auto` selects fanotify, which is kernel-recursive
/// and legitimately Rescan-BRIDGES a widen (the whole widen surfaces as one
/// structural Rescan) — so cells asserting the same-fd continuous DELIVERY
/// (distinct from that structural bridge) must pin inotify rather than take the
/// ambient backend.
fn inotify_watcher() -> TokioWatcher {
  TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify)).expect("build watcher")
}

/// Waits until an event satisfying `pred` arrives, or the deadline lapses.
async fn wait_for(
  watcher: &mut TokioWatcher,
  mut pred: impl FnMut(&Event) -> bool,
) -> Option<Event> {
  tokio::time::timeout(scaled(DEADLINE), async {
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

/// Converges on live coverage of `dir`: creates a fresh file there and waits
/// briefly for its delivery, retrying until one lands. A descending re-arm
/// (a `replace_root` widen rebuilds the tree on a new inotify instance)
/// descends asynchronously, so a single create in a not-yet-armed directory
/// is lost — inotify never re-delivers a create that predates its watch — but
/// once the re-arm reaches `dir`, a subsequent create is delivered. Returns
/// `false` only if coverage never becomes live within the retry budget.
async fn coverage_becomes_live(watcher: &mut TokioWatcher, dir: &Path, tag: &str) -> bool {
  for attempt in 0..40 {
    let probe = dir.join(format!("{tag}-{attempt}.txt"));
    if std::fs::write(&probe, b"x").is_err() {
      return false;
    }
    let seen = tokio::time::timeout(scaled(Duration::from_millis(500)), async {
      while let Some(event) = watcher.next().await {
        if covers(&event, &probe) {
          return true;
        }
      }
      false
    })
    .await
    .unwrap_or(false);
    if seen {
      return true;
    }
  }
  false
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
  let _ = tokio::time::timeout(scaled(DEADLINE), async {
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
  let mut w =
    TokioWatcher::new(WatcherOptions::new().with_move_window(scaled(Duration::from_secs(10))))
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

  let closed = tokio::time::timeout(scaled(DEADLINE), w.close()).await;
  stop.store(true, Ordering::Relaxed);
  producer.join().expect("producer joins");
  assert!(
    matches!(closed, Ok(Ok(()))),
    "close must fully quiesce under sustained traffic — the reader observes shutdown mid-drain, \
     not after an EAGAIN that never comes: {closed:?}"
  );
}

/// Widening `x/y` → `x` on the descending backend is CONTINUOUS (the
/// same-transport commit): the live stream is kept and the old subtree keeps
/// delivering at its unchanged absolute paths, while the newly covered ground
/// goes live via cold discovery. The STRICT no-Rescan / no-epoch-bump contract
/// is pinned deterministically by the hermetic cell
/// `a_widening_replace_keeps_the_stream_and_dominates_nothing`; here — on a real
/// kernel — an honest root-`[]` `Rescan` (a dirty cold-read escalation on the
/// freshly-covered ground) is TOLERATED as a covering delivery, but a misaddress
/// or a lost write is not. Narrowing back is the stream-replace (Rescan-bridged)
/// path, and repeated swap cycles neither leak watch descriptors into refusals
/// nor strand coverage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_root_widens_and_rebinds() {
  let root = scratch_root("replace-widen");
  let sub = root.join("y");
  std::fs::create_dir_all(sub.join("deep")).expect("create tree");
  let mut w = inotify_watcher();
  let handle = w.watch(&sub, Interest::all()).await.expect("watch");
  // Settle the birth crawl before the swap so the widen's own window is the
  // only thing under test.
  assert!(
    coverage_becomes_live(&mut w, &sub.join("deep"), "birth").await,
    "the birth crawl reaches the deep old ground"
  );

  w.replace_root(handle, &root)
    .await
    .expect("the swap commits");
  assert_eq!(w.root_path(handle), Some(root.clone()));

  // Zero-gap continuity (the point of D2): a write under the OLD subtree lands
  // at its EXACT unchanged absolute path on the SAME stream after the widen.
  // The strict no-Rescan / no-epoch-bump contract is pinned deterministically by
  // the hermetic cell `a_widening_replace_keeps_the_stream_and_dominates_nothing`;
  // a real kernel under a signal storm may additionally escalate a dirty
  // cold-read of the fresh ground into an honest root-`[]` `Rescan` (which covers
  // `post` by ancestry) — tolerated via `covers`. A MISADDRESSED delivery or a
  // LOST write covers `post` by neither and fails the deadline below.
  let post = sub.join("post-widen.txt");
  std::fs::write(&post, b"post").expect("write post");
  let delivered = tokio::time::timeout(scaled(DEADLINE), async {
    while let Some(event) = w.next().await {
      if covers(&event, &post) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    delivered,
    "the old subtree delivers across the widen — at its exact path, or via an honest covering Rescan"
  );

  // The deep old ground stayed live, and the newly covered ground is armed
  // by the cold crawl.
  assert!(
    coverage_becomes_live(&mut w, &sub.join("deep"), "old-ground").await,
    "the old subtree's interior coverage rode across the widen"
  );
  assert!(
    coverage_becomes_live(&mut w, &root, "outside").await,
    "newly covered ground is live"
  );

  // Narrowing back is the stream-replace path — Rescan-bridged.
  w.replace_root(handle, &sub).await.expect("narrow commits");
  let covering = wait_for(&mut w, |e| e.is_rescan() && e.path() == sub).await;
  assert!(
    covering.is_some(),
    "a narrowing replace bridges with a Rescan"
  );

  // Swap cycles: watch bookkeeping survives — a leak of descriptors (or a
  // stranded adoption) would surface as arm refusals or dead coverage here.
  for _ in 0..3 {
    w.replace_root(handle, &root).await.expect("widen commits");
    w.replace_root(handle, &sub).await.expect("narrow commits");
  }
  w.replace_root(handle, &root).await.expect("final widen");
  assert!(
    coverage_becomes_live(&mut w, &root, "after-cycles").await,
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

/// The barrier-honesty headline (INV-ROOT): a change under the old subtree made
/// BEFORE a widening replace is either individually DELIVERED at its exact path
/// or DOMINATED by an honest `Rescan`, and a `sync_root` cookie written after the
/// widen resolves the barrier strictly behind it on the one surviving kernel
/// queue. The barrier NEVER certifies `Delivered` over a change it neither
/// delivered nor dominated. The strict no-Rescan continuity is pinned by the
/// hermetic cell; a signal-storm kernel's honest dirty-read `Rescan` is the
/// domination signal, tolerated here — never a false Delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sync_barrier_across_a_widen_resolves_by_delivery() {
  let root = scratch_root("widen-sync");
  let sub = root.join("y");
  std::fs::create_dir_all(&sub).expect("create tree");
  let mut w = inotify_watcher();
  let handle = w.watch(&sub, Interest::all()).await.expect("watch");
  assert!(
    coverage_becomes_live(&mut w, &sub, "birth").await,
    "the birth crawl settles"
  );

  // The pre-widen change: written, recorded by the live stream, NOT consumed.
  let pre = sub.join("before-the-widen.txt");
  std::fs::write(&pre, b"x").expect("write pre");

  w.replace_root(handle, &root)
    .await
    .expect("the widen commits");
  assert_eq!(w.root_path(handle), Some(root.clone()));

  // The barrier: the cookie's create rides the SAME queue behind the pre-widen
  // change, so the cookie resolves the barrier. INV-ROOT — the barrier must
  // NEVER certify `Delivered` over a change it did not deliver — holds two ways:
  // the pre-widen change is DELIVERED at its exact path before the cookie, OR an
  // honest root-`[]` `Rescan` DOMINATES it (covers `pre` by ancestry), re-obliging
  // its re-enumeration. A signal-storm kernel can emit that dominating Rescan; it
  // is tolerated because it IS the domination signal, not a false Delivered. The
  // one dishonest ending — the cookie reached with `pre` NEITHER delivered NOR
  // dominated — is a false Delivered and fails the assertion below.
  let (admission, _ticket) = w.mint_sync_ticket();
  let cookie = w
    .sync_root(handle, root.clone(), ".tributaries-sync-widen", admission)
    .await
    .expect("the cookie writes");
  let barrier_honest = tokio::time::timeout(scaled(DEADLINE), async {
    let mut saw_pre = false;
    let mut dominated = false;
    while let Some(event) = w.next().await {
      if event.is_rescan() && pre.starts_with(event.path()) {
        // An honest Rescan at the root (an ancestor of `pre`) dominates the
        // pre-widen change: the barrier resolves by domination, not delivery.
        dominated = true;
      }
      if event.path() == pre {
        saw_pre = true;
      }
      if event.path() == cookie {
        // The barrier resolves here. Honest iff `pre` was already delivered or
        // an honest Rescan dominated it; a bare cookie is a false Delivered.
        return saw_pre || dominated;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    barrier_honest,
    "the barrier resolves honestly — the pre-widen change is DELIVERED before the cookie, \
     or an honest Rescan dominates it; never a false Delivered over lost coverage"
  );

  // The freshly covered ground goes live via the widen's cold discovery.
  assert!(
    coverage_becomes_live(&mut w, &root, "fresh").await,
    "newly covered ground is live after the widen"
  );

  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// A DEEP widen (`r/a/b/c` → `r`) adopts across a multi-segment chain: the old
/// subtree keeps delivering at its exact absolute paths, the connecting interior
/// and the fresh ground both go live, and the handle reports the new root. The
/// strict no-Rescan continuity is pinned hermetically
/// (`a_widening_replace_keeps_the_stream_and_dominates_nothing`); on a real
/// kernel an honest root-`[]` `Rescan` (a dirty cold-read escalation) is
/// tolerated as a covering delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deep_widen_adopts_across_the_chain() {
  let root = scratch_root("deep-widen");
  let old = root.join("a").join("b").join("c");
  std::fs::create_dir_all(&old).expect("create tree");
  let mut w = inotify_watcher();
  let handle = w.watch(&old, Interest::all()).await.expect("watch");
  assert!(
    coverage_becomes_live(&mut w, &old, "birth").await,
    "the birth crawl settles"
  );

  w.replace_root(handle, &root)
    .await
    .expect("the deep widen commits");
  assert_eq!(w.root_path(handle), Some(root.clone()));

  // Zero-gap continuity across the multi-segment chain: the old subtree's write
  // lands at its EXACT unchanged absolute path on the same stream. The strict
  // no-Rescan contract is pinned hermetically (see
  // `a_widening_replace_keeps_the_stream_and_dominates_nothing`); a signal-storm
  // kernel may escalate a dirty cold-read of the fresh ground to an honest
  // root-`[]` `Rescan` covering `post` — tolerated via `covers`. A misaddressed
  // delivery or a lost write covers `post` by neither and fails the deadline.
  let post = old.join("across.txt");
  std::fs::write(&post, b"x").expect("write across");
  let delivered = tokio::time::timeout(scaled(DEADLINE), async {
    while let Some(event) = w.next().await {
      if covers(&event, &post) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    delivered,
    "the adopted subtree delivers across the deep widen — at its exact path, or via an honest covering Rescan"
  );

  // The connecting chain and the fresh ground both armed.
  assert!(
    coverage_becomes_live(&mut w, &root.join("a").join("b"), "chain").await,
    "the connecting interior is covered"
  );
  assert!(
    coverage_becomes_live(&mut w, &root, "fresh").await,
    "the fresh ground is covered"
  );

  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// A DISJOINT replace stays on the stream-replace path: the commit bridges
/// with its covering Rescan and the new ground goes live on the new stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disjoint_replace_stays_rescan_bridged() {
  let a = scratch_root("disjoint-a");
  let b = scratch_root("disjoint-b");
  let mut w = watcher();
  let handle = w.watch(&a, Interest::all()).await.expect("watch");
  assert!(coverage_becomes_live(&mut w, &a, "birth").await);

  w.replace_root(handle, &b).await.expect("the swap commits");
  assert_eq!(w.root_path(handle), Some(b.clone()));
  let covering = wait_for(&mut w, |e| e.is_rescan() && e.path() == b).await;
  assert!(
    covering.is_some(),
    "a disjoint replace bridges with a Rescan"
  );
  assert!(coverage_becomes_live(&mut w, &b, "new-ground").await);

  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&a);
  let _ = std::fs::remove_dir_all(&b);
}

/// Suite 8 (privileged, CI: `linux-verify.sh inotify-priv`) — the kernel W1 of
/// docs/2026-07-19-d2-golden-root-binding.md, end to end: an ext4 loopback is
/// unmounted and remounted on the SAME loop device (identity-preserving —
/// `(dev, ino)` of the root survive the cycle while every inotify watch on the
/// superblock is destroyed) RACING a widening `replace_root` onto it. Whatever
/// the interleaving, the witnessed-window commit gate (INV-ROOT) forbids the
/// one dishonest ending — a certified-live widen whose root binding died
/// silently — so a post-cycle write under the old subtree must ALWAYS become
/// observable: delivered by live coverage, or covered by a `Rescan`
/// (domination / the death funnel / the tainted-window fallback bridge).
/// Silence within the deadline is the false-certification class and fails.
///
/// The race is swept across jittered offsets: each iteration is one
/// interleaving sample, and EVERY sample must end honest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn widen_over_unmount_rebind_is_never_silently_certified() {
  use std::process::Command;

  if !privileged_or_skip("widen_over_unmount_rebind_is_never_silently_certified") {
    return;
  }

  // Build a private ext4 loopback pinned to an EXPLICIT loop device, so the
  // remount preserves `st_dev` (an auto-allocated `-o loop` remount could land
  // on a different loop minor and mint a different identity — the W2 shape,
  // not W1's same-identity rebind).
  let image =
    std::env::temp_dir().join(format!("tributary-fs-widen-w1-{}.img", std::process::id()));
  let dd = Command::new("dd")
    .args([
      "if=/dev/zero",
      &format!("of={}", image.display()),
      "bs=1M",
      "count=16",
    ])
    .status();
  if !dd.map(|s| s.success()).unwrap_or(false) {
    eprintln!("SKIP widen_over_unmount_rebind: dd refused");
    return;
  }
  if !Command::new("mkfs.ext4")
    .args(["-q", "-F"])
    .arg(&image)
    .status()
    .map(|s| s.success())
    .unwrap_or(false)
  {
    eprintln!("SKIP widen_over_unmount_rebind: mkfs.ext4 unavailable");
    return;
  }
  let loopdev = match Command::new("losetup")
    .args(["-f", "--show"])
    .arg(&image)
    .output()
  {
    Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
    _ => {
      eprintln!("SKIP widen_over_unmount_rebind: losetup unavailable");
      let _ = std::fs::remove_file(&image);
      return;
    }
  };
  let mount = scratch_root("widen-w1-mnt");
  let mounted = Command::new("mount")
    .arg(&loopdev)
    .arg(&mount)
    .status()
    .map(|s| s.success())
    .unwrap_or(false);
  if !mounted {
    eprintln!("SKIP widen_over_unmount_rebind: loop mount refused");
    let _ = Command::new("losetup").arg("-d").arg(&loopdev).status();
    let _ = std::fs::remove_file(&image);
    return;
  }

  for (round, delay_ms) in [0_u64, 15, 45].into_iter().enumerate() {
    // Fresh layout per round, persisted on the image across the cycle.
    let root = mount.join(format!("w1-{round}"));
    let sub = root.join("sub");
    std::fs::create_dir_all(&sub).expect("layout");
    let mut w = watcher();
    let handle = w.watch(&sub, Interest::all()).await.expect("watch sub");
    assert!(coverage_becomes_live(&mut w, &sub, "birth").await);

    // The race: the widen onto `root` vs the identity-preserving mount cycle.
    let widen = w.replace_root(handle, &root);
    let cycle = {
      let loopdev = loopdev.clone();
      let mount = mount.clone();
      tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(delay_ms));
        // A busy umount (the watcher's fds do not pin it; scratch cwd could)
        // retries briefly; failure to cycle skips the round's race (the widen
        // then just commits normally — a valid, if uninteresting, sample).
        for _ in 0..50 {
          if Command::new("umount")
            .arg(&mount)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
          {
            break;
          }
          std::thread::sleep(Duration::from_millis(20));
        }
        let _ = Command::new("mount").arg(&loopdev).arg(&mount).status();
      })
    };
    let widened = widen.await;
    cycle.await.expect("mount cycle task");

    // Whatever the interleaving produced, the ending must be observable: a
    // probe write under the (re-mounted) old subtree is delivered or covered
    // by a Rescan at it or any ancestor — never silence over dead coverage.
    let probe = sub.join(format!("probe-{round}.txt"));
    let _ = std::fs::write(&probe, b"w1");
    let observed = wait_for(&mut w, |event| covers(event, &probe)).await;
    assert!(
      observed.is_some(),
      "round {round} (widen: {widened:?}): the mount cycle must surface — \
       delivered coverage or a covering Rescan, never silent false-certification"
    );

    let _ = w.close().await;
  }

  let _ = Command::new("umount").arg(&mount).status();
  let _ = Command::new("losetup").arg("-d").arg(&loopdev).status();
  let _ = std::fs::remove_file(&image);
  let _ = std::fs::remove_dir_all(&mount);
}
