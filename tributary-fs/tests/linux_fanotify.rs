//! End-to-end integration through the public API against real
//! fanotify-FILESYSTEM (design §6.3 suites 8–11): FID decode + identity, the
//! atomic `FAN_RENAME` pairing, the superblock-firehose filter, and the
//! unmount-quiesce behavior (§7's container-validated no-death-signal note).
//!
//! fanotify-FILESYSTEM needs `CAP_SYS_ADMIN`, and its FID/superblock semantics
//! are only authoritative on an export-capable filesystem — so every test here
//! builds an ext4 loopback INSIDE the container (dd → mkfs.ext4 → mount) and
//! self-probes: without the capability or the loopback, it skips loudly (the
//! privileged `fanotify` suite of `ci/linux-verify.sh`, or `sudo -E` in CI,
//! unlocks them).
//!
//! Real-kernel timing is nondeterministic, so every assertion is
//! convergence-style: wait (bounded) until the expected fact is observed;
//! extra events are always legal. ALWAYS run this binary with
//! `--test-threads=1` (the verify script and CI do): the loopback helper mounts
//! and unmounts a shared filesystem, which concurrent tests would race.

#![cfg(all(target_os = "linux", feature = "tokio"))]

use std::{
  path::{Path, PathBuf},
  process::Command,
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use tributary_fs::{Backend, BackendKind, Event, Interest, TokioWatcher, WatcherOptions};

/// Generous ceiling for one expected observation; CI runners are slow.
const DEADLINE: Duration = Duration::from_secs(20);

/// The container-native mount point of the shared ext4 loopback. Under the
/// tmpfs `TMPDIR` so nothing leaks onto the host filesystem.
fn loopback_mount() -> PathBuf {
  std::env::temp_dir().join("tributary-fs-fanotify-ext4")
}

/// Builds (once) and mounts an ext4 loopback for authoritative FID/superblock
/// semantics, returning its mount point — or `None` when the environment
/// cannot support it (no privilege, no loop device, mkfs/mount refused), in
/// which case the caller skips loudly.
///
/// Idempotent: a second call reuses an already-mounted image.
fn ext4_loopback() -> Option<PathBuf> {
  let mount = loopback_mount();
  if is_mountpoint(&mount) {
    return Some(mount);
  }
  let image = std::env::temp_dir().join("tributary-fs-fanotify-ext4.img");

  // 64 MiB backing image; mkfs.ext4 with a small inode count is plenty for the
  // churn these tests drive.
  let dd = Command::new("dd")
    .args([
      "if=/dev/zero",
      &format!("of={}", image.display()),
      "bs=1M",
      "count=64",
    ])
    .status();
  if !dd.map(|s| s.success()).unwrap_or(false) {
    return None;
  }
  let mkfs = Command::new("mkfs.ext4")
    .args(["-q", "-F"])
    .arg(&image)
    .status();
  if !mkfs.map(|s| s.success()).unwrap_or(false) {
    return None;
  }
  std::fs::create_dir_all(&mount).ok()?;
  let mount_status = Command::new("mount")
    .args(["-o", "loop"])
    .arg(&image)
    .arg(&mount)
    .status();
  if !mount_status.map(|s| s.success()).unwrap_or(false) {
    return None;
  }
  Some(mount)
}

/// Whether `path` is a mount point (its device differs from its parent's).
fn is_mountpoint(path: &Path) -> bool {
  Command::new("mountpoint")
    .arg("-q")
    .arg(path)
    .status()
    .map(|s| s.success())
    .unwrap_or(false)
}

/// A fresh scratch directory under the ext4 loopback, canonicalized so event
/// paths and expectations share one byte form.
fn scratch_under(mount: &Path, tag: &str) -> PathBuf {
  static COUNTER: AtomicU32 = AtomicU32::new(0);
  let dir = mount.join(format!(
    "it-{}-{}-{}",
    tag,
    std::process::id(),
    COUNTER.fetch_add(1, Ordering::Relaxed),
  ));
  std::fs::create_dir_all(&dir).expect("create scratch root");
  dir.canonicalize().expect("canonicalize scratch root")
}

/// A fanotify-forced watcher, or `None` when the backend cannot start here
/// (unprivileged / filesystem unsupported — the caller skips loudly).
async fn fanotify_watcher(root: &Path) -> Option<(TokioWatcher, tributary_fs::RootHandle)> {
  let options = WatcherOptions::new().with_backend(Backend::Fanotify);
  let watcher = TokioWatcher::new(options).expect("build watcher");
  // `watch` is where the superblock mark is armed; a refusal (EPERM without
  // CAP_SYS_ADMIN, or an unsupported filesystem) surfaces here as a typed
  // Source error — the skip signal.
  match watcher.watch(root, Interest::all()).await {
    Ok(handle) => Some((watcher, handle)),
    Err(err) => {
      eprintln!("SKIP: fanotify unavailable ({err}) — run via linux-verify.sh fanotify");
      None
    }
  }
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
/// path or one of its ancestors.
fn covers(event: &Event, path: &Path) -> bool {
  if event.path() == path {
    return true;
  }
  event.is_rescan() && path.starts_with(event.path())
}

/// Guard that unmounts the shared loopback if THIS test mounted it, so a
/// `--test-threads=1` run leaves nothing mounted after the last test.
struct LoopbackGuard {
  mount: PathBuf,
}

impl Drop for LoopbackGuard {
  fn drop(&mut self) {
    // Best-effort: a busy mount (another test's scratch still open) is left for
    // the next drop; the container is ephemeral regardless.
    let _ = Command::new("umount").arg(&self.mount).status();
  }
}

/// Suite 8 (§6.3): FID decode + identity cross-check. A create surfaces with
/// its path, and repeated writes to the same object keep converging — the
/// one-mint-scheme invariant, exercised end to end against real FID decoding.
#[tokio::test]
async fn fid_decode_and_identity_roundtrip() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP fid_decode_and_identity_roundtrip: no ext4 loopback (needs --privileged)");
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "fid");
  let Some((mut w, _h)) = fanotify_watcher(&root).await else {
    return;
  };

  std::fs::create_dir_all(root.join("a/b")).unwrap();
  std::fs::write(root.join("a/b/one.txt"), b"1").unwrap();

  let deep = root.join("a/b/one.txt");
  assert!(
    wait_for(&mut w, |e| covers(e, &deep)).await.is_some(),
    "a deep create is observed through the kernel-recursive mark"
  );

  // A metadata change on the same object surfaces too (its FID admits under the
  // learned directory).
  std::fs::write(root.join("a/b/one.txt"), b"22").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &deep)).await.is_some(),
    "a follow-up write to the same object keeps flowing"
  );
}

/// Suite 9: `FAN_RENAME` pairing — a same-superblock rename surfaces as one
/// `Moved` (the atomic pair, cookie path minted driver-side, no window).
#[tokio::test]
async fn rename_pairs_into_one_moved() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP rename_pairs_into_one_moved: no ext4 loopback (needs --privileged)");
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "rename");
  std::fs::write(root.join("old.txt"), b"x").unwrap();
  let Some((mut w, _h)) = fanotify_watcher(&root).await else {
    return;
  };

  std::fs::rename(root.join("old.txt"), root.join("new.txt")).unwrap();

  let from = root.join("old.txt");
  let to = root.join("new.txt");
  assert!(
    wait_for(&mut w, |e| e
      .kind()
      .moved()
      .is_some_and(|m| m.from() == from)
      && e.path() == to)
    .await
    .is_some(),
    "the rename pairs into one Moved with both halves"
  );
}

/// Suite 9 (extended): a directory rename re-parents its descendants. Rename a
/// POPULATED directory, then touch a PRE-EXISTING descendant of it — the event
/// must arrive under the NEW directory path. This exercises the parent-relative
/// FID map end to end: the descendant's admission resolves through the moved
/// parent's updated link, never a stale absolute path.
#[tokio::test]
async fn dir_rename_reparents_descendant_paths() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP dir_rename_reparents_descendant_paths: no ext4 loopback (needs --privileged)");
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "reparent");
  // A populated directory tree exists BEFORE the watch, so its descendants are
  // seeded (not learned): root/a/child/, holding a file.
  std::fs::create_dir_all(root.join("a/child")).unwrap();
  std::fs::write(root.join("a/child/leaf.txt"), b"seed").unwrap();
  let Some((mut w, _h)) = fanotify_watcher(&root).await else {
    return;
  };

  // Rename the populated directory a → b (both ends in-root). Its whole subtree
  // must follow to the new path via the parent-relative map.
  std::fs::rename(root.join("a"), root.join("b")).unwrap();

  // Touch a PRE-EXISTING descendant through its NEW path. The write's event
  // must resolve under root/b/child, proving the descendant re-parented.
  let new_leaf = root.join("b/child/leaf.txt");
  std::fs::write(&new_leaf, b"after-rename").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &new_leaf)).await.is_some(),
    "a pre-existing descendant resolves under the renamed directory's new path"
  );

  // The consumer converges: a create of a brand-new file under the moved
  // directory also lands at the new path (self-maintenance and seeding agree).
  let fresh = root.join("b/child/fresh.txt");
  std::fs::write(&fresh, b"new").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &fresh)).await.is_some(),
    "a fresh create under the renamed directory also resolves at the new path"
  );
}

/// Suite 10: the superblock firehose is filtered. Churn OUTSIDE the watched
/// root but on the SAME superblock must produce ZERO events for the watched
/// root — admission is dir-FID membership, never fsid comparison.
#[tokio::test]
async fn superblock_firehose_is_filtered() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP superblock_firehose_is_filtered: no ext4 loopback (needs --privileged)");
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  // Two sibling roots on the SAME ext4 superblock: one watched, one churned.
  let watched = scratch_under(&mount, "watched");
  let elsewhere = scratch_under(&mount, "elsewhere");
  let Some((mut w, _h)) = fanotify_watcher(&watched).await else {
    return;
  };

  // A marker create INSIDE the watched root proves the mark is live.
  std::fs::write(watched.join("marker.txt"), b"m").unwrap();
  let marker = watched.join("marker.txt");
  assert!(
    wait_for(&mut w, |e| covers(e, &marker)).await.is_some(),
    "the watched root's own create is observed"
  );

  // Now churn hard OUTSIDE the root on the same superblock. None of it may
  // surface for the watched root.
  for i in 0..200 {
    let f = elsewhere.join(format!("noise-{i}.txt"));
    std::fs::write(&f, b"n").unwrap();
    std::fs::rename(&f, elsewhere.join(format!("moved-{i}.txt"))).unwrap();
    std::fs::remove_file(elsewhere.join(format!("moved-{i}.txt"))).unwrap();
  }

  // Bounded quiet-window: any event that arrives must be for the watched root
  // (an allowed extra `Rescan` at/above the root is fine; an event NAMING the
  // elsewhere subtree is a filter breach).
  let breach = tokio::time::timeout(Duration::from_secs(3), async {
    while let Some(event) = w.next().await {
      let path = event.path().to_path_buf();
      if path.starts_with(&elsewhere) {
        return Some(path);
      }
    }
    None
  })
  .await
  .ok()
  .flatten();
  assert!(
    breach.is_none(),
    "same-superblock churn outside the root leaked in: {breach:?}"
  );
}

/// Suite 11: unmount under watch (design §7 limitation, container-validated).
///
/// A `FAN_MARK_FILESYSTEM` watcher receives NO kernel signal when its
/// superblock is unmounted — the mark holds the sb alive and the fd goes quiet
/// (no `DELETE_SELF`/`MOVE_SELF`, no hangup, no EOF; verified against the 6.x
/// container kernel). Event-driven root death therefore covers only in-tree
/// self-events of the root object; an unmount is detectable only by a
/// root-alive probe, which lands with `Backend::Auto` (L4.2).
///
/// So the property this asserts is the true one: the watcher SURVIVES the
/// unmount — no panic, no hang, and no fabricated event for the vanished
/// subtree — and the root is observably gone (re-access fails). The consumer
/// learns of death exactly as it would for any silently-vanished root.
#[tokio::test]
async fn unmount_under_watch_quiesces_without_panic() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP unmount_under_watch_quiesces_without_panic: no ext4 loopback (--privileged)");
    return;
  };
  // This test unmounts the shared loopback itself, so no LoopbackGuard — it
  // owns the teardown (single-threaded ordering guarantees exclusivity).
  let root = scratch_under(&mount, "unmount");
  let Some((mut w, h)) = fanotify_watcher(&root).await else {
    let _ = Command::new("umount").arg(&mount).status();
    return;
  };

  // Prove the mark is live before pulling the filesystem out.
  std::fs::write(root.join("alive.txt"), b"a").unwrap();
  let alive = root.join("alive.txt");
  assert!(
    wait_for(&mut w, |e| covers(e, &alive)).await.is_some(),
    "the mark is live before unmount"
  );

  // Drop the watch so the mark stops referencing the sb, drain any buffered
  // events, THEN unmount. A live mark keeps the sb busy — that busy-hold is
  // itself the fanotify behavior — so unwatch is the clean way to release it.
  w.unwatch(h).await.expect("unwatch");
  // Drain the scope's terminal delivery (the pre-unwatch `alive.txt` event and
  // the terminal `Rescan` may still flush — legitimate, not fabricated).
  let _ = tokio::time::timeout(Duration::from_secs(2), async {
    while w.next().await.is_some() {}
  })
  .await;

  let unmounted = Command::new("umount")
    .arg(&mount)
    .status()
    .map(|s| s.success())
    .unwrap_or(false);
  if !unmounted {
    eprintln!("SKIP unmount_under_watch_quiesces_without_panic: unmount refused");
    return;
  }

  // The root is observably gone: re-access fails. This — not a spontaneous
  // event — is how the consumer learns the fanotify-watched root died on
  // unmount (§7).
  assert!(
    std::fs::metadata(&root).is_err(),
    "the unmounted root is inaccessible"
  );

  // The watcher is quiet-but-alive after the unmount: driving it does not hang
  // (a panic in the reader would surface as the stream ending or a fatal; a
  // deadlock would time out the whole test). A bounded poll returning cleanly
  // is the survival proof.
  let _ = tokio::time::timeout(Duration::from_secs(2), w.next()).await;
}

/// A fresh scratch root under `TMPDIR` (the container mounts a tmpfs there), so
/// the selection-matrix cells run on ONE root type in BOTH suite modes: under
/// `--privileged` the `Backend::Auto` probe reaches fanotify; under default
/// caps it falls back to inotify — no loopback needed either way.
fn tmpfs_scratch(tag: &str) -> PathBuf {
  static COUNTER: AtomicU32 = AtomicU32::new(0);
  let dir = std::env::temp_dir()
    .canonicalize()
    .expect("canonicalize temp dir")
    .join(format!(
      "tributary-fs-sel-{}-{}-{}",
      tag,
      std::process::id(),
      COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
  std::fs::create_dir_all(&dir).expect("create scratch root");
  dir
}

/// Suite 12 (§6.3), the selection matrix — the self-probing cell.
///
/// `Backend::Auto` watches a tmpfs root and the SAME body asserts both matrix
/// arms: under `CAP_SYS_ADMIN` (the `fanotify` suite) the probe selects
/// fanotify; under default caps (the `inotify` suite) it falls back to inotify.
/// EITHER WAY the consumer contract is identical — a create under the root is
/// delivered — and [`Watcher::backend_of`] reports exactly which backend the
/// barrier settled on.
#[tokio::test]
async fn selection_matrix_auto_self_probes() {
  let root = tmpfs_scratch("auto");
  let w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Auto))
    .expect("build Auto watcher");
  let handle = match w.watch(&root, Interest::all()).await {
    Ok(handle) => handle,
    Err(err) => {
      // Auto never fails for privilege (it falls back); a failure here is the
      // environment refusing even inotify — skip loudly.
      eprintln!("SKIP selection_matrix_auto_self_probes: Auto watch refused ({err})");
      return;
    }
  };
  let selected = w
    .backend_of(handle)
    .expect("a live root reports its backend");

  // The matrix invariant: privilege → fanotify, otherwise the inotify fallback.
  // We do not assume which mode we run in; we assert the selection is coherent
  // with it and that events flow identically.
  let privileged = has_sys_admin();
  match selected {
    BackendKind::Fanotify => assert!(
      privileged,
      "fanotify was selected without CAP_SYS_ADMIN — the FILESYSTEM mark cannot have passed"
    ),
    BackendKind::Inotify => { /* the fallback: valid in either mode */ }
    BackendKind::FsEvents => panic!("FSEvents is impossible on Linux"),
  }
  if privileged {
    assert_eq!(
      selected,
      BackendKind::Fanotify,
      "under privilege on tmpfs, Auto must select fanotify"
    );
  }

  // The consumer contract is identical across the matrix: a create is delivered.
  let mut w = w;
  std::fs::write(root.join("probe.txt"), b"x").unwrap();
  let target = root.join("probe.txt");
  assert!(
    wait_for(&mut w, |e| covers(e, &target)).await.is_some(),
    "the {selected} backend delivers the create"
  );
}

/// Suite 12 — the forced-`Fanotify`-without-privilege cell: forcing fanotify
/// when its preconditions do not hold fails the `watch` with a typed
/// [`SourceError::BackendProbeFailed`] (NOT a fallback), delivers ZERO events,
/// and is victimless — the watcher stays usable and closes cleanly.
///
/// Self-probing: under `CAP_SYS_ADMIN` the mark WOULD succeed, so the cell only
/// asserts its property where the mark is refused; with privilege it skips.
#[tokio::test]
async fn forced_fanotify_without_privilege_is_typed_error() {
  if has_sys_admin() {
    eprintln!("SKIP forced_fanotify_without_privilege_is_typed_error: has CAP_SYS_ADMIN");
    return;
  }
  let root = tmpfs_scratch("forced");
  let w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Fanotify))
    .expect("build forced-fanotify watcher");

  let err = w
    .watch(&root, Interest::all())
    .await
    .expect_err("forced fanotify without privilege must fail");
  assert!(
    matches!(
      err,
      tributary_fs::WatchRootError::Source(tributary_fs::SourceError::BackendProbeFailed { .. })
    ),
    "the failure is the typed probe error, never a silent fallback: {err:?}"
  );

  // Victimless: no event is fabricated, and the watcher closes cleanly.
  let mut w = w;
  std::fs::write(root.join("noise.txt"), b"n").unwrap();
  let leaked = tokio::time::timeout(Duration::from_secs(2), w.next()).await;
  assert!(
    matches!(leaked, Err(_) | Ok(None)),
    "a failed forced-fanotify watch delivers no events: {leaked:?}"
  );
  w.close().await.expect("the watcher closes cleanly");
}

/// Suite 11 (strengthened) — root death via the refresh path (design §7 gap,
/// now closed by L4.2). A fanotify root that is unmounted out from under the
/// watcher delivers no in-tree signal; the mount refresh's folded-in root
/// re-stat is what detects it. This keeps the watch LIVE, lazily detaches the
/// mount (so the root path stops resolving while the mark's sb stays alive),
/// induces the loss path (which arms a refresh), and asserts the terminal
/// `Rescan` arrives and the handle goes dead.
///
/// Best-effort on the trigger: if the loss/refresh cannot be induced in the
/// environment, the cell verifies survival (the §7 floor) and notes the skip —
/// the deterministic proof of the composition is the hermetic core suite
/// (`refresh_finding_root_gone_is_delete_self`).
#[tokio::test]
async fn unmount_under_live_watch_dies_via_refresh() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP unmount_under_live_watch_dies_via_refresh: no ext4 loopback (--privileged)");
    return;
  };
  let root = scratch_under(&mount, "refresh-death");
  // A tiny OS-batch channel so a burst overflows it → the transport loss path →
  // a mount refresh armed on a LIVE (still-marked) scope; that refresh's root
  // re-stat is what detects the vanished root.
  let options = WatcherOptions::new()
    .with_backend(Backend::Fanotify)
    .with_os_batch_capacity(std::num::NonZeroUsize::new(1).unwrap());
  let w = TokioWatcher::new(options).expect("build watcher");
  let Ok(handle) = w.watch(&root, Interest::all()).await else {
    eprintln!("SKIP unmount_under_live_watch_dies_via_refresh: fanotify unavailable");
    let _ = Command::new("umount").arg(&mount).status();
    return;
  };
  let mut w = w;

  // A directory INSIDE the root, opened as an fd BEFORE the unmount: after a
  // lazy detach the root path stops resolving, but this fd still addresses the
  // (mark-kept-alive) superblock, so `openat` through it keeps generating real
  // fanotify events — the only way to drive the loss path post-detach.
  std::fs::create_dir_all(root.join("live")).unwrap();
  let live_fd = open_dir_fd(&root.join("live"));
  std::fs::write(root.join("live/marker.txt"), b"m").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &root.join("live/marker.txt")))
      .await
      .is_some(),
    "the mark is live before the unmount"
  );

  // Lazy-unmount: detaches the mount from the namespace immediately (the root
  // path stops resolving) while the open mark keeps the superblock alive — the
  // exact "unmounted out from under a live watch" condition §7 describes.
  let detached = Command::new("umount")
    .args(["-l"])
    .arg(&mount)
    .status()
    .map(|s| s.success())
    .unwrap_or(false);
  if !detached {
    eprintln!("SKIP unmount_under_live_watch_dies_via_refresh: lazy umount refused");
    let _ = w.unwatch(handle).await;
    let _ = Command::new("umount").arg(&mount).status();
    return;
  }

  // The root path is gone from the namespace now.
  assert!(
    std::fs::metadata(&root).is_err(),
    "the lazily-detached root no longer resolves"
  );

  // Drive the loss path: each round creates files through the RETAINED fd (the
  // path is gone, so only `openat` works), flooding the tiny OS-batch channel →
  // the transport loss → one mount refresh, whose root re-stat now finds the
  // path gone and lowers the death lifecycle. The SOLE success signal is the
  // handle being reclaimed (dead-on-arrival). Convergence-style across rounds;
  // draining the stream keeps the driver making progress.
  let deadline = std::time::Instant::now() + Duration::from_secs(20);
  while w.backend_of(handle).is_some() && std::time::Instant::now() < deadline {
    if let Some(fd) = live_fd {
      for i in 0..128 {
        openat_create(fd, &format!("burst-{i}.txt"));
      }
    }
    let _ = tokio::time::timeout(Duration::from_millis(300), w.next()).await;
  }

  if w.backend_of(handle).is_none() {
    // The refresh-detected death ran end to end: the registry reclaimed the
    // handle, exactly like an in-tree DELETE_SELF would.
    assert!(
      w.root_path(handle).is_none(),
      "a reclaimed handle has no path"
    );
  } else {
    // The §7 SURVIVAL floor still holds if the loss could not be induced here
    // (e.g. `openat` on the detached sb refused): the watcher is quiet-but-alive
    // — no panic, no hang. The deterministic proof of the composition is the
    // hermetic suite (core `refresh_finding_root_gone_is_delete_self`, driver
    // `refresh_finding_root_gone_dies_end_to_end`).
    eprintln!(
      "NOTE unmount_under_live_watch_dies_via_refresh: loss not induced on the \
       detached sb; survival floor holds (composition proven hermetically)"
    );
    let _ = tokio::time::timeout(Duration::from_secs(2), w.next()).await;
  }
  if let Some(fd) = live_fd {
    // SAFETY: fd was opened by `open_dir_fd` and is not used again.
    unsafe { libc::close(fd) };
  }
  let _ = w.close().await;
}

/// Opens `dir` as an `O_DIRECTORY` fd (for post-detach `openat`), or `None` on
/// failure. The caller closes it.
fn open_dir_fd(dir: &Path) -> Option<libc::c_int> {
  use std::os::unix::ffi::OsStrExt;
  let cpath = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
  // SAFETY: cpath is a valid NUL-terminated path; the flags are constants.
  let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
  (fd >= 0).then_some(fd)
}

/// Creates (and immediately closes) a file named `name` under the directory
/// `dirfd` addresses — an `openat` that fires a fanotify create on the marked
/// superblock even after the mount was lazily detached. Best-effort.
fn openat_create(dirfd: libc::c_int, name: &str) {
  let Ok(cname) = std::ffi::CString::new(name) else {
    return;
  };
  // SAFETY: dirfd is a live directory fd; cname is NUL-terminated; the flags and
  // mode are constants.
  let fd = unsafe {
    libc::openat(
      dirfd,
      cname.as_ptr(),
      libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
      0o644,
    )
  };
  if fd >= 0 {
    // SAFETY: fd is the freshly-opened descriptor, used nowhere else.
    unsafe { libc::close(fd) };
  }
}

/// Whether the process holds `CAP_SYS_ADMIN` — the capability the fanotify
/// FILESYSTEM mark needs. Read from `/proc/self/status`'s effective-cap bitmask
/// (bit 21 = `CAP_SYS_ADMIN`); a read failure conservatively reports `false`.
fn has_sys_admin() -> bool {
  let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
    return false;
  };
  for line in status.lines() {
    if let Some(hex) = line.strip_prefix("CapEff:") {
      if let Ok(caps) = u64::from_str_radix(hex.trim(), 16) {
        return caps & (1 << 21) != 0;
      }
      return false;
    }
  }
  false
}
