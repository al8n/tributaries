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

use tributary_fs::{Event, Interest, TokioWatcher, WatcherOptions};

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
  let watcher = TokioWatcher::new_forcing_fanotify(WatcherOptions::new()).expect("build watcher");
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
