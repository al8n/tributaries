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

// not(miri): drives real fanotify/statx syscalls, an ext4 loopback, and a tokio
// runtime — none of which miri can execute. Sans-I/O logic lives in the lib tests.
#![cfg(all(target_os = "linux", feature = "tokio", not(miri)))]

use std::{
  path::{Path, PathBuf},
  process::Command,
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
  },
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

/// Suite 9 (boundary move-in) — the completeness invariant at the rename site. A
/// POPULATED directory created OUTSIDE the watched root (same superblock) is
/// `mv`'d INTO the root; fanotify synthesizes no per-descendant creates for the
/// rename, so unless the reader walks the moved subtree in, a mutation of a
/// PRE-EXISTING nested descendant would hit an unmapped FID and drop as
/// outside-root. The property: after the move-in, touching a pre-existing nested
/// descendant file is DELIVERED, path-correct under the new location.
#[tokio::test]
async fn move_in_populated_dir_delivers_descendant_events() {
  let Some(mount) = ext4_loopback() else {
    eprintln!(
      "SKIP move_in_populated_dir_delivers_descendant_events: no ext4 loopback (--privileged)"
    );
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "movein");
  // A sibling staging area on the SAME superblock but OUTSIDE the watched root,
  // so its subtree is never seeded by the spawn walk.
  let outside = scratch_under(&mount, "movein-src");
  // A populated tree built OUTSIDE the root: outside/incoming/nested/deep.txt.
  let src = outside.join("incoming");
  std::fs::create_dir_all(src.join("nested")).unwrap();
  std::fs::write(src.join("nested/deep.txt"), b"seed").unwrap();

  let Some((mut w, _h)) = fanotify_watcher(&root).await else {
    return;
  };
  // Prove the mark is live before the boundary move.
  std::fs::write(root.join("alive.txt"), b"a").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &root.join("alive.txt")))
      .await
      .is_some(),
    "the mark is live before the move-in"
  );

  // Move the populated directory INTO the root: root/incoming now holds the
  // pre-existing nested/deep.txt the spawn walk never saw.
  std::fs::rename(&src, root.join("incoming")).unwrap();

  // Mutate the PRE-EXISTING nested descendant through its NEW path. Without the
  // move-in subtree walk, root/incoming/nested is an unmapped directory and this
  // event drops as outside-root; with it, the event is delivered path-correct.
  let deep = root.join("incoming/nested/deep.txt");
  std::fs::write(&deep, b"after-move-in").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &deep)).await.is_some(),
    "a pre-existing nested descendant of a moved-in directory is observed under its new path"
  );
  let _ = w.close().await;
}

/// Suite 9 (boundary move-in, burst) — a populated directory `mv`'d INTO the root
/// then IMMEDIATELY `mv`'d again in-root, with NO wait between the two renames, so
/// the reader may see both in one batch BEFORE the move-in subtree walk runs. The
/// pre-fix hole: the first walk read the already-vanished first destination as an
/// empty success, and the second (in-root) rename saw the now-known FID and
/// skipped the walk — leaving the moved directory's pre-existing descendants blind
/// FOREVER, with no loss signal.
///
/// Best-effort by nature (the batch boundary is timing-dependent): the property is
/// COVERAGE-HONESTY, not a specific delivery. Either the descendant event is
/// delivered directly (the walk rebased to the final destination) OR a `Rescan`
/// covering it arrives (the reader classified the stale walk as incomplete and
/// escalated, so the consumer re-enumerates and finds the descendant) — both are
/// accepted by `covers`. Only the silent-drop the fix removes would time out here.
#[tokio::test]
async fn burst_move_in_then_reparent_is_coverage_honest() {
  let Some(mount) = ext4_loopback() else {
    eprintln!(
      "SKIP burst_move_in_then_reparent_is_coverage_honest: no ext4 loopback (--privileged)"
    );
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "burst");
  let outside = scratch_under(&mount, "burst-src");
  // A populated tree built OUTSIDE the root: outside/incoming/nested/deep.txt.
  let src = outside.join("incoming");
  std::fs::create_dir_all(src.join("nested")).unwrap();
  std::fs::write(src.join("nested/deep.txt"), b"seed").unwrap();

  let Some((mut w, _h)) = fanotify_watcher(&root).await else {
    return;
  };
  std::fs::write(root.join("alive.txt"), b"a").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &root.join("alive.txt")))
      .await
      .is_some(),
    "the mark is live before the burst"
  );

  // The burst: move IN to root/a, then IMMEDIATELY in-root to root/b — no wait, so
  // both renames may land in one read batch before the deferred walk runs.
  std::fs::rename(&src, root.join("a")).unwrap();
  std::fs::rename(root.join("a"), root.join("b")).unwrap();

  // Mutate the pre-existing nested descendant under its FINAL path. The event must
  // be delivered OR covered by a rescan — never silently dropped.
  let deep = root.join("b/nested/deep.txt");
  std::fs::write(&deep, b"after-burst").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &deep)).await.is_some(),
    "after a move-in-then-reparent burst, a nested descendant is delivered or rescan-covered — \
     never silently blind"
  );
  let _ = w.close().await;
}

/// Suite 9 (boundary move-out twin) — a POPULATED in-root directory `mv`'d OUT of
/// the root stops admitting its descendants: after the move-out, mutating its old
/// nested descendant delivers NO event and never emits a stale in-root path. The
/// parent-relative representation re-parents the top onto an absent parent, so
/// every descendant's walk breaks and evicts lazily.
#[tokio::test]
async fn move_out_populated_dir_stops_descendant_events() {
  let Some(mount) = ext4_loopback() else {
    eprintln!(
      "SKIP move_out_populated_dir_stops_descendant_events: no ext4 loopback (--privileged)"
    );
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "moveout");
  let outside = scratch_under(&mount, "moveout-dst");
  // A populated tree built INSIDE the root BEFORE the watch, so it is seeded:
  // root/leaving/nested/deep.txt.
  let inside = root.join("leaving");
  std::fs::create_dir_all(inside.join("nested")).unwrap();
  std::fs::write(inside.join("nested/deep.txt"), b"seed").unwrap();

  let Some((mut w, _h)) = fanotify_watcher(&root).await else {
    return;
  };
  // Prove the seeded descendant is live IN-ROOT before the move-out.
  let in_root_deep = inside.join("nested/deep.txt");
  std::fs::write(&in_root_deep, b"before-move-out").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &in_root_deep))
      .await
      .is_some(),
    "the seeded descendant is observed while still in-root"
  );

  // Move the populated directory OUT of the root, then mutate its old descendant
  // at the NEW (out-of-root) location.
  let moved = outside.join("leaving");
  std::fs::rename(&inside, &moved).unwrap();
  let moved_deep = moved.join("nested/deep.txt");
  std::fs::write(&moved_deep, b"after-move-out").unwrap();

  // The move-out of `leaving` itself is a legitimate boundary event (the in-root
  // source end lowers to a located rescan / a self-event on the moved directory),
  // so an event NAMING `leaving` is expected and allowed. What must NOT leak is a
  // DESCENDANT event: after the move-out, the seeded `leaving/nested` subtree
  // stops admitting, so mutating `nested/deep.txt` at either the stale old path or
  // the new out-of-root path delivers nothing. The breach is a path reaching into
  // the `nested` descendant (strictly deeper than the moved directory).
  let old_nested = inside.join("nested");
  let new_nested = moved.join("nested");
  let breach = tokio::time::timeout(Duration::from_secs(3), async {
    while let Some(event) = w.next().await {
      let path = event.path().to_path_buf();
      if path.starts_with(&old_nested) || path.starts_with(&new_nested) {
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
    "a moved-out directory's descendant leaked an event: {breach:?}"
  );
  let _ = w.close().await;
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

/// Suite 10 (scope-fence, static) — a symlink PLACED INSIDE the watched root
/// before the watch, pointing at an outside-root same-superblock directory, must
/// never make the seed walk admit that outside directory. The walk pins every
/// directory as an `O_NOFOLLOW` fd and reads/opens children fd-relative, so a
/// symlink is never followed and the outside target's FID never seeds the map —
/// churn inside the outside directory (reached through the in-root symlink or
/// directly) produces ZERO events for the watched root.
///
/// This is the deterministic guard for the objects-not-paths invariant; the
/// racing twin below exercises the swap-after-listing window the fd-relative walk
/// closes.
#[tokio::test]
async fn in_root_symlink_to_outside_dir_is_never_admitted() {
  let Some(mount) = ext4_loopback() else {
    eprintln!(
      "SKIP in_root_symlink_to_outside_dir_is_never_admitted: no ext4 loopback (--privileged)"
    );
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "symlink-fence");
  // An outside-root directory on the SAME superblock, holding a pre-existing
  // nested subtree the walk must never learn.
  let outside = scratch_under(&mount, "symlink-fence-target");
  std::fs::create_dir_all(outside.join("nested")).unwrap();
  // A symlink INSIDE the root pointing at that outside directory, placed BEFORE
  // the watch so the seed walk encounters it as a listed entry.
  let link = root.join("into-outside");
  std::os::unix::fs::symlink(&outside, &link).unwrap();

  let Some((mut w, _h)) = fanotify_watcher(&root).await else {
    return;
  };
  // Prove the mark is live before the churn.
  std::fs::write(root.join("alive.txt"), b"a").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &root.join("alive.txt")))
      .await
      .is_some(),
    "the mark is live before the symlink-fence churn"
  );

  // Churn hard inside the OUTSIDE directory — both directly and through the
  // in-root symlink path. If the walk had followed the symlink and admitted the
  // outside subtree, these would deliver as in-root; the fd-relative walk never
  // admitted it, so none may.
  for i in 0..200 {
    let direct = outside.join("nested").join(format!("d-{i}.txt"));
    std::fs::write(&direct, b"n").unwrap();
    std::fs::remove_file(&direct).unwrap();
    // Also mutate via the in-root symlink path: writing `root/into-outside/x`
    // resolves (through the symlink) to the outside directory. The EVENT the
    // kernel reports is keyed on the outside directory's FID, which is unmapped,
    // so it must drop — never surface under the in-root symlink path.
    let via_link = link.join(format!("l-{i}.txt"));
    std::fs::write(&via_link, b"n").unwrap();
    std::fs::remove_file(&via_link).unwrap();
  }

  // No event may name anything under the outside directory OR under the in-root
  // symlink path (an admitted outside subtree would leak either form).
  let breach = tokio::time::timeout(Duration::from_secs(3), async {
    while let Some(event) = w.next().await {
      let path = event.path().to_path_buf();
      if path.starts_with(&outside) || path.starts_with(&link) {
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
    "an in-root symlink to an outside directory leaked an event (the walk followed it): {breach:?}"
  );
  let _ = w.close().await;
}

/// Suite 10 (scope-fence, RACE) — the reviewer's best-effort: a seed walk over a
/// deep in-root tree racing a swap loop that repeatedly `mv`s an in-root directory
/// away and drops a symlink to an OUTSIDE-root same-superblock directory in its
/// place. The pre-fix hole classified an entry by `d_type`, then did every later
/// step (`symlink_metadata`, `name_to_handle_at`, `read_dir`) by RECONSTRUCTED
/// PATHNAME — so a swap landing AFTER the classification redirected the handle
/// read and the descent OUTSIDE the root, seeding a foreign directory FID; since
/// the FILESYSTEM mark covers the whole superblock, every later event under that
/// outside subtree then delivered as in-root. The fd-relative walk pins each
/// directory `O_NOFOLLOW` and opens children relative to the parent fd, so a
/// swapped-in symlink fails the open (`ELOOP`/`ENOTDIR`) and its target is never
/// descended.
///
/// Best-effort by nature (winning the swap window is timing-dependent): the
/// property is SCOPE-FENCE HONESTY, asserted after the churn settles. A genuinely
/// raced walk either skipped the swapped entry (fd-relative — the honest outcome)
/// or, had it gone incomplete, escalated to fatal → Auto's next `watch` re-selects
/// — both leave NO foreign admission. So the assertion is one-sided: churn inside
/// the outside directory after the walk settles must deliver ZERO in-root events
/// naming it. Only the silent foreign admission the fix removes would surface one.
#[tokio::test]
async fn racing_swap_to_outside_dir_never_admits_foreign_subtree() {
  let Some(mount) = ext4_loopback() else {
    eprintln!(
      "SKIP racing_swap_to_outside_dir_never_admits_foreign_subtree: no ext4 loopback (--privileged)"
    );
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  // The outside-root target the swap loop points its symlinks at, with a
  // pre-existing nested subtree that must never become in-root.
  let outside = scratch_under(&mount, "race-target");
  std::fs::create_dir_all(outside.join("nested")).unwrap();

  // Run several racing attempts: each builds a fresh deep in-root tree, then
  // spawns a swap loop (mv the mid-tree directory away + symlink the outside dir
  // in its place) WHILE the watch's seed walk runs. Winning the window is
  // probabilistic, so repeat — any single admission would be caught.
  for attempt in 0..8u32 {
    let root = scratch_under(&mount, &format!("race-{attempt}"));
    // A deep tree so the walk spends time descending: root/a/b/c/d/e with a
    // `swap` directory partway down that the loop yanks.
    let deep = root.join("a/b/c/d/e");
    std::fs::create_dir_all(&deep).unwrap();
    let swap = root.join("a/b/swap");
    std::fs::create_dir_all(swap.join("inner")).unwrap();
    let moved_away = root.join("a/b/swap-moved");
    let target = outside.clone();

    // The swap loop: repeatedly rename `swap` away and drop a symlink to the
    // outside dir in its place, then restore — churning the exact directory the
    // walk may be about to classify-then-path-resolve. Clone the paths into the
    // thread so `swap` stays available for the post-join cleanup below.
    let swap_in_thread = swap.clone();
    let swap_thread = std::thread::spawn(move || {
      for _ in 0..400 {
        let _ = std::fs::rename(&swap_in_thread, &moved_away);
        let _ = std::os::unix::fs::symlink(&target, &swap_in_thread);
        // Undo so the tree is walkable again for the next attempt's shape.
        let _ = std::fs::remove_file(&swap_in_thread);
        let _ = std::fs::rename(&moved_away, &swap_in_thread);
      }
    });

    // Start the watch DURING the swap churn (its seed walk races the loop).
    let watcher = fanotify_watcher(&root).await;
    let _ = swap_thread.join();
    let Some((mut w, _h)) = watcher else {
      // fanotify unavailable — the whole cell can only run privileged.
      return;
    };

    // Let the swap settle to a stable state and prove the mark is live.
    let _ = std::fs::remove_file(&swap);
    let _ = std::fs::create_dir_all(swap.join("inner"));
    std::fs::write(root.join("alive.txt"), b"a").unwrap();
    let _ = wait_for(&mut w, |e| covers(e, &root.join("alive.txt"))).await;

    // Now churn inside the OUTSIDE directory. If any racing swap had seeded the
    // outside dir's FID into the map, these would deliver as in-root under the
    // swapped path — the silent foreign admission the fix removes.
    for i in 0..100 {
      let f = outside.join("nested").join(format!("r-{attempt}-{i}.txt"));
      std::fs::write(&f, b"n").unwrap();
      std::fs::remove_file(&f).unwrap();
    }

    let breach = tokio::time::timeout(Duration::from_secs(2), async {
      while let Some(event) = w.next().await {
        let path = event.path().to_path_buf();
        // A leak is an event whose path reaches into the outside directory — the
        // foreign subtree that must never have been admitted. (Events naming the
        // in-root `swap` path itself are legitimate: it is a real in-root object.)
        if path.starts_with(&outside) {
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
      "a racing swap seeded a foreign outside subtree (attempt {attempt}): {breach:?}"
    );
    let _ = w.close().await;
  }
}

/// Suite 12 (spawn pin, RACE) — the best-effort race guard for the ROOT-PATH
/// swap the spawn pin closes. Marking the superblock via `AT_FDCWD` + the
/// canonical root PATHNAME let a symlink swapped in at the root path for that one
/// `fanotify_mark` call mark the WRONG superblock, and since every later check
/// re-read the restored path, the source went live with a complete FID map for
/// the intended root while the kernel fd listened elsewhere — no events, no
/// overflow, no death. Pinning the root once (`openat2 RESOLVE_NO_SYMLINKS`) and
/// marking fd-relative on the pin makes a swap in that window fail the pin typed
/// rather than aim the mark at another superblock.
///
/// The property is HONESTY under the race: for every `Backend::Auto` spawn that
/// returns a live watcher, a marker written under the watched root MUST be
/// delivered within the deadline — OR the spawn must have failed. The one outcome
/// the fix forbids is a live-but-listening-elsewhere source: a live handle whose
/// root's own writes never surface. Best-effort by nature (winning the swap window
/// is timing-dependent), so it repeats; a single blind live handle fails it.
#[tokio::test]
async fn racing_root_path_swap_never_goes_live_listening_elsewhere() {
  let Some(mount) = ext4_loopback() else {
    eprintln!(
      "SKIP racing_root_path_swap_never_goes_live_listening_elsewhere: no ext4 loopback (--privileged)"
    );
    return;
  };
  if !has_sys_admin() {
    // Without CAP_SYS_ADMIN Auto never reaches the fanotify mark (it falls back
    // to inotify), so the mark-on-wrong-sb window this cell targets cannot arise.
    eprintln!(
      "SKIP racing_root_path_swap_never_goes_live_listening_elsewhere: no CAP_SYS_ADMIN (Auto would pick inotify)"
    );
    return;
  }
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  // An OTHER local directory on the SAME superblock the swap points the root
  // symlink at — if the mark ever landed here, writes under the true root would
  // go silent (the blind bug).
  let other = scratch_under(&mount, "root-swap-other");
  std::fs::create_dir_all(&other).unwrap();

  for attempt in 0..10u32 {
    // A parent holding the root under a STABLE name the loop swaps: `parent/root`
    // is a real directory, repeatedly renamed away and replaced by a symlink to
    // `other`, then restored — the exact canonical-root path swap the mark once
    // raced.
    let parent = scratch_under(&mount, &format!("root-swap-{attempt}"));
    let root = parent.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let moved_away = parent.join("root-moved");
    let target = other.clone();
    let root_in_thread = root.clone();

    let swap_thread = std::thread::spawn(move || {
      for _ in 0..300 {
        let _ = std::fs::rename(&root_in_thread, &moved_away);
        let _ = std::os::unix::fs::symlink(&target, &root_in_thread);
        let _ = std::fs::remove_file(&root_in_thread);
        let _ = std::fs::rename(&moved_away, &root_in_thread);
      }
    });

    // Spawn Auto DURING the swap churn: its canonicalize→pin→mark sequence races
    // the loop. Either the pin lands on the true root, or a swap makes the pin
    // (RESOLVE_NO_SYMLINKS) refuse typed — never a mark on `other`'s superblock.
    let watcher = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Auto))
      .expect("build Auto watcher");
    let watched = watcher.watch(&root, Interest::all()).await;
    let _ = swap_thread.join();

    // Restore a stable real root so the marker write and its delivery are
    // deterministic once the churn is over.
    let _ = std::fs::remove_file(&root);
    let _ = std::fs::rename(parent.join("root-moved"), &root);
    if !std::fs::metadata(&root)
      .map(|m| m.is_dir())
      .unwrap_or(false)
    {
      let _ = std::fs::remove_dir_all(&root);
      std::fs::create_dir_all(&root).unwrap();
    }

    let handle = match watched {
      // A live watcher MUST see its own root's writes — else it is the blind bug.
      Ok(handle) => handle,
      // Any typed error is the OTHER legal outcome — nothing went live, so nothing
      // can be blind. A raced swap can surface as the pin's `RESOLVE_NO_SYMLINKS`
      // refusal (a `Source` error) OR as `NotFound`/`NotADirectory` when the swap
      // caught the earlier canonicalize; all are honest. The one thing forbidden is
      // the watcher having silently died (`Closed`) — the raced spawn must fail
      // cleanly and leave it usable.
      Err(err) => {
        assert!(
          !matches!(err, tributary_fs::WatchRootError::Closed),
          "a raced spawn must fail typed and leave the watcher usable, never Closed \
           (attempt {attempt}): {err:?}"
        );
        let _ = std::fs::remove_dir_all(&parent);
        continue;
      }
    };

    // The watcher is live. The invariant a live source must satisfy: a write under
    // the root IT REPORTS must be delivered. If the mark had landed on `other`'s
    // superblock (the pre-fix breach) while the reported root stayed the intended
    // one, this write under the reported root would never surface — precisely the
    // blindness the pin forbids. (If canonicalize legitimately resolved the root
    // symlink to `other`, the reported root IS `other` and the write there is
    // delivered — also correct.) `root_path` returning the intended root but its
    // writes going silent is the exact failure signature.
    let watched_root = watcher.root_path(handle).unwrap_or_else(|| root.clone());
    let mut watcher = watcher;
    let marker = watched_root.join(format!("marker-{attempt}.txt"));
    std::fs::create_dir_all(&watched_root).unwrap();
    std::fs::write(&marker, b"m").unwrap();
    let delivered = wait_for(&mut watcher, |e| covers(e, &marker))
      .await
      .is_some();
    assert!(
      delivered,
      "a live Auto watcher delivered NO event for a write under its own reported root \
       (attempt {attempt}, reported root {watched_root:?}) — a source went live listening elsewhere"
    );
    let _ = watcher.close().await;
    let _ = std::fs::remove_dir_all(&parent);
  }
  let _ = std::fs::remove_dir_all(&other);
}

/// Suite 12 (reseed root pin, RACE) — the best-effort guard for a ROOT REPLACED at
/// its path while watched. A live reseed (loss → full re-walk) re-opens the root by
/// PATH; `RESOLVE_NO_SYMLINKS` stops a symlink swap, but a PLAIN same-superblock
/// directory swapped in at the root path (mv the root away + mkdir the same name)
/// opens and exports a handle just like the true root — so a reseed that did not
/// re-verify would rebind the LIVE admission map to the REPLACEMENT tree, delivering
/// the replacement's events as in-root and dropping the original root's forever,
/// with no death. Verifying the reopened handle against the spawn anchor makes such
/// a reseed a failed attempt (retry → blind → fatal), the terminal the replaced-root
/// machinery owes.
///
/// The property is HONESTY under the replacement, asserted one-sided like the other
/// race cells: after the root is replaced at its path, an event inside the
/// REPLACEMENT tree must NEVER be delivered as in-root. The watcher may die
/// terminally (the anchor-mismatch reseed OR the periodic liveness refresh, whose
/// root re-stat finds a different `(dev,ino)`, lowers the death lifecycle) or keep
/// delivering only pre-replacement truth — both are correct. The one outcome
/// forbidden is a live handle delivering the replacement subtree's events. A short
/// liveness interval bounds the refresh-death arm; heavy churn best-effort provokes
/// a loss to exercise the reseed arm.
#[tokio::test]
async fn racing_root_replacement_never_reseeds_onto_the_replacement() {
  let Some(mount) = ext4_loopback() else {
    eprintln!(
      "SKIP racing_root_replacement_never_reseeds_onto_the_replacement: no ext4 loopback (--privileged)"
    );
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };

  for attempt in 0..6u32 {
    // A parent holding the watched root under a STABLE name: `parent/root`. The
    // replacement swaps the whole directory object out (mv away + mkdir same name),
    // so the path stays valid but names a DIFFERENT same-superblock directory.
    let parent = scratch_under(&mount, &format!("root-replace-{attempt}"));
    let root = parent.join("root");
    std::fs::create_dir_all(&root).unwrap();

    // A short liveness interval so the refresh-death arm is reachable inside the
    // deadline; the reseed arm needs only that a loss fire while replaced.
    let options = WatcherOptions::new()
      .with_backend(Backend::Fanotify)
      .with_root_liveness_interval(Duration::from_millis(300));
    let w = TokioWatcher::new(options).expect("build watcher");
    let Ok(handle) = w.watch(&root, Interest::all()).await else {
      eprintln!(
        "SKIP racing_root_replacement_never_reseeds_onto_the_replacement: fanotify unavailable"
      );
      return;
    };
    let mut w = w;

    // Prove the mark is live on the ORIGINAL root before the replacement.
    std::fs::write(root.join("alive.txt"), b"a").unwrap();
    assert!(
      wait_for(&mut w, |e| covers(e, &root.join("alive.txt")))
        .await
        .is_some(),
      "the mark is live on the original root before the replacement (attempt {attempt})"
    );

    // Replace the root object at its path: mv the original away, mkdir a fresh
    // directory under the same name. `replacement` is a DISTINCT same-superblock
    // directory; anything created inside it is replacement-only truth.
    let moved_away = parent.join("root-original");
    std::fs::rename(&root, &moved_away).unwrap();
    std::fs::create_dir(&root).unwrap();

    // Churn hard inside the REPLACEMENT to (best-effort) provoke a loss AND to give
    // the reseed something foreign to (wrongly) admit. `replacement_marker` is the
    // canary: if any of this ever delivers as in-root, the map rebound onto the
    // replacement — the breach the fix removes.
    let replacement_dir = root.join("replacement-subtree");
    std::fs::create_dir_all(&replacement_dir).unwrap();
    for i in 0..500 {
      let f = replacement_dir.join(format!("noise-{i}.txt"));
      let _ = std::fs::write(&f, b"n");
      let _ = std::fs::remove_file(&f);
    }
    let replacement_marker = replacement_dir.join("canary.txt");
    std::fs::write(&replacement_marker, b"c").unwrap();

    // The one forbidden outcome: an event NAMING the replacement subtree delivered
    // as in-root. A dead handle (stream ended / terminal) is legal; a live handle
    // delivering only the pre-replacement `alive.txt` or a terminal `Rescan` is
    // legal. A path reaching into `replacement-subtree` is the breach.
    let breach = tokio::time::timeout(Duration::from_secs(3), async {
      while let Some(event) = w.next().await {
        let path = event.path().to_path_buf();
        if path.starts_with(&replacement_dir) {
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
      "a root-replacement reseed rebound the live map onto the replacement subtree \
       (attempt {attempt}): {breach:?}"
    );

    // The handle is either dead (the honest terminal) or still bound to the original
    // root — never silently rebound. Both are accepted; we only forbade foreign
    // delivery above. Clean up regardless.
    let _ = w.unwatch(handle).await;
    let _ = w.close().await;
    let _ = std::fs::remove_dir_all(&parent);
  }
}

/// Suite 12 (move-in subtree pin, RACE) — the best-effort guard for a MOVED-IN
/// DIRECTORY REPLACED at its path before its deferred walk runs. A populated
/// directory moved INTO the root is learned under its FID as `pending_walk`; the
/// reader then walks
/// its pre-existing descendants in, resolving the moved dir's CURRENT path through
/// the map and re-opening it by PATH. `RESOLVE_NO_SYMLINKS` stops a symlink swap,
/// but a PLAIN same-superblock directory swapped in at that resolved path (mv the
/// moved-in dir away + mkdir the same name before the deferred walk runs) opens and
/// exports a handle — so the pre-fix walk would seed the REPLACEMENT's PRE-EXISTING
/// descendants under the moved dir's FID: a foreign subtree admitted under the
/// moved-in identity, AND — because it seeds the wrong descendants — the TRUE moved
/// dir's own pre-existing descendant left unmapped and BLIND. Verifying the reopened
/// directory's handle against the learned FID makes such a walk `Incomplete` (→
/// retry → fatal), so the walk either maps the genuine descendants or the scope dies
/// and Auto re-selects — never a silent wrong-tree seed.
///
/// Best-effort by nature (winning the pre-walk window is timing-dependent), so it
/// repeats, restoring the GENUINE moved dir (with its pre-existing `nested/deep.txt`)
/// after the race so the assertion is deterministic. The property is COVERAGE
/// HONESTY, expressed like [`burst_move_in_then_reparent_is_coverage_honest`]:
/// mutating the true pre-existing descendant is delivered directly (the walk mapped
/// the genuine subtree) OR a `Rescan` covers it (the walk re-opened a replacement,
/// went `Incomplete`, and the death→re-enumerate path recovered it) — both accepted
/// by `covers`. A pre-fix wrong-tree seed leaves the true descendant blind and never
/// rescanned, so this times out: the exact silent foreign admission the fix removes.
#[tokio::test]
async fn racing_moved_in_replacement_is_coverage_honest() {
  let Some(mount) = ext4_loopback() else {
    eprintln!(
      "SKIP racing_moved_in_replacement_is_coverage_honest: no ext4 loopback (--privileged)"
    );
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };

  for attempt in 0..8u32 {
    let root = scratch_under(&mount, &format!("movein-replace-{attempt}"));
    let outside = scratch_under(&mount, &format!("movein-replace-src-{attempt}"));
    // The GENUINE populated tree built OUTSIDE the root (same superblock): its
    // pre-existing descendant `nested/deep.txt` gets NO create event on the move-in
    // (fanotify synthesizes none for a rename), so it is mapped ONLY if the deferred
    // walk re-opens the true moved dir. A wrong-tree seed leaves it blind.
    let src = outside.join("incoming");
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::write(src.join("nested/deep.txt"), b"seed").unwrap();

    let Some((mut w, _h)) = fanotify_watcher(&root).await else {
      // fanotify unavailable — the whole cell can only run privileged.
      return;
    };
    std::fs::write(root.join("alive.txt"), b"a").unwrap();
    assert!(
      wait_for(&mut w, |e| covers(e, &root.join("alive.txt")))
        .await
        .is_some(),
      "the mark is live before the move-in race (attempt {attempt})"
    );

    // A swap loop that (best-effort) replaces the moved-in dir at its destination
    // path out from under the deferred subtree walk: mv the just-arrived dir away
    // and mkdir a fresh same-superblock REPLACEMENT holding a DISTINCT pre-existing
    // descendant, then restore the genuine dir. If the walk re-opens a replacement,
    // the pre-fix seed would map the replacement's descendant under the moved dir's
    // FID and miss the true `nested`; the fix's handle-verification rejects it.
    let dest = root.join("incoming");
    let dest_in_thread = dest.clone();
    let stolen = root.join("incoming-stolen");
    let stolen_in_thread = stolen.clone();
    let swap_thread = std::thread::spawn(move || {
      for _ in 0..200 {
        if std::fs::rename(&dest_in_thread, &stolen_in_thread).is_ok() {
          let _ = std::fs::create_dir(&dest_in_thread);
          let _ = std::fs::create_dir_all(dest_in_thread.join("replacement-only"));
          let _ = std::fs::remove_dir_all(&dest_in_thread);
          // Restore the GENUINE moved dir so the next iteration races afresh and the
          // post-join state converges on the true tree.
          let _ = std::fs::rename(&stolen_in_thread, &dest_in_thread);
        }
      }
    });

    // Move the populated dir IN, racing the swap loop: the reader learns it pending
    // and defers the subtree walk, which may re-open a REPLACEMENT the loop dropped.
    let _ = std::fs::rename(&src, &dest);
    let _ = swap_thread.join();

    // Deterministically restore the GENUINE moved dir with its pre-existing
    // descendant, wherever the race left it: the true tree may be at `incoming` or
    // parked at `incoming-stolen`, or a replacement may sit at `incoming`. Force
    // `incoming/nested/deep.txt` to exist as the genuine pre-existing descendant so
    // the coverage assertion is about the true subtree, not a fresh create.
    if std::fs::metadata(dest.join("nested/deep.txt")).is_err() {
      let _ = std::fs::remove_dir_all(&dest);
      if std::fs::rename(&stolen, &dest).is_err()
        || std::fs::metadata(dest.join("nested/deep.txt")).is_err()
      {
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(dest.join("nested")).unwrap();
        std::fs::write(dest.join("nested/deep.txt"), b"seed").unwrap();
      }
    }
    let _ = std::fs::remove_dir_all(&stolen);

    // Coverage honesty of the TRUE pre-existing descendant: mutating it is delivered
    // directly (genuine walk) OR rescan-covered (replacement re-open → Incomplete →
    // death → re-enumerate) — never silently blind (the pre-fix wrong-tree seed).
    let deep = dest.join("nested/deep.txt");
    std::fs::write(&deep, b"after-race").unwrap();
    assert!(
      wait_for(&mut w, |e| covers(e, &deep)).await.is_some(),
      "after a moved-in-replacement race, the true pre-existing descendant is delivered or \
       rescan-covered — never silently blind (attempt {attempt})"
    );
    let _ = w.close().await;
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
  }
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
    other => panic!("{other} is impossible on Linux"),
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

/// Suite 11 (strengthened) — root death via the PERIODIC LIVENESS TICK (design
/// §7 L4.1/L4.2). A fanotify root unmounted out from under a LIVE watch delivers
/// no in-tree signal AND no loss — the mark holds the superblock alive and the
/// fd goes quiet — so the only detection is the periodic root re-stat. The
/// property asserted is terminal reclamation WITHOUT inducing any loss.
///
/// A short `root_liveness_interval` makes it deterministic: watch live, plain
/// lazy-unmount (no retained fd, no channel-flood trick), then wait for the tick
/// to re-stat the now-gone root and lower the death lifecycle — the handle goes
/// dead-on-arrival, exactly like an in-tree `DELETE_SELF` would.
#[tokio::test]
async fn unmount_under_live_watch_dies_via_refresh() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP unmount_under_live_watch_dies_via_refresh: no ext4 loopback (--privileged)");
    return;
  };
  let root = scratch_under(&mount, "refresh-death");
  // A SHORT liveness interval: the periodic root re-stat is what detects a
  // signal-silent unmount, and a fraction of a second makes the death arrive
  // deterministically inside the test's deadline without any induced loss.
  let options = WatcherOptions::new()
    .with_backend(Backend::Fanotify)
    .with_root_liveness_interval(Duration::from_millis(500));
  let w = TokioWatcher::new(options).expect("build watcher");
  let Ok(handle) = w.watch(&root, Interest::all()).await else {
    eprintln!("SKIP unmount_under_live_watch_dies_via_refresh: fanotify unavailable");
    let _ = Command::new("umount").arg(&mount).status();
    return;
  };
  let mut w = w;

  // Prove the mark is live before pulling the filesystem out.
  std::fs::write(root.join("marker.txt"), b"m").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &root.join("marker.txt")))
      .await
      .is_some(),
    "the mark is live before the unmount"
  );

  // Lazy-unmount: detaches the mount from the namespace immediately (the root
  // path stops resolving) while the open mark keeps the superblock alive — the
  // exact "unmounted out from under a live watch" condition §7 describes. NO
  // loss is induced; the tick alone must catch it.
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

  // Wait — draining the stream so the driver makes progress — for the periodic
  // tick to fire a refresh, find the root gone, and lower the death lifecycle.
  // The SOLE success signal is the handle being reclaimed (dead-on-arrival). No
  // loss, no openat trick: the tick is the entire mechanism under test.
  let deadline = std::time::Instant::now() + Duration::from_secs(20);
  while w.backend_of(handle).is_some() && std::time::Instant::now() < deadline {
    let _ = tokio::time::timeout(Duration::from_millis(300), w.next()).await;
  }

  assert!(
    w.backend_of(handle).is_none(),
    "the periodic liveness tick detected the unmounted root and reclaimed the handle \
     with no induced loss"
  );
  assert!(
    w.root_path(handle).is_none(),
    "a reclaimed handle has no path"
  );
  let _ = w.close().await;
}

/// Sets `path`'s permission bits (raw `chmod`), returning whether it succeeded.
fn chmod(path: &Path, mode: u32) -> bool {
  use std::os::unix::fs::PermissionsExt;
  std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).is_ok()
}

/// Whether THIS process cannot read `dir` — i.e. an `EACCES`-style walk failure
/// would genuinely fire. Root with `CAP_DAC_OVERRIDE` (the usual privileged
/// container identity) reads a `chmod 000` directory regardless, so a walk-
/// incompleteness cell can only assert its property where this returns `true`;
/// elsewhere it skips loudly (the unprivileged CI leg and non-root devs hit it).
fn dir_is_unreadable(dir: &Path) -> bool {
  std::fs::read_dir(dir).is_err()
}

/// Suite 12 (walk-completeness selection precondition, design §5 `Walk` row).
///
/// A `chmod 000` subdirectory the walker cannot enter makes the seed walk
/// INCOMPLETE — fanotify's admission map would be born blind to that subtree, so
/// fanotify is not viable. Under `Backend::Auto` the spawn falls back to inotify
/// (which surfaces an unreadable directory natively through its per-directory
/// arms), and events under OTHER (readable) subtrees still flow. Self-probing:
/// where the process reads the 000 dir anyway (root + `CAP_DAC_OVERRIDE`), the
/// incompleteness cannot arise, so the cell skips loudly.
#[tokio::test]
async fn auto_falls_back_to_inotify_on_unwalkable_subtree() {
  let root = tmpfs_scratch("walk-fallback");
  // Two subtrees: one readable (events must flow through it), one made
  // unreadable so the walk cannot complete.
  let readable = root.join("readable");
  let blocked = root.join("blocked");
  std::fs::create_dir_all(readable.join("inner")).unwrap();
  std::fs::create_dir_all(&blocked).unwrap();
  if !chmod(&blocked, 0o000) {
    eprintln!("SKIP auto_falls_back_to_inotify_on_unwalkable_subtree: chmod refused");
    return;
  }
  if !dir_is_unreadable(&blocked) {
    // Root with DAC_OVERRIDE reads it anyway — the walk would complete, so the
    // fallback cannot be exercised here.
    let _ = chmod(&blocked, 0o755);
    eprintln!(
      "SKIP auto_falls_back_to_inotify_on_unwalkable_subtree: the 000 subdir is readable \
       (root/CAP_DAC_OVERRIDE) — run the default-caps/unprivileged leg to exercise the fallback"
    );
    return;
  }

  let w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Auto))
    .expect("build Auto watcher");
  let handle = match w.watch(&root, Interest::all()).await {
    Ok(handle) => handle,
    Err(err) => {
      let _ = chmod(&blocked, 0o755);
      panic!("Auto must not fail on an unwalkable subtree — it falls back: {err:?}");
    }
  };
  let selected = w
    .backend_of(handle)
    .expect("a live root reports its backend");
  assert_eq!(
    selected,
    BackendKind::Inotify,
    "an unwalkable in-root subtree makes fanotify not viable — Auto falls back to inotify"
  );

  // Events under the READABLE subtree still flow (the fallback backend is live).
  let mut w = w;
  let target = readable.join("inner/created.txt");
  std::fs::write(&target, b"x").unwrap();
  let flowed = wait_for(&mut w, |e| covers(e, &target)).await.is_some();
  // Restore before asserting so a failure still leaves the tree removable.
  let _ = chmod(&blocked, 0o755);
  assert!(
    flowed,
    "after the inotify fallback, a create under a readable subtree is delivered"
  );
  let _ = w.close().await;
}

/// Suite 12 — the forced-`Fanotify` half of the walk-completeness precondition:
/// an unwalkable subtree makes forced `Fanotify` fail with a typed
/// [`SourceError::BackendProbeFailed`] (the `Walk` stage), NOT a fallback and NOT
/// a live-but-blind source. Needs `CAP_SYS_ADMIN` for the mark to pass the probe
/// (so the walk stage is even reached) AND the 000 dir to be unreadable to this
/// process — a combination only an unusual environment provides, so the cell
/// skips loudly whenever either does not hold.
#[tokio::test]
async fn forced_fanotify_typed_error_on_unwalkable_subtree() {
  if !has_sys_admin() {
    eprintln!("SKIP forced_fanotify_typed_error_on_unwalkable_subtree: no CAP_SYS_ADMIN");
    return;
  }
  let root = tmpfs_scratch("walk-forced");
  let blocked = root.join("blocked");
  std::fs::create_dir_all(&blocked).unwrap();
  if !chmod(&blocked, 0o000) || !dir_is_unreadable(&blocked) {
    let _ = chmod(&blocked, 0o755);
    eprintln!(
      "SKIP forced_fanotify_typed_error_on_unwalkable_subtree: the 000 subdir is readable \
       (CAP_SYS_ADMIN implies DAC_OVERRIDE) — the walk stage cannot be forced to fail here"
    );
    return;
  }

  let w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Fanotify))
    .expect("build forced-fanotify watcher");
  let result = w.watch(&root, Interest::all()).await;
  let _ = chmod(&blocked, 0o755);
  let err = result.expect_err("forced fanotify on an unwalkable tree must fail");
  assert!(
    matches!(
      err,
      tributary_fs::WatchRootError::Source(tributary_fs::SourceError::BackendProbeFailed { .. })
    ),
    "an unwalkable subtree surfaces the typed viability error, never a blind source: {err:?}"
  );
  w.close().await.expect("the watcher closes cleanly");
}

/// Suite 12 — the walk-completeness precondition reached via a ZERO directory cap
/// instead of an unreadable subtree: a `max_map_directories` of `Some(0)` means the
/// admission map may never hold even the root anchor, so the seed walk is unviable
/// for ANY root. Under `Backend::Auto` this forces the inotify fall-back, and events
/// still flow through it. Unlike the 000-subdir cell, this needs no privilege games
/// (no `chmod`, no `CAP_DAC_OVERRIDE` self-probe), so it exercises the fall-back in
/// EVERY suite mode — including the privileged `fanotify` run where the 000 cell
/// skips.
#[tokio::test]
async fn auto_falls_back_to_inotify_under_a_zero_directory_cap() {
  let root = tmpfs_scratch("zero-cap-fallback");
  std::fs::create_dir_all(root.join("inner")).unwrap();

  let w = TokioWatcher::new(
    WatcherOptions::new()
      .with_backend(Backend::Auto)
      .with_max_map_directories(Some(0)),
  )
  .expect("build Auto watcher with a zero directory cap");
  let handle = w
    .watch(&root, Interest::all())
    .await
    .expect("Auto must not fail under a zero cap — it falls back to inotify");
  let selected = w
    .backend_of(handle)
    .expect("a live root reports its backend");
  assert_eq!(
    selected,
    BackendKind::Inotify,
    "a zero directory cap makes fanotify unviable (no map may hold even the anchor) — Auto \
     falls back to inotify"
  );

  // The fall-back backend is live: a create still flows (inotify keeps no map cap).
  let mut w = w;
  let target = root.join("inner/created.txt");
  std::fs::write(&target, b"x").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &target)).await.is_some(),
    "after the inotify fall-back a create is delivered — the zero cap never made a blind source"
  );
  let _ = w.close().await;
}

/// Suite 12 — the forced-`Fanotify` half of the zero-cap precondition: a
/// `max_map_directories` of `Some(0)` makes forced `Fanotify` fail with the typed
/// [`SourceError::BackendProbeFailed`] (`Walk` stage), never a fall-back and never a
/// live one-node map whose first event trips the `over_capacity` fatal. Needs
/// `CAP_SYS_ADMIN` so the mark passes the probe and the walk stage is reached; the
/// zero cap then fails the walk regardless of DAC (no unreadable-dir self-probe
/// needed), so this cell only gates on privilege.
#[tokio::test]
async fn forced_fanotify_typed_error_under_a_zero_directory_cap() {
  if !has_sys_admin() {
    eprintln!("SKIP forced_fanotify_typed_error_under_a_zero_directory_cap: no CAP_SYS_ADMIN");
    return;
  }
  let root = tmpfs_scratch("zero-cap-forced");
  std::fs::create_dir_all(&root).unwrap();

  let w = TokioWatcher::new(
    WatcherOptions::new()
      .with_backend(Backend::Fanotify)
      .with_max_map_directories(Some(0)),
  )
  .expect("build forced-fanotify watcher with a zero directory cap");
  let err = w
    .watch(&root, Interest::all())
    .await
    .expect_err("forced fanotify under a zero cap must fail, never build a one-node map");
  assert!(
    matches!(
      err,
      tributary_fs::WatchRootError::Source(tributary_fs::SourceError::BackendProbeFailed { .. })
    ),
    "a zero directory cap surfaces the typed viability error, never a blind or one-node source: \
     {err:?}"
  );
  w.close().await.expect("the watcher closes cleanly");
}

/// Churn smoke: a long create/delete churn of FILES under a watched root must not
/// grow unbounded memory — the intern table is directory-bounded (file target
/// FIDs are never interned). This drives thousands of file create/deletes and
/// asserts the watcher stays live and responsive (a leak of one id per file would
/// be observable as growth; the property under test is that the source keeps
/// converging with a bounded map). Runs on whichever backend `Auto` selects; the
/// map bound is the fanotify concern, and inotify has no such table.
#[tokio::test]
async fn file_churn_keeps_a_bounded_map() {
  let root = tmpfs_scratch("churn");
  let w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Auto))
    .expect("build Auto watcher");
  let Ok(handle) = w.watch(&root, Interest::all()).await else {
    eprintln!("SKIP file_churn_keeps_a_bounded_map: watch refused");
    return;
  };
  let selected = w.backend_of(handle).expect("live backend");
  let mut w = w;

  // A marker proves the stream is live before the churn.
  std::fs::write(root.join("start.txt"), b"s").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &root.join("start.txt")))
      .await
      .is_some(),
    "the {selected} stream is live before the churn"
  );

  // Churn: many DISTINCT files created then deleted. Under fanotify each create
  // carries a target FID that must NOT be interned; a per-file id leak would
  // grow the map's intern table without bound.
  for i in 0..3000 {
    let f = root.join(format!("churn-{i}.txt"));
    std::fs::write(&f, b"c").unwrap();
    std::fs::remove_file(&f).unwrap();
    // Drain opportunistically so the reader makes progress and the channel does
    // not back up (this is a liveness smoke, not a delivery assertion).
    if i % 256 == 0 {
      let _ = tokio::time::timeout(Duration::from_millis(1), w.next()).await;
    }
  }

  // The source is still live and responsive after the churn: a fresh create is
  // delivered. A blown-up map (OOM) or a dead reader would fail this.
  let after = root.join("after-churn.txt");
  std::fs::write(&after, b"a").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &after)).await.is_some(),
    "the {selected} source stays live and responsive after a heavy file churn"
  );
  let _ = w.close().await;
}

/// Bind-mounts `src` at `dst` (both must already exist), returning a guard that
/// unmounts on drop — so a `--test-threads=1` run never leaks a bind even when the
/// test body panics (the guard's `Drop` runs on unwind). `None` when the bind is
/// refused (no privilege / no mount support — the caller skips loudly).
fn bind_mount(src: &Path, dst: &Path) -> Option<BindGuard> {
  let status = Command::new("mount")
    .arg("--bind")
    .arg(src)
    .arg(dst)
    .status();
  if !status.map(|s| s.success()).unwrap_or(false) {
    return None;
  }
  Some(BindGuard {
    at: dst.to_path_buf(),
  })
}

/// Unmounts a bind on drop, best-effort but retried lazily (a still-busy bind is
/// caught on the next umount attempt). Keeps a `--test-threads=1` fanotify run from
/// leaving stray binds under the shared loopback for a later test to trip over.
struct BindGuard {
  at: PathBuf,
}

impl Drop for BindGuard {
  fn drop(&mut self) {
    // `-l` (lazy) so a bind still referenced by an fd detaches once quiescent,
    // rather than wedging the ephemeral container's teardown.
    let _ = Command::new("umount").arg("-l").arg(&self.at).status();
  }
}

/// A `mount --bind` of an OUTSIDE-root directory (same superblock, SAME device) at
/// a point INSIDE the watched root is a mount boundary the seed walk must NOT
/// descend: the bind shares the root's device, so a device-only fence would descend
/// across it and seed the outside subtree into the admission map — then churn on the
/// outside origin would deliver as in-root (a scope-fence breach). The mount-id
/// fence skips the bind exactly as a submount, so churn on the origin produces ZERO
/// in-root delivery and nothing under the bind point ever surfaces.
#[tokio::test]
async fn bind_mount_of_outside_dir_is_a_boundary() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP bind_mount_of_outside_dir_is_a_boundary: no ext4 loopback (--privileged)");
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "bind-boundary");
  // An OUTSIDE-root directory on the same superblock (same device as the root),
  // holding a pre-existing nested subtree, and the in-root mount point the bind
  // lands on — both created BEFORE the watch so the seed walk sees the bind.
  let origin = scratch_under(&mount, "bind-boundary-origin");
  std::fs::create_dir_all(origin.join("nested")).unwrap();
  let bind_point = root.join("bound");
  std::fs::create_dir_all(&bind_point).unwrap();
  let Some(_bind) = bind_mount(&origin, &bind_point) else {
    eprintln!("SKIP bind_mount_of_outside_dir_is_a_boundary: bind mount refused (--privileged)");
    return;
  };

  let Some((mut w, _h)) = fanotify_watcher(&root).await else {
    return;
  };
  // The mark is live before the churn (an in-root sibling create flows).
  std::fs::write(root.join("alive.txt"), b"a").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &root.join("alive.txt")))
      .await
      .is_some(),
    "the mark is live before the bind-boundary churn"
  );

  // Churn hard on the OUTSIDE origin (its subtree the bind exposes at `bound`). If
  // the walk had descended the bind, the origin's directories would be in the map
  // and this churn would deliver — as either the origin path OR the in-root bind
  // path. The mount-id fence never seeded them, so none may.
  for i in 0..200 {
    let via_origin = origin.join("nested").join(format!("o-{i}.txt"));
    std::fs::write(&via_origin, b"n").unwrap();
    std::fs::remove_file(&via_origin).unwrap();
    let via_bind = bind_point.join("nested").join(format!("b-{i}.txt"));
    std::fs::write(&via_bind, b"n").unwrap();
    std::fs::remove_file(&via_bind).unwrap();
  }

  // No event may name anything under the outside origin OR under the in-root bind
  // point — an admitted bind subtree would leak either form.
  let breach = tokio::time::timeout(Duration::from_secs(3), async {
    while let Some(event) = w.next().await {
      let path = event.path().to_path_buf();
      if path.starts_with(&origin) || path.starts_with(&bind_point) {
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
    "a same-device bind of an outside directory into the root leaked an event (the walk \
     descended across the mount boundary): {breach:?}"
  );
  let _ = w.close().await;
}

// The live-walk mount-frame regression (a re-mounted root: same object, new mount
// id) is proven HERMETICALLY, not here — see
// `os::linux::fanotify::source::tests::seed_from_fd_fences_on_the_handed_mount_frame_not_a_stale_one`
// (the descent fences on the frame the walk hands it, which the live path-reopen
// walks now re-read fresh from the reopened fd) plus the real-fs `seed_walk` /
// `subtree_walk` descent cells (a correct fresh frame is what lets them descend at
// all). A container reproduction is not reliable: the only post-re-mount live reopen
// is the loss RESEED (a move-in cannot reach a re-mounted root — a rename across the
// mount boundary fails `EXDEV`), a loss is non-deterministic to provoke, and the
// handle-keyed admission map keeps delivering a pre-existing descendant's events
// straight from the spawn map until a reseed actually rebuilds it — so absent a
// provoked loss there is nothing for a container cell to observe.

/// A `mount --bind` of the watched root onto a directory INSIDE itself is a cycle:
/// the bind exposes the whole root again beneath `root/sub/loop`, and it shares the
/// root's mount id (a self-bind), so the mount fence does NOT stop it — only the
/// walk's per-run visited-handle guard bounds it. The property is TERMINATION: the
/// spawn's seed walk completes (the watcher starts, or skips loudly on an
/// unwalkable-tree fallback), never hanging or recursing without bound.
#[tokio::test]
async fn ancestor_self_bind_cycle_terminates() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP ancestor_self_bind_cycle_terminates: no ext4 loopback (--privileged)");
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "self-bind-cycle");
  let loop_point = root.join("sub/loop");
  std::fs::create_dir_all(&loop_point).unwrap();
  // Bind the ROOT onto a directory inside itself: `root/sub/loop` now re-exposes
  // the whole root (including `sub/loop` again — an unbounded descent without the
  // visited-handle guard).
  let Some(_bind) = bind_mount(&root, &loop_point) else {
    eprintln!("SKIP ancestor_self_bind_cycle_terminates: bind mount refused (--privileged)");
    return;
  };

  // The property is that spawn TERMINATES — the seed walk's cycle guard bounds the
  // self-bind rather than looping forever. Wrap the whole watch in a deadline:
  // unbounded recursion would hang here and trip the timeout, whereas the cycle
  // guard returns promptly whether the walk mapped the tree (watcher live) or hit
  // the viability fallback.
  let started = tokio::time::timeout(DEADLINE, async {
    let options = WatcherOptions::new().with_backend(Backend::Fanotify);
    let watcher = TokioWatcher::new(options).expect("build watcher");
    let outcome = watcher.watch(&root, Interest::all()).await;
    (watcher, outcome)
  })
  .await;
  match started {
    Ok((watcher, Ok(_handle))) => {
      // The walk terminated and mapped the tree — the cycle guard bounded the
      // self-bind. Live and responsive, AND the tree is intact: a create under the
      // pre-existing `sub` directory resolves to its true root-relative path
      // `sub/nested.txt`. A re-parented root anchor (the bug the guard's
      // skip-entirely ordering avoids: re-seeding the re-encountered root under
      // `sub/loop` would overwrite its `parent == None` anchor) would resolve this
      // path wrong or drop it.
      let mut w = watcher;
      let nested = root.join("sub/nested.txt");
      std::fs::write(&nested, b"a").unwrap();
      assert!(
        wait_for(&mut w, |e| covers(e, &nested)).await.is_some(),
        "the self-bind cycle walk terminated, the source is live, and the root \
         anchor's tree is intact (a nested create resolves under the true root)"
      );
      let _ = w.close().await;
    }
    Ok((_watcher, Err(err))) => {
      // An honest fallback (an unwalkable tree under the cycle → NotViable, or a
      // typed error under forced Fanotify) is also acceptable — the point is that
      // spawn RETURNED rather than hanging.
      eprintln!("self-bind cycle walk terminated with an honest error (no hang): {err}");
    }
    Err(_) => panic!(
      "the self-bind cycle made spawn hang — the seed walk recursed without bound (the \
       visited-handle guard is missing or ineffective)"
    ),
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

/// Reader-teardown fairness under sustained traffic (the container half of the
/// fanotify liveness proof; the hermetic unit test pins only the top-of-loop
/// control check). A producer churns files continuously so the fanotify fd stays
/// readable, then the watcher is CLOSED under that load. `close()` must fully
/// quiesce (`Ok(())`): the reader observes the shutdown between reads rather than
/// after an `EAGAIN` the stream never yields. Without the interleaved control
/// check the teardown `join` would wedge past the close grace and surface as
/// `NotQuiesced`.
#[tokio::test]
async fn close_quiesces_under_sustained_traffic() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP close_quiesces_under_sustained_traffic: no ext4 loopback (needs --privileged)");
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "close-load");
  let Some((mut w, _h)) = fanotify_watcher(&root).await else {
    return;
  };

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

/// A kernel-recursive swap on fanotify: widening the root keeps the KR
/// profile, the covering `Rescan` bridges the swap, newly covered ground is
/// live under the fresh superblock mark, and `backend_stats` is re-pointed
/// at the replacement's counters.
#[tokio::test]
async fn replace_root_swaps_the_mark_and_repoints_stats() {
  let Some(mount) = ext4_loopback() else {
    eprintln!("SKIP replace_root_swaps_the_mark_and_repoints_stats: no ext4 loopback");
    return;
  };
  let _guard = LoopbackGuard {
    mount: mount.clone(),
  };
  let root = scratch_under(&mount, "replace");
  let sub = root.join("y");
  std::fs::create_dir_all(&sub).unwrap();
  let Some((mut w, handle)) = fanotify_watcher(&sub).await else {
    return;
  };
  assert!(w.backend_stats(handle).is_some(), "stats before the swap");

  w.replace_root(handle, &root)
    .await
    .expect("the swap commits");
  assert_eq!(w.root_path(handle), Some(root.clone()));
  assert_eq!(
    w.backend_of(handle).expect("live").as_str(),
    "fanotify",
    "KR stays KR"
  );
  assert!(
    w.backend_stats(handle).is_some(),
    "stats re-point at the replacement stream"
  );
  let covering = wait_for(&mut w, |e| e.is_rescan() && e.path() == root).await;
  assert!(covering.is_some(), "the covering Rescan arrives");

  let outside = root.join("outside.txt");
  std::fs::write(&outside, b"x").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &outside)).await.is_some(),
    "newly covered ground is live under the new mark"
  );
}
