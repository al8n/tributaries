//! Real-inotify end-to-end regressions for the crate-internal set-cover pair.
//!
//! These three tests lived in the external `linux_inotify` integration binary until Codex R43
//! demoted [`Watcher::set_cover`] / [`Watcher::request_set_cover`] to `pub(crate)` (the ack
//! resolves at effect-queue time, not watch-live time — the pair stays off the public surface
//! until the effect-completion fence lands), which an external test binary can no longer call.
//!
//! Real-kernel timing is nondeterministic, so every assertion is convergence-style: wait
//! (bounded) until the expected fact is observed; extra events are always legal. Unlike the
//! external binary this module runs inside the parallel lib-test harness, where sibling unit
//! tests (e.g. the `os::linux::inotify` suite) arm real inotify watches concurrently — so all
//! watch-descriptor assertions are **object-scoped**: [`wds_watching`] matches fdinfo entries
//! against the `(device, inode)` pairs of THIS test's own scratch directories, never a
//! process-wide count that another test's arm or teardown could satisfy or mask (Codex R45;
//! device+inode rather than inode alone, since inodes are unique only per device — R46).

use std::{
  collections::HashSet,
  os::unix::fs::MetadataExt,
  path::{Path, PathBuf},
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use super::Watcher;
use crate::{Backend, Event, Interest, WatcherOptions};

type TokioWatcher = Watcher<agnostic_lite::tokio::TokioRuntime>;

/// Generous ceiling for one expected observation; CI runners are slow.
const DEADLINE: Duration = Duration::from_secs(20);

/// A fresh scratch root under `TMPDIR`, canonicalized so event paths and expectations share
/// one byte form.
fn scratch_root(tag: &str) -> PathBuf {
  static COUNTER: AtomicU32 = AtomicU32::new(0);
  let dir = std::env::temp_dir()
    .canonicalize()
    .expect("canonicalize temp dir")
    .join(format!(
      "tributary-fs-kt-{}-{}-{}",
      tag,
      std::process::id(),
      COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
  std::fs::create_dir_all(&dir).expect("create scratch root");
  dir
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

/// The `(device, inode)` identities of `paths` (each must exist), with the device in the
/// KERNEL encoding fdinfo prints: `sdev:` carries the superblock's `s_dev` — `MKDEV`, i.e.
/// `major << 20 | minor` — while `stat`'s `st_dev` is glibc-encoded, so the two only happen
/// to coincide on major-0 devices like tmpfs. Converting through `major`/`minor` makes the
/// match hold on ANY filesystem, not just the tmp one (Codex R46).
fn objects_of(paths: &[PathBuf]) -> HashSet<(u64, u64)> {
  paths
    .iter()
    .map(|path| {
      let meta = std::fs::metadata(path).expect("stat scratch dir");
      let major = u64::from(libc::major(meta.dev()));
      let minor = u64::from(libc::minor(meta.dev()));
      ((major << 20) | (minor & 0xF_FFFF), meta.ino())
    })
    .collect()
}

/// Whether one fdinfo line records an inotify watch on one of `objects`: it must start with
/// the `inotify wd:` marker and its `sdev:` + `ino:` hex fields must BOTH match one pair —
/// device and inode together, since inode numbers are unique only within a device and this
/// scans every inotify fd in the process (Codex R46).
fn line_matches(line: &str, objects: &HashSet<(u64, u64)>) -> bool {
  if !line.starts_with("inotify wd:") {
    return false;
  }
  let field = |prefix: &str| {
    line
      .split_whitespace()
      .find_map(|token| token.strip_prefix(prefix))
      .and_then(|hex| u64::from_str_radix(hex, 16).ok())
  };
  match (field("sdev:"), field("ino:")) {
    (Some(sdev), Some(ino)) => objects.contains(&(sdev, ino)),
    _ => false,
  }
}

/// How many inotify watch descriptors THIS PROCESS holds **on the given objects**: an
/// inotify fd's `/proc/self/fdinfo/<fd>` lists one `inotify wd:<wd> ino:<hex> sdev:<hex> ...`
/// line per live watch, naming the watched object. Matching on this test's own directories'
/// `(device, inode)` pairs makes the count immune to every sibling test's inotify activity
/// (the `os::linux::inotify` unit tests arm and release real watches, unlocked, in this same
/// parallel binary — a process-wide count could be satisfied or masked by them, Codex R45),
/// including a sibling watching a same-inode object on a DIFFERENT filesystem (Codex R46).
fn wds_watching(objects: &HashSet<(u64, u64)>) -> usize {
  let mut total = 0;
  let Ok(entries) = std::fs::read_dir("/proc/self/fdinfo") else {
    return 0;
  };
  for entry in entries.flatten() {
    if let Ok(content) = std::fs::read_to_string(entry.path()) {
      total += content
        .lines()
        .filter(|line| line_matches(line, objects))
        .count();
    }
  }
  total
}

/// The fdinfo matcher is device+inode exact: a line with the right inode on the WRONG
/// device (the R46 collision) is rejected, the right pair on either field order is
/// counted, and non-inotify lines never match.
#[test]
fn fdinfo_line_matching_is_device_and_inode_exact() {
  let objects: HashSet<(u64, u64)> = [(0x11, 0x16fa6)].into_iter().collect();
  assert!(
    line_matches(
      "inotify wd:3 ino:16fa6 sdev:11 mask:fff ignored_mask:0",
      &objects
    ),
    "the matching (sdev, ino) pair is counted"
  );
  assert!(
    line_matches("inotify wd:3 sdev:11 ino:16fa6 mask:fff", &objects),
    "field order does not matter"
  );
  assert!(
    !line_matches("inotify wd:9 ino:16fa6 sdev:800002 mask:fff", &objects),
    "the same inode on a DIFFERENT device is rejected (Codex R46)"
  );
  assert!(
    !line_matches("inotify wd:9 ino:dead sdev:11 mask:fff", &objects),
    "a different inode on the same device is rejected"
  );
  assert!(
    !line_matches("pos:\t0", &objects),
    "a non-inotify fdinfo line never matches"
  );
  assert!(
    !line_matches("inotify wd:9 mask:fff", &objects),
    "a line missing either field is rejected, never miscounted"
  );
}

/// Waits (bounded) until `done()` holds, polling the kernel-visible state; `false` on lapse.
async fn converge(mut done: impl FnMut() -> bool) -> bool {
  tokio::time::timeout(DEADLINE, async {
    loop {
      if done() {
        return true;
      }
      tokio::time::sleep(Duration::from_millis(25)).await;
    }
  })
  .await
  .unwrap_or(false)
}

/// Closes the watcher and waits (bounded) until no watch descriptor on this test's own
/// inodes remains (Codex R44): dropping a [`Watcher`] only *requests* an asynchronous driver
/// shutdown, so a test must prove its kernel teardown finished rather than leak watches past
/// its end. Object-scoped, so a sibling test's activity can neither satisfy nor stall it.
async fn close_and_drain(w: TokioWatcher, objects: &HashSet<(u64, u64)>) {
  w.close().await.expect("close watcher");
  assert!(
    converge(|| wds_watching(objects) == 0).await,
    "watcher teardown releases every watch descriptor on this test's directories (Codex R44)"
  );
}

/// M2-B set-cover, end to end against real inotify: a wide root that armed per-directory
/// watches over TWO nested subtrees is reconciled in place down to a retained cover, then
/// **grown back**. Phase 1 (shrink): the strictly-outside subtree's watch descriptors are
/// reclaimed (its object-scoped wd count drops to zero) while the retained subtree's stay
/// intact and keep delivering with NO gap (never re-armed), and the pruned subtree stops
/// delivering — the whole point of shrinking the kernel coverage rather than releasing and
/// re-arming. Phase 2 (grow, Codex R36): re-issuing a cover that once again includes the
/// pruned subtree re-arms it in place, so a fresh deep write under it IS delivered again —
/// the bidirectional dual, without which a survivor watching a previously-pruned subtree
/// would sit over a hole no watch backs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cover_prunes_outside_subtree_then_grows_it_back() {
  let root = scratch_root("shrink");
  std::fs::create_dir_all(root.join("keep/deep")).unwrap();
  std::fs::create_dir_all(root.join("drop/deep")).unwrap();
  let all = objects_of(&[
    root.clone(),
    root.join("keep"),
    root.join("keep/deep"),
    root.join("drop"),
    root.join("drop/deep"),
  ]);
  let retained = objects_of(&[root.clone(), root.join("keep"), root.join("keep/deep")]);
  let pruned = objects_of(&[root.join("drop"), root.join("drop/deep")]);

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
  assert!(
    converge(|| wds_watching(&all) == 5).await,
    "root + keep + keep/deep + drop + drop/deep all hold watches before the shrink (got {})",
    wds_watching(&all)
  );

  // Shrink the wide root down to the /keep cover: /drop and /drop/deep are strictly outside it, so
  // their watches are pruned; the root (connecting ancestor) and /keep + /keep/deep stay armed with
  // NO re-arm.
  w.set_cover(h, vec![root.join("keep")])
    .await
    .expect("set_cover prune");

  // The pruned subtree's descriptors are reclaimed (the disarms apply asynchronously,
  // fire-and-forget) — and ONLY those: the retained cover's three watches survive untouched.
  assert!(
    converge(|| wds_watching(&pruned) == 0).await,
    "the strictly-outside /drop subtree's watch descriptors are reclaimed after the shrink"
  );
  assert_eq!(
    wds_watching(&retained),
    3,
    "the retained root + keep + keep/deep watches survive the shrink untouched (no re-arm)"
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
  close_and_drain(w, &all).await;
}

/// M2-B set-cover, the R37-F1 regression: growing back to a RETAINED ANCESTOR whose connecting watch
/// is still armed must re-arm the descendants the narrower cover pruned. A narrow cover {a/b/deep}
/// keeps a/b as a connecting ancestor (its watch survives) while pruning a/b's OTHER child a/b/other.
/// Growing to {a/b} then finds a/b's watch present — the exact situation the OLD exact-path grow check
/// mishandled by skipping the re-arm, leaving a/b/other a silent hole. The broadening-delta rule
/// re-arms a/b's deepest still-watched ancestor-or-self (a/b itself), re-installing a/b/other, so a
/// deep write under it is delivered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cover_grows_a_retained_ancestor_re_arming_pruned_descendants() {
  let root = scratch_root("grow-ancestor");
  // a/b has TWO descendant subtrees: a/b/deep (retained by the narrow cover) and a/b/other (pruned by
  // it — the cover keeps only a/b/deep under a/b, so a/b stays purely as a CONNECTING ANCESTOR).
  std::fs::create_dir_all(root.join("a/b/deep")).unwrap();
  std::fs::create_dir_all(root.join("a/b/other")).unwrap();
  let all = objects_of(&[
    root.clone(),
    root.join("a"),
    root.join("a/b"),
    root.join("a/b/deep"),
    root.join("a/b/other"),
  ]);

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let h = w.watch(&root, Interest::all()).await.expect("watch root");

  // Prove a/b/other is armed before the narrow cover.
  let other_before = root.join("a/b/other/before.txt");
  std::fs::write(&other_before, b"x").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &other_before))
      .await
      .is_some(),
    "a/b/other is armed before the narrow cover"
  );

  // Narrow to {a/b/deep}: a/b/other is strictly outside it, so it is pruned; a/b (the connecting
  // ancestor of a/b/deep) STAYS armed.
  w.set_cover(h, vec![root.join("a/b/deep")])
    .await
    .expect("narrow cover");

  // Drain stragglers so the quiet window sees only post-shrink deliveries.
  let _ = tokio::time::timeout(Duration::from_millis(500), async {
    while w.next().await.is_some() {}
  })
  .await;

  // a/b/other stops delivering (pruned).
  let other_after = root.join("a/b/other/after.txt");
  std::fs::write(&other_after, b"z").unwrap();
  let leaked = tokio::time::timeout(Duration::from_secs(3), async {
    while let Some(event) = w.next().await {
      if event.path().starts_with(root.join("a/b/other")) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    !leaked,
    "a/b/other stops delivering under the narrow {{a/b/deep}} cover"
  );

  // GROW to {a/b}: a/b is a retained prefix whose OWN watch still exists (it was the connecting
  // ancestor), but whose descendant a/b/other was pruned. The broadening delta re-arms a/b's deepest
  // still-watched ancestor-or-self — a/b itself — re-installing a/b/other. The OLD exact-path check
  // saw a/b's watch present and skipped the re-arm, leaving a/b/other a silent hole (Codex R37-F1).
  w.set_cover(h, vec![root.join("a/b")])
    .await
    .expect("grow to the retained ancestor");

  let _ = tokio::time::timeout(Duration::from_millis(500), async {
    while w.next().await.is_some() {}
  })
  .await;

  let other_regrown = root.join("a/b/other/regrown.txt");
  std::fs::write(&other_regrown, b"w").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &other_regrown))
      .await
      .is_some(),
    "growing back to the retained ANCESTOR a/b re-arms the previously-pruned a/b/other (Codex R37-F1)"
  );
  close_and_drain(w, &all).await;
}

/// M2-B set-cover, the R37-F1 root-key cancel: after an applied shrink, re-issuing the root's OWN key
/// (the cancel-equivalent = full coverage) must re-arm every previously-pruned region. The broadening
/// delta of the root against any narrower applied cover is the root itself, so its subtree is re-armed
/// wholesale, re-installing the pruned /drop — a deep write under it is delivered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cover_root_key_cancel_re_arms_every_pruned_region() {
  let root = scratch_root("grow-cancel");
  std::fs::create_dir_all(root.join("keep/deep")).unwrap();
  std::fs::create_dir_all(root.join("drop/deep")).unwrap();
  let all = objects_of(&[
    root.clone(),
    root.join("keep"),
    root.join("keep/deep"),
    root.join("drop"),
    root.join("drop/deep"),
  ]);

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let h = w.watch(&root, Interest::all()).await.expect("watch root");

  // Arm the /drop subtree, then prove it delivers.
  let drop_before = root.join("drop/deep/before.txt");
  std::fs::write(&drop_before, b"x").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &drop_before))
      .await
      .is_some(),
    "the /drop subtree is armed before the shrink"
  );

  // Shrink to {keep}: /drop is strictly outside it, so it is pruned.
  w.set_cover(h, vec![root.join("keep")])
    .await
    .expect("shrink to {keep}");

  let _ = tokio::time::timeout(Duration::from_millis(500), async {
    while w.next().await.is_some() {}
  })
  .await;

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
  assert!(!leaked, "the pruned /drop subtree stops delivering");

  // ROOT-KEY CANCEL: re-issue the root's OWN key = full coverage. The broadening delta is the root
  // itself (not under the narrower {keep}), so the root's subtree is re-armed, re-installing every
  // previously-pruned region — /drop included (Codex R37-F1, the full-cover cancel).
  w.set_cover(h, vec![root.clone()])
    .await
    .expect("root-key cancel");

  let _ = tokio::time::timeout(Duration::from_millis(500), async {
    while w.next().await.is_some() {}
  })
  .await;

  let drop_regrown = root.join("drop/deep/regrown.txt");
  std::fs::write(&drop_regrown, b"w").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &drop_regrown))
      .await
      .is_some(),
    "a root-key cancel after an applied shrink re-arms every previously-pruned region (Codex R37-F1)"
  );
  close_and_drain(w, &all).await;
}
