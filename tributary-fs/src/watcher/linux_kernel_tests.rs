//! Real-inotify end-to-end regressions for the crate-internal set-cover pair.
//!
//! These three tests lived in the external `linux_inotify` integration binary until Codex R43
//! demoted [`Watcher::set_cover`] / [`Watcher::request_set_cover`] to `pub(crate)` (the ack
//! resolves at effect-queue time, not watch-live time — the pair stays off the public surface
//! until the effect-completion fence lands), which an external test binary can no longer call.
//!
//! Real-kernel timing is nondeterministic, so every assertion is convergence-style: wait
//! (bounded) until the expected fact is observed; extra events are always legal. Unlike the
//! external binary this module runs inside the parallel lib-test harness, so the trio
//! serializes itself on [`KERNEL_SERIAL`]: `count_inotify_wds` sums watch descriptors
//! process-wide, which only reflects the watcher under test while no sibling holds one.

use std::{
  path::{Path, PathBuf},
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use super::Watcher;
use crate::{Backend, Event, Interest, WatcherOptions};

type TokioWatcher = Watcher<agnostic_lite::tokio::TokioRuntime>;

/// Serializes the trio: these tests count process-wide inotify state and each drives its own
/// real kernel watcher, so they must not overlap each other (the surrounding lib tests are
/// sans-I/O and hold no inotify fds). An async mutex — the guard is held across awaits.
static KERNEL_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

/// Total inotify watch descriptors held by THIS process, summed across every inotify fd:
/// an inotify fd's `/proc/self/fdinfo/<fd>` lists one `inotify wd:<n> ...` line per live
/// per-directory watch. Meaningful only under [`KERNEL_SERIAL`], so the single watcher
/// under test is the only inotify fd and this reflects its descending watch count.
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

/// Closes the watcher and waits (bounded) until the process-wide inotify wd count has
/// returned to `baseline` (Codex R44): dropping a [`Watcher`] only *requests* an
/// asynchronous driver shutdown, so returning — and releasing [`KERNEL_SERIAL`] — before
/// the teardown is proven would let a successor test observe THIS test's late wd release
/// as its own shrink (`count < before` falsely satisfied). Every test in this module ends
/// through here, still under the serial guard.
async fn close_to_baseline(w: TokioWatcher, baseline: usize) {
  w.close().await.expect("close watcher");
  let drained = tokio::time::timeout(DEADLINE, async {
    loop {
      if count_inotify_wds() <= baseline {
        return true;
      }
      tokio::time::sleep(Duration::from_millis(25)).await;
    }
  })
  .await
  .unwrap_or(false);
  assert!(
    drained,
    "watcher teardown returns the process-wide inotify wd count to its pre-test baseline \
     before the serial guard is released (Codex R44)"
  );
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cover_prunes_outside_subtree_then_grows_it_back() {
  let _serial = KERNEL_SERIAL.lock().await;
  let baseline = count_inotify_wds();
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

  close_to_baseline(w, baseline).await;
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
  let _serial = KERNEL_SERIAL.lock().await;
  let baseline = count_inotify_wds();
  let root = scratch_root("grow-ancestor");
  // a/b has TWO descendant subtrees: a/b/deep (retained by the narrow cover) and a/b/other (pruned by
  // it — the cover keeps only a/b/deep under a/b, so a/b stays purely as a CONNECTING ANCESTOR).
  std::fs::create_dir_all(root.join("a/b/deep")).unwrap();
  std::fs::create_dir_all(root.join("a/b/other")).unwrap();

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

  close_to_baseline(w, baseline).await;
}

/// M2-B set-cover, the R37-F1 root-key cancel: after an applied shrink, re-issuing the root's OWN key
/// (the cancel-equivalent = full coverage) must re-arm every previously-pruned region. The broadening
/// delta of the root against any narrower applied cover is the root itself, so its subtree is re-armed
/// wholesale, re-installing the pruned /drop — a deep write under it is delivered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cover_root_key_cancel_re_arms_every_pruned_region() {
  let _serial = KERNEL_SERIAL.lock().await;
  let baseline = count_inotify_wds();
  let root = scratch_root("grow-cancel");
  std::fs::create_dir_all(root.join("keep/deep")).unwrap();
  std::fs::create_dir_all(root.join("drop/deep")).unwrap();

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

  close_to_baseline(w, baseline).await;
}
