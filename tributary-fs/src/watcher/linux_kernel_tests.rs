//! Real-inotify end-to-end regressions for the public set-cover pair: the in-place
//! prune/grow reconciles, and the effect-completion fence's acceptance test
//! (`set_cover_ack_resolves_at_watch_live`) — the one cell that deliberately
//! writes with NO convergence wait, because the resolved ack itself is the claim
//! that the retained cover's kernel watches are live.
//!
//! Real-kernel timing is nondeterministic, so every other assertion is convergence-style:
//! wait (bounded) until the expected fact is observed; extra events are always legal. Unlike
//! the external `linux_inotify` binary this module runs inside the parallel lib-test harness,
//! where sibling unit tests (e.g. the `os::linux::inotify` suite) arm real inotify watches
//! concurrently — so all watch-descriptor assertions are **object-scoped**: [`wds_watching`]
//! matches fdinfo entries against the `(device, inode)` pairs of THIS test's own scratch
//! directories, never a process-wide count that another test's arm or teardown could satisfy
//! or mask (device+inode rather than inode alone, since inodes are unique only per device).

use std::{
  collections::HashSet,
  os::unix::fs::MetadataExt,
  path::{Path, PathBuf},
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use super::Watcher;
use crate::{
  Backend, CoverOutcome, Event, Interest, SyncRootDenied, WatcherOptions, error::SyncRootError,
};

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

/// An event NAMES a path when it reports that object itself and is not a `Rescan` — a real
/// delivery under a live watch.
///
/// The strictness is the point, and it is what every post-grow probe below asserts on. A grow
/// that re-covers ground which was DARK now stands a covering `Rescan` at the scope ROOT, and
/// such a `Rescan` satisfies [`covers`] for EVERY path under the root — including a probe
/// written after the grow. A probe assertion phrased in terms of [`covers`] would therefore be
/// answered by the grow's own cover and would prove nothing about the watch that was supposed
/// to deliver it, which is exactly the claim those probes exist to make.
fn names(event: &Event, path: &Path) -> bool {
  !event.is_rescan() && event.path() == path
}

/// The `(device, inode)` identities of `paths` (each must exist), with the device in the
/// KERNEL encoding fdinfo prints: `sdev:` carries the superblock's `s_dev` — `MKDEV`, i.e.
/// `major << 20 | minor` — while `stat`'s `st_dev` is glibc-encoded, so the two only happen
/// to coincide on major-0 devices like tmpfs. Converting through `major`/`minor` makes the
/// match hold on ANY filesystem, not just the tmp one.
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
/// scans every inotify fd in the process.
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
/// parallel binary — a process-wide count could be satisfied or masked by them),
/// including a sibling watching a same-inode object on a DIFFERENT filesystem.
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
/// device (the cross-device inode collision) is rejected, the right pair on either field order is
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
    "the same inode on a DIFFERENT device is rejected"
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
/// inodes remains: dropping a [`Watcher`] only *requests* an asynchronous driver
/// shutdown, so a test must prove its kernel teardown finished rather than leak watches past
/// its end. Object-scoped, so a sibling test's activity can neither satisfy nor stall it.
async fn close_and_drain(w: TokioWatcher, objects: &HashSet<(u64, u64)>) {
  w.close().await.expect("close watcher");
  assert!(
    converge(|| wds_watching(objects) == 0).await,
    "watcher teardown releases every watch descriptor on this test's directories"
  );
}

/// Set-cover: end to end against real inotify: a wide root that armed per-directory
/// watches over TWO nested subtrees is reconciled in place down to a retained cover, then
/// **grown back**. Phase 1 (shrink): the strictly-outside subtree's watch descriptors are
/// reclaimed (its object-scoped wd count drops to zero) while the retained subtree's stay
/// intact and keep delivering with NO gap (never re-armed), and the pruned subtree stops
/// delivering — the whole point of shrinking the kernel coverage rather than releasing and
/// re-arming. Phase 2 (grow): re-issuing a cover that once again includes the
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
  // /keep/deep and /drop/deep hold live per-directory watches. Both facts are collected
  // in ONE pass over the stream — two sequential waits would let the first CONSUME the
  // second's event when the kernel delivers them in the other order (the race the first
  // real CI run of this moved test exposed; the external suite documents the same idiom
  // on its churn test).
  let keep_probe = root.join("keep/deep/before.txt");
  let drop_probe = root.join("drop/deep/before.txt");
  std::fs::write(&keep_probe, b"x").unwrap();
  std::fs::write(&drop_probe, b"x").unwrap();
  let (mut keep_seen, mut drop_seen) = (false, false);
  let both_armed = tokio::time::timeout(DEADLINE, async {
    while let Some(event) = w.next().await {
      keep_seen |= covers(&event, &keep_probe);
      drop_seen |= covers(&event, &drop_probe);
      if keep_seen && drop_seen {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    both_armed,
    "both nested subtrees are armed — their deep writes surface in one collection pass \
     (keep: {keep_seen}, drop: {drop_seen})"
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

  // PHASE 2 — GROW BACK: re-issue a cover that once again includes /drop. The
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
    // By NAME: this grow re-covers dark ground that HOLDS content (`before.txt`, `after.txt`),
    // so it now stands a covering `Rescan` of its own — which must not be able to answer a
    // claim about the re-armed watch (see [`names`]).
    wait_for(&mut w, |e| names(e, &drop_regrown))
      .await
      .is_some(),
    "the re-armed /drop/deep subtree delivers again after the set-cover grew it back"
  );
  close_and_drain(w, &all).await;
}

/// Set-cover: the regression: growing back to a RETAINED ANCESTOR whose connecting watch
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
  // saw a/b's watch present and skipped the re-arm, leaving a/b/other a silent hole.
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
    // By NAME: a/b/other held `before.txt` and `after.txt` while it was dark, so this grow
    // stands a covering `Rescan` of its own — see [`names`].
    wait_for(&mut w, |e| names(e, &other_regrown))
      .await
      .is_some(),
    "growing back to the retained ANCESTOR a/b re-arms the previously-pruned a/b/other"
  );
  close_and_drain(w, &all).await;
}

/// The effect-completion fence's ACCEPTANCE TEST (design §6 risk register): the resolved
/// ack IS "the retained cover is live". Shrink to `{keep}` and prove the coverage gap the
/// old queue-time ack would hide (a deep write under the pruned /drop yields nothing);
/// then grow back with `set_cover({keep, drop})` and — immediately on the resolved ack,
/// with deliberately NO convergence wait, drain, or sleep — write under the re-grown
/// subtree and assert that write is delivered BY NAME. Under a queue-time ack that write
/// races the re-arm cascade and is lost; under the settle-time fence every re-armed watch
/// (the grandchild `drop/deep` included — re-arms emit no `Created`, so nothing else covers
/// it) is live before the ack resolves. That immediacy is this cell's whole claim.
///
/// # The grow-back is not clean, and this cell is what proves it isn't
///
/// The verdict is `Degraded`, and that is the CORRECT answer rather than a blemish the
/// immediacy claim has to tolerate. `gap.txt` is written under /drop/deep while that ground
/// is dark, and the quiet window above proves the consumer was never told: the prune took the
/// watches that would have recorded it, and the grow's crawl is suppressed, so it announces
/// nothing for what it finds. Whatever the re-covered ground already held — `gap.txt`, and
/// `before.txt` from before the prune, which is dark for the same reason — is absorbed in
/// silence. This cell used to write that content deliberately, prove nothing was delivered,
/// and then assert the grow-back reported clean, which is issue #82 asserted as correct.
///
/// So the grow OWES a cover for exactly the interval this cell proved was dark, and it pays
/// it: the freshly-installed /drop reads back non-empty, which supplies the bridge window's
/// loss half, and that window's closing `Rescan` at the scope root routes through the cover
/// fence's loss memory and settles the fence `Degraded`. `Degraded` here reads "re-read this
/// ground" — the only honest answer to a consumer that was never told what landed while the
/// ground was dark. An empty pruned subtree would still settle `Applied`; the content is what
/// makes this one owe.
///
/// The cover is therefore asserted as DELIVERED, not merely as a verdict: a `Rescan` at /drop
/// or an ancestor must reach the consumer's stream. And the probe is asserted by NAME
/// ([`names`]), because that same covering `Rescan` satisfies [`covers`] for every path under
/// the root — a `covers`-shaped probe would be answered by the cover itself and would leave
/// the immediacy claim proving nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cover_ack_resolves_at_watch_live() {
  let root = scratch_root("fence-ack");
  std::fs::create_dir_all(root.join("keep")).unwrap();
  std::fs::create_dir_all(root.join("drop/deep")).unwrap();
  let all = objects_of(&[
    root.clone(),
    root.join("keep"),
    root.join("drop"),
    root.join("drop/deep"),
  ]);
  let pruned = objects_of(&[root.join("drop"), root.join("drop/deep")]);

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let h = w.watch(&root, Interest::all()).await.expect("watch root");

  // /drop/deep holds a live per-directory watch before the shrink: a deep write surfaces.
  let before = root.join("drop/deep/before.txt");
  std::fs::write(&before, b"x").unwrap();
  assert!(
    wait_for(&mut w, |e| covers(e, &before)).await.is_some(),
    "the /drop subtree is armed before the shrink"
  );

  // Shrink to {keep} and PROVE THE GAP: the pruned subtree's descriptors are reclaimed,
  // and a deep write under it yields NOTHING within a bounded quiet window — exactly the
  // hole the grow's ack must not resolve before closing, and exactly the content the
  // grow-back below owes a cover for. `gap.txt` outlives this window: it stays under the
  // ground being re-covered, unnamed by any record and unreported by any listing.
  w.set_cover(h, vec![root.join("keep")])
    .await
    .expect("set_cover shrink");
  assert!(
    converge(|| wds_watching(&pruned) == 0).await,
    "the pruned /drop subtree's watch descriptors are reclaimed"
  );
  // Drain pre-shrink stragglers so the quiet window sees only post-shrink deliveries
  // (the suite's usual idiom — legal here, this is the SHRINK phase).
  let _ = tokio::time::timeout(Duration::from_millis(500), async {
    while w.next().await.is_some() {}
  })
  .await;
  let gap = root.join("drop/deep/gap.txt");
  std::fs::write(&gap, b"y").unwrap();
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
    "the gap is real: the pruned /drop delivers nothing, so gap.txt is content the consumer \
     was never told about"
  );

  // GROW BACK — and write the INSTANT the ack resolves. No drain, no converge, no sleep
  // between the resolved ack and the write: that immediacy is the whole point.
  let outcome = w
    .set_cover(h, vec![root.join("keep"), root.join("drop")])
    .await
    .expect("set_cover grow");
  assert!(
    outcome.is_degraded(),
    "the grow re-covers ground that was dark and holds content nothing ever reported \
     (`before.txt`, and the `gap.txt` written while /drop was pruned), so its window owes a \
     cover and the fence settles Degraded, got {outcome:?}"
  );
  let probe = root.join("drop/deep/immediate.txt");
  std::fs::write(&probe, b"z").unwrap();

  // Both facts in ONE collection pass, in the order the driver produces them (the cover is
  // offered ahead of the verdict it justifies; the probe's own event follows the write): the
  // promised cover really is ON THE WIRE, and the immediate write is delivered BY NAME. Two
  // sequential waits would let the first consume the other's event — the same race the
  // prune/grow cell documents — and a `covers`-shaped probe would let the cover answer for
  // the write.
  let dark = root.join("drop");
  let (mut covered, mut immediate) = (false, false);
  let both = tokio::time::timeout(DEADLINE, async {
    while let Some(event) = w.next().await {
      covered |= event.is_rescan() && dark.starts_with(event.path());
      immediate |= names(&event, &probe);
      if covered && immediate {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    both,
    "the Degraded verdict's cover reaches the consumer — a Rescan at /drop or an ancestor, \
     obliging re-enumeration of the ground that was dark — AND the write issued immediately \
     on the resolved ack is delivered by name: the ack resolves at watch-live, not at \
     effect-queue time (cover: {covered}, immediate: {immediate})"
  );
  close_and_drain(w, &all).await;
}

/// Set-cover: the root-key cancel: after an applied shrink, re-issuing the root's OWN key
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
  // previously-pruned region — /drop included (the full-cover cancel).
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
    // By NAME: the cancel re-covers dark ground that HOLDS content, so it stands a covering
    // `Rescan` of its own — see [`names`].
    wait_for(&mut w, |e| names(e, &drop_regrown))
      .await
      .is_some(),
    "a root-key cancel after an applied shrink re-arms every previously-pruned region"
  );
  close_and_drain(w, &all).await;
}

/// A set-cover that narrows a root down to a FILE keeps the reserved cookie
/// directory of the covered ground armed, so a SECOND sync there is still
/// observable.
///
/// The whole failure needs a real kernel to exist. The reserved directory is a
/// sibling of whatever the cover retained, so a cover naming a file marks it
/// strictly outside; drop its watch and the next sync into that directory finds
/// the reserved directory already standing, takes the `EEXIST` arm, and creates
/// its marker with no directory create anywhere for a parent watch to re-arm
/// from. inotify is non-recursive: no watch, no event, and the caller's barrier
/// can only time out while `sync_root` reported success.
///
/// Staged so the second sync is the one that matters: the FIRST sync creates the
/// reserved directory (and arms it through the root's own watch), the cover then
/// shrinks past it, and only then does the second sync run.
///
/// Revert witness: drop the reserved-directory arm from the core's set-cover
/// prune filter and the second sync's marker never arrives — the wait below burns
/// its whole deadline while the pruned sibling assertion still passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cover_keeps_a_covered_directory_s_reserved_sync_directory_armed() {
  let root = scratch_root("cover-cookie-dir");
  std::fs::create_dir_all(root.join("drop")).expect("a plain sibling directory");
  std::fs::write(root.join("kept.txt"), b"x").expect("the file the cover retains");

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let handle = w.watch(&root, Interest::all()).await.expect("watch root");
  let canonical = w.root_path(handle).expect("root path");

  // First sync: the reserved directory is CREATED, so the root's own watch sees
  // its create and arms it. This is the arm the cover must not take away.
  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let first = w
    .sync_root(handle, &canonical, admission)
    .await
    .expect("the first sync admits and writes its cookie");
  assert!(
    wait_for(&mut w, |e| names(e, &first)).await.is_some(),
    "staging: the first sync's marker is reported, so its reserved directory is armed"
  );
  let reserved = first
    .parent()
    .expect("a marker stands inside the reserved directory")
    .to_path_buf();
  let reserved_object = objects_of(&[reserved.clone()]);
  let pruned_object = objects_of(&[canonical.join("drop")]);
  let all = objects_of(&[canonical.clone(), reserved.clone(), canonical.join("drop")]);
  assert_eq!(
    wds_watching(&reserved_object),
    1,
    "staging: the reserved directory holds its own kernel watch before the cut"
  );

  // The caller keeps ONE file subscription. Every sibling of that file is
  // strictly outside the cover — the plain directory and the reserved directory
  // alike.
  assert!(
    w.cover_fence_entry_spent(handle).await,
    "staging: the scope's loss memory is spent before the shrink, so its fence inherits nothing"
  );
  assert_eq!(
    w.set_cover(handle, vec![canonical.join("kept.txt")])
      .await
      .expect("set_cover shrink"),
    CoverOutcome::Applied,
    "the shrink's own window is clean: the first sync's retirement stands a \
     domination `Rescan`, and a domination is not a coverage loss"
  );
  assert!(
    converge(|| wds_watching(&pruned_object) == 0).await,
    "the plain sibling's watch descriptor is reclaimed — the cut really ran"
  );
  assert_eq!(
    wds_watching(&reserved_object),
    1,
    "and the reserved directory's watch survives it"
  );

  // Second sync: the reserved directory already exists, so nothing is created
  // for the root's watch to report and only the surviving watch can carry the
  // marker.
  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let second = w
    .sync_root(handle, &canonical, admission)
    .await
    .expect("the second sync admits and writes its cookie");
  assert_eq!(
    second.parent(),
    Some(reserved.as_path()),
    "staging: the second marker reuses the reserved directory the first one made"
  );
  assert!(
    wait_for(&mut w, |e| names(e, &second)).await.is_some(),
    "the second sync's marker is reported — the barrier the caller is waiting on can be met"
  );

  let _ = std::fs::remove_file(&first);
  let _ = std::fs::remove_file(&second);
  close_and_drain(w, &all).await;
  let _ = std::fs::remove_dir_all(&root);
}

/// A cover change DOMINATES the live obligation standing in the ground it takes
/// — asked on the far side of the write's own return.
///
/// `sync_root` answers the instant the marker exists, and the barrier's
/// observation happens strictly after. Holding the pruned ground for as long as
/// an obligation named it made `set_cover` apply a cover it had not been asked
/// for; the barrier is retired instead, dominated by the located `Rescan` the
/// retirement stands, and the caller's cover is the cover that applies.
///
/// Real inotify, because what the cell rests on is the kernel's: the ground the
/// cover names nothing for really loses its watch descriptors — the marker's own
/// directory and the reserved directory inside it among them — and the marker is
/// really unlinked from the filesystem rather than merely forgotten.
///
/// The second sync is the proof the cut really took that ground: `<root>/a` is
/// outside the applied cover now, so the admission refuses it before birth
/// instead of placing a marker nothing could report.
///
/// Revert witness: put `retained.extend(cookies.live_sync_dirs(scope))` back in
/// the `SetCover` handler and `<root>/a` keeps its watch, the marker stays on
/// disk, and the second sync is admitted — the widening this replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cover_dominates_the_owned_marker_standing_in_the_ground_it_takes() {
  let root = scratch_root("cover-owned-marker");
  std::fs::create_dir_all(root.join("a")).expect("the ground the sync writes in");
  std::fs::create_dir_all(root.join("b")).expect("the ground the cover keeps");
  std::fs::create_dir_all(root.join("c")).expect("the ground the cut takes");

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let handle = w.watch(&root, Interest::all()).await.expect("watch root");
  let canonical = w.root_path(handle).expect("root path");
  let target = canonical.join("a");

  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let first = w
    .sync_root(handle, &target, admission)
    .await
    .expect("the sync admits and writes its marker");
  assert!(
    wait_for(&mut w, |e| names(e, &first)).await.is_some(),
    "staging: the marker is reported, so its reserved directory is armed"
  );
  let reserved = first
    .parent()
    .expect("a marker stands inside the reserved directory")
    .to_path_buf();

  let target_object = objects_of(&[target.clone()]);
  let reserved_object = objects_of(&[reserved.clone()]);
  let cut_object = objects_of(&[canonical.join("c")]);
  let all = objects_of(&[
    canonical.clone(),
    target.clone(),
    reserved.clone(),
    canonical.join("b"),
    canonical.join("c"),
  ]);

  // The obligation is OWNED and unreaped — nothing has removed its marker — and
  // the cover the caller now asks for names neither it nor the sibling beside it.
  assert!(
    w.cover_fence_entry_spent(handle).await,
    "staging: the scope's loss memory is spent before the shrink, so its fence inherits nothing"
  );
  assert_eq!(
    w.set_cover(handle, vec![canonical.join("b")])
      .await
      .expect("set_cover shrink"),
    CoverOutcome::Applied,
    "the domination does not degrade the shrink: its `Rescan` tells the \
     dominated caller to re-read, it does not say this cover has a hole"
  );
  // …and the dominated caller IS told, on its own stream: the covering `Rescan`
  // the retirement stands names the ground its marker stood in.
  assert!(
    wait_for(&mut w, |e| covers(e, &target)).await.is_some(),
    "a barrier is never retired silently: the covering `Rescan` names its ground"
  );
  assert!(
    converge(|| wds_watching(&cut_object) == 0).await,
    "the sibling the cover named nothing for loses its watch — the cut really ran"
  );
  assert!(
    converge(|| wds_watching(&target_object) == 0).await,
    "and so does the dominated barrier's own ground: the cover that applies is      the one the caller asked for"
  );
  assert!(
    converge(|| wds_watching(&reserved_object) == 0).await,
    "the reserved directory inside it goes with the ground holding it"
  );

  // The retirement withdrew the marker rather than leaving a file no barrier is
  // waiting for and no cover reports.
  assert!(
    converge(|| !first.exists()).await,
    "the dominated barrier's marker is withdrawn from the filesystem"
  );

  // And the ground really is outside the applied cover now: a fresh sync of it is
  // refused before birth rather than placing a marker nothing could report.
  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let refused = w.sync_root(handle, &target, admission).await;
  assert!(
    matches!(
      refused,
      Err(SyncRootDenied {
        error: SyncRootError::DirUncovered { .. },
        ..
      })
    ),
    "a sync of ground the cover took is refused, not admitted: {refused:?}"
  );

  let _ = std::fs::remove_file(&first);
  close_and_drain(w, &all).await;
  let _ = std::fs::remove_dir_all(&root);
}

/// A SAME-NAME SUBSTITUTION of the ground a live sync stands on dominates its
/// barrier — with the covering `Rescan` on the stream, never a certificate.
///
/// A peer renames `<root>/a` aside and moves a prepared directory onto its name
/// while a marker is standing inside it: every identity the admission pinned
/// still matches whatever the write reached, because the objects are real and
/// the pin carried one of them through the rename. What separates the two
/// worlds is COVERAGE — the reconcile drops the incumbent watch before arming
/// the arrival — and that is exactly the transition the barrier is dispatched
/// under an epoch to see.
///
/// Real inotify because the ordering the rule rests on is the kernel's: the
/// substitution's own records precede anything the new directory produces, in one
/// queue, which is the premise the epoch is allowed to lean on here and is not
/// allowed to lean on under FSEvents coalescing.
///
/// Revert witness: raise no bump at `drain_monitor`'s child-watch ARM or DROP
/// and the substitution passes silently — no `Rescan` covering `<root>/a`
/// arrives, and the marker stays on disk as a certificate over a window whose
/// ground was replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_same_name_substitution_under_a_live_sync_dominates_its_barrier() {
  let root = scratch_root("substitution-dominates");
  std::fs::create_dir_all(root.join("a")).expect("the ground the sync writes in");
  std::fs::create_dir_all(root.join("spare")).expect("the replacement, prepared aside");

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let handle = w.watch(&root, Interest::all()).await.expect("watch root");
  let canonical = w.root_path(handle).expect("root path");
  let target = canonical.join("a");

  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let first = w
    .sync_root(handle, &target, admission)
    .await
    .expect("the sync admits and writes its marker");
  assert!(
    wait_for(&mut w, |e| names(e, &first)).await.is_some(),
    "staging: the marker is reported, so its ground is armed"
  );

  // The substitution: the judged object moves aside and a prepared directory
  // takes its name, in the window between the write and the observation.
  std::fs::rename(&target, canonical.join("aside")).expect("the judged ground moves aside");
  std::fs::rename(canonical.join("spare"), &target).expect("the replacement takes its name");

  // Sampled AFTER the substitution, which is the only instant every one of these
  // names resolves: `aside` does not exist until the first rename creates it, and
  // `spare` stops existing at the second. The three objects are the same three
  // either way — the root, the carried-away incumbent, and its replacement — and
  // sampling here names each of them by the path it answers to at teardown.
  let all = objects_of(&[canonical.clone(), target.clone(), canonical.join("aside")]);

  assert!(
    wait_for(&mut w, |e| covers(e, &target)).await.is_some(),
    "the replaced ground is covered by a `Rescan`, not certified by the marker \
     standing in the object that was carried away"
  );

  let _ = std::fs::remove_dir_all(canonical.join("aside"));
  close_and_drain(w, &all).await;
  let _ = std::fs::remove_dir_all(&root);
}

/// A STABLE TREE delivers its marker and dominates nothing.
///
/// The negative the whole rule depends on, and the reason retirement is
/// location-scoped rather than scope-wide: a barrier on a tree whose watch set
/// does not move must resolve by DELIVERY. If ordinary syncs answered
/// `Dominated`, the terminal would carry no information and every caller would
/// re-enumerate for nothing.
///
/// Asserted as a delta: the marker's own event arrives, and across a window that
/// would comfortably have carried one, no `Rescan` covering its ground follows,
/// and the marker is still on disk — nothing withdrew it.
///
/// Revert witness: make `BarrierLocation::intersects` answer `true` for every
/// located ground, or raise a bump where the funnel list deliberately raises none
/// (a data event, a reparent within the scope, a widen commit), and the `Rescan`
/// this cell refuses appears.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stable_tree_delivers_its_marker_and_dominates_nothing() {
  let root = scratch_root("stable-delivers");
  std::fs::create_dir_all(root.join("a")).expect("the ground the sync writes in");
  std::fs::create_dir_all(root.join("b")).expect("a sibling that never moves");

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let handle = w.watch(&root, Interest::all()).await.expect("watch root");
  let canonical = w.root_path(handle).expect("root path");
  let target = canonical.join("a");

  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let marker = w
    .sync_root(handle, &target, admission)
    .await
    .expect("the sync admits and writes its marker");
  assert!(
    wait_for(&mut w, |e| names(e, &marker)).await.is_some(),
    "the marker's OWN event is what resolves a barrier on a stable tree"
  );

  // Ordinary traffic the funnels deliberately do not bump on: data events under
  // ground whose watches are already armed.
  std::fs::write(canonical.join("b").join("data.txt"), b"payload").expect("an ordinary write");
  assert!(
    wait_for(&mut w, |e| names(e, &canonical.join("b").join("data.txt")))
      .await
      .is_some(),
    "staging: the tree is live and delivering"
  );

  assert!(
    marker.exists(),
    "nothing withdrew the marker: no transition touched its ground"
  );

  let all = objects_of(&[canonical.clone(), target.clone(), canonical.join("b")]);
  let _ = std::fs::remove_file(&marker);
  close_and_drain(w, &all).await;
  let _ = std::fs::remove_dir_all(&root);
}

/// The obligation's coordinate is the LANDING the admission pinned, not the
/// spelling its caller passed — which is what the domination is judged on.
///
/// `<root>/alias` is an intermediate symlink to `<root>/actual`, so a sync of
/// `<root>/alias/sub` pins, validates and writes at `<root>/actual/sub`. That is
/// also where the kernel's watch descriptor is: a crawl arms OBJECTS and never
/// follows a link, so no watch of this root stands at the spelling. The record
/// therefore keeps the LANDING, and the retirement's covering `Rescan` is minted
/// from it — a `Rescan` at the spelling would name ground no watch of this root
/// stands on, telling the caller to re-read a path that reports nothing.
///
/// Real inotify and a real symlink, because both halves of that are the kernel's:
/// the resolution really follows the link, and the watch descriptors really sit
/// on the resolved objects.
///
/// Revert witness: record the caller's spelling as the obligation's ground
/// instead of the landing and the `Rescan` this cell waits for names
/// `<root>/alias/sub`, which `covers` cannot match against the landing the marker
/// actually stood in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cover_dominates_a_live_alias_sync_at_the_landing_it_wrote_in() {
  let root = scratch_root("cover-alias-landing");
  let actual = root.join("actual");
  std::fs::create_dir_all(actual.join("sub")).expect("the ground the sync really writes in");
  std::fs::create_dir_all(root.join("keep")).expect("the ground the cover keeps");
  std::fs::create_dir_all(root.join("cut")).expect("the ground the cut takes");
  // A pre-existing link, standing before the watch: nothing here needs it created
  // live.
  std::os::unix::fs::symlink(&actual, root.join("alias")).expect("the intermediate link");

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let handle = w.watch(&root, Interest::all()).await.expect("watch root");
  let canonical = w.root_path(handle).expect("root path");
  let spelled = canonical.join("alias").join("sub");
  let landing = canonical.join("actual").join("sub");

  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let first = w
    .sync_root(handle, &spelled, admission)
    .await
    .expect("a sync through the link admits");
  assert!(
    first.starts_with(&landing),
    "staging: the marker landed where the link RESOLVES ({}), not where it was \
     spelled",
    first.display()
  );
  assert!(
    wait_for(&mut w, |e| names(e, &first)).await.is_some(),
    "staging: the marker is reported, so the landing's reserved directory is armed"
  );
  let reserved = first
    .parent()
    .expect("a marker stands inside the reserved directory")
    .to_path_buf();

  let landing_object = objects_of(&[landing.clone()]);
  let reserved_object = objects_of(&[reserved.clone()]);
  let cut_object = objects_of(&[canonical.join("cut")]);
  let all = objects_of(&[
    canonical.clone(),
    actual.clone(),
    landing.clone(),
    reserved.clone(),
    canonical.join("keep"),
    canonical.join("cut"),
  ]);

  // The cover the caller now asks for names neither the landing nor the sibling
  // beside it, so it dominates the barrier standing in the landing.
  assert!(
    w.cover_fence_entry_spent(handle).await,
    "staging: the scope's loss memory is spent before the shrink, so its fence inherits nothing"
  );
  assert_eq!(
    w.set_cover(handle, vec![canonical.join("keep")])
      .await
      .expect("set_cover shrink"),
    CoverOutcome::Applied,
    "the domination does not degrade the shrink: its `Rescan` tells the \
     dominated caller to re-read, it does not say this cover has a hole"
  );

  // The covering `Rescan` the retirement stands has to name the LANDING: that is
  // the ground the marker stood in and the only ground a watch of this root is
  // armed at. Read before the watch assertions below, because the instruction is
  // what the caller acts on.
  let covered_landing = wait_for(&mut w, |e| covers(e, &landing)).await;
  assert!(
    covered_landing.is_some(),
    "the retirement's covering `Rescan` names the landing, not the spelling"
  );

  assert!(
    converge(|| wds_watching(&cut_object) == 0).await,
    "the sibling the cover named nothing for loses its watch — the cut really ran"
  );
  assert!(
    converge(|| wds_watching(&landing_object) == 0).await,
    "and the landing goes with it: the cover that applies is the caller's"
  );
  assert!(
    converge(|| wds_watching(&reserved_object) == 0).await,
    "the reserved directory standing inside it goes with the ground holding it"
  );
  assert!(
    converge(|| !first.exists()).await,
    "the dominated barrier's marker is withdrawn from the landing it stood in"
  );

  let _ = std::fs::remove_file(&first);
  close_and_drain(w, &all).await;
  let _ = std::fs::remove_dir_all(&root);
}

/// A sync whose caller-supplied directory is covered but whose RESOLVED landing
/// is not is refused, and refused by the landing's name.
///
/// The admission's cover test is lexical, and a spelling is not a location: with
/// the cover narrowed to `<root>/keep`, `<root>/keep/link/sub` reads as covered
/// ground while the pre-existing intermediate symlink resolves it into
/// `<root>/drop/sub` — a subtree the cut stopped watching. Every other word
/// passes there too: the landing is contained by the root, no exclusion and no
/// prune pattern name it, and it stands in the root's own mount. So the cover has
/// to be asked a second time, of the pins, or the write would land a marker in
/// unarmed ground and `sync_root` would answer `Ok` over a barrier that could
/// only time out.
///
/// Real inotify, because what the cell rests on is the kernel's: the pruned
/// subtree really has no watch descriptor, and the resolution really follows the
/// link.
///
/// Revert witness: drop the landing's cover check from `admitted_ground_refusal`
/// and this sync is ADMITTED — a reserved directory and a marker appear under
/// `<root>/drop/sub` and the refusal assertion below fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sync_resolving_through_a_link_into_pruned_ground_is_refused_as_uncovered() {
  let root = scratch_root("cover-link-uncovered");
  let keep = root.join("keep");
  let dropped = root.join("drop");
  std::fs::create_dir_all(&keep).expect("the ground the cover keeps");
  std::fs::create_dir_all(dropped.join("sub")).expect("the ground the cover drops");
  // A pre-existing link, standing before the watch: nothing here needs it created
  // live.
  std::os::unix::fs::symlink(&dropped, keep.join("link")).expect("the intermediate link");

  let w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let handle = w.watch(&root, Interest::all()).await.expect("watch root");
  let canonical = w.root_path(handle).expect("root path");
  let landing = canonical.join("drop").join("sub");
  let landing_object = objects_of(&[landing.clone()]);
  let all = objects_of(&[canonical.clone(), canonical.join("keep"), landing.clone()]);
  assert!(
    converge(|| wds_watching(&landing_object) == 1).await,
    "staging: the cold crawl armed the subtree the cover is about to take"
  );

  w.set_cover(handle, vec![canonical.join("keep")])
    .await
    .expect("set_cover shrink");
  assert!(
    converge(|| wds_watching(&landing_object) == 0).await,
    "staging: the cut reclaimed the landing's watch descriptor"
  );

  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let denied = w
    .sync_root(
      handle,
      canonical.join("keep").join("link").join("sub"),
      admission,
    )
    .await
    .expect_err("a sync whose landing the cut took cannot be admitted");
  match denied.error {
    crate::error::SyncRootError::DirUncovered { ref dir } => assert_eq!(
      dir, &landing,
      "the refusal names WHERE the caller's directory actually is, not the \
       spelling that reached covered ground"
    ),
    ref other => panic!("a landing outside the applied cover is uncovered ground: {other:?}"),
  }
  assert!(
    denied.admission.is_some(),
    "and it is pre-birth: the admission comes back for a same-sequence retry"
  );
  assert!(
    std::fs::read_dir(&landing)
      .expect("the landing is still there")
      .next()
      .is_none(),
    "nothing was created in the pruned subtree — no reserved directory, no marker"
  );

  close_and_drain(w, &all).await;
  let _ = std::fs::remove_dir_all(&root);
}

/// Arms one [`SYNC_DOOR_STEP`](crate::driver::SYNC_DOOR_STEP) entry and takes it
/// back down when the guard drops.
///
/// The list is process-global (the door samples on a pool thread, which no
/// thread-local of this test's own thread could reach), so an arming names both the
/// directory it speaks for and the point of the door's three it stands in front of;
/// this cell's scratch root makes the pair unique to it.
struct DoorStep {
  dir: PathBuf,
  point: crate::driver::SyncDoorPoint,
}

impl DoorStep {
  fn arm(
    dir: &Path,
    point: crate::driver::SyncDoorPoint,
    step: impl FnOnce() + Send + 'static,
  ) -> Self {
    crate::driver::SYNC_DOOR_STEP
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .push((dir.to_path_buf(), point, Box::new(step)));
    Self {
      dir: dir.to_path_buf(),
      point,
    }
  }
}

impl Drop for DoorStep {
  fn drop(&mut self) {
    crate::driver::SYNC_DOOR_STEP
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .retain(|(armed_for, armed_at, _)| *armed_for != self.dir || *armed_at != self.point);
  }
}

/// The kernel's own witness for the door's split sampling: a root whose death is
/// reported WHILE a later sampling job is still parked.
///
/// An open descriptor on a directory holds its dentry, and `rmdir` of a directory
/// something still holds unhashes the dentry instead of unlinking its inode — so
/// the `IN_DELETE_SELF` a watcher's root death rests on is DEFERRED until that
/// descriptor closes. That is what made a cancelled admission a correctness problem
/// rather than an accounting one: the old door opened root, target and reserved
/// directory in one pool closure, so a hang on the second open kept the root
/// descriptor for the whole hang, and a caller that dropped its future had no way
/// to reach into the closure and let it go. The root could then die with the
/// watcher reporting nothing at all.
///
/// Here the sampling is parked at the door's SECOND point — reaching it is itself
/// the proof that the root job answered — the caller's future is dropped, and the
/// root is removed while the second job is still inside the parked step. The root's
/// death must be observed on the stream within the ordinary deadline.
///
/// Revert witness: take the three opens in one closure again and this cell waits
/// out its deadline — the root's death is not reported until the gate is released.
///
/// Real inotify, because the fact is the kernel's: no modelled tree can be asked
/// what an open descriptor does to a `rmdir`'s notification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_parked_sampling_never_defers_the_root_s_death() {
  let outer = scratch_root("door-parked-rootdeath");
  let root = outer.join("watched");
  let target = root.join("a");
  std::fs::create_dir_all(&target).expect("the directory the sync names");

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let handle = w.watch(&root, Interest::all()).await.expect("watch root");
  let canonical = w.root_path(handle).expect("root path");

  let (entered, sampling_entered) = std::sync::mpsc::channel::<()>();
  let (release, released) = std::sync::mpsc::channel::<()>();
  let _step = DoorStep::arm(&target, crate::driver::SyncDoorPoint::Target, move || {
    let _ = entered.send(());
    // Returns when this cell drops its sender, and not before: for as long as this
    // call is here, the door's second open has not come back.
    let _ = released.recv();
  });

  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let mut call = Box::pin(w.sync_root(handle, &target, admission));
  // One job per poll: the first poll dispatches the ROOT sampling, and the door is
  // polled again only once that job answers. Short timeouts are what do that
  // polling — each returns as soon as the future is pending again.
  let mut reached = false;
  for _ in 0..600 {
    if tokio::time::timeout(Duration::from_millis(50), &mut call)
      .await
      .is_ok()
    {
      break;
    }
    if sampling_entered.try_recv().is_ok() {
      reached = true;
      break;
    }
  }
  assert!(
    reached,
    "staging: the door's ROOT sampling answered and its TARGET sampling reached the \
     parked step"
  );
  // The caller walks away with every reading the door had completed — the root's
  // above all — while the second job stays inside its own call.
  drop(call);

  std::fs::remove_dir(&target).expect("empty the root");
  std::fs::remove_dir(&root).expect("remove the watched root");
  let seen = wait_for(&mut w, |e| {
    e.root() == handle && (e.is_rescan() || (e.kind().is_removed() && e.path() == canonical))
  })
  .await;
  assert!(
    seen.is_some(),
    "the root's death is reported while a sampling job is still parked — nothing the \
     door completed is holding the root's dentry open"
  );

  // And the watcher closes once that job finally returns.
  drop(release);
  tokio::time::timeout(DEADLINE, w.close())
    .await
    .expect("close is not waiting on a sampling nobody is waiting for")
    .expect("the watcher closes");

  let _ = std::fs::remove_dir_all(&outer);
}

/// Arms one [`COOKIE_WRITE_STEP`](crate::driver::COOKIE_WRITE_STEP) entry and
/// takes it back down when the guard drops.
///
/// Keyed by the directory the sync named, which this cell's scratch root makes
/// unique to it.
struct WriteStep {
  dir: PathBuf,
}

impl WriteStep {
  fn arm(dir: &Path, step: impl FnOnce() + Send + 'static) -> Self {
    crate::driver::COOKIE_WRITE_STEP
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .push((dir.to_path_buf(), Box::new(step)));
    Self {
      dir: dir.to_path_buf(),
    }
  }
}

impl Drop for WriteStep {
  fn drop(&mut self) {
    crate::driver::COOKIE_WRITE_STEP
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .retain(|(armed_for, _)| *armed_for != self.dir);
  }
}

/// A stalled cookie write may not postpone an inotify root's death.
///
/// The door hands its completed pins to the detached WRITE, which owns them for
/// the whole of its run — and an open descriptor on a directory holds its dentry,
/// so `rmdir` of the root unhashes it instead of unlinking the inode and the
/// `IN_DELETE_SELF` the death rests on is queued only once that descriptor
/// closes. A write stalled in a syscall therefore holds the root's own death
/// notice for exactly as long as the stall lasts, which on a mount that never
/// answers has no bound: the scope would stay falsely live, refusing syncs as
/// in-flight and reporting close non-quiescent, with no event to say otherwise.
///
/// The periodic root-liveness tick is what does not depend on that notice. Here
/// the write is parked at its own top — reaching the step is itself the proof
/// that the admission's pins are held by it — the root is removed while it is
/// parked, and the death must be observed within a few liveness intervals rather
/// than at the release. Releasing the gate afterwards must still leave a clean
/// close.
///
/// Revert witness: narrow the tick's gate back to fanotify alone
/// ([`liveness_ticked`](crate::core::DriverCore::liveness_ticked)) and this cell
/// waits out its deadline — the death arrives only after the gate is released.
///
/// Real inotify, because the fact is the kernel's: no modelled tree can be asked
/// what an open descriptor does to a `rmdir`'s notification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_parked_cookie_write_never_defers_the_root_s_death() {
  let outer = scratch_root("write-parked-rootdeath");
  let root = outer.join("watched");
  let target = root.join("a");
  std::fs::create_dir_all(&target).expect("the directory the sync names");

  // A cadence far under the observation deadline, so "within a few intervals" is
  // a real bound rather than a restatement of the deadline.
  let mut w = TokioWatcher::new(
    WatcherOptions::new()
      .with_backend(Backend::Inotify)
      .with_root_liveness_interval(Duration::from_millis(200)),
  )
  .expect("build inotify watcher");
  let handle = w.watch(&root, Interest::all()).await.expect("watch root");
  let canonical = w.root_path(handle).expect("root path");

  let (entered, write_entered) = std::sync::mpsc::channel::<()>();
  let (release, released) = std::sync::mpsc::channel::<()>();
  let _step = WriteStep::arm(&target, move || {
    let _ = entered.send(());
    // Returns when this cell drops its sender, and not before: for as long as
    // this call is here, the write owning the admission's pins has not come back.
    let _ = released.recv();
  });

  let (admission, _ticket) = w.mint_sync_ticket().expect("this host seeds a watcher");
  let mut call = Box::pin(w.sync_root(handle, &target, admission));
  // The door samples on the pool one job per poll, then the driver admits and
  // dispatches the write; short timeouts are what keep polling across both.
  let mut reached = false;
  for _ in 0..600 {
    if tokio::time::timeout(Duration::from_millis(50), &mut call)
      .await
      .is_ok()
    {
      break;
    }
    if write_entered.try_recv().is_ok() {
      reached = true;
      break;
    }
  }
  assert!(
    reached,
    "staging: the sync was admitted and its write reached the parked step holding \
     the admission's pins"
  );
  // The caller walks away. The write keeps the pins regardless — which is the
  // whole of the problem — so the root's dentry stays held either way.
  drop(call);

  std::fs::remove_dir(&target).expect("empty the root");
  std::fs::remove_dir(&root).expect("remove the watched root");
  let seen = wait_for(&mut w, |e| {
    e.root() == handle && (e.is_rescan() || (e.kind().is_removed() && e.path() == canonical))
  })
  .await;
  assert!(
    seen.is_some(),
    "the root's death is reported while the write is still parked — the tick does \
     not wait on a notice the write's own descriptors are deferring"
  );

  // And the watcher closes once that write finally returns.
  drop(release);
  tokio::time::timeout(DEADLINE, w.close())
    .await
    .expect("close is not waiting on a write nobody is waiting for")
    .expect("the watcher closes");

  let _ = std::fs::remove_dir_all(&outer);
}
