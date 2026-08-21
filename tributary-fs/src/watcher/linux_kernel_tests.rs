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
