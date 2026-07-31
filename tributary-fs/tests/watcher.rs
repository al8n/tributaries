//! End-to-end integration through the public API against real FSEvents.
//!
//! Real-kernel timing is nondeterministic, so every assertion is
//! convergence-style: wait (bounded) until the expected fact is observed;
//! extra events — coalesced kinds, additional `Rescan`s — are always legal.

// not(miri): drives real FSEvents and a tokio runtime — syscalls miri cannot
// execute. The sans-I/O logic these exercise is covered by the lib unit tests.
#![cfg(all(target_os = "macos", feature = "tokio", not(miri)))]

use std::{
  path::{Path, PathBuf},
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use tributary_fs::{Event, Interest, TokioWatcher, WatcherOptions};

mod common;

use common::{Inventory, covers, delivered, reconcile};

/// Generous ceiling for one expected observation; macOS CI runners are slow.
const DEADLINE: Duration = Duration::from_secs(20);

/// A fresh canonicalized scratch root (`/tmp` is a symlink — FSEvents reports
/// resolved paths, so the root must be canonical before comparisons).
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

/// Two claims about one churn, kept apart because a backend can honour either
/// without the other.
///
/// The DECODE claim is that FSEvents' flag word became a verb naming the exact
/// object: an appearance (`ITEM_CREATED`, or `ITEM_MODIFIED` when the write
/// coalesced into the same record) and then a disappearance. The CONVERGENCE
/// claim is that a consumer obeying the stream ends holding the real tree. A
/// `Rescan` satisfies the second — by sending the consumer back to the
/// filesystem, which is all it promises — and refutes nothing about the first,
/// so the decode assertions refuse it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_and_remove_converge() {
  let root = scratch_root("create");
  let mut w = watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  assert_eq!(w.root_path(handle), Some(root.clone()));
  let mut inventory = Inventory::seeded(&root);

  let file = root.join("a.txt");
  std::fs::write(&file, b"hello").expect("create");
  let seen = wait_for(&mut w, |e| {
    delivered(e, &file) && (e.kind().is_created() || e.kind().is_modified())
  })
  .await;
  assert!(
    seen.is_some(),
    "the creation of {} was delivered as a verb, not merely rescanned",
    file.display()
  );
  inventory.apply(&seen.expect("the delivered create"));

  std::fs::remove_file(&file).expect("remove");
  let seen = wait_for(&mut w, |e| delivered(e, &file) && e.kind().is_removed()).await;
  assert!(
    seen.is_some(),
    "the removal of {} was delivered as a verb, not merely rescanned",
    file.display()
  );
  inventory.apply(&seen.expect("the delivered removal"));

  // Convergence needs a tree that OUTLIVES the churn to be a claim at all: the
  // create and the removal cancel, so a model driven by them alone agrees with
  // the empty root no matter what the stream said. A directory that arrives
  // already holding a file gives it something to hold — the model can reach
  // `keep/` only through the stream, by a delivered create or by re-reading
  // under a covering `Rescan`, and both are legal ways for FSEvents to get
  // there. Silence is not.
  let kept = root.join("keep");
  std::fs::create_dir(&kept).expect("create dir");
  std::fs::write(kept.join("kept.txt"), b"stay").expect("create nested");
  assert!(
    reconcile(&mut w, &mut inventory, DEADLINE).await,
    "the consumer converged on the real tree: {:?}",
    inventory.disagreement()
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// The rename vocabulary has exactly two legal endings, and both are
/// DELIVERIES: the halves pair into one `Moved` naming where the object came
/// from, or — when the two `ITEM_RENAMED` records land in different batches and
/// the vanished source can no longer be vouched for — they degrade to a
/// `Removed` plus a `Created`, which is the ending this cell's name calls
/// documented. A `Rescan` over the destination is neither. It is what the
/// backend emits when it could not say which of the two happened, so admitting
/// it here would leave the cell unable to distinguish a working rename decode
/// from no rename decode at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_is_a_move_or_the_documented_degrade() {
  let root = scratch_root("rename");
  let mut w = watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  let from = root.join("old.txt");
  let to = root.join("new.txt");
  std::fs::write(&from, b"payload").expect("create");
  assert!(
    wait_for(&mut w, |e| covers(e, &from)).await.is_some(),
    "the source object's ground is live before the rename"
  );

  std::fs::rename(&from, &to).expect("rename");
  let seen = wait_for(&mut w, |e| {
    let paired_move = e.kind().moved().is_some_and(|m| m.from() == from);
    delivered(e, &to) && (paired_move || e.kind().is_created())
  })
  .await;
  assert!(
    seen.is_some(),
    "the rename surfaced as a Moved naming {} or as its documented degrade — not as a rescan",
    from.display()
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_roots_are_rejected() {
  let root = scratch_root("overlap");
  let sub = root.join("sub");
  std::fs::create_dir_all(&sub).expect("create subdir");

  let w = watcher();
  let _outer = w.watch(&root, Interest::all()).await.expect("watch outer");

  let err = w
    .watch(&sub, Interest::all())
    .await
    .expect_err("a nested root must be rejected");
  assert!(err.is_overlaps(), "got {err:?}");

  let _ = std::fs::remove_dir_all(&root);
}

/// The last component with its ASCII case swapped — a second spelling of the
/// SAME object on the default case-insensitive APFS. `None` when the volume
/// is case-sensitive (the spellings are then genuinely different names, and
/// identity-based disjointness has nothing to prove).
fn case_alias_of(path: &Path) -> Option<PathBuf> {
  use std::os::unix::fs::MetadataExt;
  let name = path.file_name()?.to_str()?;
  let swapped: String = name
    .chars()
    .map(|c| {
      if c.is_ascii_lowercase() {
        c.to_ascii_uppercase()
      } else {
        c.to_ascii_lowercase()
      }
    })
    .collect();
  if swapped == name {
    return None;
  }
  let alias = path.with_file_name(swapped);
  let original = std::fs::metadata(path).ok()?;
  let aliased = std::fs::metadata(&alias).ok()?;
  ((original.dev(), original.ino()) == (aliased.dev(), aliased.ino())).then_some(alias)
}

/// Root disjointness is decided by object identity, so a case-swapped
/// spelling of a watched root — or a path nested through one — is rejected
/// exactly like the canonical spelling, while a genuinely distinct sibling is
/// admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_aliased_roots_are_rejected_on_insensitive_volumes() {
  let root = scratch_root("caseal");
  let Some(alias) = case_alias_of(&root) else {
    eprintln!("skipping: the volume is case-sensitive");
    return;
  };
  std::fs::create_dir_all(root.join("sub")).expect("create subdir");

  let w = watcher();
  let _held = w
    .watch(&root, Interest::all())
    .await
    .expect("watch original");

  let err = w
    .watch(&alias, Interest::all())
    .await
    .expect_err("one subtree, two spellings");
  assert!(err.is_overlaps(), "got {err:?}");

  let err = w
    .watch(alias.join("sub"), Interest::all())
    .await
    .expect_err("nested through the aliased spelling");
  assert!(err.is_overlaps(), "got {err:?}");

  let sibling = scratch_root("caseal-sib");
  let _distinct = w
    .watch(&sibling, Interest::all())
    .await
    .expect("a distinct sibling is admitted");

  let _ = std::fs::remove_dir_all(&root);
  let _ = std::fs::remove_dir_all(&sibling);
}

/// Two concurrent watches of one object under different spellings admit
/// exactly one winner (the reservation-time identity makes the collision
/// deterministic).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_case_aliased_watches_admit_exactly_one() {
  let root = scratch_root("caserace");
  let Some(alias) = case_alias_of(&root) else {
    eprintln!("skipping: the volume is case-sensitive");
    return;
  };

  let w = watcher();
  let (a, b) = tokio::join!(
    w.watch(&root, Interest::all()),
    w.watch(&alias, Interest::all())
  );
  assert_eq!(
    u8::from(a.is_ok()) + u8::from(b.is_ok()),
    1,
    "exactly one spelling wins: {a:?} / {b:?}"
  );

  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_and_non_directory_roots_are_rejected() {
  let root = scratch_root("badroots");
  let w = watcher();

  let err = w
    .watch(root.join("nope"), Interest::all())
    .await
    .expect_err("a missing root must be rejected");
  assert!(err.is_not_found(), "got {err:?}");

  let file = root.join("plain.txt");
  std::fs::write(&file, b"x").expect("create file");
  let err = w
    .watch(&file, Interest::all())
    .await
    .expect_err("a non-directory root must be rejected");
  assert!(err.is_not_a_directory(), "got {err:?}");

  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unwatch_stops_delivery() {
  let root = scratch_root("unwatch");
  let mut w = watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");

  // Prove the watch is live, then stop it.
  let probe = root.join("before.txt");
  std::fs::write(&probe, b"x").expect("create");
  assert!(wait_for(&mut w, |e| covers(e, &probe)).await.is_some());
  w.unwatch(handle).await.expect("unwatch");

  // A second unwatch of the same handle no longer names a live root.
  let err = w.unwatch(handle).await.expect_err("handle is dead");
  assert!(err.is_unknown_root(), "got {err:?}");

  // Give any decoded trailing events a moment to flush, then churn: nothing
  // about the new file may arrive.
  tokio::time::sleep(Duration::from_millis(500)).await;
  while tokio::time::timeout(Duration::from_millis(100), w.next())
    .await
    .is_ok()
  {}
  let after = root.join("after.txt");
  std::fs::write(&after, b"x").expect("create");
  let quiet = tokio::time::timeout(Duration::from_secs(2), async {
    while let Some(event) = w.next().await {
      assert_ne!(
        event.path(),
        after.as_path(),
        "an unwatched root delivered {event:?}"
      );
    }
  })
  .await;
  assert!(quiet.is_err(), "the stream stayed quiet after unwatch");

  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleted_root_surfaces_and_kills_the_handle() {
  let outer = scratch_root("rootdeath");
  let root = outer.join("watched");
  std::fs::create_dir_all(&root).expect("create watched root");

  let mut w = watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  let canonical = w.root_path(handle).expect("root path");

  std::fs::remove_dir_all(&root).expect("delete the watched root");
  let seen = wait_for(&mut w, |e| {
    e.root() == handle && (e.is_rescan() || (e.kind().is_removed() && e.path() == canonical))
  })
  .await;
  assert!(
    seen.is_some(),
    "the root's death surfaced as a Removed or a Rescan"
  );

  // The scope was torn down; the handle no longer names a live root.
  let err = match w.unwatch(handle).await {
    Err(err) => err,
    Ok(()) => {
      // The teardown may still be in flight; a second attempt must fail.
      tokio::time::sleep(Duration::from_millis(500)).await;
      w.unwatch(handle)
        .await
        .expect_err("handle outlived its root")
    }
  };
  assert!(err.is_unknown_root() || err.is_closed(), "got {err:?}");

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&outer);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_quiesces() {
  let root = scratch_root("close");
  let w = watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");
  tokio::time::timeout(Duration::from_secs(10), w.close())
    .await
    .expect("close resolved within its deadline")
    .expect("close confirmed");
  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewatch_after_root_death_succeeds() {
  let outer = scratch_root("rewatch");
  let root = outer.join("watched");
  std::fs::create_dir_all(&root).expect("create watched root");

  let mut w = watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  std::fs::remove_dir_all(&root).expect("delete the watched root");
  let seen = wait_for(&mut w, |e| e.root() == handle && e.is_rescan()).await;
  assert!(seen.is_some(), "the root's death surfaced");

  // The dead root's registry entry must stop blocking a fresh watch of the
  // recreated path; the driver's teardown propagates asynchronously, so poll.
  std::fs::create_dir_all(&root).expect("recreate the root");
  let deadline = std::time::Instant::now() + DEADLINE;
  let rewatched = loop {
    match w.watch(&root, Interest::all()).await {
      Ok(handle) => break handle,
      Err(err) if err.is_overlaps() => {
        assert!(
          std::time::Instant::now() < deadline,
          "the dead root kept blocking a fresh watch: {err:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
      Err(err) => panic!("unexpected watch failure: {err:?}"),
    }
  };
  assert_ne!(rewatched, handle, "a fresh scope for the recreated root");

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&outer);
}

/// Widening `x/y` → `x` under live churn: the handle survives, a covering
/// `Rescan` naming the new root arrives (pre-swap writes under `y` are
/// delivered or dominated by it), post-swap writes OUTSIDE the old subtree
/// deliver, `root_path` flips, the backend stays FSEvents, and the old root
/// is immediately re-watchable as its own scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_root_widens_under_live_churn() {
  let root = scratch_root("replace-widen");
  let sub = root.join("y");
  std::fs::create_dir_all(&sub).expect("create sub");
  let mut w = watcher();
  let handle = w.watch(&sub, Interest::all()).await.expect("watch");
  assert_eq!(w.root_path(handle), Some(sub.clone()));
  let backend = w.backend_of(handle).expect("a live backend");

  // Live churn right up to the swap.
  std::fs::write(sub.join("pre.txt"), b"pre").expect("write pre");

  w.replace_root(handle, &root)
    .await
    .expect("the swap commits");
  assert_eq!(w.root_path(handle), Some(root.clone()), "the view re-roots");
  assert_eq!(w.backend_of(handle), Some(backend));

  // The commit's covering Rescan names the new root — everything under it
  // (the pre-swap write included) is re-read by contract.
  let covering = wait_for(&mut w, |e| e.is_rescan() && e.path() == root).await;
  assert!(covering.is_some(), "the covering Rescan arrives");

  // Post-swap: a write OUTSIDE the old subtree delivers under the new root.
  let outside = root.join("outside.txt");
  std::fs::write(&outside, b"post").expect("write outside");
  let seen = wait_for(&mut w, |e| covers(e, &outside)).await;
  assert!(seen.is_some(), "newly covered ground is live");

  // The registry entry was OVERWRITTEN, not left at the old root: a watch
  // of the old (now nested) root refuses naming the NEW coverage.
  match w.watch(&sub, Interest::all()).await {
    Err(err) => match err {
      tributary_fs::WatchRootError::Overlaps { existing, .. } => assert_eq!(existing, root),
      other => panic!("expected Overlaps naming the new root, got {other:?}"),
    },
    Ok(_) => panic!("the widened coverage must contain the old root"),
  }
  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// The swap window is REPLAYED, not merely rescanned: the replacement stream
/// resumes the retiring one's FSEvents journal point, so a write made just
/// before the swap arrives as a concrete change under the new root — not only
/// as the covering `Rescan`. Best-effort by construction (a purged journal
/// falls back to the `Rescan`), so the cell asserts the pre-swap object is
/// covered AND that at least one non-`Rescan` change names it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_root_replays_the_swap_window_from_the_journal() {
  let root = scratch_root("replace-replay");
  let sub = root.join("y");
  std::fs::create_dir_all(&sub).expect("create sub");
  let mut w = watcher();
  let handle = w.watch(&sub, Interest::all()).await.expect("watch");

  // Prime the stream so it has a journal point to resume FROM (a stream that
  // never delivered mints no token).
  let primer = sub.join("primer.txt");
  std::fs::write(&primer, b"p").expect("write primer");
  assert!(
    wait_for(&mut w, |e| covers(e, &primer)).await.is_some(),
    "the stream is live and has minted a resume point"
  );

  // The write the swap must not lose: made under the OLD root, immediately
  // before the replace commits.
  let pre = sub.join("pre-swap.txt");
  std::fs::write(&pre, b"x").expect("write pre-swap");

  w.replace_root(handle, &root)
    .await
    .expect("the swap commits");

  // The journal replay delivers it as a CONCRETE change (the covering Rescan
  // would also "cover" it — this asserts the denser delivery the resume buys).
  let replayed = wait_for(&mut w, |e| delivered(e, &pre)).await;
  assert!(
    replayed.is_some(),
    "the pre-swap write is replayed from the journal, not only rescanned"
  );

  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}
