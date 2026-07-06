//! End-to-end integration through the public [`Tributaries`] API against a real OS
//! backend (FSEvents on macOS, inotify/fanotify on Linux).
//!
//! These exercise the umbrella's own contracts over the concrete stack: overlapping
//! subscriptions collapse onto one kernel watch (design §4), one raw change fans out to
//! every covering subscriber under its own id (design §5), the opt-in coalescer settles
//! a burst (design §6), and a coverage-loss `Rescan` reaches every subscriber (design
//! §8). They are **unprivileged** and run in the default test suite.
//!
//! Real-kernel timing is nondeterministic, so every assertion is convergence-style:
//! wait (bounded) until the expected fact is observed; extra events — coalesced kinds,
//! additional `Rescan`s — are always legal. A backend that reports nothing within the
//! deadline fails loudly rather than hanging (the outer `timeout`).

// not(miri): drives a real kernel watch and a tokio runtime — syscalls miri cannot
// execute. The sans-I/O logic these exercise (subsumption, fan-out, coalescing, epoch
// rebasing) is covered exhaustively by the crate's lib unit + property tests.
#![cfg(all(feature = "tokio", not(miri)))]

use std::{
  collections::HashSet,
  path::{Path, PathBuf},
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use tempfile::TempDir;
use tributaries::{
  DebounceConfig, Event, Filter, Interest, Subscription, TokioTributaries, TributariesOptions,
};

/// Generous ceiling for one expected observation; CI runners (macOS especially) are
/// slow and FSEvents batches on its own latency timer.
const DEADLINE: Duration = Duration::from_secs(20);

/// A fresh, **canonicalized** scratch directory under a `TempDir`. The temp dir root is
/// a symlink on macOS (`/var` → `/private/var`), and both FSEvents and the umbrella key
/// off canonical paths, so the returned path must already be canonical for the
/// `event.subscription()` / coverage comparisons to line up.
fn scratch(prefix: &str) -> (TempDir, PathBuf) {
  static COUNTER: AtomicU32 = AtomicU32::new(0);
  let dir = tempfile::Builder::new()
    .prefix(&format!(
      "tributaries-it-{}-{}-",
      prefix,
      COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
    .tempdir()
    .expect("create temp dir");
  let canonical = dir
    .path()
    .canonicalize()
    .expect("canonicalize scratch root");
  (dir, canonical)
}

/// A watcher with the given options.
fn watcher(options: TributariesOptions) -> TokioTributaries {
  TokioTributaries::new(options).expect("build watcher")
}

/// Waits until an event satisfying `pred` arrives, or the deadline lapses, returning it.
async fn wait_for(w: &mut TokioTributaries, mut pred: impl FnMut(&Event) -> bool) -> Option<Event> {
  tokio::time::timeout(DEADLINE, async {
    while let Some(event) = w.next().await {
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

/// Waits until events have been delivered to **every** subscription in `wanted` that
/// also satisfies `pred` (each match retires that subscription), or the deadline lapses.
/// Returns whether all were observed. Events for other subscriptions are ignored.
async fn wait_until_all(
  w: &mut TokioTributaries,
  wanted: &[Subscription],
  mut pred: impl FnMut(&Event) -> bool,
) -> bool {
  let mut outstanding: HashSet<Subscription> = wanted.iter().copied().collect();
  tokio::time::timeout(DEADLINE, async {
    while !outstanding.is_empty() {
      let Some(event) = w.next().await else {
        return false;
      };
      if outstanding.contains(&event.subscription()) && pred(&event) {
        outstanding.remove(&event.subscription());
      }
    }
    true
  })
  .await
  .unwrap_or(false)
}

/// An event "reaches" `path` when it names it directly or is a `Rescan` at the path or
/// one of its ancestors (a rescan obliges re-enumeration below it).
fn reaches(event: &Event, path: &Path) -> bool {
  event.path() == path || (event.is_rescan() && path.starts_with(event.path()))
}

/// Two overlapping subscriptions collapse onto a single kernel watch (design §4): the
/// second `watch()` of a nested path — which the layer below would reject with
/// `Overlaps` — succeeds here, because subsumption folds it onto the shared root rather
/// than arming a second, overlapping kernel watch. That success is the observable proof
/// exactly one kernel watch is armed (the disjointness the fs layer enforces would
/// otherwise reject it), since the fanotify-only `backend_stats` is unavailable here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_subscriptions_one_kernel_watch() {
  let (_dir, root) = scratch("overlap");
  let sub_dir = root.join("nested");
  std::fs::create_dir_all(&sub_dir).expect("create nested dir");

  let mut w = watcher(TributariesOptions::new());

  // Watch the outer root, then a nested path. The nested watch OVERLAPS the outer one;
  // tributary-fs rejects overlapping roots, so this succeeding proves the umbrella
  // subsumed both onto the one already-armed kernel watch (design §4).
  let outer = w
    .watch(&root, Interest::all(), Filter::all())
    .await
    .expect("outer watch arms one kernel watch");
  let nested = w
    .watch(&sub_dir, Interest::all(), Filter::all())
    .await
    .expect("an overlapping nested watch is subsumed, never surfaces Overlaps");
  assert_ne!(
    outer, nested,
    "each watch call yields its own subscription id"
  );

  // A change under the nested overlap is still delivered (the shared watch is live).
  let file = sub_dir.join("probe.txt");
  std::fs::write(&file, b"hi").expect("write probe");
  assert!(
    wait_for(&mut w, |e| reaches(e, &file)).await.is_some(),
    "the single shared kernel watch delivers a change under the overlap"
  );

  w.close().await.expect("close");
}

/// One raw change under the overlap of two subscriptions fans out to BOTH, each under
/// its own subscription id (design §5).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn event_fans_to_both_overlapping_subs() {
  let (_dir, root) = scratch("fanout");
  let sub_dir = root.join("nested");
  std::fs::create_dir_all(&sub_dir).expect("create nested dir");

  let mut w = watcher(TributariesOptions::new());

  // Two overlapping subscriptions: the outer root and the nested subtree. A change under
  // the nested subtree is covered by BOTH.
  let outer = w
    .watch(&root, Interest::all(), Filter::all())
    .await
    .expect("watch outer");
  let inner = w
    .watch(&sub_dir, Interest::all(), Filter::all())
    .await
    .expect("watch nested");

  let file = sub_dir.join("shared.txt");
  std::fs::write(&file, b"payload").expect("write shared file");

  // The one write must reach BOTH subscriptions, each retagged with its own id.
  let both = wait_until_all(&mut w, &[outer, inner], |e| reaches(e, &file)).await;
  assert!(
    both,
    "a write under the overlap fans out to both the outer and the nested subscription"
  );

  w.close().await.expect("close");
}

/// A subscription's [`Filter`] narrows what it is delivered (design §7): a filter that
/// admits only a chosen file excludes changes to a sibling, while an all-admitting
/// subscription of the same root still sees both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filter_narrows_delivery_on_the_real_stack() {
  let (_dir, root) = scratch("filter");
  let mut w = watcher(TributariesOptions::new());

  let wanted = root.join("keep.log");
  let wanted_for_pred = wanted.clone();
  // One subscription admits only `keep.log`; a second admits everything.
  let picky = w
    .watch(
      &root,
      Interest::all(),
      Filter::new(move |e| e.path() == wanted_for_pred),
    )
    .await
    .expect("watch with a narrowing filter");
  let permissive = w
    .watch(&root, Interest::all(), Filter::all())
    .await
    .expect("watch admitting everything");

  // Touch the wanted file: BOTH subscriptions must see it (it passes the picky filter).
  std::fs::write(&wanted, b"a").expect("write keep.log");
  assert!(
    wait_until_all(&mut w, &[picky, permissive], |e| reaches(e, &wanted)).await,
    "the admitted file reaches both the filtered and the permissive subscription"
  );

  // Touch an excluded sibling: only the permissive subscription may see it. The picky
  // subscription must NEVER be delivered the sibling — assert the permissive one sees it
  // while no picky delivery for the sibling ever arrives within a bounded window.
  let excluded = root.join("ignore.tmp");
  std::fs::write(&excluded, b"b").expect("write ignore.tmp");
  let saw_excluded = tokio::time::timeout(DEADLINE, async {
    while let Some(event) = w.next().await {
      assert!(
        !(event.subscription() == picky && event.path() == excluded),
        "the narrowing filter delivered an excluded sibling to the picky subscription"
      );
      if event.subscription() == permissive && reaches(&event, &excluded) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    saw_excluded,
    "the permissive subscription still sees the sibling the filter excluded"
  );

  w.close().await.expect("close");
}

/// With a [`DebounceConfig`], a rapid burst of writes to one path collapses to a
/// bounded number of delivered events (design §6). Real FSEvents already coalesces, so
/// this asserts the settled outcome — the file's final change is delivered and the burst
/// does not fan into an unbounded storm — rather than an exact count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debounced_burst_coalesces() {
  let (_dir, root) = scratch("debounce");
  // A settle window comfortably longer than the burst, so the whole burst lands inside
  // one quiet window and collapses; a hold cap that still bounds a busy path.
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_millis(200))
    .with_max_hold(Duration::from_millis(2000));
  let mut w = watcher(TributariesOptions::new().debounce(cfg));

  let sub = w
    .watch(&root, Interest::all(), Filter::all())
    .await
    .expect("watch with debounce");

  // Fire a rapid burst of writes to one path.
  let file = root.join("busy.txt");
  for i in 0..20u32 {
    std::fs::write(&file, i.to_le_bytes()).expect("burst write");
  }

  // The coalesced settle must still deliver *something* covering the file (no silent
  // loss): the burst collapses but its net effect emits.
  let seen = wait_for(&mut w, |e| e.subscription() == sub && reaches(e, &file)).await;
  assert!(
    seen.is_some(),
    "the debounced burst collapses but its settled effect is still delivered"
  );

  // Drain briefly and confirm the burst did not explode into a per-write storm: after
  // the settle window, the number of further events covering the file is bounded well
  // below the 20 raw writes (coalescing held). This is a soft, timing-tolerant bound.
  let mut extra = 0u32;
  let _ = tokio::time::timeout(cfg.quiet_window() * 3, async {
    while let Some(event) = w.next().await {
      if event.subscription() == sub && reaches(&event, &file) {
        extra += 1;
      }
    }
  })
  .await;
  assert!(
    extra < 20,
    "the burst coalesced (saw {extra} extra file events, far below the 20 raw writes)"
  );

  w.close().await.expect("close");
}

/// A coverage-loss `Rescan` reaches EVERY subscriber of the affected root (design §8).
/// Deleting the watched root surfaces its terminal `Rescan` (or `Removed`) to every
/// subscription of that root, bypassing coverage narrowing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rescan_delivered_to_all() {
  // An outer dir holds the watched root, so deleting the root does not delete the temp
  // dir out from under the still-open handle.
  let (_dir, outer) = scratch("rescan");
  let root = outer.join("watched");
  let nested = root.join("nested");
  std::fs::create_dir_all(&nested).expect("create nested");

  let mut w = watcher(TributariesOptions::new());

  // Two overlapping subscriptions of the same (subsumed) root: the outer root and a
  // nested subtree. A plain change at the root would NOT reach the nested subscription,
  // but a coverage-loss Rescan must reach BOTH.
  let outer_sub = w
    .watch(&root, Interest::all(), Filter::all())
    .await
    .expect("watch root");
  let nested_sub = w
    .watch(&nested, Interest::all(), Filter::all())
    .await
    .expect("watch nested");

  // Destroy the watched subtree: its coverage is lost, which must surface as a
  // Rescan (or a Removed of the root) to every subscriber of the root.
  std::fs::remove_dir_all(&root).expect("delete the watched root");

  let all = wait_until_all(&mut w, &[outer_sub, nested_sub], |e| {
    e.is_rescan() || (e.kind().is_removed() && reaches(e, &root))
  })
  .await;
  assert!(
    all,
    "the coverage-loss Rescan (or root Removed) reaches every subscriber of the root"
  );

  w.close().await.expect("close");
}
