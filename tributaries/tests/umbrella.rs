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

// Drives a real kernel watch on a tokio runtime: off miri (which cannot execute the
// syscalls) and gated onto the platforms with a real backend (elsewhere `tributary-fs`
// compiles but arms fail at runtime). The sans-I/O logic these exercise (subsumption,
// fan-out, coalescing, epoch rebasing) is covered exhaustively by the crate's lib
// unit + property tests.
#![cfg(all(
  feature = "tokio",
  not(miri),
  any(target_os = "macos", target_os = "linux", target_os = "windows")
))]

use std::{
  collections::HashSet,
  ffi::OsString,
  num::NonZeroUsize,
  path::{Path, PathBuf},
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use futures_util::FutureExt;
use tempfile::TempDir;
use tributaries::{
  Debounce, DebounceConfig, Event, Filter, Subscription, TokioTributaries, TributariesOptions,
  WatchOptions, WatcherOptions,
};

/// The concrete delivered-event type of the local-fs driver (`C = OsString`, `V = ()`).
type Ev = Event<OsString, ()>;

/// A path's `OsString` components — the located key the generic `watch` takes (the fs
/// convenience the umbrella keys on; the caller supplies canonical paths, as `scratch`
/// does).
fn key(path: &Path) -> Vec<OsString> {
  path
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

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

/// A watcher with the given umbrella options (default fs-watcher transport options).
fn watcher(options: TributariesOptions) -> TokioTributaries {
  TokioTributaries::new(WatcherOptions::new(), options).expect("build watcher")
}

/// Waits until an event satisfying `pred` arrives, or the deadline lapses, returning it.
async fn wait_for(w: &mut TokioTributaries, mut pred: impl FnMut(&Ev) -> bool) -> Option<Ev> {
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
  mut pred: impl FnMut(&Ev) -> bool,
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
/// one of its ancestors — the path-typed convenience over [`Event::reaches`] (the fs
/// key IS the path's components).
fn reaches(event: &Ev, path: &Path) -> bool {
  event.reaches(&key(path))
}

/// One settle probe's window; the handshake below re-probes until [`DEADLINE`].
const SETTLE_STEP: Duration = Duration::from_millis(250);

/// Settles a **pre-existing** directory's coverage before a delivery probe, so that probe
/// tests a real delivery rather than the registration window.
///
/// `watch()` resolves once the ROOT's native stream is live — never once a descending
/// backend's bootstrap crawl has armed the subtree that already existed below it. A write
/// into an already-existing subdirectory issued the instant `watch()` returns can therefore
/// land in a not-yet-armed directory: no kernel record, and no listing announces it either
/// (the registration's crawl reports no inventory for ground that merely pre-existed the
/// grant). What answers it is the window's closing `Rescan` **at the root** — and since
/// [`Event::reaches`] is satisfied by a `Rescan` at the key **or any ancestor**, a probe
/// asserted with `reaches` alone inside that window is satisfied by the `Rescan` and proves
/// nothing about delivery. That softness is older than the window: any `Rescan`-only
/// backend would have satisfied such a predicate. What changed is only that it became
/// reachable on the common path, at registration.
///
/// The handshake: touch a throwaway name in `dir` until one comes back as a **genuine**
/// (non-`Rescan`) event. A genuine delivery for a file in `dir` is proof `dir` itself is
/// armed and live, which is exactly what the cell's own probe needs — and it establishes
/// that without waiting on the bootstrap `Rescan`, which would couple these cells to the
/// mechanism under change and does not exist at all on a kernel-recursive backend (there
/// the first probe is delivered immediately and the handshake costs one write).
async fn settle_delivery_under(w: &mut TokioTributaries, dir: &Path) {
  let settled = tokio::time::timeout(DEADLINE, async {
    let mut attempt = 0u32;
    loop {
      let probe = dir.join(format!("settle-{attempt}.probe"));
      attempt += 1;
      std::fs::write(&probe, b"settle").expect("write the settle probe");
      let seen = tokio::time::timeout(SETTLE_STEP, async {
        while let Some(event) = w.next().await {
          if !event.is_rescan() && reaches(&event, &probe) {
            return true;
          }
        }
        false
      })
      .await
      .unwrap_or(false);
      if seen {
        return;
      }
    }
  })
  .await;
  assert!(
    settled.is_ok(),
    "coverage under {} never settled: no probe written there came back as a genuine event",
    dir.display()
  );
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
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("outer watch arms one kernel watch");
  let nested = w
    .watch(key(&sub_dir), (), WatchOptions::new())
    .await
    .expect("an overlapping nested watch is subsumed, never surfaces Overlaps");
  assert_ne!(
    outer, nested,
    "each watch call yields its own subscription id"
  );

  // A change under the nested overlap is still delivered (the shared watch is live). Settle
  // `nested`'s coverage first, then demand a GENUINE event: a `Rescan` at the root reaches
  // every key below it, so `reaches` alone would be satisfied by the registration window's
  // closing `Rescan` without the shared watch delivering anything.
  settle_delivery_under(&mut w, &sub_dir).await;
  let file = sub_dir.join("probe.txt");
  std::fs::write(&file, b"hi").expect("write probe");
  assert!(
    wait_for(&mut w, |e| !e.is_rescan() && reaches(e, &file))
      .await
      .is_some(),
    "the single shared kernel watch delivers a change under the overlap"
  );

  w.close().await.expect("close");
}

/// The **widen** narrow-first-then-ancestor case over the PRODUCTION armer (design §4):
/// watch a child, then watch its ancestor. The ancestor watch is a widen — it subsumes
/// the child's root. Because [`tributary_fs::Watcher::watch`] rejects a root overlapping
/// a live one (`Overlaps`), the widen can only succeed by unwatching the subsumed child
/// root BEFORE arming the wider ancestor root. This asserts (a) the ancestor watch
/// SUCCEEDS (`Ok`, not `Overlaps`) — the regression: the pre-fix arm-before-unwatch order
/// would have failed here against the real watcher; (b) the child subscription receives
/// the widen dominating `Rescan`; and (c) a subsequent write under the child is delivered
/// to BOTH subscriptions — events keep routing through the widened root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn widen_narrow_first_then_ancestor_succeeds_and_keeps_routing() {
  let (_dir, root) = scratch("widen");
  let child = root.join("child");
  std::fs::create_dir_all(&child).expect("create child dir");

  let mut w = watcher(TributariesOptions::new());

  // Watch the NARROW child first (arms one kernel watch of /root/child).
  let child_sub = w
    .watch(key(&child), (), WatchOptions::new())
    .await
    .expect("watch the narrow child first");

  // Now watch its ANCESTOR /root — a widen. Against the real watcher this succeeds ONLY
  // because the widen unwatches /root/child before arming /root; the pre-fix
  // arm-before-unwatch order would have been rejected `Overlaps` here.
  let root_sub = w.watch(key(&root), (), WatchOptions::new()).await.expect(
    "the ancestor watch widens (Ok, not Overlaps) — arms the wider root after \
             disarming the subsumed child",
  );
  assert_ne!(
    child_sub, root_sub,
    "each watch yields its own subscription id"
  );

  // (b) The re-pointed child subscription receives the widen dominating Rescan (naming
  // the widened root, or an ancestor of the child).
  let saw_rescan = wait_for(&mut w, |e| {
    e.subscription() == child_sub && e.is_rescan() && reaches(e, &child)
  })
  .await;
  assert!(
    saw_rescan.is_some(),
    "the widen re-point delivers the child subscription a dominating Rescan"
  );

  // (c) A write under the child after the widen must reach BOTH subscriptions — the child
  // (re-pointed) and the ancestor — proving events keep routing through the widened root.
  let file = child.join("after-widen.txt");
  std::fs::write(&file, b"payload").expect("write under child after widen");
  let both = wait_until_all(&mut w, &[child_sub, root_sub], |e| reaches(e, &file)).await;
  assert!(
    both,
    "a write under the child routes to both subscriptions through the widened root"
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
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch outer");
  let inner = w
    .watch(key(&sub_dir), (), WatchOptions::new())
    .await
    .expect("watch nested");

  // Settle `nested`'s coverage before probing, and demand GENUINE events below: the
  // registration window's closing `Rescan` is at the root, and a root `Rescan` reaches every
  // key under it — so `reaches` alone would fan a re-enumeration instruction out to both
  // subscriptions and satisfy the fan-out claim with no change delivered at all.
  settle_delivery_under(&mut w, &sub_dir).await;
  let file = sub_dir.join("shared.txt");
  std::fs::write(&file, b"payload").expect("write shared file");

  // The one write must reach BOTH subscriptions, each retagged with its own id.
  let both = wait_until_all(&mut w, &[outer, inner], |e| {
    !e.is_rescan() && reaches(e, &file)
  })
  .await;
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
      key(&root),
      (),
      WatchOptions::new().with_filter(Filter::new(move |e| e.path() == wanted_for_pred)),
    )
    .await
    .expect("watch with a narrowing filter");
  let permissive = w
    .watch(key(&root), (), WatchOptions::new())
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
    .watch(key(&root), (), WatchOptions::new())
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

/// Per-subscription debounce override (design §6): with the watcher-global
/// debounce ON, a sibling subscription of the SAME root watched with [`Debounce::Off`]
/// passes its events through raw while the inheriting subscription's delivery is held
/// for the settle window — so the Off subscription's first delivery arrives strictly
/// before the settled sibling's, and both eventually observe the change (no silent
/// loss).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_sub_debounce_off_overrides_the_global_default() {
  let (_dir, root) = scratch("debounce-override");
  // A LONG settle window: the inheriting subscription's delivery is held well past the
  // last kernel event, while the Off override's rides through on the same tick its raw
  // event arrives — the relative first-delivery order is deterministic even on a slow
  // CI kernel (the event channel is FIFO, and the settled emission is enqueued at least
  // a full quiet window later).
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_secs(3))
    .with_max_hold(Duration::from_secs(15));
  let mut w = watcher(TributariesOptions::new().debounce(cfg));

  let settled = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch inheriting the global debounce");
  let raw = w
    .watch(
      key(&root),
      (),
      WatchOptions::new().with_debounce(Debounce::Off),
    )
    .await
    .expect("watch with the per-sub Off override");

  let file = root.join("busy.txt");
  for i in 0..10u32 {
    std::fs::write(&file, i.to_le_bytes()).expect("burst write");
  }

  // Scan the merged stream, recording each subscription's FIRST observation of the
  // file: both must arrive (no silent loss), the raw one first (raw ordering observed).
  let mut first: Vec<Subscription> = Vec::new();
  let observed = tokio::time::timeout(DEADLINE, async {
    while let Some(event) = w.next().await {
      if reaches(&event, &file) && !first.contains(&event.subscription()) {
        first.push(event.subscription());
        if first.len() == 2 {
          return true;
        }
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    observed,
    "both the raw and the settled subscription observe the burst"
  );
  assert_eq!(
    first,
    vec![raw, settled],
    "the Off override's raw delivery precedes the settled sibling's held one"
  );

  w.close().await.expect("close");
}

/// A move decomposes per subscriber by two-endpoint coverage (design §5): a rename
/// within an outer watched root, between two nested subscriptions, delivers the
/// source-only subscription a `Removed(from)` (it saw the file leave its tree) and the
/// destination-only subscription a `Created(to)` (it saw the file arrive) — while the
/// outer subscription covering both endpoints sees the move itself. The source-only
/// subscription learning the file left is exactly the move-out the pre-fix fan-out
/// silently dropped (it tested only the destination path).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn move_decomposes_across_sibling_subscriptions() {
  let (_dir, root) = scratch("move");
  let src = root.join("src");
  let dst = root.join("dst");
  std::fs::create_dir_all(&src).expect("create src");
  std::fs::create_dir_all(&dst).expect("create dst");

  let mut w = watcher(TributariesOptions::new());

  // The outer root covers BOTH endpoints; two nested subs each cover ONE. All three are
  // subsumed onto the single /root kernel watch, so the one rename fans out to all.
  let _outer = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch outer root");
  let src_sub = w
    .watch(key(&src), (), WatchOptions::new())
    .await
    .expect("watch src subtree");
  let dst_sub = w
    .watch(key(&dst), (), WatchOptions::new())
    .await
    .expect("watch dst subtree");

  // Create then rename a file from src/ to dst/ — a within-root move.
  let from = src.join("f.txt");
  let to = dst.join("f.txt");
  std::fs::write(&from, b"payload").expect("write source file");
  // Let the create settle so the rename is observed as a move, not folded into create.
  let _ = wait_for(&mut w, |e| e.subscription() == src_sub && reaches(e, &from)).await;
  std::fs::rename(&from, &to).expect("rename src -> dst");

  // The source-only subscription must observe the file LEFT its tree: a Removed at the
  // source (the move-out projection), or a coverage-loss Rescan. It must NOT be silently
  // skipped — the core assertion of the move-out fix.
  let src_saw_departure = wait_for(&mut w, |e| {
    e.subscription() == src_sub && (e.kind().is_removed() || e.is_rescan()) && reaches(e, &from)
  })
  .await;
  assert!(
    src_saw_departure.is_some(),
    "the source-only subscription learns the file left its tree (move-out Removed) — \
     never silently dropped"
  );

  // The destination-only subscription must observe the file ARRIVED: a Created at the
  // destination (the move-in projection), or a Rescan.
  let dst_saw_arrival = wait_for(&mut w, |e| {
    e.subscription() == dst_sub
      && (e.kind().is_created() || e.kind().is_modified() || e.is_rescan())
      && reaches(e, &to)
  })
  .await;
  assert!(
    dst_saw_arrival.is_some(),
    "the destination-only subscription sees the file arrive (move-in Created)"
  );

  w.close().await.expect("close");
}

/// A deleted watched root is retired and its path can be re-watched (design §4,
/// dead-root retirement). After the root is deleted, `tributary-fs` tears its handle
/// down and emits a terminal `Rescan`/`Removed`; the umbrella fans that out and then
/// retires the dead root. Recreating the path and watching it again must therefore
/// re-arm a FRESH kernel root (not resolve `Covered` against the dead handle), and a
/// write under the recreated root must reach the new subscription. The regression: a
/// stale subsumer entry would make the second watch `Covered` against a dead handle, so
/// the new subscription would receive nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleted_root_is_retired_and_can_be_rewatched() {
  // An outer dir holds the watched root, so deleting the root does not delete the temp
  // dir out from under the still-open handle, and the path can be recreated in place.
  let (_dir, outer) = scratch("retire");
  let root = outer.join("watched");
  std::fs::create_dir_all(&root).expect("create the watched root");

  let mut w = watcher(TributariesOptions::new());

  // Watch /root (arms one kernel watch).
  let first = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch the root");

  // Delete /root: its handle is torn down and a terminal Rescan/Removed surfaces to the
  // subscription. Draining it through `next()` is what drives retirement (the umbrella
  // retires the dead root right after fanning the terminal signal out).
  std::fs::remove_dir_all(&root).expect("delete the watched root");
  let saw_terminal = wait_for(&mut w, |e| {
    e.subscription() == first && (e.is_rescan() || (e.kind().is_removed() && reaches(e, &root)))
  })
  .await;
  assert!(
    saw_terminal.is_some(),
    "the deleted root surfaces a terminal Rescan/Removed to its subscription"
  );

  // Recreate the path and watch it AGAIN. This must re-arm a fresh kernel root — if the
  // dead root had not been retired, the subsumer would still hold its (dead) handle and
  // this would resolve `Covered` against it, delivering nothing below.
  std::fs::create_dir_all(&root).expect("recreate the watched root");
  let second = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("re-watch the recreated root re-arms a fresh kernel root");

  // A write under the recreated root must reach the NEW subscription (proving the fresh
  // arm is live, not a dead handle the stale entry would have reused).
  let file = root.join("after-rewatch.txt");
  std::fs::write(&file, b"payload").expect("write under the recreated root");
  let delivered = wait_for(&mut w, |e| e.subscription() == second && reaches(e, &file)).await;
  assert!(
    delivered.is_some(),
    "a write under the recreated, re-armed root reaches the new subscription"
  );

  w.close().await.expect("close");
}

/// The set-cover effect-completion fence over the public API — issue #17's exact loss, now
/// impossible. Sub A pins the root at its own key; sub B covers `/keep`. Unwatching A leaves
/// the shared root over-broad, so the umbrella issues the fire-and-forget PRUNE down to
/// `{/keep}` (a descending backend reclaims the kernel watches under `/drop`). A later
/// `watch(/drop/deep)` is then Covered-OUTSIDE the narrowed cover, so the umbrella AWAITS
/// [`Source::grow`] before committing — and the fs binding's ack resolves at **watch-live**,
/// never at effect-queue time, with the grow ordered after the prune on the watcher's one FIFO
/// control channel. A write into `/drop/deep` **immediately** after `watch()` returns — no
/// settle, no convergence wait; the immediacy IS the fence's guarantee ("changes from now on",
/// dated from the return) — must reach the newcomer as a genuine event, with no `Rescan`
/// standing in for a lost write. Pre-fence, the grow ack resolved at effect-QUEUE time, so this
/// write raced the re-arm cascade and was silently lost on inotify.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn covered_outside_grow_fence_delivers_an_immediate_write() {
  let (_dir, root) = scratch("grow-fence");
  let keep = root.join("keep");
  let deep = root.join("drop").join("deep");
  std::fs::create_dir_all(&keep).expect("create keep");
  std::fs::create_dir_all(&deep).expect("create drop/deep");

  let mut w = watcher(TributariesOptions::new());

  // Sub A pins the root at its own key; sub B covers /keep. Both ride the one kernel root.
  let sub_a = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch the root");
  let _sub_b = w
    .watch(key(&keep), (), WatchOptions::new())
    .await
    .expect("watch /keep");

  // Unwatch A: the root survives for B but is over-broad — the prune to {/keep} fires.
  w.unwatch(sub_a)
    .await
    .expect("unwatch the root-key subscription");

  // Covered-OUTSIDE watch of the pruned region: the awaited grow re-arms /drop/deep and the
  // watch returns only once that coverage is live. `CoverageIncomplete` is the documented
  // retryable outcome — the fence conservatively degrades a window any covering `Rescan`
  // touched (including a grow coalescing into a still-in-flight read on a slow host) — so
  // the caller's contract is to re-issue; a clean settle then applies.
  let mut newcomer = None;
  for _ in 0..40 {
    match w.watch(key(&deep), (), WatchOptions::new()).await {
      Ok(sub) => {
        newcomer = Some(sub);
        break;
      }
      Err(err) if err.is_coverage_incomplete() => {
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
      Err(err) => panic!("the covered-outside watch failed: {err}"),
    }
  }
  let newcomer = newcomer.expect("the covered-outside watch grows and commits within the budget");

  // Write IMMEDIATELY on return — deliberately no wait of any kind between watch() and the
  // write; only the delivery observation below is convergence-style.
  let file = deep.join("immediate.txt");
  std::fs::write(&file, b"payload").expect("write into the regrown subtree");

  let observed = wait_for(&mut w, |e| {
    e.subscription() == newcomer && !e.is_rescan() && reaches(e, &file)
  })
  .await;
  assert!(
    observed.is_some(),
    "the write issued immediately after the covered-outside watch returned is delivered to the \
     newcomer as a genuine event — the grow fence left no request→apply window to lose it in"
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
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch root");
  let nested_sub = w
    .watch(key(&nested), (), WatchOptions::new())
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

/// Close-responsiveness under backpressure (design backpressure doc, invariants II/III):
/// a **stalled consumer** (never draining `next()`) fills a tiny bounded event channel, so
/// the owner sheds the affected subscription to a parked `Rescan`. Because the owner NEVER
/// awaits the event channel, `close()` is still serviced promptly on the separate command
/// mailbox — it must return within the deadline rather than deadlocking behind the full
/// channel (the failure mode of the rejected bounded-plus-`send().await` design).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_is_responsive_while_event_channel_is_full() {
  let (_dir, root) = scratch("close-full");
  // A one-slot event channel, so a couple of undrained changes fill it.
  let options =
    TributariesOptions::new().with_event_capacity(NonZeroUsize::new(1).expect("nonzero"));
  let w = watcher(options);
  let _sub = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch the root");

  // Generate a burst of changes WITHOUT ever draining next(): the bounded channel fills and
  // the owner parks Rescans — it never blocks on the channel.
  for i in 0..50u32 {
    std::fs::write(root.join(format!("f{i}.txt")), b"x").expect("burst write");
  }
  // Let the owner pump the source and fill the channel.
  tokio::time::sleep(Duration::from_millis(300)).await;

  // Close must still return promptly even though the event channel is full and undrained.
  let closed = tokio::time::timeout(DEADLINE, w.close()).await;
  assert!(
    closed.is_ok(),
    "close returned while the event channel was full — not deadlocked behind it"
  );
  assert!(
    closed.expect("close within the deadline").is_ok(),
    "close succeeded"
  );
}

/// End-to-end backpressure recovery over the real stack (design backpressure doc, invariant
/// I, no-silent-loss): a consumer that stalls under a tiny bounded channel and later
/// RESUMES must receive a coverage `Rescan` for the affected subscription — the shed's
/// dominating re-enumeration signal, so nothing lost to the overflow is silently dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_then_resumed_consumer_gets_a_rescan_no_silent_loss() {
  let (_dir, root) = scratch("stall-resume");
  let options =
    TributariesOptions::new().with_event_capacity(NonZeroUsize::new(1).expect("nonzero"));
  let mut w = watcher(options);
  let sub = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch the root");

  // Stall: generate a burst without draining, so the one-slot channel overflows and the
  // owner parks a dominating Rescan for the subscription.
  for i in 0..50u32 {
    std::fs::write(root.join(format!("f{i}.txt")), b"x").expect("burst write");
  }
  tokio::time::sleep(Duration::from_millis(300)).await;

  // Resume draining: among the delivered events the owner must surface a Rescan for the
  // subscription (its parked shed), so the consumer re-enumerates rather than losing the
  // dropped deltas silently.
  let saw_rescan = wait_for(&mut w, |e| e.subscription() == sub && e.is_rescan()).await;
  assert!(
    saw_rescan.is_some(),
    "the resumed consumer receives the shed's dominating Rescan (no silent loss)"
  );

  w.close().await.expect("close");
}

/// The sync barrier's promise, end to end against the real kernel: after
/// `sync` resolves, every change made BEFORE the call is already deliverable —
/// a plain drain finds them all, with no sleeping and no polling. The cookie
/// that establishes the barrier is itself never delivered (the reserved
/// namespace is suppressed), and the barrier resolves `Delivered`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_resolves_once_pre_call_changes_are_deliverable() {
  let (_tmp, root) = scratch("sync-barrier");
  let mut w = watcher(TributariesOptions::new());
  let sub = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch");

  // The changes the barrier must account for — made BEFORE the sync call.
  for i in 0..8 {
    std::fs::write(root.join(format!("pre-{i}.txt")), b"x").expect("write");
  }

  let outcome = w
    .sync(sub, Duration::from_secs(20))
    .await
    .expect("the barrier is established");
  assert!(
    outcome.is_delivered() || outcome.is_dominated(),
    "the barrier is met by delivery or by domination: {outcome:?}"
  );

  // Now DRAIN what is already deliverable — no sleeps, no retries. Every
  // pre-sync write must be accounted for: named directly, or covered by a
  // Rescan that obliges re-enumeration.
  let mut seen = std::collections::HashSet::new();
  let mut rescanned = false;
  while let Some(event) = w.next().now_or_never().flatten() {
    if event.kind().is_rescan() {
      // Not held to the artifact rule, and the same reason as its twin in
      // `indexer_shaped.rs`: the umbrella never classifies a `Rescan` against the
      // reserved namespace, because it names no object and masking one would hide
      // a coverage loss inside the namespace whose events it may have eaten. A
      // LOCATED `Rescan` may therefore name the cookie directory itself. The rule
      // below is about DELIVERED CHANGES.
      rescanned = true;
      continue;
    }
    if let Some(leaf) = event.key().last().and_then(|c| c.to_str()) {
      assert!(
        !leaf.starts_with(".tributaries-sync-"),
        "a sync cookie must NEVER surface on a consumer stream: {leaf}"
      );
      seen.insert(leaf.to_owned());
    }
  }
  for i in 0..8 {
    let name = format!("pre-{i}.txt");
    assert!(
      seen.contains(&name) || rescanned,
      "the barrier promised {name} was deliverable, but a plain drain missed it (seen: {seen:?})"
    );
  }

  w.close().await.expect("close");
}

/// A sync on a subscription the caller has already unwatched refuses typed —
/// a caller-unwatch owes no `Rescan`, so the barrier could never be met
/// honestly, and the API says so rather than hanging or lying.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_on_a_dead_subscription_refuses_typed() {
  let (_tmp, root) = scratch("sync-dead");
  let w = watcher(TributariesOptions::new());
  let sub = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch");
  w.unwatch(sub).await.expect("unwatch");

  let err = w
    .sync(sub, Duration::from_secs(5))
    .await
    .expect_err("a dead subscription cannot be synced");
  assert!(err.is_unknown_subscription(), "{err:?}");
  w.close().await.expect("close");
}

/// The barrier flushes the DEBOUNCE too: a settle coalescer holds deltas back
/// on its timer, so a sync that resolved without flushing them would promise a
/// delivery the consumer could not yet read. After `sync`, the pre-call writes
/// are deliverable immediately — no waiting for the settle window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_flushes_the_debounce_for_its_subscription() {
  let (_tmp, root) = scratch("sync-debounce");
  // A long settle window: without the barrier's flush, nothing would be
  // deliverable for a whole second.
  let mut w = watcher(
    TributariesOptions::new().debounce(
      DebounceConfig::new()
        .with_quiet_window(Duration::from_secs(1))
        .with_max_hold(Duration::from_secs(5)),
    ),
  );
  let sub = w
    .watch(key(&root), (), WatchOptions::new())
    .await
    .expect("watch");

  std::fs::write(root.join("held.txt"), b"x").expect("write");

  let outcome = w
    .sync(sub, Duration::from_secs(20))
    .await
    .expect("the barrier is established");
  assert!(
    outcome.is_delivered() || outcome.is_dominated(),
    "{outcome:?}"
  );

  // Deliverable NOW — the barrier flushed what the debounce was holding.
  let mut seen = false;
  let mut rescanned = false;
  while let Some(event) = w.next().now_or_never().flatten() {
    if event.kind().is_rescan() {
      rescanned = true;
    }
    if event.key().last().and_then(|c| c.to_str()) == Some("held.txt") {
      seen = true;
    }
  }
  assert!(
    seen || rescanned,
    "the barrier must flush the sub's debounced deltas, not promise over them"
  );

  w.close().await.expect("close");
}
