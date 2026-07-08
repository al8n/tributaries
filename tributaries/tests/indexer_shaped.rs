//! Indexer-shaped generic-key integration, end-to-end through the public
//! [`Tributaries`] API over a **caller-supplied [`Source`]** with a **custom, non-`OsString`
//! key** — mirroring findit-indexer's `FsMonitor`.
//!
//! Where [`umbrella`](../umbrella.rs) drives the pure-fs `C = OsString`, `V = ()` convenience,
//! this suite instantiates the generic driver at a richer coordinate: the key `C = Comp`
//! (a `[Volume(v), Seg(..), …]` location, like an indexer's volume-relative path) and the
//! caller value `V = Loc` (a per-watch attribution payload). The [`Source`] is
//! [`IndexerSource`], a mount-map (`key-prefix ↔ absolute-path`) over a **real**
//! [`tributary_fs::Watcher`] — the single place a key ↔ path conversion happens — so the
//! whole umbrella (subsumption, fan-out, epoch rebasing, backpressure, the wait-free
//! [`WatchView`] value plane) is exercised over a genuinely generic key against a live OS
//! backend, exactly as a downstream consumer would wire it.
//!
//! Real-kernel timing is nondeterministic, so every assertion is convergence-style: wait
//! (bounded) until the expected fact is observed. The one place overflow must be *forced*
//! (backpressure) drives the producer strictly ahead of the consumer rather than sleeping.

// not(miri): drives a real kernel watch and a tokio runtime — syscalls miri cannot execute.
#![cfg(all(feature = "tokio", not(miri)))]

use std::{
  collections::HashSet,
  future::Future,
  num::NonZeroUsize,
  path::{Path, PathBuf},
  pin::pin,
  sync::atomic::{AtomicU32, Ordering},
  task::{Context, Poll, Waker},
  time::Duration,
};

use agnostic_lite::{RuntimeLite, tokio::TokioRuntime};
use tempfile::TempDir;
use tributaries::{
  Armed, DebounceConfig, Epoch, Event, Filter, Interest, RootHandle, Source, SourceEvent,
  Subscription, Tributaries, TributariesOptions, WatchError, WatchView, WatcherOptions,
};
use tributary_fs::Watcher;

/// The custom, **non-`OsString`** key component: an indexer-shaped location coordinate.
///
/// A watched location is a `Vec<Comp>` = `[Volume(v), Seg("a"), Seg("b"), …]` — a volume id
/// followed by volume-relative path segments. `Volume` sorts before `Seg` (variant order),
/// so `[Volume(v)]` is a strict prefix — hence an ancestor — of `[Volume(v), Seg("a")]`,
/// which is exactly the coverage relation the subsumption radix keys on.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Comp {
  Volume(u64),
  Seg(String),
}

/// The per-watch caller value threaded through the generic value plane: attribution's
/// **owning** payload, returned by [`WatchView::resolve`] / [`WatchView::covering`].
#[derive(Clone, Debug, PartialEq)]
struct Loc {
  id: u64,
}

/// A caller-supplied [`Source`] over a **real** [`tributary_fs::Watcher`], the shape an
/// indexer's `FsMonitor` binds: a mount-map pairs each key-prefix (`[Comp::Volume(v)]`) with
/// an absolute filesystem root, and this is the single place a key ↔ path conversion happens
/// (mirroring the fs source's "key ↔ path knowledge lives here only").
struct IndexerSource<R: RuntimeLite> {
  watcher: Watcher<R>,
  mounts: Vec<(Vec<Comp>, PathBuf)>,
}

impl<R: RuntimeLite> IndexerSource<R> {
  fn new(watcher: Watcher<R>, mounts: Vec<(Vec<Comp>, PathBuf)>) -> Self {
    Self { watcher, mounts }
  }

  /// The one key → path conversion: the longest mount whose key-prefix begins `key`, with
  /// the remaining `Seg` components joined onto its absolute root.
  fn key_to_path(&self, key: &[Comp]) -> Option<PathBuf> {
    let (prefix, root) = self
      .mounts
      .iter()
      .filter(|(kp, _)| key.starts_with(kp))
      .max_by_key(|(kp, _)| kp.len())?;
    let mut path = root.clone();
    for comp in &key[prefix.len()..] {
      match comp {
        Comp::Seg(seg) => path.push(seg),
        Comp::Volume(_) => return None,
      }
    }
    Some(path)
  }

  /// The reverse (one path → key) conversion: the longest mount whose absolute root is an
  /// ancestor of `path`, with the trailing path components appended as `Seg`s.
  fn path_to_key(&self, path: &Path) -> Option<Vec<Comp>> {
    let (prefix, root) = self
      .mounts
      .iter()
      .filter(|(_, root)| path.starts_with(root))
      .max_by_key(|(_, root)| root.components().count())?;
    let rel = path.strip_prefix(root).ok()?;
    let mut key = prefix.clone();
    key.extend(
      rel
        .components()
        .map(|c| Comp::Seg(c.as_os_str().to_string_lossy().into_owned())),
    );
    Some(key)
  }
}

impl<R: RuntimeLite> Source<Comp> for IndexerSource<R> {
  type Handle = RootHandle;

  async fn arm(&mut self, key: &[Comp]) -> Result<Armed<Comp, RootHandle>, WatchError> {
    // A well-formed watch always resolves under a registered mount; `?`/`From` surfaces a
    // genuine arm failure (`WatchRootError` is `#[non_exhaustive]` — never constructed here).
    let path = self
      .key_to_path(key)
      .expect("indexer source: every armed key lies under a registered mount");
    let handle = self.watcher.watch(path, Interest::all()).await?;
    // Adopt the filesystem-authoritative canonical path as the committed key (design §4):
    // events arrive in canonical coordinates, so the index must key on them.
    let canonical_key = self
      .watcher
      .root_path(handle)
      .and_then(|path| self.path_to_key(&path))
      .unwrap_or_else(|| key.to_vec());
    Ok(Armed::new(handle, canonical_key))
  }

  async fn disarm(&mut self, handle: RootHandle) {
    // Best-effort, mirroring the fs source: a released root's runtime conditions reach the
    // umbrella in-band as events, not as an error here.
    let _ = self.watcher.unwatch(handle).await;
  }

  async fn next(&mut self) -> Option<SourceEvent<Comp, RootHandle>> {
    loop {
      let raw = self.watcher.next().await?;
      // Reverse the raw canonical path back into the key space; a change outside every mount
      // (never a watched root's) is skipped rather than mis-keyed.
      let Some(key) = self.path_to_key(raw.path()) else {
        continue;
      };
      let from = raw
        .kind()
        .moved()
        .and_then(|moved| self.path_to_key(moved.from()));
      return Some(SourceEvent::new(
        raw.root(),
        key,
        raw.kind().clone(),
        from,
        raw.location().clone(),
        raw.epoch(),
        raw.change_id(),
      ));
    }
  }

  fn root_key(&self, handle: RootHandle) -> Option<Vec<Comp>> {
    // `root_path` reads the live-root registry synchronously and answers `None` for a
    // torn-down handle, so a terminal `Rescan` reports `None` here — the dead/retired signal
    // `retire_if_dead` classifies on.
    self
      .watcher
      .root_path(handle)
      .and_then(|path| self.path_to_key(&path))
  }
}

/// The generic driver instantiated at the indexer coordinate: custom key `Comp`, caller
/// value `Loc`, tokio runtime, fs [`RootHandle`].
type Indexer = Tributaries<Comp, Loc, TokioRuntime>;

/// Generous ceiling for one expected observation; CI runners (macOS especially) are slow and
/// FSEvents batches on its own latency timer.
const DEADLINE: Duration = Duration::from_secs(20);

/// A fresh, **canonicalized** scratch directory: the temp-dir root is a symlink on macOS
/// (`/var` → `/private/var`), and both the kernel backend and the mount-map key off canonical
/// paths, so the mount's absolute root must already be canonical for the key reversal to line
/// up with reported event paths.
fn scratch(prefix: &str) -> (TempDir, PathBuf) {
  static COUNTER: AtomicU32 = AtomicU32::new(0);
  let dir = tempfile::Builder::new()
    .prefix(&format!(
      "tributaries-idx-{prefix}-{}-",
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

/// One mounted volume rooted at a fresh canonical scratch dir: the temp dir (kept alive), its
/// absolute root, the mount key `[Volume(v)]`, and the built umbrella handle.
struct Rig {
  _dir: TempDir,
  root: PathBuf,
  volume: Vec<Comp>,
  w: Indexer,
}

/// Builds a single-mount indexer over a real watcher, with the given umbrella options.
fn rig(prefix: &str, volume: u64, options: TributariesOptions) -> Rig {
  let (dir, root) = scratch(prefix);
  let watcher = Watcher::<TokioRuntime>::new(WatcherOptions::new()).expect("build watcher");
  let volume_key = std::vec![Comp::Volume(volume)];
  let source = IndexerSource::new(watcher, std::vec![(volume_key.clone(), root.clone())]);
  let w: Indexer = Tributaries::with_source(source, options);
  Rig {
    _dir: dir,
    root,
    volume: volume_key,
    w,
  }
}

/// A located key under `volume`: `[Volume(v), Seg(seg0), …]`.
fn key(volume: &[Comp], segs: &[&str]) -> Vec<Comp> {
  let mut key = volume.to_vec();
  key.extend(segs.iter().map(|seg| Comp::Seg((*seg).to_string())));
  key
}

/// An event "reaches" `key` when it names it directly or is a `Rescan` at the key or one of
/// its ancestors (a rescan obliges re-enumeration below it).
fn reaches(event: &Event<Comp, Loc>, key: &[Comp]) -> bool {
  event.key() == key || (event.is_rescan() && key.starts_with(event.key()))
}

/// The owning [`Loc`] id the wait-free value plane resolves for `key`, if any.
fn resolved_id(view: &WatchView<Comp, Loc, RootHandle>, key: &[Comp]) -> Option<u64> {
  view.resolve(key).map(|snapshot| snapshot.get().id)
}

/// Waits until an event satisfying `pred` arrives, or the deadline lapses, returning it.
async fn wait_for(
  w: &mut Indexer,
  mut pred: impl FnMut(&Event<Comp, Loc>) -> bool,
) -> Option<Event<Comp, Loc>> {
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

/// Waits until an event satisfying `pred` has reached **every** subscription in `wanted`
/// (each match retires that subscription), or the deadline lapses. `pred` is evaluated on
/// **every** delivered event — including ones for subscriptions outside `wanted` — and only
/// its result gates retirement; a `pred` that carries an exclusion assertion therefore fires
/// on those other-subscription events too, so it can prove a disjoint subscription was *not*
/// wrongly delivered (never a short-circuited tautology).
async fn wait_until_all(
  w: &mut Indexer,
  wanted: &[Subscription],
  mut pred: impl FnMut(&Event<Comp, Loc>) -> bool,
) -> bool {
  let mut outstanding: HashSet<Subscription> = wanted.iter().copied().collect();
  tokio::time::timeout(DEADLINE, async {
    while !outstanding.is_empty() {
      let Some(event) = w.next().await else {
        return false;
      };
      // Run `pred` unconditionally (its assertion side-effect must fire on every event, not
      // just the wanted ones); retirement is gated on the result AND membership in `wanted`.
      let hit = pred(&event);
      if hit && outstanding.contains(&event.subscription()) {
        outstanding.remove(&event.subscription());
      }
    }
    true
  })
  .await
  .unwrap_or(false)
}

/// Polls the wait-free [`WatchView`] `pred` until it holds, or the deadline lapses. Every
/// probe is an `&self` load (no lock, no driver round-trip); this only bounds *eventual
/// consistency*, never blocks.
async fn converge(mut pred: impl FnMut() -> bool) -> bool {
  tokio::time::timeout(DEADLINE, async {
    loop {
      if pred() {
        return true;
      }
      tokio::task::yield_now().await;
    }
  })
  .await
  .unwrap_or(false)
}

/// (a) The concurrent [`WatchView`] read plane (design §5): a separate task reads
/// membership / attribution wait-free while the actor mutates, and converges — eventually
/// consistently — on the committed watch-set with the right owning [`Loc`].
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_view_reads_are_wait_free_and_eventually_consistent() {
  let outer = rig("view", 1, TributariesOptions::new());
  std::fs::create_dir_all(outer.root.join("sub")).expect("create sub");
  std::fs::create_dir_all(outer.root.join("other")).expect("create other");
  let Rig {
    _dir, volume, w, ..
  } = outer;

  let sub_key = key(&volume, &["sub"]);
  let other_key = key(&volume, &["other"]);
  let view = w.view();

  // Before any commit the view reads empty — eventually consistent, wait-free.
  assert!(
    !view.is_watched(&sub_key),
    "an unwatched key reads not-present"
  );
  assert!(resolved_id(&view, &sub_key).is_none(), "no owning Loc yet");

  // A separate task hammers the view (`&self`, wait-free) while the actor commits.
  let reader = {
    let view = view.clone();
    let sub_key = sub_key.clone();
    tokio::spawn(async move {
      converge(move || {
        view.is_watched(&sub_key) && view.resolve(&sub_key).map(|s| s.get().id) == Some(7)
      })
      .await
    })
  };

  // The actor mutates concurrently: two disjoint roots with distinct owning Locs.
  let sub = w
    .watch(
      sub_key.clone(),
      Loc { id: 7 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch sub");
  let _other = w
    .watch(
      other_key.clone(),
      Loc { id: 9 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch other");

  assert!(
    reader.await.expect("reader task joins"),
    "the concurrent reader converged to watched + the right owning Loc, wait-free"
  );

  // The committed watch-set is now directly readable, each disjoint root under its own Loc.
  assert_eq!(
    resolved_id(&view, &sub_key),
    Some(7),
    "resolve returns the owning Loc of the sub root"
  );
  assert_eq!(
    resolved_id(&view, &other_key),
    Some(9),
    "each disjoint root resolves to its own owning Loc"
  );
  assert!(
    view.is_watched(&sub_key),
    "the committed root reads present"
  );

  // Eventual consistency in reverse: an unwatch is observed wait-free.
  w.unwatch(sub).await.expect("unwatch sub");
  assert!(
    converge(move || !view.is_watched(&sub_key)).await,
    "the view reflects the unwatch (eventually consistent)"
  );

  w.close().await.expect("close");
}

/// (b) Overlap subsumption over the production armer (design §4): a deep watch then its
/// ancestor **widens** onto one kernel root, folding the descendant (covered, no longer an
/// exact root) while routing survives — a change under the folded descendant still reaches
/// both subscriptions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlap_subsumption_widens_and_folds_descendant() {
  let outer = rig("subsume", 2, TributariesOptions::new());
  let deep_dir = outer.root.join("a").join("b").join("c");
  std::fs::create_dir_all(&deep_dir).expect("create deep dir");
  let Rig {
    _dir,
    volume,
    mut w,
    ..
  } = outer;

  let deep_key = key(&volume, &["a", "b", "c"]);
  let anc_key = key(&volume, &["a"]);
  let view = w.view();

  // Watch the DEEP dir first — a disjoint root.
  let deep = w
    .watch(
      deep_key.clone(),
      Loc { id: 1 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch deep");
  assert!(view.contains(&deep_key), "the deep dir is an exact root");
  assert_eq!(view.len(), 1, "one kernel root so far");

  // Watch its ANCESTOR — a widen. The layer below rejects an overlapping root (`Overlaps`);
  // this succeeds because the widen disarms the subsumed deep root before arming the wider
  // one, folding the descendant onto it.
  let anc = w
    .watch(
      anc_key.clone(),
      Loc { id: 2 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch ancestor widens (Ok, not Overlaps)");
  assert_ne!(deep, anc, "each watch mints its own subscription id");

  assert!(
    converge(|| {
      view.len() == 1
        && view.contains(&anc_key)
        && !view.contains(&deep_key)
        && view.is_watched(&deep_key)
    })
    .await,
    "the widen collapses to one root; the descendant is folded (covered, not an exact root)"
  );

  // Routing survives the fold: a write under the DEEP dir reaches BOTH the folded descendant
  // subscription and the wider ancestor subscription, through the one widened root.
  let file_key = key(&volume, &["a", "b", "c", "probe.txt"]);
  std::fs::write(deep_dir.join("probe.txt"), b"x").expect("write probe");
  assert!(
    wait_until_all(&mut w, &[deep, anc], |e| reaches(e, &file_key)).await,
    "a write under the folded descendant routes to both subscriptions"
  );

  w.close().await.expect("close");
}

/// (c) Attribution both ways (design §3/§5): one change under an overlap **fans out** to
/// every covering subscription (each retagged with its own id), never to a disjoint one; and
/// the wait-free value plane **resolves** each key to its owning root's [`Loc`].
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attribution_fans_out_to_covering_subs_and_resolves_owning_loc() {
  let outer = rig("attrib", 3, TributariesOptions::new());
  let np_child = outer.root.join("np").join("child");
  let other_dir = outer.root.join("other");
  std::fs::create_dir_all(&np_child).expect("create np/child");
  std::fs::create_dir_all(&other_dir).expect("create other");
  let Rig {
    _dir,
    volume,
    mut w,
    ..
  } = outer;
  let view = w.view();

  let np_key = key(&volume, &["np"]);
  let child_key = key(&volume, &["np", "child"]);
  let other_key = key(&volume, &["other"]);

  // NP is the owning root (Loc 1); child is covered by it (Loc 2); OTHER is a disjoint owning
  // root (Loc 3).
  let np_sub = w
    .watch(
      np_key.clone(),
      Loc { id: 1 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch np");
  let child_sub = w
    .watch(
      child_key.clone(),
      Loc { id: 2 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch child (covered)");
  let other_sub = w
    .watch(
      other_key.clone(),
      Loc { id: 3 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch other");
  assert_ne!(other_sub, np_sub, "distinct subscriptions");

  // A change under np/child fans out to BOTH np_sub and child_sub, and NEVER to the disjoint
  // OTHER subscription. To prove that exclusion is a real no-cross-delivery — not merely
  // "nothing arrived at other_sub yet" — drive a SECOND change under OTHER's own key and make
  // other_sub's own delivery of THAT a positive bound in the same wait: `pred` (now evaluated
  // on every delivered event) asserts on EVERY event that other_sub never receives the
  // np/child probe, while other_sub is required to retire on its own change. All three
  // retiring proves the channel to other_sub is live/reachable and still correctly excluded
  // the disjoint np/child event (mirrors umbrella.rs::filter_narrows_delivery_on_the_real_stack).
  let probe_key = key(&volume, &["np", "child", "probe.txt"]);
  let other_probe_key = key(&volume, &["other", "probe.txt"]);
  std::fs::write(np_child.join("probe.txt"), b"x").expect("write np/child probe");
  std::fs::write(other_dir.join("probe.txt"), b"x").expect("write other probe");
  assert!(
    wait_until_all(&mut w, &[np_sub, child_sub, other_sub], |e| {
      assert!(
        !(e.subscription() == other_sub && reaches(e, &probe_key)),
        "the disjoint OTHER subscription must never receive the np/child change"
      );
      if e.subscription() == other_sub {
        // other_sub's liveness bound: it DOES receive the change under its own key.
        reaches(e, &other_probe_key)
      } else {
        // np_sub / child_sub: the fan-out of the one np/child change to every covering sub.
        reaches(e, &probe_key)
      }
    })
    .await,
    "the np/child change fans out to every covering subscription (np owner + covered child), \
     while the live, reachable other_sub receives only its own change — never the np/child one"
  );

  // Attribution by longest live subscription (design §5, per-subscription attribution): resolve
  // returns the value of the LONGEST live subscription whose key covers the probe. The covered
  // `child` sub owns its OWN value even though it shares np's armed root, so np/child resolves to
  // child's Loc (2) — NOT the covering np root's (1) — and the disjoint OTHER subtree to its own
  // (3). (An armed root can outlive the subscription whose value equalled it; attribution reads
  // the live-subscription coverage plane, never the departed root's stored value.)
  assert_eq!(
    resolved_id(&view, &probe_key),
    Some(2),
    "np/child resolves to the covered child subscription's own Loc (the longest live sub), not \
     the covering np root's"
  );
  assert_eq!(
    resolved_id(&view, &other_key),
    Some(3),
    "a disjoint subtree resolves to its own owning Loc"
  );

  w.close().await.expect("close");
}

/// (d) The opt-in settle coalescer (design §6): a rapid burst to one path collapses to a
/// bounded number of delivered events, and still delivers the burst's settled effect (no
/// silent loss).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debounce_coalesces_a_burst() {
  let cfg = DebounceConfig::new()
    .with_quiet_window(Duration::from_millis(200))
    .with_max_hold(Duration::from_millis(2000));
  let outer = rig("debounce", 4, TributariesOptions::new().debounce(cfg));
  let Rig {
    _dir,
    root,
    volume,
    mut w,
  } = outer;

  let sub = w
    .watch(
      key(&volume, &[]),
      Loc { id: 1 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch the volume root");

  let busy_key = key(&volume, &["busy.txt"]);
  for i in 0..20u32 {
    std::fs::write(root.join("busy.txt"), i.to_le_bytes()).expect("burst write");
  }

  // The coalesced settle still delivers something covering the file (its net effect emits).
  assert!(
    wait_for(&mut w, |e| e.subscription() == sub && reaches(e, &busy_key))
      .await
      .is_some(),
    "the debounced burst collapses but its settled effect is still delivered"
  );

  // After the settle window, further events covering the file are bounded well below the 20
  // raw writes — the burst coalesced rather than fanning into a per-write storm.
  let mut extra = 0u32;
  let _ = tokio::time::timeout(cfg.quiet_window() * 3, async {
    while let Some(event) = w.next().await {
      if event.subscription() == sub && reaches(&event, &busy_key) {
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

/// (e) No silent loss across a widen (design §8): a re-pointed subscription — one whose
/// stream already advanced — is delivered a **dominating** `Rescan` naming the widened root,
/// whose epoch strictly dominates every event delivered to it before the widen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn widen_delivers_dominating_rescan_no_silent_loss() {
  let outer = rig("widen", 5, TributariesOptions::new());
  let child = outer.root.join("proj").join("child");
  std::fs::create_dir_all(&child).expect("create proj/child");
  let Rig {
    _dir,
    volume,
    mut w,
    ..
  } = outer;

  let child_key = key(&volume, &["proj", "child"]);
  let anc_key = key(&volume, &["proj"]);

  let child_sub = w
    .watch(
      child_key.clone(),
      Loc { id: 1 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch child");

  // Advance the child's stream first, so the re-point Rescan has a prior stream to dominate.
  let seed_key = key(&volume, &["proj", "child", "seed.txt"]);
  std::fs::write(child.join("seed.txt"), b"x").expect("write seed");
  let seed = wait_for(&mut w, |e| {
    e.subscription() == child_sub && reaches(e, &seed_key)
  })
  .await
  .expect("the child sees its seed change");

  // Widen: watch the ancestor. The child is re-pointed onto the wider root and owed a
  // dominating Rescan across the coverage re-point.
  let _anc = w
    .watch(
      anc_key.clone(),
      Loc { id: 2 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch ancestor widens");
  let rescan = wait_for(&mut w, |e| {
    e.subscription() == child_sub && e.is_rescan() && child_key.starts_with(e.key())
  })
  .await
  .expect("the widen delivers the child a Rescan naming an ancestor of its key");

  assert_eq!(
    rescan.key(),
    anc_key.as_slice(),
    "the Rescan names the widened root to re-enumerate"
  );
  assert!(
    rescan.epoch() > seed.epoch(),
    "the re-point Rescan strictly dominates the child's pre-widen stream (no silent loss)"
  );

  w.close().await.expect("close");
}

/// (f) The one residual "dropped wait" (invariant I1): a `watch` whose caller vanished after
/// the reconcile committed (its reply `oneshot` closed) does not leak a persistent root — the
/// orphan is reconciled away. Polling the future once enqueues the command (so the owner
/// commits) before dropping the reply; a later awaited watch is a FIFO barrier proving the
/// orphan was fully processed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_whose_caller_vanished_after_commit_is_reconciled_away() {
  let outer = rig("orphan", 6, TributariesOptions::new());
  std::fs::create_dir_all(outer.root.join("gone")).expect("create gone");
  std::fs::create_dir_all(outer.root.join("live")).expect("create live");
  let Rig {
    _dir, volume, w, ..
  } = outer;
  let view = w.view();

  let orphan_key = key(&volume, &["gone"]);
  let live_key = key(&volume, &["live"]);

  // Enqueue the watch command, then drop the wait: one poll drives the future past the
  // (unbounded) command send and parks it on the reply; dropping it closes the reply oneshot.
  {
    let mut fut = pin!(w.watch(
      orphan_key.clone(),
      Loc { id: 99 },
      Interest::all(),
      Filter::all()
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
      matches!(fut.as_mut().poll(&mut cx), Poll::Pending),
      "the watch parks on its reply after enqueuing the command"
    );
  }

  // FIFO barrier: a later awaited watch is processed strictly after the orphan command, so
  // once it returns the orphan has been committed-then-reconciled-away.
  let _live = w
    .watch(
      live_key.clone(),
      Loc { id: 1 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch live");

  assert!(
    !view.is_watched(&orphan_key),
    "the orphaned subscription was reconciled away — its root does not persist"
  );
  assert!(
    view.is_watched(&live_key),
    "the live watch committed normally"
  );

  w.close().await.expect("close");
}

/// (g) Teardown: `close()` flushes and quiesces the actor — the retained clone's data plane
/// (`next` → `None`) and control plane (a later `watch` → `Err`) both observe the teardown;
/// and a non-last handle drop is benign (the ref-counted actor stays alive and functional).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_and_handle_drop_teardown() {
  let outer = rig("close", 7, TributariesOptions::new());
  std::fs::create_dir_all(outer.root.join("d")).expect("create d");
  let Rig {
    _dir, volume, w, ..
  } = outer;

  let key_d = key(&volume, &["d"]);
  // A retained clone shares the actor's data + control planes; a *non-last* clone dropped is
  // benign — the actor stays alive, so the subsequent watch still succeeds.
  let mut reader = w.clone();
  drop(w.clone());
  let _sub = w
    .watch(key_d.clone(), Loc { id: 1 }, Interest::all(), Filter::all())
    .await
    .expect("watch survives a non-last clone drop (actor alive)");

  w.close().await.expect("close returns Ok");

  // Teardown reached the DATA plane: the retained clone's stream ends.
  assert!(
    matches!(
      tokio::time::timeout(DEADLINE, reader.next()).await,
      Ok(None)
    ),
    "the event stream ends once the actor tore down (close teardown)"
  );
  // Teardown reached the CONTROL plane: a further command errors (owner gone).
  assert!(
    reader
      .watch(key_d.clone(), Loc { id: 2 }, Interest::all(), Filter::all())
      .await
      .is_err(),
    "a watch after teardown errors (control plane closed)"
  );
}

/// (h.1) Close-responsiveness under backpressure (design backpressure doc, invariants
/// II/III): a stalled consumer fills a one-slot event channel, yet `close()` — serviced on
/// the separate command mailbox the owner never blocks behind — returns within the deadline
/// rather than deadlocking behind the full channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_consumer_close_is_responsive() {
  let options =
    TributariesOptions::new().with_event_capacity(NonZeroUsize::new(1).expect("nonzero"));
  let outer = rig("close-full", 8, options);
  let Rig {
    _dir,
    root,
    volume,
    w,
  } = outer;
  let _sub = w
    .watch(
      key(&volume, &[]),
      Loc { id: 1 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch the volume root");

  // Fill the one-slot channel with an undrained burst — the consumer never calls next().
  for i in 0..64u32 {
    std::fs::write(root.join(format!("f{i}.txt")), b"x").expect("burst write");
  }

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

/// (h.2) Overflow → per-sub dominating `Rescan` (design backpressure doc, no-silent-loss):
/// driving the producer strictly ahead of the consumer over a one-slot channel overflows the
/// subscription; the owner sheds it to a parked `Rescan` and suppresses its ordinary events,
/// so on resume the next delivery is exactly that `Rescan`, whose epoch strictly dominates
/// every ordinary event delivered before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_consumer_resume_gets_dominating_rescan_no_silent_loss() {
  let options =
    TributariesOptions::new().with_event_capacity(NonZeroUsize::new(1).expect("nonzero"));
  let outer = rig("stall-resume", 9, options);
  let Rig {
    _dir,
    root,
    volume,
    mut w,
  } = outer;

  let root_key = key(&volume, &[]);
  let sub = w
    .watch(
      root_key.clone(),
      Loc { id: 1 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch the volume root");

  // Produce many events per drained one: the one-slot channel stays saturated, the sub sheds
  // to a parked Rescan, and — ordinary events for a parked sub being suppressed — the next
  // delivery for it is the Rescan.
  let mut counter = 0u32;
  let mut max_ordinary: Option<Epoch> = None;
  let outcome = tokio::time::timeout(DEADLINE, async {
    loop {
      for _ in 0..16 {
        std::fs::write(root.join(format!("f{counter}.txt")), b"x").expect("burst write");
        counter += 1;
      }
      match w.next().await {
        Some(event) if event.subscription() == sub => {
          if event.is_rescan() {
            return Some(event);
          }
          max_ordinary = Some(max_ordinary.map_or(event.epoch(), |m| m.max(event.epoch())));
        }
        Some(_) => {}
        None => return None,
      }
    }
  })
  .await;

  let rescan = outcome
    .expect("a Rescan surfaced before the deadline")
    .expect("the stream did not end");
  assert!(rescan.is_rescan(), "the shed signal is a Rescan");
  assert_eq!(
    rescan.subscription(),
    sub,
    "the Rescan is for the overflowed subscription"
  );
  assert_eq!(
    rescan.key(),
    root_key.as_slice(),
    "the Rescan names the sub's covered key to re-enumerate"
  );
  if let Some(max) = max_ordinary {
    assert!(
      rescan.epoch() > max,
      "the shed Rescan strictly dominates every ordinary event delivered before it"
    );
  }

  w.close().await.expect("close");
}

/// (i) Root death → terminal `Rescan` + retirement (design §4): deleting a watched root
/// surfaces a terminal `Rescan`/`Removed` to its subscription, then the dead root is retired
/// — so re-creating the path and re-watching re-arms a FRESH root (not a `Covered` resolve
/// against the dead handle), and a write under it reaches the new subscription.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleted_root_delivers_terminal_rescan_and_is_retired() {
  let outer = rig("root-death", 10, TributariesOptions::new());
  // A subdir root, so deleting it does not remove the mount root out from under the handle.
  let watched = outer.root.join("watched");
  std::fs::create_dir_all(&watched).expect("create the watched root");
  let Rig {
    _dir,
    volume,
    mut w,
    ..
  } = outer;
  let view = w.view();

  let watched_key = key(&volume, &["watched"]);
  let sub = w
    .watch(
      watched_key.clone(),
      Loc { id: 1 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("watch the subdir root");

  // Delete the watched root: its handle is torn down and a terminal signal surfaces.
  std::fs::remove_dir_all(&watched).expect("delete the watched root");
  assert!(
    wait_for(&mut w, |e| e.subscription() == sub
      && (e.is_rescan()
        || (e.kind().is_removed() && reaches(e, &watched_key))))
    .await
    .is_some(),
    "the deleted root surfaces a terminal Rescan/Removed to its subscription"
  );
  // Retirement republishes the watch-set without the dead root.
  assert!(
    converge(|| !view.is_watched(&watched_key)).await,
    "the dead root is retired from the published watch-set"
  );

  // Re-create and re-watch: this must re-arm a fresh root (had the dead root not retired, the
  // second watch would resolve Covered against the dead handle and receive nothing below).
  std::fs::create_dir_all(&watched).expect("recreate the watched root");
  let second = w
    .watch(
      watched_key.clone(),
      Loc { id: 2 },
      Interest::all(),
      Filter::all(),
    )
    .await
    .expect("re-watch re-arms a fresh root");
  assert_ne!(sub, second, "the re-watch mints a new subscription");

  let probe_key = key(&volume, &["watched", "after.txt"]);
  std::fs::write(watched.join("after.txt"), b"x").expect("write under the recreated root");
  assert!(
    wait_for(&mut w, |e| e.subscription() == second
      && reaches(e, &probe_key))
    .await
    .is_some(),
    "a write under the recreated, re-armed root reaches the new subscription"
  );

  w.close().await.expect("close");
}
