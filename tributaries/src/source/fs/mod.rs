//! The default local-filesystem [`Source`]: [`FsSource`] over one
//! [`tributary_fs::Watcher`], gated behind the crate's default `fs` feature.
//!
//! This is the fs half of the seam [`source`](crate::source) defines: it binds
//! `C = OsString` (a path's components) to real kernel watches, and it is the only
//! place the crate maps a key to a path and reverses a raw filesystem event back into
//! a key. The neutral traits, carriers, and their contracts live in the parent module;
//! everything here is the binding's own business.

use std::{
  collections::{HashMap, HashSet, VecDeque},
  ffi::OsString,
  path::{Path, PathBuf},
  sync::Arc,
  vec::Vec,
};

use agnostic_lite::RuntimeLite;
use tributary_fs::{
  CloseError as FsCloseError, CoverOutcome, Coverage as FsCoverage, Event as FsEvent,
  EventKind as FsEventKind, ReplaceRootError, RequestOutcome, RootHandle, RootOptions, SkipReason,
  SourceError, UnwatchError as FsUnwatchError, WatchRootError, Watcher, WatcherOptions,
};
#[cfg(feature = "sync")]
use tributary_fs::{SyncRootDenied, SyncRootError, SyncTicket};
use tributary_proto::Interest;

use futures_util::Stream;
use tributary_proto::glob::Glob;

use super::{
  Armed, BoxListing, Coverage, EntryKind, ListItem, Metadata, RootLister, Source, SourceEvent,
};
#[cfg(feature = "sync")]
use super::{Begun, SyncToken};
#[cfg(feature = "sync")]
use crate::error::SyncError;
use crate::{
  error::{BuildError, FaultKind, ListError, SourceCloseError, SourceFault, WatchError},
  event::{EventKind, path_components},
  options::RootGlobs,
};

#[cfg(test)]
mod tests;

/// The default source: the local filesystem, over one [`tributary_fs::Watcher`].
///
/// Binds `C = OsString` (a path's [components](std::path::Path::components)) to real
/// kernel watches. This is the only place the crate maps a key to a path and reverses a
/// raw filesystem event back into a key.
pub struct FsSource<R> {
  watcher: Watcher<R>,
  /// The blocking-job spawner [`list`](Source::list)'s walk runs its `read_dir` and
  /// per-entry metadata reads on — captured from `R` at construction, in the mold of the
  /// lower watcher's own detached pool handle, so the [`Source`] impl below still names
  /// no `R` item and every walk stays off the caller's executor thread.
  blocking: BlockingSpawner,
  /// Roots whose release was requested (via the synchronous [`disarm`](Source::disarm)) but not yet
  /// handed to the [`Watcher`]'s control channel, each paired with the released root's **canonical
  /// path** captured at `disarm` time (while it was still live in the registry). [`arm`](Source::arm)
  /// drains this queue two ways (contract clause 2): (1) **opportunistically** it walks
  /// the queue and hands each entry to the watcher via the NON-BLOCKING, reply-less
  /// [`request_unwatch`](tributary_fs::Watcher::request_unwatch) — moving it to the in-flight
  /// [`enqueued`](Self::enqueued) sidecar — so the arm AWAITS NOTHING for a release that does not
  /// overlap it (keeping clause 5 eventual: every queued release is enqueued the moment the control
  /// channel has room), and (2) **on demand** it resolves any
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps) the watch attempt reports by AWAITING an
  /// [`unwatch`](tributary_fs::Watcher::unwatch) of the entry the watcher *named* as the conflict
  /// (identity-aware — it catches case/normalization aliases) and retrying. The only release work a
  /// single arm AWAITS is (2) — bounded by that arm's OWN overlapping conflicts, never the (disjoint)
  /// backlog — so a caller-bounded `Watch`, and any [`close`](crate::Tributaries::close) queued behind
  /// it, never waits on unrelated teardown latency. The [`disarm`](Source::disarm) DOOR drops any
  /// release whose root already answered [`root_path`](tributary_fs::Watcher::root_path) `None` (a
  /// foreign brand or an already-torn-down own root), so every entry here carries `Some(path)` and
  /// names a live-at-disarm root of THIS instance — the stored path is always present for the (2)
  /// exact-match (the `Option` is the shape shared with [`enqueued`](Self::enqueued); the door makes
  /// `Some` an invariant, not merely a possibility). Bounded by the live-root count: each
  /// generation-unique handle is released at most once, and a hostile `disarm(fresh_foreign)` flood
  /// adds nothing — every foreign disarm dies at the door.
  pending_releases: VecDeque<(RootHandle, Option<PathBuf>)>,
  /// Requested releases whose reply-less [`request_unwatch`](tributary_fs::Watcher::request_unwatch)
  /// the control channel ACCEPTED but the watcher registry may not yet reflect — the **in-flight**
  /// releases. Kept so a conflicting later arm can still resolve an
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps) the watcher NAMES against a release whose
  /// fire-and-forget teardown has not landed yet: the entry is no longer in
  /// [`pending_releases`](Self::pending_releases), so without this sidecar the exact-match would miss
  /// and the arm would wrongly surface the overlap. On such a match the arm AWAITS an
  /// [`unwatch`](tributary_fs::Watcher::unwatch) of the named handle — which, enqueued after the
  /// reply-less request on the one FIFO channel, forces the teardown to land — then retries. Pruned at
  /// each arm's top of every entry the watcher has since applied
  /// ([`root_path`](tributary_fs::Watcher::root_path) `None`) — once the registry has forgotten a root
  /// it can never NAME it — so it is bounded by the in-flight (requested-but-unapplied) release count,
  /// never the watcher's lifetime.
  enqueued: Vec<(RootHandle, Option<PathBuf>)>,
  /// Union mirror of the requested releases — queued in [`pending_releases`](Self::pending_releases)
  /// AND in-flight in [`enqueued`](Self::enqueued) — for O(1) [`root_key`](Source::root_key) liveness
  /// answers (contract clause 3: a requested release is logically dead **immediately**, before its
  /// teardown lands). A handle stays dead-marked here exactly while the watcher still reports its root
  /// live; the same top-of-arm prune drops the mark the instant
  /// [`root_path`](tributary_fs::Watcher::root_path) takes over answering `None`, so the invariant
  /// "`root_key` is `None` from `disarm` until the handle is fully gone" holds unbroken while the set
  /// stays bounded by in-flight releases.
  pending_set: HashSet<RootHandle>,
  /// Prunes ([`set_cover`](Source::set_cover) requests) the watcher's control channel was momentarily
  /// too full to accept — the contract's full-channel deferral (clause 3), **latest-wins per handle**
  /// (clause 6): a re-request for a queued handle REPLACES its stale snapshot, and an awaited
  /// [`grow`](Source::grow) for the handle REMOVES the queued prune outright (the grow's fresh cover
  /// is newer and its applied coverage authoritative). Re-forwarded via
  /// [`flush_deferred_prunes`](Self::flush_deferred_prunes) at the next op that touches the watcher
  /// (`set_cover`, `grow`, `disarm`, `arm`). Bounded by the live-root count (one entry per handle);
  /// entries for since-dead roots self-drain on the next flush (the reply-less request enqueues and
  /// the driver skips the unknown scope). Losslessness is NOT required here (clause 5): entries still
  /// queued at `Drop` are simply dropped — an unpruned root is merely over-broad, self-healing.
  deferred_prunes: HashMap<RootHandle, Vec<PathBuf>>,
  /// The ticket (and the token that minted it) for each root's IN-FLIGHT
  /// [`begin_sync`](Source::begin_sync) — the incarnation-precise cancel address
  /// the abandonment path consumes. [`begin_sync`](Source::begin_sync) inserts the
  /// entry BEFORE it awaits [`Watcher::sync_root`] and removes it on a normal
  /// return (Ok or Err); if that future is DROPPED mid-await (a caller cancel or a
  /// close won the owner's race), the entry deliberately REMAINS, and
  /// [`cancel_sync`](Source::cancel_sync) takes it to address the sync by the
  /// watcher-minted [`SyncTicket`] — the only precise handle on a write the owner
  /// abandoned before it learned the cookie path. The stored [`SyncToken`] is the
  /// umbrella-level incarnation guard: a `cancel_sync` whose token does not match
  /// the stored one is stale (for an older incarnation) and dropped. Bounded by the
  /// live-root count, and in practice ≤ 1 (the owner awaits `begin_sync` inline, so
  /// at most one sync is in flight at a time); entries for since-released roots are
  /// pruned at the top of [`arm`](Source::arm) alongside `pending_set`/`enqueued`.
  #[cfg(feature = "sync")]
  pending_syncs: HashMap<RootHandle, (SyncToken, SyncTicket)>,
  /// Awaited [`Watcher::set_cover`] round-trips [`grow`](Source::grow) actually performed — proves
  /// the kernel-recursive short-circuit skipped the round-trip.
  #[cfg(test)]
  cover_round_trips: usize,
  /// Deferred prunes successfully re-forwarded by [`flush_deferred_prunes`](Self::flush_deferred_prunes)
  /// — distinguishes a grow's SUPERSEDED (removed, never forwarded) queued prune from a flushed one.
  #[cfg(test)]
  deferred_forwards: usize,
  /// [`Watcher::request_cancel_sync`] calls [`cancel_sync`](Source::cancel_sync) actually issued —
  /// distinguishes a stale/mismatched-token cancel (touches nothing) from a matching-token cancel of
  /// a live entry, which removes it and fires the watcher-side cancel.
  #[cfg(all(test, feature = "sync"))]
  sync_cancels_requested: usize,
}

impl<R> core::fmt::Debug for FsSource<R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("FsSource")
      .field("watcher", &self.watcher)
      .finish()
  }
}

impl<R: RuntimeLite> FsSource<R> {
  /// Builds a local-filesystem source, spawning the underlying `tributary-fs` watcher on
  /// `R`.
  ///
  /// # Errors
  ///
  /// [`BuildError::Source`] when the underlying `tributary-fs` watcher cannot be built.
  pub fn new(options: WatcherOptions) -> Result<Self, BuildError> {
    // The only fs build failure is a configuration bound (too many exclusion paths); it
    // has no dedicated neutral kind, so it folds to `Other` with the whole fs error
    // preserved in the box for `BuildError::as_fs` recovery.
    let watcher = Watcher::new(options)
      .map_err(|err| BuildError::Source(SourceFault::new(FaultKind::Other).with_source(err)))?;
    Ok(Self {
      watcher,
      blocking: Arc::new(|job| R::spawn_blocking_detach(job)),
      pending_releases: VecDeque::new(),
      enqueued: Vec::new(),
      pending_set: HashSet::new(),
      deferred_prunes: HashMap::new(),
      #[cfg(feature = "sync")]
      pending_syncs: HashMap::new(),
      #[cfg(test)]
      cover_round_trips: 0,
      #[cfg(test)]
      deferred_forwards: 0,
      #[cfg(all(test, feature = "sync"))]
      sync_cancels_requested: 0,
    })
  }
}

// The deferral queue and the Source seam below are channel and registry work:
// no method names an `R` item (the runtime bound lives on `new`, the one
// place the watcher driver is spawned).
impl<R> FsSource<R> {
  /// Queues a prune the control channel refused (momentarily full), **latest-wins per handle**
  /// ([`Source::set_cover`] contract clause 6): a newer request for the same handle replaces the
  /// stale snapshot, so a later flush never applies an outdated cover.
  fn defer_prune(&mut self, handle: RootHandle, retained: Vec<PathBuf>) {
    self.deferred_prunes.insert(handle, retained);
  }

  /// Re-forwards every deferred prune the control channel now has room for — the re-forward half of
  /// the full-channel deferral ([`Source::set_cover`] contract clause 3), called at the top of every
  /// op that touches the watcher (`set_cover`, `grow`, `disarm`, `arm`). Purely non-blocking: each
  /// entry is handed over via the reply-less [`Watcher::request_set_cover`] `try_send`; an entry the
  /// channel still refuses stays queued for the next flush (or is dropped at `Drop` — clause 5,
  /// losslessness not required for a prune).
  fn flush_deferred_prunes(&mut self) {
    // Split-borrow: the watcher is a shared reborrow so `retain` can mutate the map.
    let watcher = &self.watcher;
    #[cfg(test)]
    let mut forwards = 0usize;
    self.deferred_prunes.retain(|handle, retained| {
      match watcher.request_set_cover(*handle, retained.clone()) {
        // Forwarded onto the control channel — drop the deferral (its work is on its way).
        RequestOutcome::Enqueued => {
          #[cfg(test)]
          {
            forwards += 1;
          }
          false
        }
        // The channel is momentarily full — keep the deferral for the next flush (clause 3). This
        // is the ONLY retain: a genuinely full channel is transient, so a genuine prune re-tries.
        RequestOutcome::Busy => true,
        // A dead or foreign root (never enqueueable): pruning it is pointless (clause 5 does not
        // require prune losslessness). DROP it — a retained never-valid entry drives the
        // monotone growth (the retired `bool` read this as backpressure and re-tried it forever).
        RequestOutcome::Rejected => false,
      }
    });
    #[cfg(test)]
    {
      self.deferred_forwards += forwards;
    }
  }
}

/// The local filesystem's [`RootLister`]: a cheap `Clone` enumerator over one
/// [`Watcher`]'s live roots, independent of the [`FsSource`] that handed it out.
///
/// It holds exactly what a walk needs — a reader over the watcher's root registry (to
/// resolve a handle to its canonical path) and the blocking-pool spawner — and nothing
/// that could drive the watcher. So it stays useful after the source has been handed to
/// a [`Tributaries`](crate::Tributaries) owner, which is the whole reason it exists.
#[derive(Clone)]
pub struct FsLister {
  view: tributary_fs::RootView,
  blocking: BlockingSpawner,
}

impl core::fmt::Debug for FsLister {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("FsLister").finish_non_exhaustive()
  }
}

impl FsLister {
  /// The ONE walk both doors run: [`FsSource::list`](Source::list) and
  /// [`RootLister::list`] differ in how they are reached, never in what they answer.
  fn walk(
    view: tributary_fs::RootView,
    blocking: BlockingSpawner,
    root: RootHandle,
    from: &[OsString],
    globs: &RootGlobs,
  ) -> impl Stream<Item = ListItem<OsString>> + Send + use<> {
    let bound = view.root_path(root).zip(view.root_identity(root));
    futures_util::stream::unfold(Walk::new(bound, from, globs, blocking), Walk::step)
  }
}

impl RootLister<OsString, RootHandle> for FsLister {
  fn list(&self, root: RootHandle, from: &[OsString], globs: &RootGlobs) -> BoxListing<OsString> {
    Box::pin(Self::walk(
      self.view.clone(),
      Arc::clone(&self.blocking),
      root,
      from,
      globs,
    ))
  }
}

/// The deepest a listing descends below its starting key.
///
/// The walk holds one OPEN directory per level, and on unix that is two descriptors — the
/// one `openat`/`statat` name, and the one the reader takes, because `rustix::fs::Dir` does
/// not lend its own back. So the ceiling is a descriptor budget as much as a cycle guard:
/// 64 levels is deeper than a real tree and still a small fraction of a default
/// `RLIMIT_NOFILE`. A directory AT the ceiling is reported as one `Io` item for its own key
/// and is not descended, so the listing is incomplete exactly there and complete everywhere
/// else.
const MAX_LIST_DEPTH: usize = 64;

/// How many entries one blocking job reads before it hands the open directory back.
///
/// The walk yields a chunk before it asks for the next one, so a directory of any width is
/// read in pieces this size: memory is bounded by the depth and this number, never by how
/// many entries a single directory holds.
const LIST_CHUNK: usize = 256;

/// One filesystem object's identity: its `(device, inode)` pair, in the widths the root
/// registry records them in.
type ObjectId = (u64, u128);

/// A root as a listing receives it: the path to open, and the object that path must
/// resolve to for the walk to be about the armed root at all.
type BoundRoot = (PathBuf, ObjectId);

/// A walk's unopened start: its bound root, the validated plain names leading down to the
/// starting key, and that key's root-relative text.
type Seed = (PathBuf, ObjectId, Vec<OsString>, String);

/// The blocking-job spawner a [`FsSource`] hands its listing reads to — the shape the
/// lower watcher's own pool handle has, captured once from the runtime at construction.
type BlockingSpawner = Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync + 'static>;

/// One open directory the walk is consuming, with everything the items it yields are
/// named from.
struct Level {
  dir: OpenDir,
  /// The absolute path of this directory — what an item's key is built from.
  path: PathBuf,
  /// Its root-relative `/`-joined text, empty at the root: what the pattern words are
  /// matched against.
  at: String,
  /// The child directories this level has read and not yet descended into, oldest first.
  /// At most one chunk's worth, which is what keeps the walk's memory independent of a
  /// directory's width.
  pending: VecDeque<(OsString, String)>,
  /// Whether the reader has reached the end of the directory.
  exhausted: bool,
  /// How far below the starting key this level sits; the start is zero.
  depth: usize,
}

impl Level {
  fn new(dir: OpenDir, path: PathBuf, at: String, depth: usize) -> Self {
    Self {
      dir,
      path,
      at,
      pending: VecDeque::new(),
      exhausted: false,
      depth,
    }
  }
}

/// What one chunk job answers: the open directory it was lent (absent only when the job
/// never answered at all), the entries it read, and whether it reached the end.
struct Chunk {
  dir: Option<OpenDir>,
  entries: Result<Vec<(OsString, Metadata)>, std::io::Error>,
  exhausted: bool,
}

/// One [`FsSource::list`](Source::list) walk in progress: a pre-order DEPTH-FIRST
/// enumeration of the root at and under the starting key, read in bounded chunks on the
/// blocking pool.
///
/// Depth-first over a stack of OPEN directories rather than breadth-first over a queue of
/// paths, for two reasons that are really one. A frontier of paths grows with the width of
/// every level, so a single wide directory costs memory proportional to its entry count
/// before the consumer receives one item; a stack costs one open directory per LEVEL. And a
/// queued PATH has to be re-opened to be read, which is the window a rename uses to put a
/// symbolic link where a directory was — an open descriptor cannot be re-pointed, so the
/// walk stays inside the tree it was asked about by construction rather than by a check
/// that can be raced.
struct Walk {
  blocking: BlockingSpawner,
  /// The pruned subtrees, matched against root-relative directory paths.
  prune: Vec<Glob>,
  /// The file narrowing, matched against a file's last segment. `None` is unengaged.
  include: Option<Vec<Glob>>,
  /// The start still to be opened: the root's path, the object identity that path must
  /// resolve to, and the validated plain names that lead down to the starting key, with
  /// the root-relative text of that key.
  ///
  /// The open is deferred to the first step because it is a syscall per component, and
  /// every syscall this walk makes belongs on the blocking pool.
  seed: Option<Seed>,
  /// The open directories of the current descent, outermost first.
  stack: Vec<Level>,
  /// Items read and not yet yielded — at most one chunk, plus the refusals it produced.
  ready: VecDeque<ListItem<OsString>>,
}

impl Walk {
  /// Seeds a walk of `root`'s subtree at `from`, or — for a handle naming no live root, or
  /// a `from` that is not a key UNDER the root — a walk whose one item is that refusal.
  ///
  /// `from` decides where the walk STARTS and the root still anchors the WORDS: the
  /// relative text a pattern is matched against is built from the root down, so listing a
  /// subtree admits exactly what listing the whole root would have admitted there. A `from`
  /// outside the root is refused rather than re-rooted — a walk that quietly changed which
  /// tree it was about would report entries the watch behind the root can never mention.
  fn new(
    bound: Option<BoundRoot>,
    from: &[OsString],
    globs: &RootGlobs,
    blocking: BlockingSpawner,
  ) -> Self {
    let prune = globs.prune().to_vec();
    let mut seed = None;
    let mut ready = VecDeque::new();
    match bound.map(|(root, identity)| (path_components(&root), root, identity)) {
      Some((root_key, root, identity)) if from.starts_with(&root_key) => {
        match Self::start_below(&from[root_key.len()..], &prune) {
          Some((names, at)) => seed = Some((root, identity, names, at)),
          // A suffix that is not a plain name under the root, or that starts on ground the
          // root's own words refuse: a key that is not a key under this root is covered by
          // no armed root, which is the same answer an unwatched key gets.
          None => ready.push_back(Err(ListError::UnknownRoot)),
        }
      }
      // Either the handle names no live root of this source, or the caller named ground
      // outside the one it does name.
      _ => ready.push_back(Err(ListError::UnknownRoot)),
    }
    Self {
      blocking,
      prune,
      include: globs.include().map(<[Glob]>::to_vec),
      seed,
      stack: Vec::new(),
      ready,
    }
  }

  /// The plain names leading to the starting key and its root-relative text, or `None`
  /// where `from` is not a key under the root after all.
  ///
  /// Every component below the root must be a PLAIN NAME: `Path::components` over it must
  /// yield exactly one [`Component::Normal`](std::path::Component::Normal) equal to the
  /// component itself, non-empty and valid UTF-8. That refuses `..`, an absolute or prefix
  /// component, an embedded separator, an empty segment and a name no pattern can be
  /// matched against — each of which, joined onto the root, addresses ground the root does
  /// not cover, and a walk is not the place to discover that.
  ///
  /// `prune` is applied to EVERY root-relative directory prefix, the starting key
  /// included. The watch never entered pruned ground, so a listing that started inside it
  /// would hand a consumer entries no change stream will ever mention.
  fn start_below(below: &[OsString], prune: &[Glob]) -> Option<(Vec<OsString>, String)> {
    let mut names = Vec::with_capacity(below.len());
    let mut at = String::new();
    for segment in below {
      let text = segment.to_str()?;
      if text.is_empty() {
        return None;
      }
      let mut components = std::path::Path::new(segment).components();
      match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(only)), None) if only == segment.as_os_str() => {}
        _ => return None,
      }
      if !at.is_empty() {
        at.push('/');
      }
      at.push_str(text);
      if prune.iter().any(|glob| glob.is_match(&at)) {
        return None;
      }
      names.push(segment.clone());
    }
    Some((names, at))
  }

  /// The next item, opening or reading one more directory whenever the last chunk is
  /// exhausted.
  async fn step(mut self) -> Option<(ListItem<OsString>, Self)> {
    loop {
      if let Some(item) = self.ready.pop_front() {
        return Some((item, self));
      }
      if let Some((root, identity, names, at)) = self.seed.take() {
        let start = names
          .iter()
          .fold(root.clone(), |path, name| path.join(name));
        match Self::open_start(&self.blocking, root, identity, names).await {
          Ok(Start::Opened(dir)) => self.stack.push(Level::new(dir, start, at, 0)),
          // The path opened, but not onto the object the root is armed on: the armed root
          // no longer names that directory, so nothing under it is ground this watch
          // covers — the same answer an unwatched key gets, and never a walk of a tree the
          // event stream says nothing about.
          Ok(Start::NotTheRoot) => self.ready.push_back(Err(ListError::UnknownRoot)),
          // A symbolic link anywhere on the way down — the starting key itself
          // included — is refused by the kernel rather than followed, and arrives here as
          // the one `Io` item that key can honestly be.
          Err(source) => self.ready.push_back(Err(ListError::Io {
            key: path_components(&start),
            source,
          })),
        }
        continue;
      }
      // Nothing open and nothing seeded: the walk is over.
      let level = self.stack.pop()?;
      let Level {
        dir,
        path,
        at,
        mut pending,
        exhausted,
        depth,
      } = level;
      if let Some((name, relative)) = pending.pop_front() {
        let child = path.join(&name);
        if depth + 1 >= MAX_LIST_DEPTH {
          // Deeper than the walk may hold open. Reported for the directory's OWN key, not
          // its parent's: the ground that is missing is everything below this entry.
          self.ready.push_back(Err(ListError::Io {
            key: path_components(&child),
            source: std::io::Error::new(
              std::io::ErrorKind::InvalidInput,
              "the listing's depth ceiling was reached, so this directory was not descended",
            ),
          }));
          self.stack.push(Level {
            dir,
            path,
            at,
            pending,
            exhausted,
            depth,
          });
          continue;
        }
        let (parent, opened) = Self::open_child(&self.blocking, dir, name).await;
        if let Some(dir) = parent {
          self.stack.push(Level {
            dir,
            path,
            at,
            pending,
            exhausted,
            depth,
          });
        }
        match opened {
          Ok(dir) => self.stack.push(Level::new(dir, child, relative, depth + 1)),
          Err(source) => self.ready.push_back(Err(ListError::Io {
            key: path_components(&child),
            source,
          })),
        }
        continue;
      }
      if exhausted {
        // Nothing left to read and nothing left to descend: the level's descriptors close
        // with it here.
        continue;
      }
      let chunk = Self::read_chunk(&self.blocking, dir).await;
      let entries = match chunk.entries {
        Ok(entries) => entries,
        // One unreadable directory is an ITEM: the listing is incomplete below this key
        // and complete everywhere else, and only the key says which half the consumer got.
        // The level is not pushed back — nothing more can be read from it.
        Err(source) => {
          self.ready.push_back(Err(ListError::Io {
            key: path_components(&path),
            source,
          }));
          continue;
        }
      };
      let Some(dir) = chunk.dir else {
        continue;
      };
      let mut level = Level {
        dir,
        path,
        at,
        pending,
        exhausted: chunk.exhausted,
        depth,
      };
      self.absorb(&level.path, &level.at, &mut level.pending, entries);
      self.stack.push(level);
    }
  }

  /// Files one chunk's entries: admitted ones onto [`ready`](Self::ready), descendable
  /// ones onto the level's own pending list.
  ///
  /// `path` is the directory the chunk came from — the ground an entry this loop cannot
  /// even NAME is reported under, exactly as a directory this loop cannot READ is reported
  /// under its own key in [`step`](Self::step).
  fn absorb(
    &mut self,
    path: &Path,
    at: &str,
    pending: &mut VecDeque<(OsString, String)>,
    entries: Vec<(OsString, Metadata)>,
  ) {
    for (name, metadata) in entries {
      // A name that is not valid UTF-8 cannot be matched, yielded, or descended
      // honestly: `prune`/`include` are text patterns, and matching them against a
      // LOSSY rendering would admit, prune, or descend the entry on words the tree
      // does not hold. The watch side makes the same refusal (`tributary-fs`'s
      // `on_enumerated` drops the entry and marks the listing lossy); a listing says
      // it out loud instead, as the one item this entry can honestly be.
      let Some(text) = name.to_str() else {
        self.ready.push_back(Err(ListError::Io {
          key: path_components(path),
          source: std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the entry's name is not UTF-8, so neither the listing nor the watch can name it",
          ),
        }));
        continue;
      };
      let relative = if at.is_empty() {
        text.to_owned()
      } else {
        std::format!("{at}/{text}")
      };
      let key = path_components(&path.join(&name));
      if metadata.is_dir() {
        // THE PRUNE WORDS, applied exactly where the arm applies them: a matching
        // directory is neither descended nor reported, so nothing this listing yields
        // can sit under ground the watch refuses to enter.
        if self.prune.iter().any(|glob| glob.is_match(&relative)) {
          continue;
        }
        pending.push_back((name, relative));
      } else if let Some(include) = self.include.as_ref() {
        // THE INCLUDE WORDS, likewise: they narrow FILES by their last segment and
        // never a directory — the rule the delivery seat applies to a change.
        if !include.iter().any(|glob| glob.is_match(text)) {
          continue;
        }
      }
      self.ready.push_back(Ok((key, metadata)));
    }
  }

  /// Opens the walk's starting directory on the blocking pool: the root with no-follow
  /// semantics, then one descriptor-relative open per validated name below it.
  async fn open_start(
    blocking: &BlockingSpawner,
    root: PathBuf,
    identity: ObjectId,
    names: Vec<OsString>,
  ) -> Result<Start, std::io::Error> {
    let (tx, rx) = futures_channel::oneshot::channel();
    (*blocking)(Box::new(move || {
      let _ = tx.send(open_start_blocking(&root, identity, &names));
    }));
    rx.await.unwrap_or_else(|_| Err(job_answered_nothing()))
  }

  /// Opens one child directory beneath `dir` on the blocking pool, handing `dir` back
  /// with the answer so the parent stays readable.
  async fn open_child(
    blocking: &BlockingSpawner,
    dir: OpenDir,
    name: OsString,
  ) -> (Option<OpenDir>, Result<OpenDir, std::io::Error>) {
    let (tx, rx) = futures_channel::oneshot::channel();
    (*blocking)(Box::new(move || {
      let opened = dir.open_child(&name);
      let _ = tx.send((dir, opened));
    }));
    match rx.await {
      Ok((dir, opened)) => (Some(dir), opened),
      Err(_) => (None, Err(job_answered_nothing())),
    }
  }

  /// Reads at most [`LIST_CHUNK`] entries of `dir` on the blocking pool and awaits the
  /// answer.
  ///
  /// The open directory is MOVED into the job and handed back with what it read, so no
  /// descriptor is touched on the async task. That is also what makes the await
  /// cancellation-safe: a consumer that drops the stream mid-chunk drops the receiver where
  /// it stands, and the job then closes the directory it holds on a pool thread the moment
  /// its syscall returns. A job that answers NOTHING — the pool refused it, or it unwound —
  /// is a failure to READ and is reported as one, rather than as an empty directory, which
  /// is a different statement entirely.
  async fn read_chunk(blocking: &BlockingSpawner, dir: OpenDir) -> Chunk {
    let (tx, rx) = futures_channel::oneshot::channel();
    (*blocking)(Box::new(move || {
      let mut dir = dir;
      let mut read = Vec::new();
      // A read that fails part way through has nothing to say about the entries it did
      // get: they are half a directory, and half a directory is not a statement a
      // consumer can act on. It answers the failure, once, for the whole key.
      let (entries, exhausted) = match dir.read(LIST_CHUNK, &mut read) {
        Ok(exhausted) => (Ok(read), exhausted),
        Err(err) => (Err(err), true),
      };
      let _ = tx.send(Chunk {
        dir: Some(dir),
        entries,
        exhausted,
      });
    }));
    rx.await.unwrap_or_else(|_| Chunk {
      dir: None,
      entries: Err(job_answered_nothing()),
      exhausted: true,
    })
  }
}

fn job_answered_nothing() -> std::io::Error {
  std::io::Error::other("the listing's blocking job answered nothing")
}

/// What opening the walk's starting directory produced.
enum Start {
  /// The registered root's own object, opened, with the start reached below it.
  Opened(OpenDir),
  /// The root's path opened onto a DIFFERENT object than the one the root is armed on.
  NotTheRoot,
}

/// Opens the root without following a final symbolic link, CHECKS that what opened is the
/// object the root is armed on, then walks down to the starting key one
/// descriptor-relative open at a time. Each parent closes as its child opens, so reaching
/// the start costs one open directory however deep it sits.
///
/// The identity check is the root's alone, and that is enough: everything below it is
/// reached through the descriptor of the directory it was read from, so binding the first
/// descriptor binds the whole walk. `O_NOFOLLOW` guards only a final symbolic link, which
/// leaves two ways for a path to name the wrong tree — the root renamed away and
/// re-created, and an ancestor replaced by a symbolic link — and both are exactly a
/// different object under the same path. The converse case is why the test is identity and
/// not the path: a root reached THROUGH a symlinked ancestor that still opens the
/// registered object IS the root, and is listed.
fn open_start_blocking(
  root: &Path,
  identity: ObjectId,
  names: &[OsString],
) -> Result<Start, std::io::Error> {
  let mut dir = OpenDir::open_root(root)?;
  if !dir.is(identity)? {
    return Ok(Start::NotTheRoot);
  }
  for name in names {
    dir = dir.open_child(name)?;
  }
  Ok(Start::Opened(dir))
}

/// One open directory of a unix listing: the descriptor every `openat`/`statat` beneath it
/// names, and the reader its entries come out of.
///
/// Two descriptors rather than one because `rustix::fs::Dir` takes a descriptor and does
/// not lend it back, and the walk needs one of its own to open and stat children RELATIVE
/// to this directory. That is the whole containment argument: a child is reached through
/// the descriptor of the directory it was read from, never by re-resolving a path that a
/// rename may have re-pointed since, and both the open and the stat refuse to traverse a
/// symbolic link.
#[cfg(unix)]
struct OpenDir {
  fd: std::os::fd::OwnedFd,
  reader: rustix::fs::Dir,
}

#[cfg(unix)]
impl OpenDir {
  /// `O_DIRECTORY` so only a directory can be opened at all, `O_NOFOLLOW` so a symbolic
  /// link in the final position is `ELOOP` rather than a door out of the tree, and
  /// `O_CLOEXEC` because a listing's descriptors are this process's business.
  fn flags() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
      | rustix::fs::OFlags::DIRECTORY
      | rustix::fs::OFlags::NOFOLLOW
      | rustix::fs::OFlags::CLOEXEC
  }

  fn open_root(path: &Path) -> Result<Self, std::io::Error> {
    let fd = rustix::fs::openat(
      rustix::fs::CWD,
      path,
      Self::flags(),
      rustix::fs::Mode::empty(),
    )?;
    Self::over(fd)
  }

  fn open_child(&self, name: &OsString) -> Result<Self, std::io::Error> {
    let fd = rustix::fs::openat(
      &self.fd,
      name.as_os_str(),
      Self::flags(),
      rustix::fs::Mode::empty(),
    )?;
    Self::over(fd)
  }

  fn over(fd: std::os::fd::OwnedFd) -> Result<Self, std::io::Error> {
    let reader = rustix::fs::Dir::read_from(&fd)?;
    Ok(Self { fd, reader })
  }

  /// Whether this open directory IS the object `identity` names — read off the DESCRIPTOR,
  /// so nothing can move under the answer between the test and the reads that follow it.
  fn is(&self, identity: ObjectId) -> Result<bool, std::io::Error> {
    let stat = rustix::fs::fstat(&self.fd)?;
    Ok(object_identity(stat.st_dev, stat.st_ino) == Some(identity))
  }

  /// Reads at most `limit` entries with the metadata `statat` reads for each WITHOUT
  /// following a symbolic link, and reports whether the directory is exhausted.
  ///
  /// `.` and `..` are not entries of the listing: one is the directory itself and the
  /// other leaves it.
  fn read(
    &mut self,
    limit: usize,
    into: &mut Vec<(OsString, Metadata)>,
  ) -> Result<bool, std::io::Error> {
    use std::os::unix::ffi::OsStrExt;

    while into.len() < limit {
      let entry = match self.reader.read() {
        None => return Ok(true),
        Some(Ok(entry)) => entry,
        Some(Err(err)) => return Err(err.into()),
      };
      let bytes = entry.file_name().to_bytes();
      if bytes == b"." || bytes == b".." {
        continue;
      }
      let name = std::ffi::OsStr::from_bytes(bytes).to_owned();
      let stat = rustix::fs::statat(
        &self.fd,
        name.as_os_str(),
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
      )?;
      into.push((name, metadata_of(&stat)));
    }
    Ok(false)
  }
}

/// One entry's facts, read from the `statat` that did not follow a link: a symbolic link
/// is therefore reported as ITSELF, which is what keeps it out of the descent.
#[cfg(unix)]
fn metadata_of(stat: &rustix::fs::Stat) -> Metadata {
  let class = rustix::fs::FileType::from_raw_mode(stat.st_mode);
  let kind = if class == rustix::fs::FileType::Directory {
    EntryKind::Dir
  } else if class == rustix::fs::FileType::Symlink {
    EntryKind::Symlink
  } else if class == rustix::fs::FileType::RegularFile {
    EntryKind::File
  } else {
    EntryKind::Other
  };
  let listed = Metadata::new(kind, u64::try_from(stat.st_size).unwrap_or(0));
  match since_epoch(stat.st_mtime, stat.st_mtime_nsec) {
    Some(offset) => listed.with_modified(std::time::UNIX_EPOCH + offset),
    None => listed,
  }
}

/// A `stat`'s device-and-inode pair in the widths the root registry records it in, or
/// `None` for a pair that does not fit them — which cannot be the registry's value either,
/// so it compares as the mismatch it is.
///
/// Generic over the two field types for the reason [`since_epoch`] is: they are not the
/// same everywhere, and one body covers every unix.
#[cfg(unix)]
fn object_identity<D, I>(dev: D, ino: I) -> Option<ObjectId>
where
  u64: TryFrom<D>,
  u128: TryFrom<I>,
{
  Some((u64::try_from(dev).ok()?, u128::try_from(ino).ok()?))
}

/// A `stat`'s seconds-and-nanoseconds pair as an offset from the epoch, or `None` for a
/// time before it — which is the same answer a source that cannot read a time gives.
///
/// Generic over the two field types because they are not the same everywhere: the kernel's
/// own `stat` carries unsigned seconds where the C library's carries a signed `time_t`, and
/// writing the conversion once over whatever they are keeps one body for every unix.
#[cfg(unix)]
fn since_epoch<S, N>(secs: S, nanos: N) -> Option<std::time::Duration>
where
  u64: TryFrom<S>,
  u32: TryFrom<N>,
{
  let secs = u64::try_from(secs).ok()?;
  let nanos = u32::try_from(nanos).ok()?;
  Some(std::time::Duration::new(secs, nanos))
}

/// The non-unix listing's open directory. `std` has no descriptor-relative open, so
/// containment rests on a no-follow check taken immediately before the read rather than on
/// a descriptor that cannot be re-pointed: a rename between the two still leaves a window.
/// The residual is recorded rather than papered over — the platform this affects is the one
/// whose backends are deferred.
#[cfg(not(unix))]
struct OpenDir {
  path: PathBuf,
  reader: std::fs::ReadDir,
}

#[cfg(not(unix))]
impl OpenDir {
  fn open_root(path: &Path) -> Result<Self, std::io::Error> {
    Self::over(path.to_path_buf())
  }

  fn open_child(&self, name: &OsString) -> Result<Self, std::io::Error> {
    Self::over(self.path.join(name))
  }

  /// The identity check is SKIPPED off unix: `std` gives this walk no descriptor to stat,
  /// and a second path lookup would answer about whatever the path names now rather than
  /// about what was opened. Recorded as a residual on the platform whose backends are
  /// deferred, alongside the no-follow residual above.
  fn is(&self, _identity: ObjectId) -> Result<bool, std::io::Error> {
    Ok(true)
  }

  fn over(path: PathBuf) -> Result<Self, std::io::Error> {
    let metadata = std::fs::symlink_metadata(&path)?;
    // A symbolic link and a non-directory are the same refusal here, under the kind that
    // is stable to name: a listing descends directories, and it reaches one by opening it
    // rather than by following anything to it. (`ErrorKind::FilesystemLoop`, which the
    // unix side gets from the kernel's own `ELOOP`, is not stable to construct.)
    if metadata.file_type().is_symlink() {
      return Err(std::io::Error::new(
        std::io::ErrorKind::NotADirectory,
        "a listing reports a symbolic link and never opens one",
      ));
    }
    if !metadata.is_dir() {
      return Err(std::io::Error::new(
        std::io::ErrorKind::NotADirectory,
        "a listing descends directories only",
      ));
    }
    let reader = std::fs::read_dir(&path)?;
    Ok(Self { path, reader })
  }

  /// Reads at most `limit` entries with their own metadata — [`std::fs::DirEntry::metadata`]
  /// does not traverse a symbolic link, so a link is reported as itself here too.
  fn read(
    &mut self,
    limit: usize,
    into: &mut Vec<(OsString, Metadata)>,
  ) -> Result<bool, std::io::Error> {
    while into.len() < limit {
      let entry = match self.reader.next() {
        None => return Ok(true),
        Some(Ok(entry)) => entry,
        Some(Err(err)) => return Err(err),
      };
      let metadata = entry.metadata()?;
      into.push((entry.file_name(), metadata_of(&metadata)));
    }
    Ok(false)
  }
}

#[cfg(not(unix))]
fn metadata_of(metadata: &std::fs::Metadata) -> Metadata {
  let kind = if metadata.is_dir() {
    EntryKind::Dir
  } else if metadata.is_symlink() {
    EntryKind::Symlink
  } else if metadata.is_file() {
    EntryKind::File
  } else {
    EntryKind::Other
  };
  let listed = Metadata::new(kind, metadata.len());
  match metadata.modified() {
    Ok(modified) => listed.with_modified(modified),
    Err(_) => listed,
  }
}

/// How many pending releases one `arm` hands to the watcher's control channel via the
/// reply-less [`Watcher::request_unwatch`] — the HARD per-arm opportunistic budget (
/// ). A channel-full stop is not a bound (the driver drains concurrently, so `try_send`
/// can keep succeeding), and every reply-less `Unwatch` handed off here is processed BEFORE this
/// arm's own `watch` command on the same FIFO control channel — so an unbounded walk would couple
/// the caller (and any close behind it) to the entire unrelated release backlog. A fixed few per
/// arm keeps that pre-watch FIFO work O(1) while preserving clause 5's eventual application
/// (later arms, the conflict-triggered path, or `Drop` take the rest).
const OPPORTUNISTIC_RELEASE_HANDOFFS: usize = 2;

impl<R> Source<OsString> for FsSource<R> {
  type Handle = RootHandle;

  fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
    // Resolve the path with the SAME canonicalization `arm` applies (via
    // `tributary_fs::Watcher::watch`, which `std::fs::canonicalize`s its root before spawning the
    // stream), so the umbrella classifies and commits on the coordinate events arrive under. A
    // non-existent or unreadable path fails here — the umbrella refuses to commit a key backed by
    // no real location, rather than accepting it silently and then never delivering an event.
    // Idempotent on an already-canonical path (`canonicalize` is a fixed point there), as the
    // trait's idempotence contract requires.
    let supplied = key_to_path(key);
    let canonical = std::fs::canonicalize(&supplied).map_err(|source| {
      // Classify by the io error's kind — the two cases a caller can act on distinctly
      // (a missing path vs a permission wall) — and fold the rest to `Other`; the whole
      // io error is preserved in the box either way. The key's display form is this
      // binding's own rendering (the neutral error is not path-typed).
      let kind = match source.kind() {
        std::io::ErrorKind::NotFound => FaultKind::NotFound,
        std::io::ErrorKind::PermissionDenied => FaultKind::PermissionDenied,
        _ => FaultKind::Other,
      };
      WatchError::canonicalize(
        supplied.display().to_string(),
        SourceFault::new(kind).with_source(source),
      )
    })?;
    Ok(path_components(&canonical))
  }

  async fn arm(
    &mut self,
    key: &[OsString],
    globs: &RootGlobs,
  ) -> Result<Armed<OsString, RootHandle>, WatchError> {
    // (0) MAINTENANCE: drop every in-flight release the watcher has SINCE applied, and its dead-mark.
    // Once the watcher's registry has forgotten a root, it can never NAME it as a conflict again, and
    // `root_path` now answers the same `None` the mirror did — so pruning here keeps both the in-flight
    // sidecar and `pending_set` bounded by the in-flight (requested-but-unapplied) release count (never
    // the watcher's lifetime), while preserving the clause-3 invariant: a handle stays dead-marked in
    // `pending_set` exactly while the watcher still reports its root live, and the prune drops the mark
    // the instant `root_path` takes over answering `None`. Split-borrow: `watcher` is a shared reborrow
    // so each `retain` can mutate a DIFFERENT field.
    {
      let watcher = &self.watcher;
      self
        .enqueued
        .retain(|(handle, _)| watcher.root_path(*handle).is_some());
      self
        .pending_set
        .retain(|handle| watcher.root_path(*handle).is_some());
      // A released/retired root can never have another in-flight sync cancelled
      // against it, so drop its cancel-address entry here too (belt-and-suspenders:
      // the abandonment path already removes it via `cancel_sync`, and the owner's
      // teardown drops the whole source). Keeps `pending_syncs` bounded by the live
      // handles, exactly like `pending_set`/`enqueued`.
      #[cfg(feature = "sync")]
      self
        .pending_syncs
        .retain(|handle, _| watcher.root_path(*handle).is_some());
    }
    // An arm touches the watcher, so re-forward any full-channel-deferred prunes first
    // (set_cover contract clause 3) — non-blocking `try_send`s, nothing awaited.
    self.flush_deferred_prunes();

    // (a) OPPORTUNISTIC NON-BLOCKING application: hand a HARD-BOUNDED few pending releases to the
    // watcher's control channel via the reply-less `request_unwatch` (a `try_send`). On acceptance
    // the entry moves from the queue to the in-flight `enqueued` sidecar and STAYS dead-marked in
    // `pending_set` (it is logically dead until its teardown lands, clause 3). This AWAITS NOTHING — a
    // disjoint arm is decoupled from every release's teardown latency. The bound is a
    // FIXED per-arm handoff budget, NOT the channel-full stop: on a multi-threaded
    // runtime the driver drains the channel concurrently, so try_send could keep succeeding and an
    // unbounded walk would enqueue the ENTIRE unrelated backlog ahead of this arm's own watch
    // command on the same FIFO channel — coupling the caller (and any close behind it) to unrelated
    // release processing. At most a fixed few per arm keeps that pre-watch FIFO work O(1); the rest
    // stay queued for later arms, the conflict-triggered path (c), or `Drop` (clause 5's three
    // routes unchanged). This is NOT the correctness mechanism — (c) is — so enqueuing an unrelated
    // release here is harmless (it was going to be released anyway).
    for _ in 0..OPPORTUNISTIC_RELEASE_HANDOFFS {
      let Some(entry) = self.pending_releases.pop_front() else {
        break;
      };
      // `entry.0` is `Copy` (a `RootHandle`), so the try_send borrows nothing of `entry`.
      match self.watcher.request_unwatch(entry.0) {
        // Accepted onto the control channel: move queue → in-flight sidecar (the success path).
        RequestOutcome::Enqueued => self.enqueued.push(entry),
        // The channel is momentarily full: return the entry to the FRONT (FIFO preserved) and
        // stop — the driver drains concurrently, so a later arm retries it (backpressure, clause
        // 5's eventual application). This is the ONLY re-front: a full channel is transient.
        RequestOutcome::Busy => {
          self.pending_releases.push_front(entry);
          break;
        }
        // Never enqueueable — a foreign brand or a closed watcher. DROP the entry AND its
        // dead-mark, then CONTINUE (do NOT re-front): re-fronting a never-valid entry wedges the
        // queue permanently and starves every genuine release behind it.
        // The `disarm` door already keeps foreign brands out of the queue; this is the
        // belt-and-suspenders drain-side kill, and it lets the genuine releases behind it drain.
        RequestOutcome::Rejected => {
          self.pending_set.remove(&entry.0);
        }
      }
    }
    // (b)+(c) Arm the root, resolving on demand any `Overlaps` the watcher reports against a
    // released-but-still-lingering root. Roots are always armed `Interest::all` (design §4): the kernel
    // watch never narrows what it collects, so a covered subscription can ask for any kind and the root
    // already carries it (interest becomes a pure fan-out gate at the umbrella).
    //
    // The two GLOB seats are the exception, and deliberately so: they are not a delivery
    // gate the umbrella could apply above the seam but the words this root is armed with,
    // so they ride the fs household straight down to `watch_with`. `prune` subtracts
    // coverage — the fs watcher never enumerates, arms or descends a matching subtree —
    // and `include` narrows which files that coverage delivers. Both are matched relative
    // to THIS root, which is the coordinate `arm_path` names, so the words the umbrella
    // handed down need no re-basing here. Absent seats (the default household) leave the
    // watch byte-for-byte the `watch(path, Interest::all())` it always was.
    //
    // The correctness guarantee — a conforming source never SURFACES an `Overlaps` for a root whose
    // release was requested, QUEUED or IN-FLIGHT (disarm contract clause 2) — is upheld here by
    // construction: the WATCHER itself names the conflicting `existing` root (it rejects by
    // object/ancestor IDENTITY, so it catches case/normalization aliases a byte-prefix overlap test
    // would miss). While the watcher's registry still reports a requested release live
    // (so it can name it), that release is in `pending_releases` (not yet handed over) OR in `enqueued`
    // (handed over, teardown not landed) — never neither — so the named `existing` EXACT-matches one of
    // the two. Retry is a **structural progress bound**, not a fixed cap: on a match
    // remove exactly that entry, AWAIT its `unwatch`, and re-attempt. An `enqueued` match awaits an
    // acked `unwatch` that — enqueued after the earlier reply-less request on the one FIFO channel —
    // resolves only once the driver has processed that teardown and reclaimed the registry entry, so
    // the retry sees the root gone. Each retry strictly SHRINKS `pending_releases` + `enqueued` (one
    // exact-matched entry removed, neither grows in the loop), so it terminates in ≤ (queued + in-flight)
    // retries with no arbitrary ceiling (the common case is ≤1; an ancestor arm over N released
    // descendants is bounded by the N the watcher names one at a time — however large N is). A rejection
    // whose named conflict is in NEITHER set — a genuine LIVE conflict (an umbrella-side disjointness
    // bug), never a lingering released root — surfaces the overlap IMMEDIATELY: there is no index-0
    // fallback, so we never unwatch an unrelated pending root to mask a real conflict.
    let arm_path = key_to_path(key);
    // Built once and cloned per retry: a conflict retry re-arms the SAME root with the
    // same words, so re-deriving them each iteration could only introduce a drift.
    let root_options = {
      let options = RootOptions::new()
        .with_interest(Interest::all())
        .with_prune(globs.prune().iter().cloned());
      match globs.include() {
        // `Some` and `None` are different seats, not a present-vs-empty list: an empty
        // `Some` admits no file at all, so it must reach the watcher as the engaged seat
        // it is rather than collapse into the absent one.
        Some(include) => options.with_include(include.iter().cloned()),
        None => options,
      }
    };
    // Progress tripwire (debug-only): the exact-match retry can run at most one more iteration than the
    // queued-plus-in-flight release count was deep, since that total strictly shrinks each retry and a
    // non-matching rejection exits immediately.
    #[cfg(debug_assertions)]
    let initial_pending = self.pending_releases.len() + self.enqueued.len();
    #[cfg(debug_assertions)]
    let mut iterations = 0usize;
    let handle = loop {
      #[cfg(debug_assertions)]
      {
        iterations += 1;
        debug_assert!(
          iterations <= initial_pending + 1,
          "FsSource::arm conflict-retry exceeded (queued + in-flight)+1 iterations — the queued and \
           in-flight release sets must strictly shrink each retry (structural progress bound)"
        );
      }
      match self
        .watcher
        .watch_with(arm_path.clone(), root_options.clone())
        .await
      {
        Ok(handle) => break handle,
        Err(WatchRootError::Overlaps { path, existing }) => {
          // Resolve ONLY a conflict the watcher NAMES against a release we requested — QUEUED (not yet
          // handed to the channel) or IN-FLIGHT (handed over, teardown not landed). Await its teardown
          // and retry; a named conflict in neither set is a genuine live overlap, surfaced as-is.
          if let Some(index) = self
            .pending_releases
            .iter()
            .position(|(_, stored)| stored.as_deref() == Some(existing.as_path()))
          {
            let (released, _) = self
              .pending_releases
              .remove(index)
              .expect("index in bounds");
            let _ = self.watcher.unwatch(released).await;
            self.pending_set.remove(&released);
          } else if let Some(index) = self
            .enqueued
            .iter()
            .position(|(_, stored)| stored.as_deref() == Some(existing.as_path()))
          {
            let (released, _) = self.enqueued.remove(index);
            let _ = self.watcher.unwatch(released).await;
            self.pending_set.remove(&released);
          } else {
            return Err(watch_error_from_fs(WatchRootError::Overlaps {
              path,
              existing,
            }));
          }
        }
        Err(err) => return Err(watch_error_from_fs(err)),
      }
    };
    // Adopt the filesystem-authoritative canonical path as the committed key (design §4, the
    // TOCTOU close): events are reported in canonical coordinates, so the index must key on
    // them. A `None` here means the root was already torn down (deleted between the request and
    // this arm completing) — a dead-on-arrival handle backing no live watch. Do NOT fall back
    // and report it armed: best-effort release it and fail, so the source never claims a dead
    // handle armed. Belt-and-suspenders under the driver's own arm-choke-point liveness check
    // (invariant I2), which guarantees this for every `Source` impl regardless.
    let Some(path) = self.watcher.root_path(handle) else {
      let _ = self.watcher.unwatch(handle).await;
      return Err(WatchError::DeadOnArrival);
    };
    Ok(Armed::new(handle, path_components(&path)))
  }

  fn disarm(&mut self, handle: RootHandle) {
    // Synchronous, non-blocking release REQUEST (contract clauses 1 & 3): queue it — paired with the
    // released root's canonical path captured NOW, while the root is still live in the registry — never
    // apply it inline. A later `arm` hands it to the watcher via the NON-BLOCKING `request_unwatch`
    // (the common path, which awaits nothing), or — if that arm's key overlaps this release — resolves
    // the conflict the watcher NAMES by awaiting exactly its `unwatch` (contract clause 2); `Drop`
    // releases whatever is left (the `Watcher`'s own teardown reclaims every live root). The
    // `pending_set` mirror makes the handle logically dead the instant this returns — `root_key`
    // answers `None`. Idempotent by the set: re-requesting an already-pending handle is a no-op.
    //
    // A queued PRUNE of the released handle is superseded by the release (set_cover contract
    // clause 4 — the whole root is going away), and a disarm is a watcher-touching op, so the other
    // deferred prunes get their non-blocking re-forward here too (clause 3).
    self.deferred_prunes.remove(&handle);
    self.flush_deferred_prunes();
    // DOOR: `root_path` answers `None` for a foreign brand OR an already-torn-down own handle. Drop
    // the disarm ENTIRELY for either — no `pending_releases` entry, no `pending_set` mark: a
    // `None`-path entry can never be the named `Overlaps` conflict (its only effect was a no-op
    // `request_unwatch`), and `root_key` correctness is preserved because `root_path` already
    // answers `None` for the handle. Post-door invariant: every `pending_releases` entry carries
    // `Some(path)` and names a live-at-disarm root of THIS instance — so the queue (and its
    // `pending_set` mirror) is bounded by the live-root count, and a hostile `disarm(fresh_foreign)`
    // flood retains nothing (every foreign disarm dies at the door).
    let Some(root_path) = self.watcher.root_path(handle) else {
      return;
    };
    if self.pending_set.insert(handle) {
      self.pending_releases.push_back((handle, Some(root_path)));
    }
  }

  /// The awaited GROW half of in-place coverage reconcile, over the watcher's
  /// **effect-completion fence**: [`Watcher::set_cover`]'s acknowledgement resolves when the
  /// reconcile has *settled* — every re-armed watch live, or a loss already signaled in-band —
  /// never at effect-queue time, which is exactly the applied-before-`Ok` fence the trait's
  /// clause 1 demands. A kernel-recursive root (fanotify / FSEvents) short-circuits to `Ok`
  /// before the round-trip: its single whole-subtree stream never narrowed, so there is nothing
  /// to grow back ([`Watcher::backend_of`] is the a-priori report; the driver's own
  /// [`Recursive`](CoverOutcome::Recursive) answer stays authoritative if the report races a
  /// backend change and the round-trip runs anyway).
  ///
  /// A grow for `handle` supersedes its queued full-channel-deferred prune (set_cover contract
  /// clause 6 — the grow's fresh cover is newer), and as a watcher-touching op re-forwards the
  /// other deferred prunes first (clause 3).
  ///
  /// # Errors
  ///
  /// The settled outcome maps per the trait's error contract — on every `Err` the fs layer has
  /// already emitted the dominating in-band `Rescan` wherever one is owed, and the umbrella
  /// keeps its record unbroadened and fails the watch retryably:
  ///
  /// - [`Degraded`](CoverOutcome::Degraded) → [`WatchError::CoverageIncomplete`]: the reconcile
  ///   settled but coverage loss was signaled inside the window, so some `retained` key may not
  ///   be backed;
  /// - [`Skipped(UnknownRoot)`](SkipReason::UnknownRoot) → a [`FaultKind::NotFound`] fault: the
  ///   covering root died concurrently with this grow (root death, stream fatal). Deliberately
  ///   NOT `CoverageIncomplete` — nothing degraded; the root is *gone* — and the caller's retry
  ///   re-plans, finds the dead root via `root_key`, retires it with terminal `Rescan`s, and
  ///   arms fresh. `Err(UnknownRoot)` (the watcher's foreign-handle pre-check) maps the same
  ///   way: either form means "no such root here";
  /// - [`Closed`](FsUnwatchError::Closed) → [`WatchError::Closed`], including a close mid-fence
  ///   (the ratified close semantics drop parked acknowledgements);
  /// - [`Skipped(NotLive)`](SkipReason::NotLive) / [`Skipped(RefusedCover)`](SkipReason::RefusedCover)
  ///   are unreachable from the umbrella (a `Covered` grow implies a committed, publicly-live
  ///   root, and the umbrella's covers are never empty or out-of-root): `debug_assert!` tripwires
  ///   plus a conservative fault in release.
  async fn grow(
    &mut self,
    handle: RootHandle,
    retained: &[Vec<OsString>],
  ) -> Result<(), WatchError> {
    // Supersede this handle's queued prune BEFORE the flush, so a stale narrower cover is never
    // re-forwarded ahead of (or instead of) this grow's fresh one.
    self.deferred_prunes.remove(&handle);
    self.flush_deferred_prunes();
    // Kernel-recursive short-circuit: coverage never narrowed, nothing to reconcile — skip the
    // command round-trip inside the caller-bounded reconcile.
    if self
      .watcher
      .backend_of(handle)
      .is_some_and(|backend| backend.is_kernel_recursive())
    {
      return Ok(());
    }
    let paths: Vec<PathBuf> = retained.iter().map(|key| key_to_path(key)).collect();
    #[cfg(test)]
    {
      self.cover_round_trips += 1;
    }
    match self.watcher.set_cover(handle, paths).await {
      Ok(CoverOutcome::Applied | CoverOutcome::Recursive) => Ok(()),
      Ok(CoverOutcome::Degraded) => Err(WatchError::CoverageIncomplete),
      Ok(CoverOutcome::Skipped(SkipReason::UnknownRoot)) => Err(WatchError::source(
        SourceFault::new(FaultKind::NotFound).with_source(format!(
          "the covering root (scope {}) died before the grow could be applied",
          handle.scope()
        )),
      )),
      Ok(CoverOutcome::Skipped(reason)) => {
        // NotLive / RefusedCover (or a future skip): unreachable from the umbrella — a grow is
        // only ever issued for a committed live root with a non-empty in-root cover — so a hit
        // here is an umbrella bug, not a runtime condition. Trip loudly in debug; fail the
        // watch conservatively in release (prior coverage is untouched, the record does not
        // broaden, the retry re-plans).
        debug_assert!(
          false,
          "FsSource::grow was skipped ({reason}) — the umbrella issued a grow for a root that \
           is not publicly live or with a refused cover"
        );
        Err(WatchError::source(
          SourceFault::new(FaultKind::Other).with_source(format!(
            "the coverage grow was skipped ({reason}) without reconciling"
          )),
        ))
      }
      // An unknown future settled outcome: fail conservatively (no broaden, retryable) with the
      // outcome preserved in the fault's message.
      Ok(outcome) => Err(WatchError::source(
        SourceFault::new(FaultKind::Other)
          .with_source(format!("unrecognized coverage-grow outcome ({outcome})")),
      )),
      // The foreign-handle pre-check — "no such root of this watcher", same answer as a
      // concurrently-dead root.
      Err(err @ FsUnwatchError::UnknownRoot) => Err(WatchError::source(
        SourceFault::new(FaultKind::NotFound).with_source(err),
      )),
      // Closed, or closed/died mid-fence: the uniform closed signal.
      Err(FsUnwatchError::Closed) => Err(WatchError::Closed),
      // An unknown future error case degrades conservatively, the whole fs error preserved.
      Err(err) => Err(WatchError::source(
        SourceFault::new(FaultKind::Other).with_source(err),
      )),
    }
  }

  /// The PRUNE half of in-place coverage reconcile: forwarded to the watcher the instant it is
  /// called via the NON-BLOCKING, reply-less [`Watcher::request_set_cover`] `try_send` (contract
  /// clause 3 — prompt), falling back to the **latest-wins per-handle deferral queue** only when
  /// the control channel is momentarily full (re-forwarded at the next watcher-touching op; a
  /// [`grow`](Self::grow) of the handle supersedes its queued prune — clause 6). The driver
  /// applies a reply-less reconcile exactly like the awaited one, latest-wins by FIFO order, so
  /// a prune followed by an awaited grow always ends at the grow's fresh cover.
  ///
  /// A handle whose [`disarm`](Self::disarm) was already requested is logically dead, so its
  /// prune is skipped outright — superseded by the release (clause 4: the whole root is going
  /// away). No result and no fence: a lost or deferred prune merely leaves the root over-broad,
  /// which is correctness-neutral and self-healing (clause 5).
  fn set_cover(&mut self, handle: RootHandle, retained: &[Vec<OsString>]) {
    if self.pending_set.contains(&handle) {
      return;
    }
    // DOOR: `root_path` answers `None` for a foreign brand OR an already-torn-down own root. A prune
    // of such a root is pointless — clause 5 does not require prune losslessness — so drop it at the
    // door rather than queue or defer it. Deferring never-valid work drives the monotone
    // `deferred_prunes` growth.
    if self.watcher.root_path(handle).is_none() {
      return;
    }
    // This request SUPERSEDES any queued older snapshot for the same handle (latest-wins,
    // clause 6) — drop it BEFORE the flush. Were the stale entry left for the flush, a full
    // channel there followed by room for the direct request below would leave the stale
    // snapshot queued BEHIND the newer applied one, and a later flush would re-apply it —
    // exactly the older-snapshot regression the clause forbids.
    self.deferred_prunes.remove(&handle);
    self.flush_deferred_prunes();
    let paths: Vec<PathBuf> = retained.iter().map(|key| key_to_path(key)).collect();
    match self.watcher.request_set_cover(handle, paths.clone()) {
      // Forwarded onto the control channel — nothing to defer.
      RequestOutcome::Enqueued => {}
      // The channel is momentarily full: fall back to the latest-wins deferral queue (clause 3),
      // re-forwarded at the next watcher-touching op.
      RequestOutcome::Busy => self.defer_prune(handle, paths),
      // A closed watcher (the door already excluded foreign/dead roots): never enqueueable, so
      // drop rather than defer — a deferral that can never forward grows without bound.
      RequestOutcome::Rejected => {}
    }
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, RootHandle>> {
    let raw = self.watcher.next().await?;
    Some(SourceEvent::from_fs(&raw))
  }

  /// The fs binding's make-before-break retarget.
  ///
  /// It carries the seam's re-basing clause literally, because
  /// [`Watcher::replace_root`](tributary_fs::Watcher::replace_root) does: the scope keeps the
  /// [`RootOptions`](tributary_fs::RootOptions) it was armed with — its interest and BOTH glob
  /// seats — and those seats are root-relative, so the same patterns are read against the new
  /// root. A depth-anchored `prune` therefore names a different directory after the widen, in
  /// either direction (`replace_root`'s own docs name the over- and under-coverage cases);
  /// `include` matches the object's name and re-bases unchanged. Nothing here restates a root's
  /// words — only an [`arm`](Source::arm) does.
  async fn replace(
    &mut self,
    handle: RootHandle,
    new_key: &[OsString],
  ) -> Result<Armed<OsString, RootHandle>, WatchError> {
    // Supersede this handle's queued prune BEFORE the flush, exactly as `grow`
    // does: the widen re-covers this root, so a prune still holding the OLD
    // retained set is stale. Left queued, a later watcher-touching op would
    // re-forward it AFTER the replace committed and narrow the widened root
    // back to the old subtree — a silent coverage loss with no `Rescan`. A
    // dropped prune is merely over-broad coverage, which self-heals.
    self.deferred_prunes.remove(&handle);
    self.flush_deferred_prunes();
    let new_root = key_to_path(new_key);
    // Make-before-break inside the fs layer: the replacement stream is live
    // BEFORE the old one retires, and the commit delivers one epoch-bumped
    // full-root `Rescan`. Atomic on failure — every error leaves the old
    // root's coverage untouched, which is exactly what lets the umbrella fall
    // back to release-and-rearm.
    match self.watcher.replace_root(handle, new_root.clone()).await {
      // The handle is PRESERVED (that is the point): the root the umbrella
      // already records simply covers more ground now.
      Ok(()) => {
        let canonical = self
          .watcher
          .root_path(handle)
          .ok_or_else(|| WatchError::Source(SourceFault::new(FaultKind::NotFound)))?;
        Ok(Armed::new(handle, path_components(&canonical)))
      }
      Err(err) => Err(replace_error_to_watch_error(err, &new_root)),
    }
  }

  #[cfg(feature = "sync")]
  async fn begin_sync(
    &mut self,
    handle: RootHandle,
    dir_key: &[OsString],
    token: SyncToken,
  ) -> Result<Begun<OsString>, SyncError> {
    // Any op that touches the watcher first re-forwards deferred prunes, so a
    // stale narrower cover never trails behind this write.
    self.flush_deferred_prunes();
    let dir = key_to_path(dir_key);
    // Mint the cancel address and record it BEFORE the await: if this future is
    // dropped mid-await (a caller cancel or a close won the owner's race), the
    // entry deliberately REMAINS for `cancel_sync` to consume — the owner never
    // learned the cookie path, so the ticket is the only precise handle on a write
    // that may still land. The token is stored beside it as the incarnation guard.
    //
    // The mint is also where the marker's LEAF comes from: the lower watcher draws
    // it off its own cryptographic stream and this binding renders none of its own,
    // so the one name the barrier stands on is minted at exactly one site in the
    // workspace. A watcher with no entropy source mints nothing and this binding
    // reports the same `Entropy` refusal the owner's own generator would have —
    // nothing has reached the filesystem yet, so the refusal leaves no marker
    // behind.
    let Some((admission, ticket)) = self.watcher.mint_sync_ticket() else {
      return Err(SyncError::Entropy);
    };
    self.pending_syncs.insert(handle, (token, ticket));
    // The fs watcher parks the write on the root's coverage-settle fence and
    // resolves at write-complete — never at observe. That is exactly the
    // bounded initiation this seam promises. The move-only admission is consumed
    // by the call (and carries the leaf it writes); the `Copy` ticket stays
    // recorded above for the abandonment cancel.
    let result = self.watcher.sync_root(handle, dir, admission).await;
    // A NORMAL return (Ok or Err) means the sync resolved server-side, so drop the
    // in-flight entry here; only the dropped-future path above leaves it behind.
    self.pending_syncs.remove(&handle);
    match result {
      Ok(path) => Ok(Begun::Installed(path_components(&path))),
      // The umbrella never retries `sync_root` at this level, so a returned
      // admission is dropped; the classification is over the carried `error`
      // alone, in `begun_from_fs`.
      Err(SyncRootDenied { error, .. }) => begun_from_fs(error),
    }
  }

  #[cfg(feature = "sync")]
  fn end_sync(&mut self, _handle: RootHandle, cookie_key: &[OsString]) {
    // A prompt request to reap the cookie now: it MARKS the obligation the driver
    // has held since it admitted the sync, so admission is guaranteed by type —
    // there is no queue a burst of control traffic could saturate. This path came
    // from the `begin_sync` reply, and the write published it before that reply
    // was sent, so the mark always finds its record. The driver OWNS every cookie
    // it wrote and unlinks it at scope or driver teardown regardless, so even a
    // reap to an already-closed driver leaks nothing. Runtime-free by design
    // (this seam carries no `R` bound): the runtime-bearing cleanup lives in the
    // driver.
    let path = key_to_path(cookie_key);
    self.flush_deferred_prunes();
    self.watcher.request_remove_cookie(path);
  }

  #[cfg(feature = "sync")]
  fn cancel_sync(&mut self, handle: RootHandle, token: SyncToken) {
    // The owner abandoned an in-flight `begin_sync` and never learned the cookie
    // path — but `begin_sync` recorded the watcher-minted ticket for this handle
    // before it awaited, so peek it and cancel by that ticket: the incarnation-
    // precise address the driver records at ADMISSION and therefore always resolves
    // while the sync is live. The stored token is the incarnation guard — a cancel
    // whose token does not match the recorded one is stale (a later incarnation
    // superseded it), and the entry is removed and the cancel issued ONLY on a
    // match, so a stale cancel leaves a live successor's entry INTACT for that
    // successor's own cancel to find; a missing entry means the sync already
    // returned (nothing to cancel). The driver reaps the cookie if the write
    // already landed, refuses the claim of a write still in the pool (so it
    // self-reaps the file it creates), retires a sync whose write was never
    // dispatched, or drops the request if the sync already resolved. Runtime-free
    // (a map lookup, a lock, and a `try_send`), like `end_sync`; the runtime-bearing
    // cleanup lives in the driver.
    self.flush_deferred_prunes();
    if let Some(&(stored, ticket)) = self.pending_syncs.get(&handle)
      && stored == token
    {
      self.pending_syncs.remove(&handle);
      #[cfg(test)]
      {
        self.sync_cancels_requested += 1;
      }
      self.watcher.request_cancel_sync(ticket);
    }
  }

  fn is_sync_artifact(&self, key: &[OsString]) -> bool {
    // Two independent grounds, because the sync namespace has two shapes and only
    // one of them carries a name this crate can predict.
    //
    // GROUND 1 — the LEAF is a name this workspace mints: the fs layer's cookie
    // DIRECTORY (whose own create is that driver's artifact, never a user change),
    // or a marker sitting directly in the sync directory, which is where every
    // version of this binding put its cookies before the cookie directory existed.
    // Both grammars live in the lower crate, which is the ONE minter of a marker
    // leaf: this binding renders no name of its own, so it can have no grammar of
    // its own to drift from that one. Matching the older shape too is what keeps a
    // crash leftover suppressed across an upgrade instead of resurfacing as a user
    // create — see `tributary_fs::is_sync_cookie_name`.
    //
    // GROUND 2 — the leaf's IMMEDIATE parent is exactly a cookie directory, whatever
    // the leaf. The cookie directory is `0o700` ground the fs driver owns, so nothing
    // that lands in it is a user change worth reporting; and a leaf grammar alone
    // cannot be the whole answer, because a marker RENAMED while it stands wears a
    // name no grammar recognizes and would then surface as a user create. Ground 1's
    // grammar and this one are therefore both needed: the leaf identifies a marker
    // wherever its directory has been moved to, and the directory identifies whatever
    // stands inside it whatever the leaf has been renamed to.
    //
    // Neither ground reads any deeper component, so a user file merely living under
    // some ancestor whose name shares the stem stays a user change — and, the other
    // way round, a marker whose ancestor directory is renamed while it stands is
    // classified the same under either path. That is what keeps it off consumer
    // streams and available to its own barrier wherever the queue reports it from:
    // the barrier is correlated by the marker's leaf under its root, so the two
    // halves read exactly the same components.
    //
    // GROUND 2 IS DECIDED FIRST, and reads only the PARENT component — because "whatever
    // the leaf" has to include a leaf that is not UTF-8. Paths on Unix are bytes, so an
    // active cookie can be renamed to an undecodable name while staying inside the
    // directory that reserves it; testing the leaf's `to_str()` first classified exactly
    // that move as reserved at its source alone, and the routing then projected the
    // internal destination onto consumer streams as a user-visible `Created`.
    //
    // The parent still converts, and needs no lossy fallback: a cookie directory's name is
    // minted as `format!("{prefix}-{euid}")`, pure ASCII, so a component that fails
    // `to_str()` cannot be one — the conversion rejects only names the classifier rejects
    // anyway. It is the LEAF whose text is optional, and only Ground 1 needs it.
    let parent_is_cookie_dir = key
      .len()
      .checked_sub(2)
      .and_then(|parent| key[parent].to_str())
      .is_some_and(tributary_fs::is_sync_cookie_dir_name);
    if parent_is_cookie_dir {
      return true;
    }
    // GROUND 1 is a grammar over TEXT, so a leaf this crate could have minted is UTF-8 by
    // construction; an undecodable leaf simply matches no minted shape and is left to the
    // ground above, which has already answered.
    key
      .last()
      .and_then(|leaf| leaf.to_str())
      .is_some_and(|leaf| {
        tributary_fs::is_sync_cookie_name(leaf) || tributary_fs::is_sync_cookie_dir_name(leaf)
      })
  }

  fn list(&self, handle: RootHandle, globs: &RootGlobs) -> impl Stream<Item = ListItem<OsString>> {
    // Through the lister's own walk, so the door the umbrella opens and the one a direct
    // caller opens can never be two walks that answer differently. The root's own key is
    // where it starts: listing a root is listing all of it.
    let from = self
      .watcher
      .root_path(handle)
      .map(|root| path_components(&root));
    FsLister::walk(
      self.watcher.root_view(),
      Arc::clone(&self.blocking),
      handle,
      from.as_deref().unwrap_or(&[]),
      globs,
    )
  }

  fn lister(&self) -> Option<Arc<dyn RootLister<OsString, RootHandle>>> {
    Some(Arc::new(FsLister {
      view: self.watcher.root_view(),
      blocking: Arc::clone(&self.blocking),
    }))
  }

  fn coverage(&self, handle: RootHandle) -> Coverage {
    // A released handle is logically dead the instant `disarm` returns (contract clause 3),
    // and a dead root has no coverage state to report: its terminal signal is the stream's.
    if self.pending_set.contains(&handle) {
      return Coverage::Proven;
    }
    // The watcher answers `Unproven` exactly while this root's periodic liveness tick is
    // being refused at its probe budget — the one condition under which nothing is
    // establishing that the root still exists. Every other root (including a backend with
    // no tick, whose root death has its own event) reads `Proven`, and so does a handle the
    // registry has forgotten.
    match self.watcher.coverage(handle) {
      Some(FsCoverage::Unproven) => Coverage::Unproven,
      Some(FsCoverage::Proven) | None => Coverage::Proven,
    }
  }

  fn root_key(&self, handle: RootHandle) -> Option<Vec<OsString>> {
    // A requested release is logically dead immediately (contract clause 3), even while its
    // transport teardown is still queued: answer `None` for a pending handle before consulting the
    // live registry, so a re-`watch` of a just-released key classifies it as gone.
    if self.pending_set.contains(&handle) {
      return None;
    }
    // `tributary_fs::Watcher::root_path` reads its live-root registry synchronously and
    // answers `None` for a torn-down handle, so a terminal `Rescan` (whose root fs has
    // forgotten) reports `None` here — exactly the dead/retired signal the owner needs.
    self
      .watcher
      .root_path(handle)
      .map(|path| path_components(&path))
  }

  /// Nothing to initiate ahead of the wait: the lower watcher's close is ONE command, and
  /// [`join_close`](Self::join_close) issues it. There is no cheaper, non-blocking half to split off
  /// — sending the command is itself the initiation, and it already awaits only mailbox room.
  ///
  /// Being a no-op is also why the umbrella entering this seam EARLY — at the instant it decides to
  /// stop, ahead of the cookie reaps and coverage releases its teardown still issues (see the seam's
  /// [contract](Source::begin_close)) — changes nothing this binding observes: the lower close is
  /// issued by `join_close`, which stays last, so every one of those requests still reaches the watcher
  /// before it is asked to close.
  fn begin_close(&mut self) {}

  /// Forwards the LOWER watcher's close — the strongest lifecycle fact this stack produces — as this
  /// source's quiescence result.
  ///
  /// `tributary_fs::Watcher::close`'s `Ok` proves every native stream torn down AND every sync
  /// cookie this watcher ever wrote confirmed removed from disk, and its `NotQuiesced` names how
  /// much was still outstanding when its own grace expired. Dropping the watcher instead — the only
  /// teardown available before this seam existed — starts the identical work but can neither await
  /// it nor report it, so an upper `close()` acknowledged over a live reader thread and an unlinked
  /// cookie still in flight, and a caller that shut its runtime down on that acknowledgement
  /// abandoned both.
  ///
  /// It is bounded by the lower close's own ~1 s grace, so a wedged mount produces a
  /// [`NotQuiesced`](SourceCloseError::NotQuiesced) report rather than an unbounded wait.
  ///
  /// The lower watcher is borrowed rather than consumed (`close_in_place`) because this source
  /// outlives the call by exactly as long as it takes the owner to drop it; a second call — there is
  /// none on the owner's path — would honestly report `Stopped`, since that call proves nothing.
  async fn join_close(&mut self) -> Result<(), SourceCloseError> {
    match self.watcher.close_in_place().await {
      Ok(()) => Ok(()),
      Err(FsCloseError::Stopped) => Err(SourceCloseError::Stopped),
      Err(FsCloseError::NotQuiesced { pending }) => Err(SourceCloseError::NotQuiesced { pending }),
      // The lower error type is `#[non_exhaustive]`: a variant added there is, by construction, a
      // close that did not prove quiescence.
      Err(_) => Err(SourceCloseError::NotQuiesced { pending: 1 }),
    }
  }
}

impl SourceEvent<OsString, RootHandle> {
  /// Reverses a raw `tributary-fs` event into a source event — **the** fs-to-neutral
  /// map: its absolute path back into key components, and its
  /// [`tributary_fs::EventKind`] into the umbrella's source-neutral [`EventKind`]
  /// (a move's source path becomes the [`Moved`](EventKind::Moved) kind's in-kind
  /// source key). The one place the fs vocabulary and a raw filesystem event's key are
  /// converted at this binding.
  fn from_fs(event: &FsEvent) -> Self {
    // The move's SOURCE coordinate, measured against the same root as the destination's:
    // the fs layer reports a `Moved` only when both endpoints lie under the watched root,
    // so this is a real location whenever the kind is a move.
    let move_from_location = event.kind().moved().map(|moved| moved.location().clone());
    let kind = match event.kind() {
      FsEventKind::Created => EventKind::Created,
      FsEventKind::Modified => EventKind::Modified,
      FsEventKind::Removed => EventKind::Removed,
      FsEventKind::Moved(moved) => EventKind::Moved {
        from: path_components(moved.from()),
      },
      FsEventKind::Rescan => EventKind::Rescan,
      // The fs enum is #[non_exhaustive]: an unknown future kind degrades to the
      // conservative re-read signal at this binding, exactly as fs itself folds
      // unknown proto kinds (the source-honesty contract).
      _ => EventKind::Rescan,
    };
    let source_event = Self::new(
      event.root(),
      path_components(event.path()),
      kind,
      event.location().clone(),
      event.epoch(),
      Some(event.change_id()),
    );
    // The class the fs layer PROVED, carried across as the same three-valued fact — an
    // unproven class stays unproven, never a stated `false` (see `with_is_dir`).
    let source_event = match event.is_dir() {
      Some(is_dir) => source_event.with_is_dir(is_dir),
      None => source_event,
    };
    match move_from_location {
      Some(location) => source_event.with_move_from_location(location),
      None => source_event,
    }
  }
}

/// Maps a raw `tributary-fs` watch-root error into the umbrella's neutral error
/// vocabulary — the error half of the fs-to-neutral binding (its event half is
/// [`SourceEvent::from_fs`]), and the one place the fs error enum crosses the seam.
///
/// Classification is honest-and-conservative, mirroring the source-honesty contract on
/// [`EventKind`]: each fs case maps to its neutral [`FaultKind`], an unknown future case
/// degrades to [`Other`](FaultKind::Other), and a closed watcher maps to the umbrella's
/// own [`WatchError::Closed`] (the uniform "the stack is closed" signal). The whole fs
/// error is always preserved in the fault's box, so [`WatchError::as_fs`] recovers full
/// fidelity.
fn watch_error_from_fs(err: WatchRootError) -> WatchError {
  let kind = match &err {
    WatchRootError::NotFound { .. } => FaultKind::NotFound,
    WatchRootError::NotADirectory { .. } => FaultKind::NotADirectory,
    WatchRootError::Overlaps { .. } => FaultKind::Conflict,
    WatchRootError::Source(source) => match source {
      SourceError::Unsupported => FaultKind::Unsupported,
      SourceError::InstanceLimit => FaultKind::Capacity,
      _ => FaultKind::Other,
    },
    // A retryable admission REFUSAL, not a fault: the watcher's teardown backlog is at its bound
    // and it declined to admit another native stream, leaving the caller's coverage untouched —
    // a source resource budget exhausted, which is exactly what [`FaultKind::Capacity`] names
    // (the instance limit above is the other one). Degrading it to `Other` destroyed the only
    // signal that separates "ask again shortly" from "this root is dead", and the umbrella's
    // failed-widen unwind reads that difference to decide whether to RETIRE established roots.
    // The sync seam already draws the same line (`SyncRootError::CleanupBacklog` → `Busy`).
    WatchRootError::CleanupBacklog => FaultKind::Capacity,
    // A CALLER-CONFIGURATION refusal, and deliberately the unclassified kind. The watcher
    // refused the per-root household before any coverage existed — a seat carrying more glob
    // patterns than it bounds — so nothing was watched, nothing was lost, and the fix is the
    // caller's own words rather than anything about the source. None of the classified kinds
    // says that: `Capacity` is the one kind the umbrella RETRIES, and re-offering a household
    // the watcher will refuse identically forever would spin; `Unsupported` is read as a verdict
    // on the platform, which a caller answers by abandoning watching altogether. `Other` keeps
    // the concrete `WatchRootError::InvalidOptions` (with the typed `OptionsError` behind it)
    // recoverable through `WatchError::as_fs`, which is exactly where the seat and its ceiling
    // are named. The arm is explicit so the classification is a decision, not the catch-all's
    // leftovers.
    WatchRootError::InvalidOptions(_) => FaultKind::Other,
    WatchRootError::Closed => return WatchError::Closed,
    _ => FaultKind::Other,
  };
  WatchError::source(SourceFault::new(kind).with_source(err))
}

/// Classifies a resolved `sync_root` result into what [`FsSource::begin_sync`] owes the caller —
/// the one arm of the seam that is NOT reached through [`sync_error_from_fs`]'s wildcard, and the
/// stage's single load-bearing production line.
///
/// [`Dominated`](SyncRootError::Dominated) is the ONE `sync_root` refusal that is not an error: a
/// coverage transition on the barrier's ground retired it before the marker could be installed,
/// and the retirement stood the covering `Rescan` for the ground this sync named — which is
/// exactly what `SyncOutcome::Dominated` promises a caller, so it is carried as the OUTCOME and
/// the caller is resolved at once. Every other refusal is delegated to [`sync_error_from_fs`]
/// unchanged, so the two classifications cannot drift apart.
///
/// FAIL-ON-REVERT: delete the `Dominated` arm (fold it into the delegation instead) and a barrier
/// that was MET reaches the caller as `sync_error_from_fs`'s wildcard —
/// `SyncError::CookieWrite(FaultKind::Other)`, a filesystem write failure for a write that never
/// happened, which is precisely the untrue and un-actionable outcome that function's own doc
/// says it avoids.
#[cfg(feature = "sync")]
fn begun_from_fs(error: SyncRootError) -> Result<Begun<OsString>, SyncError> {
  match error {
    SyncRootError::Dominated => Ok(Begun::Dominated),
    error => Err(sync_error_from_fs(error)),
  }
}

/// Classifies a refused sync-cookie write into the neutral barrier vocabulary — the third of
/// this binding's seam mappings, beside [`watch_error_from_fs`] and
/// [`replace_error_to_watch_error`], and standalone for the same reason they are: the
/// classification is the contract, so it is asserted directly rather than through a barrier that
/// has to be provoked.
///
/// The line it draws is between a barrier that FAILED and one that could never have been met:
///
/// - **the cookie directory is not covered** — outside the root, under a watcher exclusion, under
///   this root's own `prune` seat, or across a mount boundary anywhere on the chain from the
///   watched root down to the reserved cookie directory's own name. All four are refused before
///   any write, and all four mean the same thing to the
///   caller: a cookie written there would produce no event on this subscription's stream, so the
///   barrier would wait for something that cannot arrive. The glob-shaped one
///   ([`DirPruned`](SyncRootError::DirPruned)) and the mount-shaped one
///   ([`DirCrossesMount`](SyncRootError::DirCrossesMount)) are no different in kind — reported as
///   write failures they read as "your filesystem refused this", which is neither true nor
///   actionable.
/// - **transient** ([`Busy`](SyncError::Busy)) — a write already in flight for this root, or a
///   cookie-cleanup backlog. Nothing was written; ask again.
/// - **a genuine write failure**, carrying the concrete `io::Error` behind an honest
///   [`FaultKind`] (a read-only tree is `PermissionDenied`).
///
/// [`Dominated`](SyncRootError::Dominated) is deliberately absent: a barrier a coverage
/// transition retired is not a refused write but a met barrier, taken by [`begun_from_fs`] as
/// [`Begun::Dominated`] before this function is ever reached. Left to the wildcard it would
/// reach a caller as a write failure, which is both untrue and un-actionable — hence this note
/// rather than silence.
///
/// The fs error type is `#[non_exhaustive]`, and the wildcard is deliberately the FAILED-write
/// arm: a variant added later is a refused barrier until it is classified here, never a silent
/// success.
#[cfg(feature = "sync")]
fn sync_error_from_fs(error: SyncRootError) -> SyncError {
  match error {
    SyncRootError::UnknownRoot | SyncRootError::Retired => SyncError::Retired,
    // Five spellings of one fact: the marker's ground is not on this
    // subscription's stream. Three are configuration words — an exclusion, the
    // root's prune seat, and a `set_cover` that narrowed the root's per-directory
    // coverage past the directory. One is the TREE's: a mount standing anywhere
    // between the watched root and the reserved cookie directory's name, a
    // same-superblock bind mount included, which no crawl of the root descends
    // across. All are permanent for the request as issued, so none is the retryable
    // `Busy` their sibling `DirReplaced` is.
    SyncRootError::DirOutsideRoot { .. }
    | SyncRootError::DirExcluded { .. }
    | SyncRootError::DirCrossesMount { .. }
    | SyncRootError::DirPruned { .. }
    | SyncRootError::DirUncovered { .. } => SyncError::CookieDirUncovered,
    SyncRootError::Write { source, .. } => {
      let kind = match source.kind() {
        std::io::ErrorKind::NotFound => FaultKind::NotFound,
        std::io::ErrorKind::PermissionDenied => FaultKind::PermissionDenied,
        _ => FaultKind::Other,
      };
      SyncError::CookieWrite(SourceFault::new(kind).with_source(source))
    }
    // A second sync raced one already in flight for this root: no physical write happened, and it
    // is a transient, retryable refusal — surfaced as the dedicated `Busy` rather than a
    // write-failure the caller might read as terminal.
    SyncRootError::WriteInFlight => SyncError::Busy,
    // The root's cookie cleanup is backlogged (too many unremoved cookies —
    // a failing unlink the driver is retrying). No physical write happened;
    // it is transient and retryable, the same shape as `WriteInFlight`.
    SyncRootError::CleanupBacklog => SyncError::Busy,
    // The cookie directory was replaced between the admission and the write, so the barrier's
    // promise is about an object that is no longer there. Nothing was written and nothing about
    // the CALLER's request is wrong — the directory it named still exists and is still covered —
    // so this is neither a write failure nor an uncovered directory but the same transient,
    // retryable shape the two above have: a fresh sync is admitted for whatever now stands at
    // the name.
    SyncRootError::DirReplaced { .. } => SyncError::Busy,
    SyncRootError::Closed => SyncError::Closed,
    _ => SyncError::CookieWrite(SourceFault::new(FaultKind::Other)),
  }
}

/// Classifies a failed in-place root replacement into the neutral vocabulary.
/// Every variant leaves the caller's coverage exactly as it was, because
/// `replace_root` is atomic on failure. Most fall through to the umbrella's
/// release-and-rearm; the retryable refusals classified
/// [`Capacity`](FaultKind::Capacity) — the teardown backlog, and the
/// watch-instance ceiling a new stream hits — are triaged there instead and fail
/// the watch outright, because release-and-rearm would tear that untouched
/// coverage down and then ask the very budget that just refused to rebuild it.
/// Both of the layer's capacity refusals must be classified here, not just one:
/// the triage reads the KIND, so a refusal left as `Other` falls into exactly
/// the unwind it is supposed to prevent.
fn replace_error_to_watch_error(err: ReplaceRootError, root: &std::path::Path) -> WatchError {
  let kind = match err {
    ReplaceRootError::NotFound { .. } => FaultKind::NotFound,
    ReplaceRootError::NotADirectory { .. } => FaultKind::NotADirectory,
    ReplaceRootError::Overlaps { .. } => FaultKind::Conflict,
    // A live scope never swaps lowering profiles, and a root that died (or a
    // replace already in flight) is not something to retry in place — the
    // release-and-rearm fallback handles all of them.
    ReplaceRootError::BackendDiverged
    | ReplaceRootError::Retired
    | ReplaceRootError::UnknownRoot
    | ReplaceRootError::ReplaceInFlight => FaultKind::Unsupported,
    // The same reclassification the watch seam makes, and it is needed in BOTH: the widen tries
    // the in-place retarget FIRST, so a backlog refusal that arrives here is the one the umbrella
    // must recognize BEFORE it disarms anything. Left as `Other` it falls through to
    // release-and-rearm, which disarms the sole subsumed root and then re-arms it against the
    // very budget that just refused.
    ReplaceRootError::CleanupBacklog => FaultKind::Capacity,
    ReplaceRootError::Closed => return WatchError::Closed,
    ReplaceRootError::Source(source) => {
      // The retarget's OTHER capacity refusal, and the one the watch seam above has always
      // recognized: a make-before-break replacement STARTS a new native stream, so the per-user
      // watch-instance ceiling is refused right here rather than through `CleanupBacklog`.
      // Classifying it `Other` left the widen's in-place triage blind to the more common of the two
      // — the retarget fell through to release-and-rearm, which disarms the sole healthy root and
      // then asks that same exhausted ceiling for a fresh stream, which is exactly the retirement
      // of a healthy root the triage exists to prevent. Every other start failure stays `Other`: a
      // stream that could not be created or started is a persistent failure, not a budget.
      let kind = match source {
        SourceError::InstanceLimit => FaultKind::Capacity,
        _ => FaultKind::Other,
      };
      return WatchError::Source(SourceFault::new(kind).with_source(source));
    }
    _ => FaultKind::Other,
  };
  let _ = root;
  WatchError::Source(SourceFault::new(kind))
}

/// Rebuilds a filesystem path from key components — the reverse of
/// [`path_components`](crate::event::path_components), and the only key → path conversion
/// the fs binding performs. `[a, b, c]` becomes `a/b/c`; an absolute key round-trips
/// through its leading root component.
pub(super) fn key_to_path(key: &[OsString]) -> PathBuf {
  key.iter().collect()
}
