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
//! whole umbrella (subsumption, fan-out, epoch rebasing, backpressure, the sync barrier, the
//! wait-free [`WatchView`] value plane) is exercised over a genuinely generic key against a live
//! OS backend, exactly as a downstream consumer would wire it.
//!
//! Real-kernel timing is nondeterministic, so every assertion is convergence-style: wait
//! (bounded) until the expected fact is observed. The one place overflow must be *forced*
//! (backpressure) drives the producer strictly ahead of the consumer rather than sleeping.

// Drives a real kernel watch on a tokio runtime: off miri (which cannot execute the
// syscalls) and gated onto the platforms with a real backend (elsewhere `tributary-fs`
// compiles but arms fail at runtime).
#![cfg(all(
  feature = "tokio",
  not(miri),
  any(target_os = "macos", target_os = "linux", target_os = "windows")
))]

use std::{
  collections::{HashMap, HashSet, VecDeque},
  future::Future,
  num::NonZeroUsize,
  path::{Path, PathBuf},
  pin::pin,
  sync::atomic::{AtomicU32, Ordering},
  task::{Context, Poll, Waker},
  time::Duration,
};

use agnostic_lite::{RuntimeLite, tokio::TokioRuntime};
use futures_util::FutureExt;
use tempfile::TempDir;
use tributaries::{
  Armed, DebounceConfig, Epoch, Event, EventKind, FaultKind, Source, SourceEvent, SourceFault,
  Subscription, SyncError, SyncToken, Tributaries, TributariesOptions, WatchError, WatchOptions,
  WatchView,
};
// The fs types come from the `tributary-fs` DEV-dependency, not the umbrella: this
// suite is the custom-source proof, compiled and run with the umbrella's `fs` feature
// OFF (its test target requires only `tokio`), exactly as a downstream crate binding
// its own transport would depend on the stack.
use tributary_fs::{
  EventKind as FsEventKind, Interest as FsInterest, RootHandle, SyncRootDenied, SyncRootError,
  SyncTicket, WatchRootError, Watcher, WatcherOptions, is_sync_cookie_dir_name,
};

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
  /// Roots whose release was requested (via the synchronous `disarm`) but not yet applied to the
  /// `Watcher`, each paired with the released root's canonical `Comp` key captured at `disarm` time.
  /// `arm` applies these opportunistically (the oldest few, bounded, up front) and on demand (resolve
  /// the `Overlaps` the watcher NAMES, then retry) — bounded per-arm release work independent of queue
  /// depth. Mirrors the fs source's conflict-triggered release retry for a caller-supplied
  /// source.
  pending_releases: VecDeque<(RootHandle, Option<Vec<Comp>>)>,
  /// Mirror of `pending_releases` for O(1) `root_key` liveness answers: a requested release is
  /// logically dead immediately.
  pending_set: HashSet<RootHandle>,
  /// The in-flight barrier per root: the [`SyncToken`] that began it (the incarnation guard) and
  /// the watcher-minted [`SyncTicket`] that can cancel it. Recorded BEFORE `begin_sync` awaits, so
  /// a future dropped mid-write still leaves `cancel_sync` a precise address for a marker that may
  /// yet land — the fs binding's own arrangement, mirrored here.
  pending_syncs: HashMap<RootHandle, (SyncToken, SyncTicket)>,
}

/// Mirror of the fs source's [`OPPORTUNISTIC_RELEASE_HANDOFFS`](../src/source/fs/mod.rs): the oldest
/// few queued releases each `arm` applies up front (bounded, keeps clause 5 eventual).
const OPPORTUNISTIC_RELEASES: usize = 2;

/// Maps a raw fs watch-root error into the umbrella's neutral error vocabulary at this
/// binding — the error half of the source's fs-to-neutral map (its event half is the
/// kind map in `next`), exactly as a downstream custom source classifies its own
/// transport failures. Honest-and-conservative: the cases this source can hit map to
/// their neutral kinds, anything else degrades to `Other`, a closed watcher maps to the
/// umbrella's own `Closed`, and the whole fs error rides in the fault's box.
fn fs_fault(err: WatchRootError) -> WatchError {
  let kind = match &err {
    WatchRootError::NotFound { .. } => FaultKind::NotFound,
    WatchRootError::NotADirectory { .. } => FaultKind::NotADirectory,
    WatchRootError::Overlaps { .. } => FaultKind::Conflict,
    WatchRootError::Closed => return WatchError::Closed,
    _ => FaultKind::Other,
  };
  WatchError::source(SourceFault::new(kind).with_source(err))
}

impl<R: RuntimeLite> IndexerSource<R> {
  fn new(watcher: Watcher<R>, mounts: Vec<(Vec<Comp>, PathBuf)>) -> Self {
    Self {
      watcher,
      mounts,
      pending_releases: VecDeque::new(),
      pending_set: HashSet::new(),
      pending_syncs: HashMap::new(),
    }
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

/// The reserved marker namespace this binding mints in — its OWN, deliberately not the fs
/// binding's `.tributaries-sync-`: a custom source owns its marker namespace exactly as it owns
/// its path shapes, and the umbrella knows neither.
const MARKER_PREFIX: &str = ".indexer-sync-";

/// The nonce's rendered width: `{:016x}` on a `u64`, so exactly sixteen lowercase hex digits,
/// zero-padded — never fewer, never more, whatever the value.
const MARKER_NONCE_DIGITS: usize = 16;

/// Renders a barrier marker's leaf from the owner's token — the binding half of the
/// [`Source::begin_sync`] contract, and the ONE place this source turns a [`SyncToken`] into an
/// identity.
///
/// **All four fields are rendered, and the last one is the load-bearing one.** The umbrella
/// resolves a barrier by MATCHING the marker's key and nothing else, and `(instance, pid, seq)`
/// is fully computable from any marker already lying under the watched tree — so a rendering of
/// those three alone hands a co-user the NEXT marker's name, which is enough to create-and-remove
/// it ahead of time and leave a stale matching event that resolves the barrier before the
/// caller's own pre-call changes have drained. `nonce` is the one field an observer cannot
/// compute, so it is the one this identity cannot afford to drop.
///
/// [`a_marker_identity_changes_with_the_token_nonce`] holds this function to exactly that, by
/// decoding the rendered nonce field back out and requiring the whole word.
fn marker_leaf(token: SyncToken) -> String {
  format!(
    "{MARKER_PREFIX}{}-{}-{}-{:0width$x}",
    token.instance(),
    token.pid(),
    token.seq(),
    token.nonce(),
    width = MARKER_NONCE_DIGITS,
  )
}

/// Whether `leaf` is a marker [`marker_leaf`] minted: the reserved prefix, then three decimal
/// fields, then the sixteen-lowercase-hex nonce, and nothing after it.
///
/// The GRAMMAR is checked rather than the prefix alone, for the reason the fs binding gives:
/// suppression removes a change from every consumer stream, so a bare prefix test would swallow
/// any user file whose name merely begins with the reserved stem — silently, for the life of the
/// watch. This is the classifier half of [`marker_leaf`]; the two are changed together.
fn is_marker_leaf(leaf: &str) -> bool {
  let Some(rest) = leaf.strip_prefix(MARKER_PREFIX) else {
    return false;
  };
  let mut fields = rest.split('-');
  let (Some(instance), Some(pid), Some(seq), Some(nonce), None) = (
    fields.next(),
    fields.next(),
    fields.next(),
    fields.next(),
    fields.next(),
  ) else {
    return false;
  };
  [instance, pid, seq]
    .iter()
    .all(|field| !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit()))
    && nonce.len() == MARKER_NONCE_DIGITS
    && nonce
      .bytes()
      .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Reads a rendered marker identity's nonce back out as the `u64` that went in: the fourth
/// `-`-separated field after the reserved prefix, all sixteen hex digits of it.
///
/// This is [`marker_leaf`]'s exact inverse on that field, and the exactness is the whole value.
/// Comparing what it returns against the token's own [`nonce`](SyncToken::nonce) admits ONE
/// rendering and rejects every reduction of it — a truncation, a fold, a digest — because a
/// rendering that discards any bit decodes to a different word. Counting distinct identities over
/// a set of probe nonces cannot do that job: it asks only that the rendering be injective ON THAT
/// SET, which `nonce & 0xff` in the same sixteen zero-padded digits satisfies for any probes with
/// distinct low bytes, while leaving the next marker's name one of 256 guesses.
fn rendered_nonce(leaf: &str) -> Result<u64, String> {
  let Some(rest) = leaf.strip_prefix(MARKER_PREFIX) else {
    return Err(format!("{leaf:?} is not in the reserved marker namespace"));
  };
  let mut fields = rest.split('-');
  let (Some(_), Some(_), Some(_), Some(nonce), None) = (
    fields.next(),
    fields.next(),
    fields.next(),
    fields.next(),
    fields.next(),
  ) else {
    return Err(format!(
      "{leaf:?} does not render exactly four fields, so it carries no nonce field to decode"
    ));
  };
  if nonce.len() != MARKER_NONCE_DIGITS {
    return Err(format!(
      "{leaf:?} renders a {}-digit nonce field; a whole `u64` needs all {MARKER_NONCE_DIGITS}",
      nonce.len()
    ));
  }
  u64::from_str_radix(nonce, 16)
    .map_err(|e| format!("{leaf:?} nonce field {nonce:?} is not a hex `u64`: {e}"))
}

impl<R: RuntimeLite> Source<Comp> for IndexerSource<R> {
  type Handle = RootHandle;

  fn canonicalize_key(&self, key: &[Comp]) -> Result<Vec<Comp>, WatchError> {
    // The indexer coordinate is already canonical (a volume id + volume-relative `Seg`s, no
    // symlink/`..` to resolve), so canonicalization is the identity — mirroring any source whose
    // key space is canonical by construction.
    Ok(key.to_vec())
  }

  async fn arm(&mut self, key: &[Comp]) -> Result<Armed<Comp, RootHandle>, WatchError> {
    // Mirror the fs source's release application: (a) opportunistically unwatch the OLDEST few queued
    // releases up front (bounded per-arm cost, keeps clause 5 eventual), then (b)+(c) attempt the watch
    // and resolve on demand any `Overlaps` the watcher NAMES against a released-but-lingering root. The
    // watcher rejects by identity and names `existing` (a canonical PATH), so reverse it into the
    // `Comp` key space to find the EXACT-matching pending entry, unwatch exactly it, and retry. Retry
    // is a structural progress bound, not a fixed cap: each retry strictly shrinks the
    // pending queue, so it terminates in ≤ pending-queue-length retries with no arbitrary ceiling; a
    // rejection naming no pending root (a genuine live conflict) surfaces the overlap immediately (no
    // index-0 fallback masking a real conflict by unwatching an unrelated pending root).
    for _ in 0..OPPORTUNISTIC_RELEASES {
      let Some((released, _)) = self.pending_releases.pop_front() else {
        break;
      };
      let _ = self.watcher.unwatch(released).await;
      self.pending_set.remove(&released);
    }
    // A well-formed watch always resolves under a registered mount.
    let path = self
      .key_to_path(key)
      .expect("indexer source: every armed key lies under a registered mount");
    #[cfg(debug_assertions)]
    let initial_pending = self.pending_releases.len();
    #[cfg(debug_assertions)]
    let mut iterations = 0usize;
    let handle = loop {
      #[cfg(debug_assertions)]
      {
        iterations += 1;
        debug_assert!(
          iterations <= initial_pending + 1,
          "IndexerSource::arm conflict-retry exceeded pending+1 iterations — pending must strictly \
           shrink each retry (structural progress bound)"
        );
      }
      match self.watcher.watch(path.clone(), FsInterest::all()).await {
        Ok(handle) => break handle,
        Err(WatchRootError::Overlaps {
          path: rejected,
          existing,
        }) => {
          // Continue ONLY while the named conflict EXACT-matches a pending entry; otherwise surface it.
          let existing_key = self.path_to_key(&existing);
          let Some(index) = self.pending_releases.iter().position(|(_, stored)| {
            existing_key
              .as_deref()
              .is_some_and(|ek| stored.as_deref() == Some(ek))
          }) else {
            return Err(fs_fault(WatchRootError::Overlaps {
              path: rejected,
              existing,
            }));
          };
          let (released, _) = self
            .pending_releases
            .remove(index)
            .expect("index in bounds");
          let _ = self.watcher.unwatch(released).await;
          self.pending_set.remove(&released);
        }
        Err(err) => return Err(fs_fault(err)),
      }
    };
    // Adopt the filesystem-authoritative canonical path as the committed key (design §4):
    // events arrive in canonical coordinates, so the index must key on them.
    let canonical_key = self
      .watcher
      .root_path(handle)
      .and_then(|path| self.path_to_key(&path))
      .unwrap_or_else(|| key.to_vec());
    Ok(Armed::new(handle, canonical_key))
  }

  fn disarm(&mut self, handle: RootHandle) {
    // Synchronous, non-blocking release REQUEST (mirroring the fs source): the watcher's `unwatch`
    // awaits a bounded ack, so queue the teardown — paired with the released root's canonical `Comp`
    // key captured NOW from the live registry (independent of `pending_set`), so a later `arm` can
    // match this entry against the conflict the watcher NAMES and apply exactly it (contract clause 2)
    // — and mark the handle logically dead at once. Applied opportunistically at a
    // subsequent `arm`, on demand when it blocks one, or at `Drop`. Idempotent by the set.
    if self.pending_set.insert(handle) {
      let key = self
        .watcher
        .root_path(handle)
        .and_then(|path| self.path_to_key(&path));
      self.pending_releases.push_back((handle, key));
    }
  }

  /// Conforming no-op `Ok`: this source arms whole subtrees and its [`set_cover`](Source::set_cover)
  /// keeps the default no-op, so its coverage never narrows below a root and `grow` has nothing to
  /// restore — every `retained` key already lies inside a live root's whole-subtree coverage
  /// (contract clause 4: a no-op conforms exactly for a source whose coverage never narrows).
  async fn grow(&mut self, handle: RootHandle, retained: &[Vec<Comp>]) -> Result<(), WatchError> {
    let _ = (handle, retained);
    Ok(())
  }

  async fn next(&mut self) -> Option<SourceEvent<Comp, RootHandle>> {
    loop {
      let raw = self.watcher.next().await?;
      // Reverse the raw canonical path back into the key space; a change outside every mount
      // (never a watched root's) is skipped rather than mis-keyed.
      let Some(key) = self.path_to_key(raw.path()) else {
        continue;
      };
      // The fs-to-neutral map at this binding, per the source-honesty contract: the four
      // single-endpoint kinds map one-to-one; a paired rename maps to a whole `Moved` only
      // when its source path ALSO reverses into the key space. A move whose source lies
      // outside every mount is outside the key space entirely — no subscriber could ever
      // cover that endpoint — so the honest, whole mapping is its move-in half alone: a
      // `Created` at the destination key (never a half-mapped `Moved`). An unknown future
      // fs kind folds to the conservative `Rescan`.
      let kind = match raw.kind() {
        FsEventKind::Created => EventKind::Created,
        FsEventKind::Modified => EventKind::Modified,
        FsEventKind::Removed => EventKind::Removed,
        FsEventKind::Moved(moved) => match self.path_to_key(moved.from()) {
          Some(from) => EventKind::Moved { from },
          None => EventKind::Created,
        },
        FsEventKind::Rescan => EventKind::Rescan,
        _ => EventKind::Rescan,
      };
      return Some(SourceEvent::new(
        raw.root(),
        key,
        kind,
        raw.location().clone(),
        raw.epoch(),
        Some(raw.change_id()),
      ));
    }
  }

  fn root_key(&self, handle: RootHandle) -> Option<Vec<Comp>> {
    // A requested release is logically dead immediately (disarm contract clause 3), even while its
    // transport teardown is still queued.
    if self.pending_set.contains(&handle) {
      return None;
    }
    // `root_path` reads the live-root registry synchronously and answers `None` for a
    // torn-down handle, so a terminal `Rescan` reports `None` here — the dead/retired signal
    // `retire_if_dead` classifies on.
    self
      .watcher
      .root_path(handle)
      .and_then(|path| self.path_to_key(&path))
  }

  /// Places the barrier marker, resolving at WRITE-complete (never at observe — the marker's own
  /// event arrives through the [`next`](Source::next) pump the umbrella would otherwise be
  /// blocking), and returns the key it landed at.
  ///
  /// The identity comes from [`marker_leaf`], which renders the WHOLE token — nonce included, as
  /// the seam requires. The lower watcher places the file inside its own per-root cookie
  /// directory, so the returned key is `[Volume(v), Seg(<cookie dir>), Seg(<marker leaf>)]`, and
  /// [`is_sync_artifact`](Source::is_sync_artifact) below answers `true` for it — without that the
  /// umbrella would never classify the marker's event and the barrier could not resolve at all.
  async fn begin_sync(
    &mut self,
    handle: RootHandle,
    dir_key: &[Comp],
    token: SyncToken,
  ) -> Result<Vec<Comp>, SyncError> {
    let Some(dir) = self.key_to_path(dir_key) else {
      return Err(SyncError::CookieDirUncovered);
    };
    // Mint the cancel address and record it BEFORE the await: a future dropped mid-write (the
    // caller timed out, or a close won the umbrella's race) deliberately leaves this entry for
    // `cancel_sync` to consume, because the umbrella never learned the marker's key.
    let (admission, ticket) = self.watcher.mint_sync_ticket();
    self.pending_syncs.insert(handle, (token, ticket));
    let placed = self
      .watcher
      .sync_root(handle, dir, marker_leaf(token), admission)
      .await;
    // A NORMAL return (either way) means the write resolved, so the in-flight entry goes here;
    // only the dropped-future path above leaves it behind.
    self.pending_syncs.remove(&handle);
    match placed {
      Ok(path) => self.path_to_key(&path).ok_or(SyncError::CookieDirUncovered),
      // The fs-to-neutral map at this binding, the sync half of `fs_fault`: honest and
      // conservative, with a refusal this source cannot classify degrading to a write failure
      // rather than to a silent success.
      Err(SyncRootDenied { error, .. }) => Err(match error {
        SyncRootError::UnknownRoot | SyncRootError::Retired => SyncError::Retired,
        SyncRootError::DirOutsideRoot { .. } => SyncError::CookieDirUncovered,
        // No physical write happened and both are retryable, so they are the dedicated
        // transient refusal rather than a write failure a caller might read as terminal.
        SyncRootError::WriteInFlight | SyncRootError::CleanupBacklog => SyncError::Busy,
        SyncRootError::Closed => SyncError::Closed,
        _ => SyncError::CookieWrite(SourceFault::new(FaultKind::Other)),
      }),
    }
  }

  /// Reaps a marker this binding placed — synchronous, non-blocking, fire-and-forget. The lower
  /// watcher owns every cookie it wrote and unlinks it at teardown regardless, so a reap that
  /// arrives late (or to an already-closed watcher) leaks nothing.
  fn end_sync(&mut self, _handle: RootHandle, cookie_key: &[Comp]) {
    if let Some(path) = self.key_to_path(cookie_key) {
      self.watcher.request_remove_cookie(path);
    }
  }

  /// Abandons an in-flight barrier the umbrella gave up on before it learned the marker's key.
  ///
  /// The recorded [`SyncToken`] is the incarnation guard: a cancel whose token does not match the
  /// stored one is stale (a later incarnation superseded it), so the entry is consumed and the
  /// cancel issued ONLY on a match, leaving a live successor's entry intact for its own cancel.
  fn cancel_sync(&mut self, handle: RootHandle, token: SyncToken) {
    if let Some(&(stored, ticket)) = self.pending_syncs.get(&handle)
      && stored == token
    {
      self.pending_syncs.remove(&handle);
      self.watcher.request_cancel_sync(ticket);
    }
  }

  /// Whether `key` names an artifact of the barrier machinery — the reserved namespace the
  /// umbrella suppresses from every consumer stream and resolves pending barriers on.
  ///
  /// Two grounds, mirroring the fs binding's: the leaf is a marker [`marker_leaf`] minted, or the
  /// leaf is the lower watcher's own per-root cookie DIRECTORY, whose create is this binding's
  /// artifact and never a user change. Neither reads any deeper component, so a user file merely
  /// living under an ancestor that shares the stem stays a user change.
  fn is_sync_artifact(&self, key: &[Comp]) -> bool {
    let Some(Comp::Seg(leaf)) = key.last() else {
      return false;
    };
    is_marker_leaf(leaf) || is_sync_cookie_dir_name(leaf)
  }
}

/// The generic driver instantiated at the indexer coordinate: custom key `Comp`, caller
/// value `Loc`, tokio runtime, fs [`RootHandle`] (spelled explicitly — the umbrella's
/// generic struct carries no fs-flavored default for `H`).
type Indexer = Tributaries<Comp, Loc, TokioRuntime, RootHandle>;

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
async fn settle_delivery_under(w: &mut Indexer, dir: &Path, dir_key: &[Comp]) {
  let settled = tokio::time::timeout(DEADLINE, async {
    let mut attempt = 0u32;
    loop {
      let name = format!("settle-{attempt}.probe");
      attempt += 1;
      let probe_key = key(dir_key, &[name.as_str()]);
      std::fs::write(dir.join(&name), b"settle").expect("write the settle probe");
      let seen = tokio::time::timeout(SETTLE_STEP, async {
        while let Some(event) = w.next().await {
          if !event.is_rescan() && event.reaches(&probe_key) {
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
    .watch(sub_key.clone(), Loc { id: 7 }, WatchOptions::new())
    .await
    .expect("watch sub");
  let _other = w
    .watch(other_key.clone(), Loc { id: 9 }, WatchOptions::new())
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
    .watch(deep_key.clone(), Loc { id: 1 }, WatchOptions::new())
    .await
    .expect("watch deep");
  assert!(view.contains(&deep_key), "the deep dir is an exact root");
  assert_eq!(view.len(), 1, "one kernel root so far");

  // Watch its ANCESTOR — a widen. The layer below rejects an overlapping root (`Overlaps`);
  // this succeeds because the widen disarms the subsumed deep root before arming the wider
  // one, folding the descendant onto it.
  let anc = w
    .watch(anc_key.clone(), Loc { id: 2 }, WatchOptions::new())
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
  // subscription and the wider ancestor subscription, through the one widened root. Settle
  // the widened root's coverage of the (pre-existing) deep dir first, and demand GENUINE
  // events: the widen's own registration closes its bootstrap window with a `Rescan` at
  // `/a`, which reaches every key below it — so `reaches` alone would retire both
  // subscriptions on a re-enumeration instruction, with no routing exercised at all.
  settle_delivery_under(&mut w, &deep_dir, &key(&volume, &["a", "b", "c"])).await;
  let file_key = key(&volume, &["a", "b", "c", "probe.txt"]);
  std::fs::write(deep_dir.join("probe.txt"), b"x").expect("write probe");
  assert!(
    wait_until_all(&mut w, &[deep, anc], |e| !e.is_rescan()
      && e.reaches(&file_key))
    .await,
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
    .watch(np_key.clone(), Loc { id: 1 }, WatchOptions::new())
    .await
    .expect("watch np");
  let child_sub = w
    .watch(child_key.clone(), Loc { id: 2 }, WatchOptions::new())
    .await
    .expect("watch child (covered)");
  let other_sub = w
    .watch(other_key.clone(), Loc { id: 3 }, WatchOptions::new())
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
  //
  // Both probe directories pre-exist their registration, so both are settled first and both
  // positive halves demand a GENUINE (non-`Rescan`) event. Each registration closes its
  // bootstrap window with a `Rescan` at its own root, and a root `Rescan` reaches every key
  // below it — so `reaches` alone retires all three subscriptions on re-enumeration
  // instructions, proving neither the fan-out nor other_sub's liveness bound. The exclusion
  // assertion is deliberately left exactly as it was: it must fire on `Rescan`s too, and it
  // cannot be tripped by one, since `other` is not an ancestor of `np/child/probe.txt` and a
  // `Rescan` only reaches keys at or below its own.
  let probe_key = key(&volume, &["np", "child", "probe.txt"]);
  let other_probe_key = key(&volume, &["other", "probe.txt"]);
  settle_delivery_under(&mut w, &np_child, &child_key).await;
  settle_delivery_under(&mut w, &other_dir, &other_key).await;
  std::fs::write(np_child.join("probe.txt"), b"x").expect("write np/child probe");
  std::fs::write(other_dir.join("probe.txt"), b"x").expect("write other probe");
  assert!(
    wait_until_all(&mut w, &[np_sub, child_sub, other_sub], |e| {
      assert!(
        !(e.subscription() == other_sub && e.reaches(&probe_key)),
        "the disjoint OTHER subscription must never receive the np/child change"
      );
      if e.subscription() == other_sub {
        // other_sub's liveness bound: it DOES receive the change under its own key.
        !e.is_rescan() && e.reaches(&other_probe_key)
      } else {
        // np_sub / child_sub: the fan-out of the one np/child change to every covering sub.
        !e.is_rescan() && e.reaches(&probe_key)
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
    .watch(key(&volume, &[]), Loc { id: 1 }, WatchOptions::new())
    .await
    .expect("watch the volume root");

  let busy_key = key(&volume, &["busy.txt"]);
  for i in 0..20u32 {
    std::fs::write(root.join("busy.txt"), i.to_le_bytes()).expect("burst write");
  }

  // The coalesced settle still delivers something covering the file (its net effect emits).
  assert!(
    wait_for(&mut w, |e| e.subscription() == sub && e.reaches(&busy_key))
      .await
      .is_some(),
    "the debounced burst collapses but its settled effect is still delivered"
  );

  // After the settle window, further events covering the file are bounded well below the 20
  // raw writes — the burst coalesced rather than fanning into a per-write storm.
  let mut extra = 0u32;
  let _ = tokio::time::timeout(cfg.quiet_window() * 3, async {
    while let Some(event) = w.next().await {
      if event.subscription() == sub && event.reaches(&busy_key) {
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
/// stream already advanced — is delivered a **dominating** `Rescan` obliging re-enumeration
/// of its own key, whose epoch strictly dominates every event delivered to it before the
/// widen.
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
    .watch(child_key.clone(), Loc { id: 1 }, WatchOptions::new())
    .await
    .expect("watch child");

  // Advance the child's stream first, so the re-point Rescan has a prior stream to dominate.
  let seed_key = key(&volume, &["proj", "child", "seed.txt"]);
  std::fs::write(child.join("seed.txt"), b"x").expect("write seed");
  let seed = wait_for(&mut w, |e| {
    e.subscription() == child_sub && e.reaches(&seed_key)
  })
  .await
  .expect("the child sees its seed change");

  // Widen: watch the ancestor. The child is re-pointed onto the wider root and owed a
  // dominating Rescan across the coverage re-point.
  let _anc = w
    .watch(anc_key.clone(), Loc { id: 2 }, WatchOptions::new())
    .await
    .expect("watch ancestor widens");
  let rescan = wait_for(&mut w, |e| {
    e.subscription() == child_sub && e.is_rescan() && e.reaches(&child_key)
  })
  .await
  .expect("the widen delivers the child a Rescan obliging re-enumeration of its key");

  // A located rescan at a STRICT ancestor is clamped to the receiving subscription's
  // own key: the loss covers everything that subscription owns and nothing above it
  // is the subscription's to re-read, so the clamped key is the widest honest
  // instruction. Naming the widened root would order this subscriber to re-enumerate
  // a root it never subscribed to.
  assert_eq!(
    rescan.key(),
    child_key.as_slice(),
    "the Rescan is clamped to the subscription's own key, never the wider root it never watched"
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
    let mut fut = pin!(w.watch(orphan_key.clone(), Loc { id: 99 }, WatchOptions::new()));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
      matches!(fut.as_mut().poll(&mut cx), Poll::Pending),
      "the watch parks on its reply after enqueuing the command"
    );
  }

  // FIFO barrier: a later awaited watch is processed strictly after the orphan command, so
  // once it returns the orphan has been committed-then-reconciled-away.
  let _live = w
    .watch(live_key.clone(), Loc { id: 1 }, WatchOptions::new())
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
    .watch(key_d.clone(), Loc { id: 1 }, WatchOptions::new())
    .await
    .expect("watch survives a non-last clone drop (actor alive)");

  w.close().await.expect("close returns Ok");

  // Teardown reached the DATA plane: the retained clone's stream ENDS — after any
  // owed buffered deliveries drain first (close delivers owed debt before the end,
  // so a straggler event ahead of the `None` is contractual, not a failure).
  assert!(
    tokio::time::timeout(DEADLINE, async { while reader.next().await.is_some() {} })
      .await
      .is_ok(),
    "the event stream ends once the actor tore down (close teardown)"
  );
  // Teardown reached the CONTROL plane: a further command errors (owner gone).
  assert!(
    reader
      .watch(key_d.clone(), Loc { id: 2 }, WatchOptions::new())
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
    .watch(key(&volume, &[]), Loc { id: 1 }, WatchOptions::new())
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
    .watch(root_key.clone(), Loc { id: 1 }, WatchOptions::new())
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
    .watch(watched_key.clone(), Loc { id: 1 }, WatchOptions::new())
    .await
    .expect("watch the subdir root");

  // Delete the watched root: its handle is torn down and a terminal signal surfaces.
  std::fs::remove_dir_all(&watched).expect("delete the watched root");
  assert!(
    wait_for(&mut w, |e| e.subscription() == sub
      && (e.is_rescan()
        || (e.kind().is_removed() && e.reaches(&watched_key))))
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
    .watch(watched_key.clone(), Loc { id: 2 }, WatchOptions::new())
    .await
    .expect("re-watch re-arms a fresh root");
  assert_ne!(sub, second, "the re-watch mints a new subscription");

  let probe_key = key(&volume, &["watched", "after.txt"]);
  std::fs::write(watched.join("after.txt"), b"x").expect("write under the recreated root");
  assert!(
    wait_for(&mut w, |e| e.subscription() == second
      && e.reaches(&probe_key))
    .await
    .is_some(),
    "a write under the recreated, re-armed root reaches the new subscription"
  );

  w.close().await.expect("close");
}

/// (j.1) The [`Source::begin_sync`] contract's UNPREDICTABILITY clause, held against this
/// suite's own binding: the rendered marker identity must carry the token's
/// [`nonce`](SyncToken::nonce) — the WHOLE word, and no fewer bits of it.
///
/// This is the cell a downstream binding fails by following the seam's prose and rendering the
/// identity fields it can name — `(instance, pid, seq)` — while ignoring the one it cannot
/// compute. Such a binding compiles, satisfies every other clause of the seam, suppresses its own
/// markers correctly, and still breaks the barrier: the umbrella resolves a barrier by MATCHING
/// the marker's key and nothing else, so a co-user under the watched tree can read one marker,
/// compute the NEXT one, create-and-remove it ahead of time, and leave a stale matching event
/// that resolves a later barrier before the caller's own pre-call changes have drained.
///
/// # Why the assertion is a decode, not a count
///
/// The load-bearing check here is [`rendered_nonce`]: the identity's nonce field is read back out
/// and must EQUAL the `u64` that went in. That equality is what "carries the whole word" means
/// operationally, and only an exact decode means it. A count of distinct identities over a set of
/// probe nonces — which this cell used to make, over 256 probes — proves nothing of the kind: it
/// asks only that the rendering be injective ON THOSE PROBES. A renderer emitting `nonce & 0xff`
/// in the same sixteen zero-padded digits is injective on any 256 probes with distinct low bytes,
/// keeps the mint/classify grammars agreeing, and passes the barrier's end-to-end cell (which has
/// no stale-marker adversary) — while leaving only 256 possible names for the next predictable
/// `(instance, pid, seq)`, few enough for a co-user to pre-create and remove every one. Picking
/// different probes only moves that blind spot; decoding removes it, for every reduction at once.
///
/// Dropping `token.nonce()` from [`marker_leaf`], or narrowing it to any part of the word, fails
/// this cell — which is the whole point: no signature checks the rendering, so a test has to.
#[test]
fn a_marker_identity_changes_with_the_token_nonce() {
  // Nonces the reductions differ on: both extremes, a pair agreeing in the low byte and nowhere
  // else, a pair agreeing in the high half, one carrying only the top bit, and one distinct in
  // every byte. The decode below is exact, so this list documents the failure modes rather than
  // carrying the proof — which is why widening or narrowing it cannot weaken the cell.
  const NONCES: [u64; 8] = [
    0,
    u64::MAX,
    0x0123_4567_89ab_cdef,
    0xfedc_ba98_7654_3210,
    0x0000_0000_0000_00ff,
    0xffff_ffff_ffff_ff00,
    0x8000_0000_0000_0000,
    0x0102_0304_0506_0708,
  ];

  for nonce in NONCES {
    let leaf = marker_leaf(SyncToken::new(9, 4242, 7, nonce));

    // THE assertion: the whole word reads back out of the identity, so the identity carries the
    // whole word. Any rendering that loses a bit of it — a truncation, a fold, a digest —
    // decodes to something else and fails right here.
    assert_eq!(
      rendered_nonce(&leaf),
      Ok(nonce),
      "the marker identity {leaf:?} does not carry SyncToken::nonce {nonce:#018x} intact: a \
       rendering that drops the word, or keeps only part of it, narrows the next marker's name \
       to a guessable set, and the barrier's unpredictability rests on that word alone"
    );

    // The grammar this binding SUPPRESSES on is the grammar it MINTS. Drift between the two would
    // strand a marker's own event outside the reserved namespace, where nothing resolves the
    // barrier it belongs to and nothing hides it from consumers.
    assert!(
      is_marker_leaf(&leaf),
      "the binding minted a marker its own is_sync_artifact grammar does not recognize: {leaf:?}"
    );
  }

  // Two barriers identical in every field a marker already lying under the tree would reveal,
  // differing only in the field an observer cannot compute, must not render alike. The decode
  // above already implies this; it is kept because it names the failure a nonce-blind binding
  // actually produces.
  let observed = SyncToken::new(9, 4242, 7, 0x0123_4567_89ab_cdef);
  let next = SyncToken::new(9, 4242, 7, 0xfedc_ba98_7654_3210);
  assert_ne!(
    marker_leaf(observed),
    marker_leaf(next),
    "two barriers differing ONLY in nonce rendered the same marker identity: this binding \
     ignores SyncToken::nonce, so the next marker's name is computable from a previous one"
  );
}

/// (j.2) The barrier end to end over this custom binding: once `sync` resolves, every change made
/// BEFORE the call is already deliverable — a plain drain finds them all, with no sleeping and no
/// polling — and no barrier artifact ever surfaces on a consumer stream.
///
/// It is what makes (j.1) a claim about the LIVE path rather than about a decorative helper: the
/// identity this barrier resolves on is the one [`marker_leaf`] rendered, classified by the
/// [`is_marker_leaf`] grammar, through the same [`Source`] seam a downstream consumer implements.
///
/// It does NOT test unpredictability: there is no co-user here racing a predicted marker, so this
/// cell resolves the same way over a rendering that keeps only part of the nonce. That property is
/// (j.1)'s alone, and (j.1) holds it by decode rather than by observing a barrier fooled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_barrier_resolves_over_the_custom_binding() {
  let Rig {
    _dir,
    root,
    volume,
    mut w,
  } = rig("sync", 10, TributariesOptions::new());
  let sub = w
    .watch(volume.clone(), Loc { id: 1 }, WatchOptions::new())
    .await
    .expect("watch the volume root");

  // The changes the barrier must account for — made BEFORE the sync call.
  for i in 0..8 {
    std::fs::write(root.join(format!("pre-{i}.txt")), b"x").expect("write a pre-call change");
  }

  let outcome = w
    .sync(sub, DEADLINE)
    .await
    .expect("the barrier is established over the custom binding");
  assert!(
    outcome.is_delivered() || outcome.is_dominated(),
    "the barrier is met by delivery or by domination: {outcome:?}"
  );

  // Now DRAIN what is already deliverable — no sleeps, no retries. Every pre-sync write must be
  // accounted for: named directly, or covered by a `Rescan` that obliges re-enumeration.
  let mut seen: HashSet<String> = HashSet::new();
  let mut rescanned = false;
  while let Some(event) = w.next().now_or_never().flatten() {
    if event.kind().is_rescan() {
      rescanned = true;
    }
    if let Some(Comp::Seg(leaf)) = event.key().last() {
      assert!(
        !is_marker_leaf(leaf) && !is_sync_cookie_dir_name(leaf),
        "a barrier artifact must NEVER surface on a consumer stream: {leaf}"
      );
      seen.insert(leaf.clone());
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
