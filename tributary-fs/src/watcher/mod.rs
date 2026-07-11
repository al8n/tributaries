//! The consumer-facing watcher.

use std::{
  collections::BTreeMap,
  marker::PhantomData,
  path::{Path, PathBuf},
  pin::Pin,
  sync::{
    Arc, PoisonError, RwLock,
    atomic::{AtomicU64, Ordering},
  },
  task::{Context, Poll},
};

use agnostic_lite::RuntimeLite;
use futures_core::Stream;
use tributary_proto::{Change, Interest, ScopeId};

use crate::{
  driver::{Command, DriverConfig, RealFs, ScopeRegistry, run},
  error::{BuildError, CloseError, UnwatchError, WatchRootError},
  event::Event,
  options::WatcherOptions,
  os::{BackendKind, BackendStats, RootIdentity, SourceError},
};

#[cfg(all(test, feature = "tokio"))]
mod tests;

// Real-kernel regression suite for the set-cover pair: the in-place prune/grow
// reconciles end to end, plus the effect-completion fence's acceptance test
// (`set_cover_ack_resolves_at_watch_live`). In-crate rather than an external
// integration binary so it runs inside the parallel lib-test harness with
// object-scoped watch-descriptor assertions (see the module docs). not(miri):
// drives real inotify syscalls and a tokio runtime.
#[cfg(all(test, target_os = "linux", feature = "tokio", not(miri)))]
mod linux_kernel_tests;

/// Mints one id per [`Watcher`], branding its handles (see [`RootHandle`]).
static WATCHER_INSTANCES: AtomicU64 = AtomicU64::new(1);

/// An opaque handle to one watched root of a [`Watcher`].
///
/// A handle is a capability scoped to the watcher that issued it: scope ids
/// are minted per driver instance, so two watchers routinely share the same
/// numeric scope. Every handle therefore also carries its watcher's instance
/// brand, and using it with any other watcher is rejected
/// ([`UnwatchError::UnknownRoot`] / a `None` path) instead of silently
/// addressing that watcher's unrelated root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootHandle {
  instance: u64,
  scope: ScopeId,
}

impl RootHandle {
  /// Wraps a driver-minted scope under the issuing watcher's brand.
  pub(crate) const fn new(instance: u64, scope: ScopeId) -> Self {
    Self { instance, scope }
  }

  /// The underlying scope id (the value [`Event`]s of this root carry).
  #[inline]
  pub const fn scope(&self) -> ScopeId {
    self.scope
  }

  /// The issuing watcher's brand.
  pub(crate) const fn instance(&self) -> u64 {
    self.instance
  }
}

/// How an awaited coverage reconcile ([`Watcher::set_cover`]) completed.
///
/// The acknowledgement is an **effect-completion fence**: for a reconcile that
/// actually ran, it resolves when the reconcile has *settled* — every re-arm
/// the grow half started has quiesced — never when its effects were merely
/// queued. The settled verdicts ([`Applied`](Self::Applied) /
/// [`Degraded`](Self::Degraded)) are constructed only by that settlement, so
/// no code path can resolve them early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoverOutcome {
  /// The reconcile settled **clean**: every watch the grow half re-armed is
  /// live and no coverage loss was signaled inside the window — writes under
  /// the retained cover from the moment the ack resolves are delivered. A
  /// caller that shrank coverage, grew it back, and writes immediately on
  /// this resolution races nothing.
  Applied,
  /// The reconcile settled, but coverage loss was signaled inside the window
  /// (a failed re-arm, an unreadable re-arm read, an overflow, or the root
  /// tearing down mid-fence): coverage may be partial, and the covering
  /// [`Rescan`](crate::EventKind::Rescan) — already delivered in-band —
  /// dominates the gap. Re-issuing the same cover re-attempts exactly the
  /// coverage the loss may have cost.
  Degraded,
  /// The root is backed by a kernel-recursive backend (fanotify / FSEvents),
  /// whose single whole-subtree stream never narrowed: there is nothing to
  /// prune or re-arm, ever, for this root. Reported explicitly — "coverage
  /// was never reduced" — rather than as a hollow `Applied`;
  /// [`BackendKind::is_kernel_recursive`](crate::BackendKind::is_kernel_recursive)
  /// on [`Watcher::backend_of`]'s report lets a caller skip the round-trip
  /// a priori.
  Recursive,
  /// No reconcile ran; the payload says why. Prior coverage — and the record
  /// the next reconcile's grow is computed against — is untouched.
  Skipped(SkipReason),
}

impl CoverOutcome {
  /// The stable snake_case name of this outcome (independent of any carried
  /// data).
  #[inline]
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Applied => "applied",
      Self::Degraded => "degraded",
      Self::Recursive => "recursive",
      Self::Skipped(_) => "skipped",
    }
  }

  /// Whether this is [`Applied`](Self::Applied).
  #[inline]
  pub const fn is_applied(&self) -> bool {
    matches!(self, Self::Applied)
  }

  /// Whether this is [`Degraded`](Self::Degraded).
  #[inline]
  pub const fn is_degraded(&self) -> bool {
    matches!(self, Self::Degraded)
  }

  /// Whether this is [`Recursive`](Self::Recursive).
  #[inline]
  pub const fn is_recursive(&self) -> bool {
    matches!(self, Self::Recursive)
  }

  /// Whether this is [`Skipped`](Self::Skipped).
  #[inline]
  pub const fn is_skipped(&self) -> bool {
    matches!(self, Self::Skipped(_))
  }

  /// The skip reason, if this is [`Skipped`](Self::Skipped).
  #[inline]
  pub const fn skip_reason(&self) -> Option<SkipReason> {
    match self {
      Self::Skipped(reason) => Some(*reason),
      _ => None,
    }
  }
}

impl core::fmt::Display for CoverOutcome {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// Why a [`Watcher::set_cover`] reconcile was [`Skipped`](CoverOutcome::Skipped):
/// the driver refused to run it, and prior coverage is untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
  /// The handle does not name a live root of the driver: never watched,
  /// already unwatched, or torn down (root death, stream fatal) concurrently
  /// with this call — indistinguishable from a root that died right after the
  /// call was made, exactly like [`Watcher::unwatch`]'s unknown-root answer.
  UnknownRoot,
  /// The root is not publicly live yet: between a descending root's stream
  /// spawn and the root arm that commits its registration there is no
  /// coverage to reconcile, and a grow in that window would convert the
  /// root's cold discovery into a `Created`-suppressing re-arm. Re-issue once
  /// [`Watcher::watch`] has resolved.
  NotLive,
  /// The retained cover was refused: empty, or entirely outside the live root
  /// (a typo, a relative path, a stale path) — acting on either would prune
  /// the whole scope's coverage.
  RefusedCover,
}

impl SkipReason {
  /// The stable snake_case name of this reason.
  #[inline]
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::UnknownRoot => "unknown_root",
      Self::NotLive => "not_live",
      Self::RefusedCover => "refused_cover",
    }
  }

  /// Whether this is [`UnknownRoot`](Self::UnknownRoot).
  #[inline]
  pub const fn is_unknown_root(&self) -> bool {
    matches!(self, Self::UnknownRoot)
  }

  /// Whether this is [`NotLive`](Self::NotLive).
  #[inline]
  pub const fn is_not_live(&self) -> bool {
    matches!(self, Self::NotLive)
  }

  /// Whether this is [`RefusedCover`](Self::RefusedCover).
  #[inline]
  pub const fn is_refused_cover(&self) -> bool {
    matches!(self, Self::RefusedCover)
  }
}

impl core::fmt::Display for SkipReason {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// One live root's registry record: its canonical path plus the object
/// identities disjointness is decided on (the root's own and every strict
/// ancestor's), captured at the spawn barrier, plus the backend the barrier
/// selected (what [`Watcher::backend_of`] reports) and — for a fanotify root —
/// the live stats handle [`Watcher::backend_stats`] snapshots.
#[derive(Debug)]
struct RootEntry {
  path: Arc<PathBuf>,
  identity: RootIdentity,
  ancestors: Arc<[RootIdentity]>,
  backend: BackendKind,
  stats: Option<crate::os::BackendStatsHandle>,
}

/// One in-flight `watch`'s reservation record: the watcher-side canonical
/// path plus the identity its pre-flight stat observed (`None` off-unix).
#[derive(Debug)]
struct PendingRoot {
  path: PathBuf,
  identity: Option<RootIdentity>,
}

/// The watcher-side registry of live roots, keyed by scope. Entries exist
/// exactly while their root is watched: every scope end (unwatch, root death,
/// stream fatal, close) removes its entry, so the registry is bounded by the
/// number of LIVE roots — deliveries carry their own root path, so nothing
/// here is needed to assemble trailing events of a dead scope.
///
/// `entries` has ONE writer: the driver task, through [`RegistryWriter`] —
/// scope-live and scope-dead execute on that single task in program order, so
/// an insert can never race a removal. The watcher side only reads entries
/// (and owns the `pending` reservations, which no one else writes).
#[derive(Debug, Default)]
struct RootSet {
  entries: BTreeMap<ScopeId, RootEntry>,
  /// Roots with a `watch` in flight, reserved so two concurrent overlapping
  /// `watch` calls cannot both pass the disjointness check.
  pending: Vec<PendingRoot>,
}

impl RootSet {
  /// The already-covered root (live or pending) that overlaps `candidate`, if
  /// any. Two roots overlap when either contains the other by bytes — or when
  /// they are one object under two spellings (`identity` equality), which
  /// byte comparison cannot see on case- or normalization-insensitive
  /// volumes. Ancestor containment across spellings needs the candidate's
  /// ancestor identities, which only the spawn barrier reads: the driver's
  /// [`ScopeRegistry::final_root_conflict`] settles those before anything
  /// goes live.
  fn overlap_of(&self, candidate: &Path, identity: Option<RootIdentity>) -> Option<PathBuf> {
    let live = self.entries.values().find(|entry| {
      candidate.starts_with(entry.path.as_path())
        || entry.path.starts_with(candidate)
        || Some(entry.identity) == identity
    });
    if let Some(entry) = live {
      return Some(entry.path.as_ref().clone());
    }
    self
      .pending
      .iter()
      .find(|reserved| {
        candidate.starts_with(&reserved.path)
          || reserved.path.starts_with(candidate)
          || (identity.is_some() && reserved.identity == identity)
      })
      .map(|reserved| reserved.path.clone())
  }
}

/// The driver task's write end of the registry — the SOLE mutator of
/// `RootSet::entries` (see the single-writer note on [`RootSet`]).
struct RegistryWriter {
  roots: Arc<RwLock<RootSet>>,
}

impl ScopeRegistry for RegistryWriter {
  fn scope_live(
    &self,
    scope: ScopeId,
    root: &Path,
    identity: RootIdentity,
    ancestors: &[RootIdentity],
    backend: BackendKind,
    stats: Option<crate::os::BackendStatsHandle>,
  ) {
    let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
    set.entries.insert(
      scope,
      RootEntry {
        path: Arc::new(root.to_path_buf()),
        identity,
        ancestors: ancestors.into(),
        backend,
        stats,
      },
    );
  }

  fn scope_dead(&self, scope: ScopeId) {
    let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
    set.entries.remove(&scope);
  }

  fn final_root_conflict(
    &self,
    final_root: &Path,
    identity: RootIdentity,
    ancestors: &[RootIdentity],
    reserved: Option<&Path>,
  ) -> Option<PathBuf> {
    let set = self.roots.read().unwrap_or_else(PoisonError::into_inner);
    let live = set.entries.values().find(|entry| {
      final_root.starts_with(entry.path.as_path())
        || entry.path.starts_with(final_root)
        || entry.identity == identity
        || ancestors.contains(&entry.identity)
        || entry.ancestors.contains(&identity)
    });
    if let Some(entry) = live {
      return Some(entry.path.as_ref().clone());
    }
    set
      .pending
      .iter()
      // A reservation holds at most one entry per path (an overlapping
      // second take is rejected), so skipping by equality skips exactly
      // the checking watch's own.
      .filter(|pending| Some(pending.path.as_path()) != reserved)
      .find(|pending| {
        final_root.starts_with(&pending.path)
          || pending.path.starts_with(final_root)
          || pending.identity == Some(identity)
      })
      .map(|pending| pending.path.clone())
  }
}

/// A pending-root reservation, held across `watch`'s awaits. Dropping it —
/// on success, failure, OR a cancelled future — releases the reservation, so
/// an abandoned `watch` can never leave a permanent overlap blocker. On
/// success the real `RootEntry` is inserted BEFORE the guard drops, so the
/// path is covered continuously.
///
/// The reserved path is ADVISORY: it holds the watcher-side canonical form,
/// which mutually excludes concurrent `watch` calls, but the backend
/// re-canonicalizes during spawn — the driver's final-root check
/// ([`ScopeRegistry::final_root_conflict`]) is the authority on what actually
/// goes live.
#[derive(Debug)]
struct Reservation {
  roots: Arc<RwLock<RootSet>>,
  path: PathBuf,
}

impl Reservation {
  /// Reserves `path`, or reports the covering root when it overlaps. The
  /// pre-flight identity lets two concurrent spelling-aliased `watch` calls
  /// collide right here — the first reserver wins deterministically — instead
  /// of both spending a spawn to lose at the driver's final check.
  fn take(
    roots: &Arc<RwLock<RootSet>>,
    path: PathBuf,
    identity: Option<RootIdentity>,
  ) -> Result<Self, WatchRootError> {
    let mut set = roots.write().unwrap_or_else(PoisonError::into_inner);
    if let Some(existing) = set.overlap_of(&path, identity) {
      return Err(WatchRootError::Overlaps { path, existing });
    }
    set.pending.push(PendingRoot {
      path: path.clone(),
      identity,
    });
    drop(set);
    Ok(Self {
      roots: Arc::clone(roots),
      path,
    })
  }
}

impl Drop for Reservation {
  fn drop(&mut self) {
    self
      .roots
      .write()
      .unwrap_or_else(PoisonError::into_inner)
      .pending
      .retain(|pending| pending.path != self.path);
  }
}

/// An asynchronous filesystem watcher: the consumer surface of the
/// `tributary-fs` driver.
///
/// A watcher owns one driver task and any number of **disjoint** watched
/// roots. It implements [`Stream`] (and offers the inherent
/// [`next`](Self::next)), yielding [`Event`]s.
///
/// # Watching means "changes from now on"
///
/// Registering a root delivers no initial inventory. A consumer that needs a
/// snapshot starts the watch **first**, then crawls the tree itself: any
/// change racing the crawl is delivered as an event, and because events are
/// grounded in what is actually on disk, applying them over the crawl's
/// result converges.
///
/// # Loss is never silent
///
/// Kernel-side drops, a full event buffer, a vanished root — every coverage
/// gap surfaces as a [`Rescan`](crate::EventKind::Rescan) event whose
/// [`epoch`](Event::epoch) dominates everything delivered before it. See
/// [`Event::epoch`] for the re-enumeration contract.
///
/// # Dropping
///
/// Dropping a watcher closes its command channel; the driver observes the
/// close and performs the same orderly stream teardown as
/// [`close`](Self::close), without anyone to confirm it to. Prefer `close()`
/// in orderly programs — it awaits the teardown.
pub struct Watcher<R: RuntimeLite> {
  /// This watcher's handle brand (see [`RootHandle`]).
  instance: u64,
  commands: async_channel::Sender<Command>,
  events: EventStream,
  roots: Arc<RwLock<RootSet>>,
  _runtime: PhantomData<R>,
}

/// The watcher's inbound event stream: the driver's `async_channel::Receiver`,
/// type-erased. Boxed because the `Receiver` embeds a pinned listener (it is
/// not `Unpin`), so the `Pin<Box<…>>` keeps `Watcher` itself `Unpin` for
/// consumers. The `+ Send + Sync` bound (the `Receiver` is both) keeps
/// `Watcher: Sync`, hence `&Watcher: Send`.
type EventStream =
  Pin<Box<dyn Stream<Item = (ScopeId, Arc<PathBuf>, Change)> + Send + Sync + 'static>>;

impl<R: RuntimeLite> core::fmt::Debug for Watcher<R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Watcher")
      .field("roots", &self.roots)
      .finish_non_exhaustive()
  }
}

impl<R: RuntimeLite> Watcher<R> {
  /// Builds a watcher and spawns its driver task on `R`.
  ///
  /// # Errors
  ///
  /// [`BuildError::TooManyExclusions`] when the options carry more exclusion
  /// directories than the OS honors
  /// ([`WatcherOptions::MAX_EXCLUSIONS`]).
  pub fn new(options: WatcherOptions) -> Result<Self, BuildError> {
    let supplied = options.exclusions_slice().len();
    if supplied > WatcherOptions::MAX_EXCLUSIONS {
      return Err(BuildError::TooManyExclusions { supplied });
    }
    let config = DriverConfig {
      latency: options.latency(),
      move_window: options.move_window(),
      os_batch_capacity: options.os_batch_capacity(),
      exclusions: options.exclusions_slice().to_vec(),
      profile: DriverConfig::platform_profile(),
      backend: options.backend(),
      root_liveness_interval: options.root_liveness_interval(),
      max_map_directories: options.max_map_directories(),
    };
    Self::spawn_with(options, config, RealFs::new())
  }

  /// Builds the watcher around `ops` — the seam the hermetic lifecycle tests
  /// drive with a fake filesystem; production always passes [`RealFs`].
  fn spawn_with(
    options: WatcherOptions,
    config: DriverConfig,
    ops: impl crate::driver::FsOps,
  ) -> Result<Self, BuildError> {
    let (command_tx, command_rx) = async_channel::bounded(16);
    let (event_tx, event_rx) = async_channel::bounded(options.event_capacity().get());
    let roots = Arc::new(RwLock::new(RootSet::default()));
    // The registry's entries are written only by the driver task: live at
    // spawn (before the grant is sent), dead at every teardown — one writer,
    // program order, no insert/remove race. This side only reads.
    let registry = RegistryWriter {
      roots: Arc::clone(&roots),
    };
    R::spawn_detach(run::<R, _>(config, ops, command_rx, event_tx, registry));
    Ok(Self {
      instance: WATCHER_INSTANCES.fetch_add(1, Ordering::Relaxed),
      commands: command_tx,
      events: Box::pin(event_rx),
      roots,
      _runtime: PhantomData,
    })
  }

  /// A watcher over a fake platform, for hermetic lifecycle tests.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn new_with(
    options: WatcherOptions,
    ops: impl crate::driver::FsOps,
  ) -> Result<Self, BuildError> {
    let config = DriverConfig {
      latency: options.latency(),
      move_window: options.move_window(),
      os_batch_capacity: options.os_batch_capacity(),
      exclusions: options.exclusions_slice().to_vec(),
      // The hermetic lifecycle suites drive the backend-agnostic scope
      // machinery over the KR profile with FSEvents-shaped payloads,
      // regardless of host — the descending profile has its own driver
      // suites. Pinning here keeps them host-independent.
      profile: crate::os::BackendKind::FsEvents,
      // The fake spawn pins its backend directly (`FakeFs::spawn_backend`), so
      // the selection knob is inert here.
      backend: options.backend(),
      root_liveness_interval: options.root_liveness_interval(),
      max_map_directories: options.max_map_directories(),
    };
    Self::spawn_with(options, config, ops)
  }

  /// Watches `root`, resolving once the native stream is live. From that
  /// moment every change under the root is delivered per `interest`
  /// (`Rescan`s are always delivered).
  ///
  /// The root is canonicalized first (a symlinked root would otherwise
  /// observe nothing), which performs a few blocking metadata syscalls
  /// inline.
  ///
  /// # A handle can be dead on arrival
  ///
  /// The returned handle names a root that was live when the stream started —
  /// but a root can die (be deleted, unmount, the stream fail) at any moment,
  /// including between the stream going live and this call resolving. Such a
  /// handle is indistinguishable from one whose root died right after
  /// `watch()` returned, which no design can prevent: [`root_path`] answers
  /// `None`, [`unwatch`] answers [`UnknownRoot`], and the root's terminal
  /// [`Rescan`](crate::EventKind::Rescan) is still delivered.
  ///
  /// [`root_path`]: Self::root_path
  /// [`unwatch`]: Self::unwatch
  /// [`UnknownRoot`]: UnwatchError::UnknownRoot
  ///
  /// # Errors
  ///
  /// - [`WatchRootError::NotFound`] / [`WatchRootError::NotADirectory`] when
  ///   the root cannot serve as a watch target;
  /// - [`WatchRootError::Overlaps`] when it is not disjoint from an
  ///   already-watched root (subsumption is the layer above's job). The check
  ///   binds to the FINAL canonical root: a path retargeted between this call
  ///   and the stream spawn is revalidated by the driver, so the disjointness
  ///   invariant holds for what is actually watched;
  /// - [`WatchRootError::Source`] when the platform stream could not start;
  /// - [`WatchRootError::Closed`] when the watcher is already closed.
  pub async fn watch(
    &self,
    root: impl Into<PathBuf>,
    interest: Interest,
  ) -> Result<RootHandle, WatchRootError> {
    let supplied = root.into();
    let canonical = std::fs::canonicalize(&supplied).map_err(|err| {
      if err.kind() == std::io::ErrorKind::NotFound {
        WatchRootError::NotFound { path: supplied }
      } else {
        WatchRootError::Source(SourceError::RootUnavailable {
          root: supplied,
          source: err,
        })
      }
    })?;
    let meta = std::fs::metadata(&canonical).ok();
    if !meta.as_ref().is_some_and(|meta| meta.is_dir()) {
      return Err(WatchRootError::NotADirectory { path: canonical });
    }
    let identity = meta.as_ref().and_then(identity_of);

    // Reserve the root before the round-trip so a concurrent overlapping
    // `watch` cannot also pass the disjointness check. The guard's Drop
    // releases the reservation on every exit — including this future being
    // cancelled at either await below. An orphaned stream cannot outlive a
    // cancellation on either side of the reply: a reply finding no receiver
    // is torn down by the driver directly, and a delivered-but-never-polled
    // reply unwinds through its `WatchGrant`.
    let reservation = Reservation::take(&self.roots, canonical.clone(), identity)?;

    let (reply, response) = futures_channel::oneshot::channel();
    let sent = self
      .commands
      .send(Command::Watch {
        root: canonical,
        interest,
        reply,
      })
      .await;
    if sent.is_err() {
      self.driver_gone();
      return Err(WatchRootError::Closed);
    }
    match response.await {
      Ok(Ok(grant)) => {
        // The driver inserted the registry entry BEFORE sending this grant
        // (and removes it at every teardown — one writer, program order), so
        // the path is covered continuously while the reservation still
        // holds: defusing is the whole commit. A scope that died in the
        // window since simply hands back a dead-on-arrival handle (see the
        // method docs).
        let scope = grant.scope();
        drop(reservation);
        grant.defuse();
        Ok(RootHandle::new(self.instance, scope))
      }
      Ok(Err(err)) => Err(err),
      Err(_) => {
        self.driver_gone();
        Err(WatchRootError::Closed)
      }
    }
  }

  /// Stops watching a root, resolving once its native stream is torn down.
  /// Events already decoded may still trail out of the stream afterwards.
  ///
  /// # Errors
  ///
  /// - [`UnwatchError::UnknownRoot`] when the handle does not name a live
  ///   root of THIS watcher (never watched, already unwatched, torn down by
  ///   root death, or issued by a different watcher);
  /// - [`UnwatchError::Closed`] when the watcher is already closed.
  pub async fn unwatch(&self, root: RootHandle) -> Result<(), UnwatchError> {
    // A foreign handle must be rejected before anything is sent: its scope
    // number can name THIS watcher's unrelated root.
    if root.instance() != self.instance {
      return Err(UnwatchError::UnknownRoot);
    }
    let (reply, response) = futures_channel::oneshot::channel();
    if self
      .commands
      .send(Command::Unwatch {
        scope: root.scope(),
        reply: Some(reply),
      })
      .await
      .is_err()
    {
      self.driver_gone();
      return Err(UnwatchError::Closed);
    }
    match response.await {
      // The registry entry is reclaimed by the driver's scope-dead signal;
      // nothing to reconcile here on either outcome.
      Ok(true) => Ok(()),
      Ok(false) => {
        // The driver never knew the scope, so its single-writer registry
        // cannot still hold an entry for it.
        debug_assert!(
          !self
            .roots
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .contains_key(&root.scope()),
          "an unknown scope must have no registry entry"
        );
        Err(UnwatchError::UnknownRoot)
      }
      Err(_) => {
        self.driver_gone();
        Err(UnwatchError::Closed)
      }
    }
  }

  /// Requests teardown of a root like [`unwatch`](Self::unwatch), but as a NON-BLOCKING,
  /// REPLY-LESS fire-and-forget: it `try_send`s the ack-less command and reports whether the
  /// control channel accepted it. Unlike `unwatch` it never awaits — so the layer above can apply
  /// a queued release opportunistically without coupling a disjoint arm (and any `close` queued
  /// behind it) to that release's teardown latency.
  ///
  /// The driver tears a reply-less `Unwatch` down exactly like the awaited one — the same stream
  /// teardown and registry reclamation — it simply sends no acknowledgement, so the caller cannot
  /// observe completion (nor the scope-existed bool). A caller that must KNOW the root is gone — to
  /// clear a just-surfaced [`Overlaps`](WatchRootError::Overlaps) naming it — awaits
  /// [`unwatch`](Self::unwatch) instead; enqueued after this reply-less request on the one FIFO
  /// control channel, that awaited `unwatch` resolves only once the driver has processed this
  /// teardown and reclaimed the registry entry.
  ///
  /// Returns `false` when the control channel is full (the caller re-tries at its next
  /// opportunity) or closed, or when `root` is a foreign handle; `true` when the request was
  /// enqueued. Never blocks and never panics.
  pub fn request_unwatch(&self, root: RootHandle) -> bool {
    if root.instance() != self.instance {
      return false;
    }
    self
      .commands
      .try_send(Command::Unwatch {
        scope: root.scope(),
        reply: None,
      })
      .is_ok()
  }

  /// Reconciles a watched root's per-directory coverage to the `retained` cover **in place**,
  /// **bidirectionally**: it prunes every descended kernel watch strictly outside the cover
  /// — the canonical absolute paths whose coverage must survive — AND re-arms any retained
  /// subtree an earlier, narrower cover pruned, while leaving every already-covered retained
  /// subtree and the connecting ancestors from the root down to each of them armed. The
  /// retained-and-covered watches are **never re-armed**, so their events keep flowing with
  /// **no gap and no re-crawl**; only a previously-pruned corner is grown back.
  ///
  /// A **best-effort optimization** the layer above uses to reclaim (and, when a survivor
  /// returns, restore) inotify watch budget after a wide root outlived the consumer whose key
  /// equalled it (the set-cover design): it only ever removes coverage no consumer is subscribed under
  /// and only ever re-arms coverage a survivor needs, emits **no**
  /// [`Rescan`](crate::EventKind::Rescan), and is a **no-op** for a kernel-recursive backend
  /// (fanotify / FSEvents), whose single whole-subtree stream has no per-directory watches to
  /// prune or grow. A watch is kept by the prune iff its path lies under a retained prefix OR
  /// is an ancestor one descends from; a retained prefix not currently covered is re-armed.
  /// `retained` are the watcher's own canonical coordinates (as
  /// [`root_path`](Self::root_path) reports), so they line up with the watches' addressing.
  ///
  /// # The acknowledgement is an effect-completion fence
  ///
  /// The returned future resolves when the reconcile has **settled** — every re-arm the grow
  /// half started has quiesced, each terminal being an armed-live watch or a loss already
  /// signaled in-band — never when its effects were merely queued or applied to the in-memory
  /// tree. What settled means is the [`CoverOutcome`]:
  ///
  /// - [`Applied`](CoverOutcome::Applied): the window was clean — **writes under the retained
  ///   cover from the moment the ack resolves are delivered**. Shrinking, growing back, and
  ///   writing immediately on the resolved ack races nothing.
  /// - [`Degraded`](CoverOutcome::Degraded): the reconcile settled, but coverage loss was
  ///   signaled inside the window (a failed re-arm, an unreadable re-arm read, an overflow, a
  ///   teardown racing the fence): coverage may be partial, and the covering
  ///   [`Rescan`](crate::EventKind::Rescan) — already delivered in-band — dominates the gap.
  ///   Re-issuing the same cover re-attempts the grow.
  /// - [`Recursive`](CoverOutcome::Recursive): the root is backed by a kernel-recursive
  ///   backend, whose coverage never narrowed — nothing to reconcile, answered immediately.
  /// - [`Skipped`](CoverOutcome::Skipped): no reconcile ran — the scope is unknown to the
  ///   driver ([`UnknownRoot`](SkipReason::UnknownRoot)), not yet publicly live
  ///   ([`NotLive`](SkipReason::NotLive)), or the cover was refused
  ///   ([`RefusedCover`](SkipReason::RefusedCover)). Prior coverage is untouched.
  ///
  /// A root torn down mid-fence (unwatch, root death) settles `Degraded` — its terminal
  /// `Rescan` covers the caller. Several in-flight reconciles of one root apply in command
  /// order (latest wins) and settle together, each acknowledged with the shared window's
  /// verdict.
  ///
  /// # Errors
  ///
  /// - [`UnwatchError::UnknownRoot`] when `root` was issued by a DIFFERENT watcher — rejected
  ///   before anything is sent, exactly as [`unwatch`](Self::unwatch) does (a live handle of
  ///   this watcher whose root just died answers `Ok(Skipped(UnknownRoot))` instead: the
  ///   driver, not the handle check, is the authority on scope liveness);
  /// - [`UnwatchError::Closed`] when the watcher is already closed, or closes (or its driver
  ///   dies) mid-fence — the ratified close semantics drop parked acknowledgements rather
  ///   than resolve them over a torn-down driver.
  pub async fn set_cover(
    &self,
    root: RootHandle,
    retained: Vec<PathBuf>,
  ) -> Result<CoverOutcome, UnwatchError> {
    // A foreign handle's scope number can name THIS watcher's unrelated root — reject
    // before anything is sent, exactly as `unwatch` does.
    if root.instance() != self.instance {
      return Err(UnwatchError::UnknownRoot);
    }
    let (reply, response) = futures_channel::oneshot::channel();
    if self
      .commands
      .send(Command::SetCover {
        scope: root.scope(),
        retained,
        reply: Some(reply),
      })
      .await
      .is_err()
    {
      self.driver_gone();
      return Err(UnwatchError::Closed);
    }
    match response.await {
      Ok(outcome) => Ok(outcome),
      // The driver dropped the reply: it closed (or died) mid-fence, so the reconcile's
      // settlement was never observed. Surface the closed state like `unwatch` — the layer
      // above keeps the (harmless) over-broad coverage and re-issues against a live watcher.
      Err(_) => {
        self.driver_gone();
        Err(UnwatchError::Closed)
      }
    }
  }

  /// Requests a coverage reconcile like [`set_cover`](Self::set_cover), but as a NON-BLOCKING,
  /// REPLY-LESS fire-and-forget: it `try_send`s the ack-less command and reports whether the
  /// control channel accepted it. Unlike `set_cover` it never awaits — so it applies a deferred
  /// reconcile PROMPTLY, without waiting for a later watcher operation to carry it (a
  /// `Covered`-outside grow arms nothing, so a queue-only reconcile would otherwise wait for an
  /// unrelated arm).
  ///
  /// The driver applies a reply-less `SetCover` exactly like the awaited one — the same in-place
  /// bidirectional reconcile, the same latest-wins ordering against other covers of the root —
  /// it simply sends no acknowledgement: `true` says the request was ENQUEUED, nothing about
  /// when (or whether) the retained cover's kernel coverage is live. A caller that must know —
  /// to write into a just-regrown subtree without racing the re-arm — awaits
  /// [`set_cover`](Self::set_cover) instead, whose acknowledgement is the effect-completion
  /// fence; a reconcile requested here still participates in that fence's bookkeeping (its
  /// window is observed at the next settlement), it just has no reply to resolve.
  ///
  /// Returns `false` when the control channel is full (the caller re-tries at its next
  /// opportunity) or closed, or when `root` is a foreign handle; `true` when the request was
  /// enqueued. Never blocks and never panics.
  pub fn request_set_cover(&self, root: RootHandle, retained: Vec<PathBuf>) -> bool {
    if root.instance() != self.instance {
      return false;
    }
    self
      .commands
      .try_send(Command::SetCover {
        scope: root.scope(),
        retained,
        reply: None,
      })
      .is_ok()
  }

  /// The driver is gone (its command channel closed without an orderly
  /// confirmation): clear the read view so the registry is empty-and-honest
  /// rather than frozen at its last state. The single-writer rule is intact —
  /// there is no writer left to race.
  fn driver_gone(&self) {
    let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
    set.entries.clear();
  }

  /// The canonical path of a watched root, if the handle names a live root
  /// of this watcher.
  pub fn root_path(&self, root: RootHandle) -> Option<PathBuf> {
    if root.instance() != self.instance {
      return None;
    }
    self
      .roots
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .entries
      .get(&root.scope())
      .map(|entry| entry.path.as_ref().clone())
  }

  /// The backend the spawn barrier selected for a watched root — the capability
  /// report for a `Backend::Auto` outcome (fanotify when the privileged probe
  /// passed, inotify on the fallback). `None` when the handle does not name a
  /// live root of this watcher (never watched, already gone, or foreign), which
  /// is indistinguishable from a root that died right after `watch` returned.
  pub fn backend_of(&self, root: RootHandle) -> Option<BackendKind> {
    if root.instance() != self.instance {
      return None;
    }
    self
      .roots
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .entries
      .get(&root.scope())
      .map(|entry| entry.backend)
  }

  /// A pollable snapshot of a watched root's backend internals (design §4.9):
  /// the fanotify admission map's size and generation, its seed/reseed walk
  /// timings and count, and the batch-memo hit/miss tallies. `None` unless the
  /// handle names a LIVE fanotify root of this watcher — a non-fanotify backend
  /// keeps no such state, and a handle that never named a live root (never
  /// watched, already gone, or foreign) reports `None` just as
  /// [`backend_of`](Self::backend_of) does.
  ///
  /// A snapshot, not a live view: the returned [`BackendStats`] holds the counter
  /// values at the moment of the call. Poll it to watch the map grow or the memo
  /// hit rate move; it costs one read-lock and a handful of atomic loads.
  pub fn backend_stats(&self, root: RootHandle) -> Option<BackendStats> {
    if root.instance() != self.instance {
      return None;
    }
    self
      .roots
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .entries
      .get(&root.scope())
      .and_then(|entry| entry.stats.as_ref())
      .map(|stats| stats.snapshot())
  }

  /// The number of registry entries — live roots only, by construction.
  // Consumed only by the runtime-backed suite, so the gate matches it: a
  // featureless test build (miri, the bare powerset combo) has no consumer.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn registry_len(&self) -> usize {
    self
      .roots
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .entries
      .len()
  }

  /// The next event, or `None` once the watcher is closed and drained.
  #[inline]
  pub async fn next(&mut self) -> Option<Event> {
    futures_util::StreamExt::next(self).await
  }

  /// Closes the watcher: tears every native stream down — including streams
  /// still being spawned or torn down on the blocking pool, which are settled
  /// inside the close accounting — drains what already arrived, and resolves
  /// once the driver has quiesced. The final drain into a full event buffer
  /// is best-effort, and quiescence is bounded by a ~1 s grace: a blocking
  /// pool wedged past it no longer holds the close. `Ok` PROVES every native
  /// stream was torn down — a spawn or teardown wedged past the grace is
  /// reported, never papered over (a wedged spawn may already own a live
  /// stream: the backend starts it and then runs post-live metadata reads
  /// inside the same call).
  ///
  /// # Errors
  ///
  /// [`CloseError::Stopped`] when the driver stopped before confirming (a
  /// panic or an external teardown) — including when the close command
  /// cannot be delivered at all — and [`CloseError::NotQuiesced`] when
  /// stream spawns or teardowns were still executing at grace expiry — those
  /// streams stay live until their wedged calls return (a wedged spawn's
  /// stream self-reclaims via its dropped result once the wedge clears; a
  /// wedged teardown's is unreachable until the call returns); the OS
  /// reclaims at process exit either way.
  pub async fn close(self) -> Result<(), CloseError> {
    let (reply, response) = futures_channel::oneshot::channel();
    if self.commands.send(Command::Close { reply }).await.is_err() {
      // The receiver vanished while this watcher still held a sender: the
      // driver stopped (a panic, an external abort) without acknowledging
      // this close, and whatever spawn/teardown work it held went
      // unobserved — that is not proof of quiescence.
      self.driver_gone();
      return Err(CloseError::Stopped);
    }
    match response.await {
      Ok(0) => Ok(()),
      Ok(pending) => Err(CloseError::NotQuiesced { pending }),
      Err(_) => {
        self.driver_gone();
        Err(CloseError::Stopped)
      }
    }
  }

  /// Wraps a scope-stamped change into the consumer event. Deliveries carry
  /// their own root path, so assembly is total — a dead, already-reclaimed
  /// scope's trailing changes (above all its terminal `Rescan`) still
  /// assemble.
  fn assemble(&self, scope: ScopeId, root_path: &Path, change: &Change) -> Event {
    Event::from_change(RootHandle::new(self.instance, scope), root_path, change)
  }
}

/// The stat-read object identity of a root, deciding disjointness where byte
/// forms cannot (spelling aliases on case-insensitive volumes).
fn identity_of(meta: &std::fs::Metadata) -> Option<RootIdentity> {
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    Some(RootIdentity::new(meta.dev(), meta.ino()))
  }
  #[cfg(not(unix))]
  {
    let _ = meta;
    None
  }
}

impl<R: RuntimeLite> Stream for Watcher<R> {
  type Item = Event;

  fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    let this = self.get_mut();
    match this.events.as_mut().poll_next(cx) {
      Poll::Ready(Some((scope, root, change))) => {
        Poll::Ready(Some(this.assemble(scope, root.as_path(), &change)))
      }
      Poll::Ready(None) => Poll::Ready(None),
      Poll::Pending => Poll::Pending,
    }
  }
}
