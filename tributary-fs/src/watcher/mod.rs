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
  os::SourceError,
};

#[cfg(all(test, feature = "tokio"))]
mod tests;

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
  entries: BTreeMap<ScopeId, Arc<PathBuf>>,
  /// Roots with a `watch` in flight, reserved so two concurrent overlapping
  /// `watch` calls cannot both pass the disjointness check.
  pending: Vec<PathBuf>,
}

impl RootSet {
  /// The already-covered root (live or pending) that overlaps `candidate`, if
  /// any. Two roots overlap when either contains the other.
  fn overlap_of(&self, candidate: &Path) -> Option<PathBuf> {
    self
      .entries
      .values()
      .map(|path| path.as_path())
      .chain(self.pending.iter().map(PathBuf::as_path))
      .find(|existing| candidate.starts_with(existing) || existing.starts_with(candidate))
      .map(Path::to_path_buf)
  }
}

/// The driver task's write end of the registry — the SOLE mutator of
/// `RootSet::entries` (see the single-writer note on [`RootSet`]).
struct RegistryWriter {
  roots: Arc<RwLock<RootSet>>,
}

impl ScopeRegistry for RegistryWriter {
  fn scope_live(&self, scope: ScopeId, root: &Path) {
    let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
    set.entries.insert(scope, Arc::new(root.to_path_buf()));
  }

  fn scope_dead(&self, scope: ScopeId) {
    let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
    set.entries.remove(&scope);
  }

  fn final_root_conflict(&self, final_root: &Path, reserved: Option<&Path>) -> Option<PathBuf> {
    let set = self.roots.read().unwrap_or_else(PoisonError::into_inner);
    set
      .entries
      .values()
      .map(|path| path.as_path())
      .chain(
        set
          .pending
          .iter()
          .map(PathBuf::as_path)
          // A reservation holds at most one entry per path (an overlapping
          // second take is rejected), so skipping by equality skips exactly
          // the checking watch's own.
          .filter(|path| Some(*path) != reserved),
      )
      .find(|existing| final_root.starts_with(existing) || existing.starts_with(final_root))
      .map(Path::to_path_buf)
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
struct Reservation {
  roots: Arc<RwLock<RootSet>>,
  path: PathBuf,
}

impl Reservation {
  /// Reserves `path`, or reports the covering root when it overlaps.
  fn take(roots: &Arc<RwLock<RootSet>>, path: PathBuf) -> Result<Self, WatchRootError> {
    let mut set = roots.write().unwrap_or_else(PoisonError::into_inner);
    if let Some(existing) = set.overlap_of(&path) {
      return Err(WatchRootError::Overlaps { path, existing });
    }
    set.pending.push(path.clone());
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
      .retain(|pending| pending != &self.path);
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
  // Boxed: async-channel's `Receiver` embeds a pinned listener (it is not
  // `Unpin`), and boxing it keeps `Watcher` itself `Unpin` for consumers.
  events: futures_util::stream::BoxStream<'static, (ScopeId, Arc<PathBuf>, Change)>,
  roots: Arc<RwLock<RootSet>>,
  _runtime: PhantomData<R>,
}

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
    };
    Self::spawn_with(options, config, RealFs)
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
      events: futures_util::StreamExt::boxed(event_rx),
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
    let is_dir = std::fs::metadata(&canonical)
      .map(|meta| meta.is_dir())
      .unwrap_or(false);
    if !is_dir {
      return Err(WatchRootError::NotADirectory { path: canonical });
    }

    // Reserve the root before the round-trip so a concurrent overlapping
    // `watch` cannot also pass the disjointness check. The guard's Drop
    // releases the reservation on every exit — including this future being
    // cancelled at either await below. An orphaned stream cannot outlive a
    // cancellation on either side of the reply: a reply finding no receiver
    // is torn down by the driver directly, and a delivered-but-never-polled
    // reply unwinds through its `WatchGrant`.
    let reservation = Reservation::take(&self.roots, canonical.clone())?;

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
        reply,
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
      .map(|path| path.as_ref().clone())
  }

  /// The number of registry entries — live roots only, by construction.
  #[cfg(test)]
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
  /// pool wedged past it no longer holds the close, and a still-pending
  /// stream's own handle drop remains the reclamation backstop.
  ///
  /// # Errors
  ///
  /// [`CloseError::Stopped`] when the driver stopped before confirming (a
  /// panic or an external teardown); OS resources are still reclaimed at
  /// process exit.
  pub async fn close(self) -> Result<(), CloseError> {
    let (reply, response) = futures_channel::oneshot::channel();
    if self.commands.send(Command::Close { reply }).await.is_err() {
      // The driver already exited through its orderly drop path.
      self.driver_gone();
      return Ok(());
    }
    match response.await {
      Ok(()) => Ok(()),
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
