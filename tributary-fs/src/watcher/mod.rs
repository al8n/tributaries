//! The consumer-facing watcher.

use std::{
  collections::BTreeMap,
  marker::PhantomData,
  path::{Path, PathBuf},
  pin::Pin,
  sync::{Arc, PoisonError, RwLock},
  task::{Context, Poll},
};

use agnostic_lite::RuntimeLite;
use futures_core::Stream;
use tributary_proto::{Change, Interest, ScopeId};

use crate::{
  driver::{Command, DriverConfig, RealFs, run},
  error::{BuildError, CloseError, UnwatchError, WatchRootError},
  event::Event,
  options::WatcherOptions,
  os::SourceError,
};

#[cfg(all(test, feature = "tokio"))]
mod tests;

/// An opaque handle to one watched root of a [`Watcher`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootHandle(ScopeId);

impl RootHandle {
  /// Wraps a driver-minted scope.
  pub(crate) const fn new(scope: ScopeId) -> Self {
    Self(scope)
  }

  /// The underlying scope id (the value [`Event`]s of this root carry).
  #[inline]
  pub const fn scope(&self) -> ScopeId {
    self.0
  }
}

/// One registered root: the canonical path events arrive under, and whether
/// the root is still live (dead roots keep their path so trailing events can
/// still be assembled, but stop participating in overlap checks).
#[derive(Debug)]
struct RootEntry {
  path: Arc<PathBuf>,
  live: bool,
}

/// The watcher-side registry of roots, shared with the event-assembly path.
#[derive(Debug, Default)]
struct RootSet {
  entries: BTreeMap<ScopeId, RootEntry>,
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
      .filter(|entry| entry.live)
      .map(|entry| entry.path.as_path())
      .chain(self.pending.iter().map(PathBuf::as_path))
      .find(|existing| candidate.starts_with(existing) || existing.starts_with(candidate))
      .map(Path::to_path_buf)
  }
}

/// A pending-root reservation, held across `watch`'s awaits. Dropping it —
/// on success, failure, OR a cancelled future — releases the reservation, so
/// an abandoned `watch` can never leave a permanent overlap blocker. On
/// success the real `RootEntry` is inserted BEFORE the guard drops, so the
/// path is covered continuously.
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
  commands: async_channel::Sender<Command>,
  // Boxed: async-channel's `Receiver` embeds a pinned listener (it is not
  // `Unpin`), and boxing it keeps `Watcher` itself `Unpin` for consumers.
  events: futures_util::stream::BoxStream<'static, (ScopeId, Change)>,
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
    let (command_tx, command_rx) = async_channel::bounded(16);
    let (event_tx, event_rx) = async_channel::bounded(options.event_capacity().get());
    let roots = Arc::new(RwLock::new(RootSet::default()));
    // The driver reports every scope end (unwatch, root death, stream fatal)
    // back into the registry, so a dead root stops blocking a fresh watch of
    // the same path while its entry keeps assembling trailing events.
    let registry = Arc::clone(&roots);
    let on_scope_dead = move |scope: ScopeId| {
      let mut set = registry.write().unwrap_or_else(PoisonError::into_inner);
      if let Some(entry) = set.entries.get_mut(&scope) {
        entry.live = false;
      }
    };
    R::spawn_detach(run::<R, RealFs>(
      config,
      RealFs,
      command_rx,
      event_tx,
      on_scope_dead,
    ));
    Ok(Self {
      commands: command_tx,
      events: futures_util::StreamExt::boxed(event_rx),
      roots,
      _runtime: PhantomData,
    })
  }

  /// Watches `root`, resolving once the native stream is live. From that
  /// moment every change under the root is delivered per `interest`
  /// (`Rescan`s are always delivered).
  ///
  /// The root is canonicalized first (a symlinked root would otherwise
  /// observe nothing), which performs a few blocking metadata syscalls
  /// inline.
  ///
  /// # Errors
  ///
  /// - [`WatchRootError::NotFound`] / [`WatchRootError::NotADirectory`] when
  ///   the root cannot serve as a watch target;
  /// - [`WatchRootError::Overlaps`] when it is not disjoint from an
  ///   already-watched root (subsumption is the layer above's job);
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
    // cancelled at either await below (the driver side then tears down an
    // orphaned stream when its reply finds no receiver).
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
      return Err(WatchRootError::Closed);
    }
    match response.await {
      Ok(Ok((scope, live_root))) => {
        let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
        set.entries.insert(
          scope,
          RootEntry {
            path: Arc::new(live_root),
            live: true,
          },
        );
        drop(set);
        // Only now may the reservation lift: the entry above covers the path.
        drop(reservation);
        Ok(RootHandle::new(scope))
      }
      Ok(Err(err)) => Err(WatchRootError::Source(err)),
      Err(_) => Err(WatchRootError::Closed),
    }
  }

  /// Stops watching a root, resolving once its native stream is torn down.
  /// Events already decoded may still trail out of the stream afterwards.
  ///
  /// # Errors
  ///
  /// - [`UnwatchError::UnknownRoot`] when the handle does not name a live
  ///   root (never watched, already unwatched, or torn down by root death);
  /// - [`UnwatchError::Closed`] when the watcher is already closed.
  pub async fn unwatch(&self, root: RootHandle) -> Result<(), UnwatchError> {
    let (reply, response) = futures_channel::oneshot::channel();
    self
      .commands
      .send(Command::Unwatch {
        scope: root.scope(),
        reply,
      })
      .await
      .map_err(|_| UnwatchError::Closed)?;
    match response.await {
      Ok(true) => {
        let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = set.entries.get_mut(&root.scope()) {
          entry.live = false;
        }
        Ok(())
      }
      Ok(false) => {
        // The driver no longer knows the scope — it already tore the root
        // down (root death raced this call). Reconcile a stale live entry so
        // the dead path stops blocking a fresh watch.
        let mut set = self.roots.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = set.entries.get_mut(&root.scope()) {
          entry.live = false;
        }
        Err(UnwatchError::UnknownRoot)
      }
      Err(_) => Err(UnwatchError::Closed),
    }
  }

  /// The canonical path of a watched root, if the handle names one.
  pub fn root_path(&self, root: RootHandle) -> Option<PathBuf> {
    self
      .roots
      .read()
      .unwrap_or_else(PoisonError::into_inner)
      .entries
      .get(&root.scope())
      .map(|entry| entry.path.as_ref().clone())
  }

  /// The next event, or `None` once the watcher is closed and drained.
  #[inline]
  pub async fn next(&mut self) -> Option<Event> {
    futures_util::StreamExt::next(self).await
  }

  /// Closes the watcher: tears every native stream down, drains what already
  /// arrived, and resolves once the driver has quiesced. The final drain into
  /// a full event buffer is best-effort.
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
      return Ok(());
    }
    response.await.map_err(|_| CloseError::Stopped)
  }

  /// Wraps a scope-stamped change into the consumer event, if the scope is
  /// still known.
  fn assemble(&self, scope: ScopeId, change: &Change) -> Option<Event> {
    let root_path = {
      let set = self.roots.read().unwrap_or_else(PoisonError::into_inner);
      set.entries.get(&scope).map(|entry| Arc::clone(&entry.path))
    }?;
    Some(Event::from_change(
      RootHandle::new(scope),
      root_path.as_path(),
      change,
    ))
  }
}

impl<R: RuntimeLite> Stream for Watcher<R> {
  type Item = Event;

  fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    let this = self.get_mut();
    loop {
      match this.events.as_mut().poll_next(cx) {
        Poll::Ready(Some((scope, change))) => {
          // A change for a scope the registry no longer knows cannot be
          // assembled into a path; skip it and keep polling.
          if let Some(event) = this.assemble(scope, &change) {
            return Poll::Ready(Some(event));
          }
        }
        Poll::Ready(None) => return Poll::Ready(None),
        Poll::Pending => return Poll::Pending,
      }
    }
  }
}
