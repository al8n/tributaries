//! Configuration for a [`Watcher`](crate::Watcher).

use std::{num::NonZeroUsize, path::PathBuf, time::Duration};

use crate::os::Backend;

#[cfg(test)]
mod tests;

/// The ceiling on the derived rename-pairing window. Deadline arithmetic
/// downstream (`now + window`) must stay finite for the process lifetime, and
/// a pairing window beyond a day is a configuration mistake, not a wish to be
/// honored.
pub(crate) const MAX_MOVE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// The one derivation of the armed rename-pairing window, shared by the
/// public options and the driver config so the two can never drift: at least
/// `2 × latency + 50 ms`, saturating on extreme inputs, capped at
/// [`MAX_MOVE_WINDOW`].
pub(crate) fn derive_move_window(move_window: Duration, latency: Duration) -> Duration {
  move_window
    .max(
      latency
        .saturating_mul(2)
        .saturating_add(Duration::from_millis(50)),
    )
    .min(MAX_MOVE_WINDOW)
}

/// Configuration for a [`Watcher`](crate::Watcher).
///
/// [`new`](Self::new) returns the defaults; every knob has a `with_*` builder,
/// a `set_*` mutator, and a read accessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherOptions {
  latency: Duration,
  move_window: Duration,
  event_capacity: NonZeroUsize,
  os_batch_capacity: NonZeroUsize,
  exclusions: Vec<PathBuf>,
  backend: Backend,
}

impl WatcherOptions {
  /// The default OS event-coalescing latency (10 ms — watchman's shipped
  /// default; raising it trades delivery lag for fewer kernel drops under
  /// churn).
  pub const DEFAULT_LATENCY: Duration = Duration::from_millis(10);

  /// The default rename-pairing window (comfortably above what the default
  /// latency makes physically necessary; see
  /// [`effective_move_window`](Self::effective_move_window)).
  pub const DEFAULT_MOVE_WINDOW: Duration = Duration::from_millis(150);

  /// The default capacity of the event channel handed to the consumer, in
  /// events.
  pub const DEFAULT_EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

  /// The default per-root capacity of the OS-callback channel, in callback
  /// batches.
  pub const DEFAULT_OS_BATCH_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

  /// The most exclusion directories the OS honors per root
  /// (`FSEventStreamSetExclusionPaths` accepts at most eight).
  pub const MAX_EXCLUSIONS: usize = crate::os::MAX_EXCLUSIONS;

  /// The default per-root backend selection: [`Backend::Auto`] — probe for
  /// fanotify-FILESYSTEM, fall back to inotify (Linux; ignored on macOS).
  pub const DEFAULT_BACKEND: Backend = Backend::Auto;

  /// The default options.
  #[inline]
  pub const fn new() -> Self {
    Self {
      latency: Self::DEFAULT_LATENCY,
      move_window: Self::DEFAULT_MOVE_WINDOW,
      event_capacity: Self::DEFAULT_EVENT_CAPACITY,
      os_batch_capacity: Self::DEFAULT_OS_BATCH_CAPACITY,
      exclusions: Vec::new(),
      backend: Self::DEFAULT_BACKEND,
    }
  }

  /// The OS event-coalescing latency.
  #[inline]
  pub const fn latency(&self) -> Duration {
    self.latency
  }

  /// Returns these options with the OS event-coalescing latency set.
  #[inline]
  #[must_use]
  pub const fn with_latency(mut self, latency: Duration) -> Self {
    self.latency = latency;
    self
  }

  /// Sets the OS event-coalescing latency.
  #[inline]
  pub const fn set_latency(&mut self, latency: Duration) -> &mut Self {
    self.latency = latency;
    self
  }

  /// The requested rename-pairing window. The window actually armed is
  /// [`effective_move_window`](Self::effective_move_window).
  #[inline]
  pub const fn move_window(&self) -> Duration {
    self.move_window
  }

  /// Returns these options with the rename-pairing window set.
  #[inline]
  #[must_use]
  pub const fn with_move_window(mut self, move_window: Duration) -> Self {
    self.move_window = move_window;
    self
  }

  /// Sets the rename-pairing window.
  #[inline]
  pub const fn set_move_window(&mut self, move_window: Duration) -> &mut Self {
    self.move_window = move_window;
    self
  }

  /// The rename-pairing window actually armed: the two halves of one rename
  /// can legally arrive one latency window apart, so the effective window
  /// never falls below `2 × latency + 50 ms` of scheduling margin.
  ///
  /// Total for every input: the derivation saturates instead of overflowing,
  /// and the result is capped at one day — deadline arithmetic downstream
  /// must stay finite, and a pairing window beyond that is a configuration
  /// mistake, not a wish to be honored.
  #[inline]
  pub fn effective_move_window(&self) -> Duration {
    derive_move_window(self.move_window, self.latency)
  }

  /// The capacity of the event channel handed to the consumer, in events.
  ///
  /// A full channel never blocks the driver: the affected scope's epoch is
  /// bumped and a single dominating `Rescan` is parked until it fits (see
  /// [`Event::epoch`](crate::Event::epoch) for the consumer contract).
  #[inline]
  pub const fn event_capacity(&self) -> NonZeroUsize {
    self.event_capacity
  }

  /// Returns these options with the consumer event-channel capacity set.
  #[inline]
  #[must_use]
  pub const fn with_event_capacity(mut self, event_capacity: NonZeroUsize) -> Self {
    self.event_capacity = event_capacity;
    self
  }

  /// Sets the consumer event-channel capacity.
  #[inline]
  pub const fn set_event_capacity(&mut self, event_capacity: NonZeroUsize) -> &mut Self {
    self.event_capacity = event_capacity;
    self
  }

  /// The per-root capacity of the OS-callback channel, in callback batches.
  ///
  /// A full channel never blocks the OS callback: the batch is dropped and
  /// surfaces as a `Rescan` through the overflow machinery.
  #[inline]
  pub const fn os_batch_capacity(&self) -> NonZeroUsize {
    self.os_batch_capacity
  }

  /// Returns these options with the per-root OS-callback capacity set.
  #[inline]
  #[must_use]
  pub const fn with_os_batch_capacity(mut self, os_batch_capacity: NonZeroUsize) -> Self {
    self.os_batch_capacity = os_batch_capacity;
    self
  }

  /// Sets the per-root OS-callback capacity.
  #[inline]
  pub const fn set_os_batch_capacity(&mut self, os_batch_capacity: NonZeroUsize) -> &mut Self {
    self.os_batch_capacity = os_batch_capacity;
    self
  }

  /// The load-shedding exclusion directories applied to every root, as a
  /// slice.
  ///
  /// Purely an optimization (at most [`MAX_EXCLUSIONS`](Self::MAX_EXCLUSIONS),
  /// enforced at [`Watcher::new`](crate::Watcher::new)); correctness never
  /// depends on them.
  #[inline]
  pub fn exclusions_slice(&self) -> &[PathBuf] {
    self.exclusions.as_slice()
  }

  /// Returns these options with the exclusion directories set.
  #[inline]
  #[must_use]
  pub fn with_exclusions(mut self, exclusions: Vec<PathBuf>) -> Self {
    self.exclusions = exclusions;
    self
  }

  /// Sets the exclusion directories.
  #[inline]
  pub fn set_exclusions(&mut self, exclusions: Vec<PathBuf>) -> &mut Self {
    self.exclusions = exclusions;
    self
  }

  /// The per-root backend selection.
  ///
  /// On Linux, [`Backend::Auto`] (the default) probes for fanotify-FILESYSTEM
  /// per root inside the pre-start barrier and falls back to inotify at the
  /// first failing probe; [`Backend::Inotify`] and [`Backend::Fanotify`] pin
  /// the choice (a forced `Fanotify` whose preconditions do not hold fails its
  /// `watch` with a typed [`WatchRootError::Source`](crate::WatchRootError::Source),
  /// never a silent fallback). macOS ignores this — FSEvents is its one backend.
  #[inline]
  pub const fn backend(&self) -> Backend {
    self.backend
  }

  /// Returns these options with the per-root backend selection set.
  #[inline]
  #[must_use]
  pub const fn with_backend(mut self, backend: Backend) -> Self {
    self.backend = backend;
    self
  }

  /// Sets the per-root backend selection.
  #[inline]
  pub const fn set_backend(&mut self, backend: Backend) -> &mut Self {
    self.backend = backend;
    self
  }
}

impl Default for WatcherOptions {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}
