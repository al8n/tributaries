//! Configuration for a [`Watcher`](crate::Watcher).

use std::{
  num::{NonZeroU32, NonZeroUsize},
  path::PathBuf,
  time::Duration,
};

use crate::os::Backend;

#[cfg(test)]
mod tests;

/// Why a [`WatcherOptions`] value cannot be honored.
///
/// Every knob is a bounded quantity: an out-of-range value reaches unchecked
/// arithmetic, an eager allocation, or a cadence that silently never fires.
/// [`WatcherOptions::validate`] converts each such value into one of these
/// BEFORE a watcher exists, so a legal-but-extreme setting is a typed refusal at
/// construction rather than a panic (or a wrap) at some later use site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OptionsError {
  /// More exclusion paths than the OS honors.
  #[error(
    "{supplied} exclusion paths exceed the OS limit of {}",
    crate::os::MAX_EXCLUSIONS
  )]
  TooManyExclusions {
    /// How many exclusion paths the options carried.
    supplied: usize,
  },
  /// The OS event-coalescing latency exceeds
  /// [`WatcherOptions::MAX_LATENCY`].
  #[error(
    "a coalescing latency of {supplied:?} exceeds the {:?} ceiling",
    WatcherOptions::MAX_LATENCY
  )]
  LatencyTooLarge {
    /// The latency the options carried.
    supplied: Duration,
  },
  /// The consumer event-channel capacity exceeds
  /// [`WatcherOptions::MAX_EVENT_CAPACITY`].
  #[error(
    "an event capacity of {supplied} exceeds the {} ceiling",
    WatcherOptions::MAX_EVENT_CAPACITY
  )]
  EventCapacityTooLarge {
    /// The capacity the options carried.
    supplied: NonZeroUsize,
  },
  /// The per-root OS-callback capacity exceeds
  /// [`WatcherOptions::MAX_OS_BATCH_CAPACITY`].
  #[error(
    "an OS batch capacity of {supplied} exceeds the {} ceiling",
    WatcherOptions::MAX_OS_BATCH_CAPACITY
  )]
  OsBatchCapacityTooLarge {
    /// The capacity the options carried.
    supplied: NonZeroUsize,
  },
  /// The native read-buffer size falls outside
  /// [`WatcherOptions::MIN_OS_BUFFER_BYTES`]`..=`[`WatcherOptions::MAX_OS_BUFFER_BYTES`].
  #[error(
    "an OS buffer of {supplied} bytes is outside {}..={}",
    WatcherOptions::MIN_OS_BUFFER_BYTES,
    WatcherOptions::MAX_OS_BUFFER_BYTES
  )]
  OsBufferBytesOutOfRange {
    /// The buffer size the options carried.
    supplied: NonZeroU32,
  },
  /// The root-liveness interval exceeds
  /// [`WatcherOptions::MAX_ROOT_LIVENESS_INTERVAL`].
  #[error(
    "a root-liveness interval of {supplied:?} exceeds the {:?} ceiling",
    WatcherOptions::MAX_ROOT_LIVENESS_INTERVAL
  )]
  RootLivenessIntervalTooLarge {
    /// The interval the options carried.
    supplied: Duration,
  },
}

impl OptionsError {
  /// Whether this is [`TooManyExclusions`](Self::TooManyExclusions).
  #[inline]
  pub const fn is_too_many_exclusions(&self) -> bool {
    matches!(self, Self::TooManyExclusions { .. })
  }
}

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
///
/// # Every knob is bounded
///
/// The builders are `const` and infallible, so a chain of them composes
/// anywhere; the range check is one explicit step, [`validate`](Self::validate),
/// which [`Watcher::new`](crate::Watcher::new) runs before it spawns anything.
/// Each ceiling names a value no downstream use site can carry — an eager
/// channel allocation, a native buffer length, a cadence that would never come
/// round — and a typed refusal at construction is the only honest answer to one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherOptions {
  latency: Duration,
  move_window: Duration,
  event_capacity: NonZeroUsize,
  os_batch_capacity: NonZeroUsize,
  os_buffer_bytes: NonZeroU32,
  exclusions: Vec<PathBuf>,
  backend: Backend,
  root_liveness_interval: Duration,
  max_map_directories: Option<usize>,
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

  /// The largest OS event-coalescing latency a watcher will start with (60 s).
  ///
  /// The latency is a coalescing window, not a timeout: past a minute it stops
  /// describing any delivery regime a consumer could want and only lifts the
  /// derived rename-pairing floor (`2 × latency + 50 ms`) toward the
  /// [`effective_move_window`](Self::effective_move_window) cap. Four orders of
  /// magnitude above [`DEFAULT_LATENCY`](Self::DEFAULT_LATENCY) is the widest
  /// setting that still names a real trade.
  pub const MAX_LATENCY: Duration = Duration::from_secs(60);

  /// The default capacity of the event channel handed to the consumer, in
  /// events.
  pub const DEFAULT_EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

  /// The largest consumer event-channel capacity (2^20 events).
  ///
  /// The channel is allocated EAGERLY at [`Watcher::new`](crate::Watcher::new),
  /// one slot per event: at 2^20 slots that is already a hundreds-of-megabytes
  /// buffer, and a capacity near `usize::MAX` is not a large buffer but an
  /// allocation-size overflow — a panic on 64-bit and an immediate one on the
  /// 32-bit targets.
  pub const MAX_EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(1 << 20).unwrap();

  /// The default per-root capacity of the OS-callback channel, in callback
  /// batches.
  pub const DEFAULT_OS_BATCH_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

  /// The largest per-root OS-callback capacity (2^16 batches).
  ///
  /// This budget is the ONLY memory bound on the source's unbounded queue, so a
  /// value large enough to never bind removes the bound rather than raising it:
  /// 2^16 in-flight batches of a full native buffer is already gigabytes per
  /// root.
  pub const MAX_OS_BATCH_CAPACITY: NonZeroUsize = NonZeroUsize::new(1 << 16).unwrap();

  /// The default native read-buffer size (64 KiB).
  pub const DEFAULT_OS_BUFFER_BYTES: NonZeroU32 = NonZeroU32::new(64 * 1024).unwrap();

  /// The smallest native read-buffer size (4 KiB) — below it a single
  /// variable-length record carrying a long name may not fit, and a buffer that
  /// cannot hold one record makes no progress.
  pub const MIN_OS_BUFFER_BYTES: NonZeroU32 = NonZeroU32::new(4 * 1024).unwrap();

  /// The largest native read-buffer size (1 MiB). The buffer is pinned for the
  /// kernel across every outstanding read — twice over on the double-buffered
  /// `ReadDirectoryChangesW` pump — so this ceiling is the largest per-root
  /// kernel-pinned footprint the crate will commit to.
  pub const MAX_OS_BUFFER_BYTES: NonZeroU32 = NonZeroU32::new(1024 * 1024).unwrap();

  /// The most exclusion directories the OS honors per root
  /// (`FSEventStreamSetExclusionPaths` accepts at most eight).
  pub const MAX_EXCLUSIONS: usize = crate::os::MAX_EXCLUSIONS;

  /// The default per-root backend selection: [`Backend::Auto`] — resolved to
  /// the host's own primitive at the spawn barrier (Linux probes for
  /// fanotify-FILESYSTEM and falls back to inotify).
  pub const DEFAULT_BACKEND: Backend = Backend::Auto;

  /// The default periodic root-liveness interval (30 s) — the detection-latency
  /// bound for a signal-silent unmount, at the watched root or below it. A
  /// `FAN_MARK_FILESYSTEM`-watched superblock unmounted out from under the watch
  /// emits NO kernel signal (the L4.1 finding), and a LAZY unmount
  /// (`umount -l`/`MNT_DETACH`) emits none under inotify either, so both Linux
  /// backends need the periodic re-read. FSEvents signals both cases in band
  /// (`RootChanged` for the root, an `UNMOUNT` flag word for a volume below it)
  /// and ignores this knob; the Windows backends report a lost root as a fatal
  /// source error and likewise never arm it. See
  /// [`root_liveness_interval`](Self::root_liveness_interval).
  pub const DEFAULT_ROOT_LIVENESS_INTERVAL: Duration = Duration::from_secs(30);

  /// The largest periodic root-liveness interval (one day).
  ///
  /// The interval is armed as a deadline (`now + interval`) whose arithmetic
  /// SATURATES, so an enormous one does not crash — it silently arms a deadline
  /// that never fires, disabling the Linux backends' only silent-unmount detector
  /// while looking configured. [`Duration::ZERO`](Duration::ZERO) is how a caller says
  /// "disabled"; anything past a day is the accidental spelling of it, and gets
  /// a typed refusal instead. One day is also the ceiling
  /// [`effective_move_window`](Self::effective_move_window) stands on: deadline
  /// arithmetic stays meaningful only while it stays finite.
  pub const MAX_ROOT_LIVENESS_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

  /// The default fanotify/USN admission-map directory cap: one million
  /// directories. See [`max_map_directories`](Self::max_map_directories) for
  /// what exceeding it does and for the memory table it is derived from.
  pub const DEFAULT_MAX_MAP_DIRECTORIES: Option<usize> = Some(1_000_000);

  /// The default options.
  #[inline]
  pub const fn new() -> Self {
    Self {
      latency: Self::DEFAULT_LATENCY,
      move_window: Self::DEFAULT_MOVE_WINDOW,
      event_capacity: Self::DEFAULT_EVENT_CAPACITY,
      os_batch_capacity: Self::DEFAULT_OS_BATCH_CAPACITY,
      os_buffer_bytes: Self::DEFAULT_OS_BUFFER_BYTES,
      exclusions: Vec::new(),
      backend: Self::DEFAULT_BACKEND,
      root_liveness_interval: Self::DEFAULT_ROOT_LIVENESS_INTERVAL,
      max_map_directories: Self::DEFAULT_MAX_MAP_DIRECTORIES,
    }
  }

  /// Checks every knob against its documented ceiling.
  ///
  /// [`Watcher::new`](crate::Watcher::new) runs this before it allocates or
  /// spawns anything, so a caller normally never calls it; it is public so a
  /// configuration layer can reject a bad setting where the setting is read,
  /// with the same verdict the watcher would give.
  ///
  /// [`move_window`](Self::move_window) is deliberately absent: its derivation
  /// saturates and caps for EVERY input (see
  /// [`effective_move_window`](Self::effective_move_window)), so no value of it
  /// is out of range.
  ///
  /// # Errors
  ///
  /// The first knob found outside its range, as an [`OptionsError`].
  pub fn validate(&self) -> Result<(), OptionsError> {
    if self.exclusions.len() > Self::MAX_EXCLUSIONS {
      return Err(OptionsError::TooManyExclusions {
        supplied: self.exclusions.len(),
      });
    }
    if self.latency > Self::MAX_LATENCY {
      return Err(OptionsError::LatencyTooLarge {
        supplied: self.latency,
      });
    }
    if self.event_capacity > Self::MAX_EVENT_CAPACITY {
      return Err(OptionsError::EventCapacityTooLarge {
        supplied: self.event_capacity,
      });
    }
    if self.os_batch_capacity > Self::MAX_OS_BATCH_CAPACITY {
      return Err(OptionsError::OsBatchCapacityTooLarge {
        supplied: self.os_batch_capacity,
      });
    }
    if self.os_buffer_bytes < Self::MIN_OS_BUFFER_BYTES
      || self.os_buffer_bytes > Self::MAX_OS_BUFFER_BYTES
    {
      return Err(OptionsError::OsBufferBytesOutOfRange {
        supplied: self.os_buffer_bytes,
      });
    }
    if self.root_liveness_interval > Self::MAX_ROOT_LIVENESS_INTERVAL {
      return Err(OptionsError::RootLivenessIntervalTooLarge {
        supplied: self.root_liveness_interval,
      });
    }
    Ok(())
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

  /// The per-root capacity of the OS-callback channel, in callback batches —
  /// how MANY producer batches may be in flight at once, and nothing else.
  ///
  /// A full channel never blocks the OS callback: the batch is dropped and
  /// surfaces as a `Rescan` through the overflow machinery. The budget covers a
  /// batch's whole retention (queue residency plus whatever the core parks), so
  /// it is the one bound on an otherwise unbounded queue.
  ///
  /// Sizing the kernel's own read buffer is a separate question with a separate
  /// knob, [`os_buffer_bytes`](Self::os_buffer_bytes): a count of batches and a
  /// count of bytes answer to different limits, and deriving one from the other
  /// makes both wrong.
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

  /// The per-source native read buffer, in BYTES: how much of one kernel read
  /// the backend can take at a time.
  ///
  /// The buffer holds variable-length kernel records, so its size trades
  /// resident (kernel-pinned) memory for how much a single read can drain
  /// before the queue is consulted again. It never bounds delivery: a buffer too
  /// small for what the kernel has queued produces the backend's own overflow
  /// signal, which surfaces as a covering
  /// [`Rescan`](crate::EventKind::Rescan) like any other loss.
  ///
  /// Honored by every backend that reads kernel records into user space —
  /// inotify, fanotify, `ReadDirectoryChangesW`, and the USN journal. FSEvents
  /// hands the callback a decoded batch and owns its own buffering, so the knob
  /// is inert on macOS.
  ///
  /// A `NonZeroU32` because it is a native buffer length (the Windows APIs take
  /// a `DWORD`), which also puts the whole legal range inside a 32-bit `usize`.
  #[inline]
  pub const fn os_buffer_bytes(&self) -> NonZeroU32 {
    self.os_buffer_bytes
  }

  /// Returns these options with the per-source native read-buffer size set.
  #[inline]
  #[must_use]
  pub const fn with_os_buffer_bytes(mut self, os_buffer_bytes: NonZeroU32) -> Self {
    self.os_buffer_bytes = os_buffer_bytes;
    self
  }

  /// Sets the per-source native read-buffer size.
  #[inline]
  pub const fn set_os_buffer_bytes(&mut self, os_buffer_bytes: NonZeroU32) -> &mut Self {
    self.os_buffer_bytes = os_buffer_bytes;
    self
  }

  /// The load-shedding exclusion directories applied to every root, as a
  /// slice.
  ///
  /// Purely an optimization (at most [`MAX_EXCLUSIONS`](Self::MAX_EXCLUSIONS),
  /// enforced at [`Watcher::new`](crate::Watcher::new)); correctness never
  /// depends on them. Subtracting ground you do not care about is how you keep a
  /// build cache's churn from costing you watches, map entries and deliveries.
  ///
  /// # What an exclusion guarantees
  ///
  /// The reported tree is the root MINUS these subtrees, on EVERY backend:
  ///
  /// - no change at or under an exclusion is delivered; and
  /// - no coverage is established there — a per-directory backend never arms or
  ///   descends into an excluded directory, so excluded churn cannot consume the
  ///   watch, node or admission-map budget the rest of the tree is competing for.
  ///
  /// Matching is a SUBTREE test on the paths as supplied, not a name-prefix one:
  /// an exclusion of `/r/cache` covers `/r/cache` and everything below it, and
  /// leaves `/r/cached` fully reported.
  ///
  /// Where a backend can decide the whole subtree itself it does — macOS hands
  /// the set to the OS, Linux fanotify fences it out of its admission map — and
  /// where it cannot, the enforcement lives one layer up, in front of the
  /// coverage bookkeeping every remaining backend shares. The USN journal also
  /// keeps its own admission map and fences exclusions out of it, the same way
  /// fanotify does, but that is a budget optimization, not a stand-down: the
  /// final delivery call for it still comes from the shared layer, alongside
  /// inotify and RDCW. Which one resolved is not something a caller has to
  /// know.
  ///
  /// # The three carve-outs
  ///
  /// - The watched root's own death is never suppressed, even by an exclusion
  ///   covering the root itself: silencing the one signal that says the watch is
  ///   over would strand the caller.
  /// - A rename CROSSING the boundary is still reported. The object left (or
  ///   joined) the reported tree, and that is a real change to it: you always get
  ///   the half that lies inside the reported tree — as a rename where the
  ///   backend pairs the crossing atomically, otherwise as the removal or
  ///   creation the crossing amounts to from inside.
  /// - [`sync_root`](crate::Watcher::sync_root) refuses a cookie directory covered
  ///   by an exclusion ahead of writing anything, on every backend: a barrier
  ///   whose completion depends on an event this option forbids is a hang waiting
  ///   to happen.
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
  /// [`Backend::Auto`] (the default) resolves to the host's own primitive
  /// inside the pre-start barrier — on Linux it probes for fanotify-FILESYSTEM
  /// per root and falls back to inotify at the first failing probe. An explicit
  /// variant pins one platform's primitive: forced-and-failing preconditions
  /// surface as a typed
  /// [`WatchRootError::Source`](crate::WatchRootError::Source) (never a silent
  /// fallback), and forcing a variant on a platform that does not own it fails
  /// the same way with [`SourceError::ForeignBackend`](crate::SourceError::ForeignBackend)
  /// (never a silent ignore).
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

  /// The periodic root-liveness interval — the detection-latency bound for an
  /// unmount no kernel signal announces, whether it takes the watched root or a
  /// mount below it.
  ///
  /// Each tick re-stats the root AND re-reads the mount table, which covers two
  /// silences:
  ///
  /// - **the root itself.** A fanotify (`FAN_MARK_FILESYSTEM`) root unmounted out
  ///   from under the watch delivers nothing (the mark holds the superblock alive
  ///   and the fd goes quiet — the L4.1 finding), and a LAZY unmount
  ///   (`umount -l`/`MNT_DETACH`) is equally silent under inotify, since the watch
  ///   itself keeps the superblock alive and no `IN_UNMOUNT` is ever sent. The
  ///   re-stat lowers the death — a terminal [`Rescan`](crate::EventKind::Rescan)
  ///   and registry reclamation — once the path no longer names the watched
  ///   object.
  /// - **a mount BELOW the root.** Its departure kills coverage under it and is
  ///   just as silent; the table re-read notices the prefix is gone and delivers
  ///   one covering [`Rescan`](crate::EventKind::Rescan) located at it, obliging
  ///   re-enumeration of that subtree.
  ///
  /// This is the WORST-CASE latency: both are also caught immediately by any loss
  /// signal (which already re-reads the mount table), so the tick only bounds the
  /// quiet case.
  ///
  /// # On a kernel that answers no mount ids, a tick can cost a WHOLE-ROOT rescan
  ///
  /// Every departure above is bounded by ONE interval, on every host — there is
  /// no class that waits several ticks. What varies is the SCOPE of the cover a
  /// tick emits.
  ///
  /// On Linux 4.11–5.7 there is no `statx(STATX_MNT_ID)`, so a boundary the
  /// watcher's own descent found cannot be told apart from a filesystem-internal
  /// one — a btrfs subvolume, which no mount table lists and which never departs.
  /// Nothing observable distinguishes "that mount departed" from "that subvolume
  /// is exactly where it always was", and no amount of re-observation ever will.
  /// The watcher therefore FAILS CLOSED: while it holds any such boundary, every
  /// tick that manages to read the mount table emits ONE
  /// [`Rescan`](crate::EventKind::Rescan) covering the whole watched root, rather
  /// than guessing at a located one.
  ///
  /// **That cost is permanent for as long as the boundary is held.** A root with
  /// btrfs subvolumes under it on such a kernel is re-read by the consumer once
  /// per interval, for the life of the watch. Raising the interval is the knob
  /// that prices it; [`Duration::ZERO`] disables the tick entirely, at the cost
  /// below.
  ///
  /// On Linux 5.8 and later the class is EMPTY — every boundary the watcher
  /// records carries a mount id, and so does the root — and the covers are
  /// located at the mount that actually departed. The fanotify backend needs 5.17
  /// regardless, so it never pays this at all.
  ///
  /// Only the Linux backends consult it — inotify and fanotify. FSEvents signals
  /// both cases in band (`RootChanged` for the root, an `UNMOUNT` flag word for a
  /// volume below it) and the Windows backends report a lost root as a fatal
  /// source error, so the knob is inert for all three.
  ///
  /// [`Duration::ZERO`] DISABLES the tick: a quiet unmount is then observed only
  /// at the next loss-triggered refresh (or never, if none occurs) — the
  /// pre-L4.2 behavior, quiet-but-alive with the root observably gone on
  /// re-access.
  #[inline]
  pub const fn root_liveness_interval(&self) -> Duration {
    self.root_liveness_interval
  }

  /// Returns these options with the periodic root-liveness interval set.
  #[inline]
  #[must_use]
  pub const fn with_root_liveness_interval(mut self, root_liveness_interval: Duration) -> Self {
    self.root_liveness_interval = root_liveness_interval;
    self
  }

  /// Sets the periodic root-liveness interval.
  #[inline]
  pub const fn set_root_liveness_interval(
    &mut self,
    root_liveness_interval: Duration,
  ) -> &mut Self {
    self.root_liveness_interval = root_liveness_interval;
    self
  }

  /// The admission-map directory cap — the ceiling on directories the per-root
  /// map holds. [`None`] is uncapped; the default is
  /// [`DEFAULT_MAX_MAP_DIRECTORIES`](Self::DEFAULT_MAX_MAP_DIRECTORIES) —
  /// **one million**.
  ///
  /// The map is O(LIVE directories): roughly ~250 bytes per directory, so ~2.5–4
  /// GB at 10 million directories (and a seed walk taking minutes) — the
  /// huge-dedicated-tree archetype that wants either a tuned cap or inotify
  /// (which carries its own per-directory kernel costs). A default of `None`
  /// makes registration's memory a function of whatever tree the caller names,
  /// which on an adversarial or accidentally-huge tree is an OOM at
  /// `watch()` — so the default is finite and the caller opts INTO the
  /// unbounded map.
  ///
  /// One million is where the footprint stops being defensible without being
  /// asked for: ~250 MB of map, ~2 orders of magnitude above a large monorepo
  /// (~10^5 directories) and one below the 10-million archetype above. Under
  /// [`Backend::Auto`] exceeding it is not even an error — the barrier falls
  /// back to inotify, whose per-directory kernel cost is one the operator can
  /// see and tune (`fs.inotify.max_user_watches`) — so the default trades an
  /// invisible multi-gigabyte blow-up for a bounded map and a visible fallback.
  ///
  /// Setting the cap trades coverage of a tree past it for that bounded
  /// footprint:
  ///
  /// - at SEED/reseed WALK time a tree exceeding the cap makes the mapped
  ///   backend unviable — under [`Backend::Auto`] the barrier falls back to
  ///   the platform's unmapped backend (inotify on Linux, RDCW on Windows),
  ///   under a forced [`Backend::Fanotify`] or [`Backend::UsnJournal`] it is a
  ///   typed [`WatchRootError::Source`](crate::WatchRootError::Source);
  /// - at LIVE learn time a create/move-in growing the map past the cap ends the
  ///   scope with a terminal [`Rescan`](crate::EventKind::Rescan) — a capped map
  ///   that silently stopped learning would drop events under the unlearned
  ///   directories forever, so the honest terminal is death, never silent loss.
  ///
  /// A cap of `Some(0)` means the map may never hold even the root anchor, so the
  /// seed walk is unviable for ANY root: under [`Backend::Auto`] this effectively
  /// forces inotify (the fall-back path), and under a forced [`Backend::Fanotify`]
  /// every root is the typed viability error. It is never silently normalized to a
  /// live one-node map.
  ///
  /// It counts ADMITTED MAP DIRECTORIES and nothing else. A mount boundary the
  /// seed walk declines to descend never becomes a map node, so it is not charged
  /// here — a root holding one boundary still seeds under a cap of one. (The
  /// walk's own report of those boundaries is bounded too, by a separate internal
  /// walk-output limit that this option does not spend.)
  ///
  /// Ignored by inotify, RDCW, and macOS (none of the three keeps a
  /// fanotify-style admission map); the Windows USN journal reads the same cap
  /// fanotify does, for the same reason.
  #[inline]
  pub const fn max_map_directories(&self) -> Option<usize> {
    self.max_map_directories
  }

  /// Returns these options with the admission-map directory cap set.
  #[inline]
  #[must_use]
  pub const fn with_max_map_directories(mut self, max_map_directories: Option<usize>) -> Self {
    self.max_map_directories = max_map_directories;
    self
  }

  /// Sets the admission-map directory cap.
  #[inline]
  pub const fn set_max_map_directories(&mut self, max_map_directories: Option<usize>) -> &mut Self {
    self.max_map_directories = max_map_directories;
    self
  }
}

impl Default for WatcherOptions {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}
