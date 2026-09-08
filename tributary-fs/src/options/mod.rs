//! Configuration for a [`Watcher`](crate::Watcher).

use std::{
  num::{NonZeroU32, NonZeroUsize},
  path::PathBuf,
  time::Duration,
};

use tributary_proto::{
  Interest,
  glob::{Glob, Globs},
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
///
/// # Configuration faces
///
/// With the `serde` feature the household is one object keyed by the field names.
/// Every key is optional: an absent one takes the value [`new`](Self::new) gives
/// it, so a document names only what it overrides, and an unknown key is ignored
/// (a document written for a later version still loads). Durations are humantime
/// text (`"10ms"`, `"2s"`), the capacities plain integers (a `0` is refused — they
/// are non-zero types), the exclusions plain paths, and `max_map_directories` is
/// either an integer cap or `null` for uncapped.
///
/// ```json
/// {
///   "latency": "25ms",
///   "event_capacity": 4096,
///   "backend": "fanotify",
///   "exclusions": ["/repo/target"],
///   "max_map_directories": 250000
/// }
/// ```
///
/// Deserializing is exactly as unchecked as the builders are: it never runs
/// [`validate`](Self::validate). A configuration layer that wants a bad setting
/// refused where the setting is READ calls it on the loaded value — the same one
/// explicit step [`Watcher::new`](crate::Watcher::new) runs.
///
/// With the `clap` feature it is a `clap::Args` group of one `--<field>` flag
/// per knob, each defaulting to the same value [`new`](Self::new) gives it, so a
/// flagless command line is the default household. `--exclusions` repeats, once
/// per path.
///
/// ```text
/// $ app --latency 25ms --watcher-event-capacity 4096 --backend fanotify \
///       --exclusions /repo/target --max-map-directories 250000
/// ```
///
/// ## The one flag that is not its field's name
///
/// [`event_capacity`](Self::event_capacity) is `--watcher-event-capacity`.
///
/// This household and the umbrella's own `TributariesOptions` both carry an
/// `event_capacity` — two different channels one level apart — and a command line
/// that flattens both (the shape a consumer configuring the whole stack has) cannot
/// carry the same flag twice: clap refuses a duplicate argument id outright. The
/// INNER, OS-layer household yields, so the flag a reader reaches for first,
/// `--event-capacity`, still means the outer channel it is named after.
///
/// The `serde` key is **unchanged** — a document nests the two households under
/// their own keys, so nothing there ever collides, and this exception is the CLI's
/// alone.
///
/// Uncapped (`max_map_directories = None`) is deliberately NOT expressible from a
/// flag — its own documentation explains why the default is finite — nor from a
/// document format without a null literal; a caller that wants it says so in code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct WatcherOptions {
  #[cfg_attr(feature = "serde", serde(with = "humantime_serde"))]
  #[cfg_attr(
    feature = "clap",
    arg(
      long,
      value_parser = humantime::parse_duration,
      default_value = clap_duration_default(WatcherOptions::DEFAULT_LATENCY),
    )
  )]
  latency: Duration,
  #[cfg_attr(feature = "serde", serde(with = "humantime_serde"))]
  #[cfg_attr(
    feature = "clap",
    arg(
      long,
      value_parser = humantime::parse_duration,
      default_value = clap_duration_default(WatcherOptions::DEFAULT_MOVE_WINDOW),
    )
  )]
  move_window: Duration,
  // The ONE flag that is not its field's name — see the type docs. Both the id and
  // the long form move: clap rejects a duplicate ID, so renaming only the long form
  // would leave the very collision this avoids.
  #[cfg_attr(
    feature = "clap",
    arg(
      id = "watcher_event_capacity",
      long = "watcher-event-capacity",
      default_value_t = WatcherOptions::DEFAULT_EVENT_CAPACITY,
    )
  )]
  event_capacity: NonZeroUsize,
  #[cfg_attr(feature = "clap", arg(long, default_value_t = WatcherOptions::DEFAULT_OS_BATCH_CAPACITY))]
  os_batch_capacity: NonZeroUsize,
  #[cfg_attr(feature = "clap", arg(long, default_value_t = WatcherOptions::DEFAULT_OS_BUFFER_BYTES))]
  os_buffer_bytes: NonZeroU32,
  #[cfg_attr(feature = "clap", arg(long))]
  exclusions: Vec<PathBuf>,
  #[cfg_attr(feature = "clap", arg(long, value_enum, default_value_t = WatcherOptions::DEFAULT_BACKEND))]
  backend: Backend,
  #[cfg_attr(feature = "serde", serde(with = "humantime_serde"))]
  #[cfg_attr(
    feature = "clap",
    arg(
      long,
      value_parser = humantime::parse_duration,
      default_value = clap_duration_default(WatcherOptions::DEFAULT_ROOT_LIVENESS_INTERVAL),
    )
  )]
  root_liveness_interval: Duration,
  #[cfg_attr(feature = "clap", arg(long, default_value = clap_default_max_map_directories()))]
  max_map_directories: Option<usize>,
}

/// A flag default rendered from the constant it mirrors, so the flag and the
/// constructor can never drift.
#[cfg(feature = "clap")]
fn clap_default(text: String) -> clap::builder::OsStr {
  clap::builder::Str::from(text).into()
}

/// The humantime text of a `Duration` default — what a `--<duration-flag>` falls
/// back to, in the same spelling its `value_parser` reads.
#[cfg(feature = "clap")]
fn clap_duration_default(duration: Duration) -> clap::builder::OsStr {
  clap_default(humantime::format_duration(duration).to_string())
}

/// The clap default for [`WatcherOptions::max_map_directories`], derived from
/// [`WatcherOptions::DEFAULT_MAX_MAP_DIRECTORIES`] itself: a cap becomes the flag's
/// default text, and an uncapped default would leave the flag with no default at
/// all.
#[cfg(feature = "clap")]
fn clap_default_max_map_directories() -> clap::builder::Resettable<clap::builder::OsStr> {
  match WatcherOptions::DEFAULT_MAX_MAP_DIRECTORIES {
    Some(cap) => clap::builder::Resettable::Value(clap_default(cap.to_string())),
    None => clap::builder::Resettable::Reset,
  }
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
  /// bound for a signal-silent unmount. A `FAN_MARK_FILESYSTEM`-watched
  /// superblock unmounted out from under the watch emits NO kernel signal (the
  /// L4.1 finding), so a periodic root re-stat is its only unmount detection;
  /// every other backend (inotify's `IN_UNMOUNT`/`IN_IGNORED`, FSEvents'
  /// `RootChanged`, and both Windows backends' own fatal-source-error report on
  /// a lost root or volume) signals root death in-band and ignores this knob.
  /// See [`root_liveness_interval`](Self::root_liveness_interval).
  pub const DEFAULT_ROOT_LIVENESS_INTERVAL: Duration = Duration::from_secs(30);

  /// The largest periodic root-liveness interval (one day).
  ///
  /// The interval is armed as a deadline (`now + interval`) whose arithmetic
  /// SATURATES, so an enormous one does not crash — it silently arms a deadline
  /// that never fires, disabling fanotify's only unmount detector while looking
  /// configured. [`Duration::ZERO`](Duration::ZERO) is how a caller says
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

  /// The periodic root-liveness interval — the detection-latency bound for a
  /// signal-silent root unmount.
  ///
  /// A fanotify (`FAN_MARK_FILESYSTEM`) root unmounted out from under the watch
  /// delivers no kernel signal (the mark holds the superblock alive and the fd
  /// goes quiet — the L4.1 finding), so the driver re-stats such a root on this
  /// cadence and lowers its death (a terminal
  /// [`Rescan`](crate::EventKind::Rescan) and registry reclamation) when the
  /// path no longer names the watched object. This is the WORST-CASE latency:
  /// an unmount is also caught immediately by any loss signal (which already
  /// re-reads the mount table), so the tick only bounds the quiet case.
  ///
  /// Only signal-silent-on-unmount backends consult it — fanotify. inotify
  /// (`IN_UNMOUNT`/`IN_IGNORED`), FSEvents (`RootChanged`), and both Windows
  /// backends (a fatal source error the moment the root or its volume is gone)
  /// surface root death in-band and never arm this tick, so the knob is inert
  /// for them.
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

/// Per-ROOT configuration for one [`Watcher::watch_with`](crate::Watcher::watch_with).
///
/// [`WatcherOptions`] configures the watcher; this configures a single root
/// armed on it, and every knob here rides that root alone. [`new`](Self::new)
/// returns the defaults — deliver everything, prune nothing, include
/// everything — which is exactly the behaviour
/// [`Watcher::watch`](crate::Watcher::watch) has always had.
///
/// # The two glob seats
///
/// The seats speak for different things, and each is matched against a
/// different string. Patterns are case-insensitive and a `*` never crosses a `/`
/// (see [`Glob`](tributary_proto::glob::Glob)).
///
/// - [`prune`](Self::prune) subtracts SUBTREES, and it is matched against a
///   **root-relative DIRECTORY path**: the segments between the watched root and
///   a directory, joined with `/`, never with a leading separator. A directory
///   whose path — or any ancestor's, below the root — matches is never
///   enumerated, never armed, never descended, and nothing at or under it is
///   delivered. The root itself is the empty path and matches nothing, so a
///   pattern can never silence the root it is configured on.
///
///   It speaks for directories ONLY. A plain FILE whose own name matches a
///   prune pattern is not dropped by it — narrowing which files arrive is
///   `include`'s seat — so `**/.*`, written to skip dot-directories, does not
///   silently ban every dotfile in the tree. Only an already-pruned directory
///   ABOVE a file takes the file with it. Because the separator is literal,
///   `**/node_modules` matches `node_modules` at any depth while `a/cache` names
///   one place.
///
///   It is the per-root, glob-shaped twin of
///   [`WatcherOptions::exclusions_slice`], and unlike that option it is enforced
///   on EVERY backend: no OS API takes a glob, so the enforcement never stands
///   down to one.
///
///   "Never enumerated, never armed" is a resource promise as much as a delivery
///   one, and where a backend can spend resources on a subtree the seat is
///   enforced at ITS boundary too. A descending backend simply never asks for a
///   watch below a pruned directory. The two kernel-recursive backends that keep
///   their own admission map — fanotify and the Windows change journal — consult
///   the seat in their seed and reseed walks, in every moved-in subtree walk,
///   before every live directory learn, and ahead of bounded transport admission,
///   so a pruned subtree costs them no map entry and its churn cannot exhaust the
///   directory cap. FSEvents (whose stream is the OS's own) and
///   `ReadDirectoryChangesW` (which keeps no map) have nothing under a pruned
///   name to spend, so for them the common layer's fence is the whole
///   enforcement.
/// - [`include`](Self::include) narrows DELIVERY, and it is matched against the
///   object's **NAME** — the last segment of its path, alone. So `*.mp4` and
///   `**/*.mp4` are the same seat here, and a pattern containing a `/` matches
///   nothing at all: there is no `/` in a name to match it against. [`None`] —
///   the default — delivers everything. It never changes coverage: the tree is
///   watched exactly as it would be without it, so a pattern can be widened
///   later without re-arming anything.
///
/// A directory change is never silenced by `include`, and neither is a
/// [`Rescan`](crate::EventKind::Rescan) or a change whose object class the
/// source did not prove — the seat fails OPEN, because a moved or removed folder
/// the consumer never hears about is a hole in its view, while an extra event is
/// one it can drop. A rename is admitted when EITHER end matches, so a media
/// file renamed to a non-media name is still reported.
///
/// Neither seat can reach the watcher's own sync cookie: `prune` never covers
/// the reserved cookie directory and `include` always admits what is inside it,
/// so a `sync` barrier resolves whatever the patterns say. A cookie directory a
/// seat WOULD have pruned is refused before anything is created
/// ([`SyncRootError::DirPruned`](crate::SyncRootError::DirPruned)) — judged on the
/// CANONICAL directory the write resolves, so a symlink into a pruned subtree is
/// refused and a file target whose parent is reportable is not.
///
/// # Configuration faces
///
/// With the `serde` feature the household is one object keyed by the field
/// names, every key optional and defaulted from [`new`](Self::new); the two glob
/// seats are lists of plain strings, and an invalid pattern is a document error.
///
/// ```json
/// { "prune": ["**/node_modules", "**/.git"], "include": ["**/*.{mp4,mov}"] }
/// ```
///
/// With the `clap` feature it is a `clap::Args` group whose `--prune` and
/// `--include` flags repeat, once per pattern. `--include` given no times at all
/// is [`None`] (deliver everything) — which is what makes the seat's absence
/// expressible from a command line at all.
///
/// ```text
/// $ app --prune '**/node_modules' --prune '**/.git' --include '**/*.mp4'
/// ```
///
/// The interest flags are `--created`, `--removed`, `--modified`, `--moved`,
/// `--attrib` and `--ondir`, and a command line that gives NONE of them parses to
/// [`new`](Self::new) — every kind, the same household the serde face and
/// [`Watcher::watch`](crate::Watcher::watch) hand back. Giving any of them narrows
/// to exactly those:
///
/// ```text
/// $ app --prune '**/node_modules'            # every kind, node_modules pruned
/// $ app --created --moved                    # creates and moves alone
/// ```
///
/// This is deliberately NOT the standalone [`Interest`] group's own clap face,
/// where a flagless parse is the EMPTY mask. There, the flags ARE the whole value
/// and an empty one is a legitimate thing to spell; here they are one field of a
/// household whose every OTHER face defaults to
/// [`Interest::all`](tributary_proto::Interest::all), and a flagless
/// `RootOptions` that silently subscribed to nothing would make the command line
/// mean something no other face means — creates, modifications, removals and moves
/// all absent, with only the unmaskable `Rescan`s left. A command line that really
/// wants the empty mask says so through the [`Interest`] group directly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct RootOptions {
  interest: Interest,
  prune: Vec<Glob>,
  include: Option<Vec<Glob>>,
}

/// The `clap` face of [`RootOptions`], and the one place the two households differ.
///
/// A derived `clap::Args` reads each boolean as "given or not given", so flattening
/// the protocol [`Interest`] group straight into [`RootOptions`] made a flagless
/// parse the EMPTY interest while every other face of the same type defaults to
/// [`Interest::all`](tributary_proto::Interest::all). The proxy keeps the flags
/// identical and only reinterprets the flagless case, so the standalone group's own
/// face is untouched.
#[cfg(feature = "clap")]
#[derive(Debug, Clone, clap::Args)]
struct RootOptionsArgs {
  #[command(flatten)]
  interest: RootInterestArgs,
  #[arg(long)]
  prune: Vec<Glob>,
  #[arg(long)]
  include: Option<Vec<Glob>>,
}

/// One `--<field>` flag per [`Interest`] bit, read as "narrow to exactly these".
#[cfg(feature = "clap")]
#[derive(Debug, Clone, clap::Args)]
struct RootInterestArgs {
  #[arg(long)]
  created: bool,
  #[arg(long)]
  removed: bool,
  #[arg(long)]
  modified: bool,
  #[arg(long)]
  moved: bool,
  #[arg(long)]
  attrib: bool,
  #[arg(long)]
  ondir: bool,
}

#[cfg(feature = "clap")]
impl From<RootInterestArgs> for Interest {
  /// NO flag given is the DEFAULT household ([`Interest::all`]); any flag given
  /// narrows to exactly the ones that were.
  fn from(args: RootInterestArgs) -> Self {
    let RootInterestArgs {
      created,
      removed,
      modified,
      moved,
      attrib,
      ondir,
    } = args;
    if !(created || removed || modified || moved || attrib || ondir) {
      return RootOptions::DEFAULT_INTEREST;
    }
    Interest::new()
      .maybe_created(created)
      .maybe_removed(removed)
      .maybe_modified(modified)
      .maybe_moved(moved)
      .maybe_attrib(attrib)
      .maybe_ondir(ondir)
  }
}

#[cfg(feature = "clap")]
impl From<Interest> for RootInterestArgs {
  /// The inverse, for `update_from_arg_matches`: the flags an already-built
  /// household would have been spelled with. The EMPTY interest has no spelling on
  /// this face — no flag given means "every kind" — so it round-trips back to
  /// [`Interest::all`], which is the same rule a flagless parse follows.
  fn from(interest: Interest) -> Self {
    Self {
      created: interest.created(),
      removed: interest.removed(),
      modified: interest.modified(),
      moved: interest.moved(),
      attrib: interest.attrib(),
      ondir: interest.ondir(),
    }
  }
}

#[cfg(feature = "clap")]
impl From<RootOptionsArgs> for RootOptions {
  fn from(args: RootOptionsArgs) -> Self {
    Self {
      interest: args.interest.into(),
      prune: args.prune,
      include: args.include,
    }
  }
}

#[cfg(feature = "clap")]
impl From<&RootOptions> for RootOptionsArgs {
  fn from(options: &RootOptions) -> Self {
    Self {
      interest: options.interest.into(),
      prune: options.prune.clone(),
      include: options.include.clone(),
    }
  }
}

#[cfg(feature = "clap")]
impl clap::FromArgMatches for RootOptions {
  fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
    RootOptionsArgs::from_arg_matches(matches).map(Into::into)
  }

  fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
    let mut args = RootOptionsArgs::from(&*self);
    args.update_from_arg_matches(matches)?;
    *self = args.into();
    Ok(())
  }
}

#[cfg(feature = "clap")]
impl clap::Args for RootOptions {
  fn augment_args(cmd: clap::Command) -> clap::Command {
    RootOptionsArgs::augment_args(cmd)
  }

  fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
    RootOptionsArgs::augment_args_for_update(cmd)
  }
}

impl RootOptions {
  /// The default per-root delivery interest: [`Interest::all`] — narrowing is
  /// the opt-in act, matching the shorthand
  /// [`Watcher::watch`](crate::Watcher::watch) took before this household
  /// existed.
  pub const DEFAULT_INTEREST: Interest = Interest::all();

  /// The default options: deliver every kind, prune nothing, include
  /// everything.
  #[inline]
  pub const fn new() -> Self {
    Self {
      interest: Self::DEFAULT_INTEREST,
      prune: Vec::new(),
      include: None,
    }
  }

  /// The root's delivery interest.
  #[inline]
  pub const fn interest(&self) -> Interest {
    self.interest
  }

  /// Returns these options with the delivery interest set.
  #[inline]
  #[must_use]
  pub const fn with_interest(mut self, interest: Interest) -> Self {
    self.interest = interest;
    self
  }

  /// Sets the delivery interest.
  #[inline]
  pub const fn set_interest(&mut self, interest: Interest) -> &mut Self {
    self.interest = interest;
    self
  }

  /// The subtrees this root never descends into, as a slice. Empty is the
  /// default — nothing is pruned. Matched against root-relative DIRECTORY paths;
  /// see the type docs for what a match subtracts and what it does not.
  #[inline]
  pub fn prune(&self) -> &[Glob] {
    self.prune.as_slice()
  }

  /// Returns these options with the pruned subtrees set.
  #[inline]
  #[must_use]
  pub fn with_prune(mut self, prune: impl IntoIterator<Item = Glob>) -> Self {
    self.prune = prune.into_iter().collect();
    self
  }

  /// Sets the pruned subtrees.
  #[inline]
  pub fn set_prune(&mut self, prune: impl IntoIterator<Item = Glob>) -> &mut Self {
    self.prune = prune.into_iter().collect();
    self
  }

  /// The file patterns delivery is narrowed to, or [`None`] — the default — for
  /// every file. Matched against the object's NAME alone, so a pattern carrying
  /// a `/` admits nothing. An EMPTY list is not the same thing as [`None`]: it
  /// is a seat that admits no file at all (directories and `Rescan`s still
  /// deliver).
  #[inline]
  pub fn include(&self) -> Option<&[Glob]> {
    self.include.as_deref()
  }

  /// Returns these options with delivery narrowed to the given file patterns.
  #[inline]
  #[must_use]
  pub fn with_include(mut self, include: impl IntoIterator<Item = Glob>) -> Self {
    self.include = Some(include.into_iter().collect());
    self
  }

  /// Sets the file patterns delivery is narrowed to.
  #[inline]
  pub fn set_include(&mut self, include: impl IntoIterator<Item = Glob>) -> &mut Self {
    self.include = Some(include.into_iter().collect());
    self
  }

  /// Returns these options delivering every file again — the [`None`] seat.
  #[inline]
  #[must_use]
  pub fn without_include(mut self) -> Self {
    self.include = None;
    self
  }

  /// Clears the include seat, delivering every file again.
  #[inline]
  pub fn clear_include(&mut self) -> &mut Self {
    self.include = None;
    self
  }

  /// The compiled seats this household names, in the shape the driver stores
  /// them on a scope: the pruned subtrees and, when the seat is engaged, the
  /// included files.
  pub(crate) fn compile(&self) -> (Globs, Option<Globs>) {
    (
      Globs::new(self.prune.iter().cloned()),
      self
        .include
        .as_ref()
        .map(|include| Globs::new(include.iter().cloned())),
    )
  }
}

impl Default for RootOptions {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}
