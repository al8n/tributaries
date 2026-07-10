//! Configuration for a [`Tributaries`](crate::Tributaries) watcher.

use core::{num::NonZeroUsize, time::Duration};

use tributary_fs::WatcherOptions;

/// Settle/debounce policy for the opt-in coalescer (design §6).
///
/// Two windows govern how long a per-`(subscription, path)` burst is held before its
/// coalesced event is emitted:
///
/// - [`quiet_window`](Self::quiet_window) — the settle time: an entry emits once no
///   further change has touched its path for this long. Each new change to the path
///   pushes the deadline out by another `quiet_window` (so a busy path keeps
///   settling), collapsing the burst per the design §6 table.
/// - [`max_hold`](Self::max_hold) — the ceiling on total hold: a *continuously*
///   touched path (whose `quiet_window` never elapses) still emits once this long has
///   passed since its first change, so the coalesced state can never be held forever.
///
/// Both are policy, not correctness — the exact numbers only trade delivery latency
/// against how aggressively a burst coalesces. [`new`](Self::new) returns the
/// defaults; every knob has a `with_*` builder, a `set_*` mutator, and a read
/// accessor.
///
/// A [`DebounceConfig`] is opt-in: absent it (the default of
/// [`TributariesOptions`]), events pass through untouched, and the coalescer is never
/// even instantiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebounceConfig {
  quiet_window: Duration,
  max_hold: Duration,
}

impl DebounceConfig {
  /// The default settle window (50 ms) — long enough to coalesce the storm of
  /// writes an editor-save or a `cp` emits, short enough to feel immediate.
  pub const DEFAULT_QUIET_WINDOW: Duration = Duration::from_millis(50);

  /// The default hold ceiling (500 ms) — the longest a continuously-touched path's
  /// coalesced state is held before it is forced out.
  pub const DEFAULT_MAX_HOLD: Duration = Duration::from_millis(500);

  /// The default debounce policy.
  #[inline]
  pub const fn new() -> Self {
    Self {
      quiet_window: Self::DEFAULT_QUIET_WINDOW,
      max_hold: Self::DEFAULT_MAX_HOLD,
    }
  }

  /// The settle window: an entry emits once its path has been quiet this long.
  #[inline]
  pub const fn quiet_window(&self) -> Duration {
    self.quiet_window
  }

  /// Returns these options with the settle window set.
  #[inline]
  #[must_use]
  pub const fn with_quiet_window(mut self, quiet_window: Duration) -> Self {
    self.quiet_window = quiet_window;
    self
  }

  /// Sets the settle window.
  #[inline]
  pub const fn set_quiet_window(&mut self, quiet_window: Duration) -> &mut Self {
    self.quiet_window = quiet_window;
    self
  }

  /// The hold ceiling: the longest a continuously-touched path's coalesced state is
  /// held before it is forced out (design §6, bounded hold).
  #[inline]
  pub const fn max_hold(&self) -> Duration {
    self.max_hold
  }

  /// Returns these options with the hold ceiling set.
  #[inline]
  #[must_use]
  pub const fn with_max_hold(mut self, max_hold: Duration) -> Self {
    self.max_hold = max_hold;
    self
  }

  /// Sets the hold ceiling.
  #[inline]
  pub const fn set_max_hold(&mut self, max_hold: Duration) -> &mut Self {
    self.max_hold = max_hold;
    self
  }
}

impl Default for DebounceConfig {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// Configuration for a [`Tributaries`](crate::Tributaries) watcher.
///
/// Embeds the lower-level [`WatcherOptions`] (forwarded to the wrapped
/// `tributary-fs` watcher), the owner→consumer [`event_capacity`](Self::event_capacity),
/// the caller→owner [`command_capacity`](Self::command_capacity), and an optional
/// [`DebounceConfig`] enabling the settle coalescer (design §6). [`new`](Self::new)
/// returns the defaults — the default watcher options, the default capacities, and
/// **no** debounce (events pass through untouched).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TributariesOptions {
  watcher: WatcherOptions,
  event_capacity: NonZeroUsize,
  command_capacity: NonZeroUsize,
  debounce: Option<DebounceConfig>,
}

impl TributariesOptions {
  /// Whether the settle coalescer is enabled by default: [`None`] — it is opt-in, so
  /// out of the box events pass through untouched.
  pub const DEFAULT_DEBOUNCE: Option<DebounceConfig> = None;

  /// The default capacity of the owner→consumer event channel (1024) — the bounded
  /// buffer the owner delivers attributed events through (design backpressure doc).
  /// Mirrors [`WatcherOptions::DEFAULT_EVENT_CAPACITY`], generous enough to absorb
  /// ordinary bursts in-order so per-subscription overflow-to-`Rescan` shedding stays
  /// rare.
  pub const DEFAULT_EVENT_CAPACITY: NonZeroUsize = WatcherOptions::DEFAULT_EVENT_CAPACITY;

  /// The default capacity of the caller→owner command mailbox (64). Deliberately much
  /// tighter than [`DEFAULT_EVENT_CAPACITY`](Self::DEFAULT_EVENT_CAPACITY): each queued
  /// command owns its key, value, and filter, so the bound caps what abandoned
  /// requests can retain (Codex R52) — while 64 in-flight control operations is far
  /// beyond what an orderly consumer keeps outstanding.
  pub const DEFAULT_COMMAND_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

  /// The default options: default [`WatcherOptions`], default capacities, no
  /// debounce.
  #[inline]
  pub fn new() -> Self {
    Self {
      watcher: WatcherOptions::new(),
      event_capacity: Self::DEFAULT_EVENT_CAPACITY,
      command_capacity: Self::DEFAULT_COMMAND_CAPACITY,
      debounce: Self::DEFAULT_DEBOUNCE,
    }
  }

  /// The lower-level watcher options forwarded to the wrapped `tributary-fs` watcher.
  #[inline]
  pub const fn watcher(&self) -> &WatcherOptions {
    &self.watcher
  }

  /// The capacity of the owner→consumer event channel (design backpressure doc): the
  /// bounded buffer [`next`](crate::Tributaries::next) drains. When it fills (a stalled
  /// consumer), the owner sheds the affected subscription to a dominating
  /// [`Rescan`](crate::EventKind::Rescan) rather than blocking or growing memory
  /// without bound — so this trades buffering headroom against how eagerly a slow
  /// consumer is asked to re-enumerate. Distinct from the wrapped watcher's own
  /// [`event_capacity`](WatcherOptions::event_capacity), which bounds the fs layer's
  /// channel one level down.
  #[inline]
  pub const fn event_capacity(&self) -> NonZeroUsize {
    self.event_capacity
  }

  /// Returns these options with the owner→consumer event-channel capacity set.
  #[inline]
  #[must_use]
  pub const fn with_event_capacity(mut self, event_capacity: NonZeroUsize) -> Self {
    self.event_capacity = event_capacity;
    self
  }

  /// Sets the owner→consumer event-channel capacity.
  #[inline]
  pub const fn set_event_capacity(&mut self, event_capacity: NonZeroUsize) -> &mut Self {
    self.event_capacity = event_capacity;
    self
  }

  /// The capacity of the caller→owner command mailbox (Codex R52): the bounded queue
  /// [`watch`](crate::Tributaries::watch)/[`unwatch`](crate::Tributaries::unwatch)
  /// submit into. When it is full — the owner busy inside a caller-bounded reconcile —
  /// a submitting call awaits ADMISSION instead of growing the queue, so abandoned
  /// (cancelled) requests can never accumulate unboundedly: a call cancelled before
  /// admission leaves nothing behind. [`close`](crate::Tributaries::close) rides its
  /// own dedicated channel and is never delayed by a full mailbox.
  #[inline]
  pub const fn command_capacity(&self) -> NonZeroUsize {
    self.command_capacity
  }

  /// Returns these options with the caller→owner command-mailbox capacity set.
  #[inline]
  #[must_use]
  pub const fn with_command_capacity(mut self, command_capacity: NonZeroUsize) -> Self {
    self.command_capacity = command_capacity;
    self
  }

  /// Sets the caller→owner command-mailbox capacity.
  #[inline]
  pub const fn set_command_capacity(&mut self, command_capacity: NonZeroUsize) -> &mut Self {
    self.command_capacity = command_capacity;
    self
  }

  /// Returns these options with the lower-level watcher options set.
  #[inline]
  #[must_use]
  pub fn with_watcher(mut self, watcher: WatcherOptions) -> Self {
    self.watcher = watcher;
    self
  }

  /// Sets the lower-level watcher options.
  #[inline]
  pub fn set_watcher(&mut self, watcher: WatcherOptions) -> &mut Self {
    self.watcher = watcher;
    self
  }

  /// The debounce policy, if the settle coalescer is enabled.
  #[inline]
  pub const fn debounce_config(&self) -> Option<DebounceConfig> {
    self.debounce
  }

  /// Returns these options with the settle coalescer enabled under `config`.
  #[inline]
  #[must_use]
  pub const fn debounce(mut self, config: DebounceConfig) -> Self {
    self.debounce = Some(config);
    self
  }

  /// Sets (or, with [`None`], clears) the debounce policy.
  #[inline]
  pub const fn set_debounce(&mut self, config: Option<DebounceConfig>) -> &mut Self {
    self.debounce = config;
    self
  }

  /// Consumes these options, yielding the parts the driver wires up: the lower-level
  /// watcher options, the owner→consumer event-channel capacity, the caller→owner
  /// command-mailbox capacity, and the optional debounce policy.
  #[inline]
  pub(crate) fn into_parts(
    self,
  ) -> (
    WatcherOptions,
    NonZeroUsize,
    NonZeroUsize,
    Option<DebounceConfig>,
  ) {
    (
      self.watcher,
      self.event_capacity,
      self.command_capacity,
      self.debounce,
    )
  }
}

impl Default for TributariesOptions {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl From<WatcherOptions> for TributariesOptions {
  /// Adopts lower-level watcher options with debounce left disabled.
  #[inline]
  fn from(watcher: WatcherOptions) -> Self {
    Self::new().with_watcher(watcher)
  }
}
