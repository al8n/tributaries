//! Configuration for a [`Tributaries`](crate::Tributaries) watcher.

use core::time::Duration;

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
/// `tributary-fs` watcher) and an optional [`DebounceConfig`] enabling the settle
/// coalescer (design §6). [`new`](Self::new) returns the defaults — the default
/// watcher options and **no** debounce (events pass through untouched).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TributariesOptions {
  watcher: WatcherOptions,
  debounce: Option<DebounceConfig>,
}

impl TributariesOptions {
  /// Whether the settle coalescer is enabled by default: [`None`] — it is opt-in, so
  /// out of the box events pass through untouched.
  pub const DEFAULT_DEBOUNCE: Option<DebounceConfig> = None;

  /// The default options: default [`WatcherOptions`], no debounce.
  #[inline]
  pub fn new() -> Self {
    Self {
      watcher: WatcherOptions::new(),
      debounce: Self::DEFAULT_DEBOUNCE,
    }
  }

  /// The lower-level watcher options forwarded to the wrapped `tributary-fs` watcher.
  #[inline]
  pub const fn watcher(&self) -> &WatcherOptions {
    &self.watcher
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
  /// watcher options and the optional debounce policy.
  #[inline]
  pub(crate) fn into_parts(self) -> (WatcherOptions, Option<DebounceConfig>) {
    (self.watcher, self.debounce)
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
