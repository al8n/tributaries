//! Configuration for a [`Tributaries`](crate::Tributaries) watcher — the watcher-global
//! [`TributariesOptions`] and the per-watch [`WatchOptions`] one
//! [`watch`](crate::Tributaries::watch) call carries.

use core::{num::NonZeroUsize, time::Duration};

use tributary_fs::WatcherOptions;

use crate::{filter::Filter, interest::Interest};

#[cfg(test)]
mod tests;

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
/// A [`DebounceConfig`] is opt-in at two levels: the watcher-global default
/// ([`TributariesOptions::debounce`]) and a per-subscription override
/// ([`WatchOptions::with_debounce`], resolved through [`Debounce`]). Absent both —
/// no global config and no [`Debounce::Custom`] override anywhere — events pass
/// through untouched, and the coalescer is never even instantiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebounceConfig {
  quiet_window: Duration,
  max_hold: Duration,
  max_buffered: usize,
}

impl DebounceConfig {
  /// The default settle window (50 ms) — long enough to coalesce the storm of
  /// writes an editor-save or a `cp` emits, short enough to feel immediate.
  pub const DEFAULT_QUIET_WINDOW: Duration = Duration::from_millis(50);

  /// The default hold ceiling (500 ms) — the longest a continuously-touched path's
  /// coalesced state is held before it is forced out.
  pub const DEFAULT_MAX_HOLD: Duration = Duration::from_millis(500);

  /// The default cap on buffered coalescer entries (1024, mirroring the event
  /// channel's default) — the structural memory bound in front of the bounded event
  /// channel. See [`max_buffered`](Self::max_buffered).
  pub const DEFAULT_MAX_BUFFERED: usize = 1024;

  /// The default debounce policy.
  #[inline]
  pub const fn new() -> Self {
    Self {
      quiet_window: Self::DEFAULT_QUIET_WINDOW,
      max_hold: Self::DEFAULT_MAX_HOLD,
      max_buffered: Self::DEFAULT_MAX_BUFFERED,
    }
  }

  /// The cap on BUFFERED coalescer entries: the settle buffer sits in FRONT of the
  /// bounded event channel, so without its own bound a high-cardinality burst under a
  /// long window could grow memory without limit and the overflow-to-`Rescan` machinery
  /// would never engage. When an admission would open an entry PAST a cap, the affected
  /// subscription is shed instead: its buffered entries are purged and a dominating
  /// parked [`Rescan`](crate::EventKind::Rescan) is owed through the same
  /// loss-accounting path as a full event channel — bounded memory, no silent loss.
  /// Collapsing onto an already-buffered entry never counts against any cap.
  ///
  /// Which entries it counts depends on where the config sits: as the watcher-global
  /// default ([`TributariesOptions::debounce`]) it is the coalescer-wide structural
  /// bound across ALL subscriptions; as a per-subscription
  /// [`Debounce::Custom`] policy it additionally caps THAT subscription's own fresh
  /// entries (the coalescer-wide bound stays in force — [`DEFAULT_MAX_BUFFERED`](Self::DEFAULT_MAX_BUFFERED)
  /// when no global config exists to read one from).
  #[inline]
  pub const fn max_buffered(&self) -> usize {
    self.max_buffered
  }

  /// Returns this policy with the buffered-entry cap set (0 is clamped to 1).
  #[inline]
  #[must_use]
  pub const fn with_max_buffered(mut self, max_buffered: usize) -> Self {
    self.max_buffered = if max_buffered == 0 { 1 } else { max_buffered };
    self
  }

  /// Sets the buffered-entry cap (0 is clamped to 1).
  #[inline]
  pub const fn set_max_buffered(&mut self, max_buffered: usize) -> &mut Self {
    self.max_buffered = if max_buffered == 0 { 1 } else { max_buffered };
    self
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

/// A subscription's debounce posture, resolved against the watcher-global default
/// ([`TributariesOptions::debounce`]) at delivery time.
///
/// Carried per watch on [`WatchOptions::with_debounce`], it makes
/// disabled-vs-inherit-vs-custom a first-class three-way state: [`Off`](Self::Off) can
/// switch settling off for one subscription while the global coalescer stays on, and
/// [`Custom`](Self::Custom) can switch it on (with its own windows) while the global
/// default is off — neither expressible with a bare `Option<DebounceConfig>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Debounce {
  /// Follow the watcher-global policy ([`TributariesOptions::debounce`]) — the default.
  #[default]
  Inherit,
  /// Raw pass-through for this subscription, even when the watcher-global coalescer is
  /// on: its events ride through undelayed and uncollapsed, in admission order.
  Off,
  /// This subscription's own settle policy, overriding the watcher-global default —
  /// including *enabling* settling when the watcher-global debounce is off (which
  /// instantiates the coalescer on first use).
  Custom(DebounceConfig),
}

impl Debounce {
  /// Whether this is [`Inherit`](Self::Inherit) — follow the watcher-global policy.
  #[inline]
  pub const fn is_inherit(&self) -> bool {
    matches!(self, Self::Inherit)
  }

  /// Whether this is [`Off`](Self::Off) — raw pass-through for this subscription.
  #[inline]
  pub const fn is_off(&self) -> bool {
    matches!(self, Self::Off)
  }

  /// Whether this is [`Custom`](Self::Custom) — the subscription's own settle policy.
  #[inline]
  pub const fn is_custom(&self) -> bool {
    matches!(self, Self::Custom(_))
  }

  /// The subscription's own settle policy, when this is [`Custom`](Self::Custom).
  #[inline]
  pub const fn as_custom(&self) -> Option<&DebounceConfig> {
    match self {
      Self::Custom(config) => Some(config),
      _ => None,
    }
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
  /// requests can retain — while 64 in-flight control operations is far
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

  /// The capacity of the caller→owner command mailbox: the bounded queue
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

  /// The debounce policy, if the settle coalescer is enabled — the watcher-global
  /// **default** every subscription inherits unless its own
  /// [`WatchOptions::with_debounce`] overrides it (see [`Debounce`]).
  #[inline]
  pub const fn debounce_config(&self) -> Option<DebounceConfig> {
    self.debounce
  }

  /// Returns these options with the settle coalescer enabled under `config` — the
  /// watcher-global default a per-watch [`Debounce`] posture resolves against.
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

/// Per-watch options for one [`watch`](crate::Tributaries::watch) call: the fan-out
/// [`Interest`] gate (design §5), the admission [`Filter`] (design §7), and the
/// [`Debounce`] posture (design §6).
///
/// [`new`](Self::new) is the deliver-everything default — every kind, every change,
/// the watcher-global debounce — and narrowing is the opt-in act, one `with_*` builder
/// per knob. Not to be confused with the fs watcher's transport-level
/// [`WatcherOptions`]: these options configure one *subscription*, never the underlying
/// kernel watch (every root is armed with the source's widest policy, design §4).
///
/// # Cloning shares the [`Filter`] slot
///
/// `Clone` clones each field, and [`Filter`]'s own [`Clone` contract](Filter#impl-Clone-for-Filter<C>)
/// shares the same swappable predicate slot — a [`swap`](Filter::swap) through any
/// handle is observed by every holder. So a cloned `WatchOptions` (and every watch
/// committed from either copy) shares one live-swappable filter; pass a fresh
/// [`Filter`] via [`with_filter`](Self::with_filter) for an independent one.
pub struct WatchOptions<C> {
  interest: Interest,
  filter: Filter<C>,
  debounce: Debounce,
}

impl<C> WatchOptions<C> {
  /// The default fan-out interest: [`Interest::all`] — deliver every kind, narrowing is
  /// the opt-in act (matching [`Filter::all`] as the filter default).
  pub const DEFAULT_INTEREST: Interest = Interest::all();

  /// The default debounce posture: [`Debounce::Inherit`] — follow the watcher-global
  /// policy.
  pub const DEFAULT_DEBOUNCE: Debounce = Debounce::Inherit;

  /// The default options: deliver everything ([`Interest::all`]), admit everything
  /// ([`Filter::all`]), inherit the watcher-global debounce ([`Debounce::Inherit`]).
  #[inline]
  pub fn new() -> Self {
    Self {
      interest: Self::DEFAULT_INTEREST,
      filter: Filter::all(),
      debounce: Self::DEFAULT_DEBOUNCE,
    }
  }

  /// The subscription's fan-out [`Interest`] gate (design §5): which **projected**
  /// delivery kinds it wants. It narrows delivery only, never the underlying source
  /// watch.
  #[inline]
  pub const fn interest(&self) -> Interest {
    self.interest
  }

  /// Returns these options with the fan-out interest gate set.
  #[inline]
  #[must_use]
  pub const fn with_interest(mut self, interest: Interest) -> Self {
    self.interest = interest;
    self
  }

  /// Sets the fan-out interest gate.
  #[inline]
  pub const fn set_interest(&mut self, interest: Interest) -> &mut Self {
    self.interest = interest;
    self
  }

  /// The subscription's admission [`Filter`] (design §7): a non-`Rescan` event is
  /// delivered only if the filter admits it. The filter is live-swappable — keep a
  /// [`clone`](Filter::clone) (it shares the swappable slot) and [`swap`](Filter::swap)
  /// it to re-scope delivery without a re-watch.
  #[inline]
  pub const fn filter(&self) -> &Filter<C> {
    &self.filter
  }

  /// Returns these options with the admission filter set.
  #[inline]
  #[must_use]
  pub fn with_filter(mut self, filter: Filter<C>) -> Self {
    self.filter = filter;
    self
  }

  /// Sets the admission filter.
  #[inline]
  pub fn set_filter(&mut self, filter: Filter<C>) -> &mut Self {
    self.filter = filter;
    self
  }

  /// The subscription's [`Debounce`] posture (design §6), resolved against the
  /// watcher-global default ([`TributariesOptions::debounce`]) at delivery time.
  #[inline]
  pub const fn debounce(&self) -> Debounce {
    self.debounce
  }

  /// Returns these options with the debounce posture set.
  #[inline]
  #[must_use]
  pub const fn with_debounce(mut self, debounce: Debounce) -> Self {
    self.debounce = debounce;
    self
  }

  /// Sets the debounce posture.
  #[inline]
  pub const fn set_debounce(&mut self, debounce: Debounce) -> &mut Self {
    self.debounce = debounce;
    self
  }

  /// Consumes these options, yielding the parts the driver commits: the fan-out
  /// interest (recorded in the subsumer's plan), the admission filter, and the debounce
  /// posture (the latter two registered adjacently at commit).
  #[inline]
  pub(crate) fn into_parts(self) -> (Interest, Filter<C>, Debounce) {
    (self.interest, self.filter, self.debounce)
  }
}

impl<C> Default for WatchOptions<C> {
  /// The deliver-everything default ([`WatchOptions::new`]).
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl<C> Clone for WatchOptions<C> {
  /// Clones every knob; the [`Filter`] clone shares the same swappable predicate slot
  /// (its own [`Clone` contract](Filter#impl-Clone-for-Filter<C>)), so a
  /// [`swap`](Filter::swap) through either copy is observed by both. Implemented
  /// manually (like [`Filter`]'s) so cloning never demands `C: Clone`.
  #[inline]
  fn clone(&self) -> Self {
    Self {
      interest: self.interest,
      filter: self.filter.clone(),
      debounce: self.debounce,
    }
  }
}

impl<C> core::fmt::Debug for WatchOptions<C> {
  /// Reports every knob (the filter as its opaque placeholder); implemented manually
  /// (like [`Filter`]'s) so formatting never demands `C: Debug`.
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("WatchOptions")
      .field("interest", &self.interest)
      .field("filter", &self.filter)
      .field("debounce", &self.debounce)
      .finish()
  }
}
