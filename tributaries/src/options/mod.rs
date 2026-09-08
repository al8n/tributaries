//! Configuration for a [`Tributaries`](crate::Tributaries) watcher — the watcher-global
//! [`TributariesOptions`] and the per-watch [`WatchOptions`] one
//! [`watch`](crate::Tributaries::watch) call carries.

use core::{num::NonZeroUsize, time::Duration};

use std::vec::Vec;

use tributary_proto::glob::Glob;

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
///
/// # Configuration faces
///
/// With the `serde` feature the policy is one object keyed by the field names, every
/// key optional and defaulted from [`new`](Self::new), unknown keys ignored. The two
/// windows are humantime text:
///
/// ```json
/// { "quiet_window": "100ms", "max_hold": "2s", "max_buffered": 4096 }
/// ```
///
/// With the `clap` feature it is a `clap::Args` group of one `--<field>` flag per
/// knob, defaulted the same way:
///
/// ```text
/// $ app --quiet-window 100ms --max-hold 2s --max-buffered 4096
/// ```
///
/// Both doors honor the same clamp the builders do: a
/// [`max_buffered`](Self::max_buffered) of `0` becomes `1`, never a buffer no entry
/// can be admitted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct DebounceConfig {
  #[cfg_attr(feature = "serde", serde(with = "humantime_serde"))]
  #[cfg_attr(
    feature = "clap",
    arg(
      long,
      value_parser = humantime::parse_duration,
      default_value = clap_duration_default(DebounceConfig::DEFAULT_QUIET_WINDOW),
    )
  )]
  quiet_window: Duration,
  #[cfg_attr(feature = "serde", serde(with = "humantime_serde"))]
  #[cfg_attr(
    feature = "clap",
    arg(
      long,
      value_parser = humantime::parse_duration,
      default_value = clap_duration_default(DebounceConfig::DEFAULT_MAX_HOLD),
    )
  )]
  max_hold: Duration,
  #[cfg_attr(feature = "serde", serde(deserialize_with = "de_max_buffered"))]
  #[cfg_attr(
    feature = "clap",
    arg(
      long,
      value_parser = clamped_max_buffered,
      default_value_t = DebounceConfig::DEFAULT_MAX_BUFFERED,
    )
  )]
  max_buffered: usize,
}

/// A flag default rendered from the constant it mirrors, so the flag and the
/// constructor can never drift.
#[cfg(feature = "clap")]
fn clap_duration_default(duration: Duration) -> clap::builder::OsStr {
  clap::builder::Str::from(humantime::format_duration(duration).to_string()).into()
}

/// The one clamp behind both faces of [`DebounceConfig::max_buffered`]: `0` is a cap
/// no entry can be admitted under, and the builders already read it as `1`. A loaded
/// or parsed value must mean what the same number means through
/// [`with_max_buffered`](DebounceConfig::with_max_buffered), so the clamp lives here
/// rather than in one door of three.
#[cfg(any(feature = "serde", feature = "clap"))]
const fn clamp_max_buffered(max_buffered: usize) -> usize {
  if max_buffered == 0 { 1 } else { max_buffered }
}

#[cfg(feature = "serde")]
fn de_max_buffered<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
  D: serde::Deserializer<'de>,
{
  use serde::Deserialize as _;

  usize::deserialize(deserializer).map(clamp_max_buffered)
}

#[cfg(feature = "clap")]
fn clamped_max_buffered(text: &str) -> Result<usize, core::num::ParseIntError> {
  text.parse().map(clamp_max_buffered)
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
///
/// # Configuration faces
///
/// With the `serde` feature the two postures that carry nothing are their own
/// lowercase names and the one that carries a policy is that name against it:
///
/// ```json
/// "inherit"
/// "off"
/// { "custom": { "quiet_window": "100ms" } }
/// ```
///
/// There is no `clap` face: a posture carrying a whole [`DebounceConfig`] is not a
/// value a single flag can name. A command line that wants one flattens
/// [`DebounceConfig`]'s own flags and hands the result to
/// [`WatchOptions::with_debounce`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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

/// Configuration for a [`Tributaries`](crate::Tributaries) watcher — purely the
/// umbrella's own knobs.
///
/// Carries the owner→consumer [`event_capacity`](Self::event_capacity), the
/// caller→owner [`command_capacity`](Self::command_capacity), and an optional
/// [`DebounceConfig`] enabling the settle coalescer (design §6). [`new`](Self::new)
/// returns the defaults — the default capacities and **no** debounce (events pass
/// through untouched). A source's own transport configuration lives with the source:
/// the pure-fs constructor takes the fs watcher's options as its own separate argument
/// (`Tributaries::new(watcher, options)` under the `fs` feature), and a pre-built
/// custom source ([`Tributaries::with_source`](crate::Tributaries::with_source)) was
/// configured by its builder.
///
/// # Configuration faces
///
/// With the `serde` feature the household is one object keyed by the field names,
/// every key optional and defaulted from [`new`](Self::new), unknown keys ignored.
/// `debounce` is the opt-in it is: absent (or `null`) leaves the coalescer off, and a
/// [`DebounceConfig`] object turns it on.
///
/// ```json
/// {
///   "event_capacity": 4096,
///   "debounce": { "quiet_window": "100ms" }
/// }
/// ```
///
/// With the `clap` feature it is a `clap::Args` group carrying the two capacity
/// flags plus [`DebounceConfig`]'s own flags, flattened. The coalescer stays off
/// until one of THOSE flags is given, so it is opt-in on the command line exactly as
/// it is in a document:
///
/// ```text
/// $ app --event-capacity 4096 --quiet-window 100ms
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct TributariesOptions {
  #[cfg_attr(feature = "clap", arg(long, default_value_t = TributariesOptions::DEFAULT_EVENT_CAPACITY))]
  event_capacity: NonZeroUsize,
  #[cfg_attr(feature = "clap", arg(long, default_value_t = TributariesOptions::DEFAULT_COMMAND_CAPACITY))]
  command_capacity: NonZeroUsize,
  #[cfg_attr(feature = "clap", command(flatten))]
  debounce: Option<DebounceConfig>,
}

impl TributariesOptions {
  /// Whether the settle coalescer is enabled by default: [`None`] — it is opt-in, so
  /// out of the box events pass through untouched.
  pub const DEFAULT_DEBOUNCE: Option<DebounceConfig> = None;

  /// The default capacity of the owner→consumer event channel (1024) — the bounded
  /// buffer the owner delivers attributed events through (design backpressure doc).
  /// Mirrors the fs watcher's own default event capacity one level down, generous
  /// enough to absorb ordinary bursts in-order so per-subscription
  /// overflow-to-`Rescan` shedding stays rare.
  pub const DEFAULT_EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

  /// The default capacity of the caller→owner command mailbox (64). Deliberately much
  /// tighter than [`DEFAULT_EVENT_CAPACITY`](Self::DEFAULT_EVENT_CAPACITY): each queued
  /// command owns its key, value, and filter, so the bound caps what abandoned
  /// requests can retain — while 64 in-flight control operations is far
  /// beyond what an orderly consumer keeps outstanding.
  pub const DEFAULT_COMMAND_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

  /// The default options: default capacities, no debounce.
  #[inline]
  pub const fn new() -> Self {
    Self {
      event_capacity: Self::DEFAULT_EVENT_CAPACITY,
      command_capacity: Self::DEFAULT_COMMAND_CAPACITY,
      debounce: Self::DEFAULT_DEBOUNCE,
    }
  }

  /// The capacity of the owner→consumer event channel (design backpressure doc): the
  /// bounded buffer [`next`](crate::Tributaries::next) drains. When it fills (a stalled
  /// consumer), the owner sheds the affected subscription to a dominating
  /// [`Rescan`](crate::EventKind::Rescan) rather than blocking or growing memory
  /// without bound — so this trades buffering headroom against how eagerly a slow
  /// consumer is asked to re-enumerate. Distinct from any capacity the source's own
  /// transport configuration carries (the fs watcher's `event_capacity` bounds the fs
  /// layer's channel one level down).
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

  /// Consumes these options, yielding the parts the driver wires up: the
  /// owner→consumer event-channel capacity, the caller→owner command-mailbox capacity,
  /// and the optional debounce policy.
  #[inline]
  pub(crate) fn into_parts(self) -> (NonZeroUsize, NonZeroUsize, Option<DebounceConfig>) {
    (self.event_capacity, self.command_capacity, self.debounce)
  }
}

impl Default for TributariesOptions {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// The per-ROOT glob words a [`Source`](crate::Source) is armed with — the two
/// seats a subscription's [`WatchOptions`] carries, extracted for the seam
/// ([`Source::arm`](crate::Source::arm)).
///
/// The seats speak for different things, and each is matched against a
/// different string. Patterns are case-insensitive and a `*` never crosses a
/// `/` (see [`Glob`]).
///
/// - [`prune`](Self::prune) subtracts SUBTREES from the watch itself, and it is
///   matched against a **root-relative DIRECTORY path**: the segments between
///   the armed root and a directory, joined with `/`, never with a leading
///   separator. A directory whose path — or any ancestor's, below the root —
///   matches is never enumerated, never armed, never descended, and nothing at
///   or under it is delivered. The root itself is the empty path and matches
///   nothing, so a pattern can never silence the root it is configured on.
///   Empty (the default) prunes nothing.
///
///   It speaks for DIRECTORIES only: a plain FILE whose own name matches a
///   prune pattern is not dropped by it — which files arrive is `include`'s
///   seat — so `**/.*`, written to skip dot-directories, does not silently ban
///   every dotfile in the tree. Because the separator is literal,
///   `**/node_modules` matches `node_modules` at any depth while `a/cache`
///   names one place.
/// - [`include`](Self::include) narrows DELIVERY, changing no coverage, and it
///   is matched against the object's **NAME** — the last segment of its path,
///   alone. So `*.mp4` and `**/*.mp4` are the same seat here, and a pattern
///   carrying a `/` matches nothing at all: there is no `/` in a name to match
///   it against. [`None`] — the default — delivers everything; an EMPTY list is
///   not the same thing, but a seat admitting no file at all. Directories,
///   re-enumeration signals, an object whose class the source did not prove,
///   and a rename whose SOURCE matched are always delivered: the seat fails
///   OPEN, because a folder the consumer never hears about is a hole in its
///   view while an extra event is one it can drop.
///
/// # One root, one set of words — and `prune` is anchored to that root
///
/// These are the words a ROOT is armed with, and the umbrella folds overlapping
/// subscriptions onto shared roots — so every subscription a root serves carries
/// words EQUAL to that root's. A watch whose seats differ from those of the root
/// that would serve it, or from any root it would subsume, is REFUSED with
/// [`WatchError::RootWordsConflict`](crate::WatchError::RootWordsConflict) — never
/// silently re-scoped, and never merged: no union or intersection of two callers'
/// seats is one either of them asked for. Unengaged words ([`new`](Self::new))
/// are just another value here; they conflict with engaged ones. Equality is this
/// type's own [`PartialEq`]: the same patterns, as written, in the same order.
///
/// Equal TEXT is not yet equal MEANING, and the two seats differ on exactly that.
/// [`include`](Self::include) matches an object's NAME, so it says the same thing
/// under any root. [`prune`](Self::prune) matches the root-relative DIRECTORY
/// path, so what it names is fixed by the root it is anchored to — the same
/// pattern under a different root is a different instruction. So a subscription
/// may share a root only when the words are EQUAL **and** either its key IS that
/// root's key, or neither side carries a `prune` seat:
///
/// - a watch DEEPER than the root already covering it would ride words written
///   for the shallower root, so `prune = ["sub"]` there would mean the covering
///   root's `sub`, not its own;
/// - a WIDEN always moves the anchor the other way — the retained words are
///   re-based onto the wider key — so `prune = ["sub"]` on a root at `/r/sub`
///   comes to name the WHOLE of that root once the watch widens to `/r`,
///   silencing a subscription that stays published.
///
/// Both are refused as
/// [`WordsConflict::Anchored`](crate::WordsConflict::Anchored); differing text is
/// [`WordsConflict::Differ`](crate::WordsConflict::Differ). An `include`-only
/// household is unaffected at any depth.
///
/// The refusal is decided before anything is armed, disarmed or re-pointed, so a
/// conflicting watch costs no coverage and owes no
/// [`Rescan`](crate::EventKind::Rescan). A narrowing that must be this
/// subscription's own whatever else is watched around it belongs in the
/// per-subscription [`Filter`](crate::Filter), which gates delivery alone — and
/// carries no anchor, so it survives every re-scoping the root does.
///
/// # A source that cannot honour a seat must SAY so
///
/// These are words the umbrella hands down, not a filter it applies afterwards:
/// nothing above the seam re-checks them, so a source that ignores one delivers
/// events the caller asked not to receive — or watches a subtree the caller
/// asked it not to enter — with nothing anywhere to notice. The stock
/// filesystem binding honours both. A source that cannot honour one MUST
/// document that in its own [`Source`](crate::Source) implementation's docs, so
/// a caller reads the limitation where it configures the seat rather than
/// inferring it from events that should not have arrived.
///
/// The default ([`new`](Self::new)) is both seats unengaged, which is exactly
/// the behaviour every source had before the seats existed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootGlobs {
  prune: Vec<Glob>,
  include: Option<Vec<Glob>>,
}

impl RootGlobs {
  /// The unengaged words: prune nothing, deliver every file.
  #[inline]
  pub const fn new() -> Self {
    Self {
      prune: Vec::new(),
      include: None,
    }
  }

  /// Whether NEITHER seat is engaged — the [`new`](Self::new) words, which ask a
  /// source for exactly what it did before the seats existed.
  #[inline]
  pub fn is_unengaged(&self) -> bool {
    self.prune.is_empty() && self.include.is_none()
  }

  /// The subtrees this root never descends into. Empty is the default. Matched
  /// against root-relative DIRECTORY paths; see the type docs for what a match
  /// subtracts and what it does not.
  #[inline]
  pub fn prune(&self) -> &[Glob] {
    self.prune.as_slice()
  }

  /// Returns these words with the pruned subtrees set.
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
  /// a `/` admits nothing.
  #[inline]
  pub fn include(&self) -> Option<&[Glob]> {
    self.include.as_deref()
  }

  /// Returns these words with delivery narrowed to the given file patterns.
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

  /// Returns these words delivering every file again — the [`None`] seat.
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
}

/// Per-watch options for one [`watch`](crate::Tributaries::watch) call: the fan-out
/// [`Interest`] gate (design §5), the admission [`Filter`] (design §7), the
/// [`Debounce`] posture (design §6), and the two per-root glob seats
/// ([`prune`](Self::prune) / [`include`](Self::include), carried down to the source as
/// [`RootGlobs`]).
///
/// [`new`](Self::new) is the deliver-everything default — every kind, every change,
/// the watcher-global debounce, no subtree pruned, every file delivered — and narrowing
/// is the opt-in act, one `with_*` builder per knob. Not to be confused with the fs
/// watcher's transport-level `WatcherOptions` (an `fs`-feature item), which configures a
/// whole watcher rather than one watch.
///
/// # Three of the knobs narrow DELIVERY; one re-scopes the WATCH
///
/// The [`Interest`] gate, the [`Filter`] and the [`Debounce`] posture are the
/// umbrella's own, applied to a root armed at the source's widest policy (design §4) —
/// so they narrow what this *subscription* sees and never what the underlying watch
/// collects, and two subscriptions sharing a root can hold entirely different ones.
///
/// The glob seats are not that. They are handed to [`Source::arm`](crate::Source::arm)
/// as the words the root itself is armed with, so [`prune`](Self::prune) subtracts
/// coverage rather than filtering it — which is exactly why it can keep a watcher out
/// of a `node_modules` tree instead of merely dropping its events. [`prune`](Self::prune)
/// is matched against root-relative DIRECTORY paths and [`include`](Self::include) against
/// the object's NAME alone; see [`RootGlobs`] for both seats in full.
///
/// The consequence to hold: they are per-ROOT, and roots are shared — so ALL subscriptions
/// sharing a root share its words. The per-subscription [`Filter`] narrows delivery further,
/// on top of them; a watch whose own seats CONFLICT with the words of the root that would
/// serve it (or of any root it would subsume) is refused with
/// [`WatchError::RootWordsConflict`](crate::WatchError::RootWordsConflict), never silently
/// re-scoped. A caller that needs a narrowing which is unconditionally its own, whatever else
/// is watched around it, wants the [`Filter`].
///
/// [`prune`](Self::prune) additionally binds a watch to ONE anchor: it is matched
/// root-relative, so a subscription carrying one may share a root only at that root's own key.
/// A watch deeper than its covering root, and a widen over any pruned root, are refused
/// ([`WordsConflict::Anchored`](crate::WordsConflict::Anchored)) even when the pattern text is
/// identical — see [`RootGlobs`]. [`include`](Self::include) matches names and carries no
/// anchor, so it is shareable at any depth.
///
/// # Cloning shares the [`Filter`] slot
///
/// `Clone` clones each field, and [`Filter`]'s own [`Clone` contract](Filter#impl-Clone-for-Filter<C>)
/// shares the same swappable predicate slot — a [`swap`](Filter::swap) through any
/// handle is observed by every holder. So a cloned `WatchOptions` (and every watch
/// committed from either copy) shares one live-swappable filter; pass a fresh
/// [`Filter`] via [`with_filter`](Self::with_filter) for an independent one.
///
/// # Configuration faces
///
/// With the `serde` feature the subscription is one object keyed by the field names,
/// every key optional and defaulted from [`new`](Self::new) — so the empty document
/// is the deliver-everything default and a key is a narrowing. The two glob seats are
/// lists of plain strings, and an invalid pattern is a document error rather than a
/// value that matches nothing later:
///
/// ```json
/// {
///   "interest": ["created", "modified"],
///   "debounce": "off",
///   "prune": ["**/node_modules"],
///   "include": ["**/*.{mp4,mov}"]
/// }
/// ```
///
/// The [`Filter`] is on neither face and never round-trips: it is a caller's own
/// closure, which no document can name. It is skipped on the way out and comes back
/// [`Filter::all`] — a loaded `WatchOptions` admits everything its [`Interest`]
/// admits, and a caller that wants a predicate installs it afterwards with
/// [`with_filter`](Self::with_filter). Neither face constrains `C`.
///
/// With the `clap` feature it is a `clap::Args` group of [`Interest`]'s own flags plus
/// a repeatable `--prune` and `--include`, once per pattern; `--include` given no times
/// at all is [`None`] (deliver every file), which is what makes the seat's ABSENCE
/// expressible from a command line. The [`Debounce`] posture is skipped there:
/// [`Debounce::Custom`] carries a whole [`DebounceConfig`], which one flag cannot name
/// (see [`Debounce`]).
///
/// ```text
/// $ app --moved=false --removed=false --prune '**/node_modules' --include '**/*.mp4'
/// ```
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, bound = ""))]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct WatchOptions<C> {
  #[cfg_attr(feature = "clap", command(flatten))]
  interest: Interest,
  #[cfg_attr(feature = "serde", serde(skip))]
  #[cfg_attr(feature = "clap", arg(skip))]
  filter: Filter<C>,
  #[cfg_attr(feature = "clap", arg(skip))]
  debounce: Debounce,
  #[cfg_attr(feature = "clap", arg(long))]
  prune: Vec<Glob>,
  #[cfg_attr(feature = "clap", arg(long))]
  include: Option<Vec<Glob>>,
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
      prune: Vec::new(),
      include: None,
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

  /// The subtrees a root armed for this subscription never descends into — the
  /// [`prune`](RootGlobs::prune) half of the per-root words handed to
  /// [`Source::arm`](crate::Source::arm), matched against root-relative
  /// DIRECTORY paths. Empty (the default) prunes nothing.
  ///
  /// Unlike the [`interest`](Self::interest) gate and the
  /// [`filter`](Self::filter), this is NOT a delivery narrowing the umbrella
  /// applies on top of a full watch: it re-scopes the underlying watch itself,
  /// so a pruned subtree is never even covered — and it is the ROOT's, shared
  /// with every subscription that root serves. See [`RootGlobs`].
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
  /// every file: the [`include`](RootGlobs::include) half of the per-root words
  /// handed to [`Source::arm`](crate::Source::arm), matched against the object's
  /// NAME alone (so a pattern carrying a `/` admits nothing). An EMPTY list is
  /// not the same thing but a seat admitting no file at all (see [`RootGlobs`]
  /// for what the seat always admits regardless).
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

  /// The two glob seats as the [`RootGlobs`] a [`Source`](crate::Source) is
  /// armed with — the same words the driver takes at commit, read here without
  /// consuming the options.
  #[inline]
  pub fn root_globs(&self) -> RootGlobs {
    RootGlobs {
      prune: self.prune.clone(),
      include: self.include.clone(),
    }
  }

  /// Consumes these options, yielding the parts the driver commits: the fan-out
  /// interest (recorded in the subsumer's plan), the admission filter, the debounce
  /// posture (the latter two registered adjacently at commit), and the per-root
  /// [`RootGlobs`] the arm carries down to the source.
  #[inline]
  pub(crate) fn into_parts(self) -> (Interest, Filter<C>, Debounce, RootGlobs) {
    (
      self.interest,
      self.filter,
      self.debounce,
      RootGlobs {
        prune: self.prune,
        include: self.include,
      },
    )
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
      prune: self.prune.clone(),
      include: self.include.clone(),
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
      .field("prune", &self.prune)
      .field("include", &self.include)
      .finish()
  }
}
