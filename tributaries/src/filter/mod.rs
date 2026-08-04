//! The per-subscription admission [`Filter`] — a live-swappable predicate over a change's
//! **pre-delivery** attributes (design §7).
//!
//! A `Filter` decides, per subscription, whether an attributed change is delivered to its caller:
//! [`fan_out`](crate::route::fan_out) consults it as an **additional** admission gate, *after* the
//! coverage ancestor test (design §5). It is a predicate over a [`FilterInput`] — the change's
//! located key, its kind, and (for the fs source) its path — the fully-typed `Filter<L>`
//! location-parsing generic is deferred (design §7). The predicate lives behind an
//! [`arc_swap::ArcSwap`] so it can be **hot-swapped** at any time without re-arming the kernel
//! watch (a re-watch): the driver holds each subscription's `Filter`, a caller that kept a clone
//! [`swap`](Filter::swap)s the closure in place, and the next change admitted sees the new
//! predicate.
//!
//! That slot is shared by every clone, so a `swap` through it is a **whole-slot** act — right for
//! a caller re-scoping its own subscriptions, wrong as a way to retire one subscription's gate.
//! The driver never writes to it: the containment below is recorded per subscription, in the
//! driver's own state, so one subscription's panicking predicate cannot change what a sibling
//! sharing the same `Filter` admits.
//!
//! # The contract: a pre-delivery predicate over *what* changed, never *when* or *whose*
//!
//! A filter inspects only the attributes a change carries **before** the umbrella turns it into a
//! delivery: the located [`key`](FilterInput::key), the [`kind`](FilterInput::kind), and the
//! [`location`](FilterInput::location) / [`path`](FilterInput::path). It **cannot** observe the
//! delivered [`Event`](crate::Event)'s [`epoch`](crate::Event::epoch) or its
//! [`value`](crate::Event::value): both are assigned *after* admission — the epoch is the
//! per-subscription monotone dominance stamp the driver rebases on (`stamp` runs only for an
//! admitted delivery, so a filtered-out one never perturbs a subscription's epoch space), and the
//! value is the caller's own attribution, baked on at emit time. At the moment the filter runs, a
//! candidate still carries the *raw* source epoch (which restarts at 0 on every re-point) and an
//! **unbaked** value, so a predicate that read them would mis-evaluate. [`FilterInput`] removes
//! that footgun by construction: those attributes are simply not reachable from a filter.
//!
//! # A `Rescan` always bypasses the filter
//!
//! A [`Rescan`](EventKind::Rescan) is a coverage-loss signal whose
//! [`epoch`](crate::Event::epoch) dominates everything before it, so it must reach every
//! subscriber unconditionally (design §7/§8). The filter is therefore **never** consulted for a
//! `Rescan`: [`fan_out`](crate::route::fan_out) delivers it before it ever reaches
//! [`admits`](Filter::admits). `admits` itself is a pure predicate — it does not special-case the
//! kind — because the bypass is enforced one level up, at the single point where coverage and
//! filter admission are both decided.

use std::sync::Arc;

use arc_swap::ArcSwap;
use tributary_proto::Location;

use crate::event::EventKind;

/// The pre-delivery view a [`Filter`] predicate inspects (design §7): the attributes of a change
/// known **before** the umbrella stamps the delivery's epoch and bakes its owning value.
///
/// It exposes only *what* changed and *where* — the located [`key`](Self::key), the
/// [`kind`](Self::kind), the [`location`](Self::location), and (for the fs source) the
/// [`path`](Self::path) — deliberately **not** the delivered [`Event`](crate::Event)'s
/// [`epoch`](crate::Event::epoch) or [`value`](crate::Event::value), which are assigned only after
/// admission. Because a candidate is still carrying the raw source epoch (restarting at 0 on a
/// re-point) and an unbaked value when the filter runs, hiding both is what keeps a filter from
/// mis-evaluating on a provisional stamp or an absent value (see [`Filter`] for the contract).
///
/// Borrowed from the change under evaluation for the duration of one [`admits`](Filter::admits)
/// call — cheap to `Copy`, holds no owned state.
#[derive(Debug, Clone, Copy)]
pub struct FilterInput<'a, C> {
  key: &'a [C],
  kind: &'a EventKind<C>,
  location: &'a Location,
}

impl<'a, C> FilterInput<'a, C> {
  /// Builds a pre-delivery view over a change's located key, kind, and location. Crate-private:
  /// the driver constructs it from the projected delivery at the fan-out admission gate.
  #[inline]
  pub(crate) fn new(key: &'a [C], kind: &'a EventKind<C>, location: &'a Location) -> Self {
    Self {
      key,
      kind,
      location,
    }
  }

  /// The change's located key — its components in `C`-space (for the fs source, the change path's
  /// components). The same coordinate coverage keys on.
  #[inline]
  #[must_use]
  pub fn key(&self) -> &[C] {
    self.key
  }

  /// What changed — the **already-projected** delivery kind (design §5): a move-out reads as
  /// `Removed`, a move-in as `Created`, so a filter gates on the kind the caller will actually
  /// receive. A [`Rescan`](EventKind::Rescan) never reaches here (it bypasses the filter).
  #[inline]
  #[must_use]
  pub fn kind(&self) -> &EventKind<C> {
    self.kind
  }

  /// The change's location relative to **the key this filter's subscription watches** —
  /// the same rebased coordinate the delivered
  /// [`Event::location`](crate::Event::location) carries, and for the same reason: the
  /// physical armed root underneath a subscription is mutable watch-set topology, so a
  /// predicate written against it would silently change meaning when an unrelated caller
  /// watches an ancestor. Against the subscription's own key, a depth or location test
  /// written once keeps admitting exactly what it admitted.
  #[inline]
  #[must_use]
  pub fn location(&self) -> &Location {
    self.location
  }
}

impl FilterInput<'_, std::ffi::OsString> {
  /// The change's absolute path — the fs-source convenience over [`key`](Self::key),
  /// reconstructed from the located key's `OsString` components (mirroring
  /// [`Event::path`](crate::Event::path)).
  ///
  /// This allocates a fresh [`PathBuf`](std::path::PathBuf) from the key components on every call;
  /// [`key`](Self::key) is the allocation-free `&[C]` accessor for hot paths.
  #[inline]
  #[must_use]
  pub fn path(&self) -> std::path::PathBuf {
    self.key.iter().collect()
  }
}

/// The boxed predicate a [`Filter`] holds: a `Send + Sync` closure over the pre-delivery
/// [`FilterInput`]. `Send + Sync` is mandatory — the driver swaps it across the async boundary and
/// reads it from whatever task polls `next()`.
type Predicate<C> = Arc<dyn Fn(&FilterInput<'_, C>) -> bool + Send + Sync>;

/// The state every clone of one [`Filter`] shares: the hot-swappable predicate, and whether
/// the caller ever asked for a predicate of its own.
struct FilterSlot<C> {
  predicate: ArcSwap<Predicate<C>>,
  /// `false` only for a filter that is still the [`all`](Filter::all) default — a predicate
  /// the driver supplies, whose evaluation is a constant `true` and can never unwind.
  ///
  /// The driver reads this to decide whether a watch is asking for filtering *at all*, so
  /// that a watcher whose filter plane has been retired can refuse the watches that would
  /// otherwise silently go unfiltered while leaving unfiltered ones — which lose nothing —
  /// admitted. It rides the shared slot rather than the handle, exactly as the predicate
  /// does: a [`swap`](Filter::swap) is a whole-slot act, so a default filter that any holder
  /// swaps a predicate into is custom from then on, for every holder.
  ///
  /// Latching (never cleared by a later swap back to an admit-all closure) is deliberate: the
  /// flag records that caller code has been installed here, and a caller that swapped once can
  /// swap again at any moment.
  custom: std::sync::atomic::AtomicBool,
}

/// A live-swappable admission predicate for one subscription (design §7), over a change's
/// pre-delivery [`FilterInput`].
///
/// Constructed with [`all`](Filter::all) (admit everything — the default) or [`new`](Filter::new)
/// (a custom predicate), and mutated in place with [`swap`](Filter::swap) — no re-watch, so a
/// caller can re-scope what a live subscription delivers at any time. The driver calls
/// [`admits`](Filter::admits) as the fan-out admission gate for every non-`Rescan` change (a
/// `Rescan` bypasses it unconditionally — coverage loss is never filtered away, design §7/§8).
///
/// The predicate sees only pre-delivery attributes ([`key`](FilterInput::key) /
/// [`kind`](FilterInput::kind) / [`path`](FilterInput::path)), never the delivered event's epoch
/// or value — both are assigned only *after* admission, so a filter cannot observe them.
///
/// Cloning a `Filter` (or sharing one behind an [`Arc`]) shares the same swappable slot: a
/// [`swap`](Filter::swap) through any handle is observed by every holder, which is what lets the
/// driver keep a subscription's filter while the caller keeps a handle to re-scope it live.
pub struct Filter<C> {
  slot: Arc<FilterSlot<C>>,
}

impl<C> Filter<C> {
  /// A filter that admits **every** change — the default (design §7). No predicate is evaluated;
  /// a subscription with this filter is gated only by key coverage.
  #[inline]
  #[must_use]
  pub fn all() -> Self {
    Self::from_predicate(|_| true, false)
  }

  /// A filter admitting exactly the changes for which `predicate` returns `true`.
  ///
  /// `predicate` sees a [`FilterInput`] — the change's [`key`](FilterInput::key),
  /// [`kind`](FilterInput::kind), and [`path`](FilterInput::path), but **not** the delivered
  /// event's epoch or value (design §7). It must be `Send + Sync`
  /// (the driver evaluates it from the polling task and may [`swap`](Filter::swap) it across the
  /// async boundary). A [`Rescan`](EventKind::Rescan) never reaches it — coverage
  /// loss bypasses the filter (design §7/§8).
  ///
  /// # Callback contract
  ///
  /// The predicate is evaluated **inline in the watcher's single owner task**, once per candidate
  /// delivery per subscription. That task also serves every other subscription, the source pump,
  /// and the control plane, so the predicate must be:
  ///
  /// - **bounded and non-blocking.** It must not perform I/O, take a lock another task can hold,
  ///   or otherwise park. An actor cannot preempt a synchronous function running on its own
  ///   thread, so a predicate that does not return holds the whole watcher — its
  ///   [`close`](crate::Tributaries::close) included — for as long as it runs. This is a
  ///   requirement on the caller, not something the watcher can enforce.
  /// - **panic-free — though a panic is contained.** If the predicate unwinds, the watcher does
  ///   not: the unwind is caught, the change is ADMITTED (over-delivery, never silent loss), the
  ///   admission gate **of the subscription whose delivery it unwound on** is permanently retired
  ///   so the panicking code is never entered again for it, and that subscription is owed a
  ///   dominating [`Rescan`](EventKind::Rescan) telling its consumer to re-enumerate. Every other
  ///   subscription is unaffected — including one registered with a **clone of this same
  ///   filter**: the retirement is recorded per subscription in the watcher's own state, never by
  ///   writing admit-everything into the shared predicate slot, so a filter value reused across
  ///   subscriptions never carries one of them's panic into another's admission.
  #[inline]
  #[must_use]
  pub fn new(predicate: impl Fn(&FilterInput<'_, C>) -> bool + Send + Sync + 'static) -> Self {
    Self::from_predicate(predicate, true)
  }

  fn from_predicate(
    predicate: impl Fn(&FilterInput<'_, C>) -> bool + Send + Sync + 'static,
    custom: bool,
  ) -> Self {
    Self {
      slot: Arc::new(FilterSlot {
        predicate: ArcSwap::from_pointee(Arc::new(predicate) as Predicate<C>),
        custom: std::sync::atomic::AtomicBool::new(custom),
      }),
    }
  }

  /// Whether caller code has ever been installed in this filter's shared slot — see
  /// [`FilterSlot::custom`].
  #[inline]
  pub(crate) fn is_custom(&self) -> bool {
    self.slot.custom.load(std::sync::atomic::Ordering::Relaxed)
  }

  /// Hot-swaps the predicate in place — every subsequent [`admits`](Self::admits) uses
  /// `predicate`, without re-arming the kernel watch (design §7).
  ///
  /// The swap is atomic and lock-free: a change being admitted concurrently observes either the
  /// old or the new predicate, never a torn state. A handle the caller retained (or the driver
  /// holds) sees the change immediately — the slot is shared.
  #[inline]
  pub fn swap(&self, predicate: impl Fn(&FilterInput<'_, C>) -> bool + Send + Sync + 'static) {
    // Marked custom BEFORE the predicate is installed, so no window exists in which caller
    // code is reachable through this slot while the slot still reads as the admit-all
    // default.
    self
      .slot
      .custom
      .store(true, std::sync::atomic::Ordering::Relaxed);
    self
      .slot
      .predicate
      .store(Arc::new(Arc::new(predicate) as Predicate<C>));
  }

  /// Whether this filter admits `input` — the fan-out admission gate (design §5/§7).
  ///
  /// A pure evaluation of the current predicate over the change's pre-delivery attributes; it does
  /// **not** special-case a [`Rescan`](EventKind::Rescan), because the unconditional
  /// Rescan bypass is enforced at fan-out — before a change reaches here (design §7/§8).
  #[inline]
  #[must_use]
  pub fn admits(&self, input: &FilterInput<'_, C>) -> bool {
    (self.slot.predicate.load())(input)
  }
}

impl<C> Clone for Filter<C> {
  /// Shares the same swappable slot — a [`swap`](Filter::swap) through either handle is seen by
  /// both (the point of the shared driver/caller split; see the type docs).
  #[inline]
  fn clone(&self) -> Self {
    Self {
      slot: Arc::clone(&self.slot),
    }
  }
}

impl<C> Default for Filter<C> {
  /// The default filter admits everything ([`Filter::all`]).
  #[inline]
  fn default() -> Self {
    Self::all()
  }
}

impl<C> core::fmt::Debug for Filter<C> {
  /// The predicate is an opaque closure with no meaningful representation, so this reports only
  /// the type — enough to place a `Filter` in a larger `Debug` dump.
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Filter").finish_non_exhaustive()
  }
}

#[cfg(test)]
mod tests;
