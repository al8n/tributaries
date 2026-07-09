//! The per-subscription admission [`Filter`] — a live-swappable predicate over a change's
//! **pre-delivery** attributes (design §7).
//!
//! A `Filter` decides, per subscription, whether an attributed change is delivered to its caller:
//! [`fan_out`](crate::route::fan_out) consults it as an **additional** admission gate, *after* the
//! coverage ancestor test (design §5). It is a predicate over a [`FilterInput`] — the change's
//! located key, its kind, and (for the fs source) its path — the fully-typed `Filter<L>`
//! location-parsing generic is deferred to M2 (design §7). The predicate lives behind an
//! [`arc_swap::ArcSwap`] so it can be **hot-swapped** at any time without re-arming the kernel
//! watch (a re-watch): the driver holds each subscription's `Filter` and [`swap`](Filter::swap)s
//! the closure in place, and the next change admitted sees the new predicate.
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

  /// The change's location relative to its watched root.
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
  predicate: Arc<ArcSwap<Predicate<C>>>,
}

impl<C> Filter<C> {
  /// A filter that admits **every** change — the default (design §7). No predicate is evaluated;
  /// a subscription with this filter is gated only by key coverage.
  #[inline]
  #[must_use]
  pub fn all() -> Self {
    Self::new(|_| true)
  }

  /// A filter admitting exactly the changes for which `predicate` returns `true`.
  ///
  /// `predicate` sees a [`FilterInput`] — the change's [`key`](FilterInput::key),
  /// [`kind`](FilterInput::kind), and [`path`](FilterInput::path), but **not** the delivered
  /// event's epoch or value (design §7). It must be `Send + Sync`
  /// (the driver evaluates it from the polling task and may [`swap`](Filter::swap) it across the
  /// async boundary). A [`Rescan`](EventKind::Rescan) never reaches it — coverage
  /// loss bypasses the filter (design §7/§8).
  #[inline]
  #[must_use]
  pub fn new(predicate: impl Fn(&FilterInput<'_, C>) -> bool + Send + Sync + 'static) -> Self {
    Self {
      predicate: Arc::new(ArcSwap::from_pointee(Arc::new(predicate) as Predicate<C>)),
    }
  }

  /// Hot-swaps the predicate in place — every subsequent [`admits`](Self::admits) uses
  /// `predicate`, without re-arming the kernel watch (design §7).
  ///
  /// The swap is atomic and lock-free: a change being admitted concurrently observes either the
  /// old or the new predicate, never a torn state. A handle the caller retained (or the driver
  /// holds) sees the change immediately — the slot is shared.
  #[inline]
  pub fn swap(&self, predicate: impl Fn(&FilterInput<'_, C>) -> bool + Send + Sync + 'static) {
    self
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
    (self.predicate.load())(input)
  }
}

impl<C> Clone for Filter<C> {
  /// Shares the same swappable slot — a [`swap`](Filter::swap) through either handle is seen by
  /// both (the point of the shared driver/caller split; see the type docs).
  #[inline]
  fn clone(&self) -> Self {
    Self {
      predicate: Arc::clone(&self.predicate),
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
