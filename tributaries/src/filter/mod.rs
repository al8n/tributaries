//! The per-subscription admission [`Filter`] — a live-swappable predicate over the
//! concrete delivered [`Event`] (design §7).
//!
//! A `Filter` decides, per subscription, whether an attributed event is delivered to
//! its caller: [`fan_out`](crate::route::fan_out) consults it as an **additional**
//! admission gate, *after* the coverage ancestor test (design §5). It is a simple
//! predicate over the concrete [`Event`] (its path, kind, epoch, …) — the fully-typed
//! `Event<L>` / `Filter<L>` location-parsing generic is deferred to M2 (design §7,
//! call B). The predicate lives behind an [`arc_swap::ArcSwap`] so it can be
//! **hot-swapped** at any time without re-arming the kernel watch (a re-watch): the
//! driver holds each subscription's `Filter` and [`swap`](Filter::swap)s the closure
//! in place, and the next event admitted sees the new predicate.
//!
//! # A `Rescan` always bypasses the filter
//!
//! A [`Rescan`](tributary_fs::EventKind::Rescan) is a coverage-loss signal whose
//! [`epoch`](Event::epoch) dominates everything before it, so it must reach every
//! subscriber unconditionally (design §7/§8). The filter is therefore **never**
//! consulted for a `Rescan`: [`fan_out`](crate::route::fan_out) delivers it before it
//! ever reaches [`admits`](Filter::admits). `admits` itself is a pure predicate — it
//! does not special-case the kind — because the bypass is enforced one level up, at
//! the single point where coverage and filter admission are both decided.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::event::Event;

/// The boxed predicate a [`Filter`] holds: a `Send + Sync` closure over the concrete
/// delivered [`Event`]. `Send + Sync` is mandatory — the driver swaps it across the
/// async boundary and reads it from whatever task polls `next()`.
type Predicate<C, V> = Arc<dyn Fn(&Event<C, V>) -> bool + Send + Sync>;

/// A live-swappable admission predicate for one subscription (design §7), over the
/// delivered [`Event<C, V>`](Event).
///
/// Constructed with [`all`](Filter::all) (admit everything — the default) or
/// [`new`](Filter::new) (a custom predicate), and mutated in place with
/// [`swap`](Filter::swap) — no re-watch, so a caller can re-scope what a live
/// subscription delivers at any time. The driver calls [`admits`](Filter::admits) as
/// the fan-out admission gate for every non-`Rescan` event (a `Rescan` bypasses it
/// unconditionally — coverage loss is never filtered away, design §7/§8).
///
/// Cloning a `Filter` (or sharing one behind an [`Arc`]) shares the same swappable
/// slot: a [`swap`](Filter::swap) through any handle is observed by every holder,
/// which is what lets the driver keep a subscription's filter while the caller keeps a
/// handle to re-scope it live.
pub struct Filter<C, V> {
  predicate: Arc<ArcSwap<Predicate<C, V>>>,
}

impl<C, V> Filter<C, V> {
  /// A filter that admits **every** event — the default (design §7). No predicate is
  /// evaluated; a subscription with this filter is gated only by key coverage.
  #[inline]
  #[must_use]
  pub fn all() -> Self {
    Self::new(|_| true)
  }

  /// A filter admitting exactly the events for which `predicate` returns `true`.
  ///
  /// `predicate` sees the concrete delivered [`Event`] — its [`key`](Event::key),
  /// [`kind`](Event::kind), [`epoch`](Event::epoch), and the rest. It must be `Send +
  /// Sync` (the driver evaluates it from the polling task and may
  /// [`swap`](Filter::swap) it across the async boundary). A
  /// [`Rescan`](tributary_fs::EventKind::Rescan) never reaches it — coverage loss
  /// bypasses the filter (design §7/§8).
  #[inline]
  #[must_use]
  pub fn new(predicate: impl Fn(&Event<C, V>) -> bool + Send + Sync + 'static) -> Self {
    Self {
      predicate: Arc::new(ArcSwap::from_pointee(Arc::new(predicate) as Predicate<C, V>)),
    }
  }

  /// Hot-swaps the predicate in place — every subsequent [`admits`](Self::admits) uses
  /// `predicate`, without re-arming the kernel watch (design §7).
  ///
  /// The swap is atomic and lock-free: an event being admitted concurrently observes
  /// either the old or the new predicate, never a torn state. A handle the caller
  /// retained (or the driver holds) sees the change immediately — the slot is shared.
  #[inline]
  pub fn swap(&self, predicate: impl Fn(&Event<C, V>) -> bool + Send + Sync + 'static) {
    self
      .predicate
      .store(Arc::new(Arc::new(predicate) as Predicate<C, V>));
  }

  /// Whether this filter admits `event` — the fan-out admission gate (design §5/§7).
  ///
  /// A pure evaluation of the current predicate; it does **not** special-case a
  /// [`Rescan`](tributary_fs::EventKind::Rescan), because the unconditional Rescan
  /// bypass is enforced at fan-out — before an event reaches here (design §7/§8).
  #[inline]
  #[must_use]
  pub fn admits(&self, event: &Event<C, V>) -> bool {
    (self.predicate.load())(event)
  }
}

impl<C, V> Clone for Filter<C, V> {
  /// Shares the same swappable slot — a [`swap`](Filter::swap) through either handle is
  /// seen by both (the point of the shared driver/caller split; see the type docs).
  #[inline]
  fn clone(&self) -> Self {
    Self {
      predicate: Arc::clone(&self.predicate),
    }
  }
}

impl<C, V> Default for Filter<C, V> {
  /// The default filter admits everything ([`Filter::all`]).
  #[inline]
  fn default() -> Self {
    Self::all()
  }
}

impl<C, V> core::fmt::Debug for Filter<C, V> {
  /// The predicate is an opaque closure with no meaningful representation, so this
  /// reports only the type — enough to place a `Filter` in a larger `Debug` dump.
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Filter").finish_non_exhaustive()
  }
}

#[cfg(test)]
mod tests;
