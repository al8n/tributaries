//! Attribution & fan-out: routing one raw event back to every caller
//! [`Subscription`] that covers it.
//!
//! This is pure logic — no I/O, no clock, no runtime — so it is exhaustively
//! unit-testable over synthetic events and paths alone. The driver performs the
//! O(1) `event.root()` → [`RootEntry`] lookup and hands the matched entry here;
//! [`fan_out`] then does the linear-in-subscribers-of-that-root coverage test.
//!
//! The one thing keeping this module pure is the [`RoutableEvent`] seam: the raw
//! event is consumed through a trait exposing only `path()` / `is_rescan()` and a
//! `deliver` that mints the retagged output. Production plugs in
//! [`tributary_fs::Event`] (whose `deliver` wraps it into a [`crate::Event`]);
//! tests plug in a trivial fake, so the routing decision is checked without
//! constructing the fs event type (whose constructor is private to that crate).
//!
//! # No silent loss
//!
//! For every raw event, the set of subscribers it is delivered to equals exactly
//! the set whose canonical path covers it **and** whose [`Filter`](crate::Filter)
//! admits it (design §5/§7) — with one override that *widens* that set, never
//! narrows it: a [`Rescan`](tributary_fs::EventKind::Rescan) is delivered to **every**
//! subscriber of the root, bypassing *both* the coverage test and the filter, because
//! a coverage-loss signal must never be narrowed or filtered away (design §5/§7/§8).
//!
//! The [`Filter`](crate::Filter) is an *additional* admission gate layered on top of
//! coverage: a non-`Rescan` event reaches a subscriber only if the subscriber's path
//! covers it **and** its filter admits the (minted) delivery. The filter runs here, at
//! fan-out — before any coalescing (design §7) — so a settle burst only ever buffers
//! events the caller actually wants.

use std::path::Path;

use tributary_fs::Event as FsEvent;

use crate::{event::Event, subscription::Subscription, subsume::RootEntry};

#[cfg(test)]
mod tests;

/// A raw event, viewed by [`fan_out`] through only what routing needs — its path,
/// whether it is a [`Rescan`](tributary_fs::EventKind::Rescan), and how to mint the
/// retagged delivery for one subscriber.
///
/// The seam that keeps [`fan_out`] pure and testable: production implements it for
/// [`tributary_fs::Event`]; tests implement it for a fake. `Delivered` is the
/// per-subscriber output — [`crate::Event`] in production.
pub(crate) trait RoutableEvent {
  /// The retagged per-subscriber delivery this event fans out into.
  type Delivered;

  /// The affected object's absolute path (the §4 ancestor-test anchor).
  fn path(&self) -> &Path;

  /// Whether this is a [`Rescan`](tributary_fs::EventKind::Rescan) — delivered to
  /// every subscriber regardless of coverage.
  fn is_rescan(&self) -> bool;

  /// Mints the delivery retagged with `sub`.
  fn deliver(&self, sub: Subscription) -> Self::Delivered;
}

impl RoutableEvent for FsEvent {
  type Delivered = Event;

  #[inline]
  fn path(&self) -> &Path {
    FsEvent::path(self)
  }

  #[inline]
  fn is_rescan(&self) -> bool {
    FsEvent::is_rescan(self)
  }

  #[inline]
  fn deliver(&self, sub: Subscription) -> Event {
    Event::from_fs(sub, self.clone())
  }
}

/// Fans one raw event out to every covering, filter-admitting subscriber of its
/// matched root, retagging each delivered copy with that subscriber's
/// [`Subscription`].
///
/// `entry` is the [`RootEntry`] the driver resolved from `event.root()` (the O(1)
/// handle map, not a radix walk). `canonical_of` resolves each subscriber to its
/// registered canonical path — the ancestor-test anchor of design §4; a
/// subscriber it cannot resolve (concurrently dropped) is skipped.
///
/// `admits` is the subscriber's [`Filter`](crate::Filter) admission gate (design §7):
/// given a subscriber and the *minted* delivery, it returns whether that subscriber's
/// filter admits it. It is only consulted for non-`Rescan` events, and only after the
/// coverage test has passed — so the closure receives a delivery the subscriber's path
/// already covers. A subscriber whose filter cannot be resolved (dropped concurrently)
/// is treated as not admitting, so nothing is delivered to a vanished subscription.
///
/// **Coverage** is the component-wise canonical-path ancestor test: a subscription
/// covers the event iff its canonical path is an ancestor of (or equal to)
/// `event.path()`. [`Path::starts_with`] is component-wise (so `/a/b` covers
/// `/a/b/c` but not `/a/bc`), which is exactly the §4 test.
///
/// **Filter** is the additional admission gate (design §7): a non-`Rescan` delivery is
/// pushed only if `admits` returns `true` for it — the filter *narrows* the covered
/// set. It runs here, before any coalescing, so a settle burst never buffers a
/// filtered-out event.
///
/// **Rescan override:** if the event is a [`Rescan`](tributary_fs::EventKind::Rescan)
/// it is delivered to *every* subscriber of the root regardless of coverage **and**
/// regardless of the filter — a coverage-loss signal is never narrowed or filtered
/// away (design §5/§7/§8).
pub(crate) fn fan_out<'a, E>(
  event: &E,
  entry: &RootEntry,
  canonical_of: impl Fn(Subscription) -> Option<&'a Path>,
  admits: impl Fn(Subscription, &E::Delivered) -> bool,
) -> Vec<E::Delivered>
where
  E: RoutableEvent,
{
  let rescan = event.is_rescan();
  let event_path = event.path();
  let mut delivered = Vec::new();
  for &sub in &entry.subscribers {
    if rescan {
      // A Rescan bypasses BOTH coverage narrowing and the filter (§5/§7/§8): it is a
      // coverage-loss signal that must reach every subscriber unconditionally, so it
      // never resolves a canonical path or consults a filter.
      delivered.push(event.deliver(sub));
      continue;
    }
    let Some(canonical) = canonical_of(sub) else {
      // A subscriber whose path we can no longer resolve was dropped
      // concurrently; it is no longer live, so there is nothing to deliver.
      continue;
    };
    // A non-Rescan event is delivered iff the subscription's path is an
    // ancestor-or-equal of the event path (§4 component-wise ancestor test) AND its
    // filter admits the minted delivery (§7 — the additional gate). Coverage is
    // checked first so the filter only ever sees a delivery the path covers.
    if event_path.starts_with(canonical) {
      let one = event.deliver(sub);
      if admits(sub, &one) {
        delivered.push(one);
      }
    }
  }
  delivered
}
