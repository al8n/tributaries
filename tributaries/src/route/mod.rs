//! Attribution & fan-out: routing one raw event back to every caller
//! [`Subscription`] that covers it.
//!
//! This is pure logic — no I/O, no clock, no runtime — so it is exhaustively
//! unit-testable over synthetic events and paths alone. The driver performs the
//! O(1) `event.root()` → [`RootEntry`] lookup and hands the matched entry here;
//! [`fan_out`] then does the linear-in-subscribers-of-that-root coverage test.
//!
//! The one thing keeping this module pure is the [`RoutableEvent`] seam: the raw
//! event is consumed through a trait exposing only its endpoint paths, whether it is
//! a [`Rescan`](tributary_fs::EventKind::Rescan), and how to mint the retagged output
//! for one subscriber (including the two synthesized single-endpoint projections a
//! move decomposes into). Production plugs in [`tributary_fs::Event`] (whose deliver
//! methods wrap it into a [`crate::Event`]); tests plug in a trivial fake, so the
//! routing decision is checked without constructing the fs event type (whose
//! constructor is private to that crate).
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
//!
//! # A [`Moved`](tributary_fs::EventKind::Moved) has two endpoints
//!
//! Every other event kind has a single covered path; a move has two — a source
//! `from` (the [`MovedEvent`](tributary_fs::MovedEvent) source) and a destination
//! `to` ([`path`](RoutableEvent::path)). Coverage must consider **both**, or a
//! subscription watching only the source silently misses that the file left its tree.
//! So [`fan_out`] decomposes a move **per subscriber** (design §5):
//!
//! - covers **both** endpoints → the full `Moved(from → to)`;
//! - covers **only `from`** (move-out) → a synthesized `Removed(from)` — the file
//!   left its tree and it cannot see where it went;
//! - covers **only `to`** (move-in) → a synthesized `Created(to)` — the file arrived
//!   from outside its watch;
//! - covers neither → nothing.
//!
//! Each subscriber thus receives **exactly one** event for a move (dedup: a
//! both-covering subscriber gets the `Moved`, never also a `Removed`/`Created`). The
//! synthesized single-endpoint projections are minted through the tributaries
//! [`Synthetic`](crate::event) wrapper — the umbrella never fabricates fs vocabulary
//! — and every projection of one raw move carries that subscriber's umbrella epoch
//! stamp (assigned downstream, design §8).

use std::path::Path;

use tributary_fs::Event as FsEvent;

use crate::{event::Event, subscription::Subscription, subsume::RootEntry};

#[cfg(test)]
mod tests;

/// A raw event, viewed by [`fan_out`] through only what routing needs — its endpoint
/// paths, whether it is a [`Rescan`](tributary_fs::EventKind::Rescan), and how to mint
/// the retagged delivery (whole, or one of the two single-endpoint move projections)
/// for one subscriber.
///
/// The seam that keeps [`fan_out`] pure and testable: production implements it for
/// [`tributary_fs::Event`]; tests implement it for a fake. `Delivered` is the
/// per-subscriber output — [`crate::Event`] in production.
pub(crate) trait RoutableEvent {
  /// The retagged per-subscriber delivery this event fans out into.
  type Delivered;

  /// The affected object's absolute path (the §4 ancestor-test anchor); for a
  /// [`Moved`](tributary_fs::EventKind::Moved) this is the **destination** `to`.
  fn path(&self) -> &Path;

  /// The move **source** `from`, iff this event is a
  /// [`Moved`](tributary_fs::EventKind::Moved) — the second endpoint coverage must
  /// test so a source-only subscriber is not silently skipped (design §5). `None` for
  /// every single-endpoint kind.
  fn move_from(&self) -> Option<&Path>;

  /// Whether this is a [`Rescan`](tributary_fs::EventKind::Rescan) — delivered to
  /// every subscriber regardless of coverage.
  fn is_rescan(&self) -> bool;

  /// Mints the whole delivery retagged with `sub` — the event as-is (a plain
  /// single-endpoint change, a `Rescan`, or the full `Moved` for a both-covering
  /// subscriber).
  fn deliver(&self, sub: Subscription) -> Self::Delivered;

  /// Mints the move-out projection for `sub`: a synthesized `Removed` at the source
  /// `from` (design §5). Only called for a move whose subscriber covers `from` but
  /// not `to`.
  fn deliver_move_out(&self, sub: Subscription) -> Self::Delivered;

  /// Mints the move-in projection for `sub`: a synthesized `Created` at the
  /// destination `to` (design §5). Only called for a move whose subscriber covers
  /// `to` but not `from`.
  fn deliver_move_in(&self, sub: Subscription) -> Self::Delivered;
}

impl RoutableEvent for FsEvent {
  type Delivered = Event;

  #[inline]
  fn path(&self) -> &Path {
    FsEvent::path(self)
  }

  #[inline]
  fn move_from(&self) -> Option<&Path> {
    self.kind().moved().map(tributary_fs::MovedEvent::from)
  }

  #[inline]
  fn is_rescan(&self) -> bool {
    FsEvent::is_rescan(self)
  }

  #[inline]
  fn deliver(&self, sub: Subscription) -> Event {
    Event::from_fs(sub, self.clone())
  }

  #[inline]
  fn deliver_move_out(&self, sub: Subscription) -> Event {
    Event::move_out(sub, self)
  }

  #[inline]
  fn deliver_move_in(&self, sub: Subscription) -> Event {
    Event::move_in(sub, self)
  }
}

/// Fans one raw event out to every covering, filter-admitting subscriber of its
/// matched root, retagging each delivered copy with that subscriber's
/// [`Subscription`] and — for a [`Moved`](tributary_fs::EventKind::Moved) — projecting
/// it per that subscriber's two-endpoint coverage.
///
/// `entry` is the [`RootEntry`] the driver resolved from `event.root()` (the O(1)
/// handle map, not a radix walk). `canonical_of` resolves each subscriber to its
/// registered canonical path — the ancestor-test anchor of design §4; a
/// subscriber it cannot resolve (concurrently dropped) is skipped.
///
/// `admits` is the subscriber's admission gate (design §5/§7): given a subscriber and
/// the *minted* (already projected) delivery, it returns whether that subscriber
/// accepts it. Production folds **both** the subscription's [`Filter`](crate::Filter)
/// and its [`Interest`](tributary_fs::Interest) gate into this closure, checking them
/// against the projected delivery's kind (so a move-out is gated by `removed` interest,
/// a move-in by `created`, a whole `Moved` by `moved`). It is only consulted for
/// non-`Rescan` events, and only after the coverage test has passed — so the closure
/// receives a delivery the subscriber's path already covers. A subscriber whose gate
/// state cannot be resolved (dropped concurrently) is treated as not admitting.
///
/// **Coverage** is the component-wise canonical-path ancestor test: a subscription
/// covers a path iff its canonical path is an ancestor of (or equal to) it.
/// [`Path::starts_with`] is component-wise (so `/a/b` covers `/a/b/c` but not
/// `/a/bc`), which is exactly the §4 test. A single-endpoint event tests only
/// `event.path()`; a move tests **both** `from` and `to` (below).
///
/// **Move decomposition (design §5):** for a [`Moved`](tributary_fs::EventKind::Moved)
/// (detected by [`move_from`](RoutableEvent::move_from) being `Some`), each subscriber
/// receives **exactly one** projection: the whole `Moved` if it covers both endpoints,
/// a synthesized `Removed(from)` if it covers only the source (move-out), a synthesized
/// `Created(to)` if it covers only the destination (move-in), or nothing. The dedup is
/// structural — the four coverage cases are disjoint — so a both-covering subscriber
/// never also gets a `Removed`/`Created`.
///
/// **Filter / interest** are the additional admission gates (design §5/§7): a
/// non-`Rescan` projection is pushed only if `admits` returns `true` for it — they
/// *narrow* the covered set. They run here, before any coalescing, so a settle burst
/// never buffers a filtered-out or uninteresting event.
///
/// **Rescan override:** if the event is a [`Rescan`](tributary_fs::EventKind::Rescan)
/// it is delivered whole to *every* subscriber of the root regardless of coverage
/// **and** regardless of filter/interest — a coverage-loss signal is never narrowed or
/// filtered away (design §5/§7/§8).
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
  let move_from = event.move_from();
  let to = event.path();
  let mut delivered = Vec::new();
  for &sub in &entry.subscribers {
    if rescan {
      // A Rescan bypasses coverage narrowing AND filter/interest (§5/§7/§8): it is a
      // coverage-loss signal that must reach every subscriber unconditionally, so it
      // never resolves a canonical path or consults a gate.
      delivered.push(event.deliver(sub));
      continue;
    }
    let Some(canonical) = canonical_of(sub) else {
      // A subscriber whose path we can no longer resolve was dropped
      // concurrently; it is no longer live, so there is nothing to deliver.
      continue;
    };
    // Mint this subscriber's projection from its two-endpoint coverage (a single
    // endpoint for a non-move). `None` means "not covered" — nothing to deliver.
    let Some(projected) = project(event, sub, canonical, to, move_from) else {
      continue;
    };
    // The filter + interest gate sees the already-projected delivery, so it gates on
    // the *projected* kind (move-out → removed, move-in → created, whole → its kind).
    if admits(sub, &projected) {
      delivered.push(projected);
    }
  }
  delivered
}

/// The single projection `sub` (registered at `canonical`) receives for one event,
/// or `None` if it covers nothing of it. A non-move tests only `to`; a move
/// (`move_from` is `Some`) decomposes per the two-endpoint rule (design §5).
fn project<E: RoutableEvent>(
  event: &E,
  sub: Subscription,
  canonical: &Path,
  to: &Path,
  move_from: Option<&Path>,
) -> Option<E::Delivered> {
  let Some(from) = move_from else {
    // A single-endpoint event: delivered whole iff its path is covered.
    return to.starts_with(canonical).then(|| event.deliver(sub));
  };
  // A move has two endpoints; the four coverage cases are disjoint (structural dedup).
  match (from.starts_with(canonical), to.starts_with(canonical)) {
    (true, true) => Some(event.deliver(sub)), // both → the whole Moved
    (true, false) => Some(event.deliver_move_out(sub)), // source only → Removed(from)
    (false, true) => Some(event.deliver_move_in(sub)), // dest only → Created(to)
    (false, false) => None,                   // neither → nothing
  }
}
