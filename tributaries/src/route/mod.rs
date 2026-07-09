//! Attribution & fan-out: routing one raw event back to every caller
//! [`Subscription`] that covers it.
//!
//! This is pure logic — no I/O, no clock, no runtime — so it is exhaustively
//! unit-testable over synthetic events and keys alone. The driver performs the O(1)
//! handle → root lookup and hands the matched root's subscriber list here; [`fan_out`]
//! then does the linear-in-subscribers-of-that-root coverage test, generic over the
//! key component `C`.
//!
//! The one thing keeping this module pure is the [`RoutableEvent`] seam: the raw event
//! is consumed through a trait exposing only its endpoint keys, whether it is a
//! [`Rescan`](crate::EventKind::Rescan), and how to mint the retagged output
//! for one subscriber (including the two synthesized single-endpoint projections a
//! move decomposes into). Production plugs in a thin adapter over the source event
//! (whose deliver methods mint a [`crate::Event`]); tests plug in a trivial fake, so
//! the routing decision is checked without constructing any source event at all.
//!
//! # No silent loss
//!
//! For every raw event, the set of subscribers it is delivered to equals exactly
//! the set whose key covers it **and** whose [`Filter`](crate::Filter) admits it
//! (design §5/§7) — with one override that *widens* that set, never narrows it: a
//! [`Rescan`](crate::EventKind::Rescan) is delivered to **every** subscriber of
//! the root, bypassing *both* the coverage test and the filter, because a
//! coverage-loss signal must never be narrowed or filtered away (design §5/§7/§8).
//!
//! The [`Filter`](crate::Filter) is an *additional* admission gate layered on top of
//! coverage: a non-`Rescan` event reaches a subscriber only if the subscriber's key
//! covers it **and** its filter admits the (minted) delivery. The filter runs here, at
//! fan-out — before any coalescing (design §7) — so a settle burst only ever buffers
//! events the caller actually wants.
//!
//! # A [`Moved`](crate::EventKind::Moved) has two endpoints
//!
//! Every other event kind has a single covered key; a move has two — a source `from`
//! and a destination `to` ([`key`](RoutableEvent::key)). Coverage must consider
//! **both**, or a subscription watching only the source silently misses that the file
//! left its tree. So [`fan_out`] decomposes a move **per subscriber** (design §5):
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
//! synthesized single-endpoint projections are minted as a flat owned
//! [`Event`](crate::Event) in the umbrella's own neutral vocabulary — and every
//! projection of one raw move carries that subscriber's umbrella epoch stamp (assigned
//! downstream, design §8).

use crate::subscription::Subscription;

#[cfg(test)]
mod tests;

/// A raw event, viewed by [`fan_out`] through only what routing needs — its endpoint
/// keys, whether it is a [`Rescan`](crate::EventKind::Rescan), and how to mint
/// the retagged delivery (whole, or one of the two single-endpoint move projections)
/// for one subscriber.
///
/// The seam that keeps [`fan_out`] pure and testable, generic over the key component
/// `C`: production implements it for a thin adapter over the raw
/// [`SourceEvent`](crate::SourceEvent); tests implement it for a fake. `Delivered` is
/// the per-subscriber output — [`crate::Event`] in production.
pub(crate) trait RoutableEvent<C> {
  /// The retagged per-subscriber delivery this event fans out into.
  type Delivered;

  /// The affected object's located key (the §4 ancestor-test anchor); for a
  /// [`Moved`](crate::EventKind::Moved) this is the **destination** `to`.
  fn key(&self) -> &[C];

  /// The move **source** `from`, iff this event is a
  /// [`Moved`](crate::EventKind::Moved) — the second endpoint coverage must
  /// test so a source-only subscriber is not silently skipped (design §5). `None` for
  /// every single-endpoint kind.
  fn move_from(&self) -> Option<&[C]>;

  /// Whether this is a [`Rescan`](crate::EventKind::Rescan) — delivered to
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

/// Fans one raw event out to every covering, filter-admitting subscriber of its
/// matched root, retagging each delivered copy with that subscriber's
/// [`Subscription`] and — for a [`Moved`](crate::EventKind::Moved) — projecting
/// it per that subscriber's two-endpoint coverage.
///
/// `subscribers` is the subscriber list of the root the driver resolved from the raw
/// event's handle (the O(1) reverse map, not a radix walk). `canonical_of` resolves
/// each subscriber to its registered key — the ancestor-test anchor of design §4; a
/// subscriber it cannot resolve (concurrently dropped) is skipped.
///
/// `admits` is the subscriber's admission gate (design §5/§7): given a subscriber and
/// the *minted* (already projected) delivery, it returns whether that subscriber
/// accepts it. Production folds **both** the subscription's [`Filter`](crate::Filter)
/// and its [`Interest`](tributary_fs::Interest) gate into this closure, checking them
/// against the projected delivery's kind (so a move-out is gated by `removed` interest,
/// a move-in by `created`, a whole `Moved` by `moved`). It is only consulted for
/// non-`Rescan` events, and only after the coverage test has passed — so the closure
/// receives a delivery the subscriber's key already covers. A subscriber whose gate
/// state cannot be resolved (dropped concurrently) is treated as not admitting.
///
/// **Coverage** is the component-wise ancestor test: a subscription covers a key iff
/// its key is an ancestor of (or equal to) it. `<[C]>::starts_with` is component-wise
/// (so `[a, b]` covers `[a, b, c]` but not `[a, bc]`), which is exactly the §4 test. A
/// single-endpoint event tests only `event.key()`; a move tests **both** `from` and
/// `to` (below).
///
/// **Move decomposition (design §5):** for a [`Moved`](crate::EventKind::Moved)
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
/// **Rescan override:** if the event is a [`Rescan`](crate::EventKind::Rescan)
/// it is delivered whole to *every* subscriber of the root regardless of coverage
/// **and** regardless of filter/interest — a coverage-loss signal is never narrowed or
/// filtered away (design §5/§7/§8).
pub(crate) fn fan_out<'a, C, E>(
  event: &E,
  subscribers: &[Subscription],
  canonical_of: impl Fn(Subscription) -> Option<&'a [C]>,
  admits: impl Fn(Subscription, &E::Delivered) -> bool,
) -> Vec<E::Delivered>
where
  C: PartialEq + 'a,
  E: RoutableEvent<C>,
{
  let rescan = event.is_rescan();
  let move_from = event.move_from();
  let to = event.key();
  let mut delivered = Vec::new();
  for &sub in subscribers {
    if rescan {
      // A Rescan bypasses coverage narrowing AND filter/interest (§5/§7/§8): it is a
      // coverage-loss signal that must reach every subscriber unconditionally, so it
      // never resolves a key or consults a gate.
      delivered.push(event.deliver(sub));
      continue;
    }
    let Some(canonical) = canonical_of(sub) else {
      // A subscriber whose key we can no longer resolve was dropped concurrently; it
      // is no longer live, so there is nothing to deliver.
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
fn project<C, E>(
  event: &E,
  sub: Subscription,
  canonical: &[C],
  to: &[C],
  move_from: Option<&[C]>,
) -> Option<E::Delivered>
where
  C: PartialEq,
  E: RoutableEvent<C>,
{
  let Some(from) = move_from else {
    // A single-endpoint event: delivered whole iff its key is covered.
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
