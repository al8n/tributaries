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
//! (design §5/§7) — with one override for a [`Rescan`](crate::EventKind::Rescan),
//! which bypasses **content admission** (filter and interest) entirely, because a
//! coverage-loss signal must never be filtered away (design §5/§7/§8).
//!
//! The [`Filter`](crate::Filter) is an *additional* admission gate layered on top of
//! coverage: a non-`Rescan` event reaches a subscriber only if the subscriber's key
//! covers it **and** its filter admits the (minted) delivery. The filter runs here, at
//! fan-out — before any coalescing (design §7) — so a settle burst only ever buffers
//! events the caller actually wants.
//!
//! # A [`Rescan`](crate::EventKind::Rescan) bypasses admission, not geometry
//!
//! A rescan says "coverage became uncertain at and below **this key**". It is a located
//! statement, and the located region either intersects a subscription's own subtree or
//! it does not. So a rescan is routed by the same ancestor test every other event is —
//! only the *content* gates are skipped:
//!
//! - the subscription is an ancestor-or-equal of the rescan key → the located rescan is
//!   delivered unchanged; re-enumerating that subtree covers the whole uncertain region;
//! - the rescan key is a strict ancestor of the subscription → the instruction is
//!   **clamped to the subscription's own key**; the uncertain region *within* this
//!   subscription is exactly its own subtree, and naming anything above it would send a
//!   consumer outside its watch;
//! - the two are disjoint → nothing is delivered; the uncertain region contains none of
//!   this subscription's coverage, so there is nothing for it to re-enumerate.
//!
//! Delivering every rescan to every subscriber of the shared physical root — as fanning
//! it out unconditionally does — is not conservatism, it is a leak: a per-subscription
//! consumer is handed a path outside its own boundary, a localized loss costs
//! `O(subscribers)` false re-enumerations, and (worst) the irrelevant sibling rescan
//! becomes *parked debt* on a subscription it never concerned, where it then suppresses
//! that subscription's real deltas. Narrowing loses nothing: a whole-root rescan still
//! reaches every subscriber, each scoped to what it owns.
//!
//! # The delivered coordinate is the receiving subscription's
//!
//! A raw event's [`location`](crate::Event::location) is relative to the **physical
//! armed root**, which the umbrella widens and re-points as unrelated subscriptions come
//! and go. A subscription's own key never moves. Fan-out therefore **rebases** every
//! minted delivery's location into the receiving subscription's coordinate — dropping
//! the `subscription_key.len() - captured_root_depth` leading segments — *before* the
//! admission gate sees it, so both [`Event::location`](crate::Event::location) and
//! [`FilterInput::location`](crate::FilterInput::location) mean "relative to the key you
//! watched" and nothing else. Without this, watching an ancestor from an unrelated
//! caller silently re-coordinates a stable subscription: a depth/location filter that
//! admitted yesterday starts rejecting, with no coverage-loss signal to explain it.
//!
//! ## The anchor is the event's own, not the call's
//!
//! The depth that rebase subtracts is
//! [`captured_root_depth`](RoutableEvent::captured_root_depth) — a property **of the
//! event**, read off the coordinate it was born carrying — never the depth of whatever
//! root the umbrella happens to have armed when fan-out runs. The two diverge, and they
//! diverge in exactly the window this module exists to protect: a source captures a
//! change while the root is `/a/b`, the change queues, an unrelated `watch("/a")` widens
//! that root **in place** (the handle is preserved, so its queue survives), and only then
//! is the queued change drained. Its location is still `/a/b`-relative; the root now
//! armed is `/a`. Subtracting the live root's depth over-strips the queued event by the
//! widen distance, re-coordinating precisely the subscription whose key never moved —
//! the failure the rebase was introduced to prevent, reintroduced from the other side.
//! Binding the anchor to the event makes each delivery carry its own correct depth, so a
//! queued pre-widen change and a fresh post-widen one both rebase right.
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
//!
//! ## A reserved endpoint is an endpoint nobody covers
//!
//! A [`Source`](crate::Source) mints its own sync-barrier artifacts inside the tree it
//! watches, and no consumer may ever be told about one
//! ([`ReservedEndpoints`]). A rename can put such an artifact at **one** end and an
//! ordinary user object at the other, so the reservation is a property of an *endpoint*,
//! never of the whole change: masking the endpoint out of every subscriber's coverage is
//! what keeps the two questions separate. The four move cases above then answer this one
//! too, unchanged — the user endpoint is delivered by exactly the projection a subscriber
//! covering only that end already receives, and a change reserved at every endpoint it has
//! reaches nobody because nobody covers any of it.
//!
//! Discarding the whole change on one endpoint's reservation instead is silent loss: the
//! user endpoint's own removal (or arrival) is deleted from every stream that was watching
//! it, with no [`Rescan`](crate::EventKind::Rescan) owed for it and nothing to tell a
//! consumer its picture of that name is now stale.

use crate::subscription::Subscription;

#[cfg(test)]
mod tests;

/// Which of a change's endpoints lie in the source's **reserved namespace** — the
/// sync-barrier artifacts a [`Source`](crate::Source) writes into the watched tree and
/// identifies through [`is_sync_artifact`](crate::Source::is_sync_artifact).
///
/// [`fan_out`] treats a reserved endpoint as covered by **nobody**, whatever the
/// subscribers' keys say, which is what makes suppression namespace-total without making
/// it event-total (see the [module docs](self#a-reserved-endpoint-is-an-endpoint-nobody-covers)).
///
/// A [`Rescan`](crate::EventKind::Rescan) is never classified — it is coverage
/// information rather than an object, and is structurally unmaskable — so it always
/// arrives here as [`None`](Self::None).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReservedEndpoints {
  /// No endpoint is reserved: the ordinary change, routed by coverage alone.
  None,
  /// A move's **source** endpoint only ([`move_from`](RoutableEvent::move_from)) — an
  /// artifact renamed out to an ordinary name, whose destination is a user object.
  Source,
  /// A move's **destination** endpoint only ([`key`](RoutableEvent::key)) — a user object
  /// renamed INTO the reserved namespace, whose source is an ordinary name.
  Destination,
  /// Every endpoint this change has: a single-endpoint change at a reserved key, or a
  /// rename BETWEEN two reserved names. Nothing about it may reach any subscriber.
  All,
}

impl ReservedEndpoints {
  /// Whether the move **source** endpoint is masked out of coverage.
  #[inline]
  pub(crate) const fn masks_source(self) -> bool {
    matches!(self, Self::Source | Self::All)
  }

  /// Whether the [`key`](RoutableEvent::key) — a move's **destination** — is masked out
  /// of coverage.
  #[inline]
  pub(crate) const fn masks_destination(self) -> bool {
    matches!(self, Self::Destination | Self::All)
  }

  /// Whether **any** endpoint is reserved: the changes a source's own sync barrier may be
  /// waiting on, and so the ones the driver must offer its pending-sync map.
  #[inline]
  pub(crate) const fn any(self) -> bool {
    !matches!(self, Self::None)
  }

  /// Whether **every** endpoint is reserved, so no subscriber may be told anything at all
  /// about this change — the case the driver can settle without routing it.
  #[inline]
  pub(crate) const fn is_total(self) -> bool {
    matches!(self, Self::All)
  }
}

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

  /// Which of this event's endpoints lie in the source's reserved namespace and are
  /// therefore covered by nobody (see [`ReservedEndpoints`]). Read once per event, not
  /// once per subscriber: the answer is the source's, and no subscriber's key can change
  /// it.
  fn reserved(&self) -> ReservedEndpoints;

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

  /// Mints this [`Rescan`](crate::EventKind::Rescan) **clamped to `key`** — the
  /// recovery projection for a subscriber the rescan strictly *contains*. Only called
  /// when `key` (the subscriber's own registered key) is a strict descendant of the
  /// rescan's key, so the delivered instruction stays inside the subscription's
  /// boundary while still re-enumerating everything of it the loss made uncertain.
  fn deliver_rescan_clamped(&self, sub: Subscription, key: &[C]) -> Self::Delivered;

  /// How many leading components of this event's [`key`](Self::key) its
  /// **location** is measured from: the depth of the armed root the source captured
  /// it against.
  ///
  /// This is the event's own anchor, fixed when the change was recorded — **not** the
  /// depth of the root its handle resolves to now. A change can outlive the root depth
  /// it was captured under: an in-place widen preserves the handle and therefore the
  /// queue behind it, so a change captured at `/a/b` can be drained after the root has
  /// become `/a`. Only the captured depth rebases such a delivery correctly (see the
  /// [module docs](self#the-anchor-is-the-events-own-not-the-calls)).
  fn captured_root_depth(&self) -> usize;

  /// Rebases a minted delivery's root-relative coordinate into the receiving
  /// subscription's own, dropping the first `strip` location segments (see the
  /// [module docs](self#the-delivered-coordinate-is-the-receiving-subscriptions)).
  /// `strip` is the subscriber's depth below the event's captured root; `0` — the
  /// subscriber *is* that root — must leave the delivery untouched.
  fn rebase(&self, delivered: &mut Self::Delivered, strip: usize);

  /// Degrades a delivery whose coordinate **cannot be stated** in the receiving
  /// subscription's to the root-anchored empty location, leaving
  /// [`key`](Self::key) as the authoritative signal — the same honest fallback a
  /// move-out projection and a clamped rescan already carry.
  ///
  /// Reached only when the subscriber sits *above* the root the event was captured
  /// against, which is exactly the widener receiving a change queued from before its own
  /// in-place widen. Its coordinate would need leading segments that were never recorded
  /// in the delivery — the key is in the source's own component space, a location in
  /// canonical segments, so they cannot be reconstructed. Reporting the capture-relative
  /// location instead would name a path *inside the subscription* that does not exist
  /// (`sub/x` for a change at `sub/b/x`), which a caller joining location onto its key
  /// would then act on. Saying "at your root, see the key" claims nothing false.
  fn anchor_at_root(&self, delivered: &mut Self::Delivered);
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
/// and its [`Interest`](crate::Interest) gate into this closure, checking them
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
/// **Rescan routing:** a [`Rescan`](crate::EventKind::Rescan) bypasses `admits`
/// entirely — a coverage-loss signal is never filtered away (design §5/§7/§8) — but it
/// is still routed by the ancestor test, in the *intersecting* form: an ancestor-or-equal
/// subscriber gets the located rescan unchanged, a subscriber the rescan strictly
/// contains gets it clamped to its own key
/// ([`deliver_rescan_clamped`](RoutableEvent::deliver_rescan_clamped)), and a disjoint
/// subscriber gets nothing. See the
/// [module docs](self#a-rescan-bypasses-admission-not-geometry).
///
/// **Coordinate rebasing:** every minted delivery is rebased into the receiving
/// subscriber's own coordinate — by `canonical.len() - event.captured_root_depth()`
/// segments — *before* `admits` sees it, so the filter and the caller read the same
/// subscription-relative location
/// ([module docs](self#the-delivered-coordinate-is-the-receiving-subscriptions)). The
/// anchor comes from the **event**
/// ([`captured_root_depth`](RoutableEvent::captured_root_depth)), not from the root
/// currently armed for its handle, so a change queued across an in-place widen still
/// rebases by the depth that was true when it was captured
/// ([module docs](self#the-anchor-is-the-events-own-not-the-calls)).
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
  let captured_root_depth = event.captured_root_depth();
  // Hoisted with the endpoint keys, for the same reason they are: the reservation is the
  // source's answer about this change, so re-asking it per subscriber would cost a call
  // per subscriber of the root and could never answer differently.
  let reserved = event.reserved();
  let mut delivered = Vec::new();
  for &sub in subscribers {
    let Some(canonical) = canonical_of(sub) else {
      // A subscriber whose key we can no longer resolve was dropped concurrently; it
      // is no longer live, so there is nothing to deliver — not even a `Rescan`, which
      // would name a subtree with no consumer left to re-enumerate it.
      continue;
    };
    // Mint this subscriber's projection: for a `Rescan`, from the intersection of the
    // uncertain subtree with this subscriber's own; otherwise from its two-endpoint
    // coverage (a single endpoint for a non-move). `None` means "nothing of this
    // subscriber is affected".
    let projected = if rescan {
      project_rescan(event, sub, canonical, to)
    } else {
      project(event, sub, canonical, to, move_from, reserved)
    };
    let Some(mut projected) = projected else {
      continue;
    };
    // Rebase into the receiving subscriber's coordinate BEFORE the gate: the filter
    // reads the same location the caller will. A subscriber AT the captured root strips
    // nothing; one BELOW it strips its own depth. A subscriber ABOVE it — the widener,
    // handed a change queued from before its own widen — has no expressible coordinate
    // at all, so the delivery degrades to root-anchored rather than reporting a
    // capture-relative location that names a path the subscription does not contain.
    match canonical.len().checked_sub(captured_root_depth) {
      Some(strip) => event.rebase(&mut projected, strip),
      None => event.anchor_at_root(&mut projected),
    }
    // The filter + interest gate sees the already-projected delivery, so it gates on
    // the *projected* kind (move-out → removed, move-in → created, whole → its kind).
    // A `Rescan` skips it: content admission never narrows a coverage-loss signal.
    if rescan || admits(sub, &projected) {
      delivered.push(projected);
    }
  }
  delivered
}

/// The single projection `sub` (registered at `canonical`) receives for one event,
/// or `None` if it covers nothing of it. A non-move tests only `to`; a move
/// (`move_from` is `Some`) decomposes per the two-endpoint rule (design §5).
///
/// An endpoint `reserved` names is covered by nobody, so it drops out of the coverage
/// pair before the decomposition reads it — see the
/// [module docs](self#a-reserved-endpoint-is-an-endpoint-nobody-covers).
fn project<C, E>(
  event: &E,
  sub: Subscription,
  canonical: &[C],
  to: &[C],
  move_from: Option<&[C]>,
  reserved: ReservedEndpoints,
) -> Option<E::Delivered>
where
  C: PartialEq,
  E: RoutableEvent<C>,
{
  let covers_to = to.starts_with(canonical) && !reserved.masks_destination();
  let Some(from) = move_from else {
    // A single-endpoint event: delivered whole iff its key is covered.
    return covers_to.then(|| event.deliver(sub));
  };
  // A move has two endpoints; the four coverage cases are disjoint (structural dedup).
  let covers_from = from.starts_with(canonical) && !reserved.masks_source();
  match (covers_from, covers_to) {
    (true, true) => Some(event.deliver(sub)), // both → the whole Moved
    (true, false) => Some(event.deliver_move_out(sub)), // source only → Removed(from)
    (false, true) => Some(event.deliver_move_in(sub)), // dest only → Created(to)
    (false, false) => None,                   // neither → nothing
  }
}

/// The recovery projection `sub` (registered at `canonical`) receives for a
/// [`Rescan`](crate::EventKind::Rescan) whose uncertain subtree is rooted at `at`, or
/// `None` when the two subtrees are disjoint.
///
/// The three cases are the ancestor test in both directions, and they are exhaustive:
/// either `at` is inside `sub`'s subtree, or `sub`'s key is inside `at`'s, or neither
/// contains the other. Only the containing case needs a clamp — the intersection of the
/// two subtrees is then `sub`'s own key, and that is the widest instruction the
/// subscription may honestly be given.
fn project_rescan<C, E>(
  event: &E,
  sub: Subscription,
  canonical: &[C],
  at: &[C],
) -> Option<E::Delivered>
where
  C: PartialEq,
  E: RoutableEvent<C>,
{
  if at.starts_with(canonical) {
    // At or below the subscription: the located rescan already names a subtree the
    // subscription owns — deliver it verbatim, precision intact.
    Some(event.deliver(sub))
  } else if canonical.starts_with(at) {
    // The loss contains the whole subscription: clamp to the subscription's own key.
    Some(event.deliver_rescan_clamped(sub, canonical))
  } else {
    // Disjoint: this subscription's coverage is entirely outside the uncertain region.
    None
  }
}
