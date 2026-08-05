//! The umbrella's source-neutral event vocabulary ([`EventKind`]) and the delivered
//! [`Event`]: a change routed to a caller [`Subscription`], generic over the key
//! component `C` and the caller value `V`.
//!
//! An [`Event`] is fully owned — it does **not** borrow the raw source event it was
//! minted from. It carries the change's **located key** (a `Vec<C>` of key components —
//! for the fs source, a path's components), its [`kind`](Event::kind) — including, for a
//! [`Moved`](EventKind::Moved), the move's source key — its umbrella
//! [`epoch`](Event::epoch) stamp, the [`Subscription`] it was routed to, and — where the
//! source supplied them — the root-relative [`location`](Event::location) and
//! [`change_id`](Event::change_id). Being owned and key-generic is what lets the sans-I/O
//! engines ([`route`](crate::route), [`coalesce`](crate::coalesce)) operate over the
//! key alone, with no coupling to any concrete source.

use std::vec::Vec;

use tributary_proto::{ChangeId, Epoch, Location};

use crate::{source::SourceEvent, subscription::Subscription};

#[cfg(test)]
mod tests;

/// What kind of change an [`Event`] reports — the umbrella's **source-neutral**
/// vocabulary, generic over the key component `C`.
///
/// The umbrella owns this vocabulary; every [`Source`](crate::Source) (the fs binding
/// included) maps its raw kinds into it at its binding. A [`Moved`](Self::Moved) carries
/// its second endpoint — the source key — **in-kind**, in the same `C` component space
/// the event is keyed in, so a whole-move delivery is lossless without any parallel
/// side-channel field.
///
/// # Source honesty (the binding contract)
///
/// A source maps into this vocabulary **honestly**, degrading only ever toward the
/// conservative signal — never inventing precision and never leaving a kind half-mapped:
///
/// - a source that cannot tell created-from-modified emits [`Modified`](Self::Modified)
///   conservatively;
/// - a source that cannot pair a rename degrades it to [`Removed`](Self::Removed) plus
///   [`Created`](Self::Created) **at its binding** — never half a move above the seam
///   (a `Moved` either carries its real source key or is not a `Moved` at all);
/// - an unknown upstream kind folds to [`Rescan`](Self::Rescan) at the binding — the
///   conservative re-read signal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventKind<C> {
  /// An object appeared at the event's key.
  Created,
  /// An object's content changed at the event's key.
  Modified,
  /// An object disappeared from the event's key.
  Removed,
  /// The object moved within the watch: the event's key is the destination, `from` is
  /// the source key in the same component space — the second endpoint routing fans out
  /// (design §5).
  Moved {
    /// The move's source key: where the object moved away from, in the same `C`
    /// component space as the event's (destination) key.
    from: Vec<C>,
  },
  /// Coverage became uncertain at (and below) the event's key: re-enumerate it.
  /// Delivered with an epoch that strictly dominates every prior delivery to its
  /// subscription; bypasses coverage, interest, filter, and coalescing.
  Rescan,
}

impl<C> EventKind<C> {
  /// The stable snake_case name of this kind.
  #[inline]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Created => "created",
      Self::Modified => "modified",
      Self::Removed => "removed",
      Self::Moved { .. } => "moved",
      Self::Rescan => "rescan",
    }
  }

  /// Whether this is [`Created`](Self::Created).
  #[inline]
  pub const fn is_created(&self) -> bool {
    matches!(self, Self::Created)
  }

  /// Whether this is [`Modified`](Self::Modified).
  #[inline]
  pub const fn is_modified(&self) -> bool {
    matches!(self, Self::Modified)
  }

  /// Whether this is [`Removed`](Self::Removed).
  #[inline]
  pub const fn is_removed(&self) -> bool {
    matches!(self, Self::Removed)
  }

  /// Whether this is [`Moved`](Self::Moved).
  #[inline]
  pub const fn is_moved(&self) -> bool {
    matches!(self, Self::Moved { .. })
  }

  /// Whether this is [`Rescan`](Self::Rescan).
  #[inline]
  pub const fn is_rescan(&self) -> bool {
    matches!(self, Self::Rescan)
  }

  /// The move's source key, iff this is [`Moved`](Self::Moved) — the second endpoint
  /// routing fans out. `None` for every single-endpoint kind.
  #[inline]
  pub fn moved_from(&self) -> Option<&[C]> {
    match self {
      Self::Moved { from } => Some(from),
      _ => None,
    }
  }
}

impl<C> core::fmt::Display for EventKind<C> {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// One change, delivered to a caller [`Subscription`], keyed by components of type
/// `C` and carrying the caller value type `V`.
///
/// A single raw source event fans out to every overlapping subscription that covers
/// it (design §5), each seeing it retagged with its own [`subscription`](Self::subscription)
/// id. The event is keyed by its [`key`](Self::key) — a `Vec<C>` of components, the
/// coordinate coverage and coalescing operate in (for the fs source, the change
/// path's components).
///
/// # Epoch is umbrella-relative, not the raw fs epoch
///
/// [`epoch`](Self::epoch) is the umbrella's own per-subscription monotone stamp,
/// assigned by the driver at delivery time (design §8) — **not** the raw source epoch
/// (`tributary-fs`'s per-event epoch), which is per-`ScopeId` and **restarts at
/// [`Epoch::START`] on every new kernel arm**. Because a subscription is delivered
/// from *different* fs roots over its lifetime (a widen re-points it onto a
/// freshly-armed wider root whose epoch sequence restarts at 0), the raw fs epoch is
/// not a valid dominance order across a re-point; the driver rebases every delivered
/// event into the subscription's own monotone space so the no-silent-loss /
/// re-enumeration contract holds end-to-end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event<C, V> {
  subscription: Subscription,
  /// The umbrella-relative stamp (design §8), assigned by the driver at delivery
  /// time in this subscription's monotone epoch space — **not** the raw fs epoch.
  epoch: Epoch,
  /// The change's located key: its components in `C`-space (for the fs source, the
  /// change path's components). Coverage and coalescing key on this.
  key: Vec<C>,
  /// What happened — including, for a whole [`Moved`](EventKind::Moved) delivery, the
  /// move's source key (the second endpoint the coalescer keys on, design §6). The
  /// synthesized move-out / move-in projections are plain `Removed` / `Created`.
  kind: EventKind<C>,
  /// The change's location relative to its watched root (fs-source metadata). The
  /// empty (root-anchored) location for a synthetic event.
  location: Location,
  /// The underlying change id, when the source supplied one; `None` for an event this
  /// crate synthesized (a widen `Rescan`, a coalesced-churn `Modified`) or a source
  /// that mints no ids.
  change_id: Option<ChangeId>,
  /// The caller value attributed to this delivery (design §3): the value of the
  /// [`subscription`](Self::subscription) this event was routed to, **baked on at emit
  /// time** by the driver (exposed by [`value`](Self::value)). Because it is captured
  /// when the event is minted — while the owning subscription is still live — it is
  /// **stable across teardown**: a consumer draining a queued event after the owner has
  /// quiesced (and the [`WatchView`](crate::WatchView) has gone empty) still attributes
  /// it from here, with no live view lookup. `None` only for an event with no live
  /// owning subscription (a pure-test fixture, or a delivery whose subscription raced
  /// retirement).
  value: Option<V>,
}

impl<C, V> Event<C, V> {
  /// Mints a synthetic event of `kind` at `key` under `location`, stamped `epoch`,
  /// for `subscription`.
  ///
  /// The coalescer's one collapse row that yields a kind carried by *neither* of the
  /// two collapsed events — `Removed` then `Created` → `Modified` (design §6) — mints
  /// its result here. A synthetic event carries no change id.
  pub(crate) fn synthetic(
    subscription: Subscription,
    key: Vec<C>,
    location: Location,
    kind: EventKind<C>,
    epoch: Epoch,
  ) -> Self {
    Self {
      subscription,
      epoch,
      key,
      kind,
      location,
      change_id: None,
      value: None,
    }
  }

  /// Mints the synthetic dominating [`Rescan`](EventKind::Rescan) delivered to a
  /// subscription re-pointed onto a widened root (design §8).
  ///
  /// `epoch` must strictly dominate every epoch previously delivered to
  /// `subscription`; the driver derives it from that subscription's high-water
  /// epoch. `key` is the widened root the consumer must re-enumerate.
  pub(crate) fn rescan(subscription: Subscription, key: Vec<C>, epoch: Epoch) -> Self {
    Self {
      subscription,
      epoch,
      key,
      kind: EventKind::Rescan,
      location: Location::new(),
      change_id: None,
      value: None,
    }
  }

  /// Retags a raw [`SourceEvent`] with the [`Subscription`] it fanned out to (design §5),
  /// carrying its located key, kind (including a whole [`Moved`](EventKind::Moved)'s
  /// in-kind source key), location, and change id.
  ///
  /// The event is born with the source's **raw** epoch as a provisional stamp; the driver
  /// rebases it into this subscription's monotone space via [`set_epoch`](Self::set_epoch)
  /// before delivery (design §8), so the raw value is never observed by a caller. This is
  /// the key-generic mint the owner's fan-out uses, over the [`Source`](crate::Source)
  /// seam rather than a concrete filesystem event.
  pub(crate) fn from_source<H>(subscription: Subscription, event: &SourceEvent<C, H>) -> Self
  where
    C: Clone,
  {
    Self {
      subscription,
      epoch: event.epoch(),
      key: event.key().to_vec(),
      kind: event.kind().clone(),
      location: event.location().clone(),
      change_id: event.change_id(),
      value: None,
    }
  }

  /// Mints the **move-out** projection of a source move for `subscription`: a synthesized
  /// [`Removed`](EventKind::Removed) at the move's source key (design §5).
  ///
  /// A subscriber covering only the source of a rename must learn the file **left** its
  /// tree; it cannot see the destination, so the move is projected to a plain
  /// `Removed(from)`.
  ///
  /// The projection carries the move's **source** location
  /// ([`SourceEvent::move_from_location`]), not the destination's: the delivered key is the
  /// source endpoint, so pairing it with the destination's coordinate would name a path this
  /// delivery is not about — and root-anchoring it (the only option before the seam carried a
  /// second location) hands a caller's location-aware [`Filter`](crate::Filter) the watched
  /// root's coordinate for a change that is not at the root, which can reject the very
  /// removal this subscriber exists to see. The pair is coherent by the same rule the
  /// destination pair obeys, so fan-out's rebase strips the right depth from it. A source
  /// that did not state one leaves the projection root-anchored, with the key as the
  /// authoritative signal, exactly as before. The epoch is provisional (rebased by the
  /// driver, design §8).
  pub(crate) fn source_move_out<H>(subscription: Subscription, event: &SourceEvent<C, H>) -> Self
  where
    C: Clone,
  {
    Self {
      subscription,
      epoch: event.epoch(),
      key: event
        .move_from()
        .expect("move-out is only minted for a move")
        .to_vec(),
      kind: EventKind::Removed,
      location: event.move_from_location().cloned().unwrap_or_default(),
      change_id: None,
      value: None,
    }
  }

  /// Mints the **move-in** projection of a source move for `subscription`: a synthesized
  /// [`Created`](EventKind::Created) at the move's destination key (design §5).
  ///
  /// A subscriber covering only the destination of a rename must learn the file
  /// **arrived** in its tree from outside its watch; it cannot see the source, so the move
  /// is projected to a plain `Created(to)`. The epoch is provisional (rebased by the
  /// driver, design §8).
  pub(crate) fn source_move_in<H>(subscription: Subscription, event: &SourceEvent<C, H>) -> Self
  where
    C: Clone,
  {
    Self {
      subscription,
      epoch: event.epoch(),
      key: event.key().to_vec(),
      kind: EventKind::Created,
      location: event.location().clone(),
      change_id: None,
      value: None,
    }
  }

  /// Mints the **clamped recovery projection** of a source
  /// [`Rescan`](EventKind::Rescan) for a subscription the loss strictly contains: the
  /// same coverage-loss signal, re-keyed to `key` — that subscription's own registered
  /// key (design §5).
  ///
  /// A rescan above a subscription makes *everything the subscription owns* uncertain,
  /// and nothing more; naming the wider key would instruct a per-subscription consumer
  /// to inspect paths outside its own watch, which no consumer can act on and which
  /// breaks the isolation a per-subscription lane exists to provide. The clamped key
  /// **is** the subscription root, so the location is the empty (root-anchored) one. The
  /// change id rides along: the clamp narrows which subtree is named, not which source
  /// record proved the loss. The epoch is provisional (rebased by the driver, design §8).
  pub(crate) fn source_rescan_clamped<H>(
    subscription: Subscription,
    event: &SourceEvent<C, H>,
    key: &[C],
  ) -> Self
  where
    C: Clone,
  {
    Self {
      subscription,
      epoch: event.epoch(),
      key: key.to_vec(),
      kind: EventKind::Rescan,
      location: Location::new(),
      change_id: event.change_id(),
      value: None,
    }
  }

  /// Rebases this delivery's [`location`](Self::location) out of the coordinate the
  /// source **captured** it in and into the receiving subscription's, dropping the first
  /// `strip` segments — where `strip` is the subscription's depth below the root that
  /// capture was anchored at.
  ///
  /// The raw source location is relative to whatever root was armed when the change was
  /// recorded, and that root moves: an unrelated caller watching an ancestor widens it,
  /// and a survivor can keep it wide long after the widener departs. A subscription's own
  /// key never moves, so it is the only coordinate a caller can hold a stable predicate
  /// against. Fan-out rebases every delivery here, before the filter gate, so a
  /// depth/location filter written once keeps meaning what it meant — instead of silently
  /// starting to reject when somebody else's `watch` re-coordinates it underneath.
  ///
  /// `strip` is derived per event from the anchor the event itself carries
  /// ([`RoutableEvent::captured_root_depth`](crate::route::RoutableEvent::captured_root_depth)),
  /// never from the root armed at delivery time: an in-place widen preserves the handle
  /// and the queue behind it, so a pre-widen change can be delivered after the root it
  /// was captured under has already widened, and only its own anchor rebases it right.
  ///
  /// A `strip` of zero (the subscription is at or above the captured root) and an
  /// already-empty location are both no-ops; a `strip` past the end yields the empty
  /// location rather than panicking, so a source that supplies a shallower location than
  /// its key implies degrades to root-anchored instead of failing.
  #[inline]
  pub(crate) fn rebase_location(&mut self, strip: usize) {
    if strip == 0 || self.location.is_empty() {
      return;
    }
    self.location = Location::from_segments(self.location.segments().iter().skip(strip).cloned());
  }

  /// Drops this delivery's [`location`](Self::location) to the root-anchored empty one,
  /// for a receiving subscription whose coordinate the delivery cannot express — it sits
  /// *above* the root the change was captured against, so the leading segments are simply
  /// not in the event (see
  /// [`RoutableEvent::anchor_at_root`](crate::route::RoutableEvent::anchor_at_root)).
  ///
  /// [`key`](Self::key) is untouched and remains the authoritative signal, as it already
  /// is for the move-out projection and the clamped rescan, which are born this way.
  #[inline]
  pub(crate) fn anchor_location_at_root(&mut self) {
    self.location = Location::new();
  }

  /// Rebases this event's epoch onto the umbrella-relative stamp the driver computed
  /// in the subscription's monotone space (design §8), replacing the provisional raw
  /// fs epoch it was seeded with.
  #[inline]
  pub(crate) fn set_epoch(&mut self, epoch: Epoch) {
    self.epoch = epoch;
  }

  /// Bakes the owning subscription's caller value onto this delivery (design §3) — the
  /// per-event attribution [`value`](Self::value) returns. The driver sets it at emit
  /// time from the live subscription this event was routed to, so attribution survives
  /// the subscription/owner teardown that empties the [`WatchView`](crate::WatchView)
  /// (its `resolve` would then answer `None`, but the baked value persists on the event).
  #[inline]
  pub(crate) fn set_value(&mut self, value: Option<V>) {
    self.value = value;
  }

  /// The caller subscription this event was routed to.
  #[inline]
  pub const fn subscription(&self) -> Subscription {
    self.subscription
  }

  /// The change's located key — its components in `C`-space (for the fs source, the
  /// change path's components). The coordinate coverage and coalescing key on.
  #[inline]
  pub fn key(&self) -> &[C] {
    &self.key
  }

  /// The change's location relative to **the key this delivery's
  /// [`subscription`](Self::subscription) watches** — never relative to the physical
  /// root the umbrella happens to have armed underneath it.
  ///
  /// The two differ whenever a subscription is covered by a broader armed root, which
  /// unrelated callers can create and destroy at any time (a `watch` of an ancestor
  /// widens the shared root; a survivor can keep it wide after the widener leaves). The
  /// driver rebases this coordinate per subscriber at fan-out, so watching `/a/b` always
  /// reports `x` for a change at `/a/b/x` — whether or not somebody else is watching
  /// `/a`. A caller may therefore hold a stable depth/location predicate against it.
  ///
  /// A synthetic widen [`Rescan`](EventKind::Rescan), and the clamped recovery
  /// projection of a rescan that contained this subscription, report the empty
  /// (root-anchored) location, since their [`key`](Self::key) *is* the subscription's own
  /// key. A move-out projection reports the move's **source** endpoint — the coordinate of
  /// its own [`key`](Self::key) — when the source stated it
  /// ([`SourceEvent::move_from_location`](crate::SourceEvent::move_from_location)), and the
  /// empty location when it did not.
  #[inline]
  pub fn location(&self) -> &Location {
    &self.location
  }

  /// What happened.
  #[inline]
  pub fn kind(&self) -> &EventKind<C> {
    &self.kind
  }

  /// This subscription's monotone reconciliation epoch for this event.
  ///
  /// The **umbrella-relative** stamp (design §8), *not* the raw source epoch
  /// ([`SourceEvent::epoch`](crate::SourceEvent::epoch)) — see the [type docs](Self). A delivered
  /// [`Rescan`](EventKind::Rescan) carries a stamp that strictly dominates every event
  /// previously delivered to this subscription; events with epochs dominated by a
  /// delivered `Rescan` may have been dropped, and everything they described is
  /// covered by re-enumerating the `Rescan`'s [`key`](Self::key).
  #[inline]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The change's unique id (monotonic per source), when the source supplied one.
  ///
  /// A synthetic event (a widen [`Rescan`](EventKind::Rescan), a coalesced-churn
  /// [`Modified`](EventKind::Modified), or a move-out/move-in projection) has no single
  /// underlying source change and so reports `None` — as does an event from a source
  /// that mints no ids; dominance rides the [`epoch`](Self::epoch), not a change id.
  #[inline]
  pub const fn change_id(&self) -> Option<ChangeId> {
    self.change_id
  }

  /// The caller value attributed to this delivery (design §3): the value of the
  /// [`subscription`](Self::subscription) this event was routed to, baked on by the
  /// driver at emit time.
  ///
  /// This is the **per-event attribution**, and it is **stable across teardown**: the
  /// value is captured when the event is minted (while its owning subscription is live),
  /// so a consumer draining a queued event *after* the owner has torn down — when the
  /// [`WatchView`](crate::WatchView) has been emptied and
  /// [`resolve`](crate::WatchView::resolve) would answer `None` — still attributes it
  /// from here. Prefer this to attribute a delivered event; use
  /// [`WatchView::resolve`](crate::WatchView::resolve) /
  /// [`covering`](crate::WatchView::covering) for the *live* "is key `k` watched, and by
  /// whom" query (membership + pre-watch dedup), which reflects the current watch-set
  /// rather than the moment a given event was emitted.
  ///
  /// `None` only when the event has no live owning subscription (a pure-test fixture, or
  /// a delivery whose subscription raced retirement).
  #[inline]
  pub const fn value(&self) -> Option<&V> {
    self.value.as_ref()
  }

  /// Whether this is a [`Rescan`](EventKind::Rescan).
  #[inline]
  pub fn is_rescan(&self) -> bool {
    self.kind.is_rescan()
  }

  /// Whether this event bears on `key` — true iff `key` is one of the event's
  /// **affected endpoints**, or the event obliges re-enumeration of `key`:
  ///
  /// - it names `key` exactly ([`key`](Self::key), the destination for a move);
  /// - it is a whole [`Moved`](EventKind::Moved) whose **source**
  ///   ([`move_from`](Self::move_from)) is `key` — a rename has two affected endpoints
  ///   and the object left that one, which is a fact about `key` as much as the arrival
  ///   is a fact about the destination;
  /// - it is a [`Rescan`](EventKind::Rescan) at `key` or an ancestor of it (a rescan
  ///   obliges re-enumeration of everything below its key).
  ///
  /// The dispatch idiom every re-enumeration-class consumer needs: a consumer tracking
  /// one object asks `reaches(that_object)` and re-reads it whenever the answer is true.
  /// Omitting the move source would let a tracked file be renamed **away** without its
  /// tracker ever being told — the whole move is delivered (the subscription covers both
  /// endpoints), the tracker asks about the only key it knows, and gets `false`. That is
  /// exactly the silent staleness this predicate exists to prevent.
  ///
  /// This is an **endpoint** test, not a subtree test: an ordinary delta below `key` does
  /// not reach `key` (only a `Rescan` propagates downward). A consumer that wants "did
  /// anything happen inside my subtree" tests `event.key().starts_with(root)` — or, for a
  /// per-subscription lane, already knows the answer is yes.
  #[inline]
  pub fn reaches(&self, key: &[C]) -> bool
  where
    C: PartialEq,
  {
    self.key() == key
      || self.move_from() == Some(key)
      || (self.kind().is_rescan() && key.starts_with(self.key()))
  }

  /// The move's source key, if this is a whole [`Moved`](EventKind::Moved) delivery —
  /// the second endpoint the coalescer keys on (design §6, move-is-atomic).
  ///
  /// `Some` iff this delivery is a whole move; the destination is [`key`](Self::key).
  /// A synthesized move-out / move-in projection is a plain `Removed` / `Created` and
  /// reports `None`.
  #[inline]
  pub fn move_from(&self) -> Option<&[C]> {
    self.kind.moved_from()
  }
}

impl<V> Event<std::ffi::OsString, V> {
  /// The change's absolute path — the fs-source convenience over [`key`](Self::key),
  /// reconstructed from the located key's `OsString` components.
  ///
  /// This allocates a fresh [`PathBuf`](std::path::PathBuf) from the key components on
  /// every call; [`key`](Self::key) is the allocation-free `&[C]` accessor for hot
  /// paths.
  #[inline]
  pub fn path(&self) -> std::path::PathBuf {
    self.key.iter().collect()
  }

  /// The move's source as an absolute path, if this is a whole
  /// [`Moved`](EventKind::Moved) delivery — the fs-source convenience over
  /// [`move_from`](Self::move_from), mirroring [`path`](Self::path).
  ///
  /// This allocates a fresh [`PathBuf`](std::path::PathBuf) from the source key's
  /// components on every call; [`move_from`](Self::move_from) is the allocation-free
  /// `Option<&[C]>` accessor for hot paths.
  #[inline]
  pub fn moved_from_path(&self) -> Option<std::path::PathBuf> {
    self.move_from().map(|from| from.iter().collect())
  }
}

/// The `OsString` components of a path — the located-key form the fs source keys on
/// (mirroring [`iradix`]'s `Path` key: one `OsString` per [`Path::components`] entry,
/// so `a/b` is an ancestor of `a/b/c` but not of `a/bc`). Only the fs binding converts
/// between keys and paths, so this rides its feature.
///
/// [`Path::components`]: std::path::Path::components
#[cfg(feature = "fs")]
pub(crate) fn path_components(path: &std::path::Path) -> Vec<std::ffi::OsString> {
  path
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}
