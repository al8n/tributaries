//! The delivered event: a filesystem change routed to a caller [`Subscription`],
//! generic over the key component `C` and the caller value `V`.
//!
//! An [`Event`] is fully owned — it does **not** borrow the raw
//! [`tributary_fs::Event`] it was minted from. It carries the change's **located
//! key** (a `Vec<C>` of key components — for the fs source, a path's components),
//! its [`kind`](Event::kind), its umbrella [`epoch`](Event::epoch) stamp, the
//! [`Subscription`] it was routed to, and — where present — the fs-source metadata
//! (root-relative [`location`](Event::location), [`change_id`](Event::change_id),
//! and rename payload). Being owned and key-generic is what lets the sans-I/O
//! engines ([`route`](crate::route), [`coalesce`](crate::coalesce)) operate over the
//! key alone, with no coupling to any concrete source.

use std::vec::Vec;

use tributary_fs::{ChangeId, Epoch, EventKind, Location, MovedEvent};

use crate::{source::SourceEvent, subscription::Subscription};

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
/// assigned by the driver at delivery time (design §8) — **not** the raw
/// [`tributary_fs::Event::epoch`], which is per-`ScopeId` and **restarts at
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
  kind: EventKind,
  /// The rename **source** key, present only for a whole [`Moved`](EventKind::Moved)
  /// delivery — the second endpoint the coalescer keys on (design §6). `None` for
  /// every single-endpoint kind (including the synthesized move-out / move-in
  /// projections, which are plain `Removed` / `Created`).
  from: Option<Vec<C>>,
  /// The change's location relative to its watched root (fs-source metadata). The
  /// empty (root-anchored) location for a synthetic event.
  location: Location,
  /// The underlying kernel change id, for an fs-source event; `None` for one this
  /// crate synthesized (a widen `Rescan`, a coalesced-churn `Modified`).
  change_id: Option<ChangeId>,
  /// The caller value attributed to this delivery (design §3). **Not populated in
  /// 0.1.0**: every constructor sets it `None`. Attribution instead runs through the
  /// wait-free value plane — a caller resolves a delivered event's [`key`](Event::key)
  /// via [`WatchView::resolve`](crate::WatchView::resolve) /
  /// [`covering`](crate::WatchView::covering), which holds the authoritative per-root
  /// value, so `V` is never cloned onto each delivery. Per-event value wiring is
  /// reserved for a future version.
  value: Option<V>,
}

impl<C, V> Event<C, V> {
  /// Mints a synthetic event of `kind` at `key` under `location`, stamped `epoch`,
  /// for `subscription`.
  ///
  /// The coalescer's one collapse row that yields a kind carried by *neither* of the
  /// two collapsed events — `Removed` then `Created` → `Modified` (design §6) — mints
  /// its result here. A synthetic event carries no change id and no fs move payload.
  pub(crate) fn synthetic(
    subscription: Subscription,
    key: Vec<C>,
    location: Location,
    kind: EventKind,
    epoch: Epoch,
  ) -> Self {
    Self {
      subscription,
      epoch,
      key,
      kind,
      from: None,
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
      from: None,
      location: Location::new(),
      change_id: None,
      value: None,
    }
  }

  /// Retags a raw [`SourceEvent`] with the [`Subscription`] it fanned out to (design §5),
  /// carrying its located key, kind (including a whole [`Moved`](EventKind::Moved)'s
  /// payload), move-source key, location, and change id.
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
      from: event.from().map(<[C]>::to_vec),
      location: event.location().clone(),
      change_id: Some(event.change_id()),
      value: None,
    }
  }

  /// Mints the **move-out** projection of a source move for `subscription`: a synthesized
  /// [`Removed`](EventKind::Removed) at the move's source key (design §5).
  ///
  /// A subscriber covering only the source of a rename must learn the file **left** its
  /// tree; it cannot see the destination, so the move is projected to a plain
  /// `Removed(from)`. The generic source seam carries no second (source) location, so the
  /// projection is root-anchored; its key is the authoritative signal. The epoch is
  /// provisional (rebased by the driver, design §8).
  pub(crate) fn source_move_out<H>(subscription: Subscription, event: &SourceEvent<C, H>) -> Self
  where
    C: Clone,
  {
    Self {
      subscription,
      epoch: event.epoch(),
      key: event
        .from()
        .expect("move-out is only minted for a move")
        .to_vec(),
      kind: EventKind::Removed,
      from: None,
      location: Location::new(),
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
      from: None,
      location: event.location().clone(),
      change_id: None,
      value: None,
    }
  }

  /// Mints a synthetic [`Moved`](EventKind::Moved) fixture from `from` to `key`,
  /// stamped `epoch`, for `subscription` — a **test-only** constructor.
  ///
  /// A synthetic event cannot carry a real [`MovedEvent`] (its constructor is private
  /// to `tributary-fs`); production moves are always fs-source-backed. This exists
  /// only so the coalescer's sans-I/O tests can exercise the move-is-atomic
  /// invariant: the move is surfaced through [`move_from`](Self::move_from) (which the
  /// coalescer keys on), while [`kind`](Self::kind) stays
  /// [`Modified`](EventKind::Modified) and [`moved`](Self::moved) is `None`.
  #[cfg(test)]
  pub(crate) fn synthetic_moved(
    subscription: Subscription,
    key: Vec<C>,
    from: Vec<C>,
    epoch: Epoch,
  ) -> Self {
    Self {
      subscription,
      epoch,
      key,
      kind: EventKind::Modified,
      from: Some(from),
      location: Location::new(),
      change_id: None,
      value: None,
    }
  }

  /// Rebases this event's epoch onto the umbrella-relative stamp the driver computed
  /// in the subscription's monotone space (design §8), replacing the provisional raw
  /// fs epoch it was seeded with.
  #[inline]
  pub(crate) fn set_epoch(&mut self, epoch: Epoch) {
    self.epoch = epoch;
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

  /// The change's location relative to its watched root.
  ///
  /// A synthetic widen [`Rescan`](EventKind::Rescan) reports the empty
  /// (root-anchored) location, since its [`key`](Self::key) *is* the root.
  #[inline]
  pub fn location(&self) -> &Location {
    &self.location
  }

  /// What happened.
  #[inline]
  pub fn kind(&self) -> &EventKind {
    &self.kind
  }

  /// This subscription's monotone reconciliation epoch for this event.
  ///
  /// The **umbrella-relative** stamp (design §8), *not* the raw
  /// [`tributary_fs::Event::epoch`] — see the [type docs](Self). A delivered
  /// [`Rescan`](EventKind::Rescan) carries a stamp that strictly dominates every event
  /// previously delivered to this subscription; events with epochs dominated by a
  /// delivered `Rescan` may have been dropped, and everything they described is
  /// covered by re-enumerating the `Rescan`'s [`key`](Self::key).
  #[inline]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The change's unique id (monotonic per watcher), for an fs-source event.
  ///
  /// A synthetic event (a widen [`Rescan`](EventKind::Rescan), or a coalesced-churn
  /// [`Modified`](EventKind::Modified)) has no single underlying kernel change and so
  /// reports `None`; its dominance rides its [`epoch`](Self::epoch), not a change id.
  #[inline]
  pub const fn change_id(&self) -> Option<ChangeId> {
    self.change_id
  }

  /// The caller value attributed to this delivery (design §3), if any.
  ///
  /// **Always `None` in 0.1.0** — the per-event value is not populated in this version.
  /// Attribute a delivered event to its owning value by resolving its
  /// [`key`](Self::key) through the wait-free value plane
  /// ([`WatchView::resolve`](crate::WatchView::resolve) /
  /// [`covering`](crate::WatchView::covering)), which holds the authoritative per-root
  /// value. Per-event value wiring is reserved for a future version.
  #[inline]
  pub const fn value(&self) -> Option<&V> {
    self.value.as_ref()
  }

  /// Whether this is a [`Rescan`](EventKind::Rescan).
  #[inline]
  pub fn is_rescan(&self) -> bool {
    self.kind.is_rescan()
  }

  /// The rename payload, if this is an fs-source [`Moved`](EventKind::Moved).
  ///
  /// Only a real `tributary-fs`-backed whole move carries a [`MovedEvent`]; a
  /// synthesized event (a widen [`Rescan`](EventKind::Rescan), a coalesced-churn
  /// [`Modified`](EventKind::Modified), or a move-out/move-in projection) holds no fs
  /// payload, so this is `None` for one.
  #[inline]
  pub const fn moved(&self) -> Option<&MovedEvent> {
    self.kind.moved()
  }

  /// The rename source key, if this is a [`Moved`](EventKind::Moved) — the
  /// wrapper-level move detector the coalescer keys on (design §6, move-is-atomic).
  ///
  /// `Some` iff this delivery is a whole move; the destination is [`key`](Self::key).
  /// Uniform across an fs-source move and a synthetic (test-only) one.
  #[inline]
  pub(crate) fn move_from(&self) -> Option<&[C]> {
    self.from.as_deref()
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
}

/// The `OsString` components of a path — the located-key form the fs source keys on
/// (mirroring [`iradix`]'s `Path` key: one `OsString` per [`Path::components`] entry,
/// so `a/b` is an ancestor of `a/b/c` but not of `a/bc`).
///
/// [`Path::components`]: std::path::Path::components
pub(crate) fn path_components(path: &std::path::Path) -> Vec<std::ffi::OsString> {
  path
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}
