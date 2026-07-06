//! The delivered event: a [`tributary_fs::Event`] retagged with the
//! [`Subscription`] it was routed to.

use std::path::{Path, PathBuf};

use tributary_fs::{Epoch, Event as FsEvent, EventKind, Location, MovedEvent};

use crate::subscription::Subscription;

/// One filesystem change, delivered to a caller [`Subscription`].
///
/// A retagging of a [`tributary_fs::Event`]: it re-exposes every accessor of the
/// wrapped event (path, kind, change id, …) unchanged, and adds
/// [`subscription`](Self::subscription) — the id of the caller watch this event
/// was fanned out to — plus its own [`epoch`](Self::epoch) stamp (below). A single
/// raw event fans out to every overlapping subscription that covers it (design §5),
/// each seeing it under its own id.
///
/// # Epoch is umbrella-relative, not the raw fs epoch
///
/// [`epoch`](Self::epoch) is **not** the wrapped [`tributary_fs::Event::epoch`]. It
/// is the umbrella's own per-subscription monotone stamp, assigned by the driver at
/// delivery time (design §8). This matters because the fs [`Epoch`] is per-`ScopeId`
/// and **restarts at [`Epoch::START`] on every new kernel arm** — a subscription is
/// delivered from *different* fs roots over its lifetime (a widen re-points it onto
/// a freshly-armed wider root whose epoch sequence restarts at 0), so the raw fs
/// epoch is not a valid dominance order across a re-point. The driver therefore
/// stamps every delivered event in the subscription's own monotone space
/// (`epoch_base + raw_fs_epoch`, rebased on each widen), so the epoch is monotone
/// per subscription across re-points and the no-silent-loss / re-enumeration
/// contract holds end-to-end. The synthetic [`Rescan`](EventKind::Rescan) emitted
/// when a subscription is re-pointed onto a widened root carries a stamp that
/// strictly dominates every event previously delivered to that subscription, while
/// the new root's genuine post-widen events tie-or-exceed it (so they are **not**
/// dominated), so a consumer re-enumerates the wider root truthfully and keeps every
/// real post-widen event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
  subscription: Subscription,
  /// The umbrella-relative stamp (design §8), assigned by the driver at delivery
  /// time in this subscription's monotone epoch space — **not** the raw fs epoch.
  epoch: Epoch,
  inner: Inner,
}

/// The event payload: either a real `tributary-fs` delivery or one this crate
/// synthesized (which cannot wrap a [`tributary_fs::Event`], whose constructor is
/// private to that crate).
///
/// Two things mint a [`Synthetic`] in production: the widen re-point's dominating
/// [`Rescan`](EventKind::Rescan) (design §8), and the coalescer's one collapse row
/// that yields a *fresh* kind — `Removed` then `Created` → `Modified` (design §6),
/// where neither the buffered nor the incoming event is itself a `Modified`. Every
/// other collapse keeps one of the two real (possibly [`Fs`](Inner::Fs)) events, so
/// its change id survives.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Inner {
  /// A raw `tributary-fs` event, retagged.
  Fs(FsEvent),
  /// An event minted at this layer (a widen `Rescan`, or a coalesced-churn
  /// `Modified`). Its epoch lives on the outer [`Event`], in the umbrella-relative
  /// space every delivered event is stamped in.
  Synthetic(Synthetic),
}

/// The fields a synthetic event needs to satisfy the same accessors a wrapped
/// [`tributary_fs::Event`] answers: its path, root-relative location, and kind. It
/// carries no change id (there is no underlying kernel change).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Synthetic {
  path: PathBuf,
  location: Location,
  kind: EventKind,
  /// The rename source, present only for a synthetic [`Moved`](EventKind::Moved).
  ///
  /// A synthetic event cannot store an [`EventKind::Moved`] (its
  /// [`MovedEvent`](tributary_fs::MovedEvent) payload has no public constructor — the
  /// umbrella never fabricates fs vocabulary), so a synthetic move keeps its `kind` as
  /// the closest lifecycle marker and carries its source here instead; the wrapper
  /// reports the move through [`move_from`](Event::move_from), which the coalescer
  /// keys on. Synthetic moves are a **test-only** construct — production moves are
  /// always [`Fs`](Inner::Fs)-backed with a real payload — so this is `None` on every
  /// event the crate itself mints.
  from: Option<PathBuf>,
}

impl Event {
  /// Retags a raw `tributary-fs` event with the subscription it was routed to.
  ///
  /// The retagged event is born carrying the wrapped event's **raw** fs epoch as a
  /// provisional stamp; the driver immediately rebases it into this subscription's
  /// monotone space via [`set_epoch`](Self::set_epoch) before delivery (design §8),
  /// so the raw value is never observed by a caller. Keeping the retag (in the
  /// unchanged [`fan_out`](crate::route) seam) separate from the stamp (driver-owned,
  /// since only the driver holds the per-subscription epoch state) is what lets the
  /// stamping be a pure, shared step.
  pub(crate) fn from_fs(subscription: Subscription, event: FsEvent) -> Self {
    Self {
      subscription,
      epoch: event.epoch(),
      inner: Inner::Fs(event),
    }
  }

  /// Rebases this event's epoch onto the umbrella-relative stamp the driver computed
  /// in the subscription's monotone space (design §8), replacing the provisional raw
  /// fs epoch [`from_fs`](Self::from_fs) seeded.
  #[inline]
  pub(crate) fn set_epoch(&mut self, epoch: Epoch) {
    self.epoch = epoch;
  }

  /// Mints the synthetic dominating [`Rescan`](EventKind::Rescan) delivered to a
  /// subscription re-pointed onto a widened root (design §8).
  ///
  /// `epoch` must strictly dominate every epoch previously delivered to
  /// `subscription`; the driver derives it from that subscription's high-water
  /// epoch. `path` is the widened root the consumer must re-enumerate.
  pub(crate) fn rescan(subscription: Subscription, path: PathBuf, epoch: Epoch) -> Self {
    Self {
      subscription,
      epoch,
      inner: Inner::Synthetic(Synthetic {
        path,
        location: Location::new(),
        kind: EventKind::Rescan,
        from: None,
      }),
    }
  }

  /// Mints the **move-out** projection of a real `tributary-fs` move for
  /// `subscription`: a synthesized [`Removed`](EventKind::Removed) at the move's
  /// source (design §5).
  ///
  /// A subscriber covering only the source of a rename must learn the file **left**
  /// its tree; it cannot see the destination (outside its watch), so the move is
  /// projected down to a plain `Removed(from)`. The event is minted through the
  /// [`Synthetic`] wrapper — the umbrella never fabricates fs vocabulary — carrying
  /// the source path and its root-relative location, reconstructed from `event`.
  ///
  /// The epoch is seeded from the wrapped event's raw fs epoch as a provisional
  /// stamp; the driver rebases it into `subscription`'s monotone space via
  /// [`set_epoch`](Self::set_epoch) before delivery (design §8), exactly as for a
  /// whole delivery.
  pub(crate) fn move_out(subscription: Subscription, event: &FsEvent) -> Self {
    let from = event
      .kind()
      .moved()
      .expect("move_out is only minted for a Moved event")
      .from()
      .to_path_buf();
    let location = source_location(event);
    Self {
      subscription,
      epoch: event.epoch(),
      inner: Inner::Synthetic(Synthetic {
        path: from,
        location,
        kind: EventKind::Removed,
        from: None,
      }),
    }
  }

  /// Mints the **move-in** projection of a real `tributary-fs` move for
  /// `subscription`: a synthesized [`Created`](EventKind::Created) at the move's
  /// destination (design §5).
  ///
  /// A subscriber covering only the destination of a rename must learn the file
  /// **arrived** in its tree from outside its watch; it cannot see the source, so the
  /// move is projected down to a plain `Created(to)`. The destination path and
  /// location are the wrapped event's own [`path`](FsEvent::path) /
  /// [`location`](FsEvent::location). The epoch is provisional (see
  /// [`move_out`](Self::move_out)); the driver rebases it (design §8).
  pub(crate) fn move_in(subscription: Subscription, event: &FsEvent) -> Self {
    Self {
      subscription,
      epoch: event.epoch(),
      inner: Inner::Synthetic(Synthetic {
        path: event.path().to_path_buf(),
        location: event.location().clone(),
        kind: EventKind::Created,
        from: None,
      }),
    }
  }

  /// Mints a synthetic event of an arbitrary `kind` at `location` under `path`,
  /// stamped `epoch`, for `subscription`.
  ///
  /// The coalescer's one collapse row that yields a kind carried by *neither* of the
  /// two collapsed events — `Removed` then `Created` → `Modified` (design §6) — mints
  /// its result here, taking `path`/`location` from the pair (identical, since they
  /// share a canonical path) and the newest observation's `epoch`. Every other
  /// collapse keeps a real event, so this is the only kind the crate synthesizes
  /// besides the widen [`Rescan`](Self::rescan). (The coalescer's tests also reach for
  /// it to build [`Created`](EventKind::Created)/[`Modified`](EventKind::Modified)/
  /// [`Removed`](EventKind::Removed)/[`Rescan`](EventKind::Rescan) fixtures without the
  /// private `tributary-fs` constructor; see [`synthetic_moved`](Self::synthetic_moved)
  /// for the move fixture.)
  pub(crate) fn synthetic(
    subscription: Subscription,
    path: PathBuf,
    location: Location,
    kind: EventKind,
    epoch: Epoch,
  ) -> Self {
    Self {
      subscription,
      epoch,
      inner: Inner::Synthetic(Synthetic {
        path,
        location,
        kind,
        from: None,
      }),
    }
  }

  /// Mints a synthetic [`Moved`](EventKind::Moved) fixture from `from` to `path`,
  /// stamped `epoch`, for `subscription` — a **test-only** constructor.
  ///
  /// A synthetic event cannot carry an [`EventKind::Moved`]: its
  /// [`MovedEvent`](tributary_fs::MovedEvent) has no public constructor and the
  /// umbrella never fabricates fs vocabulary. Production moves are always
  /// [`Fs`](Inner::Fs)-backed with a real payload, so nothing in the crate mints one;
  /// this exists only so the coalescer's sans-I/O tests can exercise the
  /// move-is-atomic invariant. The move is surfaced through
  /// [`move_from`](Self::move_from) (which the coalescer keys on) — its public
  /// [`kind`](Self::kind) stays [`Modified`](EventKind::Modified) and its
  /// [`moved`](Self::moved) is `None`, since it holds no fs payload.
  #[cfg(test)]
  pub(crate) fn synthetic_moved(
    subscription: Subscription,
    path: PathBuf,
    from: PathBuf,
    epoch: Epoch,
  ) -> Self {
    Self {
      subscription,
      epoch,
      inner: Inner::Synthetic(Synthetic {
        path,
        location: Location::new(),
        kind: EventKind::Modified,
        from: Some(from),
      }),
    }
  }

  /// The caller subscription this event was routed to.
  #[inline]
  pub const fn subscription(&self) -> Subscription {
    self.subscription
  }

  /// The affected object's absolute path.
  ///
  /// See [`tributary_fs::Event::path`] for the byte-form caveat; for a synthetic
  /// widen [`Rescan`](EventKind::Rescan) this is the widened root to re-enumerate.
  #[inline]
  pub fn path(&self) -> &Path {
    match &self.inner {
      Inner::Fs(event) => event.path(),
      Inner::Synthetic(synthetic) => synthetic.path.as_path(),
    }
  }

  /// The affected object's location relative to its watched root.
  ///
  /// A synthetic widen [`Rescan`](EventKind::Rescan) reports the empty
  /// (root-anchored) location, since its [`path`](Self::path) *is* the root.
  #[inline]
  pub fn location(&self) -> &Location {
    match &self.inner {
      Inner::Fs(event) => event.location(),
      Inner::Synthetic(synthetic) => &synthetic.location,
    }
  }

  /// What happened.
  #[inline]
  pub fn kind(&self) -> &EventKind {
    match &self.inner {
      Inner::Fs(event) => event.kind(),
      Inner::Synthetic(synthetic) => &synthetic.kind,
    }
  }

  /// This subscription's monotone reconciliation epoch for this event.
  ///
  /// This is the **umbrella-relative** stamp (design §8), *not* the raw
  /// [`tributary_fs::Event::epoch`]. Because the fs epoch restarts at
  /// [`Epoch::START`] on every new kernel arm, the driver rebases each subscription
  /// onto its own monotone space (`epoch_base + raw_fs_epoch`, bumped on every
  /// widen), so this value is monotone-nondecreasing across the subscription's whole
  /// lifetime — including across a widen re-point onto a freshly-armed wider root.
  ///
  /// A delivered [`Rescan`](EventKind::Rescan) — one fs itself reports, or the
  /// synthetic one minted on a widen — carries a stamp that strictly dominates every
  /// event previously delivered to this subscription; events with epochs dominated
  /// by a delivered `Rescan` may have been dropped, and everything they described is
  /// covered by re-enumerating the `Rescan`'s [`path`](Self::path). See
  /// [`tributary_fs::Event::epoch`] for the underlying re-enumeration contract.
  #[inline]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The change's unique id (monotonic per watcher), for a wrapped event.
  ///
  /// A synthetic event (a widen [`Rescan`](EventKind::Rescan), or a coalesced-churn
  /// [`Modified`](EventKind::Modified)) has no single underlying kernel change and so
  /// reports `None`; its dominance rides its [`epoch`](Self::epoch), not a change id.
  #[inline]
  pub fn change_id(&self) -> Option<tributary_fs::ChangeId> {
    match &self.inner {
      Inner::Fs(event) => Some(event.change_id()),
      Inner::Synthetic(_) => None,
    }
  }

  /// Whether this is a [`Rescan`](EventKind::Rescan) (wrapped or synthetic).
  #[inline]
  pub fn is_rescan(&self) -> bool {
    match &self.inner {
      Inner::Fs(event) => event.is_rescan(),
      Inner::Synthetic(synthetic) => synthetic.kind.is_rescan(),
    }
  }

  /// The rename payload, if this is a [`Moved`](EventKind::Moved).
  ///
  /// Only a real `tributary-fs`-backed move carries a [`MovedEvent`]; an event this
  /// crate synthesized (a widen [`Rescan`](EventKind::Rescan), or a coalesced-churn
  /// [`Modified`](EventKind::Modified)) holds no fs payload, so this is `None` for one.
  #[inline]
  pub fn moved(&self) -> Option<&MovedEvent> {
    match &self.inner {
      Inner::Fs(event) => event.kind().moved(),
      Inner::Synthetic(_) => None,
    }
  }

  /// The rename source, if this is a [`Moved`](EventKind::Moved) — the wrapper-level
  /// move detector the coalescer keys on (design §6, move-is-atomic).
  ///
  /// Uniform across both representations: an [`Fs`](Inner::Fs)-backed move reads it
  /// from its real [`MovedEvent`], and a synthetic move (test-only) from its stored
  /// source. `Some` iff the event is a move; the destination is [`path`](Self::path).
  #[inline]
  pub(crate) fn move_from(&self) -> Option<&Path> {
    match &self.inner {
      Inner::Fs(event) => event.kind().moved().map(MovedEvent::from),
      Inner::Synthetic(synthetic) => synthetic.from.as_deref(),
    }
  }
}

/// Reconstructs the root-relative [`Location`] of a move's **source** from its fs
/// event, for the synthesized move-out [`Removed`](EventKind::Removed) (design §5).
///
/// `tributary-fs` reports a move's destination location but not its source's, and it
/// exposes the source only as an absolute path (`MovedEvent::from`). The watched root
/// path is recoverable without any I/O: the destination absolute path is the root
/// joined with the destination location, so stripping the destination location's
/// trailing components off it yields the root; the source location is then the source
/// path relative to that root. A real within-root move has both endpoints under the
/// root, so this strip always succeeds; if it somehow cannot (a malformed pairing),
/// the empty (root-anchored) location is a safe, non-panicking fallback — `path()`
/// (the absolute source) remains authoritative for coverage and coalescing.
fn source_location(event: &FsEvent) -> Location {
  let dest = event.path();
  let dest_depth = event.location().len();
  // The root is the destination path minus the destination location's own components.
  let mut root = dest;
  for _ in 0..dest_depth {
    match root.parent() {
      Some(parent) => root = parent,
      None => return Location::new(),
    }
  }
  let from = event
    .kind()
    .moved()
    .map(MovedEvent::from)
    .unwrap_or_else(|| Path::new(""));
  match from.strip_prefix(root) {
    Ok(rel) => Location::from_segments(
      rel
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(tributary_fs::Segment::new)),
    ),
    Err(_) => Location::new(),
  }
}
