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

/// The event payload: either a real `tributary-fs` delivery or a `Rescan` this
/// crate synthesized (which cannot wrap a [`tributary_fs::Event`], whose
/// constructor is private to that crate).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Inner {
  /// A raw `tributary-fs` event, retagged.
  Fs(FsEvent),
  /// A coverage-loss `Rescan` minted at this layer (widen re-point, §8).
  Rescan(SyntheticRescan),
}

/// The fields a synthetic [`Rescan`](EventKind::Rescan) needs to satisfy the same
/// accessors a wrapped [`tributary_fs::Event`] answers. Its epoch lives on the outer
/// [`Event`], in the umbrella-relative space every delivered event is stamped in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SyntheticRescan {
  path: PathBuf,
  location: Location,
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
      inner: Inner::Rescan(SyntheticRescan {
        path,
        location: Location::new(),
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
      Inner::Rescan(rescan) => rescan.path.as_path(),
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
      Inner::Rescan(rescan) => &rescan.location,
    }
  }

  /// What happened.
  #[inline]
  pub fn kind(&self) -> &EventKind {
    match &self.inner {
      Inner::Fs(event) => event.kind(),
      Inner::Rescan(_) => &EventKind::Rescan,
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
  /// A synthetic widen [`Rescan`](EventKind::Rescan) has no underlying kernel
  /// change and so reports `None`; its dominance rides its [`epoch`](Self::epoch),
  /// not a change id.
  #[inline]
  pub fn change_id(&self) -> Option<tributary_fs::ChangeId> {
    match &self.inner {
      Inner::Fs(event) => Some(event.change_id()),
      Inner::Rescan(_) => None,
    }
  }

  /// Whether this is a [`Rescan`](EventKind::Rescan) (wrapped or synthetic).
  #[inline]
  pub fn is_rescan(&self) -> bool {
    match &self.inner {
      Inner::Fs(event) => event.is_rescan(),
      Inner::Rescan(_) => true,
    }
  }

  /// The rename payload, if this is a [`Moved`](EventKind::Moved).
  ///
  /// A synthetic [`Rescan`](EventKind::Rescan) is never a move, so this is `None`.
  #[inline]
  pub fn moved(&self) -> Option<&MovedEvent> {
    self.kind().moved()
  }
}
