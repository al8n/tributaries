//! The consumer-facing change vocabulary.

use std::path::{Path, PathBuf};

use tributary_proto::{Change, ChangeId, ChangeKind, Epoch, Location};

use crate::watcher::RootHandle;

#[cfg(test)]
mod tests;

/// One filesystem change, delivered by a [`Watcher`](crate::Watcher).
///
/// An event carries both the absolute [`path`](Self::path) (the watched root
/// joined with the change's location) and the root-relative
/// [`location`](Self::location) for consumers that keep their own per-root
/// indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
  root: RootHandle,
  path: PathBuf,
  location: Location,
  kind: EventKind,
  epoch: Epoch,
  id: ChangeId,
}

impl Event {
  /// Assembles the consumer event from a scope's change and its root path.
  pub(crate) fn from_change(root: RootHandle, root_path: &Path, change: &Change) -> Self {
    let kind = match change.kind() {
      ChangeKind::Created => EventKind::Created,
      ChangeKind::Modified => EventKind::Modified,
      ChangeKind::Removed => EventKind::Removed,
      ChangeKind::Moved(from) => EventKind::Moved(MovedEvent {
        from: absolute(root_path, from),
        location: from.clone(),
      }),
      ChangeKind::Rescan => EventKind::Rescan,
      // The proto vocabulary is non-exhaustive; an unknown future kind is
      // surfaced as the conservative "re-read this location" signal rather
      // than dropped.
      _ => EventKind::Rescan,
    };
    Self {
      root,
      path: absolute(root_path, change.location()),
      location: change.location().clone(),
      kind,
      epoch: change.epoch(),
      id: change.id(),
    }
  }

  /// Assembles a consumer event exactly as [`Watcher`](crate::Watcher)'s own delivery path
  /// does — `Event::from_change` under a [`RootHandle`] branded with `instance` and the
  /// change's own scope.
  ///
  /// **Internal, not public API** (hence `#[doc(hidden)]`; it is exempt from this crate's
  /// semver surface and may change or vanish in a patch release). It exists because the
  /// `tributaries` umbrella binds this vocabulary to its own
  /// (`SourceEvent::from_fs`) and that binding had no cell of its own: an `Event` is minted
  /// only by a live watcher draining a real kernel stream, so every test of the binding was
  /// forced to hand-build the *output* and assert against itself, leaving the conversion —
  /// including which of a rename's two locations reaches the umbrella — unwitnessed. A
  /// cross-crate seam that mints a REAL lower-layer event from a real [`Change`] is what lets
  /// that conversion be tested as the conversion it is.
  ///
  /// It is deliberately not `#[cfg(test)]`: `cfg(test)` does not apply to a crate compiled as
  /// a dependency, which is exactly how the umbrella's unit tests see this one.
  #[doc(hidden)]
  pub fn from_change_under_instance(instance: u64, root_path: &Path, change: &Change) -> Self {
    Self::from_change(RootHandle::new(instance, change.scope()), root_path, change)
  }

  /// The watched root this event belongs to.
  #[inline]
  pub const fn root(&self) -> RootHandle {
    self.root
  }

  /// The affected object's absolute path (the watched root joined with
  /// [`location`](Self::location)).
  ///
  /// Paths are reported in the filesystem's stored byte form — on macOS that
  /// is decomposed Unicode (NFD), which may differ byte-wise from the form the
  /// caller typed. APFS/HFS+ lookups are normalization-insensitive, so the
  /// path always *opens* the right object; treat it as an opaque handle rather
  /// than byte-comparing it against independently-sourced strings.
  #[inline]
  pub fn path(&self) -> &Path {
    self.path.as_path()
  }

  /// The affected object's location relative to its watched root.
  #[inline]
  pub const fn location(&self) -> &Location {
    &self.location
  }

  /// What happened.
  #[inline]
  pub const fn kind(&self) -> &EventKind {
    &self.kind
  }

  /// The scope's reconciliation epoch this event was emitted under.
  ///
  /// The no-silent-loss contract: whenever coverage becomes uncertain (kernel
  /// drops, a lagging consumer, a lost root) the epoch is bumped and a
  /// [`Rescan`](EventKind::Rescan) carrying the new epoch is delivered — never
  /// filtered. On a `Rescan`, re-enumerate its [`path`](Self::path); events
  /// with epochs dominated by a delivered `Rescan` may have been dropped, and
  /// everything they described is covered by that re-enumeration.
  #[inline]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The change's unique id (monotonic per watcher).
  #[inline]
  pub const fn change_id(&self) -> ChangeId {
    self.id
  }

  /// Whether this is a [`Rescan`](EventKind::Rescan).
  #[inline]
  pub const fn is_rescan(&self) -> bool {
    self.kind.is_rescan()
  }
}

/// The payload of a paired rename: where the object moved from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedEvent {
  from: PathBuf,
  location: Location,
}

impl MovedEvent {
  /// The absolute path the object moved away from.
  #[inline]
  pub fn from(&self) -> &Path {
    self.from.as_path()
  }

  /// The source endpoint's location relative to the watched root — the second
  /// coordinate of the rename, measured against the same root as
  /// [`Event::location`].
  ///
  /// A rename is reported as [`Moved`](EventKind::Moved) only when **both**
  /// endpoints lie under the watched root (a move across the boundary degrades
  /// to a [`Created`](EventKind::Created) or [`Removed`](EventKind::Removed)),
  /// so this is always a real location under that root rather than a
  /// placeholder.
  #[inline]
  pub const fn location(&self) -> &Location {
    &self.location
  }
}

/// What kind of change an [`Event`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventKind {
  /// An object appeared (created, or moved in from outside the watched root).
  Created,
  /// An object's content or metadata changed.
  Modified,
  /// An object disappeared (removed, or moved out of the watched root).
  Removed,
  /// An object moved within its watched root; the payload carries the source
  /// path. A rename whose halves could not be paired degrades to a
  /// [`Removed`](Self::Removed) plus a [`Created`](Self::Created) — degraded,
  /// never silent.
  Moved(MovedEvent),
  /// Coverage became uncertain at this path: re-enumerate it. See
  /// [`Event::epoch`] for the contract.
  Rescan,
}

impl EventKind {
  /// The stable snake_case name of this kind.
  #[inline]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Created => "created",
      Self::Modified => "modified",
      Self::Removed => "removed",
      Self::Moved(_) => "moved",
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
    matches!(self, Self::Moved(_))
  }

  /// Whether this is [`Rescan`](Self::Rescan).
  #[inline]
  pub const fn is_rescan(&self) -> bool {
    matches!(self, Self::Rescan)
  }

  /// The rename payload, if this is [`Moved`](Self::Moved).
  #[inline]
  pub const fn moved(&self) -> Option<&MovedEvent> {
    match self {
      Self::Moved(moved) => Some(moved),
      _ => None,
    }
  }
}

impl core::fmt::Display for EventKind {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// The watched root's path joined with a root-relative location.
fn absolute(root_path: &Path, location: &Location) -> PathBuf {
  let mut path = root_path.to_path_buf();
  for segment in location.segments() {
    path.push(segment.as_str());
  }
  path
}
