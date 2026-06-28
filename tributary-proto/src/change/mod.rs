//! The consumer-facing change vocabulary the core emits.

use crate::{
  id::{ChangeId, ScopeId},
  path::Location,
};

/// What happened to an object at a [`Change`]'s location.
///
/// The destination location always lives on the [`Change`] itself; a
/// [`Moved`](Self::Moved) additionally carries the *source* location it came
/// from. [`Rescan`](Self::Rescan) is the no-silent-loss escape: whenever the
/// core's view becomes uncertain (a queue overflow, a watch-limit refusal, a
/// failed enumerate) it emits a `Rescan` for the affected
/// [`scope`](Change::scope) and the consumer re-enumerates, rather than the core
/// guessing or dropping events.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChangeKind {
  /// An object was created at the change's location.
  Created,
  /// An object's content changed at the change's location.
  Modified,
  /// An object was removed from the change's location.
  Removed,
  /// An object was moved to the change's location, from the carried source.
  Moved(Location),
  /// The core's view of the change's scope is uncertain; re-enumerate it.
  Rescan,
}

impl ChangeKind {
  /// The stable snake_case name of this kind (independent of any carried data).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Created => "created",
      Self::Modified => "modified",
      Self::Removed => "removed",
      Self::Moved(_) => "moved",
      Self::Rescan => "rescan",
    }
  }

  /// Whether this is a [`Created`](Self::Created).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_created(&self) -> bool {
    matches!(self, Self::Created)
  }

  /// Whether this is a [`Modified`](Self::Modified).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_modified(&self) -> bool {
    matches!(self, Self::Modified)
  }

  /// Whether this is a [`Removed`](Self::Removed).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_removed(&self) -> bool {
    matches!(self, Self::Removed)
  }

  /// Whether this is a [`Moved`](Self::Moved).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_moved(&self) -> bool {
    matches!(self, Self::Moved(_))
  }

  /// Whether this is a [`Rescan`](Self::Rescan).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_rescan(&self) -> bool {
    matches!(self, Self::Rescan)
  }

  /// The source location of a [`Moved`](Self::Moved), if any.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn moved_from(&self) -> Option<&Location> {
    match self {
      Self::Moved(from) => Some(from),
      _ => None,
    }
  }
}

impl core::fmt::Display for ChangeKind {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// One normalized, deduped change the core hands to the consumer.
///
/// Every change is born tagged with its disjoint root ([`scope`](Self::scope))
/// so attribution is O(1), and stamped with a unique [`ChangeId`] that is the
/// dedup / identity key. `watershed::Event<L>` wraps this, mapping the
/// canonical [`Location`] to the consumer's location type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Change {
  id: ChangeId,
  scope: ScopeId,
  location: Location,
  kind: ChangeKind,
}

impl Change {
  /// Builds a change. The core mints [`id`](Self::id) and tags
  /// [`scope`](Self::scope) from the originating watch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(id: ChangeId, scope: ScopeId, location: Location, kind: ChangeKind) -> Self {
    Self {
      id,
      scope,
      location,
      kind,
    }
  }

  /// The unique dedup / identity key of this change.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> ChangeId {
    self.id
  }

  /// The disjoint watched root this change belongs to.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn scope(&self) -> ScopeId {
    self.scope
  }

  /// The change's location, relative to its watched root.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn location(&self) -> &Location {
    &self.location
  }

  /// What happened.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn kind(&self) -> &ChangeKind {
    &self.kind
  }
}

#[cfg(test)]
mod tests;
