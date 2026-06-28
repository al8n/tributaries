//! The blast radius of a notification-queue overflow.

use crate::id::{ScopeId, WatchId};

/// What part of the watched world a queue overflow invalidated.
///
/// Handed to [`on_overflow`](crate::Monitor::on_overflow) when the driver
/// observes a dropped-event condition (`IN_Q_OVERFLOW`, `FAN_Q_OVERFLOW`,
/// FSEvents `MustScanSubDirs` / dropped). The core cannot know *what* it missed,
/// so — per the no-silent-loss rule — it turns the overflow into a
/// [`Rescan`](crate::ChangeKind::Rescan) covering exactly this scope, and the
/// consumer re-enumerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
  /// Everything observed on the affected backend instance (a shared inotify fd's
  /// queue overflowed, so every root multiplexed onto it is suspect).
  All,
  /// One disjoint watched root (its isolated queue overflowed).
  Root(ScopeId),
  /// A single watched subtree below a root (a targeted rescan, e.g. FSEvents
  /// `MustScanSubDirs` for one directory).
  Subtree(WatchId),
}

impl Scope {
  /// Whether this overflow covers an entire backend instance.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_all(&self) -> bool {
    matches!(self, Self::All)
  }

  /// Whether this overflow is scoped to one disjoint root.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_root(&self) -> bool {
    matches!(self, Self::Root(_))
  }

  /// Whether this overflow is scoped to one subtree.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_subtree(&self) -> bool {
    matches!(self, Self::Subtree(_))
  }

  /// The disjoint root this overflow is scoped to, if any.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn root(&self) -> Option<ScopeId> {
    match self {
      Self::Root(id) => Some(*id),
      _ => None,
    }
  }

  /// The subtree watch this overflow is scoped to, if any.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn subtree(&self) -> Option<WatchId> {
    match self {
      Self::Subtree(id) => Some(*id),
      _ => None,
    }
  }
}

#[cfg(test)]
mod tests;
