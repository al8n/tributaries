//! The blast radius of a notification-queue overflow.

use crate::{
  id::{ScopeId, WatchId},
  path::Location,
};

/// A single watched subtree below a root: the nearest [`WatchId`] plus a descent
/// below it (empty = the watch's own directory).
///
/// A per-directory backend names the affected directory's own watch with an
/// empty descent. A kernel-recursive backend has only its root watch, so a
/// targeted deep rescan (FSEvents `MustScanSubDirs` for one directory) names the
/// root plus the root-relative descent to the affected directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubtreeScope {
  watch: WatchId,
  descent: Location,
}

impl SubtreeScope {
  /// The subtree rooted at `watch` itself (no descent).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(watch: WatchId) -> Self {
    Self {
      watch,
      descent: Location::new(),
    }
  }

  /// The nearest watch covering the affected subtree.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn watch(&self) -> WatchId {
    self.watch
  }

  /// The descent below [`watch`](Self::watch) to the affected directory; empty
  /// means the watch's own directory.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn descent(&self) -> &Location {
    &self.descent
  }

  /// Returns this scope descended to a directory below its watch (builder form).
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub fn with_descent(mut self, descent: Location) -> Self {
    self.descent = descent;
    self
  }
}

/// What part of the watched world a queue overflow invalidated.
///
/// Handed to [`on_overflow`](crate::Monitor::on_overflow) when the driver
/// observes a dropped-event condition (`IN_Q_OVERFLOW`, `FAN_Q_OVERFLOW`,
/// FSEvents `MustScanSubDirs` / dropped). The core cannot know *what* it missed,
/// so — per the no-silent-loss rule — it turns the overflow into a
/// [`Rescan`](crate::ChangeKind::Rescan) covering exactly this scope, and the
/// consumer re-enumerates.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
  /// Everything observed on the affected backend instance (a shared inotify fd's
  /// queue overflowed, so every root multiplexed onto it is suspect).
  All,
  /// One disjoint watched root (its isolated queue overflowed).
  Root(ScopeId),
  /// A single watched subtree below a root (a targeted rescan), located by the
  /// nearest watch plus a descent below it.
  Subtree(SubtreeScope),
}

impl Scope {
  /// A subtree overflow rooted at `watch` itself (no descent).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn subtree_of(watch: WatchId) -> Self {
    Self::Subtree(SubtreeScope::new(watch))
  }

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

  /// The located subtree this overflow is scoped to, if any.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn subtree(&self) -> Option<&SubtreeScope> {
    match self {
      Self::Subtree(sub) => Some(sub),
      _ => None,
    }
  }
}

impl From<SubtreeScope> for Scope {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn from(value: SubtreeScope) -> Self {
    Self::Subtree(value)
  }
}

#[cfg(test)]
mod tests;
