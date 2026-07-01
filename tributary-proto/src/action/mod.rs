//! Commands the core issues to the driver.
//!
//! The core never performs I/O; instead it emits [`Action`]s for the driver to
//! execute (install a watch, read a directory, stat a path) and the driver feeds
//! the outcomes back through the `Monitor::on_*` inputs. Handles in these
//! commands are proto-minted: the driver maps each [`WatchId`] to its raw OS
//! handle, and correlates each [`ReqId`] with the request it answers.

use crate::{
  id::{ReqId, ScopeId, WatchId},
  interest::Interest,
  path::Segment,
};

/// A directory child, addressed relative to its already-watched parent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WatchChild {
  parent: WatchId,
  name: Segment,
}

impl WatchChild {
  /// Builds a child reference under `parent` named `name`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(parent: WatchId, name: Segment) -> Self {
    Self { parent, name }
  }

  /// The already-watched parent directory.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn parent(&self) -> WatchId {
    self.parent
  }

  /// The child's canonical name within the parent.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn name(&self) -> &Segment {
    &self.name
  }
}

/// What a [`Action::Watch`] should establish a watch on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WatchTarget {
  /// A disjoint watched root, identified by its scope.
  Root(ScopeId),
  /// A child of an already-watched directory (used when the core descends, i.e.
  /// the backend is not kernel-recursive).
  Child(WatchChild),
}

impl WatchTarget {
  /// Builds a [`Child`](Self::Child) target from its parts.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn child(parent: WatchId, name: Segment) -> Self {
    Self::Child(WatchChild::new(parent, name))
  }

  /// Whether this targets a disjoint root.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_root(&self) -> bool {
    matches!(self, Self::Root(_))
  }

  /// Whether this targets a child of an already-watched directory.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_child(&self) -> bool {
    matches!(self, Self::Child(_))
  }

  /// The root scope, if this targets a root.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn root(&self) -> Option<ScopeId> {
    match self {
      Self::Root(id) => Some(*id),
      Self::Child(_) => None,
    }
  }

  /// The child reference, if this targets a child.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_child(&self) -> Option<&WatchChild> {
    match self {
      Self::Child(child) => Some(child),
      Self::Root(_) => None,
    }
  }
}

/// The payload of an [`Action::Watch`]: install `mask` on `target`, minting it
/// as `id`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WatchCommand {
  id: WatchId,
  target: WatchTarget,
  mask: Interest,
}

impl WatchCommand {
  /// Builds a watch command.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(id: WatchId, target: WatchTarget, mask: Interest) -> Self {
    Self { id, target, mask }
  }

  /// The proto-minted handle the driver should bind to the new raw watch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> WatchId {
    self.id
  }

  /// What to watch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn target(&self) -> &WatchTarget {
    &self.target
  }

  /// The subscription mask to install.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn mask(&self) -> Interest {
    self.mask
  }
}

/// The payload of an [`Action::Enumerate`]: read directory `dir`, answering
/// under `req`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnumerateCommand {
  req: ReqId,
  dir: WatchId,
}

impl EnumerateCommand {
  /// Builds an enumerate command.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(req: ReqId, dir: WatchId) -> Self {
    Self { req, dir }
  }

  /// The request id to echo back in the [`EnumerateResult`](crate::EnumerateResult).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn req(&self) -> ReqId {
    self.req
  }

  /// The already-watched directory to read.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn dir(&self) -> WatchId {
    self.dir
  }
}

/// A directory child to stat, addressed relative to its watched parent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatChild {
  parent: WatchId,
  name: Segment,
}

impl StatChild {
  /// Builds a child stat target under `parent` named `name`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(parent: WatchId, name: Segment) -> Self {
    Self { parent, name }
  }

  /// The watched parent directory.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn parent(&self) -> WatchId {
    self.parent
  }

  /// The child's canonical name within the parent.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn name(&self) -> &Segment {
    &self.name
  }
}

/// What a [`Action::Stat`] should stat.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatTarget {
  /// The watched object itself.
  Watch(WatchId),
  /// A named child of a watched directory.
  Child(StatChild),
}

impl StatTarget {
  /// Builds a [`Child`](Self::Child) stat target from its parts.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn child(parent: WatchId, name: Segment) -> Self {
    Self::Child(StatChild::new(parent, name))
  }

  /// Whether this stats a watched object itself.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_watch(&self) -> bool {
    matches!(self, Self::Watch(_))
  }

  /// Whether this stats a named child.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_child(&self) -> bool {
    matches!(self, Self::Child(_))
  }

  /// The watched object, if this stats one directly.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn watch(&self) -> Option<WatchId> {
    match self {
      Self::Watch(id) => Some(*id),
      Self::Child(_) => None,
    }
  }

  /// The child reference, if this stats a child.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_child(&self) -> Option<&StatChild> {
    match self {
      Self::Child(child) => Some(child),
      Self::Watch(_) => None,
    }
  }
}

/// The payload of an [`Action::Stat`]: stat `of`, answering under `req`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatCommand {
  req: ReqId,
  of: StatTarget,
}

impl StatCommand {
  /// Builds a stat command.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(req: ReqId, of: StatTarget) -> Self {
    Self { req, of }
  }

  /// The request id to echo back with the stat result.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn req(&self) -> ReqId {
    self.req
  }

  /// What to stat.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn of(&self) -> &StatTarget {
    &self.of
  }
}

/// A command the core issues to the driver.
///
/// The driver executes each action and reports the outcome back through the
/// `Monitor::on_*` inputs (a [`Watch`](Self::Watch) is answered by
/// [`on_watch_result`](crate::Monitor::on_watch_result), an
/// [`Enumerate`](Self::Enumerate) by [`on_enumerate`](crate::Monitor::on_enumerate)).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Action {
  /// Install a watch.
  Watch(WatchCommand),
  /// Remove a previously-installed watch.
  ///
  /// May target a watch the driver has not yet acknowledged through
  /// [`on_watch_result`](crate::Monitor::on_watch_result): a pending child watch
  /// can be dropped before its install completes (a parent teardown, or a
  /// moved-away source). The driver must treat an `Unwatch` of a handle it never
  /// bound to a kernel watch as a no-op.
  Unwatch(WatchId),
  /// Read a watched directory's entries.
  Enumerate(EnumerateCommand),
  /// Stat a target.
  Stat(StatCommand),
}

impl Action {
  /// Builds a [`Watch`](Self::Watch) action from its parts.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn watch(id: WatchId, target: WatchTarget, mask: Interest) -> Self {
    Self::Watch(WatchCommand::new(id, target, mask))
  }

  /// Builds an [`Enumerate`](Self::Enumerate) action from its parts.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn enumerate(req: ReqId, dir: WatchId) -> Self {
    Self::Enumerate(EnumerateCommand::new(req, dir))
  }

  /// Builds a [`Stat`](Self::Stat) action from its parts.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn stat(req: ReqId, of: StatTarget) -> Self {
    Self::Stat(StatCommand::new(req, of))
  }

  /// Whether this is a [`Watch`](Self::Watch).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_watch(&self) -> bool {
    matches!(self, Self::Watch(_))
  }

  /// Whether this is an [`Unwatch`](Self::Unwatch).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_unwatch(&self) -> bool {
    matches!(self, Self::Unwatch(_))
  }

  /// Whether this is an [`Enumerate`](Self::Enumerate).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_enumerate(&self) -> bool {
    matches!(self, Self::Enumerate(_))
  }

  /// Whether this is a [`Stat`](Self::Stat).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_stat(&self) -> bool {
    matches!(self, Self::Stat(_))
  }

  /// The watch command, if this is a [`Watch`](Self::Watch).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_watch(&self) -> Option<&WatchCommand> {
    match self {
      Self::Watch(cmd) => Some(cmd),
      _ => None,
    }
  }

  /// The watch handle to remove, if this is an [`Unwatch`](Self::Unwatch).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_unwatch(&self) -> Option<WatchId> {
    match self {
      Self::Unwatch(id) => Some(*id),
      _ => None,
    }
  }

  /// The enumerate command, if this is an [`Enumerate`](Self::Enumerate).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_enumerate(&self) -> Option<&EnumerateCommand> {
    match self {
      Self::Enumerate(cmd) => Some(cmd),
      _ => None,
    }
  }

  /// The stat command, if this is a [`Stat`](Self::Stat).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_stat(&self) -> Option<&StatCommand> {
    match self {
      Self::Stat(cmd) => Some(cmd),
      _ => None,
    }
  }
}

#[cfg(test)]
mod tests;
