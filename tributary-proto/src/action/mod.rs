//! Commands the core issues to the driver.
//!
//! The core never performs I/O; instead it emits [`Action`]s for the driver to
//! execute (install a watch, read a directory, stat a path) and the driver feeds
//! the outcomes back through the `Monitor::on_*` inputs. Handles in these
//! commands are proto-minted: the driver maps each [`WatchId`] to its raw OS
//! handle, and correlates each [`ReqId`] with the request it answers.

use crate::{
  id::{ArmAttempt, ReqId, ScopeId, WatchId},
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
  /// A disjoint watched root, identified by its scope. Establishing a root is
  /// the bootstrap: the driver starts the scope's native source and arms the
  /// root on it.
  Root(ScopeId),
  /// A child of an already-watched directory (used when the core descends, i.e.
  /// the backend is not kernel-recursive).
  Child(WatchChild),
  /// Re-add the kernel watch of `scope`'s EXISTING root on its LIVE source —
  /// never a source (re)start. Issued when a loss on a
  /// [`lossy_watch_teardown`](crate::Capabilities::lossy_watch_teardown)
  /// backend forces the root's binding to be re-proven: the driver resolves
  /// the scope's live root path and installs the watch through the ordinary
  /// arm path, and the acknowledgement answers whether the binding was still
  /// live ([`WatchAck::Aliased`]) or had to be re-established
  /// ([`WatchAck::Installed`]). A distinct variant so a re-add can never be
  /// confused with the stream-spawning [`Root`](Self::Root) bootstrap.
  RearmRoot(ScopeId),
}

impl WatchTarget {
  /// Builds a [`Child`](Self::Child) target from its parts.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn child(parent: WatchId, name: Segment) -> Self {
    Self::Child(WatchChild::new(parent, name))
  }

  /// Whether this targets a disjoint root's bootstrap.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_root(&self) -> bool {
    matches!(self, Self::Root(_))
  }

  /// Whether this targets a child of an already-watched directory.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_child(&self) -> bool {
    matches!(self, Self::Child(_))
  }

  /// Whether this re-adds an existing root's kernel watch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_rearm_root(&self) -> bool {
    matches!(self, Self::RearmRoot(_))
  }

  /// The root scope, if this targets a root's bootstrap. `None` for a
  /// [`RearmRoot`](Self::RearmRoot): a re-add must never be executed as a
  /// source start.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn root(&self) -> Option<ScopeId> {
    match self {
      Self::Root(id) => Some(*id),
      _ => None,
    }
  }

  /// The root scope, if this re-adds an existing root's kernel watch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn rearm_root(&self) -> Option<ScopeId> {
    match self {
      Self::RearmRoot(id) => Some(*id),
      _ => None,
    }
  }

  /// The child reference, if this targets a child.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_child(&self) -> Option<&WatchChild> {
    match self {
      Self::Child(child) => Some(child),
      _ => None,
    }
  }
}

/// How a successful [`Action::Watch`] bound its target, reported through
/// `Monitor::on_watch_result`'s `Ok`.
///
/// The distinction carries real information only for a re-add of an
/// already-tracked watch (a binding re-proof on a
/// [`lossy_watch_teardown`](crate::Capabilities::lossy_watch_teardown)
/// backend): [`Installed`](Self::Installed) means the target was NOT bound
/// when the arm ran — the old binding was dead (or bound elsewhere) and a
/// window of unrecorded changes may precede this acknowledgement — while
/// [`Aliased`](Self::Aliased) means the binding was live all along and
/// nothing was missed. A first-time install reports [`Installed`](Self::Installed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchAck {
  /// A kernel watch was freshly created by this arm.
  Installed,
  /// The target was already watched; the arm attached to the existing live
  /// binding (the `EEXIST` aliasing path).
  Aliased,
}

impl WatchAck {
  /// Whether this arm freshly created its kernel watch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_installed(&self) -> bool {
    matches!(self, Self::Installed)
  }

  /// Whether this arm attached to an already-live binding.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_aliased(&self) -> bool {
    matches!(self, Self::Aliased)
  }
}

/// The payload of an [`Action::Watch`]: install `mask` on `target`, minting it
/// as `id`, under the arm attempt `attempt`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WatchCommand {
  id: WatchId,
  attempt: ArmAttempt,
  target: WatchTarget,
  mask: Interest,
}

impl WatchCommand {
  /// Builds a watch command.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(id: WatchId, attempt: ArmAttempt, target: WatchTarget, mask: Interest) -> Self {
    Self {
      id,
      attempt,
      target,
      mask,
    }
  }

  /// The proto-minted handle the driver should bind to the new raw watch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> WatchId {
    self.id
  }

  /// The attempt this arm is, to be echoed back through
  /// [`on_watch_result`](crate::Monitor::on_watch_result).
  ///
  /// A [`WatchId`] outlives its bindings, so several attempts can name it over
  /// time; the token must be CAPTURED here and reported with the outcome, not
  /// re-read when the outcome lands — re-reading would answer for whichever arm
  /// is current and reintroduce exactly the misattribution it exists to fence.
  /// See [`ArmAttempt`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn attempt(&self) -> ArmAttempt {
    self.attempt
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
/// [`Enumerate`](Self::Enumerate) by [`on_enumerate`](crate::Monitor::on_enumerate),
/// a [`Stat`](Self::Stat) by [`on_stat_result`](crate::Monitor::on_stat_result)).
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
  /// Stat a target whose kind a listing could not settle.
  ///
  /// The core issues one only for a slot a
  /// [`DirEntry`](crate::DirEntry) reported as
  /// [`FileKind::Unknown`](crate::FileKind::Unknown): it cannot descend into
  /// what it cannot classify, and guessing "not a directory" would leave a real
  /// directory unwatched — a permanently blind subtree — while guessing
  /// "directory" would arm a watch on every unclassifiable file. Until the
  /// answer arrives the slot stands as a coverage deficit, so a driver that
  /// never answers degrades to a re-signalled `Rescan` rather than to silence.
  Stat(StatCommand),
}

impl Action {
  /// Builds a [`Watch`](Self::Watch) action from its parts.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn watch(
    id: WatchId,
    attempt: ArmAttempt,
    target: WatchTarget,
    mask: Interest,
  ) -> Self {
    Self::Watch(WatchCommand::new(id, attempt, target, mask))
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
