//! The normalized event vocabulary the driver feeds the core.
//!
//! The driver owns all raw-OS decoding; by the time anything reaches the core it
//! is an [`OsRecord`] (a single normalized event) or an [`EnumerateResult`] (the
//! outcome of a requested directory read). The core never sees a raw `inotify`
//! struct, an FSEvents flag word, or a `dirent`.

use crate::{
  id::{MoveCookie, WatchId},
  path::Segment,
};
use std::vec::Vec;

/// The kind of a filesystem object, as far as the backend could tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileKind {
  /// A regular file.
  File,
  /// A directory.
  Dir,
  /// A symbolic link (not followed by the core).
  Symlink,
  /// A known object that is none of the above (fifo, socket, device, …).
  Other,
  /// The kind could not be determined from the available information.
  Unknown,
}

impl FileKind {
  /// The stable snake_case name of this kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::File => "file",
      Self::Dir => "dir",
      Self::Symlink => "symlink",
      Self::Other => "other",
      Self::Unknown => "unknown",
    }
  }

  /// Whether this is a [`Dir`](Self::Dir) (the only kind the core descends into).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_dir(&self) -> bool {
    matches!(self, Self::Dir)
  }

  /// Whether this is a [`File`](Self::File).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_file(&self) -> bool {
    matches!(self, Self::File)
  }

  /// Whether this is a [`Symlink`](Self::Symlink).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_symlink(&self) -> bool {
    matches!(self, Self::Symlink)
  }

  /// Whether this is [`Other`](Self::Other).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_other(&self) -> bool {
    matches!(self, Self::Other)
  }

  /// Whether the kind is [`Unknown`](Self::Unknown).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_unknown(&self) -> bool {
    matches!(self, Self::Unknown)
  }
}

impl core::fmt::Display for FileKind {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// The normalized kind of a single [`OsRecord`].
///
/// Every backend's raw event vocabulary is lowered by its driver into this
/// shared set. The names follow inotify's lifecycle (the richest source), but
/// fanotify and FSEvents map onto the same variants. The core turns these into
/// consumer-facing [`ChangeKind`](crate::ChangeKind)s — pairing
/// [`MovedFrom`](Self::MovedFrom) / [`MovedTo`](Self::MovedTo) into a single
/// move, and treating [`Ignored`](Self::Ignored) as the authoritative teardown
/// signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordKind {
  /// A child object was created in the watched directory.
  Created,
  /// A child object was removed from the watched directory.
  Removed,
  /// A watched object's content / data changed.
  Modified,
  /// A watched object's metadata changed (mode, owner, times, xattrs, links).
  Attrib,
  /// The source half of a rename (inotify `IN_MOVED_FROM`); pairs with a
  /// [`MovedTo`](Self::MovedTo) by [`cookie`](OsRecord::cookie).
  MovedFrom,
  /// The destination half of a rename (inotify `IN_MOVED_TO`); pairs with a
  /// [`MovedFrom`](Self::MovedFrom) by [`cookie`](OsRecord::cookie).
  MovedTo,
  /// The watched object itself was moved (inotify `IN_MOVE_SELF`).
  MoveSelf,
  /// The watched object itself was deleted (inotify `IN_DELETE_SELF`).
  DeleteSelf,
  /// The watch was removed by the kernel and will deliver no more events
  /// (inotify `IN_IGNORED`) — the authoritative teardown signal for one watch.
  Ignored,
}

impl RecordKind {
  /// The stable snake_case name of this kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Created => "created",
      Self::Removed => "removed",
      Self::Modified => "modified",
      Self::Attrib => "attrib",
      Self::MovedFrom => "moved_from",
      Self::MovedTo => "moved_to",
      Self::MoveSelf => "move_self",
      Self::DeleteSelf => "delete_self",
      Self::Ignored => "ignored",
    }
  }

  /// Whether this is the source half of a rename.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_moved_from(&self) -> bool {
    matches!(self, Self::MovedFrom)
  }

  /// Whether this is the destination half of a rename.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_moved_to(&self) -> bool {
    matches!(self, Self::MovedTo)
  }

  /// Whether this is one half of a rename (either direction), so it carries a
  /// pairing [`cookie`](OsRecord::cookie).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_move_half(&self) -> bool {
    matches!(self, Self::MovedFrom | Self::MovedTo)
  }

  /// Whether this is the [`Ignored`](Self::Ignored) teardown signal.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_teardown(&self) -> bool {
    matches!(self, Self::Ignored)
  }

  /// Whether this event targets the watched object itself (no child name),
  /// rather than a child within it.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_self_event(&self) -> bool {
    matches!(self, Self::MoveSelf | Self::DeleteSelf | Self::Ignored)
  }
}

impl core::fmt::Display for RecordKind {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// The class of an I/O failure while servicing a core request.
///
/// Carried by [`EnumerateResult::Failed`]; a failed or partial enumerate is one
/// of the [`Rescan`](crate::ChangeKind::Rescan) triggers, so the core dispatches
/// on the class (a vanished directory is benign; descriptor exhaustion may want
/// backoff).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IoClass {
  /// The target no longer exists (`ENOENT`).
  NotFound,
  /// Access was denied (`EACCES` / `EPERM`).
  Permission,
  /// A symbolic-link loop was hit (`ELOOP`).
  Loop,
  /// The process or system ran out of file descriptors (`EMFILE` / `ENFILE`).
  OutOfDescriptors,
  /// Any other I/O failure.
  Io,
}

impl IoClass {
  /// The stable snake_case name of this class.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::NotFound => "not_found",
      Self::Permission => "permission",
      Self::Loop => "loop",
      Self::OutOfDescriptors => "out_of_descriptors",
      Self::Io => "io",
    }
  }

  /// Whether this is [`NotFound`](Self::NotFound) — usually a benign race
  /// (the directory was removed before it could be read).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_not_found(&self) -> bool {
    matches!(self, Self::NotFound)
  }

  /// Whether this is [`Permission`](Self::Permission).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_permission(&self) -> bool {
    matches!(self, Self::Permission)
  }

  /// Whether this is [`Loop`](Self::Loop).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_loop(&self) -> bool {
    matches!(self, Self::Loop)
  }

  /// Whether this is [`OutOfDescriptors`](Self::OutOfDescriptors).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_out_of_descriptors(&self) -> bool {
    matches!(self, Self::OutOfDescriptors)
  }

  /// Whether this is [`Io`](Self::Io).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_io(&self) -> bool {
    matches!(self, Self::Io)
  }
}

impl core::fmt::Display for IoClass {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// One entry from a directory enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DirEntry {
  name: Segment,
  kind: FileKind,
}

impl DirEntry {
  /// Builds an entry from a canonical name and its kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(name: Segment, kind: FileKind) -> Self {
    Self { name, kind }
  }

  /// The entry's canonical name.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn name(&self) -> &Segment {
    &self.name
  }

  /// The entry's kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn kind(&self) -> FileKind {
    self.kind
  }

  /// Whether the entry is a directory (the core descends into these when not
  /// kernel-recursive).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_dir(&self) -> bool {
    self.kind.is_dir()
  }
}

/// The outcome of a directory enumeration the core requested via
/// [`Action::Enumerate`](crate::Action::Enumerate).
///
/// A [`Partial`](Self::Partial) or [`Failed`](Self::Failed) result is a
/// [`Rescan`](crate::ChangeKind::Rescan) trigger: the core cannot trust an
/// incomplete inventory, so it re-enumerates rather than silently miss entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EnumerateResult {
  /// The directory was read in full.
  Ok(Vec<DirEntry>),
  /// The directory was read only partially (it changed mid-read, or the buffer
  /// was truncated); the core treats the subtree as needing a rescan.
  Partial(Vec<DirEntry>),
  /// The directory could not be read.
  Failed(IoClass),
}

impl EnumerateResult {
  /// Whether the directory was read in full.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_ok(&self) -> bool {
    matches!(self, Self::Ok(_))
  }

  /// Whether the directory was read only partially.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_partial(&self) -> bool {
    matches!(self, Self::Partial(_))
  }

  /// Whether the directory could not be read.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_failed(&self) -> bool {
    matches!(self, Self::Failed(_))
  }

  /// Whether this result forces a rescan (it is partial or failed).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn forces_rescan(&self) -> bool {
    matches!(self, Self::Partial(_) | Self::Failed(_))
  }

  /// The entries read, for both [`Ok`](Self::Ok) and [`Partial`](Self::Partial);
  /// an empty slice for [`Failed`](Self::Failed).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn entries(&self) -> &[DirEntry] {
    match self {
      Self::Ok(entries) | Self::Partial(entries) => entries.as_slice(),
      Self::Failed(_) => &[],
    }
  }

  /// The failure class, if this is [`Failed`](Self::Failed).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn failure(&self) -> Option<IoClass> {
    match self {
      Self::Failed(class) => Some(*class),
      _ => None,
    }
  }
}

/// A single normalized filesystem event, attributed to one established watch.
///
/// This is the only event shape the core ingests. Every record carries the
/// [`WatchId`] it arrived on, so the core attributes it to a disjoint root in
/// O(1) without consulting any path index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsRecord {
  watch: WatchId,
  kind: RecordKind,
  name: Option<Segment>,
  is_dir: Option<bool>,
  cookie: Option<MoveCookie>,
}

impl OsRecord {
  /// Builds a record for `kind` arriving on `watch`, with no child name, unknown
  /// directory-ness, and no move cookie.
  ///
  /// Use the `with_*` builders to attach a child name, the directory flag, or a
  /// move-pairing cookie.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(watch: WatchId, kind: RecordKind) -> Self {
    Self {
      watch,
      kind,
      name: None,
      is_dir: None,
      cookie: None,
    }
  }

  /// The watch this record arrived on.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn watch(&self) -> WatchId {
    self.watch
  }

  /// The record's normalized kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn kind(&self) -> RecordKind {
    self.kind
  }

  /// The affected child's name, or `None` when the event targets the watched
  /// object itself (a self-event).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn name(&self) -> Option<&Segment> {
    self.name.as_ref()
  }

  /// Whether the affected object is a directory, when the backend reported it
  /// (`IN_ISDIR` for inotify); `None` when unknown.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_dir(&self) -> Option<bool> {
    self.is_dir
  }

  /// The move-pairing cookie, present iff [`kind`](Self::kind) is a move half.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn cookie(&self) -> Option<MoveCookie> {
    self.cookie
  }

  /// Returns this record with the affected child's name set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub fn with_name(mut self, name: Segment) -> Self {
    self.name = Some(name);
    self
  }

  /// Returns this record with the directory flag set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub const fn with_is_dir(mut self, is_dir: bool) -> Self {
    self.is_dir = Some(is_dir);
    self
  }

  /// Returns this record with the move-pairing cookie set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub const fn with_cookie(mut self, cookie: MoveCookie) -> Self {
    self.cookie = Some(cookie);
    self
  }
}

#[cfg(test)]
mod tests;
