//! The normalized event vocabulary the driver feeds the core.
//!
//! The driver owns all raw-OS decoding; by the time anything reaches the core it
//! is an [`OsRecord`] (a single normalized event) or an [`EnumerateResult`] (the
//! outcome of a requested directory read). The core never sees a raw `inotify`
//! struct, an FSEvents flag word, or a `dirent`.

use crate::{
  id::{Identity, MoveCookie, WatchId},
  interest::Interest,
  path::{Location, Segment},
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
  ///
  /// The driver contract requires records from one backend queue to arrive in
  /// kernel order, so a non-root `MoveSelf` always FOLLOWS its parent-side
  /// [`MovedFrom`](Self::MovedFrom) (and, for an in-tree rename, the paired
  /// [`MovedTo`](Self::MovedTo)) — the same ordering the move-cookie pairing
  /// window already depends on. By the time it arrives, the core has either
  /// detached-and-held the source (fencing its stale path) or reparented it
  /// (its path is current), so a non-root `MoveSelf` carries no new
  /// information; a parent-side record lost to a queue overflow is healed by
  /// the overflow's own `Rescan` + watch-set re-arm, which prunes the vacated
  /// slot.
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

/// Every independent fact one native event proved about its target.
///
/// A [`RecordKind`] names ONE verb, but a backend's raw event does not: a
/// fanotify mask can carry `FAN_CREATE | FAN_ATTRIB`, an FSEvents flag word
/// `ItemCreated | ItemXattrMod`, a USN reason delta `FILE_CREATE |
/// BASIC_INFO_CHANGE`. Every one of those bits is a fact the kernel PROVED, and
/// a lowering that resolves the mask to a single winning verb by priority
/// throws the losers away — after which a subscriber interested only in a
/// discarded fact is delivered nothing at all, with no
/// [`Rescan`](crate::ChangeKind::Rescan) to cover the silence.
///
/// So a record carries the whole set, and admission tests ALL of it: a change
/// is delivered when the subscriber wants the change's own kind **or** any
/// fact its record proved ([`admits`](Self::admits)). Widening admission is
/// always safe — over-delivery is the direction the [`Interest`] contract
/// already allows — and it is what makes "a proven fact reaches every
/// subscriber that asked for it" hold without multiplying one event into
/// several changes.
///
/// The set's five facts are exactly the five subscribable kinds of
/// [`Interest`], so admission is a plain intersection. A lowering builds one by
/// mapping each native bit it tested, then takes the verb from the set
/// ([`primary`](Self::primary)) rather than choosing one itself — the priority
/// lives here, in the protocol, where every backend shares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Evidence {
  created: bool,
  removed: bool,
  modified: bool,
  attrib: bool,
  moved: bool,
}

impl Evidence {
  /// The empty set: an event that proved nothing.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new() -> Self {
    Self {
      created: false,
      removed: false,
      modified: false,
      attrib: false,
      moved: false,
    }
  }

  /// The singleton set a [`RecordKind`] proves on its own — what a record built
  /// from a verb alone carries.
  ///
  /// Both move halves and a [`MoveSelf`](RecordKind::MoveSelf) prove
  /// [`moved`](Self::moved); a [`DeleteSelf`](RecordKind::DeleteSelf) proves
  /// [`removed`](Self::removed). [`Ignored`](RecordKind::Ignored) proves
  /// NOTHING about the object — it is the watch's teardown, whose coverage
  /// story is an unconditional `Rescan`, not a delivery.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn of(kind: RecordKind) -> Self {
    let empty = Self::new();
    match kind {
      RecordKind::Created => empty.with_created(),
      RecordKind::Removed | RecordKind::DeleteSelf => empty.with_removed(),
      RecordKind::Modified => empty.with_modified(),
      RecordKind::Attrib => empty.with_attrib(),
      RecordKind::MovedFrom | RecordKind::MovedTo | RecordKind::MoveSelf => empty.with_moved(),
      RecordKind::Ignored => empty,
    }
  }

  /// Whether create was proven.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn created(&self) -> bool {
    self.created
  }

  /// Whether removal was proven.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn removed(&self) -> bool {
    self.removed
  }

  /// Whether a content / data change was proven.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn modified(&self) -> bool {
    self.modified
  }

  /// Whether a metadata change (mode, owner, times, xattrs, links) was proven.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn attrib(&self) -> bool {
    self.attrib
  }

  /// Whether a rename was proven.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn moved(&self) -> bool {
    self.moved
  }

  /// Whether nothing at all was proven.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_empty(&self) -> bool {
    !(self.created || self.removed || self.modified || self.attrib || self.moved)
  }

  /// The union of two fact sets — the ONLY way to combine evidence, so
  /// carrying a record's evidence forward can never narrow it.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub const fn union(self, other: Self) -> Self {
    Self {
      created: self.created || other.created,
      removed: self.removed || other.removed,
      modified: self.modified || other.modified,
      attrib: self.attrib || other.attrib,
      moved: self.moved || other.moved,
    }
  }

  /// Whether `interest` subscribes to ANY fact in this set — the admission
  /// test. Empty evidence admits nothing.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn admits(&self, interest: Interest) -> bool {
    (self.created && interest.created())
      || (self.removed && interest.removed())
      || (self.modified && interest.modified())
      || (self.attrib && interest.attrib())
      || (self.moved && interest.moved())
  }

  /// The dirent verb this set resolves to: the structural facts outrank the
  /// content ones, since a create or a removal SUBSUMES whatever content or
  /// metadata change the kernel merged into the same word, while the reverse
  /// would report a lifecycle transition as an edit.
  ///
  /// `None` for a set naming no dirent fact — the empty set, or one proving
  /// only [`moved`](Self::moved). A move needs a DIRECTION no fact set carries,
  /// so a move half is minted from its verb
  /// ([`OsRecord::new`](OsRecord::new)) and picks up its `moved` fact from
  /// [`of`](Self::of).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn primary(&self) -> Option<RecordKind> {
    if self.created {
      Some(RecordKind::Created)
    } else if self.removed {
      Some(RecordKind::Removed)
    } else if self.modified {
      Some(RecordKind::Modified)
    } else if self.attrib {
      Some(RecordKind::Attrib)
    } else {
      None
    }
  }
}

macro_rules! evidence_flag {
  ($field:ident, $set:ident, $with:ident, $maybe:ident) => {
    #[doc = concat!("Records that `", stringify!($field), "` was proven.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $set(&mut self) -> &mut Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Returns this set additionally proving `", stringify!($field), "`.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    #[must_use]
    pub const fn $with(mut self) -> Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Returns this set proving `", stringify!($field), "` iff `proven`.")]
    ///
    /// The per-bit form a lowering maps a native mask through, so translating a
    /// mask is a total function over the bits it tests rather than a priority
    /// contest that silently discards the losers.
    #[cfg_attr(not(tarpaulin), inline(always))]
    #[must_use]
    pub const fn $maybe(mut self, proven: bool) -> Self {
      self.$field = proven;
      self
    }
  };
}

impl Evidence {
  evidence_flag!(created, set_created, with_created, maybe_created);
  evidence_flag!(removed, set_removed, with_removed, maybe_removed);
  evidence_flag!(modified, set_modified, with_modified, maybe_modified);
  evidence_flag!(attrib, set_attrib, with_attrib, maybe_attrib);
  evidence_flag!(moved, set_moved, with_moved, maybe_moved);
}

impl Default for Evidence {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn default() -> Self {
    Self::new()
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
  node: Option<Identity>,
}

impl DirEntry {
  /// Builds an entry from a canonical name and its kind, with no object identity.
  ///
  /// Use [`with_node`](Self::with_node) to attach the identity the driver read for this
  /// entry; without it the core treats a same-name reappearance conservatively.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(name: Segment, kind: FileKind) -> Self {
    Self {
      name,
      kind,
      node: None,
    }
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

  /// The entry's object identity, if the driver could supply one. The core uses it to
  /// tell a same-name replacement from a survivor when re-arming (see [`Identity`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn node(&self) -> Option<Identity> {
    self.node
  }

  /// Whether the entry is a directory (the core descends into these when not
  /// kernel-recursive).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_dir(&self) -> bool {
    self.kind.is_dir()
  }

  /// Returns this entry with its object [`Identity`] set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub const fn with_node(mut self, node: Identity) -> Self {
    self.node = Some(node);
    self
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

/// What a driver's stat found: the object's kind, plus its identity when one
/// could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatEntry {
  kind: FileKind,
  node: Option<Identity>,
}

impl StatEntry {
  /// Builds an entry for a stat'd object of `kind`, with no object identity.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(kind: FileKind) -> Self {
    Self { kind, node: None }
  }

  /// The stat'd object's kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn kind(&self) -> FileKind {
    self.kind
  }

  /// The stat'd object's identity, if the driver could supply one.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn node(&self) -> Option<Identity> {
    self.node
  }

  /// Whether the stat'd object is a directory.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_dir(&self) -> bool {
    self.kind.is_dir()
  }

  /// Returns this entry with its object [`Identity`] set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub const fn with_node(mut self, node: Identity) -> Self {
    self.node = Some(node);
    self
  }
}

/// The outcome of a stat the core requested via
/// [`Action::Stat`](crate::Action::Stat).
///
/// The core asks only when a listing left an object's kind
/// [`Unknown`](FileKind::Unknown) — a kind it cannot act on, since an unwatched
/// directory is a permanently blind subtree. Neither a
/// [`Failed`](Self::Failed) result nor an answer that is itself `Unknown`
/// resolves anything, so both leave the slot's coverage deficit standing and
/// earn a covering [`Rescan`](crate::ChangeKind::Rescan): the core never
/// re-asks in a loop, and the darkness is never silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatResult {
  /// The target was stat'd.
  Ok(StatEntry),
  /// The target could not be stat'd.
  Failed(IoClass),
}

impl StatResult {
  /// Builds an [`Ok`](Self::Ok) result for a bare kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn found(kind: FileKind) -> Self {
    Self::Ok(StatEntry::new(kind))
  }

  /// Whether the target was stat'd.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_ok(&self) -> bool {
    matches!(self, Self::Ok(_))
  }

  /// Whether the stat failed.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_failed(&self) -> bool {
    matches!(self, Self::Failed(_))
  }

  /// The stat'd entry, if this succeeded.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn entry(&self) -> Option<StatEntry> {
    match self {
      Self::Ok(entry) => Some(*entry),
      Self::Failed(_) => None,
    }
  }

  /// The failure class, if this is [`Failed`](Self::Failed).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn failure(&self) -> Option<IoClass> {
    match self {
      Self::Failed(class) => Some(*class),
      Self::Ok(_) => None,
    }
  }

  /// The kind this result settles the target to, or `None` when it settles
  /// nothing — a failure, or an answer that is itself
  /// [`Unknown`](FileKind::Unknown).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn resolved(&self) -> Option<FileKind> {
    match self {
      Self::Ok(entry) if !entry.kind.is_unknown() => Some(entry.kind),
      _ => None,
    }
  }
}

/// A single normalized filesystem event, attributed to one established watch.
///
/// This is the only event shape the core ingests. Every record carries the
/// [`WatchId`] it arrived on, so the core attributes it to a disjoint root in
/// O(1) without consulting any path index.
///
/// A record addresses the watch itself (a self-event, `target: None`) or an
/// object below the watched directory by a watch-relative [`Location`]
/// (`target: Some`). How deep that location may reach is the backend's
/// addressing contract:
///
/// - A **per-directory** backend (inotify, fanotify-inode) always produces the
///   depth-one shape — exactly one segment, the affected DIRECT child — because
///   every event arrives on the watch of its immediate parent. A descending
///   `Monitor` enforces this: a deeper record is a driver bug and escalates to a
///   `Rescan` of the arrival watch rather than being mis-attributed.
/// - A **kernel-recursive** backend (FSEvents, fanotify-FILESYSTEM) reports
///   arbitrarily deep paths on its one root watch; its driver lowers each full
///   path to the root-relative remainder and feeds it as a multi-segment
///   `target`.
///
/// A self-event kind ([`RecordKind::is_self_event`]) never carries a target;
/// that combination also escalates to a `Rescan` instead of guessing which
/// object it meant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsRecord {
  watch: WatchId,
  kind: RecordKind,
  evidence: Evidence,
  target: Option<Location>,
  is_dir: Option<bool>,
  cookie: Option<MoveCookie>,
  node: Option<Identity>,
}

impl OsRecord {
  /// Builds a record for `kind` arriving on `watch`, with no target (a
  /// self-event shape), unknown directory-ness, no move cookie, and no object
  /// identity.
  ///
  /// Its [`evidence`](Self::evidence) is the singleton `kind` proves on its own
  /// ([`Evidence::of`]) — the honest set for a backend whose events are precise
  /// verbs. A backend whose one event can prove SEVERAL facts builds the set
  /// instead ([`proved`](Self::proved), [`also_proved`](Self::also_proved)), so
  /// nothing it observed is dropped on the way in.
  ///
  /// Use the `with_*` builders to attach the affected child's name (or a deeper
  /// kernel-recursive target), the directory flag, a move-pairing cookie, or the
  /// affected object's identity.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(watch: WatchId, kind: RecordKind) -> Self {
    Self {
      watch,
      kind,
      evidence: Evidence::of(kind),
      target: None,
      is_dir: None,
      cookie: None,
      node: None,
    }
  }

  /// Builds a record from the WHOLE fact set a native mask proved, taking its
  /// [`kind`](Self::kind) from the set rather than from the lowering.
  ///
  /// This is the shape a mask-merging backend lowers through: it maps each bit
  /// it tested into `evidence` and hands the set over, so choosing which verb
  /// wins is the protocol's job ([`Evidence::primary`]) and the facts that did
  /// not win still travel — no lowering has a priority chain in which to lose
  /// one.
  ///
  /// `None` when `evidence` names no dirent fact: an event proving nothing
  /// addresses nothing, and a lone [`moved`](Evidence::moved) has no direction,
  /// so both would mean inventing a verb.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn proved(watch: WatchId, evidence: Evidence) -> Option<Self> {
    match evidence.primary() {
      Some(kind) => Some(Self {
        watch,
        kind,
        evidence,
        target: None,
        is_dir: None,
        cookie: None,
        node: None,
      }),
      None => None,
    }
  }

  /// The watch this record arrived on.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn watch(&self) -> WatchId {
    self.watch
  }

  /// The record's normalized kind — the ONE verb its coverage reconciliation
  /// runs on. What it is ADMITTED on is the wider
  /// [`evidence`](Self::evidence).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn kind(&self) -> RecordKind {
    self.kind
  }

  /// Every fact this record's native event proved. Always contains the
  /// singleton [`kind`](Self::kind) implies, and never shrinks.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn evidence(&self) -> Evidence {
    self.evidence
  }

  /// The affected object's watch-relative location, or `None` when the event
  /// targets the watched object itself (a self-event). One segment on a
  /// per-directory backend; possibly deeper on a kernel-recursive one.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn target(&self) -> Option<&Location> {
    self.target.as_ref()
  }

  /// The affected DIRECT child's name — `Some` iff the record addresses exactly
  /// one segment below its watch (the depth-one shape every per-directory
  /// backend produces). A deeper kernel-recursive target yields `None`; use
  /// [`target`](Self::target) for the full form.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn name(&self) -> Option<&Segment> {
    match &self.target {
      Some(target) if target.len() == 1 => target.name(),
      _ => None,
    }
  }

  /// How many segments below its watch this record addresses (0 = self-event).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn depth(&self) -> usize {
    match self.target.as_ref() {
      Some(target) => target.len(),
      None => 0,
    }
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

  /// The affected child object's identity, if the driver could supply one. Lets the core
  /// install a watch tagged with its object identity, so a later re-arm can tell a
  /// same-name replacement from a survivor (see [`Identity`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn node(&self) -> Option<Identity> {
    self.node
  }

  /// Returns this record addressing one DIRECT child of its watch — the
  /// depth-one shape. See [`with_target`](Self::with_target) for the deeper
  /// kernel-recursive form.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub fn with_name(mut self, name: Segment) -> Self {
    self.target = Some(Location::from_segments([name]));
    self
  }

  /// Returns this record with its full watch-relative target location set. Only
  /// a kernel-recursive monitor accepts a target deeper than one segment (see
  /// the type-level addressing contract).
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub fn with_target(mut self, target: Location) -> Self {
    self.target = Some(target);
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

  /// Returns this record with the affected child object's [`Identity`] set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub const fn with_node(mut self, node: Identity) -> Self {
    self.node = Some(node);
    self
  }

  /// Returns this record additionally proving `more` — the facts its native
  /// event carried alongside its verb (a rename word that also reported a
  /// content change, a create mask that also reported an attribute one).
  ///
  /// A UNION, never an assignment: evidence only ever grows, so no builder in
  /// the chain can drop a fact an earlier one stated.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[must_use]
  pub const fn also_proved(mut self, more: Evidence) -> Self {
    self.evidence = self.evidence.union(more);
    self
  }
}

#[cfg(test)]
mod tests;
