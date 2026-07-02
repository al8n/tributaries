//! The FSEvents payload vocabulary and its pure decode helpers.
//!
//! Pure data only — no FFI — so this module compiles (and its tests run) on
//! every platform, including under miri. The unsafe CoreFoundation decode in
//! `os::macos` reduces each event to these types as early as possible.

use std::{
  num::NonZeroU64,
  path::PathBuf,
  sync::atomic::{AtomicBool, Ordering},
};

use super::{SourceError, SourceMessage};

/// The raw flag word of one FSEvents event.
///
/// The bit values are the stable ABI constants of `FSEvents.h`; a macOS-only
/// test asserts each against the system bindings. Flags are HINTS, not a log:
/// within one latency window all operations on a path merge into a single
/// event whose word is the OR of everything that happened, with ordering
/// unrecoverable — truth must be established by stat, never minted from a
/// flag word alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FsEventFlags(u32);

macro_rules! flag_predicate {
  ($(#[$meta:meta])* $konst:ident, $predicate:ident, $bit:literal) => {
    $(#[$meta])*
    pub(crate) const $konst: Self = Self($bit);

    $(#[$meta])*
    #[inline]
    pub(crate) const fn $predicate(self) -> bool {
      self.contains(Self::$konst)
    }
  };
}

// The complete header flag vocabulary is declared even where the driver does
// not yet consult it (own-event marking, hardlink and clone classes are
// deferred surface), and the raw-word accessors serve the test suites.
#[allow(dead_code)]
impl FsEventFlags {
  /// Wraps a raw flag word.
  #[inline]
  pub(crate) const fn new(bits: u32) -> Self {
    Self(bits)
  }

  /// The raw flag word.
  #[inline]
  pub(crate) const fn bits(self) -> u32 {
    self.0
  }

  /// Whether every bit of `other` is set in `self`.
  #[inline]
  pub(crate) const fn contains(self, other: Self) -> bool {
    self.0 & other.0 == other.0
  }

  flag_predicate!(
    /// Rescan the flagged path AND everything below it; the path can lie
    /// above the watched root (hierarchical coalescing) or be `/`.
    MUST_SCAN_SUBDIRS,
    must_scan_subdirs,
    0x0000_0001
  );
  flag_predicate!(
    /// The client-side buffer overflowed; accompanies `MUST_SCAN_SUBDIRS`.
    USER_DROPPED,
    user_dropped,
    0x0000_0002
  );
  flag_predicate!(
    /// The kernel-side buffer overflowed; accompanies `MUST_SCAN_SUBDIRS`.
    KERNEL_DROPPED,
    kernel_dropped,
    0x0000_0004
  );
  flag_predicate!(
    /// The 64-bit journal id counter wrapped: every stored id is invalid.
    EVENT_IDS_WRAPPED,
    event_ids_wrapped,
    0x0000_0008
  );
  flag_predicate!(
    /// The history→live sentinel of a `sinceWhen` replay; ignore its path.
    HISTORY_DONE,
    history_done,
    0x0000_0010
  );
  flag_predicate!(
    /// The watched root (or an ancestor) moved or vanished; the event id is
    /// zero and the path is the original registered root.
    ROOT_CHANGED,
    root_changed,
    0x0000_0020
  );
  flag_predicate!(
    /// A volume mounted at the flagged path.
    MOUNT,
    mount,
    0x0000_0040
  );
  flag_predicate!(
    /// A volume unmounted at the flagged path.
    UNMOUNT,
    unmount,
    0x0000_0080
  );
  flag_predicate!(
    /// The item appeared.
    ITEM_CREATED,
    item_created,
    0x0000_0100
  );
  flag_predicate!(
    /// The item vanished.
    ITEM_REMOVED,
    item_removed,
    0x0000_0200
  );
  flag_predicate!(
    /// The item's inode metadata changed.
    ITEM_INODE_META_MOD,
    item_inode_meta_mod,
    0x0000_0400
  );
  flag_predicate!(
    /// The item was one side of a rename (source and destination each get
    /// their own event; FSEvents supplies no pairing token).
    ITEM_RENAMED,
    item_renamed,
    0x0000_0800
  );
  flag_predicate!(
    /// The item's content changed.
    ITEM_MODIFIED,
    item_modified,
    0x0000_1000
  );
  flag_predicate!(
    /// The item's Finder info changed.
    ITEM_FINDER_INFO_MOD,
    item_finder_info_mod,
    0x0000_2000
  );
  flag_predicate!(
    /// The item's ownership changed.
    ITEM_CHANGE_OWNER,
    item_change_owner,
    0x0000_4000
  );
  flag_predicate!(
    /// The item's extended attributes changed.
    ITEM_XATTR_MOD,
    item_xattr_mod,
    0x0000_8000
  );
  flag_predicate!(
    /// The item is a regular file.
    ITEM_IS_FILE,
    item_is_file,
    0x0001_0000
  );
  flag_predicate!(
    /// The item is a directory.
    ITEM_IS_DIR,
    item_is_dir,
    0x0002_0000
  );
  flag_predicate!(
    /// The item is a symbolic link (the link object itself, never followed).
    ITEM_IS_SYMLINK,
    item_is_symlink,
    0x0004_0000
  );
  flag_predicate!(
    /// The event was caused by this process (requires the MarkSelf option).
    OWN_EVENT,
    own_event,
    0x0008_0000
  );
  flag_predicate!(
    /// The item is a hard link.
    ITEM_IS_HARDLINK,
    item_is_hardlink,
    0x0010_0000
  );
  flag_predicate!(
    /// The item is the last hard link to its inode.
    ITEM_IS_LAST_HARDLINK,
    item_is_last_hardlink,
    0x0020_0000
  );
  flag_predicate!(
    /// The item is an APFS clone (a distinct inode).
    ITEM_CLONED,
    item_cloned,
    0x0040_0000
  );

  /// Whether the stream lost sync with the journal on either side — the
  /// whole-stream loss signal (each also sets `MUST_SCAN_SUBDIRS`).
  #[inline]
  pub(crate) const fn lost_sync(self) -> bool {
    self.user_dropped() || self.kernel_dropped()
  }

  /// The bits a rename word may carry and still be trusted as *only* a
  /// rename: the rename verb plus pure type hints. Any other bit means the
  /// window coalesced additional operations into the word.
  const PURE_RENAME: u32 = Self::ITEM_RENAMED.0
    | Self::ITEM_IS_FILE.0
    | Self::ITEM_IS_DIR.0
    | Self::ITEM_IS_SYMLINK.0
    | Self::ITEM_IS_HARDLINK.0
    | Self::ITEM_IS_LAST_HARDLINK.0;

  /// Whether this word is a rename and NOTHING but a rename (type hints
  /// aside). Only a pure rename half may take the no-probe pairing fast
  /// path: a word also carrying create/remove/modify/attrib bits is an
  /// ambiguous coalescing and must be grounded by a probe, or the extra
  /// operation would be silently dropped.
  #[inline]
  pub(crate) const fn is_pure_rename(self) -> bool {
    self.item_renamed() && self.0 & !Self::PURE_RENAME == 0
  }
}

/// One decoded FSEvents event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawOsEvent {
  /// Absolute path in filesystem representation — decomposed UTF-8 bytes, as
  /// delivered; prefix comparisons must use the same transform on both sides.
  pub(crate) path: PathBuf,
  /// The raw flag word.
  pub(crate) flags: FsEventFlags,
  /// The journal event id; zero only on synthetic events (`ROOT_CHANGED`).
  pub(crate) event_id: u64,
  /// The extended-data inode, when the OS supplied one.
  pub(crate) file_id: Option<NonZeroU64>,
}

/// Mints the identity payload from an extended-data fileID.
///
/// The inode arrives boxed as a signed 64-bit CFNumber; the bit-cast is the
/// lossless inverse of that storage. Zero is not a valid inode on APFS/HFS+
/// and maps to `None` — the conservative "unknown identity".
#[inline]
pub(crate) const fn file_id_from_extended(raw: i64) -> Option<NonZeroU64> {
  NonZeroU64::new(raw as u64)
}

/// Rebuilds a path from NUL-terminated filesystem-representation bytes.
///
/// Bytes past the first NUL are buffer slack, not path. An empty
/// representation is no path at all and yields `None`.
pub(crate) fn path_from_fs_repr(bytes: &[u8]) -> Option<PathBuf> {
  let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
  if end == 0 {
    return None;
  }
  #[cfg(unix)]
  {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
    Some(PathBuf::from(OsStr::from_bytes(&bytes[..end])))
  }
  #[cfg(not(unix))]
  {
    Some(PathBuf::from(
      String::from_utf8_lossy(&bytes[..end]).into_owned(),
    ))
  }
}

/// A non-blocking send's outcome, reduced to the two facts the forwarding
/// protocol dispatches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
  /// The message was accepted.
  Sent,
  /// The channel was full; the message was dropped.
  Full,
  /// The receiver is gone; nothing will be read again.
  Closed,
}

/// Forwards one decoded callback batch: data on the bounded channel, loss on
/// the control channel.
///
/// Loss is an IN-BAND control message, never a latch a wake must later drain:
/// the control channel is unbounded, so [`signal_loss`] cannot fail for lack
/// of capacity, and the dedup flag bounds it to one in-flight `Overflow` per
/// acknowledgement — there is no interleaving in which a loss is recorded
/// with no message left to observe it (the latch-and-wake protocol this
/// replaces had exactly that hole, three review rounds running).
///
/// A batch dropped on a full data channel and an undecodable entry both
/// degrade to the same `Overflow`; a closed data channel means the receiver
/// is gone and nothing is signaled.
pub(crate) fn forward_batch<D, C>(
  overflow_pending: &AtomicBool,
  events: Vec<RawOsEvent>,
  lossy: bool,
  mut send_data: D,
  send_control: C,
) where
  D: FnMut(SourceMessage) -> SendOutcome,
  C: FnOnce(SourceMessage) -> bool,
{
  let mut lost = lossy;
  if !events.is_empty() {
    match send_data(SourceMessage::Batch(events)) {
      SendOutcome::Sent => {}
      SendOutcome::Full => lost = true,
      SendOutcome::Closed => return,
    }
  }
  if lost {
    signal_loss(overflow_pending, send_control);
  }
}

/// Sends one deduplicated `Overflow` on the control channel.
///
/// The flag's false→true transition elects exactly one sender; it stays set
/// until the driver acknowledges the message (resetting the flag), so at most
/// one `Overflow` is ever in flight — losses meanwhile are covered by it,
/// since the driver's rescan reads current state. `send` returning `false`
/// means the control receiver is gone; the flag is restored so a future
/// generation is not muted.
pub(crate) fn signal_loss<C>(overflow_pending: &AtomicBool, send: C)
where
  C: FnOnce(SourceMessage) -> bool,
{
  if !overflow_pending.swap(true, Ordering::AcqRel) && !send(SourceMessage::Overflow) {
    overflow_pending.store(false, Ordering::Release);
  }
}

/// Sends the stream's one terminal `Fatal` on the control channel, at most
/// once ever. Unbounded control means the send cannot fail for capacity; the
/// flag makes later panics no-ops.
pub(crate) fn signal_fatal_once<C>(fatal_sent: &AtomicBool, err: SourceError, send: C)
where
  C: FnOnce(SourceMessage) -> bool,
{
  if !fatal_sent.swap(true, Ordering::AcqRel) {
    let _ = send(SourceMessage::Fatal(err));
  }
}

#[cfg(test)]
mod tests;
