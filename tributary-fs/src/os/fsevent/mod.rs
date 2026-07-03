//! The FSEvents payload vocabulary and its pure decode helpers.
//!
//! Pure data only — no FFI — so this module compiles (and its tests run) on
//! every platform, including under miri. The unsafe CoreFoundation decode in
//! `os::macos` reduces each event to these types as early as possible.

use std::{
  num::NonZeroU64,
  path::PathBuf,
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
  },
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

/// The transport-side state one source's callback owns: the batch budget and
/// the two signal dedups.
///
/// Every message of a source — `Batch`, `Overflow`, `Fatal` — rides ONE
/// unbounded FIFO queue, so per-source ordering between data and the signals
/// covering it holds by construction (there is no second lane to race) and a
/// signal send can never fail for capacity. The queue being unbounded, memory
/// is bounded here instead: a batch may enqueue only under a [`BudgetPermit`],
/// and the dedups keep at most one `Overflow` (per acknowledgement) and one
/// `Fatal` (ever) in flight.
#[derive(Debug)]
pub(crate) struct TransportState {
  /// Batches currently enqueued (or being processed); the budget cap bounds
  /// the queue's memory since the queue itself is unbounded.
  in_flight: Arc<AtomicUsize>,
  /// The most batches allowed in flight at once.
  budget: usize,
  /// One `Overflow` is enqueued and not yet acknowledged; further losses are
  /// covered by it (the rescan it becomes reads current state).
  overflow_pending: Arc<AtomicBool>,
  /// The terminal `Fatal` was sent; later failures are no-ops.
  fatal_sent: AtomicBool,
}

impl TransportState {
  /// A fresh transport allowing `budget` batches in flight.
  pub(crate) fn new(budget: usize) -> Self {
    Self {
      in_flight: Arc::new(AtomicUsize::new(0)),
      budget,
      overflow_pending: Arc::new(AtomicBool::new(false)),
      fatal_sent: AtomicBool::new(false),
    }
  }

  /// Batches currently holding a permit (in the queue or being processed).
  #[cfg(test)]
  pub(crate) fn in_flight(&self) -> usize {
    self.in_flight.load(Ordering::Acquire)
  }

  /// Whether an unacknowledged `Overflow` is in flight.
  #[cfg(test)]
  pub(crate) fn overflow_pending(&self) -> bool {
    self.overflow_pending.load(Ordering::Acquire)
  }
}

/// The RAII budget slot one enqueued batch holds; dropping it — after
/// processing, on a discarded payload, in a shutdown drain, anywhere —
/// returns the slot, so the budget cannot leak on any path.
#[derive(Debug)]
pub(crate) struct BudgetPermit(Arc<AtomicUsize>);

impl BudgetPermit {
  /// Claims a slot, or `None` when the budget is exhausted.
  fn acquire(transport: &TransportState) -> Option<Self> {
    let cap = transport.budget;
    transport
      .in_flight
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
        (n < cap).then_some(n + 1)
      })
      .ok()?;
    Some(Self(Arc::clone(&transport.in_flight)))
  }
}

impl Drop for BudgetPermit {
  fn drop(&mut self) {
    self.0.fetch_sub(1, Ordering::AcqRel);
  }
}

/// One callback invocation's decoded events plus the budget slot they occupy.
/// The batch boundary is preserved (it is the natural rename-pairing window).
#[derive(Debug)]
pub(crate) struct BatchPayload {
  /// The decoded events, in callback order.
  pub(crate) events: Vec<RawOsEvent>,
  /// The budget slot; released when the payload drops.
  pub(crate) permit: BudgetPermit,
}

/// The RAII acknowledgement riding an `Overflow` message: dropping it —
/// normally by the driver just before it acts on the loss, but equally by a
/// refused send or a shutdown drain — re-arms the dedup so the next loss
/// signals afresh. A loss racing the acknowledgement either elects a fresh
/// message or is covered by the rescan the acknowledged one is about to
/// become.
#[derive(Debug)]
pub(crate) struct OverflowAck(Arc<AtomicBool>);

impl Drop for OverflowAck {
  fn drop(&mut self) {
    self.0.store(false, Ordering::Release);
  }
}

/// Forwards one decoded callback batch onto the source's single ordered
/// queue.
///
/// `send` returning `false` means the receiver is gone (the queue is
/// unbounded, so capacity is never the reason); nothing further is signaled —
/// a refused `Overflow` is dropped by the send itself, and its
/// [`OverflowAck`] resets the dedup so a future generation is not muted.
///
/// A batch over budget and an undecodable entry both degrade to the same
/// in-order `Overflow`.
pub(crate) fn forward_batch<S>(
  transport: &TransportState,
  events: Vec<RawOsEvent>,
  lossy: bool,
  mut send: S,
) where
  S: FnMut(SourceMessage) -> bool,
{
  let mut lost = lossy;
  if !events.is_empty() {
    match BudgetPermit::acquire(transport) {
      Some(permit) => {
        if !send(SourceMessage::Batch(BatchPayload { events, permit })) {
          return;
        }
      }
      None => lost = true,
    }
  }
  if lost {
    signal_loss(transport, send);
  }
}

/// Enqueues one deduplicated `Overflow`.
///
/// The dedup's false→true transition elects exactly one sender; the flag
/// stays set until the message's [`OverflowAck`] drops (the driver
/// acknowledging, a refused send, a drain), so at most one `Overflow` is ever
/// in flight and losses meanwhile are covered by it.
pub(crate) fn signal_loss<S>(transport: &TransportState, mut send: S)
where
  S: FnMut(SourceMessage) -> bool,
{
  if !transport.overflow_pending.swap(true, Ordering::AcqRel) {
    let ack = OverflowAck(Arc::clone(&transport.overflow_pending));
    // A refused send drops the message here, whose ack re-arms the dedup.
    let _ = send(SourceMessage::Overflow(ack));
  }
}

/// Enqueues the stream's one terminal `Fatal`, at most once ever.
pub(crate) fn signal_fatal_once<S>(transport: &TransportState, err: SourceError, mut send: S)
where
  S: FnMut(SourceMessage) -> bool,
{
  if !transport.fatal_sent.swap(true, Ordering::AcqRel) {
    let _ = send(SourceMessage::Fatal(err));
  }
}

#[cfg(test)]
mod tests;
