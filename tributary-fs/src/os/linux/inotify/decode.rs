//! Pure decode of the kernel `inotify_event` wire layout.
//!
//! Runs everywhere tests run (including miri) — nothing here touches an fd.
//! The `IN_*` constants restate the kernel ABI values locally so this module
//! carries no libc dependency; the FFI layer cross-asserts them against libc
//! when it lands.
//!
//! Invariant: every wire-derived offset and length is advanced through checked
//! arithmetic and read through `get`, so a truncated or length-overflowing
//! record is `lossy`, never a panic — on 32-bit as on 64-bit. (A kernel `len`
//! up to `u32::MAX` would otherwise wrap `at + HEADER + len` past `usize` and
//! panic on i686 before the slice bound is ever tested.)

/// A child object was created in the watched directory.
pub(crate) const IN_CREATE: u32 = 0x0000_0100;
/// A child object was removed from the watched directory.
pub(crate) const IN_DELETE: u32 = 0x0000_0200;
/// The watched object itself was deleted.
pub(crate) const IN_DELETE_SELF: u32 = 0x0000_0400;
/// A watched object's content changed.
pub(crate) const IN_MODIFY: u32 = 0x0000_0002;
/// A watched object's metadata changed.
pub(crate) const IN_ATTRIB: u32 = 0x0000_0004;
/// The watched object itself was moved.
pub(crate) const IN_MOVE_SELF: u32 = 0x0000_0800;
/// The source half of a rename, cookie-paired with [`IN_MOVED_TO`].
pub(crate) const IN_MOVED_FROM: u32 = 0x0000_0040;
/// The destination half of a rename, cookie-paired with [`IN_MOVED_FROM`].
pub(crate) const IN_MOVED_TO: u32 = 0x0000_0080;
/// The filesystem holding the watched object was unmounted.
pub(crate) const IN_UNMOUNT: u32 = 0x0000_2000;
/// The kernel queue overflowed; events were lost (`wd == -1`).
pub(crate) const IN_Q_OVERFLOW: u32 = 0x0000_4000;
/// The watch was removed and will deliver no more events — the authoritative
/// teardown signal for one `wd`.
pub(crate) const IN_IGNORED: u32 = 0x0000_8000;
/// The subject of the event is a directory.
pub(crate) const IN_ISDIR: u32 = 0x4000_0000;
/// Arm only if the target is a directory (atomic kind check at the syscall).
pub(crate) const IN_ONLYDIR: u32 = 0x0100_0000;
/// Never resolve a symlink at arm time.
pub(crate) const IN_DONT_FOLLOW: u32 = 0x0200_0000;
/// Suppress events for children after they are unlinked.
pub(crate) const IN_EXCL_UNLINK: u32 = 0x0400_0000;
/// Fail with `EEXIST` instead of updating the mask when the inode is already
/// watched — the deterministic aliasing signal.
pub(crate) const IN_MASK_CREATE: u32 = 0x1000_0000;

/// The mask every directory watch arms with: the record vocabulary the
/// Monitor consumes plus the arm-time guards (`IN_ONLYDIR`, `IN_DONT_FOLLOW`,
/// `IN_EXCL_UNLINK`, `IN_MASK_CREATE`).
pub(crate) const WATCH_MASK: u32 = IN_ATTRIB
  | IN_CREATE
  | IN_DELETE
  | IN_DELETE_SELF
  | IN_MODIFY
  | IN_MOVE_SELF
  | IN_MOVED_FROM
  | IN_MOVED_TO
  | IN_ONLYDIR
  | IN_DONT_FOLLOW
  | IN_EXCL_UNLINK
  | IN_MASK_CREATE;

/// A raw inotify event's mask word, with predicates over the kernel bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InotifyMask(pub(crate) u32);

impl InotifyMask {
  /// The kernel queue overflowed (the event carries `wd == -1`).
  pub(crate) const fn is_overflow(self) -> bool {
    self.0 & IN_Q_OVERFLOW != 0
  }

  /// The watch was torn down; no more events follow for its `wd`.
  pub(crate) const fn is_ignored(self) -> bool {
    self.0 & IN_IGNORED != 0
  }

  /// The event's subject is a directory.
  pub(crate) const fn is_dir(self) -> bool {
    self.0 & IN_ISDIR != 0
  }

  /// The source half of a rename.
  pub(crate) const fn moved_from(self) -> bool {
    self.0 & IN_MOVED_FROM != 0
  }

  /// The destination half of a rename.
  pub(crate) const fn moved_to(self) -> bool {
    self.0 & IN_MOVED_TO != 0
  }

  /// The watched object itself moved.
  pub(crate) const fn move_self(self) -> bool {
    self.0 & IN_MOVE_SELF != 0
  }

  /// The watched object itself was deleted.
  pub(crate) const fn delete_self(self) -> bool {
    self.0 & IN_DELETE_SELF != 0
  }

  /// The backing filesystem was unmounted.
  pub(crate) const fn unmount(self) -> bool {
    self.0 & IN_UNMOUNT != 0
  }

  /// A child was created.
  pub(crate) const fn created(self) -> bool {
    self.0 & IN_CREATE != 0
  }

  /// A child was removed.
  pub(crate) const fn removed(self) -> bool {
    self.0 & IN_DELETE != 0
  }

  /// Content changed.
  pub(crate) const fn modified(self) -> bool {
    self.0 & IN_MODIFY != 0
  }

  /// Metadata changed.
  pub(crate) const fn attrib(self) -> bool {
    self.0 & IN_ATTRIB != 0
  }
}

/// One decoded kernel record: `{ wd, mask, cookie }` plus the NUL-trimmed
/// child name (`None` for self-events and the overflow sentinel). The name is
/// raw bytes — Linux names need not be UTF-8; the lowering layer owns that
/// escalation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawInotifyEvent {
  pub(crate) wd: i32,
  pub(crate) mask: InotifyMask,
  pub(crate) cookie: u32,
  pub(crate) name: Option<Vec<u8>>,
}

/// The outcome of decoding one `read()` buffer: the intact records, plus
/// `lossy` when a structurally invalid tail forced an early stop — the caller
/// degrades that to the ordered loss signal, never a panic.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DecodeOutcome {
  pub(crate) events: Vec<RawInotifyEvent>,
  pub(crate) lossy: bool,
}

/// Header size of the kernel `inotify_event` struct.
const HEADER: usize = 16;

/// Decodes a buffer of packed `inotify_event` records (native-endian, as read
/// from the instance fd on this same machine). Never panics: a truncated or
/// structurally absurd record marks the outcome `lossy` and stops.
pub(crate) fn decode_events(buf: &[u8]) -> DecodeOutcome {
  let mut events = Vec::new();
  let mut lossy = false;
  let mut at = 0usize;

  while at < buf.len() {
    let Some(header) = buf.get(at..at + HEADER) else {
      lossy = true;
      break;
    };
    // The four header words; slices are exactly 4 bytes, so the conversions
    // cannot fail.
    let wd = i32::from_ne_bytes(header[0..4].try_into().expect("4 bytes"));
    let mask = u32::from_ne_bytes(header[4..8].try_into().expect("4 bytes"));
    let cookie = u32::from_ne_bytes(header[8..12].try_into().expect("4 bytes"));
    let len = u32::from_ne_bytes(header[12..16].try_into().expect("4 bytes")) as usize;

    // `len` is the kernel-supplied name length (a u32 widened to usize). On a
    // 32-bit target `at + HEADER + len` can wrap usize and panic before the
    // slice bound is ever tested, so resolve the name range through checked
    // arithmetic: any overflow is a structurally impossible record that stops
    // the walk lossy, exactly like an out-of-range length — never a panic.
    let Some((name_start, name_end)) = at
      .checked_add(HEADER)
      .and_then(|start| start.checked_add(len).map(|end| (start, end)))
    else {
      lossy = true;
      break;
    };
    let Some(name_bytes) = buf.get(name_start..name_end) else {
      lossy = true;
      break;
    };
    // The kernel NUL-pads names up to `len`; trim to the real bytes. An
    // all-NUL (or zero-len) name is a self-event: no child addressed.
    let trimmed_end = name_bytes
      .iter()
      .rposition(|b| *b != 0)
      .map_or(0, |last| last + 1);
    let name = if trimmed_end == 0 {
      None
    } else {
      Some(name_bytes[..trimmed_end].to_vec())
    };

    events.push(RawInotifyEvent {
      wd,
      mask: InotifyMask(mask),
      cookie,
      name,
    });
    at = name_end;
  }

  DecodeOutcome { events, lossy }
}
