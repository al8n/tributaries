//! Pure decode of the fanotify FID wire layout.
//!
//! Runs everywhere tests run (including miri) — nothing here touches an fd.
//! The `FAN_*` mask constants and info-record type tags restate the kernel ABI
//! locally so this module carries no libc dependency; the FFI layer
//! cross-asserts them against libc.
//!
//! One `read()` buffer holds a run of variable-length events, each led by a
//! fixed `fanotify_event_metadata` header (native-endian, as read on this
//! machine) and followed by info records up to the header's `event_len`. A
//! `FAN_REPORT_DFID_NAME|TARGET_FID` stream carries, per dirent event, a
//! `DFID_NAME` record (the parent directory's FID plus the affected child's
//! name) and — for the child's own FID — a `FID` record; a `FAN_RENAME`
//! carries the `OLD_DFID_NAME`/`NEW_DFID_NAME` pair in one event.
//!
//! Every length is bounds-checked against the buffer: a truncated or
//! structurally impossible record sets `lossy` and stops, never panics or
//! reads out of bounds. Unknown info-record types are skipped by their own
//! `len`, so a kernel that grows the vocabulary degrades gracefully.

use std::{boxed::Box, vec::Vec};

/// A watched object's content changed.
pub(crate) const FAN_MODIFY: u64 = 0x0000_0002;
/// A watched object's metadata changed.
pub(crate) const FAN_ATTRIB: u64 = 0x0000_0004;
/// A child object was created in a watched directory.
pub(crate) const FAN_CREATE: u64 = 0x0000_0100;
/// A child object was removed from a watched directory.
pub(crate) const FAN_DELETE: u64 = 0x0000_0200;
/// The watched object itself was deleted.
pub(crate) const FAN_DELETE_SELF: u64 = 0x0000_0400;
/// The watched object itself was moved.
pub(crate) const FAN_MOVE_SELF: u64 = 0x0000_0800;
/// An atomic rename, reported with both directory FIDs and both names in ONE
/// event (5.17+). The composite the KR pairing rides.
pub(crate) const FAN_RENAME: u64 = 0x1000_0000;
/// The kernel queue overflowed; events were lost (a bare signal — no FID).
pub(crate) const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
/// The subject of the event is a directory.
pub(crate) const FAN_ONDIR: u64 = 0x4000_0000;

/// `EOVERFLOW` (Linux `asm-generic`): `name_to_handle_at`'s "your buffer was too
/// small" answer, returned AFTER it establishes a handle exists and writes the
/// required byte count back into `handle_bytes`. Restated locally so this pure
/// module carries no libc dependency; the FFI layer cross-asserts it against
/// libc. Errno-only, never a mask bit, hence its distance from the `FAN_*` set.
pub(crate) const EOVERFLOW: i32 = 75;

/// A record carrying a bare FID (the affected object's own handle, e.g. the
/// child's `FAN_REPORT_TARGET_FID` on a create).
pub(crate) const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
/// A record carrying a directory FID and the affected entry's name.
pub(crate) const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
/// A record carrying a bare directory FID (no name).
pub(crate) const FAN_EVENT_INFO_TYPE_DFID: u8 = 3;
/// The `FAN_RENAME` source: old directory FID + old name.
pub(crate) const FAN_EVENT_INFO_TYPE_OLD_DFID_NAME: u8 = 10;
/// The `FAN_RENAME` destination: new directory FID + new name.
pub(crate) const FAN_EVENT_INFO_TYPE_NEW_DFID_NAME: u8 = 12;

/// A raw fanotify event's mask word, with predicates over the kernel bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FanMask(u64);

impl FanMask {
  /// Wraps a raw mask word.
  pub(crate) const fn new(bits: u64) -> Self {
    Self(bits)
  }

  /// The raw mask bits.
  pub(crate) const fn bits(self) -> u64 {
    self.0
  }

  /// A child was created in the watched directory.
  pub(crate) const fn created(self) -> bool {
    self.0 & FAN_CREATE != 0
  }

  /// A child was removed from the watched directory.
  pub(crate) const fn removed(self) -> bool {
    self.0 & FAN_DELETE != 0
  }

  /// Content changed.
  pub(crate) const fn modified(self) -> bool {
    self.0 & FAN_MODIFY != 0
  }

  /// Metadata changed.
  pub(crate) const fn attrib(self) -> bool {
    self.0 & FAN_ATTRIB != 0
  }

  /// An atomic rename (both halves ride this one event).
  pub(crate) const fn rename(self) -> bool {
    self.0 & FAN_RENAME != 0
  }

  /// The watched object itself was deleted.
  pub(crate) const fn delete_self(self) -> bool {
    self.0 & FAN_DELETE_SELF != 0
  }

  /// The watched object itself moved.
  pub(crate) const fn move_self(self) -> bool {
    self.0 & FAN_MOVE_SELF != 0
  }

  /// The subject is a directory.
  pub(crate) const fn ondir(self) -> bool {
    self.0 & FAN_ONDIR != 0
  }

  /// The kernel queue overflowed.
  pub(crate) const fn q_overflow(self) -> bool {
    self.0 & FAN_Q_OVERFLOW != 0
  }
}

/// A filesystem object's exact identity: its superblock id plus an opaque
/// NFS-style file handle.
///
/// `handle` is the handle's `type` word (native-endian) followed by the
/// kernel's opaque bytes — the encoding embeds a generation counter, making
/// this a STRONGER identity than `(dev, ino)` (a recycled inode gets a fresh
/// generation and thus a different handle). Equality is byte-exact: two equal
/// `Fid`s name the same object appearance, and a hash is never substituted for
/// the comparison (a collision would fabricate identity — the class the exact
/// intern table exists to kill).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Fid {
  fsid: [u8; 8],
  handle: Box<[u8]>,
}

impl Fid {
  /// Builds a FID from its superblock id and its type-tagged handle bytes.
  pub(crate) fn new(fsid: [u8; 8], handle: Box<[u8]>) -> Self {
    Self { fsid, handle }
  }

  /// The superblock id the handle is scoped to.
  pub(crate) fn fsid(&self) -> [u8; 8] {
    self.fsid
  }

  /// The opaque, type-tagged handle bytes.
  pub(crate) fn handle(&self) -> &[u8] {
    &self.handle
  }
}

/// A `FAN_RENAME`'s two halves, each a directory FID plus the entry name in
/// that directory — the atomic pair the lowering emits as adjacent
/// `MovedFrom`/`MovedTo` with no pairing window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RenameInfo {
  pub(crate) old_dir: Fid,
  pub(crate) old_name: Vec<u8>,
  pub(crate) new_dir: Fid,
  pub(crate) new_name: Vec<u8>,
}

/// One decoded fanotify event after the info records are parsed.
///
/// A dirent event carries `dir_fid` (the affected directory, from its
/// `DFID_NAME` record) with `name` (the affected child) and, when the kernel
/// supplied it, `target_fid` (the child's own FID from `FAN_REPORT_TARGET_FID`
/// — the create self-maintenance handle). A self-event (`DELETE_SELF`,
/// `MOVE_SELF`) carries only the object's own `dir_fid`. A `FAN_RENAME`
/// carries `rename` and leaves the single-FID fields empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawFanotifyEvent {
  pub(crate) mask: FanMask,
  pub(crate) dir_fid: Option<Fid>,
  pub(crate) target_fid: Option<Fid>,
  pub(crate) name: Option<Vec<u8>>,
  pub(crate) rename: Option<RenameInfo>,
}

/// The outcome of decoding one `read()` buffer: the intact events, plus
/// `lossy` when a structurally invalid record forced an early stop (the caller
/// degrades that to the ordered loss signal) or an overflow marker was seen.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DecodeOutcome {
  pub(crate) events: Vec<RawFanotifyEvent>,
  pub(crate) lossy: bool,
}

/// `fanotify_event_metadata` header size (native ABI): u32 + u8 + u8 + u16 +
/// u64 + i32 + i32.
const METADATA_LEN: usize = 24;
/// `fanotify_event_info_header` size: u8 + u8 + u16.
const INFO_HEADER_LEN: usize = 4;
/// `__kernel_fsid_t` size: two i32.
const FSID_LEN: usize = 8;
/// `struct file_handle` fixed prefix: u32 handle_bytes + i32 handle_type.
const FILE_HANDLE_PREFIX: usize = 8;

/// One `DFID`/`FID`-family info record's parsed payload: the FID plus the
/// optional trailing name (present only for the `*_NAME` types).
struct FidRecord {
  fid: Fid,
  name: Option<Vec<u8>>,
}

/// Decodes a buffer of packed `fanotify_event_metadata` records with their
/// info records. Never panics: a truncated or structurally impossible record
/// marks the outcome `lossy` and stops.
pub(crate) fn decode_events(buf: &[u8]) -> DecodeOutcome {
  let mut events = Vec::new();
  let mut lossy = false;
  let mut at = 0usize;

  while at < buf.len() {
    let Some(header) = buf.get(at..at + METADATA_LEN) else {
      lossy = true;
      break;
    };
    let event_len = u32::from_ne_bytes(header[0..4].try_into().expect("4 bytes")) as usize;
    let mask = u64::from_ne_bytes(header[8..16].try_into().expect("8 bytes"));

    // `event_len` spans the whole event (header + every info record). A value
    // below the header, or past the buffer, is structurally impossible: stop
    // rather than walk off the record.
    if event_len < METADATA_LEN || event_len > buf.len() - at {
      lossy = true;
      break;
    }

    let mask = FanMask::new(mask);
    // An overflow marker carries no FID and no attribution — it is a bare
    // loss signal, exactly the inotify `IN_Q_OVERFLOW` vocabulary.
    if mask.q_overflow() {
      lossy = true;
      at += event_len;
      continue;
    }

    let info = &buf[at + METADATA_LEN..at + event_len];
    match decode_info(mask, info) {
      Some(event) => events.push(event),
      None => {
        lossy = true;
        break;
      }
    }
    at += event_len;
  }

  DecodeOutcome { events, lossy }
}

/// Parses one event's info-record region into the classified FIDs and names.
/// Returns `None` on any structurally invalid record (the caller marks the
/// batch lossy and stops).
fn decode_info(mask: FanMask, mut info: &[u8]) -> Option<RawFanotifyEvent> {
  let mut dir_fid = None;
  let mut target_fid = None;
  let mut name = None;
  let mut rename_old: Option<(Fid, Vec<u8>)> = None;
  let mut rename_new: Option<(Fid, Vec<u8>)> = None;

  while !info.is_empty() {
    let header = info.get(..INFO_HEADER_LEN)?;
    let info_type = header[0];
    let record_len = u16::from_ne_bytes(header[2..4].try_into().expect("2 bytes")) as usize;
    // A record shorter than its own header, or overrunning the region, is
    // corruption — never trust a length that walks past the event.
    if record_len < INFO_HEADER_LEN || record_len > info.len() {
      return None;
    }
    let payload = &info[INFO_HEADER_LEN..record_len];

    match info_type {
      FAN_EVENT_INFO_TYPE_DFID_NAME => {
        let record = decode_fid_record(payload, true)?;
        dir_fid = Some(record.fid);
        name = record.name;
      }
      FAN_EVENT_INFO_TYPE_DFID => {
        let record = decode_fid_record(payload, false)?;
        dir_fid = Some(record.fid);
      }
      FAN_EVENT_INFO_TYPE_FID => {
        let record = decode_fid_record(payload, false)?;
        target_fid = Some(record.fid);
      }
      FAN_EVENT_INFO_TYPE_OLD_DFID_NAME => {
        let record = decode_fid_record(payload, true)?;
        rename_old = Some((record.fid, record.name.unwrap_or_default()));
      }
      FAN_EVENT_INFO_TYPE_NEW_DFID_NAME => {
        let record = decode_fid_record(payload, true)?;
        rename_new = Some((record.fid, record.name.unwrap_or_default()));
      }
      // A PIDFD, an ERROR record, or a future info type: skip it by its own
      // length. The kernel guarantees the tags we consume are self-delimited,
      // so an unknown one never desynchronizes the walk.
      _ => {}
    }

    info = &info[record_len..];
  }

  let rename = match (rename_old, rename_new) {
    (Some((old_dir, old_name)), Some((new_dir, new_name))) => Some(RenameInfo {
      old_dir,
      old_name,
      new_dir,
      new_name,
    }),
    // A rename must carry BOTH halves; one alone is malformed for this
    // vocabulary and cannot be paired.
    (Some(_), None) | (None, Some(_)) if mask.rename() => return None,
    _ => None,
  };

  Some(RawFanotifyEvent {
    mask,
    dir_fid,
    target_fid,
    name,
    rename,
  })
}

/// Parses one FID payload: `fsid` (8 bytes) + `struct file_handle`
/// (`handle_bytes` u32, `handle_type` i32, then `handle_bytes` opaque bytes),
/// optionally followed by a NUL-terminated name (the `*_NAME` record types).
///
/// The stored handle is `handle_type` (native-endian) followed by the opaque
/// bytes — a byte-exact identity that never needs the object re-stat'd.
fn decode_fid_record(payload: &[u8], has_name: bool) -> Option<FidRecord> {
  let fsid: [u8; 8] = payload.get(..FSID_LEN)?.try_into().expect("8 bytes");
  let fh = payload.get(FSID_LEN..)?;
  let fh_prefix = fh.get(..FILE_HANDLE_PREFIX)?;
  let handle_bytes = u32::from_ne_bytes(fh_prefix[0..4].try_into().expect("4 bytes")) as usize;
  let type_bytes = &fh_prefix[4..8];
  let opaque = fh.get(FILE_HANDLE_PREFIX..FILE_HANDLE_PREFIX + handle_bytes)?;

  let mut handle = Vec::with_capacity(type_bytes.len() + opaque.len());
  handle.extend_from_slice(type_bytes);
  handle.extend_from_slice(opaque);
  let fid = Fid::new(fsid, handle.into_boxed_slice());

  let name = if has_name {
    let after = &fh[FILE_HANDLE_PREFIX + handle_bytes..];
    // The name is NUL-terminated and NUL-padded up to the record's `len`; trim
    // at the first NUL. An empty name (a bare directory FID reported with the
    // DFID_NAME tag) yields `None`.
    let end = after.iter().position(|b| *b == 0).unwrap_or(after.len());
    if end == 0 {
      None
    } else {
      Some(after[..end].to_vec())
    }
  } else {
    None
  };

  Some(FidRecord { fid, name })
}

/// What to do after one `name_to_handle_at` attempt, given its return code, its
/// errno on failure, and whether the buffer was ALREADY grown once by a prior
/// `EOVERFLOW`. Pure so the per-errno decision is testable without a live
/// syscall — the FFI wrapper supplies the raw outcome and executes the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandleAttempt {
  /// `rc == 0`: the handle is fully encoded at the buffer's `handle_bytes`.
  Encoded,
  /// `EOVERFLOW` on the FIRST try: the kernel wrote the required size into
  /// `handle_bytes` and proved a handle exists — grow the buffer to that size
  /// and retry exactly once.
  Grow,
  /// The filesystem cannot encode a handle for this object: any errno other
  /// than `EOVERFLOW`, OR a SECOND `EOVERFLOW` (the kernel asking to grow again
  /// after already sizing the buffer to its own reported requirement — a lying
  /// kernel, treated as failure rather than looped on).
  Unsupported,
}

/// The pure `name_to_handle_at` outcome → next-action decision. `EOVERFLOW`
/// (and only `EOVERFLOW`) proves a handle exists; the first one asks to grow,
/// a second is a broken kernel. `rc == 0` is the encoded handle; every other
/// errno is a non-exporting (or transient/permission) failure.
pub(crate) fn classify_handle_attempt(rc: i32, errno: Option<i32>, grown: bool) -> HandleAttempt {
  if rc == 0 {
    return HandleAttempt::Encoded;
  }
  match (errno == Some(EOVERFLOW), grown) {
    (true, false) => HandleAttempt::Grow,
    _ => HandleAttempt::Unsupported,
  }
}

#[cfg(test)]
mod tests;
