//! The `ReadDirectoryChangesW` source: the pure decode and rename-pairing
//! machinery now; the OVERLAPPED handle/pump layer follows behind the same
//! seam.

pub(crate) mod decode;
pub(crate) mod pairing;

/// The `FILE_NOTIFY_CHANGE_*` completion-filter vocabulary and the fixed
/// subscription every RDCW read is issued with.
///
/// The ABI values are spelled out here rather than imported, for two reasons
/// that both bear on correctness:
///
/// * Three of the twelve bits (the named-stream trio) are WDK constants that
///   the Win32 `windows-sys` surface does not export at all, so half the
///   subscription would have to be literals regardless — and a filter written
///   half in imports and half in literals is exactly the shape that lost the
///   extended-attribute bit.
/// * The constant now lives in host-compiled code, so the subscription is a
///   plain value a test on any platform can assert against the decoder's
///   vocabulary. The kernel is the only executor of the read; it must not also
///   be the only executor of the read's *contract*. [`ffi`](super::ffi) still
///   pins each value that Win32 does export with a compile-time equality
///   assertion, so a wrong literal cannot survive a Windows build.
///
/// The subscription is deliberately TOTAL over the notify vocabulary: the core
/// narrows per subscription, and a kernel filter is not a place to be clever.
/// A bit left out here is not a lost optimization but a mutation the
/// filesystem is never required to report — silence with no `Overflow` and no
/// covering `Rescan`, which is the one outcome the loss accounting forbids.
// The windows read is the production consumer of these; on every other host
// only the twins and the conformance matrix reach them.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
pub(crate) mod notify {
  /// A file name in the watched subtree changed (create, delete, rename).
  pub(crate) const FILE_NAME: u32 = 0x0000_0001;
  /// A directory name in the watched subtree changed.
  pub(crate) const DIR_NAME: u32 = 0x0000_0002;
  /// An object's attributes changed.
  pub(crate) const ATTRIBUTES: u32 = 0x0000_0004;
  /// An object's size changed.
  pub(crate) const SIZE: u32 = 0x0000_0008;
  /// An object's last-write time changed.
  pub(crate) const LAST_WRITE: u32 = 0x0000_0010;
  /// An object's last-ACCESS time changed. Part of the metadata universe
  /// `Interest::attrib` subscribes, exactly like the write and creation
  /// stamps beside it.
  pub(crate) const LAST_ACCESS: u32 = 0x0000_0020;
  /// An object's creation time changed.
  pub(crate) const CREATION: u32 = 0x0000_0040;
  /// An object's extended attributes changed. The USN vocabulary lowers
  /// `USN_REASON_EA_CHANGE` to `Attrib`; without this bit the same mutation
  /// is not merely lowered differently on the RDCW arm, it is never reported
  /// at all — the backend choice would decide convergence.
  pub(crate) const EA: u32 = 0x0000_0080;
  /// An object's security descriptor changed.
  pub(crate) const SECURITY: u32 = 0x0000_0100;
  /// A named stream was added to or removed from an object (WDK).
  pub(crate) const STREAM_NAME: u32 = 0x0000_0200;
  /// A named stream's size changed (WDK).
  pub(crate) const STREAM_SIZE: u32 = 0x0000_0400;
  /// A named stream was written (WDK).
  pub(crate) const STREAM_WRITE: u32 = 0x0000_0800;

  /// The three named-stream bits, the only ones that make the kernel report
  /// the `FILE_ACTION_*_STREAM` actions the decoder folds onto their owner.
  pub(crate) const STREAMS: u32 = STREAM_NAME | STREAM_SIZE | STREAM_WRITE;

  /// The filter both record layouts subscribe: the whole notify vocabulary —
  /// the RDCW projection of the proto Interest universe (per-subscription
  /// narrowing happens in the core, never by thinning the kernel
  /// subscription).
  pub(crate) const FILTER: u32 = FILE_NAME
    | DIR_NAME
    | ATTRIBUTES
    | SIZE
    | LAST_WRITE
    | LAST_ACCESS
    | CREATION
    | EA
    | SECURITY
    | STREAMS;
}

#[cfg(test)]
mod notify_tests {
  use super::{super::usn::reason, notify};

  /// The subscription is the whole vocabulary. Written as an explicit OR of
  /// literals rather than `FILTER`'s own definition, so an omission has to be
  /// made twice — in the constant and in the expectation — before it can pass.
  #[test]
  fn the_subscription_covers_the_whole_notify_vocabulary() {
    assert_eq!(
      notify::FILTER,
      0x0001
        | 0x0002
        | 0x0004
        | 0x0008
        | 0x0010
        | 0x0020
        | 0x0040
        | 0x0080
        | 0x0100
        | 0x0200
        | 0x0400
        | 0x0800
    );
  }

  /// The three bits whose absence made three separate mutations unreportable,
  /// pinned to their ABI values individually so a regression names itself.
  #[test]
  fn the_metadata_and_stream_bits_are_subscribed() {
    assert_eq!(notify::EA, 0x0080, "FILE_NOTIFY_CHANGE_EA");
    assert_eq!(
      notify::LAST_ACCESS,
      0x0020,
      "FILE_NOTIFY_CHANGE_LAST_ACCESS"
    );
    assert_eq!(notify::STREAM_NAME, 0x0200);
    assert_eq!(notify::STREAM_SIZE, 0x0400);
    assert_eq!(notify::STREAM_WRITE, 0x0800);
    for (label, bit) in [
      ("extended attributes", notify::EA),
      ("last-access time", notify::LAST_ACCESS),
      ("stream name", notify::STREAM_NAME),
      ("stream size", notify::STREAM_SIZE),
      ("stream write", notify::STREAM_WRITE),
    ] {
      assert_ne!(notify::FILTER & bit, 0, "{label} is not subscribed");
    }
  }

  /// The executable conformance matrix between the two Windows backends.
  ///
  /// Both are supposed to report the same universe of user-visible mutations;
  /// the extended-attribute hole existed precisely because their interest
  /// tables lived in different files with nothing comparing them. Each row
  /// names a class of mutation, the USN reason bits that report it, and the
  /// RDCW filter bits that report the SAME mutation. The union of the USN
  /// column must exhaust everything the reason vocabulary lowers, and every
  /// RDCW column must be inside the subscription — so a reason added to one
  /// backend with no counterpart in the other fails here rather than in the
  /// field.
  #[test]
  fn both_windows_backends_subscribe_the_same_universe() {
    const MATRIX: &[(&str, u32, u32)] = &[
      (
        "unnamed data write",
        reason::MODIFY,
        notify::SIZE | notify::LAST_WRITE,
      ),
      ("extended attributes", reason::EA_CHANGE, notify::EA),
      (
        "security descriptor",
        reason::SECURITY_CHANGE,
        notify::SECURITY,
      ),
      (
        "basic info: times and attributes",
        reason::BASIC_INFO_CHANGE,
        notify::ATTRIBUTES | notify::LAST_WRITE | notify::LAST_ACCESS | notify::CREATION,
      ),
      (
        "the content-indexed attribute",
        reason::INDEXABLE_CHANGE,
        notify::ATTRIBUTES,
      ),
      (
        "compression, encryption, integrity, storage class",
        reason::COMPRESSION_CHANGE
          | reason::ENCRYPTION_CHANGE
          | reason::INTEGRITY_CHANGE
          | reason::DESIRED_STORAGE_CLASS_CHANGE,
        notify::ATTRIBUTES,
      ),
      (
        "named streams",
        reason::NAMED_DATA_OVERWRITE
          | reason::NAMED_DATA_EXTEND
          | reason::NAMED_DATA_TRUNCATION
          | reason::STREAM_CHANGE,
        notify::STREAMS,
      ),
      (
        "reparse points",
        reason::REPARSE_POINT_CHANGE,
        notify::ATTRIBUTES,
      ),
      (
        "dirent lifecycle and links",
        reason::STRUCTURAL,
        notify::FILE_NAME | notify::DIR_NAME,
      ),
    ];

    let mut usn_covered = 0u32;
    for (label, usn_bits, rdcw_bits) in MATRIX {
      assert_ne!(*usn_bits, 0, "{label}: the row names no journal reason");
      assert_ne!(*rdcw_bits, 0, "{label}: the row names no notify filter bit");
      assert_eq!(
        rdcw_bits & !notify::FILTER,
        0,
        "{label}: the notify bits reporting it are not subscribed"
      );
      usn_covered |= usn_bits;
    }

    let reportable =
      reason::MODIFY | reason::ATTRIB | reason::STRUCTURAL | reason::REPARSE_POINT_CHANGE;
    assert_eq!(
      reportable & !usn_covered,
      0,
      "a journal reason the vocabulary lowers has no RDCW counterpart in the matrix"
    );
    assert_eq!(
      usn_covered & reason::FILTERED,
      0,
      "a deliberately unlowered journal reason claims an RDCW counterpart"
    );
  }
}
