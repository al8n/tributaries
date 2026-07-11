//! The pure `ReadDirectoryChangesW` completion-buffer decode.
//!
//! One completion delivers a chain of `FILE_NOTIFY_INFORMATION` (basic) or
//! `FILE_NOTIFY_EXTENDED_INFORMATION` (extended) records linked by
//! `NextEntryOffset`. The chain is kernel-produced but decoded defensively:
//! every offset is validated (in-bounds, DWORD-aligned, forward-progress) and
//! every multi-byte field is an explicit little-endian load from `&[u8]`, so a
//! malformed or truncated chain refuses the REMAINDER as decode loss — never
//! UB, never a panic — and the whole module runs under miri on every host.

/// The typed `FILE_ACTION_*` word of one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RdcwAction {
  /// `FILE_ACTION_ADDED` — the object appeared under the watched root.
  Added,
  /// `FILE_ACTION_REMOVED` — the object left the watched root.
  Removed,
  /// `FILE_ACTION_MODIFIED` — contents or attributes changed.
  Modified,
  /// `FILE_ACTION_RENAMED_OLD_NAME` — the departing half of a rename pair.
  RenamedOld,
  /// `FILE_ACTION_RENAMED_NEW_NAME` — the arriving half of a rename pair.
  RenamedNew,
  /// An action word this vocabulary does not know; the lowering degrades it
  /// to a located rescan rather than guessing a verb.
  Unknown(u32),
}

impl RdcwAction {
  const fn from_word(word: u32) -> Self {
    match word {
      1 => Self::Added,
      2 => Self::Removed,
      3 => Self::Modified,
      4 => Self::RenamedOld,
      5 => Self::RenamedNew,
      other => Self::Unknown(other),
    }
  }
}

/// A record's watch-relative name, decoded from UTF-16LE.
///
/// Components are split on the `\` separators FIRST, at the code-unit level
/// (`0x005C` can never be part of a surrogate pair), then decoded one by one —
/// so an undecodable component still leaves every ancestor above it named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RdcwName {
  /// Every component decoded to strict UTF-8. Components are never empty and
  /// never carry a separator.
  Utf8(Vec<String>),
  /// A component cannot become UTF-8 (an unpaired surrogate — WTF-16 that has
  /// no Unicode spelling): `prefix` is the decodable ancestor chain above it
  /// (empty = the undecodable component sits directly under the root), and
  /// the lowering escalates to a located rescan THERE — never a lossy
  /// transliteration.
  Escalate {
    /// The decoded components above the first undecodable one.
    prefix: Vec<String>,
  },
}

/// One decoded record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RdcwRecord {
  /// The typed action word.
  pub(crate) action: RdcwAction,
  /// The watch-relative name.
  pub(crate) name: RdcwName,
  /// The 64-bit file reference number (extended records only). Per-record
  /// identity is inert under the kernel-recursive profile — this grounds
  /// rename pairing, never registry identity.
  pub(crate) file_id: Option<u64>,
  /// The 64-bit parent file reference number (extended records only).
  pub(crate) parent_id: Option<u64>,
  /// The `FILE_ATTRIBUTE_*` word (extended records only) — directory
  /// discrimination without a racy stat.
  pub(crate) attributes: Option<u32>,
  /// The reparse tag (extended records only), nonzero when the object is a
  /// reparse point (junction, symlink, …).
  pub(crate) reparse_tag: Option<u32>,
}

impl RdcwRecord {
  /// Whether the extended attributes mark the object as a directory
  /// (`FILE_ATTRIBUTE_DIRECTORY`); `None` on basic records — the record's
  /// directory-ness stays unknown, the FSEvents no-hint default.
  pub(crate) fn is_dir(&self) -> Option<bool> {
    self.attributes.map(|attrs| attrs & 0x10 != 0)
  }
}

/// One decoded completion buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedBuffer {
  /// The records decoded before any refusal, in kernel order.
  pub(crate) records: Vec<RdcwRecord>,
  /// Whether the chain was refused before its end (malformed offset, a
  /// truncated record, an invalid name length): the records already decoded
  /// stand, and the pump signals the refusal as in-order loss at this
  /// position.
  pub(crate) lossy: bool,
}

/// The fixed prefix of a basic `FILE_NOTIFY_INFORMATION` record.
const BASIC_HEADER: usize = 12;
/// The fixed prefix of a `FILE_NOTIFY_EXTENDED_INFORMATION` record.
const EXTENDED_HEADER: usize = 84;

/// Decodes a watch-relative UTF-16LE name into components: separator split at
/// the code-unit level first, then strict per-component decode, so the
/// escalation point of a WTF-16 component keeps its decodable ancestors.
fn decode_name(units: &[u16]) -> RdcwName {
  let mut components = Vec::new();
  for component in units.split(|&unit| unit == u16::from(b'\\')) {
    if component.is_empty() {
      continue;
    }
    match char::decode_utf16(component.iter().copied()).collect::<Result<String, _>>() {
      Ok(decoded) => components.push(decoded),
      Err(_) => {
        return RdcwName::Escalate { prefix: components };
      }
    }
  }
  RdcwName::Utf8(components)
}

#[inline]
fn load_u32(buf: &[u8], at: usize) -> u32 {
  u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

#[inline]
fn load_u64(buf: &[u8], at: usize) -> u64 {
  let mut bytes = [0u8; 8];
  bytes.copy_from_slice(&buf[at..at + 8]);
  u64::from_le_bytes(bytes)
}

/// Decodes one completion buffer's record chain.
///
/// `extended` selects the record layout the read was issued with — the kernel
/// never mixes layouts within one buffer.
pub(crate) fn decode_records(buf: &[u8], extended: bool) -> DecodedBuffer {
  let header = if extended {
    EXTENDED_HEADER
  } else {
    BASIC_HEADER
  };
  let mut records = Vec::new();
  let mut at = 0usize;

  loop {
    // The fixed prefix must fit; a shorter tail is a truncated chain.
    let Some(end_of_header) = at.checked_add(header) else {
      return DecodedBuffer {
        records,
        lossy: true,
      };
    };
    if end_of_header > buf.len() {
      return DecodedBuffer {
        records,
        lossy: true,
      };
    }

    let next_offset = load_u32(buf, at) as usize;
    let action = RdcwAction::from_word(load_u32(buf, at + 4));
    let (file_id, parent_id, attributes, reparse_tag, name_len_at) = if extended {
      (
        Some(load_u64(buf, at + 64)),
        Some(load_u64(buf, at + 72)),
        Some(load_u32(buf, at + 56)),
        Some(load_u32(buf, at + 60)),
        at + 80,
      )
    } else {
      (None, None, None, None, at + 8)
    };

    // The name is FileNameLength BYTES of UTF-16LE: an odd length is a
    // malformed record, and the payload must fit the buffer.
    let name_len = load_u32(buf, name_len_at) as usize;
    let name_at = end_of_header;
    let name_fits = name_len % 2 == 0
      && name_at
        .checked_add(name_len)
        .is_some_and(|end| end <= buf.len());
    if !name_fits {
      return DecodedBuffer {
        records,
        lossy: true,
      };
    }

    let units: Vec<u16> = buf[name_at..name_at + name_len]
      .chunks_exact(2)
      .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
      .collect();
    let name = decode_name(&units);

    records.push(RdcwRecord {
      action,
      name,
      file_id,
      parent_id,
      attributes,
      reparse_tag,
    });

    if next_offset == 0 {
      return DecodedBuffer {
        records,
        lossy: false,
      };
    }
    // A link must be DWORD-aligned and make forward progress past this
    // record's fixed prefix, inside the buffer.
    let aligned = next_offset % 4 == 0;
    let Some(next_at) = at.checked_add(next_offset) else {
      return DecodedBuffer {
        records,
        lossy: true,
      };
    };
    if !aligned || next_offset < header || next_at >= buf.len() {
      return DecodedBuffer {
        records,
        lossy: true,
      };
    }
    at = next_at;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Appends one record to `buf`, returning the offset it was written at.
  /// `next` is the NextEntryOffset to record; the name is given in UTF-16
  /// code units so tests can plant unpaired surrogates.
  fn push_record(buf: &mut Vec<u8>, extended: bool, next: u32, action: u32, name: &[u16]) -> usize {
    let at = buf.len();
    buf.extend_from_slice(&next.to_le_bytes());
    buf.extend_from_slice(&action.to_le_bytes());
    if extended {
      for filler in [1u64, 2, 3, 4, 5, 6] {
        // The six timestamp/size fields, distinct so a misaligned load shows.
        buf.extend_from_slice(&filler.to_le_bytes());
      }
      buf.extend_from_slice(&0x10u32.to_le_bytes()); // FileAttributes: directory
      buf.extend_from_slice(&0u32.to_le_bytes()); // ReparsePointTag
      buf.extend_from_slice(&0xAABBu64.to_le_bytes()); // FileId
      buf.extend_from_slice(&0xCCDDu64.to_le_bytes()); // ParentFileId
    }
    let bytes: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&bytes);
    at
  }

  fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
  }

  #[test]
  fn one_basic_record_decodes() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 1, &utf16("a\\b.txt"));
    let decoded = decode_records(&buf, false);
    assert!(!decoded.lossy);
    assert_eq!(decoded.records.len(), 1);
    let record = &decoded.records[0];
    assert_eq!(record.action, RdcwAction::Added);
    assert_eq!(
      record.name,
      RdcwName::Utf8(vec!["a".into(), "b.txt".into()])
    );
    assert_eq!(record.file_id, None);
    assert_eq!(record.is_dir(), None);
  }

  #[test]
  fn extended_fields_surface() {
    let mut buf = Vec::new();
    push_record(&mut buf, true, 0, 5, &utf16("dir"));
    let decoded = decode_records(&buf, true);
    assert!(!decoded.lossy);
    let record = &decoded.records[0];
    assert_eq!(record.action, RdcwAction::RenamedNew);
    assert_eq!(record.file_id, Some(0xAABB));
    assert_eq!(record.parent_id, Some(0xCCDD));
    assert_eq!(record.is_dir(), Some(true));
    assert_eq!(record.reparse_tag, Some(0));
  }

  #[test]
  fn chains_walk_in_order_with_padding() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 1, &utf16("first"));
    // Retro-link: DWORD-align the second record, then patch the first link.
    while buf.len() % 4 != 0 {
      buf.push(0);
    }
    let second_at = buf.len();
    push_record(&mut buf, false, 0, 2, &utf16("second"));
    buf[0..4].copy_from_slice(&(second_at as u32).to_le_bytes());

    let decoded = decode_records(&buf, false);
    assert!(!decoded.lossy);
    assert_eq!(decoded.records.len(), 2);
    assert_eq!(decoded.records[0].action, RdcwAction::Added);
    assert_eq!(decoded.records[1].action, RdcwAction::Removed);
  }

  #[test]
  fn unknown_actions_are_carried_not_guessed() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 99, &utf16("odd"));
    let decoded = decode_records(&buf, false);
    assert_eq!(decoded.records[0].action, RdcwAction::Unknown(99));
  }

  #[test]
  fn unpaired_surrogate_escalates_the_name() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 3, &[0xD800, u16::from(b'x')]);
    let decoded = decode_records(&buf, false);
    assert!(!decoded.lossy, "a WTF-16 name is a valid record");
    assert_eq!(
      decoded.records[0].name,
      RdcwName::Escalate { prefix: vec![] }
    );
  }

  #[test]
  fn escalation_keeps_the_decodable_ancestors() {
    let mut name = utf16("a\\b\\");
    name.push(0xDC00); // an unpaired low surrogate as the leaf component
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 3, &name);
    let decoded = decode_records(&buf, false);
    assert_eq!(
      decoded.records[0].name,
      RdcwName::Escalate {
        prefix: vec!["a".into(), "b".into()],
      }
    );
  }

  #[test]
  fn truncated_header_refuses_lossy() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 1, &utf16("kept"));
    let kept_len = buf.len();
    while buf.len() % 4 != 0 {
      buf.push(0);
    }
    let second_at = buf.len();
    buf[0..4].copy_from_slice(&(second_at as u32).to_le_bytes());
    buf.extend_from_slice(&[0u8; 6]); // half a header

    let decoded = decode_records(&buf, false);
    assert!(decoded.lossy);
    assert_eq!(decoded.records.len(), 1, "the intact prefix stands");
    assert!(kept_len > 0);
  }

  #[test]
  fn name_overrun_refuses_lossy() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 1, &utf16("x"));
    // Claim a name longer than the buffer holds.
    buf[8..12].copy_from_slice(&1024u32.to_le_bytes());
    let decoded = decode_records(&buf, false);
    assert!(decoded.lossy);
    assert!(decoded.records.is_empty());
  }

  #[test]
  fn odd_name_length_refuses_lossy() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 1, &utf16("x"));
    buf[8..12].copy_from_slice(&1u32.to_le_bytes());
    buf.push(0); // keep the claimed byte in-bounds so parity alone refuses
    let decoded = decode_records(&buf, false);
    assert!(decoded.lossy);
  }

  #[test]
  fn misaligned_or_backward_links_refuse_lossy() {
    for bad_next in [2u32, 6, 10] {
      let mut buf = Vec::new();
      push_record(&mut buf, false, bad_next, 1, &utf16("x"));
      buf.extend_from_slice(&[0u8; 64]);
      let decoded = decode_records(&buf, false);
      assert!(decoded.lossy, "next={bad_next} must refuse");
      assert_eq!(decoded.records.len(), 1);
    }
  }

  #[test]
  fn empty_buffer_is_a_truncated_chain() {
    let decoded = decode_records(&[], false);
    assert!(decoded.lossy);
    assert!(decoded.records.is_empty());
  }

  #[test]
  fn separators_split_and_empty_components_drop() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 1, &utf16("a\\\\b"));
    let decoded = decode_records(&buf, false);
    assert_eq!(
      decoded.records[0].name,
      RdcwName::Utf8(vec!["a".into(), "b".into()])
    );
  }
}
