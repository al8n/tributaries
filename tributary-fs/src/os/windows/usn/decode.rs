//! The pure USN change-journal buffer decode.
//!
//! One `FSCTL_READ_USN_JOURNAL` output is a leading next-USN cursor (`i64`)
//! followed by a chain of `USN_RECORD_V2`/`V3` records, each
//! `RecordLength`-strided. The chain is kernel-produced but decoded
//! defensively: every stride and name window is validated, every multi-byte
//! field is an explicit little-endian load from `&[u8]`, and a malformed
//! record refuses the REMAINDER as decode loss — never UB, never a panic —
//! so the whole module runs under miri on every host.
//!
//! `V2` (NTFS) carries 64-bit reference numbers, zero-extended here; `V3`
//! (ReFS) carries `FILE_ID_128`. `V4` range-tracking records exist only when
//! explicitly enabled, which this backend never does; one arriving anyway is
//! a protocol surprise — skipped by its own stride and marked lossy.

/// A record's single name component (the object's name in its parent),
/// decoded from UTF-16LE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsnName {
  /// The name in strict UTF-8.
  Utf8(String),
  /// The name has no Unicode spelling (an unpaired surrogate): the lowering
  /// escalates to a located rescan of the PARENT, never a transliteration.
  Escalate,
}

/// One decoded journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UsnRecord {
  /// The subject's file reference number (64-bit zero-extended on V2).
  pub(crate) frn: u128,
  /// The subject's PARENT directory reference number.
  pub(crate) parent: u128,
  /// This record's journal offset (the cursor that follows it is the next).
  pub(crate) usn: i64,
  /// The cumulative `USN_REASON_*` mask as of this record.
  pub(crate) reason: u32,
  /// The `USN_SOURCE_*` provenance mask.
  pub(crate) source_info: u32,
  /// The subject's `FILE_ATTRIBUTE_*` word.
  pub(crate) attributes: u32,
  /// The subject's name in its parent.
  pub(crate) name: UsnName,
}

impl UsnRecord {
  /// Whether the attributes mark the subject a directory.
  pub(crate) fn is_dir(&self) -> bool {
    self.attributes & 0x10 != 0
  }
}

/// One decoded read buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedJournal {
  /// The next-read cursor the kernel prefixed the chain with.
  pub(crate) next_usn: i64,
  /// The records decoded before any refusal, in journal order.
  pub(crate) records: Vec<UsnRecord>,
  /// Whether the chain was refused (or a record skipped) before its end:
  /// the records already decoded stand, and the source takes the ordered
  /// loss barrier BEFORE advancing past the refusal.
  pub(crate) lossy: bool,
}

/// The fixed prefix of a `USN_RECORD_V2`.
const V2_HEADER: usize = 60;
/// The fixed prefix of a `USN_RECORD_V3`.
const V3_HEADER: usize = 76;

#[inline]
fn load_u16(buf: &[u8], at: usize) -> u16 {
  u16::from_le_bytes([buf[at], buf[at + 1]])
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

#[inline]
fn load_u128(buf: &[u8], at: usize) -> u128 {
  let mut bytes = [0u8; 16];
  bytes.copy_from_slice(&buf[at..at + 16]);
  u128::from_le_bytes(bytes)
}

/// Decodes one name window as a single component (USN names carry no
/// separators — location comes from the parent chain, not the record).
fn decode_name(units: &[u16]) -> UsnName {
  match char::decode_utf16(units.iter().copied()).collect::<Result<String, _>>() {
    Ok(name) => UsnName::Utf8(name),
    Err(_) => UsnName::Escalate,
  }
}

/// Decodes one `FSCTL_READ_USN_JOURNAL` output buffer.
pub(crate) fn decode_journal(buf: &[u8]) -> DecodedJournal {
  // The leading cursor: a buffer too short even for it is wholly refused
  // (cursor 0 tells the source to re-anchor via a fresh query).
  if buf.len() < 8 {
    return DecodedJournal {
      next_usn: 0,
      records: Vec::new(),
      lossy: true,
    };
  }
  let next_usn = load_u64(buf, 0) as i64;
  let mut records = Vec::new();
  let mut lossy = false;
  let mut at = 8usize;

  while at < buf.len() {
    // The stride and version live in the first 8 bytes of every record
    // layout; a tail too short for them is a truncated chain.
    if at + 8 > buf.len() {
      lossy = true;
      break;
    }
    let record_length = load_u32(buf, at) as usize;
    let major = load_u16(buf, at + 4);
    // A stride must be 8-aligned, cover its own header, and stay in-bounds:
    // anything else poisons the walk (there is no other way to find the
    // next record), so the remainder is refused.
    let Some(record_end) = at.checked_add(record_length) else {
      lossy = true;
      break;
    };
    if record_length == 0 || !record_length.is_multiple_of(8) || record_end > buf.len() {
      lossy = true;
      break;
    }

    let (header, wide_ids) = match major {
      2 => (V2_HEADER, false),
      3 => (V3_HEADER, true),
      // A version outside the read ceiling: the stride is still valid, so
      // skip the record and mark the gap.
      _ => {
        lossy = true;
        at = record_end;
        continue;
      }
    };
    if record_length < header {
      lossy = true;
      break;
    }

    let (frn, parent, tail) = if wide_ids {
      (load_u128(buf, at + 8), load_u128(buf, at + 24), at + 40)
    } else {
      (
        u128::from(load_u64(buf, at + 8)),
        u128::from(load_u64(buf, at + 16)),
        at + 24,
      )
    };
    let usn = load_u64(buf, tail) as i64;
    let reason = load_u32(buf, tail + 16);
    let source_info = load_u32(buf, tail + 20);
    let attributes = load_u32(buf, tail + 28);
    let name_len = load_u16(buf, tail + 32) as usize;
    let name_off = load_u16(buf, tail + 34) as usize;

    // The name window must sit inside ITS record and split into u16 units.
    let name_fits = name_len.is_multiple_of(2)
      && name_off >= header
      && at
        .checked_add(name_off)
        .and_then(|start| start.checked_add(name_len))
        .is_some_and(|end| end <= record_end);
    if !name_fits {
      lossy = true;
      break;
    }
    let name_at = at + name_off;
    let units: Vec<u16> = buf[name_at..name_at + name_len]
      .as_chunks::<2>()
      .0
      .iter()
      .map(|pair| u16::from_le_bytes(*pair))
      .collect();

    records.push(UsnRecord {
      frn,
      parent,
      usn,
      reason,
      source_info,
      attributes,
      name: decode_name(&units),
    });
    at = record_end;
  }

  DecodedJournal {
    next_usn,
    records,
    lossy,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn push_v2(buf: &mut Vec<u8>, frn: u64, parent: u64, usn: i64, reason: u32, name: &[u16]) {
    let name_bytes: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    let unpadded = V2_HEADER + name_bytes.len();
    let record_length = unpadded.next_multiple_of(8);
    buf.extend_from_slice(&(record_length as u32).to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes()); // MajorVersion
    buf.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    buf.extend_from_slice(&frn.to_le_bytes());
    buf.extend_from_slice(&parent.to_le_bytes());
    buf.extend_from_slice(&usn.to_le_bytes());
    buf.extend_from_slice(&7i64.to_le_bytes()); // TimeStamp
    buf.extend_from_slice(&reason.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // SourceInfo
    buf.extend_from_slice(&0u32.to_le_bytes()); // SecurityId
    buf.extend_from_slice(&0x20u32.to_le_bytes()); // FileAttributes: archive
    buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(V2_HEADER as u16).to_le_bytes());
    buf.extend_from_slice(&name_bytes);
    buf.resize(buf.len().next_multiple_of(8), 0);
  }

  fn push_v3(buf: &mut Vec<u8>, frn: u128, parent: u128, name: &[u16]) {
    let name_bytes: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    let unpadded = V3_HEADER + name_bytes.len();
    let record_length = unpadded.next_multiple_of(8);
    buf.extend_from_slice(&(record_length as u32).to_le_bytes());
    buf.extend_from_slice(&3u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&frn.to_le_bytes());
    buf.extend_from_slice(&parent.to_le_bytes());
    buf.extend_from_slice(&11i64.to_le_bytes()); // Usn
    buf.extend_from_slice(&7i64.to_le_bytes()); // TimeStamp
    buf.extend_from_slice(&0x100u32.to_le_bytes()); // Reason: FILE_CREATE
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0x10u32.to_le_bytes()); // directory
    buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(V3_HEADER as u16).to_le_bytes());
    buf.extend_from_slice(&name_bytes);
    buf.resize(buf.len().next_multiple_of(8), 0);
  }

  fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
  }

  #[test]
  fn v2_records_decode_with_cursor() {
    let mut buf = 42i64.to_le_bytes().to_vec();
    push_v2(&mut buf, 7, 3, 40, 0x100, &utf16("made.txt"));
    push_v2(&mut buf, 8, 3, 41, 0x200, &utf16("gone.txt"));
    let decoded = decode_journal(&buf);
    assert!(!decoded.lossy);
    assert_eq!(decoded.next_usn, 42);
    assert_eq!(decoded.records.len(), 2);
    assert_eq!(decoded.records[0].frn, 7);
    assert_eq!(decoded.records[0].parent, 3);
    assert_eq!(decoded.records[0].usn, 40);
    assert_eq!(decoded.records[0].reason, 0x100);
    assert!(!decoded.records[0].is_dir());
    assert_eq!(decoded.records[0].name, UsnName::Utf8("made.txt".into()));
    assert_eq!(decoded.records[1].reason, 0x200);
  }

  #[test]
  fn v3_wide_ids_decode() {
    let mut buf = 5i64.to_le_bytes().to_vec();
    let frn = (9u128 << 64) | 7;
    push_v3(&mut buf, frn, 3, &utf16("dir"));
    let decoded = decode_journal(&buf);
    assert!(!decoded.lossy);
    let record = &decoded.records[0];
    assert_eq!(record.frn, frn);
    assert_eq!(record.parent, 3);
    assert!(record.is_dir());
  }

  #[test]
  fn an_unknown_version_is_skipped_lossy() {
    let mut buf = 5i64.to_le_bytes().to_vec();
    push_v2(&mut buf, 7, 3, 1, 0x100, &utf16("kept")); // will be rewritten to v4
    let v4_at = 8;
    buf[v4_at + 4..v4_at + 6].copy_from_slice(&4u16.to_le_bytes());
    push_v2(&mut buf, 8, 3, 2, 0x200, &utf16("after"));
    let decoded = decode_journal(&buf);
    assert!(decoded.lossy, "the surprise version marks the gap");
    assert_eq!(decoded.records.len(), 1, "the chain continues past it");
    assert_eq!(decoded.records[0].frn, 8);
  }

  #[test]
  fn a_short_cursor_refuses_whole() {
    let decoded = decode_journal(&[0u8; 4]);
    assert!(decoded.lossy);
    assert!(decoded.records.is_empty());
    assert_eq!(decoded.next_usn, 0);
  }

  #[test]
  fn a_bad_stride_refuses_the_remainder() {
    let mut buf = 5i64.to_le_bytes().to_vec();
    push_v2(&mut buf, 7, 3, 1, 0x100, &utf16("ok"));
    let second_at = buf.len();
    push_v2(&mut buf, 8, 3, 2, 0x200, &utf16("bad"));
    // Corrupt the second record's stride: unaligned.
    buf[second_at..second_at + 4].copy_from_slice(&61u32.to_le_bytes());
    let decoded = decode_journal(&buf);
    assert!(decoded.lossy);
    assert_eq!(decoded.records.len(), 1);
  }

  #[test]
  fn a_name_overrunning_its_record_refuses() {
    let mut buf = 5i64.to_le_bytes().to_vec();
    push_v2(&mut buf, 7, 3, 1, 0x100, &utf16("x"));
    // Claim a name longer than the record holds.
    buf[8 + 56..8 + 58].copy_from_slice(&512u16.to_le_bytes());
    let decoded = decode_journal(&buf);
    assert!(decoded.lossy);
    assert!(decoded.records.is_empty());
  }

  #[test]
  fn an_unpaired_surrogate_escalates() {
    let mut buf = 5i64.to_le_bytes().to_vec();
    push_v2(&mut buf, 7, 3, 1, 0x100, &[0xD800]);
    let decoded = decode_journal(&buf);
    assert!(!decoded.lossy, "a WTF-16 name is a valid record");
    assert_eq!(decoded.records[0].name, UsnName::Escalate);
  }

  #[test]
  fn an_empty_chain_is_just_the_cursor() {
    let buf = 99i64.to_le_bytes().to_vec();
    let decoded = decode_journal(&buf);
    assert!(!decoded.lossy);
    assert!(decoded.records.is_empty());
    assert_eq!(decoded.next_usn, 99);
  }
}
