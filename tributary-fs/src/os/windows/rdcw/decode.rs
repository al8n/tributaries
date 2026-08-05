//! The pure `ReadDirectoryChangesW` completion-buffer decode.
//!
//! One completion delivers a chain of `FILE_NOTIFY_INFORMATION` (basic) or
//! `FILE_NOTIFY_EXTENDED_INFORMATION` (extended) records linked by
//! `NextEntryOffset`. The chain is kernel-produced but decoded defensively:
//! every offset is validated BEFORE the record it strides is read — in-bounds,
//! DWORD-aligned, and landing on the record's own 4-byte-rounded end — so a
//! `FileNameLength` can never reach past its own record into the next one's
//! header, and no link can vault over a record the walk would then never
//! visit. Every multi-byte field is an explicit little-endian load from
//! `&[u8]`, so a malformed or truncated chain refuses the REMAINDER as decode
//! loss — never UB, never a panic — and the whole module runs under miri on
//! every host.
//!
//! Refusing is the SAFE direction here only because the refusal is signalled:
//! `lower_rdcw_buffer` turns it into in-order loss and the pump into a rescan.
//! Accepting a chain that skipped records is the unsafe direction, because
//! nothing downstream can tell that it did.

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
  /// `FILE_ACTION_ADDED_STREAM` — a named stream (an NTFS alternate data
  /// stream) was created on the object the name's owner half denotes.
  StreamAdded,
  /// `FILE_ACTION_REMOVED_STREAM` — a named stream was deleted.
  StreamRemoved,
  /// `FILE_ACTION_MODIFIED_STREAM` — a named stream was written or resized.
  StreamModified,
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
      6 => Self::StreamAdded,
      7 => Self::StreamRemoved,
      8 => Self::StreamModified,
      // 9..=11 (`REMOVED_BY_DELETE`, `ID_NOT_TUNNELLED`,
      // `TUNNELLED_ID_COLLISION`) are reported only for subscriptions this
      // backend never issues, and two of them carry an id rather than a name
      // in the name field. Decoding them by their MS-FSCC meaning would be
      // guessing at a payload shape no read here can produce; the located
      // rescan stays the honest cover.
      other => Self::Unknown(other),
    }
  }

  /// Whether the action describes a NAMED STREAM of its subject rather than
  /// the subject itself — the records whose name carries an `owner:stream`
  /// suffix the decoder folds away.
  pub(crate) const fn is_stream(self) -> bool {
    matches!(
      self,
      Self::StreamAdded | Self::StreamRemoved | Self::StreamModified
    )
  }
}

/// A record's watch-relative name, decoded from UTF-16LE.
///
/// Components are split on the `\` separators FIRST, at the code-unit level
/// (`0x005C` can never be part of a surrogate pair), then decoded one by one —
/// so an undecodable component still leaves every ancestor above it named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RdcwName {
  /// Every component decoded to strict UTF-8 AND spelled a name a consumer's
  /// own enumeration would produce. Components are never empty and never
  /// carry a separator or a stream suffix.
  Utf8(Vec<String>),
  /// A component cannot be published as authoritative: `prefix` is the usable
  /// ancestor chain above it (empty = the refused component sits directly
  /// under the root), and the lowering escalates to a located rescan THERE.
  ///
  /// Two independent causes reach this, and both are "the decoder does not
  /// possess the name the consumer indexes by":
  ///
  /// * the component has no Unicode spelling (an unpaired surrogate — WTF-16),
  ///   so no `Segment` can carry it and a lossy transliteration would name a
  ///   different object;
  /// * the component is a generated 8.3 SHORT-NAME ALIAS
  ///   ([`is_short_name_alias`]). Both notify layouts are documented to return
  ///   either spelling when an object has both, and which one arrives is
  ///   unspecified — it follows the spelling the mutating process happened to
  ///   open by. Publishing `LONGFI~1.TXT` as the event's stable location
  ///   silently diverges from the `Long File Name.txt` a crawl indexed, and no
  ///   later event repairs it. Expansion is not available to a PURE decode
  ///   (and is impossible in principle for a removal or a rename's departing
  ///   half, whose name no longer resolves), so the alias escalates to a
  ///   rescan at its parent instead: the consumer re-enumerates and learns the
  ///   canonical name from the filesystem, which is the only authority for it.
  Escalate {
    /// The usable components above the first refused one.
    prefix: Vec<String>,
  },
}

/// Whether `component` may be an NTFS-GENERATED 8.3 short-name alias — a
/// spelling that denotes an object whose canonical name is something else.
///
/// A generated alias always carries a `~` followed by the disambiguating
/// decimal run (`LONGFI~1.TXT`, `PROGRA~2`, `A1B2C3~1.DLL`), fits 8.3, and is
/// upper-cased, so the test is: at most one `.`, a base of 1..=8 and an
/// extension of at most 3 characters, no lowercase ASCII letter anywhere, and
/// a base whose final `~` is neither first nor last and is followed only by
/// ASCII digits.
///
/// It is deliberately a SYNTACTIC over-approximation. A file a user really
/// named `PROGRA~1` matches and earns a parent rescan it did not need, which
/// costs one re-enumeration; the reverse error — accepting an alias as the
/// canonical location — is a permanent divergence between the consumer's index
/// and the tree, with no event that ever repairs it. Names an object shares
/// with its own short form (`README.TXT` is its own alias) carry no `~` and so
/// never match: there is nothing to diverge from.
pub(crate) fn is_short_name_alias(component: &str) -> bool {
  if component.chars().any(|c| c.is_ascii_lowercase()) {
    return false;
  }
  let mut halves = component.split('.');
  let (Some(base), extension) = (halves.next(), halves.next()) else {
    return false;
  };
  // A third `.` puts the name outside 8.3 entirely.
  if halves.next().is_some() {
    return false;
  }
  if !(1..=8).contains(&base.chars().count()) {
    return false;
  }
  if extension.is_some_and(|ext| ext.chars().count() > 3) {
    return false;
  }
  let Some((head, tail)) = base.rsplit_once('~') else {
    return false;
  };
  !head.is_empty() && !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit())
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
/// escalation point of a refused component keeps its usable ancestors.
///
/// `stream` marks the named-stream actions, whose name is spelled
/// `owner\path:stream:$DATA`. The suffix is cut at the code-unit level (`:` is
/// `0x003A`, never half of a surrogate pair) BEFORE decoding, so the fold
/// works on a name whose stream part is undecodable, and so a `:` can never
/// enter a `Segment` — the proto path vocabulary has no spelling for one.
/// Cutting the suffix leaves the OWNER, which is the object whose bytes
/// changed and the only one a consumer holds; the stream itself is not a
/// dirent and has no location of its own.
///
/// An owner half that cuts away to nothing (`:stream:$DATA` — a stream on the
/// watched directory itself) yields the empty component list, which the
/// lowering reads as the root and covers there.
fn decode_name(units: &[u16], stream: bool) -> RdcwName {
  const SEPARATOR: u16 = b'\\' as u16;
  const COLON: u16 = b':' as u16;

  let raw: Vec<&[u16]> = units
    .split(|&unit| unit == SEPARATOR)
    .filter(|component| !component.is_empty())
    .collect();
  let last = raw.len().wrapping_sub(1);
  let mut components = Vec::with_capacity(raw.len());
  for (index, component) in raw.into_iter().enumerate() {
    let component = match (stream && index == last)
      .then(|| component.iter().position(|&unit| unit == COLON))
      .flatten()
    {
      Some(at) => &component[..at],
      None => component,
    };
    if component.is_empty() {
      continue;
    }
    let Ok(decoded) = char::decode_utf16(component.iter().copied()).collect::<Result<String, _>>()
    else {
      return RdcwName::Escalate { prefix: components };
    };
    // A spelling the kernel is free to substitute is not a location: it names
    // the object for an opener, not for an index.
    if is_short_name_alias(&decoded) {
      return RdcwName::Escalate { prefix: components };
    }
    components.push(decoded);
  }
  RdcwName::Utf8(components)
}

/// The whole extent of a record whose fixed prefix is `header` bytes and whose
/// name is `name_len` bytes.
///
/// MS-FSCC 2.7.1: "The **FileName** array MUST be padded to the next 4-byte
/// boundary counted from the beginning of the structure." The record therefore
/// runs to that boundary — its name plus the padding that squares it off — and
/// nothing narrower or wider is the record.
///
/// Fallible in both steps: `name_len` is a kernel `u32`, so at 32-bit pointer
/// width either the sum or the rounding can leave `usize`, and an
/// unrepresentable extent must be a refusal rather than a debug-build panic.
#[inline]
fn padded_extent(header: usize, name_len: usize) -> Option<usize> {
  header.checked_add(name_len)?.checked_next_multiple_of(4)
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

    // `FileNameLength` sits INSIDE the fixed prefix already proven present, so
    // it can be read here — ahead of the link whose validation it grounds.
    let name_len = load_u32(buf, name_len_at) as usize;

    // The link is validated BEFORE anything is decoded off the record, because
    // the link is the record's own extent: a record whose stride is
    // untrustworthy has no trustworthy extent either, and bounding its name by
    // the whole buffer instead would let the name consume the NEXT record's
    // header and publish that as a real location.
    //
    // Alignment, forward progress and in-boundsness are NOT enough. A link may
    // satisfy all three and still be larger than the record it strides — and
    // the buffer it jumps over is not slack, it is where the records the walk
    // then never visits are sitting. Nothing downstream can notice: the decode
    // returns cleanly, the pump signals no loss because the chain never
    // refused, and the consumer diverges permanently on changes it was never
    // told it missed. Losing coverage without a covering signal is the one
    // failure this whole seam exists to prevent, so the stride is held to the
    // record's own padded end.
    let Some(padded_end) = padded_extent(header, name_len) else {
      return DecodedBuffer {
        records,
        lossy: true,
      };
    };
    let next_at = if next_offset == 0 {
      // A zero link ends the chain, and the terminal record's extent is the
      // rest of the completion — the pump hands the decode exactly the
      // transferred bytes, so there is nothing narrower to know. What may
      // TRAIL it is its own padding and nothing else: a run long enough to BE
      // a record is an end marker the buffer itself contradicts, and walking
      // away from it would strand every record behind it under a clean decode.
      // The allowance is deliberately the padding and not an exact end — a
      // completion may be reported at the terminal record's unpadded length or
      // at its padded one, and both are well-formed.
      let stranded = at
        .checked_add(padded_end)
        .map_or(0, |end_of_record| buf.len().saturating_sub(end_of_record));
      if stranded >= header {
        return DecodedBuffer {
          records,
          lossy: true,
        };
      }
      None
    } else {
      let Some(next_at) = at.checked_add(next_offset) else {
        return DecodedBuffer {
          records,
          lossy: true,
        };
      };
      // MS-FSCC 2.7.1 fixes the BASIC stride exactly — `NextEntryOffset` is
      // "the offset, in bytes, from the beginning of this structure to the
      // subsequent FILE_NOTIFY_INFORMATION structure", the padding rule above
      // fixes where this structure ends, and MS-SMB2 2.2.36 calls the buffer
      // "an array of FILE_NOTIFY_INFORMATION structures" — so the next record
      // begins on this one's padded end and nowhere else.
      //
      // The EXTENDED layout has NO MS-FSCC section; `winnt.h` documents only
      // "the number of bytes that must be skipped to get to the next record",
      // and the structure's own alignment is 8 (six `LARGE_INTEGER` fields
      // over an 84-byte prefix, itself not a multiple of 8), so a producer
      // that rounds its entries to 8 rather than 4 is inside its documentation.
      // Demanding the 4-rounded end there would refuse HALF of every real
      // extended completion — and extended is the layout this backend issues
      // first — trading silent loss for a permanent rescan storm. So the
      // extended stride is held to the property the loss barrier actually
      // needs, WITHOUT guessing a padding granularity: whatever gap it leaves
      // must be too small to have been a record the walk skipped, and no
      // record is shorter than its own fixed prefix.
      let gap = next_offset.checked_sub(padded_end);
      let strides_to_the_next_record = if extended {
        gap.is_some_and(|gap| gap < header)
      } else {
        gap == Some(0)
      };
      // A stride at or past the end leaves no room for the record it promises.
      if !next_offset.is_multiple_of(4) || !strides_to_the_next_record || next_at >= buf.len() {
        return DecodedBuffer {
          records,
          lossy: true,
        };
      }
      Some(next_at)
    };
    let extent = next_at.unwrap_or(buf.len());

    // The name is FileNameLength BYTES of UTF-16LE: an odd length is a
    // malformed record, and the payload must fit inside THIS record's extent.
    //
    // For a NONTERMINAL record the extent test is now implied — the stride
    // bound above already proved `next_offset >= header + name_len` — so what
    // it still catches on its own is the parity and the TERMINAL record, whose
    // extent is the completion itself. It is kept whole rather than narrowed
    // to those two: it is the guard that holds if the stride rule is ever
    // loosened, and the pair is cheap.
    let name_at = end_of_header;
    let name_fits = name_len.is_multiple_of(2)
      && name_at
        .checked_add(name_len)
        .is_some_and(|end| end <= extent);
    if !name_fits {
      return DecodedBuffer {
        records,
        lossy: true,
      };
    }

    let units: Vec<u16> = buf[name_at..name_at + name_len]
      .as_chunks::<2>()
      .0
      .iter()
      .map(|pair| u16::from_le_bytes(*pair))
      .collect();
    let name = decode_name(&units, action.is_stream());

    records.push(RdcwRecord {
      action,
      name,
      file_id,
      parent_id,
      attributes,
      reparse_tag,
    });

    let Some(next_at) = next_at else {
      return DecodedBuffer {
        records,
        lossy: false,
      };
    };
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

  /// Pads `buf` out to the next 4-byte boundary — the round-up MS-FSCC 2.7.1
  /// requires after every record's name, and so the point the next record of a
  /// well-formed chain begins on.
  fn pad4(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
      buf.push(0);
    }
  }

  /// Overwrites the `NextEntryOffset` of the record at `at` with `next` — a
  /// stride RELATIVE to that record's own start, which is what the field is.
  fn link(buf: &mut [u8], at: usize, next: usize) {
    buf[at..at + 4].copy_from_slice(&(next as u32).to_le_bytes());
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

  /// MUTATION WITNESS: move the link validation back below the push and this
  /// FAILS at `next=2 publishes nothing`.
  #[test]
  fn misaligned_or_backward_links_refuse_lossy() {
    for bad_next in [2u32, 6, 10] {
      let mut buf = Vec::new();
      push_record(&mut buf, false, bad_next, 1, &utf16("x"));
      buf.extend_from_slice(&[0u8; 64]);
      let decoded = decode_records(&buf, false);
      assert!(decoded.lossy, "next={bad_next} must refuse");
      // The link is this record's own extent, so a bad one is refused BEFORE
      // the record is decoded: nothing bounds its name once the stride is
      // untrustworthy, and the loss signal covers the whole refusal anyway.
      assert!(
        decoded.records.is_empty(),
        "next={bad_next} publishes nothing"
      );
    }
  }

  /// The name of a NONTERMINAL record lives inside that record's own stride.
  /// A `FileNameLength` reaching past `NextEntryOffset` walks into the next
  /// record's header, and bounding it by the whole completion instead would
  /// publish those header bytes as a real location under a clean (non-lossy)
  /// decode — a name no enumeration would ever produce, delivered as authority.
  ///
  /// MUTATION WITNESS, restated: bounding the name by `buf.len()` alone no
  /// longer reaches this. An over-long `FileNameLength` inflates the record's
  /// PADDED END, so the stride bound refuses the shape before the name is ever
  /// measured, and the name bound is reached only once that lower bound is
  /// gone too. Both must go: bound the name by `buf.len()` AND accept a link
  /// shorter than the padded end, and both legs FAIL at `must refuse` — the
  /// decode returns `lossy: false` with two records, the first named out of
  /// the second's header bytes. The two guards are deliberately redundant;
  /// this cell pins the outcome they jointly hold.
  #[test]
  fn a_name_may_not_reach_past_its_own_stride() {
    for extended in [false, true] {
      let header = if extended {
        EXTENDED_HEADER
      } else {
        BASIC_HEADER
      };
      let name_len_at = header - 4;
      let mut buf = Vec::new();
      push_record(&mut buf, extended, 0, 1, &utf16("one"));
      while buf.len() % 4 != 0 {
        buf.push(0);
      }
      let second_at = buf.len();
      push_record(&mut buf, extended, 0, 2, &utf16("two"));
      buf[0..4].copy_from_slice(&(second_at as u32).to_le_bytes());
      // A name that overruns the stride by 16 bytes: still inside the
      // completion, so only the stride bound can refuse it.
      let overrun = (second_at - header + 16) as u32;
      buf[name_len_at..name_len_at + 4].copy_from_slice(&overrun.to_le_bytes());

      let decoded = decode_records(&buf, extended);
      assert!(decoded.lossy, "extended={extended} must refuse");
      assert!(
        decoded.records.is_empty(),
        "extended={extended}: an over-long name is never published"
      );
    }
  }

  /// A zero `NextEntryOffset` is the chain's end marker — but an end marker is
  /// a CLAIM, and a completion still holding a whole record behind it
  /// contradicts the claim.
  ///
  /// CORRECTION. This cell previously asserted the opposite: that bytes shaped
  /// like a record behind a zero link are "trailing slack — never a record",
  /// and that the decode is therefore clean. That was wrong, and it wrote the
  /// defect into the suite as a contract. The pump hands the decode exactly
  /// `bytes_transferred`, so the kernel does not report bytes holding nothing;
  /// a whole record's worth of them behind an end marker is a malformed chain.
  /// Reading them as slack dropped every record behind the marker and still
  /// returned `lossy: false`, so the pump emitted no `Overflow` and the
  /// consumer diverged permanently on changes nothing ever told it it missed —
  /// coverage ending with no covering signal, which is the one failure this
  /// seam exists to prevent. What a terminal record may legitimately carry
  /// behind it is padding, which [`a_zero_links_own_padding_is_not_a_record`]
  /// pins from the other side; the two cells bracket the allowance.
  ///
  /// MUTATION WITNESS: drop the `stranded >= header` refusal and both legs
  /// FAIL at `a record behind the end marker is loss`.
  #[test]
  fn a_zero_link_may_not_strand_a_record_behind_it() {
    for extended in [false, true] {
      let mut buf = Vec::new();
      push_record(&mut buf, extended, 0, 1, &utf16("only"));
      pad4(&mut buf);
      push_record(&mut buf, extended, 0, 2, &utf16("stranded"));

      let decoded = decode_records(&buf, extended);
      assert!(
        decoded.lossy,
        "extended={extended}: a record behind the end marker is loss"
      );
      // The marker IS this record's extent — a terminal record's name is
      // bounded by the rest of the completion and nothing else — so a marker
      // the buffer contradicts is refused before the record it bounds, exactly
      // as a nonterminal record's bad stride is.
      assert!(
        decoded.records.is_empty(),
        "extended={extended}: a contradicted extent publishes nothing"
      );

      // Records AHEAD of the contradicted marker still stand: only the record
      // whose own extent is in dispute is withheld.
      let mut buf = Vec::new();
      let first = push_record(&mut buf, extended, 0, 1, &utf16("kept"));
      pad4(&mut buf);
      let second = buf.len();
      push_record(&mut buf, extended, 0, 2, &utf16("terminal"));
      pad4(&mut buf);
      push_record(&mut buf, extended, 0, 3, &utf16("stranded"));
      link(&mut buf, first, second - first);

      let decoded = decode_records(&buf, extended);
      assert!(decoded.lossy, "extended={extended} must refuse");
      assert_eq!(
        decoded.records.len(),
        1,
        "extended={extended}: the intact prefix stands"
      );
      assert_eq!(decoded.records[0].name, RdcwName::Utf8(vec!["kept".into()]));
    }
  }

  /// The over-tightening guard, and the other half of that bracket. A terminal
  /// record's own padding is not a stranded record, and neither is a
  /// completion reported at the record's UNPADDED length — MS-FSCC 2.7.1 pads
  /// `FileName` to the next 4-byte boundary, but the completion's transferred
  /// count is the kernel's to report and both spellings are well-formed. The
  /// allowance is therefore a ceiling and not an exact end: anything too small
  /// to have BEEN a record is slack.
  ///
  /// If this refusal were ever tightened into an exact end, every real
  /// completion whose reported length disagreed by a byte would go lossy and
  /// the backend would rescan forever. This cell is what fails first.
  ///
  /// MUTATION WITNESS: replace `stranded >= header` with `stranded != 0` and
  /// both legs FAIL at `3 trailing bytes are slack, not loss` — the first
  /// count past the padded end, which an exact end would have refused.
  #[test]
  fn a_zero_links_own_padding_is_not_a_record() {
    for extended in [false, true] {
      let header = if extended {
        EXTENDED_HEADER
      } else {
        BASIC_HEADER
      };
      // "odd" is three UTF-16 units, so the record's unpadded end is two bytes
      // short of the 4-byte boundary and the padding is real.
      let body = header + 6;
      let padded = body.next_multiple_of(4);
      assert_eq!(padded - body, 2, "extended={extended}: the padding is real");

      // Every trailing count too small to have been a record is slack. This
      // spans the unpadded end (0), the padded end, and every byte between the
      // padding and a whole record's worth of bytes.
      for trailing in 0..(padded - body + header) {
        let mut buf = Vec::new();
        push_record(&mut buf, extended, 0, 3, &utf16("odd"));
        buf.resize(body + trailing, 0);

        let decoded = decode_records(&buf, extended);
        assert!(
          !decoded.lossy,
          "extended={extended}: {trailing} trailing bytes are slack, not loss"
        );
        assert_eq!(decoded.records.len(), 1);
        assert_eq!(decoded.records[0].name, RdcwName::Utf8(vec!["odd".into()]));
      }

      // One byte more and a whole record could be sitting there unvisited.
      let mut buf = Vec::new();
      push_record(&mut buf, extended, 0, 3, &utf16("odd"));
      buf.resize(body + (padded - body + header), 0);
      let decoded = decode_records(&buf, extended);
      assert!(
        decoded.lossy,
        "extended={extended}: a whole record's worth of trailing bytes is loss"
      );
    }
  }

  /// A link that does not clear the record's own fixed prefix cannot be a
  /// stride (the next header would overlap this one's), so the record is
  /// refused before it is decoded rather than published and then disowned.
  ///
  /// MUTATION WITNESS: move the link validation back below the push and this
  /// FAILS on `records.is_empty()` — the record is published first and the
  /// chain disowned only afterwards.
  #[test]
  fn a_link_inside_the_fixed_header_refuses_before_the_record() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 8, 1, &utf16("x"));
    buf.extend_from_slice(&[0u8; 64]);
    let decoded = decode_records(&buf, false);
    assert!(decoded.lossy);
    assert!(decoded.records.is_empty());
  }

  /// A link past the completion is the shape that made the whole-buffer name
  /// bound worst: the record claims an extent nothing in the buffer can
  /// contradict. It is refused before the name is read.
  ///
  /// MUTATION WITNESS: move the link validation back below the push and this
  /// FAILS on `records.is_empty()`.
  #[test]
  fn a_link_past_the_buffer_refuses_before_the_record() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 4096, 1, &utf16("x"));
    let decoded = decode_records(&buf, false);
    assert!(decoded.lossy);
    assert!(decoded.records.is_empty());
  }

  /// The defect this bound exists for. A link can be DWORD-aligned, clear the
  /// fixed prefix and land well inside the completion — passing every test the
  /// stride used to face — and STILL be larger than the record it strides. The
  /// bytes it overshoots are not slack: they are where the records the walk
  /// then never visits are sitting. Nothing downstream could notice, because
  /// the decode returned `lossy: false` and the pump signals loss only when the
  /// chain refuses, so the skipped change was gone with no covering rescan and
  /// the consumer stayed diverged.
  ///
  /// MUTATION WITNESS: drop `strides_to_the_next_record` from the refusal and
  /// both legs FAIL at `must refuse` — the decode returns `lossy: false` with
  /// the FIRST and THIRD records and no trace of the second.
  #[test]
  fn an_inflated_stride_that_skips_a_record_refuses_lossy() {
    for extended in [false, true] {
      let mut buf = Vec::new();
      let first = push_record(&mut buf, extended, 0, 1, &utf16("first"));
      pad4(&mut buf);
      push_record(&mut buf, extended, 0, 2, &utf16("skipped"));
      pad4(&mut buf);
      let third = buf.len();
      push_record(&mut buf, extended, 0, 3, &utf16("third"));
      // A link over the whole middle record: aligned, forward, in-bounds.
      link(&mut buf, first, third - first);

      let decoded = decode_records(&buf, extended);
      assert!(decoded.lossy, "extended={extended} must refuse");
      assert!(
        decoded.records.is_empty(),
        "extended={extended}: an untrustworthy stride publishes nothing"
      );
    }
  }

  /// A link SHORTER than the record it strides is refused too.
  ///
  /// It cannot be witnessed against the stride's lower bound alone, and saying
  /// so is the point: `NextEntryOffset` is a multiple of 4 and the padded end
  /// is the SMALLEST multiple of 4 that holds the name, so every aligned link
  /// below the padded end already cuts the name short and the name-extent
  /// bound refuses it first. The two are redundant on purpose, and MEASURED to
  /// be: dropping either one alone leaves this cell green.
  ///
  /// MUTATION WITNESS: both must go. Bound the name by `buf.len()` AND accept
  /// a link shorter than the padded end, and both legs FAIL at `an
  /// untrustworthy stride publishes nothing` — the short-linked record is
  /// published before the walk resumes inside its own name.
  #[test]
  fn a_stride_shorter_than_the_record_refuses_lossy() {
    for extended in [false, true] {
      let header = if extended {
        EXTENDED_HEADER
      } else {
        BASIC_HEADER
      };
      let mut buf = Vec::new();
      let first = push_record(&mut buf, extended, 0, 1, &utf16("a long enough name"));
      pad4(&mut buf);
      let second = buf.len();
      push_record(&mut buf, extended, 0, 2, &utf16("second"));
      // Four bytes short of this record's own padded end — still aligned,
      // still clear of the fixed prefix, still inside the completion.
      let short = second - first - 4;
      assert!(
        short > header,
        "extended={extended}: the link clears the prefix"
      );
      link(&mut buf, first, short);

      let decoded = decode_records(&buf, extended);
      assert!(decoded.lossy, "extended={extended} must refuse");
      assert!(
        decoded.records.is_empty(),
        "extended={extended}: an untrustworthy stride publishes nothing"
      );
    }
  }

  /// The normal path, unchanged. A well-formed chain whose links land exactly
  /// on each record's padded end walks to the end and publishes every record —
  /// the guard against a bound that refuses what the kernel really sends.
  ///
  /// MUTATION WITNESS: round the record's end to 8 instead of 4 (the shape an
  /// off-by-one in the padding constant takes) and this FAILS at `an exact
  /// chain is clean`, alongside every other cell that walks a real chain.
  #[test]
  fn an_exact_chain_walks_clean() {
    for extended in [false, true] {
      let mut buf = Vec::new();
      let first = push_record(&mut buf, extended, 0, 1, &utf16("one"));
      pad4(&mut buf);
      let second = buf.len();
      push_record(&mut buf, extended, 0, 2, &utf16("two"));
      pad4(&mut buf);
      let third = buf.len();
      push_record(&mut buf, extended, 0, 3, &utf16("three"));
      link(&mut buf, first, second - first);
      link(&mut buf, second, third - second);

      let decoded = decode_records(&buf, extended);
      assert!(
        !decoded.lossy,
        "extended={extended}: an exact chain is clean"
      );
      assert_eq!(decoded.records.len(), 3);
      assert_eq!(decoded.records[0].action, RdcwAction::Added);
      assert_eq!(decoded.records[1].action, RdcwAction::Removed);
      assert_eq!(decoded.records[2].action, RdcwAction::Modified);
      assert_eq!(
        decoded.records[2].name,
        RdcwName::Utf8(vec!["three".into()])
      );
    }
  }

  /// THE over-tightening guard for the layout this backend issues FIRST.
  ///
  /// The basic record's stride is fixed by MS-FSCC 2.7.1 and is held to it
  /// exactly. The extended record has no MS-FSCC section at all — `winnt.h`
  /// documents only "the number of bytes that must be skipped to get to the
  /// next record" — and its own alignment is 8, six `LARGE_INTEGER` fields
  /// over an 84-byte prefix that is itself not a multiple of 8. A producer
  /// rounding those entries to 8 rather than to 4 is inside its documentation,
  /// and for half of all name lengths the two ends differ. Holding extended to
  /// the 4-rounded end would refuse those completions wholesale and trade one
  /// silent loss for a permanent rescan storm, so the extended stride is held
  /// only to the property the loss barrier needs: the gap must be too small to
  /// have been a record.
  ///
  /// MUTATION WITNESS: hold the extended stride to the same exact end as the
  /// basic one (`gap == Some(0)` for both layouts) and this FAILS at
  /// `an 8-aligned stride is well-formed`.
  #[test]
  fn an_eight_aligned_extended_chain_is_not_loss() {
    let mut buf = Vec::new();
    let first = push_record(&mut buf, true, 0, 1, &utf16("one"));
    assert_eq!(buf.len(), 90, "84 + three UTF-16 units");
    while !buf.len().is_multiple_of(8) {
      buf.push(0);
    }
    let second = buf.len();
    assert_eq!(
      second, 96,
      "the 8-rounded end is four past the 4-rounded one"
    );
    push_record(&mut buf, true, 0, 2, &utf16("two"));
    link(&mut buf, first, second - first);

    let decoded = decode_records(&buf, true);
    assert!(!decoded.lossy, "an 8-aligned stride is well-formed");
    assert_eq!(decoded.records.len(), 2);
    assert_eq!(decoded.records[1].name, RdcwName::Utf8(vec!["two".into()]));
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

  /// The three named-stream actions decode as themselves. Left as
  /// `Unknown`, each one's only lowering was a rescan of a colon-bearing
  /// location — and with the filter bits now subscribed, they arrive.
  #[test]
  fn stream_actions_decode() {
    for (word, expected) in [
      (6u32, RdcwAction::StreamAdded),
      (7, RdcwAction::StreamRemoved),
      (8, RdcwAction::StreamModified),
    ] {
      let mut buf = Vec::new();
      push_record(&mut buf, false, 0, word, &utf16("dir\\file.txt:ads:$DATA"));
      let decoded = decode_records(&buf, false);
      assert_eq!(decoded.records[0].action, expected);
      assert!(expected.is_stream());
      assert_eq!(
        decoded.records[0].name,
        RdcwName::Utf8(vec!["dir".into(), "file.txt".into()]),
        "the stream suffix folds onto its owner"
      );
    }
  }

  /// The fold is scoped to the stream actions and to the LAST component: an
  /// ordinary action's name is never cut, and an ancestor is never cut.
  #[test]
  fn the_stream_fold_touches_only_a_stream_records_leaf() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 3, &utf16("file.txt:ads:$DATA"));
    let decoded = decode_records(&buf, false);
    assert_eq!(
      decoded.records[0].name,
      RdcwName::Utf8(vec!["file.txt:ads:$DATA".into()]),
      "a non-stream action's name is delivered verbatim"
    );

    // A `:` can only ever appear in the leaf of a real notify name, so a
    // planted one above it must survive: cutting it would rewrite an
    // ancestor the record never named.
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 8, &utf16("od:d\\file.txt:ads"));
    let decoded = decode_records(&buf, false);
    assert_eq!(
      decoded.records[0].name,
      RdcwName::Utf8(vec!["od:d".into(), "file.txt".into()])
    );
  }

  /// A stream on the watched directory itself folds to the empty name, which
  /// the lowering reads as the root and covers there — never a location whose
  /// leaf is a stream suffix.
  #[test]
  fn a_stream_on_the_root_folds_to_the_root() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 7, &utf16(":ads:$DATA"));
    let decoded = decode_records(&buf, false);
    assert_eq!(decoded.records[0].name, RdcwName::Utf8(vec![]));
  }

  /// No fold, on any action, may leave a `:` inside a component: the proto
  /// path vocabulary has no spelling for one.
  #[test]
  fn a_stream_action_never_publishes_a_colon() {
    for word in [6u32, 7, 8] {
      for name in ["f:s", "f:s:$DATA", ":s", "a\\b\\f:s:$DATA", "f:", "f::x"] {
        let mut buf = Vec::new();
        push_record(&mut buf, false, 0, word, &utf16(name));
        let decoded = decode_records(&buf, false);
        let (RdcwName::Utf8(components) | RdcwName::Escalate { prefix: components }) =
          &decoded.records[0].name;
        assert!(
          components.iter().all(|c| !c.contains(':')),
          "action {word} on {name:?} published {components:?}"
        );
      }
    }
  }

  /// The 8.3 classifier: generated aliases are recognized, and names that
  /// merely resemble them are not.
  #[test]
  fn short_name_aliases_classify() {
    for alias in [
      "LONGFI~1.TXT",
      "PROGRA~1",
      "PROGRA~2",
      "A~1",
      "AB12CD~1.DLL",
      "LONGF~12",
      "X~9.C",
    ] {
      assert!(is_short_name_alias(alias), "{alias} is a generated alias");
    }
    for plain in [
      "",
      "README.TXT",         // its own short form: nothing to diverge from
      "Long File Name.txt", // the canonical spelling
      "longfi~1.txt",       // aliases are upper-cased
      "~1.TXT",             // a generated alias always keeps a base
      "LONGFI~",            // no disambiguating run
      "LONGFI~1A",          // the run is not decimal
      "MY~FILE.TXT",        // ditto
      "ABCDEFGHI~1.TXT",    // the base is past 8
      "LONGFI~1.TEXT",      // the extension is past 3
      "LONG~1.A.B",         // two dots is not 8.3
    ] {
      assert!(!is_short_name_alias(plain), "{plain} is not an alias");
    }
  }

  /// The whole point: a record delivered under the short spelling must not
  /// publish it as the event's location. It escalates at the alias, keeping
  /// every canonical ancestor above it, so the lowering covers the parent and
  /// the consumer re-reads the canonical name from the filesystem.
  #[test]
  fn a_short_name_alias_escalates_instead_of_publishing() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 3, &utf16("deep\\LONGFI~1.TXT"));
    let decoded = decode_records(&buf, false);
    assert!(!decoded.lossy, "an alias is a well-formed record");
    assert_eq!(
      decoded.records[0].name,
      RdcwName::Escalate {
        prefix: vec!["deep".into()],
      }
    );

    // An aliased DIRECTORY escalates there, not at its leaf: everything below
    // an unresolvable ancestor is unresolvable too.
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 2, &utf16("PROGRA~1\\sub\\gone.txt"));
    let decoded = decode_records(&buf, false);
    assert_eq!(
      decoded.records[0].name,
      RdcwName::Escalate { prefix: vec![] }
    );

    // And a canonical name in the same position still delivers.
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 3, &utf16("deep\\Long File Name.txt"));
    let decoded = decode_records(&buf, false);
    assert_eq!(
      decoded.records[0].name,
      RdcwName::Utf8(vec!["deep".into(), "Long File Name.txt".into()])
    );
  }

  /// The fold runs BEFORE the alias test, so a stream on a short-named owner
  /// is judged on the owner rather than on `OWNER~1.TXT:ads:$DATA`, which no
  /// 8.3 shape would ever match.
  #[test]
  fn the_stream_fold_precedes_the_alias_test() {
    let mut buf = Vec::new();
    push_record(&mut buf, false, 0, 8, &utf16("d\\LONGFI~1.TXT:ads:$DATA"));
    let decoded = decode_records(&buf, false);
    assert_eq!(
      decoded.records[0].name,
      RdcwName::Escalate {
        prefix: vec!["d".into()],
      }
    );
  }
}
