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
    let name_fits = name_len.is_multiple_of(2)
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

    if next_offset == 0 {
      return DecodedBuffer {
        records,
        lossy: false,
      };
    }
    // A link must be DWORD-aligned and make forward progress past this
    // record's fixed prefix, inside the buffer.
    let aligned = next_offset.is_multiple_of(4);
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
