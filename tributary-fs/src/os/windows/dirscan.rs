//! The pure `FILE_ID_EXTD_DIR_INFO` page decode — handle-bound directory
//! enumeration's record chain.
//!
//! `GetFileInformationByHandleEx(FileIdExtdDirectoryInfo)` fills a buffer
//! with `NextEntryOffset`-chained records read THROUGH a directory handle:
//! each carries the child's attributes, reparse tag, 128-bit file id, and
//! UTF-16 name. Enumerating through the handle is what makes the USN walks
//! immune to path replacement — no path is ever re-opened to list children,
//! so no impostor directory can be enumerated in the original's place.
//!
//! Decoded defensively like every kernel-produced chain in this crate:
//! validated offsets, explicit little-endian loads, refusal of the remainder
//! on malformation — never UB — so the module runs under miri on every host.

/// One enumerated child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirChild {
  /// The child's name: strict UTF-8, or `None` when it has no Unicode
  /// spelling (the caller's map-death signal for a directory).
  pub(crate) name: Option<String>,
  /// The child's 128-bit file reference number, from the enumeration
  /// itself — authoritative without opening the child.
  pub(crate) frn: u128,
  /// The child's `FILE_ATTRIBUTE_*` word.
  pub(crate) attributes: u32,
}

impl DirChild {
  /// Whether the attributes mark a directory.
  pub(crate) fn is_dir(&self) -> bool {
    self.attributes & 0x10 != 0
  }

  /// Whether the attributes mark a reparse point (a containment boundary).
  pub(crate) fn is_reparse(&self) -> bool {
    self.attributes & 0x400 != 0
  }
}

/// One decoded enumeration page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedPage {
  /// The children decoded before any refusal, `.`/`..` dropped.
  pub(crate) children: Vec<DirChild>,
  /// Whether the chain was refused before its end — the walk treats a
  /// lossy page as a broken walk (fail closed), never a partial listing.
  pub(crate) lossy: bool,
}

/// The fixed prefix of one `FILE_ID_EXTD_DIR_INFO` record.
const HEADER: usize = 88;

#[inline]
fn load_u32(buf: &[u8], at: usize) -> u32 {
  u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

#[inline]
fn load_u128(buf: &[u8], at: usize) -> u128 {
  let mut bytes = [0u8; 16];
  bytes.copy_from_slice(&buf[at..at + 16]);
  u128::from_le_bytes(bytes)
}

/// Decodes one `FileIdExtdDirectoryInfo` page.
pub(crate) fn decode_page(buf: &[u8]) -> DecodedPage {
  let mut children = Vec::new();
  let mut at = 0usize;

  loop {
    if at + HEADER > buf.len() {
      return DecodedPage {
        children,
        lossy: true,
      };
    }
    let next_offset = load_u32(buf, at) as usize;
    let attributes = load_u32(buf, at + 56);
    let name_len = load_u32(buf, at + 60) as usize;
    let frn = load_u128(buf, at + 72);

    let name_at = at + HEADER;
    let name_fits = name_len.is_multiple_of(2)
      && name_at
        .checked_add(name_len)
        .is_some_and(|end| end <= buf.len())
      && (next_offset == 0 || name_at + name_len <= at + next_offset);
    if !name_fits {
      return DecodedPage {
        children,
        lossy: true,
      };
    }
    let units: Vec<u16> = buf[name_at..name_at + name_len]
      .as_chunks::<2>()
      .0
      .iter()
      .map(|pair| u16::from_le_bytes(*pair))
      .collect();
    let dot = units == [u16::from(b'.')];
    let dotdot = units == [u16::from(b'.'), u16::from(b'.')];
    if !dot && !dotdot {
      let name = char::decode_utf16(units.iter().copied())
        .collect::<Result<String, _>>()
        .ok();
      children.push(DirChild {
        name,
        frn,
        attributes,
      });
    }

    if next_offset == 0 {
      return DecodedPage {
        children,
        lossy: false,
      };
    }
    let aligned = next_offset.is_multiple_of(8);
    let Some(next_at) = at.checked_add(next_offset) else {
      return DecodedPage {
        children,
        lossy: true,
      };
    };
    if !aligned || next_offset < HEADER || next_at >= buf.len() {
      return DecodedPage {
        children,
        lossy: true,
      };
    }
    at = next_at;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn push_record(buf: &mut Vec<u8>, next: u32, attrs: u32, frn: u128, name: &[u16]) {
    let at = buf.len();
    buf.extend_from_slice(&next.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
    for _ in 0..6 {
      buf.extend_from_slice(&0i64.to_le_bytes()); // times + sizes
    }
    buf.extend_from_slice(&attrs.to_le_bytes());
    let name_bytes: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // EaSize
    buf.extend_from_slice(&0u32.to_le_bytes()); // ReparsePointTag
    buf.extend_from_slice(&frn.to_le_bytes());
    buf.extend_from_slice(&name_bytes);
    let _ = at;
    if next != 0 {
      buf.resize(at + next as usize, 0);
    }
  }

  fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
  }

  fn stride(name: &[u16]) -> u32 {
    ((HEADER + name.len() * 2).next_multiple_of(8)) as u32
  }

  #[test]
  fn pages_decode_with_dots_dropped() {
    let mut buf = Vec::new();
    push_record(&mut buf, stride(&utf16(".")), 0x10, 1, &utf16("."));
    push_record(&mut buf, stride(&utf16("..")), 0x10, 2, &utf16(".."));
    push_record(&mut buf, stride(&utf16("kid")), 0x10, 7, &utf16("kid"));
    push_record(&mut buf, 0, 0x20, 8, &utf16("file.txt"));
    let page = decode_page(&buf);
    assert!(!page.lossy);
    assert_eq!(page.children.len(), 2);
    assert_eq!(page.children[0].name.as_deref(), Some("kid"));
    assert_eq!(page.children[0].frn, 7);
    assert!(page.children[0].is_dir());
    assert!(!page.children[1].is_dir());
  }

  #[test]
  fn reparse_attributes_surface() {
    let mut buf = Vec::new();
    push_record(&mut buf, 0, 0x410, 9, &utf16("junction"));
    let page = decode_page(&buf);
    assert!(page.children[0].is_dir());
    assert!(page.children[0].is_reparse());
  }

  #[test]
  fn an_unpaired_surrogate_name_is_none() {
    let mut buf = Vec::new();
    push_record(&mut buf, 0, 0x10, 9, &[0xD800]);
    let page = decode_page(&buf);
    assert!(!page.lossy);
    assert_eq!(page.children[0].name, None);
    assert_eq!(page.children[0].frn, 9);
  }

  #[test]
  fn truncation_and_bad_strides_refuse() {
    let decoded = decode_page(&[0u8; 40]);
    assert!(decoded.lossy);

    let mut buf = Vec::new();
    push_record(&mut buf, 0, 0x10, 7, &utf16("ok"));
    let keep = decode_page(&buf);
    assert!(!keep.lossy);

    // A misaligned link refuses the remainder, keeping the prefix.
    let mut buf = Vec::new();
    push_record(&mut buf, stride(&utf16("a")) + 4, 0x10, 7, &utf16("a"));
    push_record(&mut buf, 0, 0x10, 8, &utf16("b"));
    let decoded = decode_page(&buf);
    assert!(decoded.lossy);
    assert_eq!(decoded.children.len(), 1);
  }

  #[test]
  fn a_name_overrunning_its_stride_refuses() {
    let mut buf = Vec::new();
    push_record(&mut buf, stride(&utf16("x")), 0x10, 7, &utf16("x"));
    push_record(&mut buf, 0, 0x10, 8, &utf16("y"));
    // Claim a name that runs past the first record's stride.
    buf[60..64].copy_from_slice(&64u32.to_le_bytes());
    let decoded = decode_page(&buf);
    assert!(decoded.lossy);
    assert!(decoded.children.is_empty());
  }

  #[test]
  fn an_empty_page_is_clean() {
    // A directory with only dot entries yields no children.
    let mut buf = Vec::new();
    push_record(&mut buf, stride(&utf16(".")), 0x10, 1, &utf16("."));
    push_record(&mut buf, 0, 0x10, 2, &utf16(".."));
    let page = decode_page(&buf);
    assert!(!page.lossy);
    assert!(page.children.is_empty());
  }
}
