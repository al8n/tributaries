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
//!
//! Every extent test here is derived from fields inside the SAME untrusted
//! record header, so their ceiling is internal consistency and nothing higher —
//! the identical ceiling the notify decode documents. The page therefore makes
//! the identical two answers, in the identical order: a stride is held to the
//! record it strides, and the counted PAYLOAD is tested against something no
//! header field can forge ([`name_is_possible`]). Both run before ANY child of
//! the record is emitted, and neither consults `FileAttributes` — the walk
//! reads names only off directories, so a FILE record is exactly where a
//! swallowing lie would hide.

use super::rdcw::decode::{name_is_possible, padded_extent};

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

    // The name must fit BOTH the page and — for a nonterminal record — this
    // record's own stride: `NextEntryOffset` is where the next record's header
    // begins, so a name reaching past it would decode that header as name text.
    // The link is a kernel u32 added to a cursor, and `at + next_offset` can
    // wrap `usize` on a 32-bit target before any bound is tested; resolving it
    // through checked arithmetic makes an unrepresentable stride a refusal
    // rather than a debug-build panic. A zero link ends the chain, and the
    // terminal record's extent is the rest of the page — the enumeration
    // reports no byte count, so there is nothing narrower to know.
    let extent = match next_offset {
      0 => buf.len(),
      _ => match at.checked_add(next_offset) {
        Some(end_of_record) => end_of_record.min(buf.len()),
        None => {
          return DecodedPage {
            children,
            lossy: true,
          };
        }
      },
    };
    let name_at = at + HEADER;
    let name_fits = name_len.is_multiple_of(2)
      && name_at
        .checked_add(name_len)
        .is_some_and(|end| end <= extent);
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

    // THE ONE TEST NOT DERIVED FROM THIS HEADER — literally the notify
    // decode's, so the two sites cannot drift. `FileNameLength` and
    // `NextEntryOffset` bound each other and nothing else, so a record that
    // inflates BOTH by the same amount satisfies every test above at once: its
    // claimed end lands exactly on its link, the alignment holds, the name
    // "fits", and the walk resumes past the entries the name has quietly
    // swallowed. MS-FSCC 2.4.23 makes each entry exactly one enumerated child,
    // so those swallowed bytes are another entry's HEADER — little-endian
    // `u32`s (a link of a few dozen or zero, a name length of a few dozen, an
    // EaSize, a reparse tag) whose high halves are zero, which is a U+0000 at
    // every even offset they land on. No Windows name in any namespace
    // contains one, so the payload betrays the shape the header cannot.
    //
    // BEFORE the dot filter and REGARDLESS of `FileAttributes`, which is the
    // whole point of putting it here. The walk reads names only off
    // directories, so an inflated name on a FILE record is never examined at
    // all: it would swallow the directory entry behind it, that directory
    // would never be mapped, and every later event beneath it would be
    // classified outside-root and dropped — a subtree lost under a page this
    // decode called clean. Testing only the records whose names are used would
    // leave exactly that hole open.
    if !name_is_possible(&units) {
      return DecodedPage {
        children,
        lossy: true,
      };
    }

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
    // A stride must land on the record it strides. Alignment, forward progress
    // and in-boundsness are not enough: a link satisfying all three can still
    // be larger than the entry it steps over, and what it steps over is not
    // slack — it is a child the walk then never sees. A skipped DIRECTORY is
    // worse than a skipped record, because it is never mapped and every later
    // event beneath it is classified outside-root and dropped too, all under a
    // clean page. So the gap the stride leaves past this record's own padded
    // end must be too small to have BEEN a record, and no record is shorter
    // than its own fixed prefix. (A link that does not even clear that prefix
    // cannot subtract at all, so the earlier `next_offset < HEADER` bound is
    // subsumed by this one.) The gap is bounded rather than pinned to zero for
    // the reason the notify decode's extended stride is: MS-FSCC 2.4.23
    // publishes no padding granularity for this layout either, and an inferred
    // one a real producer disagrees with turns every enumeration into a stall.
    let gap = padded_extent(HEADER, name_len).and_then(|end| next_offset.checked_sub(end));
    let strides_to_the_next_record = gap.is_some_and(|gap| gap < HEADER);
    if !aligned || !strides_to_the_next_record || next_at >= buf.len() {
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

  /// Appends one record to `buf`, returning the offset it was written at.
  fn push_record(buf: &mut Vec<u8>, next: u32, attrs: u32, frn: u128, name: &[u16]) -> usize {
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
    if next != 0 {
      buf.resize(at + next as usize, 0);
    }
    at
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

  /// A `NextEntryOffset` of nearly `u32::MAX`: on a 32-bit target (i686)
  /// `at + next_offset` overflows `usize`, and the old bound computed that sum
  /// unchecked — a panic on the add, before any bound was ever tested. Resolved
  /// through checked arithmetic it is a refusal at every pointer width, which
  /// is what the page's fail-closed contract wants.
  ///
  /// MUTATION WITNESS (32-bit only): revert the bound to the unchecked
  /// `at + next_offset` and this FAILS under
  /// `cargo miri test --target i686-unknown-linux-gnu` with `attempt to add
  /// with overflow`. At 64-bit pointer width the sum is representable, so the
  /// mutation is invisible there and only the refusal itself stays pinned.
  #[test]
  fn an_absurd_stride_refuses_rather_than_overflowing() {
    let mut buf = Vec::new();
    push_record(&mut buf, stride(&utf16("ok")), 0x10, 7, &utf16("ok"));
    let second_at = buf.len();
    push_record(&mut buf, 0, 0x10, 8, &utf16("absurd"));
    // Patched in rather than passed to the helper, which pads the page out to
    // whatever stride it is given.
    buf[second_at..second_at + 4].copy_from_slice(&(u32::MAX - 7).to_le_bytes());
    let decoded = decode_page(&buf);
    assert!(
      decoded.lossy,
      "a stride nothing can contain refuses the page"
    );
  }

  /// R4's Finding A: the coherent lie, at the site the notify decode's sweep
  /// did not reach.
  ///
  /// A FILE record links over the DIRECTORY behind it and inflates its own
  /// `FileNameLength` by exactly what the link was inflated by. Every test
  /// derived from the header then agrees with itself — the claimed end lands on
  /// the link to the byte, the alignment holds, the name "fits" — and the walk
  /// resumes on the third record having never seen the second.
  ///
  /// What that costs is worse than one dropped entry, which is why the file
  /// attribute is the load-bearing detail: the walk reads names only off
  /// directories, so the inflated name on a file record is never examined at
  /// all. The swallowed DIRECTORY is never mapped, and every later event
  /// beneath it is then classified outside-root and dropped too — a whole
  /// subtree lost under a page reported clean. A check that ran only on the
  /// records whose names are used would leave exactly this shape open.
  ///
  /// MUTATION WITNESS: drop the `name_is_possible` refusal and this FAILS at
  /// `a swallowing record is never published` — the page decodes clean with the
  /// FIRST and THIRD children and no trace of `kid`.
  #[test]
  fn a_file_record_may_not_swallow_the_directory_its_link_skips() {
    let mut buf = Vec::new();
    let first = push_record(
      &mut buf,
      stride(&utf16("file.txt")),
      0x20,
      7,
      &utf16("file.txt"),
    );
    push_record(&mut buf, stride(&utf16("kid")), 0x10, 8, &utf16("kid"));
    let third = buf.len();
    push_record(&mut buf, 0, 0x20, 9, &utf16("third.txt"));

    // Link over the directory, then grow the file's name to cover exactly the
    // bytes the link steps over.
    let stride_over = third - first;
    buf[first..first + 4].copy_from_slice(&(stride_over as u32).to_le_bytes());
    let inflated = (stride_over - HEADER) as u32;
    buf[first + 60..first + 64].copy_from_slice(&inflated.to_le_bytes());
    // Coherent by construction: the claimed end IS the link, so nothing
    // computed from this header can tell them apart.
    assert_eq!(
      padded_extent(HEADER, inflated as usize),
      Some(stride_over),
      "the claimed end is the link"
    );

    let page = decode_page(&buf);
    assert!(page.lossy, "a name that cannot exist refuses the page");
    assert!(
      page.children.is_empty(),
      "a swallowing record is never published"
    );
  }

  /// The same site's simpler shape, and the one the payload test cannot reach:
  /// an HONEST name whose link is a whole entry too long. Nothing in the record
  /// is inconsistent — the name is real, the stride is aligned, forward and
  /// well inside the page — and the entry it vaults is simply never visited.
  ///
  /// MUTATION WITNESS: drop `strides_to_the_next_record` from the refusal and
  /// this FAILS at `a link that vaults a child is not a stride` — the page
  /// decodes clean with the first and third children and no trace of `kid`.
  #[test]
  fn an_inflated_stride_that_skips_a_child_refuses_lossy() {
    let mut buf = Vec::new();
    let first = push_record(
      &mut buf,
      stride(&utf16("file.txt")),
      0x20,
      7,
      &utf16("file.txt"),
    );
    push_record(&mut buf, stride(&utf16("kid")), 0x10, 8, &utf16("kid"));
    let third = buf.len();
    push_record(&mut buf, 0, 0x20, 9, &utf16("third.txt"));
    buf[first..first + 4].copy_from_slice(&((third - first) as u32).to_le_bytes());

    let page = decode_page(&buf);
    assert!(page.lossy, "a link that vaults a child is not a stride");
    assert_eq!(
      page.children.len(),
      1,
      "the vaulting record stands and the chain refuses behind it"
    );
    assert!(
      page.children.iter().all(|child| child.frn != 8),
      "the skipped directory is never published"
    );
  }

  /// The over-tightening guard for both of the tests above. A page whose
  /// entries are packed the way an enumeration really packs them — the two dot
  /// entries first, names of both parities so half the entries carry real
  /// padding, files and directories interleaved — must decode clean and whole.
  /// A refusal here is not one rescan: the caller reads a lossy page as a
  /// broken walk, so an over-tight bound would disqualify the journal backend
  /// on every volume rather than cost a re-enumeration.
  ///
  /// MUTATION WITNESS: hold the stride to the record's exact 4-rounded end
  /// (`gap == Some(0)`) and this FAILS at `an ordinary enumeration page is not
  /// loss` — every 8-aligned entry whose name length is not a multiple of 4
  /// leaves a four-byte gap.
  #[test]
  fn an_ordinary_multi_child_page_stays_clean() {
    let names = [
      ".",
      "..",
      "a",
      "bb",
      "ccc",
      "dddd",
      "Long File Name.txt",
      "z",
    ];
    let mut buf = Vec::new();
    for (index, name) in names.iter().enumerate() {
      let units = utf16(name);
      let last = index + 1 == names.len();
      let next = if last { 0 } else { stride(&units) };
      // Directories and files alternate: the check must not depend on either.
      let attrs = if index % 2 == 0 { 0x10 } else { 0x20 };
      push_record(&mut buf, next, attrs, index as u128, &units);
    }

    let page = decode_page(&buf);
    assert!(!page.lossy, "an ordinary enumeration page is not loss");
    let decoded: Vec<Option<&str>> = page
      .children
      .iter()
      .map(|child| child.name.as_deref())
      .collect();
    assert_eq!(
      decoded,
      names[2..].iter().copied().map(Some).collect::<Vec<_>>(),
      "the dots drop and every other child stands, in order"
    );
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
