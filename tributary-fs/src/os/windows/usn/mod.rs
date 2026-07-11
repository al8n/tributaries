//! The USN change-journal source's pure machinery: the reason vocabulary,
//! the cumulative-mask delta table, and the FRN-keyed rename pairing.
//!
//! Reasons are CUMULATIVE per open session — each successive record for one
//! open instance carries the OR of everything so far, finalized by a record
//! carrying `USN_REASON_CLOSE`. Emitting every record's full mask would
//! re-report old facts on every write, so the session table remembers the
//! last mask emitted per subject and lowers only the DELTA; `CLOSE` retires
//! the entry. The table is a bounded noise filter, not an accounting
//! structure: evicting an entry merely re-reports already-reported bits,
//! never loses one, so the cap is harmless by construction.

pub(crate) mod decode;
pub(crate) mod map;

use decode::UsnRecord;

/// `USN_REASON_*` bits (the stable journal ABI).
pub(crate) mod reason {
  pub(crate) const DATA_OVERWRITE: u32 = 0x1;
  pub(crate) const DATA_EXTEND: u32 = 0x2;
  pub(crate) const DATA_TRUNCATION: u32 = 0x4;
  pub(crate) const NAMED_DATA_OVERWRITE: u32 = 0x10;
  pub(crate) const NAMED_DATA_EXTEND: u32 = 0x20;
  pub(crate) const NAMED_DATA_TRUNCATION: u32 = 0x40;
  pub(crate) const FILE_CREATE: u32 = 0x100;
  pub(crate) const FILE_DELETE: u32 = 0x200;
  pub(crate) const EA_CHANGE: u32 = 0x400;
  pub(crate) const SECURITY_CHANGE: u32 = 0x800;
  pub(crate) const RENAME_OLD_NAME: u32 = 0x1000;
  pub(crate) const RENAME_NEW_NAME: u32 = 0x2000;
  pub(crate) const INDEXABLE_CHANGE: u32 = 0x4000;
  pub(crate) const BASIC_INFO_CHANGE: u32 = 0x8000;
  pub(crate) const HARD_LINK_CHANGE: u32 = 0x1_0000;
  pub(crate) const COMPRESSION_CHANGE: u32 = 0x2_0000;
  pub(crate) const ENCRYPTION_CHANGE: u32 = 0x4_0000;
  pub(crate) const OBJECT_ID_CHANGE: u32 = 0x8_0000;
  pub(crate) const REPARSE_POINT_CHANGE: u32 = 0x10_0000;
  pub(crate) const STREAM_CHANGE: u32 = 0x20_0000;
  pub(crate) const TRANSACTED_CHANGE: u32 = 0x40_0000;
  pub(crate) const INTEGRITY_CHANGE: u32 = 0x80_0000;
  pub(crate) const DESIRED_STORAGE_CLASS_CHANGE: u32 = 0x100_0000;
  pub(crate) const CLOSE: u32 = 0x8000_0000;

  /// The bits this vocabulary deliberately never lowers: index/object-id/
  /// transaction bookkeeping is filesystem-internal, invisible to a
  /// consumer's tree.
  pub(crate) const FILTERED: u32 = INDEXABLE_CHANGE | OBJECT_ID_CHANGE | TRANSACTED_CHANGE;

  /// Content mutations that lower to `Modified`.
  pub(crate) const MODIFY: u32 = DATA_OVERWRITE | DATA_EXTEND | DATA_TRUNCATION;

  /// Metadata mutations that lower to `Attrib` (named streams deliberately
  /// among them: an ADS write changes the OWNER file's metadata surface,
  /// never a child object).
  pub(crate) const ATTRIB: u32 = EA_CHANGE
    | SECURITY_CHANGE
    | BASIC_INFO_CHANGE
    | COMPRESSION_CHANGE
    | ENCRYPTION_CHANGE
    | INTEGRITY_CHANGE
    | DESIRED_STORAGE_CLASS_CHANGE
    | NAMED_DATA_OVERWRITE
    | NAMED_DATA_EXTEND
    | NAMED_DATA_TRUNCATION
    | STREAM_CHANGE;

  /// Structural bits the map (and the lowering's verb choice) act on.
  pub(crate) const STRUCTURAL: u32 =
    FILE_CREATE | FILE_DELETE | RENAME_OLD_NAME | RENAME_NEW_NAME | HARD_LINK_CHANGE;
}

/// The bounded last-emitted-mask table that turns cumulative reasons into
/// deltas.
#[derive(Debug)]
pub(crate) struct SessionTable {
  last: std::collections::BTreeMap<u128, u32>,
  cap: usize,
}

impl SessionTable {
  /// A table bounded at `cap` live sessions.
  pub(crate) fn new(cap: usize) -> Self {
    Self {
      last: std::collections::BTreeMap::new(),
      cap,
    }
  }

  /// The mask bits `record` NEWLY reports (its cumulative mask minus what
  /// this table already saw emitted for the subject). A `CLOSE` retires the
  /// session; a full table evicts an arbitrary session first (harmless: the
  /// evicted subject's next record re-reports, never under-reports).
  pub(crate) fn delta(&mut self, record: &UsnRecord) -> u32 {
    let seen = self.last.get(&record.frn).copied().unwrap_or(0);
    let fresh = record.reason & !seen;
    if record.reason & reason::CLOSE != 0 {
      self.last.remove(&record.frn);
    } else if fresh != 0 {
      if self.last.len() >= self.cap && !self.last.contains_key(&record.frn) {
        let evict = self.last.keys().next().copied();
        if let Some(evict) = evict {
          self.last.remove(&evict);
        }
      }
      self.last.insert(record.frn, record.reason);
    }
    // CLOSE itself is session GC, never a reportable fact.
    fresh & !reason::CLOSE
  }

  /// How many sessions the table currently tracks.
  pub(crate) fn len(&self) -> usize {
    self.last.len()
  }
}

/// One journal event after pairing — what the source lowers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsnEvent {
  /// A non-rename record (its delta mask attached by the session table).
  Single(UsnRecord),
  /// An atomically paired rename: the OLD and NEW halves share the FRN.
  Renamed {
    /// The departing half (`RENAME_OLD_NAME` in its delta).
    old: UsnRecord,
    /// The arriving half (`RENAME_NEW_NAME` in its delta).
    new: UsnRecord,
  },
  /// An OLD half whose NEW never arrived.
  WidowOld(UsnRecord),
  /// A NEW half with no OLD held.
  WidowNew(UsnRecord),
}

/// The FRN-keyed rename pairing state: at most one OLD half carried between
/// records (and across read boundaries) — the RDCW carry-slot shape, with
/// the journal's stronger key (rename halves SHARE the subject FRN).
#[derive(Debug, Default)]
pub(crate) struct UsnPairer {
  pending_old: Option<UsnRecord>,
}

impl UsnPairer {
  /// A fresh pairer with an empty carry slot.
  pub(crate) const fn new() -> Self {
    Self { pending_old: None }
  }

  /// Feeds one record (with `delta` as its fresh mask) in journal order,
  /// appending completed events to `out`.
  pub(crate) fn push(&mut self, record: UsnRecord, delta: u32, out: &mut Vec<UsnEvent>) {
    let is_old = delta & reason::RENAME_OLD_NAME != 0;
    let is_new = delta & reason::RENAME_NEW_NAME != 0;
    if is_old && !is_new {
      self.flush(out);
      self.pending_old = Some(record);
      return;
    }
    if is_new {
      match self.pending_old.take() {
        Some(old) if old.frn == record.frn => {
          out.push(UsnEvent::Renamed { old, new: record });
        }
        Some(stranger) => {
          out.push(UsnEvent::WidowOld(stranger));
          out.push(UsnEvent::WidowNew(record));
        }
        None => out.push(UsnEvent::WidowNew(record)),
      }
      return;
    }
    // Any other record breaks adjacency: the held OLD widows first.
    self.flush(out);
    out.push(UsnEvent::Single(record));
  }

  /// Widows the held OLD, if any — the read-boundary, loss-barrier, and
  /// teardown flush.
  pub(crate) fn flush(&mut self, out: &mut Vec<UsnEvent>) {
    if let Some(old) = self.pending_old.take() {
      out.push(UsnEvent::WidowOld(old));
    }
  }

  /// Whether an OLD half is parked — the source's cue to bound its next
  /// journal wait.
  pub(crate) fn holds_old(&self) -> bool {
    self.pending_old.is_some()
  }
}

#[cfg(test)]
mod tests {
  use super::{
    decode::{UsnName, UsnRecord},
    *,
  };

  fn record(frn: u128, reason_mask: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent: 1,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: 0x20,
      name: UsnName::Utf8(name.into()),
    }
  }

  #[test]
  fn cumulative_masks_emit_as_deltas() {
    let mut table = SessionTable::new(16);
    let first = record(7, reason::DATA_EXTEND, "f");
    assert_eq!(table.delta(&first), reason::DATA_EXTEND);
    let second = record(7, reason::DATA_EXTEND | reason::DATA_OVERWRITE, "f");
    assert_eq!(
      table.delta(&second),
      reason::DATA_OVERWRITE,
      "only the new bit"
    );
    let third = record(
      7,
      reason::DATA_EXTEND | reason::DATA_OVERWRITE | reason::CLOSE,
      "f",
    );
    assert_eq!(table.delta(&third), 0, "CLOSE alone reports nothing");
    assert_eq!(table.len(), 0, "CLOSE retires the session");
    // A fresh session after CLOSE re-reports from zero.
    let reopened = record(7, reason::DATA_EXTEND, "f");
    assert_eq!(table.delta(&reopened), reason::DATA_EXTEND);
  }

  #[test]
  fn eviction_rereports_but_never_loses() {
    let mut table = SessionTable::new(1);
    let a = record(1, reason::DATA_EXTEND, "a");
    assert_eq!(table.delta(&a), reason::DATA_EXTEND);
    let b = record(2, reason::DATA_OVERWRITE, "b");
    assert_eq!(table.delta(&b), reason::DATA_OVERWRITE, "b evicts a");
    let a_again = record(1, reason::DATA_EXTEND, "a");
    assert_eq!(
      table.delta(&a_again),
      reason::DATA_EXTEND,
      "the evicted session re-reports — noisy, never silent"
    );
  }

  #[test]
  fn frn_keyed_halves_pair() {
    let mut pairer = UsnPairer::new();
    let mut out = Vec::new();
    let mut table = SessionTable::new(16);

    let old = record(7, reason::RENAME_OLD_NAME, "before");
    let delta = table.delta(&old);
    pairer.push(old, delta, &mut out);
    assert!(out.is_empty());
    assert!(pairer.holds_old());

    // The NEW half is a fresh session (the OLD closed its own record), so
    // its cumulative mask stands alone.
    let new = record(7, reason::RENAME_NEW_NAME, "after");
    let delta = table.delta(&new);
    pairer.push(new, delta, &mut out);
    assert_eq!(out.len(), 1);
    assert!(matches!(&out[0], UsnEvent::Renamed { old, new }
      if old.name == UsnName::Utf8("before".into())
        && new.name == UsnName::Utf8("after".into())));
  }

  #[test]
  fn a_different_frn_widows_both() {
    let mut pairer = UsnPairer::new();
    let mut out = Vec::new();
    pairer.push(
      record(7, reason::RENAME_OLD_NAME, "x"),
      reason::RENAME_OLD_NAME,
      &mut out,
    );
    pairer.push(
      record(9, reason::RENAME_NEW_NAME, "y"),
      reason::RENAME_NEW_NAME,
      &mut out,
    );
    assert_eq!(out.len(), 2);
    assert!(matches!(&out[0], UsnEvent::WidowOld(rec) if rec.frn == 7));
    assert!(matches!(&out[1], UsnEvent::WidowNew(rec) if rec.frn == 9));
  }

  #[test]
  fn an_intervening_record_widows_in_order() {
    let mut pairer = UsnPairer::new();
    let mut out = Vec::new();
    pairer.push(
      record(7, reason::RENAME_OLD_NAME, "x"),
      reason::RENAME_OLD_NAME,
      &mut out,
    );
    pairer.push(
      record(8, reason::FILE_CREATE, "z"),
      reason::FILE_CREATE,
      &mut out,
    );
    assert_eq!(out.len(), 2);
    assert!(matches!(&out[0], UsnEvent::WidowOld(_)));
    assert!(matches!(&out[1], UsnEvent::Single(rec) if rec.frn == 8));
    pairer.flush(&mut out);
    assert_eq!(out.len(), 2, "flush on empty is a no-op");
  }

  #[test]
  fn vocabulary_partitions_are_disjoint() {
    assert_eq!(reason::MODIFY & reason::ATTRIB, 0);
    assert_eq!(reason::MODIFY & reason::STRUCTURAL, 0);
    assert_eq!(reason::ATTRIB & reason::STRUCTURAL, 0);
    assert_eq!(reason::FILTERED & reason::MODIFY, 0);
    assert_eq!(reason::FILTERED & reason::ATTRIB, 0);
    assert_eq!(reason::FILTERED & reason::STRUCTURAL, 0);
    assert_eq!(
      reason::CLOSE & (reason::MODIFY | reason::ATTRIB | reason::STRUCTURAL),
      0
    );
  }
}
